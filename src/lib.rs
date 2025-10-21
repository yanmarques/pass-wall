use std::{
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Form, Router,
    body::Body,
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use axum_extra::extract::{CookieJar, Host as HeaderHost};
use bytes::Bytes;
use cookie::SameSite;
use hyper::{StatusCode, Uri};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, errors::ErrorKind,
};
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

// Internals
pub const CSRF_TOKEN_COOKIE_NAME: &str = "csrf_token";

// Config
pub const DEFAULT_KEYSIZE: usize = 32;
pub const DEFAULT_COOKIE_NAME: &str = "passwall_session";
pub const DEFAULT_PORT: u16 = 9000;

// Input validation
pub const MAX_PASSWORD_LENGTH: usize = 256;
pub const MAX_USER_LENGTH: usize = 256;
pub const MAX_CSRF_TOKEN_LENGTH: usize = 32;
pub const MAX_BODY_LENGTH: usize = (MAX_PASSWORD_LENGTH + MAX_USER_LENGTH) * 2;

/// JWT claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub redirect: Option<String>,
    pub user: Option<String>,
    pub exp: u64,
}

/// Allowed user
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    // Argon password bytes
    pub password_hash: String,
}

impl<'a> Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("password_hash", &"...")
            .finish()
    }
}

/// Define who and what can be access and be accessed
#[derive(Clone, Debug)]
pub struct Policy {
    pub users: rustc_hash::FxHashMap<String, User>,
    pub authorized_hosts: rustc_hash::FxHashMap<String, Vec<String>>,
}

impl Policy {
    /// Returns a [`Host`] if the given user is authorized to access the given host, according to the
    /// defined policy.
    ///
    /// Returns [`None`] otherwise.
    pub fn authorize(&self, user: &String) -> Option<&Vec<String>> {
        return self.authorized_hosts.get(user);
    }
}

/// User configuration to define who can access what hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    /// The host. It can be a subdomain or a base domain, and it may include a port. It must not include
    /// schemes (e.g.: https:// or http://).
    pub host: String,
    /// All users authorized to access the host. If `include_subdomain` is true, also authorize
    /// users to access all subdomain's of the host's domain (only if a subdomain).
    pub allowed_users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SameSiteConfig {
    #[allow(non_camel_case_types)]
    strict,
    #[allow(non_camel_case_types)]
    lax,
    #[allow(non_camel_case_types)]
    none,
}

impl SameSiteConfig {
    pub fn to_cookie_samesite(&self) -> SameSite {
        match self {
            Self::strict => SameSite::Strict,
            Self::lax => SameSite::Lax,
            Self::none => SameSite::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// The cookie name. Default is 'passwall_session'.
    pub cookie_name: String,
    /// Define the maximum lifetime of the session tokens in seconds. Default is 1 hour.
    pub expiration_secs: u64,
    /// Controls the 'SameSite' cookie attribute. Choices are 'strict', 'lax', or 'none'. Default
    /// is 'strict'.
    pub same_site: SameSiteConfig,
    /// Controls the 'Secure' cookie attribute. When true, allows the cookie to be sent by browers over unencrypted http requests. Default is false.
    pub insecure_http: bool,
    /// Controls the 'HttpOnly' cookie attribute. When true, allows JavaScript code in the page to
    /// access the cookie through `document.cookie`. Default is false.
    pub disable_secure_http_only: bool,
}

impl SessionConfig {
    pub fn default() -> Self {
        Self {
            cookie_name: String::from(DEFAULT_COOKIE_NAME),
            expiration_secs: 60 * 60,
            same_site: SameSiteConfig::strict,
            insecure_http: false,
            disable_secure_http_only: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server listener address in the following format: HOST:PORT. Default is 0.0.0.0:9000
    pub app_bind: String,
    /// A cryptographically secure key used to encrypt Json Web Tokens. It is important this key be
    /// generated correctly. Use the default generated config unless you know what you are doing.
    /// The default key generates 256 bits of entropy for the HMAC-SHA256 algorithm used in JWTs.
    pub app_key: String,
    /// Allowed users.
    pub users: Vec<User>,
    /// Access control per host and user.
    pub acl: Vec<AccessControlConfig>,
    /// Session configuration.
    pub session: SessionConfig,
}

/// All static pages
#[derive(Clone)]
pub struct StaticPages {
    pub login: Bytes,
    pub unauthenticated: Bytes,
    pub unauthorized: Bytes,
}

/// Some shared data
#[derive(Clone)]
pub struct AppState {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub static_pages: StaticPages,
    pub policy: Policy,
    pub session: SessionConfig,
}

/// Login form input
#[derive(Deserialize, Debug)]
struct LoginInput {
    name: String,
    password: String,
    csrf_token: String,
}

#[derive(Deserialize, Debug)]
struct SigninQuery {
    redirect: Option<String>,
}

/// Local app error
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self.0, "request handling error");

        (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl Config {
    pub fn default() -> Self {
        let mut bytes = [0u8; DEFAULT_KEYSIZE];
        OsRng.try_fill_bytes(&mut bytes).expect("get random bytes");
        let key = hex::encode(&bytes);

        Self {
            app_bind: format!("0.0.0.0:{DEFAULT_PORT}"),
            app_key: key,
            users: vec![],
            acl: vec![],
            session: SessionConfig::default(),
        }
    }
}

impl Claims {
    pub fn new(user: Option<String>, redirect: Option<String>, expire_in: u64) -> Self {
        let expiration = SystemTime::now() + Duration::from_secs(expire_in);

        Claims {
            redirect,
            user,
            exp: expiration
                .duration_since(UNIX_EPOCH)
                .expect("can not get current timestamp")
                .as_secs(),
        }
    }
}

impl TryFrom<Config> for Policy {
    type Error = anyhow::Error;

    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut users = rustc_hash::FxHashMap::<String, User>::default();
        for user in &value.users {
            if user.name.len() > MAX_USER_LENGTH {
                return Err(anyhow::anyhow!(
                    "User name is too large. To keep things civilized, the maximum user name length is hardcapped to {}",
                    MAX_USER_LENGTH,
                ));
            }

            if let Err(err) = PasswordHash::new(&user.password_hash) {
                let char = user.password_hash.chars().last();
                return Err(anyhow::anyhow!(
                    "User password hash is invalid or malformed. Affected user: {}, password hash: ...{}, err: {:?}",
                    user.name,
                    char.unwrap_or(' '),
                    err,
                ));
            }

            users.insert(
                user.name.clone(),
                User {
                    name: user.name.clone(),
                    password_hash: user.password_hash.clone(),
                },
            );
        }

        let mut authorized_hosts = rustc_hash::FxHashMap::<String, Vec<String>>::default();

        for access_control in &value.acl {
            if access_control.host.is_empty() {
                return Err(anyhow::anyhow!("ACL configuration contains an empty host",));
            }

            for user_name in &access_control.allowed_users {
                if user_name.is_empty() {
                    return Err(anyhow::anyhow!(
                        "ACL configuration contains an empty allowed username",
                    ));
                }

                let user = match users.get(user_name) {
                    Some(u) => u,
                    None => {
                        return Err(anyhow::anyhow!(
                            "The endpoint '{}' configuration specifies an inexistent user called '{}'",
                            access_control.host,
                            user_name
                        ));
                    }
                };

                if let Some(hosts) = authorized_hosts.get_mut(&user.name) {
                    hosts.push(access_control.host.clone());
                } else {
                    authorized_hosts.insert(
                        user.name.clone(),
                        Vec::from_iter([access_control.host.clone()]),
                    );
                }
            }
        }

        Ok(Policy {
            users,
            authorized_hosts,
        })
    }
}

pub fn app(config: &Config) -> anyhow::Result<Router> {
    let static_pages = StaticPages {
        login: Bytes::from_owner(include_bytes!("./../static/login.html")),
        unauthenticated: Bytes::from_owner(include_bytes!("./../static/unauthenticated.html")),
        unauthorized: Bytes::from_owner(include_bytes!("./../static/unauthorized.html")),
    };

    let policy = Policy::try_from(config.clone())?;
    tracing::debug!(?policy, "runtime policy");

    let app_key_bytes = config.app_key.as_bytes();

    let app = Router::new()
        .route("/", axum::routing::get(show_signin))
        .route("/healthz", axum::routing::get(show_health))
        .route("/signin", axum::routing::post(signin))
        .route("/authenticate", axum::routing::get(proxy_authenticate))
        .with_state(AppState {
            policy,
            static_pages,
            encoding_key: EncodingKey::from_secret(&app_key_bytes),
            decoding_key: DecodingKey::from_secret(&app_key_bytes),
            session: config.session.clone(),
        });

    return Ok(app);
}

/// Return whether the given token is a valid JWT token for the key
fn validate_token(token: &str, key: &DecodingKey) -> Option<TokenData<Claims>> {
    let validation = Validation::new(Algorithm::HS256);
    match jsonwebtoken::decode::<Claims>(token, key, &validation) {
        Ok(data) => Some(data),
        Err(err) => {
            tracing::error!(?err, "token is invalid");
            match *err.kind() {
                ErrorKind::InvalidToken => tracing::error!("Token is invalid"),
                ErrorKind::InvalidIssuer => tracing::error!("Issuer is invalid"),
                _ => (),
            };

            return None;
        }
    }
}

async fn show_health() -> Result<Response, AppError> {
    return Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())?);
}

async fn signin(
    State(app_state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> Result<Response, AppError> {
    if input.name.len() > MAX_USER_LENGTH
        || input.password.len() > MAX_PASSWORD_LENGTH
        || input.csrf_token.len() > MAX_CSRF_TOKEN_LENGTH
    {
        tracing::error!(
            name_length = input.name.len(),
            password_length = input.password.len(),
            csrf_token_length = input.csrf_token.len(),
            "received a signin form that is too large"
        );
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from(app_state.static_pages.unauthenticated))?);
    }

    let redirect = match jar
        .get(&app_state.session.cookie_name)
        .and_then(|prev_cookie| validate_token(prev_cookie.value(), &app_state.decoding_key))
        .and_then(|prev_token| prev_token.claims.redirect)
    {
        Some(t) => t,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header("location", "/")
                .body(Body::empty())?);
        }
    };

    let mut csrf_matches = false;
    if let Some(csrf_cookie) = jar.get(CSRF_TOKEN_COOKIE_NAME) {
        let csrf_from_cookie = csrf_cookie.value().as_bytes();
        let csrf_from_form = input.csrf_token.as_bytes();
        csrf_matches = csrf_from_cookie.ct_eq(csrf_from_form).unwrap_u8() == 1;
    }

    if csrf_matches == false {
        return Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header("location", "/")
            .body(Body::empty())?);
    }

    if let Some(user) = app_state.policy.users.get(&input.name) {
        if Uri::try_from(&redirect).is_ok() {
            if let Some(hosts) = app_state.policy.authorize(&user.name) {
                let password_hash = user.password_hash.clone();

                let crypto_op = tokio::spawn(async move {
                    let parsed_hash = PasswordHash::new(&password_hash).map_err(|err| {
                        tracing::error!(?err, "failed to parse user's password hash");
                        return anyhow::anyhow!("failed to parse user's password");
                    })?;

                    Argon2::default()
                        .verify_password(input.password.as_bytes(), &parsed_hash)
                        .map_err(|err| {
                            tracing::error!(?err, "failed to verify user password");
                            return anyhow::anyhow!("failed to verify user password");
                        })
                })
                .await?;

                if crypto_op.is_ok() {
                    let claims = Claims::new(
                        Some(user.name.clone()),
                        None,
                        app_state.session.expiration_secs,
                    );

                    let token = jsonwebtoken::encode(
                        &Header::new(Algorithm::HS256),
                        &claims,
                        &app_state.encoding_key,
                    )?;

                    let mut response_builder = Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", redirect);

                    for host in hosts {
                        let set_cookie =
                            cookie::Cookie::build((&app_state.session.cookie_name, &token))
                                .secure(!app_state.session.insecure_http)
                                .http_only(!app_state.session.disable_secure_http_only)
                                .domain(host)
                                .same_site(app_state.session.same_site.to_cookie_samesite());

                        response_builder =
                            response_builder.header("set-cookie", set_cookie.to_string());
                    }

                    return Ok(response_builder.body(Body::empty())?);
                }
            }
        }
    }

    return Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(app_state.static_pages.unauthenticated))?);
}

async fn show_signin(
    State(app_state): State<AppState>,
    Query(signin_query): Query<SigninQuery>,
    jar: CookieJar,
) -> Result<Response, AppError> {
    let redirect = signin_query
        .redirect
        .and_then(|url| Uri::try_from(url).ok())
        .ok_or_else(|| AppError::from(anyhow::anyhow!("missing redirect query param")))?;

    let authenticated_user = jar
        .get(&app_state.session.cookie_name)
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| token.claims.user);

    if let Some(user) = authenticated_user {
        if let Some(_hosts) = app_state.policy.authorize(&user) {
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header("location", redirect.to_string())
                .body(Body::empty())?);
        }
    }

    let claims = Claims::new(
        None,
        Some(redirect.to_string()),
        app_state.session.expiration_secs,
    );
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &app_state.encoding_key,
    )?;

    let sess_cookie = cookie::Cookie::build((&app_state.session.cookie_name, token))
        .secure(!app_state.session.insecure_http)
        .http_only(!app_state.session.disable_secure_http_only)
        .same_site(app_state.session.same_site.to_cookie_samesite())
        .build();

    let mut rng = rand::rngs::OsRng;
    let mut csrf_token = [0u8; 16];
    rng.try_fill_bytes(&mut csrf_token)
        .expect("get random bytes");

    let csrf_cookie = cookie::Cookie::build(("csrf_token", hex::encode(&csrf_token)))
        .secure(!app_state.session.insecure_http)
        .http_only(false)
        .same_site(SameSite::Strict)
        .build();

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("set-cookie", sess_cookie.to_string())
        .header("set-cookie", csrf_cookie.to_string())
        .body(Body::from(app_state.static_pages.login.clone()))?);
}

async fn proxy_authenticate(
    State(app_state): State<AppState>,
    HeaderHost(header_host): HeaderHost,
    jar: CookieJar,
) -> Result<Response, AppError> {
    let authorized_hosts = jar
        .get(&app_state.session.cookie_name)
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| token.claims.user)
        .and_then(|user| app_state.policy.users.get(&user))
        .and_then(|authenticated_user| {
            tracing::debug!(user = authenticated_user.name, header_host, "authenticated");
            app_state.policy.authorize(&authenticated_user.name)
        });

    if authorized_hosts.is_none() {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())?);
    }

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())?);
}

pub fn policy_test(user: &User, acls: &[AccessControlConfig]) -> Policy {
    let mut hosts = Vec::with_capacity(acls.len());
    for acl in acls.iter() {
        hosts.push(acl.host.clone());
    }

    let policy = Policy {
        users: rustc_hash::FxHashMap::from_iter([(user.name.clone(), user.clone())]),
        authorized_hosts: rustc_hash::FxHashMap::from_iter([(user.name.clone(), hosts)]),
    };
    return policy;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorize_policy() {
        let user = User {
            name: String::from("admin"),
            password_hash: String::new(),
        };

        let policy = policy_test(
            &user,
            &[AccessControlConfig {
                host: String::from("example.com"),
                allowed_users: vec![],
            }],
        );

        let hosts = policy.authorize(&user.name);
        assert_ne!(hosts, None);
        assert_eq!(hosts.unwrap(), &["example.com"]);

        assert_eq!(policy.authorize(&"not-admin".to_string()), None);
    }
}
