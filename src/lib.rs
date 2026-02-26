use std::{
    fmt::Debug,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use argon2::PasswordVerifier;
use axum::{
    Form, Router,
    body::Body,
    extract::{Query, State},
    http::{self, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use bytes::Bytes;
use jsonwebtoken as jwt;
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

// Mimic a password verification
pub const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$EIEQWL9mT6fnuqIaN2qblA$cM+GsXMCdV0R2j8j45OZyyoBFAupCIsHIsofoE71Wu8";

// Internals
pub const CSRF_TOKEN_COOKIE_NAME: &str = "passwall_csrf_token";
pub const HTML_CTYPE: &str = "text/html; charset=utf-8";
pub const X_ORIGINAL_URL: &str = "x-original-url";

// Config
pub const DEFAULT_KEYSIZE: usize = 32;
pub const DEFAULT_PREAUTH_COOKIE_NAME: &str = "passwall_preauth_session";
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "passwall_session";
pub const DEFAULT_PORT: u16 = 9000;

// Input validation
pub const MAX_PASSWORD_LENGTH: usize = 256;
pub const MAX_USER_LENGTH: usize = 256;
pub const MAX_CSRF_TOKEN_LENGTH: usize = 32;

type PolicyAuthHosts =
    rustc_hash::FxHashMap<String, rustc_hash::FxHashMap<(String, u16), DomainAcl>>;

/// JWT claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub redirect: Option<String>,
    pub user: Option<String>,
    pub csrf_token: Option<String>,
    pub exp: u64,
}

/// Allowed user
#[derive(Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
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

/// Define who and what can access and be accessed.
#[derive(Clone, Debug)]
pub struct Policy {
    pub users: rustc_hash::FxHashMap<String, User>,
    pub authorized_hosts: PolicyAuthHosts,
}

impl Policy {
    /// Returns the first ACL configuration for the user.
    ///
    /// Returns [`None`] otherwise.
    pub fn homepage(&self, user: &str) -> Option<&DomainAcl> {
        return self
            .authorized_hosts
            .get(user)
            .and_then(|hosts| hosts.iter().next())
            .and_then(|(_, acl)| Some(acl));
    }

    /// Returns the ACL configuration for the given host, if the policy allows the user to access
    /// the host.
    ///
    /// Returns [`None`] otherwise.
    pub fn authorize(&self, user: &str, host: &str, port: u16) -> Option<&DomainAcl> {
        // TODO: avoid allocations in [`host.to_string()`]
        return self
            .authorized_hosts
            .get(user)
            .and_then(|hosts| hosts.get(&(host.to_string(), port)));
    }
}

/// User configuration to define who can access what hosts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainAclConfig {
    /// The host. It can be a subdomain or a base domain.
    /// It should not include schemes (e.g.: https:// or http://).
    pub domain: String,
    pub port: u16,
    /// All users authorized to access the host.
    pub allowed_users: Vec<String>,
    /// Override session options.
    pub cookie: HostCookieConfig,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DomainAcl {
    pub uri: String,
    pub cookie: HostCookieConfig,
    pub domain: String,
    pub port: u16,
}

impl DomainAcl {
    pub fn new(
        domain_config: DomainAclConfig,
        server_config: &ServerConfig,
    ) -> anyhow::Result<Self> {
        let uri = Uri::builder()
            .scheme(if server_config.scheme_https {
                "https"
            } else {
                "http"
            })
            .authority(format!("{}:{}", domain_config.domain, domain_config.port))
            .path_and_query("/")
            .build()?;

        Ok(Self {
            uri: uri.to_string(),
            domain: domain_config.domain,
            port: domain_config.port,
            cookie: domain_config.cookie,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SimpleSameSite {
    #[allow(non_camel_case_types)]
    strict,
    #[allow(non_camel_case_types)]
    lax,
    #[allow(non_camel_case_types)]
    none,
}

impl SimpleSameSite {
    pub fn to_cookie_samesite(&self) -> cookie::SameSite {
        match self {
            Self::strict => cookie::SameSite::Strict,
            Self::lax => cookie::SameSite::Lax,
            Self::none => cookie::SameSite::None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostCookieConfig {
    /// Controls the 'SameSite' cookie attribute. Choices are 'strict', 'lax', or 'none'. Default
    /// is 'strict'.
    pub same_site: SimpleSameSite,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// The cookie name. Default is 'passwall_session'.
    pub cookie_name: String,
    /// Define the maximum lifetime of the session tokens in seconds. Default is 1 hour.
    pub expiration_secs: u64,
}

impl SessionConfig {
    pub fn default() -> Self {
        Self {
            cookie_name: String::from(DEFAULT_SESSION_COOKIE_NAME),
            expiration_secs: 60 * 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server listener address in the following format: <HOST>:<PORT>. Default is 0.0.0.0:9000
    pub bind: String,
    /// A cryptographically secure key used to encrypt Json Web Tokens.
    /// Use the default generated config unless you know what you are doing.
    /// The default key generates 256 bits of entropy for the HMAC-SHA256 algorithm used in JWTs.
    pub key: String,
    /// Whether the reverse proxy uses HTTPS.
    pub scheme_https: bool,
    /// Session configuration.
    pub session: SessionConfig,
    /// The URL to redirect the authentication server can not figure out the URL the anonymous user
    /// aims to arrive. This usually happens when the user manually type the authentication URL,
    /// in which case, the server needs information of where to fall back.
    pub fallback_url: String,
    pub url_prefix: Option<String>,
}

impl ServerConfig {
    pub fn url_prefix(&self) -> &str {
        if let Some(url) = self.url_prefix.as_ref() {
            return url;
        }

        return "/";
    }

    /// Controls the 'HttpOnly' cookie attribute. When true, allows JavaScript code in the page to
    /// access the cookie through `document.cookie`. Default is false.
    pub fn http_only_cookie(&self) -> bool {
        return self.scheme_https;
    }

    /// Controls the 'Secure' cookie attribute. When true, allows the cookie to be sent by browers
    /// over unencrypted http requests. Default is false.
    pub fn secure_cookie(&self) -> bool {
        return self.scheme_https;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server specific configuration.
    pub server: ServerConfig,
    /// Allowed users.
    pub users: Vec<User>,
    /// Access control per host and user.
    pub acl: Vec<DomainAclConfig>,
}

/// HTML application pages.
#[derive(Clone)]
pub struct StaticPages {
    pub login: Bytes,
    /// Consistent with HTTP status 401, even though I'd prefer to call it "unauthenticated"
    pub unauthorized: Bytes,
    /// Consistent with HTTP status 403
    pub forbidden: Bytes,
}

/// Some shared data
#[derive(Clone)]
pub struct AppState {
    /// Secret key to generate tokens.
    pub encoding_key: jwt::EncodingKey,
    /// Secret key to decode tokens.
    pub decoding_key: jwt::DecodingKey,
    pub static_pages: StaticPages,
    pub policy: Policy,
    pub server_cfg: ServerConfig,
    /// During sign in, it performs password verification regardless of whether
    /// the given user exists or not. This is the hash used for the verification.
    pub dummy_passwd_hash: argon2::PasswordHash<'static>,
}

impl AppState {
    pub fn default_port(&self) -> u16 {
        if self.server_cfg.scheme_https {
            return 443;
        }

        return 80;
    }
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
            server: ServerConfig {
                bind: format!("0.0.0.0:{DEFAULT_PORT}"),
                key: key,
                session: SessionConfig::default(),
                scheme_https: true,
                fallback_url: String::new(),
                url_prefix: None,
            },
            users: vec![],
            acl: vec![],
        }
    }
}

impl Claims {
    pub fn new(
        user: Option<String>,
        redirect: Option<String>,
        csrf_token: Option<String>,
        expire_in: u64,
    ) -> Self {
        let expiration = SystemTime::now() + Duration::from_secs(expire_in);

        Claims {
            redirect,
            user,
            csrf_token,
            exp: expiration
                .duration_since(UNIX_EPOCH)
                .expect("can not get current timestamp")
                .as_secs(),
        }
    }

    pub fn redirect_and_csrf_token(&self) -> Option<(&String, &String)> {
        self.redirect.as_ref().and_then(|redirect| {
            self.csrf_token
                .as_ref()
                .map(|csrf_token| (redirect, csrf_token))
        })
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

            if let Err(err) = argon2::PasswordHash::new(&user.password_hash) {
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

        let mut authorized_hosts = PolicyAuthHosts::default();

        for access_control in &value.acl {
            if access_control.domain.is_empty() {
                return Err(anyhow::anyhow!("ACL configuration contains an empty host"));
            }

            if let Some(domain) = &access_control.cookie.domain {
                if !access_control.domain.ends_with(domain) {
                    return Err(anyhow::anyhow!(
                        "Specified domain '{}' must be a subdomain of '{}'. ",
                        access_control.domain,
                        domain
                    ));
                }
            }

            for user_name in &access_control.allowed_users {
                if user_name.is_empty() {
                    return Err(anyhow::anyhow!(
                        "The domain '{}' configuration contains an empty allowed username",
                        access_control.domain,
                    ));
                }

                let user = match users.get(user_name) {
                    Some(u) => u,
                    None => {
                        return Err(anyhow::anyhow!(
                            "The domain '{}' configuration specifies an inexistent user called '{}'",
                            access_control.domain,
                            user_name
                        ));
                    }
                };

                if let Some(hosts) = authorized_hosts.get_mut(&user.name) {
                    hosts.insert(
                        (access_control.domain.clone(), access_control.port),
                        DomainAcl::new(access_control.clone(), &value.server)?,
                    );
                } else {
                    authorized_hosts.insert(
                        user.name.clone(),
                        rustc_hash::FxHashMap::from_iter([(
                            (access_control.domain.clone(), access_control.port),
                            DomainAcl::new(access_control.clone(), &value.server)?,
                        )]),
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
        unauthorized: Bytes::from_owner(include_bytes!("./../static/unauthorized.html")),
        forbidden: Bytes::from_owner(include_bytes!("./../static/forbidden.html")),
    };

    let policy = Policy::try_from(config.clone())?;
    tracing::debug!(?policy, "runtime policy");

    let app_key_bytes = config.server.key.as_bytes();

    let dummy_passwd_hash =
        argon2::PasswordHash::new(DUMMY_PASSWORD_HASH).expect("failed to parse dummy's password");

    let mut app = Router::new()
        .route("/", axum::routing::get(show_signin))
        .route("/homepage", axum::routing::get(homepage))
        .route("/signout", axum::routing::post(signout))
        .route("/signin", axum::routing::post(signin))
        .route("/authenticate", axum::routing::get(proxy_authenticate))
        .route("/healthz", axum::routing::get(show_health))
        .route("/readyz", axum::routing::get(show_health))
        .with_state(AppState {
            policy,
            static_pages,
            server_cfg: config.server.clone(),
            encoding_key: jwt::EncodingKey::from_secret(&app_key_bytes),
            decoding_key: jwt::DecodingKey::from_secret(&app_key_bytes),
            dummy_passwd_hash,
        });

    if let Some(url_prefix) = config.server.url_prefix.as_ref() {
        app = Router::new().nest(url_prefix, app);
    }

    return Ok(app);
}

/// Return whether the given token is a valid JWT token for the key
fn validate_token(token: &str, key: &jwt::DecodingKey) -> Option<jwt::TokenData<Claims>> {
    let validation = jwt::Validation::new(jwt::Algorithm::HS256);
    match jwt::decode::<Claims>(token, key, &validation) {
        Ok(data) => Some(data),
        Err(err) => {
            tracing::error!(?err, "token is invalid");
            match *err.kind() {
                jwt::errors::ErrorKind::InvalidToken => tracing::error!("Token is invalid"),
                jwt::errors::ErrorKind::InvalidIssuer => tracing::error!("Issuer is invalid"),
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

async fn homepage(State(app_state): State<AppState>, jar: CookieJar) -> Result<Response, AppError> {
    let jwt_claims = match jar
        .get(&app_state.server_cfg.session.cookie_name)
        .as_ref()
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| Some(token.claims))
    {
        Some(j) => j,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(http::header::LOCATION, app_state.server_cfg.fallback_url)
                .body(Body::empty())?);
        }
    };

    let url = jwt_claims
        .user
        .and_then(|user| app_state.policy.homepage(&user))
        .and_then(|acl| Some(&acl.uri))
        .unwrap_or(&app_state.server_cfg.fallback_url);

    return Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(http::header::LOCATION, url)
        .body(Body::empty())?);
}

async fn signout(
    State(app_state): State<AppState>,
    Query(signin_query): Query<SigninQuery>,
    jar: CookieJar,
) -> Result<Response, AppError> {
    let cookie = match jar.get(&app_state.server_cfg.session.cookie_name) {
        Some(c) => c,
        None => {
            let location = if let Some(redirect_url) = signin_query.redirect {
                // TODO: urlencode
                &format!(
                    "{}?redirect={}",
                    &app_state.server_cfg.url_prefix(),
                    redirect_url
                )
            } else {
                app_state.server_cfg.url_prefix()
            };

            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(http::header::LOCATION, location)
                .body(Body::empty())?);
        }
    };

    let jwt_claims = match validate_token(cookie.value(), &app_state.decoding_key)
        .and_then(|token| Some(token.claims))
    {
        Some(j) => j,
        None => {
            let location = if let Some(redirect_url) = signin_query.redirect {
                // TODO: urlencode
                &format!(
                    "{}?redirect={}",
                    &app_state.server_cfg.url_prefix(),
                    redirect_url
                )
            } else {
                app_state.server_cfg.url_prefix()
            };

            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(http::header::LOCATION, location)
                .body(Body::empty())?);
        }
    };

    let user = match jwt_claims.user.as_ref() {
        Some(u) => u,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::empty())?);
        }
    };

    let redirect_url = signin_query.redirect.as_ref().or_else(|| {
        jwt_claims.redirect.as_ref().or_else(|| {
            app_state
                .policy
                .homepage(&user)
                .and_then(|acl| Some(&acl.uri))
        })
    });

    let location = if let Some(url) = redirect_url {
        // TODO: urlencode
        &format!("{}?redirect={}", &app_state.server_cfg.url_prefix(), url)
    } else {
        app_state.server_cfg.url_prefix()
    };

    let set_cookie = cookie::Cookie::build((&app_state.server_cfg.session.cookie_name, ""))
        .secure(app_state.server_cfg.secure_cookie())
        .http_only(app_state.server_cfg.http_only_cookie())
        .domain(cookie.domain().unwrap_or(""))
        .path("/");

    let response = Response::builder()
        .status(StatusCode::FOUND)
        .header(http::header::LOCATION, location)
        .header(http::header::SET_COOKIE, set_cookie.to_string())
        .body(Body::empty())?;

    return Ok(response);
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
        tracing::warn!(
            name_length = input.name.len(),
            password_length = input.password.len(),
            csrf_token_length = input.csrf_token.len(),
            "received a signin form that is too large"
        );
        return Ok(Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header(http::header::CONTENT_TYPE, HTML_CTYPE)
            .body(Body::empty())?);
    }

    let preauth_cookie = match jar.get(DEFAULT_PREAUTH_COOKIE_NAME) {
        Some(c) => c,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(http::header::LOCATION, app_state.server_cfg.fallback_url)
                .body(Body::empty())?);
        }
    };

    let jwt_claims = match validate_token(preauth_cookie.value(), &app_state.decoding_key)
        .and_then(|preauth_token| Some(preauth_token.claims))
    {
        Some(j) => j,
        None => {
            let set_cookie = cookie::Cookie::build((DEFAULT_PREAUTH_COOKIE_NAME, ""))
                .secure(app_state.server_cfg.secure_cookie())
                .http_only(app_state.server_cfg.http_only_cookie())
                .domain(preauth_cookie.domain().unwrap_or(""))
                .path("/");

            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(http::header::LOCATION, app_state.server_cfg.fallback_url)
                .header(http::header::SET_COOKIE, set_cookie.to_string())
                .body(Body::empty())?);
        }
    };

    let (redirect_url, csrf_token) = match jwt_claims.redirect_and_csrf_token() {
        Some(a) => a,
        None => {
            tracing::warn!("missing client JWT parameters");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(http::header::CONTENT_TYPE, HTML_CTYPE)
                .body(Body::empty())?);
        }
    };

    let csrf_from_cookie = csrf_token.as_bytes();
    let csrf_from_form = input.csrf_token.as_bytes();

    if csrf_from_cookie.ct_eq(csrf_from_form).unwrap_u8() != 1 {
        tracing::warn!("CSRF failed");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(http::header::CONTENT_TYPE, HTML_CTYPE)
            .body(Body::empty())?);
    }

    if let Some(user) = app_state.policy.users.get(&input.name) {
        let password_hash = user.password_hash.clone();

        let authed = tokio::task::spawn_blocking(move || {
            // TODO: perf: pre-compute this PasswordHash
            let parsed_hash = argon2::PasswordHash::new(&password_hash).map_err(|err| {
                tracing::error!(?err, "failed to parse user's password hash");
                return anyhow::anyhow!("failed to parse user's password");
            })?;

            argon2::Argon2::default()
                .verify_password(input.password.as_bytes(), &parsed_hash)
                .map_err(|err| {
                    tracing::error!(?err, "failed to verify user password");
                    return anyhow::anyhow!("failed to verify user password");
                })
        })
        .await?;

        if let Err(err) = authed {
            tracing::warn!(?err, "auth unsuccessful");
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(http::header::CONTENT_TYPE, HTML_CTYPE)
                .body(Body::from(app_state.static_pages.unauthorized.clone()))?);
        }

        let redirect_uri = match Uri::try_from(redirect_url) {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    ?redirect_url,
                    "invalid redirect url inside the jwt, aborting"
                );

                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(http::header::CONTENT_TYPE, HTML_CTYPE)
                    .body(Body::empty())?);
            }
        };

        let host = redirect_uri.host().unwrap_or("");
        let port = redirect_uri.port_u16().unwrap_or(app_state.default_port());
        if let Some(acl_config) = app_state.policy.authorize(&user.name, host, port) {
            let claims = Claims::new(
                Some(user.name.clone()),
                None,
                None,
                app_state.server_cfg.session.expiration_secs,
            );

            let token = jwt::encode(
                &jwt::Header::new(jwt::Algorithm::HS256),
                &claims,
                &app_state.encoding_key,
            )?;

            let mut set_cookie =
                cookie::Cookie::build((&app_state.server_cfg.session.cookie_name, &token))
                    .secure(app_state.server_cfg.secure_cookie())
                    .http_only(app_state.server_cfg.http_only_cookie())
                    .path("/")
                    .same_site(acl_config.cookie.same_site.to_cookie_samesite());

            if let Some(domain) = &acl_config.cookie.domain {
                set_cookie = set_cookie.domain(domain);
            }

            let response = Response::builder()
                .status(StatusCode::FOUND)
                .header(http::header::LOCATION, redirect_url)
                .header(http::header::SET_COOKIE, set_cookie.to_string())
                .body(Body::empty())?;

            return Ok(response);
        }

        tracing::warn!(user = user.name, "unauthorized user");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(http::header::CONTENT_TYPE, HTML_CTYPE)
            .body(Body::from(app_state.static_pages.forbidden))?);
    }

    // resist user enumeration through timing attacks
    let _ = tokio::task::spawn_blocking(move || {
        let _ = argon2::Argon2::default()
            .verify_password(input.password.as_bytes(), &app_state.dummy_passwd_hash);
    })
    .await
    .inspect_err(|err| {
        tracing::warn!(?err, "checking dummy password");
    });

    tracing::warn!(user = input.name, "unknown user");
    return Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(http::header::CONTENT_TYPE, HTML_CTYPE)
        .body(Body::from(app_state.static_pages.unauthorized.clone()))?);
}

async fn show_signin(
    State(app_state): State<AppState>,
    Query(signin_query): Query<SigninQuery>,
    jar: CookieJar,
) -> Result<Response, AppError> {
    let redirect_url = match signin_query.redirect {
        Some(r) => r,
        None => {
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(http::header::LOCATION, &app_state.server_cfg.fallback_url)
                .body(Body::empty())?);
        }
    };

    let redirect_uri = match Uri::try_from(&redirect_url) {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(?err, ?redirect_url, "failed to parse url");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(http::header::CONTENT_TYPE, HTML_CTYPE)
                .body(Body::empty())?);
        }
    };

    let authenticated_user = jar
        .get(&app_state.server_cfg.session.cookie_name)
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| token.claims.user);

    if let Some(user) = authenticated_user {
        let host = redirect_uri.host().unwrap_or("");
        let port = redirect_uri.port_u16().unwrap_or(app_state.default_port());
        if let Some(_acl_config) = app_state.policy.authorize(&user, host, port) {
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header(http::header::LOCATION, &redirect_url)
                .body(Body::empty())?);
        }

        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(http::header::CONTENT_TYPE, HTML_CTYPE)
            .body(Body::from(app_state.static_pages.forbidden.clone()))?);
    }

    let preauth_claims = jar
        .get(DEFAULT_PREAUTH_COOKIE_NAME)
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| Some(token.claims));

    let has_redirect_changed = preauth_claims.as_ref().and_then(|c| {
        if c.redirect.as_ref() == Some(&redirect_url) {
            Some(false)
        } else {
            Some(true)
        }
    });

    if preauth_claims.is_some() && has_redirect_changed == Some(false) {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, HTML_CTYPE)
            .body(Body::from(app_state.static_pages.login.clone()))?);
    }

    let mut rng = rand::rngs::OsRng;
    let mut csrf_token_bytes = [0u8; 16];
    rng.try_fill_bytes(&mut csrf_token_bytes)
        .expect("get random bytes");
    let csrf_token = hex::encode(&csrf_token_bytes);

    let claims = Claims::new(
        None,
        Some(redirect_url),
        Some(csrf_token.clone()),
        app_state.server_cfg.session.expiration_secs,
    );
    let token = jwt::encode(
        &jwt::Header::new(jwt::Algorithm::HS256),
        &claims,
        &app_state.encoding_key,
    )?;

    let sess_cookie = cookie::Cookie::build((DEFAULT_PREAUTH_COOKIE_NAME, token))
        .secure(app_state.server_cfg.secure_cookie())
        .http_only(app_state.server_cfg.http_only_cookie())
        .same_site(cookie::SameSite::Strict)
        .path("/")
        .build();

    let csrf_cookie = cookie::Cookie::build((CSRF_TOKEN_COOKIE_NAME, &csrf_token))
        .secure(app_state.server_cfg.secure_cookie())
        .http_only(false)
        .same_site(cookie::SameSite::Strict)
        .path("/")
        .build();

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, HTML_CTYPE)
        .header(http::header::SET_COOKIE, sess_cookie.to_string())
        .header(http::header::SET_COOKIE, csrf_cookie.to_string())
        .body(Body::from(app_state.static_pages.login.clone()))?);
}

async fn proxy_authenticate(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, AppError> {
    let original_url = headers
        .get(X_ORIGINAL_URL)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    let redirect_uri = match Uri::try_from(original_url) {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(?err, ?original_url, "failed to parse url");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(http::header::CONTENT_TYPE, HTML_CTYPE)
                .body(Body::empty())?);
        }
    };
    let authorized_hosts = jar
        .get(&app_state.server_cfg.session.cookie_name)
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| token.claims.user)
        .and_then(|user| app_state.policy.users.get(&user))
        .and_then(|authenticated_user| {
            let host = redirect_uri.host().unwrap_or("");
            let port = redirect_uri.port_u16().unwrap_or(app_state.default_port());
            tracing::debug!(user = authenticated_user.name, host, "authenticated");
            app_state
                .policy
                .authorize(&authenticated_user.name, host, port)
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

pub fn policy_test(config: Config, user: &User, acls: &[DomainAclConfig]) -> Policy {
    let mut hosts = rustc_hash::FxHashMap::<(String, u16), DomainAcl>::default();
    for acl in acls {
        hosts.insert(
            (acl.domain.clone(), acl.port),
            DomainAcl::new(acl.clone(), &config.server).expect("create domain acl"),
        );
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
            Config::default(),
            &user,
            &[DomainAclConfig {
                domain: String::from("example.com"),
                port: 8443,
                allowed_users: vec![],
                cookie: HostCookieConfig {
                    same_site: SimpleSameSite::strict,
                    domain: None,
                },
            }],
        );

        let hosts = policy.authorize(&user.name, "example.com", 8443);
        assert_ne!(hosts, None);
        assert_eq!(hosts.unwrap().domain, "example.com");
        assert_eq!(hosts.unwrap().cookie.same_site, SimpleSameSite::strict);

        assert_eq!(
            policy.authorize(&"not-admin".to_string(), "example.com", 8443),
            None
        );
    }
}
