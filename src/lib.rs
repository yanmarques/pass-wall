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

pub const DEFAULT_KEYSIZE: usize = 32;
pub const DEFAULT_COOKIE_NAME: &str = "passwall_session";
pub const DEFAULT_PORT: u16 = 9000;
pub const MAX_PASSWORD_LENGTH: usize = 256;
pub const MAX_USER_LENGTH: usize = 256;
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

/// Allowed host
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Host {
    /// Original host value from the configuration.
    pub value: String,
    /// Domain used in the session cookie.
    pub base_domain: String,
    pub ndots: usize,
    pub include_subdomains: bool,
    pub include_siblings: bool,
    pub host_is_subdomain: bool,
}

impl Host {
    pub fn from(value: String, acl: &AccessControlConfig) -> Self {
        let domain = parse_host_domain(&value);

        Self {
            ndots: value.split(".").count(),
            value,
            base_domain: domain,
            include_subdomains: acl.include_subdomains,
            include_siblings: acl.include_siblings,
            host_is_subdomain: acl.host_is_subdomain,
        }
    }

    pub fn deduce_cookie_domain<H>(&self, host: H) -> anyhow::Result<Option<&String>>
    where
        H: AsRef<str> + PartialEq<String>,
    {
        if self.include_subdomains {
            return Ok(Some(&self.value));
        }

        if !self.host_is_subdomain && host != self.value {
            return Err(anyhow::anyhow!("invalid host domain"));
        }

        if self.host_is_subdomain && self.include_siblings {
            return Ok(Some(&self.base_domain));
        }

        if self.host_is_subdomain && !self.include_siblings && host != self.value {
            return Err(anyhow::anyhow!("invalid host subdomain"));
        }

        return Ok(None);
    }
}

/// Define who and what can be access and be accessed
#[derive(Clone, Debug)]
pub struct Policy {
    pub users: rustc_hash::FxHashMap<String, User>,
    pub authorized_hosts: rustc_hash::FxHashMap<String, rustc_hash::FxHashMap<String, Host>>,
}

impl Policy {
    /// Returns a [`Host`] if the given user is authorized to access the given host, according to the
    /// defined policy.
    ///
    /// Returns [`None`] otherwise.
    pub fn authorize<H>(&self, user: &String, header_host: H) -> Option<&Host>
    where
        H: AsRef<str>,
    {
        return self.authorized_hosts.get(user).and_then(|hosts| {
            if let Some(host) = hosts.get(header_host.as_ref()) {
                return Some(host);
            }

            // TODO: use caching and an efficient domain comparison algorithm
            let ndots = header_host.as_ref().split('.').count();
            let base_domain = parse_host_domain(header_host.as_ref());
            let subdomain = extract_subdomain(header_host);

            // 1. is subdomain:
            //  1. include subdomains? does header_host included in host
            //  2. include siblings? does header_host base domain included host base domain? (base
            //     domain parsing is currently lacking)
            // 2. is base domain:
            //  1. include subdomains? does header host included in host
            //  2. include siblings can't be true here
            for host in hosts.values() {
                if host.include_subdomains && subdomain == host.value && ndots == (host.ndots + 1) {
                    return Some(host);
                }

                if host.host_is_subdomain
                    && host.include_siblings
                    && base_domain == host.base_domain
                    && ndots == host.ndots
                {
                    return Some(host);
                }
            }

            return None;
        });
    }
}

/// User configuration to define who can access what hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    /// The host. It can be a subdomain or a base domain, and it may include a port. It must not include
    /// schemes (e.g.: https:// or http://).
    pub host: String,
    /// 1. if host is a base domain:
    ///     1. include_subdomains will set cookie Domain=example.com
    ///     2. otherwise, cookie domain is not set. if we receive user requests not from the
    ///        expected base domain, reject the request
    /// 2. if host is a subdomain:
    ///     1. if include_subdomains, will set cookie Domain=private.example.com
    ///     2. if include_siblings, will set cookie Domain=example.com
    ///     3. if not include_subdomains and not include_siblings, will not set cookie domain. if
    ///        we receive user requests not from expected subdomain, reject the request
    /// Whether to authorize users access to any subdomain in the host's domain, if a subdomain. Effectively, this
    /// controls which 'Domain' used in the session cookie. If false, the cookie 'Domain' attribute
    /// will match the host only, and not it's domain (if it is a subdomain).
    pub include_subdomains: bool,
    pub include_siblings: bool,
    pub host_is_subdomain: bool,
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
                return Err(anyhow::anyhow!(
                    "User password hash is invalid or malformed. Affected user: {}, password_hash: {}, err: {:?}",
                    user.name,
                    user.password_hash,
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

        let mut authorized_hosts =
            rustc_hash::FxHashMap::<String, rustc_hash::FxHashMap<String, Host>>::default();

        for access_control in &value.acl {
            if !access_control.host_is_subdomain && access_control.include_siblings {
                return Err(anyhow::anyhow!(
                    "Only subdomains can include siblings. For instance, one does not usually want to serve 'example.com' base domain and all other domains hosted on '.com' top level domain. Affected host '{}'",
                    access_control.host,
                ));
            }

            for user_name in &access_control.allowed_users {
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
                    hosts.insert(
                        access_control.host.clone(),
                        Host::from(access_control.host.clone(), &access_control),
                    );
                } else {
                    authorized_hosts.insert(
                        user.name.clone(),
                        rustc_hash::FxHashMap::from_iter([(
                            access_control.host.clone(),
                            Host::from(access_control.host.clone(), &access_control),
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

/// Get the subdomain part of the subdomain
/// TODO: use string views instead of string copies
pub(crate) fn extract_subdomain<H>(host: H) -> String
where
    H: AsRef<str>,
{
    let subs = host.as_ref().split(".").collect::<Vec<&str>>();
    if subs.len() < 2 {
        return String::from(host.as_ref());
    }

    let domain = String::from(&subs[1..].join("."));
    return domain;
}

/// Get the domain to use in the cookie from the Uri
/// TODO: use string views instead of string copies
pub(crate) fn parse_host_domain<H>(host: H) -> String
where
    H: AsRef<str>,
{
    let subs = host.as_ref().split(".").collect::<Vec<&str>>();
    if subs.len() < 2 {
        return String::from(host.as_ref());
    }

    let domain = String::from(&subs[subs.len() - 2..].join("."));
    return domain;
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

async fn signin(
    State(app_state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<LoginInput>,
) -> Result<Response, AppError> {
    if input.name.len() > MAX_USER_LENGTH || input.password.len() > MAX_PASSWORD_LENGTH {
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

    if let Some(user) = app_state.policy.users.get(&input.name) {
        if let Ok(uri) = Uri::try_from(&redirect) {
            let header_host = uri
                .host()
                .ok_or_else(|| anyhow::anyhow!("invalid redirect host"))?;
            if let Some(host) = app_state.policy.authorize(&user.name, header_host) {
                let parsed_hash = PasswordHash::new(&user.password_hash).map_err(|err| {
                    tracing::error!(?err, "failed to parse user's password hash");
                    return anyhow::anyhow!("failed to parse user's password");
                })?;

                let crypto_op =
                    Argon2::default().verify_password(input.password.as_bytes(), &parsed_hash);

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

                    let mut builder =
                        cookie::Cookie::build((&app_state.session.cookie_name, token))
                            .secure(!app_state.session.insecure_http)
                            .http_only(!app_state.session.disable_secure_http_only)
                            .same_site(app_state.session.same_site.to_cookie_samesite());

                    match host.deduce_cookie_domain(header_host) {
                        Ok(Some(domain)) => builder = builder.domain(domain),
                        Err(_) => {
                            tracing::warn!(
                                "detected a potentially misconfiguration in authorized hosts. this can happen if you disable 'include_subdomains' and 'include_siblings' for a host and users do not access the proxy server from the configured host's address. whenever this happens, the request is rejected with status 403. configured host address: {}, request header host: {}",
                                host.value,
                                header_host
                            );
                            return Ok(Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from(app_state.static_pages.unauthorized))?);
                        }
                        _ => {
                            // do not set cookie domain
                        }
                    };

                    return Ok(Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", redirect)
                        .header("set-cookie", builder.to_string())
                        .body(Body::empty())?);
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
        .and_then(|token| token.claims.user)
        .and_then(|user| app_state.policy.users.get(&user));

    if let Some(user) = authenticated_user {
        if let Some(_host) = app_state.policy.authorize(
            &user.name,
            redirect
                .host()
                .ok_or_else(|| anyhow::anyhow!("invalid redirect host"))?,
        ) {
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

    let cookie = cookie::Cookie::build((&app_state.session.cookie_name, token))
        .secure(!app_state.session.insecure_http)
        .http_only(!app_state.session.disable_secure_http_only)
        .same_site(app_state.session.same_site.to_cookie_samesite())
        .build();

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("set-cookie", cookie.to_string())
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
            app_state
                .policy
                .authorize(&authenticated_user.name, &header_host)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_domain_with_multi_level_subdomains() {
        let result = parse_host_domain("foo.public.example.com");
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_parse_host_domain_with_subdomain() {
        let result = parse_host_domain("public.example.com");
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_parse_host_domain_with_regular_domain() {
        let result = parse_host_domain("example.com");
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_parse_host_domain_with_localhost() {
        let result = parse_host_domain("localhost");
        assert_eq!(result, "localhost");
    }

    fn policy_test(user: &User, acls: &[AccessControlConfig]) -> Policy {
        let mut hosts = rustc_hash::FxHashMap::default();
        for acl in acls.iter() {
            hosts.insert(acl.host.clone(), Host::from(acl.host.clone(), &acl));
        }

        let policy = Policy {
            users: rustc_hash::FxHashMap::from_iter([(user.name.clone(), user.clone())]),
            authorized_hosts: rustc_hash::FxHashMap::from_iter([(user.name.clone(), hosts)]),
        };
        return policy;
    }

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
                host_is_subdomain: false,
                include_subdomains: false,
                include_siblings: false,
                allowed_users: vec![],
            }],
        );

        assert!(policy.authorize(&user.name, "example.com").is_some());
        assert!(policy.authorize(&user.name, "domain.com").is_none());
        assert!(policy.authorize(&user.name, "sub.example.com").is_none());
        assert!(policy.authorize(&user.name, "another.domain.com").is_none());
        assert!(
            policy
                .authorize(&user.name, "private.example.com")
                .is_none()
        );

        let policy = policy_test(
            &user,
            &[AccessControlConfig {
                host: String::from("example.com"),
                host_is_subdomain: false,
                include_subdomains: false,
                include_siblings: true,
                allowed_users: vec![],
            }],
        );

        assert!(policy.authorize(&user.name, "example.com").is_some());
        assert!(policy.authorize(&user.name, "domain.com").is_none());
        assert!(policy.authorize(&user.name, "sub.example.com").is_none());
        assert!(policy.authorize(&user.name, "another.domain.com").is_none());
        assert!(
            policy
                .authorize(&user.name, "private.example.com")
                .is_none()
        );

        let policy = policy_test(
            &user,
            &[AccessControlConfig {
                host: String::from("example.com"),
                host_is_subdomain: false,
                include_subdomains: true,
                include_siblings: true,
                allowed_users: vec![],
            }],
        );

        assert!(policy.authorize(&user.name, "example.com").is_some());
        assert!(policy.authorize(&user.name, "sub.example.com").is_some());
        assert!(
            policy
                .authorize(&user.name, "nested.sub.example.com")
                .is_none()
        );
        assert!(policy.authorize(&user.name, "domain.com").is_none());
        assert!(policy.authorize(&user.name, "another.domain.com").is_none());

        let policy = policy_test(
            &user,
            &[AccessControlConfig {
                host: String::from("sub.example.com"),
                host_is_subdomain: true,
                include_subdomains: true,
                include_siblings: true,
                allowed_users: vec![],
            }],
        );

        assert!(policy.authorize(&user.name, "sub.example.com").is_some());
        assert!(
            policy
                .authorize(&user.name, "nested.sub.example.com")
                .is_some()
        );
        assert!(
            policy
                .authorize(&user.name, "super.nested.sub.example.com")
                .is_none()
        );
        assert!(policy.authorize(&user.name, "other.example.com").is_some());
        assert!(policy.authorize(&user.name, "example.com").is_none());
        assert!(policy.authorize(&user.name, "domain.com").is_none());
        assert!(policy.authorize(&user.name, "another.domain.com").is_none());
        assert!(
            policy
                .authorize(&user.name, "nested.another.domain.com")
                .is_none()
        );

        let policy = policy_test(
            &user,
            &[AccessControlConfig {
                host: String::from("sub.example.com"),
                host_is_subdomain: true,
                include_subdomains: true,
                include_siblings: false,
                allowed_users: vec![],
            }],
        );

        assert!(policy.authorize(&user.name, "sub.example.com").is_some());
        assert!(
            policy
                .authorize(&user.name, "nested.sub.example.com")
                .is_some()
        );
        assert!(
            policy
                .authorize(&user.name, "super.nested.sub.example.com")
                .is_none()
        );
        assert!(policy.authorize(&user.name, "example.com").is_none());
        assert!(policy.authorize(&user.name, "other.example.com").is_none());
        assert!(policy.authorize(&user.name, "domain.com").is_none());
        assert!(policy.authorize(&user.name, "another.domain.com").is_none());
        assert!(
            policy
                .authorize(&user.name, "nested.another.domain.com")
                .is_none()
        );

        let policy = policy_test(
            &user,
            &[AccessControlConfig {
                host: String::from("sub.example.com"),
                host_is_subdomain: true,
                include_subdomains: false,
                include_siblings: false,
                allowed_users: vec![],
            }],
        );

        assert!(policy.authorize(&user.name, "sub.example.com").is_some());
        assert!(
            policy
                .authorize(&user.name, "nested.sub.example.com")
                .is_none()
        );
        assert!(
            policy
                .authorize(&user.name, "super.nested.sub.example.com")
                .is_none()
        );
        assert!(policy.authorize(&user.name, "example.com").is_none());
        assert!(policy.authorize(&user.name, "other.example.com").is_none());
        assert!(policy.authorize(&user.name, "domain.com").is_none());
        assert!(policy.authorize(&user.name, "another.domain.com").is_none());
        assert!(
            policy
                .authorize(&user.name, "nested.another.domain.com")
                .is_none()
        );
    }
}
