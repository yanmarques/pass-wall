use std::{
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axum::{
    Form, Router,
    body::Body,
    extract::{Query, State},
    http::Uri,
    response::{IntoResponse, Response},
};
use axum_extra::extract::{CookieJar, Host as HeaderHost};
use bytes::Bytes;
use clap::Parser;
use hyper::StatusCode;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, errors::ErrorKind,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

extern crate bcrypt;

/// JWT claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    redirect: Option<String>,
    user: Option<String>,
    exp: u64,
}

/// Allowed user
#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize)]
struct User {
    name: String,
    // bcrypt
    password_hash: String,
}

/// Allowed host
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct Host {
    value: String,
    domain: String,
}

impl From<String> for Host {
    fn from(value: String) -> Self {
        let domain = parse_host_domain(&value);
        Self { value, domain }
    }
}

/// Define who and what can be access and be accessed
#[derive(Clone, Debug)]
struct Policy {
    users: rustc_hash::FxHashMap<String, User>,
    authorized_hosts: rustc_hash::FxHashMap<User, rustc_hash::FxHashMap<String, Host>>,
}

impl Policy {
    /// Returns a [`Host`] if the given user is authorized to access the given host, according to the
    /// defined policy.
    ///
    /// Returns [`None`] otherwise.
    pub fn authorize<H>(&self, user: &User, host: H) -> Option<&Host>
    where
        H: AsRef<str>,
    {
        return self
            .authorized_hosts
            .get(user)
            .and_then(|hosts| hosts.get(host.as_ref()));
    }
}

/// All static pages
#[derive(Clone)]
struct StaticPages {
    login: Bytes,
    unauthenticated: Bytes,
    unauthorized: Bytes,
}

/// Some shared data
#[derive(Clone)]
struct AppState {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    static_pages: StaticPages,
    policy: Policy,
    session_cookie_name: String,
    session_expiration: u64,
}

/// Login form input
#[derive(Deserialize, Debug)]
struct LoginInput {
    name: String,
    password: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AccessControlConfig {
    host: String,
    allowed_users: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    app_bind: String,
    app_key: String,
    users: Vec<User>,
    acl: Vec<AccessControlConfig>,
    session_cookie_name: String,
    session_expiration_secs: u64,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "passwall.yaml")]
    config: String,
}

#[derive(Deserialize, Debug)]
struct SigninQuery {
    redirect: Option<String>,
}

/// Local app error
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!(error = ?self.0, "request handling error");

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

impl Claims {
    fn new(user: Option<String>, redirect: Option<String>, expire_in: u64) -> Self {
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
            users.insert(
                user.name.clone(),
                User {
                    name: user.name.clone(),
                    password_hash: user.password_hash.clone(),
                },
            );
        }

        let mut authorized_hosts =
            rustc_hash::FxHashMap::<User, rustc_hash::FxHashMap<String, Host>>::default();

        for access_control in &value.acl {
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

                if let Some(hosts) = authorized_hosts.get_mut(&user) {
                    hosts.insert(
                        access_control.host.clone(),
                        Host::from(access_control.host.clone()),
                    );
                } else {
                    authorized_hosts.insert(
                        user.clone(),
                        rustc_hash::FxHashMap::from_iter([(
                            access_control.host.clone(),
                            Host::from(access_control.host.clone()),
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

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .event_format(
            tracing_subscriber::fmt::format()
                .with_line_number(true)
                .compact(),
        )
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let app_config: Config = serde_yaml_ng::from_slice(
        &fs::read(args.config.clone()).context(format!("open config file: {}", args.config))?,
    )
    .context(format!("parse yaml config: {}", args.config))?;

    let static_pages = StaticPages {
        login: Bytes::from_owner(
            fs::read("./static/login.html").context("open html ./static/login.html")?,
        ),
        unauthenticated: Bytes::from_owner(
            fs::read("./static/unauthenticated.html")
                .context("open html ./static/unauthenticated.html")?,
        ),
        unauthorized: Bytes::from_owner(
            fs::read("./static/unauthorized.html")
                .context("open html ./static/unauthorized.html")?,
        ),
    };

    let policy = Policy::try_from(app_config.clone())?;

    // TODO: mask password hashes
    tracing::debug!(?policy, "runtime policy");

    let app_key_bytes = app_config.app_key.into_bytes();

    let app = Router::new()
        .route("/", axum::routing::get(show_signin))
        .route("/signin", axum::routing::post(signin))
        .route("/authenticate", axum::routing::get(proxy_authenticate))
        .with_state(AppState {
            policy,
            static_pages,
            encoding_key: EncodingKey::from_secret(&app_key_bytes),
            decoding_key: DecodingKey::from_secret(&app_key_bytes),
            session_cookie_name: app_config.session_cookie_name.clone(),
            session_expiration: app_config.session_expiration_secs,
        });

    let listener = tokio::net::TcpListener::bind(app_config.app_bind.clone())
        .await
        .context(format!("start listener on addr: {}", app_config.app_bind))?;
    tracing::info!("starting listener");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix;

    let term = async {
        unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("unable to install unix TERM signal handler")
            .recv()
            .await
    };

    let int = async {
        unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("unable to install unix INT signal handler")
            .recv()
            .await
    };

    let mut which_signal = "SIGTERM";
    tokio::select! {
        _ = int => {
            which_signal = "SIGINT";
        }
        _ = term => {},
    };

    info!("received signal {which_signal}, exiting");
}

/// Get the domain to use in the cookie from the Uri
fn parse_host_domain(host: &str) -> String {
    let subs = host.split(".").collect::<Vec<&str>>();
    if subs.len() < 2 {
        return String::from(host);
    }

    let mut domain = String::from(&subs[subs.len() - 2..].join("."));
    domain.insert(0, '.');
    return domain;
}

/// Return whether the given token is a valid JWT token for the key
fn validate_token(token: &str, key: &DecodingKey) -> Option<TokenData<Claims>> {
    let validation = Validation::new(Algorithm::HS256);
    match jsonwebtoken::decode::<Claims>(token, key, &validation) {
        Ok(data) => Some(data),
        Err(err) => {
            error!(?err, "token is invalid");
            match *err.kind() {
                ErrorKind::InvalidToken => error!("Token is invalid"),
                ErrorKind::InvalidIssuer => error!("Issuer is invalid"),
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
    let redirect = match jar
        .get(&app_state.session_cookie_name)
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
            if let Some(host) = app_state.policy.authorize(
                &user,
                uri.host()
                    .ok_or_else(|| anyhow::anyhow!("invalid redirect host"))?,
            ) {
                let valid = bcrypt::verify(input.password, &user.password_hash)?;
                if valid {
                    let claims =
                        Claims::new(Some(user.name.clone()), None, app_state.session_expiration);

                    let token = jsonwebtoken::encode(
                        &Header::new(Algorithm::HS256),
                        &claims,
                        &app_state.encoding_key,
                    )?;

                    let cookie = cookie::Cookie::build((&app_state.session_cookie_name, token))
                        .http_only(true)
                        .domain(&host.domain)
                        .same_site(cookie::SameSite::Strict)
                        .build();

                    return Ok(Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", redirect)
                        .header("set-cookie", cookie.to_string())
                        .body(Body::empty())?);
                }
            }
        }
    }

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header("location", "/")
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
        .get(&app_state.session_cookie_name)
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| token.claims.user)
        .and_then(|user| app_state.policy.users.get(&user));

    if let Some(user) = authenticated_user {
        if let Some(_host) = app_state.policy.authorize(
            &user,
            redirect
                .host()
                .ok_or_else(|| anyhow::anyhow!("invalid redirect host"))?,
        ) {
            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header("location", redirect.to_string())
                .body(Body::empty())?);
        }

        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from(app_state.static_pages.unauthorized))?);
    }

    let claims = Claims::new(
        None,
        Some(redirect.to_string()),
        app_state.session_expiration,
    );
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &app_state.encoding_key,
    )?;

    let cookie = cookie::Cookie::build((&app_state.session_cookie_name, token))
        .http_only(true)
        .same_site(cookie::SameSite::Strict);

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
        .get(&app_state.session_cookie_name)
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| token.claims.user)
        .and_then(|user| app_state.policy.users.get(&user))
        .and_then(|authenticated_user| {
            tracing::debug!(user = authenticated_user.name, header_host, "authenticated");
            app_state
                .policy
                .authorize(&authenticated_user, &header_host)
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
    fn test_parse_host_domain_with_subdomain() {
        let result = parse_host_domain("public.example.com");
        assert_eq!(result, ".example.com");
    }

    #[test]
    fn test_parse_host_domain_with_regular_domain() {
        let result = parse_host_domain("example.com");
        assert_eq!(result, ".example.com");
    }

    #[test]
    fn test_parse_host_domain_with_localhost() {
        let result = parse_host_domain("localhost");
        assert_eq!(result, "localhost");
    }
}
