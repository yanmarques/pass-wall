use std::{
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Form, Router,
    body::Body,
    extract::{Query, State},
    http::Uri,
    response::{IntoResponse, Response},
};
use axum_extra::extract::{CookieJar, Host};
use bytes::Bytes;
use clap::Parser;
use hyper::StatusCode;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, errors::ErrorKind,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};
use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};

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

/// Define who and what can be access and be accessed
#[derive(Clone, Debug)]
struct Policy {
    users: rustc_hash::FxHashMap<String, User>,
    authorized_hosts: rustc_hash::FxHashMap<User, Vec<String>>,
}

/// All static pages
#[derive(Clone)]
struct StaticPages {
    login: Bytes,
    login_failed: Bytes,
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

        let mut authorized_hosts = rustc_hash::FxHashMap::<User, Vec<String>>::default();

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
                    hosts.push(access_control.host.clone());
                } else {
                    authorized_hosts
                        .insert(user.clone(), Vec::from_iter([access_control.host.clone()]));
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
    tracing_subscriber::fmt::Subscriber::builder()
        .with_line_number(true)
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init()?;

    let args = Args::parse();
    let app_config: Config = serde_yaml_ng::from_slice(&fs::read(args.config)?)?;

    let static_pages = StaticPages {
        login: Bytes::from_owner(fs::read("./static/login.html")?),
        login_failed: Bytes::from_owner(fs::read("./static/login_failed.html")?),
        unauthorized: Bytes::from_owner(fs::read("./static/unauthorized.html")?),
    };

    let policy = Policy::try_from(app_config.clone())?;

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

    let listener = tokio::net::TcpListener::bind(app_config.app_bind).await?;
    info!("starting listener");
    axum::serve(listener, app).await?;

    Ok(())
}

/// Get the domain to use in the cookie from the Uri
fn get_cookie_domain(host: &str) -> String {
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
        let valid = bcrypt::verify(input.password, &user.password_hash)?;

        if valid {
            let authorized_hosts = app_state
                .policy
                .authorized_hosts
                .get(&user)
                .expect("bug? could not find allowed hosts for a valid user");

            let uri = Uri::try_from(&redirect)?;
            let host = uri
                .host()
                .ok_or_else(|| anyhow::anyhow!("invalid redirect"))?;

            if !authorized_hosts.contains(&String::from(host)) {
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(Body::from(app_state.static_pages.unauthorized))?);
            }

            let claims = Claims::new(Some(user.name.clone()), None, app_state.session_expiration);

            let token = jsonwebtoken::encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &app_state.encoding_key,
            )?;

            let cookie = cookie::Cookie::build((&app_state.session_cookie_name, token))
                .http_only(true)
                .domain(get_cookie_domain(host))
                .same_site(cookie::SameSite::Strict)
                .build();

            return Ok(Response::builder()
                .status(StatusCode::FOUND)
                .header("location", &redirect)
                .header("set-cookie", cookie.to_string())
                .body(Body::empty())?);
        }
    }

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(app_state.static_pages.login_failed))?);
}

async fn show_signin(
    State(app_state): State<AppState>,
    Query(signin_query): Query<SigninQuery>,
) -> Result<Response, AppError> {
    if let Some(redirect) = &signin_query.redirect {
        if Uri::try_from(redirect).is_ok() {
            let claims = Claims::new(None, Some(redirect.clone()), 60 * 60);
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
                .body(Body::from(app_state.static_pages.login))
                .expect("could not build response from static login page"));
        }
    }

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(app_state.static_pages.login))
        .expect("could not build response from static login page"));
}

async fn proxy_authenticate(
    State(app_state): State<AppState>,
    Host(header_host): Host,
    jar: CookieJar,
) -> Result<Response, AppError> {
    let authenticated_user = jar
        .get(&app_state.session_cookie_name)
        .and_then(|cookie| validate_token(cookie.value(), &app_state.decoding_key))
        .and_then(|token| token.claims.user)
        .and_then(|user| app_state.policy.users.get(&user));

    if authenticated_user.is_none() {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())?);
    }

    let user = authenticated_user.expect("unwrap authenticated user");
    debug!(user = user.name, "authenticated user");

    let authorized_hosts = app_state
        .policy
        .authorized_hosts
        .get(&user)
        .expect("bug? could not find allowed hosts for a valid user");

    if authorized_hosts.contains(&header_host) {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())?);
    }

    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::empty())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cookie_domain_with_subdomain() {
        let result = get_cookie_domain("public.example.com");
        assert_eq!(result, ".example.com");
    }

    #[test]
    fn test_get_cookie_domain_with_regular_domain() {
        let result = get_cookie_domain("example.com");
        assert_eq!(result, ".example.com");
    }

    #[test]
    fn test_get_cookie_domain_with_localhost() {
        let result = get_cookie_domain("localhost");
        assert_eq!(result, "localhost");
    }
}
