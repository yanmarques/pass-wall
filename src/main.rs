use std::fs;

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
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

use pass_wall::{Claims, Config, Policy};

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
    pub session_cookie_name: String,
    pub session_expiration: u64,
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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "passwall.yaml")]
    config: String,
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
        login: Bytes::from_owner(include_bytes!("./../static/login.html")),
        unauthenticated: Bytes::from_owner(include_bytes!("./../static/unauthenticated.html")),
        unauthorized: Bytes::from_owner(include_bytes!("./../static/unauthorized.html")),
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

    tracing::info!("received signal {which_signal}, exiting");
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
