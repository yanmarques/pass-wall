use std::{
    fs,
    path::{Path, PathBuf},
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
use clap::{Parser, Subcommand};
use hyper::StatusCode;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, errors::ErrorKind,
};
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

use pass_wall::{Claims, Config, Policy, SessionConfig};

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
    pub session: SessionConfig,
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
#[command(version, about = "Password-protected proxy authentication that actually works", long_about = None)]
struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Start proxy authentication HTTP server")]
    Serve {
        #[arg(short, long, default_value = "passwall.yaml")]
        config: PathBuf,
    },

    #[command(
        about = "Generate a default configuration.",
        long_about = "The default configuration will use secure defaults and generate a new key for you. However, you are still responsible for adding users and authorized hosts in the configuration file"
    )]
    Generate {
        #[arg(
            short,
            long,
            help = "Save configuration in the given path. Panics if given path already exists."
        )]
        out: PathBuf,
    },
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

    let cli = Cli::parse();
    match cli.commands.unwrap_or(Commands::Serve {
        config: Path::new("./passwall.yaml").to_path_buf(),
    }) {
        Commands::Serve { config } => serve(config).await?,
        Commands::Generate { out } => {
            let config = Config::default();
            let contents = serde_yaml_ng::to_string(&config)?;
            std::fs::write(out, contents)?;
        }
    }

    Ok(())
}

async fn serve(config_path: PathBuf) -> anyhow::Result<()> {
    let app_config: Config = serde_yaml_ng::from_slice(
        &fs::read(config_path.clone()).context(format!("open config file: {:?}", config_path))?,
    )
    .context(format!("parse yaml config: {:?}", config_path))?;

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
            session: app_config.session.clone(),
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
                let valid = bcrypt::verify(input.password, &user.password_hash)?;
                if valid {
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
