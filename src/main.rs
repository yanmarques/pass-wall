use std::{
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Form, Router,
    body::Body,
    extract::{Request, State},
    http::Uri,
    response::{IntoResponse, Response},
};
use bcrypt::DEFAULT_COST;
use bytes::Bytes;
use clap::Parser;
use hyper::StatusCode;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, errors::ErrorKind,
};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};
use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};

extern crate bcrypt;

type HttpClient = hyper_util::client::legacy::Client<HttpConnector, Body>;

const COOKIE_NAME: &str = "passwall";
const DEFAULT_HTTP_SCHEME: &str = "https";

/// JWT claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user: String,
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
    endpoints: rustc_hash::FxHashMap<String, Uri>,
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
        let mut endpoints = rustc_hash::FxHashMap::<String, Uri>::default();

        for endpoint in value.endpoints {
            for user_name in endpoint.allowed_users {
                let user = match users.get(&user_name) {
                    Some(u) => u,
                    None => {
                        return Err(anyhow::anyhow!(
                            "The endpoint '{}' configuration specifies an inexistent user called '{}'",
                            endpoint.domain,
                            user_name
                        ));
                    }
                };

                if let Some(hosts) = authorized_hosts.get_mut(&user) {
                    hosts.push(endpoint.domain.clone());
                } else {
                    authorized_hosts
                        .insert(user.clone(), Vec::from_iter([endpoint.domain.clone()]));
                }

                let uri = Uri::try_from(endpoint.dest.clone())?;

                if uri.scheme_str() != Some("http") && uri.scheme_str() != Some("https") {
                    return Err(anyhow::anyhow!(
                        "The endpoint '{}' specifies a destination '{}' that is neither 'http://' nor 'https://', and we only support these protocols. Please, add which protocol of the destination host",
                        endpoint.domain,
                        endpoint.dest,
                    ));
                }

                endpoints.insert(endpoint.domain.clone(), uri);
            }
        }

        Ok(Policy {
            users,
            authorized_hosts,
            endpoints,
        })
    }
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
    http_client: HttpClient,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    static_pages: StaticPages,
    policy: Policy,
}

/// Login form input
#[derive(Deserialize, Debug)]
struct LoginInput {
    name: String,
    password: String,
}

#[derive(Deserialize, Clone, Debug)]
struct Endpoint {
    domain: String,
    dest: String,
    allowed_users: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    app_bind: String,
    app_key: String,
    users: Vec<User>,
    endpoints: Vec<Endpoint>,
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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "passwall.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::Subscriber::builder()
        .with_line_number(true)
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .try_init()?;

    let http_client: HttpClient =
        hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(HttpConnector::new());

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
        .route(
            "/login",
            axum::routing::post(authenticate).get(handle_all_requests),
        )
        .fallback(handle_all_requests)
        .with_state(AppState {
            http_client,
            policy,
            static_pages,
            encoding_key: EncodingKey::from_secret(&app_key_bytes),
            decoding_key: DecodingKey::from_secret(&app_key_bytes),
        });

    let listener = tokio::net::TcpListener::bind(app_config.app_bind).await?;
    info!("starting listener");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn authenticate(
    State(app_state): State<AppState>,
    Form(input): Form<LoginInput>,
) -> Result<Response, AppError> {
    // TODO: handle user authenticating to the not allowed host
    if let Some(user) = app_state.policy.users.get(&input.name) {
        let valid = bcrypt::verify(input.password, &user.password_hash)?;

        if valid {
            let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);

            let claims = Claims {
                user: user.name.clone(),
                exp: expiration
                    .duration_since(UNIX_EPOCH)
                    .expect("can not get current timestamp")
                    .as_secs(),
            };

            let token = jsonwebtoken::encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &app_state.encoding_key,
            )?;

            return Ok(Response::builder()
                .status(302)
                .header("location", "/")
                .header(
                    "set-cookie",
                    format!("{}={}; HttpOnly; SameSite=Strict", COOKIE_NAME, token),
                )
                .body(Body::empty())
                .expect("could not build response from static login page"));
        }
    }

    return Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(app_state.static_pages.login_failed))
        .expect("could not build response from static login page"));
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

async fn handle_all_requests(
    State(app_state): State<AppState>,
    mut req: Request,
) -> Result<Response, AppError> {
    let mut authenticated_user = None;

    if let Some(cookie_header) = req.headers().get("cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie_value in cookie_str.split(";") {
                let parsing_result =
                    cookie::Cookie::parse_encoded(cookie_value).inspect_err(|err| {
                        error!(?err, "failed to parse cookie");
                    });

                if let Ok(cookies) = parsing_result {
                    let (name, value) = cookies.name_value();
                    if name == COOKIE_NAME {
                        if let Some(data) = validate_token(value, &app_state.decoding_key) {
                            authenticated_user = app_state.policy.users.get(&data.claims.user);
                        }

                        break;
                    }
                }
            }
        }
    }

    if authenticated_user.is_none() {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from(app_state.static_pages.login))
            .expect("could not build response from static login page"));
    }

    let user = authenticated_user.expect("unwrap authenticated user");
    debug!(user = user.name, "authenticated user");

    let authorized_hosts = app_state
        .policy
        .authorized_hosts
        .get(&user)
        .expect("bug? could not find allowed hosts for a valid user");

    let header_host = req
        .headers()
        .get("host")
        .map(|h| h.to_str().unwrap_or_default())
        .map(String::from);

    if let Some(host) = header_host {
        if authorized_hosts.contains(&host) {
            let path = req.uri().path();
            let path_query = req
                .uri()
                .path_and_query()
                .map(|v| v.as_str())
                .unwrap_or(path);

            let endpoint = app_state
                .policy
                .endpoints
                .get(&host)
                .expect("bug? authorized host has no endpoint");

            *req.uri_mut() = Uri::builder()
                .scheme(
                    endpoint
                        .scheme()
                        .map(|s| s.as_str())
                        .unwrap_or(DEFAULT_HTTP_SCHEME),
                )
                .authority(
                    endpoint
                        .authority()
                        .map(|a| a.as_str())
                        .expect("bug? endpoint is missing authority in URL"),
                )
                .path_and_query(path_query)
                .build()?;

            return Ok(app_state.http_client.request(req).await?.into_response());
        }
    }

    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "text/html; charset=utf-8")
        .body(Body::from(app_state.static_pages.unauthorized))?)
}
