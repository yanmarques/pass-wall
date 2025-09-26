use std::{net::SocketAddr, path::Path, str::FromStr, sync::Arc};

use hyper::StatusCode;
use pass_wall::{AccessControlConfig, Config, User};
use reqwest::{
    Client, RequestBuilder, Url,
    cookie::{CookieStore, Jar},
    redirect::Policy,
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

const DEFAULT_PORT: u16 = 9000;
const DEFAULT_COOKIE_NAME: &str = "passwall_session";
const DEFAULT_USER: &str = "admin";
const DEFAULT_PASSWORD: &str = "admin";
const DEFAULT_HOST: &str = "private.example.com";

struct TestContainer {
    container: ContainerAsync<GenericImage>,
    client: Client,
    base_url: Url,
    jar: Arc<Jar>,
}

impl TestContainer {
    fn new(
        container: ContainerAsync<GenericImage>,
        client: Client,
        jar: Arc<Jar>,
        base_url: Url,
    ) -> Self {
        Self {
            container,
            client,
            jar,
            base_url,
        }
    }

    fn get(&self, path: &str) -> RequestBuilder {
        return self.client.get(self.base_url.join(path).unwrap());
    }

    fn post(&self, path: &str) -> RequestBuilder {
        return self.client.post(self.base_url.join(path).unwrap());
    }
}

fn new_user(name: &str, password: &str) -> User {
    User {
        name: String::from(name),
        password_hash: bcrypt::hash(password, bcrypt::DEFAULT_COST).expect(&format!(
            "failed to hash password, for some reason: {}",
            password
        )),
    }
}

fn default_config() -> Config {
    Config {
        app_bind: String::from(format!("0.0.0.0:{DEFAULT_PORT}")),
        app_key: String::from("supersecret"),
        session_cookie_name: String::from(DEFAULT_COOKIE_NAME),
        session_expiration_secs: 60 * 60,
        users: Vec::from_iter([new_user(DEFAULT_USER, DEFAULT_PASSWORD)]),
        acl: Vec::from_iter([AccessControlConfig {
            host: String::from(DEFAULT_HOST),
            allowed_users: vec![String::from(DEFAULT_USER)],
        }]),
    }
}

async fn build_client(config: &Config) -> anyhow::Result<TestContainer> {
    let tmpdir = tempfile::tempdir()?;

    let policy_str = serde_yaml_ng::to_string(&config)?;
    let config_path = tmpdir.path().join("passwall.yml");
    std::fs::write(&config_path, policy_str)?;

    let container_port = SocketAddr::from_str(&config.app_bind)?.port();
    let container = GenericImage::new("debian", "bookworm")
        .with_exposed_port(container_port.tcp())
        .with_entrypoint("/pass-wall")
        .with_cmd(["--config", "/passwall.yaml"])
        .with_env_var("RUST_LOG", "pass_wall=debug")
        .with_copy_to("/passwall.yaml", config_path)
        .with_copy_to("/pass-wall", Path::new("./target/debug/pass-wall"))
        .with_ready_conditions(vec![WaitFor::message_on_stdout("starting listener")])
        .start()
        .await?;

    let host = container.get_host().await?;
    let port = container.get_host_port_ipv4(container_port).await?;

    let jar = Arc::new(Jar::default());
    let client = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .redirect(Policy::none())
        .build()?;

    let http = TestContainer::new(
        container,
        client,
        jar.clone(),
        Url::parse(&format!("http://{host}:{port}"))?,
    );
    return Ok(http);
}

async fn signin(
    config: &Config,
    client: &TestContainer,
    host: &str,
    user: &str,
    password: &str,
) -> anyhow::Result<Option<String>> {
    let target = format!("http://{}/", host);
    assert_eq!(
        client
            .get("/")
            .query(&[("redirect", &target)])
            .send()
            .await?
            .status(),
        StatusCode::OK,
    );

    let cookie = client.jar.cookies(&client.base_url);
    assert!(cookie.is_some());
    assert!(
        cookie
            .unwrap()
            .to_str()?
            .contains(&format!("{}=", config.session_cookie_name))
    );

    let resp = client
        .post("/signin")
        .form(&[("name", user), ("password", password)])
        .send()
        .await?;

    if resp.status() != StatusCode::FOUND {
        return Ok(None);
    }

    assert_eq!(resp.headers().get("location").unwrap().to_str()?, &target);

    // reqwest won't keep cookie because of domain mismatch, so we do the dirty job
    let session_cookies = resp.headers().get("set-cookie");
    assert_ne!(session_cookies, None);
    let session = session_cookies
        .and_then(|cookie| cookie.to_str().ok())
        .and_then(|cookie| cookie.split_once(";"))
        .and_then(|fragments| fragments.0.split_once("="))
        .and_then(|fragments| Some(fragments.1))
        .unwrap();

    return Ok(Some(String::from(session)));
}

async fn check_proxy_auth(
    config: &Config,
    client: &TestContainer,
    host: &str,
    session: &String,
) -> anyhow::Result<()> {
    assert_eq!(
        client
            .get("/authenticate")
            .header("host", host)
            .header(
                "cookie",
                format!("{}={}", config.session_cookie_name, session)
            )
            .send()
            .await?
            .status(),
        StatusCode::OK
    );

    Ok(())
}

#[tokio::test]
async fn test_authorizes_user() -> anyhow::Result<()> {
    let config = default_config();

    let client = build_client(&config).await?;
    let session = signin(
        &config,
        &client,
        DEFAULT_HOST,
        DEFAULT_USER,
        DEFAULT_PASSWORD,
    )
    .await?
    .expect("failed to sign in");

    check_proxy_auth(&config, &client, DEFAULT_HOST, &session).await?;

    Ok(())
}
