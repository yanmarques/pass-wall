use std::{net::SocketAddr, path::Path, str::FromStr, sync::Arc};

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use hyper::StatusCode;
use pass_wall::{AccessControlConfig, Config, User};
use reqwest::{
    Client, RequestBuilder, Url,
    cookie::{CookieStore, Jar},
    redirect::Policy as RedirectPolicy,
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

const DEFAULT_USER: &str = "admin";
const DEFAULT_PASSWORD: &str = "admin";
const DEFAULT_HOST: &str = "private.example.com";
const DEFAULT_DOMAIN: &str = "example.com";

enum Expect {
    Failure,
    Success,
}

enum Subdomains {
    Include,
    Exclude,
}

struct TestClient {
    #[allow(dead_code)]
    container: ContainerAsync<GenericImage>,
    config: Config,
    client: Client,
    base_url: Url,
    jar: Arc<Jar>,
    session: Option<String>,
}

impl TestClient {
    fn new(
        config: Config,
        container: ContainerAsync<GenericImage>,
        client: Client,
        jar: Arc<Jar>,
        base_url: Url,
    ) -> Self {
        Self {
            session: None,
            config,
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

    async fn signin(
        &mut self,
        expect: Expect,
        host: &str,
        user: &str,
        password: &str,
    ) -> anyhow::Result<reqwest::Response> {
        let target = format!("http://{}/", host);
        assert_eq!(
            self.get("/")
                .query(&[("redirect", &target)])
                .send()
                .await?
                .status(),
            StatusCode::OK,
        );

        let cookie = self.jar.cookies(&self.base_url);
        assert!(cookie.is_some());
        assert!(
            cookie
                .unwrap()
                .to_str()?
                .contains(&format!("{}=", self.config.session.cookie_name))
        );

        let resp = self
            .post("/signin")
            .form(&[("name", user), ("password", password)])
            .send()
            .await?;

        match &expect {
            Expect::Success => {
                assert_eq!(
                    resp.status(),
                    StatusCode::FOUND,
                    "expected success, host: {}",
                    host
                );
                assert_eq!(resp.headers().get("location").unwrap().to_str()?, &target);

                // reqwest won't keep cookie because of domain mismatch, so we do the dirty job
                let session_cookies = resp.headers().get("set-cookie");
                assert_ne!(session_cookies, None);
                let session = session_cookies
                    .clone()
                    .and_then(|cookie| cookie.to_str().ok())
                    .and_then(|cookie| cookie.split_once(";"))
                    .and_then(|fragments| fragments.0.split_once("="))
                    .and_then(|fragments| Some(fragments.1))
                    .unwrap();

                self.session = Some(String::from(session));

                return Ok(resp);
            }
            Expect::Failure => {
                assert_eq!(
                    resp.status(),
                    StatusCode::UNAUTHORIZED,
                    "expected failure, host: {}",
                    host
                );
            }
        }

        return Ok(resp);
    }

    async fn check_proxy_auth(&self, expect: Expect, host: &str) -> anyhow::Result<()> {
        let resp = self
            .get("/authenticate")
            .header("host", host)
            .header(
                "cookie",
                format!(
                    "{}={}",
                    self.config.session.cookie_name,
                    self.session.clone().unwrap(),
                ),
            )
            .send()
            .await?;

        match expect {
            Expect::Success => {
                assert_eq!(resp.status(), StatusCode::OK);
            }
            Expect::Failure => {
                assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            }
        };

        Ok(())
    }
}

fn new_user(name: &str, password: &str) -> User {
    // iv not initialized, doesn't matter
    let mut salt = vec![0; 8];
    let salt_string = SaltString::encode_b64(&mut salt).expect("generate password hash salt");
    User {
        name: String::from(name),
        password_hash: Argon2::default()
            .hash_password(password.as_bytes(), &salt_string)
            .expect(&format!(
                "failed to hash password, for some reason: {}",
                password
            ))
            .serialize()
            .to_string(),
    }
}

fn new_subdomain(subdomain: &str, basedomain: &str) -> String {
    format!("{subdomain}.{basedomain}")
}

fn default_config(subdomains: Subdomains) -> Config {
    let mut config = Config::default();
    config.users = Vec::from_iter([new_user(DEFAULT_USER, DEFAULT_PASSWORD)]);
    config.acl = Vec::from_iter([AccessControlConfig {
        host: String::from(DEFAULT_HOST),
        base_domain: None,
        include_subdomains: if let Subdomains::Include = subdomains {
            true
        } else {
            false
        },
        allowed_users: vec![String::from(DEFAULT_USER)],
    }]);

    return config;
}

async fn build_client(config: &Config) -> anyhow::Result<TestClient> {
    let tmpdir = tempfile::tempdir()?;

    let policy_str = serde_yaml_ng::to_string(&config)?;
    let config_path = tmpdir.path().join("passwall.yml");
    std::fs::write(&config_path, policy_str)?;

    let container_port = SocketAddr::from_str(&config.app_bind)?.port();
    let container = GenericImage::new("debian", "bookworm")
        .with_exposed_port(container_port.tcp())
        .with_entrypoint("/pass-wall")
        .with_cmd(["serve", "--config", "/passwall.yaml"])
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
        .redirect(RedirectPolicy::none())
        .build()?;

    let http = TestClient::new(
        config.clone(),
        container,
        client,
        jar.clone(),
        Url::parse(&format!("http://{host}:{port}"))?,
    );
    return Ok(http);
}

#[tokio::test]
async fn test_authorizes_user() -> anyhow::Result<()> {
    let config = default_config(Subdomains::Include);
    let mut client = build_client(&config).await?;
    client
        .signin(
            Expect::Success,
            DEFAULT_HOST,
            DEFAULT_USER,
            DEFAULT_PASSWORD,
        )
        .await?;

    client
        .check_proxy_auth(Expect::Success, DEFAULT_HOST)
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_rejects_invalid_password() -> anyhow::Result<()> {
    let config = default_config(Subdomains::Include);
    let mut client = build_client(&config).await?;

    client
        .signin(
            Expect::Failure,
            DEFAULT_HOST,
            DEFAULT_USER,
            "notthepassword",
        )
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_rejects_invalid_credentials() -> anyhow::Result<()> {
    let config = default_config(Subdomains::Include);
    let mut client = build_client(&config).await?;
    client
        .signin(Expect::Failure, DEFAULT_HOST, "user123", "notthepassword")
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_rejects_valid_credentials_unauthorized_host() -> anyhow::Result<()> {
    let config = default_config(Subdomains::Exclude);
    let mut client = build_client(&config).await?;
    client
        .signin(
            Expect::Failure,
            &new_subdomain("notexists", DEFAULT_DOMAIN),
            DEFAULT_USER,
            DEFAULT_PASSWORD,
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn test_rejects_host_impersonation() -> anyhow::Result<()> {
    let config = default_config(Subdomains::Include);
    let mut client = build_client(&config).await?;
    client
        .signin(
            Expect::Success,
            DEFAULT_HOST,
            DEFAULT_USER,
            DEFAULT_PASSWORD,
        )
        .await?;

    client
        .check_proxy_auth(Expect::Success, DEFAULT_HOST)
        .await?;

    client
        .check_proxy_auth(Expect::Failure, "another.domain.com")
        .await?;

    Ok(())
}
