use futures_util::StreamExt;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::Path,
    str::FromStr,
    sync::{Arc, mpsc},
};

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::http::StatusCode;
use passwall::{Config, DomainAclConfig, HostCookieConfig, SimpleSameSite, User};
use reqwest::{
    Client, RequestBuilder, Url,
    cookie::{CookieStore, Jar},
    redirect::Policy as RedirectPolicy,
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    bollard::{
        Docker,
        query_parameters::{
            InspectContainerOptions, InspectNetworkOptions, LogsOptions, LogsOptionsBuilder,
            WaitContainerOptions,
        },
        secret::NetworkCreateRequest,
    },
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
};
use thirtyfour::{
    By, CapabilitiesHelper, DesiredCapabilities, WebDriver, WebElement,
    error::{WebDriverError, WebDriverResult},
    prelude::ElementQueryable,
};

const DEFAULT_USER: &str = "admin";
const DEFAULT_PASSWORD: &str = "admin";
const DEFAULT_HOST: &str = "private.example.com";
const DEFAULT_DOMAIN: &str = "example.com";

const DEFAULT_SELENIUM_VIDEO_GID: u32 = 1201;

enum Expect {
    Failure,
    Success,
}

struct TestClient {
    #[allow(dead_code)]
    containers: Vec<ContainerAsync<GenericImage>>,
    video_container_id: String,
    config: Config,
    client: Client,
    passwall_url: Url,
    selenium_url: Url,
    nginx_url: Url,
    jar: Arc<Jar>,
    session: Option<String>,
}

impl TestClient {
    fn new(
        config: Config,
        containers: Vec<ContainerAsync<GenericImage>>,
        video_container_id: String,
        client: Client,
        jar: Arc<Jar>,
        passwall_url: Url,
        selenium_url: Url,
        nginx_url: Url,
    ) -> Self {
        Self {
            video_container_id,
            session: None,
            config,
            containers,
            client,
            jar,
            passwall_url,
            selenium_url,
            nginx_url,
        }
    }

    fn get(&self, path: &str) -> RequestBuilder {
        return self.client.get(self.passwall_url.join(path).unwrap());
    }

    fn post(&self, path: &str) -> RequestBuilder {
        return self.client.post(self.passwall_url.join(path).unwrap());
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

        let cookie = self.jar.cookies(&self.passwall_url);
        assert!(cookie.is_some());
        assert!(
            cookie
                .unwrap()
                .to_str()?
                .contains(&format!("{}=", self.config.server.session.cookie_name))
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
                let session_cookies = resp.headers().get_all("set-cookie");
                for acl in &self.config.acl {
                    let mut found = false;
                    for session_cookie in &session_cookies {
                        if let Some(cookie) = session_cookie
                            .to_str()
                            .ok()
                            .and_then(|cookie| cookie::Cookie::parse(cookie).ok())
                        {
                            let domain = cookie.domain().unwrap();
                            if acl.domain == domain {
                                self.session = Some(cookie.value().to_string());
                                found = true;
                                break;
                            }
                        }
                    }

                    assert!(found == true, "missing domain in cookie: {}", acl.domain);
                }

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
                    self.config.server.session.cookie_name,
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

impl Drop for TestClient {
    fn drop(&mut self) {
        let container_id = self.video_container_id.clone();
        // synchronously wait for async task
        let (tx, rx) = mpsc::channel::<()>();

        tokio::spawn(async move {
            if let Ok(cli) = testcontainers::core::client::docker_client_instance().await {
                let _ = cli.remove_network("grid").await;
                let opts: Option<LogsOptions> =
                    Some(LogsOptionsBuilder::new().follow(true).build());
                let mut stream = cli.logs(&container_id, opts);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok(info) => {
                            if info.to_string().contains("Video recording stopped") {
                                break;
                            }
                        }
                        Err(_err) => {}
                    };
                }

                let _ = tx.send(());
            }
        });

        let _ = rx.recv();
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

fn default_config() -> Config {
    let mut config = Config::default();
    config.users = Vec::from_iter([new_user(DEFAULT_USER, DEFAULT_PASSWORD)]);
    config.acl = Vec::from_iter([DomainAclConfig {
        domain: String::from(DEFAULT_HOST),
        port: 80,
        cookie: HostCookieConfig {
            same_site: SimpleSameSite::strict,
            domain: None,
        },
        allowed_users: vec![String::from(DEFAULT_USER)],
    }]);

    return config;
}

async fn get_bridge_ip_address(
    client: &Docker,
    container: &ContainerAsync<GenericImage>,
    network: &str,
) -> color_eyre::Result<IpAddr> {
    let container_id = container.id();

    let get_ip_address = async move || -> color_eyre::Result<IpAddr> {
        let opts: Option<InspectContainerOptions> = None;
        let container_settings = client.inspect_container(container_id, opts).await?;

        let host_config = container_settings
            .host_config
            .expect("missing container 'HostConfig'");

        let network_mode = host_config
            .network_mode
            .expect("missing container HostConfig.NetworkMode");

        let opts: Option<InspectNetworkOptions> = None;
        let network_settings = client.inspect_network(&network_mode, opts).await?;

        network_settings
            .driver
            .expect("missing container network driver mode");

        let container_network_settings = container_settings
            .network_settings
            .expect("missing container NetworkSettings");

        let networks = container_network_settings
            .networks
            .expect("missing container NetworkSettings.Networks");
        let network_config = networks
            .get(network)
            .expect(&format!("unknown network {}", network));
        let ip = network_config
            .ip_address
            .as_ref()
            .expect("missing ip address");

        return Ok(IpAddr::V4(Ipv4Addr::from_str(ip)?));
    };

    for _ in 0..3 {
        if let Ok(ip) = get_ip_address().await {
            return Ok(ip);
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    return Err(color_eyre::eyre::eyre!(
        "failed to get container ip address"
    ));
}

async fn build_client(config: &Config) -> color_eyre::Result<TestClient> {
    // try to use whatever is in "DOCKER_HOST" environment, or docker by default.
    // otherwise, try podman
    let docker_socket = std::env::var("DOCKER_HOST").unwrap_or("/var/run/docker.sock".into());

    if std::fs::exists(docker_socket).is_ok_and(|r| r == false) {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").expect("missing 'XDG_RUNTIME_DIR'");

        tokio::process::Command::new("systemctl")
            .args(["--user", "start", "podman.socket"])
            .spawn()
            .expect("start podman socket")
            .wait()
            .await
            .expect("start podman socket");

        unsafe {
            std::env::set_var(
                "DOCKER_HOST",
                format!("unix://{}/{}", runtime_dir, "podman/podman.sock"),
            );
        }
    }

    let tmpdir = tempfile::tempdir()?;

    let policy_str = serde_yaml_ng::to_string(&config)?;
    let config_path = tmpdir.path().join("passwall.yml");
    std::fs::write(&config_path, policy_str)?;

    let cli = testcontainers::core::client::docker_client_instance().await?;
    let net_config = NetworkCreateRequest {
        name: "grid".into(),
        ..Default::default()
    };

    if let Err(err) = cli.create_network(net_config.clone()).await {
        match err {
            testcontainers::bollard::errors::Error::DockerResponseServerError {
                status_code,
                message,
            } => {
                if status_code != 409 {
                    return Err(color_eyre::eyre::eyre!(
                        "DockerResponseServerError status_code={} message={}",
                        status_code,
                        message
                    ));
                }
            }
            _ => {
                return Err(color_eyre::eyre::eyre!(err));
            }
        };
    }

    let auth_container_port = SocketAddr::from_str(&config.server.bind)?.port();
    let auth_container = GenericImage::new("docker.io/debian", "trixie-slim")
        .with_exposed_port(auth_container_port.tcp())
        .with_entrypoint("/pass-wall")
        .with_cmd(["serve", "--config", "/passwall.yaml"])
        .with_env_var("RUST_LOG", "passwall=trace")
        .with_copy_to("/passwall.yaml", config_path)
        .with_copy_to("/pass-wall", Path::new("./target/debug/pass-wall"))
        .with_ready_conditions(vec![WaitFor::message_on_stdout("starting listener")])
        .with_container_name("passwall")
        .with_network(&net_config.name)
        .start()
        .await?;

    let auth_host = auth_container.get_host().await?;
    let auth_port = auth_container
        .get_host_port_ipv4(auth_container_port)
        .await?;

    let nginx_container = GenericImage::new("docker.io/nginx", "1.28.2")
        .with_exposed_port(80.into())
        .with_host(
            "passwall",
            testcontainers::core::Host::Addr(
                get_bridge_ip_address(&cli, &auth_container, &net_config.name).await?,
            ),
        )
        .with_copy_to("/etc/nginx/nginx.conf", Path::new("./tests/nginx.conf"))
        .with_ready_conditions(vec![WaitFor::message_on_stderr("start worker processes")])
        .with_container_name("nginx")
        .with_network(&net_config.name)
        .start()
        .await?;

    let nginx_host = nginx_container.get_host().await?;
    let nginx_port = nginx_container.get_host_port_ipv4(80).await?;

    let jar = Arc::new(Jar::default());
    let client = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .redirect(RedirectPolicy::none())
        .build()?;

    // let hub_container = GenericImage::new("docker.io/selenium/hub", "4.41.0")
    //     .with_exposed_port(4442.into())
    //     .with_exposed_port(4443.into())
    //     .with_exposed_port(4444.into())
    //     .with_container_name("selenium-hub")
    //     .with_ready_conditions(vec![WaitFor::message_on_stdout("Started Selenium Hub")])
    //     .with_network(&net_config.name)
    //     .start()
    //     .await?;
    //
    let nginx_ip = get_bridge_ip_address(&cli, &nginx_container, &net_config.name).await?;
    let selenium_container = GenericImage::new("docker.io/selenium/node-chromium", "145.0")
        .with_host(
            "sub-a.example.com",
            testcontainers::core::Host::Addr(nginx_ip),
        )
        .with_host(
            "sub-b.example.com",
            testcontainers::core::Host::Addr(nginx_ip),
        )
        .with_host(
            "sub-c.example.com",
            testcontainers::core::Host::Addr(nginx_ip),
        )
        .with_host(
            "auth.example.com",
            testcontainers::core::Host::Addr(nginx_ip),
        )
        .with_env_var("SE_EVENT_BUS_HOST", "hub")
        .with_env_var("SE_EVENT_BUS_PUBLISH_PORT", "4442")
        .with_env_var("SE_EVENT_BUS_SUBSCRIBE_PORT", "4443")
        .with_shm_size(2048 * 1024) // 2G
        .with_ready_conditions([WaitFor::message_on_stdout("Started Selenium node")].into())
        .with_container_name("chromium")
        .with_network(&net_config.name)
        .start()
        .await?;

    let videos_dir = format!(
        "{}/tests/videos",
        std::env::current_dir()?.to_string_lossy()
    );

    // ensure the pod can create files in the videos folder
    // TODO: dynamically query the group id from the selenium/video image
    std::fs::remove_dir_all(&videos_dir)?;
    std::fs::create_dir_all(&videos_dir)?;
    let mut perms = std::fs::metadata(&videos_dir)?.permissions();
    perms.set_mode(0o770);
    std::fs::set_permissions(&videos_dir, perms)?;
    std::process::Command::new("podman")
        .args([
            "unshare",
            "chgrp",
            &DEFAULT_SELENIUM_VIDEO_GID.to_string(),
            &videos_dir,
        ])
        .spawn()?
        .wait()?;

    let video_container = GenericImage::new("docker.io/selenium/video", "ffmpeg-8.0-20260222")
        .with_mount(Mount::bind_mount(videos_dir, "/videos"))
        .with_env_var("DISPLAY_CONTAINER_NAME", "chromium")
        .with_env_var("SE_VIDEO_FILE_NAME", "auto")
        .with_ready_conditions([WaitFor::message_on_stdout("Waiting for the display")].into())
        .with_network(&net_config.name)
        .start()
        .await?;

    let video_container_id = video_container.id().to_string();
    let http = TestClient::new(
        config.clone(),
        [
            auth_container,
            nginx_container,
            // hub_container,
            video_container,
            selenium_container,
        ]
        .into(),
        video_container_id,
        client,
        jar.clone(),
        Url::parse(&format!("http://{auth_host}:{auth_port}"))?,
        Url::parse(&format!("http://127.0.0.1:4444"))?,
        Url::parse(&format!("http://{nginx_host}:{nginx_port}"))?,
    );
    return Ok(http);
}

async fn wait_for_input_filled(
    driver: &WebDriver,
    id: &str,
    timeout: tokio::time::Duration,
) -> WebDriverResult<WebElement> {
    let elem = driver.find(By::Id(id)).await?;

    let start = std::time::Instant::now();
    loop {
        let value = elem.prop("value").await?.unwrap_or_default();
        if !value.is_empty() {
            return Ok(elem);
        }

        if start.elapsed() > timeout {
            return Err(WebDriverError::Timeout("input not filled".into()));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}

// main test scenarios:
// 1. single subdomain, cookie is per subdomain
// 2. multiple subdomains, cookie works for all subdomains of that domain
// 2. single domain, cookie works only for that domain, not for subdomains
#[tokio::test(flavor = "multi_thread")]
async fn test_authorizes_subdomain() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let mut config = Config::default();
    config.users.push(new_user(DEFAULT_USER, DEFAULT_PASSWORD));
    config.server.url_prefix = Some("/passwall/".into());
    config.server.scheme_https = false;
    config.acl.push(DomainAclConfig {
        domain: "sub-c.example.com".into(),
        port: 80,
        allowed_users: vec![DEFAULT_USER.into()],
        cookie: HostCookieConfig {
            same_site: SimpleSameSite::strict,
            domain: None,
        },
    });

    let client = build_client(&config).await?;
    let server_url = client.selenium_url.to_string();

    let mut caps = DesiredCapabilities::chrome();
    caps.insert_base_capability("se:name".into(), "test_authorizes_subdomain".into());

    let driver = WebDriver::new(&server_url, caps).await?;
    driver.goto("http://sub-c.example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    let name_form = driver.query(By::Id("name")).first().await?;
    name_form.send_keys(DEFAULT_USER).await?;

    let password_form = driver.query(By::Id("password")).first().await?;
    password_form.send_keys(DEFAULT_PASSWORD).await?;

    let elem_button = driver
        .query(By::Css("button[type='submit']"))
        .first()
        .await?;
    elem_button.click().await?;

    let elem = driver.query(By::Id("page")).first().await?;
    let page = elem.text().await?;
    assert_eq!(page, "sub-c");

    driver.quit().await?;
    return Ok(());
}

// #[tokio::test]
// async fn test_authorizes_user() -> anyhow::Result<()> {
//     let config = default_config();
//     let mut client = build_client(&config).await?;
//     client
//         .signin(
//             Expect::Success,
//             DEFAULT_HOST,
//             DEFAULT_USER,
//             DEFAULT_PASSWORD,
//         )
//         .await?;
//
//     client
//         .check_proxy_auth(Expect::Success, DEFAULT_HOST)
//         .await?;
//
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_rejects_invalid_password() -> anyhow::Result<()> {
//     let config = default_config();
//     let mut client = build_client(&config).await?;
//
//     client
//         .signin(
//             Expect::Failure,
//             DEFAULT_HOST,
//             DEFAULT_USER,
//             &format!("{}{}", DEFAULT_PASSWORD, "notthepassword"),
//         )
//         .await?;
//
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_rejects_invalid_credentials() -> anyhow::Result<()> {
//     let config = default_config();
//     let mut client = build_client(&config).await?;
//     client
//         .signin(
//             Expect::Failure,
//             DEFAULT_HOST,
//             &format!("{}{}", DEFAULT_USER, "user123"),
//             "notthepassword",
//         )
//         .await?;
//
//     Ok(())
// }

// #[tokio::test]
// async fn test_authorizes_every_domain_for_user() -> anyhow::Result<()> {
//     let mut config = default_config();
//     config.acl.extend([
//         DomainAclConfig {
//             domain: "sub.other.com".into(),
//             port: 80,
//             allowed_users: Vec::from_iter([DEFAULT_USER.to_string()]),
//             cookie: HostCookieConfig {
//                 same_site: SimpleSameSite::strict,
//                 domain: None,
//             },
//         },
//         DomainAclConfig {
//             domain: "another.com".into(),
//             port: 80,
//             allowed_users: Vec::from_iter([DEFAULT_USER.to_string()]),
//             cookie: HostCookieConfig {
//                 same_site: SimpleSameSite::strict,
//                 domain: None,
//             },
//         },
//     ]);
//
//     let mut client = build_client(&config).await?;
//
//     client
//         .signin(
//             Expect::Success,
//             DEFAULT_DOMAIN,
//             DEFAULT_USER,
//             DEFAULT_PASSWORD,
//         )
//         .await?;
//     Ok(())
// }
//
// #[tokio::test]
// async fn test_authorizes_and_ignores_host_header() -> anyhow::Result<()> {
//     let config = default_config();
//     let mut client = build_client(&config).await?;
//     client
//         .signin(
//             Expect::Success,
//             "notexists.com",
//             DEFAULT_USER,
//             DEFAULT_PASSWORD,
//         )
//         .await?;
//     Ok(())
// }
