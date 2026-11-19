use futures_util::StreamExt;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::Path,
    str::FromStr,
    sync::mpsc,
};

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use passwall::{Config, DomainAclConfig, HostCookieConfig, SimpleSameSite, User};
use reqwest::Url;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    bollard::{
        Docker,
        query_parameters::{
            InspectContainerOptions, InspectNetworkOptions, LogsOptions, LogsOptionsBuilder,
        },
        secret::NetworkCreateRequest,
    },
    core::{IntoContainerPort, Mount, WaitFor},
    runners::AsyncRunner,
};
use thirtyfour::{
    By, DesiredCapabilities, WebDriver, WebElement,
    error::{WebDriverError, WebDriverResult},
    prelude::ElementQueryable,
};

const DEFAULT_USER: &str = "admin";
const DEFAULT_PASSWORD: &str = "admin";

const DEFAULT_PASSWALL_HOSTNAME: &str = "passwall";

// TODO: handle passwall under the same domain name, different path
const DEFAULT_NGINX_CONF_TEMPLATE: &str = "user root root;
worker_processes    auto;

error_log   /dev/stderr  info;
pid /run/nginx.pid;

events {
    worker_connections  64;
}

http {
    default_type  text/html;
    log_format main '$remote_addr - $remote_user $request';
    upstream authserver {
        server {AUTHSERVER_HOST};
    }

{BODY}

    server {
        listen        80;
        server_name   {AUTHSERVER_NAME};
        access_log   /dev/stdout  main;

        location /favicon.ico {
	    return 404;
	}

	location / {
	    proxy_pass http://authserver{URL_PREFIX};
	}
    }
}";
const DEFAULT_NGINX_CONF_SERVER_TEMPLATE: &str = "
    server {
        listen        80;
        server_name   {SERVER_NAME};
        access_log   /dev/stdout  main;
        location /favicon.ico {
	    return 404;
	}

        location / {
	    auth_request /authenticate;
	    error_page 401 =302 $scheme://{AUTHSERVER_NAME}/?redirect=$scheme://$host$request_uri;
            try_files \"\" @success;
        }

        location @success {
	    return 200 '<div id=\"page\">{PAGE_CONTENT}</div>';
        }

        location = /authenticate {
	    internal;
	    proxy_set_header X-Original-Url $scheme://$host$request_uri;
	    proxy_pass http://authserver{URL_PREFIX}authenticate;
        }
    }";

const DEFAULT_SELENIUM_VIDEO_GID: u32 = 1201;

struct TestClient {
    #[allow(dead_code)]
    containers: Vec<ContainerAsync<GenericImage>>,
    video_container_id: String,
    selenium_url: Url,
}

struct NginxConf {
    config: Config,
    authserver_host: String,
    authserver_name: String,
    servers: Vec<String>,
}

impl NginxConf {
    fn new(config: Config, authserver_name: String, server_names: &[&str]) -> Self {
        let servers = server_names.iter().map(|s| s.to_string()).collect();
        let authserver_host = format!("{}:{}", DEFAULT_PASSWALL_HOSTNAME, passwall::DEFAULT_PORT);
        Self {
            config,
            authserver_host,
            authserver_name,
            servers,
        }
    }

    fn to_string(&self) -> String {
        let conf = DEFAULT_NGINX_CONF_TEMPLATE
            .replace("{AUTHSERVER_HOST}", &self.authserver_host)
            .replace("{AUTHSERVER_NAME}", &self.authserver_name)
            .replace("{URL_PREFIX}", self.config.server.url_prefix());
        let mut body = String::new();
        for server_name in self.servers.iter() {
            body.push_str(
                DEFAULT_NGINX_CONF_SERVER_TEMPLATE
                    .replace("{SERVER_NAME}", &server_name)
                    .replace("{AUTHSERVER_NAME}", &self.authserver_name)
                    .replace("{URL_PREFIX}", self.config.server.url_prefix())
                    .replace("{PAGE_CONTENT}", &server_name)
                    .as_ref(),
            );
        }
        return conf.replace("{BODY}", &body);
    }
}

impl TestClient {
    fn new(
        containers: Vec<ContainerAsync<GenericImage>>,
        video_container_id: String,
        selenium_url: Url,
    ) -> Self {
        Self {
            video_container_id,
            containers,
            selenium_url,
        }
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

async fn build_client(config: &Config, nginx: &NginxConf) -> color_eyre::Result<TestClient> {
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
        .with_network(&net_config.name)
        .start()
        .await?;

    let config_path = tmpdir.path().join("nginx.conf");
    std::fs::write(&config_path, nginx.to_string())?;

    let nginx_container = GenericImage::new("docker.io/nginx", "1.31.9")
        .with_exposed_port(80.into())
        .with_host(
            DEFAULT_PASSWALL_HOSTNAME,
            testcontainers::core::Host::Addr(
                get_bridge_ip_address(&cli, &auth_container, &net_config.name).await?,
            ),
        )
        .with_copy_to("/etc/nginx/nginx.conf", config_path)
        .with_ready_conditions(vec![WaitFor::message_on_stderr("start worker processes")])
        .with_network(&net_config.name)
        .start()
        .await?;

    let hub_container = GenericImage::new("docker.io/selenium/hub", "4.52")
        .with_exposed_port(4444.into())
        .with_ready_conditions(vec![WaitFor::message_on_stdout("Started Selenium Hub")])
        .with_network(&net_config.name)
        .start()
        .await?;

    let nginx_ip = get_bridge_ip_address(&cli, &nginx_container, &net_config.name).await?;
    let hub_ip = get_bridge_ip_address(&cli, &hub_container, &net_config.name).await?;
    let mut selenium_cr = GenericImage::new("docker.io/selenium/node-chromium", "156.0")
        .with_exposed_port(7900.into())
        .with_host(
            &nginx.authserver_name,
            testcontainers::core::Host::Addr(nginx_ip),
        );

    for server_name in nginx.servers.iter() {
        selenium_cr =
            selenium_cr.with_host(server_name, testcontainers::core::Host::Addr(nginx_ip));
    }

    let selenium_container = selenium_cr
        .with_host("hub", testcontainers::core::Host::Addr(hub_ip))
        .with_env_var("SE_EVENT_BUS_HOST", "hub")
        .with_env_var("SE_EVENT_BUS_PUBLISH_PORT", "4442")
        .with_env_var("SE_EVENT_BUS_SUBSCRIBE_PORT", "4443")
        .with_shm_size(2048 * 1024) // 2G
        .with_ready_conditions([WaitFor::message_on_stdout("Started Selenium node")].into())
        .with_network(&net_config.name)
        .start()
        .await?;

    let videos_dir = format!(
        "{}/tests/videos",
        std::env::current_dir()?.to_string_lossy()
    );

    // ensure the pod can create files in the videos folder
    // TODO: dynamically query the group id from the selenium/video image
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

    let opts: Option<InspectContainerOptions> = None;
    let selenium_container_name = cli
        .inspect_container(selenium_container.id(), opts)
        .await?
        .name
        .ok_or_else(|| {
            return color_eyre::eyre::eyre!("missing selenium container name");
        })?;

    let video_container = GenericImage::new("docker.io/selenium/video", "ffmpeg-8.1-20261101")
        .with_mount(Mount::bind_mount(videos_dir, "/videos"))
        .with_env_var(
            "DISPLAY_CONTAINER_NAME",
            selenium_container_name.trim_start_matches("/"),
        )
        .with_env_var("SE_VIDEO_FILE_NAME", "auto")
        .with_ready_conditions([WaitFor::message_on_stdout("Waiting for the display")].into())
        .with_network(&net_config.name)
        .start()
        .await?;

    let hub_host = hub_container.get_host().await?;
    let hub_port = hub_container.get_host_port_ipv4(4444).await?;

    let video_container_id = video_container.id().to_string();
    let http = TestClient::new(
        [
            auth_container,
            nginx_container,
            hub_container,
            video_container,
            selenium_container,
        ]
        .into(),
        video_container_id,
        Url::parse(&format!("http://{hub_host}:{hub_port}"))?,
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

async fn wait_for_url_match_host(
    driver: &WebDriver,
    host: &str,
    timeout: tokio::time::Duration,
) -> WebDriverResult<()> {
    let start = std::time::Instant::now();

    loop {
        let url = driver.current_url().await?;
        if url.host_str() == Some(host) {
            return Ok(());
        }

        if start.elapsed() > timeout {
            return Err(WebDriverError::Timeout("url did not match".into()));
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}

async fn wait_for_url_not_match_host(
    driver: &WebDriver,
    host: &str,
    timeout: tokio::time::Duration,
) -> WebDriverResult<()> {
    let start = std::time::Instant::now();

    loop {
        let url = driver.current_url().await?;
        if url.host_str() == Some(host) {
            return Err(WebDriverError::Timeout("url matched host".into()));
        }

        if start.elapsed() > timeout {
            return Ok(());
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
}

async fn signin(driver: &WebDriver, user: &str, password: &str) -> color_eyre::Result<()> {
    let name_form = driver.query(By::Id("name")).first().await?;
    name_form.send_keys(user).await?;

    let password_form = driver.query(By::Id("password")).first().await?;
    password_form.send_keys(password).await?;

    let elem_button = driver
        .query(By::Css("button[type='submit']"))
        .first()
        .await?;
    elem_button.click().await?;

    return Ok(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_authorizes_one_domain() -> color_eyre::Result<()> {
    let _ = color_eyre::install();

    let mut config = Config::default();
    config.users.push(new_user(DEFAULT_USER, DEFAULT_PASSWORD));
    config.server.scheme_https = false;
    config.acl.push(DomainAclConfig {
        domain: "example.com".into(),
        port: 80,
        allowed_users: vec![DEFAULT_USER.into()],
        cookie: HostCookieConfig {
            same_site: SimpleSameSite::lax,
            domain: Some("example.com".into()),
        },
    });

    let nginx = NginxConf::new(config.clone(), "auth.example.com".into(), &["example.com"]);

    let client = build_client(&config, &nginx).await?;
    let server_url = client.selenium_url.to_string();

    let caps = DesiredCapabilities::chrome();

    let driver = WebDriver::new(&server_url, caps).await?;
    driver.goto("http://example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    wait_for_url_match_host(
        &driver,
        "auth.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    signin(&driver, DEFAULT_USER, DEFAULT_PASSWORD).await?;

    let elem = driver.query(By::Id("page")).first().await?;
    let page = elem.text().await?;
    assert_eq!(page, "example.com");

    driver.quit().await?;
    return Ok(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_server_url_prefix() -> color_eyre::Result<()> {
    let _ = color_eyre::install();

    let mut config = Config::default();
    config.users.push(new_user(DEFAULT_USER, DEFAULT_PASSWORD));
    config.server.scheme_https = false;
    config.server.url_prefix = Some("/prefix/".into());
    config.acl.push(DomainAclConfig {
        domain: "example.com".into(),
        port: 80,
        allowed_users: vec![DEFAULT_USER.into()],
        cookie: HostCookieConfig {
            same_site: SimpleSameSite::lax,
            domain: Some("example.com".into()),
        },
    });

    let nginx = NginxConf::new(config.clone(), "auth.example.com".into(), &["example.com"]);

    let client = build_client(&config, &nginx).await?;

    let server_url = client.selenium_url.to_string();

    let caps = DesiredCapabilities::chrome();

    let driver = WebDriver::new(&server_url, caps).await?;
    driver.goto("http://example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    wait_for_url_match_host(
        &driver,
        "auth.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    signin(&driver, DEFAULT_USER, DEFAULT_PASSWORD).await?;

    let elem = driver.query(By::Id("page")).first().await?;
    let page = elem.text().await?;
    assert_eq!(page, "example.com");

    driver.quit().await?;
    return Ok(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_authorizes_multiple_subdomains_access_all() -> color_eyre::Result<()> {
    let _ = color_eyre::install();

    let mut config = Config::default();
    config.users.push(new_user(DEFAULT_USER, DEFAULT_PASSWORD));
    config.server.scheme_https = false;
    config.acl.extend([
        DomainAclConfig {
            domain: "sub-a.example.com".into(),
            port: 80,
            allowed_users: vec![DEFAULT_USER.into()],
            cookie: HostCookieConfig {
                same_site: SimpleSameSite::lax,
                domain: Some("example.com".into()),
            },
        },
        DomainAclConfig {
            domain: "sub-b.example.com".into(),
            port: 80,
            allowed_users: vec![DEFAULT_USER.into()],
            cookie: HostCookieConfig {
                same_site: SimpleSameSite::lax,
                domain: Some("example.com".into()),
            },
        },
    ]);

    let nginx = NginxConf::new(
        config.clone(),
        "auth.example.com".into(),
        &["sub-a.example.com", "sub-b.example.com"],
    );

    let client = build_client(&config, &nginx).await?;
    let server_url = client.selenium_url.to_string();

    let caps = DesiredCapabilities::chrome();

    let driver = WebDriver::new(&server_url, caps).await?;
    driver.goto("http://sub-a.example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    wait_for_url_match_host(
        &driver,
        "auth.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    signin(&driver, DEFAULT_USER, DEFAULT_PASSWORD).await?;

    let elem = driver.query(By::Id("page")).first().await?;
    let page = elem.text().await?;
    assert_eq!(page, "sub-a.example.com");

    driver.goto("http://sub-b.example.com").await?;

    wait_for_url_match_host(
        &driver,
        "sub-b.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    let elem = driver.query(By::Id("page")).first().await?;
    let page = elem.text().await?;
    assert_eq!(page, "sub-b.example.com");

    driver.quit().await?;
    return Ok(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_rejects_invalid_creds() -> color_eyre::Result<()> {
    let _ = color_eyre::install();

    let mut config = Config::default();
    config.users.push(new_user(DEFAULT_USER, DEFAULT_PASSWORD));
    config.server.scheme_https = false;
    config.acl.extend([DomainAclConfig {
        domain: "example.com".into(),
        port: 80,
        allowed_users: vec![DEFAULT_USER.into()],
        cookie: HostCookieConfig {
            same_site: SimpleSameSite::lax,
            domain: Some("example.com".into()),
        },
    }]);

    let nginx = NginxConf::new(config.clone(), "auth.example.com".into(), &["example.com"]);

    let client = build_client(&config, &nginx).await?;
    let server_url = client.selenium_url.to_string();

    let caps = DesiredCapabilities::chrome();

    let driver = WebDriver::new(&server_url, caps).await?;
    driver.goto("http://example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    wait_for_url_match_host(
        &driver,
        "auth.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    signin(&driver, DEFAULT_USER, "not-the-password").await?;

    wait_for_url_not_match_host(
        &driver,
        "example.com".into(),
        tokio::time::Duration::from_secs(2),
    )
    .await?;

    signin(&driver, "not-the-user", DEFAULT_PASSWORD).await?;

    wait_for_url_not_match_host(
        &driver,
        "example.com".into(),
        tokio::time::Duration::from_secs(2),
    )
    .await?;

    let mut long_str = String::with_capacity(1024);
    for _ in 0..1024 {
        long_str.push('A');
    }

    signin(&driver, &long_str, DEFAULT_PASSWORD).await?;

    wait_for_url_not_match_host(
        &driver,
        "example.com".into(),
        tokio::time::Duration::from_secs(2),
    )
    .await?;

    driver.goto("http://example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    wait_for_url_match_host(
        &driver,
        "auth.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    signin(&driver, DEFAULT_USER, &long_str).await?;

    wait_for_url_not_match_host(
        &driver,
        "example.com".into(),
        tokio::time::Duration::from_secs(2),
    )
    .await?;

    driver.goto("http://example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    wait_for_url_match_host(
        &driver,
        "auth.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    signin(&driver, &long_str, &long_str).await?;

    wait_for_url_not_match_host(
        &driver,
        "example.com".into(),
        tokio::time::Duration::from_secs(2),
    )
    .await?;

    driver.quit().await?;
    return Ok(());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_rejects_unauthorized_user() -> color_eyre::Result<()> {
    let _ = color_eyre::install();

    let user_a = "user_a";
    let user_b = "user_b";

    let mut config = Config::default();
    config.users.push(new_user(user_a, DEFAULT_PASSWORD));
    config.users.push(new_user(user_b, DEFAULT_PASSWORD));
    config.server.scheme_https = false;
    config.acl.extend([
        DomainAclConfig {
            domain: "sub-a.example.com".into(),
            port: 80,
            allowed_users: vec![user_a.into()],
            cookie: HostCookieConfig {
                same_site: SimpleSameSite::lax,
                domain: Some("example.com".into()),
            },
        },
        DomainAclConfig {
            domain: "sub-b.example.com".into(),
            port: 80,
            allowed_users: vec![user_b.into()],
            cookie: HostCookieConfig {
                same_site: SimpleSameSite::lax,
                domain: Some("example.com".into()),
            },
        },
    ]);

    let nginx = NginxConf::new(
        config.clone(),
        "auth.example.com".into(),
        &["sub-a.example.com", "sub-b.example.com"],
    );

    let client = build_client(&config, &nginx).await?;
    let server_url = client.selenium_url.to_string();

    let caps = DesiredCapabilities::chrome();

    let driver = WebDriver::new(&server_url, caps).await?;
    driver.goto("http://sub-a.example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    wait_for_url_match_host(
        &driver,
        "auth.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    signin(&driver, user_b, DEFAULT_PASSWORD).await?;

    wait_for_url_not_match_host(
        &driver,
        "sub-a.example.com".into(),
        tokio::time::Duration::from_secs(2),
    )
    .await?;

    driver.delete_all_cookies().await?;

    driver.goto("http://sub-b.example.com").await?;

    let _ = wait_for_input_filled(&driver, "csrf_token", tokio::time::Duration::from_secs(2)).await;

    wait_for_url_match_host(
        &driver,
        "auth.example.com",
        tokio::time::Duration::from_secs(5),
    )
    .await?;

    signin(&driver, user_a, DEFAULT_PASSWORD).await?;

    wait_for_url_not_match_host(
        &driver,
        "sub-b.example.com".into(),
        tokio::time::Duration::from_secs(2),
    )
    .await?;

    driver.quit().await?;

    return Ok(());
}
