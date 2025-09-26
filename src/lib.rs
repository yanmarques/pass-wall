use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

extern crate bcrypt;

/// JWT claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub redirect: Option<String>,
    pub user: Option<String>,
    pub exp: u64,
}

/// Allowed user
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    // bcrypt
    pub password_hash: String,
}

/// Allowed host
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Host {
    pub value: String,
    pub domain: String,
}

impl From<String> for Host {
    fn from(value: String) -> Self {
        let domain = parse_host_domain(&value);
        Self { value, domain }
    }
}

/// Define who and what can be access and be accessed
#[derive(Clone, Debug)]
pub struct Policy {
    pub users: rustc_hash::FxHashMap<String, User>,
    pub authorized_hosts: rustc_hash::FxHashMap<User, rustc_hash::FxHashMap<String, Host>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    pub host: String,
    pub allowed_users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub app_bind: String,
    pub app_key: String,
    pub users: Vec<User>,
    pub acl: Vec<AccessControlConfig>,
    pub session_cookie_name: String,
    pub session_expiration_secs: u64,
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

/// Get the domain to use in the cookie from the Uri
pub(crate) fn parse_host_domain(host: &str) -> String {
    let subs = host.split(".").collect::<Vec<&str>>();
    if subs.len() < 2 {
        return String::from(host);
    }

    let mut domain = String::from(&subs[subs.len() - 2..].join("."));
    domain.insert(0, '.');
    return domain;
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
