use std::time::Duration;

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::{body::Body, http::Request};
use cookie::Cookie;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use pass_wall::{AccessControlConfig, Config, Host, Policy, User};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use tokio::runtime::Runtime;
use tower::ServiceExt;

const DEFAULT_PASSWORD: &str = "admin";

fn policy_test(user: &User, acls: &[AccessControlConfig]) -> Policy {
    let mut hosts = rustc_hash::FxHashMap::default();
    for acl in acls.iter() {
        hosts.insert(acl.host.clone(), Host::from(acl.host.clone(), &acl));
    }

    let policy = Policy {
        users: rustc_hash::FxHashMap::from_iter([(user.name.clone(), user.clone())]),
        authorized_hosts: rustc_hash::FxHashMap::from_iter([(user.name.clone(), hosts)]),
    };
    return policy;
}

fn generate_policy_test(user: &User, length: usize) -> anyhow::Result<Policy> {
    let acls = generate_acls(user, length)?;
    return Ok(policy_test(user, &acls));
}

fn generate_acls(user: &User, length: usize) -> anyhow::Result<Vec<AccessControlConfig>> {
    let mut rng = StdRng::seed_from_u64(42);
    let mut acls = Vec::with_capacity(length);
    for _ in 0..length {
        let ndots = 2 + rng.next_u32() % 2;
        let mut subs = Vec::with_capacity(ndots as usize);
        for _ in 0..ndots as usize {
            let mut bytes = Vec::<u8>::with_capacity(6);
            let sublen = 2 + rng.next_u32() % 6;
            for _ in 0..sublen {
                bytes.push(0);
            }
            rng.fill_bytes(&mut bytes);
            let sub = hex::encode(bytes);
            subs.push(sub);
        }

        acls.push(AccessControlConfig {
            host: subs.join("."),
            host_is_subdomain: rng.random(),
            include_subdomains: rng.random(),
            include_siblings: rng.random(),
            allowed_users: vec![user.name.clone()],
        });
    }

    Ok(acls)
}

fn bench_policy_authorize(user: &User, policy: &Policy) {
    black_box(policy.authorize(&user.name, "sub.example.com"));
}

async fn bench_app_signin(config: &Config, user: &str, password: &str) {
    let app = pass_wall::app(config).expect("get app router");
    let response = app
        .oneshot(
            Request::builder()
                .uri("/?redirect=http://private.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("failed to send first request");

    let auth_cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|header| header.to_str().ok())
        .and_then(|set_cookie| Cookie::parse_encoded(set_cookie).ok())
        .expect("set-cookie response");

    let app = pass_wall::app(config).expect("get app router");
    black_box(
        app.oneshot(
            Request::builder()
                .header("cookie", auth_cookie.to_string())
                .uri("/signin")
                .method("POST")
                .body(Body::new(format!("user={}&password={}", user, password)))
                .unwrap(),
        )
        .await
        .expect("failed to send first request"),
    );
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut salt = vec![0; 8];
    let salt_string = SaltString::encode_b64(&mut salt).expect("generate password hash salt");
    let user = User {
        name: String::from("admin"),
        password_hash: Argon2::default()
            .hash_password(DEFAULT_PASSWORD.as_bytes(), &salt_string)
            .expect(&format!(
                "failed to hash password, for some reason: {}",
                DEFAULT_PASSWORD
            ))
            .serialize()
            .to_string(),
    };
    let rt = Runtime::new().expect("span new runtime");

    let mut group = c.benchmark_group("Policy::authorize");
    group.bench_function("length-100", |b| {
        b.iter_batched(
            || generate_policy_test(&user, 100).expect("generate policy test"),
            |policy| bench_policy_authorize(black_box(&user.clone()), black_box(&policy)),
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();

    let mut group = c.benchmark_group("Policy::authorize");
    group.bench_function("length-10000", |b| {
        b.iter_batched(
            || generate_policy_test(&user, 10000).expect("generate policy test"),
            |policy| bench_policy_authorize(black_box(&user.clone()), black_box(&policy)),
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();

    let mut group = c.benchmark_group("Policy::authorize");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(60));
    group.bench_function("length-1000000", |b| {
        b.iter_batched(
            || generate_policy_test(&user, 1000000).expect("generate policy test"),
            |policy| bench_policy_authorize(black_box(&user.clone()), black_box(&policy)),
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();

    let mut group = c.benchmark_group("app::flow");
    group.bench_function("length-100", |b| {
        b.iter_batched(
            || {
                let acls = generate_acls(&user, 100).expect("generate policy test");
                let mut config = Config::default();
                config.users = vec![user.clone()];
                config.acl = acls;
                return config;
            },
            |config| {
                rt.block_on(async {
                    bench_app_signin(
                        black_box(&config),
                        black_box(&user.name),
                        black_box(DEFAULT_PASSWORD),
                    )
                    .await;
                });
            },
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
