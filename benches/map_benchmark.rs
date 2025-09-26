use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use pass_wall::{AccessControlConfig, Host, Policy, User};
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};

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
            allowed_users: vec![],
        });
    }

    Ok(policy_test(user, &acls))
}

fn bench_policy_authorize(user: &User, policy: &Policy) {
    policy.authorize(&user.name, "sub.example.com");
}

fn criterion_benchmark(c: &mut Criterion) {
    let user = User {
        name: String::from("admin"),
        password_hash: String::new(),
    };

    let mut group = c.benchmark_group("Policy::authorize");
    group.bench_function("length-100", |b| {
        b.iter_batched(
            || generate_policy_test(&user, 100).expect("generate policy test"),
            |policy| bench_policy_authorize(&user.clone(), &policy),
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();

    let mut group = c.benchmark_group("Policy::authorize");
    group.bench_function("length-10000", |b| {
        b.iter_batched(
            || generate_policy_test(&user, 10000).expect("generate policy test"),
            |policy| bench_policy_authorize(&user.clone(), &policy),
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
            |policy| bench_policy_authorize(&user.clone(), &policy),
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
