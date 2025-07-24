use criterion::{Criterion, criterion_group, criterion_main};
use heapless::LinearMap;
use rand::Rng;
use rustc_hash::FxHashMap;
use std::{collections::BTreeMap, hint::black_box};

const MAP_SIZE: usize = 16;

struct KeyValue {
    key: String,
    #[allow(dead_code)]
    value: i32,
}

#[inline]
fn search_btreemap(map: &BTreeMap<String, i32>, key: &String) {
    let value = map.get(key);
    black_box(value);
}

#[inline]
fn search_fxhashmap(map: &FxHashMap<String, i32>, key: &String) {
    let value = map.get(key);
    black_box(value);
}

#[inline]
fn search_linearmap(map: &LinearMap<String, i32, MAP_SIZE>, key: &String) {
    let value = map.get(key);
    black_box(value);
}

#[inline]
fn search_hb_hashmap(map: &hashbrown::HashMap<String, i32>, key: &String) {
    let value = map.get(key);
    black_box(value);
}

#[inline]
fn search_vector(map: &Vec<KeyValue>, key: &String) {
    for kv in map.iter() {
        if kv.key == *key {
            black_box(kv);
            break;
        }
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut btreemap: BTreeMap<String, i32> = BTreeMap::new();
    let mut fxhashmap: FxHashMap<String, i32> = FxHashMap::default();
    let mut linearmap: LinearMap<String, i32, MAP_SIZE> = LinearMap::default();
    let mut hb_hashmap: hashbrown::HashMap<String, i32> = hashbrown::HashMap::new();
    let mut vector: Vec<KeyValue> = Vec::new();

    let mut rng = rand::rng();
    let mut keys: Vec<String> = vec![];

    for _ in 0..MAP_SIZE {
        let key = (0..32)
            .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
            .map(String::from)
            .collect::<Vec<String>>()
            .join("");
        keys.push(key.clone());
        btreemap.insert(key.clone(), 1);
        hb_hashmap.insert(key.clone(), 1);
        vector.push(KeyValue {
            key: key.clone(),
            value: 1,
        });
        linearmap
            .insert(key.clone(), 1)
            .expect("insert value in LinearMap");
        fxhashmap.insert(key, 1);
    }

    c.bench_function("btree_hashmap_known_key", |b| {
        b.iter(|| {
            for key in keys.iter() {
                search_btreemap(black_box(&btreemap), key);
            }
        })
    });

    let unknown_key = (0..32)
        .map(|_| rng.sample(rand::distr::Alphanumeric) as char)
        .map(String::from)
        .collect::<Vec<String>>()
        .join("");

    c.bench_function("btree_hashmap_unknown_key", |b| {
        b.iter(|| {
            for _ in 0..keys.len() {
                search_btreemap(black_box(&btreemap), &unknown_key);
            }
        })
    });

    c.bench_function("fx_hashmap_known_key", |b| {
        b.iter(|| {
            for key in keys.iter() {
                search_fxhashmap(black_box(&fxhashmap), &key);
            }
        })
    });

    c.bench_function("fx_hashmap_unknown_key", |b| {
        b.iter(|| {
            for _ in 0..keys.len() {
                search_fxhashmap(black_box(&fxhashmap), &unknown_key);
            }
        })
    });

    c.bench_function("linearmap_known_key", |b| {
        b.iter(|| {
            for key in keys.iter() {
                search_linearmap(black_box(&linearmap), &key);
            }
        })
    });

    c.bench_function("linearmap_unknown_key", |b| {
        b.iter(|| {
            for _ in 0..keys.len() {
                search_linearmap(black_box(&linearmap), &unknown_key);
            }
        })
    });

    c.bench_function("hb_hashmap_known_key", |b| {
        b.iter(|| {
            for key in keys.iter() {
                search_hb_hashmap(black_box(&hb_hashmap), &key);
            }
        })
    });

    c.bench_function("hb_hashmap_unknown_key", |b| {
        b.iter(|| {
            for _ in 0..keys.len() {
                search_hb_hashmap(black_box(&hb_hashmap), &unknown_key);
            }
        })
    });

    c.bench_function("vector_known_key", |b| {
        b.iter(|| {
            for key in keys.iter() {
                search_vector(black_box(&vector), &key);
            }
        })
    });

    c.bench_function("vector_unknown_key", |b| {
        b.iter(|| {
            for _ in 0..keys.len() {
                search_vector(black_box(&vector), &unknown_key);
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
