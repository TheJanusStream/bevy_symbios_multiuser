use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
enum TestMessage {
    Move { x: f32, y: f32 },
    Chat(String),
    StateUpdate { id: u64, data: Vec<u8> },
}

fn bench_serialize(c: &mut Criterion) {
    let msg = TestMessage::Move { x: 1.0, y: 2.0 };
    c.bench_function("serialize_move", |b| {
        b.iter(|| bincode::serialize(black_box(&msg)).unwrap())
    });

    let chat = TestMessage::Chat("Hello, world!".to_string());
    c.bench_function("serialize_chat", |b| {
        b.iter(|| bincode::serialize(black_box(&chat)).unwrap())
    });

    let large = TestMessage::StateUpdate {
        id: 42,
        data: vec![0u8; 1024],
    };
    c.bench_function("serialize_state_1kb", |b| {
        b.iter(|| bincode::serialize(black_box(&large)).unwrap())
    });
}

fn bench_deserialize(c: &mut Criterion) {
    let msg = TestMessage::Move { x: 1.0, y: 2.0 };
    let bytes = bincode::serialize(&msg).unwrap();
    c.bench_function("deserialize_move", |b| {
        b.iter(|| bincode::deserialize::<TestMessage>(black_box(&bytes)).unwrap())
    });

    let chat = TestMessage::Chat("Hello, world!".to_string());
    let chat_bytes = bincode::serialize(&chat).unwrap();
    c.bench_function("deserialize_chat", |b| {
        b.iter(|| bincode::deserialize::<TestMessage>(black_box(&chat_bytes)).unwrap())
    });

    let large = TestMessage::StateUpdate {
        id: 42,
        data: vec![0u8; 1024],
    };
    let large_bytes = bincode::serialize(&large).unwrap();
    c.bench_function("deserialize_state_1kb", |b| {
        b.iter(|| bincode::deserialize::<TestMessage>(black_box(&large_bytes)).unwrap())
    });
}

fn bench_roundtrip(c: &mut Criterion) {
    let msg = TestMessage::Move { x: 1.0, y: 2.0 };
    c.bench_function("roundtrip_move", |b| {
        b.iter(|| {
            let bytes = bincode::serialize(black_box(&msg)).unwrap();
            bincode::deserialize::<TestMessage>(black_box(&bytes)).unwrap()
        })
    });
}

criterion_group!(benches, bench_serialize, bench_deserialize, bench_roundtrip);
criterion_main!(benches);
