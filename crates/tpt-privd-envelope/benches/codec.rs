//! Frame encode/decode micro-benchmarks (I12).
#![allow(missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tpt_privd_envelope::{Command, CommandId, CommandKind, decode, encode};

fn bench_encode(c: &mut Criterion) {
    let payloads: Vec<(u32, Vec<u8>)> = vec![
        (0, Vec::new()),
        (1, b"hello".to_vec()),
        (64, vec![0xAB; 64]),
        (1024, vec![0xCD; 1024]),
    ];
    let mut group = c.benchmark_group("envelope/encode");
    for (n, payload) in payloads {
        let cmd = Command::new(CommandId(1), CommandKind::ECHO, payload);
        group.bench_function(format!("payload_{n}"), |b| {
            b.iter(|| encode(black_box(&cmd)).unwrap());
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let payloads: Vec<(u32, Vec<u8>)> = vec![
        (0, Vec::new()),
        (1, b"hello".to_vec()),
        (64, vec![0xAB; 64]),
        (1024, vec![0xCD; 1024]),
    ];
    let mut group = c.benchmark_group("envelope/decode");
    for (n, payload) in payloads {
        let bytes = encode(&Command::new(CommandId(1), CommandKind::ECHO, payload)).unwrap();
        group.bench_function(format!("payload_{n}"), |b| {
            b.iter(|| decode(black_box(&bytes)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
