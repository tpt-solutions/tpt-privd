//! Frame encode/decode benchmarks (I12).
#![allow(missing_docs)]

use std::io::Cursor;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tpt_privd_envelope::{Command, CommandId, CommandKind, encode};
use tpt_privd_transport::{FrameLimits, read_frame, write_frame};

fn bench_roundtrip(c: &mut Criterion) {
    let limits = FrameLimits::new(1024 * 1024);
    let mut group = c.benchmark_group("transport/frame_roundtrip");
    for n in [0usize, 1, 64, 1024] {
        let cmd = Command::new(CommandId(1), CommandKind::ECHO, vec![0xAB; n]);
        let bytes = encode(&cmd).unwrap();
        group.bench_function(format!("payload_{n}"), |b| {
            b.iter(|| {
                let mut cursor = Cursor::new(Vec::new());
                write_frame(&mut cursor, black_box(&bytes), limits).unwrap();
                cursor.set_position(0);
                let out = read_frame(&mut cursor, limits).unwrap();
                black_box(out);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
