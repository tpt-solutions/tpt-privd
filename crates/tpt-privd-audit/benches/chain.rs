//! Audit append + verify hot-path benchmarks (I12).
#![allow(missing_docs)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tpt_privd_audit::AuditOutcome;
use tpt_privd_audit::{AuditKeypair, AuditLog, NewRecord};
use tpt_privd_envelope::{CommandId, CommandKind};

struct TempLog {
    dir: std::path::PathBuf,
}

impl TempLog {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tpt-privd-bench-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }
    fn log(&self) -> std::path::PathBuf {
        self.dir.join("bench.jsonl")
    }
    fn key(&self) -> std::path::PathBuf {
        self.dir.join("bench.key")
    }
}

impl Drop for TempLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn record(i: u64) -> NewRecord {
    NewRecord {
        command_id: CommandId(i),
        command_version: 1,
        command_kind: CommandKind::ECHO,
        payload_sha256: [0u8; 32],
        caller_uid: Some(1000),
        outcome: AuditOutcome::Executed,
        error_code: None,
        result_sha256: Some([1u8; 32]),
    }
}

fn bench_append(c: &mut Criterion) {
    let t = TempLog::new();
    let mut log = AuditLog::open(&t.log(), &t.key()).unwrap();
    for i in 0..16 {
        log.append(record(u64::from(u32::try_from(i).unwrap())))
            .unwrap();
    }
    let mut i = 16u64;
    c.bench_function("audit/append", |b| {
        b.iter(|| {
            let id = i;
            i += 1;
            log.append(record(id)).unwrap();
            black_box(id);
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let t = TempLog::new();
    {
        let mut log = AuditLog::open(&t.log(), &t.key()).unwrap();
        for i in 0..64 {
            log.append(record(i)).unwrap();
        }
    }
    let keypair = AuditKeypair::load_or_generate(&t.key()).unwrap();
    let pk = keypair.public_key_hex();
    c.bench_function("audit/verify_64", |b| {
        b.iter(|| {
            AuditLog::verify_file(black_box(&t.log()), black_box(&pk)).unwrap();
        });
    });
}

criterion_group!(benches, bench_append, bench_verify);
criterion_main!(benches);
