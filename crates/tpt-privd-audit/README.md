# tpt-privd-audit

[![Crates.io](https://img.shields.io/crates/v/tpt-privd-audit.svg)](https://crates.io/crates/tpt-privd-audit)
[![Docs.rs](https://docs.rs/tpt-privd-audit/badge.svg)](https://docs.rs/tpt-privd-audit)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)

An append-only, hash-chained, Ed25519-signed audit log for
[`tpt-privd`](../../README.md). Every command the daemon sees, whether it was
executed, denied, or rejected, produces one record. Any later change to the
file breaks verification at the exact record where history diverges.

The crate is useful on its own. An operator can verify a log offline with
the public key alone, without running the daemon.

## Contents

- [What is recorded](#what-is-recorded)
- [On-disk format](#on-disk-format)
- [Integrity model](#integrity-model)
- [Keys](#keys)
- [Writing records](#writing-records)
- [Verifying a log](#verifying-a-log)
- [Sinks](#sinks)
- [Crash recovery](#crash-recovery)
- [Example](#example)
- [Security notes](#security-notes)
- [License](#license)

## What is recorded

Each `AuditRecord` stores metadata, not payloads:

| Field | Content |
|---|---|
| `seq` | Zero-based position in the log. |
| `ts_ms` | Event time in Unix milliseconds. |
| `command_id`, `command_version`, `command_kind` | Identity of the command. |
| `payload_sha256` | SHA-256 digest of the request payload. |
| `caller_uid` | Peer uid from `SO_PEERCRED` when available. |
| `outcome` | `AuditOutcome`: `Executed`, `PolicyDenied`, `ExecutionFailed`, `VersionMismatch`, or `InternalError`. |
| `error_code` | Optional `ErrorCode` returned to the caller. |
| `result_sha256` | Optional digest of the result payload. |
| `prev_hash`, `hash`, `sig` | Chain and signature fields (see below). |

Payloads are never stored. The log stays small, and it does not persist
bytes that a consumer might later classify as sensitive. Keep the original
payload in your own system if you need it, and match it by digest.

## On-disk format

The log is JSON Lines: one record per line, with binary fields
hex-encoded.

```json
{"seq":0,"command_id":1,"command_kind":1,"outcome":"executed", "...":"...","prev_hash":"00…00","hash":"9f…","sig":"3a…"}
```

JSON was chosen so an auditor can read the log with `jq` or `grep` without
special tooling. Integrity does **not** depend on JSON text. Hashes and
signatures are computed over a fixed-order binary canonical form, exposed as
`AuditRecord::canonical_bytes`. Two JSON encodings of the same record hash
identically.

## Integrity model

- **Chain.** `prev_hash` is the previous record's `hash`. The first record
  uses 32 zero bytes. Deleting, reordering, or editing any record breaks the
  chain at that point.
- **Hash.** `hash` is SHA-256 over the canonical bytes, which include
  `prev_hash`.
- **Signature.** `sig` is an Ed25519 signature over `hash`, made with the
  daemon's signing key.

Signing is **per record**, not in periodic checkpoints. Ed25519 is cheap
enough for this, and no record is ever unsigned, even briefly.

Limits to be aware of: a party holding the signing key can forge a new,
consistent chain. Protect the key (see below), and ship log copies off the
host if you need protection against a host-level attacker who can rewrite
the file.

## Keys

`AuditLog::open(log_path, key_path)` loads the Ed25519 secret seed at
`key_path`. On first run it generates one and writes it with mode `0600`,
using `create_new` and `fsync`.

Auto-generation is a development convenience. In production, provision the
key with configuration management and make sure the daemon's user is the
only reader. The public key is available from `public_key_hex()` and is
embedded in verification reports.

`AuditKeypair` is available if you manage keys yourself, and its
`sign_hash_hex` rejects malformed input rather than panicking.
`verify_signature_hex` checks one signature without opening a log.

## Writing records

```rust
use tpt_privd_audit::{AuditLog, AuditOutcome, NewRecord};
use tpt_privd_envelope::{CommandId, CommandKind};

let mut log = AuditLog::open(
    std::path::Path::new("/var/lib/tpt-privd/audit.jsonl"),
    std::path::Path::new("/var/lib/tpt-privd/audit.key"),
)?;

let record = log.append(NewRecord {
    command_id: CommandId(42),
    command_version: 1,
    command_kind: CommandKind::ECHO,
    payload_sha256: [0u8; 32],
    caller_uid: Some(1000),
    outcome: AuditOutcome::Executed,
    error_code: None,
    result_sha256: None,
})?;
println!("appended seq {}", record.seq);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`append` writes one line and syncs it. If the write fails, the in-memory
state is rolled back, so the next append continues the chain correctly.
`records()` returns the cached records, bounded in memory. Records remain
on disk, and `verify()` reads the whole file.

## Verifying a log

From code:

```rust,ignore
let report = tpt_privd_audit::AuditLog::verify_file(path, public_key_hex)?;
println!("verified {} records", report.records_verified);
```

From the daemon CLI (uses the log's embedded key unless you pass one):

```sh
tpt-privd-daemon verify-audit /var/lib/tpt-privd/audit.jsonl \
  --key /etc/tpt-privd/audit.key
```

`verify_chain(&records, public_key_hex)` runs the same checks over records
you have already loaded. On failure it returns a `ChainBreak` naming the
`seq` where verification first fails, so an investigator knows where to
look.

Verification checks, for every record:

1. `prev_hash` equals the previous record's `hash`.
2. `hash` matches a fresh SHA-256 of the canonical bytes.
3. `sig` verifies against the public key.

Run it on a timer or from a log-shipping job. A failure is a security event.

## Sinks

Local JSONL is the authoritative record. Optional `AuditSink`s receive a
copy after each durable append:

| Sink | Purpose |
|---|---|
| `MemorySink` | Collects records in memory, for tests and short-lived tooling. |
| `JsonlMirrorSink` | Writes a second JSONL file, for example on another volume. |
| `FnSink` | Wraps a closure. |
| `spawn_audit_shipper` | Background thread that forwards records over a channel to a shipper. |

Attach sinks with `AuditLog::add_sink`. A sink failure never rolls back or
blocks an append. The local file remains the source of truth, so a broken
shipper cannot stop command processing. `format_summary` renders one record
as a single human-readable line.

## Crash recovery

- A torn final line, left by a crash mid-write, is detected on `open` and
  truncated. Complete lines are always parseable.
- Blank lines are skipped on read.
- Opens use `O_NOFOLLOW` where available, so a symlink planted at the log or
  key path is refused.

## Example

The doctest above writes into a temporary directory and verifies the result.
For a full flow with the daemon, run:

```sh
cargo run -p tpt-privd-daemon --example e2e
```

## Benchmarks

```sh
cargo bench -p tpt-privd-audit
```

The `chain` benchmark measures append and verify cost against log length.

## Security notes

- Protect the signing key. Mode `0600`, owned by the daemon user, and
  provisioned outside the daemon in production.
- Verify logs from a machine that does not hold the signing key, when you
  need an independent check.
- The log holds caller uids and command metadata. Treat it as sensitive, and
  restrict read access.
- Disk exhaustion makes appends fail. The daemon fails stop rather than run
  unaudited. This is intentional.

## Minimum supported Rust version

1.85, edition 2024.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE)
or [MIT license](../../LICENSE-MIT), at your option.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
