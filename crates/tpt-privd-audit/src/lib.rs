//! Append-only, Ed25519-signed, hash-chained audit log for `tpt-privd`.
//!
//! # Format decision (JSON Lines)
//!
//! Each record is one JSON object per line (JSONL / NDJSON) with
//! hex-encoded binary fields. Chosen over raw CBOR frames because:
//!
//! - **Human-readable / greppable** — an auditor can `jq` or `grep` the log
//!   without bespoke tooling.
//! - **Crash-safe** — a partial write at the end of file leaves a truncated
//!   final line that [`AuditLog::open`] detects and truncates; complete
//!   lines are always parseable.
//! - **Append-only friendly** — one `write` of `record + '\n'` per command.
//!
//! The *integrity* of each record does not depend on JSON canonicalization:
//! the chain hash and Ed25519 signature are computed over a **fixed-order
//! binary canonical form** (see [`AuditRecord::canonical_bytes`]), not over
//! the JSON text. Two encodings of the same logical record therefore always
//! hash identically.
//!
//! # Hash chain + signatures
//!
//! Each record stores:
//! - `prev_hash` — SHA-256 of the previous record's `hash` (all-zero for
//!   the first record), forming a tamper-evident chain.
//! - `hash` — SHA-256 of this record's canonical bytes (which embed
//!   `prev_hash`).
//! - `sig` — Ed25519 signature **over `hash`**, made with the daemon's
//!   signing key.
//!
//! Signing granularity is **per record** (not periodic checkpoints): with
//! Ed25519 this is cheap, and it means every single line is independently
//! non-repudiable — no window where a batch of records is unsigned.
//!
//! [`AuditLog::verify`] replays the whole file, checks the chain links,
//! recomputes every hash, and verifies every signature against the embedded
//! public key (or a caller-supplied one). Any corruption, reordering,
//! deletion of a middle record, or bit-flip causes verification to fail at
//! the exact `seq` where history diverges.
//!
//! # Key provisioning
//!
//! [`AuditLog::open`] generates a fresh Ed25519 keypair on first use and
//! writes the secret seed to `secret_key_path` with mode `0600` (Unix).
//! The public key is stored in every record's companion metadata and also
//! returned by [`AuditLog::public_key_hex`]. For production, provision the
//! secret key externally (file provisioned by config management, or a
//! future HSM/kms path) rather than letting the daemon auto-generate it —
//! auto-generation is a development convenience, documented as such.
//!
//! # What is stored
//!
//! Full command/result payloads are **not** retained — only their SHA-256
//! digests plus metadata (id, version, kind, caller uid, outcome code).
//! This bounds log growth and avoids persisting payload bytes that a
//! consumer might later classify as sensitive.
//!
//! # Secondary sinks (I5)
//!
//! After each durable local append, optional [`AuditSink`]s are notified
//! (memory collector, JSONL mirror, channel shipper). The **local JSONL
//! file remains the authoritative chain** — sink failures never roll back
//! or block an append. See [`AuditLog::add_sink`] and
//! [`spawn_audit_shipper`].
//!
//! # Example
//!
//! ```
//! use tpt_privd_audit::{AuditLog, AuditOutcome, NewRecord};
//! use tpt_privd_envelope::{CommandId, CommandKind};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = std::env::temp_dir().join(format!(
//!     "tpt-privd-audit-doc-{}",
//!     std::process::id()
//! ));
//! std::fs::create_dir_all(&dir)?;
//! let log_path = dir.join("audit.jsonl");
//! let key_path = dir.join("audit.key");
//!
//! let mut log = AuditLog::open(&log_path, &key_path)?;
//! let rec = log.append(NewRecord {
//!     command_id: CommandId(1),
//!     command_version: 1,
//!     command_kind: CommandKind::ECHO,
//!     payload_sha256: [0u8; 32],
//!     caller_uid: Some(1000),
//!     outcome: AuditOutcome::Executed,
//!     error_code: None,
//!     result_sha256: None,
//! })?;
//!
//! let report = log.verify()?;
//! assert!(report.records_verified > 0);
//! assert_eq!(rec.seq, 0);
//!
//! let _ = std::fs::remove_dir_all(&dir);
//! # Ok(())
//! # }
//! ```

#![deny(missing_docs)]

mod chain;
mod keypair;
mod log;
mod record;
mod sink;

pub use chain::{ChainBreak, ChainReport, verify_chain};
pub use keypair::{AuditKeypair, KeypairError, verify_signature_hex};
pub use log::{AuditLog, LogError, NewRecord, sha256_hex};
pub use record::{AuditOutcome, AuditRecord};
pub use sink::{
    AuditShipper, AuditSink, FnSink, JsonlMirrorSink, MemorySink, ShipperError, SinkError,
    format_summary, spawn_audit_shipper,
};
