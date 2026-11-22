# Changelog

All notable changes to `tpt-privd-audit` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Append-only JSONL audit log (`AuditLog`) with fixed-order canonical hash
  form, SHA-256 hash chain, and per-record Ed25519 signatures.
- `AuditRecord`, `AuditOutcome`, and `NewRecord`. Payloads are recorded as
  SHA-256 digests only.
- `verify` / `verify_file` full replay verification and `verify_chain` with
  `ChainReport` and `ChainBreak` reporting the first diverging `seq`.
- `AuditKeypair` load-or-generate (`create_new`, mode `0600`, `fsync`) and
  `verify_signature_hex`.
- Torn-tail crash recovery on open, and append rollback when a write fails.
- `O_NOFOLLOW` opens for the log and key files.
- Bounded in-memory record cache.
- `AuditSink` trait with `MemorySink`, `JsonlMirrorSink`, `FnSink`,
  `spawn_audit_shipper`, and `format_summary`. Sink failures never block
  appends.
- `sign_hash_hex` rejects malformed input instead of panicking.
- `chain` benchmark.
