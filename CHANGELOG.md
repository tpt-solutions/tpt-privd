# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Envelope format versioning policy

The wire envelope carries an explicit `version: u32` field, currently
`ENVELOPE_VERSION = 1` (`tpt-privd-envelope`).

- **Patch / minor crate releases** do not change `ENVELOPE_VERSION`.
- **Any change to the CBOR shape or semantics of `Command` /
  `CommandResult`** bumps `ENVELOPE_VERSION`. This is a **breaking wire
  change** for every consumer: the daemon rejects mismatched versions with
  `ErrorCode::UnsupportedVersion` (audited as `VersionMismatch`) and does
  not execute.
- There is **no forward- or backward-compatible minor-version negotiation**
  in v1. A consumer and daemon must speak the exact same
  `ENVELOPE_VERSION`. If compatibility windows are ever needed, they will
  be designed explicitly (and recorded here) rather than assumed.
- `ErrorCode` and `AuditOutcome` are `#[non_exhaustive]` — new variants
  may be added in minor releases; consumers must handle unknown variants
  gracefully. The audit canonical form assigns unknown `ErrorCode`s a
  distinct tag (255) so future variants do not collide with existing tags.

## [Unreleased]

### Added

- Workspace bootstrap: dual MIT/Apache-2.0 license metadata, rustfmt,
  clippy (pedantic, workspace lints), cargo-deny, GitHub Actions CI
  (test + clippy + fmt + deny + MSRV 1.85 + docs), Dependabot
  (cargo + github-actions), README, architecture doc, `SECURITY.md`,
  `CONTRIBUTING.md`, `docs/DEPLOYMENT.md` (systemd unit + tmpfiles.d).
- `tpt-privd-envelope`: `Command` / `CommandResult` / `CommandKind` (open
  `u32` enum with `CUSTOM_START` consumer range), CBOR codec via
  `ciborium`, `ENVELOPE_VERSION` gate, round-trip and malformed-input
  tests. Crate README, `readme` + docs.rs metadata, `exclude = ["fuzz"]`.
- `tpt-privd-transport`: length-prefixed framing (hostile-length
  rejection before allocation), Unix domain socket bind/connect with
  mode/ownership via `fchmod`/`fchown` on the listener fd (F10),
  live-socket refusal (F5), `SO_PEERCRED` peer credentials (Linux),
  one-shot `serve_one`, read/write timeouts mapped to
  `TransportError::Timeout` (L1).
- `tpt-privd-policy`: `CommandExecutor` trait, `PolicyViolation`,
  `MockExecutor` with built-in `NOP`/`ECHO` plus configurable custom
  allowlist.
- `tpt-privd-audit`: append-only JSONL log, fixed-order canonical hash
  form, SHA-256 hash chain, per-record Ed25519 signatures, torn-tail
  crash recovery, append rollback (F7), full replay verification,
  keypair load-or-generate (`create_new` + 0600 + fsync, F8),
  `O_NOFOLLOW` opens (F13), bounded in-memory record cache (F21),
  blank-line skip (L7), `sign_hash_hex` rejects bad input (L5).
- `tpt-privd-client`: one-shot `call` / `call_with_options` /
  `call_with_limits` with connect/read/write timeouts (F11), result id
  check (L11), `Encode`/`IdMismatch` errors (F1).
- `tpt-privd-daemon`: TOML config with discovery (`$TPRIVD_CONFIG`,
  XDG, `/etc`, defaults + warning), validation (zero timeouts, empty
  paths — F19), `--check`/`--print-config` (L17), socket mode octal
  strings (L18), CLI subcommands `verify-audit` and `call` (A2),
  capability drop via `tpt-l-sandbox` path dependency (Linux), accept
  loop with overall connection deadline + execute soft timeout (F12),
  accept-error backoff and peercred fail-closed (F15), fail-stop on
  audit append failure (F6), request pipeline
  (version → policy → execute → audit → reply), malformed CBOR
  transport-reject audit record (F16), end-to-end +
  `custom_consumer` examples, Unix-socket integration tests with
  readiness channel (F17), `cargo-fuzz` target for the envelope
  decoder (standalone workspace, F22).
- Publish order + `tpt-l-sandbox` crates.io blocker documented in
  `docs/DEPLOYMENT.md` (A7).
- Phase 12 (partial): systemd socket activation (`LISTEN_FDS`,
  `packaging/tpt-privd.socket`, I1); optional seccomp config wiring
  after caps (I2, default off) + `explain-caps` CLI vs
  `CommandExecutor::required_caps` (I2); built-in
  `CommandKind::METRICS` (2) Prometheus text over the audited channel
  with process counters (I3); `schemars` JSON Schema +
  `deny_unknown_fields` + `--print-schema` (I8); `cargo xtask`
  gates/schema/publish-order/packaging-check (I9); consumer scaffold
  `templates/consumer/` (I10); `tracing` +
  `RUST_LOG` replacing hot-path `eprintln!` (I11); Criterion benches
  for envelope/transport/audit (I12). Scheduled fuzz +
  non-blocking `cargo-semver-checks` workflow (C5).
- Phase 12 continued: OpenTelemetry export behind cargo feature `otel`
  (`tracing-opentelemetry` + stdout span exporter, CI-checked) (I4);
  audit shipper (`AuditSink` / `MemorySink` / `JsonlMirrorSink` /
  `AuditShipper` + `spawn_audit_shipper`; local chain remains
  authoritative) (I5); root CapEff harness (`examples/caps_probe`,
  `packaging/Dockerfile.caps-harness`, `verify-caps.sh`, CI job) (I6);
  Nix flake with sibling `tpt-linux-sandbox` as a flake input (I7 —
  full `nixosTest` VM deferred).

## [0.1.0] — unreleased

Initial implementation of Phases 0–8 per `todo.md`.
