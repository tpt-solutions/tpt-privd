# tpt-privd — Implementation Checklist

See `spec.txt` for the design spec and the "Resolved decisions
(2026-09-24)" section for the decisions this checklist assumes. Dual
license (MIT OR Apache-2.0, TPT Solutions) is already in place at repo
root as `LICENSE-MIT` / `LICENSE-APACHE`.

## Phase 0 — Workspace Bootstrap

- [ ] `git init`, initial commit (spec.txt, todo.md, LICENSE-MIT,
      LICENSE-APACHE)
- [ ] Root `Cargo.toml` as a workspace (`[workspace] members = [...]`),
      `license = "MIT OR Apache-2.0"` on every member crate
- [ ] `.gitignore` (target/, Cargo.lock policy — commit it, this is a bin
      workspace)
- [ ] `rustfmt.toml`, `clippy.toml` (deny warnings in CI)
- [ ] `cargo-deny` config (license check, advisory check — match
      `tpt-linux-sandbox`'s existing setup for consistency)
- [ ] CI workflow (build + test + clippy + fmt --check + cargo-deny on
      every push/PR)
- [ ] Top-level `README.md` (what this is, why it exists, link to
      spec.txt, quickstart once Phase 6 lands)
- [ ] Crate layout decision: confirm split into `tpt-privd-envelope`,
      `tpt-privd-transport`, `tpt-privd-policy`, `tpt-privd-audit`,
      `tpt-privd-daemon` (bin), `tpt-privd-client` vs. a flatter
      structure — record the choice in README before Phase 1 starts

## Phase 1 — Command Envelope (wire format)

- [ ] Define `CommandId`, `Command { id, version, kind, payload }`,
      `CommandResult { id, outcome, audit_ref }`, `CommandSuccess`,
      `CommandError` types per spec's architecture section
- [ ] `CommandKind` as an open/extensible enum (consumer-defined variants
      — decide the extension mechanism: enum with a catch-all
      `Custom(u32)` variant, or generic over a consumer-supplied kind
      type)
- [ ] serde `Serialize`/`Deserialize` derives; CBOR encode/decode via
      `serde_cbor` or `ciborium` (pick one, match what
      `tpt-protocol-tup` uses if reasonable for consistency)
- [ ] Envelope version negotiation/compat story (what happens when
      daemon and caller disagree on `version`)
- [ ] Unit tests: round-trip encode/decode, version mismatch rejection,
      malformed payload handling

## Phase 2 — Transport (Unix domain socket)

- [ ] Socket listener setup (path, permissions/ownership so only the
      intended unprivileged caller can connect — `SO_PEERCRED` or
      equivalent for caller identification)
- [ ] Message framing over the stream (length-prefixed CBOR frames)
- [ ] Connection handling: one-shot request/reply per spec's synchronous
      execution semantics decision
- [ ] Graceful handling of malformed/oversized frames, slow/hostile
      clients (timeouts, max frame size)
- [ ] Integration test: real socket, real client connecting and getting
      a real `CommandResult` back

## Phase 3 — Policy & Execution

- [ ] `CommandExecutor` trait per spec (`policy_check`, `execute`)
- [ ] Per-command-type policy check mechanism (bounding what a caller
      can do per `CommandKind`, e.g. "may only touch table X")
- [ ] `PolicyViolation` error type with enough detail to audit-log
      meaningfully
- [ ] Example/mock `CommandExecutor` implementation + mock `CommandKind`
      variants, used for integration tests (since no real consumer
      exists yet — see spec's resolved decisions)
- [ ] Tests: policy accepts in-bounds commands, rejects out-of-bounds
      ones, rejection is itself audit-logged

## Phase 4 — Audit Log

- [ ] Append-only file-backed log format (one record per line/frame,
      CBOR or a simpler line format — decide and document)
- [ ] Hash chain: each record includes hash of previous record (mirror
      the shape of `tpt-citadel`'s `AuditRecord` for conceptual
      consistency, but implemented independently — no dependency)
- [ ] Ed25519 signing of each record (or of periodic checkpoints —
      decide granularity), keypair provisioning story for the daemon
- [ ] Tamper-evidence verification routine (replay the log, verify chain
      + signatures, detect breaks)
- [ ] `AuditLogRef` wiring into `CommandResult`
- [ ] Tests: tamper detection (corrupt a record, verify chain breaks),
      full replay/verify on a real log file, crash-during-write recovery
      behavior

## Phase 5 — Privilege Dropping

- [ ] Add `tpt-linux-sandbox` (`tpt-l-sandbox`) as a path dependency
- [ ] Daemon startup sequence: start with needed privileges/capabilities,
      immediately call into `Sandbox` builder (`.caps()`, `.seccomp()`,
      `.landlock()`, `.namespaces()`, `.apply()`) before accepting any
      connections
- [ ] Define the minimum capability set for a first mock/example role
      (e.g. `CAP_NET_ADMIN`-shaped example, matching spec's own example)
- [ ] Verify (manually, on Linux) that a compromised connection handler
      cannot escalate past the dropped capability set
- [ ] Document the capability-dropping sequence in README/architecture
      doc — this is a security-critical ordering, must be explicit

## Phase 6 — Daemon Binary & Client Library

- [ ] `tpt-privd-daemon` bin: wires transport + policy/executor + audit
      log + privilege-dropping into a runnable daemon
- [ ] Config (socket path, capability set, policy config, audit log
      path/keypair path) — file-based config, no hardcoding
- [ ] Minimal `tpt-privd-client` library: connect, send `Command`,
      receive `CommandResult`, for use by the mock consumer and future
      real consumers
- [ ] End-to-end example: client sends a mock command, daemon
      policy-checks, executes, audit-logs, returns result — runnable via
      `cargo run --example`

## Phase 7 — Testing

- [ ] Full integration test suite: socket round-trip, policy
      accept/reject, audit tamper-detection, privilege-drop verification
      (where CI environment allows)
- [ ] Fuzz testing on the envelope decoder (malformed CBOR should never
      panic/crash the daemon)
- [ ] Document what can and can't be tested in CI (Landlock/seccomp
      likely need a real Linux kernel, not all CI runners support this —
      note the gap, don't silently skip)

## Phase 8 — Docs & Packaging

- [ ] Architecture doc (expand on spec.txt's architecture section with
      the as-built crate layout and sequence diagrams for
      request→policy→execute→audit→reply)
- [ ] README usage section: how a new consumer repo defines its own
      `CommandKind` variants and policy, and depends on this crate
- [ ] `CHANGELOG.md`, versioning policy for the envelope format going
      forward
- [ ] Confirm every crate's `Cargo.toml` has correct `license`,
      `description`, `repository` metadata before any publish

## Deferred (explicitly out of scope for now — revisit when noted)

- **vsock / remote transport** — deferred until `tpt-quorum`'s 2-node
  failover design exists and settles whether a standby node needs to
  issue commands to the active node's `privd`.
- **Async job/ticket model for long-running commands** — deferred until
  `tpt-netctl`'s actual apply latency is measured against a real
  ruleset; don't design this speculatively.
- **Multi-tenant / multi-consumer daemon with per-caller policy
  scoping** — deferred until a second real consumer repo exists to
  validate the scoping model against; v1 targets single-daemon,
  single-caller-per-socket.
- **Any domain-specific `CommandKind` vocabulary** (firewall rules, GPIO
  pins, etc.) — explicitly out of scope per spec; each consumer repo
  layers its own command types on top of this crate.
