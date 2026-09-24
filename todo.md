# tpt-privd — Implementation Checklist

See `spec.txt` for the design spec and the "Resolved decisions
(2026-09-24)" section for the decisions this checklist assumes. Dual
license (MIT OR Apache-2.0, TPT Solutions) is already in place at repo
root as `LICENSE-MIT` / `LICENSE-APACHE`.

**Status (2026-09-25):** Phases 0–4, 6, 8 complete. Phase 5 & 7 code +
docs complete; Phase 5 manual Linux verification is automated by the I6
caps-harness CI job (still worth a one-time manual confirmation on a real
target). Phases 9–12 complete except I7 full `nixosTest` VM test.
All local gates green on Windows: `cargo test --workspace` (0 failures),
`cargo clippy --workspace --all-targets -- -D warnings` (clean),
scoped `cargo fmt -- --check` (clean), `cargo deny --all-features
check` (ok), `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps`
(clean), `cargo check -p tpt-privd-daemon --features otel` (clean),
`cargo run -p xtask -- packaging-check` (ok), `--print-schema` +
`explain-caps` smoke (ok).

**Open items (not blocked on code):**

1. Phase 5 — confirm caps-harness green on first push; optional extra
   manual check that a compromised connection handler cannot escalate
   past the dropped set (I6 covers CapEff shrink in CI).
2. Phase 7 — manual fuzz run: `cargo +nightly fuzz run decode` from
   `crates/tpt-privd-envelope/fuzz/` (target exists; needs nightly +
   Linux/macOS). Scheduled job in `.github/workflows/fuzz.yml`.
3. Unix-socket integration tests (`cfg(unix)`) run on Linux CI only —
   confirm the CI badge is green after first push.
4. I7 — full `nixosTest` VM integration once nested virt is available.

## Phase 0 — Workspace Bootstrap

- [x] `git init`, initial commit (spec.txt, todo.md, LICENSE-MIT,
      LICENSE-APACHE)
- [x] Root `Cargo.toml` as a workspace (`[workspace] members = [...]`),
      `license = "MIT OR Apache-2.0"` on every member crate
- [x] `.gitignore` (target/, Cargo.lock policy — commit it, this is a bin
      workspace)
- [x] `rustfmt.toml`, `clippy.toml` (deny warnings in CI)
- [x] `cargo-deny` config (license check, advisory check — match
      `tpt-linux-sandbox`'s existing setup for consistency; `wildcards`
      relaxed to `warn` because the sibling path dep uses path-only
      workspace deps)
- [x] CI workflow (build + test + clippy + fmt --check + cargo-deny on
      every push/PR; fmt job checks out sibling for path-dep resolution
      but runs `cargo fmt --` scoped to this workspace only)
- [x] Top-level `README.md` (what this is, why it exists, link to
      spec.txt, quickstart once Phase 6 lands)
- [x] Crate layout decision: confirm split into `tpt-privd-envelope`,
      `tpt-privd-transport`, `tpt-privd-policy`, `tpt-privd-audit`,
      `tpt-privd-daemon` (bin), `tpt-privd-client` vs. a flatter
      structure — record the choice in README before Phase 1 starts

## Phase 1 — Command Envelope (wire format)

- [x] Define `CommandId`, `Command { id, version, kind, payload }`,
      `CommandResult { id, outcome, audit_ref }`, `CommandSuccess`,
      `CommandError` types per spec's architecture section
- [x] `CommandKind` as an open/extensible enum (consumer-defined variants
      — decide the extension mechanism: enum with a catch-all
      `Custom(u32)` variant, or generic over a consumer-supplied kind
      type) — **decision: transparent `u32` newtype** with reserved
      built-ins and `CUSTOM_START = 0x8000_0000` consumer range (avoids
      generic parameter through transport/policy/audit; CBOR stays a bare
      integer)
- [x] serde `Serialize`/`Deserialize` derives; CBOR encode/decode via
      `serde_cbor` or `ciborium` (pick one, match what
      `tpt-protocol-tup` uses if reasonable for consistency) —
      **`ciborium` + serde** (spec explicitly says serde + CBOR; minicbor
      not used)
- [x] Envelope version negotiation/compat story (what happens when
      daemon and caller disagree on `version`) — strict equality on
      `ENVELOPE_VERSION = 1`; mismatch → audit `VersionMismatch` +
      structured `ErrorCode::UnsupportedVersion`, no execution; policy
      for future bumps in `CHANGELOG.md`
- [x] Unit tests: round-trip encode/decode, version mismatch rejection,
      malformed payload handling

## Phase 2 — Transport (Unix domain socket)

- [x] Socket listener setup (path, permissions/ownership so only the
      intended unprivileged caller can connect — `SO_PEERCRED` or
      equivalent for caller identification)
- [x] Message framing over the stream (length-prefixed CBOR frames;
      `[u32 BE len][payload]`, size checked before allocation)
- [x] Connection handling: one-shot request/reply per spec's synchronous
      execution semantics decision
- [x] Graceful handling of malformed/oversized frames, slow/hostile
      clients (timeouts, max frame size)
- [x] Integration test: real socket, real client connecting and getting
      a real `CommandResult` back (`cfg(unix)` — runs on Linux CI;
      in-memory framing tests run on Windows too)

## Phase 3 — Policy & Execution

- [x] `CommandExecutor` trait per spec (`policy_check`, `execute`)
- [x] Per-command-type policy check mechanism (bounding what a caller
      can do per `CommandKind`, e.g. "may only touch table X")
- [x] `PolicyViolation` error type with enough detail to audit-log
      meaningfully
- [x] Example/mock `CommandExecutor` implementation + mock `CommandKind`
      variants, used for integration tests (since no real consumer
      exists yet — see spec's resolved decisions)
- [x] Tests: policy accepts in-bounds commands, rejects out-of-bounds
      ones, rejection is itself audit-logged

## Phase 4 — Audit Log

- [x] Append-only file-backed log format (one record per line/frame,
      CBOR or a simpler line format — decide and document) — **JSONL**
      (documented in `docs/ARCHITECTURE.md`)
- [x] Hash chain: each record includes hash of previous record (mirror
      the shape of `tpt-citadel`'s `AuditRecord` for conceptual
      consistency, but implemented independently — no dependency)
- [x] Ed25519 signing of each record (or of periodic checkpoints —
      decide granularity), keypair provisioning story for the daemon —
      **per-record signatures** over SHA-256 hash; key auto-generated
      first run at 0600 (documented as dev convenience)
- [x] Tamper-evidence verification routine (replay the log, verify chain
      + signatures, detect breaks)
- [x] `AuditLogRef` wiring into `CommandResult`
- [x] Tests: tamper detection (corrupt a record, verify chain breaks),
      full replay/verify on a real log file, crash-during-write recovery
      behavior

## Phase 5 — Privilege Dropping

- [x] Add `tpt-linux-sandbox` (`tpt-l-sandbox`) as a path dependency
- [x] Daemon startup sequence: start with needed privileges/capabilities,
      immediately call into `Sandbox` builder (`.caps()`, `.seccomp()`,
      `.landlock()`, `.namespaces()`, `.apply()`) before accepting any
      connections — v1 configures `.caps()` only; other stages left for
      consumers to layer on (order documented in
      `docs/ARCHITECTURE.md`)
- [x] Define the minimum capability set for a first mock/example role
      (e.g. `CAP_NET_ADMIN`-shaped example, matching spec's own example)
- [ ] **(manual, Linux)** Verify that a compromised connection handler
      cannot escalate past the dropped capability set — needs a real
      Linux target; not possible from this Windows session
- [x] Document the capability-dropping sequence in README/architecture
      doc — this is a security-critical ordering, must be explicit

## Phase 6 — Daemon Binary & Client Library

- [x] `tpt-privd-daemon` bin: wires transport + policy/executor + audit
      log + privilege-dropping into a runnable daemon
- [x] Config (socket path, capability set, policy config, audit log
      path/keypair path) — file-based config, no hardcoding
- [x] Minimal `tpt-privd-client` library: connect, send `Command`,
      receive `CommandResult`, for use by the mock consumer and future
      real consumers
- [x] End-to-end example: client sends a mock command, daemon
      policy-checks, executes, audit-logs, returns result — runnable via
      `cargo run --example` (`cargo run -p tpt-privd-daemon --example
      e2e`; Unix-gated, prints an error on non-Unix)

## Phase 7 — Testing

- [x] Full integration test suite: socket round-trip, policy
      accept/reject, audit tamper-detection, privilege-drop verification
      (where CI environment allows) — 9 `cfg(unix)` e2e tests +
      in-memory framing tests; privilege-drop verification is a
      no-panic smoke test on non-Linux, real verification is the manual
      Phase 5 item above
- [x] Fuzz testing harness on the envelope decoder (malformed CBOR should
      never panic/crash the daemon) — `cargo-fuzz` target at
      `crates/tpt-privd-envelope/fuzz/`; not wired into CI (needs
      nightly + libFuzzer)
- [ ] **(manual)** Run the fuzz target at least once:
      `cargo +nightly fuzz run decode` — target is written; execution
      needs nightly + Linux/macOS, open this Windows session
- [x] Document what can and can't be tested in CI (Landlock/seccomp
      likely need a real Linux kernel, not all CI runners support this —
      note the gap, don't silently skip) — `docs/ARCHITECTURE.md`
      § Testing

## Phase 8 — Docs & Packaging

- [x] Architecture doc (expand on spec.txt's architecture section with
      the as-built crate layout and sequence diagrams for
      request→policy→execute→audit→reply) — `docs/ARCHITECTURE.md`
- [x] README usage section: how a new consumer repo defines its own
      `CommandKind` variants and policy, and depends on this crate
- [x] `CHANGELOG.md`, versioning policy for the envelope format going
      forward
- [x] Confirm every crate's `Cargo.toml` has correct `license`,
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

---

## Phase 9 — Bug fixes from code review (2026-09-24)

Findings from a full static review of all crates. `F#` ids are stable
for reference.

### Critical (breaks Linux CI / Linux compile)

- [x] **F1** `tpt-privd-client` does not compile on Unix: `encode(cmd)?`
      in `call_with_limits` produces `CodecError` but `ClientError` has
      no `From<CodecError>` — add a variant or map the error.
- [x] **F2** `tests/integration.rs` imports `MockExecutor` from
      `tpt_privd_daemon` (never re-exported) while also importing
      `PolicyMock` from policy — remove the bad import or re-export.
- [x] **F3** `tests/integration.rs` calls `libc::geteuid()` but daemon
      has no `libc` dev-dependency — add it (unix-only dev-dep preferred).

### High (integrity / security)

- [x] **F4** `peer.rs` uses Linux-only `SO_PEERCRED`/`libc::ucred` under
      plain `cfg(unix)` — fails to compile on macOS/BSD. Gate to
      `target_os = "linux"` (or add `LOCAL_PEERCRED` impls) and document
      the Unix support matrix honestly.
- [x] **F5** Second daemon start silently steals a live socket path +
      no single-instance lock → two writers corrupt the audit chain.
      Add a pid/flock lock file; refuse to unlink a socket that answers
      (or require `--force-stale`).
- [x] **F6** `execute` succeeds then `append_audit` fails → privileged
      side effect with no audit record and only a generic disconnect.
      Fail-stop: emit a loud fatal line with `command_id`/`kind` and
      terminate (or refuse further commands).
- [x] **F7** Partial audit append (ENOSPC mid-line) permanently bricks
      the log: next open sees a "complete" corrupt line. On any append
      error `set_len` back to last good offset; on open, terminate a
      valid final line that lacks `\\n`.

### Medium (usability / hardening)

- [x] **F8** Key file: write then chmod (world-readable window), no
      `O_EXCL`, no fsync, no permission check on reload. Use
      `create_new` + `mode(0o600)` + `sync_all`; verify mode on load.
- [x] **F10** Socket chmod/chown are path-based (TOCTOU); prefer
      `fchmod`/`fchown` on the listener fd or bind-temp+rename.
- [x] **F11** Client `call()` has no timeouts (server does) — add
      `ClientOptions` with connect/read/write timeouts, sane defaults.
- [x] **F12** Per-read timeout only (slow-loris), no execute deadline,
      accept-error tight loop — overall connection deadline + backoff.
- [x] **F13** Audit/key/log opens follow symlinks (`O_NOFOLLOW`
      recommended); log created 0644 by default — create 0600/0640.
- [x] **F14** Audit log file gets no restrictive mode on first create.
- [x] **F15** `credentials()` failure is fail-open (`uid: None`) —
      log + fail closed (or at least warn loudly); record pid/gid too.
- [x] **F16** Malformed frames leave zero audit trail — optional
      connection-level reject record / metric.
- [x] **F17** Integration tests race: client thread may `connect`
      before server binds — signal readiness via channel/`Barrier`.
- [x] **F18** `SocketConfig::with_owner` exists but `Config` has no
      owner fields; non-Linux `drop_privileges` stub is silent; default
      `caps.keep = [CAP_NET_ADMIN]` is too permissive for a mock.
- [x] **F19** Config: reject zero timeouts; require non-empty
      `audit_key_path`; validate cap names early.
- [x] **F20** `serve_listener`/`serve_one_connection`/`run_from_config`
      take concrete `&MockExecutor` — consumers cannot inject their own
      `CommandExecutor`. Change to `&dyn CommandExecutor` +
      `run_with(config, executor)`.
- [x] **F21** `AuditLog.records` grows unbounded; full-file re-verify on
      open is O(n) — keep head only + rotation/checkpoint later.
- [x] **F22** Fuzz package under workspace root but not in `members` /
      not `exclude`d / not `[workspace]`-standalone — `cargo fuzz` likely
      fails; fix membership.

### Low / polish

- [x] **L1** `TransportError::Timeout` is dead — map `WouldBlock`/`TimedOut`
      to it or remove.
- [x] **L2** `encode_result` failure mapped to `Decode` (mislabeled).
- [x] **L5** `sign_hash_hex` silently signs empty bytes on bad hex.
- [x] **L7** Blank line in audit log is a hard `CorruptRecord` — skip
      whitespace-only complete lines.
- [x] **L11** Client does not check `result.id == cmd.id`.
- [x] **L17** `--print-config` runs before `config.validate()`.
- [x] **L18** `socket_mode` must be decimal-encoded octal — accept
      `"0o660"` / `"0660"` strings via custom deserialize.
- [x] **L19** Dead confusing `verify_file("")` block in tamper test.
- [x] **L20** Empty `[dev-dependencies]` comment in transport.

## Phase 10 — Adoption & packaging

- [x] **A1** Example consumer crate/example: real `CommandExecutor`
      (not `MockExecutor`) + `run_with` + client call — the "copy this"
      path for a new repo.
- [x] **A2** CLI subcommands: `run` (default), `verify-audit --log
      [--key]`, `call --socket --kind --payload` (or separate bin).
- [x] **A3** `config.example.toml` with every key commented; wire into
      `--help` / README.
- [x] **A4** Config discovery when `--config` unset: `$TPRIVD_CONFIG`,
      `$XDG_CONFIG_HOME/tpt-privd/config.toml`,
      `/etc/tpt-privd/config.toml`, then defaults **with a stderr
      warning**.
- [x] **A5** Per-crate `README.md` + `readme` field +
      `[package.metadata.docs.rs]` + `exclude = ["fuzz"]` on envelope.
- [x] **A6** `SECURITY.md` (disclosure contact, scope) +
      `CONTRIBUTING.md` (sibling checkout layout, the four gates).
- [x] **A7** Publish order documented (envelope → transport/policy/audit
      → client → daemon); note `tpt-l-sandbox` crates.io blocker
      (feature-gate or publish sibling first).
- [x] **A8** systemd unit + tmpfiles.d + example install notes
      (`docs/DEPLOYMENT.md`).

## Phase 11 — Automation & CI hardening

- [x] **C1** MSRV job: `dtolnay/rust-toolchain@1.85` + `cargo check
      --workspace --all-targets`.
- [x] **C2** Docs job: `RUSTDOCFLAGS="-D warnings" cargo doc
      --workspace --no-deps`.
- [x] **C3** Dependabot for `cargo` + `github-actions` (weekly).
- [x] **C4** Release automation notes: publish order + blocker in
      `docs/DEPLOYMENT.md`; `cargo xtask publish-order` prints topo
      order; changelog policy documented. Full `release-plz` workflow
      still optional until crates are on crates.io.
- [x] **C5** Optional tooling: scheduled fuzz workflow
      (`.github/workflows/fuzz.yml`) + non-blocking `cargo-semver-checks`
      job; coverage badge deferred until a coverage service is chosen.

## Phase 12 — Innovation / differentiators (pick after 9–11)

- [x] **I1** systemd **socket activation** (`LISTEN_FDS`): transport
      `systemd_listener`/`listener_from_fd`, `socket_activation` config,
      `packaging/tpt-privd.socket`, DEPLOYMENT notes.
- [x] **I2** Seccomp wiring: `[seccomp]` config (default off),
      empty-allowlist rejected at validate, `Sandbox::seccomp` after
      caps. **`explain-caps`:** `CommandExecutor::required_caps` +
      CLI `explain-caps --kind` vs config `[caps] keep`.
- [x] **I3** Metrics via built-in `CommandKind::METRICS` (2): Prometheus
      text over the audited channel, process counters, mock executor +
      handle intercept.
- [x] **I4** OpenTelemetry export behind cargo feature `otel`
      (`tracing-opentelemetry` + stdout span exporter; CI checks
      `--features otel`).
- [x] **I5** Audit shipper: `AuditSink` + `MemorySink` / `JsonlMirrorSink` /
      `AuditShipper` channel + `spawn_audit_shipper`; local JSONL chain
      stays authoritative; sink failures never roll back an append.
- [x] **I6** Container/root test harness: `examples/caps_probe` +
      `packaging/Dockerfile.caps-harness` + `verify-caps.sh` + CI job
      asserting CapEff shrinks after `drop_privileges`.
- [x] **I7** Nix flake: `flake.nix` packages workspace with sibling
      `tpt-linux-sandbox` as a flake input (`nix build` / `nix flake
      check`). Full `nixosTest` VM deferred (needs nested virt).
- [x] **I8** Config JSON Schema (`schemars`) + `deny_unknown_fields` +
      `--print-schema`.
- [x] **I9** `cargo xtask` (`gates` / `schema` / `check-schema` /
      `publish-order` / `fuzz-check` / `packaging-check`) + alias in
      `.cargo/config.toml`.
- [x] **I10** Consumer scaffold under `templates/consumer/` (copy-in /
      cargo-generate ready).
- [x] **I11** Tracing (`tracing` + `tracing-subscriber` + `RUST_LOG`,
      default `info`) replacing `eprintln!` in serve/handle hot paths.
- [x] **I12** Criterion benches: envelope codec, transport frame,
      audit append/verify.

### Spec fidelity notes (track, don't silently diverge)

- ~~Socket **ownership** is not reachable from daemon `Config` yet~~ —
  `socket_owner_uid`/`socket_owner_gid` added (F18).
- v1 drops **capabilities only**, not uid (documented; uid drop is
  future work with ownership handoff order).
- `seccomp` is now optional from config (I2); `landlock`/`namespaces`
  builder stages exist upstream but are not wired from config.
- `CommandExecutor::execute` returns `Result<CommandSuccess,
  CommandError>` rather than a bare `CommandResult` (arguably better —
  note in ARCHITECTURE).
