# tpt-privd

Privileged command daemon: an unprivileged control surface sends typed,
versioned commands over a local Unix socket; a privileged daemon
policy-checks, executes, append-only audit-logs every outcome, and drops
capabilities before accepting a single connection.

[![CI](https://github.com/TPT-Solutions/tpt-privd/actions/workflows/ci.yml/badge.svg)](https://github.com/TPT-Solutions/tpt-privd/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

**Design spec:** [`spec.txt`](spec.txt) · **Architecture (as-built):**
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · **Deployment:**
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) · **Checklist:**
[`todo.md`](todo.md) · **Changelog:** [`CHANGELOG.md`](CHANGELOG.md) ·
**Contributing:** [`CONTRIBUTING.md`](CONTRIBUTING.md) (issues only)

---

## Why this exists

Anything that manages host-level state (network config, filesystem changes,
service restarts) faces the same tension: the process handling user requests
should not itself run with root or elevated capabilities, but *something*
has to make the privileged change. OPNsense solves this with `configd`.
`tpt-privd` is that pattern as reusable shared plumbing for the TPT
portfolio — the generic envelope, transport, policy, audit, and
privilege-drop sequence, with **no domain-specific command vocabulary**.

Each consumer repo layers its own `CommandKind` values and policy on top.

## Crate layout (confirmed)

Split into six crates rather than one flat package, so consumers can depend
on only the envelope (for wire compatibility) without pulling in the daemon:

| Crate | Role |
|---|---|
| `tpt-privd-envelope` | `Command` / `CommandResult` types, CBOR codec, version gate |
| `tpt-privd-transport` | Length-prefixed framing + Unix socket listener/client + `SO_PEERCRED` |
| `tpt-privd-policy` | `CommandExecutor` trait, `PolicyViolation`, `MockExecutor` |
| `tpt-privd-audit` | Append-only JSONL log, SHA-256 hash chain, Ed25519 per-record signatures |
| `tpt-privd-client` | Thin client: connect, send one `Command`, read one `CommandResult` |
| `tpt-privd-daemon` | Binary (and lib): config, wiring, capability drop, accept loop |

Rationale for the split (recorded before Phase 1 per the checklist):
envelope and audit are independently reusable (a consumer might verify an
audit log offline without running the daemon); transport/policy form the
daemon's spine; keeping the binary separate lets tests drive the full
request path in-process.

## Quickstart

Requires a Unix-like OS for the full daemon path (Unix domain sockets;
Linux for capability dropping). Envelope/policy/audit unit tests run
everywhere, including Windows.

```sh
# Full workspace tests
cargo test --workspace

# End-to-end example: binds a real socket, runs echo + policy deny +
# allowlisted custom kind, verifies the audit chain — all in-process,
# no root required.
cargo run -p tpt-privd-daemon --example e2e

# Run the daemon itself (Linux; typically as root so it can bind the
# socket and drop caps afterward)
cargo run -p tpt-privd-daemon -- --config /etc/tpt-privd/config.toml

# Validate config / print resolved config / print JSON Schema
cargo run -p tpt-privd-daemon -- --check --config crates/tpt-privd-daemon/config.example.toml
cargo run -p tpt-privd-daemon -- --print-schema

# Offline audit verification (chain + signatures)
cargo run -p tpt-privd-daemon -- verify-audit /var/lib/tpt-privd/audit.jsonl

# One-shot client against a running daemon (kind 1 = ECHO, 2 = METRICS)
cargo run -p tpt-privd-daemon -- call \
  --socket /run/tpt-privd/privd.sock --kind 1 --payload hello

# Capability calculator vs [caps] keep (I2)
cargo run -p tpt-privd-daemon -- explain-caps --kind 1

# Workspace gates (I9)
cargo xtask gates
cargo xtask packaging-check
```

Config discovery when `--config` is unset: `$TPRIVD_CONFIG`,
`$XDG_CONFIG_HOME/tpt-privd/config.toml`,
`$HOME/.config/tpt-privd/config.toml`, `/etc/tpt-privd/config.toml`,
then built-in defaults with a stderr warning.

Example config (see `crates/tpt-privd-daemon/config.example.toml` for
every key commented):

```toml
socket_path = "/run/tpt-privd/privd.sock"
socket_mode = "0o660"           # or decimal 432 — TOML has no octal
socket_activation = false       # true: inherit systemd LISTEN_FDS (I1)
audit_log_path = "/var/lib/tpt-privd/audit.jsonl"
audit_key_path = "/var/lib/tpt-privd/audit.key"

[caps]
drop_all = true
keep = ["CAP_NET_ADMIN"]         # mock/example role (spec's illustration)

[seccomp]
enabled = false                  # I2 (experimental, Linux): default-deny
allow = []
on_deny = "kill"                 # or "errno" while bring-up-testing

[limits]
max_frame_size = 1048576
read_timeout_ms = 5000
write_timeout_ms = 5000
execute_timeout_ms = 30000

# Allowlisted custom CommandKind values for the MockExecutor stand-in.
# Built-ins: NOP=0, ECHO=1, METRICS=2 (Prometheus text over audited channel).
allowed_custom_kinds = [2147483649]
```

## Capability dropping (security-critical ordering)

The daemon's startup order is **not** arbitrary — it is the whole point of
the design:

1. Parse and validate config.
2. Open the audit log (load or first-run generate the Ed25519 key).
3. Bind the Unix socket (or inherit a systemd-activated fd) and set
   mode/ownership on the socket file when binding ourselves.
4. **Drop capabilities** (and optional seccomp) via `tpt-l-sandbox`'s
   `Sandbox::new().caps(...).seccomp(...).apply()`.
5. Enter the accept loop — only now are unprivileged connections served.

Steps 2–3 need the privileges the process was started with (creating
`/run/...`, `chmod`/`chown` the socket, writing the key file). Step 4 must
complete before any `accept(2)`: a compromised connection handler must
never observe the pre-drop capability set. The socket file descriptor
remains valid across capability drop; the already-bound listener does not
need the dropped caps to `accept`.

On non-Linux targets the drop step compiles as a no-op stub; production
deployments must run on Linux. See `docs/ARCHITECTURE.md` for the full
sequence diagram.

## Defining your own commands (for a new consumer repo)

1. Depend on `tpt-privd-envelope` and `tpt-privd-client` (and the daemon
   binary / a fork of its wiring, depending on whether you run your own
   instance).
2. Allocate command kinds from `CommandKind::CUSTOM_START` (`0x8000_0000`)
   upward so you never collide with future built-ins (`NOP`, `ECHO`, …):

   ```rust
   use tpt_privd_envelope::CommandKind;

   const KIND_WRITE_TABLE: u32 = CommandKind::CUSTOM_START + 1;
   ```

3. Implement `tpt_privd_policy::CommandExecutor` for your domain:
   - `policy_check` inspects `cmd.kind` and `cmd.payload` and returns
     `Err(PolicyViolation)` for anything out of bounds (this is where
     "may only touch table X" lives).
   - `execute` performs the privileged operation and returns
     `CommandSuccess` / `CommandError`.
4. Wire it into your daemon instance the same way `MockExecutor` is wired
   in `run_from_config`.

Until a real consumer exists, `MockExecutor` + the `e2e` example stand in
as the domain layer (per the spec's resolved decisions).

## Testing & CI

- **Unit + integration tests** run on every push (`cargo test --workspace`).
  Unix-socket integration tests are `cfg(unix)` and run on Linux CI; the
  framing layer has equivalent in-memory tests that run everywhere.
- **Clippy** with `-D warnings` and workspace pedantic lints.
- **rustfmt** `--check`.
- **cargo-deny** license + advisory + ban checks.
- **Fuzzing** (C5): scheduled daily workflow
  (`.github/workflows/fuzz.yml`) + manual
  `cargo +nightly fuzz run decode` from `crates/tpt-privd-envelope/fuzz/`.
- **Observability (I11/I3/I4):** `tracing` + `RUST_LOG`; scrape metrics with
  `call --kind 2` (Prometheus text over the audited socket); optional
  `--features otel` layers OpenTelemetry stdout export for local debugging.
- **Audit shipping (I5):** `AuditSink` + `MemorySink` / `JsonlMirrorSink` /
  `AuditShipper` — local JSONL chain stays authoritative; sink errors never
  fail an append.
- **Dev tasks (I9):** `cargo xtask gates` / `schema` / `publish-order` /
  `packaging-check`.
- **Consumer scaffold (I10):** `templates/consumer/`.
- **CapEff harness (I6):** `packaging/verify-caps.sh` (or CI
  `caps-harness` job) builds `Dockerfile.caps-harness` and runs
  `examples/caps_probe` as root.
- **Nix (I7):** `flake.nix` packages the workspace with sibling
  `tpt-linux-sandbox` as a flake input (`nix build` / `nix flake check`).

What CI **cannot** test (documented gap, not silently skipped): real
Landlock/seccomp enforcement and non-root capability dropping need a Linux
kernel with the relevant LSMs enabled and typically root — GitHub-hosted
runners are not a substitute for a manual verification on a real target
(the I6 caps harness automates CapEff shrink in CI; full LSM coverage
still needs a real target). See `docs/ARCHITECTURE.md` § Testing.

## Deferred (out of scope for v1)

Per `spec.txt` and `todo.md`: vsock/remote transport, async job/ticket
model for long-running commands, multi-tenant per-caller policy scoping,
full `nixosTest` VM integration for I7 (needs nested virt), and any
domain-specific command vocabulary — all gated on prerequisites that do
not exist yet.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at
your option.

Copyright 2026 TPT Solutions.
