# tpt-privd-daemon

[![Crates.io](https://img.shields.io/crates/v/tpt-privd-daemon.svg)](https://crates.io/crates/tpt-privd-daemon)
[![Docs.rs](https://docs.rs/tpt-privd-daemon/badge.svg)](https://docs.rs/tpt-privd-daemon)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)

The privileged command daemon for [`tpt-privd`](../../README.md). It listens on
a Unix socket, accepts typed commands from unprivileged clients, checks each
one against policy, executes the allowed ones, writes an audit record for every
outcome, and drops its Linux capabilities **before** it accepts any connection.

This crate is both a binary (`tpt-privd-daemon`) and a library. The library
lets a consumer repository wire in its own `CommandExecutor` and config, and
lets the integration tests drive the full request path in-process.

## Contents

- [How a request flows](#how-a-request-flows)
- [Startup order](#startup-order)
- [Command line](#command-line)
- [Configuration](#configuration)
- [Library use](#library-use)
- [Building from source](#building-from-source)
- [Examples and tests](#examples-and-tests)
- [Observability](#observability)
- [Deployment](#deployment)
- [Platform support](#platform-support)
- [Security notes](#security-notes)
- [License](#license)

## How a request flows

```text
client ──► socket (SO_PEERCRED) ──► frame decode ──► version gate
                                                        │
                       audit ◄── policy_check ◄─────────┤
                         ▲             │ Ok             │
                         │             ▼                │
                         │         execute (timeout)    │
                         │             │                │
                         └──── audit record + reply ◄───┘
```

Every path that reaches the version gate or the policy check writes an audit
record, including denials and version mismatches. The record is written before
the reply is sent.

## Startup order

The order is security-critical. Changing it changes what an attacker
could observe:

1. Parse and validate the config.
2. Open the audit log, loading or generating the Ed25519 key.
3. Bind the Unix socket, or take the fd that systemd passed in, and apply mode
   and ownership.
4. **Drop capabilities** through [`tpt-l-sandbox`](https://github.com/TPT-Solutions/tpt-linux-sandbox)
   (Linux only), and optionally apply seccomp.
5. Enter the accept loop.

Steps 2 and 3 need the privileges the daemon was started with. Step 4 has to
finish before the first `accept`, so no connection handler ever runs with the
pre-drop capability set. The bound listener stays valid after the drop.

On non-Linux Unix builds, step 4 is a no-op stub. Seccomp is rejected in
config on those builds, so a misconfigured unit fails at startup rather than
running unfiltered. See [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)
for the full sequence.

## Command line

With no subcommand, the binary runs the daemon:

```sh
tpt-privd-daemon --config /etc/tpt-privd/config.toml
```

| Invocation | Purpose |
|---|---|
| `tpt-privd-daemon --config <path>` | Run the daemon. |
| `tpt-privd-daemon --check --config <path>` | Validate the config and exit. |
| `tpt-privd-daemon --print-config` | Print the resolved config. |
| `tpt-privd-daemon --print-schema` | Print the config's JSON Schema. |
| `tpt-privd-daemon verify-audit <log> [--key <pub>]` | Verify an audit log offline. |
| `tpt-privd-daemon call --socket <path> --kind <n> --payload <s>` | Send one command to a running daemon. |
| `tpt-privd-daemon explain-caps --kind <n>` | Compare a kind's required capabilities with `[caps] keep`. |

Config discovery when `--config` is omitted, in order:

1. `$TPRIVD_CONFIG`
2. `$XDG_CONFIG_HOME/tpt-privd/config.toml`
3. `$HOME/.config/tpt-privd/config.toml`
4. `/etc/tpt-privd/config.toml`
5. Built-in defaults, with a warning on stderr

A typical call against the built-in echo kind:

```sh
tpt-privd-daemon call --socket /run/tpt-privd/privd.sock --kind 1 --payload hello
```

## Configuration

The full annotated reference is
[`config.example.toml`](config.example.toml). Commonly changed keys:

```toml
socket_path = "/run/tpt-privd/privd.sock"
socket_mode = "0o660"              # or decimal 432; TOML has no octal literal
socket_activation = false          # true: take the fd from systemd LISTEN_FDS
audit_log_path = "/var/lib/tpt-privd/audit.jsonl"
audit_key_path = "/var/lib/tpt-privd/audit.key"

[caps]
drop_all = true
keep = ["CAP_NET_ADMIN"]           # minimal set your executor actually needs

[seccomp]
enabled = false                    # Linux only; experimental
allow = []
on_deny = "kill"                   # or "errno" while bringing up a profile

[limits]
max_frame_size = 1048576
read_timeout_ms = 5000
write_timeout_ms = 5000
execute_timeout_ms = 30000

# Custom kinds the MockExecutor will accept.
# Built-ins: NOP = 0, ECHO = 1, METRICS = 2.
allowed_custom_kinds = [2147483649]  # 0x8000_0001
```

Notes:

- `socket_owner_uid` and `socket_owner_gid` set the socket's ownership
  explicitly. Prefer them over sharing a group you do not control.
- `read_timeout_ms`, `write_timeout_ms`, and `execute_timeout_ms` must be
  non-zero. Validation rejects zero.
- `keep` is the complete capability set the daemon retains. Keep it to what
  the executor needs, and check it with `explain-caps`.
- The config uses `deny_unknown_fields`, so a misspelled key is an error.
  `--print-schema` produces a schema editors can use for completion.

## Library use

The library exposes the daemon loop and the request handler, so a consumer
can supply its own executor:

```rust,ignore
use tpt_privd_daemon::{Config, run_with};
use tpt_privd_policy::CommandExecutor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(std::path::Path::new("/etc/tpt-privd/config.toml"))?;
    let executor = MyExecutor::new(); // implements CommandExecutor
    run_with(&config, &executor)?;
    Ok(())
}
```

Public entry points:

| Item | Use |
|---|---|
| `Config`, `Config::load`, `Config::from_toml`, `Config::validate` | Load and check configuration. |
| `run_from_config` | Run with the bundled `MockExecutor`. |
| `run_with` | Run with your own `CommandExecutor`. |
| `serve_listener`, `serve_one_connection` | Lower-level serving, for tests and custom setups. |
| `handle_cbor_payload`, `HandleDeps` | Handle one encoded request in-process. |
| `drop_privileges` | Apply the capability drop (Linux). |
| `prometheus_text` | Render metrics as Prometheus text. |
| `MockExecutor` | Re-exported stand-in executor. |

See the [API docs](https://docs.rs/tpt-privd-daemon) for signatures.

## Building from source

`tpt-privd` depends on the sibling `tpt-linux-sandbox` workspace through a path
dependency. Clone the two repositories side by side:

```text
parent/
  tpt-privd/
  tpt-linux-sandbox/   # provides crates/tpt-l-sandbox
```

CI does the same. Do not change the path without updating both the
`Cargo.toml` and `.github/workflows/ci.yml`.

```sh
cargo test --workspace
cargo run -p tpt-privd-daemon -- --check --config crates/tpt-privd-daemon/config.example.toml
```

Socket and privilege-drop code is Unix-only, and the capability drop is
Linux-only. Windows builds run the library tests and the Unix-independent
parts of the workspace. The Unix-gated integration tests are `#![cfg(unix)]`.

To build with OpenTelemetry export:

```sh
cargo build -p tpt-privd-daemon --features otel
```

Before opening an issue about a build problem, confirm that the workspace
gates pass on your machine:

```sh
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt -p tpt-privd-envelope -p tpt-privd-transport \
  -p tpt-privd-policy -p tpt-privd-audit -p tpt-privd-client \
  -p tpt-privd-daemon -p xtask -- --check
cargo deny --all-features check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Do not run `cargo fmt --all`. It also formats the sibling checkout.

## Examples and tests

| Name | What it shows |
|---|---|
| `examples/e2e.rs` | Binds a real socket, sends echo, a policy denial, and an allowlisted custom kind, then verifies the audit chain. No root required. |
| `examples/custom_consumer.rs` | A real consumer `CommandExecutor` (not the mock) wired through `run_with` and exercised by a client call. |
| `examples/caps_probe.rs` | Linux-only probe that prints `CapEff` before and after the capability drop. Run inside the capability harness container. |
| `tests/integration.rs` | Drives the full request path in-process. |

```sh
cargo run -p tpt-privd-daemon --example e2e
cargo test -p tpt-privd-daemon
```

## Observability

- Logs go through `tracing`. Set `RUST_LOG` to adjust the filter.
- `--features otel` adds OpenTelemetry spans. The default exporter writes to
  stdout. For production, point `OTEL_EXPORTER_OTLP_*` at a collector.
- The built-in `METRICS` kind (`2`) returns Prometheus text over the audited
  channel, so reading metrics is also recorded in the audit log.

## Deployment

The systemd service and socket units, tmpfiles configuration, and the
capability-harness Dockerfile live in [`packaging/`](../../packaging/). The step-by-step guide,
including the publish order, is
[`docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md).

Verify the audit log on a schedule:

```sh
tpt-privd-daemon verify-audit /var/lib/tpt-privd/audit.jsonl \
  --key /etc/tpt-privd/audit.key
```

## Platform support

| Target | Daemon runs | Socket | Capability drop | Seccomp |
|---|---|---|---|---|
| Linux | yes | yes | yes | yes (experimental) |
| Other Unix | yes | yes | no-op stub | rejected in config |
| Windows | no; library tests only | no | no | no |

## Security notes

- Run the daemon on Linux. Elsewhere, the capability drop does nothing.
- Keep `[caps] keep` minimal. The `CAP_NET_ADMIN` entry in the example is
  illustrative.
- Protect `audit.key` with mode `0600`, provisioned outside the daemon in
  production.
- Restrict the socket with owner and group, not by making it world-writable.
- Policy and executor code run with the kept capabilities. Review them as
  privileged code.

## Minimum supported Rust version

1.85, edition 2024.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE)
or [MIT license](../../LICENSE-MIT), at your option.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
