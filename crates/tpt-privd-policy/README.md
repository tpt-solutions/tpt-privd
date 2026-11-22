# tpt-privd-policy

[![Crates.io](https://img.shields.io/crates/v/tpt-privd-policy.svg)](https://crates.io/crates/tpt-privd-policy)
[![Docs.rs](https://docs.rs/tpt-privd-policy/badge.svg)](https://docs.rs/tpt-privd-policy)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)

Per-command-kind policy checks and the `CommandExecutor` trait for
[`tpt-privd`](../../README.md). This is where a consumer decides which
requests the privileged daemon will carry out, and what they actually do.

A consumer repository typically depends on this crate to:

1. Implement `CommandExecutor` for its own command vocabulary.
2. Pass that executor to the daemon (`tpt_privd_daemon::run_with`).

## Contents

- [Model](#model)
- [The `CommandExecutor` trait](#the-commandexecutor-trait)
- [Writing a policy](#writing-a-policy)
- [PolicyViolation](#policyviolation)
- [MockExecutor](#mockexecutor)
- [Example](#example)
- [Security notes](#security-notes)
- [License](#license)

## Model

Policy is evaluated **per command kind**, and it runs before anything
executes:

```text
Command ──► policy_check() ──Err──► PolicyViolation ──► audit: policy_denied
                 │                                       reply: PolicyDenied
                 Ok
                 ▼
             execute() ──Err──► audit: execution_failed
                 │              reply: ExecutionFailed
                 Ok
                 ▼
             audit: executed, reply: success
```

A compromised unprivileged caller can still send any bytes to the socket.
Policy limits what those bytes can make the privileged process do. For
example, a kind may be restricted to a specific table or path by inspecting
`cmd.payload` in `policy_check`, even if the caller is otherwise allowed to
send that kind.

## The `CommandExecutor` trait

```rust
pub trait CommandExecutor: Send + Sync {
    fn policy_check(&self, cmd: &Command) -> Result<(), PolicyViolation>;
    fn execute(&self, cmd: &Command) -> Result<CommandSuccess, CommandError>;
    fn required_caps(&self, cmd: &Command) -> Vec<String>; // has a default
}
```

- `policy_check` must be **pure and side-effect free**. It should look only
  at the command and immutable configuration.
- `execute` is only called after `policy_check` returns `Ok`. It runs in the
  privileged process, after capabilities have been dropped to the minimum
  set in config.
- `required_caps` names the Linux capabilities a kind needs. The daemon's
  `explain-caps` subcommand compares this against the `[caps] keep` list.
  The default implementation returns an empty list.
- The trait requires `Send + Sync` because the daemon may share one executor
  across threads.

Check the exact signatures in the [API docs](https://docs.rs/tpt-privd-policy).

## Writing a policy

A typical implementation matches on the kind, validates the payload, and
only then allows the command. The sketch below shows `policy_check` only;
a real executor also implements `execute`:

```rust,ignore
use tpt_privd_envelope::{Command, CommandKind};
use tpt_privd_policy::{CommandExecutor, PolicyViolation};

const RESTART: CommandKind = CommandKind(CommandKind::CUSTOM_START);

impl CommandExecutor for MyExecutor {
    fn policy_check(&self, cmd: &Command) -> Result<(), PolicyViolation> {
        match cmd.kind {
            CommandKind::NOP | CommandKind::ECHO => Ok(()),
            RESTART => {
                // Only named units from an allowlist may be restarted.
                let unit = std::str::from_utf8(&cmd.payload).unwrap_or("");
                if matches!(unit, "nginx" | "postgresql") {
                    Ok(())
                } else {
                    Err(PolicyViolation::new(cmd.kind, "unit not in allowlist"))
                }
            }
            other => Err(PolicyViolation::new(other, "unknown command kind")),
        }
    }

    // fn execute(...) and fn required_caps(...) omitted.
}
```

Guidelines:

- **Default deny.** Unknown kinds fall through to `Err`.
- **Validate the payload in `policy_check`**, not only in `execute`. Both
  places are cheap, and the audit log records a denial only once.
- **Do not trust length or encoding.** Parse payloads with strict,
  bounded decoders. The transport already caps frame size, but field values
  are still untrusted.
- **Never build a shell command from payload bytes.** Pass arguments as
  separate `argv` entries, or use typed operations.

## PolicyViolation

`PolicyViolation` has two public fields: `kind` (the denied `CommandKind`)
and `reason` (a human-readable string). Build one with
`PolicyViolation::new(kind, reason)`. The daemon writes it to the audit log
so denials can be investigated later. It does not reach the caller in
detail: the caller only receives `ErrorCode::PolicyDenied`.

The payload is deliberately not part of the violation. Keep reasons short
and free of secrets, because they are stored in the audit trail.

## MockExecutor

`MockExecutor` is a stand-in used by tests and the bundled end-to-end
example:

- Allows `NOP` and `ECHO` unconditionally, and `METRICS` as well.
- Allows custom kinds only if they appear in an explicit allowlist, built
  with `MockExecutor::new()`, `with_allowed(kinds)`, or `allow(kind)`.
  The daemon populates the allowlist from `allowed_custom_kinds`.
- Performs no privileged work.

Replace it with your own executor before deploying anything.

## Example

Run the bundled end-to-end example from the workspace root. It drives a
real socket through the daemon with echo, a policy denial, and an
allowlisted custom kind, then verifies the audit chain:

```sh
cargo run -p tpt-privd-daemon --example e2e
```

## Security notes

- Policy code runs in the **privileged** process. Keep it small, pure, and
  reviewed.
- Anything an executor does with the filesystem or network needs the matching
  capability in the daemon's `[caps] keep` list. Declare it through
  `required_caps` so `explain-caps` can check it.
- The policy layer does not authenticate callers. Access to the socket is
  controlled by file permissions. See
  [`tpt-privd-transport`](../tpt-privd-transport/README.md#permissions-and-ownership).

## Minimum supported Rust version

1.85, edition 2024.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE)
or [MIT license](../../LICENSE-MIT), at your option.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
