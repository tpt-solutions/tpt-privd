# tpt-privd-envelope

[![Crates.io](https://img.shields.io/crates/v/tpt-privd-envelope.svg)](https://crates.io/crates/tpt-privd-envelope)
[![Docs.rs](https://docs.rs/tpt-privd-envelope/badge.svg)](https://docs.rs/tpt-privd-envelope)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)

The typed, versioned command envelope for [`tpt-privd`](../../README.md).
This crate defines the wire types that a client and the privileged daemon
exchange, and the CBOR codec that turns them into bytes.

It has no I/O and no platform dependencies, so it is the crate to depend on
when you only need wire compatibility: for example to build commands in an
unprivileged process, or to decode audit-adjacent results in a tool that
never talks to a socket.

## Contents

- [Types](#types)
- [Encoding](#encoding)
- [Versioning](#versioning)
- [Extending command kinds](#extending-command-kinds)
- [Example](#example)
- [Features and platform support](#features-and-platform-support)
- [Stability](#stability)
- [License](#license)

## Types

| Type | Purpose |
|---|---|
| `Command` | A request: id, envelope version, kind, and opaque payload bytes. |
| `CommandId(u64)` | Caller-chosen correlation id. The daemon echoes it in the result. |
| `CommandKind(u32)` | Open `u32` newtype identifying what to do. |
| `CommandResult` | A reply: the echoed `id`, an `outcome` that is either a success or an error, and an `audit_ref`. |
| `CommandSuccess` | The successful `payload` bytes. |
| `CommandError` | A structured `code` (`ErrorCode`) and a human-readable `message`. |
| `ErrorCode` | `#[non_exhaustive]` enum: `UnsupportedVersion`, `PolicyDenied`, `ExecutionFailed`, `Internal`. |
| `AuditLogRef` | `seq` and `hash` of the audit record written for this command. Present on every result. |
| `EnvelopeError` | Version-gate failures. |
| `CodecError` | CBOR encode and decode failures. |

Built-in command kinds:

| Constant | Value | Meaning |
|---|---|---|
| `CommandKind::NOP` | `0` | No operation. Useful for health checks. |
| `CommandKind::ECHO` | `1` | Returns the payload unchanged. |
| `CommandKind::METRICS` | `2` | Returns Prometheus text over the audited channel. |
| `CommandKind::CUSTOM_START` | `0x8000_0000` | First value in the consumer-defined range. |

## Encoding

Messages are encoded with [`ciborium`](https://crates.io/crates/ciborium)
through `serde`:

```rust
use tpt_privd_envelope::{Command, CommandId, CommandKind, decode, encode};

let cmd = Command::new(CommandId(7), CommandKind::ECHO, b"ping".to_vec());
let bytes = encode(&cmd)?;
let back = decode(&bytes)?;
assert_eq!(cmd, back);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`encode_result` and `decode_result` do the same for `CommandResult`. The
framing around these bytes (a 4-byte big-endian length prefix) is handled
by [`tpt-privd-transport`](../tpt-privd-transport/README.md), not here.

## Versioning

Every `Command` carries a `version: u32` field. This crate speaks
`ENVELOPE_VERSION` (currently `1`). The daemon rejects any other value
with `ErrorCode::UnsupportedVersion`, records a `VersionMismatch` in the
audit log, and does not execute the command.

`check_version` performs the same comparison for your own code:

```rust
use tpt_privd_envelope::{check_version, ENVELOPE_VERSION};

assert!(check_version(ENVELOPE_VERSION).is_ok());
```

There is no forward or backward negotiation in v1. Any change to the CBOR
shape or meaning of `Command` or `CommandResult` bumps `ENVELOPE_VERSION`
and is a breaking wire change. See the root
[CHANGELOG](../../CHANGELOG.md) for the full policy.

## Extending command kinds

`CommandKind` is an open enum. The built-ins occupy the low range, and
consumers take the range starting at `CUSTOM_START`. Map a domain enum onto
that range once, and keep the mapping stable:

```rust
use tpt_privd_envelope::CommandKind;

#[derive(Clone, Copy)]
#[repr(u32)]
enum Op {
    RestartService = 0,
    ReloadFirewall = 1,
}

fn kind(op: Op) -> CommandKind {
    CommandKind(CommandKind::CUSTOM_START + op as u32)
}

assert!(kind(Op::RestartService).is_custom());
```

Changing an existing value is a wire break. Add new values instead.

`ErrorCode` and `AuditOutcome` are `#[non_exhaustive]`, so new variants can
arrive in minor releases. Match them with a wildcard arm.

## Example

```rust
use tpt_privd_envelope::{
    Command, CommandId, CommandKind, ENVELOPE_VERSION, decode, encode,
};

let cmd = Command::new(CommandId(1), CommandKind::ECHO, b"hello".to_vec());
assert_eq!(cmd.version, ENVELOPE_VERSION);

let wire = encode(&cmd)?;
let received = decode(&wire)?;
assert_eq!(received.payload, b"hello");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features and platform support

- No Cargo features.
- Pure Rust. Builds and tests on Linux, macOS, and Windows.
- `no_std` is not supported; the crate uses `Vec` and `std::error::Error`.

## Stability

Pre-1.0. The wire format is pinned by `ENVELOPE_VERSION`. Rust API changes
are recorded in [CHANGELOG.md](CHANGELOG.md).

## Fuzzing

A `cargo-fuzz` target for the decoder lives in `fuzz/`. It is a separate
package, excluded from the workspace, and needs nightly:

```sh
cd crates/tpt-privd-envelope/fuzz
cargo +nightly fuzz run decode
```

## Minimum supported Rust version

1.85, edition 2024.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE)
or [MIT license](../../LICENSE-MIT), at your option.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
