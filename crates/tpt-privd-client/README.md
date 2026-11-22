# tpt-privd-client

[![Crates.io](https://img.shields.io/crates/v/tpt-privd-client.svg)](https://crates.io/crates/tpt-privd-client)
[![Docs.rs](https://docs.rs/tpt-privd-client/badge.svg)](https://docs.rs/tpt-privd-client)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)

A small client for sending commands to a running
[`tpt-privd`](../../README.md) daemon. It is the unprivileged side of the
pattern: your process builds a `Command`, sends it over the daemon's Unix
socket, and gets back a `CommandResult`.

Each call is one request and one reply on a fresh connection. There is no
connection pool, no session, and no retry. Those choices keep every command's
audit record unambiguous.

## Contents

- [Quick start](#quick-start)
- [Handling the result](#handling-the-result)
- [Timeouts and limits](#timeouts-and-limits)
- [Errors](#errors)
- [Choosing the socket path](#choosing-the-socket-path)
- [Platform support](#platform-support)
- [License](#license)

## Quick start

Add the dependencies:

```toml
[dependencies]
tpt-privd-client = "0.1"
tpt-privd-envelope = "0.1"
```

Send an echo:

```rust
use std::path::Path;
use tpt_privd_client::call;
use tpt_privd_envelope::{Command, CommandId, CommandKind};

let cmd = Command::new(CommandId(1), CommandKind::ECHO, b"hello".to_vec());
let result = call(Path::new("/run/tpt-privd/privd.sock"), &cmd)?;
```

`CommandId` is yours to choose. The daemon echoes it back, and the client
checks that the reply matches what was sent.

## Handling the result

`call` returns `Ok(CommandResult)` whenever a valid reply arrived, even when
the daemon refused the command. A refusal is a *successful exchange* with an
error outcome. Match on the outcome:

```rust
// result.audit_ref holds the seq and hash of the audit record the daemon
// wrote for this command, whatever the outcome. Store it to correlate logs.
match result.outcome {
    Ok(success) => {
        // success.payload holds the command's output.
        println!("ok: {} bytes", success.payload.len());
    }
    Err(error) => {
        // error.code is an ErrorCode: UnsupportedVersion, PolicyDenied,
        // ExecutionFailed, or Internal. The enum is non_exhaustive, so keep a
        // wildcard arm.
        eprintln!("denied or failed: {:?}: {}", error.code, error.message);
    }
}
```

Use `ErrorCode::PolicyDenied` to tell the user their request was not allowed.
Treat `Internal` and `ExecutionFailed` as operational problems to investigate.

## Timeouts and limits

`call` uses `ClientOptions::default()`: 5 seconds each for connect, read,
and write, with the default 1 MiB frame limit.

Override these with `call_with_options` or `call_with_limits`:

```rust
use std::time::Duration;
use tpt_privd_client::{ClientOptions, call_with_options};

let opts = ClientOptions {
    read_timeout: Duration::from_secs(30), // for slow commands
    ..ClientOptions::default()
};
let result = call_with_options(socket, &cmd, &opts)?;
```

The read timeout bounds how long you wait for the daemon's reply. The
daemon has its own `execute_timeout_ms` for the privileged work. Keep the
client's read timeout larger than that value, or the client will give up
while the daemon is still working.

## Errors

`ClientError` has these variants:

| Variant | Meaning |
|---|---|
| `Transport(TransportError)` | Connect, read, or write failed or timed out, or a frame was oversized. |
| `Encode(String)` | The request could not be CBOR-encoded. |
| `Decode(String)` | The reply was not a valid `CommandResult`. |
| `IdMismatch { sent, got }` | The reply's `CommandId` differs from the request. |
| `UnsupportedPlatform` | Built on a target without Unix domain sockets. |

A `ClientError` means the exchange itself failed. Daemon-side refusals
arrive as `Ok(CommandResult)` with an `Err` outcome, as described above.

## Choosing the socket path

Use the path your deployment configures, typically
`/run/tpt-privd/privd.sock`. Do not hard-code it in library code. Accept it
from configuration or an environment variable so that tests can point at a
temporary daemon.

The socket's owner, group, and mode decide who can connect. If `call`
returns a permission error, check that your process is in the socket's group
(see [`tpt-privd-transport`](../tpt-privd-transport/README.md#permissions-and-ownership)).

## Platform support

- Requires Unix domain sockets. Builds on Linux, macOS, and the BSDs.
- On other targets the crate still compiles, and every call returns
  `ClientError::UnsupportedPlatform`. This keeps cross-platform code
  compiling.

## Minimum supported Rust version

1.85, edition 2024.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE)
or [MIT license](../../LICENSE-MIT), at your option.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
