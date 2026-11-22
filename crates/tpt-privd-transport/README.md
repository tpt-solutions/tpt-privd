# tpt-privd-transport

[![Crates.io](https://img.shields.io/crates/v/tpt-privd-transport.svg)](https://crates.io/crates/tpt-privd-transport)
[![Docs.rs](https://docs.rs/tpt-privd-transport/badge.svg)](https://docs.rs/tpt-privd-transport)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)

Length-prefixed framing and Unix domain socket transport for
[`tpt-privd`](../../README.md). This crate moves encoded
[`tpt-privd-envelope`](../tpt-privd-envelope/README.md) messages between an
unprivileged client and the privileged daemon.

It has two layers:

1. **Framing** (`read_frame` / `write_frame`). Works over any `Read` and
   `Write`, so it is fully testable with in-memory buffers on every
   platform.
2. **Socket** (`bind_listener`, `connect`, `serve_one`, and friends).
   Unix only, behind `cfg(unix)`.

## Contents

- [Wire format](#wire-format)
- [Framing API](#framing-api)
- [Unix socket API](#unix-socket-api)
- [Peer credentials](#peer-credentials)
- [Permissions and ownership](#permissions-and-ownership)
- [Connection model](#connection-model)
- [Errors](#errors)
- [Platform support](#platform-support)
- [Example](#example)
- [License](#license)

## Wire format

```text
+----------------------+----------------------------+
| u32 length (BE)      | CBOR payload (length bytes)|
+----------------------+----------------------------+
```

The length counts the payload only, not the four prefix bytes. A frame
whose declared length exceeds the configured maximum is rejected
**before** any allocation, so a hostile peer cannot make the daemon reserve
gigabytes with a four-byte header.

The default maximum is `DEFAULT_MAX_FRAME_SIZE` (1 MiB). Override it with
`FrameLimits`.

## Framing API

```rust
use std::io::Cursor;
use tpt_privd_transport::{FrameLimits, read_frame, write_frame};

let mut buf = Vec::new();
write_frame(&mut buf, b"payload", FrameLimits::default())?;

let mut reader = Cursor::new(buf);
let payload = read_frame(&mut reader, FrameLimits::default())?;
assert_eq!(payload, b"payload");
# Ok::<(), Box<dyn std::error::Error>>(())
```

`FrameLimits` sets the maximum frame size for one direction. Use a tighter
limit for requests from untrusted callers than you would for replies.

## Unix socket API

| Item | Role |
|---|---|
| `SocketConfig` | Path, mode, optional owner uid and gid for a socket you bind. |
| `bind_listener(&SocketConfig)` | Binds the socket, refuses a live socket already at the path, and applies mode and ownership. |
| `listener_from_fd(fd)` | Wraps an already-bound listening fd (for example from a supervisor). |
| `systemd_listener()` | Returns the socket passed by systemd socket activation (`LISTEN_FDS`), or `None`. |
| `connect(path)` | Client-side connect. |
| `serve_one(stream, limits, handler)` | Given an accepted `UnixStream`, reads one frame, passes its bytes to `handler`, and writes the returned bytes as the reply. |
| `credentials(&stream)` | Returns `PeerCredentials` for the connected peer. |

Binding is done in this order so the path is never left world-accessible:

1. Create the socket at a fresh path.
2. Apply mode and ownership to the listener **file descriptor** with
   `fchmod` and `fchown`, not to the path. This avoids a time-of-check to
   time-of-use race on the path.
3. Start listening.

## Peer credentials

On Linux, `credentials` reads `SO_PEERCRED` and returns a
`PeerCredentials` value with the peer's pid, uid, and gid. The daemon
writes these into the audit record for every command.

Peer credentials are for **accountability**, not the only access gate in
v1. The socket's owner, group, and mode decide who can connect at all.
Per-caller authorization is deferred.

On other Unix platforms, `credentials` fails closed with
`io::ErrorKind::Unsupported` until `getpeereid` or `LOCAL_PEERCRED` is
implemented.

## Permissions and ownership

Recommended production setup, matching the packaged systemd socket unit:

- Owner: the daemon user.
- Group: a dedicated group whose members may send commands.
- Mode: `0o660`. TOML has no octal literal, so the daemon config accepts
  `"0o660"` or the decimal value `432`.

Prefer `socket_owner_uid` and `socket_owner_gid` over granting access to a
shared group you do not control.

## Connection model

One request and one reply per connection. The client connects, writes one
frame, reads one frame, and closes. The server never pipelines or
multiplexes on a connection. This keeps each command's lifetime and audit
record unambiguous.

Read and write timeouts are applied to every stream. A stalled peer
produces `TransportError::Timeout` instead of blocking the daemon.

## Errors

`TransportError` has these variants:

| Variant | Meaning |
|---|---|
| `Io` | Underlying I/O failure (reset, EOF before a header, and so on). |
| `FrameTooLarge { size, max }` | Declared length exceeded the limit. The connection should be dropped. |
| `UnexpectedEof` | The stream ended before a complete frame arrived. |
| `Decode` / `Encode` | CBOR problems surfaced through the transport helpers. |
| `Socket` | Bind, listen, or permission failure, including a live socket already at the path. |
| `Timeout { .. }` | A read or write exceeded its deadline. |

## Platform support

| Item | Linux | macOS / BSD | Windows |
|---|---|---|---|
| Framing (`read_frame`, `write_frame`) | yes | yes | yes |
| Unix socket API | yes | yes | not compiled |
| `SO_PEERCRED` credentials | yes | not yet (fails closed) | not compiled |

## Example

A minimal echo server that reads one frame and writes it back:

```rust,no_run
use std::path::Path;
use tpt_privd_transport::{
    FrameLimits, SocketConfig, bind_listener, connect, read_frame, write_frame,
};

let path = Path::new("/tmp/tpt-privd-demo.sock");
let listener = bind_listener(&SocketConfig::new(path))?;

// Server side (normally a loop in the daemon).
let (mut stream, _) = listener.accept()?;
let request = read_frame(&mut stream, FrameLimits::default())?;
write_frame(&mut stream, &request, FrameLimits::default())?;

// Client side.
let mut client = connect(path)?;
write_frame(&mut client, b"ping", FrameLimits::default())?;
let reply = read_frame(&mut client, FrameLimits::default())?;
assert_eq!(reply, b"ping");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Most code should use [`tpt-privd-client`](../tpt-privd-client/README.md)
for the client side instead of calling `connect` directly.

## Benchmarks

```sh
cargo bench -p tpt-privd-transport
```

The `frame` benchmark measures framing overhead for representative payload
sizes.

## Minimum supported Rust version

1.85, edition 2024.

## License

Licensed under either of [Apache License, Version 2.0](../../LICENSE-APACHE)
or [MIT license](../../LICENSE-MIT), at your option.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
