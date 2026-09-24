//! Length-prefixed CBOR framing and Unix domain socket transport for tpt-privd.
//!
//! # Framing
//!
//! Every message on the wire is:
//!
//! ```text
//! [u32 big-endian length][CBOR payload bytes]
//! ```
//!
//! The length is the payload size only (not including itself). Frames larger
//! than the configured maximum are rejected before allocation. This works
//! over any [`Read`](std::io::Read) + [`Write`](std::io::Write) stream, so
//! the framing layer is fully testable with in-memory buffers on every
//! platform; only the Unix domain socket listener/client are `cfg(unix)`.
//!
//! # Connection model
//!
//! One-shot request/reply per connection (see the spec's synchronous
//! execution decision): the client connects, sends exactly one framed
//! command, reads exactly one framed result, and the connection closes.
//! The server never pipelines or multiplexes on a single connection.
//!
//! # Peer identification
//!
//! On Linux the server reads `SO_PEERCRED` to learn the connecting process's
//! uid/gid/pid, which is recorded in the audit log. On other Unix platforms
//! peer credential lookup fails closed with `Unsupported` until
//! `LOCAL_PEERCRED`/`getpeereid` is implemented. Socket file permissions
//! (owner/group/mode set at bind time) are the primary access control;
//! peer credentials are recorded for accountability, not used as the sole
//! authorization gate in v1 (multi-tenant per-caller policy is deferred).
//!
//! # Platform support
//!
//! Framing is cross-platform. Socket code requires `cfg(unix)`. Full peer
//! credentials require Linux (`SO_PEERCRED`). Windows builds compile the
//! framing layer and skip the socket module.

#![deny(missing_docs)]

mod error;
mod frame;

pub use error::TransportError;
pub use frame::{DEFAULT_MAX_FRAME_SIZE, FrameLimits, read_frame, write_frame};

#[cfg(unix)]
mod peer;
#[cfg(unix)]
mod socket;

#[cfg(unix)]
pub use peer::PeerCredentials;
#[cfg(unix)]
pub use socket::{
    SocketConfig, bind_listener, connect, credentials, listener_from_fd, serve_one,
    systemd_listener,
};
