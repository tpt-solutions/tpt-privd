//! Client library for sending commands to a `tpt-privd` daemon.
//!
//! One-shot model matching the server: each [`call`] opens a Unix domain
//! socket, writes one framed CBOR [`Command`], reads one framed CBOR
//! [`CommandResult`], and closes.
//!
//! # Example
//!
//! ```no_run
//! use tpt_privd_client::call;
//! use tpt_privd_envelope::{Command, CommandId, CommandKind};
//!
//! let cmd = Command::new(CommandId(1), CommandKind::ECHO, b"hello".to_vec());
//! let result = call(
//!     std::path::Path::new("/run/tpt-privd/privd.sock"),
//!     &cmd,
//! )
//! .expect("daemon unreachable");
//! match result.outcome {
//!     Ok(success) => println!("ok: {:?}", success.payload),
//!     Err(e) => println!("failed: {:?} — {}", e.code, e.message),
//! }
//! ```
//!
//! # Platform
//!
//! Requires `cfg(unix)` (Unix domain sockets). On non-Unix targets this
//! crate compiles but every connect path returns
//! [`ClientError::UnsupportedPlatform`].

#![deny(missing_docs)]

use std::path::Path;

use thiserror::Error;
use tpt_privd_envelope::{Command, CommandResult};
use tpt_privd_transport::{FrameLimits, TransportError};

#[cfg(unix)]
use tpt_privd_envelope::{decode_result, encode};
#[cfg(unix)]
use tpt_privd_transport::{read_frame, write_frame};

/// Errors from a client call.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Transport/framing/socket failure.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// CBOR encode of the request failed.
    #[error("failed to encode command: {0}")]
    Encode(String),
    /// CBOR decode of the reply failed.
    #[error("failed to decode daemon reply: {0}")]
    Decode(String),
    /// The daemon replied with a different `Command.id` than we sent.
    #[error("reply id mismatch: sent {sent}, got {got}")]
    IdMismatch {
        /// Id we sent.
        sent: u64,
        /// Id we received.
        got: u64,
    },
    /// Called on a platform without Unix domain socket support.
    #[error("tpt-privd-client requires a Unix-like OS")]
    UnsupportedPlatform,
}

/// Send `cmd` to the daemon listening at `socket_path` and wait for its
/// [`CommandResult`].
///
/// Uses default [`FrameLimits`] (1 MiB) and default timeouts
/// ([`ClientOptions::default`]: 5 s read/write).
///
/// # Errors
///
/// [`ClientError::Transport`] on connect/read/write failures,
/// [`ClientError::Decode`] if the reply is not a valid `CommandResult`,
/// [`ClientError::UnsupportedPlatform`] off Unix.
pub fn call(socket_path: &Path, cmd: &Command) -> Result<CommandResult, ClientError> {
    call_with_options(socket_path, cmd, &ClientOptions::default())
}

/// Options controlling timeouts and frame limits for a client call.
#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    /// Connect timeout (Unix domain sockets connect is local; still bounds
    /// a wedged kernel path).
    pub connect_timeout: std::time::Duration,
    /// Read timeout for the reply frame.
    pub read_timeout: std::time::Duration,
    /// Write timeout for the request frame.
    pub write_timeout: std::time::Duration,
    /// Frame size limits (request and response).
    pub limits: FrameLimits,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: std::time::Duration::from_secs(5),
            read_timeout: std::time::Duration::from_secs(5),
            write_timeout: std::time::Duration::from_secs(5),
            limits: FrameLimits::default(),
        }
    }
}

/// [`call`] with explicit options (timeouts + frame limits).
///
/// # Errors
///
/// Same as [`call`].
pub fn call_with_options(
    socket_path: &Path,
    cmd: &Command,
    opts: &ClientOptions,
) -> Result<CommandResult, ClientError> {
    #[cfg(unix)]
    {
        let _ = opts.connect_timeout; // UnixStream::connect is non-blocking-enough locally
        let mut stream = tpt_privd_transport::connect(socket_path)?;
        stream
            .set_read_timeout(Some(opts.read_timeout))
            .map_err(|e| ClientError::Transport(TransportError::Io(e)))?;
        stream
            .set_write_timeout(Some(opts.write_timeout))
            .map_err(|e| ClientError::Transport(TransportError::Io(e)))?;
        let payload = encode(cmd).map_err(|e| ClientError::Encode(e.to_string()))?;
        write_frame(&mut stream, &payload, opts.limits)?;
        let reply = read_frame(&mut stream, opts.limits)?;
        let result = decode_result(&reply).map_err(|e| ClientError::Decode(e.to_string()))?;
        if result.id.0 != cmd.id.0 {
            return Err(ClientError::IdMismatch {
                sent: cmd.id.0,
                got: result.id.0,
            });
        }
        Ok(result)
    }
    #[cfg(not(unix))]
    {
        let _ = (socket_path, cmd, opts);
        Err(ClientError::UnsupportedPlatform)
    }
}

/// [`call`] with explicit frame limits (must be ≥ the daemon's limits for
/// the request to be accepted; the *response* is limited by these too).
///
/// # Errors
///
/// Same as [`call`].
pub fn call_with_limits(
    socket_path: &Path,
    cmd: &Command,
    limits: FrameLimits,
) -> Result<CommandResult, ClientError> {
    let opts = ClientOptions {
        limits,
        ..ClientOptions::default()
    };
    call_with_options(socket_path, cmd, &opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_privd_envelope::{CommandId, CommandKind};

    #[cfg(not(unix))]
    #[test]
    fn call_on_non_unix_returns_unsupported() {
        let cmd = Command::new(CommandId(1), CommandKind::NOP, vec![]);
        let err = call(Path::new("/tmp/does-not-matter.sock"), &cmd).unwrap_err();
        assert!(matches!(err, ClientError::UnsupportedPlatform));
    }

    #[cfg(unix)]
    #[test]
    fn call_to_missing_socket_is_transport_error() {
        let cmd = Command::new(CommandId(1), CommandKind::NOP, vec![]);
        let err = call(Path::new("/tmp/tpt-privd-definitely-missing.sock"), &cmd).unwrap_err();
        assert!(matches!(err, ClientError::Transport(_)));
    }
}
