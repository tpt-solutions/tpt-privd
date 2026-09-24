//! Transport error type.

use thiserror::Error;

/// Errors produced while framing or moving bytes over a stream/socket.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Underlying I/O failure (EOF, reset, timeout, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A frame length prefix exceeded the configured maximum.
    ///
    /// The connection must be dropped without allocating the claimed size.
    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge {
        /// Claimed payload size from the length prefix.
        size: u64,
        /// Configured maximum.
        max: u64,
    },
    /// EOF occurred before a complete frame arrived (or mid-frame).
    #[error("unexpected end of stream while reading frame")]
    UnexpectedEof,
    /// CBOR payload failed to decode into the expected envelope type.
    #[error("frame payload decode failed: {0}")]
    Decode(String),
    /// CBOR encode of an outgoing payload failed (rare — plain data types).
    #[error("frame payload encode failed: {0}")]
    Encode(String),
    /// Socket path / bind / listen failure with context.
    #[error("socket error: {0}")]
    Socket(String),
    /// Read or write exceeded the configured timeout.
    #[error("timed out during {op}")]
    Timeout {
        /// Which operation timed out.
        op: &'static str,
    },
}
