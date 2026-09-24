//! Error types for envelope decoding and version checks.

use thiserror::Error;

/// Failure to encode or decode an envelope.
#[derive(Debug, Error)]
pub enum CodecError {
    /// CBOR serialization failed.
    #[error("CBOR encode failed: {0}")]
    Encode(String),
    /// CBOR deserialization failed (malformed, truncated, wrong shape).
    #[error("CBOR decode failed: {0}")]
    Decode(String),
}

impl From<ciborium::ser::Error<std::io::Error>> for CodecError {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Self::Encode(e.to_string())
    }
}

impl From<ciborium::de::Error<std::io::Error>> for CodecError {
    fn from(e: ciborium::de::Error<std::io::Error>) -> Self {
        Self::Decode(e.to_string())
    }
}

/// Envelope-level rejection that is *not* a codec failure — the bytes were
/// well-formed enough to parse, but the content is unacceptable.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// `Command.version` did not match [`ENVELOPE_VERSION`](crate::ENVELOPE_VERSION).
    #[error("unsupported envelope version {got} (daemon speaks {supported})")]
    UnsupportedVersion {
        /// Version found on the command.
        got: u32,
        /// Version this build supports.
        supported: u32,
    },
}
