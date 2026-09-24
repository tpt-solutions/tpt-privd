//! Typed, versioned command envelope for `tpt-privd`.
//!
//! This crate defines the wire types shared by the daemon and its clients:
//! [`Command`], [`CommandResult`], and the [`CommandKind`] extension
//! mechanism. Encoding is CBOR via [`ciborium`], matching the portfolio's
//! CBOR preference (see `tpt-protocol-tup`).
//!
//! # Versioning
//!
//! [`ENVELOPE_VERSION`] is the version this crate speaks. The daemon rejects
//! any command whose `version` field does not equal it, returning a
//! structured [`ErrorCode::UnsupportedVersion`] without executing. There is
//! no forward-compatible negotiation in v1 — a version bump is a breaking
//! wire change. See `docs/ARCHITECTURE.md` for the compatibility policy.
//!
//! # Extension mechanism
//!
//! [`CommandKind`] is an open enum: a transparent `u32` newtype with
//! reserved built-in constants ([`CommandKind::NOP`],
//! [`CommandKind::ECHO`]) and a consumer-defined range starting at
//! [`CommandKind::CUSTOM_START`]. Consumers map their own domain enums onto
//! `Custom(u32)` values in that range. This keeps the wire representation a
//! single stable integer while still allowing open extension without a
//! generic parameter propagating through every trait.
//!
//! # Example
//!
//! ```
//! use tpt_privd_envelope::{Command, CommandId, CommandKind, ENVELOPE_VERSION};
//!
//! let cmd = Command::new(CommandId(1), CommandKind::ECHO, b"ping".to_vec());
//! assert_eq!(cmd.version, ENVELOPE_VERSION);
//!
//! let bytes = tpt_privd_envelope::encode(&cmd).unwrap();
//! let decoded = tpt_privd_envelope::decode(&bytes).unwrap();
//! assert_eq!(cmd, decoded);
//! ```

#![deny(missing_docs)]

mod codec;
mod error;
mod types;

pub use codec::{decode, decode_result, encode, encode_result};
pub use error::{CodecError, EnvelopeError};
pub use types::{
    AuditLogRef, Command, CommandError, CommandId, CommandKind, CommandResult, CommandSuccess,
    ErrorCode,
};

/// The envelope format version this crate encodes and decodes.
///
/// The daemon rejects commands whose `version` differs from this value.
/// Bumping it is a breaking wire change for every consumer.
pub const ENVELOPE_VERSION: u32 = 1;

/// Returns `Ok(())` if `version` matches [`ENVELOPE_VERSION`], otherwise the
/// structured error the daemon should reply with.
///
/// Callers (the daemon) should audit-log the rejection before sending it.
///
/// # Errors
///
/// [`EnvelopeError::UnsupportedVersion`] when `version != ENVELOPE_VERSION`.
pub fn check_version(version: u32) -> Result<(), EnvelopeError> {
    if version == ENVELOPE_VERSION {
        Ok(())
    } else {
        Err(EnvelopeError::UnsupportedVersion {
            got: version,
            supported: ENVELOPE_VERSION,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_version_accepts_current() {
        assert!(check_version(ENVELOPE_VERSION).is_ok());
    }

    #[test]
    fn check_version_rejects_old_and_future() {
        assert!(matches!(
            check_version(0),
            Err(EnvelopeError::UnsupportedVersion { got: 0, .. })
        ));
        assert!(matches!(
            check_version(ENVELOPE_VERSION + 1),
            Err(EnvelopeError::UnsupportedVersion { .. })
        ));
    }
}
