//! Core envelope types shared by daemon and clients.

use serde::{Deserialize, Serialize};

use crate::ENVELOPE_VERSION;

/// Unique identifier for a command within a client's session.
///
/// Echoed back verbatim in the matching [`CommandResult`] so the caller can
/// correlate request and reply. The daemon does not interpret the value
/// beyond uniqueness per connection (connections are one-shot, so in
/// practice this is caller-chosen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandId(pub u64);

/// Open command-kind enum: a stable `u32` on the wire.
///
/// # Extension mechanism
///
/// Consumers define their own domain kinds by allocating values from
/// [`CommandKind::CUSTOM_START`] upward and converting to/from their own
/// enums. Built-in kinds ([`CommandKind::NOP`], [`CommandKind::ECHO`]) live
/// in the low range reserved for this crate.
///
/// This is deliberately *not* a closed Rust `enum` with a `Custom` variant:
/// a `u32` newtype keeps the CBOR representation a bare integer (no
/// externally-tagged enum overhead), avoids a generic parameter propagating
/// through transport/policy/audit, and still gives consumers an open,
/// collision-resistant namespace via the reserved range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandKind(pub u32);

impl CommandKind {
    /// Built-in no-op: succeeds with an empty payload. Useful as a
    /// connectivity/liveness probe.
    pub const NOP: Self = Self(0);
    /// Built-in echo: returns the command payload unchanged.
    pub const ECHO: Self = Self(1);
    /// Built-in metrics scrape: returns Prometheus text exposition format
    /// over the same audited channel (no second listener — I3).
    pub const METRICS: Self = Self(2);

    /// First value in the consumer-defined range. Consumers should allocate
    /// their own kinds starting here to avoid colliding with future
    /// built-ins.
    pub const CUSTOM_START: u32 = 0x8000_0000;

    /// Returns `true` if this kind is in the consumer-defined range.
    #[must_use]
    pub const fn is_custom(self) -> bool {
        self.0 >= Self::CUSTOM_START
    }
}

/// A single command from an unprivileged caller to the privileged daemon.
///
/// `payload` is opaque bytes interpreted per-`kind` by the consumer's
/// [`CommandExecutor`](https://docs.rs/tpt-privd-policy) implementation.
/// The envelope layer never inspects it (except to hash it for the audit
/// log).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    /// Caller-chosen correlation id, echoed in the result.
    pub id: CommandId,
    /// Envelope format version. Must equal [`ENVELOPE_VERSION`].
    pub version: u32,
    /// Which command this is (built-in or consumer-defined).
    pub kind: CommandKind,
    /// Opaque per-kind payload.
    pub payload: Vec<u8>,
}

impl Command {
    /// Build a command at the current [`ENVELOPE_VERSION`].
    #[must_use]
    pub fn new(id: CommandId, kind: CommandKind, payload: Vec<u8>) -> Self {
        Self {
            id,
            version: ENVELOPE_VERSION,
            kind,
            payload,
        }
    }
}

/// Successful execution of a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSuccess {
    /// Opaque per-kind response payload (e.g. echo output).
    pub payload: Vec<u8>,
}

/// Machine-readable failure classification for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// `cmd.version` did not match the daemon's [`ENVELOPE_VERSION`].
    UnsupportedVersion,
    /// The policy check rejected the command before execution.
    PolicyDenied,
    /// The executor attempted the command and it failed.
    ExecutionFailed,
    /// Unexpected internal error (audit write failure, framing bug, etc.).
    Internal,
}

/// Structured error attached to a failed [`CommandResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandError {
    /// Why it failed, in machine-readable form.
    pub code: ErrorCode,
    /// Human-readable detail for logs and callers. Never contains secrets.
    pub message: String,
}

impl CommandError {
    /// Convenience constructor.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Where in the audit log this command's record landed.
///
/// Returned to the caller so it can reference the exact tamper-evident
/// record without the daemon re-reading the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogRef {
    /// Zero-based sequence number of the record.
    pub seq: u64,
    /// Hex-encoded SHA-256 of the record (the chain hash, not the
    /// Ed25519 signature).
    pub hash: String,
}

/// The daemon's reply to a single [`Command`].
///
/// Always carries an [`AuditLogRef`]: every command — success, policy
/// denial, version mismatch, execution failure — is audit-logged before the
/// reply is sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    /// Echo of the request's [`CommandId`].
    pub id: CommandId,
    /// Success or structured failure.
    pub outcome: Result<CommandSuccess, CommandError>,
    /// Reference to the audit-log record for this command.
    pub audit_ref: AuditLogRef,
}

impl CommandResult {
    /// Build a successful result.
    #[must_use]
    pub fn ok(id: CommandId, payload: Vec<u8>, audit_ref: AuditLogRef) -> Self {
        Self {
            id,
            outcome: Ok(CommandSuccess { payload }),
            audit_ref,
        }
    }

    /// Build a failed result.
    #[must_use]
    pub fn err(id: CommandId, error: CommandError, audit_ref: AuditLogRef) -> Self {
        Self {
            id,
            outcome: Err(error),
            audit_ref,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_new_uses_current_version() {
        let c = Command::new(CommandId(7), CommandKind::NOP, vec![]);
        assert_eq!(c.version, ENVELOPE_VERSION);
    }

    #[test]
    fn custom_kind_range() {
        assert!(!CommandKind::NOP.is_custom());
        assert!(!CommandKind::ECHO.is_custom());
        assert!(!CommandKind::METRICS.is_custom());
        assert!(CommandKind(CommandKind::CUSTOM_START).is_custom());
        assert!(CommandKind(0x8000_0042).is_custom());
    }

    #[test]
    fn result_constructors() {
        let id = CommandId(1);
        let ar = AuditLogRef {
            seq: 0,
            hash: "00".repeat(32),
        };
        let ok = CommandResult::ok(id, b"hi".to_vec(), ar.clone());
        assert_eq!(ok.outcome.as_ref().unwrap().payload, b"hi");
        assert_eq!(ok.audit_ref, ar);

        let err = CommandResult::err(
            id,
            CommandError::new(ErrorCode::PolicyDenied, "nope"),
            ar.clone(),
        );
        assert_eq!(
            err.outcome.as_ref().unwrap_err().code,
            ErrorCode::PolicyDenied
        );
        assert_eq!(err.audit_ref, ar);
    }
}
