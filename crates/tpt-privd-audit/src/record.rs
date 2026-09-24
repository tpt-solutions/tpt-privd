//! The on-disk audit record type and its canonical hash form.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tpt_privd_envelope::{CommandId, CommandKind, ErrorCode};

/// High-level outcome recorded for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Policy check failed; command was not executed.
    PolicyDenied,
    /// Executor ran and returned success.
    Executed,
    /// Executor ran and returned failure.
    ExecutionFailed,
    /// Rejected before policy/exec because `version` did not match.
    VersionMismatch,
    /// Unexpected internal error while handling the connection.
    InternalError,
}

/// One tamper-evident audit record.
///
/// Serialized as a single JSON object per line (see crate docs). Binary
/// fields are hex strings in the JSON representation for readability; the
/// hash/signature are always computed over [`AuditRecord::canonical_bytes`],
/// never over the JSON text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Zero-based sequence number, strictly increasing by 1.
    pub seq: u64,
    /// Unix timestamp in milliseconds (UTC).
    pub ts_ms: u64,
    /// SHA-256 of the previous record's `hash` (32 zero bytes for `seq == 0`).
    pub prev_hash: String,
    /// SHA-256 of this record's [`AuditRecord::canonical_bytes`].
    pub hash: String,
    /// Hex-encoded 64-byte Ed25519 signature over the `hash` bytes.
    pub sig: String,
    /// Echo of the command's [`CommandId`].
    pub command_id: u64,
    /// Echo of the command's envelope version.
    pub command_version: u32,
    /// Echo of the command's kind value.
    pub command_kind: u32,
    /// SHA-256 of the command payload (not the payload itself).
    pub payload_sha256: String,
    /// Connecting process's effective UID from `SO_PEERCRED`, if available.
    pub caller_uid: Option<u32>,
    /// What happened.
    pub outcome: AuditOutcome,
    /// Structured error code, present iff `outcome` is a failure variant.
    pub error_code: Option<ErrorCode>,
    /// SHA-256 of the result payload on success (not the payload itself).
    pub result_sha256: Option<String>,
}

impl AuditRecord {
    /// Fixed-order binary form over which `hash` and `sig` are computed.
    ///
    /// Layout (all integers little-endian unless noted):
    ///
    /// ```text
    /// seq:u64 | ts_ms:u64 | prev_hash:32B | command_id:u64 |
    /// command_version:u32 | command_kind:u32 | payload_sha256:32B |
    /// caller_uid_tag:u8 (0=none,1=present) | [caller_uid:u32] |
    /// outcome_tag:u8 | error_code_tag:u8 (0=none,1=present) | [error_code:u8] |
    /// result_sha256_tag:u8 (0=none,1=present) | [result_sha256:32B]
    /// ```
    ///
    /// Deterministic, allocation-light, and independent of JSON key order
    /// or whitespace.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&self.ts_ms.to_le_bytes());
        buf.extend_from_slice(&decode_32(&self.prev_hash));
        buf.extend_from_slice(&self.command_id.to_le_bytes());
        buf.extend_from_slice(&self.command_version.to_le_bytes());
        buf.extend_from_slice(&self.command_kind.to_le_bytes());
        buf.extend_from_slice(&decode_32(&self.payload_sha256));

        match self.caller_uid {
            None => buf.push(0),
            Some(uid) => {
                buf.push(1);
                buf.extend_from_slice(&uid.to_le_bytes());
            }
        }

        buf.push(outcome_tag(self.outcome));

        match self.error_code {
            None => buf.push(0),
            Some(code) => {
                buf.push(1);
                buf.push(error_code_tag(code));
            }
        }

        match &self.result_sha256 {
            None => buf.push(0),
            Some(h) => {
                buf.push(1);
                buf.extend_from_slice(&decode_32(h));
            }
        }

        buf
    }

    /// SHA-256 of [`AuditRecord::canonical_bytes`], hex-encoded lowercase.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hex::encode(hasher.finalize())
    }
}

fn outcome_tag(outcome: AuditOutcome) -> u8 {
    match outcome {
        AuditOutcome::PolicyDenied => 0,
        AuditOutcome::Executed => 1,
        AuditOutcome::ExecutionFailed => 2,
        AuditOutcome::VersionMismatch => 3,
        AuditOutcome::InternalError => 4,
    }
}

fn error_code_tag(code: ErrorCode) -> u8 {
    match code {
        ErrorCode::UnsupportedVersion => 0,
        ErrorCode::PolicyDenied => 1,
        ErrorCode::ExecutionFailed => 2,
        ErrorCode::Internal => 3,
        // ErrorCode is #[non_exhaustive]; future variants get a distinct tag.
        // Using a high sentinel keeps them from colliding with known codes.
        _ => 255,
    }
}

fn decode_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).unwrap_or_default();
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Build the `payload_sha256` / `result_sha256` hex string for `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

// Keep CommandId/CommandKind referenced so rustdoc links resolve in this module.
#[allow(dead_code)]
fn _doc_links(_: CommandId, _: CommandKind) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditRecord {
        AuditRecord {
            seq: 3,
            ts_ms: 1_700_000_000_000,
            prev_hash: "11".repeat(32),
            hash: String::new(), // filled by caller
            sig: String::new(),
            command_id: 42,
            command_version: 1,
            command_kind: 0x8000_0001,
            payload_sha256: "aa".repeat(32),
            caller_uid: Some(1000),
            outcome: AuditOutcome::Executed,
            error_code: None,
            result_sha256: Some("bb".repeat(32)),
        }
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let a = sample();
        let b = sample();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_change_with_seq() {
        let mut a = sample();
        let mut b = sample();
        b.seq = 4;
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        a.seq = 4;
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn hash_is_stable_hex_sha256() {
        let r = sample();
        let h1 = r.compute_hash();
        let h2 = r.compute_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        // Must match independent sha256 of canonical bytes.
        let mut hasher = Sha256::new();
        hasher.update(r.canonical_bytes());
        assert_eq!(h1, hex::encode(hasher.finalize()));
    }

    #[test]
    fn optional_fields_affect_canonical_bytes() {
        let with_uid = sample();
        let mut without_uid = sample();
        without_uid.caller_uid = None;
        assert_ne!(with_uid.canonical_bytes(), without_uid.canonical_bytes());

        let with_result = sample();
        let mut without_result = sample();
        without_result.result_sha256 = None;
        assert_ne!(
            with_result.canonical_bytes(),
            without_result.canonical_bytes()
        );

        // Flip only caller_uid on an otherwise-identical pair.
        let mut a = sample();
        let mut b = sample();
        a.caller_uid = Some(999);
        b.caller_uid = Some(1000);
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());

        // Different result hashes.
        let mut c = sample();
        let mut d = sample();
        c.result_sha256 = Some("ff".repeat(32));
        d.result_sha256 = Some("ee".repeat(32));
        assert_ne!(c.canonical_bytes(), d.canonical_bytes());
    }

    #[test]
    fn outcome_tags_differ() {
        let mut r = sample();
        r.outcome = AuditOutcome::PolicyDenied;
        let policy = r.canonical_bytes();
        r.outcome = AuditOutcome::Executed;
        let executed = r.canonical_bytes();
        r.outcome = AuditOutcome::ExecutionFailed;
        let failed = r.canonical_bytes();
        r.outcome = AuditOutcome::VersionMismatch;
        let mismatch = r.canonical_bytes();
        r.outcome = AuditOutcome::InternalError;
        let internal = r.canonical_bytes();

        let all = [&policy, &executed, &failed, &mismatch, &internal];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "outcome tags {i} and {j} must differ");
                }
            }
        }
    }

    #[test]
    fn sha256_hex_known_value() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn decode_32_handles_bad_hex_as_zeros() {
        assert_eq!(decode_32("not-hex"), [0u8; 32]);
        assert_eq!(decode_32(""), [0u8; 32]);
    }

    #[test]
    fn json_roundtrip_preserves_logical_content() {
        let mut r = sample();
        r.hash = r.compute_hash();
        r.sig = "ab".repeat(64);
        let json = serde_json::to_string(&r).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert_eq!(r.canonical_bytes(), back.canonical_bytes());
    }
}
