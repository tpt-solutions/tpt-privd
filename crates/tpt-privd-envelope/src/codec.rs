//! CBOR encode/decode for [`Command`] and [`CommandResult`].

use crate::error::CodecError;
use crate::types::{Command, CommandResult};

/// Encode a [`Command`] to CBOR bytes.
///
/// # Errors
///
/// Returns [`CodecError::Encode`] if serialization fails (should not happen
/// for these plain data types).
pub fn encode(cmd: &Command) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(cmd, &mut buf)?;
    Ok(buf)
}

/// Decode a [`Command`] from CBOR bytes.
///
/// # Errors
///
/// Returns [`CodecError::Decode`] on malformed, truncated, or
/// wrong-shaped input. Never panics.
pub fn decode(bytes: &[u8]) -> Result<Command, CodecError> {
    ciborium::from_reader(bytes).map_err(Into::into)
}

/// Encode a [`CommandResult`] to CBOR bytes.
///
/// # Errors
///
/// Returns [`CodecError::Encode`] if serialization fails.
pub fn encode_result(result: &CommandResult) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::into_writer(result, &mut buf)?;
    Ok(buf)
}

/// Decode a [`CommandResult`] from CBOR bytes.
///
/// # Errors
///
/// Returns [`CodecError::Decode`] on malformed input. Never panics.
pub fn decode_result(bytes: &[u8]) -> Result<CommandResult, CodecError> {
    ciborium::from_reader(bytes).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ENVELOPE_VERSION;
    use crate::types::{
        AuditLogRef, CommandError, CommandId, CommandKind, CommandSuccess, ErrorCode,
    };

    fn sample_command() -> Command {
        Command::new(CommandId(42), CommandKind::ECHO, b"hello world".to_vec())
    }

    fn sample_result() -> CommandResult {
        CommandResult {
            id: CommandId(42),
            outcome: Ok(CommandSuccess {
                payload: b"hello world".to_vec(),
            }),
            audit_ref: AuditLogRef {
                seq: 7,
                hash: "ab".repeat(32),
            },
        }
    }

    #[test]
    fn command_roundtrip() {
        let cmd = sample_command();
        let bytes = encode(&cmd).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(cmd, decoded);
    }

    #[test]
    fn command_roundtrip_empty_payload() {
        let cmd = Command::new(CommandId(0), CommandKind::NOP, vec![]);
        let bytes = encode(&cmd).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(cmd, decoded);
        assert_eq!(decoded.payload.len(), 0);
    }

    #[test]
    fn command_roundtrip_custom_kind() {
        let cmd = Command::new(
            CommandId(1),
            CommandKind(CommandKind::CUSTOM_START + 9),
            vec![1, 2, 3],
        );
        let bytes = encode(&cmd).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(cmd, decoded);
        assert!(decoded.kind.is_custom());
    }

    #[test]
    fn result_roundtrip_success() {
        let r = sample_result();
        let bytes = encode_result(&r).unwrap();
        let decoded = decode_result(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn result_roundtrip_error() {
        let r = CommandResult {
            id: CommandId(9),
            outcome: Err(CommandError::new(
                ErrorCode::UnsupportedVersion,
                "bad version",
            )),
            audit_ref: AuditLogRef {
                seq: 0,
                hash: "00".repeat(32),
            },
        };
        let bytes = encode_result(&r).unwrap();
        let decoded = decode_result(&bytes).unwrap();
        assert_eq!(r, decoded);
        let err = decoded.outcome.unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);
    }

    #[test]
    fn decode_rejects_empty() {
        assert!(decode(&[]).is_err());
        assert!(decode_result(&[]).is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        // Never-panics on arbitrary bytes; all must return Err.
        let cases: &[&[u8]] = &[
            &[0xff, 0xfe, 0xfd],
            &[0x00],
            &[0xa1],             // map(1) with no key
            &[0x1a, 0xff, 0xff], // truncated
            b"not cbor at all",
        ];
        for case in cases {
            assert!(decode(case).is_err(), "expected err for {case:?}");
            assert!(decode_result(case).is_err(), "expected err for {case:?}");
        }
    }

    #[test]
    fn decode_rejects_wrong_shape() {
        // Encode a bare map that is not a Command (missing required fields).
        let mut buf = Vec::new();
        ciborium::into_writer(&std::collections::BTreeMap::<u8, u8>::new(), &mut buf).unwrap();
        assert!(decode(&buf).is_err());
    }

    #[test]
    fn version_field_is_preserved_verbatim() {
        // Even if version is wrong, decode succeeds — version checking is
        // the caller's job (check_version / the daemon).
        let mut cmd = sample_command();
        cmd.version = 99;
        let bytes = encode(&cmd).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.version, 99);
        assert_ne!(decoded.version, ENVELOPE_VERSION);
    }

    #[test]
    fn malformed_bytes_never_panic_deterministic_scan() {
        // Exhaustive-ish scan of short byte strings: decoder must return
        // Result, never panic.
        for len in 0..4usize {
            let max = 1u64 << (8 * len.min(3));
            for i in 0..max.min(4096) {
                let mut buf = vec![0u8; len];
                for (j, b) in buf.iter_mut().enumerate() {
                    *b = ((i >> (8 * j)) & 0xff) as u8;
                }
                let _ = decode(&buf);
                let _ = decode_result(&buf);
            }
        }
    }
}
