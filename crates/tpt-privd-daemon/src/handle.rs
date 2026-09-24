//! Core request handling: version check → policy → execute → audit → reply.
//!
//! Kept free of socket types so it is unit-testable on every platform and
//! reusable by the Unix accept loop.

use tpt_privd_audit::{AuditLog, AuditOutcome, NewRecord};
use tpt_privd_envelope::{
    AuditLogRef, Command, CommandError, CommandResult, ErrorCode, check_version, decode,
    encode_result,
};
use tpt_privd_policy::CommandExecutor;
use tpt_privd_transport::TransportError;

/// Everything [`handle_cbor_payload`] needs to process one request.
pub struct HandleDeps<'a> {
    /// The policy/execution implementation.
    pub executor: &'a dyn CommandExecutor,
    /// The audit log to append every outcome to.
    pub audit: &'a mut AuditLog,
    /// `SO_PEERCRED` uid, if the transport supplied one.
    pub caller_uid: Option<u32>,
}

/// Process one raw CBOR command payload and return the raw CBOR result
/// payload to write back on the wire.
///
/// Never returns `Err` for application-level failures (policy denial,
/// version mismatch, execution failure) — those become a `CommandResult`
/// with `outcome: Err(...)` **and a real audit record**. `Err` is reserved
/// for failures where no trustworthy reply can be built (CBOR decode
/// failure of the request, audit-log write failure).
///
/// # Errors
///
/// [`TransportError::Decode`] if the request bytes are not a valid
/// [`Command`], [`TransportError::Encode`] if the reply cannot be encoded,
/// or [`TransportError::Io`] propagated from audit-log writes.
pub fn handle_cbor_payload(
    deps: &mut HandleDeps<'_>,
    request_bytes: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let cmd = match decode(request_bytes) {
        Ok(cmd) => cmd,
        Err(e) => {
            // F16: connection-level reject — leave a chain entry so
            // malformed traffic is not invisible. No correlatable
            // CommandId exists, so use zeros + InternalError.
            crate::metrics::record_transport_reject();
            append_transport_reject(deps, request_bytes)?;
            return Err(TransportError::Decode(e.to_string()));
        }
    };

    let result = if let Err(e) = check_version(cmd.version) {
        let audit_ref = append_audit(
            deps,
            &cmd,
            AuditOutcome::VersionMismatch,
            Some(ErrorCode::UnsupportedVersion),
            None,
        )?;
        CommandResult::err(
            cmd.id,
            CommandError::new(ErrorCode::UnsupportedVersion, e.to_string()),
            audit_ref,
        )
    } else {
        // I3: built-in metrics scrape — audited like any other command,
        // answered from process counters without a second listener.
        if cmd.kind == tpt_privd_envelope::CommandKind::METRICS {
            crate::metrics::record_total();
            crate::metrics::record_metrics_scrape();
            let payload = crate::metrics::prometheus_text().into_bytes();
            let result_hash = tpt_privd_audit::sha256_hex(&payload);
            let audit_ref = append_audit(
                deps,
                &cmd,
                AuditOutcome::Executed,
                None,
                Some(result_hash.as_str()),
            )?;
            return encode_result(&CommandResult::ok(cmd.id, payload, audit_ref))
                .map_err(|e| TransportError::Encode(e.to_string()));
        }
        match deps.executor.policy_check(&cmd) {
            Err(violation) => {
                crate::metrics::record_policy_deny();
                let audit_ref = append_audit(
                    deps,
                    &cmd,
                    AuditOutcome::PolicyDenied,
                    Some(ErrorCode::PolicyDenied),
                    None,
                )?;
                CommandResult::err(
                    cmd.id,
                    CommandError::new(ErrorCode::PolicyDenied, violation.reason),
                    audit_ref,
                )
            }
            Ok(()) => match deps.executor.execute(&cmd) {
                Ok(success) => {
                    crate::metrics::record_executed();
                    let result_hash = tpt_privd_audit::sha256_hex(&success.payload);
                    let audit_ref = append_audit(
                        deps,
                        &cmd,
                        AuditOutcome::Executed,
                        None,
                        Some(result_hash.as_str()),
                    )?;
                    CommandResult::ok(cmd.id, success.payload, audit_ref)
                }
                Err(exec_err) => {
                    crate::metrics::record_execution_failure();
                    let audit_ref = append_audit(
                        deps,
                        &cmd,
                        AuditOutcome::ExecutionFailed,
                        Some(exec_err.code),
                        None,
                    )?;
                    CommandResult::err(cmd.id, exec_err, audit_ref)
                }
            },
        }
    };

    crate::metrics::record_total();
    if matches!(
        result.outcome,
        Err(ref e) if e.code == ErrorCode::UnsupportedVersion
    ) {
        crate::metrics::record_version_mismatch();
    }

    encode_result(&result).map_err(|e| TransportError::Encode(e.to_string()))
}

/// F16: best-effort connection-level reject record for undecodable frames.
/// Uses zeroed command fields — there is nothing correlatable on the wire.
/// Failure here is logged but does not mask the original decode error.
fn append_transport_reject(
    deps: &mut HandleDeps<'_>,
    request_bytes: &[u8],
) -> Result<(), TransportError> {
    let payload_hash = hex_decode_32(&tpt_privd_audit::sha256_hex(request_bytes));
    match deps.audit.append(NewRecord {
        command_id: tpt_privd_envelope::CommandId(0),
        command_version: 0,
        command_kind: tpt_privd_envelope::CommandKind(0),
        payload_sha256: payload_hash,
        caller_uid: deps.caller_uid,
        outcome: AuditOutcome::InternalError,
        error_code: Some(ErrorCode::Internal),
        result_sha256: None,
    }) {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::error!(error = %e, "transport-reject audit failed");
            Err(TransportError::Io(std::io::Error::other(format!(
                "AUDIT FAIL-STOP: transport reject audit failed: {e}"
            ))))
        }
    }
}

fn append_audit(
    deps: &mut HandleDeps<'_>,
    cmd: &Command,
    outcome: AuditOutcome,
    error_code: Option<ErrorCode>,
    result_sha256_hex: Option<&str>,
) -> Result<AuditLogRef, TransportError> {
    let payload_hash = hex_decode_32(&tpt_privd_audit::sha256_hex(&cmd.payload));
    let result_hash = result_sha256_hex.and_then(hex_decode_32_opt);

    let rec = match deps.audit.append(NewRecord {
        command_id: cmd.id,
        command_version: cmd.version,
        command_kind: cmd.kind,
        payload_sha256: payload_hash,
        caller_uid: deps.caller_uid,
        outcome,
        error_code,
        result_sha256: result_hash,
    }) {
        Ok(rec) => rec,
        Err(e) => {
            // F6: audit-write failure after (possibly) successful execute is
            // fail-stop. The privileged side effect is now invisible to the
            // chain — surface an unmissable fatal log and propagate so the
            // accept loop treats it as hard (ServeError), not a per-conn skip.
            tracing::error!(
                command_id = cmd.id.0,
                command_kind = cmd.kind.0,
                outcome = ?outcome,
                error = %e,
                "FATAL: audit append failed after command; refusing to continue \
                 silently — investigate disk/key immediately"
            );
            return Err(TransportError::Io(std::io::Error::other(format!(
                "AUDIT FAIL-STOP: {e}"
            ))));
        }
    };

    Ok(AuditLogRef {
        seq: rec.seq,
        hash: rec.hash,
    })
}

fn hex_decode_32(hex_str: &str) -> [u8; 32] {
    hex_decode_32_opt(hex_str).unwrap_or([0u8; 32])
}

fn hex_decode_32_opt(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_privd_envelope::{CommandId, CommandKind, CommandSuccess, decode_result};
    use tpt_privd_policy::PolicyViolation;

    struct FailExec;
    impl CommandExecutor for FailExec {
        fn policy_check(&self, _cmd: &Command) -> Result<(), PolicyViolation> {
            Ok(())
        }
        fn execute(&self, _cmd: &Command) -> Result<CommandSuccess, CommandError> {
            Err(CommandError::new(ErrorCode::ExecutionFailed, "boom"))
        }
    }

    struct TempAudit {
        dir: std::path::PathBuf,
    }

    impl TempAudit {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tpt-privd-handle-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }
        fn log(&self) -> std::path::PathBuf {
            self.dir.join("a.jsonl")
        }
        fn key(&self) -> std::path::PathBuf {
            self.dir.join("a.key")
        }
    }
    impl Drop for TempAudit {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn handle(
        audit: &mut AuditLog,
        executor: &dyn CommandExecutor,
        cmd: &Command,
        uid: Option<u32>,
    ) -> CommandResult {
        let mut deps = HandleDeps {
            executor,
            audit,
            caller_uid: uid,
        };
        let bytes = tpt_privd_envelope::encode(cmd).unwrap();
        let resp = handle_cbor_payload(&mut deps, &bytes).unwrap();
        decode_result(&resp).unwrap()
    }

    #[test]
    fn echo_success_returns_payload_and_audits_executed() {
        let t = TempAudit::new();
        let mut audit = AuditLog::open(&t.log(), &t.key()).unwrap();
        let exec = tpt_privd_policy::MockExecutor::new();
        let cmd = Command::new(CommandId(7), CommandKind::ECHO, b"hello".to_vec());

        let result = handle(&mut audit, &exec, &cmd, Some(1000));
        assert_eq!(result.id, CommandId(7));
        let success = result.outcome.unwrap();
        assert_eq!(success.payload, b"hello");
        assert_eq!(result.audit_ref.seq, 0);

        let recs = audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].outcome, AuditOutcome::Executed);
        assert_eq!(recs[0].caller_uid, Some(1000));
        assert_eq!(recs[0].command_id, 7);
    }

    #[test]
    fn policy_denial_is_audited_and_returned_structured() {
        let t = TempAudit::new();
        let mut audit = AuditLog::open(&t.log(), &t.key()).unwrap();
        let exec = tpt_privd_policy::MockExecutor::new();
        let cmd = Command::new(
            CommandId(3),
            CommandKind(CommandKind::CUSTOM_START + 1),
            vec![1, 2],
        );

        let result = handle(&mut audit, &exec, &cmd, None);
        let err = result.outcome.unwrap_err();
        assert_eq!(err.code, ErrorCode::PolicyDenied);
        assert!(err.message.contains("allowlist"));

        let recs = audit.records();
        assert_eq!(recs[0].outcome, AuditOutcome::PolicyDenied);
        assert_eq!(recs[0].error_code, Some(ErrorCode::PolicyDenied));
    }

    #[test]
    fn version_mismatch_is_audited_and_rejected() {
        let t = TempAudit::new();
        let mut audit = AuditLog::open(&t.log(), &t.key()).unwrap();
        let exec = tpt_privd_policy::MockExecutor::new();
        let mut cmd = Command::new(CommandId(9), CommandKind::ECHO, b"x".to_vec());
        cmd.version = 999;

        let result = handle(&mut audit, &exec, &cmd, None);
        let err = result.outcome.unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedVersion);

        let recs = audit.records();
        assert_eq!(recs[0].outcome, AuditOutcome::VersionMismatch);
    }

    #[test]
    fn execution_failure_is_audited() {
        let t = TempAudit::new();
        let mut audit = AuditLog::open(&t.log(), &t.key()).unwrap();

        let mut deps = HandleDeps {
            executor: &FailExec,
            audit: &mut audit,
            caller_uid: None,
        };
        let cmd = Command::new(CommandId(5), CommandKind::NOP, vec![]);
        let bytes = tpt_privd_envelope::encode(&cmd).unwrap();
        let resp = handle_cbor_payload(&mut deps, &bytes).unwrap();
        let result = decode_result(&resp).unwrap();
        assert_eq!(result.outcome.unwrap_err().code, ErrorCode::ExecutionFailed);
        assert_eq!(audit.records()[0].outcome, AuditOutcome::ExecutionFailed);
    }

    #[test]
    fn malformed_cbor_returns_decode_error_and_audits_transport_reject() {
        let t = TempAudit::new();
        let mut audit = AuditLog::open(&t.log(), &t.key()).unwrap();
        let exec = tpt_privd_policy::MockExecutor::new();
        let mut deps = HandleDeps {
            executor: &exec,
            audit: &mut audit,
            caller_uid: Some(42),
        };
        let err = handle_cbor_payload(&mut deps, b"not-cbor").unwrap_err();
        assert!(matches!(err, TransportError::Decode(_)));
        // F16: connection-level reject is recorded (zeros + InternalError).
        assert_eq!(audit.len(), 1);
        assert_eq!(audit.records()[0].outcome, AuditOutcome::InternalError);
        assert_eq!(audit.records()[0].caller_uid, Some(42));
        assert_eq!(audit.records()[0].command_id, 0);
        audit.verify().unwrap();
    }

    #[test]
    fn metrics_kind_returns_prometheus_text_and_audits() {
        let t = TempAudit::new();
        let mut audit = AuditLog::open(&t.log(), &t.key()).unwrap();
        let exec = tpt_privd_policy::MockExecutor::new();
        let cmd = Command::new(CommandId(11), CommandKind::METRICS, vec![]);

        let result = handle(&mut audit, &exec, &cmd, Some(1000));
        let success = result.outcome.unwrap();
        let text = String::from_utf8(success.payload).unwrap();
        assert!(text.contains("tpt_privd_commands_total"));

        let recs = audit.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].outcome, AuditOutcome::Executed);
        assert_eq!(recs[0].command_kind, CommandKind::METRICS.0);
        audit.verify().unwrap();
    }

    #[test]
    fn every_outcome_lands_in_audit_chain() {
        let t = TempAudit::new();
        let mut audit = AuditLog::open(&t.log(), &t.key()).unwrap();
        let exec = tpt_privd_policy::MockExecutor::new();

        handle(
            &mut audit,
            &exec,
            &Command::new(CommandId(1), CommandKind::ECHO, b"a".to_vec()),
            Some(1),
        );
        handle(
            &mut audit,
            &exec,
            &Command::new(
                CommandId(2),
                CommandKind(CommandKind::CUSTOM_START + 50),
                vec![],
            ),
            Some(1),
        );
        let mut bad = Command::new(CommandId(3), CommandKind::NOP, vec![]);
        bad.version = 42;
        handle(&mut audit, &exec, &bad, Some(1));

        assert_eq!(audit.len(), 3);
        audit.verify().unwrap();
    }
}
