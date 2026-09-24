//! Hash-chain verification (replay the log, check links + signatures).

use crate::keypair::verify_signature_hex;
use crate::record::AuditRecord;

/// Where verification stopped, if it failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// Sequence number of the first bad/missing record.
    pub seq: u64,
    /// Human-readable description of what failed.
    pub reason: String,
}

/// Successful full verification report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Number of records successfully verified.
    pub records_verified: u64,
    /// Hex hash of the final record (chain head), empty if log was empty.
    pub head_hash: String,
    /// Public key that signed the records (from the last record's companion
    /// verification uses caller-supplied key; this is informational from
    /// the first record if provided by caller — see [`verify_chain`]).
    pub public_key_hint: Option<String>,
}

/// Verify a complete in-memory sequence of records.
///
/// Checks, for each record in order:
/// 1. `seq` is exactly `prev.seq + 1` (or `0` for the first).
/// 2. `prev_hash` matches the previous record's `hash` (or is 32 zero bytes
///    for the first).
/// 3. Recomputed `hash` equals the stored `hash`.
/// 4. Ed25519 `sig` verifies over `hash` against `public_key_hex`.
///
/// # Errors
///
/// Returns the first [`ChainBreak`] encountered, or `Ok(report)` if the
/// entire sequence is intact.
pub fn verify_chain(
    records: &[AuditRecord],
    public_key_hex: &str,
) -> Result<ChainReport, ChainBreak> {
    let mut prev_hash = "00".repeat(32);

    for (i, rec) in records.iter().enumerate() {
        let expected_seq = i as u64;
        if rec.seq != expected_seq {
            return Err(ChainBreak {
                seq: rec.seq,
                reason: format!("expected seq {expected_seq}, found {}", rec.seq),
            });
        }

        if rec.prev_hash != prev_hash {
            return Err(ChainBreak {
                seq: rec.seq,
                reason: format!(
                    "prev_hash mismatch: stored {}, expected {prev_hash}",
                    rec.prev_hash
                ),
            });
        }

        let recomputed = rec.compute_hash();
        if recomputed != rec.hash {
            return Err(ChainBreak {
                seq: rec.seq,
                reason: format!(
                    "hash mismatch: stored {}, recomputed {recomputed} — record tampered or truncated fields",
                    rec.hash
                ),
            });
        }

        if !verify_signature_hex(public_key_hex, &rec.hash, &rec.sig) {
            return Err(ChainBreak {
                seq: rec.seq,
                reason: "Ed25519 signature verification failed".into(),
            });
        }

        prev_hash.clone_from(&rec.hash);
    }

    Ok(ChainReport {
        records_verified: records.len() as u64,
        head_hash: prev_hash,
        public_key_hint: Some(public_key_hex.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::AuditKeypair;
    use crate::record::AuditOutcome;
    use tpt_privd_envelope::CommandKind;

    fn make_record(kp: &AuditKeypair, seq: u64, prev_hash: &str) -> AuditRecord {
        let mut rec = AuditRecord {
            seq,
            ts_ms: 1_700_000_000_000 + seq,
            prev_hash: prev_hash.to_string(),
            hash: String::new(),
            sig: String::new(),
            command_id: seq,
            command_version: 1,
            command_kind: CommandKind::ECHO.0,
            payload_sha256: "aa".repeat(32),
            caller_uid: Some(1000),
            outcome: AuditOutcome::Executed,
            error_code: None,
            result_sha256: Some("bb".repeat(32)),
        };
        rec.hash = rec.compute_hash();
        rec.sig = kp.sign_hash_hex(&rec.hash).expect("valid hash hex");
        rec
    }

    fn make_chain(kp: &AuditKeypair, n: u64) -> Vec<AuditRecord> {
        let mut out = Vec::new();
        let mut prev = "00".repeat(32);
        for i in 0..n {
            let rec = make_record(kp, i, &prev);
            prev = rec.hash.clone();
            out.push(rec);
        }
        out
    }

    #[test]
    fn valid_chain_verifies() {
        let kp = AuditKeypair::generate();
        let chain = make_chain(&kp, 5);
        let report = verify_chain(&chain, &kp.public_key_hex()).unwrap();
        assert_eq!(report.records_verified, 5);
        assert_eq!(report.head_hash, chain.last().unwrap().hash);
    }

    #[test]
    fn empty_chain_verifies() {
        let kp = AuditKeypair::generate();
        let report = verify_chain(&[], &kp.public_key_hex()).unwrap();
        assert_eq!(report.records_verified, 0);
    }

    #[test]
    fn broken_prev_link_detected() {
        let kp = AuditKeypair::generate();
        let mut chain = make_chain(&kp, 3);
        chain[2].prev_hash = "ff".repeat(32);
        // Note: chain[2].hash still matches its old canonical bytes, but
        // prev_hash changed so recomputed hash ≠ stored hash → caught at 2.
        let err = verify_chain(&chain, &kp.public_key_hex()).unwrap_err();
        assert_eq!(err.seq, 2);
    }

    #[test]
    fn deleted_middle_record_detected() {
        let kp = AuditKeypair::generate();
        let mut chain = make_chain(&kp, 4);
        chain.remove(1);
        // Now indices: seq claims 0,2,3 but position expects 0,1,2.
        let err = verify_chain(&chain, &kp.public_key_hex()).unwrap_err();
        assert_eq!(err.seq, 2, "should fail at the record after the gap");
        assert!(err.reason.contains("expected seq 1"));
    }

    #[test]
    fn bitflip_in_outcome_detected() {
        let kp = AuditKeypair::generate();
        let mut chain = make_chain(&kp, 2);
        chain[1].outcome = AuditOutcome::PolicyDenied; // was Executed
        let err = verify_chain(&chain, &kp.public_key_hex()).unwrap_err();
        assert_eq!(err.seq, 1);
        assert!(err.reason.contains("hash mismatch"));
    }

    #[test]
    fn signature_from_wrong_key_detected() {
        let kp = AuditKeypair::generate();
        let other = AuditKeypair::generate();
        let chain = make_chain(&kp, 3);
        let err = verify_chain(&chain, &other.public_key_hex()).unwrap_err();
        assert_eq!(err.seq, 0);
        assert!(err.reason.contains("signature"));
    }

    #[test]
    fn rehashed_tamper_still_fails_signature() {
        // Attacker changes a field AND recomputes hash, but cannot re-sign.
        let kp = AuditKeypair::generate();
        let mut chain = make_chain(&kp, 2);
        chain[1].caller_uid = Some(0); // "was root all along?"
        chain[1].hash = chain[1].compute_hash(); // fix the hash
        // prev_hash of nothing after it in this 2-chain... actually seq 1
        // is last. Signature still old → fails.
        let err = verify_chain(&chain, &kp.public_key_hex()).unwrap_err();
        assert_eq!(err.seq, 1);
        assert!(err.reason.contains("signature"));
    }
}
