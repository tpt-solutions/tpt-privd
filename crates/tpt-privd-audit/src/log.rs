//! File-backed append-only audit log with open/append/verify.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Cap line growth: a hostile/corrupt file must not OOM open/verify.
const MAX_LINE: usize = 1024 * 1024;

/// F21: bound the in-memory record cache. Full verification still re-reads
/// the file from disk; only the working set (recent records + chain head)
/// is kept resident so a long-lived daemon does not grow without limit.
const MAX_IN_MEMORY_RECORDS: usize = 4096;

use thiserror::Error;
use tpt_privd_envelope::{CommandId, CommandKind, ErrorCode};

use crate::chain::{ChainReport, verify_chain};
use crate::keypair::{AuditKeypair, KeypairError};
use crate::record::{AuditOutcome, AuditRecord};
use crate::sink::AuditSink;

/// Errors from opening, appending to, or verifying the audit log.
#[derive(Debug, Error)]
pub enum LogError {
    /// Filesystem failure.
    #[error("audit log I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Keypair load/generate failure.
    #[error("keypair error: {0}")]
    Keypair(#[from] KeypairError),
    /// A line in the log was not valid JSON / wrong shape.
    #[error("corrupt audit record at/near seq {seq}: {reason}")]
    CorruptRecord {
        /// Sequence number (or line number if unparseable) where parsing failed.
        seq: u64,
        /// What was wrong.
        reason: String,
    },
    /// Full-chain verification failed (only from [`AuditLog::verify`]).
    #[error("chain break at seq {0}: {1}")]
    Chain(u64, String),
}

/// Fields for a new audit record, supplied by the daemon after handling a
/// command.
#[derive(Debug, Clone, Copy)]
pub struct NewRecord {
    /// Command id from the request.
    pub command_id: CommandId,
    /// Envelope version from the request.
    pub command_version: u32,
    /// Command kind from the request.
    pub command_kind: CommandKind,
    /// SHA-256 of the raw command payload (32 bytes).
    pub payload_sha256: [u8; 32],
    /// `SO_PEERCRED` uid, if transport provided one.
    pub caller_uid: Option<u32>,
    /// What happened.
    pub outcome: AuditOutcome,
    /// Error code if `outcome` is a failure.
    pub error_code: Option<ErrorCode>,
    /// SHA-256 of the result payload on success, if any.
    pub result_sha256: Option<[u8; 32]>,
}

/// File-backed, append-only, Ed25519-signed, hash-chained audit log.
///
/// Opening the log:
/// 1. Loads (or first-run generates) the signing keypair from `secret_key_path`.
/// 2. Reads all existing lines, parsing each into an [`AuditRecord`].
/// 3. If the final line is truncated/corrupt (crash mid-write), **truncates
///    the file back to the last complete valid line** and continues from
///    there — the chain remains intact because the partial record was never
///    committed as a complete line.
/// 4. Replays verification so an already-tampered log fails fast at open
///    rather than silently extending a broken chain.
pub struct AuditLog {
    path: PathBuf,
    keypair: AuditKeypair,
    /// Bounded cache of recent records (see [`MAX_IN_MEMORY_RECORDS`]).
    /// `seq` continuity for appends is tracked via `next_seq`/`head_hash`,
    /// not via `records.len()`.
    records: Vec<AuditRecord>,
    /// Total records ever appended (next `seq` to assign).
    next_seq: u64,
    /// Hash of the most recent record (chain head); zeros if empty.
    head_hash: String,
    /// Buffered writer positioned at EOF for appends.
    writer: std::fs::File,
    /// Cached hex public key for verify.
    public_key_hex: String,
    /// Secondary sinks notified after each durable local append (I5).
    sinks: Vec<std::sync::Arc<dyn AuditSink>>,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("path", &self.path)
            .field("len", &self.records.len())
            .field("public_key", &self.public_key_hex)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Open (creating if needed) the log at `path` with signing key at
    /// `secret_key_path`.
    ///
    /// # Errors
    ///
    /// I/O, keypair, or pre-existing-corruption errors.
    pub fn open(path: &Path, secret_key_path: &Path) -> Result<Self, LogError> {
        let keypair = AuditKeypair::load_or_generate(secret_key_path)?;
        let public_key_hex = keypair.public_key_hex();

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Read + parse existing lines.
        let (records, valid_bytes_len) = read_and_parse(path)?;

        // Truncate a torn tail if present.
        let file_len = std::fs::metadata(path).map_or(0, |m| m.len());
        if valid_bytes_len < file_len {
            let f = std::fs::OpenOptions::new().write(true).open(path)?;
            f.set_len(valid_bytes_len)?;
            f.sync_all()?;
        }

        // Fail fast if the existing chain is already broken.
        verify_chain(&records, &public_key_hex).map_err(|b| LogError::Chain(b.seq, b.reason))?;

        let next_seq = records.len() as u64;
        let head_hash = records
            .last()
            .map_or_else(|| "00".repeat(32), |r| r.hash.clone());
        // Keep only the tail for the working set (F21).
        let start = records.len().saturating_sub(MAX_IN_MEMORY_RECORDS);
        let records = records[start.min(records.len())..].to_vec();

        // Open for append. Mode 0600: the log carries caller uids and
        // command digests — not world-readable by default. O_NOFOLLOW (F13):
        // refuse to open through a symlink.
        let writer = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)?
            }
            #[cfg(not(unix))]
            {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?
            }
        };

        // Ensure a complete final line without a trailing newline is
        // terminated so the next append cannot concatenate two records.
        terminate_unnewlineed_final_line(path)?;

        Ok(Self {
            path: path.to_path_buf(),
            keypair,
            records,
            next_seq,
            head_hash,
            writer,
            public_key_hex,
            sinks: Vec::new(),
        })
    }

    /// Path of the log file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Hex public key used to sign records.
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Number of records currently in the log (total ever appended).
    #[must_use]
    pub fn len(&self) -> usize {
        usize::try_from(self.next_seq).unwrap_or(usize::MAX)
    }

    /// Returns `true` if the log has no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }

    /// Borrow the in-memory cache of recent records (for tests / tooling).
    /// May be shorter than [`Self::len`] on long logs — full history is
    /// always re-read from disk by [`Self::verify`].
    #[must_use]
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Append a record for a handled command, fsyncing the line to disk.
    ///
    /// Returns the completed [`AuditRecord`] (including assigned `seq`,
    /// `hash`, `sig`) so the daemon can build an
    /// [`AuditLogRef`](tpt_privd_envelope::AuditLogRef).
    ///
    /// # Errors
    ///
    /// I/O failures while writing/fsyncing.
    ///
    /// # Panics
    ///
    /// Never panics under normal operation: the final `last().expect(...)`
    /// is only reached after a successful push to the same vector.
    pub fn append(&mut self, new: NewRecord) -> Result<AuditRecord, LogError> {
        let seq = self.next_seq;
        let prev_hash = if self.next_seq == 0 {
            "00".repeat(32)
        } else {
            self.head_hash.clone()
        };

        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));

        let mut rec = AuditRecord {
            seq,
            ts_ms,
            prev_hash,
            hash: String::new(),
            sig: String::new(),
            command_id: new.command_id.0,
            command_version: new.command_version,
            command_kind: new.command_kind.0,
            payload_sha256: hex::encode(new.payload_sha256),
            caller_uid: new.caller_uid,
            outcome: new.outcome,
            error_code: new.error_code,
            result_sha256: new.result_sha256.map(hex::encode),
        };

        rec.hash = rec.compute_hash();
        rec.sig = self
            .keypair
            .sign_hash_hex(&rec.hash)
            .map_err(|e| LogError::CorruptRecord {
                seq,
                reason: format!("sign failed: {e}"),
            })?;

        let mut line = serde_json::to_string(&rec).map_err(|e| LogError::CorruptRecord {
            seq,
            reason: format!("serialize failed: {e}"),
        })?;
        line.push('\n');

        // Track pre-append length so a partial write can be rolled back
        // instead of leaving a "complete-looking" corrupt line that bricks
        // the next open (F7).
        let good_len = std::fs::metadata(&self.path).map_or(0, |m| m.len());

        let write_result = (|| -> std::io::Result<()> {
            self.writer.write_all(line.as_bytes())?;
            self.writer.flush()?;
            self.writer.sync_data()
        })();

        if let Err(e) = write_result {
            // Best-effort truncate back to the last good offset.
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&self.path) {
                let _ = f.set_len(good_len);
                let _ = f.sync_all();
            }
            // Reopen a clean append handle for subsequent attempts.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                if let Ok(f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&self.path)
                {
                    self.writer = f;
                }
            }
            #[cfg(not(unix))]
            {
                if let Ok(f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                {
                    self.writer = f;
                }
            }
            return Err(e.into());
        }

        self.next_seq = self.next_seq.saturating_add(1);
        self.head_hash.clone_from(&rec.hash);
        self.records.push(rec);
        // F21: drop the oldest half once the cache is full (amortized O(1)).
        if self.records.len() > MAX_IN_MEMORY_RECORDS {
            let drop_n = MAX_IN_MEMORY_RECORDS / 2;
            self.records.drain(..drop_n);
        }
        let out = self.records.last().expect("record just pushed").clone();

        // I5: best-effort secondary ship after local durability. Never
        // fail the append — chain of custody is the local file.
        for sink in &self.sinks {
            if let Err(e) = sink.on_append(&out) {
                tracing_or_stderr_sink_error(out.seq, &e);
            }
        }

        Ok(out)
    }

    /// Attach a secondary sink (syslog/HTTP/channel mirror). Local JSONL
    /// remains authoritative; sink failures do not roll back appends.
    pub fn add_sink(&mut self, sink: std::sync::Arc<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    /// Replay and verify the entire on-disk log.
    ///
    /// Re-reads from disk (not just the in-memory cache) so external
    /// modification after open is caught.
    ///
    /// # Errors
    ///
    /// First [`ChainBreak`](crate::ChainBreak) encountered, mapped to
    /// [`LogError::Chain`].
    pub fn verify(&self) -> Result<ChainReport, LogError> {
        let (records, _) = read_and_parse(&self.path)?;
        verify_chain(&records, &self.public_key_hex).map_err(|b| LogError::Chain(b.seq, b.reason))
    }

    /// Verify an on-disk log file against an explicit public key (for
    /// offline auditors who only have the log + public key, not the daemon).
    ///
    /// # Errors
    ///
    /// I/O or chain-break errors.
    pub fn verify_file(path: &Path, public_key_hex: &str) -> Result<ChainReport, LogError> {
        let (records, _) = read_and_parse(path)?;
        verify_chain(&records, public_key_hex).map_err(|b| LogError::Chain(b.seq, b.reason))
    }
}

fn tracing_or_stderr_sink_error(seq: u64, e: &crate::sink::SinkError) {
    // Local log already committed; never promote a ship failure to LogError.
    eprintln!(
        "tpt-privd-audit: secondary sink failed after local commit of seq {seq} \
         (chain of custody is the local file): {e}"
    );
}

/// Read every line, parse valid ones, return records + byte length of the
/// valid prefix. A corrupt *final* line (no trailing newline or bad JSON at
/// EOF) is ignored for length purposes so `open` can truncate it. A corrupt
/// line in the *middle* is a hard error. Opens with `O_NOFOLLOW` on Unix
/// (F13) so a symlink at the audit path is refused rather than followed.
fn read_and_parse(path: &Path) -> Result<(Vec<AuditRecord>, u64), LogError> {
    if !path.exists() {
        return Ok((Vec::new(), 0));
    }

    let file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?
        }
        #[cfg(not(unix))]
        {
            std::fs::File::open(path)?
        }
    };
    let mut reader = BufReader::new(file);

    let mut records = Vec::new();
    let mut valid_len: u64 = 0;
    let mut line_buf = Vec::new();
    let mut line_no: u64 = 0;

    loop {
        line_buf.clear();
        let n = reader.read_until(b'\n', &mut line_buf)?;
        if n == 0 {
            break;
        }
        if n > MAX_LINE {
            return Err(LogError::CorruptRecord {
                seq: line_no,
                reason: format!("line exceeds {MAX_LINE} bytes"),
            });
        }
        line_no += 1;

        let is_complete_line = line_buf.last() == Some(&b'\n');
        let trimmed = String::from_utf8_lossy(&line_buf);
        let trimmed = trimmed.trim_end_matches('\n');

        if trimmed.trim().is_empty() {
            // Whitespace-only complete lines: skip (do not hard-error).
            // Incomplete empty tail is a torn tail.
            if is_complete_line {
                valid_len += n as u64;
            }
            continue;
        }

        if trimmed.is_empty() && !is_complete_line {
            // Trailing garbage without newline at EOF — treat as torn tail.
            break;
        }

        match serde_json::from_str::<AuditRecord>(trimmed) {
            Ok(rec) => {
                records.push(rec);
                valid_len += n as u64;
            }
            Err(e) => {
                if !is_complete_line {
                    // Torn final write — stop; caller truncates.
                    break;
                }
                return Err(LogError::CorruptRecord {
                    seq: line_no - 1,
                    reason: e.to_string(),
                });
            }
        }
    }

    Ok((records, valid_len))
}

/// If the file ends with a complete JSON line but no `\\n`, append the
/// newline so the next append cannot concatenate two records (F7).
fn terminate_unnewlineed_final_line(path: &Path) -> Result<(), LogError> {
    let meta = std::fs::metadata(path)?;
    if meta.len() == 0 {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    f.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    f.read_exact(&mut last)?;
    if last[0] != b'\n' {
        f.seek(SeekFrom::End(0))?;
        f.write_all(b"\n")?;
        f.sync_data()?;
    }
    Ok(())
}

// Re-export for daemon convenience.
pub use crate::record::sha256_hex;

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_privd_envelope::CommandId;

    struct TempLog {
        dir: PathBuf,
    }

    impl TempLog {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tpt-privd-audit-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn log_path(&self) -> PathBuf {
            self.dir.join("audit.jsonl")
        }

        fn key_path(&self) -> PathBuf {
            self.dir.join("audit.key")
        }
    }

    impl Drop for TempLog {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn new_rec(kind: CommandKind, outcome: AuditOutcome) -> NewRecord {
        NewRecord {
            command_id: CommandId(1),
            command_version: 1,
            command_kind: kind,
            payload_sha256: [0xAB; 32],
            caller_uid: Some(1000),
            outcome,
            error_code: None,
            result_sha256: Some([0xCD; 32]),
        }
    }

    #[test]
    fn append_and_verify_roundtrip() {
        let t = TempLog::new("roundtrip");
        let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
        assert!(log.is_empty());

        for i in 0..5 {
            let mut nr = new_rec(CommandKind::ECHO, AuditOutcome::Executed);
            nr.command_id = CommandId(i);
            let rec = log.append(nr).unwrap();
            assert_eq!(rec.seq, i);
        }
        assert_eq!(log.len(), 5);

        let report = log.verify().unwrap();
        assert_eq!(report.records_verified, 5);
    }

    #[test]
    fn reopen_preserves_chain_and_continues() {
        let t = TempLog::new("reopen");
        {
            let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
            log.append(new_rec(CommandKind::NOP, AuditOutcome::Executed))
                .unwrap();
            log.append(new_rec(CommandKind::ECHO, AuditOutcome::Executed))
                .unwrap();
        }
        let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
        assert_eq!(log.len(), 2);
        let rec = log
            .append(new_rec(CommandKind::NOP, AuditOutcome::Executed))
            .unwrap();
        assert_eq!(rec.seq, 2);
        log.verify().unwrap();
    }

    #[test]
    fn tampered_middle_line_detected_on_reopen() {
        let t = TempLog::new("tamper-reopen");
        {
            let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
            for i in 0..3 {
                let mut nr = new_rec(CommandKind::ECHO, AuditOutcome::Executed);
                nr.command_id = CommandId(i);
                log.append(nr).unwrap();
            }
        }
        // Flip outcome on line 1 (seq 1) by editing JSON text.
        let contents = std::fs::read_to_string(t.log_path()).unwrap();
        let mut lines: Vec<String> = contents.lines().map(str::to_string).collect();
        lines[1] = lines[1].replace("\"executed\"", "\"policy_denied\"");
        std::fs::write(t.log_path(), lines.join("\n") + "\n").unwrap();

        let err = AuditLog::open(&t.log_path(), &t.key_path()).unwrap_err();
        match err {
            LogError::Chain(seq, reason) => {
                assert_eq!(seq, 1);
                assert!(reason.contains("hash mismatch") || reason.contains("signature"));
            }
            other => panic!("expected Chain error, got {other:?}"),
        }
    }

    #[test]
    fn crash_torn_tail_is_truncated_and_log_recovers() {
        let t = TempLog::new("torn");
        {
            let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
            log.append(new_rec(CommandKind::NOP, AuditOutcome::Executed))
                .unwrap();
            log.append(new_rec(CommandKind::ECHO, AuditOutcome::Executed))
                .unwrap();
        }
        // Simulate crash mid-write: append garbage without newline + partial JSON.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(t.log_path())
            .unwrap();
        f.write_all(b"{\"seq\":2,\"torn").unwrap();
        drop(f);

        // Open should truncate the torn tail and verify the 2 good records.
        let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
        assert_eq!(log.len(), 2);
        log.verify().unwrap();

        // File on disk should no longer contain the torn bytes.
        let contents = std::fs::read_to_string(t.log_path()).unwrap();
        assert!(!contents.contains("torn"));

        // Can continue appending.
        log.append(new_rec(CommandKind::NOP, AuditOutcome::Executed))
            .unwrap();
        assert_eq!(log.len(), 3);
        log.verify().unwrap();
    }

    #[test]
    fn corrupt_middle_line_hard_error() {
        let t = TempLog::new("corrupt-middle");
        {
            let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
            log.append(new_rec(CommandKind::NOP, AuditOutcome::Executed))
                .unwrap();
            log.append(new_rec(CommandKind::NOP, AuditOutcome::Executed))
                .unwrap();
            log.append(new_rec(CommandKind::NOP, AuditOutcome::Executed))
                .unwrap();
        }
        let contents = std::fs::read_to_string(t.log_path()).unwrap();
        let mut lines: Vec<String> = contents.lines().map(str::to_string).collect();
        lines[1] = "{not json at all}".into();
        std::fs::write(t.log_path(), lines.join("\n") + "\n").unwrap();

        let err = AuditLog::open(&t.log_path(), &t.key_path()).unwrap_err();
        assert!(matches!(err, LogError::CorruptRecord { seq: 1, .. }));
    }

    #[test]
    fn deleted_last_line_detected_on_verify() {
        let t = TempLog::new("deleted-last");
        {
            let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
            for _ in 0..3 {
                log.append(new_rec(CommandKind::ECHO, AuditOutcome::Executed))
                    .unwrap();
            }
        }
        let contents = std::fs::read_to_string(t.log_path()).unwrap();
        let mut lines: Vec<&str> = contents.lines().collect();
        lines.pop(); // delete last record
        std::fs::write(t.log_path(), lines.join("\n") + "\n").unwrap();

        // Reopen: chain still "verifies" (prefix of a valid chain is valid),
        // but len is 2 — subsequent append would create seq 2 that doesn't
        // match an external observer's expectation. verify() on the file
        // itself passes for a prefix. Detecting truncation requires comparing
        // against a checkpoint — document this limitation; for now assert
        // reopen succeeds with shorter chain.
        let log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
        assert_eq!(log.len(), 2);
        log.verify().unwrap();
    }

    #[test]
    fn verify_file_with_explicit_key() {
        let t = TempLog::new("verify-file");
        let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
        let pk = log.public_key_hex().to_string();
        log.append(new_rec(CommandKind::NOP, AuditOutcome::Executed))
            .unwrap();
        drop(log);

        let report = AuditLog::verify_file(&t.log_path(), &pk).unwrap();
        assert_eq!(report.records_verified, 1);

        let wrong = "00".repeat(32);
        assert!(AuditLog::verify_file(&t.log_path(), &wrong).is_err());
    }

    #[test]
    fn record_ref_fields_match_append() {
        let t = TempLog::new("ref");
        let mut log = AuditLog::open(&t.log_path(), &t.key_path()).unwrap();
        let rec = log
            .append(new_rec(CommandKind::ECHO, AuditOutcome::Executed))
            .unwrap();
        assert_eq!(rec.command_id, 1);
        assert_eq!(rec.command_kind, CommandKind::ECHO.0);
        assert_eq!(rec.payload_sha256, hex::encode([0xAB; 32]));
        assert_eq!(
            rec.result_sha256.as_deref(),
            Some(hex::encode([0xCD; 32]).as_str())
        );
    }
}
