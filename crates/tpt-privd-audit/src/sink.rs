//! Secondary audit sinks (I5): ship durable local records elsewhere
//! without changing the local hash-chain as the source of truth.

use std::sync::mpsc::{Receiver, SendError, Sender, channel};
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::record::AuditRecord;

/// Errors from a secondary sink (never fail the local append).
#[derive(Debug, Error)]
pub enum SinkError {
    /// Channel closed (shipper thread exited).
    #[error("audit sink channel closed: {0}")]
    Channel(String),
    /// I/O failure in a file-mirror sink.
    #[error("audit sink I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Custom sink failure.
    #[error("audit sink: {0}")]
    Other(String),
}

/// Secondary destination for records already durably appended locally.
///
/// # Chain of custody
///
/// The local JSONL log remains the **authoritative** chain. Sinks are
/// best-effort replicas: a sink failure is logged/counted but never rolls
/// back or blocks the local append (which has already fsynced). Offline
/// verification always uses `verify-audit` against the local file.
pub trait AuditSink: Send + Sync {
    /// Called after a successful local append (record is durable on disk).
    ///
    /// # Errors
    ///
    /// Sink-specific failure; callers of [`AuditLog::append`](crate::AuditLog::append)
    /// ignore sink errors (local chain already committed).
    fn on_append(&self, record: &AuditRecord) -> Result<(), SinkError>;
}

/// In-memory collector for tests and in-process consumers.
#[derive(Debug, Default)]
pub struct MemorySink {
    inner: Mutex<Vec<AuditRecord>>,
}

impl MemorySink {
    /// New empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of received records.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl AuditSink for MemorySink {
    fn on_append(&self, record: &AuditRecord) -> Result<(), SinkError> {
        if let Ok(mut g) = self.inner.lock() {
            g.push(record.clone());
        }
        Ok(())
    }
}

/// Function-backed sink for ad-hoc hooks.
pub struct FnSink<F>
where
    F: Fn(&AuditRecord) -> Result<(), SinkError> + Send + Sync,
{
    f: F,
}

impl<F> FnSink<F>
where
    F: Fn(&AuditRecord) -> Result<(), SinkError> + Send + Sync,
{
    /// Wrap `f` as an [`AuditSink`].
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F> AuditSink for FnSink<F>
where
    F: Fn(&AuditRecord) -> Result<(), SinkError> + Send + Sync,
{
    fn on_append(&self, record: &AuditRecord) -> Result<(), SinkError> {
        (self.f)(record)
    }
}

/// Queue handle: cloneable sender side used by [`crate::log::AuditLog`].
///
/// Pair with [`spawn_audit_shipper`] to process records on a background
/// thread (async shipping without pulling a runtime into the audit crate).
#[derive(Clone)]
pub struct AuditShipper {
    tx: Sender<AuditRecord>,
}

impl AuditShipper {
    /// Create a shipper channel. Returns `(shipper_to_attach_to_log, receiver_for_worker)`.
    #[must_use]
    pub fn channel() -> (Self, Receiver<AuditRecord>) {
        let (tx, rx) = channel();
        (Self { tx }, rx)
    }
}

impl AuditSink for AuditShipper {
    fn on_append(&self, record: &AuditRecord) -> Result<(), SinkError> {
        self.tx
            .send(record.clone())
            .map_err(|e| SinkError::Channel(format!("send failed: {e}")))
    }
}

/// Errors from a shipper worker.
#[derive(Debug, Error)]
pub enum ShipperError {
    /// Channel disconnected (log dropped).
    #[error("shipper channel disconnected: {0}")]
    Disconnected(#[from] SendError<AuditRecord>),
    /// Sink reported an error (record still durable locally).
    #[error("sink failed after local commit: {0}")]
    Sink(#[from] SinkError),
}

/// Spawn a background thread that drains `rx` into `sink` until the
/// channel closes (all `AuditShipper` clones dropped).
///
/// Returns the join handle. Sink errors are reported on stderr and the
/// worker continues — local chain is never blocked by shipping.
///
/// # Panics
///
/// If the OS refuses to spawn the thread (`thread::Builder::spawn` fails).
#[must_use]
pub fn spawn_audit_shipper(
    rx: Receiver<AuditRecord>,
    sink: Arc<dyn AuditSink>,
    name: &str,
) -> std::thread::JoinHandle<()> {
    let name = name.to_string();
    std::thread::Builder::new()
        .name(format!("audit-ship-{name}"))
        .spawn(move || {
            while let Ok(rec) = rx.recv() {
                if let Err(e) = sink.on_append(&rec) {
                    eprintln!(
                        "tpt-privd-audit: shipper {name} failed for seq {} (local log is fine): {e}",
                        rec.seq
                    );
                }
            }
        })
        .expect("spawn audit shipper thread")
}

/// JSONL mirror: append the same record lines to `path` (no re-signing —
/// copies the already-signed local record).
pub struct JsonlMirrorSink {
    file: Mutex<std::fs::File>,
}

impl JsonlMirrorSink {
    /// Open/create `path` for append. Parent dirs are created.
    ///
    /// # Errors
    ///
    /// Filesystem failures.
    pub fn open(path: &std::path::Path) -> Result<Self, SinkError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl AuditSink for JsonlMirrorSink {
    fn on_append(&self, record: &AuditRecord) -> Result<(), SinkError> {
        use std::io::Write as _;
        let mut line =
            serde_json::to_string(record).map_err(|e| SinkError::Other(e.to_string()))?;
        line.push('\n');
        let mut f = self
            .file
            .lock()
            .map_err(|_| SinkError::Other("lock poisoned".into()))?;
        f.write_all(line.as_bytes())?;
        f.flush()?;
        Ok(())
    }
}

/// Compact one-line summary for tracing/logging sinks.
#[must_use]
pub fn format_summary(rec: &AuditRecord) -> String {
    format!(
        "seq={} id={} kind={:#x} outcome={:?} caller={:?}",
        rec.seq, rec.command_id, rec.command_kind, rec.outcome, rec.caller_uid
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_privd_envelope::{CommandId, CommandKind};

    use crate::log::{AuditLog, NewRecord};
    use crate::record::AuditOutcome;

    fn new_rec(id: u64) -> NewRecord {
        NewRecord {
            command_id: CommandId(id),
            command_version: 1,
            command_kind: CommandKind::ECHO,
            payload_sha256: [0u8; 32],
            caller_uid: Some(1000),
            outcome: AuditOutcome::Executed,
            error_code: None,
            result_sha256: None,
        }
    }

    struct TempLog {
        dir: std::path::PathBuf,
    }
    impl TempLog {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tpt-privd-sink-{}-{}",
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
    impl Drop for TempLog {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn memory_sink_receives_after_local_append() {
        let t = TempLog::new();
        let mut log = AuditLog::open(&t.log(), &t.key()).unwrap();
        let mem = Arc::new(MemorySink::new());
        log.add_sink(mem.clone());
        log.append(new_rec(1)).unwrap();
        log.append(new_rec(2)).unwrap();
        assert_eq!(mem.records().len(), 2);
        assert_eq!(mem.records()[0].command_id, 1);
        log.verify().unwrap();
    }

    #[test]
    fn shipper_thread_delivers_async() {
        let t = TempLog::new();
        let mut log = AuditLog::open(&t.log(), &t.key()).unwrap();
        let (shipper, rx) = AuditShipper::channel();
        let mem = Arc::new(MemorySink::new());
        log.add_sink(Arc::new(shipper));
        let h = spawn_audit_shipper(rx, mem.clone(), "test");
        log.append(new_rec(10)).unwrap();
        log.append(new_rec(11)).unwrap();
        drop(log);
        h.join().unwrap();
        assert_eq!(mem.records().len(), 2);
    }

    #[test]
    fn jsonl_mirror_writes_lines() {
        let t = TempLog::new();
        let mirror_path = t.dir.join("mirror.jsonl");
        let mut log = AuditLog::open(&t.log(), &t.key()).unwrap();
        let mirror = JsonlMirrorSink::open(&mirror_path).unwrap();
        log.add_sink(Arc::new(mirror));
        log.append(new_rec(3)).unwrap();
        let text = std::fs::read_to_string(&mirror_path).unwrap();
        assert!(text.contains("\"command_id\":3") || text.contains("\"command_id\": 3"));
        assert!(text.lines().count() >= 1);
    }

    #[test]
    fn summary_formats() {
        let t = TempLog::new();
        let mut log = AuditLog::open(&t.log(), &t.key()).unwrap();
        let rec = log.append(new_rec(9)).unwrap();
        let s = format_summary(&rec);
        assert!(s.contains("seq=0"));
        assert!(s.contains("Executed"));
    }
}
