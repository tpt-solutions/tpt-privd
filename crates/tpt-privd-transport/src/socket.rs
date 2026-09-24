//! Unix domain socket listener setup and one-shot connection handling.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use crate::error::TransportError;
use crate::frame::{FrameLimits, read_frame, write_frame};
use crate::peer::{PeerCredentials, peer_credentials};

/// Configuration for binding the daemon's listening socket.
#[derive(Debug, Clone)]
pub struct SocketConfig {
    /// Filesystem path of the socket.
    pub path: std::path::PathBuf,
    /// Permission bits for the socket file (e.g. `0o660`).
    ///
    /// Combined with `owner_uid`/`owner_gid`, this is the primary access
    /// control: only processes that can open the socket can connect.
    pub mode: u32,
    /// Optional owning UID for the socket file (`chown`). `None` leaves the
    /// owner as the binding process (typically root before privilege drop).
    pub owner_uid: Option<u32>,
    /// Optional owning GID for the socket file.
    pub owner_gid: Option<u32>,
}

impl SocketConfig {
    /// Socket at `path` with mode `0o660`, owned by the binder.
    #[must_use]
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: 0o660,
            owner_uid: None,
            owner_gid: None,
        }
    }

    /// Override the socket file mode.
    #[must_use]
    pub const fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    /// Set socket file owner (uid + gid).
    #[must_use]
    pub const fn with_owner(mut self, uid: u32, gid: u32) -> Self {
        self.owner_uid = Some(uid);
        self.owner_gid = Some(gid);
        self
    }
}

/// Bind a listening Unix domain socket at `config.path`.
///
/// Creates parent directories as needed, removes a stale socket file at the
/// path (only if it is actually a socket), binds, applies mode/ownership,
/// and returns the listener. Call this **before** privilege drop so the
/// socket is owned correctly; the fd remains valid across capability drop.
///
/// # Errors
///
/// Returns [`TransportError::Socket`] on bind/permission failures, or
/// [`TransportError::Io`] on I/O errors.
pub fn bind_listener(config: &SocketConfig) -> Result<UnixListener, TransportError> {
    let path = &config.path;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                TransportError::Socket(format!("create socket dir {}: {e}", parent.display()))
            })?;
        }
    }

    // Remove a stale socket file (but never a non-socket file — refuse to
    // clobber something that isn't ours). F5: if the existing socket
    // still answers, refuse — a live daemon owns the path.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_socket() {
            if socket_answers(path) {
                return Err(TransportError::Socket(format!(
                    "socket {} is already in use by a live listener; \
                     refusing to steal the path (stop the other instance \
                     or remove the socket file manually if truly stale)",
                    path.display()
                )));
            }
            std::fs::remove_file(path).map_err(|e| {
                TransportError::Socket(format!("remove stale socket {}: {e}", path.display()))
            })?;
        } else {
            return Err(TransportError::Socket(format!(
                "refusing to bind over non-socket path {}",
                path.display()
            )));
        }
    }

    let listener = UnixListener::bind(path)
        .map_err(|e| TransportError::Socket(format!("bind {}: {e}", path.display())))?;

    // F10: apply mode/ownership on the listener *fd* (fchmod/fchown), not
    // the path — avoids the bind→chmod TOCTOU window where another process
    // could replace the path between the two calls.
    apply_listener_perms(&listener, config)?;

    Ok(listener)
}

/// Wrap a listener file descriptor already bound by systemd socket activation.
///
/// systemd sets `LISTEN_FDS` / `LISTEN_PID` and passes the listening socket
/// as fd `SD_LISTEN_FDS_START` (3). The daemon does not bind or chmod the
/// path in this mode — unit `SocketMode=`/`SocketUser=` own that.
///
/// # Errors
///
/// [`TransportError::Socket`] if the fd is not a listening Unix socket.
pub fn listener_from_fd(fd: std::os::unix::io::RawFd) -> Result<UnixListener, TransportError> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: caller guarantees `fd` is an open listening socket owned by
    // this process (systemd LISTEN_FDS contract). UnixListener takes ownership.
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    // Fail fast if systemd handed us something that is not a listener.
    // `accept` would fail later anyway; this keeps the error at startup.
    let _ = listener.local_addr().map_err(|e| {
        TransportError::Socket(format!(
            "systemd-provided fd {fd} is not a usable Unix listener: {e}"
        ))
    })?;
    Ok(listener)
}

/// Detect a systemd socket-activated listener (`LISTEN_FDS` + `LISTEN_PID`).
///
/// Returns `Ok(None)` when not under socket activation (env unset or
/// `LISTEN_PID` does not match this process).
///
/// # Errors
///
/// [`TransportError::Socket`] if `LISTEN_FDS` is present but invalid, or
/// more than one fd is passed (v1 uses a single socket).
pub fn systemd_listener() -> Result<Option<UnixListener>, TransportError> {
    let Ok(listen_pid) = std::env::var("LISTEN_PID") else {
        return Ok(None);
    };
    let Ok(listen_fds) = std::env::var("LISTEN_FDS") else {
        return Ok(None);
    };
    let pid: u32 = listen_pid
        .parse()
        .map_err(|_| TransportError::Socket(format!("invalid LISTEN_PID={listen_pid:?}")))?;
    if pid != std::process::id() {
        return Ok(None);
    }
    let n: u32 = listen_fds
        .parse()
        .map_err(|_| TransportError::Socket(format!("invalid LISTEN_FDS={listen_fds:?}")))?;
    if n == 0 {
        return Ok(None);
    }
    if n != 1 {
        return Err(TransportError::Socket(format!(
            "socket activation expected LISTEN_FDS=1, got {n} (v1 serves one socket)"
        )));
    }
    // SD_LISTEN_FDS_START == 3 (systemd convention).
    Ok(Some(listener_from_fd(3)?))
}

/// F10: `fchmod`/`fchown` on the bound listener fd.
fn apply_listener_perms(
    listener: &UnixListener,
    config: &SocketConfig,
) -> Result<(), TransportError> {
    use std::os::unix::io::AsRawFd;

    let fd = listener.as_raw_fd();
    // SAFETY: fd is a valid open descriptor owned by `listener`.
    let rc = unsafe { libc::fchmod(fd, config.mode as libc::mode_t) };
    if rc != 0 {
        return Err(TransportError::Socket(format!(
            "fchmod(listener): {}",
            io::Error::last_os_error()
        )));
    }

    if config.owner_uid.is_some() || config.owner_gid.is_some() {
        let uid = config.owner_uid.unwrap_or(u32::MAX); // -1 = no change
        let gid = config.owner_gid.unwrap_or(u32::MAX);
        // SAFETY: fd is valid; fchown does not retain the pointer.
        let rc = unsafe {
            libc::fchown(
                fd,
                #[allow(clippy::cast_sign_loss)]
                {
                    uid as libc::uid_t
                },
                #[allow(clippy::cast_sign_loss)]
                {
                    gid as libc::gid_t
                },
            )
        };
        if rc != 0 {
            return Err(TransportError::Socket(format!(
                "fchown(listener): {}",
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Connect to a daemon socket at `path`.
///
/// # Errors
///
/// Returns [`TransportError::Socket`] if the connect fails.
pub fn connect(path: &Path) -> Result<UnixStream, TransportError> {
    UnixStream::connect(path)
        .map_err(|e| TransportError::Socket(format!("connect {}: {e}", path.display())))
}

/// Handle one accepted connection: read exactly one frame, pass the payload
/// bytes to `handle`, write exactly one response frame, close.
///
/// `handle` receives the raw CBOR payload and returns the raw CBOR response
/// (or an error to drop the connection without replying). Timeouts should be
/// set on the stream by the caller before invoking this.
///
/// # Errors
///
/// Framing/I/O errors from [`read_frame`]/[`write_frame`], or whatever
/// `handle` returns.
pub fn serve_one<F>(
    mut stream: UnixStream,
    limits: FrameLimits,
    handle: F,
) -> Result<(), TransportError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, TransportError>,
{
    let request = read_frame(&mut stream, limits)?;
    let response = handle(&request)?;
    write_frame(&mut stream, &response, limits)
}

/// Read peer credentials from an accepted stream (Linux `SO_PEERCRED`).
///
/// # Errors
///
/// Returns [`io::Error`] if `getsockopt` fails.
pub fn credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    peer_credentials(stream)
}

// Re-export for socket-path stat checks used in tests.
#[cfg(test)]
pub(crate) fn is_socket(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

/// Returns true if a connect to `path` succeeds (someone is listening).
fn socket_answers(path: &Path) -> bool {
    UnixStream::connect(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{read_frame, write_frame};
    use std::time::Duration;

    fn tmp_socket_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tpt-privd-test-{}-{}-{}.sock",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bind_creates_socket_with_configured_mode() {
        let path = tmp_socket_path("bind-mode");
        cleanup(&path);
        let cfg = SocketConfig::new(&path).with_mode(0o600);
        let _listener = bind_listener(&cfg).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.permissions().mode() & 0o777 == 0o600);
        cleanup(&path);
    }

    #[test]
    fn bind_refuses_non_socket_existing_file() {
        let path = tmp_socket_path("not-socket");
        std::fs::write(&path, b"i am a regular file").unwrap();
        let cfg = SocketConfig::new(&path);
        let err = bind_listener(&cfg).unwrap_err();
        assert!(matches!(err, TransportError::Socket(_)));
        // File must be untouched.
        assert_eq!(std::fs::read(&path).unwrap(), b"i am a regular file");
        cleanup(&path);
    }

    #[test]
    fn bind_replaces_stale_socket() {
        let path = tmp_socket_path("stale");
        cleanup(&path);
        // First bind creates it. Drop the listener so nothing is accepting —
        // the path is then a *stale* socket and may be replaced.
        {
            let _l1 = bind_listener(&SocketConfig::new(&path)).unwrap();
            assert!(is_socket(&path));
        }
        // Second bind should succeed by removing the stale socket.
        let _l2 = bind_listener(&SocketConfig::new(&path)).unwrap();
        assert!(is_socket(&path));
        cleanup(&path);
    }

    #[test]
    fn bind_refuses_live_socket() {
        let path = tmp_socket_path("live");
        cleanup(&path);
        // Hold a listener open so the socket answers (or at least exists
        // as a bound listener). A non-accepting listener still accepts TCP
        // style connects into the backlog, so socket_answers() is true.
        let _live = bind_listener(&SocketConfig::new(&path)).unwrap();
        let err = bind_listener(&SocketConfig::new(&path)).unwrap_err();
        assert!(
            matches!(err, TransportError::Socket(msg) if msg.contains("in use")),
            "expected live-socket refusal, got {err:?}"
        );
        cleanup(&path);
    }

    #[test]
    fn one_shot_request_reply_over_real_socket() {
        let path = tmp_socket_path("oneshot");
        cleanup(&path);
        let listener = bind_listener(&SocketConfig::new(&path)).unwrap();
        let limits = FrameLimits::default();

        let server = std::thread::spawn(move || {
            let (stream, _addr) = listener.accept().unwrap();
            let peer = credentials(&stream).unwrap();
            serve_one(stream, limits, move |req| {
                // Echo back with peer uid prefixed for verification.
                let mut resp = Vec::from(peer.uid.to_be_bytes());
                resp.extend_from_slice(req);
                Ok(resp)
            })
            .unwrap();
        });

        let mut client = connect(&path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write_frame(&mut client, b"ping-payload", limits).unwrap();
        let mut resp = Vec::new();
        let resp_frame = read_frame(&mut client, limits).unwrap();
        resp.extend_from_slice(&resp_frame);
        assert_eq!(&resp[4..], b"ping-payload");

        server.join().unwrap();
        cleanup(&path);
    }

    #[test]
    fn peer_credentials_match_self_on_loopback_connect() {
        let path = tmp_socket_path("peercred");
        cleanup(&path);
        let listener = bind_listener(&SocketConfig::new(&path)).unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            credentials(&stream).unwrap()
        });

        let _client = connect(&path).unwrap();
        let peer = server.join().unwrap();
        // Same process — pid should match ours.
        assert_eq!(peer.pid, std::process::id() as i32);
        cleanup(&path);
    }

    #[test]
    fn oversized_frame_rejected_on_wire() {
        let path = tmp_socket_path("oversize");
        cleanup(&path);
        let listener = bind_listener(&SocketConfig::new(&path)).unwrap();
        let limits = FrameLimits::new(64);

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut s = stream;
            // Client will try to send 128 bytes; server limits to 64.
            // Server read should fail with FrameTooLarge.
            let err = read_frame(&mut s, limits).unwrap_err();
            assert!(matches!(err, TransportError::FrameTooLarge { .. }));
        });

        // Client uses default (large) limits to write, but server rejects.
        // Actually write_frame checks against the *writer's* limits. Use a
        // client that writes with a larger limit than the server's read limit.
        let client_limits = FrameLimits::new(1024);
        let mut client = connect(&path).unwrap();
        // This write succeeds (client allows 1024); server read must reject.
        write_frame(&mut client, &vec![0u8; 128], client_limits).unwrap();
        server.join().unwrap();
        cleanup(&path);
    }

    #[test]
    fn slow_or_silent_client_times_out_via_read_timeout() {
        let path = tmp_socket_path("timeout");
        cleanup(&path);
        let listener = bind_listener(&SocketConfig::new(&path)).unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut s = stream;
            let err = read_frame(&mut s, FrameLimits::default()).unwrap_err();
            // Either Timeout (unix read_timeout) or Io with WouldBlock/TimedOut.
            match err {
                TransportError::Timeout { .. } => {}
                TransportError::Io(e) => {
                    assert!(
                        matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ),
                        "unexpected io error: {e:?}"
                    );
                }
                other => panic!("expected timeout, got {other:?}"),
            }
        });

        // Client connects but never writes.
        let _client = connect(&path).unwrap();
        server.join().unwrap();
        cleanup(&path);
    }

    #[test]
    fn serve_one_handles_decode_error_path_via_handle() {
        let path = tmp_socket_path("handle-err");
        cleanup(&path);
        let listener = bind_listener(&SocketConfig::new(&path)).unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let result = serve_one(stream, FrameLimits::default(), |_req| {
                Err(TransportError::Socket("handler rejected".into()))
            });
            assert!(result.is_err());
        });

        let mut client = connect(&path).unwrap();
        write_frame(&mut client, b"anything", FrameLimits::default()).unwrap();
        // Server drops without replying; client read gets EOF eventually
        // only after close — but server thread finishes regardless.
        drop(client);
        server.join().unwrap();
        cleanup(&path);
    }
}
