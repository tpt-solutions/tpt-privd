//! Peer credentials via `SO_PEERCRED` (Linux).
//!
//! macOS/BSD use `LOCAL_PEERCRED` / `getpeereid` instead; those platforms
//! are not implemented yet — [`peer_credentials`] returns an unsupported-
//! platform error so callers fail closed rather than misattributing uid 0.

use std::io;
use std::os::unix::io::AsRawFd;

/// Identity of the process on the other end of a Unix domain socket.
///
/// Read from `SO_PEERCRED` after `accept(2)`. On Linux this is authoritative
/// for the connecting process (kernel-provided, not spoofable by the peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// PID of the peer process.
    pub pid: i32,
    /// Effective UID of the peer process.
    pub uid: u32,
    /// Effective GID of the peer process.
    pub gid: u32,
}

/// Read peer credentials from an accepted stream.
///
/// # Errors
///
/// On Linux, returns [`io::Error`] if the `getsockopt` call fails. On other
/// Unix platforms (macOS, BSD) returns `Unsupported` until
/// `LOCAL_PEERCRED`/`getpeereid` is implemented — fail closed rather than
/// guessing.
pub fn peer_credentials(stream: &std::os::unix::net::UnixStream) -> io::Result<PeerCredentials> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` is a valid, correctly-sized buffer for SO_PEERCRED;
        // `len` is set to its size on entry as required by getsockopt.
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::from_mut(&mut cred).cast(),
                std::ptr::from_mut(&mut len),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PeerCredentials {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = stream;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer credentials require Linux SO_PEERCRED (macOS/BSD LOCAL_PEERCRED not yet implemented)",
        ))
    }
}
