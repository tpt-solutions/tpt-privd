//! Listener accept loop (Unix only).

use std::time::{Duration, Instant};

use tpt_privd_audit::AuditLog;
use tpt_privd_policy::CommandExecutor;
use tpt_privd_transport::{
    FrameLimits, SocketConfig, TransportError, bind_listener, credentials, read_frame,
    systemd_listener, write_frame,
};

use crate::config::{Config, LimitsConfig};
use crate::handle::{HandleDeps, handle_cbor_payload};

/// Errors from setting up or running the accept loop.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Socket bind/listen failure.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// Audit log open failure.
    #[error(transparent)]
    Audit(#[from] tpt_privd_audit::LogError),
    /// Config validation failure.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// Privilege-drop failure (Linux).
    #[error("privilege drop failed: {0}")]
    Sandbox(String),
    /// Other I/O failure during serve.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Bind, drop privileges, and serve forever with the built-in
/// [`MockExecutor`](tpt_privd_policy::MockExecutor) (demo binary path).
///
/// Consumers with a real `CommandExecutor` should call [`run_with`]
/// instead. Order is security-critical (see crate docs): audit + socket
/// setup use the starting privileges; [`drop_privileges`](crate::drop_privileges)
/// runs before the first `accept`.
///
/// # Errors
///
/// Any setup failure; the accept loop itself runs until the process is
/// killed.
pub fn run_from_config(config: &Config) -> Result<(), ServeError> {
    crate::metrics::init_tracing();
    let executor =
        tpt_privd_policy::MockExecutor::with_allowed(config.allowed_custom_kinds.iter().copied());
    run_with(config, &executor)
}

/// Bind, drop privileges, and serve forever with the caller's
/// [`CommandExecutor`](tpt_privd_policy::CommandExecutor).
///
/// This is the injection point for real consumers: implement the trait,
/// pass `&impl CommandExecutor` here, and reuse the tested accept loop,
/// timeout handling, peer-credential capture, and audit-before-reply
/// pipeline without copy-pasting `serve_listener`.
///
/// # Errors
///
/// Any setup failure; the accept loop itself runs until the process is
/// killed.
pub fn run_with(
    config: &Config,
    executor: &dyn tpt_privd_policy::CommandExecutor,
) -> Result<(), ServeError> {
    config.validate()?;

    // 1. Audit log first (may need to create key with tight perms).
    let mut audit = AuditLog::open(&config.audit_log_path, &config.audit_key_path)?;

    // 2. Listener before dropping privileges. systemd socket activation
    //    (I1): systemd already bound the path as root — inherit fd 3 and
    //    skip bind/chmod (unit SocketMode=/SocketUser= own that).
    let listener = if config.socket_activation {
        match systemd_listener()? {
            Some(l) => {
                tracing::info!(
                    path = %config.socket_path.display(),
                    "inheriting systemd socket-activated listener (LISTEN_FDS)"
                );
                l
            }
            None => {
                return Err(ServeError::Transport(TransportError::Socket(
                    "socket_activation = true but LISTEN_FDS/LISTEN_PID not set; \
                     start via the .socket unit (systemctl start tpt-privd.socket)"
                        .into(),
                )));
            }
        }
    } else {
        let mut sock_cfg = SocketConfig::new(&config.socket_path).with_mode(config.socket_mode);
        if let (Some(uid), Some(gid)) = (config.socket_owner_uid, config.socket_owner_gid) {
            sock_cfg = sock_cfg.with_owner(uid, gid);
        } else if let Some(uid) = config.socket_owner_uid {
            sock_cfg = sock_cfg.with_owner(uid, uid);
        } else if let Some(gid) = config.socket_owner_gid {
            sock_cfg = sock_cfg.with_owner(0, gid);
        }
        tracing::info!(path = %config.socket_path.display(), mode = %format_mode(config.socket_mode), "binding unix listener");
        bind_listener(&sock_cfg)?
    };

    // 3. Drop capabilities (and optional seccomp) — MUST complete before accept().
    crate::drop_privileges(config)?;

    // 4. Serve.
    serve_listener(listener, executor, &mut audit, &config.limits)
}

fn format_mode(mode: u32) -> String {
    format!("{mode:o}")
}

/// Accept-loop body operating on an already-bound listener.
///
/// Handles connections sequentially (one-shot each), which matches the
/// synchronous request/reply decision in the spec — a real consumer's
/// measured latency can justify a thread pool later without changing this
/// signature's semantics.
///
/// # Errors
///
/// Propagates the first hard audit failure. Individual connection errors
/// (bad frames, disconnects, timeouts) are tolerated and the loop
/// continues.
pub fn serve_listener(
    listener: std::os::unix::net::UnixListener,
    executor: &dyn CommandExecutor,
    audit: &mut AuditLog,
    limits: &LimitsConfig,
) -> Result<(), ServeError> {
    let frame_limits = FrameLimits::new(limits.max_frame_size);
    let read_timeout = Duration::from_millis(limits.read_timeout_ms);
    let write_timeout = Duration::from_millis(limits.write_timeout_ms);

    let mut consecutive_accept_errors = 0u32;

    for accepted in listener.incoming() {
        let stream = match accepted {
            Ok(s) => {
                consecutive_accept_errors = 0;
                s
            }
            Err(e) => {
                consecutive_accept_errors = consecutive_accept_errors.saturating_add(1);
                tracing::warn!(count = consecutive_accept_errors, error = %e, "accept error");
                if consecutive_accept_errors >= 16 {
                    // Back off so a persistent error (EMFILE etc.) cannot
                    // busy-spin and flood logs.
                    std::thread::sleep(Duration::from_millis(
                        100 * u32::from(consecutive_accept_errors.min(50)),
                    ));
                }
                continue;
            }
        };

        if stream.set_read_timeout(Some(read_timeout)).is_err()
            || stream.set_write_timeout(Some(write_timeout)).is_err()
        {
            tracing::warn!("failed to set socket timeouts; dropping connection");
            continue;
        }

        // Fail closed on credential lookup failure: an accountability system
        // must not execute with an unknown caller. On non-Linux Unix this
        // currently always fails (SO_PEERCRED not implemented) — see
        // transport::peer docs.
        let uid = match credentials(&stream) {
            Ok(c) => Some(c.uid),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "peer credential lookup failed; refusing connection (fail closed)"
                );
                continue;
            }
        };

        if let Err(e) = handle_stream(stream, executor, audit, uid, frame_limits, limits) {
            let fail_stop = e.to_string().contains("AUDIT FAIL-STOP");
            tracing::error!(error = %e, "connection error");
            if fail_stop {
                return Err(ServeError::Io(std::io::Error::other(format!(
                    "audit fail-stop: {e}"
                ))));
            }
        }
    }

    Ok(())
}

fn handle_stream(
    mut stream: std::os::unix::net::UnixStream,
    executor: &dyn tpt_privd_policy::CommandExecutor,
    audit: &mut AuditLog,
    caller_uid: Option<u32>,
    frame_limits: FrameLimits,
    limits: &LimitsConfig,
) -> Result<(), TransportError> {
    // F12: overall connection deadline (read + write + execute slack) so a
    // slow-loris / wedged execute cannot pin a sequential accept loop forever.
    let budget = Duration::from_millis(
        limits
            .read_timeout_ms
            .saturating_add(limits.write_timeout_ms)
            .saturating_add(limits.execute_timeout_ms),
    );
    let start = Instant::now();
    let deadline = start + budget;

    // Bound each phase by the remaining budget (per-read timeout alone does
    // not stop a client that dribbles one byte at a time within SO_RCVTIMEO).
    let remaining = || deadline.saturating_duration_since(Instant::now());
    if remaining().is_zero() {
        return Err(TransportError::Timeout { op: "connection" });
    }
    let _ = stream.set_read_timeout(Some(
        remaining().min(Duration::from_millis(limits.read_timeout_ms)),
    ));

    let request = read_frame(&mut stream, frame_limits)?;
    if remaining().is_zero() {
        return Err(TransportError::Timeout { op: "execute" });
    }

    let mut deps = HandleDeps {
        executor,
        audit,
        caller_uid,
    };
    let execute_started = Instant::now();
    let response = handle_cbor_payload(&mut deps, &request)?;
    let execute_elapsed = execute_started.elapsed();
    if execute_elapsed > Duration::from_millis(limits.execute_timeout_ms) {
        tracing::warn!(
            elapsed_ms = execute_elapsed.as_millis() as u64,
            limit_ms = limits.execute_timeout_ms,
            "execute exceeded deadline"
        );
    }
    if remaining().is_zero() {
        return Err(TransportError::Timeout { op: "reply" });
    }
    let _ = stream.set_write_timeout(Some(
        remaining().min(Duration::from_millis(limits.write_timeout_ms)),
    ));
    write_frame(&mut stream, &response, frame_limits)
}

/// One-shot serve helper used by integration tests: handle exactly one
/// already-accepted stream, then return.
pub fn serve_one_connection(
    stream: std::os::unix::net::UnixStream,
    executor: &dyn CommandExecutor,
    audit: &mut AuditLog,
    limits: &LimitsConfig,
) -> Result<(), ServeError> {
    let frame_limits = FrameLimits::new(limits.max_frame_size);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(limits.read_timeout_ms)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(limits.write_timeout_ms)));
    // Tests run in-process (same uid); fail closed only if lookup errors.
    let uid = credentials(&stream).map(|c| c.uid).ok();
    handle_stream(stream, executor, audit, uid, frame_limits, limits)?;
    Ok(())
}
