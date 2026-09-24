//! Full integration tests: real Unix socket, real client, real audit log.
//!
//! Everything here requires `cfg(unix)` — Windows CI/dev builds skip this
//! file's tests entirely (the framing layer is covered by unit tests in
//! `tpt-privd-transport` on every platform).

#![cfg(unix)]

#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

use tpt_privd_audit::{AuditLog, AuditOutcome};
use tpt_privd_client::call;
use tpt_privd_daemon::{Config, HandleDeps, serve_one_connection};
use tpt_privd_envelope::{
    Command, CommandId, CommandKind, ENVELOPE_VERSION, ErrorCode, decode, encode,
};
use tpt_privd_policy::MockExecutor;

struct TempEnv {
    dir: PathBuf,
}

impl TempEnv {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tpt-privd-it-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("privd.sock")
    }
    fn audit(&self) -> PathBuf {
        self.dir.join("audit.jsonl")
    }
    fn key(&self) -> PathBuf {
        self.dir.join("audit.key")
    }
}

impl Drop for TempEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn default_config(env: &TempEnv) -> Config {
    Config {
        socket_path: env.socket(),
        socket_mode: 0o600,
        audit_log_path: env.audit(),
        audit_key_path: env.key(),
        ..Config::default()
    }
}

/// Spin a one-shot server on a thread for a single connection, run `client`
/// against it, join, return.
fn with_one_shot_server<R>(env: &TempEnv, allowed_custom: &[u32], client: impl FnOnce() -> R) -> R {
    let socket = env.socket();
    let audit_path = env.audit();
    let key_path = env.key();
    let allowed: Vec<u32> = allowed_custom.to_vec();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    let server = std::thread::spawn(move || {
        let config = Config {
            socket_path: socket.clone(),
            socket_mode: 0o600,
            audit_log_path: audit_path.clone(),
            audit_key_path: key_path.clone(),
            allowed_custom_kinds: allowed.clone(),
            ..Config::default()
        };
        let sock_cfg =
            tpt_privd_transport::SocketConfig::new(&socket).with_mode(config.socket_mode);
        let listener = tpt_privd_transport::bind_listener(&sock_cfg).unwrap();
        let mut audit = AuditLog::open(&audit_path, &key_path).unwrap();
        let executor = MockExecutor::with_allowed(allowed.iter().copied());
        ready_tx.send(()).expect("signal ready");

        let (stream, _) = listener.accept().unwrap();
        serve_one_connection(stream, &executor, &mut audit, &config.limits).unwrap();

        // Keep audit around so client can also reopen it after join if needed.
        // Drop closes the file.
        drop(audit);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server bind");
    let client_result = client();
    server.join().unwrap();
    client_result
}

#[test]
fn end_to_end_echo_roundtrip() {
    let env = TempEnv::new("echo");
    let socket = env.socket();

    let result = with_one_shot_server(&env, &[], move || {
        let cmd = Command::new(CommandId(42), CommandKind::ECHO, b"hello-privd".to_vec());
        call(&socket, &cmd).expect("client call failed")
    });

    assert_eq!(result.id, CommandId(42));
    let success = result.outcome.expect("echo should succeed");
    assert_eq!(success.payload, b"hello-privd");
    assert_eq!(result.audit_ref.seq, 0);
    assert_eq!(result.audit_ref.hash.len(), 64);

    // Audit log on disk verifies.
    let log = AuditLog::open(&env.audit(), &env.key()).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log.records()[0].outcome, AuditOutcome::Executed);
    log.verify().unwrap();
}

#[test]
fn end_to_end_policy_denial() {
    let env = TempEnv::new("deny");
    let socket = env.socket();

    let result = with_one_shot_server(&env, &[], move || {
        let cmd = Command::new(
            CommandId(7),
            CommandKind(CommandKind::CUSTOM_START + 1),
            b"should not run".to_vec(),
        );
        call(&socket, &cmd).expect("client call failed")
    });

    let err = result.outcome.expect_err("must be denied");
    assert_eq!(err.code, ErrorCode::PolicyDenied);
    assert!(err.message.contains("allowlist"));

    let log = AuditLog::open(&env.audit(), &env.key()).unwrap();
    assert_eq!(log.records()[0].outcome, AuditOutcome::PolicyDenied);
    log.verify().unwrap();
}

#[test]
fn end_to_end_allowed_custom_kind() {
    let env = TempEnv::new("custom-ok");
    let socket = env.socket();
    let custom = CommandKind::CUSTOM_START + 99;

    let result = with_one_shot_server(&env, &[custom], move || {
        let cmd = Command::new(CommandId(8), CommandKind(custom), b"payload".to_vec());
        call(&socket, &cmd).expect("client call failed")
    });

    let success = result.outcome.expect("allowlisted custom should run");
    assert_eq!(success.payload, b"mock-ok");
}

#[test]
fn end_to_end_version_mismatch() {
    let env = TempEnv::new("version");
    let socket = env.socket();

    let result = with_one_shot_server(&env, &[], move || {
        let mut cmd = Command::new(CommandId(1), CommandKind::NOP, vec![]);
        cmd.version = ENVELOPE_VERSION + 10;
        call(&socket, &cmd).expect("client call failed")
    });

    let err = result.outcome.expect_err("must fail version check");
    assert_eq!(err.code, ErrorCode::UnsupportedVersion);

    let log = AuditLog::open(&env.audit(), &env.key()).unwrap();
    assert_eq!(log.records()[0].outcome, AuditOutcome::VersionMismatch);
    log.verify().unwrap();
}

#[test]
fn multiple_sequential_one_shot_connections() {
    // Each connection is one-shot; run three separate client calls against
    // three server accept cycles on the same socket path + audit log.
    let env = TempEnv::new("multi");
    let socket = env.socket();
    let audit_path = env.audit();
    let key_path = env.key();

    // Single long-lived server thread accepting 3 connections.
    let server = std::thread::spawn(move || {
        let sock_cfg = tpt_privd_transport::SocketConfig::new(&socket).with_mode(0o600);
        let listener = tpt_privd_transport::bind_listener(&sock_cfg).unwrap();
        let mut audit = AuditLog::open(&audit_path, &key_path).unwrap();
        let executor = MockExecutor::new();
        let limits = Config::default().limits;

        for _ in 0..3 {
            let (stream, _) = listener.accept().unwrap();
            serve_one_connection(stream, &executor, &mut audit, &limits).unwrap();
        }
        audit.verify().unwrap();
        assert_eq!(audit.len(), 3);
    });

    for i in 0..3u64 {
        let cmd = Command::new(
            CommandId(i),
            CommandKind::ECHO,
            format!("msg-{i}").into_bytes(),
        );
        let result = call(&socket, &cmd).expect("call failed");
        assert_eq!(result.id, CommandId(i));
        assert_eq!(
            result.outcome.unwrap().payload,
            format!("msg-{i}").into_bytes()
        );
        assert_eq!(result.audit_ref.seq, i);
    }

    server.join().unwrap();
}

#[test]
fn audit_tamper_detection_end_to_end() {
    let env = TempEnv::new("tamper");
    let socket = env.socket();

    with_one_shot_server(&env, &[], move || {
        let cmd = Command::new(CommandId(1), CommandKind::ECHO, b"x".to_vec());
        call(&socket, &cmd).unwrap();
    });

    // Tamper with the single record's outcome, then verify must fail.
    let contents = std::fs::read_to_string(env.audit()).unwrap();
    let tampered = contents.replace("\"executed\"", "\"policy_denied\"");
    assert_ne!(
        contents, tampered,
        "test setup: string must exist to replace"
    );
    std::fs::write(env.audit(), tampered).unwrap();

    let open_result = AuditLog::open(&env.audit(), &env.key());
    assert!(open_result.is_err(), "reopening tampered log must fail");
}

#[test]
fn hostile_oversized_frame_dropped_without_reply() {
    let env = TempEnv::new("oversize");
    let socket = env.socket();
    let audit_path = env.audit();
    let key_path = env.key();

    let server = std::thread::spawn(move || {
        let sock_cfg = tpt_privd_transport::SocketConfig::new(&socket).with_mode(0o600);
        let listener = tpt_privd_transport::bind_listener(&sock_cfg).unwrap();
        let mut audit = AuditLog::open(&audit_path, &key_path).unwrap();
        let executor = MockExecutor::new();
        // Tiny frame limit: 16 bytes.
        let mut limits = Config::default().limits;
        limits.max_frame_size = 16;

        let (stream, _) = listener.accept().unwrap();
        // serve_one_connection will fail with FrameTooLarge; must not panic
        // and must not append an audit record (never got a parseable command).
        let result = serve_one_connection(stream, &executor, &mut audit, &limits);
        assert!(result.is_err());
        assert!(audit.is_empty());
    });

    // Client sends a frame larger than the server's 16-byte limit.
    // Use transport directly with a larger client-side limit.
    let mut client = tpt_privd_transport::connect(&socket).unwrap();
    let client_limits = tpt_privd_transport::FrameLimits::new(1024 * 1024);
    // 100-byte payload > server's 16.
    let payload = vec![0u8; 100];
    tpt_privd_transport::write_frame(&mut client, &payload, client_limits).unwrap();
    // Server drops the connection; client read gets EOF eventually — just
    // drop the client.
    drop(client);

    server.join().unwrap();
}

#[test]
fn malformed_cbor_frame_dropped_and_not_audited() {
    let env = TempEnv::new("malformed");
    let socket = env.socket();
    let audit_path = env.audit();
    let key_path = env.key();

    let server = std::thread::spawn(move || {
        let sock_cfg = tpt_privd_transport::SocketConfig::new(&socket).with_mode(0o600);
        let listener = tpt_privd_transport::bind_listener(&sock_cfg).unwrap();
        let mut audit = AuditLog::open(&audit_path, &key_path).unwrap();
        let executor = MockExecutor::new();
        let limits = Config::default().limits;

        let (stream, _) = listener.accept().unwrap();
        let result = serve_one_connection(stream, &executor, &mut audit, &limits);
        assert!(result.is_err(), "malformed CBOR must fail the connection");
        // F16: connection-level reject is recorded so hostile traffic is not
        // invisible to the chain (zeroed command fields + InternalError).
        assert_eq!(
            audit.len(),
            1,
            "malformed CBOR must leave a transport-reject audit record"
        );
        assert_eq!(
            audit.records()[0].outcome,
            tpt_privd_audit::AuditOutcome::InternalError
        );
        audit.verify().unwrap();
    });

    let mut client = tpt_privd_transport::connect(&socket).unwrap();
    let limits = tpt_privd_transport::FrameLimits::default();
    tpt_privd_transport::write_frame(&mut client, b"definitely not cbor \xff\xfe", limits).unwrap();
    drop(client);

    server.join().unwrap();
}

#[test]
fn peer_uid_recorded_in_audit() {
    let env = TempEnv::new("peeruid");
    let socket = env.socket();
    let audit_path = env.audit();
    let key_path = env.key();

    let server = std::thread::spawn(move || {
        let sock_cfg = tpt_privd_transport::SocketConfig::new(&socket).with_mode(0o600);
        let listener = tpt_privd_transport::bind_listener(&sock_cfg).unwrap();
        let mut audit = AuditLog::open(&audit_path, &key_path).unwrap();
        let executor = MockExecutor::new();
        let limits = Config::default().limits;
        let (stream, _) = listener.accept().unwrap();
        serve_one_connection(stream, &executor, &mut audit, &limits).unwrap();
        let rec = &audit.records()[0];
        // Same process — SO_PEERCRED uid should match our effective uid.
        let self_uid = unsafe { libc::geteuid() };
        assert_eq!(rec.caller_uid, Some(self_uid));
    });

    let socket2 = env.socket();
    let cmd = Command::new(CommandId(1), CommandKind::NOP, vec![]);
    let _ = call(&socket2, &cmd).unwrap();
    server.join().unwrap();
}

// Reference HandleDeps so the import is used even if some tests don't.
#[allow(dead_code)]
fn _assert_deps_export() {
    let _ = std::mem::size_of::<HandleDeps<'static>>();
}

#[test]
fn decode_encode_used_in_process() {
    // Sanity: the integration test file actually uses envelope codec paths.
    let cmd = Command::new(CommandId(0), CommandKind::NOP, vec![]);
    let bytes = encode(&cmd).unwrap();
    let back = decode(&bytes).unwrap();
    assert_eq!(cmd, back);
    // Small sleep so Duration import is used if we add timeout assertions.
    let _ = Duration::from_secs(1);
}
