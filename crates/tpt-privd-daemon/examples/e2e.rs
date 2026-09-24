//! End-to-end example: client sends a mock command, daemon policy-checks,
//! executes, audit-logs, returns the result.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p tpt-privd-daemon --example e2e
//! ```
//!
//! Spawns the full request path in-process (bind real Unix socket →
//! accept one connection → handle → reply) so no separate daemon process
//! or root privileges are required. Unix only — non-Unix builds print an
//! error and exit.

#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
use tpt_privd_audit::AuditLog;
#[cfg(unix)]
use tpt_privd_client::call;
#[cfg(unix)]
use tpt_privd_daemon::{Config, serve_one_connection};
#[cfg(unix)]
use tpt_privd_envelope::{Command, CommandId, CommandKind, ErrorCode};
#[cfg(unix)]
use tpt_privd_policy::MockExecutor;

#[cfg(unix)]
fn main() {
    let dir: PathBuf = std::env::temp_dir().join(format!("tpt-privd-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let socket = dir.join("privd.sock");
    let audit_path = dir.join("audit.jsonl");
    let key_path = dir.join("audit.key");

    let config = Config {
        socket_path: socket.clone(),
        socket_mode: 0o600,
        audit_log_path: audit_path.clone(),
        audit_key_path: key_path.clone(),
        // Allow one custom kind so we can show accept + deny.
        allowed_custom_kinds: vec![CommandKind::CUSTOM_START + 1],
        ..Config::default()
    };

    let sock_cfg = tpt_privd_transport::SocketConfig::new(&socket).with_mode(config.socket_mode);
    let listener = tpt_privd_transport::bind_listener(&sock_cfg).expect("bind socket");
    println!("bound socket: {}", socket.display());

    // Server thread: handle 3 one-shot connections (echo, denied custom, allowed custom).
    let server_cfg = config.clone();
    let server = std::thread::spawn(move || {
        let mut audit = AuditLog::open(&server_cfg.audit_log_path, &server_cfg.audit_key_path)
            .expect("open audit log");
        let executor = MockExecutor::with_allowed(server_cfg.allowed_custom_kinds.iter().copied());

        for i in 0..3 {
            let (stream, _) = listener.accept().expect("accept");
            serve_one_connection(stream, &executor, &mut audit, &server_cfg.limits)
                .unwrap_or_else(|e| panic!("serve connection {i}: {e}"));
        }

        println!(
            "server: audit log has {} records, verifying chain…",
            audit.len()
        );
        let report = audit.verify().expect("audit chain must verify");
        println!(
            "server: chain OK — {} records verified, head={}",
            report.records_verified, report.head_hash
        );
    });

    // Client 1: Echo
    let echo = Command::new(
        CommandId(1),
        CommandKind::ECHO,
        b"hello from client".to_vec(),
    );
    let r = call(&socket, &echo).expect("echo call");
    println!(
        "client 1 (echo): outcome={:?} audit_ref=seq {}",
        r.outcome
            .as_ref()
            .map(|s| String::from_utf8_lossy(&s.payload)),
        r.audit_ref.seq
    );

    // Client 2: Denied custom kind (not in allowlist... wait, we allowed +1.
    // Use +2 to show denial.)
    let denied = Command::new(
        CommandId(2),
        CommandKind(CommandKind::CUSTOM_START + 2),
        b"not allowed".to_vec(),
    );
    let r = call(&socket, &denied).expect("denied call reaches daemon");
    println!(
        "client 2 (denied custom): code={:?} msg={}",
        r.outcome.as_ref().unwrap_err().code,
        r.outcome.as_ref().unwrap_err().message
    );
    assert_eq!(
        r.outcome.as_ref().unwrap_err().code,
        ErrorCode::PolicyDenied
    );

    // Client 3: Allowed custom kind
    let allowed = Command::new(
        CommandId(3),
        CommandKind(CommandKind::CUSTOM_START + 1),
        b"permitted payload".to_vec(),
    );
    let r = call(&socket, &allowed).expect("allowed call");
    println!(
        "client 3 (allowed custom): payload={:?} audit_ref=seq {}",
        String::from_utf8_lossy(&r.outcome.as_ref().unwrap().payload),
        r.audit_ref.seq
    );

    server.join().expect("server thread");

    // Offline verify with only the public key file path (same as key path's
    // public half — here we reuse the daemon's key load).
    let kp = tpt_privd_audit::AuditKeypair::load_or_generate(&key_path).expect("load key");
    let report = AuditLog::verify_file(&audit_path, &kp.public_key_hex()).expect("verify");
    println!(
        "offline verify: {} records, head={}",
        report.records_verified, report.head_hash
    );

    println!("\nExample completed successfully.");
    println!("Audit log: {}", audit_path.display());
    println!("Audit key: {}", key_path.display());

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(not(unix))]
fn main() {
    eprintln!("tpt-privd e2e example requires a Unix-like OS (Unix domain sockets).");
    std::process::exit(1);
}
