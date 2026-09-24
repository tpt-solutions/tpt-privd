//! End-to-end example: a *real* consumer `CommandExecutor` (not `MockExecutor`)
//! wired through `run_with`, exercised by a client call.
//!
//! Run on Unix:
//! ```sh
//! cargo run -p tpt-privd-daemon --example custom_consumer
//! ```
//!
//! Demonstrates the four-step integration from the README:
//! 1. Allocate a kind from `CommandKind::CUSTOM_START`.
//! 2. Implement `CommandExecutor` with a payload-inspecting policy.
//! 3. Wire it with `run_with(config, &executor)`.
//! 4. Call it with `tpt_privd_client::call`.

#[cfg(unix)]
use tpt_privd_envelope::{Command, CommandError, CommandKind, CommandSuccess};
#[cfg(unix)]
use tpt_privd_policy::{CommandExecutor, PolicyViolation};

/// Consumer command kinds — start at CUSTOM_START to avoid built-in collisions.
#[cfg(unix)]
const KIND_WRITE_TABLE: u32 = CommandKind::CUSTOM_START + 1;

/// Payload shape for `KIND_WRITE_TABLE`: `table_name` is the first line,
/// body is the rest. Policy only allows writes to table `users`.
#[cfg(unix)]
struct TableWriter;

#[cfg(unix)]
impl CommandExecutor for TableWriter {
    fn policy_check(&self, cmd: &Command) -> Result<(), PolicyViolation> {
        if cmd.kind.0 != KIND_WRITE_TABLE {
            return Err(PolicyViolation::new(
                cmd.kind,
                format!("unknown kind {}", cmd.kind.0),
            ));
        }
        let text = String::from_utf8_lossy(&cmd.payload);
        let table = text.lines().next().unwrap_or("");
        if table != "users" {
            return Err(PolicyViolation::new(
                cmd.kind,
                format!("may only touch table `users`, got `{table}`"),
            ));
        }
        Ok(())
    }

    fn execute(&self, cmd: &Command) -> Result<CommandSuccess, CommandError> {
        // Real consumer would write to a DB here. Simulate success.
        let text = String::from_utf8_lossy(&cmd.payload);
        let body = text.lines().skip(1).collect::<Vec<_>>().join("\n");
        Ok(CommandSuccess {
            payload: format!("wrote {} bytes to users", body.len()).into_bytes(),
        })
    }
}

#[cfg(unix)]
fn main() {
    use std::sync::mpsc;
    use tpt_privd_client::call;
    use tpt_privd_daemon::{Config, run_with};
    use tpt_privd_envelope::CommandId;

    let dir = std::env::temp_dir().join(format!(
        "tpt-privd-custom-consumer-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");

    let config = Config {
        socket_path: dir.join("privd.sock"),
        socket_mode: 0o600,
        audit_log_path: dir.join("audit.jsonl"),
        audit_key_path: dir.join("audit.key"),
        // Mock allowlist unused — we inject TableWriter.
        allowed_custom_kinds: vec![],
        ..Config::default()
    };

    let (ready_tx, ready_rx) = mpsc::channel();
    let sock_for_ready = config.socket_path.clone();
    // run_with blocks forever; run it on a thread. Signal after bind by
    // polling for the socket file (simpler than a bind hook).
    let config2 = config.clone();
    let server = std::thread::spawn(move || {
        // Tiny delay so we can signal after we know bind happened: poll.
        let result = run_with(&config2, &TableWriter);
        if let Err(e) = result {
            eprintln!("server exited: {e}");
        }
    });

    // Wait for the socket to appear (bind happens inside run_with before accept).
    for _ in 0..100 {
        if sock_for_ready.exists() {
            let _ = ready_tx.send(());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    ready_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("socket should appear");

    // Allowed write to `users`.
    let allowed = Command::new(
        CommandId(1),
        CommandKind(KIND_WRITE_TABLE),
        b"users\nalice@example.com".to_vec(),
    );
    let r = call(&config.socket_path, &allowed).expect("call");
    match r.outcome {
        Ok(ok) => println!(
            "allowed → {:?} (audit seq {})",
            String::from_utf8_lossy(&ok.payload),
            r.audit_ref.seq
        ),
        Err(e) => panic!("unexpected denial: {e:?}"),
    }

    // Denied write to another table — policy fires, still audited.
    let denied = Command::new(
        CommandId(2),
        CommandKind(KIND_WRITE_TABLE),
        b"secrets\nshould-not-land".to_vec(),
    );
    let r = call(&config.socket_path, &denied).expect("call");
    match r.outcome {
        Ok(_) => panic!("policy should have denied"),
        Err(e) => println!("denied → {} — {}", e.code, e.message),
    }

    // Offline audit verify.
    let kp = tpt_privd_audit::AuditKeypair::load_or_generate(&config.audit_key_path).unwrap();
    let report =
        tpt_privd_audit::AuditLog::verify_file(&config.audit_log_path, &kp.public_key_hex())
            .expect("audit must verify");
    println!(
        "audit OK: {} records, head={}",
        report.records_verified, report.head_hash
    );

    // Daemon thread blocks on accept forever; process exit ends it.
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
    println!("custom_consumer example passed");
}

#[cfg(not(unix))]
fn main() {
    eprintln!("custom_consumer example requires a Unix-like OS (Unix domain sockets).");
    std::process::exit(1);
}
