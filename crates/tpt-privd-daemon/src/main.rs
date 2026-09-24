//! `tpt-privd-daemon` binary entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[cfg(unix)]
use tpt_privd_daemon::{Config, run_from_config};

/// Privileged command daemon for tpt-privd.
///
/// Listens on a Unix domain socket, policy-checks and executes typed
/// commands, append-only audit-logs every outcome, and drops capabilities
/// before accepting connections.
///
/// Subcommands:
///   (none)            run the daemon (default)
///   verify-audit      offline chain + signature check
///   call              send one command to a running daemon
///   explain-caps      print required Linux caps for a `CommandKind` (I2)
///
/// Examples:
///   tpt-privd-daemon --config /etc/tpt-privd/config.toml
///   tpt-privd-daemon --check --config ./config.example.toml
///   tpt-privd-daemon verify-audit /var/lib/tpt-privd/audit.jsonl
///   tpt-privd-daemon call --socket /run/tpt-privd/privd.sock --kind 1 --payload hello
///   tpt-privd-daemon explain-caps --kind 2147483649
#[derive(Parser, Debug)]
#[command(
    name = "tpt-privd-daemon",
    version,
    about,
    after_help = "See config.example.toml for every key."
)]
struct Cli {
    /// Path to the TOML config file. Discovery when unset:
    /// `$TPRIVD_CONFIG`, `$XDG_CONFIG_HOME/tpt-privd/config.toml`,
    /// `$HOME/.config/tpt-privd/config.toml`, `/etc/tpt-privd/config.toml`,
    /// then built-in defaults (with a stderr warning).
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    /// Override the socket path from config (useful for tests/dev).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Print the resolved config as TOML and exit.
    #[arg(long)]
    print_config: bool,
    /// Print the config JSON Schema (schemars, I8) and exit.
    #[arg(long)]
    print_schema: bool,
    /// Validate the config and exit 0/1 without starting the daemon.
    #[arg(long)]
    check: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify an audit log offline (chain + signatures) and exit.
    VerifyAudit {
        /// Path to the audit log JSONL file.
        log: PathBuf,
        /// Key file (defaults to `audit.key` next to the log's directory).
        #[arg(long, value_name = "KEY")]
        key: Option<PathBuf>,
    },
    /// Send one framed command to a running daemon and print the result.
    Call {
        /// Unix domain socket path of the daemon.
        #[arg(long)]
        socket: PathBuf,
        /// `CommandKind` as decimal integer (e.g. 1 = ECHO).
        #[arg(long)]
        kind: u32,
        /// Payload as UTF-8 text (default) or hex with `0x` prefix.
        #[arg(long, default_value = "")]
        payload: String,
        /// Optional command id (defaults to a random-ish timestamp id).
        #[arg(long)]
        id: Option<u64>,
    },
    /// Print which Linux capabilities a `CommandKind` needs (I2 explain-caps).
    ///
    /// Compares `CommandExecutor::required_caps` against `[caps] keep`
    /// from the resolved config and exits 0 if the keep-set covers the
    /// requirement (or 1 if not).
    ExplainCaps {
        /// `CommandKind` as decimal integer (e.g. 2147483649 = `CUSTOM_START+1`).
        #[arg(long)]
        kind: u32,
        /// Optional payload (mock may inspect it; usually unused for caps).
        #[arg(long, default_value = "")]
        payload: String,
    },
}

#[cfg(unix)]
fn main() -> ExitCode {
    let cli = Cli::parse();

    // Subcommands that do not start the daemon.
    match &cli.command {
        Some(Command::VerifyAudit { log, key }) => {
            return verify_audit_cli(log, key.as_deref());
        }
        Some(Command::Call {
            socket,
            kind,
            payload,
            id,
        }) => {
            return call_cli(socket, *kind, payload, *id);
        }
        Some(Command::ExplainCaps { kind, payload }) => {
            return explain_caps_cli(cli.config.as_deref(), *kind, payload);
        }
        None => {}
    }

    let mut config = match load_config(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tpt-privd-daemon: failed to load config: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(sock) = cli.socket {
        config.socket_path = sock;
    }

    if cli.print_schema {
        return print_schema();
    }

    // Validate BEFORE --print-config so we never print a config that
    // would be rejected (L17).
    if let Err(e) = config.validate() {
        eprintln!("tpt-privd-daemon: invalid config: {e}");
        return ExitCode::FAILURE;
    }

    if cli.print_config {
        return match toml::to_string_pretty(&config) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("tpt-privd-daemon: cannot serialize config: {e}");
                ExitCode::FAILURE
            }
        };
    }

    if cli.check {
        eprintln!("tpt-privd-daemon: config OK");
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "tpt-privd-daemon: binding {}, audit {}",
        config.socket_path.display(),
        config.audit_log_path.display()
    );

    match run_from_config(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tpt-privd-daemon: fatal: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(unix))]
fn main() -> ExitCode {
    let cli = Cli::parse();

    match &cli.command {
        Some(Command::VerifyAudit { log, key }) => {
            return verify_audit_cli(log, key.as_deref());
        }
        Some(Command::Call { .. }) => {
            eprintln!("tpt-privd-daemon: `call` requires a Unix-like OS (Unix domain sockets).");
            return ExitCode::FAILURE;
        }
        Some(Command::ExplainCaps { kind, payload }) => {
            return explain_caps_cli(cli.config.as_deref(), *kind, payload);
        }
        None => {}
    }

    // Config-only paths (--check / --print-config) work everywhere;
    // starting the accept loop needs Unix domain sockets.
    let mut config = match load_config(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tpt-privd-daemon: failed to load config: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(sock) = cli.socket {
        config.socket_path = sock;
    }
    if cli.print_schema {
        return print_schema();
    }
    if let Err(e) = config.validate() {
        eprintln!("tpt-privd-daemon: invalid config: {e}");
        return ExitCode::FAILURE;
    }
    if cli.print_config {
        return match toml::to_string_pretty(&config) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("tpt-privd-daemon: cannot serialize config: {e}");
                ExitCode::FAILURE
            }
        };
    }
    if cli.check {
        eprintln!("tpt-privd-daemon: config OK");
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "tpt-privd-daemon: requires a Unix-like OS (Unix domain sockets + Linux capability \
         dropping). This build was compiled for a non-Unix target and cannot serve. \
         Use --check/--print-config/verify-audit, or build on Unix."
    );
    ExitCode::FAILURE
}

/// I8: dump the JSON Schema for [`tpt_privd_daemon::Config`].
fn print_schema() -> ExitCode {
    let schema = schemars::schema_for!(tpt_privd_daemon::Config);
    match serde_json::to_string_pretty(&schema) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tpt-privd-daemon: cannot serialize schema: {e}");
            ExitCode::FAILURE
        }
    }
}

/// I2: capability calculator — `required_caps(kind)` vs config `[caps] keep`.
fn explain_caps_cli(config_path: Option<&std::path::Path>, kind: u32, payload: &str) -> ExitCode {
    use tpt_privd_envelope::{Command, CommandId, CommandKind};
    use tpt_privd_policy::{CommandExecutor, MockExecutor};

    let config = match load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tpt-privd-daemon: failed to load config: {e}");
            return ExitCode::FAILURE;
        }
    };

    let bytes = if let Some(hex_str) = payload.strip_prefix("0x") {
        match hex::decode(hex_str) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("tpt-privd-daemon: invalid --payload hex: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        payload.as_bytes().to_vec()
    };

    let cmd = Command::new(CommandId(0), CommandKind(kind), bytes);
    let executor = MockExecutor::with_allowed(config.allowed_custom_kinds.iter().copied());
    let required = executor.required_caps(&cmd);
    let keep = &config.caps.keep;
    let drop_all = config.caps.drop_all;
    let policy = executor.policy_check(&cmd);

    println!("kind              = {kind} ({kind:#010x})");
    println!("caps.drop_all     = {drop_all}");
    println!("caps.keep         = {keep:?}");
    println!("required_caps     = {required:?}");
    match &policy {
        Ok(()) => println!("policy            = allowed (mock executor)"),
        Err(e) => println!("policy            = DENIED ({e}) — will not execute"),
    }

    if policy.is_err() {
        println!("verdict           = N/A (policy denies this kind; required_caps unused)");
        return ExitCode::SUCCESS;
    }

    if required.is_empty() {
        println!("verdict           = OK (no extra caps required)");
        return ExitCode::SUCCESS;
    }

    // When drop_all is false the process keeps its starting set — treat as
    // covering requirements only if we are not shrinking (documented caveat:
    // starting set is environment-dependent).
    if !drop_all {
        println!(
            "verdict           = UNKNOWN (drop_all=false keeps the start-time set; \
             verify with `capsh --print` / the caps harness)"
        );
        return ExitCode::SUCCESS;
    }

    let missing: Vec<_> = required
        .iter()
        .filter(|c| !keep.iter().any(|k| cap_eq(k, c)))
        .collect();
    if missing.is_empty() {
        println!("verdict           = OK (keep covers required)");
        ExitCode::SUCCESS
    } else {
        println!("verdict           = FAIL (missing from keep: {missing:?})");
        ExitCode::FAILURE
    }
}

fn cap_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.trim()
            .to_ascii_uppercase()
            .trim_start_matches("CAP_")
            .to_string()
    };
    norm(a) == norm(b)
}

/// A4: config discovery when `--config` is unset (works everywhere).
fn load_config(
    explicit: Option<&std::path::Path>,
) -> Result<tpt_privd_daemon::Config, tpt_privd_daemon::ConfigError> {
    use tpt_privd_daemon::Config;

    if let Some(path) = explicit {
        return Config::load(path);
    }

    // clap no longer has env = "TPRIVD_CONFIG" on --config so we control order.
    if let Ok(p) = std::env::var("TPRIVD_CONFIG") {
        if !p.is_empty() {
            let path = PathBuf::from(p);
            if path.exists() {
                return tpt_privd_daemon::Config::load(&path);
            }
            eprintln!(
                "tpt-privd-daemon: TPRIVD_CONFIG={} does not exist; continuing discovery",
                path.display()
            );
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            candidates.push(PathBuf::from(xdg).join("tpt-privd/config.toml"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            candidates.push(PathBuf::from(home).join(".config/tpt-privd/config.toml"));
        }
    }
    candidates.push(PathBuf::from("/etc/tpt-privd/config.toml"));

    for path in &candidates {
        if path.exists() {
            eprintln!(
                "tpt-privd-daemon: no --config given; discovered {}",
                path.display()
            );
            return tpt_privd_daemon::Config::load(path);
        }
    }

    eprintln!(
        "tpt-privd-daemon: no config found (checked $TPRIVD_CONFIG, XDG_CONFIG_HOME, \
         $HOME/.config/tpt-privd, /etc/tpt-privd); using built-in defaults \
         (paths under /run and /var/lib — typically need root). See config.example.toml."
    );
    Ok(tpt_privd_daemon::Config::default())
}

/// Offline audit-log verification (pure file I/O — works everywhere).
fn verify_audit_cli(log_path: &std::path::Path, key_path: Option<&std::path::Path>) -> ExitCode {
    use tpt_privd_audit::{AuditKeypair, AuditLog};

    let key_path_owned = key_path.map_or_else(
        || {
            log_path
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join("audit.key")
        },
        PathBuf::from,
    );

    let keypair = match AuditKeypair::load_or_generate(&key_path_owned) {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "tpt-privd-daemon: cannot load key {}: {e}",
                key_path_owned.display()
            );
            return ExitCode::FAILURE;
        }
    };

    match AuditLog::verify_file(log_path, &keypair.public_key_hex()) {
        Ok(report) => {
            println!(
                "OK: {} records verified, head={}",
                report.records_verified, report.head_hash
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A2: one-shot client subcommand.
#[cfg(unix)]
fn call_cli(socket: &std::path::Path, kind: u32, payload: &str, id: Option<u64>) -> ExitCode {
    use tpt_privd_client::call;
    use tpt_privd_envelope::{Command, CommandId, CommandKind};

    let bytes = if let Some(hex_str) = payload.strip_prefix("0x") {
        match hex::decode(hex_str) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("tpt-privd-daemon: invalid --payload hex: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        payload.as_bytes().to_vec()
    };

    let cmd_id = id.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1)
    });
    let cmd = Command::new(CommandId(cmd_id), CommandKind(kind), bytes);

    match call(socket, &cmd) {
        Ok(result) => {
            match result.outcome {
                Ok(success) => {
                    println!(
                        "OK id={} audit_seq={} payload_len={}",
                        result.id.0,
                        result.audit_ref.seq,
                        success.payload.len()
                    );
                    if !success.payload.is_empty() {
                        match std::str::from_utf8(&success.payload) {
                            Ok(s) => println!("{s}"),
                            Err(_) => println!("0x{}", hex::encode(&success.payload)),
                        }
                    }
                }
                Err(e) => {
                    println!(
                        "ERR id={} code={:?} audit_seq={}: {}",
                        result.id.0, e.code, result.audit_ref.seq, e.message
                    );
                    return ExitCode::FAILURE;
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("tpt-privd-daemon: call failed: {e}");
            ExitCode::FAILURE
        }
    }
}
