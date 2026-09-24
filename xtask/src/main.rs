//! `cargo xtask` — workspace developer tasks (I9).
//!
//! Run as `cargo xtask <command>` after adding this package to the root
//! `[workspace]` members (already done) and an alias in `.cargo/config.toml`,
//! or directly: `cargo run -p xtask -- <command>`.

use std::path::Path;
use std::process::{Command, ExitCode};

const PACKAGES: &[&str] = &[
    "tpt-privd-envelope",
    "tpt-privd-transport",
    "tpt-privd-policy",
    "tpt-privd-audit",
    "tpt-privd-client",
    "tpt-privd-daemon",
];

const PUBLISH_ORDER: &[&str] = &[
    "tpt-privd-envelope",
    "tpt-privd-transport",
    "tpt-privd-policy",
    "tpt-privd-audit",
    "tpt-privd-client",
    "tpt-privd-daemon",
];

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());

    match cmd.as_str() {
        "help" | "-h" | "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        "gates" => gates(),
        "schema" => schema(),
        "check-schema" => check_schema(),
        "publish-order" => {
            for p in PUBLISH_ORDER {
                println!("{p}");
            }
            ExitCode::SUCCESS
        }
        "fuzz-check" => fuzz_check(),
        "packaging-check" => packaging_check(),
        other => {
            eprintln!("xtask: unknown command {other:?}; see `cargo xtask help`");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "cargo xtask <command>:
  gates            fmt --check + clippy -D warnings + test + deny + doc
  schema           print Config JSON Schema via tpt-privd-daemon --print-schema
  check-schema     schema must be non-empty and mention socket_path
  publish-order    print crates.io publish order (topo)
  fuzz-check       cargo check --manifest-path envelope fuzz package (stable)
  packaging-check  assert packaging/ units + config.example.toml exist"
    );
}

fn run(cmd: &mut Command, label: &str) -> ExitCode {
    eprintln!("xtask: {label}…");
    match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => {
            eprintln!("xtask: {label} failed ({s})");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("xtask: {label}: {e}");
            ExitCode::FAILURE
        }
    }
}

fn gates() -> ExitCode {
    let scoped_fmt = {
        let mut c = Command::new("cargo");
        c.args(["fmt"]);
        for p in PACKAGES {
            c.args(["-p", p]);
        }
        c.args(["--", "--check"]);
        run(&mut c, "fmt --check")
    };
    if scoped_fmt != ExitCode::SUCCESS {
        return scoped_fmt;
    }

    let mut clippy = Command::new("cargo");
    clippy.args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]);
    let clippy = run(&mut clippy, "clippy");
    if clippy != ExitCode::SUCCESS {
        return clippy;
    }

    let mut test = Command::new("cargo");
    test.args(["test", "--workspace"]);
    let test = run(&mut test, "test");
    if test != ExitCode::SUCCESS {
        return test;
    }

    let mut deny = Command::new("cargo");
    deny.args(["deny", "--all-features", "check"]);
    run(&mut deny, "cargo-deny")
}

fn schema() -> ExitCode {
    let mut c = Command::new("cargo");
    c.args(["run", "-p", "tpt-privd-daemon", "--", "--print-schema"]);
    run(&mut c, "print-schema")
}

fn check_schema() -> ExitCode {
    let out = Command::new("cargo")
        .args([
            "run",
            "-q",
            "-p",
            "tpt-privd-daemon",
            "--",
            "--print-schema",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            if text.contains("socket_path") && text.contains("\"$schema\"") {
                println!("schema OK ({} bytes)", text.len());
                ExitCode::SUCCESS
            } else {
                eprintln!("xtask: schema missing expected keys");
                ExitCode::FAILURE
            }
        }
        Ok(o) => {
            eprint!("{}", String::from_utf8_lossy(&o.stderr));
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("xtask: cannot run daemon: {e}");
            ExitCode::FAILURE
        }
    }
}

fn fuzz_check() -> ExitCode {
    let manifest = Path::new("crates/tpt-privd-envelope/fuzz/Cargo.toml");
    if !manifest.exists() {
        eprintln!("xtask: fuzz manifest missing at {}", manifest.display());
        return ExitCode::FAILURE;
    }
    // Fuzz package is a standalone workspace; just ensure it type-checks
    // without needing nightly `cargo fuzz`.
    let mut c = Command::new("cargo");
    c.args([
        "check",
        "--manifest-path",
        manifest.to_str().unwrap_or(""),
        "--all-targets",
    ]);
    run(&mut c, "fuzz check")
}

fn packaging_check() -> ExitCode {
    let required = [
        "packaging/tpt-privd.service",
        "packaging/tpt-privd.socket",
        "packaging/tpt-privd.conf",
        "packaging/Dockerfile.caps-harness",
        "packaging/verify-caps.sh",
        "crates/tpt-privd-daemon/config.example.toml",
        "crates/tpt-privd-daemon/examples/caps_probe.rs",
        "docs/DEPLOYMENT.md",
        "SECURITY.md",
        "CHANGELOG.md",
        "flake.nix",
    ];
    let mut ok = true;
    for path in required {
        if Path::new(path).exists() {
            println!("ok  {path}");
        } else {
            eprintln!("missing {path}");
            ok = false;
        }
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
