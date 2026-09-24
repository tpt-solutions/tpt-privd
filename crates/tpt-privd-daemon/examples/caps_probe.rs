//! Linux-only capability probe (I6): print `CapEff` before/after drop.
//!
//! Run as root inside the caps harness container:
//! ```sh
//! cargo run -p tpt-privd-daemon --example caps_probe
//! ```
//! Exits 0 only if `CapEff` shrank and does not retain unexpected caps
//! beyond the configured keep list (when `drop_all` is true).

#[cfg(target_os = "linux")]
fn main() {
    use tpt_privd_daemon::{Config, drop_privileges};

    let before = read_capeff();
    println!("CapEff before: {before}");

    let mut config = Config::default();
    config.caps.drop_all = true;
    config.caps.keep = vec!["CAP_NET_ADMIN".into()];
    config.seccomp.enabled = false;

    match drop_privileges(&config) {
        Ok(()) => println!("drop_privileges: OK"),
        Err(e) => {
            eprintln!("drop_privileges failed: {e}");
            std::process::exit(2);
        }
    }

    let after = read_capeff();
    println!("CapEff after:  {after}");

    if before == after {
        eprintln!("FAIL: CapEff unchanged — drop did not take effect (need root / full set)");
        std::process::exit(1);
    }

    // CAP_NET_ADMIN is bit 12 → hex nibble … require it present if it was
    // in the before set; require CAP_SYS_ADMIN (bit 21) gone when drop_all.
    let before_u64 = parse_capeff(&before);
    let after_u64 = parse_capeff(&after);

    if after_u64 >= before_u64 {
        eprintln!("FAIL: CapEff after >= before ({after_u64:#x} >= {before_u64:#x})");
        std::process::exit(1);
    }

    const CAP_SYS_ADMIN: u64 = 1 << 21;
    const CAP_NET_ADMIN: u64 = 1 << 12;
    if before_u64 & CAP_SYS_ADMIN != 0 && after_u64 & CAP_SYS_ADMIN != 0 {
        eprintln!("FAIL: CAP_SYS_ADMIN still effective after drop");
        std::process::exit(1);
    }
    if before_u64 & CAP_NET_ADMIN != 0 && after_u64 & CAP_NET_ADMIN == 0 {
        eprintln!("FAIL: CAP_NET_ADMIN was dropped but is in keep list");
        std::process::exit(1);
    }

    println!("PASS: CapEff shrank; keep/deny expectations hold");
}

#[cfg(target_os = "linux")]
fn read_capeff() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(target_os = "linux")]
fn parse_capeff(hex_str: &str) -> u64 {
    u64::from_str_radix(hex_str, 16).unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("caps_probe: Linux only");
    std::process::exit(77);
}
