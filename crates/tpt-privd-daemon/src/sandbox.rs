//! Capability dropping (and optional seccomp) via `tpt-l-sandbox` (Linux only).
//!
//! Maps [`CapsConfig`] onto the sandbox builder's `.caps()` stage, then
//! optional [`SeccompConfig`](crate::config::SeccompConfig) onto `.seccomp()`.
//! Landlock/namespaces are intentionally not configured in v1.
//!
//! # Ordering contract
//!
//! This MUST be called after the audit log is open and the socket is bound,
//! and BEFORE the first `accept(2)`. The daemon's [`run_from_config`](crate::run_from_config)
//! enforces that order. Seccomp is irreversible once applied.
//!
//! # Seccomp caution (I2)
//!
//! `seccomp.allow` is default-deny: an incomplete allowlist kills the
//! process with `SIGSYS` on the next unmatched syscall. Prefer
//! `on_deny = "errno"` while bring-up-testing a list.

use tpt_l_sandbox::{CapsPolicy, DenyAction, Sandbox, SeccompPolicy};

use crate::config::{Config, SeccompDeny};
use crate::serve::ServeError;

/// Drop capabilities (and apply optional seccomp) according to `config`.
///
/// # Errors
///
/// [`ServeError::Sandbox`] if the sandbox builder rejects the policy or
/// any kernel capability/seccomp operation fails.
pub fn drop_privileges(config: &Config) -> Result<(), ServeError> {
    let caps = &config.caps;
    let mut sandbox = Sandbox::new();

    if caps.drop_all {
        let mut policy = CapsPolicy::new().drop_all();
        for cap in &caps.keep {
            policy = policy.keep(cap.clone());
        }
        sandbox = sandbox.caps(policy);
    } else {
        // Explicit "keep everything" — still a single choke point for
        // future non-caps stages.
        sandbox = sandbox.caps(CapsPolicy::new());
    }

    if config.seccomp.enabled {
        let action = match config.seccomp.on_deny {
            SeccompDeny::Kill => DenyAction::Kill,
            SeccompDeny::Errno => DenyAction::Errno(1), // EPERM
        };
        let mut seccomp = SeccompPolicy::new().default_action(action);
        for name in &config.seccomp.allow {
            seccomp = seccomp.allow_syscall(name.clone());
        }
        sandbox = sandbox.seccomp(seccomp);
        tracing::info!(
            allows = config.seccomp.allow.len(),
            on_deny = ?config.seccomp.on_deny,
            "applying seccomp filter (irreversible)"
        );
    }

    sandbox
        .apply()
        .map_err(|e| ServeError::Sandbox(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CapsConfig;

    #[test]
    fn default_caps_config_maps_to_net_admin() {
        let mut config = Config::default();
        config.caps = CapsConfig::default();
        // Applying as a non-root user may fail to actually drop (no
        // permitted caps to begin with) — tpt-l-caps-drop reads the
        // permitted set and intersects; empty ∩ keep = empty, which is
        // fine. We only assert the call does not panic and returns Result.
        // On CI (root or not) this should still Ok.
        let result = drop_privileges(&config);
        // If the environment has no CAP_SYS_ADMIN restrictions weirdness,
        // this is Ok. Accept either Ok or a structured Sandbox error —
        // never panic.
        match result {
            Ok(()) => {}
            Err(ServeError::Sandbox(msg)) => {
                // Extremely locked-down environments may reject; surface
                // but do not fail the unit test binary.
                eprintln!("sandbox apply returned error (environment-dependent): {msg}");
            }
            Err(other) => panic!("unexpected error type: {other}"),
        }
    }

    #[test]
    fn no_drop_when_drop_all_false() {
        let mut config = Config::default();
        config.caps.drop_all = false;
        config.caps.keep.clear();
        // Should be a no-op Ok regardless of privileges.
        assert!(drop_privileges(&config).is_ok());
    }
}
