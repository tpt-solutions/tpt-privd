//! Privileged command daemon: unprivileged socket in, audited privileged execution out.
//!
//! # Crate layout
//!
//! This crate is both a library (so integration tests and the example can
//! drive the full request path in-process) and a binary (`tpt-privd-daemon`).
//!
//! # Startup / privilege-drop ordering (security-critical)
//!
//! See `run_from_config` — the order is:
//!
//! 1. Parse + validate config.
//! 2. Open audit log (load/generate Ed25519 key).
//! 3. Bind the Unix socket + set mode/ownership.
//! 4. **Drop capabilities via `tpt-l-sandbox`** (Linux only).
//! 5. Enter the accept loop (only now are unprivileged connections served).
//!
//! Steps 2–3 need the privileges the daemon was started with; step 4 must
//! complete before any connection is accepted. Details and rationale live in
//! `docs/ARCHITECTURE.md` and the README "Capability dropping" section.
//!
//! # Platform
//!
//! The full socket + privilege-drop path requires Unix (and Linux for
//! capability dropping). On other targets the binary starts, prints an
//! error, and exits non-zero; the library still exposes the pure
//! request-handling pieces for tests.

#![deny(missing_docs)]

mod config;
mod handle;
mod metrics;

#[cfg(unix)]
mod serve;

#[cfg(target_os = "linux")]
mod sandbox;

pub use config::{CapsConfig, Config, ConfigError, LimitsConfig, SeccompConfig, SeccompDeny};
pub use handle::{HandleDeps, handle_cbor_payload};
pub use metrics::prometheus_text;

#[cfg(unix)]
pub use serve::{ServeError, run_from_config, run_with, serve_listener, serve_one_connection};
pub use tpt_privd_policy::MockExecutor;

#[cfg(target_os = "linux")]
pub use sandbox::drop_privileges;

#[cfg(all(unix, not(target_os = "linux")))]
/// Non-Linux Unix builds compile a stub: capability dropping is a no-op.
/// Production deployments must run on Linux for real capability dropping.
///
/// Seccomp is also Linux-only: enabling it in config is an error here so a
/// mis-deployed unit fails fast instead of running unfiltered.
pub fn drop_privileges(config: &Config) -> Result<(), serve::ServeError> {
    if config.seccomp.enabled {
        return Err(serve::ServeError::Sandbox(
            "seccomp is only supported on Linux (this is a non-Linux Unix build)".into(),
        ));
    }
    Ok(())
}
