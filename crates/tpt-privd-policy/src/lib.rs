//! Per-command-type policy checks and [`CommandExecutor`] trait for tpt-privd.
//!
//! # Model
//!
//! Policy is **per command kind**, not global. Before any execution the
//! daemon calls [`CommandExecutor::policy_check`]; only if that returns
//! `Ok` does it call [`CommandExecutor::execute`]. A violation returns a
//! structured [`PolicyViolation`] that the daemon audit-logs and surfaces to
//! the caller as [`ErrorCode::PolicyDenied`](tpt_privd_envelope::ErrorCode::PolicyDenied).
//!
//! This bounds the blast radius of a compromised unprivileged caller: even
//! with full socket access, each kind can be independently constrained (e.g.
//! "kind X may only touch table Y" is enforced in the executor's
//! `policy_check` by inspecting `cmd.payload`).
//!
//! # Mock executor
//!
//! [`MockExecutor`] is a ready-made implementation for tests and the
//! end-to-end example: it always allows the built-in [`NOP`](tpt_privd_envelope::CommandKind::NOP)
//! and [`ECHO`](tpt_privd_envelope::CommandKind::ECHO) kinds, and allows
//! custom kinds only if present in an explicit allowlist. It is the stand-in
//! "real consumer" until a domain repo exists (see spec resolved decisions).
//!
//! # Example
//!
//! ```
//! use tpt_privd_envelope::{Command, CommandId, CommandKind};
//! use tpt_privd_policy::{CommandExecutor, MockExecutor};
//!
//! let exec = MockExecutor::new();
//! let echo = Command::new(CommandId(1), CommandKind::ECHO, b"x".to_vec());
//! assert!(exec.policy_check(&echo).is_ok());
//! assert_eq!(exec.execute(&echo).unwrap().payload, b"x");
//!
//! let custom = Command::new(
//!     CommandId(2),
//!     CommandKind(CommandKind::CUSTOM_START),
//!     vec![],
//! );
//! assert!(exec.policy_check(&custom).is_err());
//! ```

#![deny(missing_docs)]

mod executor;
mod mock;
mod violation;

pub use executor::CommandExecutor;
pub use mock::MockExecutor;
pub use violation::PolicyViolation;
