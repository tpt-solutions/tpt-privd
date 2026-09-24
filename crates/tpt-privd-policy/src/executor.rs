//! The [`CommandExecutor`] trait.

use tpt_privd_envelope::{Command, CommandError, CommandSuccess};

use crate::violation::PolicyViolation;

/// Policy check + execution for commands arriving at the daemon.
///
/// Implementors are responsible for:
/// 1. **`policy_check`** — reject out-of-bounds commands *before* any
///    side effects. Inspect `cmd.kind` and `cmd.payload`. Must be free of
///    side effects itself (the daemon treats a `PolicyViolation` as
///    "did not run").
/// 2. **`execute`** — perform the privileged operation only after the
///    daemon has already called `policy_check` and gotten `Ok`. Return a
///    structured success/failure; the daemon wraps it in a
///    [`CommandResult`](tpt_privd_envelope::CommandResult) with an audit
///    reference.
///
/// Implementors must be `Send + Sync` because the daemon shares one
/// executor across connection-handling threads.
pub trait CommandExecutor: Send + Sync {
    /// Decide whether `cmd` is within the bounds this executor is willing
    /// to cause.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyViolation`] with enough detail (kind + reason) for
    /// the daemon to audit-log a meaningful denial.
    fn policy_check(&self, cmd: &Command) -> Result<(), PolicyViolation>;

    /// Execute an already-policy-approved command.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] with [`ErrorCode::ExecutionFailed`](tpt_privd_envelope::ErrorCode::ExecutionFailed)
    /// (or a more specific non-exhaustive code) if the operation fails.
    fn execute(&self, cmd: &Command) -> Result<CommandSuccess, CommandError>;

    /// Linux capability names (e.g. `"CAP_NET_ADMIN"`) this kind needs in
    /// the daemon's post-drop set for `execute` to succeed (I2
    /// `explain-caps`).
    ///
    /// Default: empty (no extra caps beyond whatever the role already
    /// keeps). Real consumers override this so operators can diff
    /// `required_caps(kind)` against `[caps] keep` in config before deploy.
    ///
    /// This is documentation/planning metadata — the daemon does **not**
    /// enforce it at request time (capability sets are process-wide).
    fn required_caps(&self, cmd: &Command) -> Vec<String> {
        let _ = cmd;
        Vec::new()
    }
}
