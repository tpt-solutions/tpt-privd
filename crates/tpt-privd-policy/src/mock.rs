//! Ready-made mock executor for tests and the end-to-end example.

use std::collections::BTreeSet;

use tpt_privd_envelope::{Command, CommandError, CommandKind, CommandSuccess, ErrorCode};

use crate::executor::CommandExecutor;
use crate::violation::PolicyViolation;

/// A trivial [`CommandExecutor`] used until a real consumer exists.
///
/// # Policy
///
/// - [`CommandKind::NOP`] and [`CommandKind::ECHO`] are always allowed.
/// - A custom kind is allowed **only** if present in the allowlist passed
///   to [`MockExecutor::with_allowed`]/[`MockExecutor::allow`].
/// - Anything else is denied with a [`PolicyViolation`].
///
/// # Execution
///
/// - `NOP` → empty success payload.
/// - `ECHO` → returns `cmd.payload` unchanged.
/// - An allowed custom kind → returns a canned `b"mock-ok"` payload (there
///   is no real domain operation to perform).
///
/// This encodes the "may only touch table X" *shape* of per-kind policy:
/// the allowlist is the bounding mechanism; a real consumer would also
/// inspect `cmd.payload` inside `policy_check`.
#[derive(Debug, Default, Clone)]
pub struct MockExecutor {
    allowed_custom: BTreeSet<u32>,
}

impl MockExecutor {
    /// New executor: only the built-in kinds are allowed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// New executor pre-populated with an allowlist of custom kind values.
    #[must_use]
    pub fn with_allowed<I>(kinds: I) -> Self
    where
        I: IntoIterator<Item = u32>,
    {
        Self {
            allowed_custom: kinds.into_iter().collect(),
        }
    }

    /// Add one custom kind to the allowlist (builder style).
    #[must_use]
    pub fn allow(mut self, kind: u32) -> Self {
        self.allowed_custom.insert(kind);
        self
    }

    /// Returns `true` if `kind` is in the custom allowlist.
    #[must_use]
    pub fn is_allowed_custom(&self, kind: u32) -> bool {
        self.allowed_custom.contains(&kind)
    }
}

impl CommandExecutor for MockExecutor {
    fn policy_check(&self, cmd: &Command) -> Result<(), PolicyViolation> {
        match cmd.kind {
            CommandKind::NOP | CommandKind::ECHO | CommandKind::METRICS => Ok(()),
            kind if kind.is_custom() => {
                if self.allowed_custom.contains(&kind.0) {
                    Ok(())
                } else {
                    Err(PolicyViolation::new(
                        kind,
                        format!("custom kind {:#010x} not in allowlist", kind.0),
                    ))
                }
            }
            // Non-custom, non-builtin: reserved for future built-ins — deny
            // until this build learns what they mean.
            kind => Err(PolicyViolation::new(
                kind,
                format!("unknown built-in kind {:#010x}", kind.0),
            )),
        }
    }

    fn execute(&self, cmd: &Command) -> Result<CommandSuccess, CommandError> {
        // Real executors would run the privileged operation here. The mock
        // was already policy-checked by the daemon before this is called.
        match cmd.kind {
            CommandKind::NOP => Ok(CommandSuccess {
                payload: Vec::new(),
            }),
            CommandKind::ECHO => Ok(CommandSuccess {
                payload: cmd.payload.clone(),
            }),
            // The daemon intercepts METRICS before the executor when running
            // the full pipeline. Standalone mock usage still returns a
            // minimal exposition so the built-in is never a hard error.
            CommandKind::METRICS => Ok(CommandSuccess {
                payload: b"# HELP tpt_privd_mock_up Mock executor metrics placeholder\n\
                          # TYPE tpt_privd_mock_up gauge\n\
                          tpt_privd_mock_up 1\n"
                    .to_vec(),
            }),
            kind if kind.is_custom() && self.allowed_custom.contains(&kind.0) => {
                Ok(CommandSuccess {
                    payload: b"mock-ok".to_vec(),
                })
            }
            kind => Err(CommandError::new(
                ErrorCode::ExecutionFailed,
                format!("mock executor cannot execute kind {:#010x}", kind.0),
            )),
        }
    }

    fn required_caps(&self, cmd: &Command) -> Vec<String> {
        match cmd.kind {
            // Mock has no real privileged work; built-ins need nothing.
            CommandKind::NOP | CommandKind::ECHO | CommandKind::METRICS => Vec::new(),
            // Allowlisted customs stand in for a network-facing consumer
            // (matches the config example / spec illustration).
            kind if kind.is_custom() && self.allowed_custom.contains(&kind.0) => {
                vec!["CAP_NET_ADMIN".to_string()]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_privd_envelope::{CommandId, ENVELOPE_VERSION};

    fn cmd(kind: CommandKind, payload: &[u8]) -> Command {
        Command {
            id: CommandId(1),
            version: ENVELOPE_VERSION,
            kind,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn nop_and_echo_always_allowed() {
        let e = MockExecutor::new();
        assert!(e.policy_check(&cmd(CommandKind::NOP, b"")).is_ok());
        assert!(e.policy_check(&cmd(CommandKind::ECHO, b"x")).is_ok());
        assert!(e.policy_check(&cmd(CommandKind::METRICS, b"")).is_ok());
    }

    #[test]
    fn metrics_executes_placeholder_exposition() {
        let e = MockExecutor::new();
        let c = cmd(CommandKind::METRICS, b"");
        let payload = e.execute(&c).unwrap().payload;
        let text = String::from_utf8(payload).unwrap();
        assert!(text.contains("tpt_privd_mock_up"));
    }

    #[test]
    fn echo_executes_by_returning_payload() {
        let e = MockExecutor::new();
        let c = cmd(CommandKind::ECHO, b"payload-bytes");
        assert_eq!(e.execute(&c).unwrap().payload, b"payload-bytes".to_vec());
    }

    #[test]
    fn nop_executes_empty() {
        let e = MockExecutor::new();
        let c = cmd(CommandKind::NOP, b"ignored");
        assert!(e.execute(&c).unwrap().payload.is_empty());
    }

    #[test]
    fn unlisted_custom_denied_with_reason() {
        let e = MockExecutor::new();
        let c = cmd(CommandKind(CommandKind::CUSTOM_START + 5), b"");
        let v = e.policy_check(&c).unwrap_err();
        assert_eq!(v.kind, c.kind);
        assert!(v.reason.contains("allowlist"));
    }

    #[test]
    fn listed_custom_allowed_and_executes() {
        let custom_id = CommandKind::CUSTOM_START + 42;
        let e = MockExecutor::new().allow(custom_id);
        let c = cmd(CommandKind(custom_id), b"data");
        assert!(e.policy_check(&c).is_ok());
        assert_eq!(e.execute(&c).unwrap().payload, b"mock-ok".to_vec());
    }

    #[test]
    fn unknown_reserved_kind_denied() {
        // Kind 3..CUSTOM_START-1 is neither builtin nor custom.
        let e = MockExecutor::new();
        let c = cmd(CommandKind(3), b"");
        let v = e.policy_check(&c).unwrap_err();
        assert!(v.reason.contains("unknown built-in"));
    }

    #[test]
    fn execute_without_policy_still_denies_unknown() {
        // Defense in depth: execute itself refuses non-allowlisted kinds
        // even if the daemon somehow skipped policy_check.
        let e = MockExecutor::new();
        let c = cmd(CommandKind(CommandKind::CUSTOM_START + 9), b"");
        let err = e.execute(&c).unwrap_err();
        assert_eq!(err.code, ErrorCode::ExecutionFailed);
    }

    #[test]
    fn with_allowed_bulk() {
        let e = MockExecutor::with_allowed([
            CommandKind::CUSTOM_START + 1,
            CommandKind::CUSTOM_START + 2,
        ]);
        assert!(e.is_allowed_custom(CommandKind::CUSTOM_START + 1));
        assert!(e.is_allowed_custom(CommandKind::CUSTOM_START + 2));
        assert!(!e.is_allowed_custom(CommandKind::CUSTOM_START + 3));
    }

    #[test]
    fn required_caps_for_builtins_empty_and_custom_net_admin() {
        let e = MockExecutor::new().allow(CommandKind::CUSTOM_START + 7);
        assert!(e.required_caps(&cmd(CommandKind::ECHO, b"")).is_empty());
        let custom = cmd(CommandKind(CommandKind::CUSTOM_START + 7), b"");
        assert_eq!(e.required_caps(&custom), vec!["CAP_NET_ADMIN"]);
    }
}
