//! Structured policy violation.

use tpt_privd_envelope::CommandKind;

/// The policy check rejected a command.
///
/// Carries enough context for a meaningful audit-log entry: which kind was
/// attempted and a human-readable reason. Deliberately does not embed the
/// full payload (payloads are hashed into the audit log separately; keeping
/// them out of the violation type avoids accidental secret leakage into
/// error paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyViolation {
    /// The command kind that was denied.
    pub kind: CommandKind,
    /// Human-readable reason (e.g. "custom kind 0x80000005 not in allowlist").
    pub reason: String,
}

impl PolicyViolation {
    /// Construct a violation for `kind`.
    #[must_use]
    pub fn new(kind: CommandKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy denied kind {:#010x}: {}",
            self.kind.0, self.reason
        )
    }
}

impl std::error::Error for PolicyViolation {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_kind_and_reason() {
        let v = PolicyViolation::new(CommandKind::ECHO, "test reason");
        let s = v.to_string();
        assert!(s.contains("0x00000001"), "got: {s}");
        assert!(s.contains("test reason"));
    }
}
