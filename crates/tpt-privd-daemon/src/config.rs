//! File-based daemon configuration (TOML), no hardcoding.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration load/validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File read failure.
    #[error("cannot read config: {0}")]
    Io(#[from] std::io::Error),
    /// TOML parse failure.
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// A value failed semantic validation.
    #[error("invalid config: {0}")]
    Invalid(String),
}

/// Capability-dropping configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CapsConfig {
    /// Drop every capability except those in `keep`.
    pub drop_all: bool,
    /// Capability names to retain when `drop_all` is set, e.g.
    /// `"CAP_NET_ADMIN"`. The mock/example role uses `CAP_NET_ADMIN` as a
    /// stand-in for a network-facing consumer (per the spec's example).
    pub keep: Vec<String>,
}

impl Default for CapsConfig {
    fn default() -> Self {
        // Mock/example role: retain only CAP_NET_ADMIN — matches the
        // spec's illustrative network-facing consumer.
        Self {
            drop_all: true,
            keep: vec!["CAP_NET_ADMIN".to_string()],
        }
    }
}

/// Frame/timeout limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum CBOR frame payload in bytes.
    pub max_frame_size: u64,
    /// Per-connection read timeout, milliseconds.
    pub read_timeout_ms: u64,
    /// Per-connection write timeout, milliseconds.
    pub write_timeout_ms: u64,
    /// Soft deadline for policy+execute on one connection, milliseconds.
    /// Overruns are logged; the overall connection budget is
    /// `read + write + execute`.
    pub execute_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_frame_size: 1024 * 1024,
            read_timeout_ms: 5_000,
            write_timeout_ms: 5_000,
            execute_timeout_ms: 30_000,
        }
    }
}

/// Optional seccomp syscall filter (Linux, applied after capability drop).
///
/// **Experimental (I2):** seccomp is default-deny. Enabling with an empty
/// `allow` list is rejected at config validation — a wrong allowlist will
/// kill the daemon with `SIGSYS` on the next unmatched syscall. Ship
/// tested lists only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct SeccompConfig {
    /// Apply a seccomp filter after the caps stage (irreversible).
    pub enabled: bool,
    /// Syscall names to allow (e.g. `"read"`, `"accept4"`, `"futex"`).
    /// Required and non-empty when `enabled`.
    pub allow: Vec<String>,
    /// Unmatched-syscall action: `"kill"` (default) or `"errno"`.
    /// `"errno"` returns `EPERM` instead of `SIGSYS` (easier to debug).
    pub on_deny: SeccompDeny,
}

/// What seccomp does to syscalls not in `allow`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[schemars(rename_all = "snake_case")]
pub enum SeccompDeny {
    /// Terminate with `SIGSYS`.
    #[default]
    Kill,
    /// Return `EPERM` to the caller.
    Errno,
}

/// Top-level daemon configuration (deserialized from TOML).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct Config {
    /// Filesystem path of the listening Unix domain socket.
    pub socket_path: PathBuf,
    /// Socket file permission bits (e.g. `432` for `0o660` — TOML has no
    /// octal literals, so store the decimal value of the mode). A string
    /// like `"0o660"` or `"0660"` is also accepted.
    #[serde(
        default = "default_socket_mode",
        deserialize_with = "deserialize_socket_mode"
    )]
    pub socket_mode: u32,
    /// Optional owning UID for the socket file (`chown` at bind). Requires
    /// privilege at bind time (pre-drop). `None` leaves the binder as owner.
    pub socket_owner_uid: Option<u32>,
    /// Optional owning GID for the socket file.
    pub socket_owner_gid: Option<u32>,
    /// Use a systemd socket-activated listener (`LISTEN_FDS`) instead of
    /// binding `socket_path`. Strongest privilege story: systemd binds as
    /// root, the daemon starts with only the inherited fd (I1).
    pub socket_activation: bool,
    /// Path of the append-only audit log (JSONL).
    pub audit_log_path: PathBuf,
    /// Path of the Ed25519 secret seed used to sign audit records.
    pub audit_key_path: PathBuf,
    /// Capability-dropping policy applied before accepting connections.
    pub caps: CapsConfig,
    /// Optional seccomp filter (Linux; after caps). Off by default (I2).
    pub seccomp: SeccompConfig,
    /// Framing and timeout limits.
    pub limits: LimitsConfig,
    /// Allowlist of custom `CommandKind` values the mock executor will run.
    ///
    /// This is the demo stand-in for real per-consumer policy config; a
    /// future real consumer would replace this with its own policy file.
    pub allowed_custom_kinds: Vec<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/tpt-privd/privd.sock"),
            socket_mode: default_socket_mode(),
            socket_owner_uid: None,
            socket_owner_gid: None,
            socket_activation: false,
            audit_log_path: PathBuf::from("/var/lib/tpt-privd/audit.jsonl"),
            audit_key_path: PathBuf::from("/var/lib/tpt-privd/audit.key"),
            caps: CapsConfig::default(),
            seccomp: SeccompConfig::default(),
            limits: LimitsConfig::default(),
            allowed_custom_kinds: Vec::new(),
        }
    }
}

fn default_socket_mode() -> u32 {
    0o660
}

/// Custom deserializer for `socket_mode` accepting either a TOML integer
/// (decimal encoding of octal, e.g. `432` = `0o660`) or a string like
/// `"0o660"` / `"0660"` / `"660"`.
fn deserialize_socket_mode<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let value = toml::Value::deserialize(deserializer)?;
    match value {
        toml::Value::Integer(n) => {
            if (0..=0o7777).contains(&n) {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Ok(n as u32)
            } else {
                Err(D::Error::custom(format!(
                    "socket_mode {n} out of range 0..=0o7777"
                )))
            }
        }
        toml::Value::String(s) => parse_mode_str(&s)
            .ok_or_else(|| D::Error::custom(format!("cannot parse socket_mode {s:?}"))),
        other => Err(D::Error::custom(format!(
            "socket_mode must be integer or string, got {other:?}"
        ))),
    }
}

fn parse_mode_str(s: &str) -> Option<u32> {
    let t = s.trim();
    let (digits, radix) = if let Some(rest) = t.strip_prefix("0o").or_else(|| t.strip_prefix("0O"))
    {
        (rest, 8)
    } else if let Some(rest) = t.strip_prefix("0").filter(|r| !r.is_empty()) {
        // "0660" style: leading zero means octal.
        (rest, 8)
    } else {
        // Bare decimal digits as a string, e.g. "432".
        (t, 10)
    };
    u32::from_str_radix(digits, radix)
        .ok()
        .filter(|&m| m <= 0o7777)
}

impl Config {
    /// Load from a TOML file.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] on I/O, parse, or validation failure.
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_toml(&text)
    }

    /// Parse + validate from TOML text.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] on parse or validation failure.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check semantic invariants.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.socket_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("socket_path must not be empty".into()));
        }
        if self.socket_mode > 0o7777 {
            return Err(ConfigError::Invalid(format!(
                "socket_mode {:#o} exceeds 0o7777",
                self.socket_mode
            )));
        }
        if self.limits.max_frame_size == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_frame_size must be > 0".into(),
            ));
        }
        if self.limits.max_frame_size > 64 * 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "limits.max_frame_size must be ≤ 64 MiB".into(),
            ));
        }
        if self.audit_log_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "audit_log_path must not be empty".into(),
            ));
        }
        if self.audit_key_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "audit_key_path must not be empty".into(),
            ));
        }
        if self.limits.read_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "limits.read_timeout_ms must be > 0 (0 would make sockets non-blocking)".into(),
            ));
        }
        if self.limits.write_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "limits.write_timeout_ms must be > 0 (0 would make sockets non-blocking)".into(),
            ));
        }
        if self.limits.execute_timeout_ms == 0 {
            return Err(ConfigError::Invalid(
                "limits.execute_timeout_ms must be > 0".into(),
            ));
        }
        if self.socket_activation && self.socket_path.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "socket_path must not be empty (used for logging even with socket_activation)"
                    .into(),
            ));
        }
        if self.seccomp.enabled && self.seccomp.allow.is_empty() {
            return Err(ConfigError::Invalid(
                "seccomp.enabled requires a non-empty seccomp.allow list \
                 (default-deny with zero allows kills the process immediately)"
                    .into(),
            ));
        }
        if self.caps.drop_all && self.caps.keep.is_empty() {
            // Allowed (drop to zero caps) but worth a soft check: empty keep
            // with drop_all means a fully capability-less daemon. That is
            // valid for the NOP/ECHO mock but would break real consumers —
            // we accept it and let the operator decide.
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn toml_roundtrip() {
        let cfg = Config {
            socket_path: PathBuf::from("/tmp/test.sock"),
            allowed_custom_kinds: vec![0x8000_0001],
            ..Config::default()
        };
        let text = toml::to_string_pretty(&cfg).unwrap();
        let back = Config::from_toml(&text).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn rejects_empty_socket_path() {
        let cfg = Config {
            socket_path: PathBuf::new(),
            ..Config::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn rejects_oversized_frame_limit() {
        let cfg = Config {
            limits: LimitsConfig {
                max_frame_size: 128 * 1024 * 1024,
                ..LimitsConfig::default()
            },
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_bad_socket_mode() {
        let cfg = Config {
            socket_mode: 0o10000,
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn example_toml_parses() {
        let text = r#"
socket_path = "/tmp/privd-example.sock"
socket_mode = 432
audit_log_path = "/tmp/privd-example.jsonl"
audit_key_path = "/tmp/privd-example.key"
allowed_custom_kinds = [2147483649]

[caps]
drop_all = true
keep = ["CAP_NET_ADMIN"]

[limits]
max_frame_size = 1048576
read_timeout_ms = 5000
write_timeout_ms = 5000
"#;
        let cfg = Config::from_toml(text).unwrap();
        assert_eq!(cfg.socket_mode, 0o660);
        assert_eq!(cfg.caps.keep, vec!["CAP_NET_ADMIN"]);
        assert_eq!(cfg.allowed_custom_kinds, vec![0x8000_0001]);
    }

    #[test]
    fn rejects_zero_timeouts() {
        let cfg = Config {
            limits: LimitsConfig {
                read_timeout_ms: 0,
                ..LimitsConfig::default()
            },
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_empty_audit_key_path() {
        let cfg = Config {
            audit_key_path: PathBuf::new(),
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn socket_mode_accepts_octal_string() {
        let text = r#"
socket_path = "/tmp/privd-example.sock"
socket_mode = "0o660"
audit_log_path = "/tmp/privd-example.jsonl"
audit_key_path = "/tmp/privd-example.key"
"#;
        let cfg = Config::from_toml(text).unwrap();
        assert_eq!(cfg.socket_mode, 0o660);
    }

    #[test]
    fn socket_mode_accepts_leading_zero_string() {
        let text = r#"
socket_path = "/tmp/privd-example.sock"
socket_mode = "0660"
audit_log_path = "/tmp/privd-example.jsonl"
audit_key_path = "/tmp/privd-example.key"
"#;
        let cfg = Config::from_toml(text).unwrap();
        assert_eq!(cfg.socket_mode, 0o660);
    }

    #[test]
    fn default_caps_retain_net_admin() {
        let caps = CapsConfig::default();
        assert!(caps.drop_all);
        assert_eq!(caps.keep, vec!["CAP_NET_ADMIN"]);
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = r#"
socket_path = "/tmp/x.sock"
audit_log_path = "/tmp/x.jsonl"
audit_key_path = "/tmp/x.key"
totally_unknown_key = 1
"#;
        assert!(Config::from_toml(text).is_err());
    }

    #[test]
    fn rejects_seccomp_enabled_without_allows() {
        let cfg = Config {
            seccomp: SeccompConfig {
                enabled: true,
                allow: vec![],
                on_deny: SeccompDeny::Errno,
            },
            ..Config::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn accepts_seccomp_with_allowlist() {
        let cfg = Config {
            seccomp: SeccompConfig {
                enabled: true,
                allow: vec!["read".into(), "write".into(), "exit_group".into()],
                on_deny: SeccompDeny::Kill,
            },
            ..Config::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn rejects_zero_execute_timeout() {
        let cfg = Config {
            limits: LimitsConfig {
                execute_timeout_ms: 0,
                ..LimitsConfig::default()
            },
            ..Config::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn schema_generates_for_config() {
        let schema = schemars::schema_for!(Config);
        let json = serde_json::to_string(&schema).unwrap();
        assert!(json.contains("socket_path"));
        assert!(json.contains("seccomp"));
        assert!(json.contains("socket_activation"));
    }
}
