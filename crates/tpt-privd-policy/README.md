# tpt-privd-policy

Per-command-type policy checks and the `CommandExecutor` trait for
`tpt-privd`.

- `CommandExecutor` (`policy_check` + `execute`)
- `PolicyViolation` with enough detail to audit-log a denial
- `MockExecutor` with built-in `NOP`/`ECHO` plus a custom-kind allowlist

Implement `CommandExecutor` for your domain and inject it with
`tpt_privd_daemon::run_with`.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
