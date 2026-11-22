# Changelog

All notable changes to `tpt-privd-policy` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `CommandExecutor` trait with `policy_check` (run first, must be pure) and
  `execute` (run only after a successful check).
- `PolicyViolation` type carrying the audit-loggable denial reason.
- `MockExecutor` with built-in `NOP` and `ECHO` kinds and a configurable
  allowlist of custom kinds.
