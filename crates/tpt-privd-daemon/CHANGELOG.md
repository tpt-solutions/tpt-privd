# Changelog

All notable changes to `tpt-privd-daemon` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `tpt-privd-daemon` binary and library.
- Startup order: validate config, open audit log, bind socket (or take
  systemd fd), drop capabilities via `tpt-l-sandbox`, then accept.
- TOML configuration with discovery (`$TPRIVD_CONFIG`, XDG, `$HOME`,
  `/etc`, then defaults with a warning), `deny_unknown_fields`, validation
  (non-zero timeouts), and a JSON Schema via `--print-schema`.
- Subcommands: `verify-audit`, `call`, `explain-caps`; flags `--check`,
  `--print-config`, `--print-schema`.
- Request handling: version gate, policy check before execution, execution
  under a timeout, and an audit record for every outcome.
- Seccomp configuration (Linux, experimental) with `on_deny = "kill"` or
  `"errno"`.
- `METRICS` command kind returning Prometheus text over the audited channel.
- `otel` cargo feature for OpenTelemetry spans (stdout exporter by default).
- Examples: `e2e`, `custom_consumer`, `caps_probe`. Integration test suite.

### Changed

- Non-Linux Unix builds compile the capability drop as a no-op stub and
  reject seccomp in config, so misconfigured deployments fail at startup.
