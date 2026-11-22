# Changelog

All notable changes to `tpt-privd-client` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `call` for one-shot request and reply over a Unix domain socket.
- `call_with_options` and `ClientOptions` for connect, read, and write
  timeouts (default 5 seconds each).
- `call_with_limits` for custom frame size limits.
- `ClientError` with `Transport`, `Encode`, `Decode`, `IdMismatch`, and
  `UnsupportedPlatform` variants.
- Reply `CommandId` is checked against the request (`IdMismatch`).
