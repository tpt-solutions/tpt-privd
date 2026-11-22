# Changelog

All notable changes to `tpt-privd-envelope` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Changes that alter the CBOR wire shape also bump `ENVELOPE_VERSION`; see
the [workspace changelog](../../CHANGELOG.md#envelope-format-versioning-policy).

## [Unreleased]

### Added

- `Command`, `CommandResult`, `CommandId`, `CommandKind`, `CommandSuccess`,
  `CommandError`, `ErrorCode`, and `AuditLogRef` wire types.
- `CommandKind` as an open `u32` newtype with `NOP` (0), `ECHO` (1),
  `METRICS` (2), and the consumer range starting at `CUSTOM_START`.
- CBOR `encode` / `decode` and `encode_result` / `decode_result` via `ciborium`.
- `ENVELOPE_VERSION` constant (`1`) and `check_version` gate returning
  `EnvelopeError::UnsupportedVersion`.
- Round-trip and malformed-input tests, and a `codec` benchmark.
- Standalone `cargo-fuzz` target for the decoder under `fuzz/`.
