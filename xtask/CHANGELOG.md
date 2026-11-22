# Changelog

All notable changes to `xtask` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This crate is not published to crates.io.

## [Unreleased]

### Added

- `gates`, `schema`, `check-schema`, `publish-order`, `fuzz-check`, and
  `packaging-check` tasks.
- Dependency-free implementation using `std::process::Command`.

### Changed

- `packaging-check` no longer requires `SECURITY.md`, which was removed.
