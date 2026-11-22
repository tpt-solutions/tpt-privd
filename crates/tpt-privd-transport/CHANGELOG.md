# Changelog

All notable changes to `tpt-privd-transport` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Length-prefixed framing (`[u32 BE length][payload]`) with `read_frame`,
  `write_frame`, `FrameLimits`, and `DEFAULT_MAX_FRAME_SIZE` (1 MiB).
  Oversized frames are rejected before allocation.
- Unix domain socket bind with mode and ownership applied via `fchmod` and
  `fchown` on the listener fd, avoiding path TOCTOU.
- Live-socket refusal on bind, so a running daemon's socket is not replaced.
- `systemd_listener` for socket activation and `listener_from_fd` for
  supervisor-provided listeners.
- `SO_PEERCRED` peer credentials on Linux via `credentials` and
  `PeerCredentials`. Other Unix platforms fail closed with `Unsupported`.
- One-shot `serve_one` and `connect` helpers.
- Read and write timeouts reported as `TransportError::Timeout`.
- `TransportError` with `Io`, `FrameTooLarge`, `UnexpectedEof`, `Decode`,
  `Encode`, `Socket`, and `Timeout` variants.
- Framing benchmark (`frame`).
