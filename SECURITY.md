# Security policy

## Supported versions

This project is pre-1.0. Security fixes land on `master` only; there is
no stable release channel yet. Once crates are published, each minor
line receives fixes until the next minor.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

- Prefer GitHub private vulnerability reporting on
  `TPT-Solutions/tpt-privd` (Security → Report a vulnerability).
- If that is unavailable, email the maintainers listed in
  `Cargo.toml` / the GitHub org with subject `[SECURITY] tpt-privd: …`.

Include: affected crate/version, reproduction steps, impact (privilege
escalation, audit-chain break, DoS, info leak), and any proposed fix.
You should receive an acknowledgement within a few business days.

## Scope

In scope:

- Privilege escalation past the configured capability drop.
- Tamper-evident audit log bypass (chain/signature forge, silent
  truncation that verifies clean).
- Unauthenticated or over-privileged socket access (mode/ownership
  bugs, `SO_PEERCRED` bypass).
- Memory-safety issues in the frame decoder / CBOR path (panic →
  crash of a privileged process).
- Command injection via policy or executor wiring in the daemon.

Out of scope:

- Issues only reachable when the operator has already written an
  intentionally insecure `CommandExecutor`.
- Denial of service from local disk-full / resource exhaustion alone
  (audit fail-stop is by design).
- The sibling `tpt-linux-sandbox` project — report those upstream.

## Hardening notes for operators

- Run the daemon on Linux so capability dropping is real (non-Linux
  Unix builds are a documented no-op stub).
- Keep `caps.keep` minimal; the example `CAP_NET_ADMIN` is illustrative.
- Protect `audit.key` (mode `0600`, provisioned externally in prod).
- Prefer socket `fchmod`/`fchown` ownership (`socket_owner_uid/gid`)
  over shared group-only trust.
- Verify the audit log periodically:
  `tpt-privd-daemon verify-audit /var/lib/tpt-privd/audit.jsonl`.
