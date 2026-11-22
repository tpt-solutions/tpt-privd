# Contributing to tpt-privd

Contributions to `tpt-privd` are accepted **through GitHub issues only**.
Please do not open pull requests; they will not be reviewed or merged.

## Reporting a bug

Open a [new issue](https://github.com/TPT-Solutions/tpt-privd/issues/new)
and include:

- The crate and version (or commit hash) you are running.
- Your OS and kernel. Note whether you are on Linux, since capability
  dropping and `SO_PEERCRED` are Linux-only.
- The exact command, config, or code that reproduces the problem.
- What you expected to happen, and what happened instead. Include the
  relevant output or log lines.

## Requesting a feature

Open an issue describing the problem you are trying to solve, not only
the change you have in mind. Explain who is affected and how the
behaviour fits the design in [`spec.txt`](spec.txt) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Questions

Usage questions also go in issues. Label them as questions in the title
so they are easy to find.

## Security

Security concerns are also reported as issues. Prefix the title with
`[SECURITY]` and leave out exploit details, reproduction steps, and
anything else that would help an attacker. Describe the affected
component and the class of problem (for example, privilege escalation
or audit-chain integrity) and the maintainers will take it from there.

## Project policies

- Licensing: by filing an issue you agree that any code you share in
  it may be used under the project's dual license (MIT OR Apache-2.0).
- Behaviour: be respectful and keep discussion on the technical
  question.
