# Contributing to tpt-privd

## Development layout

`tpt-privd` depends on the sibling `tpt-linux-sandbox` workspace via a
path dependency. Clone them as neighbors:

```text
parent/
  tpt-privd/
  tpt-linux-sandbox/   # provides crates/tpt-l-sandbox
```

CI does the same (`actions/checkout` with `path: tpt-privd` and
`path: tpt-linux-sandbox`). Do not change the path without updating
both `Cargo.toml` and `.github/workflows/ci.yml`.

Full socket / privilege-drop paths require Unix; capability drop is
Linux-only. Windows is supported for library tests and the scoped
gates below (Unix-gated integration tests are `#![cfg(unix)]`).

## Local gates (must be green before a PR)

Always run these from the repo root. **Never** use `cargo fmt --all`
(it formats the sibling checkout too) — scope to this workspace:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p tpt-privd-daemon --features otel --all-targets -- -D warnings
cargo fmt -p tpt-privd-envelope -p tpt-privd-transport \
  -p tpt-privd-policy -p tpt-privd-audit -p tpt-privd-client \
  -p tpt-privd-daemon -p xtask -- --check
cargo deny --all-features check
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

`cargo deny` may print `wildcards` / unresolved-workspace-dependency
**warnings** for the sibling path dep; those are expected (`warn` in
`deny.toml`). Advisories, bans, licenses, and sources must be `ok`.

## Checklist for PRs

- [ ] All four gates above green locally (or CI green on the PR).
- [ ] `cargo fmt` applied to the six packages (not `--all`).
- [ ] Public API changes documented in `CHANGELOG.md`.
- [ ] Security-relevant changes: note threat model impact in the PR
      description; see `SECURITY.md`.
- [ ] Finding IDs in `todo.md` (`F#`/`L#`/`A#`/`C#`) are stable — do
      not renumber; add new ids instead.

## Style

- Edition 2024, MSRV **1.85**.
- `missing_docs` is denied workspace-wide; document every public item.
- Prefer `#[non_exhaustive]`-free open enums where CBOR stability
  matters (`CommandKind`, `ErrorCode` already follow the documented
  extension story).
- No drive-by refactors in bugfix PRs.

## Releases / publish order

See `docs/DEPLOYMENT.md` § Publish order. Blocker: `tpt-l-sandbox`
must be on crates.io (or the path dep feature-gated) before
`tpt-privd-daemon` can publish.

## Fuzzing

From `crates/tpt-privd-envelope/fuzz/` (nightly + cargo-fuzz):

```sh
cargo +nightly fuzz run decode
```

The fuzz package is a standalone workspace (`[workspace]` table) and is
`exclude`d from the root members list so `cargo fuzz` works.

## Security reports

See `SECURITY.md` — do not file public issues for vulnerabilities.
