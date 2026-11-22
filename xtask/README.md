# xtask

Development task runner for [`tpt-privd`](../README.md). It is not published
to crates.io. It exists so that the project's quality gates, config schema
checks, and packaging checks run the same way on a laptop and in CI.

`xtask` has no dependencies. It runs external tools with `std::process::Command`,
which keeps it cheap to build and easy to audit.

## Usage

Run from the workspace root:

```sh
cargo xtask <task>
```

The `xtask` alias is defined in [`.cargo/config.toml`](../.cargo/config.toml)
and maps to `cargo run -p xtask --`.

| Task | What it does |
|---|---|
| `help` | Print the task list. `-h` and `--help` also work. |
| `gates` | Run the local quality gates in order, stopping at the first failure: `cargo fmt --check` scoped to this workspace's packages, `cargo clippy --workspace --all-targets` with warnings denied, `cargo test --workspace`, and `cargo deny --all-features check`. |
| `schema` | Print the daemon config's JSON Schema. |
| `check-schema` | Check that the committed schema matches the schema generated from the code. |
| `publish-order` | Print the crates.io publish order as a topological sort, so that each dependency is published before its dependents. |
| `fuzz-check` | Type-check the standalone fuzz package under `crates/tpt-privd-envelope/fuzz/`, without needing nightly `cargo fuzz`. |
| `packaging-check` | Confirm the packaging files and key documents exist: the systemd units, `tpt-privd.conf`, the capability harness, `config.example.toml`, `docs/DEPLOYMENT.md`, `CHANGELOG.md`, and `flake.nix`. |

## Why `fmt` is scoped

`gates` never runs `cargo fmt --all`. The workspace depends on a sibling
checkout, `tpt-linux-sandbox`, and `--all` would format that tree too. The
package list is fixed in the task so the scope stays correct.

## Adding a task

1. Add a function to [`src/main.rs`](src/main.rs) that returns `ExitCode`.
2. Shell out with `Command`, and report failures with the same `run` helper
   the other tasks use.
3. Add the match arm in `main` and a line to the `help` text.
4. If the task needs a new file to exist, add it to the `packaging-check`
   list only when it is part of the packaged deliverable.

Keep the crate dependency-free. If a task truly needs a crate, discuss it
in an issue first.

## Minimum supported Rust version

1.85, edition 2024.

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE)
or [MIT license](../LICENSE-MIT), at your option.
