# tpt-privd consumer template (I10)

Scaffold for a repo that layers domain `CommandKind`s and a real
`CommandExecutor` on top of `tpt-privd`.

Not a crates.io package — copy these files into a new repository (or use
[`cargo-generate`](https://cargo-generate.github.io/cargo-generate/) with
this directory as the template root once a `cargo-generate.toml` is added).

## Layout

```text
.
├── cargo-generate.toml          # optional metadata for cargo-generate
├── Cargo.toml                   # bin crate depending on tpt-privd-* crates
├── config.toml                  # daemon config skeleton
├── README.md                    # this file
└── src/
    ├── main.rs                  # implements CommandExecutor + run_with
    └── commands.rs              # your CommandKind constants (≥ CUSTOM_START)
```

## Dependency order (crates.io)

See `docs/DEPLOYMENT.md` § Publish order. Until `tpt-privd-daemon` is
published, depend via git:

```toml
[dependencies]
tpt-privd-envelope = { git = "https://github.com/TPT-Solutions/tpt-privd" }
tpt-privd-transport = { git = "https://github.com/TPT-Solutions/tpt-privd" }
tpt-privd-policy = { git = "https://github.com/TPT-Solutions/tpt-privd" }
tpt-privd-audit = { git = "https://github.com/TPT-Solutions/tpt-privd" }
tpt-privd-client = { git = "https://github.com/TPT-Solutions/tpt-privd" }
tpt-privd-daemon = { git = "https://github.com/TPT-Solutions/tpt-privd" }
```

## Checklist

1. Define `CommandKind` values starting at `CommandKind::CUSTOM_START`.
2. Implement `CommandExecutor` (`policy_check` + `execute`).
3. Call `tpt_privd_daemon::run_with(&config, &executor)`.
4. Keep capability set minimal for your domain (`[caps] keep` in config).
5. Scrape `CommandKind::METRICS` (2) over the same socket.
6. Schedule `verify-audit` on the live log.
