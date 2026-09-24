# tpt-privd-daemon

Privileged command daemon binary (and library) for `tpt-privd`: unprivileged
socket in, audited privileged execution out.

## CLI

```sh
# Run the daemon (default subcommand)
tpt-privd-daemon --config /etc/tpt-privd/config.toml

# Validate config without starting
tpt-privd-daemon --check --config ./config.example.toml

# Print resolved config
tpt-privd-daemon --print-config

# Offline audit verification (chain + signatures)
tpt-privd-daemon verify-audit /var/lib/tpt-privd/audit.jsonl

# Send one command to a running daemon
tpt-privd-daemon call \
  --socket /run/tpt-privd/privd.sock \
  --kind 1 \
  --payload hello

# Capability calculator: required_caps vs [caps] keep (I2)
tpt-privd-daemon explain-caps --kind 2147483649

# Print config JSON Schema
tpt-privd-daemon --print-schema
```

Optional cargo feature `otel` (I4) layers OpenTelemetry (stdout span
exporter) onto the same `tracing` subscriber:

```sh
cargo build -p tpt-privd-daemon --features otel
```

Config discovery when `--config` is unset: `$TPRIVD_CONFIG`,
`$XDG_CONFIG_HOME/tpt-privd/config.toml`,
`$HOME/.config/tpt-privd/config.toml`, `/etc/tpt-privd/config.toml`,
then built-in defaults with a stderr warning.

## Library

```rust
use tpt_privd_daemon::{Config, run_with, MockExecutor};

let config = Config::default();
let executor = MockExecutor::new();
// run_with(&config, &executor).unwrap(); // Unix only
```

See `config.example.toml` for every key. Capability drop is Linux-only
via `tpt-l-sandbox`.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
