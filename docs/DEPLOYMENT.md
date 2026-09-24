# Deployment

Notes for running `tpt-privd` as a system service on Linux.

## Install layout

| Path | Purpose |
|------|---------|
| `/usr/local/bin/tpt-privd-daemon` | Binary (or distro package path) |
| `/etc/tpt-privd/config.toml` | Daemon config |
| `/etc/tpt-privd/audit.key` | Ed25519 audit signing key (`0600`, root) |
| `/var/lib/tpt-privd/audit.jsonl` | Append-only audit log |
| `/run/tpt-privd/privd.sock` | Unix domain socket |
| `/usr/lib/tmpfiles.d/tpt-privd.conf` | Runtime dir creation |
| `/usr/lib/systemd/system/tpt-privd.service` | Unit |
| `/usr/lib/systemd/system/tpt-privd.socket` | Socket unit (I1 activation) |

Socket parent dir is created by the daemon if missing; tmpfiles.d is
belt-and-braces for early boot before the unit starts.

## tmpfiles.d

`packaging/tpt-privd.conf` (install as `/usr/lib/tmpfiles.d/tpt-privd.conf`):

```conf
# Type Path Mode User Group Argument
d /run/tpt-privd 0775 root tpt-privd - -
d /var/lib/tpt-privd 0750 root tpt-privd - -
```

Create the `tpt-privd` group (or use your service group) and add the
unprivileged client user(s) to it so socket mode `0660` is sufficient:

```sh
groupadd --system tpt-privd
usermod -aG tpt-privd alice
```

## systemd unit

`packaging/tpt-privd.service` (install as
`/usr/lib/systemd/system/tpt-privd.service`):

```ini
[Unit]
Description=TPT privileged command daemon
Documentation=https://github.com/TPT-Solutions/tpt-privd
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tpt-privd-daemon --config /etc/tpt-privd/config.toml
Restart=on-failure
RestartSec=2
# Hardening (capability drop still runs in-process via tpt-l-sandbox)
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tpt-privd /run/tpt-privd
# Capability bounding: keep only what the role needs (example)
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
# The daemon drops remaining caps itself before accept(); bounding set
# is a second layer.
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
```

Enable:

```sh
systemctl daemon-reload
systemctl enable --now tpt-privd
systemctl status tpt-privd
```

## Socket activation (I1)

Strongest privilege story: systemd binds the path as root; the daemon starts
with only the inherited listening fd (`LISTEN_FDS`).

1. Set `socket_activation = true` in `config.toml`.
2. Install `packaging/tpt-privd.socket` as
   `/usr/lib/systemd/system/tpt-privd.socket`.
3. Enable the socket (not only the service):

```sh
systemctl daemon-reload
systemctl enable --now tpt-privd.socket
# First connection (or an explicit start) spawns the daemon:
systemctl start tpt-privd
systemctl status tpt-privd.socket tpt-privd
```

Socket mode/owner come from the `.socket` unit (`SocketMode=`, `SocketUser=`,
`SocketGroup=`), not from `socket_mode` / `socket_owner_*`.

## Tracing (I11) and OpenTelemetry (I4)

Logs go to stderr via `tracing`. Default filter is `info`; override with
`RUST_LOG` (e.g. `Environment=RUST_LOG=debug` in the unit).

Optional cargo feature `otel` layers OpenTelemetry on top of the same
subscriber (stdout span exporter by default — point
`OTEL_EXPORTER_OTLP_*` at an agent when you swap processors in prod):

```sh
cargo build -p tpt-privd-daemon --features otel
```

CI checks the feature with `cargo check -p tpt-privd-daemon --features otel`.

```sh
tpt-privd-daemon --print-schema --config /etc/tpt-privd/config.toml
```

`--print-schema` dumps the JSON Schema for the config (I8); unknown keys
are rejected at load time (`deny_unknown_fields`).

## Capability calculator (I2 `explain-caps`)

Print the Linux capabilities a command kind needs vs `[caps] keep`
(exit 0 = covered, 1 = missing when `drop_all = true`):

```sh
tpt-privd-daemon explain-caps --kind 2147483649 --payload 0x
# optional config override (same discovery / --config as run):
tpt-privd-daemon --config /etc/tpt-privd/config.toml \
  explain-caps --kind 2147483649
```

Custom kinds (`>= CUSTOM_START`) report `CAP_NET_ADMIN` from the mock
executor's `required_caps`; built-ins report none. The admin executor
should return the real set for its handlers.

## CapEff harness (I6)

On a Linux box with Docker and sibling checkouts:

```sh
./packaging/verify-caps.sh
```

Builds `packaging/Dockerfile.caps-harness` from the monorepo parent and
runs `examples/caps_probe` as root (prints `CapEff` before/after
`drop_privileges`). The CI `caps-harness` job does the same.

## Nix (I7)

```sh
nix build          # packages the workspace (sibling via flake input)
nix flake check
```

`flake.nix` takes `tpt-linux-sandbox` as a flake input and re-links it
next to the workspace source so the path dependency resolves in the
Nix store. Full `nixosTest` VM coverage is deferred (needs nested virt).

## Metrics (I3)

Built-in `CommandKind::METRICS` (`2`) returns Prometheus text exposition
over the same audited channel — no second listener:

```sh
tpt-privd-daemon call \
  --socket /run/tpt-privd/privd.sock \
  --kind 2
```

## Config discovery order

When `--config` is unset:

1. `$TPRIVD_CONFIG`
2. `$XDG_CONFIG_HOME/tpt-privd/config.toml`
3. `$HOME/.config/tpt-privd/config.toml`
4. `/etc/tpt-privd/config.toml`
5. Built-in defaults + stderr warning

Production systems should pass `--config` explicitly in the unit file
(`Environment=TPRIVD_CONFIG=...` also works).

## Validate before start

```sh
tpt-privd-daemon --check --config /etc/tpt-privd/config.toml
tpt-privd-daemon --print-config --config /etc/tpt-privd/config.toml
tpt-privd-daemon --print-schema
```

## Audit verification

```sh
tpt-privd-daemon verify-audit /var/lib/tpt-privd/audit.jsonl
# optional explicit key:
tpt-privd-daemon verify-audit /var/lib/tpt-privd/audit.jsonl \
  --key /etc/tpt-privd/audit.key
```

Wire this into a timer or log-shipping job. A FAIL means the chain or
a signature broke — treat as a security event (`SECURITY.md`).

## Smoke client

```sh
tpt-privd-daemon call \
  --socket /run/tpt-privd/privd.sock \
  --kind 1 \
  --payload hello
```

`kind 1` is `CommandKind::ECHO` on the mock executor.

## Key provisioning

First run auto-generates `audit.key` at mode `0600` (dev convenience).
In production, provision the key out-of-band (config management,
`secrets/`), verify mode `0600`, and back it up with the audit log
verification process — losing the key makes offline verification
impossible without the public key material.

## Publish order

For crates.io releases, publish in dependency order:

1. `tpt-privd-envelope` (no internal deps)
2. `tpt-privd-transport`, `tpt-privd-policy`, `tpt-privd-audit`
   (all depend only on envelope; parallelizable)
3. `tpt-privd-client` (envelope + transport)
4. `tpt-privd-daemon` (everything + `tpt-l-sandbox`)

**Blocker:** `tpt-privd-daemon` has a non-optional path+version dep on
`tpt-l-sandbox`. Publish `tpt-linux-sandbox` first, or feature-gate the
Linux sandbox dep before the first `cargo publish` of the daemon.

Manual publish is fine for now (C4 note): tag-driven workflow, update
`CHANGELOG.md`, `cargo publish -p <crate>` in the order above — or use
`cargo xtask publish-order` (I9) to print the same topo order.

Optional release automation (still open as C4): `release-plz` or a
tag-driven workflow that runs `cargo publish` in that order after CI is
green. Coverage and `cargo-semver-checks` can be added the same way;
fuzz is scheduled via `.github/workflows/fuzz.yml` (C5).

## Non-Linux Unix

Capability dropping is a no-op stub off Linux — do not deploy the
privilege-drop story there without reading `docs/ARCHITECTURE.md`
§ Privilege dropping.
