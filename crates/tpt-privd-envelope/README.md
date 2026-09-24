# tpt-privd-envelope

Typed, versioned command envelope for `tpt-privd` — the CBOR wire format
shared by the daemon and its clients.

- `Command` / `CommandResult` / `CommandKind` (open `u32` enum with
  `CUSTOM_START` consumer range)
- CBOR encode/decode via `ciborium` + `serde`
- Strict `ENVELOPE_VERSION` gate (mismatch → `UnsupportedVersion`)

```rust
use tpt_privd_envelope::{Command, CommandId, CommandKind, ENVELOPE_VERSION};

let cmd = Command::new(CommandId(1), CommandKind::ECHO, b"ping".to_vec());
assert_eq!(cmd.version, ENVELOPE_VERSION);
let bytes = tpt_privd_envelope::encode(&cmd).unwrap();
```

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
