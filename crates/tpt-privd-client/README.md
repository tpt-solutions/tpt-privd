# tpt-privd-client

Thin client for sending one-shot commands to a `tpt-privd` daemon.

```rust
use tpt_privd_client::call;
use tpt_privd_envelope::{Command, CommandId, CommandKind};

let cmd = Command::new(CommandId(1), CommandKind::ECHO, b"hello".to_vec());
let result = call(
    std::path::Path::new("/run/tpt-privd/privd.sock"),
    &cmd,
).expect("daemon unreachable");
```

Uses default 5 s connect/read/write timeouts (`ClientOptions` for
overrides). Requires `cfg(unix)`.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
