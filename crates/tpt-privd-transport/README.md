# tpt-privd-transport

Length-prefixed CBOR framing and Unix domain socket transport for
`tpt-privd`.

- `[u32 BE len][CBOR payload]` framing with size checked before allocation
- One-shot request/reply over `AF_UNIX`
- `SO_PEERCRED` peer identification (Linux)
- Mode/ownership on the listener **fd** (`fchmod`/`fchown`) to avoid path
  TOCTOU

Framing is cross-platform; socket code is `cfg(unix)`.

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
