# tpt-privd-audit

Append-only, Ed25519-signed, hash-chained audit log for `tpt-privd`.

- JSONL records, one object per line
- SHA-256 hash chain over a fixed-order canonical form
- Per-record Ed25519 signatures
- Torn-tail crash recovery, full replay verification
- Key load-or-generate at mode `0600` (dev convenience; provision
  externally in production)
- `O_NOFOLLOW` on Unix opens; bounded in-memory record cache

Offline verify:

```sh
tpt-privd-daemon verify-audit /var/lib/tpt-privd/audit.jsonl
```

Part of [tpt-privd](https://github.com/TPT-Solutions/tpt-privd).
