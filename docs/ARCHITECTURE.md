# tpt-privd — Architecture (as-built)

This expands on `spec.txt`'s architecture section with the crate layout and
request path as actually implemented. Spec resolved decisions from
2026-09-24 are assumed (CBOR envelope, self-contained audit log,
`tpt-linux-sandbox` path dependency, UDS-only v1, synchronous one-shot).

## Crate dependency graph

```text
                    tpt-privd-envelope
                     /       |       \
                    /        |        \
     tpt-privd-transport  tpt-privd-policy  tpt-privd-audit
                    \        |        /
                     \       |       /
                      tpt-privd-client
                             |
                      tpt-privd-daemon (bin + lib)
                             |
              [cfg(target_os = "linux")]
                      tpt-l-sandbox  (path dep → sibling repo)
```

- **envelope** has no internal deps — pure types + CBOR.
- **transport** depends only on envelope (frames are raw bytes; CBOR
  decode happens one layer up).
- **policy** depends only on envelope.
- **audit** depends only on envelope (records carry command metadata).
- **client** composes envelope + transport.
- **daemon** composes everything; the accept loop and privilege-drop live
  here, not in the leaf crates.

## Request → policy → execute → audit → reply

One-shot connection: connect → one frame in → handle → one frame out →
close. No pipelining, no request IDs multiplexed on a live connection
(`CommandId` is a caller-chosen correlator for the single in-flight
command).

```text
 Client                         Daemon (post-drop accept loop)
   |                                        |
   |--- AF_UNIX connect ------------------->|  (socket bound pre-drop,
   |                                        |   mode/owner set at bind)
   |    SO_PEERCRED → (pid, uid, gid)       |
   |                                        |
   |--- [u32 len][CBOR Command] ----------->|
   |                                        |  read_frame (size-checked
   |                                        |  before allocation)
   |                                        |
    |                    decode(Command) ----+--> Err: audit transport
    |                                        |    reject (zeros +
    |                                        |    InternalError), drop
    |                                        |    conn, no reply
    |                                        |    (F16: no CommandId yet)
   |                                        |
   |                    check_version ------+--> mismatch:
   |                                        |      audit(VersionMismatch)
   |                                        |      reply CommandResult{Err}
   |                                        |
   |                    executor.policy_check
   |                                        |--> Violation:
   |                                        |      audit(PolicyDenied)
   |                                        |      reply CommandResult{Err}
   |                                        |
   |                    executor.execute ---+--> Err:
   |                                        |      audit(ExecutionFailed)
   |                                        |      reply CommandResult{Err}
   |                                        |
   |                                        |--> Ok:
   |                                        |      audit(Executed)
   |                                        |      reply CommandResult{Ok}
   |                                        |
   |<-- [u32 len][CBOR CommandResult] ------|
   |    (includes AuditLogRef{seq, hash})   |
   |                                        |
   |--- close ----------------------------->|
```

Every path that produces a `CommandResult` (success **or** structured
failure) first appends an audit record and includes its `AuditLogRef`.
Malformed CBOR after a valid frame length is also audit-logged as a
transport-reject record (F16: zeroed `CommandId`/`CommandKind`,
`InternalError`) — it still cannot be correlated to a real command id.
Frame-level oversize/truncation fails in `read_frame` before decode and
is not audited (never reaches the handler).

## Privilege-drop sequence (security-critical)

```text
 main
  │
  ├─ 1. Config::load / validate
  │
  ├─ 2. AuditLog::open(audit_log_path, audit_key_path)
  │       └─ loads or first-run generates Ed25519 key (0600 on Unix)
  │          Needs: write access to audit paths
  │
  ├─ 3. bind_listener(SocketConfig)
  │       ├─ create_dir_all(parent)
  │       ├─ remove stale socket (only if actually a socket;
  │       │   refuse if a live socket still answers)
  │       ├─ bind(2)
  │       ├─ fchmod(mode) on listener fd  ← primary access control
  │       └─ fchown(owner) on listener fd if configured
  │          Needs: privilege to create path + fchmod/fchown
  │
  ├─ 4. drop_privileges(config)          [Linux: tpt-l-sandbox]
  │       Sandbox::new()
  │           .caps(CapsPolicy::new().drop_all().keep(each config.caps.keep))
  │           .apply()
  │       Stages inside tpt-l-sandbox: validate → (unpriv setup) →
  │       namespaces → fs jail → **caps** → **seccomp (opt-in)** → landlock
  │       v1 configures caps always; seccomp only when `[seccomp] enabled`
  │       with a non-empty allowlist (default-deny — incomplete lists
  │       SIGSYS-kill; prefer `on_deny = "errno"` while testing). Landlock
  │       and namespaces remain unwired.
  │       are supported by the builder and can be layered on later
  │       without changing this ordering.
  │       MUST complete before any accept(2).
  │
  └─ 5. serve_listener(listener, executor, audit, limits)
          for stream in listener.incoming():
              set read/write timeouts
              uid = SO_PEERCRED
              read_frame → handle_cbor_payload → write_frame
```

Rationale for ordering:

- The socket fd, once bound, remains valid after capability drop — no cap
  is needed to `accept` on an existing listener.
- The audit key and log must be writable for the process's whole lifetime;
  if you drop to a non-root uid (future work — v1 drops caps only, not
  uid), provision ownership accordingly before step 4.
- Nothing user-controlled is processed until step 5.

## Wire format

### Framing

```text
[u32 big-endian length][CBOR payload]
```

`length` is payload bytes only. Validated against `limits.max_frame_size`
(default 1 MiB) **before** allocating — a hostile `0xFFFFFFFF` prefix
causes an immediate `FrameTooLarge` and connection drop, not a 4 GiB
allocation attempt.

### Envelope (CBOR via `ciborium` + `serde`)

```rust
struct Command {
    id: u64,             // CommandId, transparent
    version: u32,         // must == ENVELOPE_VERSION (1)
    kind: u32,            // CommandKind, transparent
    payload: Vec<u8>,     // opaque per-kind
}

struct CommandResult {
    id: u64,
    outcome: Result<CommandSuccess { payload: Vec<u8> },
                     CommandError { code: ErrorCode, message: String }>,
    audit_ref: { seq: u64, hash: String /* hex SHA-256 */ },
}
```

**Version negotiation (v1):** strict equality. `cmd.version !=
ENVELOPE_VERSION` → audit-logged `VersionMismatch` + structured
`ErrorCode::UnsupportedVersion` reply; no execution. There is no
forward-compatible minor-version dance — a bump is a breaking wire change.
Policy for future bumps is recorded in `CHANGELOG.md`.

**`CommandKind` extension mechanism (decision):** a transparent `u32`
newtype with reserved built-ins (`0 = NOP`, `1 = ECHO`) and
`CUSTOM_START = 0x8000_0000` for consumers — *not* a closed Rust `enum`
with a `Custom` variant, and *not* a generic `Command<K>`. A `u32` keeps
the CBOR representation a bare integer, avoids a generic parameter
propagating through transport/policy/audit, and still gives consumers an
open, collision-resistant namespace. Consumers map their domain enums
onto/from `CommandKind(u32)` in their own repos.

## Audit log format

**JSON Lines (NDJSON)**, one object per line, hex-encoded binary fields.
Chosen over CBOR frames because it is greppable/`jq`-able and a torn final
line (crash mid-write) is detectable and truncated on open, while complete
lines always parse.

Integrity does **not** depend on JSON canonicalization. Each record stores:

- `prev_hash` — SHA-256 of the previous record's `hash` (32 zero bytes for
  seq 0), forming the chain.
- `hash` — SHA-256 of `canonical_bytes()`, a fixed-order binary layout of
  all fields (see `AuditRecord::canonical_bytes`).
- `sig` — Ed25519 signature **over `hash`**, per record (not batched —
  every line is independently non-repudiable; Ed25519 is cheap enough).

Full command/result **payloads are not stored** — only SHA-256 digests plus
metadata (id, version, kind, caller uid, outcome, error code). This bounds
log growth and avoids persisting bytes a consumer might later classify as
sensitive.

**Verification** (`AuditLog::verify` / `verify_file`): replay the file,
check `seq` continuity and `prev_hash` links, recompute every `hash`,
verify every `sig` against the public key. Any bit-flip, reordering,
middle deletion, or resign-with-wrong-key fails at the exact divergent
`seq`.

**Crash recovery:** on open, parse lines until a torn tail (incomplete
final line / bad JSON at EOF without newline) is found; truncate the file
back to the last complete valid line; then full-chain verify before
accepting appends. A corrupt line in the *middle* is a hard error.

**Key provisioning:** first run auto-generates a keypair at
`audit_key_path` (mode `0600` on Unix). Production should provision the
secret externally (config management, future HSM path) — auto-generation is
a development convenience, documented as such.

## Peer identification

On Linux, `SO_PEERCRED` after `accept` yields `(pid, uid, gid)`, recorded
as `caller_uid` in each audit record. Socket file mode/owner set at bind
time is the **primary access control** (who can open the socket at all);
peer credentials are for accountability, not v1's sole authorization gate
(multi-tenant per-caller policy is deferred per the spec).

## Platform / cfg gating

| Component | Windows dev build | Linux CI / prod |
|---|---|---|
| envelope, policy, audit, config, handle | compiled + tested | compiled + tested |
| transport framing | compiled + tested (in-memory) | compiled + tested |
| transport socket + peercred | `cfg(unix)` — skipped | compiled + tested |
| daemon accept loop, client `call` | `cfg(unix)` — skipped | compiled + tested |
| capability drop (`tpt-l-sandbox`) | not a dependency | path dep, `cfg(target_os = "linux")` |

Windows is a **development convenience only** — the binary's `main` prints
an error and exits non-zero on non-Unix. Production is Linux.

## Testing: what is covered, what is not

**Covered in CI (Linux):**

- Envelope: round-trips, version gate, malformed-CBOR never panics
  (deterministic scan + fuzz target for manual runs).
- Framing: hostile length prefix, truncation, oversize, timeouts.
- Socket: real UDS bind/connect, peercred == self on loopback, mode bits.
- Policy: accept/deny matrix for built-ins + allowlisted custom kinds.
- Audit: chain verify, tamper (bit-flip, field change, wrong key, deleted
  middle record), torn-tail crash recovery, reopen-continues.
- Daemon handle path: every outcome (exec / policy-denied / version /
  exec-failed) audited and returns structured `CommandResult`.
- Integration (`tests/integration.rs`, `cfg(unix)`): full client → socket
  → daemon → audit → client round-trip for each outcome class;
  frame-level oversize rejected before decode (no audit); malformed CBOR
  after a valid frame length **is** audit-logged (F16 transport-reject
  record: zero ids, `InternalError`).
- Feature `otel` (I4): `cargo check -p tpt-privd-daemon --features otel`
  job so the optional OpenTelemetry layer keeps compiling.
- CapEff harness (I6): CI `caps-harness` job builds
  `packaging/Dockerfile.caps-harness` and runs `examples/caps_probe` as
  root, asserting `CapEff` shrinks and keep/deny expectations hold after
  `drop_privileges`.
- Audit shipper (I5): unit tests for `MemorySink`, `JsonlMirrorSink`,
  shipper thread delivery; sink failures never roll back a local append.

**Not covered in CI (documented gap):**

- Landlock/namespaces enforcement (never enabled from config). Seccomp can
  be enabled experimentally via `[seccomp]` but is not covered by CI
  (kernel + syscall allowlist are environment-specific).
- Full LSM / seccomp enforcement under real load — needs a kernel with the
  LSMs enabled; the I6 harness covers CapEff shrink only.
- Manual verification steps from the checklist ("compromised connection
  handler cannot escalate past the dropped set") — I6 automates CapEff
  observation in CI; the full threat-model check still wants a real
  Linux target.

This gap is called out rather than silently skipped, per the Phase 7
checklist item.

## Fuzzing

`crates/tpt-privd-envelope/fuzz/` contains a `cargo-fuzz` target driving
`decode` / `decode_result` with arbitrary bytes. Scheduled in CI via
`.github/workflows/fuzz.yml` (C5, daily + manual dispatch) with a 60s
budget; full runs still need nightly + libFuzzer toolchain. Manual:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run decode
```

The invariant under test: **malformed input never panics or aborts the
daemon's decoder** — always `Err`.
