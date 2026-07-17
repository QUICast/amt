# quicast-amtq

Experimental implementation of the `amtq-00` wire format in the working AMT
over QUIC draft.

This package is a workspace sibling of `quicast-amt`. It reuses that crate's
RFC 7450 codec, IGMPv3/MLDv2 processing, multicast packet validation, and
membership aggregation, while keeping draft churn and eventual QUIC/TLS
dependencies outside the stable AMT package.

## Implemented

- QUIC variable-length integers, including valid non-minimal encodings.
- Incremental control-record headers with a pre-allocation length check.
- SETTINGS negotiation and duplicate/role/value validation.
- AMT Request, Membership Query, and Membership Update profile validation.
- Zero Response MAC, zero Gateway Address flag, zero ECN capability, and
  one-outstanding-Request rules.
- Connection-wide IGMP or MLD address-family binding.
- Transactional Requested and Authorized Reception State.
- Monotonic Delivery Contexts with mandatory Context 0 and acknowledgment.
- Datagram COMPLETE and FRAGMENT formats.
- Bounded out-of-order fragment reassembly with conflict detection, expiry,
  and least-recently-updated eviction.
- Reliable Data Block and Data Record framing.
- Reliable context close tracking through Final Block ID and an explicit
  close-drain event.
- Source/group filtering against Requested or Authorized Reception State.
- Draft application error codes and absolute protocol limits.
- An optional raw quiche adapter with exact peer transport-parameter checks.
- An optional tokio-quiche Datagram Mode driver with bounded command, event,
  control-stream, and multicast-data queues.
- A production-oriented endpoint layer with TLS identities and trust stores,
  reference-identity verification, optional Gateway mTLS, stateless address
  validation, global/per-IP admission limits, keepalive, stable connection
  IDs, lifecycle accounting, and bounded graceful shutdown.
- Native Relay subscription aggregation through `mcrx-core`, including
  cross-connection ASM/SSM collapse and optional Linux shared capture.
- Native Gateway publication through `mctx-core` while preserving complete
  multicast IP datagrams and their original source/group tuple.
- Dedicated bounded native-I/O workers, best-effort overload shedding, and one
  immutable packet allocation shared across Relay fan-out targets.
- A runnable `amtq relay` and `amtq gateway` with explicit TLS trust, optional
  Gateway client certificates, static ASM/SSM joins, membership refresh, and
  graceful shutdown.
- TLS reference-identity verification, SETTINGS, membership authorization,
  context acknowledgment, COMPLETE delivery, and fragmented delivery in a
  real localhost QUIC integration test.

## Not Yet Implemented

- Reliable Block Mode stream lifecycle, including FIN, RESET_STREAM, and
  STOP_SENDING handling.
- Transparent LAN IGMPv3/MLDv2 membership capture.
- Automatic Gateway reconnect and AMTQ Relay discovery.
- Connection migration interoperability tests.
- Metrics, configuration files, and live interoperability tests.

The tokio-quiche driver currently implements Datagram Mode only. It rejects a
configuration that advertises Reliable Block Mode rather than negotiating a
mode whose stream lifecycle is incomplete.

## Features

- Default: runtime-independent codecs, state machines, reassembly, and
  Reliable Block framing/bookkeeping.
- `transport-quiche`: raw quiche configuration, ALPN and exact peer
  transport-parameter validation, and application-close mapping.
- `runtime-tokio-quiche`: bounded asynchronous Gateway/Relay drivers and
  controllers for Datagram Mode, plus managed client/server endpoints. This
  feature includes `transport-quiche`.
- `native-multicast`: managed AMTQ services backed by the reusable
  `quicast-amt` native multicast primitives.
- `shared-upstream`: Linux `mcrx-core` shared raw capture for high subscription
  counts. This includes `native-multicast`.
- `daemon`: the `amtq` executable and signal-aware multi-threaded Tokio
  runtime. This includes `native-multicast`.

The optional layers use quiche `0.28` and tokio-quiche `0.18`, matching the
versions used by the surrounding QUICast stack.

## Build

From the repository root:

```bash
cargo test -p quicast-amtq
cargo test -p quicast-amtq --features transport-quiche
cargo test -p quicast-amtq --features runtime-tokio-quiche
cargo test -p quicast-amtq --features daemon
cargo build -p quicast-amtq --release --features daemon,shared-upstream
cargo clippy -p quicast-amtq --all-targets -- -D warnings
cargo clippy -p quicast-amtq --all-targets \
  --features daemon -- -D warnings
```

The endpoint integration tests require permission to bind local UDP sockets.
They cover idle keepalive, admission rejection, hostname mismatch rejection,
optional mTLS, and connection cleanup in addition to the complete AMTQ
Datagram Mode exchange.

On Linux, the ignored namespace test exercises the complete native path:

```bash
sudo -E env PATH="$PATH" cargo test -p quicast-amtq \
  --features daemon,shared-upstream \
  --test native_system_linux -- --ignored --test-threads=1 --nocapture
```

The package is intentionally `publish = false` while the draft and wire format
are experimental.
