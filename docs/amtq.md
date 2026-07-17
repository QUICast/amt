# AMT over QUIC

The `amtq` branch adds an experimental AMT over QUIC implementation as a
separate `quicast-amtq` package in this repository. It targets the draft ALPN
token `amtq-00`.

## Package Boundary

`quicast-amt` remains the stable RFC 7450 implementation and daemon.
`quicast-amtq` depends on its runtime-independent library surface and owns:

- AMTQ control and data framing.
- SETTINGS and Delivery Context negotiation.
- Gateway and Relay AMTQ connection state.
- Fragment reassembly and Reliable Data Block state.
- AMTQ-specific validation and application errors.

The existing membership table is now generic over a stable tunnel key.
`RelayState` remains an alias keyed by `SocketAddr`, preserving classic AMT
behavior. AMTQ can instead key aggregate relay state by a QUIC connection
newtype so NAT rebinding and migration do not create a new tunnel.

## Protocol Core

The protocol core is deliberately transport independent. It provides:

- Strict codecs with absolute draft limits checked before allocation.
- Role-aware SETTINGS and control-message state machines.
- Transactional relay membership updates. A pending update contains the full
  resulting Requested Reception State; the caller evaluates authorization and
  atomically commits an Authorized Reception State that must be a subset.
- Context 0 and monotonically increasing context identifiers.
- COMPLETE and FRAGMENT Datagram Mode framing with bounded reassembly.
- Reliable Block framing, bounded compressed block bookkeeping, Final Block ID
  completion, and close-drain signaling.
- Data filtering against current reception state after reassembly and again
  immediately before relay transmission.

Malformed encapsulated multicast packets and packets outside reception state
are discarded. Protocol-limit, control-state, SETTINGS, and context violations
map to the draft's application error codes.

## Quiche Transport

The optional `transport-quiche` feature implements the raw quiche boundary:

- ALPN `amtq-00` configuration without enabling 0-RTT.
- Directional stream and DATAGRAM transport parameters.
- Exact validation of peer `initial_max_streams_bidi`,
  `initial_max_streams_uni`, and `max_datagram_frame_size`.
- Construction of session capabilities only after the handshake is established.
- Mapping draft `ProtocolError` values to QUIC application closes.

The optional `runtime-tokio-quiche` feature adds bounded asynchronous Gateway
and Relay drivers and controllers for Datagram Mode. The drivers enforce
Stream 0, reject prohibited streams and Gateway DATAGRAM frames, incrementally
parse bounded control records, fragment against quiche's current writable
DATAGRAM size, and reassemble before applying reception-state filtering. Local
commands and externally visible events use bounded Tokio channels.

The localhost integration test performs a certificate- and hostname-verified
QUIC handshake, exact transport negotiation, SETTINGS exchange, Request,
Membership Query, transactional Membership Update authorization, Context 0
acknowledgment, COMPLETE delivery, and fragmented delivery.

The QUIC transport is optional. A default build of `quicast-amtq` does not
compile quiche, tokio-quiche, Tokio, or TLS dependencies.

## Managed Endpoints

The `runtime-tokio-quiche` feature also provides a managed endpoint boundary:

- `RelayEndpoint` binds the UDP socket, installs the Relay identity, retains
  stateless client-address validation, and admits connections against global
  and per-source-IP limits before starting TLS work.
- A Relay publishes a `RelayConnection` only after the QUIC handshake, ALPN,
  certificate policy, and exact AMTQ transport-parameter checks succeed.
- `connect_gateway` verifies the Relay reference identity against either
  system roots or an explicit PEM trust bundle. There is no insecure mode.
- Relay deployments can require a Gateway certificate from a configured CA.
- Process-local `ConnectionId` values remain stable across QUIC migration and
  implement the generic `MembershipEndpoint` key used by shared reception
  state.
- Keepalive PING scheduling is independent of application traffic. Shutdown
  uses a dedicated state signal that cannot be blocked by a saturated command
  queue.
- Lifecycle status is separate from protocol events, allowing exact active,
  rejected, failed-handshake, closed, and forced-shutdown accounting without
  consuming events intended for the application.

The integration suite verifies idle survival beyond the negotiated timeout,
capacity rejection, wrong-hostname rejection, optional mutual TLS, and active
connection cleanup.

## Native Data Plane

The optional `native-multicast` feature connects the managed endpoints to the
same raw multicast primitives used by classic AMT:

- The Relay applies each pending Membership Update to a cloned aggregate
  `MembershipTable<ConnectionId>`. It reconciles all required native
  subscriptions before authorizing the update and commits the candidate only
  after required joins succeed.
- Aggregate-limit or native-join denial does not close the connection.
  Requested state still commits, while the intersection of prior Authorized
  state and current Requested state remains authorized, as required by the
  draft's no-failure-signal authorization model.
- Aggregate state collapses overlapping Gateway requests. One ASM request
  supersedes SSM subscriptions for the same group, while pure SSM interest
  retains the exact union of requested sources.
- Upstream capture runs on a named native thread. It uses a bounded packet
  channel and a nonzero idle poll interval, so raw socket work cannot block the
  Tokio QUIC runtime or regress into a busy loop.
- The Relay opens Datagram Context 0 after the first non-empty authorized
  state and forwards only after the Gateway acknowledges that context.
- One normalized AMT Multicast Data message is held in `Arc<[u8]>` across
  Gateway fan-out. Each connection performs its own path-sized framing without
  first copying the complete multicast packet.
- A slow Gateway fills bounded queues and loses best-effort multicast data
  rather than forcing a protocol close. Control-plane limit violations remain
  fail-closed.
- The Gateway automatically performs SETTINGS, Request, Membership Query, and
  periodic full-state Membership Update processing. Accepted multicast IP
  datagrams are published through a dedicated `mctx-core` worker.

The `shared-upstream` feature selects `mcrx-core` shared raw capture on Linux.
Other supported systems retain per-subscription capture. Native socket and
platform limitations are inherited from `mcrx-core` and `mctx-core`.

## First Daemon

The `daemon` feature builds a deliberately small `amtq` executable. AMTQ does
not require a dedicated UDP port; the examples use 2268 only as a convenient
provisioned test port.

Relay:

```bash
cargo build -p quicast-amtq --release --features daemon,shared-upstream

sudo ./target/release/amtq relay \
  --bind 0.0.0.0:2268 \
  --cert /etc/quicast/amtq/fullchain.pem \
  --key /etc/quicast/amtq/private-key.pem \
  --upstream-interface 192.0.2.10 \
  --max-subscriptions 4096
```

Static IPv4 ASM Gateway:

```bash
sudo ./target/release/amtq gateway \
  --relay 203.0.113.10:2268 \
  --server-name relay.example \
  --protocol igmpv3 \
  --join 239.1.2.3 \
  --downstream-interface 192.168.1.10
```

Static IPv4 SSM Gateway:

```bash
sudo ./target/release/amtq gateway \
  --relay 203.0.113.10:2268 \
  --server-name relay.example \
  --protocol igmpv3 \
  --join 192.0.2.20@232.1.2.3 \
  --downstream-interface 192.168.1.10
```

Use `--ca FILE` for a private Relay CA. Without it, the Gateway verifies
against system roots. There is no insecure verification mode. A Relay can add
`--client-ca FILE`; Gateways then provide both `--client-cert` and
`--client-key`.

The first daemon intentionally accepts static memberships only. Transparent
LAN membership capture and reconnect policy belong above this now-tested
service boundary and do not require wire-format changes.

## Testing

The unprivileged native loopback test uses real TLS and QUIC, automatically
completes a no-interest membership transaction, and verifies worker cleanup.
The ignored Linux namespace test adds real `mcrx`/`mctx` packet forwarding:

```bash
sudo -E env PATH="$PATH" cargo test -p quicast-amtq \
  --features daemon,shared-upstream \
  --test native_system_linux -- --ignored --test-threads=1 --nocapture
```

## Next Milestone

1. Add automatic Gateway reconnect with bounded backoff and full membership
   replay, then transparent local IGMPv3/MLDv2 membership capture.
2. Run remote quiche interoperability and QUIC migration/rebinding tests.
3. Implement Reliable Block Mode stream FIN/RESET/STOP_SENDING semantics before
   enabling that mode in the runtime.
4. Add configuration files and Heimdall-style optional metrics.
5. Track draft revisions without changing the stable RFC 7450 package.
