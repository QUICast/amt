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

## Next Milestone

The next implementation milestone is native multicast and a useful daemon:

1. Connect Relay Authorized Reception State to shared native `mcrx-core`
   subscriptions and Gateway delivery to `mctx-core`.
2. Add an `amtq` executable only once it can join, tunnel, and publish real
   multicast rather than merely maintain a QUIC handshake.
3. Add connection migration/rebinding and remote quiche interoperability tests.
4. Implement Reliable Block Mode stream FIN/RESET/STOP_SENDING semantics before
   enabling that mode in the runtime.
5. Add configuration and metrics after the lifecycle is stable.
