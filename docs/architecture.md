# Architecture

This crate is split into runtime-agnostic protocol/state components and small
blocking role runners.

## Roles

AMT has two active roles:

- Relay: receives AMT messages from gateways, subscribes to native multicast
  upstream, and encapsulates native multicast IP datagrams into AMT Multicast
  Data.
- Gateway: discovers a relay, sends membership reports to it, receives AMT
  Multicast Data, and forwards traffic onto the local receiver side.

## Relay Flow

```text
Gateway                           Relay
   | -- Relay Discovery ----------> |
   | <------- Relay Advertisement -- |
   | -- Request -------------------> |
   | <------- Membership Query ----- |
   | -- Membership Update --------> |
   |                                | join native multicast upstream
   | <------- Multicast Data ------- |
   | -- Teardown -----------------> |
```

The relay code is organized as follows:

- `relay::Relay` handles RFC 7450 control messages and authentication.
- `state::RelayState` tracks gateway interest by endpoint and group/source.
- `state::UpstreamSubscription` summarizes the native multicast joins needed
  for the current gateway set.
- `upstream::UpstreamManager` reconciles those subscriptions into
  `mcrx_core::RawContext` subscriptions.
- `daemon::run_relay` connects the UDP AMT socket to the relay state machine and
  forwards raw upstream datagrams as AMT Multicast Data.

The relay currently uses HMAC-SHA256 for the Response MAC derivation and takes
the first six bytes as the RFC 7450 Response MAC field. Secrets rotate
periodically, authentication comparison is constant-time, and the immediately
previous secret remains valid for at most two advertised query intervals.

Membership updates are applied to candidate state. Native subscriptions are
added before stale subscriptions are removed, and the candidate relay state is
committed only when required additions succeed. A bad or unsupported join can
therefore reject one update but cannot terminate the daemon or replace working
state. Configurable endpoint/group/source limits and per-source/global token
buckets bound public control-plane work.

The blocking relay daemon also keeps lightweight gateway activity bookkeeping.
Accepted Membership Updates mark a gateway as active, Teardown removes it
immediately, and idle gateway state is pruned after a configurable timeout so
native upstream subscriptions are reconciled back down when a gateway vanishes
without sending Teardown.

## Gateway Flow

The gateway code is organized as follows:

- `gateway::Gateway` handles Relay Advertisement, Membership Query, Multicast
  Data, and Teardown state.
- `driad` optionally resolves an SSM source address to AMTRELAY DNS records and
  selects the relay used to build the gateway session.
- `membership` builds IGMPv3 or MLDv2 membership reports for configured joins.
- `local_membership::LocalMembershipManager` listens for local IGMPv3/MLDv2
  receiver reports in transparent mode and converts aggregate LAN interest into
  AMT Membership Updates.
- `downstream::DownstreamPublisher` forwards complete multicast IP datagrams
  through `mctx_core::RawContext`.
- `daemon::run_gateway` connects the UDP AMT socket to the gateway state
  machine.

The gateway supports both ASM and SSM membership requests toward the relay:

- ASM is encoded as a `ModeIsExclude` record with no blocked sources.
- SSM is encoded as a `ModeIsInclude` record with the selected source.

With the `driad` Cargo feature, the daemon edge can resolve a configured SSM
source through RFC 8777 DNS Reverse IP AMT Discovery before constructing the
gateway session. DRIAD candidates remain ordered by precedence and are tried on
handshake timeout. DNS replies are source-bound and fully question-checked;
remote plaintext resolvers require an explicit insecure override. Future
multi-source transparent DRIAD will still need separate per-source sessions.

The blocking gateway daemon periodically starts a fresh Request-Nonce cycle,
waits for a validated Membership Query, and then replays complete desired
membership state. A timeout returns to discovery and rotates through configured
relay candidates. This keeps healthy gateways alive, detects relay restarts,
and prevents stale Query/MAC replay.

The gateway daemon also installs a small shutdown signal handler. On Ctrl-C or
SIGTERM it sends AMT Teardown when the relay has supplied enough state to build
one, which gives the relay an immediate cleanup signal instead of waiting for
idle expiry.

In transparent mode, local receiver reports are tracked per reporter IP and
collapsed into the minimum upstream AMT interest needed for the LAN. If any
local receiver has ASM interest for a group, the gateway advertises ASM
upstream for that group. Otherwise it advertises the exact set of SSM sources
reported by local receivers.

Transparent mode filters LAN-local control and discovery groups before building
AMT Membership Updates. IPv4 `224.0.0.0/24`, common local discovery groups such
as SSDP, and IPv6 link-local multicast scope stay local to the receiver LAN and
are not exported to the relay.

Silent transparent reporters expire after a configurable timeout. This is
conservative bookkeeping rather than a complete IGMP/MLD multicast-router
listener state machine.

## Packet Handling

AMT Multicast Data carries a complete IP multicast datagram. The gateway accepts
it only from the selected relay and only when its `(S,G)` matches current
reception state. IP length, source, destination, and IPv4 header checksum are
validated before raw downstream injection. Fragmented IPv4 packets are
preserved without treating fragment payload as a UDP header.

The relay applies a fixed configurable path MTU (1500 bytes by default) and
derives the tunnel MTU separately for IPv4 and IPv6 gateway endpoints.
Oversized IPv4 packets with DF clear are fragmented before AMT encapsulation;
DF-set IPv4, IPv4 packets carrying header options, and IPv6 packets are dropped,
so the outer AMT datagram itself is never deliberately fragmented. Operators
can configure 1280 bytes for a conservative Internet-path assumption. ICMP
Packet Too Big feedback toward SSM sources still requires a portable
raw-unicast transmit path.

RFC 9601 ECN capability negotiation is intentionally left disabled: gateway
Request messages keep the E bit clear and the daemon creates ordinary UDP
sockets whose outer ECN field is Not-ECT. This is the safe compatibility mode;
the implementation never copies the inner ECN bits into an outer header that a
non-ECN gateway might discard.

## SSM Fidelity

The gateway uses `mctx-core` raw transmit to inject complete IP datagrams. This
preserves the original source/group tuple carried by AMT Multicast Data, so
local downstream receivers can use SSM.

- The relay can receive SSM upstream through `mcrx-core`.
- The gateway can request SSM from the relay.
- The gateway can forward the original `(S,G)` downstream through `mctx-core`.

Raw downstream transmit may require elevated privileges and explicit interface
selection. `mctx-core` currently does not support raw IPv6 transmit on Windows.

## Runtime Model

The protocol and state types are runtime-agnostic. Build with
`--no-default-features` for this portable core. The default `runtime` feature
adds config, daemon, mcrx, and mctx modules. Runtime receive loops use bounded
drains and short polling sleeps for simplicity.

Future runtime integrations can reuse:

- `Relay::handle_datagram`
- `Gateway::handle_datagram`
- `DriadResolver` when built with `--features driad`
- `LocalMembershipManager`
- `UpstreamManager`
- `DownstreamPublisher`

The blocking runners are intentionally not the architectural center of the
crate.

## Configuration

The binary loads role-specific TOML config through `config::FileConfig`.
Configuration is intentionally kept at the daemon edge: protocol/state modules
do not know about TOML, filesystems, or process-level defaults. CLI arguments
are applied after the file so a deployment config can be reused for local tests
with small overrides.

## Metrics

The daemon edge also owns AMT metrics behind the `metrics` Cargo feature.
`metrics::MetricsRecorder` accumulates role counters in process memory and
periodically emits Heimdall-style single-header JSONL samples when the feature
is enabled and an output directory is configured.

The relay emits `amt-relay` samples with gateway and upstream subscription
gauges plus AMT control/upstream forwarding counters. The gateway emits
`amt-gateway` samples with relay/downstream/transparent-mode gauges plus AMT
control, downstream forwarding, and local membership counters.

Metric collection is deliberately passive: it should not change protocol state,
native multicast subscription reconciliation, or forwarding behavior.

## Error Boundaries

Protocol-level decode errors stay in `protocol`.

Membership parse/build errors stay in `membership`.

Native multicast receive errors from `mcrx-core` are contained at the
daemon/upstream boundary. Failed additions roll back; failed removals remain
active and are retried periodically.

`mcrx-core 0.2.5` currently creates one capture socket per raw subscription and
polls subscriptions linearly. The relay caps unique upstream subscriptions at
256 by default. A shared capture socket with in-crate `(S,G)` demultiplexing is
the required sibling-crate improvement for substantially larger deployments.

Native multicast send errors from `mctx-core` are surfaced through the
downstream boundary.
