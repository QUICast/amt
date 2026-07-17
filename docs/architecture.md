# Architecture

This crate is split into runtime-agnostic protocol/state components and small
blocking role runners.

The repository also contains the experimental `quicast-amtq` workspace package.
It reuses the RFC 7450 codec and membership machinery but owns AMTQ framing,
connection-bound state, Delivery Contexts, and data-mode processing. See
[`amtq.md`](amtq.md) for that package boundary and rollout.

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
- `state::RelayState` tracks gateway interest by endpoint and group/source. It
  is an alias of the generic `state::MembershipTable<SocketAddr>`; transports
  with stable connection identity can supply another key type.
- `state::UpstreamSubscription` summarizes the native multicast joins needed
  for the current gateway set.
- `upstream::UpstreamManager` reconciles those subscriptions into
  `mcrx_core::RawContext` subscriptions, or Linux shared capture sockets when
  built with `shared-upstream`.
- `pmtu` builds and transmits rate-limited ICMP feedback toward oversized SSM
  sources when built with `pmtu-feedback`.
- `daemon::run_relay` connects the UDP AMT socket to the relay state machine and
  forwards raw upstream datagrams as AMT Multicast Data.
- `udp::AmtUdpSocket` supplies per-datagram outer ECN metadata and transmit
  markings through `quinn-udp`.

The relay currently uses HMAC-SHA256 for the Response MAC derivation and takes
the first six bytes as the RFC 7450 Response MAC field. Secrets rotate
periodically, authentication comparison is constant-time, and the immediately
previous secret remains valid for at most two advertised query intervals.
The relay's encapsulated General Query uses Maximum Response Code `1` for an
immediate gateway response. Query and Membership Update parsers validate only
the complete IP datagram and ignore permitted trailing AMT padding; padding is
never forwarded into the local IGMP/MLD path.

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
without sending Teardown. A configured endpoint timeout must exceed the query
interval advertised to gateways.

## Gateway Flow

The gateway code is organized as follows:

- `gateway::Gateway` handles Relay Advertisement, Membership Query, Multicast
  Data, and Teardown state.
- `driad` resolves SSM source addresses to ordered AMTRELAY candidates.
- `membership` builds IGMPv3 or MLDv2 membership reports for configured joins.
- `local_membership::LocalMembershipManager` listens for local IGMPv3/MLDv2
  receiver reports in transparent mode and converts aggregate LAN interest into
  AMT Membership Updates.
- `downstream::DownstreamPublisher` forwards complete multicast IP datagrams
  through `mctx_core::RawContext`.
- `daemon::run_gateway` runs either one static relay session or independent
  source-owned DRIAD sessions.

The gateway supports both ASM and SSM membership requests toward the relay:

- ASM is encoded as a `ModeIsExclude` record with no blocked sources.
- SSM is encoded as a `ModeIsInclude` record with the selected source.

With the `driad` Cargo feature, configured and transparent SSM interest is
partitioned by source. Each source owns a `DriadSourceTunnel` with its own UDP
socket, gateway state machine, DNS refresh state, candidate/probe queues,
hold-down map, and traffic-health backoff. Multiple groups for one source share
that tunnel; failure or rediscovery for one source does not disturb another.

DNS runs in a bounded worker set and is asynchronous relative to the gateway
loop. Replies are source-bound and fully question-checked, CNAME/DNAME aliases
are followed, truncated UDP answers retry over TCP, and a shared limiter bounds
queries across source workers. Candidate precedence is preserved while equal
candidates are randomized and address families interleaved. Staggered probes
advance only within the current discovery/precedence tier, and only the first
valid non-L Membership Query is promoted and receives membership state. L and
no-traffic outcomes install per-relay hold-downs. A type-0 NoRelay result tears
down and suppresses that source until DNS later returns usable candidates.

`auto` places RFC 7450 anycast ahead of DRIAD. Explicit `driad` mode is the RFC
8777 administrative override that starts at source-owned records. DNS-SD is a
separate, not-yet-implemented discovery tier.

Each established gateway state periodically starts a fresh Request-Nonce cycle,
waits for a validated Membership Query, and then replays complete desired
membership state. A timeout restarts only that session's discovery. This keeps
healthy gateways alive, detects relay restarts, and prevents stale Query/MAC
replay.

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
can configure 1280 bytes for a conservative Internet-path assumption.

With `pmtu-feedback`, the relay follows RFC 7450 Section 5.3.3.6.2 for SSM:
DF-set IPv4 drops produce ICMPv4 Fragmentation Needed and IPv6 drops produce
ICMPv6 Packet Too Big. The relay evaluates all matching gateways first and
sends one response with the smallest affected tunnel MTU. Feedback is bounded
per `(source, group)`, suppressed for invoking ICMP errors, and sent through
`mctx_core::RawIpContext` using the configured upstream interface address.

RFC 9601 ECN support is opt-in. An enabled gateway sets the Request `E` bit; an
enabled relay stores that capability in a bounded, expiring endpoint table and
uses RFC 6040 normal-mode encapsulation only for those gateways. All control
traffic and data for unknown or non-capable gateways use a Not-ECT outer header.
At the gateway, RFC 6040 Figure 4 combines inner and outer markings before raw
downstream injection. IPv4 header checksums are repaired when ECN changes, and
the invalid inner-Not-ECT/outer-CE combination is dropped. This keeps the
default compatibility mode safe while allowing complete propagation when both
ends opt in.

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
drains and short polling sleeps for simplicity. `shared-upstream` selects the
Linux shared mcrx capture backend; `pmtu-feedback` adds mctx raw-IP control
transmit. Both are opt-in and imply `runtime`.

The crate deliberately rejects iOS targets at compile time. Supported daemon
targets are Linux, macOS, and Windows; compiling the core without runtime does
not imply an iOS support commitment.

Future runtime integrations can reuse:

- `Relay::handle_datagram`
- `Gateway::handle_datagram`
- `Gateway::handle_datagram_with_ecn`
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
`amt-gateway` samples with relay/downstream/transparent-mode gauges, DRIAD
source/active/probe/hold-down gauges, and AMT control, discovery, downstream,
and local-membership counters.

Metric collection is deliberately passive: it should not change protocol state,
native multicast subscription reconciliation, or forwarding behavior.

## Error Boundaries

Protocol-level decode errors stay in `protocol`.

Membership parse/build errors stay in `membership`.

Native multicast receive errors from `mcrx-core` are contained at the
daemon/upstream boundary. Failed additions roll back; failed removals remain
active and are retried periodically.

The portable mcrx backend creates one capture socket per raw subscription and
polls subscriptions linearly. The relay therefore keeps a conservative default
cap of 256. On Linux, `shared-upstream` uses `mcrx-core 0.3.0` family/interface
capture sockets with indexed `(S,G)` demultiplexing, removing descriptor and
polling growth when operators configure a larger subscription limit.

Native multicast send errors from `mctx-core` are surfaced through the
downstream boundary. Raw-IP PMTU feedback failures are counted and summarized
without terminating multicast forwarding.
