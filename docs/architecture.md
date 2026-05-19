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
the first six bytes as the RFC 7450 Response MAC field.

The blocking relay daemon also keeps lightweight gateway activity bookkeeping.
Accepted Membership Updates mark a gateway as active, Teardown removes it
immediately, and idle gateway state is pruned after a configurable timeout so
native upstream subscriptions are reconciled back down when a gateway vanishes
without sending Teardown.

## Gateway Flow

The gateway code is organized as follows:

- `gateway::Gateway` handles Relay Advertisement, Membership Query, Multicast
  Data, and Teardown state.
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

The blocking gateway daemon periodically refreshes its current Membership
Update state after the initial Membership Query. This keeps healthy gateways
alive across relay-side idle pruning while still allowing crashed or
disconnected gateways to age out.

The gateway daemon also installs a small shutdown signal handler. On Ctrl-C or
SIGTERM it sends AMT Teardown when the relay has supplied enough state to build
one, which gives the relay an immediate cleanup signal instead of waiting for
idle expiry.

In transparent mode, local receiver reports are tracked per reporter IP and
collapsed into the minimum upstream AMT interest needed for the LAN. If any
local receiver has ASM interest for a group, the gateway advertises ASM
upstream for that group. Otherwise it advertises the exact set of SSM sources
reported by local receivers.

The current transparent gateway learns from reports and state changes, but it
does not yet run the full IGMP/MLD listener timer machinery needed to age out
silent receivers.

## Packet Handling

AMT Multicast Data carries a complete IP multicast datagram. The relay preserves
that datagram when forwarding from native multicast into AMT, and the gateway
preserves it when forwarding from AMT onto the local downstream side.

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

The protocol and state types are runtime-agnostic. The current `daemon` module
contains small blocking role runners and uses short polling sleeps for
simplicity.

Future runtime integrations can reuse:

- `Relay::handle_datagram`
- `Gateway::handle_datagram`
- `LocalMembershipManager`
- `UpstreamManager`
- `DownstreamPublisher`

The blocking runners are intentionally not the architectural center of the
crate.

## Error Boundaries

Protocol-level decode errors stay in `protocol`.

Membership parse/build errors stay in `membership`.

Native multicast receive errors from `mcrx-core` are surfaced through the
daemon/upstream boundary.

Native multicast send errors from `mctx-core` are surfaced through the
downstream boundary.
