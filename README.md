# amt

Lightweight Rust building blocks for [Automatic Multicast Tunneling][rfc7450]
(AMT, RFC 7450). The crates.io package is `quicast-amt`; the library crate and
installed CLI binary are both named `amt`.

This repository is now a Cargo workspace. The existing package remains
`quicast-amt`; the experimental `crates/quicast-amtq` package contains the
runtime-agnostic core plus optional quiche and tokio-quiche Datagram Mode
transport and managed TLS endpoint layer for the in-progress AMT over QUIC
draft. It is not yet a runnable AMTQ daemon. See
[`docs/amtq.md`](docs/amtq.md).

The crate currently includes:

- RFC 7450 message encoding and decoding.
- Relay-side discovery, request, membership update, teardown, and multicast
  forwarding state.
- Gateway-side discovery, request, membership update, multicast data, and
  teardown state.
- IGMPv3 and MLDv2 query/report packet helpers.
- Simple blocking relay and gateway runners.
- TOML configuration for the relay and gateway daemons.
- Optional RFC 8777 DRIAD discovery with independent configured or transparent
  SSM source sessions, Happy Eyeballs probing, and relay hold-downs.
- Optional [RFC 9601][rfc9601]/[RFC 6040][rfc6040] ECN propagation across the
  AMT tunnel.
- Heimdall-style single-header JSONL metrics output.
- Raw relay upstream receive through `mcrx-core` with its `raw-packets`
  feature.
- Optional Linux shared upstream capture through `mcrx-core/raw-shared-capture`.
- Raw gateway downstream transmit through `mctx-core` with its `raw-packets`
  feature.
- Optional RFC 7450 SSM Path MTU feedback through `mctx-core/raw-ip`.
- Transparent gateway mode that listens for local IGMPv3/MLDv2 receiver reports
  and turns them into AMT Membership Updates.

[rfc7450]: https://datatracker.ietf.org/doc/html/rfc7450
[rfc8777]: https://datatracker.ietf.org/doc/html/rfc8777
[rfc6040]: https://datatracker.ietf.org/doc/html/rfc6040
[rfc9601]: https://datatracker.ietf.org/doc/html/rfc9601

## Status

This is an early production-oriented implementation. Relay membership changes
are authenticated and peer-bound, and the public control plane is rate-limited
and resource-bounded. Deployments should still use firewall source restrictions
and operational monitoring.

Implemented:

- AMT Relay Discovery and Relay Advertisement.
- AMT Request and Membership Query.
- AMT Membership Update with IGMPv3/MLDv2 report parsing.
- AMT Multicast Data encoding/decoding.
- AMT Teardown.
- Relay upstream subscription reconciliation for ASM/SSM interests.
- Gateway joins for a configured group and optional source.
- Gateway DRIAD relay discovery with an independent tunnel per SSM source.
- Asynchronous DRIAD DNS TTL refresh, multi-relay probing, L-flag handling,
  traffic-health failover, and authoritative NoRelay withdrawal.
- RFC 9601 ECN capability signaling and RFC 6040 encapsulation/decapsulation.
- Gateway local membership learning for transparent IGMPv3/MLDv2 operation.
- Relay idle gateway pruning and gateway membership refreshes.
- Gateway signal handling that sends AMT Teardown on graceful shutdown.
- Config-file loading with CLI overrides.
- Role-level daemon metrics counters and gauges written as Heimdall JSONL.
- Localhost socket-level relay/gateway roundtrip test.
- Gateway peer/session validation and reception-state filtering for tunneled data.
- Configurable relay state limits, control-plane rate limits, and rotating
  authentication secrets.
- Transactional upstream joins: a failed native join rejects the update without
  terminating the relay or replacing working state.
- Fixed-PMTU tunnel filtering with inner IPv4 fragmentation and MTU drop
  metrics.
- Rate-limited ICMPv4 Fragmentation Needed and ICMPv6 Packet Too Big feedback
  toward oversized SSM sources.
- Linux shared raw capture with indexed `(S,G)` demultiplexing for large relay
  subscription sets.

Current limitations:

- The simple role runners use blocking loops and polling. They are intentionally
  small and easy to inspect, not yet optimized.
- Relay raw upstream receive may require root, `CAP_NET_RAW`, or explicit
  interface selection depending on platform.
- The relay retains a conservative default of 256 unique upstream
  subscriptions. Linux builds with `shared-upstream` can raise that limit while
  using approximately one capture socket per family/interface instead of one
  socket per subscription. Other platforms retain the existing raw backend.
- Gateway raw downstream transmit may require root, `CAP_NET_RAW`, or explicit
  interface selection depending on platform. `mctx-core` raw IPv6 transmit is
  not supported on Windows yet.
- Transparent mode currently listens for IGMPv3 reports to `224.0.0.22` or
  MLDv2 reports to `ff02::16`. It is not yet a full multicast router/TUN mode,
  and legacy IGMPv1/v2 reports sent directly to a multicast group are not the
  primary path.
- Transparent mode filters LAN-local multicast groups from AMT Membership
  Updates, including IPv4 `224.0.0.0/24`, SSDP/SLP discovery groups, and IPv6
  link-local multicast (`ff02::/16`).
- Transparent mode expires silent local reporters after 260 seconds by default.
  This is deliberately simpler than a complete multicast-router listener state
  machine.
- DRIAD applies only to SSM. In transparent DRIAD mode, ASM and non-SSM reports
  are ignored with an operator warning; use a static relay session for those
  interests.
- `auto` implements static configuration, RFC 7450 anycast, and DRIAD ordering.
  DNS-SD `_amt._udp` discovery, which RFC 8777 recommends ahead of anycast, is
  not implemented yet.
- DRIAD can probe IPv4 and IPv6 outer relays for either inner multicast family.
  An explicit `--bind` restricts candidates to that outer family and must use
  port zero because each source owns an independent socket.
- The gateway always performs Relay Discovery. An AMTRELAY `D=1` record permits
  a direct Request as an optimization, but does not require one; `D=0` is fully
  honored by the current flow.
- DRIAD requires a loopback validating resolver by default. Plain DNS to a
  remote resolver requires an explicit insecure override.
- PMTU feedback is opt-in, requires `pmtu-feedback`, an explicit local
  `--upstream-interface`, and raw-socket privileges. One relay instance emits
  feedback for the inner IP family matching that interface address; use
  separate instances or addresses for independent IPv4 and IPv6 sources.
- ECN is opt-in with `--ecn` or `ecn = true`; compatibility mode remains the
  default. Enabling ECN requires operating-system support for per-datagram ECN
  metadata and may fail at startup when that support is unavailable.
- AMT metrics use Heimdall's JSONL container format with `amt-relay` and
  `amt-gateway` artifact types. The current local Heimdall tree needs matching
  ingestors before those new artifact types are queryable there.

## Build

```bash
cargo build
cargo check --no-default-features
cargo build --features driad
cargo build --features metrics
cargo build --features driad,metrics,shared-upstream,pmtu-feedback
cargo test
cargo test -p quicast-amtq
cargo test -p quicast-amtq --features runtime-tokio-quiche
cargo run -- --help
cargo install quicast-amt
```

The default `runtime` feature builds the daemon and raw mcrx/mctx integration.
`--no-default-features` builds only the portable protocol, query, membership,
gateway, relay, and state-machine core.

The supported daemon targets are Linux, macOS, and Windows. iOS is deliberately
rejected at compile time, including core-only builds, because this project does
not provide or claim an iOS-supported AMT product surface. Other targets are
unsupported unless documented explicitly.

The registry manifest targets these sibling-crate releases:

- `mcrx-core = 0.3.0` with `raw-packets` and optional `raw-shared-capture`
- `mctx-core = 0.3.0` with `raw-packets` and optional `raw-ip`

The `0.3.0` sibling versions must be published before a registry-only build or
package verification can succeed. Local development can use Cargo's
`[patch.crates-io]` mechanism without introducing path dependencies into this
manifest.

The completed sibling-crate implementation requests are retained in
[`docs/sibling-crate-prompts.md`](docs/sibling-crate-prompts.md) for design
history and acceptance criteria.

## CLI

```text
amt relay [--config FILE] [--bind ADDRESS:PORT] [--relay-address IP] [--upstream-interface IP] [--upstream-ifindex INDEX] [--gateway-idle-timeout SECONDS] [--gateway-prune-interval SECONDS] [--path-mtu BYTES] [--pmtu-feedback|--no-pmtu-feedback] [--ecn|--no-ecn] [--metrics-dir DIR] [--node-id ID] [--metrics-interval-ms MS]
amt gateway [--config FILE] [--relay ADDRESS:PORT] [--relay-discovery static|driad|auto] [--group GROUP] [--source SOURCE] [--transparent] [--bind ADDRESS:PORT] [--protocol igmpv3|mldv2] [DRIAD OPTIONS] [--ecn|--no-ecn] [--downstream-interface IP] [--downstream-ifindex INDEX] [--downstream-ttl TTL] [--local-membership-interface IP] [--local-membership-ifindex INDEX] [--local-query-interval SECONDS] [--local-reporter-timeout SECONDS] [--membership-refresh-interval SECONDS] [--no-downstream-loopback] [--no-downstream] [--metrics-dir DIR] [--node-id ID] [--metrics-interval-ms MS]
```

Run `amt gateway --help` for the complete DRIAD timer, DNS-rate, candidate,
source-tunnel, probe, and resolver-worker controls.

### Relay

Run a relay on the standard AMT UDP port:

```bash
cargo run --release --features metrics -- relay \
  --bind 0.0.0.0:2268 \
  --relay-address 203.0.113.10 \
  --upstream-interface 192.0.2.10 \
  --metrics-dir ./heimdall-import \
  --node-id linode-amt-relay
```

`--relay-address` is the IP address advertised to gateways. It is important
when binding to `0.0.0.0`; otherwise the default advertised address is loopback.
An IPv6-only `--relay-address` infers `[::]:2268`; AMT uses UDP port `2268` for
both address families. Use explicit binds or separate service instances when
the operating system's dual-stack socket behavior is unsuitable.

`--upstream-interface` selects the native multicast receive interface for
`mcrx-core` raw receive.

The relay daemon prunes idle gateways after 260 seconds by default and checks
for expired gateways every 5 seconds. Use `--gateway-idle-timeout 0` to disable
pruning, or tune `--gateway-idle-timeout` and `--gateway-prune-interval` for
test setups. A non-zero idle timeout must be greater than the advertised query
interval, which is 125 seconds by default.

The fixed relay path MTU defaults to 1500 bytes and can be changed with
`--path-mtu` or `relay.path_mtu`; use 1280 when a conservative Internet-path
assumption is preferable. Oversized IPv4 packets with DF clear are fragmented
inside AMT; DF-set IPv4, IPv4 packets with header options, and IPv6 packets are
dropped rather than relying on outer tunnel fragmentation. AMT UDP sockets also
enforce non-fragmenting outer transmission; startup fails on a platform that
cannot provide that guarantee, and an oversized send is reported by the OS
instead of being fragmented in transit.

Build with `--features pmtu-feedback` and pass `--pmtu-feedback` to send the
RFC 7450-required ICMPv4 Fragmentation Needed or ICMPv6 Packet Too Big response
toward an SSM source when DF-set IPv4 or IPv6 traffic exceeds a tunnel MTU. The
relay sends one rate-limited response containing the smallest affected TMTU.
The explicit `--upstream-interface` address supplies the ICMP source and must
match the inner traffic family.

On Linux, `--features shared-upstream` replaces per-subscription receive
sockets with shared family/interface capture sockets and indexed userspace
demultiplexing. The CLI is unchanged; raise
`relay.limits.max_upstream_subscriptions` only after enabling that feature.

Pass `--ecn` (or set `relay.ecn = true`) to let the relay use RFC 6040 normal
mode for gateways that declare ECN support in their AMT Request. Gateways that
do not set the RFC 9601 `E` bit always receive safe Not-ECT outer headers.

### Gateway

Run a gateway that joins an ASM group through a remote relay and forwards
received multicast IP datagrams locally:

```bash
cargo run --release --features metrics -- gateway \
  --relay 203.0.113.10:2268 \
  --group 239.1.2.3 \
  --downstream-interface 192.168.1.20
```

Run a gateway that requests SSM from the AMT relay:

```bash
cargo run --release -- gateway \
  --relay 203.0.113.10:2268 \
  --group 232.1.2.3 \
  --source 192.0.2.10 \
  --downstream-interface 192.168.1.20
```

The `--bind` and `--relay` addresses select the outer AMT tunnel family, while
`--downstream-interface` selects the inner multicast family. The downstream
interface must be IPv4 for IGMPv3 and IPv6 for MLDv2; IPv6 multicast over an
IPv4 AMT tunnel, and the reverse, are both supported.

The gateway uses raw downstream transmit, so local SSM receivers can join the
original `(S,G)` carried inside AMT Multicast Data. Raw transmit may require
elevated privileges.

Run a gateway that discovers the AMT relay for an SSM source through DRIAD
([RFC 8777][rfc8777]):

```bash
cargo run --release --features driad -- gateway \
  --relay-discovery driad \
  --group 232.1.2.3 \
  --source 192.0.2.10 \
  --downstream-interface 192.168.1.20
```

Transparent DRIAD learns independent SSM sources from the LAN:

```bash
cargo run --release --features driad -- gateway \
  --relay-discovery auto \
  --transparent \
  --protocol igmpv3 \
  --downstream-interface 192.168.1.20
```

`--relay-discovery static` is the default and requires `--relay`.
`--relay-discovery driad` is an administrative override that uses source-owned
AMTRELAY records directly. `auto` uses a configured relay when present;
otherwise, each source probes the RFC 7450 anycast addresses before its DRIAD
candidates. DNS-SD is not implemented yet.
Use `--driad-resolver IP[:PORT]` to override `/etc/resolv.conf`. The resolver
must be loopback unless `--driad-allow-insecure-dns` is supplied. That override
permits spoofable plaintext DNS and should be used only on a trusted network.

Configured joins and transparent IGMPv3/MLDv2 INCLUDE records are partitioned
by source. Each source gets an independent UDP tunnel, DNS lifecycle, relay
candidate set, hold-down table, and rediscovery state. Multiple groups for one
source share that source's tunnel. Only the chosen non-L connection receives a
Membership Update.

The daemon refreshes DRIAD asynchronously using the minimum TTL across the
AMTRELAY, CNAME/DNAME, and A/AAAA records involved in a selection. Refreshes are
bounded to 1 second through 24 hours. Resolver failures retain the last usable
candidate set and retry with randomized exponential backoff. A healthy active
tunnel is retained when DNS changes; the refreshed set is used on the next
rediscovery so routine DNS maintenance does not interrupt multicast traffic.
An explicit AMTRELAY `NoRelay` record withdraws that source: the gateway sends
Teardown when possible and suppresses both anycast and DNS candidates until a
later valid AMTRELAY result appears.

Equal-precedence candidates are randomized and address families are
interleaved. Probes are staggered by 250 ms, with four concurrent probes per
source by default. A valid Membership Query without L wins. L responses are
held down for 10 minutes. If subscribed traffic does not arrive, the timeout
backs off randomly from 4 to 120 seconds and the relay is held down for 5
minutes. Defaults also cap the gateway at 256 source tunnels and eight blocking
DNS workers, while DNS queries are limited to 10 per 100 ms.

Pass `--ecn` (or set `gateway.ecn = true`) to advertise RFC 9601 capability and
apply RFC 6040 decapsulation. In particular, outer CE is propagated into an
ECN-capable inner packet, while an invalid outer-CE/inner-Not-ECT combination is
dropped. Compatibility mode is the default and keeps the Request `E` bit and
outer ECN field clear.

The gateway daemon refreshes its current Membership Update state every 60
seconds by default, which keeps relay-side idle pruning from removing healthy
gateways and detects relay restarts. A configured value of `0` disables the
custom interval but retains the 60-second safety/liveness probe.

On Ctrl-C/SIGTERM, the gateway daemon attempts to send AMT Teardown before
exiting. If the process is killed abruptly, relay-side idle pruning is the
fallback cleanup path.

Run a transparent IPv4 gateway that learns local receiver interest from IGMPv3
reports instead of using a fixed `--group`:

```bash
cargo run --release --features metrics -- gateway \
  --relay 203.0.113.10:2268 \
  --transparent \
  --protocol igmpv3 \
  --downstream-interface 192.168.1.20 \
  --metrics-dir ./heimdall-import \
  --node-id local-amt-gateway
```

The transparent gateway sends periodic local General Queries by default and
listens for receiver reports on the same interface. Use
`--local-query-interval 0` to disable those local queries, or
`--local-membership-interface` if the report listener must use a different
interface address than downstream raw transmit. Silent reporters expire after
260 seconds; tune this with `--local-reporter-timeout`. The timeout must be at
least twice the query interval plus 10 seconds. Disabling local queries also
disables reporter aging, because the gateway can no longer verify continued
receiver presence.

## Configuration

Both daemon roles accept `--config FILE`. Values from the config file are loaded
first; CLI flags override them.

Minimal relay config:

```toml
[relay]
bind = "0.0.0.0:2268"
ecn = true
relay_address = "203.0.113.10"
upstream_interface = "192.0.2.10"
gateway_idle_timeout_secs = 260
path_mtu = 1500

[relay.limits]
max_endpoints = 4096
max_endpoints_per_ip = 256
max_groups_per_endpoint = 128
max_sources_per_group = 128
max_upstream_subscriptions = 256

[relay.rate_limit]
per_source_per_second = 10
per_source_burst = 20

[metrics]
output_dir = "./heimdall-import"
node_id = "linode-amt-relay"
interval_ms = 1000
max_file_bytes = 67108864
```

Minimal transparent gateway config:

```toml
[gateway]
relay = "203.0.113.10:2268"
ecn = true
protocol = "igmpv3"
transparent = true
membership_refresh_interval_secs = 60

[gateway.downstream]
interface = "192.168.1.20"
ttl = 16

[gateway.local_membership]
query_interval_secs = 30
reporter_timeout_secs = 260

[metrics]
output_dir = "./heimdall-import"
node_id = "local-amt-gateway"
interval_ms = 1000
max_file_bytes = 67108864
```

Configured joins can also be expressed in TOML:

```toml
[[gateway.joins]]
group = "239.1.2.3"

[[gateway.joins]]
group = "232.1.2.3"
source = "192.0.2.10"
```

DRIAD gateway config:

```toml
[gateway]
relay_discovery = "driad"
protocol = "igmpv3"
ecn = true
membership_refresh_interval_secs = 60

[gateway.driad]
resolver = "127.0.0.53:53"
timeout_ms = 1000
attempts = 2
max_candidates = 64
max_queries_per_window = 10
query_rate_window_ms = 100
happy_eyeballs_delay_ms = 250
relay_hold_down_secs = 600
traffic_hold_down_secs = 300
initial_traffic_timeout_secs = 4
maximum_traffic_timeout_secs = 120
max_source_tunnels = 256
max_concurrent_probes = 4
max_dns_workers = 8

[[gateway.joins]]
group = "232.1.2.3"
source = "192.0.2.10"
```

## Metrics

Metrics are compiled only with the `metrics` Cargo feature. When that feature
is enabled and `--metrics-dir` or `[metrics].output_dir` is set, the daemon
writes single-header JSONL files:

```text
<metrics-dir>/<node-id>/amt-relay.jsonl
<metrics-dir>/<node-id>/amt-gateway.jsonl
```

Without `--features metrics`, the same config and CLI fields are accepted but
the daemon logs that metrics were requested by a binary built without metrics
support.

Each sample row includes `ts`, `interval_secs`, role gauges, and counters in
`*_total`, `*_delta`, and `*_per_sec` form. The relay reports gateway counts,
upstream subscription counts, upstream receive/forward totals, AMT control
traffic, authentication rejections, teardowns, and pruning. The gateway reports
relay connectivity, configured joins, discovery/update traffic, AMT Multicast
Data receive, downstream forwarding, local query, and transparent membership
activity. DRIAD gateways additionally report source/active tunnel, live probe,
and held-down relay gauges plus DNS, selection, L, no-traffic, and timeout
counters.

Metric files rotate to a single `.jsonl.1` backup at 64 MiB by default. Set
`metrics.max_file_bytes = 0` to disable rotation.

## Tests

Run all tests:

```bash
cargo test
```

The socket-level tests bind localhost UDP sockets and verify:

- gateway discovery to relay
- relay advertisement
- gateway request
- relay membership query
- gateway membership update
- relay state update
- AMT multicast data delivery
- teardown
- DRIAD fallback around an unresponsive candidate
- L-flag hold-down and selection of another relay
- Membership Update only after a valid non-L Membership Query
- no-traffic hold-down, NoRelay withdrawal, and an idle non-spinning tunnel

Some sandboxed environments block UDP socket binds. In those environments the
test must be run with appropriate socket permissions.

There is also an ignored Linux system test harness that creates relay, gateway,
source, and receiver network namespaces, then runs real AMT ASM, SSM, teardown,
pruning, and optional metrics checks end-to-end. It requires Linux, `iproute2`,
and root privileges or equivalent `CAP_NET_ADMIN`/`CAP_NET_RAW` capability:

```bash
sudo -E cargo test --features metrics,shared-upstream --test system_linux -- --ignored --test-threads=1 --nocapture
```

For the portable per-subscription upstream backend, omit `shared-upstream`.
For a no-metrics build, omit `metrics`. The tests are ignored by
default and skip themselves on non-Linux hosts or without sufficient privileges.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration and Heimdall metrics](docs/configuration.md)
- [Linode to local network test](docs/linode-local-test.md)
- [Raw `mctx-core` transmit integration](docs/mctx-raw-packets.md)

## Library Layout

- `protocol`: AMT wire codec.
- `query`: IGMPv3 and MLDv2 General Query packet builders.
- `membership`: IGMP/MLD membership report parser and builder.
- `state`: relay-side gateway membership and upstream subscription state.
- `relay`: runtime-agnostic relay state machine.
- `upstream`: relay upstream raw multicast receive manager using `mcrx-core`.
- `gateway`: runtime-agnostic gateway state machine.
- `local_membership`: local IGMPv3/MLDv2 report listener and membership delta
  tracker for transparent gateway mode.
- `downstream`: gateway downstream raw multicast transmitter using `mctx-core`.
- `daemon`: simple blocking relay and gateway runners.

## License

BSD-2-Clause.
