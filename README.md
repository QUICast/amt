# amt

Lightweight Rust building blocks for [Automatic Multicast Tunneling][rfc7450]
(AMT, RFC 7450). The crates.io package is `quicast-amt`; the library crate and
installed CLI binary are both named `amt`.

The crate currently includes:

- RFC 7450 message encoding and decoding.
- Relay-side discovery, request, membership update, teardown, and multicast
  forwarding state.
- Gateway-side discovery, request, membership update, multicast data, and
  teardown state.
- IGMPv3 and MLDv2 query/report packet helpers.
- Simple blocking relay and gateway runners.
- TOML configuration for the relay and gateway daemons.
- Optional DRIAD DNS relay discovery for configured SSM sources.
- Optional [RFC 9601][rfc9601]/[RFC 6040][rfc6040] ECN propagation across the
  AMT tunnel.
- Heimdall-style single-header JSONL metrics output.
- Raw relay upstream receive through `mcrx-core` with its `raw-packets`
  feature.
- Raw gateway downstream transmit through `mctx-core` with its `raw-packets`
  feature.
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
- Gateway DRIAD relay discovery for a configured SSM source.
- DRIAD DNS TTL refresh with asynchronous live candidate-set replacement.
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

Current limitations:

- The simple role runners use blocking loops and polling. They are intentionally
  small and easy to inspect, not yet optimized.
- Relay raw upstream receive may require root, `CAP_NET_RAW`, or explicit
  interface selection depending on platform.
- `mcrx-core 0.2.5` currently owns one raw capture socket per upstream
  subscription and polls those sockets linearly. The relay therefore defaults
  to at most 256 unique upstream subscriptions. Raising that limit is possible,
  but efficient large-scale relays need shared capture and packet demultiplexing
  support in `mcrx-core`.
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
- DRIAD is currently limited to explicitly configured SSM joins with one source
  address per gateway session. Transparent-mode DRIAD and multi-source
  multi-relay sessions are planned follow-ups.
- One gateway session uses one outer address family. DRIAD failover candidates
  from the other family are ignored; run a separate gateway instance for
  independent IPv4 and IPv6 outer tunnels. Cross-family Happy Eyeballs is a
  recommended future optimization, not a requirement for DRIAD operation.
- The gateway always performs Relay Discovery. An AMTRELAY `D=1` record permits
  a direct Request as an optimization, but does not require one; `D=0` is fully
  honored by the current flow.
- DRIAD requires a loopback validating resolver by default. Plain DNS to a
  remote resolver requires an explicit insecure override.
- The relay does not yet generate ICMPv4 Fragmentation Needed or ICMPv6 Packet
  Too Big feedback toward oversized SSM sources; that needs a portable raw
  unicast transmit path in addition to the multicast-only mctx API.
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
cargo build --features driad,metrics
cargo test
cargo run -- --help
cargo install quicast-amt
```

The default `runtime` feature builds the daemon and raw mcrx/mctx integration.
`--no-default-features` builds only the portable protocol, query, membership,
gateway, relay, and state-machine core.

The crate depends on crates.io releases:

- `mcrx-core = 0.2.5` with `raw-packets`
- `mctx-core = 0.2.3` with `raw-packets`

Copy/paste-ready requests for the next sibling-crate capabilities live in
[`docs/sibling-crate-prompts.md`](docs/sibling-crate-prompts.md).

## CLI

```text
amt relay [--config FILE] [--bind ADDRESS:PORT] [--relay-address IP] [--upstream-interface IP] [--upstream-ifindex INDEX] [--gateway-idle-timeout SECONDS] [--gateway-prune-interval SECONDS] [--path-mtu BYTES] [--ecn|--no-ecn] [--metrics-dir DIR] [--node-id ID] [--metrics-interval-ms MS]
amt gateway [--config FILE] [--relay ADDRESS:PORT] [--relay-discovery static|driad|auto] [--group GROUP] [--source SOURCE] [--transparent] [--bind ADDRESS:PORT] [--protocol igmpv3|mldv2] [--driad-resolver IP[:PORT]] [--driad-timeout-ms MS] [--driad-attempts COUNT] [--driad-allow-insecure-dns] [--ecn|--no-ecn] [--downstream-interface IP] [--downstream-ifindex INDEX] [--downstream-ttl TTL] [--local-membership-interface IP] [--local-membership-ifindex INDEX] [--local-query-interval SECONDS] [--local-reporter-timeout SECONDS] [--membership-refresh-interval SECONDS] [--no-downstream-loopback] [--no-downstream] [--metrics-dir DIR] [--node-id ID] [--metrics-interval-ms MS]
```

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
test setups.

The fixed relay path MTU defaults to 1500 bytes and can be changed with
`--path-mtu` or `relay.path_mtu`; use 1280 when a conservative Internet-path
assumption is preferable. Oversized IPv4 packets with DF clear are fragmented
inside AMT; DF-set IPv4, IPv4 packets with header options, and IPv6 packets are
dropped rather than relying on outer tunnel fragmentation. The drop counters
make these cases observable, but generating ICMP Packet Too Big feedback still
requires a portable raw-unicast transmit API from `mctx-core`.

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

`--relay-discovery static` is the default and requires `--relay`.
`--relay-discovery auto` uses `--relay` when present, otherwise it tries DRIAD.
Use `--driad-resolver IP[:PORT]` to override `/etc/resolv.conf`. The resolver
must be loopback unless `--driad-allow-insecure-dns` is supplied. That override
permits spoofable plaintext DNS and should be used only on a trusted network.

The first DRIAD implementation intentionally supports one configured SSM source
per gateway session. It does not yet choose separate relays for different
sources learned in transparent mode.

The daemon refreshes DRIAD asynchronously using the minimum TTL across the
AMTRELAY, CNAME/DNAME, and A/AAAA records involved in a selection. Refreshes are
bounded to 1 second through 24 hours. Resolver failures retain the last usable
candidate set and retry with randomized exponential backoff. A healthy active
tunnel is retained when DNS changes; the refreshed set is used on the next
rediscovery so routine DNS maintenance does not interrupt multicast traffic.
An explicit AMTRELAY `NoRelay` record is treated as a withdrawal: the gateway
sends Teardown when possible and stops instead of continuing with stale state.

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
activity.

Metric files rotate to a single `.jsonl.1` backup at 64 MiB by default. Set
`metrics.max_file_bytes = 0` to disable rotation.

## Tests

Run all tests:

```bash
cargo test
```

The integration test in `tests/amt_roundtrip.rs` binds localhost UDP sockets and
verifies:

- gateway discovery to relay
- relay advertisement
- gateway request
- relay membership query
- gateway membership update
- relay state update
- AMT multicast data delivery
- teardown

Some sandboxed environments block UDP socket binds. In those environments the
test must be run with appropriate socket permissions.

There is also an ignored Linux system test harness that creates relay, gateway,
source, and receiver network namespaces, then runs real AMT ASM, SSM, teardown,
pruning, and optional metrics checks end-to-end. It requires Linux, `iproute2`,
and root privileges or equivalent `CAP_NET_ADMIN`/`CAP_NET_RAW` capability:

```bash
sudo -E cargo test --features metrics --test system_linux -- --ignored --test-threads=1 --nocapture
```

For a no-metrics build, omit `--features metrics`. The tests are ignored by
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
