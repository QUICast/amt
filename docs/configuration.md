# Configuration And Heimdall Metrics

The `amt` binary supports TOML config files for both daemon roles. Config values
are loaded first, then CLI flags override them. This makes config files useful
for repeatable daemon deployments while still keeping one-off test overrides
easy.

## Relay Config

```toml
[relay]
bind = "0.0.0.0:2268"
ecn = true
relay_address = "203.0.113.10"
upstream_interface = "192.0.2.10"
gateway_idle_timeout_secs = 260
gateway_prune_interval_secs = 5
secret_rotation_secs = 7200
path_mtu = 1500
pmtu_feedback = true

[relay.limits]
max_endpoints = 4096
max_endpoints_per_ip = 256
max_groups_per_endpoint = 128
max_sources_per_group = 128
max_total_endpoint_groups = 16384
max_total_sources = 65536
max_upstream_subscriptions = 256
max_records_per_report = 512

[relay.rate_limit]
per_source_per_second = 10
per_source_burst = 20
global_per_second = 1000
global_burst = 2000

[metrics]
output_dir = "/var/lib/heimdall/import"
node_id = "linode-amt-relay"
interval_ms = 1000
max_file_bytes = 67108864
```

Run it with:

```bash
amt relay --config relay.toml
```

Multiple advertised addresses can be written as:

```toml
[relay]
relay_addresses = ["203.0.113.10", "2001:db8::10"]
```

Relay limits reject an authenticated update before changing live state. The
`L` flag is also set in Membership Queries once endpoint or upstream capacity
reaches 90 percent. Limit and rate values must be non-zero. A
`secret_rotation_secs` value of `0` disables automatic secret rotation; the
default retains the current and immediately previous secret during rotation.
If a shorter rotation interval is configured, the relay delays the next
rotation until the previous secret's two-query-interval grace period expires.
`gateway_idle_timeout_secs` must be `0` to disable endpoint aging or greater
than the relay's advertised query interval, which is 125 seconds by default.
The conservative 256-subscription default remains suitable for the portable
per-subscription backend. A Linux build with `--features shared-upstream` uses
`mcrx-core 0.3.0` shared capture sockets and can safely configure a larger
limit after accounting for kernel multicast-membership limits and userspace
queue bounds.

`path_mtu` is the fixed downstream AMT path MTU and defaults to 1500 bytes.
Set it to 1280 for a conservative Internet-path assumption. The relay subtracts
the outer IP, UDP, and AMT headers to derive the tunnel MTU. It fragments
oversized IPv4 payloads when DF is clear and drops oversized IPv4 DF, IPv4
packets with header options, or IPv6 payloads rather than creating outer
fragments. The AMT UDP socket enforces IPv4 DF and IPv6 no-fragment semantics
for both ECN and compatibility modes; daemon startup fails if the target cannot
provide them.

`pmtu_feedback = true` enables RFC 7450 feedback for oversized SSM packets and
requires a binary built with `--features pmtu-feedback`. The relay sends a
rate-limited ICMPv4 Fragmentation Needed response for DF-set IPv4 or ICMPv6
Packet Too Big for IPv6, advertising the smallest affected tunnel MTU. An
explicit `upstream_interface` address is mandatory because it supplies the
local ICMP source and raw-IP egress selector. The address family must match the
inner SSM source family; Windows raw IPv6 feedback is unsupported by
`mctx-core 0.3.1`.

`ecn = true` enables RFC 9601 support. The relay records the Request `E` bit
per gateway and copies inner ECN into the outer AMT IP header only for capable
gateways. It uses safe Not-ECT compatibility mode for every other gateway.
The equivalent CLI switches are `--ecn` and `--no-ecn`; compatibility mode is
the default.

An explicitly configured downstream interface belongs to the inner multicast
family, not the AMT tunnel family. An IGMPv3 gateway therefore accepts an IPv4
selector and an MLDv2 gateway accepts an IPv6 selector, even when the relay
connection uses the other IP family.

Without `gateway.downstream.interface` or `interface_index`, AMT requests
route-selected egress from `mctx-core 0.3.1`. Linux supports route-selected
IPv4 and IPv6; macOS supports route-selected IPv4 but requires an explicit
interface for IPv6; Windows requires an explicit IPv4 interface and does not
support full-header IPv6. Route changes are followed by mctx on supported
route-selected paths. Explicit selectors remain pinned.

Raw downstream forwarding preserves the complete inner datagram, including the
IPv4 TTL or IPv6 Hop Limit. The removed `--downstream-ttl` option and legacy
`gateway.downstream.ttl` key are rejected before the daemon starts. Set the
desired value at the multicast source.

Omitting `loopback` leaves the platform preference unspecified.
`loopback = true` is rejected for MLDv2 because full-header IPv6 uses
link-layer injection and cannot deliver into the sending host's IP receive
path. Use another interface or host for IPv6 receivers.

Transparent mode sends local General Queries unless
`gateway.local_membership.query_interval_secs = 0`. Active queries require an
address-valued local membership interface, supplied directly or inherited from
`gateway.downstream.interface`, so their IP source is valid. MLDv2 queries
target link-local `ff02::1` and also require an explicit downstream interface
or index; they cannot use route-selected egress. Passive report capture with a
zero query interval does not impose these transmit requirements.

## Gateway Config

Transparent gateway:

```toml
[gateway]
bind = "0.0.0.0:0"
relay = "203.0.113.10:2268"
ecn = true
protocol = "igmpv3"
transparent = true
membership_refresh_interval_secs = 60

[gateway.downstream]
interface = "192.168.1.20"
loopback = true

[gateway.local_membership]
query_interval_secs = 30
reporter_timeout_secs = 260

[metrics]
output_dir = "/var/lib/heimdall/import"
node_id = "local-amt-gateway"
interval_ms = 1000
```

`reporter_timeout_secs` must be at least twice `query_interval_secs` plus 10
seconds. Setting the query interval to zero disables both General Queries and
reporter aging.

`ecn = true` makes the gateway set the RFC 9601 Request `E` bit and apply RFC
6040 decapsulation to tunneled multicast. Outer CE is propagated into an
ECN-capable inner packet; outer CE with an inner Not-ECT packet is dropped.
The daemon fails startup when ECN receive metadata cannot be enabled on a
supported platform, rather than advertising a capability it cannot honor.
With ECN disabled, the daemon retains its plain `UdpSocket` compatibility path.

Configured ASM/SSM joins:

```toml
[gateway]
relay = "203.0.113.10:2268"
protocol = "igmpv3"

[[gateway.joins]]
group = "239.1.2.3"

[[gateway.joins]]
group = "232.1.2.3"
source = "192.0.2.10"
```

Run it with:

```bash
amt gateway --config gateway.toml
```

DRIAD SSM discovery:

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

Build the binary with `--features driad` to enable DRIAD. In `static` mode,
`relay` is required. `driad` uses the source's AMTRELAY records directly as an
administrative override. In `auto`, a configured `relay` wins; without one,
the gateway probes RFC 7450 anycast before DRIAD. DNS-SD `_amt._udp` discovery
is not implemented yet.

DRIAD supports multiple configured SSM sources and SSM INCLUDE records learned
in transparent mode. Each source owns an independent socket, DNS lifecycle,
candidate set, hold-down state, and AMT tunnel; groups sharing a source share
that tunnel. ASM and non-SSM transparent records are ignored with a warning.
An explicit DRIAD `bind` must use port zero and restricts only the outer tunnel
family, which is independent of the inner multicast family.

The effective minimum TTL across AMTRELAY, CNAME/DNAME, and A/AAAA answers
drives asynchronous refreshes, bounded to 1 second through 24 hours. Refresh
failure retains the current relay set and uses randomized exponential backoff.
Successful refreshes replace the failover candidates immediately, while a
healthy active tunnel stays in place until normal rediscovery to avoid packet
loss or duplication from an unnecessary RPF-tree change. An explicit AMTRELAY
`NoRelay` result sends Teardown and suppresses every relay candidate for that
source until a later valid DNS result appears.

Candidates are ordered by discovery tier and AMTRELAY precedence, ties are
randomized, and IPv4/IPv6 addresses are interleaved. Only a candidate that
returns a valid Membership Query with L clear receives a Membership Update.
The defaults stagger probes by 250 ms, hold an L response for 10 minutes, use a
random 4-to-120-second exponential traffic timeout, and hold a no-traffic relay
for 5 minutes. DNS queries are limited to 10 per 100 ms. Resource defaults are
64 candidates per source, 256 source tunnels, four probes per source, and eight
blocking DNS workers. Every value is configurable in `[gateway.driad]` or with
the corresponding `--driad-*` CLI option shown by `amt gateway --help`.

DRIAD accepts loopback resolvers by default so DNS trust can be supplied by a
local validating resolver. To use plaintext DNS to a remote resolver, set
`allow_insecure_dns = true` or pass `--driad-allow-insecure-dns`. This weakens
relay-selection security and should be limited to trusted networks.

CLI overrides are applied after the file:

```bash
amt gateway --config gateway.toml --downstream-interface "$LOCAL_LAN_IP"
```

## Metrics Output

Metrics are behind the `metrics` Cargo feature. Build or run with:

```bash
cargo build --release --features metrics
cargo run --release --features metrics -- gateway --config gateway.toml
```

Metrics are disabled unless `[metrics].output_dir` or `--metrics-dir` is set.
When the feature and output directory are both enabled, AMT writes
Heimdall-style single-header JSONL under:

```text
<output_dir>/<node_id>/amt-relay.jsonl
<output_dir>/<node_id>/amt-gateway.jsonl
```

If a config requests metrics but the binary was built without `--features
metrics`, the daemon starts normally and logs that metrics are unavailable in
that build.

Metrics files rotate at 64 MiB by default, retaining one `.jsonl.1` backup.
Set `max_file_bytes = 0` to disable rotation.

The header uses Heimdall's canonical JSONL schema:

```json
{"schema":"heimdall-jsonl-v1","artifact_type":"amt-relay","node_id":"linode-amt-relay","producer":"amt","created_at":0.0,"flags":{"role":"relay","node_id":"linode-amt-relay"}}
```

Relay headers also record the bounded packet-queue capacity and the actual AMT
tunnel receive/send buffer sizes granted by the operating system.

Sample rows use the same shape as the existing Heimdall producers: `ts`,
`interval_secs`, gauges, and cumulative counters with matching deltas and rates.

Relay gauges:

- `active_gateways`
- `active_upstream_subscriptions`
- `upstream_capture_sockets`
- `upstream_queue_depth`
- `upstream_queue_high_water`

Gateway gauges:

- `relay_connected`
- `downstream_enabled`
- `transparent_enabled`
- `configured_joins`
- `driad_source_tunnels`
- `driad_active_tunnels`
- `driad_candidate_probes`
- `driad_held_down_relays`

Counter families include:

- AMT control datagrams, invalid/ignored/rate-limited datagrams, responses, and send errors.
- Relay resource-limit rejections, upstream reconciliation failures, capture
  worker failures, bounded-queue drops, tunnel MTU drops, generated IPv4
  fragments, SSM PMTU feedback outcomes, and RFC 6040 normal-mode sends.
- Relay membership updates, applied records, teardowns, authentication rejections, and gateway expiry.
- Relay upstream subscription changes, native multicast receive, unmatched
  packets, successful per-Gateway forwards, and per-Gateway forward errors.
- Gateway discovery, membership queries, membership updates, refreshes, and teardown.
- Gateway AMT Multicast Data receive, downstream forwarding, non-multicast packets, and forwarding errors.
- DRIAD refreshes, NoRelay withdrawals, candidate changes, probe starts,
  probe timeouts/errors, established tunnels, L/no-traffic hold-downs, and
  active-query timeouts.
- Gateway ECN CE reception/propagation, currently-unused combinations, and
  invalid Not-ECT/CE drops.
- Transparent gateway local queries, local membership reports, and parse errors.

Each counter is emitted as:

```text
<name>_total
<name>_delta
<name>_per_sec
```

For example:

```json
{"ts":1760000000.0,"interval_secs":1.0,"active_gateways":1,"upstream_packets_received_total":10,"upstream_packets_received_delta":2,"upstream_packets_received_per_sec":2.0}
```

The local Heimdall tree currently recognizes the common JSONL container format
but does not yet include first-class `amt-relay` or `amt-gateway` ingestors. Add
those artifact parsers before expecting these files to appear in Heimdall
queries and reports.
