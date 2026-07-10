# Configuration And Heimdall Metrics

The `amt` binary supports TOML config files for both daemon roles. Config values
are loaded first, then CLI flags override them. This makes config files useful
for repeatable daemon deployments while still keeping one-off test overrides
easy.

## Relay Config

```toml
[relay]
bind = "0.0.0.0:2268"
relay_address = "203.0.113.10"
upstream_interface = "192.0.2.10"
gateway_idle_timeout_secs = 260
gateway_prune_interval_secs = 5
secret_rotation_secs = 7200
path_mtu = 1500

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
The conservative 256-subscription default reflects `mcrx-core 0.2.5` using one
raw socket per subscription; increase it only after accounting for file
descriptor and linear polling costs.

`path_mtu` is the fixed downstream AMT path MTU and defaults to 1500 bytes.
Set it to 1280 for a conservative Internet-path assumption. The relay subtracts
the outer IP, UDP, and AMT headers to derive the tunnel MTU. It fragments
oversized IPv4 payloads when DF is clear and drops oversized IPv4 DF, IPv4
packets with header options, or IPv6 payloads rather than creating outer
fragments. ICMP Packet Too Big feedback requires raw unicast transmit support
that `mctx-core` does not currently expose.

The downstream interface belongs to the inner multicast family, not the AMT
tunnel family. An IGMPv3 gateway therefore requires an IPv4 downstream
interface and an MLDv2 gateway requires an IPv6 downstream interface, even when
the relay connection uses the other IP family.

## Gateway Config

Transparent gateway:

```toml
[gateway]
bind = "0.0.0.0:0"
relay = "203.0.113.10:2268"
protocol = "igmpv3"
transparent = true
membership_refresh_interval_secs = 60

[gateway.downstream]
interface = "192.168.1.20"
ttl = 16
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
membership_refresh_interval_secs = 60

[gateway.driad]
resolver = "127.0.0.53:53"
timeout_ms = 1000
attempts = 2

[[gateway.joins]]
group = "232.1.2.3"
source = "192.0.2.10"
```

Build the binary with `--features driad` to enable DRIAD. In `static` mode,
`relay` is required. In `auto` mode, a configured `relay` wins; without one,
the gateway performs DRIAD for the configured SSM source. The current DRIAD
path intentionally supports one source address per gateway session and does not
yet perform transparent-mode per-source relay selection.

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

Sample rows use the same shape as the existing Heimdall producers: `ts`,
`interval_secs`, gauges, and cumulative counters with matching deltas and rates.

Relay gauges:

- `active_gateways`
- `active_upstream_subscriptions`

Gateway gauges:

- `relay_connected`
- `downstream_enabled`
- `transparent_enabled`
- `configured_joins`

Counter families include:

- AMT control datagrams, invalid/ignored/rate-limited datagrams, responses, and send errors.
- Relay resource-limit rejections, upstream reconciliation failures, tunnel
  MTU drops, and generated IPv4 fragments.
- Relay membership updates, applied records, teardowns, authentication rejections, and gateway expiry.
- Relay upstream subscription changes, native multicast receive, unmatched packets, forwarded packets, and forward errors.
- Gateway discovery, membership queries, membership updates, refreshes, and teardown.
- Gateway AMT Multicast Data receive, downstream forwarding, non-multicast packets, and forwarding errors.
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
