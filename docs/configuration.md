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

[metrics]
output_dir = "/var/lib/heimdall/import"
node_id = "linode-amt-relay"
interval_ms = 1000
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

[metrics]
output_dir = "/var/lib/heimdall/import"
node_id = "local-amt-gateway"
interval_ms = 1000
```

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
resolver = "192.0.2.53:53"
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

- AMT control datagrams, invalid datagrams, ignored datagrams, responses, and send errors.
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
