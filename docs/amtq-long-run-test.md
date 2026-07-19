# AMT versus AMTQ Long-Run Test

This test compares classic AMT and AMTQ concurrently. The source sends each
sequence twice, once to a classic-AMT multicast group and once to an AMTQ
multicast group. Alternating the send order avoids consistently favoring one
path. This first harness is IPv4-only; IPv6/MLDv2 needs a separate run.

The receiver records sequence numbers, source timestamps, arrival timestamps,
corruption, duplicates, and reordering. The report includes a paired latency
delta:

```text
(AMTQ receive - AMTQ send) - (AMT receive - AMT send)
```

A stable clock offset between the Linode and receiver cancels from this value.
Synchronize both machines with NTP or chrony if the absolute one-way latency
figures will also be used.

The defaults are:

| Path | Group | UDP port | Tunnel port |
|---|---|---:|---:|
| Classic AMT | `239.250.10.1` | `5501` | `2268` |
| AMTQ | `239.250.10.2` | `5502` | `2269` |

Use a receiver on another LAN machine when possible. That includes downstream
LAN delivery in the measurement and avoids same-host multicast behavior.

This is a stability and comparative-delivery test, not a relay capacity
benchmark. At the default 50 pairs per second and 1,200-byte payload, each
tunnel carries about 480 kbit/s of probe payload.

## Build

On the Linux relay:

```bash
git switch amtq
git pull --ff-only
cargo build --release -p quicast-amt --features shared-upstream
cargo build --release -p quicast-amtq --features daemon,shared-upstream
python3 scripts/amtq-ab-test.py self-test
```

On the macOS gateway:

```bash
git switch amtq
git pull --ff-only
cargo build --release -p quicast-amt
cargo build --release -p quicast-amtq --features daemon
python3 scripts/amtq-ab-test.py self-test
```

## Start The Relays

On the Linode at `172.104.156.144`, set the native multicast interface address
and the AMTQ certificate paths:

```bash
export LINODE_PUBLIC_IP=172.104.156.144
export LINODE_UPSTREAM_IP="$(ip -4 route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
export AMTQ_CERT=/etc/quicast/amtq/fullchain.pem
export AMTQ_KEY=/etc/quicast/amtq/private-key.pem
```

Run classic AMT:

```bash
sudo ./target/release/amt relay \
  --bind 0.0.0.0:2268 \
  --relay-address "$LINODE_PUBLIC_IP" \
  --upstream-interface "$LINODE_UPSTREAM_IP"
```

Run AMTQ in another terminal:

```bash
sudo ./target/release/amtq relay \
  --bind 0.0.0.0:2269 \
  --cert "$AMTQ_CERT" \
  --key "$AMTQ_KEY" \
  --upstream-interface "$LINODE_UPSTREAM_IP"
```

## Start The Gateways

On the Mac, set its LAN address and the DNS identity in the Relay certificate:

```bash
export LINODE_PUBLIC_IP=172.104.156.144
export LOCAL_LAN_IP="$(ipconfig getifaddr en0)"
export AMTQ_SERVER_NAME=relay.example
```

Run the classic Gateway:

```bash
sudo ./target/release/amt gateway \
  --relay "$LINODE_PUBLIC_IP:2268" \
  --protocol igmpv3 \
  --group 239.250.10.1 \
  --downstream-interface "$LOCAL_LAN_IP" \
  --membership-refresh-interval 30
```

Run the AMTQ Gateway in another terminal:

```bash
sudo ./target/release/amtq gateway \
  --relay "$LINODE_PUBLIC_IP:2269" \
  --server-name "$AMTQ_SERVER_NAME" \
  --protocol igmpv3 \
  --join 239.250.10.2 \
  --downstream-interface "$LOCAL_LAN_IP" \
  --refresh 30
```

Add `--ca /path/to/ca.pem` when the AMTQ Relay certificate is not rooted in
the system trust store.

## Start The Receiver

Start the receiver before the source. On a LAN receiver with a checkout of
this repository:

```bash
export RX_IP=192.168.188.49
mkdir -p /tmp/amtq-ab

python3 scripts/amtq-ab-test.py receive \
  --interface "$RX_IP" \
  --duration 6h10m \
  --startup-timeout 10m \
  --output /tmp/amtq-ab/receiver.csv \
  | tee /tmp/amtq-ab/receiver.log
```

The receiver accepts any run ID by default. Its capture duration begins with
the first valid probe, so relay and sender setup time is not counted as packet
loss. It exits with an error if no valid probe arrives within
`--startup-timeout`. For an unattended repeat, pass the same explicit UUID to
sender and receiver with `--run-id`.

## Start The Source

On the Linode:

```bash
mkdir -p /tmp/amtq-ab

python3 scripts/amtq-ab-test.py send \
  --interface "$LINODE_UPSTREAM_IP" \
  --duration 6h \
  --pps 50 \
  --sizes 1200 \
  --output /tmp/amtq-ab/source.csv \
  | tee /tmp/amtq-ab/source.log
```

`1200`-byte UDP payloads model typical media packets. A second run with
`--sizes 256,1200,1400` exercises both COMPLETE and path-sized FRAGMENT AMTQ
datagrams. Keep the fixed-size run as the primary latency comparison.

## Sample Process Resources

The sampler is optional. Supply the actual process IDs and run it on both
hosts:

```bash
python3 scripts/amtq-ab-test.py sample \
  --process classic-relay=1234 \
  --process amtq-relay=1235 \
  --duration 6h \
  --output /tmp/amtq-ab/relay-resources.csv
```

```bash
python3 scripts/amtq-ab-test.py sample \
  --process classic-gateway=2345 \
  --process amtq-gateway=2346 \
  --duration 6h \
  --output /tmp/amtq-ab/gateway-resources.csv
```

The sampler records cumulative process CPU time and derives utilization from
successive deltas. On Linux it uses `/proc` clock ticks; other systems use the
process CPU duration reported by `ps`. The report includes observed CPU
seconds, mean and P95 utilization, peak RSS, and RSS change. Packet delivery
and paired latency remain the primary results; resource samples are supporting
evidence.

## Produce The Report

Move `source.csv` and any resource logs to the receiver, then run:

```bash
python3 scripts/amtq-ab-test.py report \
  --source /tmp/amtq-ab/source.csv \
  --receive /tmp/amtq-ab/receiver.csv \
  --resource-log /tmp/amtq-ab/relay-resources.csv \
  --resource-log /tmp/amtq-ab/gateway-resources.csv \
  --json-out /tmp/amtq-ab/report.json \
  > /tmp/amtq-ab/report.md
```

The report command streams the CSV files into a temporary disk-backed SQLite
database so multi-hour runs do not need to fit in RAM. Use
`--work-dir /path/with/free/space` if the system temporary directory is small.

For a defensible first result, run at least one six-hour daytime test and one
overnight test. Preserve the exact commit ID, command lines, host kernel and OS
versions, QUIC implementation version, packet size, offered packet rate, and
whether the receiver was local or on another LAN host.

Define acceptance thresholds before looking at the report. Reasonable initial
questions are whether AMTQ has any disconnect, monotonic RSS growth, materially
higher loss, or more than a few milliseconds of added paired P95 latency.

The two paths use different multicast groups to prevent duplicate downstream
delivery. Repeat the run with the group assignments swapped on the source,
relays, gateways, and receiver to expose any group-specific bias. Also run each
path alone once: the simultaneous comparison removes time-of-day drift but
makes the paths compete for the same access links.

Do not mix capacity results into the primary six-hour latency baseline. For
headless packet-rate and multi-Gateway fan-out procedures, see
[AMT versus AMTQ Scale Test](amtq-scale-test.md).

## Optional Wire Capture

Capture a short representative window rather than the complete multi-hour
run:

```bash
LINODE_DEV="$(ip route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
sudo timeout 600 tcpdump -ni "$LINODE_DEV" -s 128 \
  -w /tmp/amtq-ab/tunnels-10m.pcap \
  'udp port 2268 or udp port 2269'
```

Separate tunnel ports make packet counts and captured bytes attributable to
classic AMT or AMTQ. Do not present captured-byte overhead without stating the
capture point and whether Ethernet headers are included.
