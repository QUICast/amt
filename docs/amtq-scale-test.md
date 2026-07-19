# AMT versus AMTQ Scale Test

This test measures short-duration packet-rate and Relay fan-out scaling. It is
separate from the long-run latency test: the source sends fixed-size payloads
without per-packet timestamps, CSV output, checksums, or sequence tracking.

Run capacity tests on dedicated ports and multicast groups. A production Relay
may retain classic-AMT Gateway state until its idle timeout, and an overloaded
AMTQ connection may need time to drain queued QUIC Datagrams. Fresh Relay
processes give the cleanest result.

## Build

```bash
cargo build --release -p quicast-amt
cargo build --release -p quicast-amtq --features daemon,shared-upstream
python3 scripts/amtq-ab-test.py self-test
```

`shared-upstream` is recommended for a Relay with many memberships. It is not
required for a single test group.

## Headless Gateways

Headless Gateways complete the normal membership protocol and count tunneled
packets, but do not publish them onto a LAN. This avoids making an offered-load
test into a multicast flood.

Classic AMT:

```bash
./target/release/amt gateway \
  --relay "$RELAY_IP:2268" \
  --protocol igmpv3 \
  --group 239.250.20.1 \
  --no-downstream
```

AMTQ:

```bash
./target/release/amtq gateway \
  --relay "$RELAY_IP:2269" \
  --server-name "$AMTQ_SERVER_NAME" \
  --protocol igmpv3 \
  --join 239.250.20.2 \
  --no-downstream
```

Add `--ca FILE` for a private AMTQ Relay CA. Omit `--bind` for a normal
roaming-capable Gateway. Give each Gateway a distinct bind port when launching
multiple instances on one host.

## Packet-Rate Sweep

Run the source on the native multicast side of both Relays:

```bash
python3 scripts/amtq-ab-test.py blast \
  --interface "$UPSTREAM_IP" \
  --classic-group 239.250.20.1 \
  --classic-port 5501 \
  --amtq-group 239.250.20.2 \
  --amtq-port 5502 \
  --duration 30s \
  --pps 4000 \
  --size 1200
```

`--pps` is the number of pairs per second: one packet goes to each path for
every pair. At 4,000 pairs/s and a 1,200-byte payload, each tunnel is offered
38.4 Mbit/s of payload. The source alternates send order to avoid consistently
favoring one path.

Use ascending steps and allow at least 30 seconds after each AMTQ step for its
traffic summary interval:

```text
250, 500, 1000, 2000, 4000, 8000
```

Stop when the sender misses its target, either Relay reports queue drops, the
Gateway delivery ratio falls, or the test host approaches CPU saturation.
Record both offered and achieved packet rates.

## Fan-Out Sweep

Start 1, 2, 4, 8, and 16 headless Gateways per protocol, all subscribed to the
same respective test group. Use a modest fixed input rate first, such as 50 or
100 pairs/s, so the result isolates per-Gateway fan-out cost rather than the
packet-rate ceiling.

Measure the Relay process during each step:

```bash
python3 scripts/amtq-ab-test.py sample \
  --process classic-relay="$CLASSIC_RELAY_PID" \
  --process amtq-relay="$AMTQ_RELAY_PID" \
  --duration 30s \
  --interval 1s \
  --output /tmp/amtq-fanout-resources.csv
```

Wait for every Gateway to report its membership before starting a step. For
AMTQ, verify `active`, `established`, and `active_subscriptions` in the Relay
status. Count recipients, not merely Gateway processes: an old classic-AMT
endpoint remains a recipient until teardown or idle pruning.

## Interpreting Results

Classic AMT is plain UDP and does not respond to congestion. A successful
`sendto` only proves that the kernel accepted a datagram. AMTQ QUIC Datagrams
are unreliable too, but QUIC still applies congestion control and pacing.
Consequently, an overloaded WAN AMT path can appear faster while silently
discarding traffic later in the network, whereas AMTQ may shed traffic at a
bounded queue or reduce its sending rate.

Separate these possible loss points:

- Native multicast capture at the Relay.
- Relay per-Gateway queue admission.
- QUIC or UDP tunnel delivery.
- Gateway receive and downstream publication queues.
- Final multicast receiver delivery.

Use Relay and Gateway counters at both ends. Do not infer a Relay capacity
limit from a WAN run unless the access path is known to have spare capacity.

## Exploratory Reference Run

The following run on 2026-07-19 is a development reference, not a portable
performance claim. Packet-rate tests used fresh isolated Relays, one headless
Gateway per path, 1,200-byte payloads, and loopback tunnel delivery on a
single-vCPU AMD EPYC Linode. The source, both Relays, and both Gateways shared
that CPU.

| Pairs/s | Payload per path | Classic delivery | AMTQ delivery | Classic Relay CPU | AMTQ Relay CPU | Classic Gateway CPU | AMTQ Gateway CPU |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 9.6 Mbit/s | 10,000/10,000 | 10,000/10,000 | 1.3% | 8.4% | 0.3% | 4.7% |
| 2,000 | 19.2 Mbit/s | 20,000/20,000 | 20,000/20,000 | 2.4% | 10.1% | 0.6% | 5.6% |
| 4,000 | 38.4 Mbit/s | 40,000/40,000 | 40,000/40,000 | 4.4% | 11.1% | 0.9% | 6.1% |
| 8,000 | 76.8 Mbit/s | 67,095/79,999 | 79,927/79,999 | 7.4% | 12.9% | 1.3% | 7.2% |

At 8,000 pairs/s, the classic Relay captured and forwarded 72,226 packets and
the classic Gateway received 67,095. AMTQ captured and forwarded 79,956 and
the Gateway received 79,927, with no native per-connection queue drops. This
suggests that the current classic blocking capture/send loop and polling
Gateway reach burst-handling limits before the split AMTQ capture worker and
event-driven QUIC path. It does not mean QUIC is intrinsically cheaper.

A separate WAN fan-out sweep held input at 50 pairs/s for 30 seconds:

| Recipients | Classic Relay CPU | AMTQ Relay CPU |
|---:|---:|---:|
| 2 | 0.43% | 2.53% |
| 4 | 0.53% | 2.97% |
| 8 | 0.80% | 4.00% |
| 16 | 1.27% | 6.17% |

The 16-recipient step delivered all 1,500 packets to every newly started
Gateway. AMTQ reported no downstream queue drops. The result shows roughly
linear fan-out cost over this range; AMTQ pays per-connection encryption,
packetization, pacing, and connection-state overhead that classic AMT does not.

Repeat on a multi-core dedicated host, with the source and sinks on separate
machines, before using these figures in a draft or deployment capacity plan.
