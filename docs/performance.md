# Classic Relay Performance

The classic RFC 7450 Relay has one adaptive data-plane design. There are no
latency, throughput, or efficiency profiles to tune.

## Data Path

Native multicast capture runs in a dedicated worker which owns
`UpstreamManager`. Valid packets enter a bounded 4,096-packet channel and wake
the Relay immediately when the channel transitions from empty. Membership
commands use a separate bounded channel and are checked after at most 256
captured packets or one millisecond.

The Relay services AMT control before each data slice. A slice forwards at most
512 packets or runs for at most two milliseconds. Each AMT Multicast Data
datagram is encoded once and reused for all matching Gateway sends. No timer is
used to accumulate a batch.

The Relay's AMT UDP socket requests four MiB send and receive buffers. Gateway
and DRIAD sockets retain their platform defaults so per-source tunnels do not
multiply that memory request. Kernel limits may reduce the Relay values;
startup output reports the values actually observed.

## Overload Semantics

Memory use is bounded. When the userspace packet queue is full, the newest
captured packet is discarded and capture continues. This preserves the order
of packets already queued and gives the Relay the best chance of draining the
raw receive socket. Drops are never silent:

- `upstream_worker_queue_drops_total` counts userspace queue overflow.
- `upstream_worker_failures_total` counts fatal capture-worker failures.
- `upstream_queue_depth` reports the current queue occupancy.
- `upstream_queue_high_water` reports the lifetime high-water mark.
- `upstream_packets_received_total` counts valid packets accepted from mcrx,
  including packets subsequently discarded because the queue was full.
- `upstream_packets_forwarded_total` counts successful per-Gateway sends.
- `upstream_forward_errors_total` counts failed per-Gateway sends.

The five-second data-plane summary includes queue drops and rate-limits log
volume naturally.

`mcrx-core 0.3.0` does not expose kernel raw-socket overflow counters. A gap
between source observation and `upstream_packets_received_total` therefore
cannot yet be attributed precisely inside AMT. It also does not expose capture
readiness, so a worker with active subscriptions uses a 250 microsecond to 2
millisecond adaptive poll. With no subscriptions it blocks without polling.

## Repeatable Linux Test

The ignored namespace test creates isolated source, Relay, and AMT sink network
namespaces. The sink performs a real RFC 7450 handshake and counts tunnel
datagrams directly; it does not run downstream Gateway forwarding. Relay
capture/forward counters and tunnel egress are therefore measured separately.

Build and run it as root on Linux with `iproute2` available:

```bash
CARGO="$(command -v cargo)"
for RATE in 1000 4000 8000; do
  sudo -E env \
    AMT_SYSTEM_BURST_RATE="$RATE" \
    AMT_SYSTEM_BURST_DURATION_MS=10000 \
    AMT_SYSTEM_BURST_PAYLOAD_BYTES=1200 \
    "$CARGO" test --features metrics --test system_linux \
      linux_namespace_relay_sustained_burst -- \
      --ignored --exact --nocapture --test-threads=1
done
```

Use a release build for capacity measurements rather than debug code:

```bash
CARGO="$(command -v cargo)"
sudo -E env \
  AMT_SYSTEM_BURST_RATE=8000 \
  AMT_SYSTEM_BURST_DURATION_MS=10000 \
  AMT_SYSTEM_BURST_PAYLOAD_BYTES=1200 \
  "$CARGO" test --release --features metrics --test system_linux \
    linux_namespace_relay_sustained_burst -- \
    --ignored --exact --nocapture --test-threads=1
```

The source helper reports offered count, elapsed time, and achieved send rate.
The AMT sink reports independently observed tunnel datagrams. Heimdall output
reports Relay capture, forwarding, queue drops, and queue high-water.

CPU time and RSS should be recorded externally for the Relay PID, for example
with `pidstat -p PID 1` and `/proc/PID/status`. A successful source `sendto`
count alone is not a delivery result.

## Results Record

The motivating isolated test used 1,200-byte payloads for ten seconds. The
original environment description did not identify its CPU model, kernel,
network namespace topology, socket-buffer limits, or build profile, so these
figures are retained as development evidence rather than a portable capacity
claim:

| Offered rate | Source | Relay captured/forwarded | Gateway received | Relay CPU |
|---:|---:|---:|---:|---:|
| 4,000 packets/s | 40,000 | 40,000 | 40,000 | not recorded |
| 8,000 packets/s | 79,999 | 72,226 | 67,095 | approximately 7.4% |

Fresh post-refactor Linux measurements were not produced on the development
Mac because no Docker/Linux daemon was available and the privileged namespace
test cannot run on macOS. Populate a new dated table only from the test above,
including kernel, CPU allocation, release/debug profile, actual socket-buffer
sizes, Relay CPU time, RSS, capture, forwarding, queue drops, and AMT sink
receipt.

Loopback, container, network-namespace, and single-vCPU results are useful for
regression testing but are not general deployment capacity claims.
