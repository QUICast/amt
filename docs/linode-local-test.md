# Linode To Local Network Test

This guide sets up a first real AMT path:

```text
Linode multicast source -> Linode AMT relay -> Internet -> local AMT gateway -> local multicast receiver
```

The goal is to verify that AMT can carry multicast traffic from a Linode to a
receiver on your local network, even though the internet path does not support
native multicast.

## Current Test Shape

The relay receives native multicast as raw IP datagrams through `mcrx-core`.

The gateway forwards complete multicast IP datagrams downstream through
`mctx-core` raw transmit. That preserves the original multicast source and group
from the AMT Multicast Data packet.

The gateway can run in transparent mode. In that mode it listens for local
IGMPv3/MLDv2 receiver reports, aggregates the receiver interest, and sends AMT
Membership Updates upstream only for groups that local receivers requested.
Local receiver joins therefore drive both the LAN receive path and the AMT
upstream subscription.

For the first test, ASM is the easiest receiver mode. Once that works, use SSM
with the Linode source IP as the source filter.

## Topology

```text
Linode:
  mctx_send source       -> 239.1.2.3:5000
  amt relay              -> UDP 0.0.0.0:2268

Internet:
  UDP AMT tunnel         -> Linode public IP:2268

Local network:
  mcrx_recv receiver     -> joins 239.1.2.3:5000 and emits IGMPv3
  amt gateway            -> learns join, receives AMT, forwards raw IP multicast
```

Example values:

```bash
GROUP=239.1.2.3
PORT=5000
LINODE_PUBLIC_IP=203.0.113.10
```

Replace `203.0.113.10` with the real Linode public IP.

## Prepare The Linode

Install Rust and build tools if needed:

```bash
sudo apt update
sudo apt install -y build-essential curl ca-certificates libcap2-bin tcpdump
curl https://sh.rustup.rs -sSf | sh
. "$HOME/.cargo/env"
```

Build the relay and sender:

```bash
cargo install quicast-amt --features metrics
cargo install mctx-core --bin mctx_send
```

If using this repository checkout instead of crates.io:

```bash
cd ~/multicast/amt
cargo build --release --features metrics

cd ~/multicast/mctx-core
cargo build --release --bin mctx_send
```

Raw receive on the relay usually needs `CAP_NET_RAW` or root:

```bash
sudo setcap cap_net_raw+ep ~/.cargo/bin/amt
getcap ~/.cargo/bin/amt
```

For a repository build, apply the capability to `target/release/amt` instead:

```bash
sudo setcap cap_net_raw+ep ~/multicast/amt/target/release/amt
getcap ~/multicast/amt/target/release/amt
```

If capabilities are not available, run the relay with `sudo`.

Raw downstream transmit on the local gateway also usually needs `CAP_NET_RAW`
or root. For a repository build on the local machine:

```bash
cargo build --release --features metrics
sudo setcap cap_net_raw+ep target/release/amt
getcap target/release/amt
```

If capabilities are not available, run the gateway binary with `sudo`.

## Open Firewall

Allow inbound UDP `2268` in the Linode Cloud Firewall.

If `ufw` is enabled on the instance:

```bash
sudo ufw allow 2268/udp
sudo ufw status
```

Restrict the source to your home public IP if practical.

## Find Interfaces

On the Linode, pick the native multicast receive/source interface.

For loopback-only first tests:

```bash
LINODE_UPSTREAM_IF=127.0.0.1
```

For the Linode default interface:

```bash
LINODE_UPSTREAM_IF=$(ip route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')
LINODE_DEV=$(ip route get 1.1.1.1 | awk '{for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}')
echo "$LINODE_UPSTREAM_IF"
echo "$LINODE_DEV"
```

Make sure the selected Linode device has multicast enabled and an IPv4
multicast route. This is especially useful on VPS setups where the default route
is unicast-only:

```bash
ip link show dev "$LINODE_DEV"
sudo ip route replace 224.0.0.0/4 dev "$LINODE_DEV"
ip route show 224.0.0.0/4
```

On macOS locally, pick the LAN interface:

```bash
LOCAL_LAN_IP=$(ipconfig getifaddr en0)
echo "$LOCAL_LAN_IP"
```

Use the right interface if your local machine is not on `en0`.

## Start The Relay

On the Linode:

```bash
HEIMDALL_IMPORT_DIR=$HOME/heimdall-import

amt relay \
  --bind 0.0.0.0:2268 \
  --relay-address "$LINODE_PUBLIC_IP" \
  --upstream-interface "$LINODE_UPSTREAM_IF" \
  --metrics-dir "$HEIMDALL_IMPORT_DIR" \
  --node-id linode-amt-relay
```

For a repository build:

```bash
~/multicast/amt/target/release/amt relay \
  --bind 0.0.0.0:2268 \
  --relay-address "$LINODE_PUBLIC_IP" \
  --upstream-interface "$LINODE_UPSTREAM_IF" \
  --metrics-dir "$HEIMDALL_IMPORT_DIR" \
  --node-id linode-amt-relay
```

`--relay-address` must be the public address reachable by the gateway. When
binding to `0.0.0.0`, omitting it would advertise loopback by default.

## Start The Transparent Local Gateway

On the local machine:

```bash
HEIMDALL_IMPORT_DIR=$PWD/heimdall-import

target/release/amt gateway \
  --relay "$LINODE_PUBLIC_IP:2268" \
  --transparent \
  --protocol igmpv3 \
  --downstream-interface "$LOCAL_LAN_IP" \
  --metrics-dir "$HEIMDALL_IMPORT_DIR" \
  --node-id local-amt-gateway
```

The gateway logs an initial local IGMPv3 General Query and then listens for
local reports to `224.0.0.22`.

Expected startup lines include:

```text
transparent local membership listening for Igmpv3 reports
sent local Igmpv3 General Query
```

If you need to separate the raw transmit interface from the report listener,
add `--local-membership-interface "$LOCAL_LAN_IP"`. Use
`--local-query-interval 0` if another querier is already present and you only
want to passively learn reports.

Metrics appear under:

```text
$HEIMDALL_IMPORT_DIR/linode-amt-relay/amt-relay.jsonl
$HEIMDALL_IMPORT_DIR/local-amt-gateway/amt-gateway.jsonl
```

## Start The Local Receiver

On the local machine, in another terminal:

```bash
cargo install mcrx-core --bin mcrx_recv

mcrx_recv 239.1.2.3 5000 --interface "$LOCAL_LAN_IP"
```

For a local `mcrx-core` repository build:

```bash
cargo build --release --manifest-path ../mcrx-core/Cargo.toml --bin mcrx_recv
../mcrx-core/target/release/mcrx_recv 239.1.2.3 5000 --interface "$LOCAL_LAN_IP"
```

Use ASM for this first local receiver test.

After ASM works, test SSM by joining the Linode sender source address:

```bash
mcrx_recv 239.1.2.3 5000 --interface "$LOCAL_LAN_IP" --source "$LINODE_UPSTREAM_IF"
```

Use the source IP that appears in the multicast IP datagram. For loopback-only
Linode tests that may be `127.0.0.1`, which is not a realistic SSM source for a
LAN receiver; prefer the Linode default interface for SSM tests.

Expected gateway and relay logs include these lines:

```text
local membership report from ...
advertised 1 local membership record(s) to relay
accepted Igmpv3 membership update (... active gateways)
upstream subscriptions changed: +1 -0 active=1
```

The gateway refreshes its membership state every 60 seconds by default, and the
relay expires idle gateways after 260 seconds by default. That means a crashed
gateway should eventually disappear from the relay's active gateway count and
upstream subscription set.

Stop the gateway with Ctrl-C for a graceful AMT Teardown. The relay should log
`accepted teardown` and then reconcile upstream subscriptions down if no other
gateway still needs the group.

If the relay and gateway connect but these membership lines do not appear, debug
the local report path first. On the local machine, `tcpdump` should see IGMPv3
reports to `224.0.0.22` after the gateway sends a query or after the receiver
joins.

For comparison, you can still bypass transparent learning and force a configured
join:

```bash
target/release/amt gateway \
  --relay "$LINODE_PUBLIC_IP:2268" \
  --group 239.1.2.3 \
  --downstream-interface "$LOCAL_LAN_IP"
```

## Start The Linode Source

If testing through loopback on the Linode:

```bash
mctx_send 239.1.2.3 5000 "hello over AMT" 1000 1000 \
  --source 127.0.0.1 \
  --interface 127.0.0.1 \
  --ttl 1
```

If testing through the Linode default interface:

```bash
mctx_send 239.1.2.3 5000 "hello over AMT" 1000 1000 \
  --source "$LINODE_UPSTREAM_IF" \
  --interface "$LINODE_UPSTREAM_IF" \
  --ttl 1
```

Expected behavior:

- The Linode relay logs forwarded multicast datagrams.
- The local gateway logs AMT Multicast Data and downstream forwarding.
- The local receiver prints the payload.

## Debugging

On the Linode:

```bash
sudo tcpdump -ni any udp port 2268
sudo tcpdump -ni any host 239.1.2.3 or udp port 5000
ip maddr show dev "$LINODE_DEV"
cat /proc/net/igmp
```

On the local machine:

```bash
sudo tcpdump -ni any udp port 2268
sudo tcpdump -ni any host 239.1.2.3 and udp port 5000
sudo tcpdump -ni any igmp
```

## Common Failures

Gateway sends discovery but gets no reply:

```text
Linode Cloud Firewall, ufw, or another firewall is blocking UDP 2268.
```

Relay replies but gateway does not proceed:

```text
The relay may be advertising the wrong address. Set --relay-address to the Linode public IP.
```

Relay accepts membership but forwards nothing:

```text
Raw receive permission, upstream interface selection, or the Linode multicast
route is wrong. Confirm --upstream-interface matches LINODE_UPSTREAM_IF, the
source uses the same --interface value, and 224.0.0.0/4 routes to LINODE_DEV.
```

Split the Linode data path with tcpdump:

```bash
ip route get 239.1.2.3
sudo tcpdump -vv -ni "$LINODE_DEV" 'udp and dst host 239.1.2.3 and dst port 5000'
```

If tcpdump sees nothing while `mctx_send` is running, the sender is not emitting
on the selected interface. Check that `mctx_send` prints the expected source
address and use both `--source "$LINODE_UPSTREAM_IF"` and
`--interface "$LINODE_UPSTREAM_IF"`.

Transparent gateway sees no local membership reports:

```text
The local receiver may not have emitted a fresh IGMPv3 report, the listener may
be on the wrong interface, or another local querier/report version interaction
may be hiding the report from the gateway.
```

Confirm the gateway sends a local query and receivers answer:

```bash
sudo tcpdump -vv -ni any 'igmp or host 224.0.0.22'
```

If tcpdump sees reports but the gateway logs nothing, run with
`--local-membership-interface "$LOCAL_LAN_IP"` and make sure the gateway has raw
receive permission.

If tcpdump sees packets but the relay logs nothing, try the raw receiver from
`mcrx-core` on the same Linode:

```bash
sudo mcrx_raw_recv 239.1.2.3 --interface "$LINODE_UPSTREAM_IF"
```

If `mcrx_raw_recv` also sees nothing, the issue is below `amt` in raw packet
receive or local outbound multicast capture. If it sees packets, restart the
relay with the newest build and check the active upstream subscription log.

Relay and gateway connect, but no native IGMP report is visible on the Linode:

```text
For the current simple gateway, this is not necessarily a failure. The local
Mac's IGMP report is link-local LAN control traffic and will not cross the
internet to the Linode. The gateway sends an AMT Membership Update over UDP
2268 instead, and the relay converts that into mcrx-core raw upstream
subscriptions. Look for "accepted Igmpv3 membership update" and "upstream
subscriptions changed" in the relay log.
```

Local receiver joins do not cause the transparent gateway to subscribe:

```text
Confirm the gateway was started with --transparent, that tcpdump sees IGMPv3
reports to 224.0.0.22, and that --local-membership-interface points at the LAN
interface when automatic interface selection is not enough.
```

Gateway forwards downstream but local receiver sees nothing:

```text
The local receiver likely joined the wrong interface, the gateway lacks raw
send privileges, or local Wi-Fi/LAN multicast filtering is in the way.
```

Local SSM receiver sees nothing:

```text
Confirm the receiver joined the source IP inside the tunneled multicast
datagram, not the AMT relay or gateway address. Also note that mctx-core raw
IPv6 transmit is not supported on Windows yet.
```
