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
  amt gateway            -> receives AMT, forwards raw IP multicast
  mcrx_recv receiver     -> joins 239.1.2.3:5000
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
cargo install amt
cargo install mctx-core --bin mctx_send
```

If using this repository checkout instead of crates.io:

```bash
cd ~/multicast/amt
cargo build --release

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
cargo build --release
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
echo "$LINODE_UPSTREAM_IF"
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
amt relay \
  --bind 0.0.0.0:2268 \
  --relay-address "$LINODE_PUBLIC_IP" \
  --upstream-interface "$LINODE_UPSTREAM_IF"
```

For a repository build:

```bash
~/multicast/amt/target/release/amt relay \
  --bind 0.0.0.0:2268 \
  --relay-address "$LINODE_PUBLIC_IP" \
  --upstream-interface "$LINODE_UPSTREAM_IF"
```

`--relay-address` must be the public address reachable by the gateway. When
binding to `0.0.0.0`, omitting it would advertise loopback by default.

## Start The Local Receiver

On the local machine:

```bash
cargo install mcrx-core --bin mcrx_recv

mcrx_recv 239.1.2.3 5000 --interface "$LOCAL_LAN_IP"
```

For a local repository build:

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

## Start The Local Gateway

On the local machine:

```bash
target/release/amt gateway \
  --relay "$LINODE_PUBLIC_IP:2268" \
  --group 239.1.2.3 \
  --downstream-interface "$LOCAL_LAN_IP"
```

Expected relay output includes:

```text
accepted Igmpv3 membership update
upstream subscriptions changed: +1 -0 active=1
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
```

On the local machine:

```bash
sudo tcpdump -ni any udp port 2268
sudo tcpdump -ni any host 239.1.2.3 and udp port 5000
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
Raw receive permission or upstream interface selection is wrong on the Linode.
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
