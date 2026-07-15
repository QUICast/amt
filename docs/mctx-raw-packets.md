# Raw mctx-core Transmit Integration

`mctx-core 0.3.0` provides two independent raw transmit features used by AMT:

- `raw-packets` forwards complete multicast datagrams downstream.
- `raw-ip` sends complete unicast ICMP PMTU feedback toward SSM sources.

This crate uses that API in the AMT gateway downstream path:

```text
AMT Multicast Data -> complete IP multicast datagram -> mctx-core RawContext -> local network
```

## Why Raw Transmit Matters

AMT Multicast Data carries a complete IPv4 or IPv6 multicast datagram. Sending
only the UDP payload with a normal UDP multicast socket creates a new local
source address and source port, which breaks local SSM receivers.

Raw transmit preserves the IP source and multicast destination from the AMT
payload, so a downstream receiver can join the original `(S,G)`.

## Current Integration

`downstream::DownstreamPublisher`:

- Parses enough of the IP header to confirm the destination is multicast.
- Selects one raw `mctx-core` publication per IP family.
- Sends the complete IP datagram with `RawContext::send_raw`.
- Keeps the UDP destination port only as optional reporting metadata.

The gateway no longer falls back to UDP payload republishing. If raw transmit is
unsupported or lacks privileges, forwarding fails loudly.

## Configuration

Gateway downstream configuration maps to `mctx-core` raw publication settings:

- `--downstream-interface IP` selects the local egress interface and bind
  address.
- `--downstream-ifindex INDEX` selects the IPv6 egress interface by index.
- The default downstream TTL/hop-limit override is `1`.
- Loopback is enabled by default.

Raw transmit requires an explicit interface or bind address. In practice, pass
`--downstream-interface` for IPv4 and either `--downstream-interface` or
`--downstream-ifindex` for IPv6.

## Platform Notes

- Linux and macOS support raw IPv4 and raw IPv6 transmit in `mctx-core`.
- Windows currently supports raw IPv4 only.
- Raw transmit usually requires elevated privileges such as root,
  Administrator, or `CAP_NET_RAW`.

## Testing Notes

The normal test suite validates parsing and control-plane behavior without
opening raw sockets.

End-to-end raw transmit testing should be done on a real network interface with
the required privileges:

```bash
sudo setcap cap_net_raw+ep target/release/amt
target/release/amt gateway \
  --relay 203.0.113.10:2268 \
  --group 232.1.2.3 \
  --source 192.0.2.10 \
  --downstream-interface 192.168.1.20
```

Use a downstream SSM receiver that joins the source address carried inside the
multicast IP datagram.

## Relay PMTU Feedback

Build AMT with `--features pmtu-feedback` and enable `--pmtu-feedback` on the
relay. When an oversized DF-set IPv4 or IPv6 packet arrived through a native
SSM subscription, AMT constructs the complete ICMPv4 Fragmentation Needed or
ICMPv6 Packet Too Big datagram and sends it through `mctx_core::RawIpContext`.
The advertised value is the smallest TMTU among affected gateways, and replies
are rate-limited per `(source, group)`.

The relay's explicit `--upstream-interface` address is both the ICMP source and
the raw-IP interface selector. IPv4 and IPv6 feedback therefore require local
addresses of the matching family; run separate relay instances when both are
needed. Linux and macOS support both families, Windows supports IPv4 only, and
all paths normally require raw-socket privileges.
