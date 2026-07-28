# Raw mctx-core Transmit Integration

`mctx-core 0.3.1` provides three independent raw transmit features used by AMT:

- `raw-packets` forwards complete multicast datagrams downstream.
- `raw-route-egress` lets supported platforms choose downstream interfaces
  from their routing tables and follow route changes.
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
- Creates the configured inner-family publication before the gateway binds its
  AMT tunnel socket.
- Selects explicit or route-selected raw egress from the downstream selectors.
- Sends the complete IP datagram with `RawContext::send_raw`.
- Preserves the complete IPv4 or IPv6 datagram byte-for-byte.
- Keeps the UDP destination port only as optional reporting metadata.

The gateway no longer falls back to UDP payload republishing. Capability and
configuration failures are reported at startup, as are raw-socket failures
encountered while creating the publication. Linux route-selected IPv6 performs
destination-dependent route lookup and AF_PACKET socket creation on first send;
those failures are reported then and remain retryable.

## Configuration

Gateway downstream configuration maps to `mctx-core` raw publication settings:

- Omitting both selectors requests route-selected egress.
- `--downstream-interface IP` selects the local egress interface and bind
  address.
- `--downstream-ifindex INDEX` selects the IPv6 egress interface by index.
- Omitting `loopback` leaves the platform preference unspecified.

AMT rejects the removed `--downstream-ttl` option and legacy
`gateway.downstream.ttl` key for both families. TTL or Hop Limit belongs in the
supplied IP header and is never rewritten. An MLDv2 gateway also rejects
`loopback = true`: full-header IPv6 uses link-layer injection and cannot feed
the sending host's local IP receive path.

Transparent active queries need a local interface address for the packet
source. MLDv2 General Queries additionally need explicit downstream egress
because their `ff02::1` destination is link-local. Set
`--local-query-interval 0` for passive capture when those query-transmit
requirements are intentionally unavailable.

## Platform Notes

| Platform | Explicit IPv4 | Route IPv4 | Explicit IPv6 | Route IPv6 |
|----------|---------------|------------|---------------|------------|
| Linux | supported | supported | full header | full header |
| macOS | supported | supported | full header | unsupported |
| Windows | supported | unsupported | unsupported | unsupported |

Linux route-selected IPv6 uses cached main-table route resolution with netlink
invalidation and transient-error recovery. macOS IPv6 therefore requires
`--downstream-interface` or `--downstream-ifindex`; Windows IPv4 requires
`--downstream-interface`.

Explicit selectors remain pinned. On Linux, an unpinned publication follows
IPv4 and IPv6 route changes without AMT replacing its publication. macOS
provides the same behavior for IPv4 only.

- Raw transmit usually requires elevated privileges such as root,
  Administrator, or `CAP_NET_RAW`.
- Linux IPv6 requires an Ethernet-like output interface. macOS IPv6 requires a
  usable Ethernet BPF interface.

## Testing Notes

The normal test suite validates capability selection, portable configuration,
TTL-option rejection, and control-plane behavior without requiring raw socket
privileges. The ignored Linux namespace suite includes explicit ASM and
route-selected SSM forwarding.

End-to-end raw transmit testing should be done on a real network interface with
the required privileges:

```bash
sudo setcap cap_net_raw+ep target/release/amt
target/release/amt gateway \
  --relay 203.0.113.10:2268 \
  --group 232.1.2.3 \
  --source 192.0.2.10
```

That command uses route-selected egress. Add
`--downstream-interface 192.168.1.20` to pin it.

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
