# Raw Transmit Plan For mctx-core

The AMT gateway ultimately needs to inject complete multicast IP datagrams onto
the local network.

The current `mctx-core` dependency sends UDP payloads through normal UDP
multicast sockets. That is useful for early payload testing, but it rewrites the
source address and source port. SSM receivers on the local network therefore
cannot see the original source/group tuple from the AMT Multicast Data packet.

## Goal

Add an optional raw packet transmit API to `mctx-core`.

The API should send complete IP datagrams, not UDP payloads.

## Feature Gate

Use:

```toml
raw-packets = []
```

This should mirror `mcrx-core` and keep normal UDP sender users unaffected.

## Desired Public API

Suggested types:

- `RawPublicationConfig`
- `RawPublication`
- `RawContext`
- `RawSendReport`

Suggested methods:

```rust
let mut ctx = RawContext::new();
let id = ctx.add_publication(config)?;
let report = ctx.send_raw(id, ip_datagram)?;
```

The raw API should be parallel to the existing UDP API. It should not change
`PublicationConfig`, `Publication`, or `Context` behavior.

## RawPublicationConfig

Suggested fields:

- address family, or infer from the datagram destination
- outgoing interface by local IP
- outgoing interface index
- optional TTL / hop limit override if the backend can apply it
- optional loopback flag if the backend can apply it
- strict multicast destination validation

The AMT gateway will usually know the desired local egress interface, but the
datagram itself already contains the source and multicast destination.

## RawSendReport

Suggested fields:

- publication id
- parsed source IP
- parsed destination/group IP
- parsed IP protocol or next-header
- bytes sent
- selected outgoing interface metadata if known

## Validation

The raw path should parse IPv4 and IPv6 headers before sending.

Reject:

- truncated IP datagrams
- invalid IPv4 total length
- invalid IPv6 payload length
- non-multicast destination addresses
- datagrams whose family does not match the raw publication configuration
- unsupported platforms or link types

Do not silently fall back to UDP send.

## Linux First Pass

Prioritize Linux.

Packet sockets are likely the most faithful first implementation because they
can transmit complete IPv4 and IPv6 datagrams as link-layer frames.

For Ethernet-like links, derive destination multicast MAC addresses:

- IPv4 multicast: `01:00:5e:xx:xx:xx`
- IPv6 multicast: `33:33:xx:xx:xx:xx`

Require explicit interface selection if needed. Returning a clear error is
better than guessing the wrong interface.

Raw IPv4 sockets with `IP_HDRINCL` may be a useful fallback for IPv4, but avoid
a design that cannot support IPv6 full-datagram transmit later.

## macOS And BSD

It is acceptable for the first pass to return unsupported.

If implemented later, BPF injection is probably the closest match to the
`mcrx-core` raw receive path.

## Windows

It is acceptable for the first pass to return unsupported.

IPv4 raw sockets may be possible with Administrator privileges, but IPv6
full-header injection has platform constraints. Do not fake support by sending
UDP payloads.

## Suggested Errors

Add `MctxError` variants similar to:

```rust
RawPacketTransmitUnsupported(String)
RawSocketCreateFailed(io::Error)
RawSocketBindFailed(io::Error)
RawSendFailed(io::Error)
InvalidRawIpDatagram
InvalidRawMulticastDestination
RawInterfaceRequired
RawUnsupportedLinkType(String)
```

## Testing

Default-feature tests must pass unchanged.

Add unit tests for:

- IPv4 datagram parsing
- IPv6 datagram parsing
- multicast destination validation
- IPv4 multicast MAC derivation
- IPv6 multicast MAC derivation

Add feature-gated API tests behind `raw-packets`.

Runtime raw transmit tests should be ignored or otherwise gated so normal CI
does not need root or `CAP_NET_RAW`.

## Integration Back Into amt

Once the raw transmit API exists, replace `DownstreamPublisher`'s UDP payload
republish path with raw datagram transmit.

The desired AMT gateway behavior is:

```text
AMT Multicast Data packet -> full IP datagram -> mctx-core raw transmit -> local network
```

That will let local SSM receivers join `(S,G)` using the original source from
the AMT Multicast Data packet.
