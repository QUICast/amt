# Sibling Crate Feature Prompts

These requests are follow-up optimizations for `mcrx-core` and `mctx-core`.
They do not block AMT DRIAD or ECN support. AMT must continue to own AMT, DNS,
IGMP/MLD, ICMP construction, and RFC policy; the sibling crates should expose
portable packet-I/O mechanisms only.

## Prompt For mcrx-core

```text
Please add an optional shared raw-capture backend to mcrx-core. Keep the current
raw-packets API and behavior source-compatible; gate the new implementation or
new API behind an additive feature such as raw-shared-capture.

Motivation: quicast-amt currently creates one raw receive socket per native
multicast subscription. At hundreds of (S,G) or (*,G) subscriptions this costs
one descriptor per subscription and RawContext::try_recv_any() polls linearly.
The desired backend should use approximately one capture socket per address
family/interface tuple, join multiple ASM/SSM memberships on that socket, and
demultiplex complete IP packets by parsed source and multicast destination in
userspace. Polling cost should scale with capture sockets, not subscriptions.

Please design the API as a transport primitive rather than adding AMT concepts.
Either preserve RawContext/RawSubscriptionConfig and select the shared backend
under the feature, or add a clearly parallel SharedRawContext API. It must still
support independent add/join/leave/remove membership handles, IPv4 and IPv6,
ASM and SSM, interface address/index selection, nonblocking try_recv, and the
complete original IP datagram plus source/group metadata. A kernel datagram
should be read once even if multiple logical memberships overlap; expose all
matching handles only if callers need that information. Leaving one membership
must not disturb other memberships sharing the socket.

Preserve the Debian/Linux behavior fixed in 0.2.5: locally emitted multicast
that is visible only as an outbound packet must not be silently lost by the raw
receive path. Keep platform-specific limitations explicit and return typed
Unsupported errors instead of silently changing semantics.

Please include:
- bounded subscription and pending-packet bookkeeping;
- no per-packet scan across every subscription (index by group, then source);
- deterministic cleanup when the final membership for a capture socket leaves;
- metrics for capture-socket count, memberships, received packets, unmatched
  packets, and demultiplex matches when the existing metrics feature is on;
- unit tests for overlap, leave isolation, interface keys, and demultiplexing;
- privileged Linux namespace tests for many ASM/SSM joins over one socket;
- compile checks for Linux, macOS, and Windows, with IPv6 caveats documented;
- README/API examples and a changelog entry.

Acceptance criteria for quicast-amt: 1,000 logical subscriptions on one
interface should use O(1) raw capture sockets per family/interface and packet
receive work should not perform an O(1,000) socket poll or subscription scan.
Do not change normal mcrx-core users unless they opt into the new feature.
```

## Prompt For mctx-core

```text
Please add an optional generic raw-IP transmit primitive to mctx-core, gated
behind an additive feature such as raw-ip or raw-control-packets. Keep the
existing multicast publication and raw-packets APIs source-compatible and
unchanged for normal users.

Motivation: quicast-amt already uses mctx-core to inject complete multicast IP
datagrams downstream. Its relay also needs to send standards-compliant unicast
ICMPv4 Fragmentation Needed and ICMPv6 Packet Too Big packets back toward an
SSM source when a packet cannot fit the configured AMT tunnel MTU. AMT will
construct and validate the complete IPv4/IPv6+ICMP packet; mctx-core should only
provide portable transmission of a caller-supplied complete IP datagram.

Please expose a transport-level API, for example a RawIpContext plus
RawIpSocketConfig/RawIpPublicationConfig with address family, optional
interface address, and optional interface index. send_ip_datagram(&[u8]) should
accept unicast destinations (and may support multicast too), preserve the
caller-provided source/destination and headers where the OS permits, use
IP_HDRINCL or the platform equivalent correctly, and surface permission,
unsupported-family, interface, routing, and EMSGSIZE errors without swallowing
them. Do not add ICMP construction or AMT-specific policy to mctx-core.

Please include:
- strict, allocation-light IPv4/IPv6 header and declared-length validation;
- explicit capability reporting for raw IPv4/raw IPv6 on each platform;
- clear Windows behavior, especially any raw IPv6 restriction;
- interface selection that cannot accidentally send through an unrelated
  default route when an interface was requested;
- no automatic source, checksum, TTL, DSCP, or ECN rewrite unless documented
  as an unavoidable platform behavior;
- unit tests for validation and typed failures;
- privileged Linux namespace tests that send complete ICMPv4 and ICMPv6
  packets and observe them at the intended unicast peer;
- Linux, macOS, and Windows compile checks;
- README/API examples and a changelog entry.

Acceptance criteria for quicast-amt: given a complete valid ICMPv4 or ICMPv6
IP datagram and an explicit upstream interface, the API can transmit it toward
the original SSM source without requiring a multicast destination or a UDP
publication. Existing multicast raw send behavior must remain unchanged unless
the new feature is selected.
```
