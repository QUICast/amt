# Sibling Crate Feature Prompts

These requests are retained as the design record for the capabilities delivered
in `mcrx-core 0.3.0` and `mctx-core 0.3.1`. AMT continues to own AMT, DNS,
IGMP/MLD, ICMP construction, and RFC policy; the sibling crates expose only
packet-I/O mechanisms.

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

## Follow-Up Prompt For mcrx-core Relay Readiness

```text
Please add an additive, portable readiness/blocking receive facility for the
raw-packets and raw-shared-capture backends in mcrx-core. Keep all existing
nonblocking APIs and behavior source-compatible.

Motivation: quicast-amt now isolates native multicast capture in a bounded
worker, but mcrx-core 0.3.0 exposes only try_recv_any(). The worker must poll
every 250 microseconds to 2 milliseconds while subscriptions are active. AMT
also cannot request a larger kernel raw receive buffer or determine whether a
kernel capture socket overflowed before userspace accepted a packet.

Provide a transport-level API which can wait until any joined raw capture
socket is readable and can be interrupted from another thread when membership
commands or shutdown arrive. One possible shape is a context-owned
RawReceiveWaiter plus a cheap cloneable RawReceiveWaker, followed by
recv_batch_into/try_recv_batch_into. Do not require Tokio or another runtime.
Do not make callers assemble their own unsafe raw-descriptor list whose
lifetime can diverge from context membership changes.

Required behavior:
- work with RawContext and SharedRawContext;
- support Linux, macOS, and Windows wherever the existing backend is supported;
- block without polling when there is no traffic;
- wake promptly for a packet or an explicit cross-thread wake request;
- remain correct when reconciliation adds or removes capture sockets;
- receive a bounded caller-selected batch without an intentional batching
  delay (return the first available packet immediately, then drain available
  packets up to the limit);
- preserve packet order per capture socket and existing round-robin fairness;
- allow a requested kernel receive-buffer size and report the actual granted
  size per capture socket;
- expose cumulative kernel overflow/drop information where the OS provides it,
  such as Linux SO_RXQ_OVFL/PACKET_STATISTICS, and explicitly report
  unavailable rather than synthesizing zero on other platforms;
- preserve complete datagrams and existing ASM/SSM demultiplex semantics;
- return typed interrupted, timeout, unsupported, and receive errors.

The wait/wake path must use bounded resources, must not create a helper thread
per subscription, and must not busy-spin. Platform-specific poll/epoll/kqueue
or Windows event code should remain encapsulated inside mcrx-core.

Add unit tests for wake-before-wait, wake-during-wait, timeout, socket-set
changes, bounded batch drain, and clean destruction. Add a privileged Linux
namespace stress test which changes memberships while a high-rate source is
active and verifies kernel/user drop accounting. Include strict Linux, macOS,
and Windows compile checks, API documentation, and a changelog entry.
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
