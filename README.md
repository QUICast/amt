# amt

Lightweight Rust building blocks for [Automatic Multicast Tunneling][rfc7450]
(AMT, RFC 7450).

The crate currently includes:

- RFC 7450 message encoding and decoding.
- Relay-side discovery, request, membership update, teardown, and multicast
  forwarding state.
- Gateway-side discovery, request, membership update, multicast data, and
  teardown state.
- IGMPv3 and MLDv2 query/report packet helpers.
- A simple blocking relay daemon.
- A simple blocking gateway daemon.
- Raw relay upstream receive through `mcrx-core` with its `raw-packets`
  feature.
- Raw gateway downstream transmit through `mctx-core` with its `raw-packets`
  feature.
- Transparent gateway mode that listens for local IGMPv3/MLDv2 receiver reports
  and turns them into AMT Membership Updates.

[rfc7450]: https://datatracker.ietf.org/doc/html/rfc7450

## Status

This is still an early implementation. It is useful for protocol development,
local integration tests, and first network tests, but it is not yet a hardened
production daemon.

Implemented:

- AMT Relay Discovery and Relay Advertisement.
- AMT Request and Membership Query.
- AMT Membership Update with IGMPv3/MLDv2 report parsing.
- AMT Multicast Data encoding/decoding.
- AMT Teardown.
- Relay upstream subscription reconciliation for ASM/SSM interests.
- Gateway joins for a configured group and optional source.
- Gateway local membership learning for transparent IGMPv3/MLDv2 operation.
- Relay idle gateway pruning and gateway membership refreshes.
- Localhost socket-level relay/gateway roundtrip test.

Current limitations:

- The simple daemons use blocking loops and polling. They are intentionally
  small and easy to inspect, not yet optimized.
- Relay raw upstream receive may require root, `CAP_NET_RAW`, or explicit
  interface selection depending on platform.
- Gateway raw downstream transmit may require root, `CAP_NET_RAW`, or explicit
  interface selection depending on platform. `mctx-core` raw IPv6 transmit is
  not supported on Windows yet.
- Transparent mode currently listens for IGMPv3 reports to `224.0.0.22` or
  MLDv2 reports to `ff02::16`. It is not yet a full multicast router/TUN mode,
  and legacy IGMPv1/v2 reports sent directly to a multicast group are not the
  primary path.
- Transparent mode does not yet age out silent local receivers with full
  IGMP/MLD listener timers; leave/state-change reports update the learned state.

## Build

```bash
cargo build
cargo test
cargo run -- --help
```

The crate depends on crates.io releases:

- `mcrx-core = 0.2.5` with `raw-packets`
- `mctx-core = 0.2.3` with `raw-packets`

## CLI

```text
amt relay [--bind ADDRESS:PORT] [--relay-address IP] [--upstream-interface IP] [--upstream-ifindex INDEX] [--gateway-idle-timeout SECONDS] [--gateway-prune-interval SECONDS]
amt daemon [--bind ADDRESS:PORT] [--relay-address IP] [--upstream-interface IP] [--upstream-ifindex INDEX] [--gateway-idle-timeout SECONDS] [--gateway-prune-interval SECONDS]
amt gateway --relay ADDRESS:PORT [--group GROUP] [--source SOURCE] [--transparent] [--bind ADDRESS:PORT] [--protocol igmpv3|mldv2] [--downstream-interface IP] [--downstream-ifindex INDEX] [--local-membership-interface IP] [--local-membership-ifindex INDEX] [--local-query-interval SECONDS] [--membership-refresh-interval SECONDS] [--no-downstream]
```

`amt daemon` is currently an alias for `amt relay`.

### Relay

Run a relay on the standard AMT UDP port:

```bash
cargo run --release -- relay \
  --bind 0.0.0.0:2268 \
  --relay-address 203.0.113.10 \
  --upstream-interface 192.0.2.10
```

`--relay-address` is the IP address advertised to gateways. It is important
when binding to `0.0.0.0`; otherwise the default advertised address is loopback.

`--upstream-interface` selects the native multicast receive interface for
`mcrx-core` raw receive.

The relay daemon prunes idle gateways after 260 seconds by default and checks
for expired gateways every 5 seconds. Use `--gateway-idle-timeout 0` to disable
pruning, or tune `--gateway-idle-timeout` and `--gateway-prune-interval` for
test setups.

### Gateway

Run a gateway that joins an ASM group through a remote relay and forwards
received multicast IP datagrams locally:

```bash
cargo run --release -- gateway \
  --relay 203.0.113.10:2268 \
  --group 239.1.2.3 \
  --downstream-interface 192.168.1.20
```

Run a gateway that requests SSM from the AMT relay:

```bash
cargo run --release -- gateway \
  --relay 203.0.113.10:2268 \
  --group 232.1.2.3 \
  --source 192.0.2.10 \
  --downstream-interface 192.168.1.20
```

The gateway uses raw downstream transmit, so local SSM receivers can join the
original `(S,G)` carried inside AMT Multicast Data. Raw transmit may require
elevated privileges.

The gateway daemon refreshes its current Membership Update state every 60
seconds by default, which keeps relay-side idle pruning from removing healthy
gateways. Use `--membership-refresh-interval 0` to disable refreshes.

Run a transparent IPv4 gateway that learns local receiver interest from IGMPv3
reports instead of using a fixed `--group`:

```bash
cargo run --release -- gateway \
  --relay 203.0.113.10:2268 \
  --transparent \
  --protocol igmpv3 \
  --downstream-interface 192.168.1.20
```

The transparent gateway sends periodic local General Queries by default and
listens for receiver reports on the same interface. Use
`--local-query-interval 0` to disable those local queries, or
`--local-membership-interface` if the report listener must use a different
interface address than downstream raw transmit.

## Tests

Run all tests:

```bash
cargo test
```

The integration test in `tests/amt_roundtrip.rs` binds localhost UDP sockets and
verifies:

- gateway discovery to relay
- relay advertisement
- gateway request
- relay membership query
- gateway membership update
- relay state update
- AMT multicast data delivery
- teardown

Some sandboxed environments block UDP socket binds. In those environments the
test must be run with appropriate socket permissions.

## Documentation

- [Architecture](docs/architecture.md)
- [Linode to local network test](docs/linode-local-test.md)
- [Raw `mctx-core` transmit integration](docs/mctx-raw-packets.md)

## Library Layout

- `protocol`: AMT wire codec.
- `query`: IGMPv3 and MLDv2 General Query packet builders.
- `membership`: IGMP/MLD membership report parser and builder.
- `state`: relay-side gateway membership and upstream subscription state.
- `relay`: runtime-agnostic relay state machine.
- `upstream`: relay upstream raw multicast receive manager using `mcrx-core`.
- `gateway`: runtime-agnostic gateway state machine.
- `local_membership`: local IGMPv3/MLDv2 report listener and membership delta
  tracker for transparent gateway mode.
- `downstream`: gateway downstream raw multicast transmitter using `mctx-core`.
- `daemon`: simple blocking relay and gateway loops.

## License

BSD-2-Clause.
