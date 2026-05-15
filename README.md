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
- UDP downstream multicast republishing through `mctx-core`.

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
- Localhost socket-level relay/gateway roundtrip test.

Current limitations:

- The gateway currently republishes AMT Multicast Data as UDP multicast payloads
  via `mctx-core`.
- Proper gateway-side SSM fidelity needs raw multicast transmit support in
  `mctx-core`, so the gateway can inject the complete IP datagram instead of
  creating a new UDP packet.
- The simple daemons use blocking loops and polling. They are intentionally
  small and easy to inspect, not yet optimized.
- Relay raw upstream receive may require root, `CAP_NET_RAW`, or explicit
  interface selection depending on platform.

## Build

```bash
cargo build
cargo test
cargo run -- --help
```

The crate depends on crates.io releases:

- `mcrx-core = 0.2.4` with `raw-packets`
- `mctx-core = 0.2.2`

## CLI

```text
amt relay [--bind ADDRESS:PORT] [--relay-address IP] [--upstream-interface IP] [--upstream-ifindex INDEX]
amt daemon [--bind ADDRESS:PORT] [--relay-address IP] [--upstream-interface IP] [--upstream-ifindex INDEX]
amt gateway --relay ADDRESS:PORT --group GROUP [--source SOURCE] [--bind ADDRESS:PORT] [--protocol igmpv3|mldv2] [--downstream-interface IP] [--downstream-ifindex INDEX] [--no-downstream]
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

### Gateway

Run a gateway that joins an ASM group through a remote relay and republishes
received UDP multicast locally:

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

Note that until raw transmit lands in `mctx-core`, local downstream receivers
should use ASM for the final hop because the UDP republisher creates a new local
UDP source.

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
- [Raw `mctx-core` transmit plan](docs/mctx-raw-packets.md)

## Library Layout

- `protocol`: AMT wire codec.
- `query`: IGMPv3 and MLDv2 General Query packet builders.
- `membership`: IGMP/MLD membership report parser and builder.
- `state`: relay-side gateway membership and upstream subscription state.
- `relay`: runtime-agnostic relay state machine.
- `upstream`: relay upstream raw multicast receive manager using `mcrx-core`.
- `gateway`: runtime-agnostic gateway state machine.
- `downstream`: gateway downstream UDP multicast republisher using `mctx-core`.
- `daemon`: simple blocking relay and gateway loops.

## License

BSD-2-Clause.
