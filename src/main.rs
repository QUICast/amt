use amt::AMT_PORT;
use amt::daemon::{self, DaemonConfig, GatewayDaemonConfig, GatewayJoin};
use amt::relay::RelayConfig;
use amt::{DownstreamConfig, GatewayConfig, MembershipProtocol};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        None | Some("daemon" | "relay") => {
            if let Some(config) = parse_relay_config(args)? {
                daemon::run(config).map_err(|error| error.to_string())
            } else {
                Ok(())
            }
        }
        Some("gateway") => {
            if let Some(config) = parse_gateway_config(args)? {
                daemon::run_gateway(config).map_err(|error| error.to_string())
            } else {
                Ok(())
            }
        }
        Some("-h" | "--help" | "help") => {
            print_usage();
            Ok(())
        }
        Some(command) => Err(format!("unknown command '{command}'\n\n{}", usage())),
    }
}

fn parse_relay_config(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<DaemonConfig>, String> {
    let mut bind = SocketAddr::from(([0, 0, 0, 0], AMT_PORT));
    let mut relay_addresses = Vec::new();
    let mut upstream_interface = None;
    let mut upstream_interface_index = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--bind requires an address like 0.0.0.0:2268".to_string())?;
                bind = value
                    .parse()
                    .map_err(|_| format!("invalid --bind address '{value}'"))?;
            }
            "--relay-address" | "--advertise" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--relay-address requires an IP address".to_string())?;
                let addr: IpAddr = value
                    .parse()
                    .map_err(|_| format!("invalid --relay-address '{value}'"))?;
                relay_addresses.push(addr);
            }
            "--upstream-interface" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--upstream-interface requires an IP address".to_string())?;
                upstream_interface = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --upstream-interface '{value}'"))?,
                );
            }
            "--upstream-ifindex" => {
                let value = args.next().ok_or_else(|| {
                    "--upstream-ifindex requires a non-zero interface index".to_string()
                })?;
                let index = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --upstream-ifindex '{value}'"))?;
                if index == 0 {
                    return Err("--upstream-ifindex must not be 0".to_string());
                }
                upstream_interface_index = Some(index);
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            other => return Err(format!("unknown daemon argument '{other}'\n\n{}", usage())),
        }
    }

    let mut config = RelayConfig::for_bind(bind);
    for addr in relay_addresses {
        config = config.with_advertise_addr(addr);
    }

    let mut daemon_config = DaemonConfig::new(config);
    daemon_config.upstream.interface = upstream_interface;
    daemon_config.upstream.interface_index = upstream_interface_index;

    Ok(Some(daemon_config))
}

fn parse_gateway_config(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<GatewayDaemonConfig>, String> {
    let mut bind = SocketAddr::from(([0, 0, 0, 0], 0));
    let mut relay = None;
    let mut protocol = None;
    let mut group = None;
    let mut source = None;
    let mut downstream = Some(DownstreamConfig::default());
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--bind requires an address like 0.0.0.0:0".to_string())?;
                bind = value
                    .parse()
                    .map_err(|_| format!("invalid --bind address '{value}'"))?;
            }
            "--relay" => {
                let value = args.next().ok_or_else(|| {
                    "--relay requires an address like 198.51.100.1:2268".to_string()
                })?;
                relay = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --relay address '{value}'"))?,
                );
            }
            "--protocol" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--protocol requires igmpv3 or mldv2".to_string())?;
                protocol = Some(parse_protocol(&value)?);
            }
            "--group" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--group requires a multicast IP address".to_string())?;
                group = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --group address '{value}'"))?,
                );
            }
            "--source" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--source requires a source IP address".to_string())?;
                source = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --source address '{value}'"))?,
                );
            }
            "--downstream-interface" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--downstream-interface requires an IP address".to_string())?;
                let interface = value
                    .parse()
                    .map_err(|_| format!("invalid --downstream-interface '{value}'"))?;
                downstream
                    .get_or_insert_with(DownstreamConfig::default)
                    .interface = Some(interface);
            }
            "--downstream-ifindex" => {
                let value = args.next().ok_or_else(|| {
                    "--downstream-ifindex requires a non-zero interface index".to_string()
                })?;
                let index = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --downstream-ifindex '{value}'"))?;
                if index == 0 {
                    return Err("--downstream-ifindex must not be 0".to_string());
                }
                downstream
                    .get_or_insert_with(DownstreamConfig::default)
                    .interface_index = Some(index);
            }
            "--no-downstream" => downstream = None,
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            other => return Err(format!("unknown gateway argument '{other}'\n\n{}", usage())),
        }
    }

    let relay = relay.ok_or_else(|| "gateway requires --relay ADDRESS:PORT".to_string())?;
    let group: IpAddr = group.ok_or_else(|| "gateway requires --group IP".to_string())?;
    if !group.is_multicast() {
        return Err("--group must be multicast".to_string());
    }
    if let Some(source) = source
        && (!same_family(group, source) || source.is_multicast())
    {
        return Err("--source must be a unicast address in the same family as --group".to_string());
    }

    let protocol = protocol.unwrap_or_else(|| match group {
        IpAddr::V4(_) => MembershipProtocol::Igmpv3,
        IpAddr::V6(_) => MembershipProtocol::Mldv2,
    });
    match (protocol, group) {
        (MembershipProtocol::Igmpv3, IpAddr::V4(_))
        | (MembershipProtocol::Mldv2, IpAddr::V6(_)) => {}
        _ => return Err("--protocol does not match --group address family".to_string()),
    }

    let mut config = GatewayDaemonConfig::new(bind, GatewayConfig::new(relay, protocol));
    config.joins.push(GatewayJoin { group, source });
    config.downstream = downstream;
    Ok(Some(config))
}

fn parse_protocol(value: &str) -> Result<MembershipProtocol, String> {
    match value {
        "igmp" | "igmpv3" | "ipv4" => Ok(MembershipProtocol::Igmpv3),
        "mld" | "mldv2" | "ipv6" => Ok(MembershipProtocol::Mldv2),
        _ => Err(format!("invalid --protocol '{value}'")),
    }
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn print_usage() {
    println!("{}", usage());
}

fn usage() -> &'static str {
    "Usage:\n  amt relay [--bind ADDRESS:PORT] [--relay-address IP] [--upstream-interface IP] [--upstream-ifindex INDEX]\n  amt daemon [--bind ADDRESS:PORT] [--relay-address IP] [--upstream-interface IP] [--upstream-ifindex INDEX]\n  amt gateway --relay ADDRESS:PORT --group GROUP [--source SOURCE] [--bind ADDRESS:PORT] [--protocol igmpv3|mldv2] [--downstream-interface IP] [--downstream-ifindex INDEX] [--no-downstream]\n\nRelay defaults to 0.0.0.0:2268 and advertises loopback unless --bind uses a concrete IP.\nGateway defaults to an ephemeral local port and forwards raw multicast IP datagrams downstream with mctx-core unless --no-downstream is set.\nRaw relay upstream receive and gateway downstream transmit may require elevated privileges or explicit interface selection on some platforms."
}
