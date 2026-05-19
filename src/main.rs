use amt::AMT_PORT;
use amt::daemon::{
    self, DEFAULT_GATEWAY_IDLE_TIMEOUT, DEFAULT_GATEWAY_PRUNE_INTERVAL,
    DEFAULT_MEMBERSHIP_REFRESH_INTERVAL, GatewayDaemonConfig, GatewayJoin, RelayDaemonConfig,
};
use amt::relay::RelayConfig;
use amt::{DownstreamConfig, GatewayConfig, LocalMembershipConfig, MembershipProtocol};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

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
        None => {
            print_usage();
            Ok(())
        }
        Some("relay") => {
            if let Some(config) = parse_relay_config(args)? {
                daemon::run_relay(config).map_err(|error| error.to_string())
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
) -> Result<Option<RelayDaemonConfig>, String> {
    let mut bind = SocketAddr::from(([0, 0, 0, 0], AMT_PORT));
    let mut relay_addresses = Vec::new();
    let mut upstream_interface = None;
    let mut upstream_interface_index = None;
    let mut gateway_idle_timeout = Some(DEFAULT_GATEWAY_IDLE_TIMEOUT);
    let mut gateway_prune_interval = DEFAULT_GATEWAY_PRUNE_INTERVAL;
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
            "--gateway-idle-timeout" => {
                let value = args.next().ok_or_else(|| {
                    "--gateway-idle-timeout requires seconds, or 0 to disable pruning".to_string()
                })?;
                let seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --gateway-idle-timeout '{value}'"))?;
                gateway_idle_timeout = (seconds != 0).then_some(Duration::from_secs(seconds));
            }
            "--gateway-prune-interval" => {
                let value = args.next().ok_or_else(|| {
                    "--gateway-prune-interval requires a positive number of seconds".to_string()
                })?;
                let seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --gateway-prune-interval '{value}'"))?;
                if seconds == 0 {
                    return Err("--gateway-prune-interval must not be 0".to_string());
                }
                gateway_prune_interval = Duration::from_secs(seconds);
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            other => return Err(format!("unknown relay argument '{other}'\n\n{}", usage())),
        }
    }

    let mut config = RelayConfig::for_bind(bind);
    for addr in relay_addresses {
        config = config.with_advertise_addr(addr);
    }

    let mut relay_daemon = RelayDaemonConfig::new(config);
    relay_daemon.upstream.interface = upstream_interface;
    relay_daemon.upstream.interface_index = upstream_interface_index;
    relay_daemon.gateway_idle_timeout = gateway_idle_timeout;
    relay_daemon.gateway_prune_interval = gateway_prune_interval;

    Ok(Some(relay_daemon))
}

fn parse_gateway_config(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<GatewayDaemonConfig>, String> {
    let mut bind = SocketAddr::from(([0, 0, 0, 0], 0));
    let mut relay = None;
    let mut protocol = None;
    let mut group: Option<IpAddr> = None;
    let mut source: Option<IpAddr> = None;
    let mut downstream = Some(DownstreamConfig::default());
    let mut transparent = false;
    let mut local_membership_interface: Option<IpAddr> = None;
    let mut local_membership_ifindex = None;
    let mut local_query_interval = Some(Duration::from_secs(30));
    let mut membership_refresh_interval = Some(DEFAULT_MEMBERSHIP_REFRESH_INTERVAL);
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
            "--transparent" => transparent = true,
            "--local-membership-interface" => {
                let value = args.next().ok_or_else(|| {
                    "--local-membership-interface requires an IP address".to_string()
                })?;
                local_membership_interface = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --local-membership-interface '{value}'"))?,
                );
            }
            "--local-membership-ifindex" => {
                let value = args.next().ok_or_else(|| {
                    "--local-membership-ifindex requires a non-zero interface index".to_string()
                })?;
                let index = value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --local-membership-ifindex '{value}'"))?;
                if index == 0 {
                    return Err("--local-membership-ifindex must not be 0".to_string());
                }
                local_membership_ifindex = Some(index);
            }
            "--local-query-interval" => {
                let value = args.next().ok_or_else(|| {
                    "--local-query-interval requires seconds, or 0 to disable queries".to_string()
                })?;
                let seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --local-query-interval '{value}'"))?;
                local_query_interval = (seconds != 0).then_some(Duration::from_secs(seconds));
            }
            "--membership-refresh-interval" => {
                let value = args.next().ok_or_else(|| {
                    "--membership-refresh-interval requires seconds, or 0 to disable refreshes"
                        .to_string()
                })?;
                let seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --membership-refresh-interval '{value}'"))?;
                membership_refresh_interval =
                    (seconds != 0).then_some(Duration::from_secs(seconds));
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
    if group.is_none() && !transparent {
        return Err("gateway requires --group IP unless --transparent is set".to_string());
    }
    if source.is_some() && group.is_none() {
        return Err("--source requires --group".to_string());
    }

    if let Some(group) = group {
        if !group.is_multicast() {
            return Err("--group must be multicast".to_string());
        }
        if let Some(source) = source
            && (!same_family(group, source) || source.is_multicast())
        {
            return Err(
                "--source must be a unicast address in the same family as --group".to_string(),
            );
        }
    }

    let protocol = protocol.unwrap_or_else(|| match group {
        Some(IpAddr::V6(_)) => MembershipProtocol::Mldv2,
        Some(IpAddr::V4(_)) | None => MembershipProtocol::Igmpv3,
    });
    if let Some(group) = group {
        match (protocol, group) {
            (MembershipProtocol::Igmpv3, IpAddr::V4(_))
            | (MembershipProtocol::Mldv2, IpAddr::V6(_)) => {}
            _ => return Err("--protocol does not match --group address family".to_string()),
        }
    }
    if let Some(interface) = local_membership_interface
        && !protocol_matches_address(protocol, interface)
    {
        return Err(
            "--local-membership-interface address family must match --protocol".to_string(),
        );
    }

    let mut config = GatewayDaemonConfig::new(bind, GatewayConfig::new(relay, protocol));
    if let Some(group) = group {
        config.joins.push(GatewayJoin { group, source });
    }
    config.downstream = downstream;
    config.membership_refresh_interval = membership_refresh_interval;
    if transparent {
        let mut local = LocalMembershipConfig::new(protocol);
        local.interface = local_membership_interface.or_else(|| {
            config
                .downstream
                .as_ref()
                .and_then(|downstream| downstream.interface)
        });
        local.interface_index = local_membership_ifindex.or_else(|| {
            config
                .downstream
                .as_ref()
                .and_then(|downstream| downstream.interface_index)
        });
        local.query_interval = local_query_interval;
        config.local_membership = Some(local);
    }
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

fn protocol_matches_address(protocol: MembershipProtocol, address: IpAddr) -> bool {
    matches!(
        (protocol, address),
        (MembershipProtocol::Igmpv3, IpAddr::V4(_)) | (MembershipProtocol::Mldv2, IpAddr::V6(_))
    )
}

fn print_usage() {
    println!("{}", usage());
}

fn usage() -> &'static str {
    concat!(
        "Usage:\n",
        "  amt relay [--bind ADDRESS:PORT] [--relay-address IP] ",
        "[--upstream-interface IP] [--upstream-ifindex INDEX] ",
        "[--gateway-idle-timeout SECONDS] [--gateway-prune-interval SECONDS]\n",
        "  amt gateway --relay ADDRESS:PORT [--group GROUP] [--source SOURCE] ",
        "[--transparent] [--bind ADDRESS:PORT] [--protocol igmpv3|mldv2] ",
        "[--downstream-interface IP] [--downstream-ifindex INDEX] ",
        "[--local-membership-interface IP] [--local-membership-ifindex INDEX] ",
        "[--local-query-interval SECONDS] [--membership-refresh-interval SECONDS] ",
        "[--no-downstream]\n\n",
        "Relay defaults to 0.0.0.0:2268 and advertises loopback unless --bind uses a concrete IP.\n",
        "Relay prunes idle gateways after 260 seconds by default; pass --gateway-idle-timeout 0 to disable pruning.\n",
        "Gateway defaults to an ephemeral local port and forwards raw multicast IP datagrams downstream with mctx-core unless --no-downstream is set.\n",
        "Gateway refreshes memberships every 60 seconds by default; pass --membership-refresh-interval 0 to disable refreshes.\n",
        "Use --transparent to learn local IGMPv3/MLDv2 receiver interest instead of requiring a configured --group.\n",
        "Raw relay upstream receive and gateway downstream transmit may require elevated privileges or explicit interface selection on some platforms.",
    )
}
