use amt::AMT_PORT;
use amt::config::{DriadFileConfig, FileConfig, MetricsFileConfig, load_file_config};
use amt::daemon::{
    self, DEFAULT_GATEWAY_IDLE_TIMEOUT, DEFAULT_GATEWAY_PRUNE_INTERVAL,
    DEFAULT_MEMBERSHIP_REFRESH_INTERVAL, GatewayDaemonConfig, GatewayJoin, RelayDaemonConfig,
};
use amt::metrics::MetricsConfig;
use amt::relay::RelayConfig;
use amt::{DownstreamConfig, GatewayConfig, LocalMembershipConfig, MembershipProtocol};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayRelayDiscovery {
    Static,
    Driad,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayDriadOptions {
    resolvers: Vec<SocketAddr>,
    timeout: Duration,
    attempts: usize,
}

impl Default for GatewayDriadOptions {
    fn default() -> Self {
        Self {
            resolvers: Vec::new(),
            timeout: Duration::from_secs(2),
            attempts: 2,
        }
    }
}

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
    let (config_path, remaining_args) = split_config_arg(args)?;
    let file_config = load_optional_config(config_path)?;
    let relay_file = file_config
        .as_ref()
        .and_then(|config| config.relay.as_ref());

    let mut bind = relay_file
        .and_then(|config| config.bind)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], AMT_PORT)));
    let mut relay_addresses = relay_file
        .and_then(|config| config.relay_address.clone())
        .map(|addresses| addresses.into_vec())
        .unwrap_or_default();
    let mut upstream_interface = relay_file.and_then(|config| config.upstream_interface);
    let mut upstream_interface_index =
        relay_file.and_then(|config| config.upstream_interface_index);
    let mut gateway_idle_timeout =
        match relay_file.and_then(|config| config.gateway_idle_timeout_secs) {
            Some(0) => None,
            Some(seconds) => Some(Duration::from_secs(seconds)),
            None => Some(DEFAULT_GATEWAY_IDLE_TIMEOUT),
        };
    let mut gateway_prune_interval =
        match relay_file.and_then(|config| config.gateway_prune_interval_secs) {
            Some(0) => return Err("relay.gateway_prune_interval_secs must not be 0".to_string()),
            Some(seconds) => Duration::from_secs(seconds),
            None => DEFAULT_GATEWAY_PRUNE_INTERVAL,
        };
    let mut metrics = metrics_config_from_file(file_config.as_ref())?;
    let mut args = remaining_args.into_iter();

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
            "--metrics-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--metrics-dir requires a directory path".to_string())?;
                metrics.output_dir = Some(PathBuf::from(value));
            }
            "--node-id" => {
                metrics.node_id = args
                    .next()
                    .ok_or_else(|| "--node-id requires a value".to_string())?;
            }
            "--metrics-interval-ms" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--metrics-interval-ms requires milliseconds".to_string())?;
                let millis = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --metrics-interval-ms '{value}'"))?;
                metrics.sample_interval = Duration::from_millis(millis);
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
    relay_daemon.metrics = metrics;

    Ok(Some(relay_daemon))
}

fn parse_gateway_config(
    args: impl IntoIterator<Item = String>,
) -> Result<Option<GatewayDaemonConfig>, String> {
    let (config_path, remaining_args) = split_config_arg(args)?;
    let file_config = load_optional_config(config_path)?;
    let gateway_file = file_config
        .as_ref()
        .and_then(|config| config.gateway.as_ref());

    let mut bind = gateway_file
        .and_then(|config| config.bind)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut relay = gateway_file.and_then(|config| config.relay);
    let mut relay_discovery = gateway_file
        .and_then(|config| config.relay_discovery.as_deref())
        .map(parse_relay_discovery)
        .transpose()?
        .unwrap_or(GatewayRelayDiscovery::Static);
    let mut driad_options =
        driad_options_from_file(gateway_file.and_then(|config| config.driad.as_ref()))?;
    let mut protocol = gateway_file
        .and_then(|config| config.protocol.as_deref())
        .map(parse_protocol)
        .transpose()?;
    let mut group: Option<IpAddr> = gateway_file.and_then(|config| config.group);
    let mut source: Option<IpAddr> = gateway_file.and_then(|config| config.source);
    let configured_joins = gateway_file
        .map(|config| {
            config
                .joins
                .iter()
                .map(|join| GatewayJoin {
                    group: join.group,
                    source: join.source,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut downstream = if gateway_file
        .and_then(|config| config.no_downstream)
        .unwrap_or(false)
    {
        None
    } else {
        Some(DownstreamConfig::default())
    };
    if let Some(config) = gateway_file.and_then(|config| config.downstream.as_ref()) {
        let downstream = downstream.get_or_insert_with(DownstreamConfig::default);
        downstream.interface = config.interface;
        downstream.interface_index = config.interface_index;
        if let Some(ttl) = config.ttl {
            downstream.ttl = Some(ttl);
        }
        if let Some(loopback) = config.loopback {
            downstream.loopback = loopback;
        }
    }
    let mut transparent = gateway_file
        .and_then(|config| config.transparent)
        .unwrap_or_else(|| {
            gateway_file
                .and_then(|config| config.local_membership.as_ref())
                .is_some()
        });
    let local_file = gateway_file.and_then(|config| config.local_membership.as_ref());
    let mut local_membership_interface: Option<IpAddr> =
        local_file.and_then(|config| config.interface);
    let mut local_membership_ifindex = local_file.and_then(|config| config.interface_index);
    let mut local_query_interval = match local_file
        .and_then(|config| config.query_interval_secs)
        .or_else(|| gateway_file.and_then(|config| config.local_query_interval_secs))
    {
        Some(0) => None,
        Some(seconds) => Some(Duration::from_secs(seconds)),
        None => Some(Duration::from_secs(30)),
    };
    let mut membership_refresh_interval =
        match gateway_file.and_then(|config| config.membership_refresh_interval_secs) {
            Some(0) => None,
            Some(seconds) => Some(Duration::from_secs(seconds)),
            None => Some(DEFAULT_MEMBERSHIP_REFRESH_INTERVAL),
        };
    let mut metrics = metrics_config_from_file(file_config.as_ref())?;
    let mut args = remaining_args.into_iter();

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
            "--relay-discovery" => {
                let value = args.next().ok_or_else(|| {
                    "--relay-discovery requires static, driad, or auto".to_string()
                })?;
                relay_discovery = parse_relay_discovery(&value)?;
            }
            "--driad-resolver" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--driad-resolver requires an IP address".to_string())?;
                driad_options.resolvers.push(parse_driad_resolver(&value)?);
            }
            "--driad-timeout-ms" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--driad-timeout-ms requires milliseconds".to_string())?;
                let millis = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --driad-timeout-ms '{value}'"))?;
                if millis == 0 {
                    return Err("--driad-timeout-ms must not be 0".to_string());
                }
                driad_options.timeout = Duration::from_millis(millis);
            }
            "--driad-attempts" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--driad-attempts requires a positive count".to_string())?;
                let attempts = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --driad-attempts '{value}'"))?;
                if attempts == 0 {
                    return Err("--driad-attempts must not be 0".to_string());
                }
                driad_options.attempts = attempts;
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
            "--downstream-ttl" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--downstream-ttl requires a TTL value".to_string())?;
                let ttl = value
                    .parse::<u8>()
                    .map_err(|_| format!("invalid --downstream-ttl '{value}'"))?;
                downstream.get_or_insert_with(DownstreamConfig::default).ttl = Some(ttl);
            }
            "--no-downstream-loopback" => {
                downstream
                    .get_or_insert_with(DownstreamConfig::default)
                    .loopback = false;
            }
            "--no-downstream" => downstream = None,
            "--metrics-dir" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--metrics-dir requires a directory path".to_string())?;
                metrics.output_dir = Some(PathBuf::from(value));
            }
            "--node-id" => {
                metrics.node_id = args
                    .next()
                    .ok_or_else(|| "--node-id requires a value".to_string())?;
            }
            "--metrics-interval-ms" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--metrics-interval-ms requires milliseconds".to_string())?;
                let millis = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --metrics-interval-ms '{value}'"))?;
                metrics.sample_interval = Duration::from_millis(millis);
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(None);
            }
            other => return Err(format!("unknown gateway argument '{other}'\n\n{}", usage())),
        }
    }

    if group.is_none() && configured_joins.is_empty() && !transparent {
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

    let inferred_group = group.or_else(|| configured_joins.first().map(|join| join.group));
    let protocol = protocol.unwrap_or_else(|| match inferred_group {
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
    for join in &configured_joins {
        validate_gateway_join(join.group, join.source)?;
        match (protocol, join.group) {
            (MembershipProtocol::Igmpv3, IpAddr::V4(_))
            | (MembershipProtocol::Mldv2, IpAddr::V6(_)) => {}
            _ => return Err("configured gateway join does not match --protocol".to_string()),
        }
    }

    let mut joins = configured_joins;
    if let Some(group) = group {
        joins.push(GatewayJoin { group, source });
    }

    let relay = resolve_gateway_relay(relay, relay_discovery, &joins, &driad_options, transparent)?;
    let mut config = GatewayDaemonConfig::new(bind, GatewayConfig::new(relay, protocol));
    config.joins = joins;
    config.downstream = downstream;
    config.membership_refresh_interval = membership_refresh_interval;
    config.metrics = metrics;
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

fn split_config_arg(
    args: impl IntoIterator<Item = String>,
) -> Result<(Option<PathBuf>, Vec<String>), String> {
    let mut config_path = None;
    let mut remaining = Vec::new();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if arg == "--config" {
            let value = args
                .next()
                .ok_or_else(|| "--config requires a TOML file path".to_string())?;
            if config_path.replace(PathBuf::from(value)).is_some() {
                return Err("--config may only be provided once".to_string());
            }
        } else if let Some(value) = arg.strip_prefix("--config=") {
            if value.is_empty() {
                return Err("--config requires a TOML file path".to_string());
            }
            if config_path.replace(PathBuf::from(value)).is_some() {
                return Err("--config may only be provided once".to_string());
            }
        } else {
            remaining.push(arg);
        }
    }

    Ok((config_path, remaining))
}

fn load_optional_config(path: Option<PathBuf>) -> Result<Option<FileConfig>, String> {
    path.map(load_file_config).transpose()
}

fn metrics_config_from_file(config: Option<&FileConfig>) -> Result<MetricsConfig, String> {
    let mut metrics = MetricsConfig::default();
    let Some(config) = config.and_then(|config| config.metrics.as_ref()) else {
        return Ok(metrics);
    };

    apply_metrics_file_config(&mut metrics, config)?;
    Ok(metrics)
}

fn apply_metrics_file_config(
    metrics: &mut MetricsConfig,
    config: &MetricsFileConfig,
) -> Result<(), String> {
    if let Some(output_dir) = config.output_dir.clone() {
        metrics.output_dir = Some(output_dir);
    }
    if let Some(node_id) = config.node_id.as_ref() {
        if node_id.trim().is_empty() {
            return Err("metrics.node_id must not be empty".to_string());
        }
        metrics.node_id = node_id.clone();
    }
    if let Some(millis) = config.interval_ms {
        metrics.sample_interval = Duration::from_millis(millis);
    }
    Ok(())
}

fn parse_relay_discovery(value: &str) -> Result<GatewayRelayDiscovery, String> {
    match value {
        "static" => Ok(GatewayRelayDiscovery::Static),
        "driad" => Ok(GatewayRelayDiscovery::Driad),
        "auto" => Ok(GatewayRelayDiscovery::Auto),
        _ => Err(format!(
            "invalid relay discovery mode '{value}'; expected static, driad, or auto"
        )),
    }
}

fn driad_options_from_file(
    config: Option<&DriadFileConfig>,
) -> Result<GatewayDriadOptions, String> {
    let mut options = GatewayDriadOptions::default();
    let Some(config) = config else {
        return Ok(options);
    };

    for resolver in config
        .resolvers
        .clone()
        .map(|resolvers| resolvers.into_vec())
        .unwrap_or_default()
    {
        options.resolvers.push(parse_driad_resolver(&resolver)?);
    }
    if let Some(timeout_ms) = config.timeout_ms {
        if timeout_ms == 0 {
            return Err("gateway.driad.timeout_ms must not be 0".to_string());
        }
        options.timeout = Duration::from_millis(timeout_ms);
    }
    if let Some(attempts) = config.attempts {
        if attempts == 0 {
            return Err("gateway.driad.attempts must not be 0".to_string());
        }
        options.attempts = attempts;
    }

    Ok(options)
}

fn parse_driad_resolver(value: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    value
        .parse::<IpAddr>()
        .map(|addr| SocketAddr::new(addr, 53))
        .map_err(|_| format!("invalid DRIAD resolver '{value}'; expected IP or IP:PORT"))
}

fn resolve_gateway_relay(
    relay: Option<SocketAddr>,
    discovery: GatewayRelayDiscovery,
    joins: &[GatewayJoin],
    driad_options: &GatewayDriadOptions,
    transparent: bool,
) -> Result<SocketAddr, String> {
    match discovery {
        GatewayRelayDiscovery::Static => {
            relay.ok_or_else(|| "gateway requires --relay ADDRESS:PORT".to_string())
        }
        GatewayRelayDiscovery::Auto => match relay {
            Some(relay) => Ok(relay),
            None => resolve_driad_relay(joins, driad_options, transparent),
        },
        GatewayRelayDiscovery::Driad => resolve_driad_relay(joins, driad_options, transparent),
    }
}

fn resolve_driad_relay(
    joins: &[GatewayJoin],
    driad_options: &GatewayDriadOptions,
    transparent: bool,
) -> Result<SocketAddr, String> {
    if transparent {
        return Err(
            "DRIAD transparent membership learning is not implemented yet; use configured SSM --group/--source joins for now"
                .to_string(),
        );
    }
    let source = driad_source_for_joins(joins)?;

    #[cfg(feature = "driad")]
    {
        let mut resolver_config = if driad_options.resolvers.is_empty() {
            amt::driad::DriadResolverConfig::system().map_err(|error| {
                format!("failed to load system DNS resolvers for DRIAD: {error}")
            })?
        } else {
            amt::driad::DriadResolverConfig::new(driad_options.resolvers.clone())
        };
        resolver_config.timeout = driad_options.timeout;
        resolver_config.attempts = driad_options.attempts;
        let resolver = amt::driad::DriadResolver::new(resolver_config);
        let selection = resolver.resolve_source(source).map_err(|error| {
            format!("DRIAD relay discovery failed for source {source}: {error}")
        })?;
        println!(
            "DRIAD selected AMT relay {} for source {} using {} (precedence {}, discovery_optional={})",
            selection.relay,
            selection.source,
            selection.query_name,
            selection.record.precedence,
            selection.record.discovery_optional
        );
        Ok(selection.relay)
    }

    #[cfg(not(feature = "driad"))]
    {
        let _ = source;
        let _ = driad_options;
        Err("DRIAD relay discovery requires building with --features driad".to_string())
    }
}

fn driad_source_for_joins(joins: &[GatewayJoin]) -> Result<IpAddr, String> {
    let mut selected = None;

    if joins.is_empty() {
        return Err(
            "DRIAD relay discovery requires a configured SSM --group and --source".to_string(),
        );
    }

    for join in joins {
        let Some(source) = join.source else {
            return Err(
                "DRIAD relay discovery requires all configured joins to be SSM joins with a source"
                    .to_string(),
            );
        };
        if let Some(existing) = selected {
            if existing != source {
                return Err(
                    "this DRIAD implementation currently supports one source address per gateway session"
                        .to_string(),
                );
            }
        } else {
            selected = Some(source);
        }
    }

    selected.ok_or_else(|| "DRIAD relay discovery requires an SSM source".to_string())
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

fn validate_gateway_join(group: IpAddr, source: Option<IpAddr>) -> Result<(), String> {
    if !group.is_multicast() {
        return Err("gateway join group must be multicast".to_string());
    }
    if let Some(source) = source
        && (!same_family(group, source) || source.is_multicast())
    {
        return Err(
            "gateway join source must be a unicast address in the same family as group".to_string(),
        );
    }
    Ok(())
}

fn print_usage() {
    println!("{}", usage());
}

fn usage() -> &'static str {
    concat!(
        "Usage:\n",
        "  amt relay [--config FILE] [--bind ADDRESS:PORT] [--relay-address IP] ",
        "[--upstream-interface IP] [--upstream-ifindex INDEX] ",
        "[--gateway-idle-timeout SECONDS] [--gateway-prune-interval SECONDS] ",
        "[--metrics-dir DIR] [--node-id ID] [--metrics-interval-ms MS]\n",
        "  amt gateway [--config FILE] [--relay ADDRESS:PORT] [--relay-discovery static|driad|auto] [--group GROUP] [--source SOURCE] ",
        "[--transparent] [--bind ADDRESS:PORT] [--protocol igmpv3|mldv2] ",
        "[--driad-resolver IP[:PORT]] [--driad-timeout-ms MS] [--driad-attempts COUNT] ",
        "[--downstream-interface IP] [--downstream-ifindex INDEX] [--downstream-ttl TTL] ",
        "[--local-membership-interface IP] [--local-membership-ifindex INDEX] ",
        "[--local-query-interval SECONDS] [--membership-refresh-interval SECONDS] ",
        "[--no-downstream-loopback] [--no-downstream] ",
        "[--metrics-dir DIR] [--node-id ID] [--metrics-interval-ms MS]\n\n",
        "Relay defaults to 0.0.0.0:2268 and advertises loopback unless --bind uses a concrete IP.\n",
        "Relay prunes idle gateways after 260 seconds by default; pass --gateway-idle-timeout 0 to disable pruning.\n",
        "Gateway defaults to an ephemeral local port and forwards raw multicast IP datagrams downstream with mctx-core unless --no-downstream is set.\n",
        "Gateway static relay discovery requires --relay; DRIAD discovery requires a configured SSM --source and the driad Cargo feature.\n",
        "Gateway refreshes memberships every 60 seconds by default; pass --membership-refresh-interval 0 to disable refreshes.\n",
        "Use --transparent to learn local IGMPv3/MLDv2 receiver interest instead of requiring a configured --group.\n",
        "Use --metrics-dir to write Heimdall JSONL metrics under DIR/node-id/.\n",
        "Raw relay upstream receive and gateway downstream transmit may require elevated privileges or explicit interface selection on some platforms.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn relay_config_file_loads_and_cli_overrides() {
        let path = write_temp_config(
            "relay",
            r#"
            [relay]
            bind = "0.0.0.0:2268"
            relay_address = "203.0.113.10"
            upstream_interface = "192.0.2.10"
            gateway_idle_timeout_secs = 120

            [metrics]
            output_dir = "/tmp/heimdall"
            node_id = "relay-a"
            interval_ms = 250
            "#,
        );

        let config = parse_relay_config([
            "--config".to_string(),
            path.display().to_string(),
            "--bind".to_string(),
            "127.0.0.1:9999".to_string(),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(config.relay.bind, "127.0.0.1:9999".parse().unwrap());
        assert_eq!(
            config.upstream.interface,
            Some("192.0.2.10".parse().unwrap())
        );
        assert_eq!(config.gateway_idle_timeout, Some(Duration::from_secs(120)));
        assert_eq!(
            config.metrics.output_dir.as_deref(),
            Some(Path::new("/tmp/heimdall"))
        );
        assert_eq!(config.metrics.node_id, "relay-a");
        assert_eq!(config.metrics.sample_interval, Duration::from_millis(250));
    }

    #[test]
    fn gateway_config_accepts_join_tables_without_top_level_group() {
        let path = write_temp_config(
            "gateway",
            r#"
            [gateway]
            relay = "203.0.113.10:2268"
            protocol = "igmpv3"

            [gateway.downstream]
            interface = "192.168.1.20"
            ttl = 16

            [[gateway.joins]]
            group = "239.1.2.3"

            [[gateway.joins]]
            group = "232.1.2.3"
            source = "192.0.2.10"
            "#,
        );

        let config = parse_gateway_config(["--config".to_string(), path.display().to_string()])
            .unwrap()
            .unwrap();

        assert_eq!(config.gateway.relay, "203.0.113.10:2268".parse().unwrap());
        assert_eq!(config.gateway.protocol, MembershipProtocol::Igmpv3);
        assert_eq!(config.joins.len(), 2);
        assert_eq!(
            config
                .downstream
                .as_ref()
                .and_then(|downstream| downstream.ttl),
            Some(16)
        );
    }

    #[test]
    fn gateway_auto_discovery_keeps_static_relay_when_configured() {
        let config = parse_gateway_config([
            "--relay".to_string(),
            "203.0.113.10:2268".to_string(),
            "--relay-discovery".to_string(),
            "auto".to_string(),
            "--group".to_string(),
            "232.1.2.3".to_string(),
            "--source".to_string(),
            "192.0.2.10".to_string(),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(config.gateway.relay, "203.0.113.10:2268".parse().unwrap());
        assert_eq!(config.joins.len(), 1);
    }

    #[test]
    fn driad_source_selection_rejects_asm_or_multiple_sources() {
        assert!(driad_source_for_joins(&[]).is_err());
        assert!(
            driad_source_for_joins(&[GatewayJoin {
                group: "239.1.2.3".parse().unwrap(),
                source: None,
            }])
            .is_err()
        );
        assert!(
            driad_source_for_joins(&[
                GatewayJoin {
                    group: "232.1.2.3".parse().unwrap(),
                    source: Some("192.0.2.10".parse().unwrap()),
                },
                GatewayJoin {
                    group: "232.1.2.4".parse().unwrap(),
                    source: Some("192.0.2.11".parse().unwrap()),
                },
            ])
            .is_err()
        );
    }

    #[cfg(not(feature = "driad"))]
    #[test]
    fn driad_discovery_requires_feature() {
        let error = parse_gateway_config([
            "--relay-discovery".to_string(),
            "driad".to_string(),
            "--group".to_string(),
            "232.1.2.3".to_string(),
            "--source".to_string(),
            "192.0.2.10".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("--features driad"));
    }

    fn write_temp_config(name: &str, contents: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        let path = std::env::temp_dir().join(format!("amt_{name}_{nanos}.toml"));
        fs::write(&path, contents).unwrap();
        path
    }
}
