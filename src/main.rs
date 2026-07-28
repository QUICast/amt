use amt::AMT_PORT;
use amt::config::{
    DriadFileConfig, FileConfig, MetricsFileConfig, RelayLimitsFileConfig, load_file_config,
};
#[cfg(feature = "driad")]
use amt::daemon::GatewayDriadConfig;
use amt::daemon::{
    self, DEFAULT_CONTROL_RATE_BURST, DEFAULT_CONTROL_RATE_PER_SECOND,
    DEFAULT_DRIAD_MAX_CONCURRENT_PROBES, DEFAULT_DRIAD_MAX_DNS_WORKERS,
    DEFAULT_DRIAD_MAX_SOURCE_TUNNELS, DEFAULT_GATEWAY_IDLE_TIMEOUT, DEFAULT_GATEWAY_PRUNE_INTERVAL,
    DEFAULT_GLOBAL_CONTROL_RATE_BURST, DEFAULT_GLOBAL_CONTROL_RATE_PER_SECOND,
    DEFAULT_MEMBERSHIP_REFRESH_INTERVAL, DEFAULT_RELAY_PATH_MTU, GatewayDaemonConfig, GatewayJoin,
    RelayDaemonConfig,
};
use amt::metrics::MetricsConfig;
use amt::relay::RelayConfig;
use amt::state::RelayLimits;
use amt::{DownstreamConfig, GatewayConfig, LocalMembershipConfig, MembershipProtocol};
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const DOWNSTREAM_TTL_UNSUPPORTED: &str = "--downstream-ttl and gateway.downstream.ttl are \
    unsupported because raw downstream forwarding preserves the complete inner IP header; \
    set the IPv4 TTL or IPv6 Hop Limit at the multicast source";

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
    allow_insecure_dns: bool,
    max_candidates: usize,
    max_queries_per_window: usize,
    query_rate_window: Duration,
    happy_eyeballs_delay: Duration,
    relay_hold_down: Duration,
    traffic_hold_down: Duration,
    initial_traffic_timeout: Duration,
    maximum_traffic_timeout: Duration,
    max_source_tunnels: usize,
    max_concurrent_probes: usize,
    max_dns_workers: usize,
}

impl Default for GatewayDriadOptions {
    fn default() -> Self {
        Self {
            resolvers: Vec::new(),
            timeout: Duration::from_secs(1),
            attempts: 2,
            allow_insecure_dns: false,
            max_candidates: 64,
            max_queries_per_window: 10,
            query_rate_window: Duration::from_millis(100),
            happy_eyeballs_delay: Duration::from_millis(250),
            relay_hold_down: Duration::from_secs(10 * 60),
            traffic_hold_down: Duration::from_secs(5 * 60),
            initial_traffic_timeout: Duration::from_secs(4),
            maximum_traffic_timeout: Duration::from_secs(120),
            max_source_tunnels: DEFAULT_DRIAD_MAX_SOURCE_TUNNELS,
            max_concurrent_probes: DEFAULT_DRIAD_MAX_CONCURRENT_PROBES,
            max_dns_workers: DEFAULT_DRIAD_MAX_DNS_WORKERS,
        }
    }
}

#[derive(Debug)]
struct ResolvedGatewayRelays {
    relays: Vec<SocketAddr>,
    #[cfg(feature = "driad")]
    driad: Option<GatewayDriadConfig>,
}

impl ResolvedGatewayRelays {
    fn static_relay(relay: SocketAddr) -> Self {
        Self {
            relays: vec![relay],
            #[cfg(feature = "driad")]
            driad: None,
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

    let mut bind = relay_file.and_then(|config| config.bind);
    let mut ecn = relay_file.and_then(|config| config.ecn).unwrap_or(false);
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
    let mut path_mtu = relay_file
        .and_then(|config| config.path_mtu)
        .unwrap_or(DEFAULT_RELAY_PATH_MTU);
    let mut pmtu_feedback = relay_file
        .and_then(|config| config.pmtu_feedback)
        .unwrap_or(false);
    validate_path_mtu(path_mtu)?;
    let mut metrics = metrics_config_from_file(file_config.as_ref())?;
    let rate_file = relay_file.and_then(|config| config.rate_limit.as_ref());
    let control_rate_per_second = rate_file
        .and_then(|config| config.per_source_per_second)
        .unwrap_or(DEFAULT_CONTROL_RATE_PER_SECOND);
    let control_rate_burst = rate_file
        .and_then(|config| config.per_source_burst)
        .unwrap_or(DEFAULT_CONTROL_RATE_BURST);
    let global_control_rate_per_second = rate_file
        .and_then(|config| config.global_per_second)
        .unwrap_or(DEFAULT_GLOBAL_CONTROL_RATE_PER_SECOND);
    let global_control_rate_burst = rate_file
        .and_then(|config| config.global_burst)
        .unwrap_or(DEFAULT_GLOBAL_CONTROL_RATE_BURST);
    if [
        control_rate_per_second,
        control_rate_burst,
        global_control_rate_per_second,
        global_control_rate_burst,
    ]
    .contains(&0)
    {
        return Err("relay rate-limit values must all be greater than 0".to_string());
    }
    let mut args = remaining_args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--bind requires an address like 0.0.0.0:2268".to_string())?;
                bind = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --bind address '{value}'"))?,
                );
            }
            "--relay-address" | "--advertise" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--relay-address requires an IP address".to_string())?;
                let addr: IpAddr = value
                    .parse()
                    .map_err(|_| format!("invalid --relay-address '{value}'"))?;
                validate_relay_address(addr, "--relay-address")?;
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
            "--path-mtu" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--path-mtu requires bytes".to_string())?;
                path_mtu = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --path-mtu '{value}'"))?;
                validate_path_mtu(path_mtu)?;
            }
            "--pmtu-feedback" => pmtu_feedback = true,
            "--no-pmtu-feedback" => pmtu_feedback = false,
            "--ecn" => ecn = true,
            "--no-ecn" => ecn = false,
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

    for address in &relay_addresses {
        validate_relay_address(*address, "relay.relay_address")?;
    }
    if pmtu_feedback && !cfg!(feature = "pmtu-feedback") {
        return Err(
            "PMTU feedback requires building quicast-amt with --features pmtu-feedback".to_string(),
        );
    }
    if pmtu_feedback && upstream_interface.is_none() {
        return Err("PMTU feedback requires --upstream-interface IP".to_string());
    }
    let bind = bind.unwrap_or_else(|| {
        if relay_addresses.iter().any(IpAddr::is_ipv6)
            && !relay_addresses.iter().any(IpAddr::is_ipv4)
        {
            SocketAddr::from(([0u16; 8], AMT_PORT))
        } else {
            SocketAddr::from(([0, 0, 0, 0], AMT_PORT))
        }
    });
    let mut config = RelayConfig::for_bind(bind);
    config.ecn = ecn;
    for addr in relay_addresses {
        config = config.with_advertise_addr(addr);
    }
    if let Some(seconds) = relay_file.and_then(|config| config.secret_rotation_secs) {
        config.secret_rotation_interval = (seconds != 0).then_some(Duration::from_secs(seconds));
    }
    if let Some(limits) = relay_file.and_then(|config| config.limits.as_ref()) {
        apply_relay_limits(&mut config.limits, limits)?;
    }

    let mut relay_daemon = RelayDaemonConfig::new(config);
    relay_daemon.upstream.interface = upstream_interface;
    relay_daemon.upstream.interface_index = upstream_interface_index;
    relay_daemon.gateway_idle_timeout = gateway_idle_timeout;
    relay_daemon.gateway_prune_interval = gateway_prune_interval;
    relay_daemon.path_mtu = path_mtu;
    relay_daemon.pmtu_feedback = pmtu_feedback;
    relay_daemon.control_rate_per_second = control_rate_per_second;
    relay_daemon.control_rate_burst = control_rate_burst;
    relay_daemon.global_control_rate_per_second = global_control_rate_per_second;
    relay_daemon.global_control_rate_burst = global_control_rate_burst;
    relay_daemon.metrics = metrics;
    relay_daemon.validate().map_err(|error| error.to_string())?;

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

    let mut bind = gateway_file.and_then(|config| config.bind);
    let mut ecn = gateway_file.and_then(|config| config.ecn).unwrap_or(false);
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
        if config.ttl.is_some() {
            return Err(DOWNSTREAM_TTL_UNSUPPORTED.to_string());
        }
        let downstream = downstream.get_or_insert_with(DownstreamConfig::default);
        downstream.interface = config.interface;
        downstream.interface_index = config.interface_index;
        if let Some(loopback) = config.loopback {
            downstream.loopback = Some(loopback);
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
    let mut local_reporter_timeout = Duration::from_secs(
        local_file
            .and_then(|config| config.reporter_timeout_secs)
            .unwrap_or(260),
    );
    if local_reporter_timeout.is_zero() {
        return Err("gateway.local_membership.reporter_timeout_secs must not be 0".to_string());
    }
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
                bind = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid --bind address '{value}'"))?,
                );
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
            "--driad-allow-insecure-dns" => driad_options.allow_insecure_dns = true,
            "--driad-max-candidates" => {
                driad_options.max_candidates =
                    parse_nonzero_usize(args.next(), "--driad-max-candidates")?;
            }
            "--driad-max-queries" => {
                driad_options.max_queries_per_window =
                    parse_nonzero_usize(args.next(), "--driad-max-queries")?;
            }
            "--driad-query-window-ms" => {
                driad_options.query_rate_window = Duration::from_millis(parse_nonzero_u64(
                    args.next(),
                    "--driad-query-window-ms",
                )?);
            }
            "--driad-happy-eyeballs-delay-ms" => {
                driad_options.happy_eyeballs_delay = Duration::from_millis(parse_nonzero_u64(
                    args.next(),
                    "--driad-happy-eyeballs-delay-ms",
                )?);
            }
            "--driad-relay-hold-down" => {
                driad_options.relay_hold_down =
                    Duration::from_secs(parse_nonzero_u64(args.next(), "--driad-relay-hold-down")?);
            }
            "--driad-traffic-hold-down" => {
                driad_options.traffic_hold_down = Duration::from_secs(parse_nonzero_u64(
                    args.next(),
                    "--driad-traffic-hold-down",
                )?);
            }
            "--driad-initial-traffic-timeout" => {
                driad_options.initial_traffic_timeout = Duration::from_secs(parse_nonzero_u64(
                    args.next(),
                    "--driad-initial-traffic-timeout",
                )?);
            }
            "--driad-maximum-traffic-timeout" => {
                driad_options.maximum_traffic_timeout = Duration::from_secs(parse_nonzero_u64(
                    args.next(),
                    "--driad-maximum-traffic-timeout",
                )?);
            }
            "--driad-max-source-tunnels" => {
                driad_options.max_source_tunnels =
                    parse_nonzero_usize(args.next(), "--driad-max-source-tunnels")?;
            }
            "--driad-max-concurrent-probes" => {
                driad_options.max_concurrent_probes =
                    parse_nonzero_usize(args.next(), "--driad-max-concurrent-probes")?;
            }
            "--driad-max-dns-workers" => {
                driad_options.max_dns_workers =
                    parse_nonzero_usize(args.next(), "--driad-max-dns-workers")?;
            }
            "--ecn" => ecn = true,
            "--no-ecn" => ecn = false,
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
            "--local-reporter-timeout" => {
                let value = args.next().ok_or_else(|| {
                    "--local-reporter-timeout requires a positive number of seconds".to_string()
                })?;
                let seconds = value
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --local-reporter-timeout '{value}'"))?;
                if seconds == 0 {
                    return Err("--local-reporter-timeout must not be 0".to_string());
                }
                local_reporter_timeout = Duration::from_secs(seconds);
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
                return Err(DOWNSTREAM_TTL_UNSUPPORTED.to_string());
            }
            "--no-downstream-loopback" => {
                downstream
                    .get_or_insert_with(DownstreamConfig::default)
                    .loopback = Some(false);
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

    validate_driad_options(&driad_options)?;

    if group.is_none() && configured_joins.is_empty() && !transparent {
        return Err("gateway requires --group IP unless --transparent is set".to_string());
    }
    if source.is_some() && group.is_none() {
        return Err("--source requires --group".to_string());
    }
    if transparent
        && let Some(interval) = local_query_interval
        && local_reporter_timeout
            < interval
                .saturating_mul(2)
                .saturating_add(Duration::from_secs(10))
    {
        return Err(
            "local reporter timeout must be at least (2 * local query interval) + 10 seconds"
                .to_string(),
        );
    }

    if let Some(group) = group {
        validate_gateway_join(group, source)?;
    }

    let inferred_group = group.or_else(|| configured_joins.first().map(|join| join.group));
    let protocol = protocol.unwrap_or(match inferred_group {
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
    if let Some(interface) = downstream
        .as_ref()
        .and_then(|downstream| downstream.interface)
        && !protocol_matches_address(protocol, interface)
    {
        return Err("--downstream-interface address family must match --protocol".to_string());
    }
    if let Some(downstream) = downstream.as_ref() {
        downstream
            .validate_options_for_protocol(protocol)
            .map_err(|error| error.to_string())?;
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

    let resolved = resolve_gateway_relays(
        relay,
        relay_discovery,
        &joins,
        &driad_options,
        transparent,
        bind,
    )?;
    let mut relays = resolved.relays;
    if relays.len() > 1
        && let Some(bind) = bind
    {
        relays.retain(|relay| same_family(bind.ip(), relay.ip()));
        if relays.is_empty() {
            return Err(
                "gateway discovery returned no relay matching the explicit bind address family"
                    .to_string(),
            );
        }
    }
    for relay in &relays {
        validate_relay_address(relay.ip(), "gateway relay")?;
        if relay.port() == 0 {
            return Err("gateway relay port must not be 0".to_string());
        }
    }
    let relay = relays[0];
    let bind = bind.unwrap_or_else(|| match relay {
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
    });
    if !same_family(bind.ip(), relay.ip()) {
        return Err("gateway bind and relay must use the same outer address family".to_string());
    }
    let gateway = GatewayConfig::new(relay, protocol)
        .with_ecn(ecn)
        .with_fallback_relays(relays.into_iter().skip(1));
    let mut config = GatewayDaemonConfig::new(bind, gateway);
    #[cfg(feature = "driad")]
    {
        config.driad = resolved.driad;
    }
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
        local.reporter_timeout = local_reporter_timeout;
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
    if let Some(bytes) = config.max_file_bytes {
        metrics.max_file_bytes = (bytes != 0).then_some(bytes);
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

fn apply_relay_limits(
    limits: &mut RelayLimits,
    configured: &RelayLimitsFileConfig,
) -> Result<(), String> {
    macro_rules! apply_limit {
        ($field:ident) => {
            if let Some(value) = configured.$field {
                if value == 0 {
                    return Err(
                        concat!("relay.limits.", stringify!($field), " must not be 0").to_string(),
                    );
                }
                limits.$field = value;
            }
        };
    }

    apply_limit!(max_endpoints);
    apply_limit!(max_endpoints_per_ip);
    apply_limit!(max_groups_per_endpoint);
    apply_limit!(max_sources_per_group);
    apply_limit!(max_total_endpoint_groups);
    apply_limit!(max_total_sources);
    apply_limit!(max_upstream_subscriptions);
    apply_limit!(max_records_per_report);
    Ok(())
}

fn validate_path_mtu(path_mtu: usize) -> Result<(), String> {
    if (1_280..=usize::from(u16::MAX)).contains(&path_mtu) {
        Ok(())
    } else {
        Err("relay path MTU must be between 1280 and 65535 bytes".to_string())
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
    if let Some(allow) = config.allow_insecure_dns {
        options.allow_insecure_dns = allow;
    }
    if let Some(value) = config.max_candidates {
        options.max_candidates = value;
    }
    if let Some(value) = config.max_queries_per_window {
        options.max_queries_per_window = value;
    }
    if let Some(value) = config.query_rate_window_ms {
        options.query_rate_window = Duration::from_millis(value);
    }
    if let Some(value) = config.happy_eyeballs_delay_ms {
        options.happy_eyeballs_delay = Duration::from_millis(value);
    }
    if let Some(value) = config.relay_hold_down_secs {
        options.relay_hold_down = Duration::from_secs(value);
    }
    if let Some(value) = config.traffic_hold_down_secs {
        options.traffic_hold_down = Duration::from_secs(value);
    }
    if let Some(value) = config.initial_traffic_timeout_secs {
        options.initial_traffic_timeout = Duration::from_secs(value);
    }
    if let Some(value) = config.maximum_traffic_timeout_secs {
        options.maximum_traffic_timeout = Duration::from_secs(value);
    }
    if let Some(value) = config.max_source_tunnels {
        options.max_source_tunnels = value;
    }
    if let Some(value) = config.max_concurrent_probes {
        options.max_concurrent_probes = value;
    }
    if let Some(value) = config.max_dns_workers {
        options.max_dns_workers = value;
    }

    Ok(options)
}

fn parse_nonzero_u64(value: Option<String>, option: &str) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("{option} requires a positive integer"))?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("invalid {option} value '{value}'"))?;
    (parsed != 0)
        .then_some(parsed)
        .ok_or_else(|| format!("{option} must not be 0"))
}

fn parse_nonzero_usize(value: Option<String>, option: &str) -> Result<usize, String> {
    let value = value.ok_or_else(|| format!("{option} requires a positive integer"))?;
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {option} value '{value}'"))?;
    (parsed != 0)
        .then_some(parsed)
        .ok_or_else(|| format!("{option} must not be 0"))
}

fn validate_driad_options(options: &GatewayDriadOptions) -> Result<(), String> {
    let positive_counts = [
        ("max_candidates", options.max_candidates),
        ("max_queries_per_window", options.max_queries_per_window),
        ("attempts", options.attempts),
        ("max_source_tunnels", options.max_source_tunnels),
        ("max_concurrent_probes", options.max_concurrent_probes),
        ("max_dns_workers", options.max_dns_workers),
    ];
    if let Some((name, _)) = positive_counts.iter().find(|(_, value)| *value == 0) {
        return Err(format!("gateway.driad.{name} must not be 0"));
    }
    let positive_durations = [
        ("timeout_ms", options.timeout),
        ("query_rate_window_ms", options.query_rate_window),
        ("happy_eyeballs_delay_ms", options.happy_eyeballs_delay),
        ("relay_hold_down_secs", options.relay_hold_down),
        ("traffic_hold_down_secs", options.traffic_hold_down),
        (
            "initial_traffic_timeout_secs",
            options.initial_traffic_timeout,
        ),
        (
            "maximum_traffic_timeout_secs",
            options.maximum_traffic_timeout,
        ),
    ];
    if let Some((name, _)) = positive_durations
        .iter()
        .find(|(_, duration)| duration.is_zero())
    {
        return Err(format!("gateway.driad.{name} must not be 0"));
    }
    if options.maximum_traffic_timeout < options.initial_traffic_timeout {
        return Err(
            "gateway.driad.maximum_traffic_timeout_secs must be at least initial_traffic_timeout_secs"
                .to_string(),
        );
    }
    Ok(())
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

fn resolve_gateway_relays(
    relay: Option<SocketAddr>,
    discovery: GatewayRelayDiscovery,
    joins: &[GatewayJoin],
    driad_options: &GatewayDriadOptions,
    transparent: bool,
    bind: Option<SocketAddr>,
) -> Result<ResolvedGatewayRelays, String> {
    match discovery {
        GatewayRelayDiscovery::Static => relay
            .map(ResolvedGatewayRelays::static_relay)
            .ok_or_else(|| "gateway requires --relay ADDRESS:PORT".to_string()),
        GatewayRelayDiscovery::Auto => match relay {
            Some(relay) => Ok(ResolvedGatewayRelays::static_relay(relay)),
            None => resolve_driad_relays(joins, driad_options, transparent, bind, true),
        },
        GatewayRelayDiscovery::Driad => {
            resolve_driad_relays(joins, driad_options, transparent, bind, false)
        }
    }
}

fn resolve_driad_relays(
    joins: &[GatewayJoin],
    driad_options: &GatewayDriadOptions,
    transparent: bool,
    bind: Option<SocketAddr>,
    use_anycast: bool,
) -> Result<ResolvedGatewayRelays, String> {
    if bind.is_some_and(|bind| bind.port() != 0) {
        return Err(
            "DRIAD requires an ephemeral --bind port because each source owns an independent AMT tunnel"
                .to_string(),
        );
    }
    let sources = driad_sources_for_joins(joins, transparent)?;

    #[cfg(feature = "driad")]
    {
        let _ = sources;
        let mut resolver_config = if driad_options.resolvers.is_empty() {
            amt::driad::DriadResolverConfig::system().map_err(|error| {
                format!("failed to load system DNS resolvers for DRIAD: {error}")
            })?
        } else {
            amt::driad::DriadResolverConfig::new(driad_options.resolvers.clone())
        };
        resolver_config.timeout = driad_options.timeout;
        resolver_config.attempts = driad_options.attempts;
        resolver_config.allow_insecure_dns = driad_options.allow_insecure_dns;
        resolver_config.max_candidates = driad_options.max_candidates;
        resolver_config.max_queries_per_window = driad_options.max_queries_per_window;
        resolver_config.query_rate_window = driad_options.query_rate_window;
        let resolver = amt::driad::DriadResolver::new(resolver_config);
        resolver
            .validate()
            .map_err(|error| format!("invalid DRIAD resolver configuration: {error}"))?;
        let relays = vec![match bind.map(|bind| bind.ip()) {
            Some(IpAddr::V6(_)) => SocketAddr::new(amt::AMT_ANYCAST_IPV6.into(), AMT_PORT),
            Some(IpAddr::V4(_)) | None => SocketAddr::new(amt::AMT_ANYCAST_IPV4.into(), AMT_PORT),
        }];
        let mut driad = GatewayDriadConfig::new(resolver);
        driad.bind = bind;
        driad.use_anycast = use_anycast;
        driad.happy_eyeballs_delay = driad_options.happy_eyeballs_delay;
        driad.relay_hold_down = driad_options.relay_hold_down;
        driad.traffic_hold_down = driad_options.traffic_hold_down;
        driad.initial_traffic_timeout = driad_options.initial_traffic_timeout;
        driad.maximum_traffic_timeout = driad_options.maximum_traffic_timeout;
        driad.max_source_tunnels = driad_options.max_source_tunnels;
        driad.max_concurrent_probes = driad_options.max_concurrent_probes;
        driad.max_dns_workers = driad_options.max_dns_workers;
        Ok(ResolvedGatewayRelays {
            relays,
            driad: Some(driad),
        })
    }

    #[cfg(not(feature = "driad"))]
    {
        let _ = sources;
        let _ = driad_options;
        let _ = bind;
        let _ = use_anycast;
        Err("DRIAD relay discovery requires building with --features driad".to_string())
    }
}

fn driad_sources_for_joins(
    joins: &[GatewayJoin],
    transparent: bool,
) -> Result<BTreeSet<IpAddr>, String> {
    if joins.is_empty() && !transparent {
        return Err(
            "DRIAD relay discovery requires a configured SSM --group and --source".to_string(),
        );
    }

    let mut sources = BTreeSet::new();
    for join in joins {
        if !is_ssm_group(join.group) {
            return Err("DRIAD requires groups in the IPv4 or IPv6 SSM range".to_string());
        }
        let Some(source) = join.source else {
            return Err(
                "DRIAD relay discovery requires all configured joins to be SSM joins with a source"
                    .to_string(),
            );
        };
        if !same_family(join.group, source) {
            return Err(
                "DRIAD SSM groups and sources must use the same address family".to_string(),
            );
        }
        if source.is_unspecified() || source.is_multicast() {
            return Err("DRIAD sources must be unicast addresses".to_string());
        }
        sources.insert(source);
    }

    Ok(sources)
}

fn is_ssm_group(group: IpAddr) -> bool {
    match group {
        IpAddr::V4(group) => group.octets()[0] == 232,
        IpAddr::V6(group) => group.segments()[0] & 0xfff0 == 0xff30,
    }
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
    if !amt::is_amt_forwardable_group(group) {
        return Err("gateway join group must be non-link-local multicast".to_string());
    }
    if let Some(source) = source
        && (!same_family(group, source) || !is_valid_source(source))
    {
        return Err(
            "gateway join source must be a unicast address in the same family as group".to_string(),
        );
    }
    Ok(())
}

fn validate_relay_address(address: IpAddr, field: &str) -> Result<(), String> {
    if is_valid_source(address) {
        Ok(())
    } else {
        Err(format!("{field} must be a unicast address"))
    }
}

fn is_valid_source(source: IpAddr) -> bool {
    match source {
        IpAddr::V4(source) => {
            !source.is_unspecified() && !source.is_multicast() && !source.is_broadcast()
        }
        IpAddr::V6(source) => !source.is_unspecified() && !source.is_multicast(),
    }
}

fn print_usage() {
    println!("{}", usage());
}

fn usage() -> &'static str {
    concat!(
        "Usage:\n",
        "  amt relay [--config FILE] [--bind ADDRESS:PORT] [--relay-address IP] ",
        "[--upstream-interface IP] [--upstream-ifindex INDEX] ",
        "[--gateway-idle-timeout SECONDS] [--gateway-prune-interval SECONDS] [--path-mtu BYTES] ",
        "[--pmtu-feedback|--no-pmtu-feedback] ",
        "[--ecn|--no-ecn] ",
        "[--metrics-dir DIR] [--node-id ID] [--metrics-interval-ms MS]\n",
        "  amt gateway [--config FILE] [--relay ADDRESS:PORT] [--relay-discovery static|driad|auto] [--group GROUP] [--source SOURCE] ",
        "[--transparent] [--bind ADDRESS:PORT] [--protocol igmpv3|mldv2] ",
        "[--driad-resolver IP[:PORT]] [--driad-timeout-ms MS] [--driad-attempts COUNT] ",
        "[--driad-allow-insecure-dns] [--driad-max-candidates COUNT] ",
        "[--driad-max-queries COUNT] [--driad-query-window-ms MS] ",
        "[--driad-happy-eyeballs-delay-ms MS] [--driad-relay-hold-down SECONDS] ",
        "[--driad-traffic-hold-down SECONDS] [--driad-initial-traffic-timeout SECONDS] ",
        "[--driad-maximum-traffic-timeout SECONDS] [--driad-max-source-tunnels COUNT] ",
        "[--driad-max-concurrent-probes COUNT] [--driad-max-dns-workers COUNT] ",
        "[--ecn|--no-ecn] ",
        "[--downstream-interface IP] [--downstream-ifindex INDEX] ",
        "[--local-membership-interface IP] [--local-membership-ifindex INDEX] ",
        "[--local-query-interval SECONDS] [--membership-refresh-interval SECONDS] ",
        "[--local-reporter-timeout SECONDS] ",
        "[--no-downstream-loopback] [--no-downstream] ",
        "[--metrics-dir DIR] [--node-id ID] [--metrics-interval-ms MS]\n\n",
        "Relay defaults to 0.0.0.0:2268 and advertises loopback unless --bind uses a concrete IP.\n",
        "Relay prunes idle gateways after 260 seconds by default; pass --gateway-idle-timeout 0 to disable pruning.\n",
        "A non-zero relay gateway idle timeout must exceed the advertised 125-second query interval.\n",
        "Relay SSM PMTU feedback is opt-in and requires the pmtu-feedback Cargo feature plus --upstream-interface.\n",
        "Gateway defaults to an ephemeral local port and forwards raw multicast IP datagrams downstream with mctx-core unless --no-downstream is set.\n",
        "Gateway static relay discovery requires --relay; DRIAD requires SSM interest from configured joins or transparent IGMPv3/MLDv2 and the driad Cargo feature.\n",
        "Gateway auto discovery probes RFC 7450 anycast before source-owned DRIAD candidates when no static relay is configured.\n",
        "Gateway refreshes memberships every 60 seconds by default; 0 retains the 60-second liveness probe.\n",
        "RFC 9601 ECN propagation is opt-in with --ecn; compatibility mode is the default.\n",
        "Use --transparent to learn local IGMPv3/MLDv2 receiver interest instead of requiring a configured --group.\n",
        "Raw downstream forwarding preserves the original IPv4 TTL or IPv6 Hop Limit; downstream overrides are unsupported.\n",
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
            ecn = true
            relay_address = "203.0.113.10"
            upstream_interface = "192.0.2.10"
            gateway_idle_timeout_secs = 260
            path_mtu = 1500

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
            "--no-ecn".to_string(),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(config.relay.bind, "127.0.0.1:9999".parse().unwrap());
        assert_eq!(
            config.upstream.interface,
            Some("192.0.2.10".parse().unwrap())
        );
        assert_eq!(config.gateway_idle_timeout, Some(Duration::from_secs(260)));
        assert_eq!(config.path_mtu, 1500);
        assert!(!config.relay.ecn);
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
            ecn = true

            [gateway.downstream]
            interface = "192.168.1.20"

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
        assert!(config.gateway.ecn);
        assert_eq!(config.joins.len(), 2);
        assert_eq!(
            config
                .downstream
                .as_ref()
                .and_then(|downstream| downstream.interface),
            Some("192.168.1.20".parse().unwrap())
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
    fn ipv6_gateway_infers_ipv6_unspecified_bind() {
        let config = parse_gateway_config([
            "--relay".to_string(),
            "[2001:db8::10]:2268".to_string(),
            "--group".to_string(),
            "ff3e::1234".to_string(),
            "--source".to_string(),
            "2001:db8::20".to_string(),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(config.bind, "[::]:0".parse().unwrap());
        assert_eq!(config.gateway.protocol, MembershipProtocol::Mldv2);
    }

    #[test]
    fn mld_over_ipv4_infers_bind_from_outer_relay_family() {
        let config = parse_gateway_config([
            "--relay".to_string(),
            "203.0.113.10:2268".to_string(),
            "--group".to_string(),
            "ff3e::1234".to_string(),
            "--source".to_string(),
            "2001:db8::20".to_string(),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(config.bind, "0.0.0.0:0".parse().unwrap());
        assert_eq!(config.gateway.protocol, MembershipProtocol::Mldv2);
    }

    #[test]
    fn gateway_rejects_explicit_outer_address_family_mismatch() {
        let error = parse_gateway_config([
            "--bind".to_string(),
            "[::]:0".to_string(),
            "--relay".to_string(),
            "203.0.113.10:2268".to_string(),
            "--group".to_string(),
            "239.1.2.3".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("same outer address family"));
    }

    #[test]
    fn gateway_rejects_downstream_interface_for_wrong_inner_family() {
        let error = parse_gateway_config([
            "--relay".to_string(),
            "203.0.113.10:2268".to_string(),
            "--group".to_string(),
            "ff3e::1234".to_string(),
            "--source".to_string(),
            "2001:db8::20".to_string(),
            "--downstream-interface".to_string(),
            "192.0.2.20".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("downstream-interface address family"));
    }

    #[test]
    fn gateway_rejects_downstream_ttl_for_ipv4() {
        let error = parse_gateway_config([
            "--relay".to_string(),
            "203.0.113.10:2268".to_string(),
            "--group".to_string(),
            "239.1.2.3".to_string(),
            "--downstream-ttl".to_string(),
            "16".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("--downstream-ttl"));
        assert!(error.contains("preserves the complete inner IP header"));
    }

    #[test]
    fn gateway_toml_rejects_downstream_ttl() {
        let path = write_temp_config(
            "gateway_downstream_ttl",
            r#"
            [gateway]
            relay = "203.0.113.10:2268"
            protocol = "igmpv3"
            group = "239.1.2.3"

            [gateway.downstream]
            interface = "192.0.2.20"
            ttl = 16
            "#,
        );

        let error =
            parse_gateway_config(["--config".to_string(), path.display().to_string()]).unwrap_err();
        fs::remove_file(path).unwrap();

        assert!(error.contains("gateway.downstream.ttl"));
        assert!(error.contains("set the IPv4 TTL or IPv6 Hop Limit at the multicast source"));
    }

    #[test]
    fn gateway_toml_rejects_loopback_for_full_header_ipv6() {
        let path = write_temp_config(
            "gateway_ipv6_loopback",
            r#"
            [gateway]
            relay = "203.0.113.10:2268"
            protocol = "mldv2"
            group = "ff3e::1234"
            source = "2001:db8::20"

            [gateway.downstream]
            interface = "2001:db8::30"
            loopback = true
            "#,
        );

        let error =
            parse_gateway_config(["--config".to_string(), path.display().to_string()]).unwrap_err();
        fs::remove_file(path).unwrap();

        assert!(error.contains("loopback=true"));
        assert!(error.contains("full-header IPv6"));
    }

    #[test]
    fn relay_path_mtu_defaults_to_common_ethernet_mtu() {
        let config = parse_relay_config(std::iter::empty()).unwrap().unwrap();

        assert_eq!(config.path_mtu, 1_500);
        assert!(!config.pmtu_feedback);
    }

    #[test]
    fn relay_rejects_idle_timeout_not_above_the_query_interval() {
        let error = parse_relay_config(["--gateway-idle-timeout".to_string(), "125".to_string()])
            .unwrap_err();
        assert!(error.contains("must be greater than"));

        let disabled = parse_relay_config(["--gateway-idle-timeout".to_string(), "0".to_string()])
            .unwrap()
            .unwrap();
        assert_eq!(disabled.gateway_idle_timeout, None);
    }

    #[cfg(feature = "pmtu-feedback")]
    #[test]
    fn relay_pmtu_feedback_requires_and_uses_upstream_interface() {
        let missing = parse_relay_config(["--pmtu-feedback".to_string()]).unwrap_err();
        assert!(missing.contains("upstream-interface"));

        let config = parse_relay_config([
            "--upstream-interface".to_string(),
            "192.0.2.10".to_string(),
            "--pmtu-feedback".to_string(),
        ])
        .unwrap()
        .unwrap();
        assert!(config.pmtu_feedback);
    }

    #[cfg(not(feature = "pmtu-feedback"))]
    #[test]
    fn relay_pmtu_feedback_rejects_a_binary_without_support() {
        let error = parse_relay_config([
            "--upstream-interface".to_string(),
            "192.0.2.10".to_string(),
            "--pmtu-feedback".to_string(),
        ])
        .unwrap_err();

        assert!(error.contains("--features pmtu-feedback"));
    }

    #[test]
    fn ipv6_only_relay_address_infers_ipv6_bind() {
        let config =
            parse_relay_config(["--relay-address".to_string(), "2001:db8::10".to_string()])
                .unwrap()
                .unwrap();

        assert_eq!(config.relay.bind, "[::]:2268".parse().unwrap());
        assert_eq!(
            config.relay.advertise_ipv6,
            "2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn driad_source_selection_supports_transparent_and_multiple_sources() {
        assert!(driad_sources_for_joins(&[], false).is_err());
        assert!(driad_sources_for_joins(&[], true).unwrap().is_empty());
        assert!(
            driad_sources_for_joins(
                &[GatewayJoin {
                    group: "239.1.2.3".parse().unwrap(),
                    source: None,
                }],
                false,
            )
            .is_err()
        );
        assert!(
            driad_sources_for_joins(
                &[GatewayJoin {
                    group: "239.1.2.3".parse().unwrap(),
                    source: Some("192.0.2.10".parse().unwrap()),
                }],
                false,
            )
            .is_err()
        );
        assert!(
            driad_sources_for_joins(
                &[GatewayJoin {
                    group: "ff3e::1234".parse().unwrap(),
                    source: Some("192.0.2.10".parse().unwrap()),
                }],
                false,
            )
            .is_err()
        );

        let sources = driad_sources_for_joins(
            &[
                GatewayJoin {
                    group: "232.1.2.3".parse().unwrap(),
                    source: Some("192.0.2.10".parse().unwrap()),
                },
                GatewayJoin {
                    group: "232.1.2.4".parse().unwrap(),
                    source: Some("192.0.2.11".parse().unwrap()),
                },
                GatewayJoin {
                    group: "232.1.2.5".parse().unwrap(),
                    source: Some("192.0.2.10".parse().unwrap()),
                },
            ],
            false,
        )
        .unwrap();
        assert_eq!(
            sources,
            BTreeSet::from(["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()])
        );
    }

    #[test]
    fn driad_source_selection_rejects_non_unicast_sources() {
        assert!(
            driad_sources_for_joins(
                &[GatewayJoin {
                    group: "232.1.2.3".parse().unwrap(),
                    source: Some("0.0.0.0".parse().unwrap()),
                }],
                false
            )
            .is_err()
        );
        assert!(
            driad_sources_for_joins(
                &[GatewayJoin {
                    group: "232.1.2.3".parse().unwrap(),
                    source: Some("232.2.3.4".parse().unwrap()),
                }],
                false
            )
            .is_err()
        );
    }

    #[cfg(feature = "driad")]
    #[test]
    fn driad_cli_applies_runtime_and_resource_controls() {
        let config = parse_gateway_config([
            "--relay-discovery".to_string(),
            "driad".to_string(),
            "--driad-resolver".to_string(),
            "127.0.0.1:53".to_string(),
            "--group".to_string(),
            "232.1.2.3".to_string(),
            "--source".to_string(),
            "192.0.2.10".to_string(),
            "--driad-max-candidates".to_string(),
            "12".to_string(),
            "--driad-max-queries".to_string(),
            "7".to_string(),
            "--driad-query-window-ms".to_string(),
            "150".to_string(),
            "--driad-happy-eyeballs-delay-ms".to_string(),
            "200".to_string(),
            "--driad-relay-hold-down".to_string(),
            "500".to_string(),
            "--driad-traffic-hold-down".to_string(),
            "240".to_string(),
            "--driad-initial-traffic-timeout".to_string(),
            "5".to_string(),
            "--driad-maximum-traffic-timeout".to_string(),
            "90".to_string(),
            "--driad-max-source-tunnels".to_string(),
            "64".to_string(),
            "--driad-max-concurrent-probes".to_string(),
            "3".to_string(),
            "--driad-max-dns-workers".to_string(),
            "4".to_string(),
        ])
        .unwrap()
        .unwrap();

        let driad = config.driad.unwrap();
        assert_eq!(driad.resolver.config().max_candidates, 12);
        assert_eq!(driad.resolver.config().max_queries_per_window, 7);
        assert_eq!(
            driad.resolver.config().query_rate_window,
            Duration::from_millis(150)
        );
        assert_eq!(driad.happy_eyeballs_delay, Duration::from_millis(200));
        assert_eq!(driad.relay_hold_down, Duration::from_secs(500));
        assert_eq!(driad.traffic_hold_down, Duration::from_secs(240));
        assert_eq!(driad.initial_traffic_timeout, Duration::from_secs(5));
        assert_eq!(driad.maximum_traffic_timeout, Duration::from_secs(90));
        assert_eq!(driad.max_source_tunnels, 64);
        assert_eq!(driad.max_concurrent_probes, 3);
        assert_eq!(driad.max_dns_workers, 4);
    }

    #[cfg(feature = "driad")]
    #[test]
    fn transparent_driad_does_not_require_a_seed_source() {
        let config = parse_gateway_config([
            "--relay-discovery".to_string(),
            "auto".to_string(),
            "--driad-resolver".to_string(),
            "127.0.0.1:53".to_string(),
            "--transparent".to_string(),
            "--protocol".to_string(),
            "igmpv3".to_string(),
        ])
        .unwrap()
        .unwrap();

        assert!(config.joins.is_empty());
        assert!(config.local_membership.is_some());
        assert!(config.driad.as_ref().unwrap().use_anycast);
    }

    #[test]
    fn driad_rejects_invalid_advanced_limits() {
        let zero = parse_gateway_config([
            "--relay-discovery".to_string(),
            "driad".to_string(),
            "--group".to_string(),
            "232.1.2.3".to_string(),
            "--source".to_string(),
            "192.0.2.10".to_string(),
            "--driad-max-dns-workers".to_string(),
            "0".to_string(),
        ])
        .unwrap_err();
        assert!(zero.contains("must not be 0"));

        let inverted = parse_gateway_config([
            "--relay-discovery".to_string(),
            "driad".to_string(),
            "--group".to_string(),
            "232.1.2.3".to_string(),
            "--source".to_string(),
            "192.0.2.10".to_string(),
            "--driad-initial-traffic-timeout".to_string(),
            "30".to_string(),
            "--driad-maximum-traffic-timeout".to_string(),
            "10".to_string(),
        ])
        .unwrap_err();
        assert!(inverted.contains("must be at least"));
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
