use crate::downstream::{DownstreamConfig, DownstreamPublisher};
#[cfg(feature = "driad")]
use crate::driad::{
    AMT_ANYCAST_IPV4, AMT_ANYCAST_IPV6, AmtRelayRecord, AmtRelayTarget, DriadError,
    DriadRelaySelection, DriadResolver,
};
use crate::ecn::{EcnCodepoint, ip_ecn};
use crate::gateway::{Gateway, GatewayAction, GatewayConfig};
use crate::local_membership::{LocalMembershipConfig, LocalMembershipManager};
use crate::membership::{MembershipRecord, MembershipRecordKind, MembershipReport};
use crate::metrics::{
    GatewayMetricsGauges, MetricsConfig, MetricsFlags, MetricsRecorder, RelayMetricsGauges,
    base_flags,
};
use crate::mtu::{Ipv4FragmentError, fragment_ipv4_for_tunnel};
#[cfg(feature = "pmtu-feedback")]
use crate::pmtu::{PmtuFeedbackOutcome, PmtuFeedbackSender};
use crate::protocol::{MembershipProtocol, Message};
use crate::query::query_interval;
use crate::relay::{Relay, RelayAction, RelayConfig, RelayError};
use crate::state::{FilterMode, RelayState};
use crate::udp::{AmtUdpSocket, SocketBufferSizes};
use crate::upstream::{UpstreamConfig, UpstreamDatagram};
use crate::upstream_worker::{UpstreamWorker, UpstreamWorkerSnapshot};
use polling::{Events, Poller};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
#[cfg(feature = "driad")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "driad")]
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

const MAX_UDP_DATAGRAM: usize = 65_535;
const MAX_CONTROL_DRAIN: usize = 128;
const MAX_RELAY_DATA_DRAIN: usize = 512;
const MAX_LOCAL_MEMBERSHIP_DRAIN: usize = 64;
const MAX_RATE_LIMIT_SOURCES: usize = 65_536;
const IDLE_SLEEP: Duration = Duration::from_millis(10);
const RELAY_DATA_FAIRNESS_BUDGET: Duration = Duration::from_millis(2);
const RELAY_IDLE_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(1);
const RELAY_TUNNEL_SOCKET_EVENT: usize = 1;
const DATA_LOG_INTERVAL: Duration = Duration::from_secs(5);
const GATEWAY_RETRY_INITIAL: Duration = Duration::from_secs(1);
const GATEWAY_RETRY_MAX: Duration = Duration::from_secs(120);
const GATEWAY_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_REPORTER_PRUNE_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(feature = "driad")]
const DRIAD_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(feature = "driad")]
const DRIAD_MAX_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
pub const DEFAULT_GATEWAY_IDLE_TIMEOUT: Duration = Duration::from_secs(260);
pub const DEFAULT_GATEWAY_PRUNE_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_RELAY_PATH_MTU: usize = 1_500;
pub const DEFAULT_MEMBERSHIP_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_CONTROL_RATE_PER_SECOND: u32 = 10;
pub const DEFAULT_CONTROL_RATE_BURST: u32 = 20;
pub const DEFAULT_GLOBAL_CONTROL_RATE_PER_SECOND: u32 = 1_000;
pub const DEFAULT_GLOBAL_CONTROL_RATE_BURST: u32 = 2_000;
pub const DEFAULT_DRIAD_MAX_SOURCE_TUNNELS: usize = 256;
pub const DEFAULT_DRIAD_MAX_CONCURRENT_PROBES: usize = 4;
pub const DEFAULT_DRIAD_MAX_DNS_WORKERS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDaemonConfig {
    pub relay: RelayConfig,
    pub upstream: UpstreamConfig,
    pub gateway_idle_timeout: Option<Duration>,
    pub gateway_prune_interval: Duration,
    pub path_mtu: usize,
    pub pmtu_feedback: bool,
    pub control_rate_per_second: u32,
    pub control_rate_burst: u32,
    pub global_control_rate_per_second: u32,
    pub global_control_rate_burst: u32,
    pub metrics: MetricsConfig,
}

impl RelayDaemonConfig {
    pub fn new(relay: RelayConfig) -> Self {
        Self {
            relay,
            upstream: UpstreamConfig::default(),
            gateway_idle_timeout: Some(DEFAULT_GATEWAY_IDLE_TIMEOUT),
            gateway_prune_interval: DEFAULT_GATEWAY_PRUNE_INTERVAL,
            path_mtu: DEFAULT_RELAY_PATH_MTU,
            pmtu_feedback: false,
            control_rate_per_second: DEFAULT_CONTROL_RATE_PER_SECOND,
            control_rate_burst: DEFAULT_CONTROL_RATE_BURST,
            global_control_rate_per_second: DEFAULT_GLOBAL_CONTROL_RATE_PER_SECOND,
            global_control_rate_burst: DEFAULT_GLOBAL_CONTROL_RATE_BURST,
            metrics: MetricsConfig::default(),
        }
    }

    /// Validates daemon-level invariants required by RFC 7450.
    pub fn validate(&self) -> io::Result<()> {
        if let Some(timeout) = self.gateway_idle_timeout {
            let advertised_interval = query_interval(self.relay.general_query.query_interval_code);
            if timeout <= advertised_interval {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "gateway idle timeout ({timeout:?}) must be greater than the advertised query interval ({advertised_interval:?})"
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl Default for RelayDaemonConfig {
    fn default() -> Self {
        Self::new(RelayConfig::default())
    }
}

impl From<RelayConfig> for RelayDaemonConfig {
    fn from(value: RelayConfig) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayJoin {
    pub group: IpAddr,
    pub source: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayDaemonConfig {
    pub bind: SocketAddr,
    pub gateway: GatewayConfig,
    pub joins: Vec<GatewayJoin>,
    pub downstream: Option<DownstreamConfig>,
    pub local_membership: Option<LocalMembershipConfig>,
    pub membership_refresh_interval: Option<Duration>,
    #[cfg(feature = "driad")]
    pub driad: Option<GatewayDriadConfig>,
    pub metrics: MetricsConfig,
}

#[cfg(feature = "driad")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayDriadConfig {
    pub resolver: DriadResolver,
    /// Explicit local address for all DRIAD tunnel sockets; port must be zero.
    pub bind: Option<SocketAddr>,
    /// Probe RFC 7450 well-known anycast before source-owned AMTRELAY records.
    pub use_anycast: bool,
    pub happy_eyeballs_delay: Duration,
    pub relay_hold_down: Duration,
    pub traffic_hold_down: Duration,
    pub initial_traffic_timeout: Duration,
    pub maximum_traffic_timeout: Duration,
    /// Maximum number of independently discovered source tunnels.
    pub max_source_tunnels: usize,
    /// Maximum number of simultaneous relay probes for one source.
    pub max_concurrent_probes: usize,
    /// Maximum number of simultaneous blocking DNS resolver workers.
    pub max_dns_workers: usize,
}

#[cfg(feature = "driad")]
impl GatewayDriadConfig {
    pub fn new(resolver: DriadResolver) -> Self {
        Self {
            resolver,
            bind: None,
            use_anycast: false,
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

    pub fn validate(&self) -> io::Result<()> {
        self.resolver.validate().map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid DRIAD resolver configuration: {error}"),
            )
        })?;
        if self.bind.is_some_and(|bind| bind.port() != 0) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "DRIAD tunnel bind port must be zero",
            ));
        }
        if self.happy_eyeballs_delay.is_zero()
            || self.relay_hold_down.is_zero()
            || self.traffic_hold_down.is_zero()
            || self.initial_traffic_timeout.is_zero()
            || self.maximum_traffic_timeout.is_zero()
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "DRIAD timers must not be zero",
            ));
        }
        if self.maximum_traffic_timeout < self.initial_traffic_timeout {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "DRIAD maximum traffic timeout must not be shorter than its initial timeout",
            ));
        }
        if self.max_source_tunnels == 0
            || self.max_concurrent_probes == 0
            || self.max_dns_workers == 0
        {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "DRIAD resource limits must not be zero",
            ));
        }
        Ok(())
    }
}

impl GatewayDaemonConfig {
    pub fn new(bind: SocketAddr, gateway: GatewayConfig) -> Self {
        Self {
            bind,
            gateway,
            joins: Vec::new(),
            downstream: Some(DownstreamConfig::default()),
            local_membership: None,
            membership_refresh_interval: Some(DEFAULT_MEMBERSHIP_REFRESH_INTERVAL),
            #[cfg(feature = "driad")]
            driad: None,
            metrics: MetricsConfig::default(),
        }
    }

    pub fn validate(&self) -> io::Result<()> {
        if let Some(local) = self.local_membership.as_ref() {
            if local.protocol != self.gateway.protocol {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "local membership protocol must match the AMT gateway protocol",
                ));
            }

            if let Some(downstream) = self.downstream.as_ref()
                && local.query_interval.is_some()
            {
                let has_query_source = matches!(
                    (local.protocol, local.interface),
                    (MembershipProtocol::Igmpv3, Some(IpAddr::V4(address)))
                        if !address.is_unspecified()
                ) || matches!(
                    (local.protocol, local.interface),
                    (MembershipProtocol::Mldv2, Some(IpAddr::V6(address)))
                        if !address.is_unspecified()
                );
                if !has_query_source {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "transparent local queries require an address-valued \
                         --local-membership-interface (or --downstream-interface) matching the \
                         protocol; use --local-query-interval 0 to disable active queries",
                    ));
                }

                if local.protocol == MembershipProtocol::Mldv2
                    && downstream.uses_route_selected_egress()
                {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "MLDv2 General Queries target link-local ff02::1 and require an explicit \
                         --downstream-interface or --downstream-ifindex; route-selected downstream \
                         egress remains available when --local-query-interval is 0",
                    ));
                }
            }
        }

        if let Some(downstream) = self.downstream.as_ref() {
            downstream
                .validate_for_protocol(self.gateway.protocol)
                .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        }
        Ok(())
    }
}

/// Runs a small blocking AMT relay daemon.
pub fn run_relay(config: impl Into<RelayDaemonConfig>) -> io::Result<()> {
    let config = config.into();
    config.validate()?;
    let metrics_config = config.metrics.clone();
    let socket = AmtUdpSocket::bind_relay(config.relay.bind, config.relay.ecn)?;
    let poller = Arc::new(Poller::new()?);
    let socket_registration =
        socket.register_readable(poller.as_ref(), RELAY_TUNNEL_SOCKET_EVENT)?;
    let shutdown = ShutdownSignal::install_with_poller(Arc::clone(&poller))?;

    let rate_source_capacity = config
        .relay
        .limits
        .max_endpoints
        .clamp(1_024, MAX_RATE_LIMIT_SOURCES);
    let upstream_subscription_limit = config.relay.limits.max_upstream_subscriptions;
    let mut relay = Relay::new(config.relay);
    let mut pmtu_feedback = RelayPmtuFeedback::new(config.pmtu_feedback, &config.upstream)?;
    let upstream = UpstreamWorker::spawn(
        config.upstream,
        upstream_subscription_limit,
        Arc::clone(&poller),
    )?;
    let mut gateway_activity = GatewayActivity::default();
    let mut metrics = MetricsRecorder::relay(
        &metrics_config,
        relay_metrics_flags(
            &metrics_config,
            socket.local_addr()?,
            &relay,
            &upstream,
            config.path_mtu,
            config.pmtu_feedback,
            socket.buffer_sizes(),
        ),
    )?;
    let mut last_gateway_prune = Instant::now();
    let mut data_log = RelayDataLog::new();
    let mut error_log = ErrorSummary::new("relay control-plane errors");
    let mut rate_limiter = ControlRateLimiter::new(
        config.control_rate_per_second,
        config.control_rate_burst,
        config.global_control_rate_per_second,
        config.global_control_rate_burst,
        rate_source_capacity,
    );
    println!(
        "amt relay listening on {} (advertising IPv4 {}, IPv6 {})",
        socket.local_addr()?,
        relay.config().advertise_ipv4,
        relay.config().advertise_ipv6
    );
    let socket_buffers = socket.buffer_sizes();
    println!(
        "relay tunnel socket buffers: receive={} bytes send={} bytes; upstream queue={} packets",
        socket_buffers.receive,
        socket_buffers.send,
        crate::upstream_worker::UPSTREAM_PACKET_QUEUE_CAPACITY
    );
    report_metrics_status(&metrics, &metrics_config);

    let mut buf = [0; MAX_UDP_DATAGRAM];
    let mut events = Events::new();
    let mut accounted_worker = UpstreamWorkerSnapshot::default();
    let run_result = (|| -> io::Result<()> {
        loop {
            if shutdown.requested() {
                println!("shutdown requested; stopping AMT relay");
                return Ok(());
            }

            let mut control_drained = 0;
            for _ in 0..MAX_CONTROL_DRAIN {
                match socket.recv_from(&mut buf) {
                    Ok((len, peer, _outer_ecn)) => {
                        control_drained += 1;
                        if !rate_limiter.allow(peer.ip()) {
                            metrics.counters_mut().control_datagrams_received_total += 1;
                            metrics.counters_mut().control_datagrams_rate_limited_total += 1;
                            continue;
                        }
                        handle_amt_datagram(
                            RelayControlPlane {
                                socket: &socket,
                                relay: &mut relay,
                                upstream: &upstream,
                                gateway_activity: &mut gateway_activity,
                                metrics: &mut metrics,
                                error_log: &mut error_log,
                            },
                            peer,
                            &buf[..len],
                        )?;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
            socket_registration.rearm()?;

            if last_gateway_prune.elapsed() >= config.gateway_prune_interval {
                let expired = config.gateway_idle_timeout.map_or(0, |timeout| {
                    prune_stale_gateways(&mut relay, &mut gateway_activity, timeout)
                });
                if expired != 0 {
                    metrics.counters_mut().gateways_expired_total += expired as u64;
                    println!(
                        "expired {expired} idle gateway(s); active gateways={}",
                        gateway_activity.len()
                    );
                }
                if let Err(error) = sync_upstream(relay.state(), &upstream, &mut metrics) {
                    error_log.record(error.to_string());
                }
                last_gateway_prune = Instant::now();
            }

            let worker_snapshot = upstream.snapshot();
            account_upstream_worker(
                worker_snapshot,
                &mut accounted_worker,
                &mut metrics,
                &mut data_log,
            );
            upstream.check_failure()?;

            let drain = drain_upstream(
                &socket,
                &relay,
                &upstream,
                config.path_mtu,
                &mut pmtu_feedback,
                &mut metrics,
                &mut data_log,
            )?;
            let worker_snapshot = upstream.snapshot();
            account_upstream_worker(
                worker_snapshot,
                &mut accounted_worker,
                &mut metrics,
                &mut data_log,
            );
            upstream.check_failure()?;

            if let Err(error) = metrics.maybe_emit_relay(RelayMetricsGauges {
                active_gateways: gateway_activity.len() as u64,
                active_upstream_subscriptions: worker_snapshot.active_subscriptions as u64,
                upstream_capture_sockets: worker_snapshot.capture_sockets as u64,
                upstream_queue_depth: worker_snapshot.queue_depth as u64,
                upstream_queue_high_water: worker_snapshot.queue_high_water as u64,
            }) {
                eprintln!("failed to write relay metrics sample: {error}");
            }
            data_log.maybe_emit();
            error_log.maybe_emit();

            if control_drained == MAX_CONTROL_DRAIN
                || drain.budget_exhausted
                || worker_snapshot.queue_depth != 0
            {
                continue;
            }

            events.clear();
            poller.wait(
                &mut events,
                Some(relay_wait_timeout(
                    last_gateway_prune,
                    config.gateway_prune_interval,
                    &metrics,
                )),
            )?;
        }
    })();

    drop(socket_registration);
    let shutdown_result = upstream.shutdown();
    run_result.and(shutdown_result)
}

/// Runs a small blocking AMT gateway daemon.
pub fn run_gateway(config: GatewayDaemonConfig) -> io::Result<()> {
    config.validate()?;

    #[cfg(feature = "driad")]
    if config.driad.is_some() {
        return run_driad_gateway(config);
    }
    run_static_gateway(config)
}

fn initialize_downstream(
    config: Option<DownstreamConfig>,
    protocol: crate::protocol::MembershipProtocol,
) -> io::Result<Option<DownstreamPublisher>> {
    config
        .map(|config| {
            DownstreamPublisher::try_new(config, protocol).map_err(|error| {
                io::Error::other(format!(
                    "failed to initialize downstream forwarding: {error}"
                ))
            })
        })
        .transpose()
}

#[cfg(feature = "driad")]
fn run_driad_gateway(mut config: GatewayDaemonConfig) -> io::Result<()> {
    let driad = config
        .driad
        .take()
        .expect("DRIAD gateway runner requires DRIAD configuration");
    driad.validate()?;
    let protocol = config.gateway.protocol;
    let ecn = config.gateway.ecn;
    let metrics_config = config.metrics.clone();
    let configured_joins = config.joins.len() as u64;
    let transparent_enabled = config.local_membership.is_some();
    let downstream_enabled = config.downstream.is_some();
    let mut downstream = initialize_downstream(config.downstream, protocol)?;
    let shutdown = ShutdownSignal::install()?;
    let mut local_membership = match config.local_membership {
        Some(local_config) => Some(LocalMembershipManager::new(local_config).map_err(|error| {
            io::Error::other(format!(
                "failed to start local membership listener: {error}"
            ))
        })?),
        None => None,
    };
    let template_gateway = Gateway::new(config.gateway);
    let mut metrics = MetricsRecorder::gateway(
        &metrics_config,
        gateway_metrics_flags(
            &metrics_config,
            config.bind,
            &template_gateway,
            downstream_enabled,
            transparent_enabled,
            configured_joins,
        ),
    )?;
    let mut tunnels = BTreeMap::<IpAddr, DriadSourceTunnel>::new();
    let resolver_workers = DriadWorkerPool::new(driad.max_dns_workers);
    let mut last_local_query: Option<Instant> = None;
    let mut last_local_prune = Instant::now();
    let mut interest_warnings = (0, 0);
    let mut data_log = GatewayDataLog::new();

    reconcile_driad_tunnels(
        &mut tunnels,
        DriadReconcileContext {
            config: &driad,
            protocol,
            ecn,
            joins: &config.joins,
            local: local_membership.as_ref(),
            metrics: &mut metrics,
            last_warnings: &mut interest_warnings,
            resolver_workers: &resolver_workers,
        },
    )?;

    println!(
        "amt DRIAD gateway active with {} source-specific tunnel(s)",
        tunnels.len()
    );
    if let Some(local) = local_membership.as_ref() {
        println!(
            "transparent local membership listening for {:?} reports",
            local.config().protocol
        );
    }
    report_metrics_status(&metrics, &metrics_config);

    loop {
        let mut made_progress = false;
        if shutdown.requested() {
            for tunnel in tunnels.values_mut() {
                tunnel.shutdown(&mut metrics);
            }
            return Ok(());
        }

        if let Some(local) = local_membership.as_ref()
            && let Some(interval) = local.config().query_interval
            && last_local_query.is_none_or(|last| last.elapsed() >= interval)
        {
            if let Some(downstream) = downstream.as_mut() {
                if let Err(error) = send_local_membership_query(downstream, local) {
                    metrics.counters_mut().downstream_forward_errors_total += 1;
                    eprintln!("failed to send local membership query: {error}");
                } else {
                    metrics.counters_mut().local_queries_sent_total += 1;
                }
            }
            last_local_query = Some(Instant::now());
            made_progress = true;
        }

        if let Some(local) = local_membership.as_mut() {
            let events = drain_local_membership_state(local, &mut metrics)?;
            if events != 0 {
                reconcile_driad_tunnels(
                    &mut tunnels,
                    DriadReconcileContext {
                        config: &driad,
                        protocol,
                        ecn,
                        joins: &config.joins,
                        local: Some(local),
                        metrics: &mut metrics,
                        last_warnings: &mut interest_warnings,
                        resolver_workers: &resolver_workers,
                    },
                )?;
                made_progress = true;
            }
            if last_local_prune.elapsed() >= LOCAL_REPORTER_PRUNE_INTERVAL {
                let expired = local.prune_stale_reporters();
                if expired != 0 {
                    reconcile_driad_tunnels(
                        &mut tunnels,
                        DriadReconcileContext {
                            config: &driad,
                            protocol,
                            ecn,
                            joins: &config.joins,
                            local: Some(local),
                            metrics: &mut metrics,
                            last_warnings: &mut interest_warnings,
                            resolver_workers: &resolver_workers,
                        },
                    )?;
                    made_progress = true;
                }
                last_local_prune = Instant::now();
            }
        }

        for tunnel in tunnels.values_mut() {
            made_progress |= tunnel.poll(
                downstream.as_mut(),
                &mut metrics,
                &mut data_log,
                config
                    .membership_refresh_interval
                    .unwrap_or(DEFAULT_MEMBERSHIP_REFRESH_INTERVAL),
            )?;
        }

        match metrics.maybe_emit_gateway(GatewayMetricsGauges {
            relay_connected: tunnels.values().any(DriadSourceTunnel::is_active),
            downstream_enabled,
            transparent_enabled,
            configured_joins,
            driad_source_tunnels: tunnels.len() as u64,
            driad_active_tunnels: tunnels.values().filter(|tunnel| tunnel.is_active()).count()
                as u64,
            driad_candidate_probes: tunnels
                .values()
                .map(|tunnel| tunnel.probe_count())
                .sum::<usize>() as u64,
            driad_held_down_relays: tunnels
                .values()
                .map(|tunnel| tunnel.hold_down_count())
                .sum::<usize>() as u64,
        }) {
            Ok(emitted) => made_progress |= emitted,
            Err(error) => eprintln!("failed to write gateway metrics sample: {error}"),
        }
        data_log.maybe_emit();
        if !made_progress {
            thread::sleep(IDLE_SLEEP);
        }
    }
}

#[cfg(feature = "driad")]
struct DriadReconcileContext<'a> {
    config: &'a GatewayDriadConfig,
    protocol: crate::protocol::MembershipProtocol,
    ecn: bool,
    joins: &'a [GatewayJoin],
    local: Option<&'a LocalMembershipManager>,
    metrics: &'a mut MetricsRecorder,
    last_warnings: &'a mut (usize, usize),
    resolver_workers: &'a DriadWorkerPool,
}

#[cfg(feature = "driad")]
fn reconcile_driad_tunnels(
    tunnels: &mut BTreeMap<IpAddr, DriadSourceTunnel>,
    context: DriadReconcileContext<'_>,
) -> io::Result<()> {
    let DriadReconcileContext {
        config,
        protocol,
        ecn,
        joins,
        local,
        metrics,
        last_warnings,
        resolver_workers,
    } = context;
    let (reports, unsupported) = desired_driad_reports(protocol, joins, local);

    let removed = tunnels
        .keys()
        .filter(|source| !reports.contains_key(source))
        .copied()
        .collect::<Vec<_>>();
    for source in removed {
        if let Some(mut tunnel) = tunnels.remove(&source) {
            tunnel.shutdown(metrics);
        }
    }
    let mut over_limit = 0;
    for (source, report) in reports {
        if let Some(tunnel) = tunnels.get_mut(&source) {
            tunnel.set_desired(report, metrics);
            continue;
        }
        if tunnels.len() >= config.max_source_tunnels {
            over_limit += 1;
            continue;
        }
        tunnels.insert(
            source,
            DriadSourceTunnel::new(
                source,
                protocol,
                ecn,
                config,
                resolver_workers.clone(),
                report,
            ),
        );
    }
    if (unsupported, over_limit) != *last_warnings {
        if unsupported != 0 {
            eprintln!(
                "DRIAD ignored {unsupported} non-SSM or ASM membership record(s); configure a static relay for those groups"
            );
        }
        if over_limit != 0 {
            eprintln!(
                "DRIAD ignored {over_limit} source(s) above the configured {}-tunnel limit",
                config.max_source_tunnels
            );
        }
        *last_warnings = (unsupported, over_limit);
    }
    Ok(())
}

#[cfg(feature = "driad")]
fn desired_driad_reports(
    protocol: crate::protocol::MembershipProtocol,
    joins: &[GatewayJoin],
    local: Option<&LocalMembershipManager>,
) -> (BTreeMap<IpAddr, MembershipReport>, usize) {
    let desired = desired_membership_report(protocol, joins, local);
    let mut records = BTreeMap::<IpAddr, Vec<MembershipRecord>>::new();
    let mut unsupported = 0;
    for record in desired.records {
        if record.kind != MembershipRecordKind::ModeIsInclude
            || !is_ssm_multicast_group(record.group)
        {
            unsupported += 1;
            continue;
        }
        for source in record.sources {
            records.entry(source).or_default().push(MembershipRecord {
                kind: MembershipRecordKind::ModeIsInclude,
                group: record.group,
                sources: vec![source],
            });
        }
    }
    (
        records
            .into_iter()
            .map(|(source, records)| (source, MembershipReport { protocol, records }))
            .collect(),
        unsupported,
    )
}

#[cfg(feature = "driad")]
fn is_ssm_multicast_group(group: IpAddr) -> bool {
    match group {
        IpAddr::V4(group) => group.octets()[0] == 232,
        IpAddr::V6(group) => group.segments()[0] & 0xfff0 == 0xff30,
    }
}

#[cfg(feature = "driad")]
fn drain_local_membership_state(
    local: &mut LocalMembershipManager,
    metrics: &mut MetricsRecorder,
) -> io::Result<usize> {
    let mut events = 0;
    for _ in 0..MAX_LOCAL_MEMBERSHIP_DRAIN {
        match local.try_recv() {
            Ok(Some(event)) => {
                events += 1;
                metrics.counters_mut().local_membership_reports_total += 1;
                println!(
                    "local membership report from {} ({} records, {} active subscriptions)",
                    event.reporter,
                    event.records_received,
                    event.active_subscriptions.len()
                );
            }
            Ok(None) => break,
            Err(error) if error.is_parse_error() => {
                events += 1;
                metrics.counters_mut().local_membership_parse_errors_total += 1;
                eprintln!("invalid local membership report: {error}");
            }
            Err(error) => {
                return Err(io::Error::other(format!(
                    "failed to receive local membership report: {error}"
                )));
            }
        }
    }
    Ok(events)
}

fn run_static_gateway(config: GatewayDaemonConfig) -> io::Result<()> {
    let protocol = config.gateway.protocol;
    let metrics_config = config.metrics.clone();
    let configured_joins = config.joins.len() as u64;
    let transparent_enabled = config.local_membership.is_some();
    let downstream_enabled = config.downstream.is_some();
    let mut downstream = initialize_downstream(config.downstream, protocol)?;
    let socket = AmtUdpSocket::bind(config.bind, config.gateway.ecn)?;
    let shutdown = ShutdownSignal::install()?;

    let mut gateway = Gateway::new(config.gateway);
    let mut local_membership = match config.local_membership {
        Some(local_config) => {
            let manager = LocalMembershipManager::new(local_config).map_err(|error| {
                io::Error::other(format!(
                    "failed to start local membership listener: {error}"
                ))
            })?;
            Some(manager)
        }
        None => None,
    };
    let mut metrics = MetricsRecorder::gateway(
        &metrics_config,
        gateway_metrics_flags(
            &metrics_config,
            socket.local_addr()?,
            &gateway,
            downstream_enabled,
            transparent_enabled,
            configured_joins,
        ),
    )?;
    let configured_refresh_interval = config
        .membership_refresh_interval
        .unwrap_or(DEFAULT_MEMBERSHIP_REFRESH_INTERVAL);
    let mut effective_refresh_interval = configured_refresh_interval;
    let mut relay_retry = GatewayRetry::due_now();
    let mut query_cycle_started: Option<Instant> = None;
    let mut last_local_query: Option<Instant> = None;
    let mut last_local_prune = Instant::now();
    let mut last_membership_refresh: Option<Instant> = None;
    let mut data_log = GatewayDataLog::new();
    let mut buf = [0; MAX_UDP_DATAGRAM];

    println!(
        "amt gateway listening on {} and discovering relay {}",
        socket.local_addr()?,
        gateway.config().relay
    );
    if let Some(local) = local_membership.as_ref() {
        println!(
            "transparent local membership listening for {:?} reports",
            local.config().protocol
        );
    }
    report_metrics_status(&metrics, &metrics_config);

    loop {
        let mut made_progress = false;

        if shutdown.requested() {
            return shutdown_gateway(&socket, &gateway, &mut metrics);
        }

        if query_cycle_started.is_some_and(|started| started.elapsed() >= GATEWAY_QUERY_TIMEOUT) {
            send_gateway_action(&socket, gateway.restart_discovery())?;
            metrics.counters_mut().gateway_discoveries_sent_total += 1;
            query_cycle_started = Some(Instant::now());
            relay_retry.reset_after_send();
            made_progress = true;
        }

        if gateway.relay_endpoint().is_none() && relay_retry.is_due() {
            send_gateway_action(&socket, gateway.discovery())?;
            metrics.counters_mut().gateway_discoveries_sent_total += 1;
            query_cycle_started.get_or_insert_with(Instant::now);
            relay_retry.after_send();
            made_progress = true;
        } else if gateway.is_awaiting_query() && relay_retry.is_due() {
            send_gateway_action(
                &socket,
                gateway.request().map_err(|error| {
                    io::Error::other(format!("failed to build gateway request: {error}"))
                })?,
            )?;
            relay_retry.after_send();
            made_progress = true;
        }

        if let Some(local) = local_membership.as_ref()
            && let Some(interval) = local.config().query_interval
        {
            let query_due = match last_local_query {
                Some(last_query) => last_query.elapsed() >= interval,
                None => true,
            };
            if query_due {
                if let Some(downstream) = downstream.as_mut() {
                    if let Err(error) = send_local_membership_query(downstream, local) {
                        metrics.counters_mut().downstream_forward_errors_total += 1;
                        eprintln!("failed to send local membership query: {error}");
                    } else {
                        metrics.counters_mut().local_queries_sent_total += 1;
                    }
                } else {
                    eprintln!(
                        "local membership query skipped because downstream forwarding is disabled"
                    );
                }
                last_local_query = Some(Instant::now());
                made_progress = true;
            }
        }

        if gateway.is_established() {
            let refresh_due = match last_membership_refresh {
                Some(last_refresh) => last_refresh.elapsed() >= effective_refresh_interval,
                None => false,
            };
            if refresh_due {
                send_gateway_action(
                    &socket,
                    gateway.begin_query_cycle().map_err(|error| {
                        io::Error::other(format!("failed to begin membership query cycle: {error}"))
                    })?,
                )?;
                println!("requested fresh Membership Query from relay");
                query_cycle_started = Some(Instant::now());
                relay_retry.reset_after_send();
                made_progress = true;
            }
        }

        for _ in 0..MAX_CONTROL_DRAIN {
            match socket.recv_from(&mut buf) {
                Ok((len, peer, outer_ecn)) => {
                    made_progress = true;
                    metrics.counters_mut().control_datagrams_received_total += 1;
                    match gateway.handle_datagram_with_ecn(peer, &buf[..len], outer_ecn) {
                        Ok(GatewayAction::Send {
                            destination,
                            datagram,
                        }) => {
                            socket.send_to(&datagram, destination, EcnCodepoint::NotEct)?;
                            metrics.counters_mut().control_responses_sent_total += 1;
                            metrics.counters_mut().control_response_bytes_sent_total +=
                                datagram.len() as u64;
                            if gateway.is_awaiting_query() {
                                query_cycle_started = Some(Instant::now());
                                relay_retry.reset_after_send();
                            }
                        }
                        Ok(GatewayAction::MembershipQuery {
                            limit,
                            query_interval,
                            previous_teardown,
                            ..
                        }) => {
                            metrics
                                .counters_mut()
                                .gateway_membership_queries_received_total += 1;
                            let endpoint_changed = previous_teardown.is_some();
                            if let Some(previous_teardown) = previous_teardown {
                                socket.send_to(
                                    &previous_teardown.datagram,
                                    previous_teardown.destination,
                                    EcnCodepoint::NotEct,
                                )?;
                                metrics.counters_mut().gateway_teardowns_sent_total += 1;
                            }
                            if limit_requires_rediscovery(
                                limit,
                                gateway.has_reported_memberships(),
                                endpoint_changed,
                            ) {
                                send_gateway_action(&socket, gateway.restart_discovery())?;
                                metrics.counters_mut().gateway_discoveries_sent_total += 1;
                                query_cycle_started = Some(Instant::now());
                                relay_retry.reset_after_send();
                                last_membership_refresh = None;
                                continue;
                            }
                            effective_refresh_interval = effective_refresh_interval_for(
                                configured_refresh_interval,
                                query_interval,
                            );
                            let refreshed = refresh_gateway_memberships(
                                &socket,
                                &mut gateway,
                                &config.joins,
                                local_membership.as_mut(),
                                &mut metrics,
                            )?;
                            if refreshed != 0 {
                                metrics.counters_mut().gateway_membership_refreshes_total += 1;
                            }
                            query_cycle_started = None;
                            last_membership_refresh = Some(Instant::now());
                        }
                        Ok(GatewayAction::MulticastData { packet, ecn }) => {
                            metrics.counters_mut().multicast_data_received_total += 1;
                            metrics.counters_mut().multicast_data_bytes_received_total +=
                                packet.len() as u64;
                            if let Some(ecn) = ecn {
                                if ecn.outer == EcnCodepoint::Ce {
                                    metrics.counters_mut().gateway_ecn_ce_received_total += 1;
                                }
                                if ecn.propagated_ce() {
                                    metrics.counters_mut().gateway_ecn_ce_propagated_total += 1;
                                }
                                if ecn.currently_unused {
                                    metrics.counters_mut().gateway_ecn_currently_unused_total += 1;
                                }
                            }
                            data_log.record_amt_packet(packet.len());
                            if let Some(downstream) = downstream.as_mut() {
                                match downstream.forward_ip_datagram(&packet) {
                                    Ok(Some(report)) => {
                                        metrics
                                            .counters_mut()
                                            .downstream_packets_forwarded_total += 1;
                                        metrics.counters_mut().downstream_bytes_forwarded_total +=
                                            report.bytes_sent as u64;
                                        data_log.record_downstream_forwarded(report.bytes_sent);
                                    }
                                    Ok(None) => {
                                        metrics
                                            .counters_mut()
                                            .downstream_non_multicast_packets_total += 1;
                                        data_log.record_non_multicast();
                                    }
                                    Err(error) => {
                                        metrics.counters_mut().downstream_forward_errors_total += 1;
                                        data_log.record_downstream_error(error.to_string());
                                    }
                                }
                            }
                        }
                        Ok(GatewayAction::DroppedEcn { ecn, packet_len }) => {
                            metrics.counters_mut().multicast_data_received_total += 1;
                            metrics.counters_mut().multicast_data_bytes_received_total +=
                                packet_len as u64;
                            if ecn.outer == EcnCodepoint::Ce {
                                metrics.counters_mut().gateway_ecn_ce_received_total += 1;
                            }
                            if ecn.currently_unused {
                                metrics.counters_mut().gateway_ecn_currently_unused_total += 1;
                            }
                            metrics.counters_mut().gateway_ecn_invalid_drops_total += 1;
                        }
                        Ok(GatewayAction::Ignored) => {
                            metrics.counters_mut().control_datagrams_ignored_total += 1;
                        }
                        Err(_) => {
                            metrics.counters_mut().control_datagrams_invalid_total += 1;
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        if let Some(local) = local_membership.as_mut() {
            let events =
                drain_local_membership(&socket, &mut gateway, local, &config.joins, &mut metrics)?;
            made_progress |= events != 0;
            if last_local_prune.elapsed() >= LOCAL_REPORTER_PRUNE_INTERVAL {
                let expired = local.prune_stale_reporters();
                if expired != 0 && gateway.is_established() {
                    send_desired_membership(
                        &socket,
                        &mut gateway,
                        &config.joins,
                        Some(local),
                        &mut metrics,
                    )?;
                }
                last_local_prune = Instant::now();
                made_progress |= expired != 0;
            }
        }
        match metrics.maybe_emit_gateway(GatewayMetricsGauges {
            relay_connected: gateway.is_established(),
            downstream_enabled,
            transparent_enabled,
            configured_joins,
            driad_source_tunnels: 0,
            driad_active_tunnels: 0,
            driad_candidate_probes: 0,
            driad_held_down_relays: 0,
        }) {
            Ok(emitted) => made_progress |= emitted,
            Err(error) => eprintln!("failed to write gateway metrics sample: {error}"),
        }
        data_log.maybe_emit();

        if !made_progress {
            thread::sleep(IDLE_SLEEP);
        }
    }
}

fn limit_requires_rediscovery(
    limit: bool,
    has_reported_memberships: bool,
    endpoint_changed: bool,
) -> bool {
    limit && (!has_reported_memberships || endpoint_changed)
}

fn report_metrics_status(metrics: &MetricsRecorder, config: &MetricsConfig) {
    if let Some(path) = metrics.path() {
        println!("heimdall metrics enabled: {}", path.display());
    } else if config.requested() && config.is_enabled() {
        println!("heimdall metrics disabled because output initialization failed");
    } else if config.requested() {
        println!("heimdall metrics requested but this binary was built without --features metrics");
    }
}

fn effective_refresh_interval_for(configured: Duration, suggested: Duration) -> Duration {
    if suggested.is_zero() {
        configured
    } else {
        configured.min(suggested)
    }
}

#[derive(Debug)]
struct RelayPmtuFeedback {
    enabled: bool,
    #[cfg(feature = "pmtu-feedback")]
    sender: Option<PmtuFeedbackSender>,
}

#[derive(Debug)]
enum RelayPmtuOutcome {
    Disabled,
    #[cfg(feature = "pmtu-feedback")]
    Sent {
        bytes_sent: usize,
    },
    #[cfg(feature = "pmtu-feedback")]
    RateLimited,
    #[cfg(feature = "pmtu-feedback")]
    Suppressed,
    #[cfg(feature = "pmtu-feedback")]
    AddressFamilyUnavailable,
    #[cfg(feature = "pmtu-feedback")]
    Failed(String),
}

impl RelayPmtuFeedback {
    fn new(enabled: bool, upstream: &UpstreamConfig) -> io::Result<Self> {
        if !enabled {
            return Ok(Self {
                enabled: false,
                #[cfg(feature = "pmtu-feedback")]
                sender: None,
            });
        }

        #[cfg(not(feature = "pmtu-feedback"))]
        {
            let _ = upstream;
            Err(io::Error::new(
                ErrorKind::Unsupported,
                "PMTU feedback requires the pmtu-feedback Cargo feature",
            ))
        }

        #[cfg(feature = "pmtu-feedback")]
        {
            let local_address = upstream.interface.ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    "PMTU feedback requires an explicit upstream interface address",
                )
            })?;
            let sender = PmtuFeedbackSender::new(local_address, upstream.interface_index)
                .map_err(|error| io::Error::other(error.to_string()))?;
            Ok(Self {
                enabled: true,
                sender: Some(sender),
            })
        }
    }

    fn send(&mut self, packet: &[u8], tunnel_mtu: usize) -> RelayPmtuOutcome {
        if !self.enabled {
            return RelayPmtuOutcome::Disabled;
        }

        #[cfg(not(feature = "pmtu-feedback"))]
        {
            let _ = (packet, tunnel_mtu);
            RelayPmtuOutcome::Disabled
        }

        #[cfg(feature = "pmtu-feedback")]
        {
            let Some(sender) = self.sender.as_mut() else {
                return RelayPmtuOutcome::Disabled;
            };
            match sender.send(packet, tunnel_mtu) {
                Ok(PmtuFeedbackOutcome::Sent { bytes_sent }) => {
                    RelayPmtuOutcome::Sent { bytes_sent }
                }
                Ok(PmtuFeedbackOutcome::RateLimited) => RelayPmtuOutcome::RateLimited,
                Ok(PmtuFeedbackOutcome::Suppressed) => RelayPmtuOutcome::Suppressed,
                Ok(PmtuFeedbackOutcome::AddressFamilyUnavailable) => {
                    RelayPmtuOutcome::AddressFamilyUnavailable
                }
                Err(error) => RelayPmtuOutcome::Failed(error.to_string()),
            }
        }
    }
}

#[cfg(feature = "driad")]
#[derive(Debug)]
struct DriadRefreshState {
    source: IpAddr,
    resolver: DriadResolver,
    next_refresh: Instant,
    pending: Option<Receiver<Result<Vec<DriadRelaySelection>, DriadError>>>,
    retry_attempt: u32,
    workers: DriadWorkerPool,
}

#[cfg(feature = "driad")]
impl DriadRefreshState {
    fn new(source: IpAddr, resolver: DriadResolver, workers: DriadWorkerPool) -> Self {
        Self {
            source,
            resolver,
            next_refresh: Instant::now(),
            pending: None,
            retry_attempt: 0,
            workers,
        }
    }

    fn poll(&mut self) -> DriadPoll {
        if let Some(pending) = self.pending.as_ref() {
            match pending.try_recv() {
                Ok(result) => {
                    self.pending = None;
                    return DriadPoll::Resolved(result);
                }
                Err(TryRecvError::Empty) => return DriadPoll::Idle,
                Err(TryRecvError::Disconnected) => {
                    self.pending = None;
                    return DriadPoll::Resolved(Err(DriadError::Io(
                        "DRIAD resolver worker stopped without a result".to_string(),
                    )));
                }
            }
        }
        if Instant::now() < self.next_refresh {
            return DriadPoll::Idle;
        }
        let Some(permit) = self.workers.try_acquire() else {
            return DriadPoll::Idle;
        };

        let resolver = self.resolver.clone();
        let source = self.source;
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("amt-driad-dns".to_string())
            .spawn(move || {
                let _permit = permit;
                let result = resolver.resolve_source_candidates(source);
                let _ = sender.send(result);
            });
        if let Err(error) = worker {
            return DriadPoll::Resolved(Err(DriadError::Io(format!(
                "failed to start DRIAD resolver worker: {error}"
            ))));
        }
        self.pending = Some(receiver);
        DriadPoll::Started
    }

    fn schedule_success(&mut self, ttl: Duration) {
        self.retry_attempt = 0;
        self.next_refresh = Instant::now() + clamp_driad_refresh(ttl);
    }

    fn schedule_failure(&mut self) {
        let upper = GatewayRetry::upper_delay(self.retry_attempt);
        self.retry_attempt = self.retry_attempt.saturating_add(1);
        self.next_refresh = Instant::now() + randomized_retry_delay(upper);
    }
}

#[cfg(feature = "driad")]
#[derive(Debug, Clone)]
struct DriadWorkerPool {
    active: Arc<AtomicUsize>,
    maximum: usize,
}

#[cfg(feature = "driad")]
impl DriadWorkerPool {
    fn new(maximum: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            maximum: maximum.max(1),
        }
    }

    fn try_acquire(&self) -> Option<DriadWorkerPermit> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.maximum).then_some(active + 1)
            })
            .ok()
            .map(|_| DriadWorkerPermit {
                active: Arc::clone(&self.active),
            })
    }
}

#[cfg(feature = "driad")]
#[derive(Debug)]
struct DriadWorkerPermit {
    active: Arc<AtomicUsize>,
}

#[cfg(feature = "driad")]
impl Drop for DriadWorkerPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "driad")]
#[derive(Debug)]
enum DriadPoll {
    Idle,
    Started,
    Resolved(Result<Vec<DriadRelaySelection>, DriadError>),
}

#[cfg(feature = "driad")]
fn clamp_driad_refresh(ttl: Duration) -> Duration {
    ttl.clamp(DRIAD_MIN_REFRESH_INTERVAL, DRIAD_MAX_REFRESH_INTERVAL)
}

#[cfg(feature = "driad")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DriadCandidateOrigin {
    Anycast,
    SourceDns,
}

#[cfg(feature = "driad")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DriadCandidate {
    selection: DriadRelaySelection,
    origin: DriadCandidateOrigin,
}

#[cfg(feature = "driad")]
impl DriadCandidate {
    fn rank(&self) -> (DriadCandidateOrigin, u8) {
        (self.origin, self.selection.record.precedence)
    }
}

#[cfg(feature = "driad")]
struct DriadProbe {
    candidate: DriadCandidate,
    socket: AmtUdpSocket,
    gateway: Gateway,
    deadline: Instant,
}

#[cfg(feature = "driad")]
struct ActiveDriadTunnel {
    candidate: DriadCandidate,
    socket: AmtUdpSocket,
    gateway: Gateway,
    effective_refresh_interval: Duration,
    query_cycle_started: Option<Instant>,
    last_membership_refresh: Instant,
    traffic_deadline: Option<Instant>,
}

#[cfg(feature = "driad")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DriadActiveFailure {
    Loaded,
    QueryTimeout,
    NoTraffic,
}

#[cfg(feature = "driad")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DriadActivePoll {
    made_progress: bool,
    failure: Option<DriadActiveFailure>,
}

#[cfg(feature = "driad")]
#[derive(Debug)]
enum DriadProbePoll {
    Pending(bool),
    Loaded(SocketAddr),
    Failed,
    Winner {
        query_interval: Duration,
        previous_teardown: Option<crate::gateway::GatewaySend>,
    },
}

#[cfg(feature = "driad")]
struct DriadSourceTunnel {
    source: IpAddr,
    protocol: crate::protocol::MembershipProtocol,
    ecn: bool,
    bind: Option<IpAddr>,
    use_anycast: bool,
    happy_eyeballs_delay: Duration,
    relay_hold_down: Duration,
    traffic_hold_down: Duration,
    initial_traffic_timeout: Duration,
    maximum_traffic_timeout: Duration,
    max_concurrent_probes: usize,
    refresh: DriadRefreshState,
    dns_candidates: Vec<DriadRelaySelection>,
    hold_downs: BTreeMap<SocketAddr, Instant>,
    pending: std::collections::VecDeque<DriadCandidate>,
    current_rank: Option<(DriadCandidateOrigin, u8)>,
    probes: Vec<DriadProbe>,
    next_probe_at: Instant,
    retry_round_at: Option<Instant>,
    retry_attempt: u32,
    traffic_retry_attempt: u32,
    no_relay_present: bool,
    active: Option<ActiveDriadTunnel>,
    desired: MembershipReport,
}

#[cfg(feature = "driad")]
impl DriadSourceTunnel {
    fn new(
        source: IpAddr,
        protocol: crate::protocol::MembershipProtocol,
        ecn: bool,
        config: &GatewayDriadConfig,
        resolver_workers: DriadWorkerPool,
        desired: MembershipReport,
    ) -> Self {
        let mut tunnel = Self {
            source,
            protocol,
            ecn,
            bind: config.bind.map(|bind| bind.ip()),
            use_anycast: config.use_anycast,
            happy_eyeballs_delay: config.happy_eyeballs_delay,
            relay_hold_down: config.relay_hold_down,
            traffic_hold_down: config.traffic_hold_down,
            initial_traffic_timeout: config.initial_traffic_timeout,
            maximum_traffic_timeout: config.maximum_traffic_timeout,
            max_concurrent_probes: config.max_concurrent_probes.max(1),
            refresh: DriadRefreshState::new(source, config.resolver.clone(), resolver_workers),
            dns_candidates: Vec::new(),
            hold_downs: BTreeMap::new(),
            pending: std::collections::VecDeque::new(),
            current_rank: None,
            probes: Vec::new(),
            next_probe_at: Instant::now(),
            retry_round_at: None,
            retry_attempt: 0,
            traffic_retry_attempt: 0,
            no_relay_present: false,
            active: None,
            desired,
        };
        tunnel.rebuild_probe_queue();
        tunnel
    }

    fn is_active(&self) -> bool {
        self.active.is_some()
    }

    fn probe_count(&self) -> usize {
        self.probes.len()
    }

    fn hold_down_count(&self) -> usize {
        let now = Instant::now();
        self.hold_downs
            .values()
            .filter(|expires| **expires > now)
            .count()
    }

    fn poll(
        &mut self,
        downstream: Option<&mut DownstreamPublisher>,
        metrics: &mut MetricsRecorder,
        data_log: &mut GatewayDataLog,
        configured_refresh_interval: Duration,
    ) -> io::Result<bool> {
        let mut made_progress = self.poll_refresh(metrics);
        if let Some(mut active) = self.active.take() {
            let outcome = self.poll_active(
                &mut active,
                downstream,
                metrics,
                data_log,
                configured_refresh_interval,
            )?;
            made_progress |= outcome.made_progress;
            match outcome.failure {
                None => self.active = Some(active),
                Some(failure) => self.fail_active(active, failure, metrics),
            }
        } else {
            made_progress |= self.poll_probes(metrics)?;
            made_progress |= self.launch_probe_if_due(metrics)?;
            self.schedule_next_round_if_exhausted();
        }
        Ok(made_progress)
    }

    fn poll_refresh(&mut self, metrics: &mut MetricsRecorder) -> bool {
        match self.refresh.poll() {
            DriadPoll::Idle => false,
            DriadPoll::Started => {
                metrics.counters_mut().driad_refreshes_started_total += 1;
                true
            }
            DriadPoll::Resolved(Ok(selections)) => {
                let ttl = selections
                    .iter()
                    .map(|selection| selection.ttl)
                    .min()
                    .unwrap_or(DRIAD_MIN_REFRESH_INTERVAL);
                let candidates_changed = self.dns_candidates != selections;
                if candidates_changed {
                    self.dns_candidates = selections;
                    metrics.counters_mut().driad_candidate_changes_total += 1;
                }
                let was_withdrawn = std::mem::take(&mut self.no_relay_present);
                if self.active.is_none() && (candidates_changed || was_withdrawn) {
                    self.rebuild_probe_queue();
                }
                self.refresh.schedule_success(ttl);
                metrics.counters_mut().driad_refreshes_succeeded_total += 1;
                true
            }
            DriadPoll::Resolved(Err(DriadError::NoRelayPresent)) => {
                let withdrawal = !self.no_relay_present
                    || !self.dns_candidates.is_empty()
                    || !self.probes.is_empty()
                    || self.active.is_some();
                self.no_relay_present = true;
                self.dns_candidates.clear();
                self.pending.clear();
                self.probes.clear();
                self.current_rank = None;
                self.retry_round_at = None;
                if let Some(active) = self.active.take()
                    && let Ok(action) = active.gateway.teardown()
                {
                    if let Err(error) = send_gateway_action(&active.socket, action) {
                        metrics.counters_mut().send_errors_total += 1;
                        eprintln!(
                            "failed to send withdrawn DRIAD tunnel teardown for source {}: {error}",
                            self.source
                        );
                    } else {
                        metrics.counters_mut().gateway_teardowns_sent_total += 1;
                    }
                }
                self.refresh.schedule_failure();
                metrics.counters_mut().driad_refreshes_succeeded_total += 1;
                if withdrawal {
                    metrics.counters_mut().driad_candidate_changes_total += 1;
                    metrics.counters_mut().driad_no_relay_withdrawals_total += 1;
                    println!(
                        "DRIAD withdrew AMT relay use for source {} after an authoritative NoRelay record",
                        self.source
                    );
                }
                true
            }
            DriadPoll::Resolved(Err(error)) => {
                self.refresh.schedule_failure();
                metrics.counters_mut().driad_refreshes_failed_total += 1;
                eprintln!("DRIAD refresh for source {} failed: {error}", self.source);
                true
            }
        }
    }

    fn rebuild_probe_queue(&mut self) {
        let now = Instant::now();
        self.hold_downs.retain(|_, expires| *expires > now);
        if self.no_relay_present {
            self.pending.clear();
            self.current_rank = None;
            self.retry_round_at = None;
            return;
        }
        let in_flight = self
            .probes
            .iter()
            .map(|probe| probe.candidate.selection.relay)
            .collect::<BTreeSet<_>>();
        let mut candidates = Vec::new();
        if self.use_anycast {
            candidates.extend(self.anycast_candidates());
        }
        candidates.extend(
            self.dns_candidates
                .iter()
                .cloned()
                .map(|selection| DriadCandidate {
                    selection,
                    origin: DriadCandidateOrigin::SourceDns,
                }),
        );
        let mut seen = in_flight;
        candidates.retain(|candidate| {
            self.address_family_allowed(candidate.selection.relay.ip())
                && !self.hold_downs.contains_key(&candidate.selection.relay)
                && seen.insert(candidate.selection.relay)
        });
        candidates.sort_by_key(DriadCandidate::rank);
        self.pending = candidates.into();
        self.current_rank = self
            .probes
            .iter()
            .map(|probe| probe.candidate.rank())
            .min()
            .or_else(|| self.pending.front().map(DriadCandidate::rank));
        self.next_probe_at = now;
        self.retry_round_at = None;
    }

    fn anycast_candidates(&self) -> Vec<DriadCandidate> {
        [IpAddr::V6(AMT_ANYCAST_IPV6), IpAddr::V4(AMT_ANYCAST_IPV4)]
            .into_iter()
            .filter(|address| self.address_family_allowed(*address))
            .map(|address| {
                let target = match address {
                    IpAddr::V4(address) => AmtRelayTarget::Ipv4(address),
                    IpAddr::V6(address) => AmtRelayTarget::Ipv6(address),
                };
                DriadCandidate {
                    selection: DriadRelaySelection {
                        source: self.source,
                        query_name: "RFC 7450 well-known anycast".to_string(),
                        record: AmtRelayRecord {
                            precedence: 0,
                            discovery_optional: false,
                            target,
                        },
                        relay: SocketAddr::new(address, crate::AMT_PORT),
                        ttl: Duration::MAX,
                    },
                    origin: DriadCandidateOrigin::Anycast,
                }
            })
            .collect()
    }

    fn address_family_allowed(&self, address: IpAddr) -> bool {
        self.bind
            .is_none_or(|bind| same_address_family(bind, address))
    }

    fn launch_probe_if_due(&mut self, metrics: &mut MetricsRecorder) -> io::Result<bool> {
        let now = Instant::now();
        if let Some(retry_at) = self.retry_round_at {
            if now < retry_at {
                return Ok(false);
            }
            self.rebuild_probe_queue();
        }
        if now < self.next_probe_at {
            return Ok(false);
        }
        if self.probes.len() >= self.max_concurrent_probes {
            return Ok(false);
        }
        if self.probes.is_empty()
            && let Some(next_rank) = self.pending.front().map(DriadCandidate::rank)
            && self.current_rank != Some(next_rank)
        {
            self.current_rank = Some(next_rank);
        }
        let Some(candidate) = self.pending.front() else {
            return Ok(false);
        };
        if Some(candidate.rank()) != self.current_rank {
            return Ok(false);
        }
        let candidate = self.pending.pop_front().expect("front candidate exists");
        let bind = match candidate.selection.relay {
            SocketAddr::V4(_) => SocketAddr::new(
                self.bind
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                0,
            ),
            SocketAddr::V6(_) => SocketAddr::new(
                self.bind
                    .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
                0,
            ),
        };
        let socket = match AmtUdpSocket::bind(bind, self.ecn) {
            Ok(socket) => socket,
            Err(error) => {
                metrics.counters_mut().driad_probe_errors_total += 1;
                self.next_probe_at = now + self.happy_eyeballs_delay;
                eprintln!(
                    "DRIAD could not open a probe for {} via {}: {error}",
                    self.source, candidate.selection.relay
                );
                return Ok(true);
            }
        };
        let gateway = Gateway::new(
            GatewayConfig::new(candidate.selection.relay, self.protocol).with_ecn(self.ecn),
        );
        if let Err(error) = send_gateway_action(&socket, gateway.discovery()) {
            metrics.counters_mut().send_errors_total += 1;
            metrics.counters_mut().driad_probe_errors_total += 1;
            self.next_probe_at = now + self.happy_eyeballs_delay;
            eprintln!(
                "DRIAD could not send a probe for {} to {}: {error}",
                self.source, candidate.selection.relay
            );
            return Ok(true);
        }
        metrics.counters_mut().gateway_discoveries_sent_total += 1;
        self.probes.push(DriadProbe {
            candidate,
            socket,
            gateway,
            deadline: now + GATEWAY_QUERY_TIMEOUT,
        });
        metrics.counters_mut().driad_probes_started_total += 1;
        self.next_probe_at = now + self.happy_eyeballs_delay;
        Ok(true)
    }

    fn poll_probes(&mut self, metrics: &mut MetricsRecorder) -> io::Result<bool> {
        let now = Instant::now();
        let mut made_progress = false;
        let mut index = 0;
        while index < self.probes.len() {
            let deadline_expired = self.probes[index].deadline <= now;
            let outcome = match poll_driad_probe(&mut self.probes[index], metrics) {
                Ok(outcome) => outcome,
                Err(error) => {
                    let relay = self.probes[index].candidate.selection.relay;
                    self.probes.swap_remove(index);
                    metrics.counters_mut().send_errors_total += 1;
                    metrics.counters_mut().driad_probe_errors_total += 1;
                    eprintln!(
                        "DRIAD probe for source {} via {relay} failed: {error}",
                        self.source
                    );
                    made_progress = true;
                    continue;
                }
            };
            match outcome {
                DriadProbePoll::Pending(progress) => {
                    made_progress |= progress;
                    if deadline_expired {
                        self.probes.swap_remove(index);
                        metrics.counters_mut().driad_probe_timeouts_total += 1;
                        made_progress = true;
                    } else {
                        index += 1;
                    }
                }
                DriadProbePoll::Failed => {
                    self.probes.swap_remove(index);
                    metrics.counters_mut().driad_probe_errors_total += 1;
                    made_progress = true;
                }
                DriadProbePoll::Loaded(relay) => {
                    let probe = self.probes.swap_remove(index);
                    self.hold_candidate(&probe.candidate, relay, self.relay_hold_down);
                    metrics.counters_mut().driad_loaded_hold_downs_total += 1;
                    made_progress = true;
                }
                DriadProbePoll::Winner {
                    query_interval,
                    previous_teardown,
                } => {
                    let probe = self.probes.swap_remove(index);
                    if let Some(previous) = previous_teardown {
                        if let Err(error) = probe.socket.send_to(
                            &previous.datagram,
                            previous.destination,
                            EcnCodepoint::NotEct,
                        ) {
                            metrics.counters_mut().send_errors_total += 1;
                            eprintln!(
                                "failed to send previous DRIAD tunnel teardown to {}: {error}",
                                previous.destination
                            );
                        } else {
                            metrics.counters_mut().gateway_teardowns_sent_total += 1;
                        }
                    }
                    let traffic_timeout = self.next_traffic_timeout();
                    let mut active = ActiveDriadTunnel {
                        candidate: probe.candidate,
                        socket: probe.socket,
                        gateway: probe.gateway,
                        effective_refresh_interval: query_interval,
                        query_cycle_started: None,
                        last_membership_refresh: now,
                        traffic_deadline: None,
                    };
                    if let Err(error) = send_driad_desired(
                        self.source,
                        &self.desired,
                        &mut active,
                        metrics,
                        traffic_timeout,
                    ) {
                        metrics.counters_mut().send_errors_total += 1;
                        metrics.counters_mut().driad_probe_errors_total += 1;
                        eprintln!(
                            "DRIAD could not activate source {} through {}: {error}",
                            self.source, active.candidate.selection.relay
                        );
                        made_progress = true;
                        continue;
                    }
                    println!(
                        "DRIAD established source {} through relay {}",
                        self.source,
                        active
                            .gateway
                            .relay_endpoint()
                            .unwrap_or(active.candidate.selection.relay)
                    );
                    self.active = Some(active);
                    metrics.counters_mut().driad_connections_established_total += 1;
                    self.probes.clear();
                    self.pending.clear();
                    self.retry_attempt = 0;
                    return Ok(true);
                }
            }
        }
        Ok(made_progress)
    }

    fn schedule_next_round_if_exhausted(&mut self) {
        if self.no_relay_present
            || self.active.is_some()
            || !self.probes.is_empty()
            || !self.pending.is_empty()
        {
            return;
        }
        if self.retry_round_at.is_none() {
            let upper = GatewayRetry::upper_delay(self.retry_attempt);
            self.retry_attempt = self.retry_attempt.saturating_add(1);
            self.retry_round_at = Some(Instant::now() + randomized_retry_delay(upper));
        }
    }

    fn poll_active(
        &mut self,
        active: &mut ActiveDriadTunnel,
        downstream: Option<&mut DownstreamPublisher>,
        metrics: &mut MetricsRecorder,
        data_log: &mut GatewayDataLog,
        configured_refresh_interval: Duration,
    ) -> io::Result<DriadActivePoll> {
        let now = Instant::now();
        let mut made_progress = false;
        let query_timed_out = active
            .query_cycle_started
            .is_some_and(|started| now.duration_since(started) >= GATEWAY_QUERY_TIMEOUT);
        if !query_timed_out
            && active.query_cycle_started.is_none()
            && now.duration_since(active.last_membership_refresh)
                >= active
                    .effective_refresh_interval
                    .min(configured_refresh_interval)
        {
            let action = match active.gateway.begin_query_cycle() {
                Ok(action) => action,
                Err(error) => {
                    eprintln!(
                        "failed to build DRIAD refresh for source {}: {error}",
                        self.source
                    );
                    return Ok(DriadActivePoll {
                        made_progress: true,
                        failure: Some(DriadActiveFailure::QueryTimeout),
                    });
                }
            };
            if let Err(error) = send_gateway_action(&active.socket, action) {
                metrics.counters_mut().send_errors_total += 1;
                eprintln!(
                    "failed to send DRIAD refresh for source {}: {error}",
                    self.source
                );
                return Ok(DriadActivePoll {
                    made_progress: true,
                    failure: Some(DriadActiveFailure::QueryTimeout),
                });
            }
            active.query_cycle_started = Some(now);
            made_progress = true;
        }

        let mut downstream = downstream;
        let mut buffer = [0u8; MAX_UDP_DATAGRAM];
        for _ in 0..MAX_CONTROL_DRAIN {
            match active.socket.recv_from(&mut buffer) {
                Ok((len, peer, outer_ecn)) => {
                    made_progress = true;
                    metrics.counters_mut().control_datagrams_received_total += 1;
                    match active
                        .gateway
                        .handle_datagram_with_ecn(peer, &buffer[..len], outer_ecn)
                    {
                        Ok(GatewayAction::Send {
                            destination,
                            datagram,
                        }) => {
                            if let Err(error) =
                                active
                                    .socket
                                    .send_to(&datagram, destination, EcnCodepoint::NotEct)
                            {
                                metrics.counters_mut().send_errors_total += 1;
                                eprintln!(
                                    "failed to send DRIAD control response for source {}: {error}",
                                    self.source
                                );
                                return Ok(DriadActivePoll {
                                    made_progress: true,
                                    failure: Some(DriadActiveFailure::QueryTimeout),
                                });
                            }
                            metrics.counters_mut().control_responses_sent_total += 1;
                            metrics.counters_mut().control_response_bytes_sent_total +=
                                datagram.len() as u64;
                        }
                        Ok(GatewayAction::MembershipQuery {
                            limit,
                            query_interval,
                            previous_teardown,
                            ..
                        }) => {
                            metrics
                                .counters_mut()
                                .gateway_membership_queries_received_total += 1;
                            if let Some(previous) = previous_teardown {
                                if let Err(error) = active.socket.send_to(
                                    &previous.datagram,
                                    previous.destination,
                                    EcnCodepoint::NotEct,
                                ) {
                                    metrics.counters_mut().send_errors_total += 1;
                                    eprintln!(
                                        "failed to send previous DRIAD tunnel teardown to {}: {error}",
                                        previous.destination
                                    );
                                } else {
                                    metrics.counters_mut().gateway_teardowns_sent_total += 1;
                                }
                            }
                            if limit {
                                return Ok(DriadActivePoll {
                                    made_progress: true,
                                    failure: Some(DriadActiveFailure::Loaded),
                                });
                            }
                            active.effective_refresh_interval = query_interval;
                            active.query_cycle_started = None;
                            let traffic_timeout = self.next_traffic_timeout();
                            if let Err(error) = send_driad_desired(
                                self.source,
                                &self.desired,
                                active,
                                metrics,
                                traffic_timeout,
                            ) {
                                metrics.counters_mut().send_errors_total += 1;
                                eprintln!(
                                    "failed to refresh DRIAD membership for source {}: {error}",
                                    self.source
                                );
                                return Ok(DriadActivePoll {
                                    made_progress: true,
                                    failure: Some(DriadActiveFailure::QueryTimeout),
                                });
                            }
                            metrics.counters_mut().gateway_membership_refreshes_total += 1;
                        }
                        Ok(GatewayAction::MulticastData { packet, ecn }) => {
                            record_gateway_multicast(
                                &packet,
                                ecn,
                                downstream.as_deref_mut(),
                                metrics,
                                data_log,
                            );
                            active.traffic_deadline = None;
                            self.traffic_retry_attempt = 0;
                        }
                        Ok(GatewayAction::DroppedEcn { ecn, packet_len }) => {
                            record_gateway_ecn_drop(ecn, packet_len, metrics);
                        }
                        Ok(GatewayAction::Ignored) => {
                            metrics.counters_mut().control_datagrams_ignored_total += 1;
                        }
                        Err(_) => {
                            metrics.counters_mut().control_datagrams_invalid_total += 1;
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    return Ok(DriadActivePoll {
                        made_progress: true,
                        failure: Some(DriadActiveFailure::QueryTimeout),
                    });
                }
            }
        }
        if active
            .query_cycle_started
            .is_some_and(|started| Instant::now().duration_since(started) >= GATEWAY_QUERY_TIMEOUT)
        {
            return Ok(DriadActivePoll {
                made_progress: true,
                failure: Some(DriadActiveFailure::QueryTimeout),
            });
        }
        if active
            .traffic_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            return Ok(DriadActivePoll {
                made_progress: true,
                failure: Some(DriadActiveFailure::NoTraffic),
            });
        }
        Ok(DriadActivePoll {
            made_progress,
            failure: None,
        })
    }

    fn fail_active(
        &mut self,
        active: ActiveDriadTunnel,
        failure: DriadActiveFailure,
        metrics: &mut MetricsRecorder,
    ) {
        let actual = active
            .gateway
            .relay_endpoint()
            .unwrap_or(active.candidate.selection.relay);
        if let Ok(action) = active.gateway.teardown() {
            if let Err(error) = send_gateway_action(&active.socket, action) {
                metrics.counters_mut().send_errors_total += 1;
                eprintln!(
                    "failed to send DRIAD teardown for source {} via {actual}: {error}",
                    self.source
                );
            } else {
                metrics.counters_mut().gateway_teardowns_sent_total += 1;
            }
        }
        match failure {
            DriadActiveFailure::Loaded => {
                metrics.counters_mut().driad_loaded_hold_downs_total += 1;
                self.hold_candidate(&active.candidate, actual, self.relay_hold_down);
                println!(
                    "DRIAD relay {actual} reported load; holding it down for {:?}",
                    self.relay_hold_down
                );
            }
            DriadActiveFailure::NoTraffic => {
                metrics.counters_mut().driad_no_traffic_hold_downs_total += 1;
                self.hold_candidate(&active.candidate, actual, self.traffic_hold_down);
                self.traffic_retry_attempt = self.traffic_retry_attempt.saturating_add(1);
                println!(
                    "DRIAD relay {actual} delivered no traffic for source {}; holding it down for {:?}",
                    self.source, self.traffic_hold_down
                );
            }
            DriadActiveFailure::QueryTimeout => {
                metrics.counters_mut().driad_query_timeouts_total += 1;
                println!("DRIAD relay {actual} stopped answering; restarting discovery");
            }
        }
        self.rebuild_probe_queue();
    }

    fn hold_candidate(
        &mut self,
        candidate: &DriadCandidate,
        actual: SocketAddr,
        duration: Duration,
    ) {
        let expires = Instant::now() + duration;
        self.hold_downs.insert(candidate.selection.relay, expires);
        self.hold_downs.insert(actual, expires);
    }

    fn next_traffic_timeout(&self) -> Duration {
        let multiplier = 1u32 << self.traffic_retry_attempt.min(5);
        let upper = self
            .initial_traffic_timeout
            .saturating_mul(multiplier)
            .min(self.maximum_traffic_timeout);
        randomized_duration_between(self.initial_traffic_timeout, upper)
    }

    fn set_desired(&mut self, desired: MembershipReport, metrics: &mut MetricsRecorder) {
        if self.desired == desired {
            return;
        }
        self.desired = desired;
        let timeout = self.next_traffic_timeout();
        if let Some(mut active) = self.active.take() {
            if let Err(error) =
                send_driad_desired(self.source, &self.desired, &mut active, metrics, timeout)
            {
                metrics.counters_mut().send_errors_total += 1;
                eprintln!(
                    "failed to update DRIAD membership for source {}: {error}",
                    self.source
                );
                self.fail_active(active, DriadActiveFailure::QueryTimeout, metrics);
            } else {
                self.active = Some(active);
            }
        }
    }

    fn shutdown(&mut self, metrics: &mut MetricsRecorder) {
        if let Some(active) = self.active.take()
            && let Ok(action) = active.gateway.teardown()
        {
            if let Err(error) = send_gateway_action(&active.socket, action) {
                metrics.counters_mut().send_errors_total += 1;
                eprintln!(
                    "failed to send DRIAD shutdown teardown for source {}: {error}",
                    self.source
                );
            } else {
                metrics.counters_mut().gateway_teardowns_sent_total += 1;
            }
        }
        self.probes.clear();
    }
}

#[cfg(feature = "driad")]
fn poll_driad_probe(
    probe: &mut DriadProbe,
    metrics: &mut MetricsRecorder,
) -> io::Result<DriadProbePoll> {
    let mut progress = false;
    let mut buffer = [0u8; MAX_UDP_DATAGRAM];
    for _ in 0..MAX_CONTROL_DRAIN {
        match probe.socket.recv_from(&mut buffer) {
            Ok((len, peer, outer_ecn)) => {
                progress = true;
                metrics.counters_mut().control_datagrams_received_total += 1;
                match probe
                    .gateway
                    .handle_datagram_with_ecn(peer, &buffer[..len], outer_ecn)
                {
                    Ok(GatewayAction::Send {
                        destination,
                        datagram,
                    }) => {
                        probe
                            .socket
                            .send_to(&datagram, destination, EcnCodepoint::NotEct)?;
                        metrics.counters_mut().control_responses_sent_total += 1;
                        metrics.counters_mut().control_response_bytes_sent_total +=
                            datagram.len() as u64;
                    }
                    Ok(GatewayAction::MembershipQuery {
                        limit,
                        query_interval,
                        previous_teardown,
                        ..
                    }) => {
                        metrics
                            .counters_mut()
                            .gateway_membership_queries_received_total += 1;
                        if limit {
                            let relay = probe
                                .gateway
                                .relay_endpoint()
                                .unwrap_or(probe.candidate.selection.relay);
                            return Ok(DriadProbePoll::Loaded(relay));
                        }
                        return Ok(DriadProbePoll::Winner {
                            query_interval,
                            previous_teardown,
                        });
                    }
                    Ok(GatewayAction::Ignored)
                    | Ok(GatewayAction::MulticastData { .. })
                    | Ok(GatewayAction::DroppedEcn { .. }) => {}
                    Err(_) => metrics.counters_mut().control_datagrams_invalid_total += 1,
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(_) => return Ok(DriadProbePoll::Failed),
        }
    }
    Ok(DriadProbePoll::Pending(progress))
}

#[cfg(feature = "driad")]
fn send_driad_desired(
    source: IpAddr,
    desired: &MembershipReport,
    active: &mut ActiveDriadTunnel,
    metrics: &mut MetricsRecorder,
    traffic_timeout: Duration,
) -> io::Result<bool> {
    let Some(action) = active
        .gateway
        .replace_memberships(desired.clone())
        .map_err(|error| io::Error::other(format!("failed to build DRIAD membership: {error}")))?
    else {
        return Ok(false);
    };
    send_gateway_action(&active.socket, action)?;
    active.last_membership_refresh = Instant::now();
    active.traffic_deadline = Some(Instant::now() + traffic_timeout);
    metrics.counters_mut().gateway_membership_updates_sent_total += 1;
    println!(
        "advertised {} membership record(s) for DRIAD source {source}",
        desired.records.len()
    );
    Ok(true)
}

#[cfg(feature = "driad")]
fn record_gateway_multicast(
    packet: &[u8],
    ecn: Option<crate::ecn::EcnDecapsulation>,
    downstream: Option<&mut DownstreamPublisher>,
    metrics: &mut MetricsRecorder,
    data_log: &mut GatewayDataLog,
) {
    metrics.counters_mut().multicast_data_received_total += 1;
    metrics.counters_mut().multicast_data_bytes_received_total += packet.len() as u64;
    if let Some(ecn) = ecn {
        if ecn.outer == EcnCodepoint::Ce {
            metrics.counters_mut().gateway_ecn_ce_received_total += 1;
        }
        if ecn.propagated_ce() {
            metrics.counters_mut().gateway_ecn_ce_propagated_total += 1;
        }
        if ecn.currently_unused {
            metrics.counters_mut().gateway_ecn_currently_unused_total += 1;
        }
    }
    data_log.record_amt_packet(packet.len());
    if let Some(downstream) = downstream {
        match downstream.forward_ip_datagram(packet) {
            Ok(Some(report)) => {
                metrics.counters_mut().downstream_packets_forwarded_total += 1;
                metrics.counters_mut().downstream_bytes_forwarded_total += report.bytes_sent as u64;
                data_log.record_downstream_forwarded(report.bytes_sent);
            }
            Ok(None) => {
                metrics
                    .counters_mut()
                    .downstream_non_multicast_packets_total += 1;
                data_log.record_non_multicast();
            }
            Err(error) => {
                metrics.counters_mut().downstream_forward_errors_total += 1;
                data_log.record_downstream_error(error.to_string());
            }
        }
    }
}

#[cfg(feature = "driad")]
fn record_gateway_ecn_drop(
    ecn: crate::ecn::EcnDecapsulation,
    packet_len: usize,
    metrics: &mut MetricsRecorder,
) {
    metrics.counters_mut().multicast_data_received_total += 1;
    metrics.counters_mut().multicast_data_bytes_received_total += packet_len as u64;
    if ecn.outer == EcnCodepoint::Ce {
        metrics.counters_mut().gateway_ecn_ce_received_total += 1;
    }
    if ecn.currently_unused {
        metrics.counters_mut().gateway_ecn_currently_unused_total += 1;
    }
    metrics.counters_mut().gateway_ecn_invalid_drops_total += 1;
}

#[derive(Debug)]
struct GatewayRetry {
    attempt: u32,
    next_attempt: Instant,
}

impl GatewayRetry {
    fn due_now() -> Self {
        Self {
            attempt: 0,
            next_attempt: Instant::now(),
        }
    }

    fn is_due(&self) -> bool {
        Instant::now() >= self.next_attempt
    }

    fn reset_after_send(&mut self) {
        self.attempt = 0;
        self.after_send();
    }

    fn after_send(&mut self) {
        let upper = Self::upper_delay(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        self.next_attempt = Instant::now() + randomized_retry_delay(upper);
    }

    fn upper_delay(attempt: u32) -> Duration {
        let multiplier = 1u64 << attempt.min(7);
        (GATEWAY_RETRY_INITIAL * multiplier as u32).min(GATEWAY_RETRY_MAX)
    }
}

fn randomized_retry_delay(upper: Duration) -> Duration {
    let lower_ms = GATEWAY_RETRY_INITIAL.as_millis() as u64;
    let upper_ms = upper.as_millis() as u64;
    let mut bytes = [0; 8];
    let random = if getrandom::fill(&mut bytes).is_ok() {
        u64::from_ne_bytes(bytes)
    } else {
        upper_ms
    };
    let span = upper_ms.saturating_sub(lower_ms).saturating_add(1);
    Duration::from_millis(lower_ms + random % span)
}

#[cfg(feature = "driad")]
fn randomized_duration_between(lower: Duration, upper: Duration) -> Duration {
    let lower_ms = u64::try_from(lower.as_millis()).unwrap_or(u64::MAX);
    let upper_ms = u64::try_from(upper.max(lower).as_millis()).unwrap_or(u64::MAX);
    let mut bytes = [0; 8];
    let random = if getrandom::fill(&mut bytes).is_ok() {
        u64::from_ne_bytes(bytes)
    } else {
        upper_ms
    };
    let span = upper_ms.saturating_sub(lower_ms).saturating_add(1);
    Duration::from_millis(lower_ms.saturating_add(random % span))
}

#[derive(Debug, Clone)]
struct ShutdownSignal {
    requested: Arc<AtomicBool>,
}

impl ShutdownSignal {
    fn install() -> io::Result<Self> {
        Self::install_inner(None)
    }

    fn install_with_poller(poller: Arc<Poller>) -> io::Result<Self> {
        Self::install_inner(Some(poller))
    }

    fn install_inner(poller: Option<Arc<Poller>>) -> io::Result<Self> {
        let requested = Arc::new(AtomicBool::new(false));
        let handler_requested = Arc::clone(&requested);
        ctrlc::set_handler(move || {
            handler_requested.store(true, Ordering::SeqCst);
            if let Some(poller) = poller.as_ref() {
                let _ = poller.notify();
            }
        })
        .map_err(|error| io::Error::other(format!("failed to install signal handler: {error}")))?;

        Ok(Self { requested })
    }

    fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

fn shutdown_gateway(
    socket: &AmtUdpSocket,
    gateway: &Gateway,
    metrics: &mut MetricsRecorder,
) -> io::Result<()> {
    match gateway.teardown() {
        Ok(action) => {
            println!("shutdown requested; sending AMT Teardown");
            send_gateway_action(socket, action)?;
            metrics.counters_mut().gateway_teardowns_sent_total += 1;
            Ok(())
        }
        Err(error) => {
            println!("shutdown requested before AMT Teardown was available: {error}");
            Ok(())
        }
    }
}

fn send_desired_membership(
    socket: &AmtUdpSocket,
    gateway: &mut Gateway,
    joins: &[GatewayJoin],
    local: Option<&mut LocalMembershipManager>,
    metrics: &mut MetricsRecorder,
) -> io::Result<bool> {
    let report = desired_membership_report(gateway.config().protocol, joins, local.as_deref());
    let record_count = report.records.len();
    let Some(action) = gateway.replace_memberships(report).map_err(|error| {
        io::Error::other(format!("failed to build local membership update: {error}"))
    })?
    else {
        return Ok(false);
    };
    send_gateway_action(socket, action)?;
    metrics.counters_mut().gateway_membership_updates_sent_total += 1;
    if let Some(local) = local {
        local.mark_advertised();
    }
    println!("advertised {record_count} local membership record(s) to relay");
    Ok(true)
}

fn drain_local_membership(
    socket: &AmtUdpSocket,
    gateway: &mut Gateway,
    local: &mut LocalMembershipManager,
    joins: &[GatewayJoin],
    metrics: &mut MetricsRecorder,
) -> io::Result<usize> {
    let mut events = 0;

    for _ in 0..MAX_LOCAL_MEMBERSHIP_DRAIN {
        match local.try_recv() {
            Ok(Some(event)) => {
                events += 1;
                metrics.counters_mut().local_membership_reports_total += 1;
                println!(
                    "local membership report from {} ({} records, {} active upstream subscriptions)",
                    event.reporter,
                    event.records_received,
                    event.active_subscriptions.len()
                );
                if gateway.response_mac().is_some() {
                    send_desired_membership(socket, gateway, joins, Some(local), metrics)?;
                } else {
                    println!("local membership pending until relay Membership Query is received");
                }
            }
            Ok(None) => break,
            Err(error) if error.is_parse_error() => {
                events += 1;
                metrics.counters_mut().local_membership_parse_errors_total += 1;
                eprintln!("invalid local membership report: {error}");
            }
            Err(error) => {
                return Err(io::Error::other(format!(
                    "failed to receive local membership report: {error}"
                )));
            }
        }
    }

    Ok(events)
}

fn refresh_gateway_memberships(
    socket: &AmtUdpSocket,
    gateway: &mut Gateway,
    joins: &[GatewayJoin],
    local: Option<&mut LocalMembershipManager>,
    metrics: &mut MetricsRecorder,
) -> io::Result<usize> {
    Ok(usize::from(send_desired_membership(
        socket, gateway, joins, local, metrics,
    )?))
}

fn desired_membership_report(
    protocol: crate::protocol::MembershipProtocol,
    joins: &[GatewayJoin],
    local: Option<&LocalMembershipManager>,
) -> MembershipReport {
    let mut state = RelayState::default();
    if let Some(report) = configured_joins_report(protocol, joins) {
        state.apply_report(SocketAddr::from(([0, 0, 0, 0], 1)), &report);
    }
    if let Some(report) = local.and_then(LocalMembershipManager::current_report) {
        state.apply_report(SocketAddr::from(([0, 0, 0, 0], 2)), &report);
    }
    let records = state
        .aggregate_interests_iter()
        .map(|(group, interest)| MembershipRecord {
            kind: match interest.mode {
                FilterMode::Include => MembershipRecordKind::ModeIsInclude,
                FilterMode::Exclude => MembershipRecordKind::ModeIsExclude,
            },
            group,
            sources: interest.sources.iter().copied().collect(),
        })
        .collect();
    MembershipReport { protocol, records }
}

fn configured_joins_report(
    protocol: crate::protocol::MembershipProtocol,
    joins: &[GatewayJoin],
) -> Option<MembershipReport> {
    let mut groups = BTreeMap::<IpAddr, Option<BTreeSet<IpAddr>>>::new();
    for join in joins {
        let interest = groups
            .entry(join.group)
            .or_insert_with(|| Some(BTreeSet::new()));
        match (interest.as_mut(), join.source) {
            (_, None) => *interest = None,
            (Some(sources), Some(source)) => {
                sources.insert(source);
            }
            (None, Some(_)) => {}
        }
    }
    let records = groups
        .into_iter()
        .map(|(group, sources)| match sources {
            Some(sources) => MembershipRecord {
                kind: MembershipRecordKind::ModeIsInclude,
                group,
                sources: sources.into_iter().collect(),
            },
            None => MembershipRecord {
                kind: MembershipRecordKind::ModeIsExclude,
                group,
                sources: Vec::new(),
            },
        })
        .collect::<Vec<_>>();
    (!records.is_empty()).then_some(MembershipReport { protocol, records })
}

fn send_local_membership_query(
    downstream: &mut DownstreamPublisher,
    local: &LocalMembershipManager,
) -> io::Result<()> {
    let query = local.local_query();
    downstream
        .forward_ip_datagram(&query)
        .map_err(|error| io::Error::other(format!("failed to transmit query: {error}")))?;
    println!(
        "sent local {:?} General Query ({} bytes)",
        local.config().protocol,
        query.len()
    );
    Ok(())
}

fn send_gateway_action(socket: &AmtUdpSocket, action: GatewayAction) -> io::Result<()> {
    if let GatewayAction::Send {
        destination,
        datagram,
    } = action
    {
        socket.send_to(&datagram, destination, EcnCodepoint::NotEct)?;
    }

    Ok(())
}

#[derive(Debug)]
struct ControlRateLimiter {
    per_source_rate: f64,
    per_source_burst: f64,
    global: TokenBucket,
    sources: BTreeMap<IpAddr, TokenBucket>,
    source_capacity: usize,
    last_cleanup: Instant,
}

impl ControlRateLimiter {
    fn new(
        per_source_rate: u32,
        per_source_burst: u32,
        global_rate: u32,
        global_burst: u32,
        source_capacity: usize,
    ) -> Self {
        let now = Instant::now();
        Self {
            per_source_rate: f64::from(per_source_rate.max(1)),
            per_source_burst: f64::from(per_source_burst.max(1)),
            global: TokenBucket::new(global_rate.max(1), global_burst.max(1), now),
            sources: BTreeMap::new(),
            source_capacity,
            last_cleanup: now,
        }
    }

    fn allow(&mut self, source: IpAddr) -> bool {
        let now = Instant::now();
        if self.last_cleanup.elapsed() >= Duration::from_secs(60) {
            self.sources
                .retain(|_, bucket| now.duration_since(bucket.last_seen) < Duration::from_secs(60));
            self.last_cleanup = now;
        }
        if !self.sources.contains_key(&source) && self.sources.len() >= self.source_capacity {
            return false;
        }
        if !self
            .sources
            .entry(source)
            .or_insert_with(|| {
                TokenBucket::new(
                    self.per_source_rate as u32,
                    self.per_source_burst as u32,
                    now,
                )
            })
            .take(now)
        {
            return false;
        }
        self.global.take(now)
    }
}

#[derive(Debug, Clone)]
struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

impl TokenBucket {
    fn new(rate: u32, burst: u32, now: Instant) -> Self {
        let burst = f64::from(burst);
        Self {
            rate: f64::from(rate),
            burst,
            tokens: burst,
            last_refill: now,
            last_seen: now,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens
            + now.duration_since(self.last_refill).as_secs_f64() * self.rate)
            .min(self.burst);
        self.last_refill = now;
        self.last_seen = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[derive(Debug, Default)]
struct GatewayActivity {
    last_seen: BTreeMap<SocketAddr, Instant>,
}

impl GatewayActivity {
    fn mark_seen(&mut self, endpoint: SocketAddr) {
        self.mark_seen_at(endpoint, Instant::now());
    }

    fn mark_seen_at(&mut self, endpoint: SocketAddr, now: Instant) {
        self.last_seen.insert(endpoint, now);
    }

    fn remove(&mut self, endpoint: SocketAddr) {
        self.last_seen.remove(&endpoint);
    }

    fn len(&self) -> usize {
        self.last_seen.len()
    }

    fn stale_endpoints(&self, timeout: Duration) -> Vec<SocketAddr> {
        self.stale_endpoints_at(timeout, Instant::now())
    }

    fn stale_endpoints_at(&self, timeout: Duration, now: Instant) -> Vec<SocketAddr> {
        self.last_seen
            .iter()
            .filter_map(|(endpoint, last_seen)| {
                now.checked_duration_since(*last_seen)
                    .is_some_and(|elapsed| elapsed >= timeout)
                    .then_some(*endpoint)
            })
            .collect()
    }
}

fn prune_stale_gateways(
    relay: &mut Relay,
    activity: &mut GatewayActivity,
    timeout: Duration,
) -> usize {
    let mut expired = 0;
    for endpoint in activity.stale_endpoints(timeout) {
        activity.remove(endpoint);
        if relay.remove_gateway(endpoint) {
            expired += 1;
            println!("expired idle gateway {endpoint}");
        }
    }
    expired
}

struct RelayControlPlane<'a> {
    socket: &'a AmtUdpSocket,
    relay: &'a mut Relay,
    upstream: &'a UpstreamWorker,
    gateway_activity: &'a mut GatewayActivity,
    metrics: &'a mut MetricsRecorder,
    error_log: &'a mut ErrorSummary,
}

fn handle_amt_datagram(
    control: RelayControlPlane<'_>,
    peer: std::net::SocketAddr,
    datagram: &[u8],
) -> io::Result<()> {
    let RelayControlPlane {
        socket,
        relay,
        upstream,
        gateway_activity,
        metrics,
        error_log,
    } = control;
    metrics.counters_mut().control_datagrams_received_total += 1;
    match relay.prepare_datagram(peer, datagram) {
        Ok((action, next_state)) => {
            if let Some(candidate) = next_state.as_ref()
                && let Err(error) = sync_upstream(candidate, upstream, metrics)
            {
                metrics.counters_mut().upstream_reconcile_failures_total += 1;
                if relay.state().contains_endpoint(peer) {
                    gateway_activity.mark_seen(peer);
                }
                error_log.record(format!(
                    "{peer} membership update rejected because upstream join failed: {error}"
                ));
                return Ok(());
            }
            if let Some(next_state) = next_state {
                relay.commit_state(next_state);
            }

            match action {
                RelayAction::Send(response) => {
                    match socket.send_to(&response, peer, EcnCodepoint::NotEct) {
                        Ok(_) => {
                            metrics.counters_mut().control_responses_sent_total += 1;
                            metrics.counters_mut().control_response_bytes_sent_total +=
                                response.len() as u64;
                        }
                        Err(_) => metrics.counters_mut().send_errors_total += 1,
                    }
                }
                RelayAction::AcceptedMembershipUpdate {
                    records_applied, ..
                } => {
                    metrics.counters_mut().membership_updates_accepted_total += 1;
                    metrics.counters_mut().membership_records_applied_total +=
                        records_applied as u64;
                    if relay.state().contains_endpoint(peer) {
                        gateway_activity.mark_seen(peer);
                    } else {
                        gateway_activity.remove(peer);
                    }
                }
                RelayAction::AcceptedTeardown { gateway, removed } => {
                    metrics.counters_mut().teardowns_accepted_total += 1;
                    let gateway_ip = gateway
                        .address
                        .as_ipv4_compatible()
                        .map(IpAddr::V4)
                        .unwrap_or_else(|| IpAddr::V6(gateway.address.as_ipv6()));
                    gateway_activity.remove(SocketAddr::new(gateway_ip, gateway.port));
                    if removed {
                        println!("{peer} disconnected from AMT relay");
                    }
                }
                RelayAction::RejectedAuth => {
                    metrics.counters_mut().auth_rejections_total += 1;
                }
                RelayAction::Ignored => {
                    metrics.counters_mut().control_datagrams_ignored_total += 1;
                }
            }

            Ok(())
        }
        Err(error) => {
            metrics.counters_mut().control_datagrams_invalid_total += 1;
            if matches!(error, RelayError::ResourceLimit(_)) {
                metrics.counters_mut().resource_limit_rejections_total += 1;
            }
            Ok(())
        }
    }
}

fn sync_upstream(
    state: &RelayState,
    upstream: &UpstreamWorker,
    metrics: &mut MetricsRecorder,
) -> io::Result<()> {
    let subscriptions = state.upstream_subscriptions();
    let changes = upstream.reconcile(subscriptions)?;
    metrics.counters_mut().upstream_subscription_adds_total += changes.added as u64;
    metrics.counters_mut().upstream_subscription_removes_total += changes.removed as u64;
    metrics.counters_mut().upstream_reconcile_failures_total += changes.failed_removals as u64;

    if changes.changed() {
        println!(
            "upstream subscriptions changed: +{} -{} active={}",
            changes.added, changes.removed, changes.active
        );
    }

    Ok(())
}

fn account_upstream_worker(
    current: UpstreamWorkerSnapshot,
    accounted: &mut UpstreamWorkerSnapshot,
    metrics: &mut MetricsRecorder,
    data_log: &mut RelayDataLog,
) {
    let accepted_packets = current
        .accepted_packets
        .saturating_sub(accounted.accepted_packets);
    let accepted_bytes = current
        .accepted_bytes
        .saturating_sub(accounted.accepted_bytes);
    let queue_drops = current.queue_drops.saturating_sub(accounted.queue_drops);
    let failures = current.failures.saturating_sub(accounted.failures);

    metrics.counters_mut().upstream_packets_received_total += accepted_packets;
    metrics.counters_mut().upstream_bytes_received_total += accepted_bytes;
    metrics.counters_mut().upstream_worker_queue_drops_total += queue_drops;
    metrics.counters_mut().upstream_worker_failures_total += failures;
    data_log.record_worker_activity(accepted_packets, accepted_bytes, queue_drops);
    *accounted = current;
}

fn relay_wait_timeout(
    last_gateway_prune: Instant,
    gateway_prune_interval: Duration,
    metrics: &MetricsRecorder,
) -> Duration {
    let minimum = Duration::from_millis(1);
    let prune_wait = gateway_prune_interval
        .saturating_sub(last_gateway_prune.elapsed())
        .max(minimum);
    let metrics_wait = metrics
        .next_emit_in()
        .unwrap_or(RELAY_IDLE_MAINTENANCE_INTERVAL)
        .max(minimum);
    prune_wait
        .min(metrics_wait)
        .min(RELAY_IDLE_MAINTENANCE_INTERVAL)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct UpstreamDrain {
    budget_exhausted: bool,
}

#[derive(Debug)]
struct RelayWorkBudget {
    started: Instant,
    packet_limit: usize,
    time_limit: Duration,
    packets: usize,
}

impl RelayWorkBudget {
    fn new(packet_limit: usize, time_limit: Duration) -> Self {
        Self {
            started: Instant::now(),
            packet_limit,
            time_limit,
            packets: 0,
        }
    }

    fn can_take_packet(&self) -> bool {
        self.packets < self.packet_limit
            && (self.packets == 0 || self.started.elapsed() < self.time_limit)
    }

    fn record_packet(&mut self) {
        self.packets += 1;
    }

    fn exhausted(&self) -> bool {
        self.packets == self.packet_limit
            || (self.packets != 0 && self.started.elapsed() >= self.time_limit)
    }
}

fn drain_upstream(
    socket: &AmtUdpSocket,
    relay: &Relay,
    upstream: &UpstreamWorker,
    path_mtu: usize,
    pmtu_feedback: &mut RelayPmtuFeedback,
    metrics: &mut MetricsRecorder,
    data_log: &mut RelayDataLog,
) -> io::Result<UpstreamDrain> {
    let mut budget = RelayWorkBudget::new(MAX_RELAY_DATA_DRAIN, RELAY_DATA_FAIRNESS_BUDGET);

    while budget.can_take_packet() {
        let Some(datagram) = upstream.try_recv()? else {
            break;
        };
        budget.record_packet();

        let mut endpoints = relay
            .state()
            .matching_endpoints(datagram.source, datagram.group)
            .peekable();
        if endpoints.peek().is_none() {
            metrics.counters_mut().upstream_unmatched_packets_total += 1;
            data_log.record_unmatched(protocol_name(&datagram));
            continue;
        }

        let response = datagram.normalized_amt_datagram();
        let forwarded_len = response.len().saturating_sub(2);
        let inner_packet = &response[2..];
        let ssm_feedback_allowed = relay
            .state()
            .has_ssm_interest(datagram.source, datagram.group);
        let mut prepared_ipv4_outer = None;
        let mut prepared_ipv6_outer = None;
        let mut feedback_mtu = None;
        let mut successful_endpoints = 0u64;
        let mut successful_bytes = 0u64;
        for endpoint in endpoints {
            let tunnel_mtu = tunnel_mtu(path_mtu, endpoint);
            if inner_packet.len() <= tunnel_mtu {
                let (ecn, normal_mode) = tunnel_ecn(relay, endpoint, inner_packet);
                if send_tunnel_datagram(socket, &response, endpoint, ecn, metrics, data_log) {
                    if normal_mode {
                        metrics
                            .counters_mut()
                            .relay_ecn_normal_mode_datagrams_sent_total += 1;
                    }
                    successful_endpoints += 1;
                    successful_bytes += inner_packet.len() as u64;
                }
                continue;
            }

            let prepared = match endpoint {
                SocketAddr::V4(_) => prepared_ipv4_outer
                    .get_or_insert_with(|| prepare_oversized_tunnel_data(inner_packet, tunnel_mtu)),
                SocketAddr::V6(_) => prepared_ipv6_outer
                    .get_or_insert_with(|| prepare_oversized_tunnel_data(inner_packet, tunnel_mtu)),
            };
            let PreparedTunnelData::Packets(fragments) = prepared else {
                metrics.counters_mut().upstream_mtu_drops_total += 1;
                data_log.record_mtu_drop(prepared.reason());
                if ssm_feedback_allowed && prepared.requires_pmtu_feedback() {
                    feedback_mtu = Some(
                        feedback_mtu.map_or(tunnel_mtu, |current: usize| current.min(tunnel_mtu)),
                    );
                }
                continue;
            };

            let mut complete = true;
            for fragment in fragments {
                let (ecn, normal_mode) = tunnel_ecn(relay, endpoint, &fragment[2..]);
                if send_tunnel_datagram(socket, fragment, endpoint, ecn, metrics, data_log) {
                    if normal_mode {
                        metrics
                            .counters_mut()
                            .relay_ecn_normal_mode_datagrams_sent_total += 1;
                    }
                    metrics.counters_mut().upstream_fragments_sent_total += 1;
                    successful_bytes += fragment.len().saturating_sub(2) as u64;
                } else {
                    complete = false;
                    break;
                }
            }
            if complete {
                successful_endpoints += 1;
            } else {
                metrics.counters_mut().upstream_mtu_drops_total += 1;
                data_log.record_mtu_drop("fragment send failed");
            }
        }

        if let Some(tunnel_mtu) = feedback_mtu {
            record_pmtu_feedback(
                pmtu_feedback.send(inner_packet, tunnel_mtu),
                metrics,
                data_log,
            );
        }

        metrics.counters_mut().upstream_packets_forwarded_total += successful_endpoints;
        metrics.counters_mut().upstream_bytes_forwarded_total += successful_bytes;
        data_log.record_forwarded(forwarded_len, successful_endpoints);
    }

    Ok(UpstreamDrain {
        budget_exhausted: budget.exhausted(),
    })
}

#[derive(Debug)]
enum PreparedTunnelData {
    Packets(Vec<Vec<u8>>),
    Drop(Ipv4FragmentError),
    DropIpv6,
}

impl PreparedTunnelData {
    fn reason(&self) -> &'static str {
        match self {
            Self::Packets(_) => "not dropped",
            Self::Drop(Ipv4FragmentError::InvalidPacket) => "invalid oversized IPv4 packet",
            Self::Drop(Ipv4FragmentError::DontFragment) => "oversized IPv4 packet has DF set",
            Self::Drop(Ipv4FragmentError::HeaderOptions) => {
                "oversized IPv4 packet contains header options"
            }
            Self::Drop(Ipv4FragmentError::MtuTooSmall) => "tunnel MTU too small",
            Self::Drop(Ipv4FragmentError::FragmentOffsetOverflow) => {
                "IPv4 fragment offset overflow"
            }
            Self::DropIpv6 => "oversized IPv6 packet",
        }
    }

    const fn requires_pmtu_feedback(&self) -> bool {
        matches!(
            self,
            Self::Drop(Ipv4FragmentError::DontFragment) | Self::DropIpv6
        )
    }
}

fn record_pmtu_feedback(
    outcome: RelayPmtuOutcome,
    metrics: &mut MetricsRecorder,
    data_log: &mut RelayDataLog,
) {
    #[cfg(not(feature = "pmtu-feedback"))]
    let _ = (metrics, data_log);

    match outcome {
        RelayPmtuOutcome::Disabled => {}
        #[cfg(feature = "pmtu-feedback")]
        RelayPmtuOutcome::Sent { bytes_sent } => {
            metrics.counters_mut().upstream_pmtu_feedback_sent_total += 1;
            metrics
                .counters_mut()
                .upstream_pmtu_feedback_bytes_sent_total += bytes_sent as u64;
        }
        #[cfg(feature = "pmtu-feedback")]
        RelayPmtuOutcome::RateLimited => {
            metrics
                .counters_mut()
                .upstream_pmtu_feedback_rate_limited_total += 1;
        }
        #[cfg(feature = "pmtu-feedback")]
        RelayPmtuOutcome::Suppressed => {
            metrics
                .counters_mut()
                .upstream_pmtu_feedback_suppressed_total += 1;
        }
        #[cfg(feature = "pmtu-feedback")]
        RelayPmtuOutcome::AddressFamilyUnavailable => {
            metrics
                .counters_mut()
                .upstream_pmtu_feedback_unavailable_total += 1;
        }
        #[cfg(feature = "pmtu-feedback")]
        RelayPmtuOutcome::Failed(error) => {
            metrics.counters_mut().upstream_pmtu_feedback_errors_total += 1;
            data_log.record_send_error(error);
        }
    }
}

fn prepare_oversized_tunnel_data(packet: &[u8], tunnel_mtu: usize) -> PreparedTunnelData {
    if packet.first().map(|byte| byte >> 4) != Some(4) {
        return PreparedTunnelData::DropIpv6;
    }
    match fragment_ipv4_for_tunnel(packet, tunnel_mtu) {
        Ok(fragments) => PreparedTunnelData::Packets(
            fragments
                .into_iter()
                .map(|fragment| {
                    let mut datagram = Vec::with_capacity(2 + fragment.len());
                    Message::MulticastData { packet: &fragment }.encode(&mut datagram);
                    datagram
                })
                .collect(),
        ),
        Err(error) => PreparedTunnelData::Drop(error),
    }
}

fn tunnel_mtu(path_mtu: usize, endpoint: SocketAddr) -> usize {
    let outer_ip_header = if endpoint.is_ipv4() { 20 } else { 40 };
    path_mtu.saturating_sub(outer_ip_header + 8 + 2)
}

fn tunnel_ecn(relay: &Relay, endpoint: SocketAddr, packet: &[u8]) -> (EcnCodepoint, bool) {
    if relay.gateway_ecn_capable(endpoint) {
        (ip_ecn(packet).unwrap_or(EcnCodepoint::NotEct), true)
    } else {
        (EcnCodepoint::NotEct, false)
    }
}

fn send_tunnel_datagram(
    socket: &AmtUdpSocket,
    datagram: &[u8],
    endpoint: SocketAddr,
    ecn: EcnCodepoint,
    metrics: &mut MetricsRecorder,
    data_log: &mut RelayDataLog,
) -> bool {
    if let Err(error) = socket.send_to(datagram, endpoint, ecn) {
        metrics.counters_mut().send_errors_total += 1;
        metrics.counters_mut().upstream_forward_errors_total += 1;
        data_log.record_send_error(format!("{endpoint}: {error}"));
        false
    } else {
        true
    }
}

#[derive(Debug)]
struct ErrorSummary {
    label: &'static str,
    last_emit: Instant,
    count: u64,
    last_error: Option<String>,
}

impl ErrorSummary {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            last_emit: Instant::now(),
            count: 0,
            last_error: None,
        }
    }

    fn record(&mut self, error: String) {
        self.count += 1;
        self.last_error = Some(error);
    }

    fn maybe_emit(&mut self) {
        if self.count == 0 || self.last_emit.elapsed() < DATA_LOG_INTERVAL {
            return;
        }
        eprintln!("{}: {} event(s)", self.label, self.count);
        if let Some(error) = self.last_error.as_deref() {
            eprintln!("  last error: {error}");
        }
        self.count = 0;
        self.last_error = None;
        self.last_emit = Instant::now();
    }
}

#[derive(Debug)]
struct RelayDataLog {
    last_emit: Instant,
    received_packets: u64,
    received_bytes: u64,
    forwarded_packets: u64,
    forwarded_bytes: u64,
    forwarded_gateway_sends: u64,
    unmatched_packets: u64,
    last_unmatched_protocol: Option<&'static str>,
    worker_queue_drops: u64,
    send_errors: u64,
    last_send_error: Option<String>,
    mtu_drops: u64,
    last_mtu_drop: Option<&'static str>,
}

impl RelayDataLog {
    fn new() -> Self {
        Self {
            last_emit: Instant::now(),
            received_packets: 0,
            received_bytes: 0,
            forwarded_packets: 0,
            forwarded_bytes: 0,
            forwarded_gateway_sends: 0,
            unmatched_packets: 0,
            last_unmatched_protocol: None,
            worker_queue_drops: 0,
            send_errors: 0,
            last_send_error: None,
            mtu_drops: 0,
            last_mtu_drop: None,
        }
    }

    fn record_worker_activity(&mut self, packets: u64, bytes: u64, queue_drops: u64) {
        self.received_packets += packets;
        self.received_bytes += bytes;
        self.worker_queue_drops += queue_drops;
    }

    fn record_unmatched(&mut self, protocol: &'static str) {
        self.unmatched_packets += 1;
        self.last_unmatched_protocol = Some(protocol);
    }

    fn record_forwarded(&mut self, bytes: usize, gateway_sends: u64) {
        if gateway_sends != 0 {
            self.forwarded_packets += 1;
            self.forwarded_bytes += (bytes as u64).saturating_mul(gateway_sends);
            self.forwarded_gateway_sends += gateway_sends;
        }
    }

    fn record_send_error(&mut self, error: String) {
        self.send_errors += 1;
        self.last_send_error = Some(error);
    }

    fn record_mtu_drop(&mut self, reason: &'static str) {
        self.mtu_drops += 1;
        self.last_mtu_drop = Some(reason);
    }

    fn maybe_emit(&mut self) {
        if self.last_emit.elapsed() < DATA_LOG_INTERVAL || !self.has_events() {
            return;
        }

        println!(
            "relay data-plane summary: received={} packets/{} bytes, forwarded={} packets to {} gateway endpoint(s)/{} bytes, unmatched={}, worker_queue_drops={}, mtu_drops={}, send_errors={}",
            self.received_packets,
            self.received_bytes,
            self.forwarded_packets,
            self.forwarded_gateway_sends,
            self.forwarded_bytes,
            self.unmatched_packets,
            self.worker_queue_drops,
            self.mtu_drops,
            self.send_errors
        );
        if let Some(protocol) = self.last_unmatched_protocol {
            println!("  last unmatched upstream protocol: {protocol}");
        }
        if let Some(error) = self.last_send_error.as_deref() {
            println!("  last relay forward error: {error}");
        }
        if let Some(reason) = self.last_mtu_drop {
            println!("  last tunnel MTU drop: {reason}");
        }
        self.reset();
    }

    fn has_events(&self) -> bool {
        self.received_packets != 0
            || self.worker_queue_drops != 0
            || self.send_errors != 0
            || self.mtu_drops != 0
    }

    fn reset(&mut self) {
        self.last_emit = Instant::now();
        self.received_packets = 0;
        self.received_bytes = 0;
        self.forwarded_packets = 0;
        self.forwarded_bytes = 0;
        self.forwarded_gateway_sends = 0;
        self.unmatched_packets = 0;
        self.last_unmatched_protocol = None;
        self.worker_queue_drops = 0;
        self.send_errors = 0;
        self.last_send_error = None;
        self.mtu_drops = 0;
        self.last_mtu_drop = None;
    }
}

#[derive(Debug)]
struct GatewayDataLog {
    last_emit: Instant,
    amt_packets: u64,
    amt_bytes: u64,
    downstream_packets: u64,
    downstream_bytes: u64,
    non_multicast_packets: u64,
    downstream_errors: u64,
    last_downstream_error: Option<String>,
}

impl GatewayDataLog {
    fn new() -> Self {
        Self {
            last_emit: Instant::now(),
            amt_packets: 0,
            amt_bytes: 0,
            downstream_packets: 0,
            downstream_bytes: 0,
            non_multicast_packets: 0,
            downstream_errors: 0,
            last_downstream_error: None,
        }
    }

    fn record_amt_packet(&mut self, bytes: usize) {
        self.amt_packets += 1;
        self.amt_bytes += bytes as u64;
    }

    fn record_downstream_forwarded(&mut self, bytes: usize) {
        self.downstream_packets += 1;
        self.downstream_bytes += bytes as u64;
    }

    fn record_non_multicast(&mut self) {
        self.non_multicast_packets += 1;
    }

    fn record_downstream_error(&mut self, error: String) {
        self.downstream_errors += 1;
        self.last_downstream_error = Some(error);
    }

    fn maybe_emit(&mut self) {
        if self.last_emit.elapsed() < DATA_LOG_INTERVAL || !self.has_events() {
            return;
        }

        println!(
            "gateway data-plane summary: received={} AMT packets/{} bytes, forwarded={} downstream packets/{} bytes, non_multicast={}, forward_errors={}",
            self.amt_packets,
            self.amt_bytes,
            self.downstream_packets,
            self.downstream_bytes,
            self.non_multicast_packets,
            self.downstream_errors
        );
        if let Some(error) = self.last_downstream_error.as_deref() {
            println!("  last gateway downstream error: {error}");
        }
        self.reset();
    }

    fn has_events(&self) -> bool {
        self.amt_packets != 0 || self.downstream_errors != 0
    }

    fn reset(&mut self) {
        self.last_emit = Instant::now();
        self.amt_packets = 0;
        self.amt_bytes = 0;
        self.downstream_packets = 0;
        self.downstream_bytes = 0;
        self.non_multicast_packets = 0;
        self.downstream_errors = 0;
        self.last_downstream_error = None;
    }
}

fn protocol_name(datagram: &UpstreamDatagram) -> &'static str {
    match datagram.packet.ip_protocol {
        Some(17) => "UDP",
        Some(2) => "IGMP",
        Some(58) => "ICMPv6",
        Some(_) | None => "IP",
    }
}

#[cfg(feature = "driad")]
fn same_address_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn relay_metrics_flags(
    config: &MetricsConfig,
    bind_addr: SocketAddr,
    relay: &Relay,
    upstream: &UpstreamWorker,
    path_mtu: usize,
    pmtu_feedback: bool,
    socket_buffers: SocketBufferSizes,
) -> MetricsFlags {
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (
            config,
            bind_addr,
            relay,
            upstream,
            path_mtu,
            pmtu_feedback,
            socket_buffers,
        );
        base_flags("relay", "")
    }
    #[cfg(feature = "metrics")]
    {
        let mut flags = base_flags("relay", &config.node_id);
        flags.insert("bind_addr".to_string(), bind_addr.to_string().into());
        flags.insert(
            "advertise_ipv4".to_string(),
            relay.config().advertise_ipv4.to_string().into(),
        );
        flags.insert(
            "advertise_ipv6".to_string(),
            relay.config().advertise_ipv6.to_string().into(),
        );
        if let Some(interface) = upstream.config().interface {
            flags.insert(
                "upstream_interface".to_string(),
                interface.to_string().into(),
            );
        }
        if let Some(index) = upstream.config().interface_index {
            flags.insert("upstream_ifindex".to_string(), index.into());
        }
        flags.insert("path_mtu".to_string(), path_mtu.into());
        flags.insert(
            "tunnel_receive_buffer_bytes".to_string(),
            socket_buffers.receive.into(),
        );
        flags.insert(
            "tunnel_send_buffer_bytes".to_string(),
            socket_buffers.send.into(),
        );
        flags.insert("pmtu_feedback_enabled".to_string(), pmtu_feedback.into());
        flags.insert(
            "shared_upstream_capture".to_string(),
            upstream.uses_shared_capture().into(),
        );
        flags.insert(
            "upstream_packet_queue_capacity".to_string(),
            crate::upstream_worker::UPSTREAM_PACKET_QUEUE_CAPACITY.into(),
        );
        flags.insert("ecn_enabled".to_string(), relay.config().ecn.into());
        flags
    }
}

fn gateway_metrics_flags(
    config: &MetricsConfig,
    bind_addr: SocketAddr,
    gateway: &Gateway,
    downstream_enabled: bool,
    transparent_enabled: bool,
    configured_joins: u64,
) -> MetricsFlags {
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (
            config,
            bind_addr,
            gateway,
            downstream_enabled,
            transparent_enabled,
            configured_joins,
        );
        base_flags("gateway", "")
    }
    #[cfg(feature = "metrics")]
    {
        let mut flags = base_flags("gateway", &config.node_id);
        flags.insert("bind_addr".to_string(), bind_addr.to_string().into());
        flags.insert(
            "relay_addr".to_string(),
            gateway.config().relay.to_string().into(),
        );
        flags.insert(
            "protocol".to_string(),
            format!("{:?}", gateway.config().protocol).into(),
        );
        flags.insert("ecn_enabled".to_string(), gateway.config().ecn.into());
        flags.insert("downstream_enabled".to_string(), downstream_enabled.into());
        flags.insert(
            "transparent_enabled".to_string(),
            transparent_enabled.into(),
        );
        flags.insert("configured_joins".to_string(), configured_joins.into());
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_validation_requires_source_for_active_local_queries() {
        let gateway = GatewayConfig::new(
            "192.0.2.10:2268".parse().unwrap(),
            MembershipProtocol::Igmpv3,
        );
        let mut config = GatewayDaemonConfig::new("0.0.0.0:0".parse().unwrap(), gateway);
        config.downstream = Some(DownstreamConfig {
            interface: Some("192.0.2.20".parse().unwrap()),
            ..DownstreamConfig::default()
        });
        config.local_membership = Some(LocalMembershipConfig::new(MembershipProtocol::Igmpv3));

        let error = config.validate().unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains("--local-membership-interface"));
    }

    #[test]
    fn gateway_validation_rejects_route_selected_mld_queries() {
        let gateway = GatewayConfig::new(
            "[2001:db8::10]:2268".parse().unwrap(),
            MembershipProtocol::Mldv2,
        );
        let mut config = GatewayDaemonConfig::new("[::]:0".parse().unwrap(), gateway);
        config.downstream = Some(DownstreamConfig::default());
        let mut local = LocalMembershipConfig::new(MembershipProtocol::Mldv2);
        local.interface = Some("fe80::20".parse().unwrap());
        config.local_membership = Some(local);

        let error = config.validate().unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains("ff02::1"));
    }

    #[test]
    fn disabled_local_queries_allow_route_selected_downstream() {
        let gateway = GatewayConfig::new(
            "192.0.2.10:2268".parse().unwrap(),
            MembershipProtocol::Igmpv3,
        );
        let mut config = GatewayDaemonConfig::new("0.0.0.0:0".parse().unwrap(), gateway);
        config.downstream = Some(DownstreamConfig::default());
        let mut local = LocalMembershipConfig::new(MembershipProtocol::Igmpv3);
        local.query_interval = None;
        config.local_membership = Some(local);

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(config.validate().is_ok());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("route-selected")
        );
    }

    #[test]
    fn relay_data_budget_forwards_the_first_packet_without_batch_delay() {
        let budget = RelayWorkBudget::new(512, Duration::from_millis(2));

        assert!(budget.can_take_packet());
    }

    #[test]
    fn relay_data_budget_yields_to_control_under_continuous_traffic() {
        let mut budget = RelayWorkBudget::new(4, Duration::from_secs(1));
        while budget.can_take_packet() {
            budget.record_packet();
        }

        assert_eq!(budget.packets, 4);
        assert!(budget.exhausted());
    }

    #[test]
    fn relay_data_budget_enforces_its_time_slice() {
        let mut budget = RelayWorkBudget::new(512, Duration::from_millis(1));
        budget.record_packet();
        thread::sleep(Duration::from_millis(2));

        assert!(!budget.can_take_packet());
        assert!(budget.exhausted());
    }

    #[test]
    fn upstream_worker_accounting_applies_only_new_activity() {
        let mut metrics = MetricsRecorder::relay(
            &MetricsConfig::default(),
            base_flags("relay", "worker-accounting-test"),
        )
        .unwrap();
        let mut data_log = RelayDataLog::new();
        let mut accounted = UpstreamWorkerSnapshot::default();
        let snapshot = UpstreamWorkerSnapshot {
            accepted_packets: 10,
            accepted_bytes: 12_000,
            queue_drops: 2,
            failures: 1,
            ..UpstreamWorkerSnapshot::default()
        };

        account_upstream_worker(snapshot, &mut accounted, &mut metrics, &mut data_log);
        account_upstream_worker(snapshot, &mut accounted, &mut metrics, &mut data_log);

        assert_eq!(metrics.counters().upstream_packets_received_total, 10);
        assert_eq!(metrics.counters().upstream_bytes_received_total, 12_000);
        assert_eq!(metrics.counters().upstream_worker_queue_drops_total, 2);
        assert_eq!(metrics.counters().upstream_worker_failures_total, 1);
        assert_eq!(data_log.received_packets, 10);
        assert_eq!(data_log.worker_queue_drops, 2);
    }

    #[test]
    fn gateway_activity_reports_only_stale_endpoints() {
        let start = Instant::now();
        let fresh = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let stale = SocketAddr::from(([198, 51, 100, 9], 40_001));
        let mut activity = GatewayActivity::default();

        activity.mark_seen_at(fresh, start + Duration::from_secs(15));
        activity.mark_seen_at(stale, start);

        assert_eq!(
            activity.stale_endpoints_at(Duration::from_secs(20), start + Duration::from_secs(19)),
            Vec::<SocketAddr>::new()
        );
        assert_eq!(
            activity.stale_endpoints_at(Duration::from_secs(20), start + Duration::from_secs(30)),
            vec![stale]
        );
    }

    #[test]
    fn prune_stale_gateways_drops_activity_even_when_relay_has_no_state() {
        let start = Instant::now();
        let stale = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let mut relay = Relay::new(RelayConfig::default());
        let mut activity = GatewayActivity::default();
        activity.mark_seen_at(stale, start);

        let expired = prune_stale_gateways(&mut relay, &mut activity, Duration::ZERO);

        assert_eq!(expired, 0);
        assert_eq!(activity.len(), 0);
        assert_eq!(relay.state().endpoint_count(), 0);
    }

    #[test]
    fn control_rate_limiter_bounds_burst_and_source_table() {
        let first = IpAddr::V4("192.0.2.1".parse().unwrap());
        let second = IpAddr::V4("192.0.2.2".parse().unwrap());
        let mut limiter = ControlRateLimiter::new(1, 2, 100, 100, 1);

        assert!(limiter.allow(first));
        assert!(limiter.allow(first));
        assert!(!limiter.allow(first));
        assert!(!limiter.allow(second));
    }

    #[test]
    fn source_overage_does_not_consume_another_sources_global_token() {
        let first = IpAddr::V4("192.0.2.1".parse().unwrap());
        let second = IpAddr::V4("192.0.2.2".parse().unwrap());
        let mut limiter = ControlRateLimiter::new(1, 1, 1, 2, 2);

        assert!(limiter.allow(first));
        assert!(!limiter.allow(first));
        assert!(limiter.allow(second));
    }

    #[test]
    fn configured_ssm_sources_for_one_group_share_one_record() {
        let group = IpAddr::V4("232.1.2.3".parse().unwrap());
        let first = IpAddr::V4("192.0.2.1".parse().unwrap());
        let second = IpAddr::V4("192.0.2.2".parse().unwrap());
        let report = configured_joins_report(
            crate::protocol::MembershipProtocol::Igmpv3,
            &[
                GatewayJoin {
                    group,
                    source: Some(first),
                },
                GatewayJoin {
                    group,
                    source: Some(second),
                },
            ],
        )
        .unwrap();

        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].sources, vec![first, second]);
    }

    #[test]
    fn relay_limit_only_preserves_existing_memberships_on_the_same_endpoint() {
        assert!(limit_requires_rediscovery(true, false, false));
        assert!(limit_requires_rediscovery(true, true, true));
        assert!(!limit_requires_rediscovery(true, true, false));
        assert!(!limit_requires_rediscovery(false, false, true));
    }

    #[test]
    fn refresh_interval_never_exceeds_relays_query_interval() {
        let configured = Duration::from_secs(60);
        assert_eq!(
            effective_refresh_interval_for(configured, Duration::from_secs(125)),
            configured
        );
        assert_eq!(
            effective_refresh_interval_for(configured, Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            effective_refresh_interval_for(configured, Duration::ZERO),
            configured
        );
    }

    #[test]
    fn relay_idle_timeout_must_exceed_advertised_query_interval() {
        let mut config = RelayDaemonConfig {
            gateway_idle_timeout: Some(Duration::from_secs(125)),
            ..RelayDaemonConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err().kind(),
            ErrorKind::InvalidInput
        );

        config.gateway_idle_timeout = Some(Duration::from_secs(126));
        assert!(config.validate().is_ok());

        config.gateway_idle_timeout = None;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn gateway_retry_backoff_is_capped() {
        assert_eq!(GatewayRetry::upper_delay(0), Duration::from_secs(1));
        assert_eq!(GatewayRetry::upper_delay(3), Duration::from_secs(8));
        assert_eq!(GatewayRetry::upper_delay(7), Duration::from_secs(120));
        assert_eq!(GatewayRetry::upper_delay(20), Duration::from_secs(120));
    }

    #[test]
    fn pmtu_feedback_is_limited_to_rfc_required_drop_reasons() {
        assert!(PreparedTunnelData::Drop(Ipv4FragmentError::DontFragment).requires_pmtu_feedback());
        assert!(PreparedTunnelData::DropIpv6.requires_pmtu_feedback());
        assert!(
            !PreparedTunnelData::Drop(Ipv4FragmentError::HeaderOptions).requires_pmtu_feedback()
        );
        assert!(
            !PreparedTunnelData::Drop(Ipv4FragmentError::InvalidPacket).requires_pmtu_feedback()
        );
    }

    #[cfg(feature = "driad")]
    #[test]
    fn driad_refresh_interval_is_bounded() {
        assert_eq!(
            clamp_driad_refresh(Duration::ZERO),
            DRIAD_MIN_REFRESH_INTERVAL
        );
        assert_eq!(
            clamp_driad_refresh(Duration::from_secs(60)),
            Duration::from_secs(60)
        );
        assert_eq!(
            clamp_driad_refresh(Duration::from_secs(7 * 24 * 60 * 60)),
            DRIAD_MAX_REFRESH_INTERVAL
        );
    }

    #[cfg(feature = "driad")]
    #[test]
    fn driad_memberships_are_partitioned_by_source() {
        let first = "192.0.2.10".parse().unwrap();
        let second = "192.0.2.11".parse().unwrap();
        let (reports, unsupported) = desired_driad_reports(
            crate::protocol::MembershipProtocol::Igmpv3,
            &[
                GatewayJoin {
                    group: "232.1.2.3".parse().unwrap(),
                    source: Some(first),
                },
                GatewayJoin {
                    group: "232.1.2.4".parse().unwrap(),
                    source: Some(first),
                },
                GatewayJoin {
                    group: "232.1.2.3".parse().unwrap(),
                    source: Some(second),
                },
                GatewayJoin {
                    group: "239.1.2.3".parse().unwrap(),
                    source: None,
                },
            ],
            None,
        );

        assert_eq!(unsupported, 1);
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[&first].records.len(), 2);
        assert!(
            reports[&first]
                .records
                .iter()
                .all(|record| record.sources == vec![first])
        );
        assert_eq!(reports[&second].records.len(), 1);
        assert_eq!(reports[&second].records[0].sources, vec![second]);
    }

    #[cfg(feature = "driad")]
    #[test]
    fn driad_worker_pool_bounds_live_resolvers() {
        let pool = DriadWorkerPool::new(2);
        let first = pool.try_acquire().unwrap();
        let second = pool.try_acquire().unwrap();
        assert!(pool.try_acquire().is_none());

        drop(first);
        let third = pool.try_acquire().unwrap();
        assert!(pool.try_acquire().is_none());
        drop((second, third));
        assert!(pool.try_acquire().is_some());
    }

    #[cfg(feature = "driad")]
    #[test]
    fn driad_source_limit_keeps_existing_tunnels_stable() {
        let resolver = DriadResolver::new(crate::driad::DriadResolverConfig::new(Vec::new()));
        let mut config = GatewayDriadConfig::new(resolver);
        config.max_source_tunnels = 1;
        let mut tunnels = BTreeMap::new();
        let mut metrics = MetricsRecorder::gateway(
            &MetricsConfig::default(),
            base_flags("gateway", "driad-limit-test"),
        )
        .unwrap();
        let mut warnings = (0, 0);
        let workers = DriadWorkerPool::new(1);
        let first = "192.0.2.10".parse().unwrap();
        let second = "192.0.2.11".parse().unwrap();

        reconcile_driad_tunnels(
            &mut tunnels,
            DriadReconcileContext {
                config: &config,
                protocol: crate::protocol::MembershipProtocol::Igmpv3,
                ecn: false,
                joins: &[
                    GatewayJoin {
                        group: "232.1.2.3".parse().unwrap(),
                        source: Some(first),
                    },
                    GatewayJoin {
                        group: "232.1.2.4".parse().unwrap(),
                        source: Some(second),
                    },
                ],
                local: None,
                metrics: &mut metrics,
                last_warnings: &mut warnings,
                resolver_workers: &workers,
            },
        )
        .unwrap();

        assert_eq!(tunnels.keys().copied().collect::<Vec<_>>(), vec![first]);
        assert_eq!(warnings, (0, 1));

        reconcile_driad_tunnels(
            &mut tunnels,
            DriadReconcileContext {
                config: &config,
                protocol: crate::protocol::MembershipProtocol::Igmpv3,
                ecn: false,
                joins: &[GatewayJoin {
                    group: "232.1.2.5".parse().unwrap(),
                    source: Some(first),
                }],
                local: None,
                metrics: &mut metrics,
                last_warnings: &mut warnings,
                resolver_workers: &workers,
            },
        )
        .unwrap();

        assert_eq!(tunnels.keys().copied().collect::<Vec<_>>(), vec![first]);
        assert_eq!(
            tunnels[&first].desired.records[0].group,
            "232.1.2.5".parse::<IpAddr>().unwrap()
        );
    }

    #[cfg(feature = "driad")]
    #[test]
    fn driad_happy_eyeballs_skips_a_black_hole_and_becomes_idle() {
        let black_hole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let relay_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        relay_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let black_hole_addr = black_hole.local_addr().unwrap();
        let relay_addr = relay_socket.local_addr().unwrap();
        let (membership_sender, membership_receiver) = mpsc::sync_channel(1);
        let relay_worker = thread::spawn(move || {
            let mut relay = Relay::new(RelayConfig::for_bind(relay_addr));
            let mut buffer = [0u8; MAX_UDP_DATAGRAM];
            for _ in 0..3 {
                let (len, peer) = relay_socket.recv_from(&mut buffer).unwrap();
                match relay.handle_datagram(peer, &buffer[..len]).unwrap() {
                    RelayAction::Send(response) => {
                        relay_socket.send_to(&response, peer).unwrap();
                    }
                    RelayAction::AcceptedMembershipUpdate {
                        upstream_subscriptions,
                        ..
                    } => {
                        membership_sender.send(upstream_subscriptions).unwrap();
                        return;
                    }
                    action => panic!("unexpected relay action: {action:?}"),
                }
            }
            panic!("gateway did not send a membership update");
        });

        let source = "192.0.2.10".parse().unwrap();
        let group = "232.1.2.3".parse().unwrap();
        let resolver = DriadResolver::new(crate::driad::DriadResolverConfig::new(Vec::new()));
        let mut config = GatewayDriadConfig::new(resolver);
        config.bind = Some("127.0.0.1:0".parse().unwrap());
        config.happy_eyeballs_delay = Duration::from_millis(1);
        config.max_concurrent_probes = 2;
        let desired = MembershipReport {
            protocol: crate::protocol::MembershipProtocol::Igmpv3,
            records: vec![MembershipRecord {
                kind: MembershipRecordKind::ModeIsInclude,
                group,
                sources: vec![source],
            }],
        };
        let workers = DriadWorkerPool::new(1);
        let mut tunnel = DriadSourceTunnel::new(
            source,
            crate::protocol::MembershipProtocol::Igmpv3,
            false,
            &config,
            workers,
            desired,
        );
        tunnel.refresh.next_refresh = Instant::now() + Duration::from_secs(60);
        tunnel.dns_candidates = vec![
            driad_test_selection(source, black_hole_addr),
            driad_test_selection(source, relay_addr),
        ];
        tunnel.rebuild_probe_queue();

        let mut metrics = MetricsRecorder::gateway(
            &MetricsConfig::default(),
            base_flags("gateway", "driad-test"),
        )
        .unwrap();
        let mut data_log = GatewayDataLog::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !tunnel.is_active() && Instant::now() < deadline {
            tunnel
                .poll(None, &mut metrics, &mut data_log, Duration::from_secs(60))
                .unwrap();
            thread::sleep(Duration::from_millis(1));
        }

        assert!(tunnel.is_active());
        assert_eq!(metrics.counters().driad_probes_started_total, 2);
        assert_eq!(metrics.counters().driad_probe_errors_total, 0);
        assert_eq!(metrics.counters().driad_connections_established_total, 1);
        assert_eq!(
            membership_receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap(),
            vec![crate::UpstreamSubscription::ssm(group, source)]
        );
        assert!(
            !tunnel
                .poll(None, &mut metrics, &mut data_log, Duration::from_secs(60),)
                .unwrap()
        );
        relay_worker.join().unwrap();

        tunnel.active.as_mut().unwrap().traffic_deadline = Some(Instant::now());
        assert!(
            tunnel
                .poll(None, &mut metrics, &mut data_log, Duration::from_secs(60),)
                .unwrap()
        );
        assert!(!tunnel.is_active());
        assert_eq!(metrics.counters().driad_no_traffic_hold_downs_total, 1);
        assert_eq!(tunnel.hold_down_count(), 1);
    }

    #[cfg(feature = "driad")]
    #[test]
    fn driad_holds_down_a_loaded_relay_and_uses_its_peer() {
        let loaded_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let healthy_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        loaded_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        healthy_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let loaded_addr = loaded_socket.local_addr().unwrap();
        let healthy_addr = healthy_socket.local_addr().unwrap();
        let (loaded_sender, loaded_receiver) = mpsc::sync_channel(1);

        let loaded_worker = thread::spawn(move || {
            let mut relay_config = RelayConfig::for_bind(loaded_addr);
            relay_config.limit = true;
            let mut relay = Relay::new(relay_config);
            let mut buffer = [0u8; MAX_UDP_DATAGRAM];
            for _ in 0..2 {
                let (len, peer) = loaded_socket.recv_from(&mut buffer).unwrap();
                let RelayAction::Send(response) =
                    relay.handle_datagram(peer, &buffer[..len]).unwrap()
                else {
                    panic!("loaded relay should only answer discovery and request");
                };
                loaded_socket.send_to(&response, peer).unwrap();
            }
            loaded_sender.send(()).unwrap();
        });
        let (membership_sender, membership_receiver) = mpsc::sync_channel(1);
        let healthy_worker = thread::spawn(move || {
            let mut relay = Relay::new(RelayConfig::for_bind(healthy_addr));
            let mut buffer = [0u8; MAX_UDP_DATAGRAM];
            for exchange in 0..3 {
                let (len, peer) = healthy_socket.recv_from(&mut buffer).unwrap();
                match relay.handle_datagram(peer, &buffer[..len]).unwrap() {
                    RelayAction::Send(response) => {
                        if exchange == 0 {
                            loaded_receiver
                                .recv_timeout(Duration::from_secs(1))
                                .unwrap();
                        }
                        healthy_socket.send_to(&response, peer).unwrap();
                    }
                    RelayAction::AcceptedMembershipUpdate { .. } => {
                        membership_sender.send(()).unwrap();
                        return;
                    }
                    action => panic!("unexpected healthy relay action: {action:?}"),
                }
            }
            panic!("healthy relay did not receive membership");
        });

        let source = "192.0.2.10".parse().unwrap();
        let group = "232.1.2.3".parse().unwrap();
        let resolver = DriadResolver::new(crate::driad::DriadResolverConfig::new(Vec::new()));
        let mut config = GatewayDriadConfig::new(resolver);
        config.bind = Some("127.0.0.1:0".parse().unwrap());
        config.happy_eyeballs_delay = Duration::from_millis(1);
        config.max_concurrent_probes = 2;
        let mut tunnel = DriadSourceTunnel::new(
            source,
            crate::protocol::MembershipProtocol::Igmpv3,
            false,
            &config,
            DriadWorkerPool::new(1),
            MembershipReport {
                protocol: crate::protocol::MembershipProtocol::Igmpv3,
                records: vec![MembershipRecord {
                    kind: MembershipRecordKind::ModeIsInclude,
                    group,
                    sources: vec![source],
                }],
            },
        );
        tunnel.refresh.next_refresh = Instant::now() + Duration::from_secs(60);
        tunnel.dns_candidates = vec![
            driad_test_selection(source, loaded_addr),
            driad_test_selection(source, healthy_addr),
        ];
        tunnel.rebuild_probe_queue();
        let mut metrics = MetricsRecorder::gateway(
            &MetricsConfig::default(),
            base_flags("gateway", "driad-loaded-test"),
        )
        .unwrap();
        let mut data_log = GatewayDataLog::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !tunnel.is_active() && Instant::now() < deadline {
            tunnel
                .poll(None, &mut metrics, &mut data_log, Duration::from_secs(60))
                .unwrap();
            thread::sleep(Duration::from_millis(1));
        }

        assert!(tunnel.is_active());
        assert_eq!(
            tunnel.active.as_ref().unwrap().candidate.selection.relay,
            healthy_addr
        );
        assert!(tunnel.hold_downs.contains_key(&loaded_addr));
        assert_eq!(metrics.counters().driad_loaded_hold_downs_total, 1);
        membership_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        loaded_worker.join().unwrap();
        healthy_worker.join().unwrap();

        tunnel.use_anycast = true;
        let (withdrawal_sender, withdrawal_receiver) = mpsc::sync_channel(1);
        withdrawal_sender
            .send(Err(DriadError::NoRelayPresent))
            .unwrap();
        tunnel.refresh.pending = Some(withdrawal_receiver);
        assert!(
            tunnel
                .poll(None, &mut metrics, &mut data_log, Duration::from_secs(60),)
                .unwrap()
        );
        assert!(!tunnel.is_active());
        assert!(tunnel.no_relay_present);
        assert!(tunnel.pending.is_empty());
        assert!(tunnel.probes.is_empty());
        assert!(tunnel.retry_round_at.is_none());
        assert_eq!(metrics.counters().driad_no_relay_withdrawals_total, 1);
        assert_eq!(metrics.counters().gateway_teardowns_sent_total, 1);
    }

    #[cfg(feature = "driad")]
    fn driad_test_selection(source: IpAddr, relay: SocketAddr) -> DriadRelaySelection {
        DriadRelaySelection {
            source,
            query_name: crate::driad::reverse_source_name(source),
            record: AmtRelayRecord {
                precedence: 10,
                discovery_optional: false,
                target: match relay.ip() {
                    IpAddr::V4(address) => AmtRelayTarget::Ipv4(address),
                    IpAddr::V6(address) => AmtRelayTarget::Ipv6(address),
                },
            },
            relay,
            ttl: Duration::from_secs(60),
        }
    }
}
