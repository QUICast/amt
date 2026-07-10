use crate::downstream::{DownstreamConfig, DownstreamPublisher};
use crate::gateway::{Gateway, GatewayAction, GatewayConfig};
use crate::local_membership::{LocalMembershipConfig, LocalMembershipManager};
use crate::membership::{MembershipRecord, MembershipRecordKind, MembershipReport};
use crate::metrics::{
    GatewayMetricsGauges, MetricsConfig, MetricsFlags, MetricsRecorder, RelayMetricsGauges,
    base_flags,
};
use crate::mtu::{Ipv4FragmentError, fragment_ipv4_for_tunnel};
use crate::protocol::Message;
use crate::relay::{Relay, RelayAction, RelayConfig, RelayError};
use crate::state::{FilterMode, RelayState};
use crate::upstream::{UpstreamConfig, UpstreamDatagram, UpstreamManager};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_UDP_DATAGRAM: usize = 65_535;
const MAX_CONTROL_DRAIN: usize = 128;
const MAX_UPSTREAM_DRAIN: usize = 64;
const MAX_LOCAL_MEMBERSHIP_DRAIN: usize = 64;
const MAX_RATE_LIMIT_SOURCES: usize = 65_536;
const IDLE_SLEEP: Duration = Duration::from_millis(10);
const DATA_LOG_INTERVAL: Duration = Duration::from_secs(5);
const GATEWAY_RETRY_INITIAL: Duration = Duration::from_secs(1);
const GATEWAY_RETRY_MAX: Duration = Duration::from_secs(120);
const GATEWAY_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_REPORTER_PRUNE_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_GATEWAY_IDLE_TIMEOUT: Duration = Duration::from_secs(260);
pub const DEFAULT_GATEWAY_PRUNE_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_RELAY_PATH_MTU: usize = 1_500;
pub const DEFAULT_MEMBERSHIP_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_CONTROL_RATE_PER_SECOND: u32 = 10;
pub const DEFAULT_CONTROL_RATE_BURST: u32 = 20;
pub const DEFAULT_GLOBAL_CONTROL_RATE_PER_SECOND: u32 = 1_000;
pub const DEFAULT_GLOBAL_CONTROL_RATE_BURST: u32 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDaemonConfig {
    pub relay: RelayConfig,
    pub upstream: UpstreamConfig,
    pub gateway_idle_timeout: Option<Duration>,
    pub gateway_prune_interval: Duration,
    pub path_mtu: usize,
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
            control_rate_per_second: DEFAULT_CONTROL_RATE_PER_SECOND,
            control_rate_burst: DEFAULT_CONTROL_RATE_BURST,
            global_control_rate_per_second: DEFAULT_GLOBAL_CONTROL_RATE_PER_SECOND,
            global_control_rate_burst: DEFAULT_GLOBAL_CONTROL_RATE_BURST,
            metrics: MetricsConfig::default(),
        }
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
    pub metrics: MetricsConfig,
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
            metrics: MetricsConfig::default(),
        }
    }
}

/// Runs a small blocking AMT relay daemon.
pub fn run_relay(config: impl Into<RelayDaemonConfig>) -> io::Result<()> {
    let config = config.into();
    let metrics_config = config.metrics.clone();
    let socket = UdpSocket::bind(config.relay.bind)?;
    socket.set_nonblocking(true)?;

    let rate_source_capacity = config
        .relay
        .limits
        .max_endpoints
        .clamp(1_024, MAX_RATE_LIMIT_SOURCES);
    let mut relay = Relay::new(config.relay);
    let mut upstream = UpstreamManager::new(config.upstream);
    let mut gateway_activity = GatewayActivity::default();
    let mut metrics = MetricsRecorder::relay(
        &metrics_config,
        relay_metrics_flags(
            &metrics_config,
            socket.local_addr()?,
            &relay,
            &upstream,
            config.path_mtu,
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
    report_metrics_status(&metrics, &metrics_config);

    let mut buf = [0; MAX_UDP_DATAGRAM];
    loop {
        let mut made_progress = false;

        for _ in 0..MAX_CONTROL_DRAIN {
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    made_progress = true;
                    if !rate_limiter.allow(peer.ip()) {
                        metrics.counters_mut().control_datagrams_received_total += 1;
                        metrics.counters_mut().control_datagrams_rate_limited_total += 1;
                        continue;
                    }
                    handle_amt_datagram(
                        RelayControlPlane {
                            socket: &socket,
                            relay: &mut relay,
                            upstream: &mut upstream,
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
            if let Err(error) = sync_upstream(relay.state(), &mut upstream, &mut metrics) {
                error_log.record(error.to_string());
            }
            last_gateway_prune = Instant::now();
            made_progress = true;
        }

        let forwarded = drain_upstream(
            &socket,
            &relay,
            &mut upstream,
            config.path_mtu,
            &mut metrics,
            &mut data_log,
        )?;
        made_progress |= forwarded != 0;
        match metrics.maybe_emit_relay(RelayMetricsGauges {
            active_gateways: gateway_activity.len() as u64,
            active_upstream_subscriptions: upstream.active_subscription_count() as u64,
        }) {
            Ok(emitted) => made_progress |= emitted,
            Err(error) => eprintln!("failed to write relay metrics sample: {error}"),
        }
        data_log.maybe_emit();
        error_log.maybe_emit();

        if !made_progress {
            thread::sleep(IDLE_SLEEP);
        }
    }
}

/// Runs a small blocking AMT gateway daemon.
pub fn run_gateway(config: GatewayDaemonConfig) -> io::Result<()> {
    let metrics_config = config.metrics.clone();
    let configured_joins = config.joins.len() as u64;
    let transparent_enabled = config.local_membership.is_some();
    let downstream_enabled = config.downstream.is_some();
    let socket = UdpSocket::bind(config.bind)?;
    socket.set_nonblocking(true)?;
    let shutdown = ShutdownSignal::install()?;

    let mut gateway = Gateway::new(config.gateway);
    let mut downstream = config.downstream.map(DownstreamPublisher::new);
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
                Ok((len, peer)) => {
                    made_progress = true;
                    metrics.counters_mut().control_datagrams_received_total += 1;
                    match gateway.handle_datagram(peer, &buf[..len]) {
                        Ok(GatewayAction::Send {
                            destination,
                            datagram,
                        }) => {
                            socket.send_to(&datagram, destination)?;
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
                        Ok(GatewayAction::MulticastData { packet }) => {
                            metrics.counters_mut().multicast_data_received_total += 1;
                            metrics.counters_mut().multicast_data_bytes_received_total +=
                                packet.len() as u64;
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

#[derive(Debug, Clone)]
struct ShutdownSignal {
    requested: Arc<AtomicBool>,
}

impl ShutdownSignal {
    fn install() -> io::Result<Self> {
        let requested = Arc::new(AtomicBool::new(false));
        let handler_requested = Arc::clone(&requested);
        ctrlc::set_handler(move || {
            handler_requested.store(true, Ordering::SeqCst);
        })
        .map_err(|error| io::Error::other(format!("failed to install signal handler: {error}")))?;

        Ok(Self { requested })
    }

    fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

fn shutdown_gateway(
    socket: &UdpSocket,
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
    socket: &UdpSocket,
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
    socket: &UdpSocket,
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
    socket: &UdpSocket,
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

fn send_gateway_action(socket: &UdpSocket, action: GatewayAction) -> io::Result<()> {
    if let GatewayAction::Send {
        destination,
        datagram,
    } = action
    {
        socket.send_to(&datagram, destination)?;
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
    socket: &'a UdpSocket,
    relay: &'a mut Relay,
    upstream: &'a mut UpstreamManager,
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
                RelayAction::Send(response) => match socket.send_to(&response, peer) {
                    Ok(_) => {
                        metrics.counters_mut().control_responses_sent_total += 1;
                        metrics.counters_mut().control_response_bytes_sent_total +=
                            response.len() as u64;
                    }
                    Err(_) => metrics.counters_mut().send_errors_total += 1,
                },
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
    upstream: &mut UpstreamManager,
    metrics: &mut MetricsRecorder,
) -> io::Result<()> {
    let subscriptions = state.upstream_subscriptions();
    let changes = upstream
        .reconcile(subscriptions)
        .map_err(|error| io::Error::other(format!("failed to update upstream receive: {error}")))?;
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

fn drain_upstream(
    socket: &UdpSocket,
    relay: &Relay,
    upstream: &mut UpstreamManager,
    path_mtu: usize,
    metrics: &mut MetricsRecorder,
    data_log: &mut RelayDataLog,
) -> io::Result<usize> {
    if upstream.active_subscription_count() == 0 {
        return Ok(0);
    }

    let mut forwarded_packets = 0;

    for _ in 0..MAX_UPSTREAM_DRAIN {
        let Some(datagram) = upstream.try_recv().map_err(|error| {
            io::Error::other(format!("failed to receive upstream multicast: {error}"))
        })?
        else {
            break;
        };
        metrics.counters_mut().upstream_packets_received_total += 1;
        metrics.counters_mut().upstream_bytes_received_total += datagram.datagram().len() as u64;
        data_log.record_received(datagram.datagram().len());

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
        let mut prepared_ipv4_outer = None;
        let mut prepared_ipv6_outer = None;
        let mut successful_endpoints = 0u64;
        let mut successful_bytes = 0u64;
        for endpoint in endpoints {
            let tunnel_mtu = tunnel_mtu(path_mtu, endpoint);
            if inner_packet.len() <= tunnel_mtu {
                if send_tunnel_datagram(socket, &response, endpoint, metrics, data_log) {
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
                continue;
            };

            let mut complete = true;
            for fragment in fragments {
                if send_tunnel_datagram(socket, fragment, endpoint, metrics, data_log) {
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

        metrics.counters_mut().upstream_packets_forwarded_total += successful_endpoints;
        metrics.counters_mut().upstream_bytes_forwarded_total += successful_bytes;
        forwarded_packets += 1;
        data_log.record_forwarded(forwarded_len, successful_endpoints);
    }

    Ok(forwarded_packets)
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

fn send_tunnel_datagram(
    socket: &UdpSocket,
    datagram: &[u8],
    endpoint: SocketAddr,
    metrics: &mut MetricsRecorder,
    data_log: &mut RelayDataLog,
) -> bool {
    if let Err(error) = socket.send_to(datagram, endpoint) {
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
            send_errors: 0,
            last_send_error: None,
            mtu_drops: 0,
            last_mtu_drop: None,
        }
    }

    fn record_received(&mut self, bytes: usize) {
        self.received_packets += 1;
        self.received_bytes += bytes as u64;
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
            "relay data-plane summary: received={} packets/{} bytes, forwarded={} packets to {} gateway endpoint(s)/{} bytes, unmatched={}, mtu_drops={}, send_errors={}",
            self.received_packets,
            self.received_bytes,
            self.forwarded_packets,
            self.forwarded_gateway_sends,
            self.forwarded_bytes,
            self.unmatched_packets,
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
        self.received_packets != 0 || self.send_errors != 0 || self.mtu_drops != 0
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

fn relay_metrics_flags(
    config: &MetricsConfig,
    bind_addr: SocketAddr,
    relay: &Relay,
    upstream: &UpstreamManager,
    path_mtu: usize,
) -> MetricsFlags {
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (config, bind_addr, relay, upstream, path_mtu);
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
    fn gateway_retry_backoff_is_capped() {
        assert_eq!(GatewayRetry::upper_delay(0), Duration::from_secs(1));
        assert_eq!(GatewayRetry::upper_delay(3), Duration::from_secs(8));
        assert_eq!(GatewayRetry::upper_delay(7), Duration::from_secs(120));
        assert_eq!(GatewayRetry::upper_delay(20), Duration::from_secs(120));
    }
}
