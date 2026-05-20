use crate::downstream::{DownstreamConfig, DownstreamPublisher};
use crate::gateway::{Gateway, GatewayAction, GatewayConfig};
use crate::local_membership::{LocalMembershipConfig, LocalMembershipManager};
use crate::metrics::{
    GatewayMetricsGauges, MetricsConfig, MetricsFlags, MetricsRecorder, RelayMetricsGauges,
    base_flags,
};
use crate::protocol::{Message, encode};
use crate::relay::{Relay, RelayAction, RelayConfig};
use crate::state::UpstreamSubscription;
use crate::upstream::{UpstreamConfig, UpstreamDatagram, UpstreamManager};
use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_UDP_DATAGRAM: usize = 65_535;
const MAX_UPSTREAM_DRAIN: usize = 64;
const MAX_LOCAL_MEMBERSHIP_DRAIN: usize = 64;
const IDLE_SLEEP: Duration = Duration::from_millis(10);
const GATEWAY_REDISCOVER_INTERVAL: Duration = Duration::from_secs(1);
pub const DEFAULT_GATEWAY_IDLE_TIMEOUT: Duration = Duration::from_secs(260);
pub const DEFAULT_GATEWAY_PRUNE_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_MEMBERSHIP_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDaemonConfig {
    pub relay: RelayConfig,
    pub upstream: UpstreamConfig,
    pub gateway_idle_timeout: Option<Duration>,
    pub gateway_prune_interval: Duration,
    pub metrics: MetricsConfig,
}

impl RelayDaemonConfig {
    pub fn new(relay: RelayConfig) -> Self {
        Self {
            relay,
            upstream: UpstreamConfig::default(),
            gateway_idle_timeout: Some(DEFAULT_GATEWAY_IDLE_TIMEOUT),
            gateway_prune_interval: DEFAULT_GATEWAY_PRUNE_INTERVAL,
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

    let mut relay = Relay::new(config.relay);
    let mut upstream = UpstreamManager::new(config.upstream);
    let mut gateway_activity = GatewayActivity::default();
    let mut metrics = MetricsRecorder::relay(
        &metrics_config,
        relay_metrics_flags(&metrics_config, socket.local_addr()?, &relay, &upstream),
    )?;
    let mut last_gateway_prune = Instant::now();
    println!(
        "amt relay listening on {} (advertising IPv4 {}, IPv6 {})",
        socket.local_addr()?,
        relay.config().advertise_ipv4,
        relay.config().advertise_ipv6
    );
    if let Some(path) = metrics.path() {
        println!("heimdall metrics enabled: {}", path.display());
    } else if metrics_config.requested() {
        println!("heimdall metrics requested but this binary was built without --features metrics");
    }

    let mut buf = [0; MAX_UDP_DATAGRAM];
    loop {
        let mut made_progress = false;

        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    made_progress = true;
                    handle_amt_datagram(
                        &socket,
                        &mut relay,
                        &mut upstream,
                        &mut gateway_activity,
                        &mut metrics,
                        peer,
                        &buf[..len],
                    )?;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        if let Some(timeout) = config.gateway_idle_timeout
            && last_gateway_prune.elapsed() >= config.gateway_prune_interval
        {
            let expired = prune_stale_gateways(&mut relay, &mut gateway_activity, timeout);
            if expired != 0 {
                metrics.counters_mut().gateways_expired_total += expired as u64;
                println!(
                    "expired {expired} idle gateway(s); active gateways={}",
                    gateway_activity.len()
                );
                sync_upstream(&relay, &mut upstream, &mut metrics)?;
            }
            last_gateway_prune = Instant::now();
            made_progress = true;
        }

        let forwarded = drain_upstream(&socket, &relay, &mut upstream, &mut metrics)?;
        made_progress |= forwarded != 0;
        match metrics.maybe_emit_relay(RelayMetricsGauges {
            active_gateways: gateway_activity.len() as u64,
            active_upstream_subscriptions: upstream.active_subscription_count() as u64,
        }) {
            Ok(emitted) => made_progress |= emitted,
            Err(error) => eprintln!("failed to write relay metrics sample: {error}"),
        }

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
    let mut last_discovery = Instant::now()
        .checked_sub(GATEWAY_REDISCOVER_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut last_local_query: Option<Instant> = None;
    let mut last_membership_refresh: Option<Instant> = None;
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
    if let Some(path) = metrics.path() {
        println!("heimdall metrics enabled: {}", path.display());
    } else if metrics_config.requested() {
        println!("heimdall metrics requested but this binary was built without --features metrics");
    }

    loop {
        let mut made_progress = false;

        if shutdown.requested() {
            return shutdown_gateway(&socket, &gateway, &mut metrics);
        }

        if gateway.relay_endpoint().is_none()
            && last_discovery.elapsed() >= GATEWAY_REDISCOVER_INTERVAL
        {
            send_gateway_action(&socket, gateway.discovery())?;
            metrics.counters_mut().gateway_discoveries_sent_total += 1;
            last_discovery = Instant::now();
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

        if gateway.response_mac().is_some()
            && let Some(interval) = config.membership_refresh_interval
        {
            let refresh_due = match last_membership_refresh {
                Some(last_refresh) => last_refresh.elapsed() >= interval,
                None => false,
            };
            if refresh_due {
                let refreshed = refresh_gateway_memberships(
                    &socket,
                    &gateway,
                    &config.joins,
                    local_membership.as_mut(),
                    &mut metrics,
                )?;
                last_membership_refresh = Some(Instant::now());
                if refreshed != 0 {
                    metrics.counters_mut().gateway_membership_refreshes_total += 1;
                    println!("refreshed {refreshed} membership update(s) to relay");
                }
                made_progress = true;
            }
        }

        loop {
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
                            println!(
                                "{peer} triggered {} byte gateway response to {destination}",
                                datagram.len()
                            );
                        }
                        Ok(GatewayAction::MembershipQuery { .. }) => {
                            metrics
                                .counters_mut()
                                .gateway_membership_queries_received_total += 1;
                            println!(
                                "{peer} sent Membership Query; sending configured/local joins"
                            );
                            for join in &config.joins {
                                send_gateway_action(
                                    &socket,
                                    gateway.join_group(join.group, join.source).map_err(
                                        |error| {
                                            io::Error::other(format!(
                                                "failed to build membership update: {error}"
                                            ))
                                        },
                                    )?,
                                )?;
                                metrics.counters_mut().gateway_membership_updates_sent_total += 1;
                            }
                            if let Some(local) = local_membership.as_mut() {
                                send_pending_local_membership(
                                    &socket,
                                    &gateway,
                                    local,
                                    &mut metrics,
                                )?;
                            }
                            last_membership_refresh = Some(Instant::now());
                        }
                        Ok(GatewayAction::MulticastData { packet }) => {
                            metrics.counters_mut().multicast_data_received_total += 1;
                            metrics.counters_mut().multicast_data_bytes_received_total +=
                                packet.len() as u64;
                            println!("{peer} sent {} byte AMT multicast packet", packet.len());
                            if let Some(downstream) = downstream.as_mut() {
                                match downstream.forward_ip_datagram(&packet) {
                                    Ok(Some(report)) => {
                                        metrics
                                            .counters_mut()
                                            .downstream_packets_forwarded_total += 1;
                                        metrics.counters_mut().downstream_bytes_forwarded_total +=
                                            report.bytes_sent as u64;
                                        let udp_port = report
                                            .udp_dst_port
                                            .map(|port| format!(":{port}"))
                                            .unwrap_or_default();
                                        println!(
                                            "forwarded downstream raw multicast {} -> {}{} (protocol {}, {} datagram bytes, {} sent)",
                                            report.source,
                                            report.group,
                                            udp_port,
                                            report.ip_protocol,
                                            report.datagram_len,
                                            report.bytes_sent
                                        );
                                    }
                                    Ok(None) => {
                                        metrics
                                            .counters_mut()
                                            .downstream_non_multicast_packets_total += 1;
                                        println!(
                                            "received AMT multicast packet is not a multicast IP datagram"
                                        );
                                    }
                                    Err(error) => {
                                        metrics.counters_mut().downstream_forward_errors_total += 1;
                                        eprintln!(
                                            "failed to forward downstream multicast packet: {error}"
                                        );
                                    }
                                }
                            }
                        }
                        Ok(GatewayAction::Ignored) => {
                            metrics.counters_mut().control_datagrams_ignored_total += 1;
                            println!("{peer} ignored AMT message");
                        }
                        Err(error) => {
                            metrics.counters_mut().control_datagrams_invalid_total += 1;
                            eprintln!("{peer} invalid gateway AMT datagram: {error}");
                        }
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        if let Some(local) = local_membership.as_mut() {
            let events = drain_local_membership(&socket, &gateway, local, &mut metrics)?;
            made_progress |= events != 0;
        }
        match metrics.maybe_emit_gateway(GatewayMetricsGauges {
            relay_connected: gateway.relay_endpoint().is_some(),
            downstream_enabled,
            transparent_enabled,
            configured_joins,
        }) {
            Ok(emitted) => made_progress |= emitted,
            Err(error) => eprintln!("failed to write gateway metrics sample: {error}"),
        }

        if !made_progress {
            thread::sleep(IDLE_SLEEP);
        }
    }
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

fn send_pending_local_membership(
    socket: &UdpSocket,
    gateway: &Gateway,
    local: &mut LocalMembershipManager,
    metrics: &mut MetricsRecorder,
) -> io::Result<()> {
    let Some(report) = local.pending_report() else {
        return Ok(());
    };
    let record_count = report.records.len();
    let action = gateway.membership_update(report).map_err(|error| {
        io::Error::other(format!("failed to build local membership update: {error}"))
    })?;
    send_gateway_action(socket, action)?;
    metrics.counters_mut().gateway_membership_updates_sent_total += 1;
    local.mark_advertised();
    println!("advertised {record_count} local membership record(s) to relay");
    Ok(())
}

fn drain_local_membership(
    socket: &UdpSocket,
    gateway: &Gateway,
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
                    "local membership report from {} ({} records, {} active upstream subscriptions)",
                    event.reporter,
                    event.records_received,
                    event.active_subscriptions.len()
                );
                if gateway.response_mac().is_some() {
                    send_pending_local_membership(socket, gateway, local, metrics)?;
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
    gateway: &Gateway,
    joins: &[GatewayJoin],
    local: Option<&mut LocalMembershipManager>,
    metrics: &mut MetricsRecorder,
) -> io::Result<usize> {
    let mut sent = 0;

    for join in joins {
        send_gateway_action(
            socket,
            gateway
                .join_group(join.group, join.source)
                .map_err(|error| {
                    io::Error::other(format!("failed to build membership refresh: {error}"))
                })?,
        )?;
        metrics.counters_mut().gateway_membership_updates_sent_total += 1;
        sent += 1;
    }

    if let Some(local) = local
        && let Some(report) = local.current_report()
    {
        let action = gateway.membership_update(report).map_err(|error| {
            io::Error::other(format!("failed to build local membership refresh: {error}"))
        })?;
        send_gateway_action(socket, action)?;
        metrics.counters_mut().gateway_membership_updates_sent_total += 1;
        local.mark_advertised();
        sent += 1;
    }

    Ok(sent)
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
        println!(
            "sent {} byte gateway datagram to {destination}",
            datagram.len()
        );
    }

    Ok(())
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

fn handle_amt_datagram(
    socket: &UdpSocket,
    relay: &mut Relay,
    upstream: &mut UpstreamManager,
    gateway_activity: &mut GatewayActivity,
    metrics: &mut MetricsRecorder,
    peer: std::net::SocketAddr,
    datagram: &[u8],
) -> io::Result<()> {
    metrics.counters_mut().control_datagrams_received_total += 1;
    match relay.handle_datagram(peer, datagram) {
        Ok(action) => {
            let sync_required = matches!(
                &action,
                RelayAction::AcceptedMembershipUpdate { .. } | RelayAction::AcceptedTeardown { .. }
            );

            match action {
                RelayAction::Send(response) => {
                    socket.send_to(&response, peer)?;
                    metrics.counters_mut().control_responses_sent_total += 1;
                    metrics.counters_mut().control_response_bytes_sent_total +=
                        response.len() as u64;
                    println!("{peer} sent {} byte response", response.len());
                }
                RelayAction::AcceptedMembershipUpdate {
                    protocol,
                    bytes,
                    records_applied,
                    upstream_subscriptions,
                } => {
                    metrics.counters_mut().membership_updates_accepted_total += 1;
                    metrics.counters_mut().membership_records_applied_total +=
                        records_applied as u64;
                    if relay.state().contains_endpoint(peer) {
                        gateway_activity.mark_seen(peer);
                    } else {
                        gateway_activity.remove(peer);
                    }
                    println!(
                        "{peer} accepted {protocol:?} membership update ({bytes} bytes, {records_applied} records, {} upstream subscriptions, {} active gateways)",
                        upstream_subscriptions.len(),
                        gateway_activity.len()
                    );
                }
                RelayAction::AcceptedTeardown { gateway, removed } => {
                    metrics.counters_mut().teardowns_accepted_total += 1;
                    let gateway_ip = gateway
                        .address
                        .as_ipv4_compatible()
                        .map(IpAddr::V4)
                        .unwrap_or_else(|| IpAddr::V6(gateway.address.as_ipv6()));
                    gateway_activity.remove(SocketAddr::new(gateway_ip, gateway.port));
                    println!(
                        "{peer} accepted teardown for {}:{} (removed={removed})",
                        gateway.address.as_ipv6(),
                        gateway.port
                    );
                }
                RelayAction::RejectedAuth => {
                    metrics.counters_mut().auth_rejections_total += 1;
                    println!("{peer} rejected AMT authentication");
                }
                RelayAction::Ignored => {
                    metrics.counters_mut().control_datagrams_ignored_total += 1;
                    println!("{peer} ignored AMT message");
                }
            }

            if sync_required {
                sync_upstream(relay, upstream, metrics)?;
            }

            Ok(())
        }
        Err(error) => {
            metrics.counters_mut().control_datagrams_invalid_total += 1;
            eprintln!("{peer} invalid AMT datagram: {error}");
            Ok(())
        }
    }
}

fn sync_upstream(
    relay: &Relay,
    upstream: &mut UpstreamManager,
    metrics: &mut MetricsRecorder,
) -> io::Result<()> {
    let subscriptions = relay.state().upstream_subscriptions();
    let changes = upstream
        .reconcile(subscriptions)
        .map_err(|error| io::Error::other(format!("failed to update upstream receive: {error}")))?;
    metrics.counters_mut().upstream_subscription_adds_total += changes.added as u64;
    metrics.counters_mut().upstream_subscription_removes_total += changes.removed as u64;

    if changes.changed() {
        println!(
            "upstream subscriptions changed: +{} -{} active={}",
            changes.added, changes.removed, changes.active
        );
        for subscription in upstream.active_subscriptions() {
            println!("  active upstream {}", format_subscription(subscription));
        }
    }

    Ok(())
}

fn drain_upstream(
    socket: &UdpSocket,
    relay: &Relay,
    upstream: &mut UpstreamManager,
    metrics: &mut MetricsRecorder,
) -> io::Result<usize> {
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

        let endpoints = relay
            .state()
            .endpoints_for_packet(datagram.source, datagram.group);
        if endpoints.is_empty() {
            metrics.counters_mut().upstream_unmatched_packets_total += 1;
            println!(
                "received upstream {} multicast datagram from {} to {}, but no gateway interest matched",
                protocol_name(&datagram),
                datagram.source,
                datagram.group
            );
            continue;
        }

        let forwarded_datagram = datagram.normalized_datagram();
        let response = encode(&Message::MulticastData {
            packet: &forwarded_datagram,
        });

        let mut successful_sends = 0u64;
        for endpoint in &endpoints {
            if let Err(error) = socket.send_to(&response, endpoint) {
                metrics.counters_mut().send_errors_total += 1;
                metrics.counters_mut().upstream_forward_errors_total += 1;
                eprintln!(
                    "failed to forward {} byte multicast datagram to {endpoint}: {error}",
                    forwarded_datagram.len()
                );
            } else {
                successful_sends += 1;
            }
        }

        metrics.counters_mut().upstream_packets_forwarded_total += successful_sends;
        metrics.counters_mut().upstream_bytes_forwarded_total +=
            successful_sends * forwarded_datagram.len() as u64;
        forwarded_packets += 1;
        println!(
            "forwarded {} byte multicast datagram from {} to {} gateway(s)",
            forwarded_datagram.len(),
            datagram.source,
            endpoints.len()
        );
    }

    Ok(forwarded_packets)
}

fn format_subscription(subscription: &UpstreamSubscription) -> String {
    match subscription.source {
        Some(source) => format!("({source}, {})", subscription.group),
        None => format!("(*, {})", subscription.group),
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
) -> MetricsFlags {
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (config, bind_addr, relay, upstream);
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
}
