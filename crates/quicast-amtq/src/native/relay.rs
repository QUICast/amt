use super::io::UpstreamWorker;
use super::{NativeError, NativeIoConfig};
use crate::control::{Context, DataMode};
use crate::session::{PendingMembershipUpdate, ReceptionState, RelayEvent};
use crate::transport::endpoint::{
    ConnectionId, RelayConnection, RelayEndpoint, RelayEndpointConfig, RelayEndpointStats,
    ShutdownReport,
};
use crate::transport::tokio_quiche::{RelayCommand, RelayTransportEvent};
use amt::query::{GeneralQueryConfig, build_general_query};
use amt::{MembershipTable, RelayLimits, UpstreamConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{MissedTickBehavior, timeout};

const DEFAULT_CONNECTION_PACKET_QUEUE: usize = 256;
const DEFAULT_EVENT_QUEUE: usize = 1_024;
const RECONCILE_RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct NativeRelayConfig {
    pub endpoint: RelayEndpointConfig,
    pub upstream: UpstreamConfig,
    pub io: NativeIoConfig,
    pub aggregate_membership_limits: RelayLimits,
    pub connection_packet_queue_capacity: usize,
    pub event_queue_capacity: usize,
    pub query: GeneralQueryConfig,
}

impl NativeRelayConfig {
    pub fn new(endpoint: RelayEndpointConfig) -> Self {
        Self {
            endpoint,
            upstream: UpstreamConfig::default(),
            io: NativeIoConfig::default(),
            aggregate_membership_limits: RelayLimits::default(),
            connection_packet_queue_capacity: DEFAULT_CONNECTION_PACKET_QUEUE,
            event_queue_capacity: DEFAULT_EVENT_QUEUE,
            query: GeneralQueryConfig::for_amt(),
        }
    }

    fn validate(&self) -> Result<(), NativeError> {
        self.io.validate()?;
        if self.aggregate_membership_limits.max_upstream_subscriptions == 0 {
            return Err(NativeError::InvalidConfig(
                "aggregate upstream subscription limit is zero",
            ));
        }
        if self.connection_packet_queue_capacity == 0 {
            return Err(NativeError::InvalidConfig(
                "Relay connection packet queue capacity is zero",
            ));
        }
        if self.event_queue_capacity == 0 {
            return Err(NativeError::InvalidConfig(
                "Relay event queue capacity is zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeRelaySnapshot {
    pub membership_updates: u64,
    pub rejected_membership_updates: u64,
    pub active_upstream_subscriptions: usize,
    pub upstream_packets: u64,
    pub forwarded_datagrams: u64,
    pub packet_queue_drops: u64,
    pub reconcile_retries: u64,
    pub connection_failures: u64,
}

#[derive(Default)]
struct NativeRelayCounters {
    membership_updates: AtomicU64,
    rejected_membership_updates: AtomicU64,
    active_upstream_subscriptions: AtomicUsize,
    upstream_packets: AtomicU64,
    forwarded_datagrams: AtomicU64,
    packet_queue_drops: AtomicU64,
    reconcile_retries: AtomicU64,
    connection_failures: AtomicU64,
}

#[derive(Clone, Default)]
pub struct NativeRelayStats {
    counters: Arc<NativeRelayCounters>,
}

impl NativeRelayStats {
    pub fn snapshot(&self) -> NativeRelaySnapshot {
        NativeRelaySnapshot {
            membership_updates: self.counters.membership_updates.load(Ordering::Relaxed),
            rejected_membership_updates: self
                .counters
                .rejected_membership_updates
                .load(Ordering::Relaxed),
            active_upstream_subscriptions: self
                .counters
                .active_upstream_subscriptions
                .load(Ordering::Relaxed),
            upstream_packets: self.counters.upstream_packets.load(Ordering::Relaxed),
            forwarded_datagrams: self.counters.forwarded_datagrams.load(Ordering::Relaxed),
            packet_queue_drops: self.counters.packet_queue_drops.load(Ordering::Relaxed),
            reconcile_retries: self.counters.reconcile_retries.load(Ordering::Relaxed),
            connection_failures: self.counters.connection_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeRelayStop {
    pub endpoint: ShutdownReport,
    pub snapshot: NativeRelaySnapshot,
}

pub struct NativeRelay {
    local_address: SocketAddr,
    endpoint_stats: RelayEndpointStats,
    stats: NativeRelayStats,
    shutdown: watch::Sender<bool>,
    finished: watch::Receiver<bool>,
    task: Option<JoinHandle<Result<NativeRelayStop, NativeError>>>,
}

impl NativeRelay {
    pub async fn bind(config: NativeRelayConfig) -> Result<Self, NativeError> {
        config.validate()?;
        let upstream = UpstreamWorker::spawn(
            config.upstream.clone(),
            &config.io,
            config
                .aggregate_membership_limits
                .max_upstream_subscriptions,
        )?;
        let endpoint = match RelayEndpoint::bind(config.endpoint.clone()).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                let _ = upstream.shutdown().await;
                return Err(error.into());
            }
        };

        let local_address = endpoint.local_address();
        let endpoint_stats = endpoint.stats();
        let stats = NativeRelayStats::default();
        let task_stats = stats.clone();
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let (finished_sender, finished) = watch::channel(false);
        let task = tokio::spawn(async move {
            let result =
                run_native_relay(endpoint, upstream, config, shutdown_receiver, task_stats).await;
            finished_sender.send_replace(true);
            result
        });

        Ok(Self {
            local_address,
            endpoint_stats,
            stats,
            shutdown,
            finished,
            task: Some(task),
        })
    }

    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    pub fn endpoint_stats(&self) -> RelayEndpointStats {
        self.endpoint_stats.clone()
    }

    pub fn stats(&self) -> NativeRelayStats {
        self.stats.clone()
    }

    pub async fn wait_stopped(&mut self) {
        while !*self.finished.borrow() {
            if self.finished.changed().await.is_err() {
                break;
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<NativeRelayStop, NativeError> {
        self.shutdown.send_replace(true);
        let task = self.task.take().ok_or(NativeError::RuntimeStopped)?;
        task.await
            .map_err(|error| NativeError::Task(error.to_string()))?
    }
}

impl Drop for NativeRelay {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.shutdown.send_replace(true);
        }
    }
}

struct RelayPeer {
    packets: mpsc::Sender<Arc<[u8]>>,
    context_ready: bool,
    authorized: ReceptionState,
}

struct MembershipAuthorization {
    pending: PendingMembershipUpdate,
    authorized: ReceptionState,
}

enum RelayPlaneEvent {
    MembershipUpdate {
        connection_id: ConnectionId,
        pending: PendingMembershipUpdate,
        response: oneshot::Sender<Result<MembershipAuthorization, NativeError>>,
    },
    ContextReady {
        connection_id: ConnectionId,
    },
    Closed {
        connection_id: ConnectionId,
        failed: bool,
    },
}

async fn run_native_relay(
    mut endpoint: RelayEndpoint,
    mut upstream: UpstreamWorker,
    config: NativeRelayConfig,
    mut shutdown: watch::Receiver<bool>,
    stats: NativeRelayStats,
) -> Result<NativeRelayStop, NativeError> {
    let (event_sender, mut events) = mpsc::channel(config.event_queue_capacity);
    let mut peers = HashMap::<ConnectionId, RelayPeer>::new();
    let mut memberships = MembershipTable::<ConnectionId>::default();
    let mut connection_tasks = JoinSet::new();
    let mut needs_reconcile = false;
    let mut reconcile_tick = tokio::time::interval(RECONCILE_RETRY_INTERVAL);
    reconcile_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    reconcile_tick.tick().await;
    let mut run_error = None;

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = endpoint.accept() => {
                let Some(connection) = accepted else {
                    run_error = Some(NativeError::RuntimeStopped);
                    break;
                };
                let connection_id = connection.id();
                let (packet_sender, packet_receiver) =
                    mpsc::channel(config.connection_packet_queue_capacity);
                peers.insert(
                    connection_id,
                    RelayPeer {
                        packets: packet_sender,
                        context_ready: false,
                        authorized: ReceptionState::default(),
                    },
                );
                connection_tasks.spawn(run_relay_connection(
                    connection,
                    packet_receiver,
                    event_sender.clone(),
                    config.query.clone(),
                ));
            }
            event = events.recv() => {
                let Some(event) = event else {
                    run_error = Some(NativeError::RuntimeStopped);
                    break;
                };
                match event {
                    RelayPlaneEvent::MembershipUpdate {
                        connection_id,
                        pending,
                        response,
                    } => {
                        let previous_authorized = peers
                            .get(&connection_id)
                            .map(|peer| peer.authorized.clone())
                            .unwrap_or_default();
                        let result = authorize_membership_update(
                            connection_id,
                            pending,
                            &previous_authorized,
                            &mut memberships,
                            &upstream,
                            &config.aggregate_membership_limits,
                            &stats,
                        ).await;
                        if let Ok((_, retry)) = &result {
                            needs_reconcile |= *retry;
                        }
                        let response_result = result.map(|(authorization, _)| {
                            if let Some(peer) = peers.get_mut(&connection_id) {
                                peer.authorized = authorization.authorized.clone();
                            }
                            authorization
                        });
                        let _ = response.send(response_result);
                    }
                    RelayPlaneEvent::ContextReady { connection_id } => {
                        if let Some(peer) = peers.get_mut(&connection_id) {
                            peer.context_ready = true;
                        }
                    }
                    RelayPlaneEvent::Closed {
                        connection_id,
                        failed,
                    } => {
                        peers.remove(&connection_id);
                        if failed {
                            stats
                                .counters
                                .connection_failures
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        if memberships.remove_endpoint(connection_id) {
                            needs_reconcile |= reconcile_memberships(
                                &memberships,
                                &upstream,
                                &stats,
                            ).await.is_err();
                        }
                    }
                }
            }
            packet = upstream.next_packet() => {
                let Some(packet) = packet else {
                    run_error = Some(upstream.stopped_error());
                    break;
                };
                forward_upstream_packet(packet, &memberships, &peers, &stats);
            }
            _ = reconcile_tick.tick(), if needs_reconcile => {
                stats
                    .counters
                    .reconcile_retries
                    .fetch_add(1, Ordering::Relaxed);
                needs_reconcile =
                    reconcile_memberships(&memberships, &upstream, &stats).await.is_err();
            }
            joined = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if let Some(Err(error)) = joined {
                    stats
                        .counters
                        .connection_failures
                        .fetch_add(1, Ordering::Relaxed);
                    run_error = Some(NativeError::Task(error.to_string()));
                    break;
                }
            }
        }
    }

    events.close();
    drop(events);
    peers.clear();
    memberships = MembershipTable::default();
    let _ = reconcile_memberships(&memberships, &upstream, &stats).await;
    let endpoint_result = endpoint.shutdown().await;

    let join_timeout = config.endpoint.connection.shutdown_timeout;
    if timeout(join_timeout, async {
        while connection_tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connection_tasks.abort_all();
    }
    upstream.shutdown().await?;

    if let Some(error) = run_error {
        return Err(error);
    }
    let endpoint_report = endpoint_result?;
    Ok(NativeRelayStop {
        endpoint: endpoint_report,
        snapshot: stats.snapshot(),
    })
}

async fn authorize_membership_update(
    connection_id: ConnectionId,
    pending: PendingMembershipUpdate,
    previous_authorized: &ReceptionState,
    memberships: &mut MembershipTable<ConnectionId>,
    upstream: &UpstreamWorker,
    limits: &RelayLimits,
    stats: &NativeRelayStats,
) -> Result<(MembershipAuthorization, bool), NativeError> {
    let protocol = pending.report().protocol;
    let requested = pending.requested_state().clone();
    let mut candidate =
        table_with_authorized_state(memberships, connection_id, &requested, protocol, limits);
    let authorized_result = match &mut candidate {
        Ok(candidate) => upstream.reconcile(candidate.upstream_subscriptions()).await,
        Err(error) => Err(NativeError::NativeIo(error.to_string())),
    };

    let (authorized, candidate, reconcile) = match (candidate, authorized_result) {
        (Ok(candidate), Ok(reconcile)) => (requested, candidate, reconcile),
        _ => {
            stats
                .counters
                .rejected_membership_updates
                .fetch_add(1, Ordering::Relaxed);
            let retained = previous_authorized.intersection(&requested);
            let candidate = table_with_authorized_state(
                memberships,
                connection_id,
                &retained,
                protocol,
                limits,
            )
            .map_err(|error| NativeError::NativeIo(error.to_string()))?;
            let reconcile = upstream
                .reconcile(candidate.upstream_subscriptions())
                .await?;
            (retained, candidate, reconcile)
        }
    };

    *memberships = candidate;
    stats
        .counters
        .membership_updates
        .fetch_add(1, Ordering::Relaxed);
    stats
        .counters
        .active_upstream_subscriptions
        .store(reconcile.active, Ordering::Relaxed);
    Ok((
        MembershipAuthorization {
            pending,
            authorized,
        },
        reconcile.failed_removals != 0,
    ))
}

fn table_with_authorized_state(
    memberships: &MembershipTable<ConnectionId>,
    connection_id: ConnectionId,
    authorized: &ReceptionState,
    protocol: amt::MembershipProtocol,
    limits: &RelayLimits,
) -> Result<MembershipTable<ConnectionId>, amt::StateLimitError> {
    let mut candidate = memberships.clone();
    candidate.remove_endpoint(connection_id);
    let report = authorized.current_report(protocol);
    if !report.records.is_empty() {
        candidate.apply_report_limited(connection_id, &report, limits)?;
    }
    Ok(candidate)
}

async fn reconcile_memberships(
    memberships: &MembershipTable<ConnectionId>,
    upstream: &UpstreamWorker,
    stats: &NativeRelayStats,
) -> Result<(), NativeError> {
    let report = upstream
        .reconcile(memberships.upstream_subscriptions())
        .await?;
    stats
        .counters
        .active_upstream_subscriptions
        .store(report.active, Ordering::Relaxed);
    if report.failed_removals != 0 {
        return Err(NativeError::NativeIo(
            "one or more upstream subscriptions could not be removed".to_owned(),
        ));
    }
    Ok(())
}

fn forward_upstream_packet(
    packet: amt::UpstreamDatagram,
    memberships: &MembershipTable<ConnectionId>,
    peers: &HashMap<ConnectionId, RelayPeer>,
    stats: &NativeRelayStats,
) {
    stats
        .counters
        .upstream_packets
        .fetch_add(1, Ordering::Relaxed);
    let recipients = memberships.endpoints_for_packet(packet.source, packet.group);
    if recipients.is_empty() {
        return;
    }
    let message: Arc<[u8]> = packet.normalized_amt_datagram().into();
    for connection_id in recipients {
        let Some(peer) = peers.get(&connection_id) else {
            continue;
        };
        if !peer.context_ready {
            continue;
        }
        match peer.packets.try_send(Arc::clone(&message)) {
            Ok(()) => {
                stats
                    .counters
                    .forwarded_datagrams
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                stats
                    .counters
                    .packet_queue_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

async fn run_relay_connection(
    mut connection: RelayConnection,
    mut packets: mpsc::Receiver<Arc<[u8]>>,
    events: mpsc::Sender<RelayPlaneEvent>,
    query: GeneralQueryConfig,
) {
    let connection_id = connection.id();
    let failed = run_relay_connection_loop(&mut connection, &mut packets, &events, &query)
        .await
        .is_err();

    let _ = connection.controller().close_handle().close();
    let _ = events
        .send(RelayPlaneEvent::Closed {
            connection_id,
            failed,
        })
        .await;
}

async fn run_relay_connection_loop(
    connection: &mut RelayConnection,
    packets: &mut mpsc::Receiver<Arc<[u8]>>,
    events: &mpsc::Sender<RelayPlaneEvent>,
    query: &GeneralQueryConfig,
) -> Result<(), NativeError> {
    let connection_id = connection.id();
    let mut context_opened = false;
    let mut context_ready = false;

    loop {
        tokio::select! {
            biased;
            event = connection.controller_mut().next_event() => {
                let Some(event) = event else {
                    return Err(NativeError::RuntimeStopped);
                };
                match event {
                    RelayTransportEvent::Connected { .. }
                    | RelayTransportEvent::Session(RelayEvent::SettingsReceived)
                    | RelayTransportEvent::Session(RelayEvent::Ignored) => {}
                    RelayTransportEvent::Session(RelayEvent::Request { protocol, .. }) => {
                        connection
                            .controller()
                            .send(RelayCommand::MembershipQuery(build_general_query(protocol, query)))
                            .await?;
                    }
                    RelayTransportEvent::Session(RelayEvent::MembershipUpdate(pending)) => {
                        let (response_sender, response_receiver) = oneshot::channel();
                        events
                            .send(RelayPlaneEvent::MembershipUpdate {
                                connection_id,
                                pending,
                                response: response_sender,
                            })
                            .await
                            .map_err(|_| NativeError::RuntimeStopped)?;
                        let authorization = response_receiver
                            .await
                            .map_err(|_| NativeError::RuntimeStopped)??;
                        let has_interests = authorization.authorized.has_interests();
                        connection
                            .controller()
                            .send(RelayCommand::CommitMembershipUpdate {
                                pending: authorization.pending,
                                authorized: authorization.authorized,
                            })
                            .await?;
                        if has_interests && !context_opened {
                            connection
                                .controller()
                                .send(RelayCommand::OpenContext(Context {
                                    id: 0,
                                    mode: DataMode::Datagram.value(),
                                }))
                                .await?;
                            context_opened = true;
                        }
                    }
                    RelayTransportEvent::Session(RelayEvent::ContextAcknowledged {
                        context_id: 0,
                    }) => {
                        context_ready = true;
                        events
                            .send(RelayPlaneEvent::ContextReady { connection_id })
                            .await
                            .map_err(|_| NativeError::RuntimeStopped)?;
                    }
                    RelayTransportEvent::Session(RelayEvent::ContextAcknowledged { .. }) => {}
                    RelayTransportEvent::Closed { clean } => {
                        return if clean {
                            Ok(())
                        } else {
                            Err(NativeError::ConnectionClosed { clean })
                        };
                    }
                }
            }
            packet = packets.recv(), if context_ready => {
                let Some(message) = packet else {
                    return Ok(());
                };
                connection
                    .controller()
                    .send(RelayCommand::SendDatagram {
                        context_id: 0,
                        message,
                    })
                    .await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amt::{MembershipProtocol, MembershipRecord, MembershipRecordKind, MembershipReport};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn aggregate_table_collapses_asm_over_ssm() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut table = MembershipTable::<ConnectionId>::default();
        let limits = RelayLimits::default();

        table
            .apply_report_limited(
                ConnectionId::from_test_value(1),
                &MembershipReport {
                    protocol: MembershipProtocol::Igmpv3,
                    records: vec![MembershipRecord {
                        kind: MembershipRecordKind::ModeIsInclude,
                        group,
                        sources: vec![source],
                    }],
                },
                &limits,
            )
            .unwrap();
        table
            .apply_report_limited(
                ConnectionId::from_test_value(2),
                &MembershipReport {
                    protocol: MembershipProtocol::Igmpv3,
                    records: vec![MembershipRecord {
                        kind: MembershipRecordKind::ModeIsExclude,
                        group,
                        sources: vec![],
                    }],
                },
                &limits,
            )
            .unwrap();

        assert_eq!(
            table.upstream_subscriptions(),
            vec![amt::UpstreamSubscription::asm(group)]
        );
        assert_eq!(
            table.endpoints_for_packet(source, group),
            vec![
                ConnectionId::from_test_value(1),
                ConnectionId::from_test_value(2)
            ]
        );
    }
}
