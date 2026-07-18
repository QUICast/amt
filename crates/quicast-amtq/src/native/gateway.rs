use super::io::{DownstreamWorker, QueueSendError};
use super::{NativeError, NativeIoConfig, random_request_nonce};
use crate::session::{GatewayEvent, ReceptionState};
use crate::transport::endpoint::{
    GatewayConnection, GatewayEndpointConfig, GatewayPathStats, ShutdownReport, connect_gateway,
};
use crate::transport::tokio_quiche::{GatewayCommand, GatewayTransportEvent};
use amt::membership::build_membership_report;
use amt::{DownstreamConfig, MembershipReport, Message, RelayLimits};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

const DEFAULT_MEMBERSHIP_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct NativeGatewayConfig {
    pub endpoint: GatewayEndpointConfig,
    pub downstream: DownstreamConfig,
    pub io: NativeIoConfig,
    pub membership: MembershipReport,
    pub membership_limits: RelayLimits,
    pub membership_refresh_interval: Duration,
}

impl NativeGatewayConfig {
    pub fn new(
        endpoint: GatewayEndpointConfig,
        downstream: DownstreamConfig,
        membership: MembershipReport,
    ) -> Self {
        Self {
            endpoint,
            downstream,
            io: NativeIoConfig::default(),
            membership,
            membership_limits: RelayLimits::default(),
            membership_refresh_interval: DEFAULT_MEMBERSHIP_REFRESH_INTERVAL,
        }
    }

    fn validate(&self) -> Result<Vec<u8>, NativeError> {
        self.io.validate()?;
        if self.membership_refresh_interval.is_zero() {
            return Err(NativeError::InvalidConfig(
                "membership refresh interval is zero",
            ));
        }
        let packet = build_membership_report(&self.membership)?;
        let mut state = ReceptionState::default();
        state.apply_report_limited(&self.membership, &self.membership_limits)?;
        Ok(packet)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeGatewaySnapshot {
    pub path_reachable: bool,
    pub path_outages: u64,
    pub path_recoveries: u64,
    pub path_datagrams_dropped: u64,
    pub membership_updates_sent: u64,
    pub multicast_datagrams_received: u64,
    pub multicast_bytes_received: u64,
    pub downstream_datagrams_queued: u64,
    pub downstream_queue_drops: u64,
}

impl Default for NativeGatewaySnapshot {
    fn default() -> Self {
        Self {
            path_reachable: true,
            path_outages: 0,
            path_recoveries: 0,
            path_datagrams_dropped: 0,
            membership_updates_sent: 0,
            multicast_datagrams_received: 0,
            multicast_bytes_received: 0,
            downstream_datagrams_queued: 0,
            downstream_queue_drops: 0,
        }
    }
}

#[derive(Default)]
struct NativeGatewayCounters {
    membership_updates_sent: AtomicU64,
    multicast_datagrams_received: AtomicU64,
    multicast_bytes_received: AtomicU64,
    downstream_datagrams_queued: AtomicU64,
    downstream_queue_drops: AtomicU64,
}

#[derive(Clone)]
pub struct NativeGatewayStats {
    counters: Arc<NativeGatewayCounters>,
    path: GatewayPathStats,
}

impl Default for NativeGatewayStats {
    fn default() -> Self {
        Self::new(GatewayPathStats::default())
    }
}

impl NativeGatewayStats {
    fn new(path: GatewayPathStats) -> Self {
        Self {
            counters: Arc::new(NativeGatewayCounters::default()),
            path,
        }
    }
}

impl NativeGatewayStats {
    pub fn snapshot(&self) -> NativeGatewaySnapshot {
        let path = self.path.snapshot();
        NativeGatewaySnapshot {
            path_reachable: path.reachable,
            path_outages: path.outages,
            path_recoveries: path.recoveries,
            path_datagrams_dropped: path.locally_dropped_datagrams,
            membership_updates_sent: self
                .counters
                .membership_updates_sent
                .load(Ordering::Relaxed),
            multicast_datagrams_received: self
                .counters
                .multicast_datagrams_received
                .load(Ordering::Relaxed),
            multicast_bytes_received: self
                .counters
                .multicast_bytes_received
                .load(Ordering::Relaxed),
            downstream_datagrams_queued: self
                .counters
                .downstream_datagrams_queued
                .load(Ordering::Relaxed),
            downstream_queue_drops: self.counters.downstream_queue_drops.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeGatewayStop {
    pub connection: ShutdownReport,
    pub snapshot: NativeGatewaySnapshot,
}

pub struct NativeGateway {
    stats: NativeGatewayStats,
    shutdown: watch::Sender<bool>,
    finished: watch::Receiver<bool>,
    task: Option<JoinHandle<Result<NativeGatewayStop, NativeError>>>,
}

impl NativeGateway {
    pub async fn connect(config: NativeGatewayConfig) -> Result<Self, NativeError> {
        let membership_packet = config.validate()?;
        let request_nonce = random_request_nonce()?;
        let downstream = DownstreamWorker::spawn(config.downstream.clone(), &config.io)?;
        let connection = match connect_gateway(config.endpoint.clone()).await {
            Ok(connection) => connection,
            Err(error) => {
                let _ = downstream.shutdown().await;
                return Err(error.into());
            }
        };

        let stats = NativeGatewayStats::new(connection.path_stats());
        let task_stats = stats.clone();
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let (finished_sender, finished) = watch::channel(false);
        let task = tokio::spawn(async move {
            let result = run_native_gateway(
                connection,
                downstream,
                config,
                membership_packet,
                request_nonce,
                shutdown_receiver,
                task_stats,
            )
            .await;
            finished_sender.send_replace(true);
            result
        });
        Ok(Self {
            stats,
            shutdown,
            finished,
            task: Some(task),
        })
    }

    pub fn stats(&self) -> NativeGatewayStats {
        self.stats.clone()
    }

    pub async fn wait_stopped(&mut self) {
        while !*self.finished.borrow() {
            if self.finished.changed().await.is_err() {
                break;
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<NativeGatewayStop, NativeError> {
        self.shutdown.send_replace(true);
        let task = self.task.take().ok_or(NativeError::RuntimeStopped)?;
        task.await
            .map_err(|error| NativeError::Task(error.to_string()))?
    }
}

impl Drop for NativeGateway {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.shutdown.send_replace(true);
        }
    }
}

async fn run_native_gateway(
    mut connection: GatewayConnection,
    downstream: DownstreamWorker,
    config: NativeGatewayConfig,
    membership_packet: Vec<u8>,
    request_nonce: u32,
    mut shutdown: watch::Receiver<bool>,
    stats: NativeGatewayStats,
) -> Result<NativeGatewayStop, NativeError> {
    let run_result = drive_native_gateway(
        &mut connection,
        &downstream,
        &config,
        &membership_packet,
        request_nonce,
        &mut shutdown,
        &stats,
    )
    .await;
    let connection_report = connection.shutdown().await;
    let downstream_result = downstream.shutdown().await;

    run_result?;
    downstream_result?;
    Ok(NativeGatewayStop {
        connection: connection_report,
        snapshot: stats.snapshot(),
    })
}

async fn drive_native_gateway(
    connection: &mut GatewayConnection,
    downstream: &DownstreamWorker,
    config: &NativeGatewayConfig,
    membership_packet: &[u8],
    request_nonce: u32,
    shutdown: &mut watch::Receiver<bool>,
    stats: &NativeGatewayStats,
) -> Result<(), NativeError> {
    let mut request_started = false;
    let mut query_accepted = false;
    let mut next_refresh = Instant::now() + config.membership_refresh_interval;

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            event = connection.controller_mut().next_event() => {
                let Some(event) = event else {
                    return Err(NativeError::RuntimeStopped);
                };
                match event {
                    GatewayTransportEvent::Connected { .. }
                    | GatewayTransportEvent::Session(GatewayEvent::Ignored)
                    | GatewayTransportEvent::Session(GatewayEvent::ContextOpened { .. })
                    | GatewayTransportEvent::Session(GatewayEvent::ContextClosed { .. })
                    | GatewayTransportEvent::Session(GatewayEvent::ContextClosing { .. }) => {}
                    GatewayTransportEvent::Session(GatewayEvent::SettingsReceived) => {
                        if !request_started {
                            connection
                                .controller()
                                .send(GatewayCommand::BeginRequest {
                                    request_nonce,
                                    protocol: config.membership.protocol,
                                })
                                .await?;
                            request_started = true;
                        }
                    }
                    GatewayTransportEvent::Session(GatewayEvent::MembershipQuery {
                        protocol,
                        ..
                    }) => {
                        if protocol != config.membership.protocol {
                            return Err(NativeError::InvalidConfig(
                                "Relay query protocol does not match Gateway membership",
                            ));
                        }
                        send_membership_update(
                            connection,
                            membership_packet,
                            stats,
                        ).await?;
                        query_accepted = true;
                        next_refresh = Instant::now() + config.membership_refresh_interval;
                    }
                    GatewayTransportEvent::MulticastData(message) => {
                        let packet = multicast_packet(&message)?;
                        stats
                            .counters
                            .multicast_datagrams_received
                            .fetch_add(1, Ordering::Relaxed);
                        stats
                            .counters
                            .multicast_bytes_received
                            .fetch_add(packet.len() as u64, Ordering::Relaxed);
                        match downstream.try_publish(packet.to_vec()) {
                            Ok(()) => {
                                stats
                                    .counters
                                    .downstream_datagrams_queued
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Err(QueueSendError::Full) => {
                                stats
                                    .counters
                                    .downstream_queue_drops
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            Err(QueueSendError::Closed) => {
                                return Err(downstream.stopped_error());
                            }
                        }
                    }
                    GatewayTransportEvent::Closed { clean } => {
                        return Err(NativeError::ConnectionClosed { clean });
                    }
                }
            }
            () = tokio::time::sleep_until(next_refresh), if query_accepted => {
                send_membership_update(connection, membership_packet, stats).await?;
                next_refresh = Instant::now() + config.membership_refresh_interval;
            }
        }
    }
    Ok(())
}

async fn send_membership_update(
    connection: &GatewayConnection,
    membership_packet: &[u8],
    stats: &NativeGatewayStats,
) -> Result<(), NativeError> {
    connection
        .controller()
        .send(GatewayCommand::MembershipUpdate(membership_packet.to_vec()))
        .await?;
    stats
        .counters
        .membership_updates_sent
        .fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn multicast_packet(message: &[u8]) -> Result<&[u8], NativeError> {
    match Message::decode(message) {
        Ok(Message::MulticastData { packet }) => Ok(packet),
        Ok(_) => Err(NativeError::NativeIo(
            "Gateway driver emitted a non-data AMT message as multicast data".to_owned(),
        )),
        Err(error) => Err(NativeError::NativeIo(format!(
            "Gateway driver emitted invalid AMT data: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amt::{MembershipProtocol, MembershipRecord, MembershipRecordKind};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn config_accepts_a_valid_static_membership() {
        let membership = MembershipReport {
            protocol: MembershipProtocol::Igmpv3,
            records: vec![MembershipRecord {
                kind: MembershipRecordKind::ModeIsExclude,
                group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
                sources: vec![],
            }],
        };
        assert!(build_membership_report(&membership).is_ok());
    }
}
