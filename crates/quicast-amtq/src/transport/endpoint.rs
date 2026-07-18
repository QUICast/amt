//! Production-oriented AMTQ socket, TLS, admission, and lifecycle boundary.

use super::roaming::gateway_socket;
pub use super::roaming::{GatewayPathSnapshot, GatewayPathStats};
use super::tokio_quiche::{
    ConnectionStatus, GatewayCloseHandle, GatewayController, GatewayDriver, GatewayDriverConfig,
    RelayCloseHandle, RelayController, RelayDriver, RelayDriverConfig, quic_settings,
};
use crate::ProtocolError;
use boring::error::ErrorStack;
use boring::ssl::{
    SslAlert, SslContextBuilder, SslFiletype, SslMethod, SslVerifyError, SslVerifyMode,
};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_quiche::ConnectionParams;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::settings::{CertificateKind, Hooks, TlsCertificatePaths};
use tokio_quiche::{InitialQuicConnection, QuicConnection};

const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONNECTIONS: usize = 1_024;
const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 32;
const DEFAULT_ACCEPT_QUEUE_CAPACITY: usize = 128;
const MAX_RELAY_CONNECTIONS: usize = 65_536;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum EndpointError {
    InvalidConfig(&'static str),
    NonUtf8Path(PathBuf),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    Protocol(ProtocolError),
    Tls(String),
    Quic(String),
    RuntimeStopped,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid AMTQ endpoint config: {reason}")
            }
            Self::NonUtf8Path(path) => {
                write!(formatter, "TLS path is not valid UTF-8: {}", path.display())
            }
            Self::Io { operation, source } => {
                write!(formatter, "AMTQ endpoint failed to {operation}: {source}")
            }
            Self::Protocol(error) => write!(formatter, "AMTQ endpoint protocol error: {error}"),
            Self::Tls(error) => write!(formatter, "AMTQ endpoint TLS error: {error}"),
            Self::Quic(error) => write!(formatter, "AMTQ endpoint QUIC error: {error}"),
            Self::RuntimeStopped => formatter.write_str("AMTQ endpoint runtime has stopped"),
        }
    }
}

impl std::error::Error for EndpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ProtocolError> for EndpointError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIdentity {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

impl TlsIdentity {
    pub fn new(certificate: impl Into<PathBuf>, private_key: impl Into<PathBuf>) -> Self {
        Self {
            certificate: certificate.into(),
            private_key: private_key.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayTrust {
    SystemRoots,
    PemFile(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayTlsConfig {
    pub server_name: String,
    pub trust: GatewayTrust,
    pub client_identity: Option<TlsIdentity>,
}

impl GatewayTlsConfig {
    pub fn system_roots(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            trust: GatewayTrust::SystemRoots,
            client_identity: None,
        }
    }

    pub fn pem_file(server_name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            server_name: server_name.into(),
            trust: GatewayTrust::PemFile(path.into()),
            client_identity: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTlsConfig {
    pub identity: TlsIdentity,
    pub client_ca: Option<PathBuf>,
}

impl RelayTlsConfig {
    pub fn new(identity: TlsIdentity) -> Self {
        Self {
            identity,
            client_ca: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPolicy {
    pub max_idle_timeout: Duration,
    pub handshake_timeout: Duration,
    pub keepalive_interval: Option<Duration>,
    pub shutdown_timeout: Duration,
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            max_idle_timeout: DEFAULT_MAX_IDLE_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            keepalive_interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }
}

impl ConnectionPolicy {
    fn validate(&self) -> Result<(), EndpointError> {
        if self.max_idle_timeout.is_zero() {
            return Err(EndpointError::InvalidConfig(
                "max idle timeout must be non-zero",
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(EndpointError::InvalidConfig(
                "handshake timeout must be non-zero",
            ));
        }
        if self.shutdown_timeout.is_zero() {
            return Err(EndpointError::InvalidConfig(
                "shutdown timeout must be non-zero",
            ));
        }
        if let Some(interval) = self.keepalive_interval {
            if interval.is_zero() {
                return Err(EndpointError::InvalidConfig(
                    "keepalive interval must be non-zero",
                ));
            }
            if interval >= self.max_idle_timeout {
                return Err(EndpointError::InvalidConfig(
                    "keepalive interval must be shorter than max idle timeout",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAdmissionPolicy {
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub accept_queue_capacity: usize,
}

impl Default for RelayAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_ip: DEFAULT_MAX_CONNECTIONS_PER_IP,
            accept_queue_capacity: DEFAULT_ACCEPT_QUEUE_CAPACITY,
        }
    }
}

impl RelayAdmissionPolicy {
    fn validate(&self) -> Result<(), EndpointError> {
        if self.max_connections == 0 {
            return Err(EndpointError::InvalidConfig(
                "maximum Relay connection count is zero",
            ));
        }
        if self.max_connections > MAX_RELAY_CONNECTIONS {
            return Err(EndpointError::InvalidConfig(
                "maximum Relay connection count exceeds its absolute limit",
            ));
        }
        if self.max_connections_per_ip == 0 {
            return Err(EndpointError::InvalidConfig(
                "maximum per-IP Relay connection count is zero",
            ));
        }
        if self.max_connections_per_ip > self.max_connections {
            return Err(EndpointError::InvalidConfig(
                "per-IP Relay connection limit exceeds the global limit",
            ));
        }
        if self.accept_queue_capacity == 0 {
            return Err(EndpointError::InvalidConfig(
                "Relay accept queue capacity is zero",
            ));
        }
        if self.accept_queue_capacity > self.max_connections {
            return Err(EndpointError::InvalidConfig(
                "Relay accept queue exceeds the connection limit",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RelayEndpointConfig {
    pub bind_address: SocketAddr,
    pub tls: RelayTlsConfig,
    pub connection: ConnectionPolicy,
    pub admission: RelayAdmissionPolicy,
    pub driver: RelayDriverConfig,
}

impl RelayEndpointConfig {
    pub fn new(bind_address: SocketAddr, identity: TlsIdentity) -> Self {
        Self {
            bind_address,
            tls: RelayTlsConfig::new(identity),
            connection: ConnectionPolicy::default(),
            admission: RelayAdmissionPolicy::default(),
            driver: RelayDriverConfig::default(),
        }
    }

    fn validate(&self) -> Result<(), EndpointError> {
        self.connection.validate()?;
        self.admission.validate()?;
        validate_identity(&self.tls.identity)?;
        if let Some(client_ca) = &self.tls.client_ca {
            validate_readable_path(client_ca)?;
            let hook = ServerTlsHook::new(&self.tls.identity, client_ca)?;
            build_server_context(&hook).map_err(tls_error)?;
        }
        let mut driver = self.driver.clone();
        driver.keepalive_interval = self.connection.keepalive_interval;
        driver.require_peer_certificate = self.tls.client_ca.is_some();
        RelayDriver::new(driver)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GatewayEndpointConfig {
    pub bind_address: SocketAddr,
    pub relay_address: SocketAddr,
    pub tls: GatewayTlsConfig,
    pub connection: ConnectionPolicy,
    pub driver: GatewayDriverConfig,
}

impl GatewayEndpointConfig {
    pub fn new(relay_address: SocketAddr, server_name: impl Into<String>) -> Self {
        let bind_address = match relay_address {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        Self {
            bind_address,
            relay_address,
            tls: GatewayTlsConfig::system_roots(server_name),
            connection: ConnectionPolicy::default(),
            driver: GatewayDriverConfig::default(),
        }
    }

    fn validate(&self) -> Result<(), EndpointError> {
        self.connection.validate()?;
        if self.bind_address.is_ipv4() != self.relay_address.is_ipv4() {
            return Err(EndpointError::InvalidConfig(
                "Gateway bind and Relay addresses use different families",
            ));
        }
        if self.tls.server_name.is_empty() {
            return Err(EndpointError::InvalidConfig(
                "Gateway TLS server name is empty",
            ));
        }
        if let Some(identity) = &self.tls.client_identity {
            validate_identity(identity)?;
        }
        if let GatewayTrust::PemFile(ca) = &self.tls.trust {
            validate_readable_path(ca)?;
            let hook = ClientTlsHook::new(ca, self.tls.client_identity.as_ref())?;
            build_client_context(&hook).map_err(tls_error)?;
        }
        let mut driver = self.driver.clone();
        driver.keepalive_interval = self.connection.keepalive_interval;
        GatewayDriver::new(driver)?;
        Ok(())
    }
}

/// Stable process-local identity for one AMTQ connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub const fn get(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn from_test_value(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "amtq-{}", self.0)
    }
}

impl amt::MembershipEndpoint for ConnectionId {
    fn source_ip(self) -> Option<IpAddr> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayEndpointSnapshot {
    pub admitted_connections: u64,
    pub established_connections: u64,
    pub rejected_connections: u64,
    pub handshake_failures: u64,
    pub closed_connections: u64,
    pub forced_shutdowns: u64,
    pub active_connections: usize,
}

#[derive(Default)]
struct RelayEndpointCounters {
    admitted: AtomicU64,
    established: AtomicU64,
    rejected: AtomicU64,
    handshake_failures: AtomicU64,
    closed: AtomicU64,
    forced_shutdowns: AtomicU64,
    active: AtomicUsize,
}

#[derive(Clone, Default)]
pub struct RelayEndpointStats {
    counters: Arc<RelayEndpointCounters>,
}

impl RelayEndpointStats {
    pub fn snapshot(&self) -> RelayEndpointSnapshot {
        RelayEndpointSnapshot {
            admitted_connections: self.counters.admitted.load(Ordering::Relaxed),
            established_connections: self.counters.established.load(Ordering::Relaxed),
            rejected_connections: self.counters.rejected.load(Ordering::Relaxed),
            handshake_failures: self.counters.handshake_failures.load(Ordering::Relaxed),
            closed_connections: self.counters.closed.load(Ordering::Relaxed),
            forced_shutdowns: self.counters.forced_shutdowns.load(Ordering::Relaxed),
            active_connections: self.counters.active.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    pub graceful: bool,
    pub forced_connections: usize,
}

pub struct RelayConnection {
    id: ConnectionId,
    local_address: SocketAddr,
    peer_address: SocketAddr,
    controller: RelayController,
    close_handle: RelayCloseHandle,
    transport: QuicConnection,
}

impl RelayConnection {
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    pub const fn peer_address(&self) -> SocketAddr {
        self.peer_address
    }

    pub const fn controller(&self) -> &RelayController {
        &self.controller
    }

    pub fn controller_mut(&mut self) -> &mut RelayController {
        &mut self.controller
    }

    pub const fn transport(&self) -> &QuicConnection {
        &self.transport
    }
}

impl Drop for RelayConnection {
    fn drop(&mut self) {
        let _ = self.close_handle.close();
    }
}

pub struct GatewayConnection {
    id: ConnectionId,
    controller: GatewayController,
    close_handle: GatewayCloseHandle,
    status: watch::Receiver<ConnectionStatus>,
    path_stats: GatewayPathStats,
    transport: QuicConnection,
    shutdown_timeout: Duration,
    closing: bool,
}

impl GatewayConnection {
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    pub const fn controller(&self) -> &GatewayController {
        &self.controller
    }

    pub fn controller_mut(&mut self) -> &mut GatewayController {
        &mut self.controller
    }

    pub const fn transport(&self) -> &QuicConnection {
        &self.transport
    }

    pub fn path_stats(&self) -> GatewayPathStats {
        self.path_stats.clone()
    }

    pub async fn shutdown(&mut self) -> ShutdownReport {
        self.closing = true;
        let _ = self.close_handle.close();
        let graceful = wait_for_closed(&mut self.status, self.shutdown_timeout).await;
        ShutdownReport {
            graceful,
            forced_connections: usize::from(!graceful),
        }
    }
}

impl Drop for GatewayConnection {
    fn drop(&mut self) {
        if !self.closing {
            let _ = self.close_handle.close();
        }
    }
}

enum RelayRuntimeCommand {
    Shutdown {
        response: Option<oneshot::Sender<ShutdownReport>>,
    },
}

pub struct RelayEndpoint {
    local_address: SocketAddr,
    incoming: mpsc::Receiver<RelayConnection>,
    commands: mpsc::Sender<RelayRuntimeCommand>,
    manager: Option<JoinHandle<()>>,
    stats: RelayEndpointStats,
    stopped: bool,
}

impl RelayEndpoint {
    pub async fn bind(mut config: RelayEndpointConfig) -> Result<Self, EndpointError> {
        config.validate()?;
        config.driver.keepalive_interval = config.connection.keepalive_interval;
        config.driver.require_peer_certificate = config.tls.client_ca.is_some();

        let socket = UdpSocket::bind(config.bind_address)
            .await
            .map_err(|source| io_error("bind the Relay UDP socket", source))?;
        let local_address = socket
            .local_addr()
            .map_err(|source| io_error("read the Relay UDP socket address", source))?;
        let mut settings = quic_settings(&config.driver.transport)?;
        apply_connection_policy(&mut settings, &config.connection);
        settings.listen_backlog = config.admission.max_connections;
        settings.disable_client_ip_validation = false;

        let identity_paths = tls_identity_paths(&config.tls.identity)?;
        let hooks = if let Some(client_ca) = &config.tls.client_ca {
            let hook = ServerTlsHook::new(&config.tls.identity, client_ca)?;
            Hooks {
                connection_hook: Some(Arc::new(hook)),
            }
        } else {
            Hooks::default()
        };
        let params = ConnectionParams::new_server(settings, identity_paths, hooks);
        let mut listeners = tokio_quiche::listen([socket], params, DefaultMetrics)
            .map_err(|source| io_error("start the Relay QUIC listener", source))?;
        let listener = listeners.pop().ok_or(EndpointError::RuntimeStopped)?;

        let (incoming_sender, incoming) = mpsc::channel(config.admission.accept_queue_capacity);
        let (command_sender, command_receiver) = mpsc::channel(1);
        let stats = RelayEndpointStats::default();
        let manager_stats = stats.clone();
        let manager = tokio::spawn(run_relay_manager(
            listener,
            config,
            incoming_sender,
            command_receiver,
            manager_stats,
        ));

        Ok(Self {
            local_address,
            incoming,
            commands: command_sender,
            manager: Some(manager),
            stats,
            stopped: false,
        })
    }

    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    pub fn stats(&self) -> RelayEndpointStats {
        self.stats.clone()
    }

    pub async fn accept(&mut self) -> Option<RelayConnection> {
        self.incoming.recv().await
    }

    pub async fn shutdown(&mut self) -> Result<ShutdownReport, EndpointError> {
        if self.stopped {
            return Ok(ShutdownReport {
                graceful: true,
                forced_connections: 0,
            });
        }
        let (response_sender, response_receiver) = oneshot::channel();
        self.commands
            .send(RelayRuntimeCommand::Shutdown {
                response: Some(response_sender),
            })
            .await
            .map_err(|_| EndpointError::RuntimeStopped)?;
        let report = response_receiver
            .await
            .map_err(|_| EndpointError::RuntimeStopped)?;
        if let Some(manager) = self.manager.take() {
            manager
                .await
                .map_err(|error| EndpointError::Quic(error.to_string()))?;
        }
        self.stopped = true;
        Ok(report)
    }
}

impl Drop for RelayEndpoint {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self
                .commands
                .try_send(RelayRuntimeCommand::Shutdown { response: None });
        }
    }
}

pub async fn connect_gateway(
    mut config: GatewayEndpointConfig,
) -> Result<GatewayConnection, EndpointError> {
    config.validate()?;
    config.driver.keepalive_interval = config.connection.keepalive_interval;
    let connection_id = next_connection_id().ok_or(EndpointError::RuntimeStopped)?;

    let socket = UdpSocket::bind(config.bind_address)
        .await
        .map_err(|source| io_error("bind the Gateway UDP socket", source))?;
    let (socket, path_stats) = gateway_socket(socket, config.relay_address)
        .map_err(|source| io_error("create the roaming Gateway QUIC socket", source))?;
    let mut settings = quic_settings(&config.driver.transport)?;
    apply_connection_policy(&mut settings, &config.connection);

    let (tls_certificate, hooks) = gateway_tls_params(&config.tls)?;
    let params = ConnectionParams::new_client(settings, tls_certificate, hooks);
    let (driver, controller) = GatewayDriver::new(config.driver)?;
    let close_handle = controller.close_handle();
    let status = controller.subscribe_status();
    let transport = tokio_quiche::quic::connect_with_config(
        socket,
        Some(&config.tls.server_name),
        &params,
        driver,
    )
    .await
    .map_err(|error| EndpointError::Quic(error.to_string()))?;

    Ok(GatewayConnection {
        id: connection_id,
        controller,
        close_handle,
        status,
        path_stats,
        transport,
        shutdown_timeout: config.connection.shutdown_timeout,
        closing: false,
    })
}

struct ActiveRelayConnection {
    peer_ip: IpAddr,
    close_handle: RelayCloseHandle,
}

async fn run_relay_manager(
    mut listener: tokio_quiche::QuicConnectionStream<DefaultMetrics>,
    config: RelayEndpointConfig,
    incoming: mpsc::Sender<RelayConnection>,
    mut commands: mpsc::Receiver<RelayRuntimeCommand>,
    stats: RelayEndpointStats,
) {
    let (cleanup_sender, mut cleanup_receiver) = mpsc::unbounded_channel();
    let (shutdown_sender, _) = watch::channel(false);
    let mut active = HashMap::<ConnectionId, ActiveRelayConnection>::new();
    let mut active_per_ip = HashMap::<IpAddr, usize>::new();

    loop {
        tokio::select! {
            biased;
            command = commands.recv() => {
                let response = match command {
                    Some(RelayRuntimeCommand::Shutdown { response }) => response,
                    None => None,
                };
                let report = shutdown_relay_connections(
                    &mut active,
                    &mut active_per_ip,
                    &mut cleanup_receiver,
                    &shutdown_sender,
                    config.connection.shutdown_timeout,
                    &stats,
                ).await;
                if let Some(response) = response {
                    let _ = response.send(report);
                }
                break;
            }
            Some(connection_id) = cleanup_receiver.recv() => {
                remove_active_connection(
                    connection_id,
                    &mut active,
                    &mut active_per_ip,
                    &stats,
                );
            }
            incoming_connection = listener.next() => {
                let Some(incoming_connection) = incoming_connection else {
                    let _ = shutdown_relay_connections(
                        &mut active,
                        &mut active_per_ip,
                        &mut cleanup_receiver,
                        &shutdown_sender,
                        config.connection.shutdown_timeout,
                        &stats,
                    ).await;
                    break;
                };
                let initial = match incoming_connection {
                    Ok(initial) => initial,
                    Err(_) => {
                        stats.counters.handshake_failures.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let peer_ip = initial.peer_addr().ip();
                let per_ip = active_per_ip.get(&peer_ip).copied().unwrap_or(0);
                if active.len() >= config.admission.max_connections
                    || per_ip >= config.admission.max_connections_per_ip
                {
                    stats.counters.rejected.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let connection_id = match next_connection_id() {
                    Some(connection_id) => connection_id,
                    None => {
                        stats.counters.rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let (driver, controller) = match RelayDriver::new(config.driver.clone()) {
                    Ok(pair) => pair,
                    Err(_) => {
                        stats.counters.rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let close_handle = controller.close_handle();
                let status = controller.subscribe_status();
                let local_address = initial.local_addr();
                let peer_address = initial.peer_addr();

                active.insert(
                    connection_id,
                    ActiveRelayConnection {
                        peer_ip,
                        close_handle: close_handle.clone(),
                    },
                );
                *active_per_ip.entry(peer_ip).or_default() += 1;
                stats.counters.admitted.fetch_add(1, Ordering::Relaxed);
                stats.counters.active.fetch_add(1, Ordering::Relaxed);

                let child_incoming = incoming.clone();
                let child_cleanup = cleanup_sender.clone();
                let child_stats = stats.clone();
                let child_shutdown = shutdown_sender.subscribe();
                tokio::spawn(run_relay_connection(
                    connection_id,
                    initial,
                    driver,
                    controller,
                    close_handle,
                    status,
                    local_address,
                    peer_address,
                    child_incoming,
                    child_cleanup,
                    child_shutdown,
                    child_stats,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_relay_connection(
    connection_id: ConnectionId,
    initial: InitialQuicConnection<UdpSocket, DefaultMetrics>,
    driver: RelayDriver,
    controller: RelayController,
    close_handle: RelayCloseHandle,
    mut status: watch::Receiver<ConnectionStatus>,
    local_address: SocketAddr,
    peer_address: SocketAddr,
    incoming: mpsc::Sender<RelayConnection>,
    cleanup: mpsc::UnboundedSender<ConnectionId>,
    mut shutdown: watch::Receiver<bool>,
    stats: RelayEndpointStats,
) {
    let handshake = initial.handshake(driver);
    tokio::pin!(handshake);
    let handshake_result = tokio::select! {
        result = &mut handshake => Some(result),
        changed = shutdown.changed() => {
            let _ = changed;
            None
        }
    };

    let Some(handshake_result) = handshake_result else {
        let _ = cleanup.send(connection_id);
        return;
    };
    let (transport, running) = match handshake_result {
        Ok(connection) => connection,
        Err(_) => {
            stats
                .counters
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            let _ = cleanup.send(connection_id);
            return;
        }
    };
    InitialQuicConnection::resume(running);
    stats.counters.established.fetch_add(1, Ordering::Relaxed);

    let connection = RelayConnection {
        id: connection_id,
        local_address,
        peer_address,
        controller,
        close_handle: close_handle.clone(),
        transport,
    };
    if incoming.try_send(connection).is_err() {
        stats.counters.rejected.fetch_add(1, Ordering::Relaxed);
        let _ = close_handle.close();
    }

    loop {
        if matches!(*status.borrow(), ConnectionStatus::Closed { .. }) {
            break;
        }
        tokio::select! {
            changed = status.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    let _ = close_handle.close();
                }
            }
        }
    }
    let _ = cleanup.send(connection_id);
}

async fn shutdown_relay_connections(
    active: &mut HashMap<ConnectionId, ActiveRelayConnection>,
    active_per_ip: &mut HashMap<IpAddr, usize>,
    cleanup: &mut mpsc::UnboundedReceiver<ConnectionId>,
    shutdown: &watch::Sender<bool>,
    timeout: Duration,
    stats: &RelayEndpointStats,
) -> ShutdownReport {
    shutdown.send_replace(true);
    for connection in active.values() {
        let _ = connection.close_handle.close();
    }

    let deadline = Instant::now() + timeout;
    while !active.is_empty() {
        let result = tokio::time::timeout_at(deadline, cleanup.recv()).await;
        match result {
            Ok(Some(connection_id)) => {
                remove_active_connection(connection_id, active, active_per_ip, stats);
            }
            Ok(None) | Err(_) => break,
        }
    }

    let forced_connections = active.len();
    if forced_connections != 0 {
        stats
            .counters
            .forced_shutdowns
            .fetch_add(forced_connections as u64, Ordering::Relaxed);
        stats
            .counters
            .closed
            .fetch_add(forced_connections as u64, Ordering::Relaxed);
        stats
            .counters
            .active
            .fetch_sub(forced_connections, Ordering::Relaxed);
        active.clear();
        active_per_ip.clear();
    }
    ShutdownReport {
        graceful: forced_connections == 0,
        forced_connections,
    }
}

fn remove_active_connection(
    connection_id: ConnectionId,
    active: &mut HashMap<ConnectionId, ActiveRelayConnection>,
    active_per_ip: &mut HashMap<IpAddr, usize>,
    stats: &RelayEndpointStats,
) {
    let Some(connection) = active.remove(&connection_id) else {
        return;
    };
    if let Some(count) = active_per_ip.get_mut(&connection.peer_ip) {
        *count -= 1;
        if *count == 0 {
            active_per_ip.remove(&connection.peer_ip);
        }
    }
    stats.counters.closed.fetch_add(1, Ordering::Relaxed);
    stats.counters.active.fetch_sub(1, Ordering::Relaxed);
}

async fn wait_for_closed(
    status: &mut watch::Receiver<ConnectionStatus>,
    timeout: Duration,
) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if matches!(*status.borrow(), ConnectionStatus::Closed { .. }) {
                return;
            }
            if status.changed().await.is_err() {
                return;
            }
        }
    })
    .await
    .is_ok()
}

fn apply_connection_policy(
    settings: &mut tokio_quiche::settings::QuicSettings,
    policy: &ConnectionPolicy,
) {
    settings.max_idle_timeout = Some(policy.max_idle_timeout);
    settings.handshake_timeout = Some(policy.handshake_timeout);
}

fn next_connection_id() -> Option<ConnectionId> {
    NEXT_CONNECTION_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .ok()
        .map(ConnectionId)
}

fn validate_identity(identity: &TlsIdentity) -> Result<(), EndpointError> {
    validate_readable_path(&identity.certificate)?;
    validate_readable_path(&identity.private_key)
}

fn validate_readable_path(path: &Path) -> Result<(), EndpointError> {
    std::fs::File::open(path)
        .map(drop)
        .map_err(|source| io_error("open a TLS file", source))
}

fn path_str(path: &Path) -> Result<&str, EndpointError> {
    path.to_str()
        .ok_or_else(|| EndpointError::NonUtf8Path(path.to_path_buf()))
}

fn tls_identity_paths(identity: &TlsIdentity) -> Result<TlsCertificatePaths<'_>, EndpointError> {
    Ok(TlsCertificatePaths {
        cert: path_str(&identity.certificate)?,
        private_key: path_str(&identity.private_key)?,
        kind: CertificateKind::X509,
    })
}

fn gateway_tls_params(
    config: &GatewayTlsConfig,
) -> Result<(Option<TlsCertificatePaths<'_>>, Hooks), EndpointError> {
    match &config.trust {
        GatewayTrust::SystemRoots => Ok((
            config
                .client_identity
                .as_ref()
                .map(tls_identity_paths)
                .transpose()?,
            Hooks::default(),
        )),
        GatewayTrust::PemFile(ca) => {
            let hook = ClientTlsHook::new(ca, config.client_identity.as_ref())?;
            let trigger = if let Some(identity) = &config.client_identity {
                tls_identity_paths(identity)?
            } else {
                // tokio-quiche 0.18 invokes ConnectionHook only when this
                // otherwise-unused TLS paths value is present.
                let ca = path_str(ca)?;
                TlsCertificatePaths {
                    cert: ca,
                    private_key: ca,
                    kind: CertificateKind::X509,
                }
            };
            Ok((
                Some(trigger),
                Hooks {
                    connection_hook: Some(Arc::new(hook)),
                },
            ))
        }
    }
}

#[derive(Clone)]
struct OwnedIdentity {
    certificate: String,
    private_key: String,
}

impl OwnedIdentity {
    fn new(identity: &TlsIdentity) -> Result<Self, EndpointError> {
        Ok(Self {
            certificate: path_str(&identity.certificate)?.to_owned(),
            private_key: path_str(&identity.private_key)?.to_owned(),
        })
    }
}

#[derive(Clone)]
struct ClientTlsHook {
    ca: String,
    identity: Option<OwnedIdentity>,
}

impl ClientTlsHook {
    fn new(ca: &Path, identity: Option<&TlsIdentity>) -> Result<Self, EndpointError> {
        Ok(Self {
            ca: path_str(ca)?.to_owned(),
            identity: identity.map(OwnedIdentity::new).transpose()?,
        })
    }
}

impl ConnectionHook for ClientTlsHook {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        build_client_context(self)
            .ok()
            .or_else(fail_closed_tls_context)
    }
}

#[derive(Clone)]
struct ServerTlsHook {
    ca: String,
    identity: OwnedIdentity,
}

impl ServerTlsHook {
    fn new(identity: &TlsIdentity, ca: &Path) -> Result<Self, EndpointError> {
        Ok(Self {
            ca: path_str(ca)?.to_owned(),
            identity: OwnedIdentity::new(identity)?,
        })
    }
}

impl ConnectionHook for ServerTlsHook {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        build_server_context(self)
            .ok()
            .or_else(fail_closed_tls_context)
    }
}

fn build_client_context(hook: &ClientTlsHook) -> Result<SslContextBuilder, ErrorStack> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;
    builder.set_ca_file(&hook.ca)?;
    builder.set_verify(SslVerifyMode::PEER);
    if let Some(identity) = &hook.identity {
        configure_identity(&mut builder, identity)?;
    }
    Ok(builder)
}

fn build_server_context(hook: &ServerTlsHook) -> Result<SslContextBuilder, ErrorStack> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())?;
    configure_identity(&mut builder, &hook.identity)?;
    builder.set_ca_file(&hook.ca)?;
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    Ok(builder)
}

fn configure_identity(
    builder: &mut SslContextBuilder,
    identity: &OwnedIdentity,
) -> Result<(), ErrorStack> {
    builder.set_certificate_chain_file(&identity.certificate)?;
    builder.set_private_key_file(&identity.private_key, SslFiletype::PEM)?;
    builder.check_private_key()
}

fn fail_closed_tls_context() -> Option<SslContextBuilder> {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).ok()?;
    builder.set_custom_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |_| Err(SslVerifyError::Invalid(SslAlert::UNKNOWN_CA)),
    );
    Some(builder)
}

fn tls_error(error: ErrorStack) -> EndpointError {
    EndpointError::Tls(error.to_string())
}

fn io_error(operation: &'static str, source: io::Error) -> EndpointError {
    EndpointError::Io { operation, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_policy_rejects_keepalive_at_or_above_idle_timeout() {
        let policy = ConnectionPolicy {
            max_idle_timeout: Duration::from_secs(1),
            keepalive_interval: Some(Duration::from_secs(1)),
            ..ConnectionPolicy::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(EndpointError::InvalidConfig(_))
        ));
    }

    #[test]
    fn gateway_bind_family_follows_the_relay() {
        let ipv4 = GatewayEndpointConfig::new("192.0.2.1:443".parse().unwrap(), "relay.example");
        assert!(ipv4.bind_address.is_ipv4());

        let ipv6 =
            GatewayEndpointConfig::new("[2001:db8::1]:443".parse().unwrap(), "relay.example");
        assert!(ipv6.bind_address.is_ipv6());
    }
}
