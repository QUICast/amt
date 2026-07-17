//! Asynchronous AMTQ Datagram Mode driver for tokio-quiche.

use super::quiche::{EndpointConfig, PeerCapabilities, close_with_protocol_error};
use crate::control::{self, Context, DataMode, Settings};
use crate::session::{
    GatewayEvent, GatewaySession, GatewaySessionConfig, PendingMembershipUpdate, ReceptionState,
    RelayEvent, RelaySession, RelaySessionConfig,
};
use crate::{
    ALPN, ApplicationError, EndpointRole, MAX_CONTROL_RECORD_VALUE, ProtocolError, WireError,
};
use amt::MembershipProtocol;
use std::collections::VecDeque;
use std::fmt;
use std::future;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant as TokioInstant;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::QuicheConnection;

pub const CONTROL_STREAM_ID: u64 = 0;

const IO_BUFFER_LEN: usize = 65_535;
const CONTROL_READ_CHUNK: usize = 16 * 1024;
const MAX_CONTROL_BUFFER: usize = MAX_CONTROL_RECORD_VALUE + 16;
const DEFAULT_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_MAX_PENDING_CONTROL_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_PENDING_DATAGRAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_DATAGRAM_REFRAGMENT_ATTEMPTS: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverLimits {
    pub channel_capacity: usize,
    pub max_pending_control_bytes: usize,
    pub max_pending_datagram_bytes: usize,
}

impl Default for DriverLimits {
    fn default() -> Self {
        Self {
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            max_pending_control_bytes: DEFAULT_MAX_PENDING_CONTROL_BYTES,
            max_pending_datagram_bytes: DEFAULT_MAX_PENDING_DATAGRAM_BYTES,
        }
    }
}

impl DriverLimits {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.channel_capacity == 0 {
            return Err(internal_error("AMTQ driver channel capacity is zero"));
        }
        if self.max_pending_control_bytes < MAX_CONTROL_BUFFER {
            return Err(internal_error(
                "AMTQ pending control-byte limit is below one maximum record",
            ));
        }
        if self.max_pending_datagram_bytes == 0 {
            return Err(internal_error(
                "AMTQ pending multicast-data byte limit is zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GatewayDriverConfig {
    pub transport: EndpointConfig,
    pub session: GatewaySessionConfig,
    pub limits: DriverLimits,
    pub keepalive_interval: Option<Duration>,
}

impl Default for GatewayDriverConfig {
    fn default() -> Self {
        Self {
            transport: EndpointConfig::gateway(false),
            session: GatewaySessionConfig::default(),
            limits: DriverLimits::default(),
            keepalive_interval: None,
        }
    }
}

impl GatewayDriverConfig {
    fn validate(&self) -> Result<(), ProtocolError> {
        self.transport.validate()?;
        self.limits.validate()?;
        if self.transport.role != EndpointRole::Gateway {
            return Err(settings_error(
                "AMTQ Gateway driver has a Relay transport profile",
            ));
        }
        validate_keepalive(self.keepalive_interval)?;
        validate_runtime_modes(&self.transport, &self.session.settings)
    }
}

#[derive(Debug, Clone)]
pub struct RelayDriverConfig {
    pub transport: EndpointConfig,
    pub session: RelaySessionConfig,
    pub limits: DriverLimits,
    pub keepalive_interval: Option<Duration>,
    pub require_peer_certificate: bool,
}

impl Default for RelayDriverConfig {
    fn default() -> Self {
        Self {
            transport: EndpointConfig::relay(false),
            session: RelaySessionConfig::default(),
            limits: DriverLimits::default(),
            keepalive_interval: None,
            require_peer_certificate: false,
        }
    }
}

impl RelayDriverConfig {
    fn validate(&self) -> Result<(), ProtocolError> {
        self.transport.validate()?;
        self.limits.validate()?;
        if self.transport.role != EndpointRole::Relay {
            return Err(settings_error(
                "AMTQ Relay driver has a Gateway transport profile",
            ));
        }
        validate_keepalive(self.keepalive_interval)?;
        validate_runtime_modes(&self.transport, &self.session.settings)
    }
}

fn validate_keepalive(interval: Option<Duration>) -> Result<(), ProtocolError> {
    if interval == Some(Duration::ZERO) {
        return Err(settings_error("AMTQ keepalive interval is zero"));
    }
    Ok(())
}

fn validate_runtime_modes(
    transport: &EndpointConfig,
    settings: &Settings,
) -> Result<(), ProtocolError> {
    if settings.supports(DataMode::ReliableBlock) || transport.reliable_block_mode {
        return Err(settings_error(
            "tokio-quiche AMTQ Reliable Block Mode is not implemented yet",
        ));
    }
    if !settings.supports(DataMode::Datagram) {
        return Err(settings_error(
            "tokio-quiche AMTQ driver requires Datagram Mode",
        ));
    }
    Ok(())
}

/// Builds tokio-quiche settings for an AMTQ endpoint.
///
/// A Gateway profile enables certificate verification. Callers still provide
/// the trust store and Relay certificate through `ConnectionParams`.
pub fn quic_settings(
    config: &EndpointConfig,
) -> Result<tokio_quiche::settings::QuicSettings, ProtocolError> {
    config.validate()?;
    let mut settings = tokio_quiche::settings::QuicSettings::default();
    settings.alpn = vec![ALPN.to_vec()];
    settings.enable_early_data = false;
    settings.initial_max_data = connection_window(config);
    settings.initial_max_stream_data_bidi_local = config.control_window;
    settings.initial_max_stream_data_bidi_remote = config.control_window;
    settings.initial_max_stream_data_uni = config.reliable_stream_window;
    settings.disable_active_migration = false;
    settings.active_connection_id_limit = 4;
    settings.dgram_recv_max_queue_len = config.datagram_recv_queue_len;
    settings.dgram_send_max_queue_len = config.datagram_send_queue_len;

    match config.role {
        EndpointRole::Gateway => {
            settings.enable_dgram = true;
            settings.initial_max_streams_bidi = 0;
            settings.initial_max_streams_uni = config.reliable_stream_credit;
            settings.verify_peer = true;
        }
        EndpointRole::Relay => {
            settings.enable_dgram = false;
            settings.initial_max_streams_bidi = 1;
            settings.initial_max_streams_uni = 0;
            settings.verify_peer = false;
        }
    }
    Ok(settings)
}

fn connection_window(config: &EndpointConfig) -> u64 {
    config.control_window.saturating_add(
        config
            .reliable_stream_window
            .saturating_mul(config.reliable_stream_credit.max(1)),
    )
}

#[derive(Debug)]
pub enum GatewayCommand {
    BeginRequest {
        request_nonce: u32,
        protocol: MembershipProtocol,
    },
    MembershipUpdate(Vec<u8>),
    Close,
}

#[derive(Debug)]
pub enum RelayCommand {
    MembershipQuery(Vec<u8>),
    AuthorizeAll(PendingMembershipUpdate),
    CommitMembershipUpdate {
        pending: PendingMembershipUpdate,
        authorized: ReceptionState,
    },
    OpenContext(Context),
    CloseContext {
        context_id: u64,
    },
    SendDatagram {
        context_id: u64,
        message: Vec<u8>,
    },
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayTransportEvent {
    Connected { peer: PeerCapabilities },
    Session(GatewayEvent),
    MulticastData(Vec<u8>),
    Closed { clean: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayTransportEvent {
    Connected { peer: PeerCapabilities },
    Session(RelayEvent),
    Closed { clean: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Handshaking,
    Established,
    Closed { clean: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerClosed;

impl fmt::Display for ControllerClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AMTQ connection driver is closed")
    }
}

impl std::error::Error for ControllerClosed {}

#[derive(Clone)]
pub struct GatewayCloseHandle {
    shutdown: watch::Sender<bool>,
}

impl GatewayCloseHandle {
    pub fn close(&self) -> Result<(), ControllerClosed> {
        self.shutdown.send(true).map_err(|_| ControllerClosed)
    }
}

#[derive(Clone)]
pub struct RelayCloseHandle {
    shutdown: watch::Sender<bool>,
}

impl RelayCloseHandle {
    pub fn close(&self) -> Result<(), ControllerClosed> {
        self.shutdown.send(true).map_err(|_| ControllerClosed)
    }
}

pub struct GatewayController {
    commands: mpsc::Sender<GatewayCommand>,
    events: mpsc::Receiver<GatewayTransportEvent>,
    status: watch::Receiver<ConnectionStatus>,
    shutdown: watch::Sender<bool>,
}

impl GatewayController {
    pub async fn send(&self, command: GatewayCommand) -> Result<(), ControllerClosed> {
        self.commands
            .send(command)
            .await
            .map_err(|_| ControllerClosed)
    }

    pub async fn next_event(&mut self) -> Option<GatewayTransportEvent> {
        self.events.recv().await
    }

    pub fn status(&self) -> ConnectionStatus {
        *self.status.borrow()
    }

    pub fn subscribe_status(&self) -> watch::Receiver<ConnectionStatus> {
        self.status.clone()
    }

    pub fn close_handle(&self) -> GatewayCloseHandle {
        GatewayCloseHandle {
            shutdown: self.shutdown.clone(),
        }
    }
}

pub struct RelayController {
    commands: mpsc::Sender<RelayCommand>,
    events: mpsc::Receiver<RelayTransportEvent>,
    status: watch::Receiver<ConnectionStatus>,
    shutdown: watch::Sender<bool>,
}

impl RelayController {
    pub async fn send(&self, command: RelayCommand) -> Result<(), ControllerClosed> {
        self.commands
            .send(command)
            .await
            .map_err(|_| ControllerClosed)
    }

    pub async fn next_event(&mut self) -> Option<RelayTransportEvent> {
        self.events.recv().await
    }

    pub fn status(&self) -> ConnectionStatus {
        *self.status.borrow()
    }

    pub fn subscribe_status(&self) -> watch::Receiver<ConnectionStatus> {
        self.status.clone()
    }

    pub fn close_handle(&self) -> RelayCloseHandle {
        RelayCloseHandle {
            shutdown: self.shutdown.clone(),
        }
    }
}

#[derive(Debug)]
struct PendingBytes {
    bytes: Vec<u8>,
    offset: usize,
}

#[derive(Debug)]
struct ControlOutput {
    queue: VecDeque<PendingBytes>,
    pending_bytes: usize,
    limit: usize,
}

impl ControlOutput {
    fn new(limit: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            pending_bytes: 0,
            limit,
        }
    }

    fn push(&mut self, bytes: Vec<u8>) -> Result<(), ProtocolError> {
        let pending = self
            .pending_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| excessive_load("AMTQ pending control-byte accounting overflow"))?;
        if pending > self.limit {
            return Err(excessive_load("AMTQ pending control-byte limit exceeded"));
        }
        self.pending_bytes = pending;
        self.queue.push_back(PendingBytes { bytes, offset: 0 });
        Ok(())
    }

    fn flush(
        &mut self,
        connection: &mut QuicheConnection,
        stream_open: bool,
    ) -> Result<(), ProtocolError> {
        if !stream_open {
            return Ok(());
        }
        while let Some(front) = self.queue.front_mut() {
            match connection.stream_send(CONTROL_STREAM_ID, &front.bytes[front.offset..], false) {
                Ok(0) | Err(quiche::Error::Done) => break,
                Ok(written) => {
                    front.offset += written;
                    self.pending_bytes -= written;
                    if front.offset == front.bytes.len() {
                        self.queue.pop_front();
                    }
                }
                Err(quiche::Error::StreamStopped(_)) => {
                    return Err(control_stream_error("AMTQ peer stopped the control stream"));
                }
                Err(quiche::Error::InvalidStreamState(_)) => break,
                Err(_) => {
                    return Err(internal_error(
                        "quiche failed to write the AMTQ control stream",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PendingDatagram {
    context_id: u64,
    message: Vec<u8>,
    fragments: VecDeque<Vec<u8>>,
    refragment_attempts: u8,
}

#[derive(Debug)]
struct DatagramOutput {
    queue: VecDeque<PendingDatagram>,
    pending_bytes: usize,
    limit: usize,
}

impl DatagramOutput {
    fn new(limit: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            pending_bytes: 0,
            limit,
        }
    }

    fn push(&mut self, context_id: u64, message: Vec<u8>) -> Result<(), ProtocolError> {
        let pending = self
            .pending_bytes
            .checked_add(message.len())
            .ok_or_else(|| excessive_load("AMTQ pending data-byte accounting overflow"))?;
        if pending > self.limit {
            return Err(excessive_load("AMTQ pending data-byte limit exceeded"));
        }
        self.pending_bytes = pending;
        self.queue.push_back(PendingDatagram {
            context_id,
            message,
            fragments: VecDeque::new(),
            refragment_attempts: 0,
        });
        Ok(())
    }

    fn flush(
        &mut self,
        connection: &mut QuicheConnection,
        session: &mut RelaySession,
    ) -> Result<(), ProtocolError> {
        while let Some(front) = self.queue.front_mut() {
            if front.fragments.is_empty() {
                let max_datagram_size = connection.dgram_max_writable_len().ok_or_else(|| {
                    settings_error("AMTQ Gateway no longer permits QUIC DATAGRAM frames")
                })?;
                front.fragments = session
                    .datagrams_for_message(front.context_id, &front.message, max_datagram_size)?
                    .into();
            }

            let Some(fragment) = front.fragments.front() else {
                return Err(internal_error(
                    "AMTQ datagram fragmenter returned no fragments",
                ));
            };
            match connection.dgram_send(fragment) {
                Ok(()) => {
                    front.fragments.pop_front();
                    if front.fragments.is_empty() {
                        self.pending_bytes -= front.message.len();
                        self.queue.pop_front();
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(quiche::Error::BufferTooShort) => {
                    front.refragment_attempts = front.refragment_attempts.saturating_add(1);
                    if front.refragment_attempts > MAX_DATAGRAM_REFRAGMENT_ATTEMPTS {
                        return Err(internal_error(
                            "AMTQ path size changed repeatedly during fragmentation",
                        ));
                    }
                    front.fragments.clear();
                }
                Err(_) => {
                    return Err(internal_error(
                        "quiche failed to queue an AMTQ DATAGRAM frame",
                    ));
                }
            }
        }
        Ok(())
    }
}

pub struct GatewayDriver {
    config: GatewayDriverConfig,
    session: Option<GatewaySession>,
    settings_ready: bool,
    control_input: Vec<u8>,
    control_output: ControlOutput,
    io_buffer: Vec<u8>,
    command_receiver: mpsc::Receiver<GatewayCommand>,
    pending_commands: VecDeque<GatewayCommand>,
    event_sender: mpsc::Sender<GatewayTransportEvent>,
    status_sender: watch::Sender<ConnectionStatus>,
    shutdown_receiver: watch::Receiver<bool>,
    shutdown_due: bool,
    keepalive_deadline: Option<TokioInstant>,
    keepalive_due: bool,
}

impl GatewayDriver {
    pub fn new(config: GatewayDriverConfig) -> Result<(Self, GatewayController), ProtocolError> {
        config.validate()?;
        let (command_sender, command_receiver) = mpsc::channel(config.limits.channel_capacity);
        let (event_sender, event_receiver) = mpsc::channel(config.limits.channel_capacity);
        let (status_sender, status_receiver) = watch::channel(ConnectionStatus::Handshaking);
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let driver = Self {
            control_output: ControlOutput::new(config.limits.max_pending_control_bytes),
            config,
            session: None,
            settings_ready: false,
            control_input: Vec::new(),
            io_buffer: vec![0; IO_BUFFER_LEN],
            command_receiver,
            pending_commands: VecDeque::new(),
            event_sender,
            status_sender,
            shutdown_receiver,
            shutdown_due: false,
            keepalive_deadline: None,
            keepalive_due: false,
        };
        Ok((
            driver,
            GatewayController {
                commands: command_sender,
                events: event_receiver,
                status: status_receiver,
                shutdown: shutdown_sender,
            },
        ))
    }

    fn session_mut(&mut self) -> Result<&mut GatewaySession, ProtocolError> {
        self.session
            .as_mut()
            .ok_or_else(|| internal_error("AMTQ Gateway session is unavailable before handshake"))
    }

    fn emit(&self, event: GatewayTransportEvent) -> Result<(), ProtocolError> {
        self.event_sender
            .try_send(event)
            .map_err(|_| excessive_load("AMTQ Gateway event queue is full"))
    }

    fn arm_keepalive(&mut self) {
        self.keepalive_deadline = self
            .config
            .keepalive_interval
            .map(|interval| TokioInstant::now() + interval);
    }

    fn flush_keepalive(&mut self, connection: &mut QuicheConnection) -> Result<(), ProtocolError> {
        if !self.keepalive_due {
            return Ok(());
        }
        connection
            .send_ack_eliciting()
            .map_err(|_| internal_error("quiche failed to schedule an AMTQ keepalive"))?;
        self.keepalive_due = false;
        self.arm_keepalive();
        Ok(())
    }

    fn process_commands(&mut self, connection: &mut QuicheConnection) -> Result<(), ProtocolError> {
        if self.shutdown_due || *self.shutdown_receiver.borrow() {
            let _ = connection.close(true, 0, b"AMTQ Gateway shutdown");
            return Ok(());
        }
        while let Ok(command) = self.command_receiver.try_recv() {
            self.pending_commands.push_back(command);
        }
        while let Some(command) = self.pending_commands.pop_front() {
            if !self.settings_ready && !matches!(command, GatewayCommand::Close) {
                self.pending_commands.push_front(command);
                break;
            }
            match command {
                GatewayCommand::BeginRequest {
                    request_nonce,
                    protocol,
                } => {
                    let encoded = self
                        .session_mut()?
                        .begin_request(request_nonce, protocol)
                        .map_err(local_command_error)?;
                    self.control_output.push(encoded)?;
                }
                GatewayCommand::MembershipUpdate(report) => {
                    let encoded = self
                        .session_mut()?
                        .membership_update(&report)
                        .map_err(local_command_error)?;
                    self.control_output.push(encoded)?;
                }
                GatewayCommand::Close => {
                    let _ = connection.close(true, 0, b"AMTQ Gateway shutdown");
                }
            }
        }
        Ok(())
    }

    fn read_control(&mut self, connection: &mut QuicheConnection) -> Result<(), ProtocolError> {
        let mut chunk = [0; CONTROL_READ_CHUNK];
        loop {
            match connection.stream_recv(CONTROL_STREAM_ID, &mut chunk) {
                Ok((read, fin)) => {
                    if read != 0 {
                        self.control_input.extend_from_slice(&chunk[..read]);
                        self.process_control_records()?;
                        if self.control_input.len() > MAX_CONTROL_BUFFER {
                            return Err(excessive_load(
                                "AMTQ control record exceeds its buffer limit",
                            ));
                        }
                    }
                    if fin {
                        return Err(control_stream_error("AMTQ peer closed the control stream"));
                    }
                    if read == 0 {
                        break;
                    }
                }
                Err(quiche::Error::Done | quiche::Error::InvalidStreamState(_)) => break,
                Err(quiche::Error::StreamReset(_)) => {
                    return Err(control_stream_error("AMTQ peer reset the control stream"));
                }
                Err(_) => {
                    return Err(internal_error(
                        "quiche failed to read the AMTQ control stream",
                    ));
                }
            }
        }
        Ok(())
    }

    fn process_control_records(&mut self) -> Result<(), ProtocolError> {
        loop {
            let decoded = control::decode_record(&self.control_input, EndpointRole::Relay);
            let (record, consumed) = match decoded {
                Ok(decoded) => decoded,
                Err(error) if error.is_incomplete() => return Ok(()),
                Err(error) => return Err(control_decode_error(error)),
            };
            let session = self.session.as_mut().ok_or_else(|| {
                internal_error("AMTQ Gateway session is unavailable before handshake")
            })?;
            let event = session.handle_control(record)?;
            if let GatewayEvent::ContextOpened {
                acknowledgement, ..
            } = &event
            {
                self.control_output.push(acknowledgement.clone())?;
            }
            if matches!(event, GatewayEvent::SettingsReceived) {
                self.settings_ready = true;
            }
            self.control_input.drain(..consumed);
            self.emit(GatewayTransportEvent::Session(event))?;
        }
    }

    fn read_datagrams(&mut self, connection: &mut QuicheConnection) -> Result<(), ProtocolError> {
        loop {
            match connection.dgram_recv(&mut self.io_buffer) {
                Ok(read) => {
                    let now = Instant::now();
                    let datagram = self.io_buffer[..read].to_vec();
                    if let Some(message) = self.session_mut()?.handle_datagram(&datagram, now)? {
                        self.emit(GatewayTransportEvent::MulticastData(message))?;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(_) => {
                    return Err(internal_error(
                        "quiche failed to read an AMTQ DATAGRAM frame",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl ApplicationOverQuic for GatewayDriver {
    fn on_conn_established(
        &mut self,
        connection: &mut QuicheConnection,
        _handshake_info: &tokio_quiche::quic::HandshakeInfo,
    ) -> tokio_quiche::QuicResult<()> {
        let result = (|| {
            let peer = PeerCapabilities::from_connection(connection, EndpointRole::Gateway)?;
            let mut session_config = self.config.session.clone();
            session_config.relay_initial_max_streams_bidi = peer.initial_max_streams_bidi;
            session_config.gateway_initial_max_streams_uni =
                self.config.transport.local_initial_max_streams_uni();
            let mut session = GatewaySession::new(session_config)?;
            self.control_output.push(session.settings_record()?)?;
            self.session = Some(session);
            self.emit(GatewayTransportEvent::Connected { peer })?;
            self.arm_keepalive();
            self.status_sender
                .send_replace(ConnectionStatus::Established);
            Ok(())
        })();
        finish_driver_result(connection, result)
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.io_buffer
    }

    async fn wait_for_data(
        &mut self,
        _connection: &mut QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        if *self.shutdown_receiver.borrow()
            || !self.pending_commands.is_empty()
            || !self.command_receiver.is_empty()
        {
            return Ok(());
        }
        let command = if let Some(deadline) = self.keepalive_deadline {
            tokio::select! {
                changed = self.shutdown_receiver.changed() => {
                    self.shutdown_due = changed.is_err() || *self.shutdown_receiver.borrow();
                    return Ok(());
                }
                command = self.command_receiver.recv() => command,
                () = tokio::time::sleep_until(deadline) => {
                    self.keepalive_due = true;
                    return Ok(());
                }
            }
        } else {
            tokio::select! {
                changed = self.shutdown_receiver.changed() => {
                    self.shutdown_due = changed.is_err() || *self.shutdown_receiver.borrow();
                    return Ok(());
                }
                command = self.command_receiver.recv() => command,
            }
        };
        match command {
            Some(command) => {
                self.pending_commands.push_back(command);
                Ok(())
            }
            None => {
                if let Some(deadline) = self.keepalive_deadline {
                    tokio::time::sleep_until(deadline).await;
                    self.keepalive_due = true;
                    Ok(())
                } else {
                    future::pending().await
                }
            }
        }
    }

    fn process_reads(&mut self, connection: &mut QuicheConnection) -> tokio_quiche::QuicResult<()> {
        let result = (|| {
            self.process_commands(connection)?;
            let readable: Vec<u64> = connection.readable().collect();
            for stream_id in readable {
                if stream_id != CONTROL_STREAM_ID {
                    return Err(protocol_error(
                        "AMTQ Gateway received a prohibited QUIC stream",
                    ));
                }
                self.read_control(connection)?;
            }
            self.read_datagrams(connection)
        })();
        finish_driver_result(connection, result)
    }

    fn process_writes(
        &mut self,
        connection: &mut QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        let result = (|| {
            self.process_commands(connection)?;
            self.control_output.flush(connection, true)?;
            self.flush_keepalive(connection)
        })();
        finish_driver_result(connection, result)
    }

    fn on_conn_close<M: Metrics>(
        &mut self,
        _connection: &mut QuicheConnection,
        _metrics: &M,
        connection_result: &tokio_quiche::QuicResult<()>,
    ) {
        let _ = self.event_sender.try_send(GatewayTransportEvent::Closed {
            clean: connection_result.is_ok(),
        });
        self.status_sender.send_replace(ConnectionStatus::Closed {
            clean: connection_result.is_ok(),
        });
    }
}

pub struct RelayDriver {
    config: RelayDriverConfig,
    session: Option<RelaySession>,
    settings_ready: bool,
    control_stream_open: bool,
    control_input: Vec<u8>,
    control_output: ControlOutput,
    datagram_output: DatagramOutput,
    io_buffer: Vec<u8>,
    command_receiver: mpsc::Receiver<RelayCommand>,
    pending_commands: VecDeque<RelayCommand>,
    event_sender: mpsc::Sender<RelayTransportEvent>,
    status_sender: watch::Sender<ConnectionStatus>,
    shutdown_receiver: watch::Receiver<bool>,
    shutdown_due: bool,
    keepalive_deadline: Option<TokioInstant>,
    keepalive_due: bool,
}

impl RelayDriver {
    pub fn new(config: RelayDriverConfig) -> Result<(Self, RelayController), ProtocolError> {
        config.validate()?;
        let (command_sender, command_receiver) = mpsc::channel(config.limits.channel_capacity);
        let (event_sender, event_receiver) = mpsc::channel(config.limits.channel_capacity);
        let (status_sender, status_receiver) = watch::channel(ConnectionStatus::Handshaking);
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let driver = Self {
            control_output: ControlOutput::new(config.limits.max_pending_control_bytes),
            datagram_output: DatagramOutput::new(config.limits.max_pending_datagram_bytes),
            config,
            session: None,
            settings_ready: false,
            control_stream_open: false,
            control_input: Vec::new(),
            io_buffer: vec![0; IO_BUFFER_LEN],
            command_receiver,
            pending_commands: VecDeque::new(),
            event_sender,
            status_sender,
            shutdown_receiver,
            shutdown_due: false,
            keepalive_deadline: None,
            keepalive_due: false,
        };
        Ok((
            driver,
            RelayController {
                commands: command_sender,
                events: event_receiver,
                status: status_receiver,
                shutdown: shutdown_sender,
            },
        ))
    }

    fn session_mut(&mut self) -> Result<&mut RelaySession, ProtocolError> {
        self.session
            .as_mut()
            .ok_or_else(|| internal_error("AMTQ Relay session is unavailable before handshake"))
    }

    fn emit(&self, event: RelayTransportEvent) -> Result<(), ProtocolError> {
        self.event_sender
            .try_send(event)
            .map_err(|_| excessive_load("AMTQ Relay event queue is full"))
    }

    fn arm_keepalive(&mut self) {
        self.keepalive_deadline = self
            .config
            .keepalive_interval
            .map(|interval| TokioInstant::now() + interval);
    }

    fn flush_keepalive(&mut self, connection: &mut QuicheConnection) -> Result<(), ProtocolError> {
        if !self.keepalive_due {
            return Ok(());
        }
        connection
            .send_ack_eliciting()
            .map_err(|_| internal_error("quiche failed to schedule an AMTQ keepalive"))?;
        self.keepalive_due = false;
        self.arm_keepalive();
        Ok(())
    }

    fn process_commands(&mut self, connection: &mut QuicheConnection) -> Result<(), ProtocolError> {
        if self.shutdown_due || *self.shutdown_receiver.borrow() {
            let _ = connection.close(true, 0, b"AMTQ Relay shutdown");
            return Ok(());
        }
        while let Ok(command) = self.command_receiver.try_recv() {
            self.pending_commands.push_back(command);
        }
        while let Some(command) = self.pending_commands.pop_front() {
            if !self.settings_ready && !matches!(command, RelayCommand::Close) {
                self.pending_commands.push_front(command);
                break;
            }
            match command {
                RelayCommand::MembershipQuery(query) => {
                    let encoded = self
                        .session_mut()?
                        .membership_query(&query)
                        .map_err(local_command_error)?;
                    self.control_output.push(encoded)?;
                }
                RelayCommand::AuthorizeAll(pending) => {
                    self.session_mut()?
                        .authorize_all(pending)
                        .map_err(local_command_error)?;
                }
                RelayCommand::CommitMembershipUpdate {
                    pending,
                    authorized,
                } => {
                    self.session_mut()?
                        .commit_membership_update(pending, authorized)
                        .map_err(local_command_error)?;
                }
                RelayCommand::OpenContext(context) => {
                    let encoded = self
                        .session_mut()?
                        .open_context(context)
                        .map_err(local_command_error)?;
                    self.control_output.push(encoded)?;
                }
                RelayCommand::CloseContext { context_id } => {
                    let encoded = self
                        .session_mut()?
                        .close_context(context_id)
                        .map_err(local_command_error)?;
                    self.control_output.push(encoded)?;
                }
                RelayCommand::SendDatagram {
                    context_id,
                    message,
                } => {
                    self.datagram_output.push(context_id, message)?;
                }
                RelayCommand::Close => {
                    let _ = connection.close(true, 0, b"AMTQ Relay shutdown");
                }
            }
        }
        Ok(())
    }

    fn read_control(&mut self, connection: &mut QuicheConnection) -> Result<(), ProtocolError> {
        self.control_stream_open = true;
        let mut chunk = [0; CONTROL_READ_CHUNK];
        loop {
            match connection.stream_recv(CONTROL_STREAM_ID, &mut chunk) {
                Ok((read, fin)) => {
                    if read != 0 {
                        self.control_input.extend_from_slice(&chunk[..read]);
                        self.process_control_records()?;
                        if self.control_input.len() > MAX_CONTROL_BUFFER {
                            return Err(excessive_load(
                                "AMTQ control record exceeds its buffer limit",
                            ));
                        }
                    }
                    if fin {
                        return Err(control_stream_error("AMTQ peer closed the control stream"));
                    }
                    if read == 0 {
                        break;
                    }
                }
                Err(quiche::Error::Done | quiche::Error::InvalidStreamState(_)) => break,
                Err(quiche::Error::StreamReset(_)) => {
                    return Err(control_stream_error("AMTQ peer reset the control stream"));
                }
                Err(_) => {
                    return Err(internal_error(
                        "quiche failed to read the AMTQ control stream",
                    ));
                }
            }
        }
        Ok(())
    }

    fn process_control_records(&mut self) -> Result<(), ProtocolError> {
        loop {
            let decoded = control::decode_record(&self.control_input, EndpointRole::Gateway);
            let (record, consumed) = match decoded {
                Ok(decoded) => decoded,
                Err(error) if error.is_incomplete() => return Ok(()),
                Err(error) => return Err(control_decode_error(error)),
            };
            let session = self.session.as_mut().ok_or_else(|| {
                internal_error("AMTQ Relay session is unavailable before handshake")
            })?;
            let event = session.handle_control(record)?;
            if matches!(event, RelayEvent::SettingsReceived) {
                self.settings_ready = true;
            }
            self.control_input.drain(..consumed);
            self.emit(RelayTransportEvent::Session(event))?;
        }
    }

    fn reject_gateway_datagrams(
        &mut self,
        connection: &mut QuicheConnection,
    ) -> Result<(), ProtocolError> {
        if connection.dgram_recv_front_len().is_some() {
            return Err(protocol_error(
                "AMTQ Relay received a prohibited Gateway DATAGRAM frame",
            ));
        }
        Ok(())
    }
}

impl ApplicationOverQuic for RelayDriver {
    fn on_conn_established(
        &mut self,
        connection: &mut QuicheConnection,
        _handshake_info: &tokio_quiche::quic::HandshakeInfo,
    ) -> tokio_quiche::QuicResult<()> {
        let result = (|| {
            if self.config.require_peer_certificate && connection.peer_cert().is_none() {
                return Err(protocol_error(
                    "AMTQ Relay requires an authenticated Gateway certificate",
                ));
            }
            let peer = PeerCapabilities::from_connection(connection, EndpointRole::Relay)?;
            let mut session_config = self.config.session.clone();
            session_config.gateway_max_datagram_frame_size = peer.max_datagram_frame_size;
            session_config.gateway_initial_max_streams_uni = peer.initial_max_streams_uni;
            let mut session = RelaySession::new(session_config)?;
            self.control_output.push(session.settings_record()?)?;
            self.session = Some(session);
            self.emit(RelayTransportEvent::Connected { peer })?;
            self.arm_keepalive();
            self.status_sender
                .send_replace(ConnectionStatus::Established);
            Ok(())
        })();
        finish_driver_result(connection, result)
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.io_buffer
    }

    async fn wait_for_data(
        &mut self,
        _connection: &mut QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        if *self.shutdown_receiver.borrow()
            || !self.pending_commands.is_empty()
            || !self.command_receiver.is_empty()
        {
            return Ok(());
        }
        let command = if let Some(deadline) = self.keepalive_deadline {
            tokio::select! {
                changed = self.shutdown_receiver.changed() => {
                    self.shutdown_due = changed.is_err() || *self.shutdown_receiver.borrow();
                    return Ok(());
                }
                command = self.command_receiver.recv() => command,
                () = tokio::time::sleep_until(deadline) => {
                    self.keepalive_due = true;
                    return Ok(());
                }
            }
        } else {
            tokio::select! {
                changed = self.shutdown_receiver.changed() => {
                    self.shutdown_due = changed.is_err() || *self.shutdown_receiver.borrow();
                    return Ok(());
                }
                command = self.command_receiver.recv() => command,
            }
        };
        match command {
            Some(command) => {
                self.pending_commands.push_back(command);
                Ok(())
            }
            None => {
                if let Some(deadline) = self.keepalive_deadline {
                    tokio::time::sleep_until(deadline).await;
                    self.keepalive_due = true;
                    Ok(())
                } else {
                    future::pending().await
                }
            }
        }
    }

    fn process_reads(&mut self, connection: &mut QuicheConnection) -> tokio_quiche::QuicResult<()> {
        let result = (|| {
            self.process_commands(connection)?;
            let readable: Vec<u64> = connection.readable().collect();
            for stream_id in readable {
                if stream_id != CONTROL_STREAM_ID {
                    let _ = connection.stream_shutdown(
                        stream_id,
                        quiche::Shutdown::Read,
                        ApplicationError::Protocol.code(),
                    );
                    return Err(protocol_error(
                        "AMTQ Relay received a prohibited QUIC stream",
                    ));
                }
                self.read_control(connection)?;
            }
            self.reject_gateway_datagrams(connection)
        })();
        finish_driver_result(connection, result)
    }

    fn process_writes(
        &mut self,
        connection: &mut QuicheConnection,
    ) -> tokio_quiche::QuicResult<()> {
        let result = (|| {
            self.process_commands(connection)?;
            self.control_output
                .flush(connection, self.control_stream_open)?;
            let session = self.session.as_mut().ok_or_else(|| {
                internal_error("AMTQ Relay session is unavailable before handshake")
            })?;
            self.datagram_output.flush(connection, session)?;
            self.flush_keepalive(connection)
        })();
        finish_driver_result(connection, result)
    }

    fn on_conn_close<M: Metrics>(
        &mut self,
        _connection: &mut QuicheConnection,
        _metrics: &M,
        connection_result: &tokio_quiche::QuicResult<()>,
    ) {
        let _ = self.event_sender.try_send(RelayTransportEvent::Closed {
            clean: connection_result.is_ok(),
        });
        self.status_sender.send_replace(ConnectionStatus::Closed {
            clean: connection_result.is_ok(),
        });
    }
}

fn finish_driver_result(
    connection: &mut QuicheConnection,
    result: Result<(), ProtocolError>,
) -> tokio_quiche::QuicResult<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = close_with_protocol_error(connection, &error);
            Err(Box::new(error))
        }
    }
}

fn control_decode_error(error: WireError) -> ProtocolError {
    match error {
        WireError::LimitExceeded { .. } => {
            excessive_load("AMTQ Control Record exceeds an absolute limit")
        }
        _ => protocol_error("invalid AMTQ Control Record framing"),
    }
}

fn local_command_error(_error: ProtocolError) -> ProtocolError {
    internal_error("local AMTQ driver command violated session state")
}

const fn protocol_error(reason: &'static str) -> ProtocolError {
    ProtocolError::new(ApplicationError::Protocol, reason)
}

const fn control_stream_error(reason: &'static str) -> ProtocolError {
    ProtocolError::new(ApplicationError::ControlStream, reason)
}

const fn settings_error(reason: &'static str) -> ProtocolError {
    ProtocolError::new(ApplicationError::Settings, reason)
}

const fn internal_error(reason: &'static str) -> ProtocolError {
    ProtocolError::new(ApplicationError::Internal, reason)
}

const fn excessive_load(reason: &'static str) -> ProtocolError {
    ProtocolError::new(ApplicationError::ExcessiveLoad, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_profiles_do_not_enable_early_data() {
        let gateway = quic_settings(&EndpointConfig::gateway(false)).unwrap();
        assert_eq!(gateway.alpn, vec![ALPN.to_vec()]);
        assert!(gateway.enable_dgram);
        assert!(!gateway.enable_early_data);
        assert_eq!(gateway.initial_max_streams_bidi, 0);
        assert!(gateway.verify_peer);

        let relay = quic_settings(&EndpointConfig::relay(false)).unwrap();
        assert!(!relay.enable_dgram);
        assert!(!relay.enable_early_data);
        assert_eq!(relay.initial_max_streams_bidi, 1);
        assert!(!relay.verify_peer);
    }

    #[test]
    fn runtime_rejects_reliable_mode_until_stream_lifecycle_is_wired() {
        let config = GatewayDriverConfig {
            transport: EndpointConfig::gateway(true),
            session: GatewaySessionConfig {
                settings: Settings::gateway(
                    DataMode::Datagram.bit() | DataMode::ReliableBlock.bit(),
                    Some(DataMode::ReliableBlock.value()),
                ),
                gateway_initial_max_streams_uni: 16,
                ..GatewaySessionConfig::default()
            },
            ..GatewayDriverConfig::default()
        };
        assert_eq!(
            GatewayDriver::new(config).err().unwrap().code,
            ApplicationError::Settings
        );
    }

    #[test]
    fn pending_output_is_bounded() {
        let mut output = DatagramOutput::new(4);
        output.push(0, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(
            output.push(0, vec![5]).unwrap_err().code,
            ApplicationError::ExcessiveLoad
        );
    }

    #[test]
    fn close_signal_bypasses_a_saturated_command_queue() {
        let config = GatewayDriverConfig {
            limits: DriverLimits {
                channel_capacity: 1,
                ..DriverLimits::default()
            },
            ..GatewayDriverConfig::default()
        };
        let (driver, controller) = GatewayDriver::new(config).unwrap();
        controller
            .commands
            .try_send(GatewayCommand::BeginRequest {
                request_nonce: 1,
                protocol: MembershipProtocol::Igmpv3,
            })
            .unwrap();
        controller.close_handle().close().unwrap();
        assert!(*driver.shutdown_receiver.borrow());
    }
}
