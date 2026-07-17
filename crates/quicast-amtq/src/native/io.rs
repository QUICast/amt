use super::NativeError;
use amt::{
    DownstreamConfig, DownstreamPublisher, UpstreamConfig, UpstreamDatagram, UpstreamManager,
    UpstreamReconcile, UpstreamSubscription,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(1);
const DEFAULT_PACKET_QUEUE_CAPACITY: usize = 1_024;
const DEFAULT_MAX_PACKET_BURST: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeIoConfig {
    pub poll_interval: Duration,
    pub packet_queue_capacity: usize,
    pub max_packet_burst: usize,
}

impl Default for NativeIoConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            packet_queue_capacity: DEFAULT_PACKET_QUEUE_CAPACITY,
            max_packet_burst: DEFAULT_MAX_PACKET_BURST,
        }
    }
}

impl NativeIoConfig {
    pub(super) fn validate(&self) -> Result<(), NativeError> {
        if self.poll_interval.is_zero() {
            return Err(NativeError::InvalidConfig(
                "native I/O poll interval is zero",
            ));
        }
        if self.packet_queue_capacity == 0 {
            return Err(NativeError::InvalidConfig(
                "native packet queue capacity is zero",
            ));
        }
        if self.max_packet_burst == 0 {
            return Err(NativeError::InvalidConfig(
                "native packet burst limit is zero",
            ));
        }
        Ok(())
    }
}

enum UpstreamCommand {
    Reconcile {
        subscriptions: Vec<UpstreamSubscription>,
        response: oneshot::Sender<Result<UpstreamReconcile, String>>,
    },
    Shutdown,
}

pub(super) struct UpstreamWorker {
    commands: std_mpsc::Sender<UpstreamCommand>,
    packets: mpsc::Receiver<UpstreamDatagram>,
    thread: Option<JoinHandle<()>>,
    failure: Arc<Mutex<Option<String>>>,
}

impl UpstreamWorker {
    pub(super) fn spawn(
        upstream: UpstreamConfig,
        io: &NativeIoConfig,
        max_subscriptions: usize,
    ) -> Result<Self, NativeError> {
        io.validate()?;
        if max_subscriptions == 0 {
            return Err(NativeError::InvalidConfig(
                "native upstream subscription limit is zero",
            ));
        }

        let (command_sender, command_receiver) = std_mpsc::channel();
        let (packet_sender, packets) = mpsc::channel(io.packet_queue_capacity);
        let (startup_sender, startup_receiver) = std_mpsc::sync_channel(1);
        let failure = Arc::new(Mutex::new(None));
        let worker_failure = Arc::clone(&failure);
        let poll_interval = io.poll_interval;
        let max_packet_burst = io.max_packet_burst;
        let thread = thread::Builder::new()
            .name("amtq-upstream".to_owned())
            .spawn(move || {
                let mut manager =
                    match UpstreamManager::with_subscription_limit(upstream, max_subscriptions) {
                        Ok(manager) => manager,
                        Err(error) => {
                            let message = error.to_string();
                            set_failure(&worker_failure, message.clone());
                            let _ = startup_sender.send(Err(message));
                            return;
                        }
                    };
                if startup_sender.send(Ok(())).is_err() {
                    return;
                }
                run_upstream_worker(
                    &mut manager,
                    command_receiver,
                    packet_sender,
                    poll_interval,
                    max_packet_burst,
                    &worker_failure,
                );
            })
            .map_err(|error| {
                NativeError::NativeIo(format!("failed to start upstream worker: {error}"))
            })?;

        match startup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                commands: command_sender,
                packets,
                thread: Some(thread),
                failure,
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(NativeError::NativeIo(error))
            }
            Err(_) => {
                let _ = thread.join();
                Err(NativeError::NativeIo(
                    "upstream worker stopped during startup".to_owned(),
                ))
            }
        }
    }

    pub(super) async fn reconcile(
        &self,
        subscriptions: Vec<UpstreamSubscription>,
    ) -> Result<UpstreamReconcile, NativeError> {
        let (response_sender, response_receiver) = oneshot::channel();
        self.commands
            .send(UpstreamCommand::Reconcile {
                subscriptions,
                response: response_sender,
            })
            .map_err(|_| self.stopped_error())?;
        response_receiver
            .await
            .map_err(|_| self.stopped_error())?
            .map_err(NativeError::NativeIo)
    }

    pub(super) async fn next_packet(&mut self) -> Option<UpstreamDatagram> {
        self.packets.recv().await
    }

    pub(super) fn stopped_error(&self) -> NativeError {
        NativeError::NativeIo(
            read_failure(&self.failure).unwrap_or_else(|| "upstream worker stopped".to_owned()),
        )
    }

    pub(super) async fn shutdown(mut self) -> Result<(), NativeError> {
        let _ = self.commands.send(UpstreamCommand::Shutdown);
        join_worker(self.thread.take(), self.failure, "upstream").await
    }
}

fn run_upstream_worker(
    manager: &mut UpstreamManager,
    commands: std_mpsc::Receiver<UpstreamCommand>,
    packets: mpsc::Sender<UpstreamDatagram>,
    poll_interval: Duration,
    max_packet_burst: usize,
    failure: &Arc<Mutex<Option<String>>>,
) {
    loop {
        let mut handled_command = false;
        while let Ok(command) = commands.try_recv() {
            handled_command = true;
            if handle_upstream_command(manager, command) {
                return;
            }
        }

        let mut received_packet = false;
        for _ in 0..max_packet_burst {
            match manager.try_recv() {
                Ok(Some(packet)) => {
                    received_packet = true;
                    let _ = packets.try_send(packet);
                }
                Ok(None) => break,
                Err(error) => {
                    set_failure(failure, error.to_string());
                    return;
                }
            }
        }

        if !received_packet && !handled_command {
            match commands.recv_timeout(poll_interval) {
                Ok(command) => {
                    if handle_upstream_command(manager, command) {
                        return;
                    }
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => {}
                Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }
}

fn handle_upstream_command(manager: &mut UpstreamManager, command: UpstreamCommand) -> bool {
    match command {
        UpstreamCommand::Reconcile {
            subscriptions,
            response,
        } => {
            let result = manager
                .reconcile(subscriptions)
                .map_err(|error| error.to_string());
            let _ = response.send(result);
            false
        }
        UpstreamCommand::Shutdown => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum QueueSendError {
    Full,
    Closed,
}

#[derive(Default)]
struct DownstreamCounters {
    packets: AtomicU64,
    bytes: AtomicU64,
    invalid: AtomicU64,
    queue_drops: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct DownstreamSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub invalid: u64,
    pub queue_drops: u64,
}

pub(super) struct DownstreamWorker {
    packets: std_mpsc::SyncSender<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    failure: Arc<Mutex<Option<String>>>,
    counters: Arc<DownstreamCounters>,
}

impl DownstreamWorker {
    pub(super) fn spawn(
        downstream: DownstreamConfig,
        io: &NativeIoConfig,
    ) -> Result<Self, NativeError> {
        io.validate()?;
        let (packet_sender, packet_receiver) =
            std_mpsc::sync_channel::<Vec<u8>>(io.packet_queue_capacity);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let failure = Arc::new(Mutex::new(None));
        let worker_failure = Arc::clone(&failure);
        let counters = Arc::new(DownstreamCounters::default());
        let worker_counters = Arc::clone(&counters);
        let poll_interval = io.poll_interval;
        let thread = thread::Builder::new()
            .name("amtq-downstream".to_owned())
            .spawn(move || {
                let mut publisher = DownstreamPublisher::new(downstream);
                while !worker_shutdown.load(Ordering::Acquire) {
                    match packet_receiver.recv_timeout(poll_interval) {
                        Ok(packet) => match publisher.forward_ip_datagram(&packet) {
                            Ok(Some(report)) => {
                                worker_counters.packets.fetch_add(1, Ordering::Relaxed);
                                worker_counters
                                    .bytes
                                    .fetch_add(report.bytes_sent as u64, Ordering::Relaxed);
                            }
                            Ok(None) => {
                                worker_counters.invalid.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(error) => {
                                set_failure(&worker_failure, error.to_string());
                                return;
                            }
                        },
                        Err(std_mpsc::RecvTimeoutError::Timeout) => {}
                        Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
                    }
                }
            })
            .map_err(|error| {
                NativeError::NativeIo(format!("failed to start downstream worker: {error}"))
            })?;

        Ok(Self {
            packets: packet_sender,
            shutdown,
            thread: Some(thread),
            failure,
            counters,
        })
    }

    pub(super) fn try_publish(&self, packet: Vec<u8>) -> Result<(), QueueSendError> {
        match self.packets.try_send(packet) {
            Ok(()) => Ok(()),
            Err(std_mpsc::TrySendError::Full(_)) => {
                self.counters.queue_drops.fetch_add(1, Ordering::Relaxed);
                Err(QueueSendError::Full)
            }
            Err(std_mpsc::TrySendError::Disconnected(_)) => Err(QueueSendError::Closed),
        }
    }

    pub(super) fn snapshot(&self) -> DownstreamSnapshot {
        DownstreamSnapshot {
            packets: self.counters.packets.load(Ordering::Relaxed),
            bytes: self.counters.bytes.load(Ordering::Relaxed),
            invalid: self.counters.invalid.load(Ordering::Relaxed),
            queue_drops: self.counters.queue_drops.load(Ordering::Relaxed),
        }
    }

    pub(super) fn stopped_error(&self) -> NativeError {
        NativeError::NativeIo(
            read_failure(&self.failure).unwrap_or_else(|| "downstream worker stopped".to_owned()),
        )
    }

    pub(super) async fn shutdown(mut self) -> Result<DownstreamSnapshot, NativeError> {
        self.shutdown.store(true, Ordering::Release);
        let snapshot = self.snapshot();
        join_worker(self.thread.take(), self.failure, "downstream").await?;
        Ok(snapshot)
    }
}

async fn join_worker(
    thread: Option<JoinHandle<()>>,
    failure: Arc<Mutex<Option<String>>>,
    name: &'static str,
) -> Result<(), NativeError> {
    let Some(thread) = thread else {
        return Ok(());
    };
    tokio::task::spawn_blocking(move || thread.join())
        .await
        .map_err(|error| NativeError::Task(error.to_string()))?
        .map_err(|_| NativeError::Task(format!("{name} worker panicked")))?;
    match read_failure(&failure) {
        Some(error) => Err(NativeError::NativeIo(error)),
        None => Ok(()),
    }
}

fn set_failure(failure: &Arc<Mutex<Option<String>>>, error: String) {
    if let Ok(mut failure) = failure.lock() {
        *failure = Some(error);
    }
}

fn read_failure(failure: &Arc<Mutex<Option<String>>>) -> Option<String> {
    failure.lock().ok().and_then(|failure| failure.clone())
}
