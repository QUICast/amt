use crate::state::UpstreamSubscription;
use crate::upstream::{UpstreamConfig, UpstreamDatagram, UpstreamManager, UpstreamReconcile};
use polling::Poller;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const UPSTREAM_PACKET_QUEUE_CAPACITY: usize = 4_096;

const COMMAND_QUEUE_CAPACITY: usize = 8;
const MAX_CAPTURE_BURST: usize = 256;
const CAPTURE_FAIRNESS_BUDGET: Duration = Duration::from_millis(1);
const MIN_CAPTURE_POLL_INTERVAL: Duration = Duration::from_micros(250);
const MAX_CAPTURE_POLL_INTERVAL: Duration = Duration::from_millis(2);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UpstreamWorkerSnapshot {
    pub accepted_packets: u64,
    pub accepted_bytes: u64,
    pub queue_drops: u64,
    pub failures: u64,
    pub queue_depth: usize,
    pub queue_high_water: usize,
    pub active_subscriptions: usize,
    pub capture_sockets: usize,
}

#[derive(Debug, Default)]
struct UpstreamWorkerCounters {
    accepted_packets: AtomicU64,
    accepted_bytes: AtomicU64,
    queue_drops: AtomicU64,
    failures: AtomicU64,
    queue_depth: AtomicUsize,
    queue_high_water: AtomicUsize,
    active_subscriptions: AtomicUsize,
    capture_sockets: AtomicUsize,
}

impl UpstreamWorkerCounters {
    fn snapshot(&self) -> UpstreamWorkerSnapshot {
        UpstreamWorkerSnapshot {
            accepted_packets: self.accepted_packets.load(Ordering::Relaxed),
            accepted_bytes: self.accepted_bytes.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Acquire),
            queue_high_water: self.queue_high_water.load(Ordering::Relaxed),
            active_subscriptions: self.active_subscriptions.load(Ordering::Relaxed),
            capture_sockets: self.capture_sockets.load(Ordering::Relaxed),
        }
    }

    fn update_runtime_gauges<S: CaptureSource>(&self, source: &S) {
        self.active_subscriptions
            .store(source.active_subscription_count(), Ordering::Relaxed);
        self.capture_sockets
            .store(source.capture_socket_count(), Ordering::Relaxed);
    }

    fn reserve_queue_slot(&self) -> (bool, usize) {
        let previous = self.queue_depth.fetch_add(1, Ordering::AcqRel);
        (previous == 0, previous + 1)
    }

    fn commit_queue_slot(&self, reserved_depth: usize) {
        let depth = reserved_depth.min(self.queue_depth.load(Ordering::Acquire));
        self.queue_high_water.fetch_max(depth, Ordering::Relaxed);
    }

    fn release_queue_slot(&self) {
        let previous = self.queue_depth.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "upstream queue reservation underflow");
    }

    fn record_dequeued(&self) {
        let previous = self.queue_depth.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "upstream queue depth underflow");
    }
}

enum UpstreamCommand {
    Reconcile {
        subscriptions: Vec<UpstreamSubscription>,
        response: SyncSender<Result<UpstreamReconcile, String>>,
    },
    Shutdown {
        response: SyncSender<Result<UpstreamReconcile, String>>,
    },
}

trait CaptureSource: Send + 'static {
    type Packet: Send + 'static;

    fn reconcile(
        &mut self,
        subscriptions: Vec<UpstreamSubscription>,
    ) -> Result<UpstreamReconcile, String>;
    fn try_recv(&mut self) -> Result<Option<Self::Packet>, String>;
    fn packet_len(packet: &Self::Packet) -> usize;
    fn active_subscription_count(&self) -> usize;
    fn capture_socket_count(&self) -> usize;
}

impl CaptureSource for UpstreamManager {
    type Packet = UpstreamDatagram;

    fn reconcile(
        &mut self,
        subscriptions: Vec<UpstreamSubscription>,
    ) -> Result<UpstreamReconcile, String> {
        UpstreamManager::reconcile(self, subscriptions).map_err(|error| error.to_string())
    }

    fn try_recv(&mut self) -> Result<Option<Self::Packet>, String> {
        UpstreamManager::try_recv(self).map_err(|error| error.to_string())
    }

    fn packet_len(packet: &Self::Packet) -> usize {
        packet.datagram().len()
    }

    fn active_subscription_count(&self) -> usize {
        UpstreamManager::active_subscription_count(self)
    }

    fn capture_socket_count(&self) -> usize {
        UpstreamManager::capture_socket_count(self)
    }
}

struct WorkerHandle<P> {
    commands: SyncSender<UpstreamCommand>,
    packets: Receiver<P>,
    counters: Arc<UpstreamWorkerCounters>,
    failure: Arc<Mutex<Option<String>>>,
    thread: Option<JoinHandle<()>>,
}

impl<P> WorkerHandle<P> {
    fn reconcile(&self, subscriptions: Vec<UpstreamSubscription>) -> io::Result<UpstreamReconcile> {
        self.check_failure()?;
        let (response, result) = mpsc::sync_channel(1);
        self.commands
            .send(UpstreamCommand::Reconcile {
                subscriptions,
                response,
            })
            .map_err(|_| self.stopped_error())?;
        result
            .recv()
            .map_err(|_| self.stopped_error())?
            .map_err(|error| {
                io::Error::other(format!("failed to update upstream receive: {error}"))
            })
    }

    fn try_recv(&self) -> io::Result<Option<P>> {
        match self.packets.try_recv() {
            Ok(packet) => {
                self.counters.record_dequeued();
                Ok(Some(packet))
            }
            Err(TryRecvError::Empty) => {
                self.check_failure()?;
                Ok(None)
            }
            Err(TryRecvError::Disconnected) => Err(self.stopped_error()),
        }
    }

    fn snapshot(&self) -> UpstreamWorkerSnapshot {
        self.counters.snapshot()
    }

    fn check_failure(&self) -> io::Result<()> {
        match read_failure(&self.failure) {
            Some(error) => Err(io::Error::other(format!(
                "upstream capture worker failed: {error}"
            ))),
            None => Ok(()),
        }
    }

    fn stopped_error(&self) -> io::Error {
        let detail = read_failure(&self.failure)
            .unwrap_or_else(|| "upstream capture worker stopped unexpectedly".to_string());
        io::Error::other(detail)
    }

    fn stop(&mut self) -> io::Result<()> {
        let Some(thread) = self.thread.take() else {
            return self.check_failure();
        };

        let (response, result) = mpsc::sync_channel(1);
        let sent = self
            .commands
            .send(UpstreamCommand::Shutdown { response })
            .is_ok();
        let cleanup = sent.then(|| result.recv());
        let joined = thread.join();

        if joined.is_err() {
            return Err(io::Error::other("upstream capture worker panicked"));
        }
        if let Some(Ok(Err(error))) = cleanup {
            return Err(io::Error::other(format!(
                "failed to clear upstream subscriptions during shutdown: {error}"
            )));
        }
        if matches!(cleanup, Some(Err(_))) {
            return Err(self.stopped_error());
        }
        self.check_failure()
    }
}

impl<P> Drop for WorkerHandle<P> {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub(crate) struct UpstreamWorker {
    handle: WorkerHandle<UpstreamDatagram>,
    #[cfg(feature = "metrics")]
    config: UpstreamConfig,
    #[cfg(feature = "metrics")]
    shared_capture: bool,
}

impl UpstreamWorker {
    pub(crate) fn spawn(
        config: UpstreamConfig,
        max_subscriptions: usize,
        poller: Arc<Poller>,
    ) -> io::Result<Self> {
        #[cfg(feature = "metrics")]
        let metrics_config = config.clone();
        let manager = UpstreamManager::with_subscription_limit(config, max_subscriptions).map_err(
            |error| io::Error::other(format!("failed to initialize upstream receive: {error}")),
        )?;
        #[cfg(feature = "metrics")]
        let shared_capture = manager.uses_shared_capture();
        let handle = spawn_worker(
            manager,
            poller,
            UPSTREAM_PACKET_QUEUE_CAPACITY,
            "amt-upstream",
        )?;
        Ok(Self {
            handle,
            #[cfg(feature = "metrics")]
            config: metrics_config,
            #[cfg(feature = "metrics")]
            shared_capture,
        })
    }

    #[cfg(feature = "metrics")]
    pub(crate) const fn config(&self) -> &UpstreamConfig {
        &self.config
    }

    #[cfg(feature = "metrics")]
    pub(crate) const fn uses_shared_capture(&self) -> bool {
        self.shared_capture
    }

    pub(crate) fn reconcile(
        &self,
        subscriptions: Vec<UpstreamSubscription>,
    ) -> io::Result<UpstreamReconcile> {
        self.handle.reconcile(subscriptions)
    }

    pub(crate) fn try_recv(&self) -> io::Result<Option<UpstreamDatagram>> {
        self.handle.try_recv()
    }

    pub(crate) fn snapshot(&self) -> UpstreamWorkerSnapshot {
        self.handle.snapshot()
    }

    pub(crate) fn check_failure(&self) -> io::Result<()> {
        self.handle.check_failure()
    }

    pub(crate) fn shutdown(mut self) -> io::Result<()> {
        self.handle.stop()
    }
}

fn spawn_worker<S: CaptureSource>(
    source: S,
    poller: Arc<Poller>,
    packet_capacity: usize,
    thread_name: &str,
) -> io::Result<WorkerHandle<S::Packet>> {
    if packet_capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream worker packet queue capacity must not be zero",
        ));
    }

    let (commands, command_receiver) = mpsc::sync_channel(COMMAND_QUEUE_CAPACITY);
    let (packet_sender, packets) = mpsc::sync_channel(packet_capacity);
    let counters = Arc::new(UpstreamWorkerCounters::default());
    counters.update_runtime_gauges(&source);
    let failure = Arc::new(Mutex::new(None));
    let worker_counters = Arc::clone(&counters);
    let worker_failure = Arc::clone(&failure);
    let thread = thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || {
            run_worker(
                source,
                command_receiver,
                packet_sender,
                worker_counters,
                worker_failure,
                poller,
            );
        })?;

    Ok(WorkerHandle {
        commands,
        packets,
        counters,
        failure,
        thread: Some(thread),
    })
}

fn run_worker<S: CaptureSource>(
    mut source: S,
    commands: Receiver<UpstreamCommand>,
    packets: SyncSender<S::Packet>,
    counters: Arc<UpstreamWorkerCounters>,
    failure: Arc<Mutex<Option<String>>>,
    poller: Arc<Poller>,
) {
    let mut poll_interval = MIN_CAPTURE_POLL_INTERVAL;

    loop {
        let mut handled_command = false;
        while let Ok(command) = commands.try_recv() {
            handled_command = true;
            if handle_command(&mut source, command, &counters) {
                return;
            }
        }

        let started = Instant::now();
        let mut received = 0;
        while received < MAX_CAPTURE_BURST && started.elapsed() < CAPTURE_FAIRNESS_BUDGET {
            let packet = match source.try_recv() {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
                Err(error) => {
                    record_failure(&failure, &counters, error);
                    let _ = poller.notify();
                    return;
                }
            };
            received += 1;
            counters.accepted_packets.fetch_add(1, Ordering::Relaxed);
            counters
                .accepted_bytes
                .fetch_add(S::packet_len(&packet) as u64, Ordering::Relaxed);

            let (was_empty, reserved_depth) = counters.reserve_queue_slot();
            match packets.try_send(packet) {
                Ok(()) => {
                    counters.commit_queue_slot(reserved_depth);
                    if was_empty && let Err(error) = poller.notify() {
                        record_failure(&failure, &counters, error.to_string());
                        return;
                    }
                }
                Err(TrySendError::Full(_)) => {
                    counters.release_queue_slot();
                    counters.queue_drops.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {
                    counters.release_queue_slot();
                    return;
                }
            }
        }

        if received != 0 {
            poll_interval = MIN_CAPTURE_POLL_INTERVAL;
            continue;
        }
        if handled_command {
            continue;
        }

        let command = if source.active_subscription_count() == 0 {
            match commands.recv() {
                Ok(command) => Some(command),
                Err(_) => {
                    let _ = source.reconcile(Vec::new());
                    return;
                }
            }
        } else {
            match commands.recv_timeout(poll_interval) {
                Ok(command) => Some(command),
                Err(RecvTimeoutError::Timeout) => {
                    poll_interval = (poll_interval * 2).min(MAX_CAPTURE_POLL_INTERVAL);
                    None
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = source.reconcile(Vec::new());
                    return;
                }
            }
        };
        if let Some(command) = command
            && handle_command(&mut source, command, &counters)
        {
            return;
        }
    }
}

fn handle_command<S: CaptureSource>(
    source: &mut S,
    command: UpstreamCommand,
    counters: &UpstreamWorkerCounters,
) -> bool {
    match command {
        UpstreamCommand::Reconcile {
            subscriptions,
            response,
        } => {
            let result = source.reconcile(subscriptions);
            counters.update_runtime_gauges(source);
            let _ = response.send(result);
            false
        }
        UpstreamCommand::Shutdown { response } => {
            let result = source.reconcile(Vec::new());
            counters.update_runtime_gauges(source);
            let _ = response.send(result);
            true
        }
    }
}

fn record_failure(
    failure: &Mutex<Option<String>>,
    counters: &UpstreamWorkerCounters,
    error: String,
) {
    counters.failures.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut failure) = failure.lock()
        && failure.is_none()
    {
        *failure = Some(error);
    }
}

fn read_failure(failure: &Mutex<Option<String>>) -> Option<String> {
    failure.lock().ok().and_then(|failure| failure.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug, Default)]
    struct FakeState {
        reconciliations: Vec<Vec<UpstreamSubscription>>,
    }

    struct FakeSource {
        packets: VecDeque<usize>,
        fail_receive: bool,
        active: usize,
        state: Arc<Mutex<FakeState>>,
    }

    impl CaptureSource for FakeSource {
        type Packet = usize;

        fn reconcile(
            &mut self,
            subscriptions: Vec<UpstreamSubscription>,
        ) -> Result<UpstreamReconcile, String> {
            let previous = self.active;
            self.active = subscriptions.len();
            self.state
                .lock()
                .unwrap()
                .reconciliations
                .push(subscriptions);
            Ok(UpstreamReconcile {
                added: self.active.saturating_sub(previous),
                removed: previous.saturating_sub(self.active),
                failed_removals: 0,
                active: self.active,
            })
        }

        fn try_recv(&mut self) -> Result<Option<Self::Packet>, String> {
            if self.fail_receive {
                return Err("injected receive failure".to_string());
            }
            Ok(self.packets.pop_front())
        }

        fn packet_len(_packet: &Self::Packet) -> usize {
            1
        }

        fn active_subscription_count(&self) -> usize {
            self.active
        }

        fn capture_socket_count(&self) -> usize {
            usize::from(self.active != 0)
        }
    }

    struct IdleSource {
        receive_calls: Arc<AtomicUsize>,
        active: usize,
    }

    impl CaptureSource for IdleSource {
        type Packet = usize;

        fn reconcile(
            &mut self,
            subscriptions: Vec<UpstreamSubscription>,
        ) -> Result<UpstreamReconcile, String> {
            let previous = self.active;
            self.active = subscriptions.len();
            Ok(UpstreamReconcile {
                added: self.active.saturating_sub(previous),
                removed: previous.saturating_sub(self.active),
                failed_removals: 0,
                active: self.active,
            })
        }

        fn try_recv(&mut self) -> Result<Option<Self::Packet>, String> {
            self.receive_calls.fetch_add(1, Ordering::Relaxed);
            Ok(None)
        }

        fn packet_len(_packet: &Self::Packet) -> usize {
            1
        }

        fn active_subscription_count(&self) -> usize {
            self.active
        }

        fn capture_socket_count(&self) -> usize {
            usize::from(self.active != 0)
        }
    }

    fn subscription() -> UpstreamSubscription {
        UpstreamSubscription::asm(IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)))
    }

    fn wait_for(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while !predicate() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::yield_now();
        }
    }

    #[test]
    fn bounded_queue_accounts_for_overflow_and_high_water() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let source = FakeSource {
            packets: (0..10).collect(),
            fail_receive: false,
            active: 1,
            state,
        };
        let mut worker =
            spawn_worker(source, Arc::new(Poller::new().unwrap()), 3, "queue-test").unwrap();

        wait_for(|| {
            let snapshot = worker.snapshot();
            snapshot.accepted_packets == 10 && snapshot.queue_drops == 7
        });
        let snapshot = worker.snapshot();
        assert_eq!(snapshot.queue_depth, 3);
        assert_eq!(snapshot.queue_high_water, 3);
        assert_eq!(snapshot.queue_drops, 7);
        worker.stop().unwrap();
    }

    #[test]
    fn worker_without_subscriptions_blocks_instead_of_polling() {
        let receive_calls = Arc::new(AtomicUsize::new(0));
        let source = IdleSource {
            receive_calls: Arc::clone(&receive_calls),
            active: 0,
        };
        let mut worker =
            spawn_worker(source, Arc::new(Poller::new().unwrap()), 1, "idle-test").unwrap();

        wait_for(|| receive_calls.load(Ordering::Relaxed) == 1);
        thread::sleep(Duration::from_millis(20));
        assert_eq!(receive_calls.load(Ordering::Relaxed), 1);
        worker.stop().unwrap();
    }

    #[test]
    fn queued_packets_preserve_capture_order() {
        let source = FakeSource {
            packets: (0..8).collect(),
            fail_receive: false,
            active: 1,
            state: Arc::new(Mutex::new(FakeState::default())),
        };
        let mut worker =
            spawn_worker(source, Arc::new(Poller::new().unwrap()), 8, "order-test").unwrap();

        wait_for(|| worker.snapshot().queue_high_water == 8);
        let packets = (0..8)
            .map(|_| worker.try_recv().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(packets, (0..8).collect::<Vec<_>>());
        worker.stop().unwrap();
    }

    #[test]
    fn reconciliation_remains_fair_while_packets_arrive() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let source = FakeSource {
            packets: (0..100_000).collect(),
            fail_receive: false,
            active: 1,
            state: Arc::clone(&state),
        };
        let mut worker = spawn_worker(
            source,
            Arc::new(Poller::new().unwrap()),
            2,
            "reconcile-test",
        )
        .unwrap();

        wait_for(|| worker.snapshot().queue_drops != 0);
        let result = worker.reconcile(vec![subscription()]).unwrap();
        assert_eq!(result.active, 1);
        worker.stop().unwrap();
        let reconciliations = &state.lock().unwrap().reconciliations;
        assert_eq!(reconciliations.first(), Some(&vec![subscription()]));
        assert_eq!(reconciliations.last(), Some(&Vec::new()));
    }

    #[test]
    fn receive_failure_is_propagated_and_wakes_the_relay() {
        let source = FakeSource {
            packets: VecDeque::new(),
            fail_receive: true,
            active: 1,
            state: Arc::new(Mutex::new(FakeState::default())),
        };
        let poller = Arc::new(Poller::new().unwrap());
        let mut worker = spawn_worker(source, Arc::clone(&poller), 2, "failure-test").unwrap();
        let mut events = polling::Events::new();

        poller
            .wait(&mut events, Some(Duration::from_secs(1)))
            .unwrap();
        assert!(worker.check_failure().is_err());
        assert_eq!(worker.snapshot().failures, 1);
        assert!(worker.stop().is_err());
    }

    #[test]
    fn shutdown_clears_subscriptions_with_queued_packets() {
        let state = Arc::new(Mutex::new(FakeState::default()));
        let source = FakeSource {
            packets: (0..10).collect(),
            fail_receive: false,
            active: 1,
            state: Arc::clone(&state),
        };
        let mut worker = spawn_worker(
            source,
            Arc::new(Poller::new().unwrap()),
            10,
            "shutdown-test",
        )
        .unwrap();

        wait_for(|| worker.snapshot().queue_depth != 0);
        worker.stop().unwrap();
        assert_eq!(
            state.lock().unwrap().reconciliations.last(),
            Some(&Vec::new())
        );
    }
}
