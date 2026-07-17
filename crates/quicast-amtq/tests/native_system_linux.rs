#![cfg(target_os = "linux")]

use mcrx_core::{Context as McrxContext, SourceFilter, SubscriptionConfig};
use mctx_core::{Context as MctxContext, OutgoingInterface, PublicationConfig};
use std::env;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RELAY_QUIC_IP: &str = "10.100.0.1";
const GATEWAY_QUIC_IP: &str = "10.100.0.2";
const RELAY_UPSTREAM_IP: &str = "10.101.0.1";
const SOURCE_IP: &str = "10.101.0.2";
const GATEWAY_DOWNSTREAM_IP: &str = "10.102.0.1";
const RECEIVER_IP: &str = "10.102.0.2";
const GROUP: &str = "232.101.0.1";
const PORT: u16 = 5000;
const AMTQ_PORT: u16 = 2268;

#[test]
#[ignore = "requires Linux root privileges, network namespaces, and raw socket capability"]
fn linux_namespace_ssm_native_forwarding() {
    let Some(fixture) = LinuxFixture::prepare() else {
        return;
    };
    let payload = "amtq-native-system";
    let mut relay = fixture.spawn_relay().unwrap();
    relay
        .wait_for_log(Duration::from_secs(10), "amtq relay listening")
        .unwrap();

    let mut gateway = fixture.spawn_gateway().unwrap();
    gateway
        .wait_for_log(Duration::from_secs(10), "amtq gateway connected")
        .unwrap();
    let mut receiver = fixture
        .spawn_receiver(payload, Duration::from_secs(20))
        .unwrap();
    receiver
        .wait_for_log(Duration::from_secs(5), "receiver joined")
        .unwrap();
    let mut source = fixture
        .spawn_source(payload, 100, Duration::from_millis(100))
        .unwrap();

    receiver.wait_success(Duration::from_secs(25)).unwrap();
    source.wait_success(Duration::from_secs(15)).unwrap();
    relay.assert_running();
    gateway.assert_running();
}

#[test]
#[ignore = "helper for Linux AMTQ namespace test"]
fn __native_helper_send_multicast() {
    if env::var("AMTQ_SYSTEM_HELPER").as_deref() != Ok("send") {
        return;
    }
    let group = env_ip("AMTQ_SYSTEM_GROUP");
    let interface = env_ip("AMTQ_SYSTEM_INTERFACE");
    let source = env_ip("AMTQ_SYSTEM_SOURCE");
    let payload = env::var("AMTQ_SYSTEM_PAYLOAD").unwrap();
    let count = env_usize("AMTQ_SYSTEM_COUNT");
    let interval = Duration::from_millis(env_u64("AMTQ_SYSTEM_INTERVAL_MS"));

    let mut config = PublicationConfig::new(group, PORT)
        .with_source_addr(source)
        .with_ttl(16)
        .with_loopback(false);
    config = match interface {
        IpAddr::V4(address) => config.with_outgoing_interface(OutgoingInterface::Ipv4Addr(address)),
        IpAddr::V6(address) => config.with_outgoing_interface(OutgoingInterface::Ipv6Addr(address)),
    };
    let mut context = MctxContext::new();
    let publication = context.add_publication(config).unwrap();
    for _ in 0..count {
        context.send(publication, payload.as_bytes()).unwrap();
        thread::sleep(interval);
    }
}

#[test]
#[ignore = "helper for Linux AMTQ namespace test"]
fn __native_helper_receive_multicast() {
    if env::var("AMTQ_SYSTEM_HELPER").as_deref() != Ok("receive") {
        return;
    }
    let group = env_ip("AMTQ_SYSTEM_GROUP");
    let interface = env_ip("AMTQ_SYSTEM_INTERFACE");
    let source = env_ip("AMTQ_SYSTEM_SOURCE");
    let expected = env::var("AMTQ_SYSTEM_PAYLOAD").unwrap().into_bytes();
    let receive_timeout = Duration::from_millis(env_u64("AMTQ_SYSTEM_TIMEOUT_MS"));

    let mut config = SubscriptionConfig::asm_ip(group, PORT);
    config.interface = Some(interface);
    config.source = SourceFilter::Source(source);
    let mut context = McrxContext::new();
    let subscription = context.add_subscription(config).unwrap();
    context.join_subscription(subscription).unwrap();
    println!("receiver joined");

    let deadline = Instant::now() + receive_timeout;
    while Instant::now() < deadline {
        match context.try_recv_any().unwrap() {
            Some(packet) if packet.payload == expected => {
                println!("receiver got expected payload");
                return;
            }
            Some(_) => {}
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
    panic!("timed out waiting for the AMTQ multicast payload");
}

struct LinuxFixture {
    relay_ns: String,
    gateway_ns: String,
    source_ns: String,
    receiver_ns: String,
    relay_quic_if: String,
    gateway_quic_if: String,
    relay_upstream_if: String,
    source_if: String,
    gateway_downstream_if: String,
    receiver_if: String,
}

impl LinuxFixture {
    fn prepare() -> Option<Self> {
        if !command_exists("ip") {
            eprintln!("skipping Linux AMTQ system test because `ip` is unavailable");
            return None;
        }
        if current_uid() != Some(0) {
            eprintln!("skipping Linux AMTQ system test because it requires root");
            return None;
        }

        let suffix = short_suffix();
        let fixture = Self {
            relay_ns: format!("aq-r-{suffix}"),
            gateway_ns: format!("aq-g-{suffix}"),
            source_ns: format!("aq-s-{suffix}"),
            receiver_ns: format!("aq-x-{suffix}"),
            relay_quic_if: format!("qr{suffix}"),
            gateway_quic_if: format!("qg{suffix}"),
            relay_upstream_if: format!("ur{suffix}"),
            source_if: format!("us{suffix}"),
            gateway_downstream_if: format!("gd{suffix}"),
            receiver_if: format!("rx{suffix}"),
        };
        fixture.setup();
        Some(fixture)
    }

    fn setup(&self) {
        for namespace in [
            &self.relay_ns,
            &self.gateway_ns,
            &self.source_ns,
            &self.receiver_ns,
        ] {
            ip(["netns", "add", namespace]).unwrap();
            ip_netns(namespace, ["link", "set", "lo", "up"]).unwrap();
        }
        self.veth_pair(
            &self.relay_quic_if,
            &self.relay_ns,
            RELAY_QUIC_IP,
            &self.gateway_quic_if,
            &self.gateway_ns,
            GATEWAY_QUIC_IP,
        );
        self.veth_pair(
            &self.relay_upstream_if,
            &self.relay_ns,
            RELAY_UPSTREAM_IP,
            &self.source_if,
            &self.source_ns,
            SOURCE_IP,
        );
        self.veth_pair(
            &self.gateway_downstream_if,
            &self.gateway_ns,
            GATEWAY_DOWNSTREAM_IP,
            &self.receiver_if,
            &self.receiver_ns,
            RECEIVER_IP,
        );
        for (namespace, interface) in [
            (&self.relay_ns, &self.relay_upstream_if),
            (&self.source_ns, &self.source_if),
            (&self.gateway_ns, &self.gateway_downstream_if),
            (&self.receiver_ns, &self.receiver_if),
        ] {
            ip_netns(
                namespace,
                ["route", "replace", "224.0.0.0/4", "dev", interface],
            )
            .unwrap();
        }
        ip_netns(
            &self.receiver_ns,
            [
                "route",
                "replace",
                "10.101.0.0/24",
                "dev",
                &self.receiver_if,
            ],
        )
        .unwrap();
    }

    fn veth_pair(
        &self,
        left_if: &str,
        left_ns: &str,
        left_ip: &str,
        right_if: &str,
        right_ns: &str,
        right_ip: &str,
    ) {
        ip([
            "link", "add", left_if, "type", "veth", "peer", "name", right_if,
        ])
        .unwrap();
        ip(["link", "set", left_if, "netns", left_ns]).unwrap();
        ip(["link", "set", right_if, "netns", right_ns]).unwrap();
        configure_interface(left_ns, left_if, left_ip);
        configure_interface(right_ns, right_if, right_ip);
    }

    fn spawn_relay(&self) -> std::io::Result<LoggedChild> {
        let mut command = netns_command(&self.relay_ns, amtq_bin());
        command.args([
            "relay",
            "--bind",
            &format!("{RELAY_QUIC_IP}:{AMTQ_PORT}"),
            "--cert",
            fixture("localhost-cert.pem").to_str().unwrap(),
            "--key",
            fixture("localhost-key.pem").to_str().unwrap(),
            "--upstream-interface",
            RELAY_UPSTREAM_IP,
            "--max-subscriptions",
            "16",
        ]);
        LoggedChild::spawn(command)
    }

    fn spawn_gateway(&self) -> std::io::Result<LoggedChild> {
        let mut command = netns_command(&self.gateway_ns, amtq_bin());
        command.args([
            "gateway",
            "--relay",
            &format!("{RELAY_QUIC_IP}:{AMTQ_PORT}"),
            "--server-name",
            "localhost",
            "--ca",
            fixture("localhost-cert.pem").to_str().unwrap(),
            "--protocol",
            "igmpv3",
            "--join",
            &format!("{SOURCE_IP}@{GROUP}"),
            "--downstream-interface",
            GATEWAY_DOWNSTREAM_IP,
            "--ttl",
            "16",
            "--refresh",
            "1",
        ]);
        LoggedChild::spawn(command)
    }

    fn spawn_source(
        &self,
        payload: &str,
        count: usize,
        interval: Duration,
    ) -> std::io::Result<LoggedChild> {
        let mut command = helper_command(&self.source_ns, "__native_helper_send_multicast");
        command
            .env("AMTQ_SYSTEM_HELPER", "send")
            .env("AMTQ_SYSTEM_GROUP", GROUP)
            .env("AMTQ_SYSTEM_INTERFACE", SOURCE_IP)
            .env("AMTQ_SYSTEM_SOURCE", SOURCE_IP)
            .env("AMTQ_SYSTEM_PAYLOAD", payload)
            .env("AMTQ_SYSTEM_COUNT", count.to_string())
            .env("AMTQ_SYSTEM_INTERVAL_MS", interval.as_millis().to_string());
        LoggedChild::spawn(command)
    }

    fn spawn_receiver(
        &self,
        payload: &str,
        receive_timeout: Duration,
    ) -> std::io::Result<LoggedChild> {
        let mut command = helper_command(&self.receiver_ns, "__native_helper_receive_multicast");
        command
            .env("AMTQ_SYSTEM_HELPER", "receive")
            .env("AMTQ_SYSTEM_GROUP", GROUP)
            .env("AMTQ_SYSTEM_INTERFACE", RECEIVER_IP)
            .env("AMTQ_SYSTEM_SOURCE", SOURCE_IP)
            .env("AMTQ_SYSTEM_PAYLOAD", payload)
            .env(
                "AMTQ_SYSTEM_TIMEOUT_MS",
                receive_timeout.as_millis().to_string(),
            );
        LoggedChild::spawn(command)
    }
}

impl Drop for LinuxFixture {
    fn drop(&mut self) {
        for namespace in [
            &self.receiver_ns,
            &self.source_ns,
            &self.gateway_ns,
            &self.relay_ns,
        ] {
            let _ = Command::new("ip")
                .args(["netns", "del", namespace])
                .status();
        }
    }
}

struct LoggedChild {
    child: Child,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    stdout_thread: Option<thread::JoinHandle<()>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
}

impl LoggedChild {
    fn spawn(mut command: Command) -> std::io::Result<Self> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let stdout = Arc::new(Mutex::new(String::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        let stdout_thread = child
            .stdout
            .take()
            .map(|pipe| capture_output(pipe, Arc::clone(&stdout)));
        let stderr_thread = child
            .stderr
            .take()
            .map(|pipe| capture_output(pipe, Arc::clone(&stderr)));
        Ok(Self {
            child,
            stdout,
            stderr,
            stdout_thread,
            stderr_thread,
        })
    }

    fn output(&self) -> String {
        format!(
            "{}{}",
            self.stdout.lock().unwrap(),
            self.stderr.lock().unwrap()
        )
    }

    fn wait_for_log(&mut self, wait: Duration, needle: &str) -> Result<(), String> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if self.output().contains(needle) {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait().map_err(|error| error.to_string())? {
                return Err(format!(
                    "child exited before log '{needle}': {status}\n{}",
                    self.output()
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(format!(
            "timed out waiting for log '{needle}'\n{}",
            self.output()
        ))
    }

    fn wait_success(&mut self, wait: Duration) -> Result<(), String> {
        let status = self.wait(wait)?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("child exited with {status}\n{}", self.output()))
        }
    }

    fn wait(&mut self, wait: Duration) -> Result<ExitStatus, String> {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().map_err(|error| error.to_string())? {
                self.join_threads();
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(format!("timed out waiting for child\n{}", self.output()))
    }

    fn assert_running(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "child stopped unexpectedly\n{}",
            self.output()
        );
    }

    fn join_threads(&mut self) {
        if let Some(thread) = self.stdout_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for LoggedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.join_threads();
    }
}

fn capture_output<R: Read + Send + 'static>(
    reader: R,
    output: Arc<Mutex<String>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => output.lock().unwrap().push_str(&line),
                Err(_) => break,
            }
        }
    })
}

fn helper_command(namespace: &str, helper: &str) -> Command {
    let mut command = netns_command(namespace, env::current_exe().unwrap());
    command.args(["--ignored", "--exact", helper, "--nocapture"]);
    command
}

fn netns_command(namespace: &str, program: PathBuf) -> Command {
    let mut command = Command::new("ip");
    command.args(["netns", "exec", namespace]).arg(program);
    command
}

fn amtq_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_amtq"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn configure_interface(namespace: &str, interface: &str, address: &str) {
    ip_netns(
        namespace,
        ["addr", "add", &format!("{address}/24"), "dev", interface],
    )
    .unwrap();
    ip_netns(namespace, ["link", "set", interface, "up"]).unwrap();
    ip_netns(namespace, ["link", "set", interface, "multicast", "on"]).unwrap();
}

fn ip<const N: usize>(args: [&str; N]) -> Result<(), String> {
    command_status(Command::new("ip").args(args))
}

fn ip_netns<const N: usize>(namespace: &str, args: [&str; N]) -> Result<(), String> {
    let mut command = Command::new("ip");
    command.args(["-n", namespace]).args(args);
    command_status(&mut command)
}

fn command_status(command: &mut Command) -> Result<(), String> {
    let output = command.output().map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "command failed with {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn command_exists(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn current_uid() -> Option<u32> {
    let output = Command::new("id").arg("-u").output().ok()?;
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

fn short_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos & 0x00ff_ffff)
}

fn env_ip(name: &str) -> IpAddr {
    env::var(name).unwrap().parse().unwrap()
}

fn env_u64(name: &str) -> u64 {
    env::var(name).unwrap().parse().unwrap()
}

fn env_usize(name: &str) -> usize {
    env::var(name).unwrap().parse().unwrap()
}
