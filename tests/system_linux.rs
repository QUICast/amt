use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mcrx_core::{Context as McrxContext, SourceFilter, SubscriptionConfig};
use mctx_core::{Context as MctxContext, OutgoingInterface, PublicationConfig};

const AMT_PORT: u16 = 2268;
const RELAY_AMT_IP: &str = "10.90.0.1";
const GATEWAY_AMT_IP: &str = "10.90.0.2";
const RELAY_UPSTREAM_IP: &str = "10.91.0.1";
const SOURCE_IP: &str = "10.91.0.2";
const GATEWAY_DOWNSTREAM_IP: &str = "10.92.0.1";
const RECEIVER_IP: &str = "10.92.0.2";
const PORT: u16 = 5000;

#[test]
#[ignore = "requires Linux root privileges, network namespaces, and raw socket capability"]
fn linux_namespace_transparent_asm_forwarding() {
    let Some(fixture) = LinuxSystemFixture::prepare("asm") else {
        return;
    };

    let group = "239.91.0.1";
    let payload = "amt-system-asm";
    let mut relay = fixture.spawn_relay("relay-asm", 4).unwrap();
    let mut gateway = fixture
        .spawn_gateway(
            "gateway-asm",
            &[
                "gateway",
                "--relay",
                &format!("{RELAY_AMT_IP}:{AMT_PORT}"),
                "--transparent",
                "--protocol",
                "igmpv3",
                "--downstream-interface",
                GATEWAY_DOWNSTREAM_IP,
                "--downstream-ttl",
                "16",
                "--local-query-interval",
                "1",
                "--membership-refresh-interval",
                "1",
            ],
        )
        .unwrap();

    relay
        .wait_for_log(Duration::from_secs(5), "amt relay listening")
        .unwrap();
    gateway
        .wait_for_log(Duration::from_secs(5), "amt gateway listening")
        .unwrap();

    let mut receiver = fixture
        .spawn_receiver("rx-asm", group, None, payload, Duration::from_secs(12))
        .unwrap();
    receiver
        .wait_for_log(Duration::from_secs(5), "receiver joined")
        .unwrap();

    let mut source = fixture
        .spawn_source("src-asm", group, payload, 40, Duration::from_millis(100))
        .unwrap();

    receiver.wait_success(Duration::from_secs(15)).unwrap();
    source.wait_success(Duration::from_secs(8)).unwrap();
}

#[test]
#[ignore = "requires Linux root privileges, network namespaces, and raw socket capability"]
fn linux_namespace_configured_ssm_forwarding() {
    let Some(fixture) = LinuxSystemFixture::prepare("ssm") else {
        return;
    };

    let group = "232.91.0.1";
    let payload = "amt-system-ssm";
    let mut relay = fixture.spawn_relay("relay-ssm", 4).unwrap();
    let mut gateway = fixture
        .spawn_gateway(
            "gateway-ssm",
            &[
                "gateway",
                "--relay",
                &format!("{RELAY_AMT_IP}:{AMT_PORT}"),
                "--group",
                group,
                "--source",
                SOURCE_IP,
                "--protocol",
                "igmpv3",
                "--downstream-interface",
                GATEWAY_DOWNSTREAM_IP,
                "--downstream-ttl",
                "16",
                "--membership-refresh-interval",
                "1",
            ],
        )
        .unwrap();

    relay
        .wait_for_log(Duration::from_secs(5), "amt relay listening")
        .unwrap();
    gateway
        .wait_for_log(Duration::from_secs(5), "amt gateway listening")
        .unwrap();

    let mut receiver = fixture
        .spawn_receiver(
            "rx-ssm",
            group,
            Some(SOURCE_IP),
            payload,
            Duration::from_secs(12),
        )
        .unwrap();
    receiver
        .wait_for_log(Duration::from_secs(5), "receiver joined")
        .unwrap();

    let mut source = fixture
        .spawn_source("src-ssm", group, payload, 40, Duration::from_millis(100))
        .unwrap();

    receiver.wait_success(Duration::from_secs(15)).unwrap();
    source.wait_success(Duration::from_secs(8)).unwrap();
}

#[test]
#[ignore = "requires Linux root privileges, network namespaces, and raw socket capability"]
fn linux_namespace_teardown_prune_and_metrics() {
    let Some(fixture) = LinuxSystemFixture::prepare("clean") else {
        return;
    };

    let group = "239.91.0.9";
    let mut relay = fixture.spawn_relay("relay-clean", 2).unwrap();
    relay
        .wait_for_log(Duration::from_secs(5), "amt relay listening")
        .unwrap();

    let mut graceful_gateway = fixture
        .spawn_gateway(
            "gateway-clean-graceful",
            &[
                "gateway",
                "--relay",
                &format!("{RELAY_AMT_IP}:{AMT_PORT}"),
                "--group",
                group,
                "--protocol",
                "igmpv3",
                "--membership-refresh-interval",
                "1",
                "--no-downstream",
            ],
        )
        .unwrap();
    relay
        .wait_for_log(Duration::from_secs(5), "upstream subscriptions changed: +1")
        .unwrap();
    let offset = relay.output().len();
    graceful_gateway.terminate().unwrap();
    graceful_gateway
        .wait_success(Duration::from_secs(5))
        .unwrap();
    relay
        .wait_for_log_after(
            Duration::from_secs(5),
            offset,
            "disconnected from AMT relay",
        )
        .unwrap();
    relay
        .wait_for_log_after(Duration::from_secs(5), offset, "active=0")
        .unwrap();

    let mut crashed_gateway = fixture
        .spawn_gateway(
            "gateway-clean-crash",
            &[
                "gateway",
                "--relay",
                &format!("{RELAY_AMT_IP}:{AMT_PORT}"),
                "--group",
                group,
                "--protocol",
                "igmpv3",
                "--membership-refresh-interval",
                "1",
                "--no-downstream",
            ],
        )
        .unwrap();
    let offset = relay.output().len();
    relay
        .wait_for_log_after(
            Duration::from_secs(5),
            offset,
            "upstream subscriptions changed: +1",
        )
        .unwrap();
    let offset = relay.output().len();
    crashed_gateway.kill().unwrap();
    let _ = crashed_gateway.wait(Duration::from_secs(5));
    relay
        .wait_for_log_after(Duration::from_secs(8), offset, "expired idle gateway")
        .unwrap();
    relay
        .wait_for_log_after(Duration::from_secs(8), offset, "active=0")
        .unwrap();

    #[cfg(feature = "metrics")]
    {
        thread::sleep(Duration::from_millis(500));
        fixture.assert_metrics_jsonl("relay-clean", "amt-relay.jsonl");
    }
}

#[test]
#[ignore = "helper for linux namespace system tests"]
fn __system_helper_send_multicast() {
    if env::var("AMT_SYSTEM_HELPER").as_deref() != Ok("send") {
        return;
    }

    let group = env_ip("AMT_SYSTEM_GROUP");
    let interface = env_ip("AMT_SYSTEM_INTERFACE");
    let source = env_ip("AMT_SYSTEM_SOURCE");
    let payload = env::var("AMT_SYSTEM_PAYLOAD").unwrap();
    let count = env_u64("AMT_SYSTEM_COUNT") as usize;
    let interval = Duration::from_millis(env_u64("AMT_SYSTEM_INTERVAL_MS"));
    let ttl = env_u64("AMT_SYSTEM_TTL") as u32;

    let mut config = PublicationConfig::new(group, PORT)
        .with_source_addr(source)
        .with_ttl(ttl)
        .with_loopback(false);
    config = match interface {
        IpAddr::V4(addr) => config.with_outgoing_interface(OutgoingInterface::Ipv4Addr(addr)),
        IpAddr::V6(addr) => config.with_outgoing_interface(OutgoingInterface::Ipv6Addr(addr)),
    };

    let mut context = MctxContext::new();
    let id = context.add_publication(config).unwrap();
    for _ in 0..count {
        context.send(id, payload.as_bytes()).unwrap();
        thread::sleep(interval);
    }
}

#[test]
#[ignore = "helper for linux namespace system tests"]
fn __system_helper_receive_multicast() {
    if env::var("AMT_SYSTEM_HELPER").as_deref() != Ok("receive") {
        return;
    }

    let group = env_ip("AMT_SYSTEM_GROUP");
    let interface = env_ip("AMT_SYSTEM_INTERFACE");
    let source = env::var("AMT_SYSTEM_SOURCE")
        .ok()
        .map(|_| env_ip("AMT_SYSTEM_SOURCE"));
    let expected_payload = env::var("AMT_SYSTEM_PAYLOAD").unwrap().into_bytes();
    let timeout = Duration::from_millis(env_u64("AMT_SYSTEM_TIMEOUT_MS"));

    let mut config = SubscriptionConfig::asm_ip(group, PORT);
    config.interface = Some(interface);
    if let Some(source) = source {
        config.source = SourceFilter::Source(source);
    }

    let mut context = McrxContext::new();
    let id = context.add_subscription(config).unwrap();
    context.join_subscription(id).unwrap();
    println!("receiver joined");

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match context.try_recv_any().unwrap() {
            Some(packet) if packet.payload == expected_payload => {
                println!("receiver got expected payload");
                return;
            }
            Some(packet) => {
                println!(
                    "receiver ignored unexpected payload: {:?}",
                    String::from_utf8_lossy(&packet.payload)
                );
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }

    panic!(
        "timed out waiting for payload {:?}",
        String::from_utf8_lossy(&expected_payload)
    );
}

struct LinuxSystemFixture {
    relay_ns: String,
    gateway_ns: String,
    source_ns: String,
    receiver_ns: String,
    relay_amt_if: String,
    gateway_amt_if: String,
    relay_upstream_if: String,
    source_if: String,
    gateway_downstream_if: String,
    receiver_if: String,
    metrics_dir: PathBuf,
}

impl LinuxSystemFixture {
    fn prepare(label: &str) -> Option<Self> {
        if !cfg!(target_os = "linux") {
            eprintln!("skipping Linux system test on non-Linux host");
            return None;
        }
        if !command_exists("ip") {
            eprintln!("skipping Linux system test because `ip` is unavailable");
            return None;
        }
        if current_uid() != Some(0) {
            eprintln!("skipping Linux system test because it needs root privileges");
            return None;
        }

        let suffix = short_suffix(label);
        let fixture = Self {
            relay_ns: format!("amt-r-{suffix}"),
            gateway_ns: format!("amt-g-{suffix}"),
            source_ns: format!("amt-s-{suffix}"),
            receiver_ns: format!("amt-x-{suffix}"),
            relay_amt_if: format!("ar{suffix}"),
            gateway_amt_if: format!("ag{suffix}"),
            relay_upstream_if: format!("ur{suffix}"),
            source_if: format!("us{suffix}"),
            gateway_downstream_if: format!("gd{suffix}"),
            receiver_if: format!("rx{suffix}"),
            metrics_dir: env::temp_dir().join(format!("amt-system-{suffix}")),
        };

        fixture.setup();
        Some(fixture)
    }

    fn setup(&self) {
        let _ = fs::remove_dir_all(&self.metrics_dir);
        fs::create_dir_all(&self.metrics_dir).unwrap();

        for ns in [
            &self.relay_ns,
            &self.gateway_ns,
            &self.source_ns,
            &self.receiver_ns,
        ] {
            ip(["netns", "add", ns]).unwrap();
            ip_netns(ns, ["link", "set", "lo", "up"]).unwrap();
        }

        self.veth_pair(
            &self.relay_amt_if,
            &self.relay_ns,
            RELAY_AMT_IP,
            &self.gateway_amt_if,
            &self.gateway_ns,
            GATEWAY_AMT_IP,
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

        ip_netns(
            &self.relay_ns,
            [
                "route",
                "replace",
                "224.0.0.0/4",
                "dev",
                &self.relay_upstream_if,
            ],
        )
        .unwrap();
        ip_netns(
            &self.source_ns,
            ["route", "replace", "224.0.0.0/4", "dev", &self.source_if],
        )
        .unwrap();
        ip_netns(
            &self.gateway_ns,
            [
                "route",
                "replace",
                "224.0.0.0/4",
                "dev",
                &self.gateway_downstream_if,
            ],
        )
        .unwrap();
        ip_netns(
            &self.receiver_ns,
            ["route", "replace", "224.0.0.0/4", "dev", &self.receiver_if],
        )
        .unwrap();
        ip_netns(
            &self.receiver_ns,
            ["route", "replace", "10.91.0.0/24", "dev", &self.receiver_if],
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

    fn spawn_relay(&self, node_id: &str, idle_timeout_secs: u64) -> std::io::Result<LoggedChild> {
        let mut command = netns_command(&self.relay_ns, amt_bin());
        command.args([
            "relay",
            "--bind",
            &format!("{RELAY_AMT_IP}:{AMT_PORT}"),
            "--relay-address",
            RELAY_AMT_IP,
            "--upstream-interface",
            RELAY_UPSTREAM_IP,
            "--gateway-idle-timeout",
            &idle_timeout_secs.to_string(),
            "--gateway-prune-interval",
            "1",
        ]);
        self.add_metrics_args(&mut command, node_id);
        LoggedChild::spawn(command)
    }

    fn spawn_gateway(&self, node_id: &str, args: &[&str]) -> std::io::Result<LoggedChild> {
        let mut command = netns_command(&self.gateway_ns, amt_bin());
        command.args(args);
        self.add_metrics_args(&mut command, node_id);
        LoggedChild::spawn(command)
    }

    fn spawn_source(
        &self,
        node_id: &str,
        group: &str,
        payload: &str,
        count: usize,
        interval: Duration,
    ) -> std::io::Result<LoggedChild> {
        let mut command = helper_command(&self.source_ns, "__system_helper_send_multicast");
        command
            .env("AMT_SYSTEM_HELPER", "send")
            .env("AMT_SYSTEM_GROUP", group)
            .env("AMT_SYSTEM_INTERFACE", SOURCE_IP)
            .env("AMT_SYSTEM_SOURCE", SOURCE_IP)
            .env("AMT_SYSTEM_PAYLOAD", payload)
            .env("AMT_SYSTEM_COUNT", count.to_string())
            .env("AMT_SYSTEM_INTERVAL_MS", interval.as_millis().to_string())
            .env("AMT_SYSTEM_TTL", "16")
            .env("AMT_SYSTEM_NODE_ID", node_id);
        LoggedChild::spawn(command)
    }

    fn spawn_receiver(
        &self,
        node_id: &str,
        group: &str,
        source: Option<&str>,
        payload: &str,
        timeout: Duration,
    ) -> std::io::Result<LoggedChild> {
        let mut command = helper_command(&self.receiver_ns, "__system_helper_receive_multicast");
        command
            .env("AMT_SYSTEM_HELPER", "receive")
            .env("AMT_SYSTEM_GROUP", group)
            .env("AMT_SYSTEM_INTERFACE", RECEIVER_IP)
            .env("AMT_SYSTEM_PAYLOAD", payload)
            .env("AMT_SYSTEM_TIMEOUT_MS", timeout.as_millis().to_string())
            .env("AMT_SYSTEM_NODE_ID", node_id);
        if let Some(source) = source {
            command.env("AMT_SYSTEM_SOURCE", source);
        }
        LoggedChild::spawn(command)
    }

    fn add_metrics_args(&self, command: &mut Command, node_id: &str) {
        command.args([
            "--metrics-dir",
            self.metrics_dir.to_str().unwrap(),
            "--node-id",
            node_id,
            "--metrics-interval-ms",
            "200",
        ]);
    }

    #[cfg(feature = "metrics")]
    fn assert_metrics_jsonl(&self, node_id: &str, file_name: &str) {
        let path = self.metrics_dir.join(node_id).join(file_name);
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let mut lines = contents.lines().filter(|line| !line.trim().is_empty());
        let header = lines
            .next()
            .unwrap_or_else(|| panic!("{} is missing a header", path.display()));
        let header: serde_json::Value = serde_json::from_str(header).unwrap();
        assert_eq!(header["schema"], "heimdall-jsonl-v1");
        assert_eq!(header["artifact_type"], "amt-relay");
        assert_eq!(header["producer"], "amt");

        let sample = lines
            .next()
            .unwrap_or_else(|| panic!("{} is missing a sample", path.display()));
        let sample: serde_json::Value = serde_json::from_str(sample).unwrap();
        assert!(sample["ts"].is_number());
        assert!(sample["interval_secs"].is_number());
    }
}

impl Drop for LinuxSystemFixture {
    fn drop(&mut self) {
        for ns in [
            &self.receiver_ns,
            &self.source_ns,
            &self.gateway_ns,
            &self.relay_ns,
        ] {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
        }
        let _ = fs::remove_dir_all(&self.metrics_dir);
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
        let stdout = self.stdout.lock().unwrap().clone();
        let stderr = self.stderr.lock().unwrap().clone();
        format!("{stdout}{stderr}")
    }

    fn wait_for_log(&mut self, timeout: Duration, needle: &str) -> Result<(), String> {
        self.wait_for_log_after(timeout, 0, needle)
    }

    fn wait_for_log_after(
        &mut self,
        timeout: Duration,
        offset: usize,
        needle: &str,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let output = self.output();
            if output
                .get(offset..)
                .is_some_and(|tail| tail.contains(needle))
            {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait().map_err(|err| err.to_string())? {
                return Err(format!(
                    "child exited before log '{needle}' appeared: {status}\n{}",
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

    fn wait_success(&mut self, timeout: Duration) -> Result<(), String> {
        let status = self.wait(timeout)?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("child exited with {status}\n{}", self.output()))
        }
    }

    fn wait(&mut self, timeout: Duration) -> Result<ExitStatus, String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().map_err(|err| err.to_string())? {
                self.join_threads();
                return Ok(status);
            }
            thread::sleep(Duration::from_millis(50));
        }
        Err(format!("timed out waiting for child\n{}", self.output()))
    }

    fn terminate(&mut self) -> Result<(), String> {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .map_err(|err| err.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("kill -TERM failed with {status}"))
        }
    }

    fn kill(&mut self) -> Result<(), String> {
        self.child.kill().map_err(|err| err.to_string())
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
    buffer: Arc<Mutex<String>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => buffer.lock().unwrap().push_str(&line),
                Err(_) => break,
            }
        }
    })
}

fn helper_command(namespace: &str, helper_test: &str) -> Command {
    let mut command = netns_command(namespace, env::current_exe().unwrap());
    command.args(["--ignored", "--exact", helper_test, "--nocapture"]);
    command
}

fn netns_command(namespace: &str, program: PathBuf) -> Command {
    let mut command = Command::new("ip");
    command.args(["netns", "exec", namespace]);
    command.arg(program);
    command
}

fn amt_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_amt"))
}

fn configure_interface(namespace: &str, interface: &str, ip: &str) {
    ip_netns(
        namespace,
        ["addr", "add", &format!("{ip}/24"), "dev", interface],
    )
    .unwrap();
    ip_netns(namespace, ["link", "set", interface, "up"]).unwrap();
    ip_netns(namespace, ["link", "set", interface, "multicast", "on"]).unwrap();
}

fn ip<const N: usize>(args: [&str; N]) -> Result<(), String> {
    let mut command = Command::new("ip");
    command.args(args);
    command_status(&mut command)
}

fn ip_netns<const N: usize>(namespace: &str, args: [&str; N]) -> Result<(), String> {
    let mut command = Command::new("ip");
    command.args(["-n", namespace]);
    command.args(args);
    command_status(&mut command)
}

fn command_status(command: &mut Command) -> Result<(), String> {
    let output = command.output().map_err(|err| err.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "command failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn command_exists(name: &str) -> bool {
    Command::new(name)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn current_uid() -> Option<u32> {
    let output = Command::new("id").arg("-u").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

fn short_suffix(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos();
    format!(
        "{}{:04x}",
        label.chars().next().unwrap_or('x'),
        (nanos & 0xffff) as u16
    )
}

fn env_ip(name: &str) -> IpAddr {
    env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required"))
        .parse()
        .unwrap_or_else(|err| panic!("{name} is invalid: {err}"))
}

fn env_u64(name: &str) -> u64 {
    env::var(name)
        .unwrap_or_else(|_| panic!("{name} is required"))
        .parse()
        .unwrap_or_else(|err| panic!("{name} is invalid: {err}"))
}
