use amt::{DownstreamConfig, MembershipProtocol, RelayLimits, UpstreamConfig};
use amtq::native::{
    NativeGateway, NativeGatewayConfig, NativeGatewaySnapshot, NativeJoin, NativeRelay,
    NativeRelayConfig, NativeRelaySnapshot, static_membership_report,
};
use amtq::transport::endpoint::{
    GatewayEndpointConfig, GatewayTrust, RelayEndpointConfig, RelayEndpointSnapshot, TlsIdentity,
};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

const DEFAULT_BIND: &str = "0.0.0.0:2268";
const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const TRAFFIC_REPORT_INTERVAL: Duration = Duration::from_secs(30);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run(env::args().skip(1)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some("relay") => match parse_relay(args) {
            Ok(config) => run_relay(config).await,
            Err(error) if error.is_empty() => Ok(()),
            Err(error) => Err(error),
        },
        Some("gateway") => match parse_gateway(args) {
            Ok(config) => run_gateway(config).await,
            Err(error) if error.is_empty() => Ok(()),
            Err(error) => Err(error),
        },
        Some("-h" | "--help" | "help") | None => {
            print_usage();
            Ok(())
        }
        Some(command) => Err(format!("unknown command '{command}'\n\n{}", usage())),
    }
}

async fn run_relay(config: NativeRelayConfig) -> Result<(), String> {
    let mut relay = NativeRelay::bind(config)
        .await
        .map_err(|error| error.to_string())?;
    println!("amtq relay listening on {}", relay.local_address());
    println!("amtq relay ready; waiting for gateways and membership updates");

    let endpoint_stats = relay.endpoint_stats();
    let native_stats = relay.stats();
    let mut reporter = RelayStatusReporter::default();
    let mut status_tick = status_interval();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let signal_error = loop {
        tokio::select! {
            result = &mut ctrl_c => {
                break result
                    .err()
                    .map(|error| format!("failed to listen for Ctrl-C: {error}"));
            }
            () = relay.wait_stopped() => break None,
            _ = status_tick.tick() => {
                print_status(reporter.observe(
                    endpoint_stats.snapshot(),
                    native_stats.snapshot(),
                    Instant::now(),
                ));
            }
        }
    };

    let stop = relay.shutdown().await.map_err(|error| error.to_string())?;
    if let Some(error) = signal_error {
        return Err(error);
    }
    println!(
        "amtq relay stopped: graceful={} active_subscriptions={} forwarded={} queue_drops={}",
        stop.endpoint.graceful,
        stop.snapshot.active_upstream_subscriptions,
        stop.snapshot.forwarded_datagrams,
        stop.snapshot.packet_queue_drops,
    );
    Ok(())
}

async fn run_gateway(config: NativeGatewayConfig) -> Result<(), String> {
    let relay_address = config.endpoint.relay_address;
    let record_count = config.membership.records.len();
    let mut gateway = NativeGateway::connect(config)
        .await
        .map_err(|error| error.to_string())?;
    println!("amtq gateway connected to {relay_address} with {record_count} membership record(s)");

    let stats = gateway.stats();
    let mut reporter = GatewayStatusReporter::default();
    let mut status_tick = status_interval();
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let signal_error = loop {
        tokio::select! {
            result = &mut ctrl_c => {
                break result
                    .err()
                    .map(|error| format!("failed to listen for Ctrl-C: {error}"));
            }
            () = gateway.wait_stopped() => break None,
            _ = status_tick.tick() => {
                print_status(reporter.observe(stats.snapshot(), Instant::now()));
            }
        }
    };

    let stop = gateway
        .shutdown()
        .await
        .map_err(|error| error.to_string())?;
    if let Some(error) = signal_error {
        return Err(error);
    }
    println!(
        "amtq gateway stopped: graceful={} received={} queued={} queue_drops={} path_outages={}",
        stop.connection.graceful,
        stop.snapshot.multicast_datagrams_received,
        stop.snapshot.downstream_datagrams_queued,
        stop.snapshot.downstream_queue_drops,
        stop.snapshot.path_outages,
    );
    Ok(())
}

fn status_interval() -> tokio::time::Interval {
    let mut interval = tokio::time::interval(STATUS_POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval
}

fn print_status(lines: Vec<String>) {
    for line in lines {
        println!("{line}");
    }
}

fn delta(current: u64, previous: u64) -> u64 {
    current.saturating_sub(previous)
}

#[derive(Default)]
struct RelayStatusReporter {
    endpoint: RelayEndpointSnapshot,
    native: NativeRelaySnapshot,
    traffic: NativeRelaySnapshot,
    last_traffic_report: Option<Instant>,
}

impl RelayStatusReporter {
    fn observe(
        &mut self,
        endpoint: RelayEndpointSnapshot,
        native: NativeRelaySnapshot,
        now: Instant,
    ) -> Vec<String> {
        let mut lines = Vec::new();

        if endpoint.active_connections != self.endpoint.active_connections
            || endpoint.established_connections != self.endpoint.established_connections
            || endpoint.closed_connections != self.endpoint.closed_connections
        {
            lines.push(format!(
                "amtq relay gateways: active={} established={} closed={}",
                endpoint.active_connections,
                endpoint.established_connections,
                endpoint.closed_connections,
            ));
        }

        if native.active_upstream_subscriptions != self.native.active_upstream_subscriptions {
            lines.push(format!(
                "amtq relay memberships: active_subscriptions={} updates={} rejected={}",
                native.active_upstream_subscriptions,
                native.membership_updates,
                native.rejected_membership_updates,
            ));
        }

        let traffic_changed = native.upstream_packets != self.traffic.upstream_packets
            || native.forwarded_datagrams != self.traffic.forwarded_datagrams
            || native.packet_queue_drops != self.traffic.packet_queue_drops;
        let report_due = self
            .last_traffic_report
            .is_none_or(|last| now.duration_since(last) >= TRAFFIC_REPORT_INTERVAL);
        if traffic_changed && report_due {
            lines.push(format!(
                "amtq relay traffic: upstream=+{} forwarded=+{} queue_drops=+{} total_forwarded={}",
                delta(native.upstream_packets, self.traffic.upstream_packets),
                delta(native.forwarded_datagrams, self.traffic.forwarded_datagrams,),
                delta(native.packet_queue_drops, self.traffic.packet_queue_drops),
                native.forwarded_datagrams,
            ));
            self.traffic = native;
            self.last_traffic_report = Some(now);
        }

        self.endpoint = endpoint;
        self.native = native;
        lines
    }
}

#[derive(Default)]
struct GatewayStatusReporter {
    membership_announced: bool,
    path: NativeGatewaySnapshot,
    traffic: NativeGatewaySnapshot,
    last_traffic_report: Option<Instant>,
}

impl GatewayStatusReporter {
    fn observe(&mut self, snapshot: NativeGatewaySnapshot, now: Instant) -> Vec<String> {
        let mut lines = Vec::new();

        if snapshot.path_outages != self.path.path_outages
            || snapshot.path_recoveries != self.path.path_recoveries
            || snapshot.path_reachable != self.path.path_reachable
        {
            if snapshot.path_reachable {
                lines.push(format!(
                    "amtq gateway network path restored; QUIC connection retained (outages={} recoveries={} local_drops={})",
                    snapshot.path_outages,
                    snapshot.path_recoveries,
                    snapshot.path_datagrams_dropped,
                ));
            } else {
                lines.push(format!(
                    "amtq gateway network path unavailable; retaining QUIC connection for migration (outages={} local_drops={})",
                    snapshot.path_outages,
                    snapshot.path_datagrams_dropped,
                ));
            }
        }
        self.path = snapshot;

        if !self.membership_announced && snapshot.membership_updates_sent != 0 {
            lines.push(format!(
                "amtq gateway membership update sent; waiting for multicast data (updates={})",
                snapshot.membership_updates_sent,
            ));
            self.membership_announced = true;
        }

        let traffic_changed = snapshot.multicast_datagrams_received
            != self.traffic.multicast_datagrams_received
            || snapshot.multicast_bytes_received != self.traffic.multicast_bytes_received
            || snapshot.downstream_datagrams_queued != self.traffic.downstream_datagrams_queued
            || snapshot.downstream_queue_drops != self.traffic.downstream_queue_drops;
        let report_due = self
            .last_traffic_report
            .is_none_or(|last| now.duration_since(last) >= TRAFFIC_REPORT_INTERVAL);
        if traffic_changed && report_due {
            lines.push(format!(
                "amtq gateway traffic: received=+{} bytes=+{} queued_for_lan=+{} queue_drops=+{} total_received={}",
                delta(
                    snapshot.multicast_datagrams_received,
                    self.traffic.multicast_datagrams_received,
                ),
                delta(
                    snapshot.multicast_bytes_received,
                    self.traffic.multicast_bytes_received,
                ),
                delta(
                    snapshot.downstream_datagrams_queued,
                    self.traffic.downstream_datagrams_queued,
                ),
                delta(
                    snapshot.downstream_queue_drops,
                    self.traffic.downstream_queue_drops,
                ),
                snapshot.multicast_datagrams_received,
            ));
            self.traffic = snapshot;
            self.last_traffic_report = Some(now);
        }

        lines
    }
}

fn parse_relay(args: impl IntoIterator<Item = String>) -> Result<NativeRelayConfig, String> {
    let mut bind = parse_socket(DEFAULT_BIND, "default Relay bind address")?;
    let mut certificate = None;
    let mut private_key = None;
    let mut client_ca = None;
    let mut upstream_interface = None;
    let mut upstream_interface_index = None;
    let mut max_connections = 1_024usize;
    let mut max_connections_per_ip = 32usize;
    let mut max_subscriptions = RelayLimits::default().max_upstream_subscriptions;
    let mut args = args.into_iter();

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--bind" => bind = parse_socket(&next_value(&mut args, "--bind")?, "--bind")?,
            "--cert" => certificate = Some(PathBuf::from(next_value(&mut args, "--cert")?)),
            "--key" => private_key = Some(PathBuf::from(next_value(&mut args, "--key")?)),
            "--client-ca" => {
                client_ca = Some(PathBuf::from(next_value(&mut args, "--client-ca")?));
            }
            "--upstream-interface" => {
                upstream_interface = Some(parse_ip(
                    &next_value(&mut args, "--upstream-interface")?,
                    "--upstream-interface",
                )?);
            }
            "--upstream-ifindex" => {
                upstream_interface_index = Some(parse_nonzero(
                    &next_value(&mut args, "--upstream-ifindex")?,
                    "--upstream-ifindex",
                )?);
            }
            "--max-connections" => {
                max_connections = parse_nonzero(
                    &next_value(&mut args, "--max-connections")?,
                    "--max-connections",
                )?;
            }
            "--max-connections-per-ip" => {
                max_connections_per_ip = parse_nonzero(
                    &next_value(&mut args, "--max-connections-per-ip")?,
                    "--max-connections-per-ip",
                )?;
            }
            "--max-subscriptions" => {
                max_subscriptions = parse_nonzero(
                    &next_value(&mut args, "--max-subscriptions")?,
                    "--max-subscriptions",
                )?;
            }
            "-h" | "--help" => {
                print_relay_usage();
                return Err(String::new());
            }
            unknown => return Err(format!("unknown relay option '{unknown}'")),
        }
    }

    let certificate = certificate.ok_or_else(|| "relay requires --cert PATH".to_owned())?;
    let private_key = private_key.ok_or_else(|| "relay requires --key PATH".to_owned())?;
    let mut endpoint = RelayEndpointConfig::new(bind, TlsIdentity::new(certificate, private_key));
    endpoint.tls.client_ca = client_ca;
    endpoint.admission.max_connections = max_connections;
    endpoint.admission.max_connections_per_ip = max_connections_per_ip;
    endpoint.admission.accept_queue_capacity = endpoint
        .admission
        .accept_queue_capacity
        .min(max_connections);

    let limits = RelayLimits {
        max_endpoints: max_connections,
        max_upstream_subscriptions: max_subscriptions,
        ..RelayLimits::default()
    };
    endpoint.driver.session.membership_limits = limits.clone();

    let mut config = NativeRelayConfig::new(endpoint);
    config.upstream = UpstreamConfig {
        interface: upstream_interface,
        interface_index: upstream_interface_index,
    };
    config.aggregate_membership_limits = limits;
    Ok(config)
}

fn parse_gateway(args: impl IntoIterator<Item = String>) -> Result<NativeGatewayConfig, String> {
    let mut relay_address = None;
    let mut server_name = None;
    let mut bind_address = None;
    let mut ca = None;
    let mut client_certificate = None;
    let mut client_private_key = None;
    let mut protocol = None;
    let mut joins = Vec::new();
    let mut downstream_interface = None;
    let mut downstream_interface_index = None;
    let mut ttl = Some(1u8);
    let mut loopback = true;
    let mut downstream_enabled = true;
    let mut refresh = Duration::from_secs(30);
    let mut args = args.into_iter();

    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--relay" => {
                relay_address = Some(parse_socket(&next_value(&mut args, "--relay")?, "--relay")?);
            }
            "--server-name" => server_name = Some(next_value(&mut args, "--server-name")?),
            "--bind" => {
                bind_address = Some(parse_socket(&next_value(&mut args, "--bind")?, "--bind")?);
            }
            "--ca" => ca = Some(PathBuf::from(next_value(&mut args, "--ca")?)),
            "--client-cert" => {
                client_certificate = Some(PathBuf::from(next_value(&mut args, "--client-cert")?));
            }
            "--client-key" => {
                client_private_key = Some(PathBuf::from(next_value(&mut args, "--client-key")?));
            }
            "--protocol" => {
                protocol = Some(parse_protocol(&next_value(&mut args, "--protocol")?)?);
            }
            "--join" => joins.push(parse_join(&next_value(&mut args, "--join")?)?),
            "--downstream-interface" => {
                downstream_interface = Some(parse_ip(
                    &next_value(&mut args, "--downstream-interface")?,
                    "--downstream-interface",
                )?);
            }
            "--downstream-ifindex" => {
                downstream_interface_index = Some(parse_nonzero(
                    &next_value(&mut args, "--downstream-ifindex")?,
                    "--downstream-ifindex",
                )?);
            }
            "--ttl" => {
                ttl = Some(parse_nonzero(&next_value(&mut args, "--ttl")?, "--ttl")?);
            }
            "--no-loopback" => loopback = false,
            "--no-downstream" => downstream_enabled = false,
            "--refresh" => {
                let seconds: u64 =
                    parse_nonzero(&next_value(&mut args, "--refresh")?, "--refresh")?;
                refresh = Duration::from_secs(seconds);
            }
            "-h" | "--help" => {
                print_gateway_usage();
                return Err(String::new());
            }
            unknown => return Err(format!("unknown gateway option '{unknown}'")),
        }
    }

    let relay_address = relay_address.ok_or_else(|| "gateway requires --relay ADDR".to_owned())?;
    let server_name =
        server_name.ok_or_else(|| "gateway requires --server-name NAME".to_owned())?;
    let protocol = protocol.ok_or_else(|| "gateway requires --protocol igmpv3|mldv2".to_owned())?;
    if joins.is_empty() {
        return Err("gateway requires at least one --join GROUP or SOURCE@GROUP".to_owned());
    }
    if downstream_interface.is_some_and(|interface| {
        !matches!(
            (protocol, interface),
            (MembershipProtocol::Igmpv3, IpAddr::V4(_))
                | (MembershipProtocol::Mldv2, IpAddr::V6(_))
        )
    }) {
        return Err("--downstream-interface address family must match --protocol".to_owned());
    }
    match (&client_certificate, &client_private_key) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => return Err("--client-cert and --client-key must be supplied together".to_owned()),
    }

    let membership =
        static_membership_report(protocol, joins).map_err(|error| error.to_string())?;
    let mut endpoint = GatewayEndpointConfig::new(relay_address, server_name);
    if let Some(bind_address) = bind_address {
        endpoint.bind_address = bind_address;
    }
    if let Some(ca) = ca {
        endpoint.tls.trust = GatewayTrust::PemFile(ca);
    }
    if let (Some(certificate), Some(private_key)) = (client_certificate, client_private_key) {
        endpoint.tls.client_identity = Some(TlsIdentity::new(certificate, private_key));
    }

    let limits = RelayLimits::default();
    endpoint.driver.session.membership_limits = limits.clone();
    let downstream = DownstreamConfig {
        interface: downstream_interface,
        interface_index: downstream_interface_index,
        ttl,
        loopback,
    };
    let mut config = NativeGatewayConfig::new(endpoint, downstream, membership);
    if !downstream_enabled {
        config = config.without_downstream();
    }
    config.membership_limits = limits;
    config.membership_refresh_interval = refresh;
    Ok(config)
}

fn parse_join(value: &str) -> Result<NativeJoin, String> {
    match value.split_once('@') {
        Some((source, group)) => Ok(NativeJoin::ssm(
            parse_ip(source, "--join source")?,
            parse_ip(group, "--join group")?,
        )),
        None => Ok(NativeJoin::asm(parse_ip(value, "--join group")?)),
    }
}

fn parse_protocol(value: &str) -> Result<MembershipProtocol, String> {
    match value {
        "igmpv3" | "igmp" => Ok(MembershipProtocol::Igmpv3),
        "mldv2" | "mld" => Ok(MembershipProtocol::Mldv2),
        _ => Err(format!(
            "invalid --protocol '{value}'; expected igmpv3 or mldv2"
        )),
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn parse_socket(value: &str, option: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {option} socket address '{value}'"))
}

fn parse_ip(value: &str, option: &str) -> Result<IpAddr, String> {
    value
        .parse()
        .map_err(|_| format!("invalid {option} IP address '{value}'"))
}

fn parse_nonzero<T>(value: &str, option: &str) -> Result<T, String>
where
    T: std::str::FromStr + Default + PartialEq,
{
    let parsed = value
        .parse()
        .map_err(|_| format!("invalid {option} value '{value}'"))?;
    if parsed == T::default() {
        return Err(format!("{option} must not be zero"));
    }
    Ok(parsed)
}

fn print_usage() {
    println!("{}", usage());
}

fn print_relay_usage() {
    println!("{}", relay_usage());
}

fn print_gateway_usage() {
    println!("{}", gateway_usage());
}

fn usage() -> String {
    format!(
        "Usage:\n  amtq relay [OPTIONS]\n  amtq gateway [OPTIONS]\n\n{}\n\n{}",
        relay_usage(),
        gateway_usage()
    )
}

fn relay_usage() -> &'static str {
    "Relay options:
  --bind ADDR                    UDP/QUIC bind address (default 0.0.0.0:2268)
  --cert PATH                    TLS certificate chain (required)
  --key PATH                     TLS private key (required)
  --client-ca PATH               Require Gateway certificates from this CA
  --upstream-interface IP        Native multicast receive interface
  --upstream-ifindex INDEX       IPv6 native receive interface index
  --max-connections COUNT        Global QUIC connection limit
  --max-connections-per-ip COUNT Per-source-IP QUIC connection limit
  --max-subscriptions COUNT      Aggregate native multicast subscription limit"
}

fn gateway_usage() -> &'static str {
    "Gateway options:
  --relay ADDR                   Relay UDP/QUIC address (required)
  --server-name NAME             Relay TLS reference identity (required)
  --ca PATH                      PEM trust bundle (default: system roots)
  --client-cert PATH             Optional Gateway certificate chain
  --client-key PATH              Optional Gateway private key
  --bind ADDR                    Pin local UDP/QUIC path (omit for roaming)
  --protocol igmpv3|mldv2        Membership protocol (required)
  --join GROUP                   Static ASM membership (repeatable)
  --join SOURCE@GROUP            Static SSM membership (repeatable)
  --downstream-interface IP      Native multicast publication interface
  --downstream-ifindex INDEX     IPv6 publication interface index
  --ttl HOPS                     Published multicast hop limit (default 1)
  --refresh SECONDS              Membership refresh interval (default 30)
  --no-loopback                  Disable local multicast loopback
  --no-downstream                Receive and discard tunneled multicast"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_asm_and_ssm_join_syntax() {
        assert_eq!(
            parse_join("239.1.2.3").unwrap(),
            NativeJoin::asm(IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)))
        );
        assert_eq!(
            parse_join("2001:db8::1@ff3e::1234").unwrap(),
            NativeJoin::ssm(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1234))
            )
        );
    }

    #[test]
    fn gateway_rejects_a_downstream_family_mismatch() {
        let result = parse_gateway(
            [
                "--relay",
                "127.0.0.1:2268",
                "--server-name",
                "localhost",
                "--protocol",
                "igmpv3",
                "--join",
                "239.1.2.3",
                "--downstream-interface",
                "::1",
            ]
            .into_iter()
            .map(str::to_owned),
        );

        assert!(result.unwrap_err().contains("address family"));
    }

    #[test]
    fn gateway_can_disable_downstream_publication() {
        let config = parse_gateway(
            [
                "--relay",
                "127.0.0.1:2268",
                "--server-name",
                "localhost",
                "--protocol",
                "igmpv3",
                "--join",
                "239.1.2.3",
                "--no-downstream",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();

        assert!(config.downstream.is_none());
    }

    #[test]
    fn relay_status_reports_changes_without_idle_or_refresh_spam() {
        let now = Instant::now();
        let mut reporter = RelayStatusReporter::default();
        assert!(
            reporter
                .observe(
                    RelayEndpointSnapshot::default(),
                    NativeRelaySnapshot::default(),
                    now,
                )
                .is_empty()
        );

        let endpoint = RelayEndpointSnapshot {
            established_connections: 1,
            active_connections: 1,
            ..RelayEndpointSnapshot::default()
        };
        let native = NativeRelaySnapshot {
            membership_updates: 1,
            active_upstream_subscriptions: 1,
            ..NativeRelaySnapshot::default()
        };
        let lines = reporter.observe(endpoint, native, now + Duration::from_secs(1));
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("active=1"));
        assert!(lines[1].contains("active_subscriptions=1"));

        let refresh = NativeRelaySnapshot {
            membership_updates: 2,
            ..native
        };
        assert!(
            reporter
                .observe(endpoint, refresh, now + Duration::from_secs(2))
                .is_empty()
        );

        let traffic = NativeRelaySnapshot {
            upstream_packets: 10,
            forwarded_datagrams: 10,
            ..refresh
        };
        let lines = reporter.observe(endpoint, traffic, now + Duration::from_secs(3));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("forwarded=+10"));

        let more_traffic = NativeRelaySnapshot {
            upstream_packets: 11,
            forwarded_datagrams: 11,
            ..traffic
        };
        assert!(
            reporter
                .observe(endpoint, more_traffic, now + Duration::from_secs(4))
                .is_empty()
        );
        let lines = reporter.observe(
            endpoint,
            more_traffic,
            now + TRAFFIC_REPORT_INTERVAL + Duration::from_secs(3),
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("forwarded=+1"));
    }

    #[test]
    fn gateway_status_reports_first_membership_and_rate_limits_traffic() {
        let now = Instant::now();
        let mut reporter = GatewayStatusReporter::default();

        let unavailable = NativeGatewaySnapshot {
            path_reachable: false,
            path_outages: 1,
            path_datagrams_dropped: 2,
            ..NativeGatewaySnapshot::default()
        };
        let lines = reporter.observe(unavailable, now);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("path unavailable"));

        let recovered = NativeGatewaySnapshot {
            path_reachable: true,
            path_outages: 1,
            path_recoveries: 1,
            path_datagrams_dropped: 2,
            ..NativeGatewaySnapshot::default()
        };
        let lines = reporter.observe(recovered, now + Duration::from_millis(1));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("path restored"));

        let membership = NativeGatewaySnapshot {
            membership_updates_sent: 1,
            ..recovered
        };
        let lines = reporter.observe(membership, now + Duration::from_millis(2));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("membership update sent"));

        let refresh = NativeGatewaySnapshot {
            membership_updates_sent: 2,
            ..membership
        };
        assert!(
            reporter
                .observe(refresh, now + Duration::from_secs(1))
                .is_empty()
        );

        let traffic = NativeGatewaySnapshot {
            multicast_datagrams_received: 4,
            multicast_bytes_received: 4_096,
            downstream_datagrams_queued: 4,
            ..refresh
        };
        let lines = reporter.observe(traffic, now + Duration::from_secs(2));
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("received=+4"));

        let more_traffic = NativeGatewaySnapshot {
            multicast_datagrams_received: 5,
            multicast_bytes_received: 5_120,
            downstream_datagrams_queued: 5,
            ..traffic
        };
        assert!(
            reporter
                .observe(more_traffic, now + Duration::from_secs(3))
                .is_empty()
        );
    }
}
