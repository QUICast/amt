use crate::downstream::{DownstreamConfig, DownstreamPublisher};
use crate::gateway::{Gateway, GatewayAction, GatewayConfig};
use crate::protocol::{Message, encode};
use crate::relay::{Relay, RelayAction, RelayConfig};
use crate::upstream::{UpstreamConfig, UpstreamManager};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

const MAX_UDP_DATAGRAM: usize = 65_535;
const MAX_UPSTREAM_DRAIN: usize = 64;
const IDLE_SLEEP: Duration = Duration::from_millis(10);
const GATEWAY_REDISCOVER_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub relay: RelayConfig,
    pub upstream: UpstreamConfig,
}

impl DaemonConfig {
    pub fn new(relay: RelayConfig) -> Self {
        Self {
            relay,
            upstream: UpstreamConfig::default(),
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self::new(RelayConfig::default())
    }
}

impl From<RelayConfig> for DaemonConfig {
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
}

impl GatewayDaemonConfig {
    pub fn new(bind: SocketAddr, gateway: GatewayConfig) -> Self {
        Self {
            bind,
            gateway,
            joins: Vec::new(),
            downstream: Some(DownstreamConfig::default()),
        }
    }
}

/// Runs a small blocking AMT relay daemon.
pub fn run(config: impl Into<DaemonConfig>) -> io::Result<()> {
    let config = config.into();
    let socket = UdpSocket::bind(config.relay.bind)?;
    socket.set_nonblocking(true)?;

    let mut relay = Relay::new(config.relay);
    let mut upstream = UpstreamManager::new(config.upstream);
    println!(
        "amt relay listening on {} (advertising IPv4 {}, IPv6 {})",
        socket.local_addr()?,
        relay.config().advertise_ipv4,
        relay.config().advertise_ipv6
    );

    let mut buf = [0; MAX_UDP_DATAGRAM];
    loop {
        let mut made_progress = false;

        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    made_progress = true;
                    handle_amt_datagram(&socket, &mut relay, &mut upstream, peer, &buf[..len])?;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        let forwarded = drain_upstream(&socket, &relay, &mut upstream)?;
        made_progress |= forwarded != 0;

        if !made_progress {
            thread::sleep(IDLE_SLEEP);
        }
    }
}

/// Runs a small blocking AMT gateway daemon.
pub fn run_gateway(config: GatewayDaemonConfig) -> io::Result<()> {
    let socket = UdpSocket::bind(config.bind)?;
    socket.set_nonblocking(true)?;

    let mut gateway = Gateway::new(config.gateway);
    let mut downstream = config.downstream.map(DownstreamPublisher::new);
    let mut last_discovery = Instant::now()
        .checked_sub(GATEWAY_REDISCOVER_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut buf = [0; MAX_UDP_DATAGRAM];

    println!(
        "amt gateway listening on {} and discovering relay {}",
        socket.local_addr()?,
        gateway.config().relay
    );

    loop {
        let mut made_progress = false;

        if gateway.relay_endpoint().is_none()
            && last_discovery.elapsed() >= GATEWAY_REDISCOVER_INTERVAL
        {
            send_gateway_action(&socket, gateway.discovery())?;
            last_discovery = Instant::now();
            made_progress = true;
        }

        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    made_progress = true;
                    match gateway.handle_datagram(peer, &buf[..len]) {
                        Ok(GatewayAction::Send {
                            destination,
                            datagram,
                        }) => {
                            socket.send_to(&datagram, destination)?;
                            println!(
                                "{peer} triggered {} byte gateway response to {destination}",
                                datagram.len()
                            );
                        }
                        Ok(GatewayAction::MembershipQuery { .. }) => {
                            println!("{peer} sent Membership Query; sending configured joins");
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
                            }
                        }
                        Ok(GatewayAction::MulticastData { packet }) => {
                            println!("{peer} sent {} byte AMT multicast packet", packet.len());
                            if let Some(downstream) = downstream.as_mut() {
                                match downstream.forward_ip_datagram(&packet) {
                                    Ok(Some(report)) => {
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
                                    Ok(None) => println!(
                                        "received AMT multicast packet is not a multicast IP datagram"
                                    ),
                                    Err(error) => eprintln!(
                                        "failed to forward downstream multicast packet: {error}"
                                    ),
                                }
                            }
                        }
                        Ok(GatewayAction::Ignored) => println!("{peer} ignored AMT message"),
                        Err(error) => eprintln!("{peer} invalid gateway AMT datagram: {error}"),
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        if !made_progress {
            thread::sleep(IDLE_SLEEP);
        }
    }
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

fn handle_amt_datagram(
    socket: &UdpSocket,
    relay: &mut Relay,
    upstream: &mut UpstreamManager,
    peer: std::net::SocketAddr,
    datagram: &[u8],
) -> io::Result<()> {
    match relay.handle_datagram(peer, datagram) {
        Ok(action) => {
            let sync_required = matches!(
                &action,
                RelayAction::AcceptedMembershipUpdate { .. } | RelayAction::AcceptedTeardown { .. }
            );

            match action {
                RelayAction::Send(response) => {
                    socket.send_to(&response, peer)?;
                    println!("{peer} sent {} byte response", response.len());
                }
                RelayAction::AcceptedMembershipUpdate {
                    protocol,
                    bytes,
                    records_applied,
                    upstream_subscriptions,
                } => {
                    println!(
                        "{peer} accepted {protocol:?} membership update ({bytes} bytes, {records_applied} records, {} upstream subscriptions)",
                        upstream_subscriptions.len()
                    );
                }
                RelayAction::AcceptedTeardown { gateway, removed } => {
                    println!(
                        "{peer} accepted teardown for {}:{} (removed={removed})",
                        gateway.address.as_ipv6(),
                        gateway.port
                    );
                }
                RelayAction::RejectedAuth => println!("{peer} rejected AMT authentication"),
                RelayAction::Ignored => println!("{peer} ignored AMT message"),
            }

            if sync_required {
                sync_upstream(relay, upstream)?;
            }

            Ok(())
        }
        Err(error) => {
            eprintln!("{peer} invalid AMT datagram: {error}");
            Ok(())
        }
    }
}

fn sync_upstream(relay: &Relay, upstream: &mut UpstreamManager) -> io::Result<()> {
    let subscriptions = relay.state().upstream_subscriptions();
    let changes = upstream
        .reconcile(subscriptions)
        .map_err(|error| io::Error::other(format!("failed to update upstream receive: {error}")))?;

    if changes.changed() {
        println!(
            "upstream subscriptions changed: +{} -{} active={}",
            changes.added, changes.removed, changes.active
        );
    }

    Ok(())
}

fn drain_upstream(
    socket: &UdpSocket,
    relay: &Relay,
    upstream: &mut UpstreamManager,
) -> io::Result<usize> {
    let mut forwarded_packets = 0;

    for _ in 0..MAX_UPSTREAM_DRAIN {
        let Some(datagram) = upstream.try_recv().map_err(|error| {
            io::Error::other(format!("failed to receive upstream multicast: {error}"))
        })?
        else {
            break;
        };

        let endpoints = relay
            .state()
            .endpoints_for_packet(datagram.source, datagram.group);
        if endpoints.is_empty() {
            continue;
        }

        let response = encode(&Message::MulticastData {
            packet: datagram.datagram(),
        });

        for endpoint in &endpoints {
            if let Err(error) = socket.send_to(&response, endpoint) {
                eprintln!(
                    "failed to forward {} byte multicast datagram to {endpoint}: {error}",
                    datagram.datagram().len()
                );
            }
        }

        forwarded_packets += 1;
        println!(
            "forwarded {} byte multicast datagram from {} to {} gateway(s)",
            datagram.datagram().len(),
            datagram.source,
            endpoints.len()
        );
    }

    Ok(forwarded_packets)
}
