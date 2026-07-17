use amt::membership::build_membership_report;
use amt::protocol::encode;
use amt::query::{GeneralQueryConfig, build_general_query};
use amt::{MembershipProtocol, MembershipRecord, MembershipRecordKind, MembershipReport, Message};
use amtq::control::{Context, DataMode};
use amtq::session::{GatewayEvent, RelayEvent};
use amtq::transport::tokio_quiche::{
    GatewayCommand, GatewayController, GatewayDriver, GatewayDriverConfig, GatewayTransportEvent,
    RelayCommand, RelayController, RelayDriver, RelayDriverConfig, RelayTransportEvent,
    quic_settings,
};
use boring::ssl::{SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};
use futures_util::StreamExt;
use std::future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_quiche::ConnectionParams;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::settings::{CertificateKind, Hooks, TlsCertificatePaths};
use tokio_quiche::socket::Socket;

const CERTIFICATE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/localhost-cert.pem"
);
const PRIVATE_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/localhost-key.pem"
);
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_NONCE: u32 = 0x1020_3040;
const CONTEXT_ID: u64 = 0;
const GROUP: Ipv4Addr = Ipv4Addr::new(239, 1, 2, 3);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

#[derive(Debug)]
struct TrustTestCertificate;

impl ConnectionHook for TrustTestCertificate {
    fn create_custom_ssl_context_builder(
        &self,
        settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        let mut builder = SslContextBuilder::new(SslMethod::tls()).ok()?;
        builder.set_ca_file(CERTIFICATE).ok()?;
        builder.set_certificate_chain_file(settings.cert).ok()?;
        builder
            .set_private_key_file(settings.private_key, SslFiletype::PEM)
            .ok()?;
        builder.set_verify(SslVerifyMode::PEER);
        Some(builder)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn certificate_verified_datagram_session_delivers_complete_and_fragmented_data() {
    let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server_address = server_socket.local_addr().unwrap();
    let relay_settings = quic_settings(&RelayDriverConfig::default().transport).unwrap();
    let relay_params =
        ConnectionParams::new_server(relay_settings, certificate_paths(), Hooks::default());
    let mut listeners =
        tokio_quiche::listen([server_socket], relay_params, DefaultMetrics).unwrap();
    let mut listener = listeners.remove(0);

    let (relay_driver, relay_controller) = RelayDriver::new(RelayDriverConfig::default()).unwrap();
    let (relay_sender, relay_receiver) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let initial = listener.next().await.unwrap().unwrap();
        let connection = initial.start(relay_driver);
        let _ = relay_sender.send(relay_controller);
        let _connection = connection;
        future::pending::<()>().await;
    });

    let client_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    client_socket.connect(server_address).await.unwrap();
    let socket = Socket::try_from(client_socket).unwrap();
    let gateway_settings = quic_settings(&GatewayDriverConfig::default().transport).unwrap();
    let gateway_params = ConnectionParams::new_client(
        gateway_settings,
        Some(certificate_paths()),
        Hooks {
            connection_hook: Some(Arc::new(TrustTestCertificate)),
        },
    );
    let (gateway_driver, mut gateway) = GatewayDriver::new(GatewayDriverConfig::default()).unwrap();
    let gateway_connection = timeout(
        EVENT_TIMEOUT,
        tokio_quiche::quic::connect_with_config(
            socket,
            Some("localhost"),
            &gateway_params,
            gateway_driver,
        ),
    )
    .await
    .expect("Gateway handshake timed out")
    .expect("Gateway handshake failed");
    let mut relay = timeout(EVENT_TIMEOUT, relay_receiver)
        .await
        .expect("Relay did not accept the connection")
        .expect("Relay accept task stopped");

    expect_gateway_connected(&mut gateway).await;
    expect_relay_connected(&mut relay).await;
    assert_eq!(
        next_gateway_event(&mut gateway).await,
        GatewayTransportEvent::Session(GatewayEvent::SettingsReceived)
    );
    assert_eq!(
        next_relay_event(&mut relay).await,
        RelayTransportEvent::Session(RelayEvent::SettingsReceived)
    );

    gateway
        .send(GatewayCommand::BeginRequest {
            request_nonce: REQUEST_NONCE,
            protocol: MembershipProtocol::Igmpv3,
        })
        .await
        .unwrap();
    assert_eq!(
        next_relay_event(&mut relay).await,
        RelayTransportEvent::Session(RelayEvent::Request {
            protocol: MembershipProtocol::Igmpv3,
            request_nonce: REQUEST_NONCE,
        })
    );

    relay
        .send(RelayCommand::MembershipQuery(build_general_query(
            MembershipProtocol::Igmpv3,
            &GeneralQueryConfig::default(),
        )))
        .await
        .unwrap();
    assert!(matches!(
        next_gateway_event(&mut gateway).await,
        GatewayTransportEvent::Session(GatewayEvent::MembershipQuery {
            protocol: MembershipProtocol::Igmpv3,
            request_nonce: REQUEST_NONCE,
            ..
        })
    ));

    let membership = build_membership_report(&MembershipReport {
        protocol: MembershipProtocol::Igmpv3,
        records: vec![MembershipRecord {
            kind: MembershipRecordKind::ModeIsExclude,
            group: IpAddr::V4(GROUP),
            sources: Vec::new(),
        }],
    })
    .unwrap();
    gateway
        .send(GatewayCommand::MembershipUpdate(membership))
        .await
        .unwrap();
    let RelayTransportEvent::Session(RelayEvent::MembershipUpdate(pending)) =
        next_relay_event(&mut relay).await
    else {
        panic!("Relay did not receive the Membership Update");
    };
    assert_eq!(pending.report().records[0].group, IpAddr::V4(GROUP));
    relay
        .send(RelayCommand::AuthorizeAll(pending))
        .await
        .unwrap();

    relay
        .send(RelayCommand::OpenContext(Context {
            id: CONTEXT_ID,
            mode: DataMode::Datagram.value(),
        }))
        .await
        .unwrap();
    assert!(matches!(
        next_gateway_event(&mut gateway).await,
        GatewayTransportEvent::Session(GatewayEvent::ContextOpened {
            context: Context {
                id: CONTEXT_ID,
                mode
            },
            ..
        }) if mode == DataMode::Datagram.value()
    ));
    assert_eq!(
        next_relay_event(&mut relay).await,
        RelayTransportEvent::Session(RelayEvent::ContextAcknowledged {
            context_id: CONTEXT_ID,
        })
    );

    for payload_len in [16, 4_096] {
        let message = multicast_message(payload_len);
        relay
            .send(RelayCommand::SendDatagram {
                context_id: CONTEXT_ID,
                message: message.clone().into(),
            })
            .await
            .unwrap();
        assert_eq!(
            next_gateway_event(&mut gateway).await,
            GatewayTransportEvent::MulticastData(message)
        );
    }

    gateway.send(GatewayCommand::Close).await.unwrap();
    drop(gateway_connection);
    server_task.abort();
}

fn certificate_paths() -> TlsCertificatePaths<'static> {
    TlsCertificatePaths {
        cert: CERTIFICATE,
        private_key: PRIVATE_KEY,
        kind: CertificateKind::X509,
    }
}

async fn next_gateway_event(controller: &mut GatewayController) -> GatewayTransportEvent {
    timeout(EVENT_TIMEOUT, controller.next_event())
        .await
        .expect("Gateway event timed out")
        .expect("Gateway driver stopped")
}

async fn next_relay_event(controller: &mut RelayController) -> RelayTransportEvent {
    timeout(EVENT_TIMEOUT, controller.next_event())
        .await
        .expect("Relay event timed out")
        .expect("Relay driver stopped")
}

async fn expect_gateway_connected(controller: &mut GatewayController) {
    assert!(matches!(
        next_gateway_event(controller).await,
        GatewayTransportEvent::Connected { .. }
    ));
}

async fn expect_relay_connected(controller: &mut RelayController) {
    assert!(matches!(
        next_relay_event(controller).await,
        RelayTransportEvent::Connected { .. }
    ));
}

fn multicast_message(payload_len: usize) -> Vec<u8> {
    let packet = ipv4_udp_multicast_packet(payload_len);
    encode(&Message::MulticastData { packet: &packet })
}

fn ipv4_udp_multicast_packet(payload_len: usize) -> Vec<u8> {
    let total_len = 20 + 8 + payload_len;
    let udp_len = 8 + payload_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234_u16.to_be_bytes());
    packet[8] = 16;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&SOURCE.octets());
    packet[16..20].copy_from_slice(&GROUP.octets());
    packet[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&5_000_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    for (index, byte) in packet[28..].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes.chunks_exact(2).fold(0_u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes([pair[0], pair[1]]))
    });
    if let Some(&last) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(last) << 8;
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}
