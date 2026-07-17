use amt::{
    DownstreamConfig, MembershipProtocol, MembershipRecord, MembershipRecordKind, MembershipReport,
};
use amtq::native::{NativeGateway, NativeGatewayConfig, NativeRelay, NativeRelayConfig};
use amtq::transport::endpoint::{
    GatewayEndpointConfig, GatewayTrust, RelayEndpointConfig, TlsIdentity,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_services_complete_membership_and_shutdown_cleanly() {
    let mut relay = NativeRelay::bind(NativeRelayConfig::new(RelayEndpointConfig::new(
        localhost(0),
        fixture_identity(),
    )))
    .await
    .unwrap();

    let mut endpoint = GatewayEndpointConfig::new(relay.local_address(), "localhost");
    endpoint.tls.trust = GatewayTrust::PemFile(fixture("localhost-cert.pem"));
    let membership = MembershipReport {
        protocol: MembershipProtocol::Igmpv3,
        records: vec![MembershipRecord {
            kind: MembershipRecordKind::ModeIsInclude,
            group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
            sources: vec![],
        }],
    };
    let mut gateway = NativeGateway::connect(NativeGatewayConfig::new(
        endpoint,
        DownstreamConfig::default(),
        membership,
    ))
    .await
    .unwrap();

    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if gateway.stats().snapshot().membership_updates_sent >= 1
                && relay.stats().snapshot().membership_updates >= 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let gateway_stop = gateway.shutdown().await.unwrap();
    let relay_stop = relay.shutdown().await.unwrap();
    assert!(gateway_stop.connection.graceful);
    assert!(relay_stop.endpoint.graceful);
    assert_eq!(relay_stop.snapshot.active_upstream_subscriptions, 0);
    assert_eq!(relay.endpoint_stats().snapshot().active_connections, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aggregate_authorization_denial_keeps_the_connection_open() {
    let mut relay_config =
        NativeRelayConfig::new(RelayEndpointConfig::new(localhost(0), fixture_identity()));
    relay_config
        .aggregate_membership_limits
        .max_groups_per_endpoint = 0;
    let mut relay = NativeRelay::bind(relay_config).await.unwrap();

    let mut endpoint = GatewayEndpointConfig::new(relay.local_address(), "localhost");
    endpoint.tls.trust = GatewayTrust::PemFile(fixture("localhost-cert.pem"));
    let membership = MembershipReport {
        protocol: MembershipProtocol::Igmpv3,
        records: vec![MembershipRecord {
            kind: MembershipRecordKind::ModeIsExclude,
            group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
            sources: vec![],
        }],
    };
    let mut gateway = NativeGateway::connect(NativeGatewayConfig::new(
        endpoint,
        DownstreamConfig::default(),
        membership,
    ))
    .await
    .unwrap();

    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            let snapshot = relay.stats().snapshot();
            if snapshot.membership_updates >= 1 && snapshot.rejected_membership_updates >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    assert_eq!(relay.endpoint_stats().snapshot().active_connections, 1);
    assert_eq!(relay.stats().snapshot().active_upstream_subscriptions, 0);
    gateway.shutdown().await.unwrap();
    relay.shutdown().await.unwrap();
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn fixture_identity() -> TlsIdentity {
    TlsIdentity::new(fixture("localhost-cert.pem"), fixture("localhost-key.pem"))
}
