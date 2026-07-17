use amt::MembershipProtocol;
use amtq::session::{GatewayEvent, RelayEvent};
use amtq::transport::endpoint::{
    ConnectionPolicy, GatewayEndpointConfig, GatewayTrust, RelayAdmissionPolicy, RelayEndpoint,
    RelayEndpointConfig, TlsIdentity, connect_gateway,
};
use amtq::transport::tokio_quiche::{
    ConnectionStatus, GatewayCommand, GatewayController, GatewayTransportEvent, RelayController,
    RelayTransportEvent,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::{Instant, sleep, timeout};

const CERTIFICATE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/localhost-cert.pem"
);
const PRIVATE_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/localhost-key.pem"
);
const TEST_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keepalive_preserves_idle_connection_and_close_releases_admission() {
    let mut relay = RelayEndpoint::bind(relay_config(4)).await.unwrap();
    let mut gateway = connect_gateway(gateway_config(relay.local_address()))
        .await
        .unwrap();
    let mut relay_connection = timeout(TEST_TIMEOUT, relay.accept())
        .await
        .unwrap()
        .unwrap();

    complete_settings(gateway.controller_mut(), relay_connection.controller_mut()).await;
    assert_ne!(gateway.id(), relay_connection.id());
    assert_eq!(relay.stats().snapshot().active_connections, 1);

    sleep(Duration::from_millis(350)).await;
    gateway
        .controller()
        .send(GatewayCommand::BeginRequest {
            request_nonce: 7,
            protocol: MembershipProtocol::Igmpv3,
        })
        .await
        .unwrap();
    assert_eq!(
        next_relay_event(relay_connection.controller_mut()).await,
        RelayTransportEvent::Session(RelayEvent::Request {
            protocol: MembershipProtocol::Igmpv3,
            request_nonce: 7,
        })
    );

    assert!(gateway.shutdown().await.graceful);
    wait_for_active_connections(&relay, 0).await;
    assert!(relay.shutdown().await.unwrap().graceful);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_admission_rejects_a_second_connection_from_the_same_ip() {
    let mut relay = RelayEndpoint::bind(relay_config(1)).await.unwrap();
    let relay_address = relay.local_address();
    let mut first_gateway = connect_gateway(gateway_config(relay_address))
        .await
        .unwrap();
    let _first_relay = timeout(TEST_TIMEOUT, relay.accept())
        .await
        .unwrap()
        .unwrap();

    let second = tokio::spawn(connect_gateway(gateway_config(relay_address)));
    wait_for_rejected_connections(&relay, 1).await;
    second.abort();
    let _ = second.await;

    let _ = first_gateway.shutdown().await;
    wait_for_active_connections(&relay, 0).await;
    assert!(relay.shutdown().await.unwrap().graceful);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_trust_rejects_the_wrong_reference_identity() {
    let mut relay = RelayEndpoint::bind(relay_config(2)).await.unwrap();
    let mut config = gateway_config(relay.local_address());
    config.tls.server_name = "not-localhost.example".to_string();

    let result = timeout(TEST_TIMEOUT, connect_gateway(config))
        .await
        .expect("hostname-mismatch handshake did not finish");
    assert!(result.is_err());
    wait_for_active_connections(&relay, 0).await;
    assert!(relay.stats().snapshot().handshake_failures >= 1);
    assert!(relay.shutdown().await.unwrap().graceful);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn optional_mutual_tls_accepts_a_trusted_gateway_certificate() {
    let mut config = relay_config(2);
    config.tls.client_ca = Some(PathBuf::from(CERTIFICATE));
    let mut relay = RelayEndpoint::bind(config).await.unwrap();

    let anonymous = timeout(
        TEST_TIMEOUT,
        connect_gateway(gateway_config(relay.local_address())),
    )
    .await
    .expect("anonymous mTLS handshake did not finish");
    if let Ok(anonymous) = anonymous {
        wait_for_gateway_closed(&anonymous).await;
    }

    let mut gateway_config = gateway_config(relay.local_address());
    gateway_config.tls.client_identity = Some(TlsIdentity::new(CERTIFICATE, PRIVATE_KEY));
    let mut gateway = connect_gateway(gateway_config).await.unwrap();
    let _relay_connection = timeout(TEST_TIMEOUT, relay.accept())
        .await
        .unwrap()
        .unwrap();

    assert!(gateway.shutdown().await.graceful);
    wait_for_active_connections(&relay, 0).await;
    assert!(relay.shutdown().await.unwrap().graceful);
}

fn relay_config(max_connections: usize) -> RelayEndpointConfig {
    let bind_address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let mut config =
        RelayEndpointConfig::new(bind_address, TlsIdentity::new(CERTIFICATE, PRIVATE_KEY));
    config.connection = test_connection_policy();
    config.admission = RelayAdmissionPolicy {
        max_connections,
        max_connections_per_ip: max_connections,
        accept_queue_capacity: max_connections,
    };
    config
}

fn gateway_config(relay_address: SocketAddr) -> GatewayEndpointConfig {
    let mut config = GatewayEndpointConfig::new(relay_address, "localhost");
    config.tls.trust = GatewayTrust::PemFile(PathBuf::from(CERTIFICATE));
    config.connection = test_connection_policy();
    config
}

fn test_connection_policy() -> ConnectionPolicy {
    ConnectionPolicy {
        max_idle_timeout: Duration::from_millis(100),
        handshake_timeout: Duration::from_millis(300),
        keepalive_interval: Some(Duration::from_millis(20)),
        shutdown_timeout: Duration::from_secs(1),
    }
}

async fn complete_settings(gateway: &mut GatewayController, relay: &mut RelayController) {
    assert!(matches!(
        next_gateway_event(gateway).await,
        GatewayTransportEvent::Connected { .. }
    ));
    assert!(matches!(
        next_relay_event(relay).await,
        RelayTransportEvent::Connected { .. }
    ));
    assert_eq!(
        next_gateway_event(gateway).await,
        GatewayTransportEvent::Session(GatewayEvent::SettingsReceived)
    );
    assert_eq!(
        next_relay_event(relay).await,
        RelayTransportEvent::Session(RelayEvent::SettingsReceived)
    );
}

async fn next_gateway_event(controller: &mut GatewayController) -> GatewayTransportEvent {
    timeout(TEST_TIMEOUT, controller.next_event())
        .await
        .expect("Gateway event timed out")
        .expect("Gateway driver stopped")
}

async fn next_relay_event(controller: &mut RelayController) -> RelayTransportEvent {
    timeout(TEST_TIMEOUT, controller.next_event())
        .await
        .expect("Relay event timed out")
        .expect("Relay driver stopped")
}

async fn wait_for_active_connections(relay: &RelayEndpoint, expected: usize) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if relay.stats().snapshot().active_connections == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Relay active connection count did not reach {expected}"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_rejected_connections(relay: &RelayEndpoint, expected: u64) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if relay.stats().snapshot().rejected_connections >= expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Relay rejected connection count did not reach {expected}"
        );
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_gateway_closed(gateway: &amtq::transport::endpoint::GatewayConnection) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        if matches!(
            gateway.controller().status(),
            ConnectionStatus::Closed { .. }
        ) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Gateway did not close after anonymous mTLS"
        );
        sleep(Duration::from_millis(10)).await;
    }
}
