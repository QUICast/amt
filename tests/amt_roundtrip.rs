use amt::protocol::encode;
use amt::{
    Gateway, GatewayAction, GatewayConfig, MembershipProtocol, Message, Relay, RelayAction,
    RelayConfig, RelaySecret, UpstreamSubscription,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[test]
fn gateway_and_relay_complete_amt_round_trip_over_udp() {
    let relay_socket = bound_local_udp();
    let gateway_socket = bound_local_udp();
    let relay_addr = relay_socket.local_addr().unwrap();
    let gateway_addr = gateway_socket.local_addr().unwrap();

    let mut relay = Relay::new(RelayConfig::for_bind(relay_addr));
    let group = Ipv4Addr::new(232, 1, 2, 3);
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let mut gateway = Gateway::new(
        GatewayConfig::new(relay_addr, MembershipProtocol::Igmpv3)
            .with_nonces(0x0102_0304, 0x0506_0708),
    );

    send_gateway_action(&gateway_socket, gateway.discovery());
    relay_recv_and_respond(&relay_socket, &mut relay);

    let action = gateway_recv(&gateway_socket, &mut gateway);
    send_gateway_action(&gateway_socket, action);
    relay_recv_and_respond(&relay_socket, &mut relay);

    let action = gateway_recv(&gateway_socket, &mut gateway);
    assert!(matches!(action, GatewayAction::MembershipQuery { .. }));
    send_gateway_action(
        &gateway_socket,
        gateway
            .join_group(IpAddr::V4(group), Some(IpAddr::V4(source)))
            .unwrap(),
    );

    let action = relay_recv_action(&relay_socket, &mut relay);
    assert_eq!(
        action,
        RelayAction::AcceptedMembershipUpdate {
            protocol: MembershipProtocol::Igmpv3,
            bytes: 44,
            records_applied: 1,
            upstream_subscriptions: vec![UpstreamSubscription::ssm(
                IpAddr::V4(group),
                IpAddr::V4(source)
            )],
        }
    );
    assert_eq!(
        relay
            .state()
            .endpoints_for_packet(IpAddr::V4(source), IpAddr::V4(group)),
        vec![gateway_addr]
    );

    let multicast_packet = ipv4_udp_multicast_packet(source, group, 5000, b"amt works");
    relay_socket
        .send_to(
            &encode(&Message::MulticastData {
                packet: &multicast_packet,
            }),
            gateway_addr,
        )
        .unwrap();

    let action = gateway_recv(&gateway_socket, &mut gateway);
    let GatewayAction::MulticastData { packet } = action else {
        panic!("expected multicast data action");
    };
    assert_eq!(packet, multicast_packet);

    send_gateway_action(&gateway_socket, gateway.teardown().unwrap());
    let action = relay_recv_action(&relay_socket, &mut relay);
    assert!(matches!(
        action,
        RelayAction::AcceptedTeardown { removed: true, .. }
    ));
    assert!(
        relay
            .state()
            .endpoints_for_packet(IpAddr::V4(source), IpAddr::V4(group))
            .is_empty()
    );
}

#[test]
fn gateway_can_refresh_membership_query_after_relay_restart() {
    let relay_socket = bound_local_udp();
    let gateway_socket = bound_local_udp();
    let relay_addr = relay_socket.local_addr().unwrap();
    let gateway_addr = gateway_socket.local_addr().unwrap();

    let group = Ipv4Addr::new(232, 1, 2, 3);
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let mut relay = relay_with_secret(relay_addr, 1);
    let mut gateway = Gateway::new(
        GatewayConfig::new(relay_addr, MembershipProtocol::Igmpv3)
            .with_nonces(0x0102_0304, 0x0506_0708),
    );

    send_gateway_action(&gateway_socket, gateway.discovery());
    relay_recv_and_respond(&relay_socket, &mut relay);
    let action = gateway_recv(&gateway_socket, &mut gateway);
    send_gateway_action(&gateway_socket, action);
    relay_recv_and_respond(&relay_socket, &mut relay);
    assert!(matches!(
        gateway_recv(&gateway_socket, &mut gateway),
        GatewayAction::MembershipQuery { .. }
    ));
    send_gateway_action(
        &gateway_socket,
        gateway
            .join_group(IpAddr::V4(group), Some(IpAddr::V4(source)))
            .unwrap(),
    );
    assert!(matches!(
        relay_recv_action(&relay_socket, &mut relay),
        RelayAction::AcceptedMembershipUpdate { .. }
    ));

    let mut restarted_relay = relay_with_secret(relay_addr, 2);
    send_gateway_action(
        &gateway_socket,
        gateway
            .join_group(IpAddr::V4(group), Some(IpAddr::V4(source)))
            .unwrap(),
    );
    assert_eq!(
        relay_recv_action(&relay_socket, &mut restarted_relay),
        RelayAction::RejectedAuth
    );
    assert!(restarted_relay.state().upstream_subscriptions().is_empty());

    send_gateway_action(&gateway_socket, gateway.begin_query_cycle().unwrap());
    relay_recv_and_respond(&relay_socket, &mut restarted_relay);
    assert!(matches!(
        gateway_recv(&gateway_socket, &mut gateway),
        GatewayAction::MembershipQuery { .. }
    ));
    send_gateway_action(
        &gateway_socket,
        gateway
            .join_group(IpAddr::V4(group), Some(IpAddr::V4(source)))
            .unwrap(),
    );

    assert!(matches!(
        relay_recv_action(&relay_socket, &mut restarted_relay),
        RelayAction::AcceptedMembershipUpdate { .. }
    ));
    assert_eq!(
        restarted_relay
            .state()
            .endpoints_for_packet(IpAddr::V4(source), IpAddr::V4(group)),
        vec![gateway_addr]
    );
}

fn relay_with_secret(addr: SocketAddr, secret_byte: u8) -> Relay {
    Relay::new(RelayConfig {
        secret: RelaySecret::new([secret_byte; 32]),
        ..RelayConfig::for_bind(addr)
    })
}

fn bound_local_udp() -> UdpSocket {
    let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    socket
}

fn send_gateway_action(socket: &UdpSocket, action: GatewayAction) {
    let (destination, datagram) = action.into_send().expect("expected gateway send action");
    socket.send_to(&datagram, destination).unwrap();
}

fn relay_recv_and_respond(socket: &UdpSocket, relay: &mut Relay) {
    let (datagram, peer) = recv_datagram(socket).unwrap();
    let action = relay.handle_datagram(peer, &datagram).unwrap();
    let RelayAction::Send(response) = action else {
        panic!("expected relay response");
    };
    socket.send_to(&response, peer).unwrap();
}

fn relay_recv_action(socket: &UdpSocket, relay: &mut Relay) -> RelayAction {
    let (datagram, peer) = recv_datagram(socket).unwrap();
    relay.handle_datagram(peer, &datagram).unwrap()
}

fn gateway_recv(socket: &UdpSocket, gateway: &mut Gateway) -> GatewayAction {
    let (datagram, peer) = recv_datagram(socket).unwrap();
    gateway.handle_datagram(peer, &datagram).unwrap()
}

fn recv_datagram(socket: &UdpSocket) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut buf = [0; 65_535];
    let (len, peer) = socket.recv_from(&mut buf)?;
    Ok((buf[..len].to_vec(), peer))
}

fn ipv4_udp_multicast_packet(
    source: Ipv4Addr,
    group: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 1;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&group.octets());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from_be_bytes([*high, 0]),
            _ => unreachable!(),
        };
        sum += u32::from(word);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}
