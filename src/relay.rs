use crate::membership::{MembershipParseError, parse_membership_report};
use crate::protocol::{
    DecodeError, GatewayAddress, GatewayEndpoint, MembershipProtocol, Message, ResponseMac, encode,
};
use crate::query::{GeneralQueryConfig, build_general_query};
use crate::state::{RelayState, UpstreamSubscription};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, PartialEq, Eq)]
pub struct RelaySecret([u8; 32]);

impl RelaySecret {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0; 32];
        if getrandom::fill(&mut bytes).is_ok() {
            return Self(bytes);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = u128::from(std::process::id());
        bytes[..16].copy_from_slice(&now.to_be_bytes());
        bytes[16..].copy_from_slice(&(now.rotate_left(17) ^ pid).to_be_bytes());
        Self(bytes)
    }

    pub const fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for RelaySecret {
    fn default() -> Self {
        Self::generate()
    }
}

impl fmt::Debug for RelaySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelaySecret(..)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    pub bind: SocketAddr,
    pub advertise_ipv4: Ipv4Addr,
    pub advertise_ipv6: Ipv6Addr,
    pub secret: RelaySecret,
    pub include_gateway_address: bool,
    pub limit: bool,
    pub general_query: GeneralQueryConfig,
}

impl RelayConfig {
    pub fn for_bind(bind: SocketAddr) -> Self {
        let mut config = Self::default();
        config.bind = bind;
        match bind.ip() {
            IpAddr::V4(addr) if !addr.is_unspecified() => config.advertise_ipv4 = addr,
            IpAddr::V6(addr) if !addr.is_unspecified() => config.advertise_ipv6 = addr,
            _ => {}
        }
        config
    }

    pub fn with_advertise_addr(mut self, addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => self.advertise_ipv4 = addr,
            IpAddr::V6(addr) => self.advertise_ipv6 = addr,
        }
        self
    }

    fn advertised_addr_for(&self, peer: SocketAddr) -> IpAddr {
        match peer {
            SocketAddr::V4(_) => self.advertise_ipv4.into(),
            SocketAddr::V6(_) => self.advertise_ipv6.into(),
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], crate::protocol::AMT_PORT)),
            advertise_ipv4: Ipv4Addr::LOCALHOST,
            advertise_ipv6: Ipv6Addr::LOCALHOST,
            secret: RelaySecret::default(),
            include_gateway_address: true,
            limit: false,
            general_query: GeneralQueryConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    config: RelayConfig,
    state: RelayState,
}

impl Relay {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            state: RelayState::default(),
        }
    }

    pub const fn config(&self) -> &RelayConfig {
        &self.config
    }

    pub const fn state(&self) -> &RelayState {
        &self.state
    }

    pub fn handle_datagram(
        &mut self,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Result<RelayAction, RelayError> {
        let message = Message::decode(datagram)?;
        match message {
            Message::RelayDiscovery { discovery_nonce } => {
                let response = Message::RelayAdvertisement {
                    discovery_nonce,
                    relay_address: self.config.advertised_addr_for(peer),
                };
                Ok(RelayAction::Send(encode(&response)))
            }
            Message::Request {
                request_nonce,
                protocol,
            } => {
                let response_mac = self.response_mac(peer.ip(), peer.port(), request_nonce);
                let general_query = build_general_query(protocol, &self.config.general_query);
                let gateway = self.config.include_gateway_address.then(|| {
                    GatewayEndpoint::new(peer.port(), GatewayAddress::from_ip_addr(peer.ip()))
                });
                let response = Message::MembershipQuery {
                    response_mac,
                    request_nonce,
                    limit: self.config.limit,
                    gateway,
                    general_query: &general_query,
                };
                Ok(RelayAction::Send(encode(&response)))
            }
            Message::MembershipUpdate {
                response_mac,
                request_nonce,
                membership_update,
            } => {
                let expected = self.response_mac(peer.ip(), peer.port(), request_nonce);
                if response_mac == expected {
                    let report = parse_membership_report(membership_update)?;
                    let records_applied = self.state.apply_report(peer, &report);
                    let upstream_subscriptions = self.state.upstream_subscriptions();
                    Ok(RelayAction::AcceptedMembershipUpdate {
                        protocol: report.protocol,
                        bytes: membership_update.len(),
                        records_applied,
                        upstream_subscriptions,
                    })
                } else {
                    Ok(RelayAction::RejectedAuth)
                }
            }
            Message::Teardown {
                response_mac,
                request_nonce,
                gateway,
            } => {
                let gateway_ip = gateway
                    .address
                    .as_ipv4_compatible()
                    .map(IpAddr::V4)
                    .unwrap_or_else(|| IpAddr::V6(gateway.address.as_ipv6()));
                let expected = self.response_mac(gateway_ip, gateway.port, request_nonce);
                if response_mac == expected {
                    let endpoint = SocketAddr::new(gateway_ip, gateway.port);
                    let removed = self.state.remove_endpoint(endpoint);
                    Ok(RelayAction::AcceptedTeardown { gateway, removed })
                } else {
                    Ok(RelayAction::RejectedAuth)
                }
            }
            Message::RelayAdvertisement { .. }
            | Message::MembershipQuery { .. }
            | Message::MulticastData { .. } => Ok(RelayAction::Ignored),
        }
    }

    pub fn response_mac(
        &self,
        gateway_ip: IpAddr,
        gateway_port: u16,
        request_nonce: u32,
    ) -> ResponseMac {
        let mut mac = HmacSha256::new_from_slice(self.config.secret.expose_bytes())
            .expect("HMAC accepts any key size");
        mac.update(&GatewayAddress::from_ip_addr(gateway_ip).octets());
        mac.update(&gateway_port.to_be_bytes());
        mac.update(&request_nonce.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        ResponseMac::new([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAction {
    Send(Vec<u8>),
    AcceptedMembershipUpdate {
        protocol: MembershipProtocol,
        bytes: usize,
        records_applied: usize,
        upstream_subscriptions: Vec<UpstreamSubscription>,
    },
    AcceptedTeardown {
        gateway: GatewayEndpoint,
        removed: bool,
    },
    RejectedAuth,
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    Decode(DecodeError),
    Membership(MembershipParseError),
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "{error}"),
            Self::Membership(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<DecodeError> for RelayError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<MembershipParseError> for RelayError {
    fn from(value: MembershipParseError) -> Self {
        Self::Membership(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Message, decode};

    fn relay() -> Relay {
        Relay::new(RelayConfig {
            secret: RelaySecret::new([7; 32]),
            ..RelayConfig::for_bind(SocketAddr::from(([192, 0, 2, 10], 2268)))
        })
    }

    #[test]
    fn discovery_gets_advertisement_with_same_nonce() {
        let mut relay = relay();
        let discovery = encode(&Message::RelayDiscovery {
            discovery_nonce: 0x1122_3344,
        });

        let action = relay
            .handle_datagram(SocketAddr::from(([198, 51, 100, 8], 40_000)), &discovery)
            .unwrap();

        let RelayAction::Send(response) = action else {
            panic!("expected response");
        };
        assert_eq!(
            decode(&response),
            Ok(Message::RelayAdvertisement {
                discovery_nonce: 0x1122_3344,
                relay_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            })
        );
    }

    #[test]
    fn request_gets_membership_query_with_gateway_fields() {
        let mut relay = relay();
        let peer = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let request = encode(&Message::Request {
            request_nonce: 0x0102_0304,
            protocol: MembershipProtocol::Igmpv3,
        });

        let action = relay.handle_datagram(peer, &request).unwrap();

        let RelayAction::Send(response) = action else {
            panic!("expected response");
        };
        let message = decode(&response).unwrap();
        let Message::MembershipQuery {
            response_mac,
            request_nonce,
            limit,
            gateway,
            general_query,
        } = message
        else {
            panic!("expected membership query");
        };

        assert_eq!(request_nonce, 0x0102_0304);
        assert_eq!(
            response_mac,
            relay.response_mac(peer.ip(), peer.port(), request_nonce)
        );
        assert!(!limit);
        assert_eq!(
            gateway,
            Some(GatewayEndpoint::new(40_000, Ipv4Addr::new(198, 51, 100, 8)))
        );
        assert_eq!(general_query[0] >> 4, 4);
        assert_eq!(general_query[24], 0x11);
    }

    #[test]
    fn request_p_flag_selects_mldv2_query() {
        let mut relay = relay();
        let request = encode(&Message::Request {
            request_nonce: 99,
            protocol: MembershipProtocol::Mldv2,
        });

        let action = relay
            .handle_datagram(SocketAddr::from(([198, 51, 100, 8], 40_000)), &request)
            .unwrap();

        let RelayAction::Send(response) = action else {
            panic!("expected response");
        };
        let Message::MembershipQuery { general_query, .. } = decode(&response).unwrap() else {
            panic!("expected membership query");
        };
        assert_eq!(general_query[0] >> 4, 6);
        assert_eq!(general_query[48], 130);
    }

    #[test]
    fn membership_update_authenticates_response_mac() {
        let mut relay = relay();
        let peer = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let nonce = 0xaabb_ccdd;
        let response_mac = relay.response_mac(peer.ip(), peer.port(), nonce);
        let group = Ipv4Addr::new(232, 1, 2, 3);
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let packet = igmpv3_join_packet(group, source);
        let update = encode(&Message::MembershipUpdate {
            response_mac,
            request_nonce: nonce,
            membership_update: &packet,
        });

        assert_eq!(
            relay.handle_datagram(peer, &update).unwrap(),
            RelayAction::AcceptedMembershipUpdate {
                protocol: MembershipProtocol::Igmpv3,
                bytes: packet.len(),
                records_applied: 1,
                upstream_subscriptions: vec![UpstreamSubscription::ssm(
                    group.into(),
                    source.into()
                )],
            }
        );
        assert_eq!(
            relay
                .state()
                .endpoints_for_packet(source.into(), group.into()),
            vec![peer]
        );
    }

    #[test]
    fn bad_membership_update_mac_is_rejected() {
        let mut relay = relay();
        let packet = igmpv3_join_packet(Ipv4Addr::new(232, 1, 2, 3), Ipv4Addr::new(192, 0, 2, 1));
        let update = encode(&Message::MembershipUpdate {
            response_mac: ResponseMac::ZERO,
            request_nonce: 1,
            membership_update: &packet,
        });

        assert_eq!(
            relay
                .handle_datagram(SocketAddr::from(([198, 51, 100, 8], 40_000)), &update)
                .unwrap(),
            RelayAction::RejectedAuth
        );
    }

    #[test]
    fn teardown_removes_endpoint_state() {
        let mut relay = relay();
        let peer = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let nonce = 0xaabb_ccdd;
        let response_mac = relay.response_mac(peer.ip(), peer.port(), nonce);
        let group = Ipv4Addr::new(232, 1, 2, 3);
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let packet = igmpv3_join_packet(group, source);
        let update = encode(&Message::MembershipUpdate {
            response_mac,
            request_nonce: nonce,
            membership_update: &packet,
        });
        relay.handle_datagram(peer, &update).unwrap();
        assert!(!relay.state().upstream_subscriptions().is_empty());

        let teardown = encode(&Message::Teardown {
            response_mac,
            request_nonce: nonce,
            gateway: GatewayEndpoint::new(peer.port(), peer.ip()),
        });

        assert_eq!(
            relay.handle_datagram(peer, &teardown).unwrap(),
            RelayAction::AcceptedTeardown {
                gateway: GatewayEndpoint::new(peer.port(), peer.ip()),
                removed: true,
            }
        );
        assert!(relay.state().upstream_subscriptions().is_empty());
    }

    fn igmpv3_join_packet(group: Ipv4Addr, source: Ipv4Addr) -> Vec<u8> {
        let mut payload = vec![0; 20];
        payload[0] = 0x22;
        payload[6..8].copy_from_slice(&1u16.to_be_bytes());
        payload[8] = 1;
        payload[10..12].copy_from_slice(&1u16.to_be_bytes());
        payload[12..16].copy_from_slice(&group.octets());
        payload[16..20].copy_from_slice(&source.octets());
        let igmp_checksum = crate::membership::checksum(&payload);
        payload[2..4].copy_from_slice(&igmp_checksum.to_be_bytes());

        let total_len = 20 + payload.len();
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 1;
        packet[9] = 2;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 1).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(224, 0, 0, 22).octets());
        let ip_checksum = crate::membership::checksum(&packet);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet.extend_from_slice(&payload);
        packet
    }
}
