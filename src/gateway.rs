use crate::membership::{
    MembershipBuildError, MembershipRecord, MembershipRecordKind, MembershipReport,
    build_membership_report,
};
use crate::protocol::{
    DecodeError, GatewayEndpoint, MembershipProtocol, Message, ResponseMac, encode,
};
use getrandom::fill as fill_random;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub relay: SocketAddr,
    pub protocol: MembershipProtocol,
    pub discovery_nonce: u32,
    pub request_nonce: u32,
}

impl GatewayConfig {
    pub fn new(relay: SocketAddr, protocol: MembershipProtocol) -> Self {
        Self {
            relay,
            protocol,
            discovery_nonce: random_nonce(),
            request_nonce: random_nonce(),
        }
    }

    pub const fn with_nonces(mut self, discovery_nonce: u32, request_nonce: u32) -> Self {
        self.discovery_nonce = discovery_nonce;
        self.request_nonce = request_nonce;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    config: GatewayConfig,
    relay_endpoint: Option<SocketAddr>,
    response_mac: Option<ResponseMac>,
    gateway_endpoint: Option<GatewayEndpoint>,
}

impl Gateway {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            relay_endpoint: None,
            response_mac: None,
            gateway_endpoint: None,
        }
    }

    pub const fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub const fn relay_endpoint(&self) -> Option<SocketAddr> {
        self.relay_endpoint
    }

    pub const fn response_mac(&self) -> Option<ResponseMac> {
        self.response_mac
    }

    pub fn discovery(&self) -> GatewayAction {
        GatewayAction::Send {
            destination: self.config.relay,
            datagram: encode(&Message::RelayDiscovery {
                discovery_nonce: self.config.discovery_nonce,
            }),
        }
    }

    pub fn handle_datagram(
        &mut self,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Result<GatewayAction, GatewayError> {
        let message = Message::decode(datagram)?;
        match message {
            Message::RelayAdvertisement {
                discovery_nonce,
                relay_address,
            } => {
                if discovery_nonce != self.config.discovery_nonce {
                    return Err(GatewayError::UnexpectedDiscoveryNonce {
                        expected: self.config.discovery_nonce,
                        actual: discovery_nonce,
                    });
                }

                let relay_endpoint = SocketAddr::new(relay_address, peer.port());
                self.relay_endpoint = Some(relay_endpoint);
                Ok(GatewayAction::Send {
                    destination: relay_endpoint,
                    datagram: encode(&Message::Request {
                        request_nonce: self.config.request_nonce,
                        protocol: self.config.protocol,
                    }),
                })
            }
            Message::MembershipQuery {
                response_mac,
                request_nonce,
                limit,
                gateway,
                general_query,
            } => {
                if request_nonce != self.config.request_nonce {
                    return Err(GatewayError::UnexpectedRequestNonce {
                        expected: self.config.request_nonce,
                        actual: request_nonce,
                    });
                }

                self.response_mac = Some(response_mac);
                self.gateway_endpoint = gateway;
                Ok(GatewayAction::MembershipQuery {
                    response_mac,
                    limit,
                    gateway,
                    general_query: general_query.to_vec(),
                })
            }
            Message::MulticastData { packet } => Ok(GatewayAction::MulticastData {
                packet: packet.to_vec(),
            }),
            Message::RelayDiscovery { .. }
            | Message::Request { .. }
            | Message::MembershipUpdate { .. }
            | Message::Teardown { .. } => Ok(GatewayAction::Ignored),
        }
    }

    pub fn membership_update(
        &self,
        report: MembershipReport,
    ) -> Result<GatewayAction, GatewayError> {
        let relay = self
            .relay_endpoint
            .ok_or(GatewayError::MissingRelayEndpoint)?;
        let response_mac = self
            .response_mac
            .ok_or(GatewayError::MissingMembershipQuery)?;
        let membership_update = build_membership_report(&report)?;
        Ok(GatewayAction::Send {
            destination: relay,
            datagram: encode(&Message::MembershipUpdate {
                response_mac,
                request_nonce: self.config.request_nonce,
                membership_update: &membership_update,
            }),
        })
    }

    pub fn join_group(
        &self,
        group: IpAddr,
        source: Option<IpAddr>,
    ) -> Result<GatewayAction, GatewayError> {
        let record = match source {
            Some(source) => MembershipRecord {
                kind: MembershipRecordKind::ModeIsInclude,
                group,
                sources: vec![source],
            },
            None => MembershipRecord {
                kind: MembershipRecordKind::ModeIsExclude,
                group,
                sources: Vec::new(),
            },
        };

        self.membership_update(MembershipReport {
            protocol: self.config.protocol,
            records: vec![record],
        })
    }

    pub fn teardown(&self) -> Result<GatewayAction, GatewayError> {
        let relay = self
            .relay_endpoint
            .ok_or(GatewayError::MissingRelayEndpoint)?;
        let response_mac = self
            .response_mac
            .ok_or(GatewayError::MissingMembershipQuery)?;
        let gateway = self
            .gateway_endpoint
            .ok_or(GatewayError::MissingGatewayEndpoint)?;

        Ok(GatewayAction::Send {
            destination: relay,
            datagram: encode(&Message::Teardown {
                response_mac,
                request_nonce: self.config.request_nonce,
                gateway,
            }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayAction {
    Send {
        destination: SocketAddr,
        datagram: Vec<u8>,
    },
    MembershipQuery {
        response_mac: ResponseMac,
        limit: bool,
        gateway: Option<GatewayEndpoint>,
        general_query: Vec<u8>,
    },
    MulticastData {
        packet: Vec<u8>,
    },
    Ignored,
}

impl GatewayAction {
    pub fn into_send(self) -> Option<(SocketAddr, Vec<u8>)> {
        match self {
            Self::Send {
                destination,
                datagram,
            } => Some((destination, datagram)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    Decode(DecodeError),
    MembershipBuild(MembershipBuildError),
    UnexpectedDiscoveryNonce { expected: u32, actual: u32 },
    UnexpectedRequestNonce { expected: u32, actual: u32 },
    MissingRelayEndpoint,
    MissingMembershipQuery,
    MissingGatewayEndpoint,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "{error}"),
            Self::MembershipBuild(error) => write!(f, "{error}"),
            Self::UnexpectedDiscoveryNonce { expected, actual } => write!(
                f,
                "unexpected Relay Advertisement nonce {actual:#x}; expected {expected:#x}"
            ),
            Self::UnexpectedRequestNonce { expected, actual } => write!(
                f,
                "unexpected Membership Query nonce {actual:#x}; expected {expected:#x}"
            ),
            Self::MissingRelayEndpoint => write!(f, "gateway has not discovered a relay yet"),
            Self::MissingMembershipQuery => {
                write!(f, "gateway has not received a Membership Query yet")
            }
            Self::MissingGatewayEndpoint => {
                write!(f, "relay did not provide gateway endpoint fields")
            }
        }
    }
}

impl std::error::Error for GatewayError {}

impl From<DecodeError> for GatewayError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<MembershipBuildError> for GatewayError {
    fn from(value: MembershipBuildError) -> Self {
        Self::MembershipBuild(value)
    }
}

fn random_nonce() -> u32 {
    let mut bytes = [0; 4];
    if fill_random(&mut bytes).is_ok() {
        return u32::from_be_bytes(bytes);
    }

    let fallback = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        ^ std::process::id();
    fallback.rotate_left(13)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::decode;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn discovery_builds_relay_discovery() {
        let relay = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2268));
        let gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );

        let GatewayAction::Send {
            destination,
            datagram,
        } = gateway.discovery()
        else {
            panic!("expected send action");
        };

        assert_eq!(destination, relay);
        assert_eq!(
            decode(&datagram),
            Ok(Message::RelayDiscovery {
                discovery_nonce: 0x0102_0304
            })
        );
    }

    #[test]
    fn advertisement_triggers_request_to_advertised_address() {
        let discovery_relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(discovery_relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        let advertisement = encode(&Message::RelayAdvertisement {
            discovery_nonce: 0x0102_0304,
            relay_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
        });

        let action = gateway
            .handle_datagram(discovery_relay, &advertisement)
            .unwrap();

        let GatewayAction::Send {
            destination,
            datagram,
        } = action
        else {
            panic!("expected request send action");
        };
        assert_eq!(destination, SocketAddr::from(([192, 0, 2, 20], 2268)));
        assert_eq!(
            decode(&datagram),
            Ok(Message::Request {
                request_nonce: 0x0506_0708,
                protocol: MembershipProtocol::Igmpv3
            })
        );
    }

    #[test]
    fn unexpected_advertisement_nonce_does_not_update_relay_endpoint() {
        let discovery_relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(discovery_relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        let advertisement = encode(&Message::RelayAdvertisement {
            discovery_nonce: 0xffff_ffff,
            relay_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
        });

        assert_eq!(
            gateway.handle_datagram(discovery_relay, &advertisement),
            Err(GatewayError::UnexpectedDiscoveryNonce {
                expected: 0x0102_0304,
                actual: 0xffff_ffff
            })
        );
        assert_eq!(gateway.relay_endpoint(), None);
    }

    #[test]
    fn unexpected_query_nonce_does_not_replace_cached_query_state() {
        let relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        let existing_mac = ResponseMac::new([1, 2, 3, 4, 5, 6]);
        let existing_gateway = GatewayEndpoint::new(40_000, Ipv4Addr::new(198, 51, 100, 8));
        gateway.relay_endpoint = Some(relay);
        gateway.response_mac = Some(existing_mac);
        gateway.gateway_endpoint = Some(existing_gateway);
        let query = encode(&Message::MembershipQuery {
            response_mac: ResponseMac::new([6, 5, 4, 3, 2, 1]),
            request_nonce: 0xffff_ffff,
            limit: true,
            gateway: None,
            general_query: &[0x45, 0, 0, 20],
        });

        assert_eq!(
            gateway.handle_datagram(relay, &query),
            Err(GatewayError::UnexpectedRequestNonce {
                expected: 0x0506_0708,
                actual: 0xffff_ffff
            })
        );
        assert_eq!(gateway.response_mac(), Some(existing_mac));
        assert_eq!(gateway.gateway_endpoint, Some(existing_gateway));
    }

    #[test]
    fn join_group_builds_membership_update_after_query() {
        let relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        gateway.relay_endpoint = Some(relay);
        let response_mac = ResponseMac::new([1, 2, 3, 4, 5, 6]);
        let query = encode(&Message::MembershipQuery {
            response_mac,
            request_nonce: 0x0506_0708,
            limit: false,
            gateway: None,
            general_query: &[0x45, 0, 0, 20],
        });
        gateway.handle_datagram(relay, &query).unwrap();

        let action = gateway
            .join_group(
                IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            )
            .unwrap();
        let (_, update) = action.into_send().unwrap();
        let Message::MembershipUpdate {
            response_mac: actual_mac,
            request_nonce,
            membership_update,
        } = decode(&update).unwrap()
        else {
            panic!("expected membership update");
        };

        assert_eq!(actual_mac, response_mac);
        assert_eq!(request_nonce, 0x0506_0708);
        assert!(membership_update.starts_with(&[0x46]));
    }

    #[test]
    fn teardown_requires_gateway_endpoint_from_membership_query() {
        let relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        gateway.relay_endpoint = Some(relay);
        let query = encode(&Message::MembershipQuery {
            response_mac: ResponseMac::new([1, 2, 3, 4, 5, 6]),
            request_nonce: 0x0506_0708,
            limit: false,
            gateway: None,
            general_query: &[0x45, 0, 0, 20],
        });
        gateway.handle_datagram(relay, &query).unwrap();

        assert_eq!(
            gateway.teardown(),
            Err(GatewayError::MissingGatewayEndpoint)
        );
    }
}
