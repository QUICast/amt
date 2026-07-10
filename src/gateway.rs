use crate::ecn::{EcnCodepoint, EcnDecapsulation, EcnError, decapsulate_ecn};
use crate::ip::{IpPacketError, parse_multicast_packet};
use crate::membership::{
    MembershipBuildError, MembershipRecord, MembershipRecordKind, MembershipReport,
    build_membership_report,
};
use crate::protocol::{
    DecodeError, GatewayEndpoint, MembershipProtocol, Message, ResponseMac, encode,
};
use crate::query::{QueryValidationError, general_query_interval};
use crate::state::RelayState;
use getrandom::fill as fill_random;
use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const RECEPTION_STATE_ENDPOINT: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    pub relay: SocketAddr,
    pub fallback_relays: Vec<SocketAddr>,
    pub protocol: MembershipProtocol,
    pub ecn: bool,
    pub discovery_nonce: u32,
    pub request_nonce: u32,
}

impl GatewayConfig {
    pub fn new(relay: SocketAddr, protocol: MembershipProtocol) -> Self {
        Self {
            relay,
            fallback_relays: Vec::new(),
            protocol,
            ecn: false,
            discovery_nonce: random_nonce(),
            request_nonce: random_nonce(),
        }
    }

    pub const fn with_nonces(mut self, discovery_nonce: u32, request_nonce: u32) -> Self {
        self.discovery_nonce = discovery_nonce;
        self.request_nonce = request_nonce;
        self
    }

    pub const fn with_ecn(mut self, enabled: bool) -> Self {
        self.ecn = enabled;
        self
    }

    pub fn with_fallback_relays(mut self, relays: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.fallback_relays.clear();
        for relay in relays {
            if relay != self.relay
                && same_family(relay.ip(), self.relay.ip())
                && !self.fallback_relays.contains(&relay)
            {
                self.fallback_relays.push(relay);
            }
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    config: GatewayConfig,
    relay_candidates: Vec<SocketAddr>,
    phase: GatewayPhase,
    relay_endpoint: Option<SocketAddr>,
    session: Option<GatewaySession>,
    reception_state: RelayState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayPhase {
    Discovering,
    AwaitingMembershipQuery,
    Established,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GatewaySession {
    response_mac: ResponseMac,
    request_nonce: u32,
    gateway_endpoint: Option<GatewayEndpoint>,
    reported_memberships: bool,
}

impl Gateway {
    pub fn new(config: GatewayConfig) -> Self {
        let mut relay_candidates = Vec::with_capacity(1 + config.fallback_relays.len());
        relay_candidates.push(config.relay);
        relay_candidates.extend(config.fallback_relays.iter().copied());
        Self {
            config: GatewayConfig {
                discovery_nonce: nonzero_or_random(config.discovery_nonce),
                request_nonce: nonzero_or_random(config.request_nonce),
                ..config
            },
            relay_candidates,
            phase: GatewayPhase::Discovering,
            relay_endpoint: None,
            session: None,
            reception_state: RelayState::default(),
        }
    }

    pub const fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub const fn relay_endpoint(&self) -> Option<SocketAddr> {
        self.relay_endpoint
    }

    pub const fn phase(&self) -> GatewayPhase {
        self.phase
    }

    pub const fn is_established(&self) -> bool {
        matches!(self.phase, GatewayPhase::Established) && self.session.is_some()
    }

    pub const fn is_awaiting_query(&self) -> bool {
        matches!(self.phase, GatewayPhase::AwaitingMembershipQuery)
    }

    pub fn response_mac(&self) -> Option<ResponseMac> {
        self.session.map(|session| session.response_mac)
    }

    pub fn has_reported_memberships(&self) -> bool {
        self.session
            .is_some_and(|session| session.reported_memberships)
    }

    pub fn discovery(&self) -> GatewayAction {
        GatewayAction::Send {
            destination: self.config.relay,
            datagram: encode(&Message::RelayDiscovery {
                discovery_nonce: self.config.discovery_nonce,
            }),
        }
    }

    pub fn request(&self) -> Result<GatewayAction, GatewayError> {
        let relay = self
            .relay_endpoint
            .ok_or(GatewayError::MissingRelayEndpoint)?;
        Ok(GatewayAction::Send {
            destination: relay,
            datagram: encode(&Message::Request {
                request_nonce: self.config.request_nonce,
                protocol: self.config.protocol,
                ecn_capable: self.config.ecn,
            }),
        })
    }

    pub fn begin_query_cycle(&mut self) -> Result<GatewayAction, GatewayError> {
        if self.relay_endpoint.is_none() {
            return Err(GatewayError::MissingRelayEndpoint);
        }
        self.config.request_nonce = random_nonce();
        self.phase = GatewayPhase::AwaitingMembershipQuery;
        self.request()
    }

    pub fn restart_discovery(&mut self) -> GatewayAction {
        if !self.config.fallback_relays.is_empty() {
            let next = self.config.fallback_relays.remove(0);
            let previous = std::mem::replace(&mut self.config.relay, next);
            if self.relay_candidates.contains(&previous) {
                self.config.fallback_relays.push(previous);
            }
        }
        self.config.discovery_nonce = random_nonce();
        self.config.request_nonce = random_nonce();
        self.phase = GatewayPhase::Discovering;
        self.relay_endpoint = None;
        self.session = None;
        self.discovery()
    }

    /// Replaces the failover set while leaving a healthy active relay in place.
    ///
    /// If the current relay is no longer present, it is retired on the next
    /// discovery restart rather than disrupting an established traffic flow.
    pub fn replace_relay_candidates(
        &mut self,
        relays: impl IntoIterator<Item = SocketAddr>,
    ) -> bool {
        let mut candidates = Vec::new();
        for relay in relays {
            if same_family(relay.ip(), self.config.relay.ip()) && !candidates.contains(&relay) {
                candidates.push(relay);
            }
        }
        if candidates.is_empty() || candidates == self.relay_candidates {
            return false;
        }

        self.relay_candidates = candidates;
        self.config.fallback_relays = self
            .relay_candidates
            .iter()
            .copied()
            .filter(|candidate| *candidate != self.config.relay)
            .collect();
        true
    }

    pub fn current_relay_is_retired(&self) -> bool {
        !self.relay_candidates.contains(&self.config.relay)
    }

    pub fn handle_datagram(
        &mut self,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Result<GatewayAction, GatewayError> {
        self.handle_datagram_with_ecn(peer, datagram, EcnCodepoint::NotEct)
    }

    /// Handles one AMT datagram together with the ECN field from its outer IP header.
    pub fn handle_datagram_with_ecn(
        &mut self,
        peer: SocketAddr,
        datagram: &[u8],
        outer_ecn: EcnCodepoint,
    ) -> Result<GatewayAction, GatewayError> {
        let expected_peer = self.relay_endpoint.unwrap_or(self.config.relay);
        if peer != expected_peer {
            return Err(GatewayError::UnexpectedPeer {
                expected: expected_peer,
                actual: peer,
            });
        }
        let message = Message::decode(datagram)?;
        match message {
            Message::RelayAdvertisement {
                discovery_nonce,
                relay_address,
            } => {
                if self.phase != GatewayPhase::Discovering {
                    return Err(GatewayError::UnexpectedMessageForState {
                        message: "Relay Advertisement",
                        phase: self.phase,
                    });
                }
                if discovery_nonce != self.config.discovery_nonce {
                    return Err(GatewayError::UnexpectedDiscoveryNonce {
                        expected: self.config.discovery_nonce,
                        actual: discovery_nonce,
                    });
                }
                if !is_usable_unicast(relay_address) || !same_family(relay_address, peer.ip()) {
                    return Err(GatewayError::InvalidRelayAddress(relay_address));
                }

                let relay_endpoint = SocketAddr::new(relay_address, peer.port());
                self.relay_endpoint = Some(relay_endpoint);
                self.phase = GatewayPhase::AwaitingMembershipQuery;
                Ok(GatewayAction::Send {
                    destination: relay_endpoint,
                    datagram: encode(&Message::Request {
                        request_nonce: self.config.request_nonce,
                        protocol: self.config.protocol,
                        ecn_capable: self.config.ecn,
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
                let relay = self
                    .relay_endpoint
                    .ok_or(GatewayError::MissingRelayEndpoint)?;
                let expected_nonce = match (self.phase, self.session) {
                    (GatewayPhase::AwaitingMembershipQuery, _) => self.config.request_nonce,
                    (GatewayPhase::Established, Some(session)) => session.request_nonce,
                    _ => {
                        return Err(GatewayError::UnexpectedMessageForState {
                            message: "Membership Query",
                            phase: self.phase,
                        });
                    }
                };
                if request_nonce != expected_nonce {
                    return Err(GatewayError::UnexpectedRequestNonce {
                        expected: expected_nonce,
                        actual: request_nonce,
                    });
                }
                let query_interval = general_query_interval(self.config.protocol, general_query)?;

                let previous_session = self.session;
                let previous_teardown = previous_session
                    .filter(|session| session.gateway_endpoint != gateway)
                    .and_then(|session| {
                        session.gateway_endpoint.map(|old_gateway| GatewaySend {
                            destination: relay,
                            datagram: encode(&Message::Teardown {
                                response_mac: session.response_mac,
                                request_nonce: session.request_nonce,
                                gateway: old_gateway,
                            }),
                        })
                    });
                self.session = Some(GatewaySession {
                    response_mac,
                    request_nonce,
                    gateway_endpoint: gateway,
                    reported_memberships: previous_session.is_some_and(|session| {
                        session.gateway_endpoint == gateway && session.reported_memberships
                    }),
                });
                self.phase = GatewayPhase::Established;
                Ok(GatewayAction::MembershipQuery {
                    response_mac,
                    limit,
                    gateway,
                    general_query: general_query.to_vec(),
                    query_interval,
                    previous_teardown,
                })
            }
            Message::MulticastData { packet } => {
                if self.relay_endpoint.is_none() {
                    return Err(GatewayError::MissingRelayEndpoint);
                }
                if self.session.is_none() {
                    return Err(GatewayError::UnexpectedMessageForState {
                        message: "Multicast Data",
                        phase: self.phase,
                    });
                }
                let parsed = parse_multicast_packet(packet)?;
                let interested = self
                    .reception_state
                    .endpoint_interest(RECEPTION_STATE_ENDPOINT, parsed.group)
                    .is_some_and(|interest| interest.wants_source(parsed.source));
                if !interested {
                    return Ok(GatewayAction::Ignored);
                }
                let mut packet = packet.to_vec();
                if self.config.ecn {
                    let ecn = decapsulate_ecn(&mut packet, outer_ecn)?;
                    if ecn.is_drop() {
                        return Ok(GatewayAction::DroppedEcn {
                            ecn,
                            packet_len: packet.len(),
                        });
                    }
                    Ok(GatewayAction::MulticastData {
                        packet,
                        ecn: Some(ecn),
                    })
                } else {
                    Ok(GatewayAction::MulticastData { packet, ecn: None })
                }
            }
            Message::RelayDiscovery { .. }
            | Message::Request { .. }
            | Message::MembershipUpdate { .. }
            | Message::Teardown { .. } => Ok(GatewayAction::Ignored),
        }
    }

    pub fn membership_update(
        &mut self,
        report: MembershipReport,
    ) -> Result<GatewayAction, GatewayError> {
        let relay = self
            .relay_endpoint
            .ok_or(GatewayError::MissingRelayEndpoint)?;
        let session = self.session.ok_or(GatewayError::MissingMembershipQuery)?;
        let membership_update = build_membership_report(&report)?;
        self.reception_state
            .apply_report(RECEPTION_STATE_ENDPOINT, &report);
        if let Some(session) = self.session.as_mut() {
            session.reported_memberships = self
                .reception_state
                .endpoint_has_interests(RECEPTION_STATE_ENDPOINT);
        }
        Ok(GatewayAction::Send {
            destination: relay,
            datagram: encode(&Message::MembershipUpdate {
                response_mac: session.response_mac,
                request_nonce: session.request_nonce,
                membership_update: &membership_update,
            }),
        })
    }

    pub fn replace_memberships(
        &mut self,
        mut report: MembershipReport,
    ) -> Result<Option<GatewayAction>, GatewayError> {
        let current = report
            .records
            .iter()
            .map(|record| record.group)
            .collect::<BTreeSet<_>>();
        for (group, _) in self.reception_state.aggregate_interests_iter() {
            if !current.contains(&group) {
                report.records.push(MembershipRecord {
                    kind: MembershipRecordKind::ChangeToInclude,
                    group,
                    sources: Vec::new(),
                });
            }
        }
        if report.records.is_empty() {
            return Ok(None);
        }
        self.membership_update(report).map(Some)
    }

    pub fn join_group(
        &mut self,
        group: IpAddr,
        source: Option<IpAddr>,
    ) -> Result<GatewayAction, GatewayError> {
        let record = match source {
            Some(source) => MembershipRecord {
                kind: MembershipRecordKind::AllowNewSources,
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
        let session = self.session.ok_or(GatewayError::MissingMembershipQuery)?;
        let gateway = session
            .gateway_endpoint
            .ok_or(GatewayError::MissingGatewayEndpoint)?;

        Ok(GatewayAction::Send {
            destination: relay,
            datagram: encode(&Message::Teardown {
                response_mac: session.response_mac,
                request_nonce: session.request_nonce,
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
        query_interval: Duration,
        previous_teardown: Option<GatewaySend>,
    },
    MulticastData {
        packet: Vec<u8>,
        ecn: Option<EcnDecapsulation>,
    },
    DroppedEcn {
        ecn: EcnDecapsulation,
        packet_len: usize,
    },
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySend {
    pub destination: SocketAddr,
    pub datagram: Vec<u8>,
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
    InvalidGeneralQuery(QueryValidationError),
    InvalidMulticastPacket(IpPacketError),
    InvalidEcn(EcnError),
    UnexpectedDiscoveryNonce {
        expected: u32,
        actual: u32,
    },
    UnexpectedRequestNonce {
        expected: u32,
        actual: u32,
    },
    UnexpectedPeer {
        expected: SocketAddr,
        actual: SocketAddr,
    },
    UnexpectedMessageForState {
        message: &'static str,
        phase: GatewayPhase,
    },
    InvalidRelayAddress(IpAddr),
    MissingRelayEndpoint,
    MissingMembershipQuery,
    MissingGatewayEndpoint,
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "{error}"),
            Self::MembershipBuild(error) => write!(f, "{error}"),
            Self::InvalidGeneralQuery(error) => write!(f, "invalid Membership Query: {error}"),
            Self::InvalidMulticastPacket(error) => write!(f, "invalid Multicast Data: {error}"),
            Self::InvalidEcn(error) => write!(f, "invalid Multicast Data ECN: {error}"),
            Self::UnexpectedDiscoveryNonce { expected, actual } => write!(
                f,
                "unexpected Relay Advertisement nonce {actual:#x}; expected {expected:#x}"
            ),
            Self::UnexpectedRequestNonce { expected, actual } => write!(
                f,
                "unexpected Membership Query nonce {actual:#x}; expected {expected:#x}"
            ),
            Self::UnexpectedPeer { expected, actual } => {
                write!(f, "AMT datagram came from {actual}; expected {expected}")
            }
            Self::UnexpectedMessageForState { message, phase } => {
                write!(f, "unexpected {message} while gateway is {phase:?}")
            }
            Self::InvalidRelayAddress(address) => {
                write!(
                    f,
                    "Relay Advertisement contains invalid relay address {address}"
                )
            }
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

impl From<QueryValidationError> for GatewayError {
    fn from(value: QueryValidationError) -> Self {
        Self::InvalidGeneralQuery(value)
    }
}

impl From<IpPacketError> for GatewayError {
    fn from(value: IpPacketError) -> Self {
        Self::InvalidMulticastPacket(value)
    }
}

impl From<EcnError> for GatewayError {
    fn from(value: EcnError) -> Self {
        Self::InvalidEcn(value)
    }
}

fn random_nonce() -> u32 {
    loop {
        let mut bytes = [0; 4];
        fill_random(&mut bytes).expect("operating-system randomness is required for AMT nonces");
        let nonce = u32::from_be_bytes(bytes);
        if nonce != 0 {
            return nonce;
        }
    }
}

fn nonzero_or_random(nonce: u32) -> u32 {
    if nonce != 0 { nonce } else { random_nonce() }
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn is_usable_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
        }
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::decode;
    use crate::query::{GeneralQueryConfig, build_general_query};
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn await_query(gateway: &mut Gateway, relay: SocketAddr) {
        gateway.relay_endpoint = Some(relay);
        gateway.phase = GatewayPhase::AwaitingMembershipQuery;
    }

    fn membership_query(
        response_mac: ResponseMac,
        request_nonce: u32,
        gateway: Option<GatewayEndpoint>,
    ) -> Vec<u8> {
        let general_query =
            build_general_query(MembershipProtocol::Igmpv3, &GeneralQueryConfig::default());
        encode(&Message::MembershipQuery {
            response_mac,
            request_nonce,
            limit: false,
            gateway,
            general_query: &general_query,
        })
    }

    fn multicast_packet(source: Ipv4Addr, group: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 16;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&group.octets());
        let checksum = crate::checksum::checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn multicast_packet_with_ecn(source: Ipv4Addr, group: Ipv4Addr, ecn: EcnCodepoint) -> Vec<u8> {
        let mut packet = multicast_packet(source, group);
        packet[1] = ecn.bits();
        packet[10..12].fill(0);
        let checksum = crate::checksum::checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

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
                protocol: MembershipProtocol::Igmpv3,
                ecn_capable: false,
            })
        );
    }

    #[test]
    fn request_builds_amt_request_for_discovered_relay() {
        let relay = SocketAddr::from(([192, 0, 2, 20], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        await_query(&mut gateway, relay);

        let action = gateway.request().unwrap();

        let GatewayAction::Send {
            destination,
            datagram,
        } = action
        else {
            panic!("expected send action");
        };
        assert_eq!(destination, relay);
        assert_eq!(
            decode(&datagram),
            Ok(Message::Request {
                request_nonce: 0x0506_0708,
                protocol: MembershipProtocol::Igmpv3,
                ecn_capable: false,
            })
        );
    }

    #[test]
    fn ecn_gateway_sets_request_capability_flag() {
        let relay = SocketAddr::from(([192, 0, 2, 20], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_ecn(true)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        await_query(&mut gateway, relay);

        let (_, datagram) = gateway.request().unwrap().into_send().unwrap();

        assert_eq!(
            decode(&datagram),
            Ok(Message::Request {
                request_nonce: 0x0506_0708,
                protocol: MembershipProtocol::Igmpv3,
                ecn_capable: true,
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
        await_query(&mut gateway, relay);
        gateway.session = Some(GatewaySession {
            response_mac: existing_mac,
            request_nonce: 0x0101_0101,
            gateway_endpoint: Some(existing_gateway),
            reported_memberships: true,
        });
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
        assert_eq!(
            gateway.session.and_then(|session| session.gateway_endpoint),
            Some(existing_gateway)
        );
    }

    #[test]
    fn join_group_builds_membership_update_after_query() {
        let relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        await_query(&mut gateway, relay);
        let response_mac = ResponseMac::new([1, 2, 3, 4, 5, 6]);
        let query = membership_query(response_mac, 0x0506_0708, None);
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
    fn repeated_ssm_joins_are_additive() {
        let relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        await_query(&mut gateway, relay);
        let query = membership_query(ResponseMac::new([1, 2, 3, 4, 5, 6]), 0x0506_0708, None);
        gateway.handle_datagram(relay, &query).unwrap();

        gateway.join_group(group, Some(first)).unwrap();
        gateway.join_group(group, Some(second)).unwrap();

        let interest = gateway
            .reception_state
            .endpoint_interest(RECEPTION_STATE_ENDPOINT, group)
            .unwrap();
        assert_eq!(interest.sources, BTreeSet::from([first, second]));
    }

    #[test]
    fn rediscovery_does_not_carry_reported_status_into_new_session() {
        let relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        await_query(&mut gateway, relay);
        let query = membership_query(ResponseMac::new([1, 2, 3, 4, 5, 6]), 0x0506_0708, None);
        gateway.handle_datagram(relay, &query).unwrap();
        gateway
            .join_group(
                IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            )
            .unwrap();
        assert!(gateway.has_reported_memberships());

        gateway.restart_discovery();

        assert!(!gateway.has_reported_memberships());
    }

    #[test]
    fn teardown_requires_gateway_endpoint_from_membership_query() {
        let relay = SocketAddr::from(([127, 0, 0, 1], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_nonces(0x0102_0304, 0x0506_0708),
        );
        await_query(&mut gateway, relay);
        let query = membership_query(ResponseMac::new([1, 2, 3, 4, 5, 6]), 0x0506_0708, None);
        gateway.handle_datagram(relay, &query).unwrap();

        assert_eq!(
            gateway.teardown(),
            Err(GatewayError::MissingGatewayEndpoint)
        );
    }

    #[test]
    fn rejects_advertisement_from_a_different_peer() {
        let relay = SocketAddr::from(([192, 0, 2, 10], 2268));
        let attacker = SocketAddr::from(([192, 0, 2, 11], 2268));
        let mut gateway =
            Gateway::new(GatewayConfig::new(relay, MembershipProtocol::Igmpv3).with_nonces(1, 2));
        let advertisement = encode(&Message::RelayAdvertisement {
            discovery_nonce: 1,
            relay_address: relay.ip(),
        });

        assert_eq!(
            gateway.handle_datagram(attacker, &advertisement),
            Err(GatewayError::UnexpectedPeer {
                expected: relay,
                actual: attacker,
            })
        );
        assert!(matches!(
            gateway.handle_datagram(attacker, &[0xff]),
            Err(GatewayError::UnexpectedPeer { .. })
        ));
        assert_eq!(gateway.relay_endpoint(), None);
    }

    #[test]
    fn multicast_data_requires_selected_relay_and_requested_source() {
        let relay = SocketAddr::from(([192, 0, 2, 10], 2268));
        let attacker = SocketAddr::from(([192, 0, 2, 11], 2268));
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let other_source = Ipv4Addr::new(192, 0, 2, 2);
        let group = Ipv4Addr::new(232, 1, 2, 3);
        let mut gateway =
            Gateway::new(GatewayConfig::new(relay, MembershipProtocol::Igmpv3).with_nonces(1, 2));
        await_query(&mut gateway, relay);
        let query = membership_query(ResponseMac::new([1; 6]), 2, None);
        gateway.handle_datagram(relay, &query).unwrap();
        gateway
            .join_group(group.into(), Some(source.into()))
            .unwrap();

        let packet = multicast_packet(source, group);
        let data = encode(&Message::MulticastData { packet: &packet });
        assert!(matches!(
            gateway.handle_datagram(attacker, &data),
            Err(GatewayError::UnexpectedPeer { .. })
        ));

        let packet = multicast_packet(other_source, group);
        let data = encode(&Message::MulticastData { packet: &packet });
        assert_eq!(
            gateway.handle_datagram(relay, &data),
            Ok(GatewayAction::Ignored)
        );
    }

    #[test]
    fn ecn_gateway_propagates_outer_ce_into_inner_packet() {
        let relay = SocketAddr::from(([192, 0, 2, 10], 2268));
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let group = Ipv4Addr::new(232, 1, 2, 3);
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_ecn(true)
                .with_nonces(1, 2),
        );
        await_query(&mut gateway, relay);
        let query = membership_query(ResponseMac::new([1; 6]), 2, None);
        gateway.handle_datagram(relay, &query).unwrap();
        gateway
            .join_group(group.into(), Some(source.into()))
            .unwrap();
        let packet = multicast_packet_with_ecn(source, group, EcnCodepoint::Ect0);
        let data = encode(&Message::MulticastData { packet: &packet });

        let action = gateway
            .handle_datagram_with_ecn(relay, &data, EcnCodepoint::Ce)
            .unwrap();

        let GatewayAction::MulticastData { packet, ecn } = action else {
            panic!("expected forwarded multicast data");
        };
        assert_eq!(crate::ecn::ip_ecn(&packet), Ok(EcnCodepoint::Ce));
        assert!(ecn.unwrap().propagated_ce());
    }

    #[test]
    fn ecn_gateway_drops_not_ect_inner_with_outer_ce() {
        let relay = SocketAddr::from(([192, 0, 2, 10], 2268));
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let group = Ipv4Addr::new(232, 1, 2, 3);
        let mut gateway = Gateway::new(
            GatewayConfig::new(relay, MembershipProtocol::Igmpv3)
                .with_ecn(true)
                .with_nonces(1, 2),
        );
        await_query(&mut gateway, relay);
        let query = membership_query(ResponseMac::new([1; 6]), 2, None);
        gateway.handle_datagram(relay, &query).unwrap();
        gateway
            .join_group(group.into(), Some(source.into()))
            .unwrap();
        let packet = multicast_packet_with_ecn(source, group, EcnCodepoint::NotEct);
        let data = encode(&Message::MulticastData { packet: &packet });

        let action = gateway
            .handle_datagram_with_ecn(relay, &data, EcnCodepoint::Ce)
            .unwrap();

        assert!(matches!(
            action,
            GatewayAction::DroppedEcn {
                ecn: EcnDecapsulation { output: None, .. },
                ..
            }
        ));
    }

    #[test]
    fn rejects_membership_query_without_valid_general_query() {
        let relay = SocketAddr::from(([192, 0, 2, 10], 2268));
        let mut gateway =
            Gateway::new(GatewayConfig::new(relay, MembershipProtocol::Igmpv3).with_nonces(1, 2));
        await_query(&mut gateway, relay);
        let query = encode(&Message::MembershipQuery {
            response_mac: ResponseMac::new([1; 6]),
            request_nonce: 2,
            limit: false,
            gateway: None,
            general_query: &[0x45, 0, 0, 20],
        });

        assert!(matches!(
            gateway.handle_datagram(relay, &query),
            Err(GatewayError::InvalidGeneralQuery(_))
        ));
        assert!(!gateway.is_established());
    }

    #[test]
    fn fresh_query_cycle_leaves_established_phase_and_rotates_nonce() {
        let relay = SocketAddr::from(([192, 0, 2, 10], 2268));
        let mut gateway =
            Gateway::new(GatewayConfig::new(relay, MembershipProtocol::Igmpv3).with_nonces(1, 2));
        await_query(&mut gateway, relay);
        let query = membership_query(ResponseMac::new([1; 6]), 2, None);
        gateway.handle_datagram(relay, &query).unwrap();
        assert!(gateway.is_established());

        let action = gateway.begin_query_cycle().unwrap();

        assert!(!gateway.is_established());
        assert!(gateway.is_awaiting_query());
        let (_, request) = action.into_send().unwrap();
        let Message::Request { request_nonce, .. } = Message::decode(&request).unwrap() else {
            panic!("expected Request");
        };
        assert_ne!(request_nonce, 0);
    }

    #[test]
    fn restart_discovery_rotates_fallback_relays() {
        let first = SocketAddr::from(([192, 0, 2, 10], 2268));
        let second = SocketAddr::from(([192, 0, 2, 11], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(first, MembershipProtocol::Igmpv3).with_fallback_relays([second]),
        );

        let (destination, _) = gateway.restart_discovery().into_send().unwrap();
        assert_eq!(destination, second);
        let (destination, _) = gateway.restart_discovery().into_send().unwrap();
        assert_eq!(destination, first);
    }

    #[test]
    fn fallback_relays_stay_in_the_primary_outer_address_family() {
        let primary = SocketAddr::from(([192, 0, 2, 1], 2268));
        let ipv4_fallback = SocketAddr::from(([192, 0, 2, 2], 2268));
        let ipv6_fallback = SocketAddr::new("2001:db8::1".parse().unwrap(), 2268);
        let config = GatewayConfig::new(primary, MembershipProtocol::Igmpv3)
            .with_fallback_relays([ipv6_fallback, ipv4_fallback]);

        assert_eq!(config.fallback_relays, vec![ipv4_fallback]);
    }

    #[test]
    fn refreshed_candidates_retire_removed_relay_without_reintroducing_it() {
        let first = SocketAddr::from(([192, 0, 2, 10], 2268));
        let second = SocketAddr::from(([192, 0, 2, 11], 2268));
        let third = SocketAddr::from(([192, 0, 2, 12], 2268));
        let mut gateway = Gateway::new(
            GatewayConfig::new(first, MembershipProtocol::Igmpv3).with_fallback_relays([second]),
        );

        assert!(gateway.replace_relay_candidates([second, third]));
        assert_eq!(gateway.config().relay, first);
        assert!(gateway.current_relay_is_retired());

        assert_eq!(gateway.restart_discovery().into_send().unwrap().0, second);
        assert_eq!(gateway.restart_discovery().into_send().unwrap().0, third);
        assert_eq!(gateway.restart_discovery().into_send().unwrap().0, second);
    }
}
