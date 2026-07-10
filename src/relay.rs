use crate::membership::{
    MembershipParseError, MembershipParseLimits, parse_membership_report_with_limits,
};
use crate::protocol::{
    DecodeError, GatewayAddress, GatewayEndpoint, MembershipProtocol, Message, ResponseMac, encode,
};
use crate::query::{GeneralQueryConfig, build_general_query, query_interval};
use crate::state::{RelayLimits, RelayState, StateLimitError, UpstreamSubscription};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, PartialEq, Eq)]
pub struct RelaySecret([u8; 32]);

impl RelaySecret {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        Self::try_generate()
            .expect("operating-system randomness is required for AMT authentication")
    }

    pub fn try_generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
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
    pub limits: RelayLimits,
    pub secret_rotation_interval: Option<Duration>,
    pub general_query: GeneralQueryConfig,
}

impl RelayConfig {
    pub fn for_bind(bind: SocketAddr) -> Self {
        let mut config = Self {
            bind,
            ..Self::default()
        };
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
            limits: RelayLimits::default(),
            secret_rotation_interval: Some(Duration::from_secs(2 * 60 * 60)),
            general_query: GeneralQueryConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    config: RelayConfig,
    state: RelayState,
    previous_secret: Option<PreviousSecret>,
    secret_rotated_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreviousSecret {
    secret: RelaySecret,
    rotated_at: Instant,
}

impl Relay {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            state: RelayState::default(),
            previous_secret: None,
            secret_rotated_at: Instant::now(),
        }
    }

    pub const fn config(&self) -> &RelayConfig {
        &self.config
    }

    pub const fn state(&self) -> &RelayState {
        &self.state
    }

    pub fn remove_gateway(&mut self, endpoint: SocketAddr) -> bool {
        self.state.remove_endpoint(endpoint)
    }

    pub fn handle_datagram(
        &mut self,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Result<RelayAction, RelayError> {
        let (action, next_state) = self.prepare_datagram(peer, datagram)?;
        if let Some(next_state) = next_state {
            self.state = next_state;
        }
        Ok(action)
    }

    pub fn prepare_datagram(
        &mut self,
        peer: SocketAddr,
        datagram: &[u8],
    ) -> Result<(RelayAction, Option<RelayState>), RelayError> {
        self.rotate_secret_if_due();
        let message = Message::decode(datagram)?;
        match message {
            Message::RelayDiscovery { discovery_nonce } => {
                if discovery_nonce == 0 {
                    return Err(RelayError::ZeroNonce);
                }
                let response = Message::RelayAdvertisement {
                    discovery_nonce,
                    relay_address: self.config.advertised_addr_for(peer),
                };
                Ok((RelayAction::Send(encode(&response)), None))
            }
            Message::Request {
                request_nonce,
                protocol,
            } => {
                if request_nonce == 0 {
                    return Err(RelayError::ZeroNonce);
                }
                let response_mac = self.response_mac(peer.ip(), peer.port(), request_nonce);
                let general_query = build_general_query(protocol, &self.config.general_query);
                let gateway = self.config.include_gateway_address.then(|| {
                    GatewayEndpoint::new(peer.port(), GatewayAddress::from_ip_addr(peer.ip()))
                });
                let response = Message::MembershipQuery {
                    response_mac,
                    request_nonce,
                    limit: self.refusing_new_endpoint(peer.ip()),
                    gateway,
                    general_query: &general_query,
                };
                Ok((RelayAction::Send(encode(&response)), None))
            }
            Message::MembershipUpdate {
                response_mac,
                request_nonce,
                membership_update,
            } => {
                if request_nonce == 0 {
                    return Err(RelayError::ZeroNonce);
                }
                if self.valid_response_mac(response_mac, peer.ip(), peer.port(), request_nonce) {
                    if !self.state.contains_endpoint(peer) && self.refusing_new_endpoint(peer.ip())
                    {
                        return Ok((RelayAction::Ignored, None));
                    }
                    let report = parse_membership_report_with_limits(
                        membership_update,
                        MembershipParseLimits {
                            max_records: self.config.limits.max_records_per_report,
                            max_sources_per_record: self.config.limits.max_sources_per_group,
                        },
                    )?;
                    if let Some(group) = report
                        .records
                        .iter()
                        .map(|record| record.group)
                        .find(|group| !crate::ip::is_amt_forwardable_group(*group))
                    {
                        return Err(RelayError::Membership(
                            MembershipParseError::InvalidMulticastGroup(group),
                        ));
                    }
                    let (records_applied, changed) = self.state.preview_report(peer, &report);
                    if !changed {
                        return Ok((
                            RelayAction::AcceptedMembershipUpdate {
                                protocol: report.protocol,
                                bytes: membership_update.len(),
                                records_applied,
                                upstream_subscriptions: self.state.upstream_subscriptions(),
                            },
                            None,
                        ));
                    }
                    let mut next_state = self.state.clone();
                    next_state.apply_report_limited(peer, &report, &self.config.limits)?;
                    let upstream_subscriptions = next_state.upstream_subscriptions();
                    Ok((
                        RelayAction::AcceptedMembershipUpdate {
                            protocol: report.protocol,
                            bytes: membership_update.len(),
                            records_applied,
                            upstream_subscriptions,
                        },
                        Some(next_state),
                    ))
                } else {
                    Ok((RelayAction::RejectedAuth, None))
                }
            }
            Message::Teardown {
                response_mac,
                request_nonce,
                gateway,
            } => {
                if request_nonce == 0 {
                    return Err(RelayError::ZeroNonce);
                }
                let gateway_ip = gateway
                    .address
                    .as_ipv4_compatible()
                    .map(IpAddr::V4)
                    .unwrap_or_else(|| IpAddr::V6(gateway.address.as_ipv6()));
                let endpoint = SocketAddr::new(gateway_ip, gateway.port);
                if self.valid_response_mac(response_mac, gateway_ip, gateway.port, request_nonce) {
                    if !self.state.contains_endpoint(endpoint) {
                        return Ok((
                            RelayAction::AcceptedTeardown {
                                gateway,
                                removed: false,
                            },
                            None,
                        ));
                    }
                    let mut next_state = self.state.clone();
                    let removed = next_state.remove_endpoint(endpoint);
                    Ok((
                        RelayAction::AcceptedTeardown { gateway, removed },
                        removed.then_some(next_state),
                    ))
                } else {
                    Ok((RelayAction::RejectedAuth, None))
                }
            }
            Message::RelayAdvertisement { .. }
            | Message::MembershipQuery { .. }
            | Message::MulticastData { .. } => Ok((RelayAction::Ignored, None)),
        }
    }

    pub fn commit_state(&mut self, state: RelayState) {
        self.state = state;
    }

    pub fn response_mac(
        &self,
        gateway_ip: IpAddr,
        gateway_port: u16,
        request_nonce: u32,
    ) -> ResponseMac {
        response_mac_with_secret(&self.config.secret, gateway_ip, gateway_port, request_nonce)
    }

    fn valid_response_mac(
        &self,
        actual: ResponseMac,
        gateway_ip: IpAddr,
        gateway_port: u16,
        request_nonce: u32,
    ) -> bool {
        actual.constant_time_eq(self.response_mac(gateway_ip, gateway_port, request_nonce))
            || self.previous_secret.as_ref().is_some_and(|previous| {
                if previous.rotated_at.elapsed()
                    > query_interval(self.config.general_query.query_interval_code) * 2
                {
                    return false;
                }
                actual.constant_time_eq(response_mac_with_secret(
                    &previous.secret,
                    gateway_ip,
                    gateway_port,
                    request_nonce,
                ))
            })
    }

    fn refusing_new_endpoint(&self, address: IpAddr) -> bool {
        self.config.limit
            || self.state.is_near_limits(&self.config.limits)
            || self
                .state
                .is_ip_near_endpoint_limit(address, self.config.limits.max_endpoints_per_ip)
    }

    fn rotate_secret_if_due(&mut self) {
        let Some(interval) = self.config.secret_rotation_interval else {
            return;
        };
        if self.secret_rotated_at.elapsed() < interval {
            return;
        }
        let previous_grace = query_interval(self.config.general_query.query_interval_code) * 2;
        if self
            .previous_secret
            .as_ref()
            .is_some_and(|previous| previous.rotated_at.elapsed() <= previous_grace)
        {
            return;
        }
        let Ok(next_secret) = RelaySecret::try_generate() else {
            return;
        };
        let now = Instant::now();
        self.previous_secret = Some(PreviousSecret {
            secret: std::mem::replace(&mut self.config.secret, next_secret),
            rotated_at: now,
        });
        self.secret_rotated_at = now;
    }
}

fn response_mac_with_secret(
    secret: &RelaySecret,
    gateway_ip: IpAddr,
    gateway_port: u16,
    request_nonce: u32,
) -> ResponseMac {
    let mut mac =
        HmacSha256::new_from_slice(secret.expose_bytes()).expect("HMAC accepts any key size");
    mac.update(&GatewayAddress::from_ip_addr(gateway_ip).octets());
    mac.update(&gateway_port.to_be_bytes());
    mac.update(&request_nonce.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    ResponseMac::new([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
    ])
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
    ResourceLimit(StateLimitError),
    ZeroNonce,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "{error}"),
            Self::Membership(error) => write!(f, "{error}"),
            Self::ResourceLimit(error) => write!(f, "{error}"),
            Self::ZeroNonce => f.write_str("AMT nonce must not be zero"),
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

impl From<StateLimitError> for RelayError {
    fn from(value: StateLimitError) -> Self {
        Self::ResourceLimit(value)
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
    fn zero_nonce_request_is_rejected_without_reflection() {
        let mut relay = relay();
        let request = encode(&Message::Request {
            request_nonce: 0,
            protocol: MembershipProtocol::Igmpv3,
        });

        assert_eq!(
            relay.handle_datagram(SocketAddr::from(([198, 51, 100, 8], 40_000)), &request),
            Err(RelayError::ZeroNonce)
        );
    }

    #[test]
    fn resource_limit_rejection_does_not_commit_membership() {
        let mut relay = relay();
        relay.config.limits.max_groups_per_endpoint = 1;
        let peer = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let nonce = 42;
        let report = crate::membership::MembershipReport {
            protocol: MembershipProtocol::Igmpv3,
            records: vec![
                crate::membership::MembershipRecord {
                    kind: crate::membership::MembershipRecordKind::ModeIsExclude,
                    group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
                    sources: Vec::new(),
                },
                crate::membership::MembershipRecord {
                    kind: crate::membership::MembershipRecordKind::ModeIsExclude,
                    group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 4)),
                    sources: Vec::new(),
                },
            ],
        };
        let packet = crate::membership::build_membership_report(&report).unwrap();
        let update = encode(&Message::MembershipUpdate {
            response_mac: relay.response_mac(peer.ip(), peer.port(), nonce),
            request_nonce: nonce,
            membership_update: &packet,
        });

        assert!(matches!(
            relay.handle_datagram(peer, &update),
            Err(RelayError::ResourceLimit(_))
        ));
        assert_eq!(relay.state().endpoint_count(), 0);
    }

    #[test]
    fn membership_query_sets_limit_flag_near_capacity() {
        let mut relay = relay();
        relay.config.limits.max_endpoints = 1;
        let endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        relay.state.apply_report(
            endpoint,
            &crate::membership::MembershipReport {
                protocol: MembershipProtocol::Igmpv3,
                records: vec![crate::membership::MembershipRecord {
                    kind: crate::membership::MembershipRecordKind::ModeIsExclude,
                    group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
                    sources: Vec::new(),
                }],
            },
        );
        let request = encode(&Message::Request {
            request_nonce: 42,
            protocol: MembershipProtocol::Igmpv3,
        });

        let RelayAction::Send(response) = relay
            .handle_datagram(SocketAddr::from(([198, 51, 100, 9], 40_001)), &request)
            .unwrap()
        else {
            panic!("expected Membership Query response");
        };
        assert!(matches!(
            Message::decode(&response),
            Ok(Message::MembershipQuery { limit: true, .. })
        ));
    }

    #[test]
    fn limit_flag_causes_new_endpoint_updates_to_be_ignored() {
        let mut relay = relay();
        relay.config.limit = true;
        let peer = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let nonce = 42;
        let packet = igmpv3_join_packet(Ipv4Addr::new(232, 1, 2, 3), Ipv4Addr::new(192, 0, 2, 1));
        let update = encode(&Message::MembershipUpdate {
            response_mac: relay.response_mac(peer.ip(), peer.port(), nonce),
            request_nonce: nonce,
            membership_update: &packet,
        });

        assert_eq!(
            relay.handle_datagram(peer, &update),
            Ok(RelayAction::Ignored)
        );
        assert_eq!(relay.state().endpoint_count(), 0);
    }

    #[test]
    fn previous_secret_expires_after_two_query_intervals() {
        let mut relay = relay();
        let peer = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let nonce = 42;
        let previous = RelaySecret::new([3; 32]);
        let mac = response_mac_with_secret(&previous, peer.ip(), peer.port(), nonce);

        relay.previous_secret = Some(PreviousSecret {
            secret: previous.clone(),
            rotated_at: Instant::now(),
        });
        assert!(relay.valid_response_mac(mac, peer.ip(), peer.port(), nonce));

        relay.previous_secret = Some(PreviousSecret {
            secret: previous,
            rotated_at: Instant::now()
                .checked_sub(Duration::from_secs(300))
                .unwrap(),
        });
        assert!(!relay.valid_response_mac(mac, peer.ip(), peer.port(), nonce));
    }

    #[test]
    fn secret_rotation_waits_until_the_previous_secret_grace_expires() {
        let mut relay = relay();
        relay.config.secret_rotation_interval = Some(Duration::ZERO);
        relay.secret_rotated_at = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        relay.previous_secret = Some(PreviousSecret {
            secret: RelaySecret::new([3; 32]),
            rotated_at: Instant::now(),
        });
        let current = relay.config.secret.clone();
        let rotated_at = relay.secret_rotated_at;

        relay.rotate_secret_if_due();

        assert_eq!(relay.config.secret, current);
        assert_eq!(relay.secret_rotated_at, rotated_at);
    }

    #[test]
    fn malformed_authenticated_membership_update_does_not_create_state() {
        let mut relay = relay();
        let peer = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let nonce = 0xaabb_ccdd;
        let response_mac = relay.response_mac(peer.ip(), peer.port(), nonce);
        let mut packet =
            igmpv3_join_packet(Ipv4Addr::new(232, 1, 2, 3), Ipv4Addr::new(192, 0, 2, 1));
        packet[26] ^= 0xff;
        let update = encode(&Message::MembershipUpdate {
            response_mac,
            request_nonce: nonce,
            membership_update: &packet,
        });

        assert!(matches!(
            relay.handle_datagram(peer, &update),
            Err(RelayError::Membership(
                MembershipParseError::InvalidChecksum("IGMP")
            ))
        ));
        assert_eq!(relay.state().endpoint_count(), 0);
        assert!(relay.state().upstream_subscriptions().is_empty());
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

    #[test]
    fn teardown_may_arrive_from_a_changed_nat_endpoint() {
        let mut relay = relay();
        let old_peer = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let new_peer = SocketAddr::from(([198, 51, 100, 8], 40_001));
        let nonce = 0xaabb_ccdd;
        let response_mac = relay.response_mac(old_peer.ip(), old_peer.port(), nonce);
        let packet = igmpv3_join_packet(Ipv4Addr::new(232, 1, 2, 3), Ipv4Addr::new(192, 0, 2, 1));
        let update = encode(&Message::MembershipUpdate {
            response_mac,
            request_nonce: nonce,
            membership_update: &packet,
        });
        relay.handle_datagram(old_peer, &update).unwrap();

        let teardown = encode(&Message::Teardown {
            response_mac,
            request_nonce: nonce,
            gateway: GatewayEndpoint::new(old_peer.port(), old_peer.ip()),
        });

        assert!(matches!(
            relay.handle_datagram(new_peer, &teardown),
            Ok(RelayAction::AcceptedTeardown { removed: true, .. })
        ));
        assert_eq!(relay.state().endpoint_count(), 0);
    }

    #[test]
    fn bad_teardown_mac_does_not_remove_endpoint_state() {
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

        let teardown = encode(&Message::Teardown {
            response_mac: ResponseMac::ZERO,
            request_nonce: nonce,
            gateway: GatewayEndpoint::new(peer.port(), peer.ip()),
        });

        assert_eq!(
            relay.handle_datagram(peer, &teardown).unwrap(),
            RelayAction::RejectedAuth
        );
        assert_eq!(
            relay
                .state()
                .endpoints_for_packet(source.into(), group.into()),
            vec![peer]
        );
        assert_eq!(
            relay.state().upstream_subscriptions(),
            vec![UpstreamSubscription::ssm(group.into(), source.into())]
        );
    }

    fn igmpv3_join_packet(group: Ipv4Addr, source: Ipv4Addr) -> Vec<u8> {
        let mut payload = vec![0; 20];
        payload[0] = 0x22;
        payload[6..8].copy_from_slice(&1u16.to_be_bytes());
        payload[8] = 1;
        payload[10..12].copy_from_slice(&1u16.to_be_bytes());
        payload[12..16].copy_from_slice(&group.octets());
        payload[16..20].copy_from_slice(&source.octets());
        let igmp_checksum = crate::checksum::checksum(&payload);
        payload[2..4].copy_from_slice(&igmp_checksum.to_be_bytes());

        let total_len = 24 + payload.len();
        let mut packet = vec![0; 24];
        packet[0] = 0x46;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 1;
        packet[9] = 2;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 1).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(224, 0, 0, 22).octets());
        packet[20..24].copy_from_slice(&[0x94, 0x04, 0, 0]);
        let ip_checksum = crate::checksum::checksum(&packet);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        packet.extend_from_slice(&payload);
        packet
    }
}
