use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// UDP port assigned by IANA for AMT.
pub const AMT_PORT: u16 = 2268;

const VERSION: u8 = 0;
const VERSION_MASK: u8 = 0xf0;
const TYPE_MASK: u8 = 0x0f;
const RESPONSE_MAC_LEN: usize = 6;
const GATEWAY_ADDRESS_LEN: usize = 16;
const GATEWAY_FIELDS_LEN: usize = 2 + GATEWAY_ADDRESS_LEN;

/// AMT message type values defined by RFC 7450 section 5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    RelayDiscovery = 1,
    RelayAdvertisement = 2,
    Request = 3,
    MembershipQuery = 4,
    MembershipUpdate = 5,
    MulticastData = 6,
    Teardown = 7,
}

impl MessageType {
    fn from_nibble(value: u8) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::RelayDiscovery),
            2 => Ok(Self::RelayAdvertisement),
            3 => Ok(Self::Request),
            4 => Ok(Self::MembershipQuery),
            5 => Ok(Self::MembershipUpdate),
            6 => Ok(Self::MulticastData),
            7 => Ok(Self::Teardown),
            other => Err(DecodeError::UnknownMessageType(other)),
        }
    }
}

/// The group membership protocol requested for a relay's Membership Query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipProtocol {
    Igmpv3,
    Mldv2,
}

impl MembershipProtocol {
    fn from_p_flag(p_flag: bool) -> Self {
        if p_flag { Self::Mldv2 } else { Self::Igmpv3 }
    }

    fn p_flag(self) -> bool {
        matches!(self, Self::Mldv2)
    }
}

/// A six-byte AMT Response MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseMac([u8; RESPONSE_MAC_LEN]);

impl ResponseMac {
    pub const ZERO: Self = Self([0; RESPONSE_MAC_LEN]);

    pub const fn new(bytes: [u8; RESPONSE_MAC_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; RESPONSE_MAC_LEN] {
        self.0
    }
}

/// A 16-byte gateway address field from Membership Query and Teardown messages.
///
/// RFC 7450 stores IPv4 gateway addresses as IPv4-compatible IPv6 addresses
/// (96 zero bits followed by the IPv4 address). Keeping the raw 16 bytes avoids
/// losing information when a message intentionally carries an IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GatewayAddress([u8; GATEWAY_ADDRESS_LEN]);

impl GatewayAddress {
    pub const fn from_octets(octets: [u8; GATEWAY_ADDRESS_LEN]) -> Self {
        Self(octets)
    }

    pub fn from_ip_addr(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => {
                let mut octets = [0; GATEWAY_ADDRESS_LEN];
                octets[12..].copy_from_slice(&addr.octets());
                Self(octets)
            }
            IpAddr::V6(addr) => Self(addr.octets()),
        }
    }

    pub const fn octets(self) -> [u8; GATEWAY_ADDRESS_LEN] {
        self.0
    }

    pub fn as_ipv6(self) -> Ipv6Addr {
        Ipv6Addr::from(self.0)
    }

    pub fn as_ipv4_compatible(self) -> Option<Ipv4Addr> {
        if self.0[..12] == [0; 12] {
            Some(Ipv4Addr::new(
                self.0[12], self.0[13], self.0[14], self.0[15],
            ))
        } else {
            None
        }
    }
}

impl From<IpAddr> for GatewayAddress {
    fn from(value: IpAddr) -> Self {
        Self::from_ip_addr(value)
    }
}

impl From<Ipv4Addr> for GatewayAddress {
    fn from(value: Ipv4Addr) -> Self {
        Self::from_ip_addr(value.into())
    }
}

impl From<Ipv6Addr> for GatewayAddress {
    fn from(value: Ipv6Addr) -> Self {
        Self::from_ip_addr(value.into())
    }
}

/// Gateway endpoint fields carried by Membership Query and Teardown messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GatewayEndpoint {
    pub port: u16,
    pub address: GatewayAddress,
}

impl GatewayEndpoint {
    pub fn new(port: u16, address: impl Into<GatewayAddress>) -> Self {
        Self {
            port,
            address: address.into(),
        }
    }
}

/// Borrowed view of one AMT message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    RelayDiscovery {
        discovery_nonce: u32,
    },
    RelayAdvertisement {
        discovery_nonce: u32,
        relay_address: IpAddr,
    },
    Request {
        request_nonce: u32,
        protocol: MembershipProtocol,
    },
    MembershipQuery {
        response_mac: ResponseMac,
        request_nonce: u32,
        limit: bool,
        gateway: Option<GatewayEndpoint>,
        general_query: &'a [u8],
    },
    MembershipUpdate {
        response_mac: ResponseMac,
        request_nonce: u32,
        membership_update: &'a [u8],
    },
    MulticastData {
        packet: &'a [u8],
    },
    Teardown {
        response_mac: ResponseMac,
        request_nonce: u32,
        gateway: GatewayEndpoint,
    },
}

impl<'a> Message<'a> {
    /// Decodes a borrowed AMT message from one UDP datagram payload.
    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        let first = *input.first().ok_or(DecodeError::Truncated {
            message_type: None,
            expected_at_least: 1,
            actual: 0,
        })?;

        let version = (first & VERSION_MASK) >> 4;
        if version != VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }

        let message_type = MessageType::from_nibble(first & TYPE_MASK)?;
        match message_type {
            MessageType::RelayDiscovery => decode_relay_discovery(input),
            MessageType::RelayAdvertisement => decode_relay_advertisement(input),
            MessageType::Request => decode_request(input),
            MessageType::MembershipQuery => decode_membership_query(input),
            MessageType::MembershipUpdate => decode_membership_update(input),
            MessageType::MulticastData => decode_multicast_data(input),
            MessageType::Teardown => decode_teardown(input),
        }
    }

    /// Encodes this message into `out`, appending to any existing bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::RelayDiscovery { discovery_nonce } => {
                out.extend_from_slice(&[header(MessageType::RelayDiscovery), 0, 0, 0]);
                put_u32(out, *discovery_nonce);
            }
            Self::RelayAdvertisement {
                discovery_nonce,
                relay_address,
            } => {
                out.extend_from_slice(&[header(MessageType::RelayAdvertisement), 0, 0, 0]);
                put_u32(out, *discovery_nonce);
                match relay_address {
                    IpAddr::V4(addr) => out.extend_from_slice(&addr.octets()),
                    IpAddr::V6(addr) => out.extend_from_slice(&addr.octets()),
                }
            }
            Self::Request {
                request_nonce,
                protocol,
            } => {
                out.push(header(MessageType::Request));
                out.push(u8::from(protocol.p_flag()));
                out.extend_from_slice(&[0, 0]);
                put_u32(out, *request_nonce);
            }
            Self::MembershipQuery {
                response_mac,
                request_nonce,
                limit,
                gateway,
                general_query,
            } => {
                out.push(header(MessageType::MembershipQuery));
                out.push((u8::from(*limit) << 1) | u8::from(gateway.is_some()));
                out.extend_from_slice(&response_mac.as_bytes());
                put_u32(out, *request_nonce);
                out.extend_from_slice(general_query);
                if let Some(gateway) = gateway {
                    put_gateway_endpoint(out, *gateway);
                }
            }
            Self::MembershipUpdate {
                response_mac,
                request_nonce,
                membership_update,
            } => {
                out.push(header(MessageType::MembershipUpdate));
                out.push(0);
                out.extend_from_slice(&response_mac.as_bytes());
                put_u32(out, *request_nonce);
                out.extend_from_slice(membership_update);
            }
            Self::MulticastData { packet } => {
                out.extend_from_slice(&[header(MessageType::MulticastData), 0]);
                out.extend_from_slice(packet);
            }
            Self::Teardown {
                response_mac,
                request_nonce,
                gateway,
            } => {
                out.push(header(MessageType::Teardown));
                out.push(0);
                out.extend_from_slice(&response_mac.as_bytes());
                put_u32(out, *request_nonce);
                put_gateway_endpoint(out, *gateway);
            }
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Self::RelayDiscovery { .. } => 8,
            Self::RelayAdvertisement { relay_address, .. } => {
                8 + match relay_address {
                    IpAddr::V4(_) => 4,
                    IpAddr::V6(_) => 16,
                }
            }
            Self::Request { .. } => 8,
            Self::MembershipQuery {
                gateway,
                general_query,
                ..
            } => 12 + general_query.len() + gateway.map(|_| GATEWAY_FIELDS_LEN).unwrap_or(0),
            Self::MembershipUpdate {
                membership_update, ..
            } => 12 + membership_update.len(),
            Self::MulticastData { packet } => 2 + packet.len(),
            Self::Teardown { .. } => 12 + GATEWAY_FIELDS_LEN,
        }
    }
}

/// Decodes a borrowed AMT message from one UDP datagram payload.
pub fn decode(input: &[u8]) -> Result<Message<'_>, DecodeError> {
    Message::decode(input)
}

/// Encodes a message into a fresh byte vector sized for the message.
pub fn encode(message: &Message<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.encoded_len());
    message.encode(&mut out);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnsupportedVersion(u8),
    UnknownMessageType(u8),
    Truncated {
        message_type: Option<MessageType>,
        expected_at_least: usize,
        actual: usize,
    },
    InvalidLength {
        message_type: MessageType,
        expected: &'static str,
        actual: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported AMT version {version}")
            }
            Self::UnknownMessageType(message_type) => {
                write!(f, "unknown AMT message type {message_type}")
            }
            Self::Truncated {
                message_type,
                expected_at_least,
                actual,
            } => {
                write!(
                    f,
                    "truncated AMT message {message_type:?}: expected at least {expected_at_least} bytes, got {actual}"
                )
            }
            Self::InvalidLength {
                message_type,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid AMT {message_type:?} length: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

fn decode_relay_discovery(input: &[u8]) -> Result<Message<'_>, DecodeError> {
    require_exact(MessageType::RelayDiscovery, input, 8)?;
    Ok(Message::RelayDiscovery {
        discovery_nonce: read_u32(input, 4),
    })
}

fn decode_relay_advertisement(input: &[u8]) -> Result<Message<'_>, DecodeError> {
    require_at_least(MessageType::RelayAdvertisement, input, 8)?;
    let discovery_nonce = read_u32(input, 4);
    let relay_address = match input.len() - 8 {
        4 => IpAddr::V4(Ipv4Addr::new(input[8], input[9], input[10], input[11])),
        16 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&input[8..24]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => {
            return Err(DecodeError::InvalidLength {
                message_type: MessageType::RelayAdvertisement,
                expected: "12 bytes for IPv4 or 24 bytes for IPv6",
                actual: input.len(),
            });
        }
    };

    Ok(Message::RelayAdvertisement {
        discovery_nonce,
        relay_address,
    })
}

fn decode_request(input: &[u8]) -> Result<Message<'_>, DecodeError> {
    require_exact(MessageType::Request, input, 8)?;
    Ok(Message::Request {
        request_nonce: read_u32(input, 4),
        protocol: MembershipProtocol::from_p_flag(input[1] & 0x01 != 0),
    })
}

fn decode_membership_query(input: &[u8]) -> Result<Message<'_>, DecodeError> {
    require_at_least(MessageType::MembershipQuery, input, 12)?;

    let has_gateway = input[1] & 0x01 != 0;
    let gateway_offset = if has_gateway {
        if input.len() < 12 + GATEWAY_FIELDS_LEN {
            return Err(DecodeError::Truncated {
                message_type: Some(MessageType::MembershipQuery),
                expected_at_least: 12 + GATEWAY_FIELDS_LEN,
                actual: input.len(),
            });
        }
        input.len() - GATEWAY_FIELDS_LEN
    } else {
        input.len()
    };

    Ok(Message::MembershipQuery {
        response_mac: read_response_mac(input),
        request_nonce: read_u32(input, 8),
        limit: input[1] & 0x02 != 0,
        gateway: has_gateway
            .then(|| read_gateway_endpoint(&input[gateway_offset..]))
            .transpose()?,
        general_query: &input[12..gateway_offset],
    })
}

fn decode_membership_update(input: &[u8]) -> Result<Message<'_>, DecodeError> {
    require_at_least(MessageType::MembershipUpdate, input, 12)?;
    Ok(Message::MembershipUpdate {
        response_mac: read_response_mac(input),
        request_nonce: read_u32(input, 8),
        membership_update: &input[12..],
    })
}

fn decode_multicast_data(input: &[u8]) -> Result<Message<'_>, DecodeError> {
    require_at_least(MessageType::MulticastData, input, 2)?;
    Ok(Message::MulticastData {
        packet: &input[2..],
    })
}

fn decode_teardown(input: &[u8]) -> Result<Message<'_>, DecodeError> {
    require_exact(MessageType::Teardown, input, 12 + GATEWAY_FIELDS_LEN)?;
    Ok(Message::Teardown {
        response_mac: read_response_mac(input),
        request_nonce: read_u32(input, 8),
        gateway: read_gateway_endpoint(&input[12..])?,
    })
}

fn header(message_type: MessageType) -> u8 {
    (VERSION << 4) | message_type as u8
}

fn require_exact(
    message_type: MessageType,
    input: &[u8],
    expected: usize,
) -> Result<(), DecodeError> {
    if input.len() == expected {
        Ok(())
    } else if input.len() < expected {
        Err(DecodeError::Truncated {
            message_type: Some(message_type),
            expected_at_least: expected,
            actual: input.len(),
        })
    } else {
        Err(DecodeError::InvalidLength {
            message_type,
            expected: "the fixed RFC 7450 message length",
            actual: input.len(),
        })
    }
}

fn require_at_least(
    message_type: MessageType,
    input: &[u8],
    expected_at_least: usize,
) -> Result<(), DecodeError> {
    if input.len() >= expected_at_least {
        Ok(())
    } else {
        Err(DecodeError::Truncated {
            message_type: Some(message_type),
            expected_at_least,
            actual: input.len(),
        })
    }
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_response_mac(input: &[u8]) -> ResponseMac {
    let mut mac = [0; RESPONSE_MAC_LEN];
    mac.copy_from_slice(&input[2..8]);
    ResponseMac::new(mac)
}

fn read_gateway_endpoint(input: &[u8]) -> Result<GatewayEndpoint, DecodeError> {
    if input.len() != GATEWAY_FIELDS_LEN {
        return Err(DecodeError::InvalidLength {
            message_type: MessageType::Teardown,
            expected: "18 gateway endpoint bytes",
            actual: input.len(),
        });
    }

    let mut address = [0; GATEWAY_ADDRESS_LEN];
    address.copy_from_slice(&input[2..18]);

    Ok(GatewayEndpoint {
        port: u16::from_be_bytes([input[0], input[1]]),
        address: GatewayAddress::from_octets(address),
    })
}

fn put_gateway_endpoint(out: &mut Vec<u8>, gateway: GatewayEndpoint) {
    out.extend_from_slice(&gateway.port.to_be_bytes());
    out.extend_from_slice(&gateway.address.octets());
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: ResponseMac = ResponseMac::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    #[test]
    fn relay_discovery_round_trip() {
        let message = Message::RelayDiscovery {
            discovery_nonce: 0x0102_0304,
        };

        let encoded = encode(&message);

        assert_eq!(encoded, [0x01, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn relay_advertisement_ipv4_round_trip() {
        let message = Message::RelayAdvertisement {
            discovery_nonce: 7,
            relay_address: IpAddr::V4(Ipv4Addr::new(192, 52, 193, 1)),
        };

        let encoded = encode(&message);

        assert_eq!(encoded.len(), 12);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn relay_advertisement_ipv6_round_trip() {
        let message = Message::RelayAdvertisement {
            discovery_nonce: 9,
            relay_address: IpAddr::V6("2001:3::1".parse().unwrap()),
        };

        let encoded = encode(&message);

        assert_eq!(encoded.len(), 24);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn request_uses_p_flag_for_mldv2() {
        let message = Message::Request {
            request_nonce: 0x1122_3344,
            protocol: MembershipProtocol::Mldv2,
        };

        let encoded = encode(&message);

        assert_eq!(encoded, [0x03, 1, 0, 0, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn membership_query_without_gateway_round_trip() {
        let query = [0x45, 0, 0, 20];
        let message = Message::MembershipQuery {
            response_mac: MAC,
            request_nonce: 0x0102_0304,
            limit: true,
            gateway: None,
            general_query: &query,
        };

        let encoded = encode(&message);

        assert_eq!(encoded[0], 0x04);
        assert_eq!(encoded[1], 0x02);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn membership_query_with_gateway_splits_trailing_fields() {
        let query = [0x60, 0, 0, 0, 0, 32];
        let gateway = GatewayEndpoint::new(50_000, Ipv4Addr::new(203, 0, 113, 8));
        let message = Message::MembershipQuery {
            response_mac: MAC,
            request_nonce: 0x5566_7788,
            limit: false,
            gateway: Some(gateway),
            general_query: &query,
        };

        let encoded = encode(&message);

        assert_eq!(encoded[0], 0x04);
        assert_eq!(encoded[1], 0x01);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn membership_update_round_trip() {
        let update = [0x46, 0, 0, 28, 0x16, 0];
        let message = Message::MembershipUpdate {
            response_mac: MAC,
            request_nonce: 0x0102_0304,
            membership_update: &update,
        };

        let encoded = encode(&message);

        assert_eq!(encoded[0], 0x05);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn multicast_data_uses_two_byte_shim() {
        let packet = [0x45, 0, 0, 20];
        let message = Message::MulticastData { packet: &packet };

        let encoded = encode(&message);

        assert_eq!(encoded, [0x06, 0, 0x45, 0, 0, 20]);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn teardown_round_trip() {
        let gateway = GatewayEndpoint::new(2268, Ipv6Addr::LOCALHOST);
        let message = Message::Teardown {
            response_mac: MAC,
            request_nonce: 0x99aa_bbcc,
            gateway,
        };

        let encoded = encode(&message);

        assert_eq!(encoded.len(), 30);
        assert_eq!(decode(&encoded), Ok(message));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        assert_eq!(
            decode(&[0x11, 0, 0, 0, 0, 0, 0, 0]),
            Err(DecodeError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn unknown_type_is_rejected() {
        assert_eq!(decode(&[0x08]), Err(DecodeError::UnknownMessageType(8)));
    }

    #[test]
    fn truncated_message_is_rejected() {
        assert_eq!(
            decode(&[0x01, 0]),
            Err(DecodeError::Truncated {
                message_type: Some(MessageType::RelayDiscovery),
                expected_at_least: 8,
                actual: 2,
            })
        );
    }
}
