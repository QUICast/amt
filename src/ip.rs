use crate::checksum::ones_complement_sum;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IPV4_FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
const IPV4_MORE_FRAGMENTS: u16 = 0x2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MulticastPacket {
    pub source: IpAddr,
    pub group: IpAddr,
    pub ip_protocol: u8,
    pub datagram_len: usize,
    pub fragmented: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPacketError {
    Truncated,
    UnsupportedVersion(u8),
    InvalidHeader,
    InvalidLength,
    InvalidChecksum,
    InvalidSource(IpAddr),
    NonMulticastDestination(IpAddr),
}

impl fmt::Display for IpPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated IP packet"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported IP version {version}"),
            Self::InvalidHeader => f.write_str("invalid IP header"),
            Self::InvalidLength => f.write_str("invalid IP packet length"),
            Self::InvalidChecksum => f.write_str("invalid IPv4 header checksum"),
            Self::InvalidSource(source) => write!(f, "invalid multicast source address {source}"),
            Self::NonMulticastDestination(destination) => {
                write!(f, "IP destination {destination} is not multicast")
            }
        }
    }
}

impl std::error::Error for IpPacketError {}

pub fn parse_multicast_packet(datagram: &[u8]) -> Result<MulticastPacket, IpPacketError> {
    let version = datagram.first().ok_or(IpPacketError::Truncated)? >> 4;
    match version {
        4 => parse_ipv4(datagram),
        6 => parse_ipv6(datagram),
        version => Err(IpPacketError::UnsupportedVersion(version)),
    }
}

pub fn is_amt_forwardable_group(group: IpAddr) -> bool {
    match group {
        IpAddr::V4(group) => group.is_multicast() && group.octets()[..3] != [224, 0, 0],
        IpAddr::V6(group) => {
            let scope = group.segments()[0] & 0x000f;
            group.is_multicast() && (3..15).contains(&scope)
        }
    }
}

pub(crate) fn has_ipv4_router_alert(options: &[u8]) -> bool {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => return false,
            1 => offset += 1,
            kind => {
                let Some(&length) = options.get(offset + 1) else {
                    return false;
                };
                let length = usize::from(length);
                if length < 2 || offset + length > options.len() {
                    return false;
                }
                if kind == 0x94 && length == 4 && options[offset + 2..offset + 4] == [0, 0] {
                    return true;
                }
                offset += length;
            }
        }
    }
    false
}

pub(crate) fn has_ipv6_router_alert(options: &[u8]) -> bool {
    let mut offset = 0;
    while offset < options.len() {
        if options[offset] == 0 {
            offset += 1;
            continue;
        }
        let Some(&length) = options.get(offset + 1) else {
            return false;
        };
        let option_end = offset + 2 + usize::from(length);
        if option_end > options.len() {
            return false;
        }
        if options[offset] == 5 && length == 2 && options[offset + 2..option_end] == [0, 0] {
            return true;
        }
        offset = option_end;
    }
    false
}

fn parse_ipv4(datagram: &[u8]) -> Result<MulticastPacket, IpPacketError> {
    if datagram.len() < IPV4_MIN_HEADER_LEN {
        return Err(IpPacketError::Truncated);
    }

    let ihl = usize::from(datagram[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || ihl > datagram.len() {
        return Err(IpPacketError::InvalidHeader);
    }
    let total_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if total_len < ihl || total_len != datagram.len() {
        return Err(IpPacketError::InvalidLength);
    }
    if ones_complement_sum(&datagram[..ihl]) != 0xffff {
        return Err(IpPacketError::InvalidChecksum);
    }

    let source = IpAddr::V4(Ipv4Addr::new(
        datagram[12],
        datagram[13],
        datagram[14],
        datagram[15],
    ));
    let group = IpAddr::V4(Ipv4Addr::new(
        datagram[16],
        datagram[17],
        datagram[18],
        datagram[19],
    ));
    validate_addresses(source, group)?;

    let fragment = u16::from_be_bytes([datagram[6], datagram[7]]);
    Ok(MulticastPacket {
        source,
        group,
        ip_protocol: datagram[9],
        datagram_len: total_len,
        fragmented: fragment & (IPV4_MORE_FRAGMENTS | IPV4_FRAGMENT_OFFSET_MASK) != 0,
    })
}

fn parse_ipv6(datagram: &[u8]) -> Result<MulticastPacket, IpPacketError> {
    if datagram.len() < IPV6_HEADER_LEN {
        return Err(IpPacketError::Truncated);
    }

    let payload_len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    let total_len = IPV6_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(IpPacketError::InvalidLength)?;
    if total_len != datagram.len() {
        return Err(IpPacketError::InvalidLength);
    }

    let source = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&datagram[8..24]).map_err(|_| IpPacketError::Truncated)?,
    ));
    let group = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&datagram[24..40]).map_err(|_| IpPacketError::Truncated)?,
    ));
    validate_addresses(source, group)?;

    Ok(MulticastPacket {
        source,
        group,
        ip_protocol: datagram[6],
        datagram_len: total_len,
        fragmented: datagram[6] == 44,
    })
}

fn validate_addresses(source: IpAddr, group: IpAddr) -> Result<(), IpPacketError> {
    let invalid_source = match source {
        IpAddr::V4(source) => {
            source.is_unspecified() || source.is_multicast() || source.is_broadcast()
        }
        IpAddr::V6(source) => source.is_unspecified() || source.is_multicast(),
    };
    if invalid_source {
        return Err(IpPacketError::InvalidSource(source));
    }
    if !group.is_multicast() {
        return Err(IpPacketError::NonMulticastDestination(group));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(fragment: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[6..8].copy_from_slice(&fragment.to_be_bytes());
        packet[8] = 16;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[239, 1, 2, 3]);
        let checksum = !ones_complement_sum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    #[test]
    fn parses_fragmented_ipv4_multicast() {
        let packet = ipv4_packet(IPV4_MORE_FRAGMENTS);
        let parsed = parse_multicast_packet(&packet).unwrap();
        assert!(parsed.fragmented);
        assert_eq!(parsed.group, "239.1.2.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rejects_trailing_data_and_bad_checksum() {
        let mut packet = ipv4_packet(0);
        packet.push(0);
        assert_eq!(
            parse_multicast_packet(&packet),
            Err(IpPacketError::InvalidLength)
        );

        let mut packet = ipv4_packet(0);
        packet[8] ^= 1;
        assert_eq!(
            parse_multicast_packet(&packet),
            Err(IpPacketError::InvalidChecksum)
        );
    }

    #[test]
    fn filters_link_local_and_reserved_multicast_scopes() {
        assert!(!is_amt_forwardable_group("224.0.0.22".parse().unwrap()));
        assert!(is_amt_forwardable_group("239.1.2.3".parse().unwrap()));
        assert!(!is_amt_forwardable_group("ff02::1".parse().unwrap()));
        assert!(is_amt_forwardable_group("ff3e::1".parse().unwrap()));
        assert!(!is_amt_forwardable_group("ffff::1".parse().unwrap()));
    }

    #[test]
    fn router_alert_must_start_at_an_option_boundary() {
        assert!(has_ipv4_router_alert(&[0x94, 4, 0, 0]));
        assert!(!has_ipv4_router_alert(&[0x82, 6, 0x94, 4, 0, 0]));
        assert!(has_ipv6_router_alert(&[5, 2, 0, 0, 1, 0]));
        assert!(!has_ipv6_router_alert(&[1, 4, 5, 2, 0, 0]));
    }
}
