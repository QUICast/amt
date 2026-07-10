use crate::checksum::{checksum, icmpv6_checksum, ones_complement_sum};
use crate::ip::{has_ipv4_router_alert, has_ipv6_router_alert};
use crate::protocol::MembershipProtocol;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

const IPV4_HEADER_LEN: usize = 24;
const IGMPV3_QUERY_LEN: usize = 12;
const IPV6_HEADER_LEN: usize = 40;
const IPV6_HOP_BY_HOP_LEN: usize = 8;
const MLDV2_QUERY_LEN: usize = 28;

const IGMP_PROTOCOL: u8 = 2;
const ICMPV6_NEXT_HEADER: u8 = 58;
const HOP_BY_HOP_NEXT_HEADER: u8 = 0;

const IGMP_MEMBERSHIP_QUERY: u8 = 0x11;
const MLD_LISTENER_QUERY: u8 = 130;

const ALL_SYSTEMS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
const ALL_NODES_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const IPV4_FRAGMENT_MASK: u16 = 0x3fff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralQueryConfig {
    pub igmp_source: Ipv4Addr,
    pub mld_source: Ipv6Addr,
    pub igmp_max_response_code: u8,
    pub mld_max_response_code: u16,
    pub robustness_variable: u8,
    pub query_interval_code: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryValidationError {
    Truncated,
    WrongAddressFamily,
    InvalidLength,
    InvalidHeader,
    InvalidChecksum,
    InvalidSource,
    NotGeneralQuery,
}

impl fmt::Display for QueryValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated General Query"),
            Self::WrongAddressFamily => {
                f.write_str("General Query address family does not match P flag")
            }
            Self::InvalidLength => f.write_str("invalid General Query packet length"),
            Self::InvalidHeader => f.write_str("invalid General Query IP header"),
            Self::InvalidChecksum => f.write_str("invalid General Query checksum"),
            Self::InvalidSource => f.write_str("invalid General Query source address"),
            Self::NotGeneralQuery => f.write_str("encapsulated packet is not a General Query"),
        }
    }
}

impl std::error::Error for QueryValidationError {}

impl Default for GeneralQueryConfig {
    fn default() -> Self {
        Self {
            // RFC 7450 allows 0.0.0.0 and :: as AMT pseudo-interface query
            // sources when no native interface address is available.
            igmp_source: Ipv4Addr::UNSPECIFIED,
            mld_source: Ipv6Addr::UNSPECIFIED,
            // IGMP encodes values below 128 in tenths of a second; MLD uses
            // milliseconds. Both defaults therefore describe 10 seconds.
            igmp_max_response_code: 100,
            mld_max_response_code: 10_000,
            robustness_variable: 2,
            query_interval_code: 125,
        }
    }
}

pub fn build_general_query(protocol: MembershipProtocol, config: &GeneralQueryConfig) -> Vec<u8> {
    match protocol {
        MembershipProtocol::Igmpv3 => build_igmpv3_general_query(config),
        MembershipProtocol::Mldv2 => build_mldv2_general_query(config),
    }
}

pub fn validate_general_query(
    protocol: MembershipProtocol,
    packet: &[u8],
) -> Result<(), QueryValidationError> {
    general_query_interval(protocol, packet).map(|_| ())
}

pub fn general_query_interval(
    protocol: MembershipProtocol,
    packet: &[u8],
) -> Result<Duration, QueryValidationError> {
    match protocol {
        MembershipProtocol::Igmpv3 => validate_igmpv3_general_query(packet),
        MembershipProtocol::Mldv2 => validate_mldv2_general_query(packet),
    }
    .map(query_interval)
}

pub fn query_interval(code: u8) -> Duration {
    let seconds = if code < 128 {
        u64::from(code)
    } else {
        let mantissa = u64::from((code & 0x0f) | 0x10);
        let exponent = u32::from((code >> 4) & 0x07) + 3;
        mantissa << exponent
    };
    Duration::from_secs(seconds)
}

pub fn encode_query_interval(interval: Duration) -> u8 {
    let seconds = interval.as_secs();
    if seconds < 128 {
        return seconds as u8;
    }
    for exponent in 0u8..=7 {
        for mantissa in 0u8..=15 {
            let code = 0x80 | (exponent << 4) | mantissa;
            if query_interval(code).as_secs() >= seconds {
                return code;
            }
        }
    }
    u8::MAX
}

fn validate_igmpv3_general_query(packet: &[u8]) -> Result<u8, QueryValidationError> {
    if packet.first().ok_or(QueryValidationError::Truncated)? >> 4 != 4 {
        return Err(QueryValidationError::WrongAddressFamily);
    }
    if packet.len() < IPV4_HEADER_LEN + IGMPV3_QUERY_LEN {
        return Err(QueryValidationError::Truncated);
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < IPV4_HEADER_LEN || ihl > packet.len() {
        return Err(QueryValidationError::InvalidHeader);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() || total_len != ihl + IGMPV3_QUERY_LEN {
        return Err(QueryValidationError::InvalidLength);
    }
    if packet[8] != 1
        || packet[9] != IGMP_PROTOCOL
        || u16::from_be_bytes([packet[6], packet[7]]) & IPV4_FRAGMENT_MASK != 0
        || packet[16..20] != ALL_SYSTEMS_V4.octets()
        || !has_ipv4_router_alert(&packet[20..ihl])
    {
        return Err(QueryValidationError::InvalidHeader);
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    if source.is_multicast() || source.is_broadcast() {
        return Err(QueryValidationError::InvalidSource);
    }
    if ones_complement_sum(&packet[..ihl]) != 0xffff {
        return Err(QueryValidationError::InvalidChecksum);
    }

    let igmp = &packet[ihl..];
    if igmp[0] != IGMP_MEMBERSHIP_QUERY
        || igmp[4..8] != [0; 4]
        || u16::from_be_bytes([igmp[10], igmp[11]]) != 0
    {
        return Err(QueryValidationError::NotGeneralQuery);
    }
    if ones_complement_sum(igmp) != 0xffff {
        return Err(QueryValidationError::InvalidChecksum);
    }
    Ok(igmp[9])
}

fn validate_mldv2_general_query(packet: &[u8]) -> Result<u8, QueryValidationError> {
    if packet.first().ok_or(QueryValidationError::Truncated)? >> 4 != 6 {
        return Err(QueryValidationError::WrongAddressFamily);
    }
    if packet.len() < IPV6_HEADER_LEN + IPV6_HOP_BY_HOP_LEN + MLDV2_QUERY_LEN {
        return Err(QueryValidationError::Truncated);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if IPV6_HEADER_LEN + payload_len != packet.len()
        || payload_len != IPV6_HOP_BY_HOP_LEN + MLDV2_QUERY_LEN
    {
        return Err(QueryValidationError::InvalidLength);
    }
    if packet[6] != HOP_BY_HOP_NEXT_HEADER
        || packet[7] != 1
        || packet[24..40] != ALL_NODES_V6.octets()
        || packet[40] != ICMPV6_NEXT_HEADER
        || !has_ipv6_router_alert(&packet[42..48])
    {
        return Err(QueryValidationError::InvalidHeader);
    }
    let source = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[8..24]).map_err(|_| QueryValidationError::Truncated)?,
    );
    if source.is_multicast() {
        return Err(QueryValidationError::InvalidSource);
    }

    let mld = &packet[IPV6_HEADER_LEN + IPV6_HOP_BY_HOP_LEN..];
    if mld[0] != MLD_LISTENER_QUERY
        || mld[1] != 0
        || mld[8..24] != [0; 16]
        || u16::from_be_bytes([mld[26], mld[27]]) != 0
    {
        return Err(QueryValidationError::NotGeneralQuery);
    }
    let destination = ALL_NODES_V6.octets();
    if icmpv6_checksum(&source.octets(), &destination, ICMPV6_NEXT_HEADER, mld) != 0 {
        return Err(QueryValidationError::InvalidChecksum);
    }
    Ok(mld[25])
}

pub fn build_igmpv3_general_query(config: &GeneralQueryConfig) -> Vec<u8> {
    let total_len = IPV4_HEADER_LEN + IGMPV3_QUERY_LEN;
    let mut packet = vec![0; total_len];

    packet[0] = 0x46; // IPv4, 24-byte header because Router Alert is present.
    packet[1] = 0xc0; // Internet Control precedence.
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 1; // Queries are link-local.
    packet[9] = IGMP_PROTOCOL;
    packet[12..16].copy_from_slice(&config.igmp_source.octets());
    packet[16..20].copy_from_slice(&ALL_SYSTEMS_V4.octets());
    packet[20..24].copy_from_slice(&[0x94, 0x04, 0x00, 0x00]); // Router Alert.

    let igmp = &mut packet[IPV4_HEADER_LEN..];
    igmp[0] = IGMP_MEMBERSHIP_QUERY;
    igmp[1] = config.igmp_max_response_code;
    igmp[8] = config.robustness_variable & 0x07;
    igmp[9] = config.query_interval_code;
    let igmp_checksum = checksum(igmp);
    igmp[2..4].copy_from_slice(&igmp_checksum.to_be_bytes());

    let header_checksum = checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    packet
}

pub fn build_mldv2_general_query(config: &GeneralQueryConfig) -> Vec<u8> {
    let payload_len = IPV6_HOP_BY_HOP_LEN + MLDV2_QUERY_LEN;
    let total_len = IPV6_HEADER_LEN + payload_len;
    let mut packet = vec![0; total_len];

    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    packet[6] = HOP_BY_HOP_NEXT_HEADER;
    packet[7] = 1; // Hop limit required by MLD.
    packet[8..24].copy_from_slice(&config.mld_source.octets());
    packet[24..40].copy_from_slice(&ALL_NODES_V6.octets());

    let hop_by_hop = &mut packet[IPV6_HEADER_LEN..IPV6_HEADER_LEN + IPV6_HOP_BY_HOP_LEN];
    hop_by_hop.copy_from_slice(&[ICMPV6_NEXT_HEADER, 0, 5, 2, 0, 0, 1, 0]);

    let mld_offset = IPV6_HEADER_LEN + IPV6_HOP_BY_HOP_LEN;
    let mld = &mut packet[mld_offset..];
    mld[0] = MLD_LISTENER_QUERY;
    mld[4..6].copy_from_slice(&config.mld_max_response_code.to_be_bytes());
    mld[24] = config.robustness_variable & 0x07;
    mld[25] = config.query_interval_code;

    let mld_checksum = icmpv6_checksum(
        &config.mld_source.octets(),
        &ALL_NODES_V6.octets(),
        ICMPV6_NEXT_HEADER,
        mld,
    );
    packet[mld_offset + 2..mld_offset + 4].copy_from_slice(&mld_checksum.to_be_bytes());

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_igmpv3_general_query_ip_datagram() {
        let packet = build_igmpv3_general_query(&GeneralQueryConfig::default());

        assert_eq!(packet.len(), 36);
        assert_eq!(packet[0], 0x46);
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 36);
        assert_eq!(packet[8], 1);
        assert_eq!(packet[9], IGMP_PROTOCOL);
        assert_eq!(&packet[16..20], &ALL_SYSTEMS_V4.octets());
        assert_eq!(&packet[20..24], &[0x94, 0x04, 0x00, 0x00]);
        assert_eq!(ones_complement_sum(&packet[..IPV4_HEADER_LEN]), 0xffff);

        let igmp = &packet[IPV4_HEADER_LEN..];
        assert_eq!(igmp[0], IGMP_MEMBERSHIP_QUERY);
        assert_eq!(igmp[1], 100);
        assert_eq!(&igmp[4..8], &[0, 0, 0, 0]);
        assert_eq!(u16::from_be_bytes([igmp[10], igmp[11]]), 0);
        assert_eq!(ones_complement_sum(igmp), 0xffff);
    }

    #[test]
    fn builds_mldv2_general_query_ip_datagram() {
        let packet = build_mldv2_general_query(&GeneralQueryConfig::default());

        assert_eq!(packet.len(), 76);
        assert_eq!(packet[0], 0x60);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 36);
        assert_eq!(packet[6], HOP_BY_HOP_NEXT_HEADER);
        assert_eq!(packet[7], 1);
        assert_eq!(&packet[24..40], &ALL_NODES_V6.octets());
        assert_eq!(&packet[40..48], &[ICMPV6_NEXT_HEADER, 0, 5, 2, 0, 0, 1, 0]);

        let mld = &packet[48..];
        assert_eq!(mld[0], MLD_LISTENER_QUERY);
        assert_eq!(u16::from_be_bytes([mld[4], mld[5]]), 10_000);
        assert_eq!(&mld[8..24], &[0; 16]);
        assert_eq!(u16::from_be_bytes([mld[26], mld[27]]), 0);

        let mut pseudo_header = Vec::new();
        pseudo_header.extend_from_slice(&Ipv6Addr::UNSPECIFIED.octets());
        pseudo_header.extend_from_slice(&ALL_NODES_V6.octets());
        pseudo_header.extend_from_slice(&(MLDV2_QUERY_LEN as u32).to_be_bytes());
        pseudo_header.extend_from_slice(&[0, 0, 0, ICMPV6_NEXT_HEADER]);
        pseudo_header.extend_from_slice(mld);
        assert_eq!(ones_complement_sum(&pseudo_header), 0xffff);
    }

    #[test]
    fn validates_built_queries_and_rejects_wrong_family() {
        let igmp = build_general_query(MembershipProtocol::Igmpv3, &GeneralQueryConfig::default());
        let mld = build_general_query(MembershipProtocol::Mldv2, &GeneralQueryConfig::default());

        assert_eq!(
            validate_general_query(MembershipProtocol::Igmpv3, &igmp),
            Ok(())
        );
        assert_eq!(
            validate_general_query(MembershipProtocol::Mldv2, &mld),
            Ok(())
        );
        assert_eq!(
            validate_general_query(MembershipProtocol::Mldv2, &igmp),
            Err(QueryValidationError::WrongAddressFamily)
        );
    }

    #[test]
    fn rejects_query_without_link_local_hop_limit() {
        let mut query =
            build_general_query(MembershipProtocol::Igmpv3, &GeneralQueryConfig::default());
        query[8] = 2;

        assert_eq!(
            validate_general_query(MembershipProtocol::Igmpv3, &query),
            Err(QueryValidationError::InvalidHeader)
        );
    }

    #[test]
    fn accepts_global_unicast_mld_query_source() {
        let config = GeneralQueryConfig {
            mld_source: "2001:db8::1".parse().unwrap(),
            ..GeneralQueryConfig::default()
        };
        let query = build_general_query(MembershipProtocol::Mldv2, &config);

        assert_eq!(
            validate_general_query(MembershipProtocol::Mldv2, &query),
            Ok(())
        );
    }

    #[test]
    fn decodes_query_interval_code() {
        assert_eq!(query_interval(125), Duration::from_secs(125));
        assert_eq!(query_interval(0x80), Duration::from_secs(128));
        assert_eq!(query_interval(0xff), Duration::from_secs(31_744));
        assert_eq!(encode_query_interval(Duration::from_secs(125)), 125);
        assert_eq!(
            query_interval(encode_query_interval(Duration::from_secs(300))),
            Duration::from_secs(304)
        );
        assert_eq!(encode_query_interval(Duration::from_secs(40_000)), u8::MAX);
    }
}
