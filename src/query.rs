use crate::protocol::MembershipProtocol;
use std::net::{Ipv4Addr, Ipv6Addr};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneralQueryConfig {
    pub igmp_source: Ipv4Addr,
    pub mld_source: Ipv6Addr,
    pub max_response_code: u16,
    pub robustness_variable: u8,
    pub query_interval_code: u8,
}

impl Default for GeneralQueryConfig {
    fn default() -> Self {
        Self {
            // RFC 7450 allows 0.0.0.0 and :: as AMT pseudo-interface query
            // sources when no native interface address is available.
            igmp_source: Ipv4Addr::UNSPECIFIED,
            mld_source: Ipv6Addr::UNSPECIFIED,
            max_response_code: 1,
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
    igmp[1] = config.max_response_code.min(u8::MAX.into()) as u8;
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
    mld[4..6].copy_from_slice(&config.max_response_code.to_be_bytes());
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

fn checksum(bytes: &[u8]) -> u16 {
    !ones_complement_sum(bytes)
}

fn icmpv6_checksum(src: &[u8; 16], dst: &[u8; 16], next_header: u8, payload: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + payload.len());
    pseudo_header.extend_from_slice(src);
    pseudo_header.extend_from_slice(dst);
    pseudo_header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo_header.extend_from_slice(payload);
    checksum(&pseudo_header)
}

fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if let [high, low] = chunk {
            u16::from_be_bytes([*high, *low])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }

    sum as u16
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
}
