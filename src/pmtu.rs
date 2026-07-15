//! RFC 7450 Path MTU feedback for oversized SSM multicast datagrams.

use crate::checksum::{checksum, icmpv6_checksum};
use crate::ip::{IpPacketError, MulticastPacket, parse_multicast_packet};
use mctx_core::{MctxError, RawIpContext, RawIpPublicationId, RawIpSocketConfig};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const ICMP_HEADER_LEN: usize = 8;
const IPV4_MIN_REASSEMBLY_MTU: usize = 576;
const IPV6_MIN_MTU: usize = 1_280;
const ICMPV4_PROTOCOL: u8 = 1;
const ICMPV6_PROTOCOL: u8 = 58;
const DEFAULT_FEEDBACK_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_TRACKED_FLOWS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtuFeedbackOutcome {
    Sent { bytes_sent: usize },
    RateLimited,
    Suppressed,
    AddressFamilyUnavailable,
}

#[derive(Debug)]
pub enum PmtuFeedbackError {
    InvalidPacket(IpPacketError),
    InvalidLocalAddress(IpAddr),
    InvalidMtu(usize),
    Transport(MctxError),
}

impl fmt::Display for PmtuFeedbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPacket(error) => write!(f, "invalid PMTU invoking packet: {error}"),
            Self::InvalidLocalAddress(address) => {
                write!(f, "invalid PMTU feedback source address {address}")
            }
            Self::InvalidMtu(mtu) => write!(f, "invalid AMT tunnel MTU {mtu}"),
            Self::Transport(error) => write!(f, "failed to send PMTU feedback: {error}"),
        }
    }
}

impl std::error::Error for PmtuFeedbackError {}

impl From<IpPacketError> for PmtuFeedbackError {
    fn from(value: IpPacketError) -> Self {
        Self::InvalidPacket(value)
    }
}

impl From<MctxError> for PmtuFeedbackError {
    fn from(value: MctxError) -> Self {
        Self::Transport(value)
    }
}

#[derive(Debug)]
pub struct PmtuFeedbackSender {
    context: RawIpContext,
    publication: RawIpPublicationId,
    local_address: IpAddr,
    limiter: FeedbackRateLimiter,
}

#[derive(Debug)]
struct FeedbackRateLimiter {
    last_feedback: BTreeMap<(IpAddr, IpAddr), Instant>,
    expirations: VecDeque<((IpAddr, IpAddr), Instant)>,
    minimum_interval: Duration,
    max_tracked_flows: usize,
}

impl FeedbackRateLimiter {
    fn new(minimum_interval: Duration, max_tracked_flows: usize) -> Self {
        Self {
            last_feedback: BTreeMap::new(),
            expirations: VecDeque::new(),
            minimum_interval,
            max_tracked_flows,
        }
    }

    fn allow(&mut self, source: IpAddr, group: IpAddr) -> bool {
        let now = Instant::now();
        while let Some(&(key, observed)) = self.expirations.front() {
            let expired = now
                .checked_duration_since(observed)
                .is_some_and(|elapsed| elapsed >= self.minimum_interval);
            if !expired {
                break;
            }
            self.expirations.pop_front();
            if self.last_feedback.get(&key) == Some(&observed) {
                self.last_feedback.remove(&key);
            }
        }

        let key = (source, group);
        if self.last_feedback.contains_key(&key)
            || self.last_feedback.len() >= self.max_tracked_flows
        {
            return false;
        }
        self.last_feedback.insert(key, now);
        self.expirations.push_back((key, now));
        true
    }
}

impl PmtuFeedbackSender {
    pub fn new(
        local_address: IpAddr,
        interface_index: Option<u32>,
    ) -> Result<Self, PmtuFeedbackError> {
        if local_address.is_unspecified() || local_address.is_multicast() {
            return Err(PmtuFeedbackError::InvalidLocalAddress(local_address));
        }

        let mut config = match local_address {
            IpAddr::V4(address) => RawIpSocketConfig::ipv4()
                .with_bind_addr(address)
                .with_interface_addr(address),
            IpAddr::V6(address) => RawIpSocketConfig::ipv6()
                .with_bind_addr(address)
                .with_interface_addr(address),
        };
        if let Some(interface_index) = interface_index {
            config = config.with_interface_index(interface_index);
        }

        let mut context = RawIpContext::new();
        let publication = context.add_publication(config)?;
        Ok(Self {
            context,
            publication,
            local_address,
            limiter: FeedbackRateLimiter::new(DEFAULT_FEEDBACK_INTERVAL, DEFAULT_TRACKED_FLOWS),
        })
    }

    pub const fn local_address(&self) -> IpAddr {
        self.local_address
    }

    pub fn send(
        &mut self,
        invoking_packet: &[u8],
        tunnel_mtu: usize,
    ) -> Result<PmtuFeedbackOutcome, PmtuFeedbackError> {
        let parsed = parse_multicast_packet(invoking_packet)?;
        if !same_family(self.local_address, parsed.source) {
            return Ok(PmtuFeedbackOutcome::AddressFamilyUnavailable);
        }
        if suppress_icmp_error(invoking_packet, parsed) {
            return Ok(PmtuFeedbackOutcome::Suppressed);
        }
        if !self.limiter.allow(parsed.source, parsed.group) {
            return Ok(PmtuFeedbackOutcome::RateLimited);
        }

        let feedback = build_pmtu_feedback(self.local_address, invoking_packet, tunnel_mtu)?;
        let report = self.context.send_ip_datagram(self.publication, &feedback)?;
        Ok(PmtuFeedbackOutcome::Sent {
            bytes_sent: report.bytes_sent,
        })
    }
}

pub fn build_pmtu_feedback(
    local_address: IpAddr,
    invoking_packet: &[u8],
    tunnel_mtu: usize,
) -> Result<Vec<u8>, PmtuFeedbackError> {
    let parsed = parse_multicast_packet(invoking_packet)?;
    match (local_address, parsed.source) {
        (IpAddr::V4(local), IpAddr::V4(source)) => {
            build_icmpv4_fragmentation_needed(local, source, invoking_packet, tunnel_mtu)
        }
        (IpAddr::V6(local), IpAddr::V6(source)) => {
            build_icmpv6_packet_too_big(local, source, invoking_packet, tunnel_mtu)
        }
        _ => Err(PmtuFeedbackError::InvalidLocalAddress(local_address)),
    }
}

fn build_icmpv4_fragmentation_needed(
    local: Ipv4Addr,
    destination: Ipv4Addr,
    invoking_packet: &[u8],
    tunnel_mtu: usize,
) -> Result<Vec<u8>, PmtuFeedbackError> {
    let mtu = u16::try_from(tunnel_mtu).map_err(|_| PmtuFeedbackError::InvalidMtu(tunnel_mtu))?;
    let max_quote = IPV4_MIN_REASSEMBLY_MTU - IPV4_HEADER_LEN - ICMP_HEADER_LEN;
    let quote_len = invoking_packet.len().min(max_quote);
    let total_len = IPV4_HEADER_LEN + ICMP_HEADER_LEN + quote_len;
    let mut packet = vec![0u8; total_len];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = ICMPV4_PROTOCOL;
    packet[12..16].copy_from_slice(&local.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20] = 3;
    packet[21] = 4;
    packet[26..28].copy_from_slice(&mtu.to_be_bytes());
    packet[28..].copy_from_slice(&invoking_packet[..quote_len]);

    let icmp_checksum = checksum(&packet[IPV4_HEADER_LEN..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    let header_checksum = checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    Ok(packet)
}

fn build_icmpv6_packet_too_big(
    local: Ipv6Addr,
    destination: Ipv6Addr,
    invoking_packet: &[u8],
    tunnel_mtu: usize,
) -> Result<Vec<u8>, PmtuFeedbackError> {
    let mtu = u32::try_from(tunnel_mtu).map_err(|_| PmtuFeedbackError::InvalidMtu(tunnel_mtu))?;
    let max_quote = IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMP_HEADER_LEN;
    let quote_len = invoking_packet.len().min(max_quote);
    let payload_len = ICMP_HEADER_LEN + quote_len;
    let mut packet = vec![0u8; IPV6_HEADER_LEN + payload_len];

    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    packet[6] = ICMPV6_PROTOCOL;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&local.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40] = 2;
    packet[44..48].copy_from_slice(&mtu.to_be_bytes());
    packet[48..].copy_from_slice(&invoking_packet[..quote_len]);

    let icmp_checksum = icmpv6_checksum(
        &local.octets(),
        &destination.octets(),
        ICMPV6_PROTOCOL,
        &packet[IPV6_HEADER_LEN..],
    );
    packet[42..44].copy_from_slice(&icmp_checksum.to_be_bytes());
    Ok(packet)
}

fn suppress_icmp_error(packet: &[u8], parsed: MulticastPacket) -> bool {
    match parsed.source {
        IpAddr::V4(_) if parsed.ip_protocol == ICMPV4_PROTOCOL => {
            if parsed.fragmented {
                return true;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            packet
                .get(header_len)
                .is_some_and(|kind| matches!(*kind, 3 | 4 | 5 | 11 | 12))
        }
        IpAddr::V6(_) => ipv6_upper_layer(packet).is_none_or(|(protocol, offset)| {
            protocol == ICMPV6_PROTOCOL && packet.get(offset).is_none_or(|kind| *kind < 128)
        }),
        _ => false,
    }
}

fn ipv6_upper_layer(packet: &[u8]) -> Option<(u8, usize)> {
    let mut next_header = *packet.get(6)?;
    let mut offset = IPV6_HEADER_LEN;

    for _ in 0..16 {
        match next_header {
            0 | 43 | 60 => {
                next_header = *packet.get(offset)?;
                let header_len = (usize::from(*packet.get(offset + 1)?) + 1).checked_mul(8)?;
                offset = offset.checked_add(header_len)?;
            }
            44 => {
                next_header = *packet.get(offset)?;
                let fragment =
                    u16::from_be_bytes([*packet.get(offset + 2)?, *packet.get(offset + 3)?]);
                if fragment & 0xfff8 != 0 {
                    return None;
                }
                offset = offset.checked_add(8)?;
            }
            51 => {
                next_header = *packet.get(offset)?;
                let header_len = (usize::from(*packet.get(offset + 1)?) + 2).checked_mul(4)?;
                offset = offset.checked_add(header_len)?;
            }
            _ => return (offset <= packet.len()).then_some((next_header, offset)),
        }

        if offset > packet.len() {
            return None;
        }
    }

    None
}

const fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::ones_complement_sum;

    fn ipv4_multicast(payload_len: usize, protocol: u8) -> Vec<u8> {
        let total_len = IPV4_HEADER_LEN + payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 16;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[232, 1, 2, 3]);
        let header_checksum = checksum(&packet[..IPV4_HEADER_LEN]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    fn ipv6_multicast(payload_len: usize, next_header: u8) -> Vec<u8> {
        let mut packet = vec![0u8; IPV6_HEADER_LEN + payload_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 16;
        packet[8..24].copy_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
        packet[24..40].copy_from_slice(&"ff3e::1234".parse::<Ipv6Addr>().unwrap().octets());
        packet
    }

    #[test]
    fn builds_valid_icmpv4_fragmentation_needed_with_bounded_quote() {
        let invoking = ipv4_multicast(1_480, 17);
        let packet =
            build_pmtu_feedback(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), &invoking, 1_230).unwrap();

        assert_eq!(packet.len(), IPV4_MIN_REASSEMBLY_MTU);
        assert_eq!(&packet[16..20], &[192, 0, 2, 10]);
        assert_eq!(&packet[20..22], &[3, 4]);
        assert_eq!(u16::from_be_bytes([packet[26], packet[27]]), 1_230);
        assert_eq!(ones_complement_sum(&packet[..20]), 0xffff);
        assert_eq!(ones_complement_sum(&packet[20..]), 0xffff);
        assert_eq!(&packet[28..48], &invoking[..20]);
    }

    #[test]
    fn builds_valid_icmpv6_packet_too_big_with_bounded_quote() {
        let invoking = ipv6_multicast(1_300, 17);
        let local = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let source = "2001:db8::10".parse::<Ipv6Addr>().unwrap();
        let packet = build_pmtu_feedback(IpAddr::V6(local), &invoking, 1_210).unwrap();

        assert_eq!(packet.len(), IPV6_MIN_MTU);
        assert_eq!(&packet[24..40], &source.octets());
        assert_eq!(&packet[40..42], &[2, 0]);
        assert_eq!(
            u32::from_be_bytes(packet[44..48].try_into().unwrap()),
            1_210
        );
        assert_eq!(
            icmpv6_checksum(
                &local.octets(),
                &source.octets(),
                ICMPV6_PROTOCOL,
                &packet[40..]
            ),
            0
        );
        assert_eq!(&packet[48..88], &invoking[..40]);
    }

    #[test]
    fn suppresses_icmp_error_responses() {
        let mut ipv4 = ipv4_multicast(8, ICMPV4_PROTOCOL);
        ipv4[20] = 3;
        let parsed = parse_multicast_packet(&ipv4).unwrap();
        assert!(suppress_icmp_error(&ipv4, parsed));

        let mut fragmented_ipv4 = ipv4_multicast(8, ICMPV4_PROTOCOL);
        fragmented_ipv4[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        fragmented_ipv4[10..12].fill(0);
        let header_checksum = checksum(&fragmented_ipv4[..IPV4_HEADER_LEN]);
        fragmented_ipv4[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        let parsed = parse_multicast_packet(&fragmented_ipv4).unwrap();
        assert!(suppress_icmp_error(&fragmented_ipv4, parsed));

        let mut ipv6 = ipv6_multicast(8, ICMPV6_PROTOCOL);
        ipv6[40] = 2;
        let parsed = parse_multicast_packet(&ipv6).unwrap();
        assert!(suppress_icmp_error(&ipv6, parsed));

        let mut extended_ipv6 = ipv6_multicast(16, 0);
        extended_ipv6[40] = ICMPV6_PROTOCOL;
        extended_ipv6[41] = 0;
        extended_ipv6[48] = 2;
        let parsed = parse_multicast_packet(&extended_ipv6).unwrap();
        assert!(suppress_icmp_error(&extended_ipv6, parsed));

        let udp = ipv6_multicast(8, 17);
        let parsed = parse_multicast_packet(&udp).unwrap();
        assert!(!suppress_icmp_error(&udp, parsed));
    }

    #[test]
    fn feedback_rate_limiter_bounds_flows_and_repeats() {
        let first_source = "192.0.2.10".parse().unwrap();
        let second_source = "192.0.2.11".parse().unwrap();
        let group = "232.1.2.3".parse().unwrap();
        let mut limiter = FeedbackRateLimiter::new(Duration::from_secs(60), 1);

        assert!(limiter.allow(first_source, group));
        assert!(!limiter.allow(first_source, group));
        assert!(!limiter.allow(second_source, group));

        let mut expiring = FeedbackRateLimiter::new(Duration::ZERO, 1);
        assert!(expiring.allow(first_source, group));
        assert!(expiring.allow(second_source, group));
    }
}
