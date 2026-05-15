use crate::state::UpstreamSubscription;
use mcrx_core::{
    McrxError, RawContext, RawPacket, RawSubscriptionConfig, SourceFilter, SubscriptionId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub interface: Option<IpAddr>,
    pub interface_index: Option<u32>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamReconcile {
    pub added: usize,
    pub removed: usize,
    pub active: usize,
}

impl UpstreamReconcile {
    pub const fn changed(self) -> bool {
        self.added != 0 || self.removed != 0
    }
}

#[derive(Debug)]
pub struct UpstreamManager {
    config: UpstreamConfig,
    context: RawContext,
    active: BTreeMap<UpstreamSubscription, SubscriptionId>,
}

impl UpstreamManager {
    pub fn new(config: UpstreamConfig) -> Self {
        Self {
            config,
            context: RawContext::new(),
            active: BTreeMap::new(),
        }
    }

    pub const fn config(&self) -> &UpstreamConfig {
        &self.config
    }

    pub fn active_subscriptions(&self) -> impl Iterator<Item = &UpstreamSubscription> {
        self.active.keys()
    }

    pub fn active_subscription_count(&self) -> usize {
        self.active.len()
    }

    pub fn reconcile(
        &mut self,
        subscriptions: impl IntoIterator<Item = UpstreamSubscription>,
    ) -> Result<UpstreamReconcile, McrxError> {
        let desired = subscriptions.into_iter().collect::<BTreeSet<_>>();
        let stale = self
            .active
            .keys()
            .filter(|subscription| !desired.contains(*subscription))
            .cloned()
            .collect::<Vec<_>>();

        let mut removed = 0;
        for subscription in stale {
            let id = self.active[&subscription];
            self.context.leave_subscription(id)?;
            self.context.remove_subscription(id);
            self.active.remove(&subscription);
            removed += 1;
        }

        let mut added = 0;
        for subscription in desired {
            if self.active.contains_key(&subscription) {
                continue;
            }

            let config = self.raw_config_for(&subscription);
            let id = self.context.add_subscription(config)?;
            if let Err(error) = self.context.join_subscription(id) {
                self.context.remove_subscription(id);
                return Err(error);
            }
            self.active.insert(subscription, id);
            added += 1;
        }

        Ok(UpstreamReconcile {
            added,
            removed,
            active: self.active.len(),
        })
    }

    pub fn try_recv(&mut self) -> Result<Option<UpstreamDatagram>, McrxError> {
        while let Some(packet) = self.context.try_recv_any()? {
            if let Some((source, group)) = packet_addresses(&packet) {
                return Ok(Some(UpstreamDatagram {
                    source,
                    group,
                    packet,
                }));
            }
        }

        Ok(None)
    }

    fn raw_config_for(&self, subscription: &UpstreamSubscription) -> RawSubscriptionConfig {
        let source = subscription
            .source
            .map(SourceFilter::Source)
            .unwrap_or(SourceFilter::Any);
        let mut config = RawSubscriptionConfig {
            group: subscription.group,
            source,
            interface: matching_family(self.config.interface, subscription.group),
            interface_index: None,
        };

        if matches!(subscription.group, IpAddr::V6(_)) {
            config.interface_index = self.config.interface_index;
        }

        config
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamDatagram {
    pub source: IpAddr,
    pub group: IpAddr,
    pub packet: RawPacket,
}

impl UpstreamDatagram {
    pub fn datagram(&self) -> &[u8] {
        self.packet.datagram()
    }

    pub fn normalized_datagram(&self) -> Vec<u8> {
        normalize_forwarded_datagram(self.datagram())
    }
}

fn packet_addresses(packet: &RawPacket) -> Option<(IpAddr, IpAddr)> {
    match (packet.source_ip, packet.group) {
        (Some(source), Some(group)) => Some((source, group)),
        _ => parse_datagram_addresses(packet.datagram()),
    }
}

fn parse_datagram_addresses(datagram: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let version = datagram.first()? >> 4;
    match version {
        4 => parse_ipv4_datagram_addresses(datagram),
        6 => parse_ipv6_datagram_addresses(datagram),
        _ => None,
    }
}

fn parse_ipv4_datagram_addresses(datagram: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if datagram.len() < 20 {
        return None;
    }

    let ihl = usize::from(datagram[0] & 0x0f) * 4;
    if ihl < 20 || datagram.len() < ihl {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if total_len < ihl || datagram.len() < total_len {
        return None;
    }

    let source = Ipv4Addr::new(datagram[12], datagram[13], datagram[14], datagram[15]);
    let group = Ipv4Addr::new(datagram[16], datagram[17], datagram[18], datagram[19]);
    Some((source.into(), group.into()))
}

fn parse_ipv6_datagram_addresses(datagram: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if datagram.len() < 40 {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    if datagram.len() < 40 + payload_len {
        return None;
    }

    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&datagram[8..24]).ok()?);
    let group = Ipv6Addr::from(<[u8; 16]>::try_from(&datagram[24..40]).ok()?);
    Some((source.into(), group.into()))
}

fn matching_family(addr: Option<IpAddr>, family: IpAddr) -> Option<IpAddr> {
    match (addr, family) {
        (Some(IpAddr::V4(addr)), IpAddr::V4(_)) => Some(addr.into()),
        (Some(IpAddr::V6(addr)), IpAddr::V6(_)) => Some(addr.into()),
        _ => None,
    }
}

fn normalize_forwarded_datagram(datagram: &[u8]) -> Vec<u8> {
    let version = datagram.first().map(|byte| byte >> 4);
    match version {
        Some(4) => normalize_ipv4_forwarded_datagram(datagram),
        Some(6) => normalize_ipv6_forwarded_datagram(datagram),
        _ => datagram.to_vec(),
    }
}

fn normalize_ipv4_forwarded_datagram(datagram: &[u8]) -> Vec<u8> {
    if datagram.len() < 20 {
        return datagram.to_vec();
    }

    let ihl = usize::from(datagram[0] & 0x0f) * 4;
    if ihl < 20 || datagram.len() < ihl {
        return datagram.to_vec();
    }

    let total_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if total_len < ihl || datagram.len() < total_len {
        return datagram.to_vec();
    }

    let mut normalized = datagram[..total_len].to_vec();
    normalized[10] = 0;
    normalized[11] = 0;
    let header_checksum = internet_checksum(&normalized[..ihl]);
    normalized[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    if normalized[9] == 17 {
        repair_udp_checksum_v4(&mut normalized, ihl);
    }

    normalized
}

fn normalize_ipv6_forwarded_datagram(datagram: &[u8]) -> Vec<u8> {
    if datagram.len() < 40 {
        return datagram.to_vec();
    }

    let payload_len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    let total_len = 40 + payload_len;
    if datagram.len() < total_len {
        return datagram.to_vec();
    }

    let mut normalized = datagram[..total_len].to_vec();
    if normalized[6] == 17 {
        repair_udp_checksum_v6(&mut normalized, 40);
    }

    normalized
}

fn repair_udp_checksum_v4(datagram: &mut [u8], udp_offset: usize) {
    if datagram.len() < udp_offset + 8 {
        return;
    }

    let udp_len = usize::from(u16::from_be_bytes([
        datagram[udp_offset + 4],
        datagram[udp_offset + 5],
    ]));
    if udp_len < 8 || datagram.len() < udp_offset + udp_len {
        return;
    }

    datagram[udp_offset + 6] = 0;
    datagram[udp_offset + 7] = 0;

    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&datagram[12..16]);
    pseudo.extend_from_slice(&datagram[16..20]);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&datagram[udp_offset..udp_offset + udp_len]);

    let checksum = udp_checksum(&pseudo);
    datagram[udp_offset + 6..udp_offset + 8].copy_from_slice(&checksum.to_be_bytes());
}

fn repair_udp_checksum_v6(datagram: &mut [u8], udp_offset: usize) {
    if datagram.len() < udp_offset + 8 {
        return;
    }

    let udp_len = usize::from(u16::from_be_bytes([
        datagram[udp_offset + 4],
        datagram[udp_offset + 5],
    ]));
    if udp_len < 8 || datagram.len() < udp_offset + udp_len {
        return;
    }

    datagram[udp_offset + 6] = 0;
    datagram[udp_offset + 7] = 0;

    let mut pseudo = Vec::with_capacity(40 + udp_len);
    pseudo.extend_from_slice(&datagram[8..24]);
    pseudo.extend_from_slice(&datagram[24..40]);
    pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&datagram[udp_offset..udp_offset + udp_len]);

    let checksum = udp_checksum(&pseudo);
    datagram[udp_offset + 6..udp_offset + 8].copy_from_slice(&checksum.to_be_bytes());
}

fn udp_checksum(bytes: &[u8]) -> u16 {
    match internet_checksum(bytes) {
        0 => 0xffff,
        checksum => checksum,
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    !ones_complement_sum(bytes)
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
    fn parses_ipv4_datagram_addresses() {
        let datagram = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 1, 17, 0, 0, 192, 0, 2, 10, 239, 1, 2, 3,
        ];

        assert_eq!(
            parse_datagram_addresses(&datagram),
            Some((
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3))
            ))
        );
    }

    #[test]
    fn parses_ipv6_datagram_addresses() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let group = Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0x8000, 0x1234);
        let mut datagram = [0; 40];
        datagram[0] = 0x60;
        datagram[8..24].copy_from_slice(&source.octets());
        datagram[24..40].copy_from_slice(&group.octets());

        assert_eq!(
            parse_datagram_addresses(&datagram),
            Some((IpAddr::V6(source), IpAddr::V6(group)))
        );
    }

    #[test]
    fn raw_config_uses_matching_interface_family() {
        let manager = UpstreamManager::new(UpstreamConfig {
            interface: Some(Ipv4Addr::new(192, 0, 2, 20).into()),
            interface_index: Some(7),
        });

        let ipv4 = manager.raw_config_for(&UpstreamSubscription::asm(IpAddr::V4(Ipv4Addr::new(
            239, 1, 2, 3,
        ))));
        let ipv6 = manager.raw_config_for(&UpstreamSubscription::asm(IpAddr::V6(Ipv6Addr::new(
            0xff3e, 0, 0, 0, 0, 0, 0x8000, 0x1234,
        ))));

        assert_eq!(ipv4.interface, Some(Ipv4Addr::new(192, 0, 2, 20).into()));
        assert_eq!(ipv4.interface_index, None);
        assert_eq!(ipv6.interface, None);
        assert_eq!(ipv6.interface_index, Some(7));
    }

    #[test]
    fn normalizes_ipv4_udp_checksum_for_forwarding() {
        let mut datagram = vec![
            0x45, 0, 0, 33, 0x12, 0x34, 0, 0, 1, 17, 0xaa, 0xbb, 192, 0, 2, 10, 239, 1, 2, 3, 12,
            34, 0x13, 0x88, 0, 13, 0xcc, 0xdd, b'h', b'e', b'l', b'l', b'o',
        ];
        let checksum = internet_checksum(&datagram[..20]);
        datagram[10..12].copy_from_slice(&checksum.to_be_bytes());

        let normalized = normalize_forwarded_datagram(&datagram);

        assert_eq!(normalized.len(), 33);
        assert_eq!(ones_complement_sum(&normalized[..20]), 0xffff);
        assert_ne!(&normalized[26..28], &[0xcc, 0xdd]);
        assert_eq!(udp_v4_sum(&normalized), 0xffff);
    }

    #[test]
    fn normalizes_ipv6_udp_checksum_for_forwarding() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let group = Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0x8000, 0x1234);
        let mut datagram = vec![0; 40 + 8 + 5];
        datagram[0] = 0x60;
        datagram[4..6].copy_from_slice(&13u16.to_be_bytes());
        datagram[6] = 17;
        datagram[7] = 1;
        datagram[8..24].copy_from_slice(&source.octets());
        datagram[24..40].copy_from_slice(&group.octets());
        datagram[40..42].copy_from_slice(&12u16.to_be_bytes());
        datagram[42..44].copy_from_slice(&5000u16.to_be_bytes());
        datagram[44..46].copy_from_slice(&13u16.to_be_bytes());
        datagram[46..48].copy_from_slice(&[0xcc, 0xdd]);
        datagram[48..].copy_from_slice(b"hello");

        let normalized = normalize_forwarded_datagram(&datagram);

        assert_eq!(normalized.len(), 53);
        assert_ne!(&normalized[46..48], &[0xcc, 0xdd]);
        assert_eq!(udp_v6_sum(&normalized), 0xffff);
    }

    fn udp_v4_sum(datagram: &[u8]) -> u16 {
        let ihl = usize::from(datagram[0] & 0x0f) * 4;
        let udp_len = usize::from(u16::from_be_bytes([datagram[ihl + 4], datagram[ihl + 5]]));
        let mut pseudo = Vec::with_capacity(12 + udp_len);
        pseudo.extend_from_slice(&datagram[12..16]);
        pseudo.extend_from_slice(&datagram[16..20]);
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&datagram[ihl..ihl + udp_len]);
        ones_complement_sum(&pseudo)
    }

    fn udp_v6_sum(datagram: &[u8]) -> u16 {
        let udp_len = usize::from(u16::from_be_bytes([datagram[44], datagram[45]]));
        let mut pseudo = Vec::with_capacity(40 + udp_len);
        pseudo.extend_from_slice(&datagram[8..24]);
        pseudo.extend_from_slice(&datagram[24..40]);
        pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&datagram[40..40 + udp_len]);
        ones_complement_sum(&pseudo)
    }
}
