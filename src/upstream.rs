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
}
