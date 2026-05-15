use mctx_core::{Context, MctxError, OutgoingInterface, PublicationConfig, PublicationId};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const UDP_PROTOCOL: u8 = 17;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownstreamConfig {
    pub interface: Option<IpAddr>,
    pub interface_index: Option<u32>,
    pub ttl: u32,
    pub loopback: bool,
}

impl Default for DownstreamConfig {
    fn default() -> Self {
        Self {
            interface: None,
            interface_index: None,
            ttl: 1,
            loopback: true,
        }
    }
}

#[derive(Debug)]
pub struct DownstreamPublisher {
    config: DownstreamConfig,
    context: Context,
    publications: BTreeMap<(IpAddr, u16), PublicationId>,
}

impl DownstreamPublisher {
    pub fn new(config: DownstreamConfig) -> Self {
        Self {
            config,
            context: Context::new(),
            publications: BTreeMap::new(),
        }
    }

    pub fn forward_ip_datagram(
        &mut self,
        datagram: &[u8],
    ) -> Result<Option<DownstreamForward>, DownstreamError> {
        let Some(udp) = parse_udp_multicast_datagram(datagram) else {
            return Ok(None);
        };

        let publication = self.publication_for(udp.group, udp.dst_port)?;
        let report = self.context.send(publication, udp.payload)?;
        Ok(Some(DownstreamForward {
            source: udp.source,
            group: udp.group,
            dst_port: udp.dst_port,
            payload_len: udp.payload.len(),
            bytes_sent: report.bytes_sent,
        }))
    }

    fn publication_for(
        &mut self,
        group: IpAddr,
        dst_port: u16,
    ) -> Result<PublicationId, MctxError> {
        let key = (group, dst_port);
        if let Some(id) = self.publications.get(&key) {
            return Ok(*id);
        }

        let mut config = PublicationConfig::new(group, dst_port)
            .with_ttl(self.config.ttl)
            .with_loopback(self.config.loopback);
        match (self.config.interface, group) {
            (Some(IpAddr::V4(interface)), IpAddr::V4(_)) => {
                config = config.with_outgoing_interface(OutgoingInterface::Ipv4Addr(interface));
            }
            (Some(IpAddr::V6(interface)), IpAddr::V6(_)) => {
                config = config.with_outgoing_interface(OutgoingInterface::Ipv6Addr(interface));
            }
            _ => {}
        }
        if matches!(group, IpAddr::V6(_))
            && let Some(index) = self.config.interface_index
        {
            config = config.with_ipv6_interface_index(index);
        }

        let id = self.context.add_publication(config)?;
        self.publications.insert(key, id);
        Ok(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownstreamForward {
    pub source: IpAddr,
    pub group: IpAddr,
    pub dst_port: u16,
    pub payload_len: usize,
    pub bytes_sent: usize,
}

#[derive(Debug)]
pub enum DownstreamError {
    Send(MctxError),
}

impl fmt::Display for DownstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DownstreamError {}

impl From<MctxError> for DownstreamError {
    fn from(value: MctxError) -> Self {
        Self::Send(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpMulticastDatagram<'a> {
    source: IpAddr,
    group: IpAddr,
    dst_port: u16,
    payload: &'a [u8],
}

fn parse_udp_multicast_datagram(datagram: &[u8]) -> Option<UdpMulticastDatagram<'_>> {
    let version = datagram.first()? >> 4;
    match version {
        4 => parse_ipv4_udp_multicast_datagram(datagram),
        6 => parse_ipv6_udp_multicast_datagram(datagram),
        _ => None,
    }
}

fn parse_ipv4_udp_multicast_datagram(datagram: &[u8]) -> Option<UdpMulticastDatagram<'_>> {
    if datagram.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }

    let ihl = usize::from(datagram[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || datagram.len() < ihl {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if total_len < ihl + UDP_HEADER_LEN || datagram.len() < total_len {
        return None;
    }
    if datagram[9] != UDP_PROTOCOL {
        return None;
    }

    let source = Ipv4Addr::new(datagram[12], datagram[13], datagram[14], datagram[15]);
    let group = Ipv4Addr::new(datagram[16], datagram[17], datagram[18], datagram[19]);
    if !group.is_multicast() {
        return None;
    }

    let udp = &datagram[ihl..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp_len > udp.len() {
        return None;
    }

    Some(UdpMulticastDatagram {
        source: source.into(),
        group: group.into(),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[UDP_HEADER_LEN..udp_len],
    })
}

fn parse_ipv6_udp_multicast_datagram(datagram: &[u8]) -> Option<UdpMulticastDatagram<'_>> {
    if datagram.len() < IPV6_HEADER_LEN {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if total_len < IPV6_HEADER_LEN + UDP_HEADER_LEN || datagram.len() < total_len {
        return None;
    }
    if datagram[6] != UDP_PROTOCOL {
        return None;
    }

    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&datagram[8..24]).ok()?);
    let group = Ipv6Addr::from(<[u8; 16]>::try_from(&datagram[24..40]).ok()?);
    if !group.is_multicast() {
        return None;
    }

    let udp = &datagram[IPV6_HEADER_LEN..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < UDP_HEADER_LEN || udp_len > udp.len() {
        return None;
    }

    Some(UdpMulticastDatagram {
        source: source.into(),
        group: group.into(),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[UDP_HEADER_LEN..udp_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_udp_multicast_payload() {
        let packet = ipv4_udp_packet(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(239, 1, 2, 3),
            5000,
            b"hello",
        );

        let parsed = parse_udp_multicast_datagram(&packet).unwrap();

        assert_eq!(parsed.source, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(parsed.group, IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)));
        assert_eq!(parsed.dst_port, 5000);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn parses_ipv6_udp_multicast_payload() {
        let packet = ipv6_udp_packet(
            "2001:db8::1".parse().unwrap(),
            "ff3e::8000:1234".parse().unwrap(),
            5000,
            b"hello",
        );

        let parsed = parse_udp_multicast_datagram(&packet).unwrap();

        assert_eq!(parsed.source, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.group, "ff3e::8000:1234".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_port, 5000);
        assert_eq!(parsed.payload, b"hello");
    }

    pub(crate) fn ipv4_udp_packet(
        source: Ipv4Addr,
        group: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let total_len = IPV4_MIN_HEADER_LEN + udp_len;
        let mut packet = vec![0; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 1;
        packet[9] = UDP_PROTOCOL;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&group.octets());
        packet[IPV4_MIN_HEADER_LEN + 2..IPV4_MIN_HEADER_LEN + 4]
            .copy_from_slice(&dst_port.to_be_bytes());
        packet[IPV4_MIN_HEADER_LEN + 4..IPV4_MIN_HEADER_LEN + 6]
            .copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(payload);
        packet
    }

    pub(crate) fn ipv6_udp_packet(
        source: Ipv6Addr,
        group: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut packet = vec![0; IPV6_HEADER_LEN + udp_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[6] = UDP_PROTOCOL;
        packet[7] = 1;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&group.octets());
        packet[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&dst_port.to_be_bytes());
        packet[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 6]
            .copy_from_slice(&(udp_len as u16).to_be_bytes());
        packet[IPV6_HEADER_LEN + UDP_HEADER_LEN..].copy_from_slice(payload);
        packet
    }
}
