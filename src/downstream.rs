use mctx_core::{
    MctxError, OutgoingInterface, PublicationAddressFamily, RawContext, RawPublicationConfig,
    RawPublicationId,
};
use std::collections::HashMap;
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
    pub ttl: Option<u8>,
    pub loopback: bool,
}

impl Default for DownstreamConfig {
    fn default() -> Self {
        Self {
            interface: None,
            interface_index: None,
            ttl: Some(1),
            loopback: true,
        }
    }
}

#[derive(Debug)]
pub struct DownstreamPublisher {
    config: DownstreamConfig,
    context: RawContext,
    publications: HashMap<PublicationAddressFamily, RawPublicationId>,
}

impl DownstreamPublisher {
    pub fn new(config: DownstreamConfig) -> Self {
        Self {
            config,
            context: RawContext::new(),
            publications: HashMap::new(),
        }
    }

    pub fn forward_ip_datagram(
        &mut self,
        datagram: &[u8],
    ) -> Result<Option<DownstreamForward>, DownstreamError> {
        let Some(multicast) = parse_ip_multicast_datagram(datagram) else {
            return Ok(None);
        };

        let publication = self.publication_for(multicast.family)?;
        let packet = &datagram[..multicast.datagram_len];
        let report = self.context.send_raw(publication, packet)?;

        Ok(Some(DownstreamForward {
            source: multicast.source,
            group: multicast.group,
            ip_protocol: multicast.ip_protocol,
            udp_dst_port: multicast.udp_dst_port,
            datagram_len: packet.len(),
            bytes_sent: report.bytes_sent,
        }))
    }

    fn publication_for(
        &mut self,
        family: PublicationAddressFamily,
    ) -> Result<RawPublicationId, MctxError> {
        if let Some(id) = self.publications.get(&family) {
            return Ok(*id);
        }

        let mut config = match family {
            PublicationAddressFamily::Ipv4 => RawPublicationConfig::ipv4(),
            PublicationAddressFamily::Ipv6 => RawPublicationConfig::ipv6(),
        }
        .with_loopback(self.config.loopback);

        if let Some(ttl) = self.config.ttl {
            config = config.with_ttl(ttl);
        }

        match (self.config.interface, family) {
            (Some(IpAddr::V4(interface)), PublicationAddressFamily::Ipv4) => {
                config = config
                    .with_outgoing_interface(OutgoingInterface::Ipv4Addr(interface))
                    .with_bind_addr(interface);
            }
            (Some(IpAddr::V6(interface)), PublicationAddressFamily::Ipv6) => {
                config = config
                    .with_outgoing_interface(OutgoingInterface::Ipv6Addr(interface))
                    .with_bind_addr(interface);
            }
            _ => {}
        }

        if family == PublicationAddressFamily::Ipv6
            && let Some(index) = self.config.interface_index
        {
            config = config.with_ipv6_interface_index(index);
        }

        let id = self.context.add_publication(config)?;
        self.publications.insert(family, id);
        Ok(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownstreamForward {
    pub source: IpAddr,
    pub group: IpAddr,
    pub ip_protocol: u8,
    pub udp_dst_port: Option<u16>,
    pub datagram_len: usize,
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
struct IpMulticastDatagram {
    family: PublicationAddressFamily,
    source: IpAddr,
    group: IpAddr,
    ip_protocol: u8,
    udp_dst_port: Option<u16>,
    datagram_len: usize,
}

fn parse_ip_multicast_datagram(datagram: &[u8]) -> Option<IpMulticastDatagram> {
    let version = datagram.first()? >> 4;
    match version {
        4 => parse_ipv4_multicast_datagram(datagram),
        6 => parse_ipv6_multicast_datagram(datagram),
        _ => None,
    }
}

fn parse_ipv4_multicast_datagram(datagram: &[u8]) -> Option<IpMulticastDatagram> {
    if datagram.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }

    let ihl = usize::from(datagram[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN || datagram.len() < ihl {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
    if total_len < ihl || datagram.len() < total_len {
        return None;
    }

    let source = Ipv4Addr::new(datagram[12], datagram[13], datagram[14], datagram[15]);
    let group = Ipv4Addr::new(datagram[16], datagram[17], datagram[18], datagram[19]);
    if !group.is_multicast() {
        return None;
    }

    Some(IpMulticastDatagram {
        family: PublicationAddressFamily::Ipv4,
        source: source.into(),
        group: group.into(),
        ip_protocol: datagram[9],
        udp_dst_port: parse_udp_dst_port(&datagram[ihl..total_len], datagram[9]),
        datagram_len: total_len,
    })
}

fn parse_ipv6_multicast_datagram(datagram: &[u8]) -> Option<IpMulticastDatagram> {
    if datagram.len() < IPV6_HEADER_LEN {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if datagram.len() < total_len {
        return None;
    }

    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&datagram[8..24]).ok()?);
    let group = Ipv6Addr::from(<[u8; 16]>::try_from(&datagram[24..40]).ok()?);
    if !group.is_multicast() {
        return None;
    }

    Some(IpMulticastDatagram {
        family: PublicationAddressFamily::Ipv6,
        source: source.into(),
        group: group.into(),
        ip_protocol: datagram[6],
        udp_dst_port: parse_udp_dst_port(&datagram[IPV6_HEADER_LEN..total_len], datagram[6]),
        datagram_len: total_len,
    })
}

fn parse_udp_dst_port(payload: &[u8], protocol: u8) -> Option<u16> {
    if protocol != UDP_PROTOCOL || payload.len() < UDP_HEADER_LEN {
        return None;
    }

    let udp_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
    if udp_len < UDP_HEADER_LEN || udp_len > payload.len() {
        return None;
    }

    Some(u16::from_be_bytes([payload[2], payload[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_udp_multicast_datagram() {
        let packet = ipv4_udp_packet(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(239, 1, 2, 3),
            5000,
            b"hello",
        );

        let parsed = parse_ip_multicast_datagram(&packet).unwrap();

        assert_eq!(parsed.family, PublicationAddressFamily::Ipv4);
        assert_eq!(parsed.source, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(parsed.group, IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)));
        assert_eq!(parsed.ip_protocol, UDP_PROTOCOL);
        assert_eq!(parsed.udp_dst_port, Some(5000));
        assert_eq!(parsed.datagram_len, packet.len());
    }

    #[test]
    fn parses_ipv6_udp_multicast_datagram() {
        let packet = ipv6_udp_packet(
            "2001:db8::1".parse().unwrap(),
            "ff3e::8000:1234".parse().unwrap(),
            5000,
            b"hello",
        );

        let parsed = parse_ip_multicast_datagram(&packet).unwrap();

        assert_eq!(parsed.family, PublicationAddressFamily::Ipv6);
        assert_eq!(parsed.source, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.group, "ff3e::8000:1234".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.ip_protocol, UDP_PROTOCOL);
        assert_eq!(parsed.udp_dst_port, Some(5000));
        assert_eq!(parsed.datagram_len, packet.len());
    }

    #[test]
    fn parses_non_udp_multicast_datagram_without_udp_port() {
        let packet = ipv4_packet(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(239, 1, 2, 3),
            1,
            &[],
        );

        let parsed = parse_ip_multicast_datagram(&packet).unwrap();

        assert_eq!(parsed.ip_protocol, 1);
        assert_eq!(parsed.udp_dst_port, None);
        assert_eq!(parsed.datagram_len, packet.len());
    }

    #[test]
    fn malformed_udp_length_keeps_datagram_but_omits_udp_port() {
        let mut packet = ipv4_udp_packet(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(239, 1, 2, 3),
            5000,
            b"hello",
        );
        packet[IPV4_MIN_HEADER_LEN + 4..IPV4_MIN_HEADER_LEN + 6]
            .copy_from_slice(&100u16.to_be_bytes());

        let parsed = parse_ip_multicast_datagram(&packet).unwrap();

        assert_eq!(parsed.ip_protocol, UDP_PROTOCOL);
        assert_eq!(parsed.udp_dst_port, None);
        assert_eq!(parsed.datagram_len, packet.len());
    }

    #[test]
    fn ignores_non_multicast_destinations() {
        let packet = ipv4_packet(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 20),
            UDP_PROTOCOL,
            &[0; UDP_HEADER_LEN],
        );

        assert_eq!(parse_ip_multicast_datagram(&packet), None);
    }

    #[test]
    fn trims_ipv4_trailing_bytes_to_ip_total_length() {
        let mut packet = ipv4_udp_packet(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(239, 1, 2, 3),
            5000,
            b"hello",
        );
        let total_len = packet.len();
        packet.extend_from_slice(&[0xaa, 0xbb]);

        let parsed = parse_ip_multicast_datagram(&packet).unwrap();

        assert_eq!(parsed.datagram_len, total_len);
    }

    pub(crate) fn ipv4_udp_packet(
        source: Ipv4Addr,
        group: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = UDP_HEADER_LEN + payload.len();
        let mut udp = vec![0; udp_len];
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp[UDP_HEADER_LEN..].copy_from_slice(payload);
        ipv4_packet(source, group, UDP_PROTOCOL, &udp)
    }

    fn ipv4_packet(source: Ipv4Addr, group: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = IPV4_MIN_HEADER_LEN + payload.len();
        let mut packet = vec![0; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 1;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&group.octets());
        packet[IPV4_MIN_HEADER_LEN..].copy_from_slice(payload);
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
