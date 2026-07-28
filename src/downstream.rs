use crate::protocol::MembershipProtocol;
use mctx_core::{
    MctxError, OutgoingInterface, PublicationAddressFamily, RawContext, RawPublicationConfig,
    RawPublicationId, raw_ipv6_egress_capabilities, raw_route_egress_capabilities,
};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const UDP_PROTOCOL: u8 = 17;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownstreamConfig {
    pub interface: Option<IpAddr>,
    pub interface_index: Option<u32>,
    pub loopback: Option<bool>,
}

impl DownstreamConfig {
    /// Validates portable downstream options against the AMT inner family.
    ///
    /// This does not reject route-selected modes unavailable on the current
    /// platform. Use [`Self::validate_for_protocol`] before starting a
    /// publisher when platform capability validation is required.
    pub fn validate_options_for_protocol(
        &self,
        protocol: MembershipProtocol,
    ) -> Result<(), DownstreamConfigError> {
        self.validate_options_for_family(protocol_family(protocol))
    }

    /// Validates downstream options and current-platform egress capabilities.
    pub fn validate_for_protocol(
        &self,
        protocol: MembershipProtocol,
    ) -> Result<(), DownstreamConfigError> {
        let family = protocol_family(protocol);
        self.validate_for_family(family)
    }

    fn validate_options_for_family(
        &self,
        family: PublicationAddressFamily,
    ) -> Result<(), DownstreamConfigError> {
        if let Some(interface) = self.interface {
            let matches_family = matches!(
                (family, interface),
                (PublicationAddressFamily::Ipv4, IpAddr::V4(_))
                    | (PublicationAddressFamily::Ipv6, IpAddr::V6(_))
            );
            if !matches_family {
                return Err(DownstreamConfigError::InterfaceAddressFamilyMismatch(
                    family,
                ));
            }
        }

        if self.interface_index == Some(0) {
            return Err(DownstreamConfigError::InvalidInterfaceIndex);
        }
        if family == PublicationAddressFamily::Ipv4
            && let Some(index) = self.interface_index
        {
            return Err(DownstreamConfigError::Ipv4InterfaceIndexUnsupported(index));
        }

        if family == PublicationAddressFamily::Ipv6 && self.loopback == Some(true) {
            return Err(DownstreamConfigError::Ipv6LoopbackUnsupported);
        }

        Ok(())
    }

    fn validate_for_family(
        &self,
        family: PublicationAddressFamily,
    ) -> Result<(), DownstreamConfigError> {
        self.validate_options_for_family(family)?;

        let route_selected = self.uses_route_selected_egress();
        if route_selected
            && !raw_route_egress_capabilities()
                .for_family(family)
                .is_supported()
        {
            return Err(DownstreamConfigError::RouteSelectedEgressUnsupported(
                family,
            ));
        }

        if family == PublicationAddressFamily::Ipv6 {
            let capabilities = raw_ipv6_egress_capabilities();
            let capability = if route_selected {
                capabilities.route_selected
            } else {
                capabilities.explicit_interface
            };
            if !capability.preserves_full_header() {
                return Err(DownstreamConfigError::FullHeaderIpv6Unsupported { route_selected });
            }
        }

        self.build_publication_config(family)
            .validate()
            .map_err(|error| DownstreamConfigError::InvalidRawConfiguration(error.to_string()))?;
        Ok(())
    }

    pub(crate) fn uses_route_selected_egress(&self) -> bool {
        self.interface.is_none() && self.interface_index.is_none()
    }

    fn publication_config(
        &self,
        family: PublicationAddressFamily,
    ) -> Result<RawPublicationConfig, DownstreamConfigError> {
        self.validate_for_family(family)?;
        Ok(self.build_publication_config(family))
    }

    fn build_publication_config(&self, family: PublicationAddressFamily) -> RawPublicationConfig {
        let mut config = match family {
            PublicationAddressFamily::Ipv4 => RawPublicationConfig::ipv4(),
            PublicationAddressFamily::Ipv6 => RawPublicationConfig::ipv6(),
        };

        if self.uses_route_selected_egress() {
            config = config.with_route_selected_egress();
        } else {
            match (self.interface, family) {
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
                && let Some(index) = self.interface_index
            {
                config = config.with_ipv6_interface_index(index);
            }
        }

        if let Some(loopback) = self.loopback {
            config = config.with_loopback(loopback);
        }

        config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownstreamConfigError {
    Ipv6LoopbackUnsupported,
    InterfaceAddressFamilyMismatch(PublicationAddressFamily),
    InvalidInterfaceIndex,
    Ipv4InterfaceIndexUnsupported(u32),
    RouteSelectedEgressUnsupported(PublicationAddressFamily),
    FullHeaderIpv6Unsupported { route_selected: bool },
    InvalidRawConfiguration(String),
}

impl fmt::Display for DownstreamConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv6LoopbackUnsupported => write!(
                f,
                "downstream loopback=true is unsupported for full-header IPv6 forwarding; \
                 use loopback=false/--no-downstream-loopback and receive on another interface"
            ),
            Self::InterfaceAddressFamilyMismatch(family) => write!(
                f,
                "--downstream-interface address family must match the {} inner protocol",
                family_name(*family)
            ),
            Self::InvalidInterfaceIndex => {
                write!(f, "--downstream-ifindex must not be 0")
            }
            Self::Ipv4InterfaceIndexUnsupported(index) => write!(
                f,
                "--downstream-ifindex {index} is IPv6-only; use --downstream-interface for IPv4"
            ),
            Self::RouteSelectedEgressUnsupported(family) => write!(
                f,
                "route-selected {} downstream egress is unsupported on this platform; \
                 configure an explicit downstream interface",
                family_name(*family)
            ),
            Self::FullHeaderIpv6Unsupported { route_selected } => {
                let mode = if *route_selected {
                    "route-selected"
                } else {
                    "explicit-interface"
                };
                write!(
                    f,
                    "{mode} full-header IPv6 downstream egress is unsupported on this platform"
                )
            }
            Self::InvalidRawConfiguration(error) => {
                write!(
                    f,
                    "invalid downstream raw publication configuration: {error}"
                )
            }
        }
    }
}

impl std::error::Error for DownstreamConfigError {}

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

    /// Creates and opens the publication for one AMT inner address family.
    pub fn try_new(
        config: DownstreamConfig,
        protocol: MembershipProtocol,
    ) -> Result<Self, DownstreamError> {
        config.validate_for_protocol(protocol)?;
        let mut publisher = Self::new(config);
        publisher.publication_for(protocol_family(protocol))?;
        Ok(publisher)
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
    ) -> Result<RawPublicationId, DownstreamError> {
        if let Some(id) = self.publications.get(&family) {
            return Ok(*id);
        }

        let config = self.config.publication_config(family)?;
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
    Configuration(DownstreamConfigError),
    Send(MctxError),
}

impl fmt::Display for DownstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "{error}"),
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

impl From<DownstreamConfigError> for DownstreamError {
    fn from(value: DownstreamConfigError) -> Self {
        Self::Configuration(value)
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

fn protocol_family(protocol: MembershipProtocol) -> PublicationAddressFamily {
    match protocol {
        MembershipProtocol::Igmpv3 => PublicationAddressFamily::Ipv4,
        MembershipProtocol::Mldv2 => PublicationAddressFamily::Ipv6,
    }
}

fn family_name(family: PublicationAddressFamily) -> &'static str {
    match family {
        PublicationAddressFamily::Ipv4 => "IPv4",
        PublicationAddressFamily::Ipv6 => "IPv6",
    }
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
    fn no_interface_builds_route_selected_publication() {
        let publication =
            DownstreamConfig::default().build_publication_config(PublicationAddressFamily::Ipv4);

        assert_eq!(
            publication.egress_mode,
            mctx_core::RawEgressMode::RouteSelected
        );
        assert_eq!(publication.bind_addr, None);
        assert_eq!(publication.outgoing_interface, None);
        assert_eq!(publication.ttl, None);
    }

    #[test]
    fn explicit_interface_stays_pinned() {
        let config = DownstreamConfig {
            interface: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
            ..DownstreamConfig::default()
        };

        let publication = config.build_publication_config(PublicationAddressFamily::Ipv4);

        assert_eq!(publication.egress_mode, mctx_core::RawEgressMode::Explicit);
        assert_eq!(
            publication.outgoing_interface,
            Some(OutgoingInterface::Ipv4Addr(Ipv4Addr::new(192, 0, 2, 2)))
        );
    }

    #[test]
    fn ipv6_loopback_request_is_rejected_portably() {
        let config = DownstreamConfig {
            interface: Some("2001:db8::2".parse().unwrap()),
            loopback: Some(true),
            ..DownstreamConfig::default()
        };

        assert_eq!(
            config
                .validate_options_for_protocol(MembershipProtocol::Mldv2)
                .unwrap_err(),
            DownstreamConfigError::Ipv6LoopbackUnsupported
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_supports_route_selected_full_header_ipv6() {
        assert!(
            DownstreamConfig::default()
                .validate_for_protocol(MembershipProtocol::Mldv2)
                .is_ok()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_requires_an_explicit_ipv6_interface() {
        assert!(matches!(
            DownstreamConfig::default()
                .validate_for_protocol(MembershipProtocol::Mldv2)
                .unwrap_err(),
            DownstreamConfigError::RouteSelectedEgressUnsupported(PublicationAddressFamily::Ipv6)
        ));

        let explicit = DownstreamConfig {
            interface: Some("2001:db8::2".parse().unwrap()),
            ..DownstreamConfig::default()
        };
        assert!(
            explicit
                .validate_for_protocol(MembershipProtocol::Mldv2)
                .is_ok()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_requires_explicit_ipv4_and_rejects_ipv6() {
        assert!(matches!(
            DownstreamConfig::default()
                .validate_for_protocol(MembershipProtocol::Igmpv3)
                .unwrap_err(),
            DownstreamConfigError::RouteSelectedEgressUnsupported(PublicationAddressFamily::Ipv4)
        ));

        let ipv6 = DownstreamConfig {
            interface: Some("2001:db8::2".parse().unwrap()),
            ..DownstreamConfig::default()
        };
        assert!(matches!(
            ipv6.validate_for_protocol(MembershipProtocol::Mldv2)
                .unwrap_err(),
            DownstreamConfigError::FullHeaderIpv6Unsupported {
                route_selected: false
            }
        ));
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
