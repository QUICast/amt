//! ECN propagation for AMT tunnels as updated by RFC 9601.

use crate::checksum::checksum;
use std::fmt;

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

/// The two-bit Explicit Congestion Notification field carried by an IP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EcnCodepoint {
    NotEct = 0b00,
    Ect1 = 0b01,
    Ect0 = 0b10,
    Ce = 0b11,
}

impl EcnCodepoint {
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b01 => Self::Ect1,
            0b10 => Self::Ect0,
            0b11 => Self::Ce,
            _ => Self::NotEct,
        }
    }

    pub const fn bits(self) -> u8 {
        self as u8
    }
}

/// RFC 6040 Figure 4's result for one decapsulated packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnDecapsulation {
    pub inner: EcnCodepoint,
    pub outer: EcnCodepoint,
    /// `None` means the packet must be dropped.
    pub output: Option<EcnCodepoint>,
    /// The input combination is currently unused and is useful to log or meter.
    pub currently_unused: bool,
}

impl EcnDecapsulation {
    pub const fn is_drop(self) -> bool {
        self.output.is_none()
    }

    pub const fn changed(self) -> bool {
        match self.output {
            Some(output) => output.bits() != self.inner.bits(),
            None => false,
        }
    }

    pub const fn propagated_ce(self) -> bool {
        matches!(self.output, Some(EcnCodepoint::Ce))
            && self.inner.bits() != EcnCodepoint::Ce.bits()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnError {
    Truncated,
    UnsupportedVersion(u8),
    InvalidHeader,
    InvalidLength,
}

impl fmt::Display for EcnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated IP packet while processing ECN"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported IP version {version} while processing ECN")
            }
            Self::InvalidHeader => f.write_str("invalid IP header while processing ECN"),
            Self::InvalidLength => f.write_str("invalid IP packet length while processing ECN"),
        }
    }
}

impl std::error::Error for EcnError {}

/// Returns the ECN field from an IPv4 or IPv6 packet.
pub fn ip_ecn(packet: &[u8]) -> Result<EcnCodepoint, EcnError> {
    let version = packet.first().ok_or(EcnError::Truncated)? >> 4;
    match version {
        4 => {
            validate_ipv4(packet)?;
            Ok(EcnCodepoint::from_bits(packet[1]))
        }
        6 => {
            validate_ipv6(packet)?;
            Ok(EcnCodepoint::from_bits(packet[1] >> 4))
        }
        other => Err(EcnError::UnsupportedVersion(other)),
    }
}

/// Applies RFC 6040 decapsulation to an embedded IP packet in place.
///
/// The caller must discard the packet when the returned result has no output.
pub fn decapsulate_ecn(
    packet: &mut [u8],
    outer: EcnCodepoint,
) -> Result<EcnDecapsulation, EcnError> {
    let inner = ip_ecn(packet)?;
    let (output, currently_unused) = decapsulation_result(inner, outer);
    let result = EcnDecapsulation {
        inner,
        outer,
        output,
        currently_unused,
    };

    if let Some(output) = output
        && output != inner
    {
        set_ip_ecn(packet, output)?;
    }

    Ok(result)
}

const fn decapsulation_result(
    inner: EcnCodepoint,
    outer: EcnCodepoint,
) -> (Option<EcnCodepoint>, bool) {
    use EcnCodepoint::{Ce, Ect0, Ect1, NotEct};

    match (inner, outer) {
        (NotEct, Ce) => (None, true),
        (NotEct, NotEct) => (Some(NotEct), false),
        (NotEct, Ect0 | Ect1) => (Some(NotEct), true),
        (Ect0, NotEct | Ect0) => (Some(Ect0), false),
        (Ect0, Ect1) => (Some(Ect1), false),
        (Ect0, Ce) => (Some(Ce), false),
        (Ect1, NotEct | Ect1) => (Some(Ect1), false),
        (Ect1, Ect0) => (Some(Ect1), true),
        (Ect1, Ce) => (Some(Ce), false),
        (Ce, Ect1) => (Some(Ce), true),
        (Ce, NotEct | Ect0 | Ce) => (Some(Ce), false),
    }
}

fn set_ip_ecn(packet: &mut [u8], ecn: EcnCodepoint) -> Result<(), EcnError> {
    match packet.first().ok_or(EcnError::Truncated)? >> 4 {
        4 => {
            let header_len = validate_ipv4(packet)?;
            packet[1] = (packet[1] & !0b11) | ecn.bits();
            packet[10..12].fill(0);
            let header_checksum = checksum(&packet[..header_len]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            Ok(())
        }
        6 => {
            validate_ipv6(packet)?;
            packet[1] = (packet[1] & !0b0011_0000) | (ecn.bits() << 4);
            Ok(())
        }
        other => Err(EcnError::UnsupportedVersion(other)),
    }
}

fn validate_ipv4(packet: &[u8]) -> Result<usize, EcnError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(EcnError::Truncated);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER_LEN || header_len > packet.len() {
        return Err(EcnError::InvalidHeader);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || total_len != packet.len() {
        return Err(EcnError::InvalidLength);
    }
    Ok(header_len)
}

fn validate_ipv6(packet: &[u8]) -> Result<(), EcnError> {
    if packet.len() < IPV6_HEADER_LEN {
        return Err(EcnError::Truncated);
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if IPV6_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(EcnError::InvalidLength)?
        != packet.len()
    {
        return Err(EcnError::InvalidLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::ones_complement_sum;

    fn ipv4_packet(ecn: EcnCodepoint) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[1] = 0b1010_1100 | ecn.bits();
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 16;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[239, 1, 2, 3]);
        let header_checksum = checksum(&packet);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    fn ipv6_packet(ecn: EcnCodepoint) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0b0110_1010;
        packet[1] = 0b1000_1111 | (ecn.bits() << 4);
        packet
    }

    #[test]
    fn extracts_ipv4_and_ipv6_ecn_without_mixing_dscp() {
        assert_eq!(
            ip_ecn(&ipv4_packet(EcnCodepoint::Ect0)),
            Ok(EcnCodepoint::Ect0)
        );
        assert_eq!(
            ip_ecn(&ipv6_packet(EcnCodepoint::Ect1)),
            Ok(EcnCodepoint::Ect1)
        );
    }

    #[test]
    fn propagates_more_severe_marking_and_repairs_ipv4_checksum() {
        let mut packet = ipv4_packet(EcnCodepoint::Ect0);
        let dscp = packet[1] & 0xfc;

        let result = decapsulate_ecn(&mut packet, EcnCodepoint::Ce).unwrap();

        assert_eq!(result.output, Some(EcnCodepoint::Ce));
        assert!(result.propagated_ce());
        assert_eq!(packet[1] & 0xfc, dscp);
        assert_eq!(ip_ecn(&packet), Ok(EcnCodepoint::Ce));
        assert_eq!(ones_complement_sum(&packet), 0xffff);
    }

    #[test]
    fn preserves_ipv6_traffic_class_and_flow_label_bits() {
        let mut packet = ipv6_packet(EcnCodepoint::Ect0);
        let first = packet[0];
        let non_ecn = packet[1] & !0x30;

        decapsulate_ecn(&mut packet, EcnCodepoint::Ect1).unwrap();

        assert_eq!(packet[0], first);
        assert_eq!(packet[1] & !0x30, non_ecn);
        assert_eq!(ip_ecn(&packet), Ok(EcnCodepoint::Ect1));
    }

    #[test]
    fn drops_not_ect_inner_with_ce_outer() {
        let mut packet = ipv4_packet(EcnCodepoint::NotEct);
        let original = packet.clone();

        let result = decapsulate_ecn(&mut packet, EcnCodepoint::Ce).unwrap();

        assert!(result.is_drop());
        assert!(result.currently_unused);
        assert_eq!(packet, original);
    }

    #[test]
    fn implements_all_rfc_6040_figure_four_outputs() {
        use EcnCodepoint::{Ce, Ect0, Ect1, NotEct};
        let expected = [
            (NotEct, NotEct, Some(NotEct)),
            (NotEct, Ect0, Some(NotEct)),
            (NotEct, Ect1, Some(NotEct)),
            (NotEct, Ce, None),
            (Ect0, NotEct, Some(Ect0)),
            (Ect0, Ect0, Some(Ect0)),
            (Ect0, Ect1, Some(Ect1)),
            (Ect0, Ce, Some(Ce)),
            (Ect1, NotEct, Some(Ect1)),
            (Ect1, Ect0, Some(Ect1)),
            (Ect1, Ect1, Some(Ect1)),
            (Ect1, Ce, Some(Ce)),
            (Ce, NotEct, Some(Ce)),
            (Ce, Ect0, Some(Ce)),
            (Ce, Ect1, Some(Ce)),
            (Ce, Ce, Some(Ce)),
        ];

        for (inner, outer, output) in expected {
            assert_eq!(decapsulation_result(inner, outer).0, output);
        }
    }
}
