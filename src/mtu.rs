use crate::checksum::checksum;
use std::fmt;

const IPV4_HEADER_LEN: usize = 20;
const IPV4_DF: u16 = 0x4000;
const IPV4_MF: u16 = 0x2000;
const IPV4_RESERVED: u16 = 0x8000;
const IPV4_OFFSET_MASK: u16 = 0x1fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4FragmentError {
    InvalidPacket,
    DontFragment,
    HeaderOptions,
    MtuTooSmall,
    FragmentOffsetOverflow,
}

impl fmt::Display for Ipv4FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPacket => f.write_str("invalid IPv4 packet"),
            Self::DontFragment => f.write_str("IPv4 packet has DF set"),
            Self::HeaderOptions => {
                f.write_str("oversized IPv4 packet contains unsupported header options")
            }
            Self::MtuTooSmall => f.write_str("tunnel MTU is too small for IPv4 fragmentation"),
            Self::FragmentOffsetOverflow => f.write_str("IPv4 fragment offset would overflow"),
        }
    }
}

impl std::error::Error for Ipv4FragmentError {}

pub fn fragment_ipv4_for_tunnel(
    packet: &[u8],
    tunnel_mtu: usize,
) -> Result<Vec<Vec<u8>>, Ipv4FragmentError> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
        return Err(Ipv4FragmentError::InvalidPacket);
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER_LEN || header_len > packet.len() {
        return Err(Ipv4FragmentError::InvalidPacket);
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() || total_len < header_len {
        return Err(Ipv4FragmentError::InvalidPacket);
    }
    if total_len <= tunnel_mtu {
        return Ok(vec![packet.to_vec()]);
    }
    if header_len != IPV4_HEADER_LEN {
        return Err(Ipv4FragmentError::HeaderOptions);
    }

    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment_field & IPV4_DF != 0 {
        return Err(Ipv4FragmentError::DontFragment);
    }
    let max_payload = tunnel_mtu
        .checked_sub(header_len)
        .map(|size| size / 8 * 8)
        .filter(|size| *size >= 8)
        .ok_or(Ipv4FragmentError::MtuTooSmall)?;
    let payload = &packet[header_len..];
    if payload.is_empty() || (fragment_field & IPV4_MF != 0 && !payload.len().is_multiple_of(8)) {
        return Err(Ipv4FragmentError::InvalidPacket);
    }

    let base_offset = usize::from(fragment_field & IPV4_OFFSET_MASK);
    base_offset
        .checked_mul(8)
        .and_then(|offset| offset.checked_add(payload.len()))
        .filter(|end| *end <= usize::from(u16::MAX) - header_len)
        .ok_or(Ipv4FragmentError::FragmentOffsetOverflow)?;
    let preserve_more_fragments = fragment_field & IPV4_MF != 0;
    let reserved = fragment_field & IPV4_RESERVED;
    let mut fragments = Vec::with_capacity(payload.len().div_ceil(max_payload));

    for chunk_start in (0..payload.len()).step_by(max_payload) {
        let chunk_end = (chunk_start + max_payload).min(payload.len());
        let chunk = &payload[chunk_start..chunk_end];
        let offset = base_offset
            .checked_add(chunk_start / 8)
            .filter(|offset| *offset <= usize::from(IPV4_OFFSET_MASK))
            .ok_or(Ipv4FragmentError::FragmentOffsetOverflow)?;
        let more_fragments = preserve_more_fragments || chunk_end < payload.len();
        let fragment_len = header_len + chunk.len();
        let mut fragment = Vec::with_capacity(fragment_len);
        fragment.extend_from_slice(&packet[..header_len]);
        fragment.extend_from_slice(chunk);
        fragment[2..4].copy_from_slice(&(fragment_len as u16).to_be_bytes());
        let flags_offset = reserved | (u16::from(more_fragments) * IPV4_MF) | offset as u16;
        fragment[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        fragment[10..12].fill(0);
        let header_checksum = checksum(&fragment[..header_len]);
        fragment[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        fragments.push(fragment);
    }

    Ok(fragments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(payload_len: usize, flags: u16) -> Vec<u8> {
        let total_len = IPV4_HEADER_LEN + payload_len;
        let mut packet = vec![0; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        packet[6..8].copy_from_slice(&flags.to_be_bytes());
        packet[8] = 16;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[239, 1, 2, 3]);
        for (index, byte) in packet[IPV4_HEADER_LEN..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let header_checksum = checksum(&packet[..IPV4_HEADER_LEN]);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet
    }

    #[test]
    fn fragments_oversized_ipv4_inside_tunnel_mtu() {
        let packet = packet(1_480, 0);
        let fragments = fragment_ipv4_for_tunnel(&packet, 1_250).unwrap();

        assert_eq!(fragments.len(), 2);
        assert!(fragments.iter().all(|fragment| fragment.len() <= 1_250));
        assert_eq!(fragments[0].len(), 1_244);
        assert_eq!(
            u16::from_be_bytes([fragments[0][6], fragments[0][7]]),
            IPV4_MF
        );
        assert_eq!(
            u16::from_be_bytes([fragments[1][6], fragments[1][7]]),
            1_224 / 8
        );
        assert!(
            fragments
                .iter()
                .all(|fragment| checksum(&fragment[..IPV4_HEADER_LEN]) == 0)
        );
        let reassembled = fragments
            .iter()
            .flat_map(|fragment| fragment[IPV4_HEADER_LEN..].iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(reassembled, packet[IPV4_HEADER_LEN..]);
    }

    #[test]
    fn refuses_to_fragment_df_packet() {
        assert_eq!(
            fragment_ipv4_for_tunnel(&packet(1_480, IPV4_DF), 1_250),
            Err(Ipv4FragmentError::DontFragment)
        );
    }

    #[test]
    fn preserves_existing_fragment_offset_and_more_flag() {
        let packet = packet(1_000, IPV4_MF | 10);
        let fragments = fragment_ipv4_for_tunnel(&packet, 620).unwrap();

        assert_eq!(fragments.len(), 2);
        assert_eq!(
            u16::from_be_bytes([fragments[0][6], fragments[0][7]]),
            IPV4_MF | 10
        );
        assert_eq!(
            u16::from_be_bytes([fragments[1][6], fragments[1][7]]),
            IPV4_MF | (10 + 600 / 8)
        );
    }

    #[test]
    fn rejects_existing_fragment_that_cannot_fit_a_reassembled_ipv4_packet() {
        assert_eq!(
            fragment_ipv4_for_tunnel(&packet(16, IPV4_OFFSET_MASK), 28),
            Err(Ipv4FragmentError::FragmentOffsetOverflow)
        );
    }
}
