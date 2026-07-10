pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    checksum_parts(&[bytes])
}

pub(crate) fn checksum_parts(parts: &[&[u8]]) -> u16 {
    !ones_complement_sum_parts(parts)
}

pub(crate) fn ones_complement_sum(bytes: &[u8]) -> u16 {
    ones_complement_sum_parts(&[bytes])
}

pub(crate) fn icmpv6_checksum(
    source: &[u8; 16],
    destination: &[u8; 16],
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let length = (payload.len() as u32).to_be_bytes();
    let next_header = [0, 0, 0, next_header];
    checksum_parts(&[source, destination, &length, &next_header, payload])
}

fn ones_complement_sum_parts(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut high_byte = None;
    for part in parts {
        for byte in *part {
            if let Some(high) = high_byte.take() {
                sum += u32::from(u16::from_be_bytes([high, *byte]));
                sum = (sum & 0xffff) + (sum >> 16);
            } else {
                high_byte = Some(*byte);
            }
        }
    }
    if let Some(high) = high_byte {
        sum += u32::from(u16::from_be_bytes([high, 0]));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_parts_preserve_odd_byte_boundaries() {
        let bytes = [1, 2, 3, 4, 5];

        assert_eq!(
            checksum_parts(&[&bytes[..1], &bytes[1..4], &bytes[4..]]),
            checksum(&bytes)
        );
    }
}
