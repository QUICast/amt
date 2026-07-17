use crate::WireError;

pub const MAX_VARINT: u64 = (1 << 62) - 1;

pub fn encoded_len(value: u64) -> Result<usize, WireError> {
    match value {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX_VARINT => Ok(8),
        _ => Err(WireError::IntegerOutOfRange(value)),
    }
}

pub fn encode(value: u64, out: &mut Vec<u8>) -> Result<(), WireError> {
    match encoded_len(value)? {
        1 => out.push(value as u8),
        2 => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
        8 => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
        _ => unreachable!("QUIC varints use 1, 2, 4, or 8 bytes"),
    }
    Ok(())
}

pub fn decode(input: &[u8]) -> Result<(u64, usize), WireError> {
    let Some(&first) = input.first() else {
        return Err(WireError::Incomplete {
            needed_at_least: 1,
            available: 0,
        });
    };
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return Err(WireError::Incomplete {
            needed_at_least: len,
            available: input.len(),
        });
    }

    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortest_encodings_round_trip_boundaries() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            MAX_VARINT,
        ] {
            let mut encoded = Vec::new();
            encode(value, &mut encoded).unwrap();
            assert_eq!(encoded.len(), encoded_len(value).unwrap());
            assert_eq!(decode(&encoded), Ok((value, encoded.len())));
        }
    }

    #[test]
    fn decoder_accepts_non_minimal_encodings() {
        assert_eq!(decode(&[0x40, 0x01]), Ok((1, 2)));
        assert_eq!(decode(&[0x80, 0, 0, 1]), Ok((1, 4)));
        assert_eq!(decode(&[0xc0, 0, 0, 0, 0, 0, 0, 1]), Ok((1, 8)));
    }

    #[test]
    fn incomplete_and_excessive_values_are_rejected() {
        assert_eq!(
            decode(&[0xc0, 0]),
            Err(WireError::Incomplete {
                needed_at_least: 8,
                available: 2
            })
        );
        assert_eq!(
            encode(MAX_VARINT + 1, &mut Vec::new()),
            Err(WireError::IntegerOutOfRange(MAX_VARINT + 1))
        );
    }
}
