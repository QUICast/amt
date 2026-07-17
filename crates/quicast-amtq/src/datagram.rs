use crate::varint;
use crate::{MAX_AMT_DATA_MESSAGE, MAX_FRAGMENT_RANGES, WireError};

pub const COMPLETE: u64 = 0x00;
pub const FRAGMENT: u64 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub context_id: u64,
    pub packet_id: u64,
    pub total_len: usize,
    pub offset: usize,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Datagram<'a> {
    Complete {
        context_id: u64,
        message: &'a [u8],
    },
    Fragment(Fragment<'a>),
    Unknown {
        format: u64,
        context_id: u64,
        payload: &'a [u8],
    },
}

pub fn decode(input: &[u8]) -> Result<Datagram<'_>, WireError> {
    let (format, mut offset) = varint::decode(input)?;
    let (context_id, len) =
        varint::decode(&input[offset..]).map_err(|error| shift_incomplete(error, offset))?;
    offset += len;

    match format {
        COMPLETE => {
            let message = &input[offset..];
            validate_message_len(message.len())?;
            Ok(Datagram::Complete {
                context_id,
                message,
            })
        }
        FRAGMENT => {
            let (packet_id, len) = decode_field(input, offset)?;
            offset += len;
            let (total_len, len) = decode_field(input, offset)?;
            offset += len;
            let (fragment_offset, len) = decode_field(input, offset)?;
            offset += len;

            let total_len = usize::try_from(total_len).map_err(|_| WireError::LengthOverflow)?;
            validate_message_len(total_len)?;
            let fragment_offset =
                usize::try_from(fragment_offset).map_err(|_| WireError::LengthOverflow)?;
            let data = &input[offset..];
            if data.is_empty() {
                return Err(WireError::Malformed(
                    "AMTQ FRAGMENT must contain at least one byte",
                ));
            }
            let end = fragment_offset
                .checked_add(data.len())
                .ok_or(WireError::LengthOverflow)?;
            if end > total_len {
                return Err(WireError::Malformed(
                    "AMTQ fragment range exceeds Total Length",
                ));
            }
            Ok(Datagram::Fragment(Fragment {
                context_id,
                packet_id,
                total_len,
                offset: fragment_offset,
                data,
            }))
        }
        format => Ok(Datagram::Unknown {
            format,
            context_id,
            payload: &input[offset..],
        }),
    }
}

pub fn encode_complete(
    context_id: u64,
    message: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    validate_message_len(message.len())?;
    varint::encode(COMPLETE, out)?;
    varint::encode(context_id, out)?;
    out.extend_from_slice(message);
    Ok(())
}

pub fn encode_fragment(fragment: Fragment<'_>, out: &mut Vec<u8>) -> Result<(), WireError> {
    validate_message_len(fragment.total_len)?;
    if fragment.data.is_empty() {
        return Err(WireError::Malformed(
            "AMTQ FRAGMENT must contain at least one byte",
        ));
    }
    let end = fragment
        .offset
        .checked_add(fragment.data.len())
        .ok_or(WireError::LengthOverflow)?;
    if end > fragment.total_len {
        return Err(WireError::Malformed(
            "AMTQ fragment range exceeds Total Length",
        ));
    }

    varint::encode(FRAGMENT, out)?;
    varint::encode(fragment.context_id, out)?;
    varint::encode(fragment.packet_id, out)?;
    varint::encode(fragment.total_len as u64, out)?;
    varint::encode(fragment.offset as u64, out)?;
    out.extend_from_slice(fragment.data);
    Ok(())
}

pub fn fragment_message(
    context_id: u64,
    packet_id: u64,
    message: &[u8],
    max_datagram_size: usize,
) -> Result<Vec<Vec<u8>>, WireError> {
    validate_message_len(message.len())?;
    let mut datagrams = Vec::new();
    let mut offset = 0;
    while offset < message.len() {
        let mut datagram = Vec::new();
        varint::encode(FRAGMENT, &mut datagram)?;
        varint::encode(context_id, &mut datagram)?;
        varint::encode(packet_id, &mut datagram)?;
        varint::encode(message.len() as u64, &mut datagram)?;
        varint::encode(offset as u64, &mut datagram)?;
        if datagram.len() >= max_datagram_size {
            return Err(WireError::Malformed(
                "QUIC DATAGRAM limit leaves no room for fragment data",
            ));
        }
        let data_len = (max_datagram_size - datagram.len()).min(message.len() - offset);
        datagram.extend_from_slice(&message[offset..offset + data_len]);
        datagrams.push(datagram);
        if datagrams.len() > MAX_FRAGMENT_RANGES {
            return Err(WireError::LimitExceeded {
                resource: "fragments per AMTQ message",
                value: datagrams.len(),
                limit: MAX_FRAGMENT_RANGES,
            });
        }
        offset += data_len;
    }
    Ok(datagrams)
}

fn validate_message_len(len: usize) -> Result<(), WireError> {
    if len == 0 {
        return Err(WireError::Malformed(
            "AMTQ Multicast Data message must not be empty",
        ));
    }
    if len > MAX_AMT_DATA_MESSAGE {
        return Err(WireError::LimitExceeded {
            resource: "AMTQ Multicast Data message",
            value: len,
            limit: MAX_AMT_DATA_MESSAGE,
        });
    }
    Ok(())
}

fn decode_field(input: &[u8], offset: usize) -> Result<(u64, usize), WireError> {
    varint::decode(&input[offset..]).map_err(|error| shift_incomplete(error, offset))
}

fn shift_incomplete(error: WireError, offset: usize) -> WireError {
    match error {
        WireError::Incomplete {
            needed_at_least,
            available,
        } => WireError::Incomplete {
            needed_at_least: offset.saturating_add(needed_at_least),
            available: offset.saturating_add(available),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_round_trip() {
        let message = [0x06, 0, 0x45, 0, 0, 20];
        let mut encoded = Vec::new();
        encode_complete(9, &message, &mut encoded).unwrap();
        assert_eq!(
            decode(&encoded),
            Ok(Datagram::Complete {
                context_id: 9,
                message: &message
            })
        );
    }

    #[test]
    fn fragmented_message_round_trip() {
        let message = vec![0x5a; 2_000];
        let encoded = fragment_message(4, 7, &message, 200).unwrap();
        assert!(encoded.len() > 1);
        assert!(encoded.iter().all(|datagram| datagram.len() <= 200));

        let mut rebuilt = vec![0; message.len()];
        for datagram in &encoded {
            let Datagram::Fragment(fragment) = decode(datagram).unwrap() else {
                panic!("expected fragment");
            };
            rebuilt[fragment.offset..fragment.offset + fragment.data.len()]
                .copy_from_slice(fragment.data);
        }
        assert_eq!(rebuilt, message);
    }

    #[test]
    fn fragment_bounds_are_validated() {
        let fragment = Fragment {
            context_id: 0,
            packet_id: 1,
            total_len: 4,
            offset: 3,
            data: &[1, 2],
        };
        assert!(encode_fragment(fragment, &mut Vec::new()).is_err());
    }

    #[test]
    fn unknown_format_is_preserved_for_discard() {
        let encoded = [0x2a, 0x07, 1, 2, 3];
        assert_eq!(
            decode(&encoded),
            Ok(Datagram::Unknown {
                format: 0x2a,
                context_id: 7,
                payload: &[1, 2, 3]
            })
        );
    }
}
