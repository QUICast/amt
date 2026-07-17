use crate::varint;
use crate::{MAX_AMT_DATA_MESSAGE, WireError};

pub const RELIABLE_DATA_BLOCK: u64 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamHeader {
    ReliableDataBlock { context_id: u64, block_id: u64 },
    Unknown { stream_type: u64 },
}

pub fn decode_stream_header(input: &[u8]) -> Result<(StreamHeader, usize), WireError> {
    let (stream_type, mut offset) = varint::decode(input)?;
    if stream_type != RELIABLE_DATA_BLOCK {
        return Ok((StreamHeader::Unknown { stream_type }, offset));
    }

    let (context_id, len) =
        varint::decode(&input[offset..]).map_err(|error| shift_incomplete(error, offset))?;
    offset += len;
    let (block_id, len) =
        varint::decode(&input[offset..]).map_err(|error| shift_incomplete(error, offset))?;
    offset += len;
    if block_id == 0 {
        return Err(WireError::Malformed(
            "AMTQ Reliable Data Block ID must be non-zero",
        ));
    }
    Ok((
        StreamHeader::ReliableDataBlock {
            context_id,
            block_id,
        },
        offset,
    ))
}

pub fn encode_stream_header(
    context_id: u64,
    block_id: u64,
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    if block_id == 0 {
        return Err(WireError::Malformed(
            "AMTQ Reliable Data Block ID must be non-zero",
        ));
    }
    varint::encode(RELIABLE_DATA_BLOCK, out)?;
    varint::encode(context_id, out)?;
    varint::encode(block_id, out)
}

pub fn decode_data_record(input: &[u8]) -> Result<(&[u8], usize), WireError> {
    let (data_len, header_len) = varint::decode(input)?;
    let data_len = usize::try_from(data_len).map_err(|_| WireError::LengthOverflow)?;
    validate_data_len(data_len)?;
    let record_len = header_len
        .checked_add(data_len)
        .ok_or(WireError::LengthOverflow)?;
    if input.len() < record_len {
        return Err(WireError::Incomplete {
            needed_at_least: record_len,
            available: input.len(),
        });
    }
    Ok((&input[header_len..record_len], record_len))
}

pub fn encode_data_record(message: &[u8], out: &mut Vec<u8>) -> Result<(), WireError> {
    validate_data_len(message.len())?;
    varint::encode(message.len() as u64, out)?;
    out.extend_from_slice(message);
    Ok(())
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BlockBoundary {
    records: usize,
}

impl BlockBoundary {
    pub fn record_completed(&mut self) {
        self.records += 1;
    }

    pub const fn record_count(self) -> usize {
        self.records
    }

    pub fn validate_fin(self, at_record_boundary: bool) -> Result<(), WireError> {
        if self.records == 0 {
            return Err(WireError::Malformed(
                "AMTQ Reliable Data Block ended before its first Data Record",
            ));
        }
        if !at_record_boundary {
            return Err(WireError::Malformed(
                "AMTQ Reliable Data Block ended inside a Data Record",
            ));
        }
        Ok(())
    }
}

fn validate_data_len(len: usize) -> Result<(), WireError> {
    if len == 0 {
        return Err(WireError::Malformed(
            "AMTQ Reliable Data Record must not be empty",
        ));
    }
    if len > MAX_AMT_DATA_MESSAGE {
        return Err(WireError::LimitExceeded {
            resource: "AMTQ Reliable Data Record",
            value: len,
            limit: MAX_AMT_DATA_MESSAGE,
        });
    }
    Ok(())
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
    fn stream_header_and_records_round_trip() {
        let mut encoded = Vec::new();
        encode_stream_header(9, 3, &mut encoded).unwrap();
        let header_len = encoded.len();
        encode_data_record(b"first", &mut encoded).unwrap();
        encode_data_record(b"second", &mut encoded).unwrap();

        assert_eq!(
            decode_stream_header(&encoded),
            Ok((
                StreamHeader::ReliableDataBlock {
                    context_id: 9,
                    block_id: 3
                },
                header_len
            ))
        );
        let (first, used) = decode_data_record(&encoded[header_len..]).unwrap();
        assert_eq!(first, b"first");
        let (second, _) = decode_data_record(&encoded[header_len + used..]).unwrap();
        assert_eq!(second, b"second");
    }

    #[test]
    fn unknown_stream_type_only_consumes_its_type() {
        assert_eq!(
            decode_stream_header(&[0x2a, 1, 2, 3]),
            Ok((StreamHeader::Unknown { stream_type: 0x2a }, 1))
        );
    }

    #[test]
    fn invalid_lengths_and_fin_boundaries_fail() {
        assert!(encode_stream_header(0, 0, &mut Vec::new()).is_err());
        assert!(decode_data_record(&[0]).is_err());

        let boundary = BlockBoundary::default();
        assert!(boundary.validate_fin(true).is_err());
        let mut boundary = BlockBoundary::default();
        boundary.record_completed();
        assert!(boundary.validate_fin(false).is_err());
        assert_eq!(boundary.validate_fin(true), Ok(()));
    }
}
