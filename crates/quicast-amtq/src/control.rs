use crate::varint;
use crate::{EndpointRole, MAX_CONTROL_RECORD_VALUE, WireError};
use std::collections::BTreeSet;

pub const SETTINGS: u64 = 0x00;
pub const AMT_CONTROL: u64 = 0x01;
pub const CONTEXT: u64 = 0x02;
pub const CONTEXT_CLOSE: u64 = 0x03;
pub const CONTEXT_ACK: u64 = 0x04;

pub const DATA_MODES: u64 = 0x00;
pub const PREFERRED_DATA_MODE: u64 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DataMode {
    Datagram = 0x00,
    ReliableBlock = 0x01,
}

impl DataMode {
    pub const fn value(self) -> u64 {
        self as u64
    }

    pub const fn bit(self) -> u64 {
        1 << self.value()
    }

    pub const fn from_value(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Datagram),
            1 => Some(Self::ReliableBlock),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub data_modes: u64,
    pub preferred_data_mode: Option<u64>,
}

impl Settings {
    pub const fn datagram_only() -> Self {
        Self {
            data_modes: DataMode::Datagram.bit(),
            preferred_data_mode: None,
        }
    }

    pub const fn gateway(data_modes: u64, preferred_data_mode: Option<u64>) -> Self {
        Self {
            data_modes,
            preferred_data_mode,
        }
    }

    pub const fn supports(&self, mode: DataMode) -> bool {
        self.data_modes & mode.bit() != 0
    }

    pub fn validate(&self, sender: EndpointRole) -> Result<(), WireError> {
        if !self.supports(DataMode::Datagram) {
            return Err(WireError::Malformed(
                "AMTQ DATA_MODES must advertise Datagram Mode",
            ));
        }
        if sender == EndpointRole::Relay && self.preferred_data_mode.is_some() {
            return Err(WireError::Malformed(
                "an AMTQ Relay must not send PREFERRED_DATA_MODE",
            ));
        }
        if let Some(preferred) = self.preferred_data_mode
            && (preferred > 61 || self.data_modes & (1 << preferred) == 0)
        {
            return Err(WireError::Malformed(
                "AMTQ PREFERRED_DATA_MODE is not present in DATA_MODES",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub id: u64,
    pub mode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextClose {
    pub id: u64,
    pub final_block_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub record_type: u64,
    pub value_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRecord<'a> {
    Settings(Settings),
    AmtControl(&'a [u8]),
    Context(Context),
    ContextClose(ContextClose),
    ContextAck { id: u64 },
    Unknown { record_type: u64, value: &'a [u8] },
}

impl ControlRecord<'_> {
    pub fn encode(&self, sender: EndpointRole, out: &mut Vec<u8>) -> Result<(), WireError> {
        let mut value = Vec::new();
        let record_type = match self {
            Self::Settings(settings) => {
                settings.validate(sender)?;
                encode_setting(DATA_MODES, settings.data_modes, &mut value)?;
                if let Some(preferred) = settings.preferred_data_mode {
                    encode_setting(PREFERRED_DATA_MODE, preferred, &mut value)?;
                }
                SETTINGS
            }
            Self::AmtControl(message) => {
                value.extend_from_slice(message);
                AMT_CONTROL
            }
            Self::Context(context) => {
                varint::encode(context.id, &mut value)?;
                varint::encode(context.mode, &mut value)?;
                CONTEXT
            }
            Self::ContextClose(context) => {
                varint::encode(context.id, &mut value)?;
                if let Some(final_block_id) = context.final_block_id {
                    varint::encode(final_block_id, &mut value)?;
                }
                CONTEXT_CLOSE
            }
            Self::ContextAck { id } => {
                varint::encode(*id, &mut value)?;
                CONTEXT_ACK
            }
            Self::Unknown {
                record_type,
                value: unknown,
            } => {
                value.extend_from_slice(unknown);
                *record_type
            }
        };
        encode_record_parts(record_type, &value, out)
    }
}

pub fn encode_record_parts(
    record_type: u64,
    value: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), WireError> {
    if value.len() > MAX_CONTROL_RECORD_VALUE {
        return Err(WireError::LimitExceeded {
            resource: "AMTQ Control Record Value",
            value: value.len(),
            limit: MAX_CONTROL_RECORD_VALUE,
        });
    }
    varint::encode(record_type, out)?;
    varint::encode(value.len() as u64, out)?;
    out.extend_from_slice(value);
    Ok(())
}

/// Decodes only a control-record header.
///
/// A stream adapter can use this function to consume an unknown record value
/// in bounded chunks instead of buffering the full value.
pub fn decode_record_header(input: &[u8]) -> Result<(RecordHeader, usize), WireError> {
    let (record_type, type_len) = varint::decode(input)?;
    let (value_len, length_len) =
        varint::decode(&input[type_len..]).map_err(|error| shift_incomplete(error, type_len))?;
    if value_len > MAX_CONTROL_RECORD_VALUE as u64 {
        return Err(WireError::LimitExceeded {
            resource: "AMTQ Control Record Value",
            value: usize::try_from(value_len).unwrap_or(usize::MAX),
            limit: MAX_CONTROL_RECORD_VALUE,
        });
    }
    Ok((
        RecordHeader {
            record_type,
            value_len: value_len as usize,
        },
        type_len + length_len,
    ))
}

pub fn decode_record(
    input: &[u8],
    sender: EndpointRole,
) -> Result<(ControlRecord<'_>, usize), WireError> {
    let (header, header_len) = decode_record_header(input)?;
    let record_len = header_len
        .checked_add(header.value_len)
        .ok_or(WireError::LengthOverflow)?;
    if input.len() < record_len {
        return Err(WireError::Incomplete {
            needed_at_least: record_len,
            available: input.len(),
        });
    }
    let value = &input[header_len..record_len];
    let record = match header.record_type {
        SETTINGS => ControlRecord::Settings(decode_settings(value, sender)?),
        AMT_CONTROL => ControlRecord::AmtControl(value),
        CONTEXT => {
            let fields = decode_exact_fields::<2>(value)?;
            ControlRecord::Context(Context {
                id: fields[0],
                mode: fields[1],
            })
        }
        CONTEXT_CLOSE => {
            let (id, first_len) = decode_required_field(value, 0)?;
            let final_block_id = if first_len == value.len() {
                None
            } else {
                let (final_block_id, second_len) = decode_required_field(value, first_len)?;
                if first_len + second_len != value.len() {
                    return Err(WireError::Malformed(
                        "invalid AMTQ CONTEXT_CLOSE record value",
                    ));
                }
                Some(final_block_id)
            };
            ControlRecord::ContextClose(ContextClose { id, final_block_id })
        }
        CONTEXT_ACK => {
            let fields = decode_exact_fields::<1>(value)?;
            ControlRecord::ContextAck { id: fields[0] }
        }
        record_type => ControlRecord::Unknown { record_type, value },
    };
    Ok((record, record_len))
}

fn decode_settings(value: &[u8], sender: EndpointRole) -> Result<Settings, WireError> {
    let mut offset = 0;
    let mut identifiers = BTreeSet::new();
    let mut data_modes = None;
    let mut preferred_data_mode = None;
    while offset < value.len() {
        let (identifier, identifier_len) =
            varint::decode(&value[offset..]).map_err(|error| shift_incomplete(error, offset))?;
        offset += identifier_len;
        let (setting_value, value_len) =
            varint::decode(&value[offset..]).map_err(|error| shift_incomplete(error, offset))?;
        offset += value_len;
        if !identifiers.insert(identifier) {
            return Err(WireError::Malformed("duplicate AMTQ setting identifier"));
        }
        match identifier {
            DATA_MODES => data_modes = Some(setting_value),
            PREFERRED_DATA_MODE => preferred_data_mode = Some(setting_value),
            _ => {}
        }
    }

    let settings = Settings {
        data_modes: data_modes
            .ok_or(WireError::Malformed("AMTQ SETTINGS is missing DATA_MODES"))?,
        preferred_data_mode,
    };
    settings.validate(sender)?;
    Ok(settings)
}

fn encode_setting(identifier: u64, value: u64, out: &mut Vec<u8>) -> Result<(), WireError> {
    varint::encode(identifier, out)?;
    varint::encode(value, out)
}

fn decode_exact_fields<const N: usize>(value: &[u8]) -> Result<[u64; N], WireError> {
    let mut fields = [0; N];
    let mut offset = 0;
    for field in &mut fields {
        let (value, len) = decode_required_field(value, offset)?;
        *field = value;
        offset += len;
    }
    if offset != value.len() {
        return Err(WireError::Malformed(
            "invalid number of fields in AMTQ control record",
        ));
    }
    Ok(fields)
}

fn decode_required_field(value: &[u8], offset: usize) -> Result<(u64, usize), WireError> {
    if offset == value.len() {
        return Err(WireError::Malformed("missing field in AMTQ control record"));
    }
    varint::decode(&value[offset..]).map_err(|error| shift_incomplete(error, offset))
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
    fn settings_round_trip_and_ignore_unknown_setting() {
        let settings = Settings::gateway(
            DataMode::Datagram.bit() | DataMode::ReliableBlock.bit(),
            Some(DataMode::ReliableBlock.value()),
        );
        let mut encoded = Vec::new();
        ControlRecord::Settings(settings.clone())
            .encode(EndpointRole::Gateway, &mut encoded)
            .unwrap();

        let (decoded, used) = decode_record(&encoded, EndpointRole::Gateway).unwrap();
        assert_eq!(used, encoded.len());
        assert_eq!(decoded, ControlRecord::Settings(settings));

        let mut value = vec![DATA_MODES as u8, DataMode::Datagram.bit() as u8];
        value.extend_from_slice(&[0x2a, 0x01]);
        let mut encoded = Vec::new();
        encode_record_parts(SETTINGS, &value, &mut encoded).unwrap();
        assert_eq!(
            decode_record(&encoded, EndpointRole::Gateway).unwrap().0,
            ControlRecord::Settings(Settings::datagram_only())
        );
    }

    #[test]
    fn settings_require_datagram_and_valid_preference() {
        for settings in [
            Settings::gateway(DataMode::ReliableBlock.bit(), None),
            Settings::gateway(DataMode::Datagram.bit(), Some(1)),
        ] {
            assert!(
                ControlRecord::Settings(settings)
                    .encode(EndpointRole::Gateway, &mut Vec::new())
                    .is_err()
            );
        }
        assert!(
            ControlRecord::Settings(Settings::gateway(
                DataMode::Datagram.bit(),
                Some(DataMode::Datagram.value())
            ))
            .encode(EndpointRole::Relay, &mut Vec::new())
            .is_err()
        );
    }

    #[test]
    fn duplicate_even_unknown_settings_are_rejected() {
        let value = [DATA_MODES as u8, 1, 0x2a, 1, 0x2a, 2];
        let mut encoded = Vec::new();
        encode_record_parts(SETTINGS, &value, &mut encoded).unwrap();
        assert!(decode_record(&encoded, EndpointRole::Gateway).is_err());
    }

    #[test]
    fn context_records_round_trip() {
        let records = [
            ControlRecord::Context(Context { id: 7, mode: 1 }),
            ControlRecord::ContextAck { id: 7 },
            ControlRecord::ContextClose(ContextClose {
                id: 7,
                final_block_id: Some(12),
            }),
        ];
        for record in records {
            let mut encoded = Vec::new();
            record.encode(EndpointRole::Relay, &mut encoded).unwrap();
            assert_eq!(
                decode_record(&encoded, EndpointRole::Relay),
                Ok((record, encoded.len()))
            );
        }
    }

    #[test]
    fn header_rejects_large_values_before_waiting_for_them() {
        let mut encoded = Vec::new();
        varint::encode(AMT_CONTROL, &mut encoded).unwrap();
        varint::encode((MAX_CONTROL_RECORD_VALUE + 1) as u64, &mut encoded).unwrap();
        assert!(matches!(
            decode_record_header(&encoded),
            Err(WireError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn incomplete_record_reports_full_required_length() {
        let encoded = [AMT_CONTROL as u8, 5, 1, 2];
        assert_eq!(
            decode_record(&encoded, EndpointRole::Gateway),
            Err(WireError::Incomplete {
                needed_at_least: 7,
                available: 4
            })
        );
    }
}
