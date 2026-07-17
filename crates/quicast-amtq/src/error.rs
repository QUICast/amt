use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ApplicationError {
    Protocol = 0x100,
    Internal = 0x101,
    ControlStream = 0x102,
    Settings = 0x103,
    AmtMessage = 0x104,
    Context = 0x105,
    ExcessiveLoad = 0x106,
}

impl ApplicationError {
    pub const fn code(self) -> u64 {
        self as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub code: ApplicationError,
    pub reason: &'static str,
}

impl ProtocolError {
    pub const fn new(code: ApplicationError, reason: &'static str) -> Self {
        Self { code, reason }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (AMTQ error {:#x})", self.reason, self.code.code())
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Incomplete {
        needed_at_least: usize,
        available: usize,
    },
    IntegerOutOfRange(u64),
    LengthOverflow,
    LimitExceeded {
        resource: &'static str,
        value: usize,
        limit: usize,
    },
    Malformed(&'static str),
}

impl WireError {
    pub const fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete {
                needed_at_least,
                available,
            } => write!(
                f,
                "incomplete AMTQ value: need at least {needed_at_least} bytes, have {available}"
            ),
            Self::IntegerOutOfRange(value) => {
                write!(f, "value {value} exceeds the QUIC variable integer range")
            }
            Self::LengthOverflow => f.write_str("AMTQ length arithmetic overflow"),
            Self::LimitExceeded {
                resource,
                value,
                limit,
            } => write!(f, "{resource} limit exceeded: {value} > {limit}"),
            Self::Malformed(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for WireError {}
