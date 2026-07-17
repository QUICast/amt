//! Runtime-agnostic protocol machinery for the experimental AMTQ draft.
//!
//! This crate owns AMTQ framing and state validation. QUIC implementations
//! provide bytes, stream lifecycle events, and transport capabilities at the
//! edge so the protocol core can be tested independently.

#![forbid(unsafe_code)]

pub mod control;
pub mod datagram;
pub mod error;
#[cfg(feature = "native-multicast")]
pub mod native;
pub mod reassembly;
pub mod reliable;
pub mod session;
#[cfg(feature = "transport-quiche")]
pub mod transport;
pub mod varint;

pub use error::{ApplicationError, ProtocolError, WireError};

/// Draft-versioned TLS ALPN token.
pub const ALPN: &[u8] = b"amtq-00";

pub const MAX_CONTROL_RECORD_VALUE: usize = 65_587;
pub const MAX_AMT_DATA_MESSAGE: usize = 65_577;
pub const MAX_OPEN_CONTEXTS: usize = 64;
pub const MAX_INCOMPLETE_MESSAGES: usize = 64;
pub const MAX_FRAGMENT_RANGES: usize = 1_024;
pub const MIN_GATEWAY_DATAGRAM_SIZE: u64 = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    Gateway,
    Relay,
}

impl EndpointRole {
    pub const fn peer(self) -> Self {
        match self {
            Self::Gateway => Self::Relay,
            Self::Relay => Self::Gateway,
        }
    }
}
