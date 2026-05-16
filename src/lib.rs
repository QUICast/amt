//! Lightweight building blocks for Automatic Multicast Tunneling (AMT).
//!
//! The protocol codec intentionally stays runtime agnostic. Runtime-specific
//! loops, such as the simple blocking daemon, live at the crate edge.

pub mod daemon;
pub mod downstream;
pub mod gateway;
pub mod local_membership;
pub mod membership;
pub mod protocol;
pub mod query;
pub mod relay;
pub mod state;
pub mod upstream;

pub use downstream::{DownstreamConfig, DownstreamForward, DownstreamPublisher};
pub use gateway::{Gateway, GatewayAction, GatewayConfig, GatewayError};
pub use local_membership::{
    LocalMembershipConfig, LocalMembershipError, LocalMembershipEvent, LocalMembershipManager,
};
pub use membership::{
    MembershipBuildError, MembershipParseError, MembershipRecord, MembershipRecordKind,
    MembershipReport,
};
pub use protocol::{
    AMT_PORT, DecodeError, GatewayAddress, GatewayEndpoint, MembershipProtocol, Message,
    MessageType, ResponseMac,
};
pub use relay::{Relay, RelayAction, RelayConfig, RelayError, RelaySecret};
pub use state::{FilterMode, GroupInterest, RelayState, UpstreamSubscription};
pub use upstream::{UpstreamConfig, UpstreamDatagram, UpstreamManager, UpstreamReconcile};
