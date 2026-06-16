//! Lightweight building blocks for Automatic Multicast Tunneling (AMT).
//!
//! The protocol codec intentionally stays runtime agnostic. Runtime-specific
//! loops, such as the simple blocking relay and gateway runners, live at the
//! crate edge.

pub mod config;
pub mod daemon;
pub mod downstream;
#[cfg(feature = "driad")]
pub mod driad;
pub mod gateway;
pub mod local_membership;
pub mod membership;
pub mod metrics;
pub mod protocol;
pub mod query;
pub mod relay;
pub mod state;
pub mod upstream;

pub use downstream::{DownstreamConfig, DownstreamForward, DownstreamPublisher};
#[cfg(feature = "driad")]
pub use driad::{
    AMTRELAY_RRTYPE, AmtRelayRecord, AmtRelayTarget, DriadError, DriadRelaySelection,
    DriadResolver, DriadResolverConfig, reverse_source_name,
};
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
