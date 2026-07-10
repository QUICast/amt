//! Lightweight building blocks for Automatic Multicast Tunneling (AMT).
//!
//! The protocol codec intentionally stays runtime agnostic. Runtime-specific
//! loops, such as the simple blocking relay and gateway runners, live at the
//! crate edge.

mod checksum;
#[cfg(feature = "runtime")]
pub mod config;
#[cfg(feature = "runtime")]
pub mod daemon;
#[cfg(feature = "runtime")]
pub mod downstream;
#[cfg(feature = "driad")]
pub mod driad;
pub mod gateway;
pub mod ip;
#[cfg(feature = "runtime")]
pub mod local_membership;
pub mod membership;
#[cfg(feature = "runtime")]
pub mod metrics;
pub mod mtu;
pub mod protocol;
pub mod query;
pub mod relay;
pub mod state;
#[cfg(feature = "runtime")]
pub mod upstream;

#[cfg(feature = "runtime")]
pub use downstream::{DownstreamConfig, DownstreamForward, DownstreamPublisher};
#[cfg(feature = "driad")]
pub use driad::{
    AMTRELAY_RRTYPE, AmtRelayRecord, AmtRelayTarget, DriadError, DriadRelaySelection,
    DriadResolver, DriadResolverConfig, reverse_source_name,
};
pub use gateway::{Gateway, GatewayAction, GatewayConfig, GatewayError, GatewayPhase, GatewaySend};
pub use ip::{IpPacketError, MulticastPacket, is_amt_forwardable_group, parse_multicast_packet};
#[cfg(feature = "runtime")]
pub use local_membership::{
    LocalMembershipConfig, LocalMembershipError, LocalMembershipEvent, LocalMembershipManager,
};
pub use membership::{
    MembershipBuildError, MembershipParseError, MembershipParseLimits, MembershipRecord,
    MembershipRecordKind, MembershipReport,
};
pub use protocol::{
    AMT_PORT, DecodeError, GatewayAddress, GatewayEndpoint, MembershipProtocol, Message,
    MessageType, ResponseMac,
};
pub use relay::{Relay, RelayAction, RelayConfig, RelayError, RelaySecret};
pub use state::{
    FilterMode, GroupInterest, RelayLimits, RelayState, StateLimitError, UpstreamSubscription,
};
#[cfg(feature = "runtime")]
pub use upstream::{UpstreamConfig, UpstreamDatagram, UpstreamManager, UpstreamReconcile};
