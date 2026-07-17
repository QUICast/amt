//! Lightweight building blocks for Automatic Multicast Tunneling (AMT).
//!
//! The protocol codec intentionally stays runtime agnostic. Runtime-specific
//! loops, such as the simple blocking relay and gateway runners, live at the
//! crate edge.

#[cfg(target_os = "ios")]
compile_error!(
    "quicast-amt does not support iOS; the supported daemon targets are Linux, macOS, and Windows"
);

mod checksum;
#[cfg(all(feature = "runtime", not(target_os = "ios")))]
pub mod config;
#[cfg(all(feature = "runtime", not(target_os = "ios")))]
pub mod daemon;
#[cfg(all(feature = "native-multicast", not(target_os = "ios")))]
pub mod downstream;
#[cfg(feature = "driad")]
pub mod driad;
pub mod ecn;
pub mod gateway;
pub mod ip;
#[cfg(all(feature = "native-multicast", not(target_os = "ios")))]
pub mod local_membership;
pub mod membership;
#[cfg(all(feature = "runtime", not(target_os = "ios")))]
pub mod metrics;
pub mod mtu;
#[cfg(all(feature = "pmtu-feedback", not(target_os = "ios")))]
pub mod pmtu;
pub mod protocol;
pub mod query;
pub mod relay;
pub mod state;
#[cfg(all(feature = "runtime", not(target_os = "ios")))]
mod udp;
#[cfg(all(feature = "native-multicast", not(target_os = "ios")))]
pub mod upstream;

#[cfg(all(feature = "native-multicast", not(target_os = "ios")))]
pub use downstream::{DownstreamConfig, DownstreamForward, DownstreamPublisher};
#[cfg(feature = "driad")]
pub use driad::{
    AMT_ANYCAST_IPV4, AMT_ANYCAST_IPV6, AMTRELAY_RRTYPE, AmtRelayRecord, AmtRelayTarget,
    DriadError, DriadRelaySelection, DriadResolver, DriadResolverConfig, reverse_source_name,
};
pub use ecn::{EcnCodepoint, EcnDecapsulation, EcnError, decapsulate_ecn, ip_ecn};
pub use gateway::{Gateway, GatewayAction, GatewayConfig, GatewayError, GatewayPhase, GatewaySend};
pub use ip::{IpPacketError, MulticastPacket, is_amt_forwardable_group, parse_multicast_packet};
#[cfg(all(feature = "native-multicast", not(target_os = "ios")))]
pub use local_membership::{
    LocalMembershipConfig, LocalMembershipError, LocalMembershipEvent, LocalMembershipManager,
};
pub use membership::{
    MembershipBuildError, MembershipParseError, MembershipParseLimits, MembershipRecord,
    MembershipRecordKind, MembershipReport,
};
#[cfg(all(feature = "pmtu-feedback", not(target_os = "ios")))]
pub use pmtu::{PmtuFeedbackError, PmtuFeedbackOutcome, PmtuFeedbackSender, build_pmtu_feedback};
pub use protocol::{
    AMT_PORT, DecodeError, GatewayAddress, GatewayEndpoint, MembershipProtocol, Message,
    MessageType, ResponseMac,
};
pub use relay::{Relay, RelayAction, RelayConfig, RelayError, RelaySecret};
pub use state::{
    FilterMode, GroupInterest, MembershipEndpoint, MembershipTable, RelayLimits, RelayState,
    StateLimitError, UpstreamSubscription,
};
#[cfg(all(feature = "native-multicast", not(target_os = "ios")))]
pub use upstream::{UpstreamConfig, UpstreamDatagram, UpstreamManager, UpstreamReconcile};
