//! Native multicast data-plane integration for AMTQ.

mod gateway;
mod io;
mod relay;

pub use gateway::{
    NativeGateway, NativeGatewayConfig, NativeGatewaySnapshot, NativeGatewayStats,
    NativeGatewayStop,
};
pub use io::NativeIoConfig;
pub use relay::{
    NativeRelay, NativeRelayConfig, NativeRelaySnapshot, NativeRelayStats, NativeRelayStop,
};

use crate::ProtocolError;
use crate::transport::endpoint::EndpointError;
use crate::transport::tokio_quiche::ControllerClosed;
use amt::membership::{MembershipBuildError, build_membership_report};
use amt::{
    MembershipProtocol, MembershipRecord, MembershipRecordKind, MembershipReport,
    is_amt_forwardable_group,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

#[derive(Debug)]
pub enum NativeError {
    InvalidConfig(&'static str),
    Endpoint(EndpointError),
    Protocol(ProtocolError),
    MembershipBuild(MembershipBuildError),
    NativeIo(String),
    ConnectionClosed { clean: bool },
    RuntimeStopped,
    Task(String),
}

impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid AMTQ native data-plane config: {reason}")
            }
            Self::Endpoint(error) => write!(formatter, "{error}"),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::MembershipBuild(error) => write!(formatter, "{error}"),
            Self::NativeIo(error) => write!(formatter, "AMTQ native multicast error: {error}"),
            Self::ConnectionClosed { clean } => {
                write!(
                    formatter,
                    "AMTQ connection closed before shutdown (clean={clean})"
                )
            }
            Self::RuntimeStopped => formatter.write_str("AMTQ native data plane has stopped"),
            Self::Task(error) => write!(formatter, "AMTQ runtime task failed: {error}"),
        }
    }
}

impl std::error::Error for NativeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Endpoint(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::MembershipBuild(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EndpointError> for NativeError {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}

impl From<ProtocolError> for NativeError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<MembershipBuildError> for NativeError {
    fn from(error: MembershipBuildError) -> Self {
        Self::MembershipBuild(error)
    }
}

impl From<ControllerClosed> for NativeError {
    fn from(_: ControllerClosed) -> Self {
        Self::RuntimeStopped
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeJoin {
    pub source: Option<IpAddr>,
    pub group: IpAddr,
}

impl NativeJoin {
    pub const fn asm(group: IpAddr) -> Self {
        Self {
            source: None,
            group,
        }
    }

    pub const fn ssm(source: IpAddr, group: IpAddr) -> Self {
        Self {
            source: Some(source),
            group,
        }
    }
}

/// Builds one full current-state report from static ASM and SSM joins.
pub fn static_membership_report(
    protocol: MembershipProtocol,
    joins: impl IntoIterator<Item = NativeJoin>,
) -> Result<MembershipReport, NativeError> {
    #[derive(Default)]
    struct GroupJoin {
        asm: bool,
        sources: BTreeSet<IpAddr>,
    }

    let mut groups = BTreeMap::<IpAddr, GroupJoin>::new();
    for join in joins {
        if !group_matches_protocol(protocol, join.group) {
            return Err(NativeError::InvalidConfig(
                "membership group does not match the selected protocol",
            ));
        }
        if !is_amt_forwardable_group(join.group) {
            return Err(NativeError::InvalidConfig(
                "membership group is not AMT-forwardable",
            ));
        }

        let group = groups.entry(join.group).or_default();
        match join.source {
            None => {
                if !group.sources.is_empty() {
                    return Err(NativeError::InvalidConfig(
                        "one group cannot mix ASM and SSM joins",
                    ));
                }
                group.asm = true;
            }
            Some(source) => {
                if group.asm {
                    return Err(NativeError::InvalidConfig(
                        "one group cannot mix ASM and SSM joins",
                    ));
                }
                if !source_matches_group(source, join.group) || !valid_source(source) {
                    return Err(NativeError::InvalidConfig(
                        "membership source is invalid or uses the wrong address family",
                    ));
                }
                group.sources.insert(source);
            }
        }
    }

    let records = groups
        .into_iter()
        .map(|(group, join)| MembershipRecord {
            kind: if join.asm {
                MembershipRecordKind::ModeIsExclude
            } else {
                MembershipRecordKind::ModeIsInclude
            },
            group,
            sources: join.sources.into_iter().collect(),
        })
        .collect();
    let report = MembershipReport { protocol, records };
    build_membership_report(&report)?;
    Ok(report)
}

fn group_matches_protocol(protocol: MembershipProtocol, group: IpAddr) -> bool {
    matches!(
        (protocol, group),
        (MembershipProtocol::Igmpv3, IpAddr::V4(_)) | (MembershipProtocol::Mldv2, IpAddr::V6(_))
    )
}

fn source_matches_group(source: IpAddr, group: IpAddr) -> bool {
    matches!(
        (source, group),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn valid_source(source: IpAddr) -> bool {
    match source {
        IpAddr::V4(source) => {
            !source.is_unspecified() && !source.is_multicast() && !source.is_broadcast()
        }
        IpAddr::V6(source) => !source.is_unspecified() && !source.is_multicast(),
    }
}

fn random_request_nonce() -> Result<u32, NativeError> {
    let mut bytes = [0; 4];
    getrandom::fill(&mut bytes).map_err(|error| {
        NativeError::NativeIo(format!("request nonce generation failed: {error}"))
    })?;
    let nonce = u32::from_ne_bytes(bytes);
    Ok(if nonce == 0 { 1 } else { nonce })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn static_membership_aggregates_ssm_sources() {
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let source_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let source_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        let report = static_membership_report(
            MembershipProtocol::Igmpv3,
            [
                NativeJoin::ssm(source_a, group),
                NativeJoin::ssm(source_b, group),
                NativeJoin::ssm(source_a, group),
            ],
        )
        .unwrap();

        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].kind, MembershipRecordKind::ModeIsInclude);
        assert_eq!(report.records[0].sources, vec![source_a, source_b]);
    }

    #[test]
    fn static_membership_rejects_asm_ssm_overlap() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        assert!(matches!(
            static_membership_report(
                MembershipProtocol::Igmpv3,
                [NativeJoin::asm(group), NativeJoin::ssm(source, group)]
            ),
            Err(NativeError::InvalidConfig(_))
        ));
    }

    #[test]
    fn static_membership_rejects_local_control_groups() {
        assert!(
            static_membership_report(
                MembershipProtocol::Igmpv3,
                [NativeJoin::asm(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)))]
            )
            .is_err()
        );
    }
}
