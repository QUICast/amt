use crate::membership::{
    MembershipParseError, MembershipRecord, MembershipRecordKind, MembershipReport,
};
use crate::protocol::MembershipProtocol;
use crate::query::{GeneralQueryConfig, build_general_query};
use crate::state::{FilterMode, GroupInterest, RelayState, UpstreamSubscription};
use mcrx_core::{
    McrxError, RawContext, RawPacket, RawSubscriptionConfig, SourceFilter, SubscriptionId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

const IGMPV3_REPORT_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);
const MLDV2_REPORT_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMembershipConfig {
    pub protocol: MembershipProtocol,
    pub interface: Option<IpAddr>,
    pub interface_index: Option<u32>,
    pub query_interval: Option<Duration>,
}

impl LocalMembershipConfig {
    pub fn new(protocol: MembershipProtocol) -> Self {
        Self {
            protocol,
            interface: None,
            interface_index: None,
            query_interval: Some(Duration::from_secs(30)),
        }
    }
}

#[derive(Debug)]
pub struct LocalMembershipManager {
    config: LocalMembershipConfig,
    context: RawContext,
    subscription_id: SubscriptionId,
    state: RelayState,
    advertised: BTreeMap<IpAddr, GroupInterest>,
}

impl LocalMembershipManager {
    pub fn new(config: LocalMembershipConfig) -> Result<Self, McrxError> {
        let mut context = RawContext::new();
        let subscription_id = context.add_subscription(raw_config_for(&config))?;
        context.join_subscription(subscription_id)?;

        Ok(Self {
            config,
            context,
            subscription_id,
            state: RelayState::default(),
            advertised: BTreeMap::new(),
        })
    }

    pub const fn config(&self) -> &LocalMembershipConfig {
        &self.config
    }

    pub const fn subscription_id(&self) -> SubscriptionId {
        self.subscription_id
    }

    pub fn local_query(&self) -> Vec<u8> {
        build_general_query(self.config.protocol, &self.query_config())
    }

    pub fn try_recv(&mut self) -> Result<Option<LocalMembershipEvent>, LocalMembershipError> {
        while let Some(packet) = self.context.try_recv_any()? {
            let report = crate::membership::parse_membership_report(packet.datagram())?;
            if report.protocol != self.config.protocol {
                continue;
            }

            let Some(reporter) = reporter_address(&packet) else {
                continue;
            };

            let records_received = report.records.len();
            self.state
                .apply_report(SocketAddr::new(reporter, 0), &report);
            let active_subscriptions = self.current_subscriptions();

            return Ok(Some(LocalMembershipEvent {
                reporter,
                records_received,
                active_subscriptions,
            }));
        }

        Ok(None)
    }

    pub fn pending_report(&self) -> Option<MembershipReport> {
        let current = self.current_exportable_interests();
        let records = delta_records(self.config.protocol, &self.advertised, &current);
        (!records.is_empty()).then_some(MembershipReport {
            protocol: self.config.protocol,
            records,
        })
    }

    pub fn current_report(&self) -> Option<MembershipReport> {
        let records = self
            .current_exportable_interests()
            .into_iter()
            .filter(|(group, _)| group_matches_protocol(self.config.protocol, *group))
            .map(|(group, interest)| record_for_interest(group, &interest, ReportRecordMode::State))
            .collect::<Vec<_>>();

        (!records.is_empty()).then_some(MembershipReport {
            protocol: self.config.protocol,
            records,
        })
    }

    pub fn mark_advertised(&mut self) {
        self.advertised = self.current_exportable_interests();
    }

    fn current_subscriptions(&self) -> Vec<UpstreamSubscription> {
        self.state.upstream_subscriptions()
    }

    fn current_interests(&self) -> BTreeMap<IpAddr, GroupInterest> {
        self.state.aggregate_interests()
    }

    fn current_exportable_interests(&self) -> BTreeMap<IpAddr, GroupInterest> {
        filter_exportable_interests(self.config.protocol, self.current_interests())
    }

    fn query_config(&self) -> GeneralQueryConfig {
        let mut config = GeneralQueryConfig::default();
        match (self.config.protocol, self.config.interface) {
            (MembershipProtocol::Igmpv3, Some(IpAddr::V4(interface))) => {
                config.igmp_source = interface;
            }
            (MembershipProtocol::Mldv2, Some(IpAddr::V6(interface))) => {
                config.mld_source = interface;
            }
            _ => {}
        }
        config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMembershipEvent {
    pub reporter: IpAddr,
    pub records_received: usize,
    pub active_subscriptions: Vec<UpstreamSubscription>,
}

#[derive(Debug)]
pub enum LocalMembershipError {
    Mcrx(McrxError),
    Parse(MembershipParseError),
}

impl LocalMembershipError {
    pub const fn is_parse_error(&self) -> bool {
        matches!(self, Self::Parse(_))
    }
}

impl fmt::Display for LocalMembershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mcrx(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LocalMembershipError {}

impl From<McrxError> for LocalMembershipError {
    fn from(value: McrxError) -> Self {
        Self::Mcrx(value)
    }
}

impl From<MembershipParseError> for LocalMembershipError {
    fn from(value: MembershipParseError) -> Self {
        Self::Parse(value)
    }
}

fn raw_config_for(config: &LocalMembershipConfig) -> RawSubscriptionConfig {
    let group = match config.protocol {
        MembershipProtocol::Igmpv3 => IpAddr::V4(IGMPV3_REPORT_GROUP),
        MembershipProtocol::Mldv2 => IpAddr::V6(MLDV2_REPORT_GROUP),
    };

    let interface = match (config.protocol, config.interface) {
        (MembershipProtocol::Igmpv3, Some(IpAddr::V4(interface))) => Some(IpAddr::V4(interface)),
        (MembershipProtocol::Mldv2, Some(IpAddr::V6(interface))) => Some(IpAddr::V6(interface)),
        _ => None,
    };

    RawSubscriptionConfig {
        group,
        source: SourceFilter::Any,
        interface,
        interface_index: matches!(config.protocol, MembershipProtocol::Mldv2)
            .then_some(config.interface_index)
            .flatten(),
    }
}

fn reporter_address(packet: &RawPacket) -> Option<IpAddr> {
    packet
        .source_ip
        .or_else(|| parse_datagram_source(packet.datagram()))
}

fn parse_datagram_source(datagram: &[u8]) -> Option<IpAddr> {
    match datagram.first()? >> 4 {
        4 if datagram.len() >= 20 => {
            Some(Ipv4Addr::new(datagram[12], datagram[13], datagram[14], datagram[15]).into())
        }
        6 if datagram.len() >= 40 => {
            Some(Ipv6Addr::from(<[u8; 16]>::try_from(&datagram[8..24]).ok()?).into())
        }
        _ => None,
    }
}

fn delta_records(
    protocol: MembershipProtocol,
    previous: &BTreeMap<IpAddr, GroupInterest>,
    current: &BTreeMap<IpAddr, GroupInterest>,
) -> Vec<MembershipRecord> {
    let groups = previous
        .keys()
        .chain(current.keys())
        .copied()
        .collect::<BTreeSet<_>>();

    let mut records = Vec::new();
    for group in groups {
        if !group_matches_protocol(protocol, group) {
            continue;
        }

        let previous = previous.get(&group);
        let current = current.get(&group);
        if previous == current {
            continue;
        }

        match current {
            Some(interest) => records.push(record_for_interest(
                group,
                interest,
                ReportRecordMode::Change,
            )),
            None => records.push(MembershipRecord {
                kind: MembershipRecordKind::ChangeToInclude,
                group,
                sources: Vec::new(),
            }),
        }
    }

    records
}

fn record_for_interest(
    group: IpAddr,
    interest: &GroupInterest,
    mode: ReportRecordMode,
) -> MembershipRecord {
    match interest.mode {
        FilterMode::Include => MembershipRecord {
            kind: match mode {
                ReportRecordMode::State => MembershipRecordKind::ModeIsInclude,
                ReportRecordMode::Change => MembershipRecordKind::ChangeToInclude,
            },
            group,
            sources: interest.sources.iter().copied().collect(),
        },
        FilterMode::Exclude => MembershipRecord {
            kind: match mode {
                ReportRecordMode::State => MembershipRecordKind::ModeIsExclude,
                ReportRecordMode::Change => MembershipRecordKind::ChangeToExclude,
            },
            group,
            sources: interest.sources.iter().copied().collect(),
        },
    }
}

fn group_matches_protocol(protocol: MembershipProtocol, group: IpAddr) -> bool {
    matches!(
        (protocol, group),
        (MembershipProtocol::Igmpv3, IpAddr::V4(_)) | (MembershipProtocol::Mldv2, IpAddr::V6(_))
    )
}

fn filter_exportable_interests(
    protocol: MembershipProtocol,
    interests: BTreeMap<IpAddr, GroupInterest>,
) -> BTreeMap<IpAddr, GroupInterest> {
    interests
        .into_iter()
        .filter(|(group, _)| group_matches_protocol(protocol, *group))
        .filter(|(group, _)| is_amt_exportable_group(*group))
        .collect()
}

fn is_amt_exportable_group(group: IpAddr) -> bool {
    match group {
        IpAddr::V4(group) => is_amt_exportable_ipv4_group(group),
        IpAddr::V6(group) => is_amt_exportable_ipv6_group(group),
    }
}

fn is_amt_exportable_ipv4_group(group: Ipv4Addr) -> bool {
    if !group.is_multicast() {
        return false;
    }

    let octets = group.octets();
    !matches!(
        octets,
        [224, 0, 0, _] | [239, 255, 255, 250] | [239, 255, 255, 253]
    )
}

fn is_amt_exportable_ipv6_group(group: Ipv6Addr) -> bool {
    group.is_multicast() && group.segments()[0] & 0x000f != 0x0002
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportRecordMode {
    State,
    Change,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{MembershipRecordKind, MembershipReport};

    fn report(records: Vec<MembershipRecord>) -> MembershipReport {
        MembershipReport {
            protocol: MembershipProtocol::Igmpv3,
            records,
        }
    }

    fn record(
        kind: MembershipRecordKind,
        group: impl Into<IpAddr>,
        sources: Vec<IpAddr>,
    ) -> MembershipRecord {
        MembershipRecord {
            kind,
            group: group.into(),
            sources,
        }
    }

    #[test]
    fn delta_advertises_asm_join_and_leave() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let previous = BTreeMap::new();
        let current = BTreeMap::from([(group, GroupInterest::exclude([]))]);

        assert_eq!(
            delta_records(MembershipProtocol::Igmpv3, &previous, &current),
            vec![record(
                MembershipRecordKind::ChangeToExclude,
                group,
                Vec::new()
            )]
        );

        assert_eq!(
            delta_records(MembershipProtocol::Igmpv3, &current, &previous),
            vec![record(
                MembershipRecordKind::ChangeToInclude,
                group,
                Vec::new()
            )]
        );
    }

    #[test]
    fn delta_advertises_exact_remaining_ssm_sources() {
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let first_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let second_source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
        let previous =
            BTreeMap::from([(group, GroupInterest::include([first_source, second_source]))]);
        let current = BTreeMap::from([(group, GroupInterest::include([second_source]))]);

        assert_eq!(
            delta_records(MembershipProtocol::Igmpv3, &previous, &current),
            vec![record(
                MembershipRecordKind::ChangeToInclude,
                group,
                vec![second_source]
            )]
        );
    }

    #[test]
    fn delta_preserves_exclude_source_filters() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let blocked = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let previous = BTreeMap::new();
        let current = BTreeMap::from([(group, GroupInterest::exclude([blocked]))]);

        assert_eq!(
            delta_records(MembershipProtocol::Igmpv3, &previous, &current),
            vec![record(
                MembershipRecordKind::ChangeToExclude,
                group,
                vec![blocked]
            )]
        );
    }

    #[test]
    fn current_report_uses_state_records_for_refreshes() {
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut manager = LocalMembershipManager {
            config: LocalMembershipConfig::new(MembershipProtocol::Igmpv3),
            context: RawContext::new(),
            subscription_id: SubscriptionId(0),
            state: RelayState::default(),
            advertised: BTreeMap::new(),
        };

        manager.state.apply_report(
            SocketAddr::from(([192, 168, 1, 10], 0)),
            &report(vec![record(
                MembershipRecordKind::ModeIsInclude,
                group,
                vec![source],
            )]),
        );

        assert_eq!(
            manager.current_report(),
            Some(report(vec![record(
                MembershipRecordKind::ModeIsInclude,
                group,
                vec![source]
            )]))
        );
    }

    #[test]
    fn transparent_export_filters_ipv4_link_local_and_service_discovery_groups() {
        let link_local = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
        let ssdp = IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250));
        let exportable = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let current = BTreeMap::from([
            (link_local, GroupInterest::exclude([])),
            (ssdp, GroupInterest::exclude([])),
            (exportable, GroupInterest::exclude([])),
        ]);

        assert_eq!(
            filter_exportable_interests(MembershipProtocol::Igmpv3, current),
            BTreeMap::from([(exportable, GroupInterest::exclude([]))])
        );
    }

    #[test]
    fn transparent_export_filters_ipv6_link_local_groups() {
        let link_local = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb));
        let site_local = IpAddr::V6(Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x1234));
        let current = BTreeMap::from([
            (link_local, GroupInterest::exclude([])),
            (site_local, GroupInterest::exclude([])),
        ]);

        assert_eq!(
            filter_exportable_interests(MembershipProtocol::Mldv2, current),
            BTreeMap::from([(site_local, GroupInterest::exclude([]))])
        );
    }

    #[test]
    fn current_report_omits_non_exportable_transparent_groups() {
        let exportable = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let mut manager = LocalMembershipManager {
            config: LocalMembershipConfig::new(MembershipProtocol::Igmpv3),
            context: RawContext::new(),
            subscription_id: SubscriptionId(0),
            state: RelayState::default(),
            advertised: BTreeMap::new(),
        };

        manager.state.apply_report(
            SocketAddr::from(([192, 168, 1, 10], 0)),
            &report(vec![
                record(
                    MembershipRecordKind::ModeIsExclude,
                    Ipv4Addr::new(224, 0, 0, 251),
                    Vec::new(),
                ),
                record(MembershipRecordKind::ModeIsExclude, exportable, Vec::new()),
            ]),
        );

        assert_eq!(
            manager.current_report(),
            Some(report(vec![record(
                MembershipRecordKind::ModeIsExclude,
                exportable,
                Vec::new()
            )]))
        );
    }

    #[test]
    fn pending_report_leaves_previously_advertised_exportable_group() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let mut manager = LocalMembershipManager {
            config: LocalMembershipConfig::new(MembershipProtocol::Igmpv3),
            context: RawContext::new(),
            subscription_id: SubscriptionId(0),
            state: RelayState::default(),
            advertised: BTreeMap::from([(group, GroupInterest::exclude([]))]),
        };

        manager.state.apply_report(
            SocketAddr::from(([192, 168, 1, 10], 0)),
            &report(vec![record(
                MembershipRecordKind::ModeIsExclude,
                Ipv4Addr::new(224, 0, 0, 251),
                Vec::new(),
            )]),
        );

        assert_eq!(
            manager.pending_report(),
            Some(report(vec![record(
                MembershipRecordKind::ChangeToInclude,
                group,
                Vec::new()
            )]))
        );
    }

    #[test]
    fn tracker_keeps_group_advertised_until_all_local_reporters_leave() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let first = SocketAddr::from(([192, 168, 1, 10], 0));
        let second = SocketAddr::from(([192, 168, 1, 11], 0));
        let mut state = RelayState::default();
        state.apply_report(
            first,
            &report(vec![record(
                MembershipRecordKind::ModeIsExclude,
                group,
                Vec::new(),
            )]),
        );
        state.apply_report(
            second,
            &report(vec![record(
                MembershipRecordKind::ModeIsExclude,
                group,
                Vec::new(),
            )]),
        );

        let advertised = state
            .aggregate_interests()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        state.apply_report(
            first,
            &report(vec![record(
                MembershipRecordKind::ChangeToInclude,
                group,
                Vec::new(),
            )]),
        );
        let current = state
            .aggregate_interests()
            .into_iter()
            .collect::<BTreeMap<_, _>>();

        assert!(delta_records(MembershipProtocol::Igmpv3, &advertised, &current).is_empty());
        assert_eq!(
            current,
            BTreeMap::from([(group, GroupInterest::exclude([]))])
        );
    }
}
