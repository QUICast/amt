use crate::membership::{MembershipRecord, MembershipRecordKind, MembershipReport};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Stable identity used to bind multicast reception state to one tunnel.
///
/// Classic AMT uses the gateway's UDP endpoint. Transports with their own
/// connection identity, such as AMTQ, can use a connection-local newtype and
/// return `None` from [`MembershipEndpoint::source_ip`].
pub trait MembershipEndpoint: Copy + Ord {
    fn source_ip(self) -> Option<IpAddr>;
}

impl MembershipEndpoint for SocketAddr {
    fn source_ip(self) -> Option<IpAddr> {
        Some(self.ip())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FilterMode {
    Include,
    Exclude,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInterest {
    pub mode: FilterMode,
    pub sources: BTreeSet<IpAddr>,
}

impl GroupInterest {
    pub fn include(sources: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            mode: FilterMode::Include,
            sources: sources.into_iter().collect(),
        }
    }

    pub fn exclude(sources: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            mode: FilterMode::Exclude,
            sources: sources.into_iter().collect(),
        }
    }

    pub fn wants_source(&self, source: IpAddr) -> bool {
        match self.mode {
            FilterMode::Include => self.sources.contains(&source),
            FilterMode::Exclude => !self.sources.contains(&source),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UpstreamSubscription {
    pub group: IpAddr,
    pub source: Option<IpAddr>,
}

impl UpstreamSubscription {
    pub fn asm(group: IpAddr) -> Self {
        Self {
            group,
            source: None,
        }
    }

    pub fn ssm(group: IpAddr, source: IpAddr) -> Self {
        Self {
            group,
            source: Some(source),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLimits {
    pub max_endpoints: usize,
    pub max_endpoints_per_ip: usize,
    pub max_groups_per_endpoint: usize,
    pub max_sources_per_group: usize,
    pub max_total_endpoint_groups: usize,
    pub max_total_sources: usize,
    pub max_upstream_subscriptions: usize,
    pub max_records_per_report: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_endpoints: 4_096,
            max_endpoints_per_ip: 256,
            max_groups_per_endpoint: 128,
            max_sources_per_group: 128,
            max_total_endpoint_groups: 16_384,
            max_total_sources: 65_536,
            max_upstream_subscriptions: 256,
            max_records_per_report: 512,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLimitError {
    pub resource: &'static str,
    pub requested: usize,
    pub limit: usize,
}

impl fmt::Display for StateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AMT relay {} limit exceeded: requested {}, limit {}",
            self.resource, self.requested, self.limit
        )
    }
}

impl std::error::Error for StateLimitError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipTable<K: MembershipEndpoint> {
    endpoints: BTreeMap<K, EndpointState>,
    forwarding: BTreeMap<IpAddr, BTreeSet<K>>,
    aggregate: BTreeMap<IpAddr, GroupInterest>,
    subscriptions: BTreeSet<UpstreamSubscription>,
    total_endpoint_groups: usize,
    total_sources: usize,
}

impl<K: MembershipEndpoint> Default for MembershipTable<K> {
    fn default() -> Self {
        Self {
            endpoints: BTreeMap::new(),
            forwarding: BTreeMap::new(),
            aggregate: BTreeMap::new(),
            subscriptions: BTreeSet::new(),
            total_endpoint_groups: 0,
            total_sources: 0,
        }
    }
}

/// RFC 7450 relay state keyed by a gateway's UDP endpoint.
pub type RelayState = MembershipTable<SocketAddr>;

impl<K: MembershipEndpoint> MembershipTable<K> {
    pub(crate) fn preview_report(&self, endpoint: K, report: &MembershipReport) -> (usize, bool) {
        if report.records.is_empty() {
            return (0, false);
        }

        let current = self.endpoints.get(&endpoint);
        let mut candidate = current.cloned().unwrap_or_default();
        let applied = report
            .records
            .iter()
            .filter(|record| candidate.apply_record(record))
            .count();
        let changed = if candidate.groups.is_empty() {
            current.is_some()
        } else {
            current != Some(&candidate)
        };
        (applied, changed)
    }

    pub fn apply_report(&mut self, endpoint: K, report: &MembershipReport) -> usize {
        if report.records.is_empty() {
            return 0;
        }

        let endpoint_state = self.endpoints.entry(endpoint).or_default();
        let mut applied = 0;
        for record in &report.records {
            if endpoint_state.apply_record(record) {
                applied += 1;
            }
        }

        if endpoint_state.groups.is_empty() {
            self.endpoints.remove(&endpoint);
        }

        self.rebuild_indexes();

        applied
    }

    pub fn apply_report_limited(
        &mut self,
        endpoint: K,
        report: &MembershipReport,
        limits: &RelayLimits,
    ) -> Result<usize, StateLimitError> {
        check_limit(
            "records per report",
            report.records.len(),
            limits.max_records_per_report,
        )?;
        for record in &report.records {
            check_limit(
                "sources per group",
                record.sources.len(),
                limits.max_sources_per_group,
            )?;
        }

        let previous = self.endpoints.get(&endpoint).cloned();
        let applied = self.apply_report(endpoint, report);
        let endpoint_state = self.endpoints.get(&endpoint);
        let endpoint_count = self.endpoints.len();
        let endpoint_ip_count = endpoint
            .source_ip()
            .map_or(0, |address| self.endpoint_count_for_ip(address));
        let endpoint_group_count = endpoint_state.map_or(0, |state| state.groups.len());
        let endpoint_group_source_count = endpoint_state
            .into_iter()
            .flat_map(|state| state.groups.values())
            .map(|interest| interest.sources.len())
            .max()
            .unwrap_or(0);
        let total_endpoint_groups = self.total_endpoint_groups;
        let total_sources = self.total_sources;

        let result = check_limit("endpoints", endpoint_count, limits.max_endpoints)
            .and_then(|()| {
                check_limit(
                    "endpoints per source IP",
                    endpoint_ip_count,
                    limits.max_endpoints_per_ip,
                )
            })
            .and_then(|()| {
                check_limit(
                    "groups per endpoint",
                    endpoint_group_count,
                    limits.max_groups_per_endpoint,
                )
            })
            .and_then(|()| {
                check_limit(
                    "sources per endpoint group",
                    endpoint_group_source_count,
                    limits.max_sources_per_group,
                )
            })
            .and_then(|()| {
                check_limit(
                    "total endpoint groups",
                    total_endpoint_groups,
                    limits.max_total_endpoint_groups,
                )
            })
            .and_then(|()| check_limit("total sources", total_sources, limits.max_total_sources))
            .and_then(|()| {
                check_limit(
                    "upstream subscriptions",
                    self.subscriptions.len(),
                    limits.max_upstream_subscriptions,
                )
            });

        if let Err(error) = result {
            match previous {
                Some(previous) => {
                    self.endpoints.insert(endpoint, previous);
                }
                None => {
                    self.endpoints.remove(&endpoint);
                }
            }
            self.rebuild_indexes();
            return Err(error);
        }

        Ok(applied)
    }

    pub fn remove_endpoint(&mut self, endpoint: K) -> bool {
        let removed = self.endpoints.remove(&endpoint).is_some();
        if removed {
            self.rebuild_indexes();
        }
        removed
    }

    pub fn contains_endpoint(&self, endpoint: K) -> bool {
        self.endpoints.contains_key(&endpoint)
    }

    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    pub fn endpoint_count_for_ip(&self, address: IpAddr) -> usize {
        self.endpoints
            .keys()
            .filter(|endpoint| endpoint.source_ip() == Some(address))
            .count()
    }

    pub fn is_ip_near_endpoint_limit(&self, address: IpAddr, limit: usize) -> bool {
        near_limit(self.endpoint_count_for_ip(address), limit)
    }

    pub fn endpoint_interest(&self, endpoint: K, group: IpAddr) -> Option<&GroupInterest> {
        self.endpoints
            .get(&endpoint)
            .and_then(|state| state.groups.get(&group))
    }

    pub fn endpoint_has_interests(&self, endpoint: K) -> bool {
        self.endpoints
            .get(&endpoint)
            .is_some_and(|state| !state.groups.is_empty())
    }

    pub fn endpoints_for_packet(&self, source: IpAddr, group: IpAddr) -> Vec<K> {
        self.matching_endpoints(source, group).collect()
    }

    pub fn matching_endpoints(
        &self,
        source: IpAddr,
        group: IpAddr,
    ) -> impl Iterator<Item = K> + '_ {
        self.forwarding
            .get(&group)
            .into_iter()
            .flat_map(move |endpoints| {
                endpoints.iter().filter_map(move |endpoint| {
                    self.endpoint_interest(*endpoint, group)
                        .is_some_and(|interest| interest.wants_source(source))
                        .then_some(*endpoint)
                })
            })
    }

    pub fn upstream_subscriptions(&self) -> Vec<UpstreamSubscription> {
        self.subscriptions.iter().cloned().collect()
    }

    pub fn has_ssm_interest(&self, source: IpAddr, group: IpAddr) -> bool {
        self.forwarding.get(&group).is_some_and(|endpoints| {
            endpoints.iter().any(|endpoint| {
                self.endpoint_interest(*endpoint, group)
                    .is_some_and(|interest| {
                        interest.mode == FilterMode::Include && interest.sources.contains(&source)
                    })
            })
        })
    }

    pub fn aggregate_interests(&self) -> BTreeMap<IpAddr, GroupInterest> {
        self.aggregate.clone()
    }

    pub fn aggregate_interests_iter(&self) -> impl Iterator<Item = (IpAddr, &GroupInterest)> {
        self.aggregate
            .iter()
            .map(|(group, interest)| (*group, interest))
    }

    pub fn is_near_limits(&self, limits: &RelayLimits) -> bool {
        near_limit(self.endpoints.len(), limits.max_endpoints)
            || near_limit(self.total_endpoint_groups, limits.max_total_endpoint_groups)
            || near_limit(self.total_sources, limits.max_total_sources)
            || near_limit(self.subscriptions.len(), limits.max_upstream_subscriptions)
    }

    fn rebuild_indexes(&mut self) {
        self.forwarding.clear();
        self.total_endpoint_groups = 0;
        self.total_sources = 0;
        let mut groups = BTreeMap::<IpAddr, GroupSummary>::new();
        for (endpoint, state) in &self.endpoints {
            self.total_endpoint_groups += state.groups.len();
            for (group, interest) in &state.groups {
                self.total_sources += interest.sources.len();
                self.forwarding.entry(*group).or_default().insert(*endpoint);
                groups.entry(*group).or_default().apply(interest);
            }
        }

        self.aggregate = groups
            .into_iter()
            .filter_map(|(group, summary)| {
                summary.into_interest().map(|interest| (group, interest))
            })
            .collect();
        self.subscriptions.clear();
        for (group, interest) in &self.aggregate {
            match interest.mode {
                FilterMode::Exclude => {
                    self.subscriptions.insert(UpstreamSubscription::asm(*group));
                }
                FilterMode::Include => {
                    self.subscriptions.extend(
                        interest
                            .sources
                            .iter()
                            .copied()
                            .map(|source| UpstreamSubscription::ssm(*group, source)),
                    );
                }
            }
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct EndpointState {
    groups: BTreeMap<IpAddr, GroupInterest>,
}

impl EndpointState {
    fn apply_record(&mut self, record: &MembershipRecord) -> bool {
        let before = self.groups.get(&record.group).cloned();
        match record.kind {
            MembershipRecordKind::LegacyReport => {
                self.groups.insert(record.group, GroupInterest::exclude([]));
            }
            MembershipRecordKind::LegacyLeave => {
                self.groups.remove(&record.group);
            }
            MembershipRecordKind::ModeIsInclude | MembershipRecordKind::ChangeToInclude => {
                if record.sources.is_empty() {
                    self.groups.remove(&record.group);
                } else {
                    self.groups.insert(
                        record.group,
                        GroupInterest::include(record.sources.iter().copied()),
                    );
                }
            }
            MembershipRecordKind::ModeIsExclude | MembershipRecordKind::ChangeToExclude => {
                self.groups.insert(
                    record.group,
                    GroupInterest::exclude(record.sources.iter().copied()),
                );
            }
            MembershipRecordKind::AllowNewSources => {
                if record.sources.is_empty() {
                    return false;
                }
                let interest = self
                    .groups
                    .entry(record.group)
                    .or_insert_with(|| GroupInterest::include([]));
                match interest.mode {
                    FilterMode::Include => interest.sources.extend(record.sources.iter().copied()),
                    FilterMode::Exclude => {
                        for source in &record.sources {
                            interest.sources.remove(source);
                        }
                    }
                }
            }
            MembershipRecordKind::BlockOldSources => {
                if record.sources.is_empty() {
                    return false;
                }
                if let Some(interest) = self.groups.get_mut(&record.group) {
                    match interest.mode {
                        FilterMode::Include => {
                            for source in &record.sources {
                                interest.sources.remove(source);
                            }
                            if interest.sources.is_empty() {
                                self.groups.remove(&record.group);
                            }
                        }
                        FilterMode::Exclude => {
                            interest.sources.extend(record.sources.iter().copied());
                        }
                    }
                }
            }
        }
        before != self.groups.get(&record.group).cloned()
    }
}

fn check_limit(
    resource: &'static str,
    requested: usize,
    limit: usize,
) -> Result<(), StateLimitError> {
    if requested <= limit {
        Ok(())
    } else {
        Err(StateLimitError {
            resource,
            requested,
            limit,
        })
    }
}

fn near_limit(value: usize, limit: usize) -> bool {
    limit != 0 && value >= limit - (limit / 10)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct GroupSummary {
    include_sources: BTreeSet<IpAddr>,
    exclude_sources: Option<BTreeSet<IpAddr>>,
}

impl GroupSummary {
    fn apply(&mut self, interest: &GroupInterest) {
        match interest.mode {
            FilterMode::Include => {
                self.include_sources
                    .extend(interest.sources.iter().copied());
            }
            FilterMode::Exclude => {
                if let Some(exclude_sources) = self.exclude_sources.as_mut() {
                    exclude_sources.retain(|source| interest.sources.contains(source));
                } else {
                    self.exclude_sources = Some(interest.sources.clone());
                }
            }
        }
    }

    fn into_interest(self) -> Option<GroupInterest> {
        if let Some(mut exclude_sources) = self.exclude_sources {
            for source in self.include_sources {
                exclude_sources.remove(&source);
            }
            return Some(GroupInterest::exclude(exclude_sources));
        }

        (!self.include_sources.is_empty()).then_some(GroupInterest::include(self.include_sources))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{MembershipRecord, MembershipRecordKind};
    use crate::protocol::MembershipProtocol;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn report(records: Vec<MembershipRecord>) -> MembershipReport {
        MembershipReport {
            protocol: MembershipProtocol::Igmpv3,
            records,
        }
    }

    fn record(kind: MembershipRecordKind, group: IpAddr, sources: Vec<IpAddr>) -> MembershipRecord {
        MembershipRecord {
            kind,
            group,
            sources,
        }
    }

    #[test]
    fn include_records_create_ssm_subscriptions() {
        let endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut state = RelayState::default();

        state.apply_report(
            endpoint,
            &report(vec![record(
                MembershipRecordKind::ModeIsInclude,
                group,
                vec![source],
            )]),
        );

        assert_eq!(
            state.upstream_subscriptions(),
            vec![UpstreamSubscription::ssm(group, source)]
        );
        assert!(state.has_ssm_interest(source, group));
        assert_eq!(state.endpoints_for_packet(source, group), vec![endpoint]);
    }

    #[test]
    fn exclude_records_create_asm_subscription_and_filter_blocked_sources() {
        let endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let group = IpAddr::V6(Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0x8000, 0x1234));
        let blocked = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let allowed = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let mut state = RelayState::default();

        state.apply_report(
            endpoint,
            &report(vec![record(
                MembershipRecordKind::ChangeToExclude,
                group,
                vec![blocked],
            )]),
        );

        assert_eq!(
            state.upstream_subscriptions(),
            vec![UpstreamSubscription::asm(group)]
        );
        assert!(!state.has_ssm_interest(allowed, group));
        assert_eq!(
            state.endpoints_for_packet(blocked, group),
            Vec::<SocketAddr>::new()
        );
        assert_eq!(state.endpoints_for_packet(allowed, group), vec![endpoint]);
    }

    #[test]
    fn ssm_interest_survives_asm_upstream_aggregation() {
        let asm_endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let ssm_endpoint = SocketAddr::from(([198, 51, 100, 9], 40_001));
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut state = RelayState::default();

        state.apply_report(
            asm_endpoint,
            &report(vec![record(
                MembershipRecordKind::ModeIsExclude,
                group,
                vec![],
            )]),
        );
        state.apply_report(
            ssm_endpoint,
            &report(vec![record(
                MembershipRecordKind::ModeIsInclude,
                group,
                vec![source],
            )]),
        );

        assert_eq!(
            state.upstream_subscriptions(),
            vec![UpstreamSubscription::asm(group)]
        );
        assert!(state.has_ssm_interest(source, group));
    }

    #[test]
    fn aggregate_interests_preserve_shared_exclude_filters() {
        let first_endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let second_endpoint = SocketAddr::from(([198, 51, 100, 9], 40_001));
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let first_blocked = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second_blocked = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let shared_blocked = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        let mut state = RelayState::default();

        state.apply_report(
            first_endpoint,
            &report(vec![record(
                MembershipRecordKind::ChangeToExclude,
                group,
                vec![first_blocked, shared_blocked],
            )]),
        );
        state.apply_report(
            second_endpoint,
            &report(vec![record(
                MembershipRecordKind::ChangeToExclude,
                group,
                vec![second_blocked, shared_blocked],
            )]),
        );

        assert_eq!(
            state.aggregate_interests(),
            BTreeMap::from([(group, GroupInterest::exclude([shared_blocked]))])
        );
    }

    #[test]
    fn block_removes_include_sources() {
        let endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut state = RelayState::default();

        state.apply_report(
            endpoint,
            &report(vec![
                record(MembershipRecordKind::AllowNewSources, group, vec![source]),
                record(MembershipRecordKind::BlockOldSources, group, vec![source]),
            ]),
        );

        assert!(state.upstream_subscriptions().is_empty());
        assert!(state.endpoints_for_packet(source, group).is_empty());
    }

    #[test]
    fn empty_include_leave_removes_only_reporting_endpoint() {
        let first_endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let second_endpoint = SocketAddr::from(([198, 51, 100, 9], 40_001));
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut state = RelayState::default();

        for endpoint in [first_endpoint, second_endpoint] {
            state.apply_report(
                endpoint,
                &report(vec![record(
                    MembershipRecordKind::ChangeToExclude,
                    group,
                    Vec::new(),
                )]),
            );
        }
        state.apply_report(
            first_endpoint,
            &report(vec![record(
                MembershipRecordKind::ChangeToInclude,
                group,
                Vec::new(),
            )]),
        );

        assert!(!state.contains_endpoint(first_endpoint));
        assert!(state.contains_endpoint(second_endpoint));
        assert_eq!(state.endpoint_count(), 1);
        assert_eq!(
            state.upstream_subscriptions(),
            vec![UpstreamSubscription::asm(group)]
        );
        assert_eq!(
            state.endpoints_for_packet(source, group),
            vec![second_endpoint]
        );
    }

    #[test]
    fn blocking_shared_ssm_source_preserves_other_gateway_interest() {
        let first_endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let second_endpoint = SocketAddr::from(([198, 51, 100, 9], 40_001));
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let mut state = RelayState::default();

        for endpoint in [first_endpoint, second_endpoint] {
            state.apply_report(
                endpoint,
                &report(vec![record(
                    MembershipRecordKind::AllowNewSources,
                    group,
                    vec![source],
                )]),
            );
        }
        state.apply_report(
            first_endpoint,
            &report(vec![record(
                MembershipRecordKind::BlockOldSources,
                group,
                vec![source],
            )]),
        );

        assert!(!state.contains_endpoint(first_endpoint));
        assert!(state.contains_endpoint(second_endpoint));
        assert_eq!(
            state.upstream_subscriptions(),
            vec![UpstreamSubscription::ssm(group, source)]
        );
        assert_eq!(
            state.endpoints_for_packet(source, group),
            vec![second_endpoint]
        );
    }

    #[test]
    fn empty_allow_new_sources_does_not_create_phantom_state() {
        let endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let mut state = RelayState::default();

        let applied = state.apply_report(
            endpoint,
            &report(vec![record(
                MembershipRecordKind::AllowNewSources,
                group,
                Vec::new(),
            )]),
        );

        assert_eq!(applied, 0);
        assert_eq!(state.endpoint_count(), 0);
        assert!(state.upstream_subscriptions().is_empty());
    }

    #[test]
    fn report_preview_detects_identical_and_net_no_change_updates() {
        let endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let mut state = RelayState::default();
        let join = report(vec![record(
            MembershipRecordKind::ModeIsExclude,
            group,
            Vec::new(),
        )]);
        state.apply_report(endpoint, &join);

        assert_eq!(state.preview_report(endpoint, &join), (0, false));
        assert_eq!(
            state.preview_report(
                endpoint,
                &report(vec![
                    record(MembershipRecordKind::ChangeToInclude, group, Vec::new()),
                    record(MembershipRecordKind::ChangeToExclude, group, Vec::new()),
                ])
            ),
            (2, false)
        );
    }

    #[test]
    fn resource_limit_rejection_rolls_back_state_and_indexes() {
        let endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let first_group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let second_group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 4));
        let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut state = RelayState::default();
        let limits = RelayLimits {
            max_groups_per_endpoint: 1,
            ..RelayLimits::default()
        };

        state
            .apply_report_limited(
                endpoint,
                &report(vec![record(
                    MembershipRecordKind::ModeIsInclude,
                    first_group,
                    vec![source],
                )]),
                &limits,
            )
            .unwrap();
        assert!(
            state
                .apply_report_limited(
                    endpoint,
                    &report(vec![record(
                        MembershipRecordKind::ModeIsInclude,
                        second_group,
                        vec![source],
                    )]),
                    &limits,
                )
                .is_err()
        );

        assert_eq!(
            state.upstream_subscriptions(),
            vec![UpstreamSubscription::ssm(first_group, source)]
        );
        assert_eq!(
            state.endpoints_for_packet(source, first_group),
            vec![endpoint]
        );
        assert!(state.endpoints_for_packet(source, second_group).is_empty());
    }

    #[test]
    fn accumulated_sources_cannot_bypass_per_group_limit() {
        let endpoint = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let group = IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3));
        let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let limits = RelayLimits {
            max_sources_per_group: 1,
            ..RelayLimits::default()
        };
        let mut state = RelayState::default();

        state
            .apply_report_limited(
                endpoint,
                &report(vec![record(
                    MembershipRecordKind::AllowNewSources,
                    group,
                    vec![first],
                )]),
                &limits,
            )
            .unwrap();
        assert!(
            state
                .apply_report_limited(
                    endpoint,
                    &report(vec![record(
                        MembershipRecordKind::AllowNewSources,
                        group,
                        vec![second],
                    )]),
                    &limits,
                )
                .is_err()
        );

        assert_eq!(
            state.endpoint_interest(endpoint, group).unwrap().sources,
            BTreeSet::from([first])
        );
    }

    #[test]
    fn endpoint_limit_is_enforced_per_source_ip() {
        let first = SocketAddr::from(([198, 51, 100, 8], 40_000));
        let second = SocketAddr::from(([198, 51, 100, 8], 40_001));
        let limits = RelayLimits {
            max_endpoints_per_ip: 1,
            ..RelayLimits::default()
        };
        let mut state = RelayState::default();

        state
            .apply_report_limited(
                first,
                &report(vec![record(
                    MembershipRecordKind::ModeIsExclude,
                    IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
                    Vec::new(),
                )]),
                &limits,
            )
            .unwrap();
        assert!(
            state
                .apply_report_limited(
                    second,
                    &report(vec![record(
                        MembershipRecordKind::ModeIsExclude,
                        IpAddr::V4(Ipv4Addr::new(239, 1, 2, 4)),
                        Vec::new(),
                    )]),
                    &limits,
                )
                .is_err()
        );
        assert_eq!(state.endpoint_count_for_ip(first.ip()), 1);
    }

    #[test]
    fn near_limit_does_not_overflow_for_large_limits() {
        assert!(!near_limit(usize::MAX / 2, usize::MAX));
        assert!(near_limit(usize::MAX - (usize::MAX / 10), usize::MAX));
    }
}
