use crate::membership::{MembershipRecord, MembershipRecordKind, MembershipReport};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RelayState {
    endpoints: BTreeMap<SocketAddr, EndpointState>,
}

impl RelayState {
    pub fn apply_report(&mut self, endpoint: SocketAddr, report: &MembershipReport) -> usize {
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

        applied
    }

    pub fn remove_endpoint(&mut self, endpoint: SocketAddr) -> bool {
        self.endpoints.remove(&endpoint).is_some()
    }

    pub fn contains_endpoint(&self, endpoint: SocketAddr) -> bool {
        self.endpoints.contains_key(&endpoint)
    }

    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    pub fn endpoint_interest(&self, endpoint: SocketAddr, group: IpAddr) -> Option<&GroupInterest> {
        self.endpoints
            .get(&endpoint)
            .and_then(|state| state.groups.get(&group))
    }

    pub fn endpoints_for_packet(&self, source: IpAddr, group: IpAddr) -> Vec<SocketAddr> {
        self.endpoints
            .iter()
            .filter_map(|(endpoint, state)| {
                state
                    .groups
                    .get(&group)
                    .filter(|interest| interest.wants_source(source))
                    .map(|_| *endpoint)
            })
            .collect()
    }

    pub fn upstream_subscriptions(&self) -> Vec<UpstreamSubscription> {
        let mut subscriptions = BTreeSet::new();
        for (group, interest) in self.aggregate_interests() {
            match interest.mode {
                FilterMode::Exclude => {
                    subscriptions.insert(UpstreamSubscription::asm(group));
                }
                FilterMode::Include => {
                    subscriptions.extend(
                        interest
                            .sources
                            .into_iter()
                            .map(|source| UpstreamSubscription::ssm(group, source)),
                    );
                }
            }
        }

        subscriptions.into_iter().collect()
    }

    pub fn aggregate_interests(&self) -> BTreeMap<IpAddr, GroupInterest> {
        let mut groups = BTreeMap::<IpAddr, GroupSummary>::new();
        for state in self.endpoints.values() {
            for (group, interest) in &state.groups {
                groups.entry(*group).or_default().apply(interest);
            }
        }

        groups
            .into_iter()
            .filter_map(|(group, summary)| {
                summary.into_interest().map(|interest| (group, interest))
            })
            .collect()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct EndpointState {
    groups: BTreeMap<IpAddr, GroupInterest>,
}

impl EndpointState {
    fn apply_record(&mut self, record: &MembershipRecord) -> bool {
        match record.kind {
            MembershipRecordKind::LegacyReport => {
                self.groups.insert(record.group, GroupInterest::exclude([]));
                true
            }
            MembershipRecordKind::LegacyLeave => self.groups.remove(&record.group).is_some(),
            MembershipRecordKind::ModeIsInclude | MembershipRecordKind::ChangeToInclude => {
                if record.sources.is_empty() {
                    self.groups.remove(&record.group);
                } else {
                    self.groups.insert(
                        record.group,
                        GroupInterest::include(record.sources.iter().copied()),
                    );
                }
                true
            }
            MembershipRecordKind::ModeIsExclude | MembershipRecordKind::ChangeToExclude => {
                self.groups.insert(
                    record.group,
                    GroupInterest::exclude(record.sources.iter().copied()),
                );
                true
            }
            MembershipRecordKind::AllowNewSources => {
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
                true
            }
            MembershipRecordKind::BlockOldSources => {
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
                true
            }
        }
    }
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
        assert_eq!(
            state.endpoints_for_packet(blocked, group),
            Vec::<SocketAddr>::new()
        );
        assert_eq!(state.endpoints_for_packet(allowed, group), vec![endpoint]);
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
}
