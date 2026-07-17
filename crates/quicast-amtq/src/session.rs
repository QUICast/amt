use crate::control::{Context, ContextClose, ControlRecord, DataMode, Settings};
use crate::datagram::{self, Datagram};
use crate::reassembly::{Reassembler, ReassemblyConfig};
use crate::reliable;
use crate::varint::MAX_VARINT;
use crate::{
    ApplicationError, EndpointRole, MAX_AMT_DATA_MESSAGE, MAX_OPEN_CONTEXTS,
    MIN_GATEWAY_DATAGRAM_SIZE, ProtocolError,
};
use amt::membership::parse_membership_report_with_limits;
use amt::protocol::encode;
use amt::query::validate_general_query;
use amt::{
    FilterMode, GroupInterest, MembershipEndpoint, MembershipParseLimits, MembershipProtocol,
    MembershipRecord, MembershipRecordKind, MembershipReport, MembershipTable, Message,
    RelayLimits, ResponseMac, UpstreamSubscription, is_amt_forwardable_group,
    parse_multicast_packet,
};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct GatewaySessionConfig {
    pub settings: Settings,
    pub relay_initial_max_streams_bidi: u64,
    pub gateway_initial_max_streams_uni: u64,
    pub membership_limits: RelayLimits,
    pub reassembly: ReassemblyConfig,
    pub max_reliable_block_ranges_per_context: usize,
}

impl Default for GatewaySessionConfig {
    fn default() -> Self {
        Self {
            settings: Settings::datagram_only(),
            relay_initial_max_streams_bidi: 1,
            gateway_initial_max_streams_uni: 0,
            membership_limits: RelayLimits::default(),
            reassembly: ReassemblyConfig::default(),
            max_reliable_block_ranges_per_context: 1_024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelaySessionConfig {
    pub settings: Settings,
    pub gateway_max_datagram_frame_size: Option<u64>,
    pub gateway_initial_max_streams_uni: u64,
    pub membership_limits: RelayLimits,
    pub max_inflight_reliable_blocks_per_context: usize,
}

impl Default for RelaySessionConfig {
    fn default() -> Self {
        Self {
            settings: Settings::datagram_only(),
            gateway_max_datagram_frame_size: Some(MIN_GATEWAY_DATAGRAM_SIZE),
            gateway_initial_max_streams_uni: 0,
            membership_limits: RelayLimits::default(),
            max_inflight_reliable_blocks_per_context: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayEvent {
    SettingsReceived,
    MembershipQuery {
        protocol: MembershipProtocol,
        request_nonce: u32,
        general_query: Vec<u8>,
    },
    ContextOpened {
        context: Context,
        acknowledgement: Vec<u8>,
    },
    ContextClosed {
        context_id: u64,
    },
    ContextClosing {
        context_id: u64,
        final_block_id: u64,
    },
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayEvent {
    SettingsReceived,
    Request {
        protocol: MembershipProtocol,
        request_nonce: u32,
    },
    MembershipUpdate(PendingMembershipUpdate),
    ContextAcknowledged {
        context_id: u64,
    },
    Ignored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SessionEndpoint;

impl MembershipEndpoint for SessionEndpoint {
    fn source_ip(self) -> Option<IpAddr> {
        None
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReceptionState {
    table: MembershipTable<SessionEndpoint>,
}

impl ReceptionState {
    pub fn wants(&self, source: IpAddr, group: IpAddr) -> bool {
        self.table
            .endpoint_interest(SessionEndpoint, group)
            .is_some_and(|interest| interest.wants_source(source))
    }

    pub fn has_interests(&self) -> bool {
        self.table.endpoint_has_interests(SessionEndpoint)
    }

    pub fn interest(&self, group: IpAddr) -> Option<&GroupInterest> {
        self.table.endpoint_interest(SessionEndpoint, group)
    }

    pub fn interests(&self) -> impl Iterator<Item = (IpAddr, &GroupInterest)> {
        self.table.aggregate_interests_iter()
    }

    pub fn upstream_subscriptions(&self) -> Vec<UpstreamSubscription> {
        self.table.upstream_subscriptions()
    }

    pub fn apply_report(&mut self, report: &MembershipReport) -> usize {
        self.table.apply_report(SessionEndpoint, report)
    }

    pub fn apply_report_limited(
        &mut self,
        report: &MembershipReport,
        limits: &RelayLimits,
    ) -> Result<usize, ProtocolError> {
        self.table
            .apply_report_limited(SessionEndpoint, report, limits)
            .map_err(|_| {
                ProtocolError::new(
                    ApplicationError::ExcessiveLoad,
                    "AMTQ membership state exceeds an admission limit",
                )
            })
    }

    pub fn is_subset_of(&self, requested: &Self) -> bool {
        self.interests().all(|(group, authorized)| {
            requested
                .interest(group)
                .is_some_and(|requested| interest_is_subset(authorized, requested))
        })
    }

    /// Returns the packet-set intersection of two reception states.
    ///
    /// Authorization policy can use this to retain previously authorized
    /// interest that is still requested while denying newly requested state.
    pub fn intersection(&self, other: &Self) -> Self {
        let mut ipv4_records = Vec::new();
        let mut ipv6_records = Vec::new();
        for (group, left) in self.interests() {
            let Some(right) = other.interest(group) else {
                continue;
            };
            let Some(interest) = intersection_interest(left, right) else {
                continue;
            };
            let record = MembershipRecord {
                kind: match interest.mode {
                    FilterMode::Include => MembershipRecordKind::ModeIsInclude,
                    FilterMode::Exclude => MembershipRecordKind::ModeIsExclude,
                },
                group,
                sources: interest.sources.into_iter().collect(),
            };
            match group {
                IpAddr::V4(_) => ipv4_records.push(record),
                IpAddr::V6(_) => ipv6_records.push(record),
            }
        }

        let mut result = Self::default();
        if !ipv4_records.is_empty() {
            result.apply_report(&MembershipReport {
                protocol: MembershipProtocol::Igmpv3,
                records: ipv4_records,
            });
        }
        if !ipv6_records.is_empty() {
            result.apply_report(&MembershipReport {
                protocol: MembershipProtocol::Mldv2,
                records: ipv6_records,
            });
        }
        result
    }

    pub fn current_report(&self, protocol: MembershipProtocol) -> MembershipReport {
        let records = self
            .interests()
            .filter(|(group, _)| {
                matches!(
                    (protocol, group),
                    (MembershipProtocol::Igmpv3, IpAddr::V4(_))
                        | (MembershipProtocol::Mldv2, IpAddr::V6(_))
                )
            })
            .map(|(group, interest)| MembershipRecord {
                kind: match interest.mode {
                    FilterMode::Include => MembershipRecordKind::ModeIsInclude,
                    FilterMode::Exclude => MembershipRecordKind::ModeIsExclude,
                },
                group,
                sources: interest.sources.iter().copied().collect(),
            })
            .collect();
        MembershipReport { protocol, records }
    }
}

fn intersection_interest(left: &GroupInterest, right: &GroupInterest) -> Option<GroupInterest> {
    let interest = match (left.mode, right.mode) {
        (FilterMode::Include, FilterMode::Include) => {
            GroupInterest::include(left.sources.intersection(&right.sources).copied())
        }
        (FilterMode::Include, FilterMode::Exclude) => {
            GroupInterest::include(left.sources.difference(&right.sources).copied())
        }
        (FilterMode::Exclude, FilterMode::Include) => {
            GroupInterest::include(right.sources.difference(&left.sources).copied())
        }
        (FilterMode::Exclude, FilterMode::Exclude) => {
            GroupInterest::exclude(left.sources.union(&right.sources).copied())
        }
    };
    (interest.mode == FilterMode::Exclude || !interest.sources.is_empty()).then_some(interest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMembershipUpdate {
    generation: u64,
    requested: ReceptionState,
    report: MembershipReport,
}

impl PendingMembershipUpdate {
    pub const fn report(&self) -> &MembershipReport {
        &self.report
    }

    pub const fn requested_state(&self) -> &ReceptionState {
        &self.requested
    }
}

#[derive(Debug)]
pub struct GatewaySession {
    negotiation: Negotiation,
    membership_limits: RelayLimits,
    protocol: Option<MembershipProtocol>,
    outstanding_request: Option<u32>,
    current_query_nonce: Option<u32>,
    requested: ReceptionState,
    contexts: BTreeMap<u64, GatewayContext>,
    last_context_id: Option<u64>,
    reassembler: Reassembler,
    max_reliable_block_ranges_per_context: usize,
}

impl GatewaySession {
    pub fn new(config: GatewaySessionConfig) -> Result<Self, ProtocolError> {
        config
            .settings
            .validate(EndpointRole::Gateway)
            .map_err(settings_error)?;
        if config.relay_initial_max_streams_bidi == 0 {
            return Err(ProtocolError::new(
                ApplicationError::Settings,
                "AMTQ Relay does not permit control Stream 0",
            ));
        }
        if config.settings.supports(DataMode::ReliableBlock)
            && config.gateway_initial_max_streams_uni == 0
        {
            return Err(ProtocolError::new(
                ApplicationError::Settings,
                "AMTQ Gateway advertised Reliable Block Mode without stream credit",
            ));
        }
        Ok(Self {
            negotiation: Negotiation::new(config.settings),
            membership_limits: config.membership_limits,
            protocol: None,
            outstanding_request: None,
            current_query_nonce: None,
            requested: ReceptionState::default(),
            contexts: BTreeMap::new(),
            last_context_id: None,
            reassembler: Reassembler::new(config.reassembly),
            max_reliable_block_ranges_per_context: config.max_reliable_block_ranges_per_context,
        })
    }

    pub fn settings_record(&mut self) -> Result<Vec<u8>, ProtocolError> {
        self.negotiation.settings_record(EndpointRole::Gateway)
    }

    pub const fn protocol(&self) -> Option<MembershipProtocol> {
        self.protocol
    }

    pub const fn requested_state(&self) -> &ReceptionState {
        &self.requested
    }

    pub fn begin_request(
        &mut self,
        request_nonce: u32,
        protocol: MembershipProtocol,
    ) -> Result<Vec<u8>, ProtocolError> {
        self.negotiation.ensure_ready()?;
        if self.outstanding_request.is_some() {
            return Err(ProtocolError::new(
                ApplicationError::AmtMessage,
                "an AMTQ Request is already outstanding",
            ));
        }
        if self.protocol.is_some_and(|selected| selected != protocol) {
            return Err(ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ connection membership protocol cannot change",
            ));
        }
        self.protocol = Some(protocol);
        self.outstanding_request = Some(request_nonce);
        encode_control_message(
            EndpointRole::Gateway,
            &Message::Request {
                request_nonce,
                protocol,
                ecn_capable: false,
            },
        )
    }

    pub fn membership_update(&mut self, packet: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        self.negotiation.ensure_ready()?;
        if self.outstanding_request.is_some() {
            return Err(ProtocolError::new(
                ApplicationError::AmtMessage,
                "Membership Update cannot be sent while a Request is outstanding",
            ));
        }
        let protocol = self.protocol.ok_or_else(|| {
            ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ membership protocol has not been selected",
            )
        })?;
        let request_nonce = self.current_query_nonce.ok_or_else(|| {
            ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ Membership Update has no accepted Membership Query",
            )
        })?;
        let report = parse_report(packet, protocol, &self.membership_limits)?;
        let mut candidate = self.requested.clone();
        candidate.apply_report_limited(&report, &self.membership_limits)?;
        let encoded = encode_control_message(
            EndpointRole::Gateway,
            &Message::MembershipUpdate {
                response_mac: ResponseMac::ZERO,
                request_nonce,
                membership_update: packet,
            },
        )?;
        self.requested = candidate;
        Ok(encoded)
    }

    pub fn handle_control(
        &mut self,
        record: ControlRecord<'_>,
    ) -> Result<GatewayEvent, ProtocolError> {
        match record {
            ControlRecord::Settings(settings) => {
                self.negotiation
                    .receive_settings(settings, EndpointRole::Relay)?;
                Ok(GatewayEvent::SettingsReceived)
            }
            _ if !self.negotiation.ready() => Err(ProtocolError::new(
                ApplicationError::Protocol,
                "AMTQ control record arrived before SETTINGS completed",
            )),
            ControlRecord::AmtControl(message) => self.handle_amt_control(message),
            ControlRecord::Context(context) => self.open_context(context),
            ControlRecord::ContextClose(context) => self.close_context(context),
            ControlRecord::ContextAck { .. } => Err(ProtocolError::new(
                ApplicationError::Protocol,
                "AMTQ Gateway received a CONTEXT_ACK",
            )),
            ControlRecord::Unknown { .. } => Ok(GatewayEvent::Ignored),
        }
    }

    pub fn handle_datagram(
        &mut self,
        input: &[u8],
        now: Instant,
    ) -> Result<Option<Vec<u8>>, ProtocolError> {
        let datagram = datagram::decode(input).map_err(|_| {
            ProtocolError::new(
                ApplicationError::Protocol,
                "invalid or excessive AMTQ Datagram",
            )
        })?;
        match datagram {
            Datagram::Unknown { .. } => Ok(None),
            Datagram::Complete {
                context_id,
                message,
            } => {
                let Some(context) = self.contexts.get(&context_id) else {
                    return Ok(None);
                };
                if context.mode != DataMode::Datagram
                    || !matches!(context.phase, GatewayContextPhase::Active)
                {
                    return Ok(None);
                }
                Ok(
                    validate_received_data(message, self.protocol, &self.requested)
                        .then(|| message.to_vec()),
                )
            }
            Datagram::Fragment(fragment) => {
                let context_id = fragment.context_id;
                let Some(context) = self.contexts.get(&context_id) else {
                    return Ok(None);
                };
                if context.mode != DataMode::Datagram {
                    return Ok(None);
                }
                let Some(message) = self.reassembler.push(fragment, now).unwrap_or(None) else {
                    return Ok(None);
                };
                let Some(context) = self.contexts.get(&context_id) else {
                    return Ok(None);
                };
                if !matches!(context.phase, GatewayContextPhase::Active) {
                    return Ok(None);
                }
                Ok(
                    validate_received_data(&message, self.protocol, &self.requested)
                        .then_some(message),
                )
            }
        }
    }

    pub fn begin_reliable_block(
        &mut self,
        context_id: u64,
        block_id: u64,
    ) -> Result<(), ProtocolError> {
        if block_id == 0 {
            return Err(context_error("AMTQ Reliable Block ID is zero"));
        }
        let context = self.contexts.get_mut(&context_id).ok_or_else(|| {
            context_error("Reliable Data Block uses an unknown or closed context")
        })?;
        if context.mode != DataMode::ReliableBlock {
            return Err(context_error(
                "Reliable Data Block uses a non-reliable context",
            ));
        }
        if let GatewayContextPhase::Closing { final_block_id } = context.phase
            && block_id > final_block_id
        {
            return Err(context_error(
                "Reliable Data Block exceeds the context Final Block ID",
            ));
        }
        match context
            .seen_blocks
            .insert(block_id, self.max_reliable_block_ranges_per_context)
        {
            IdInsert::Inserted => {}
            IdInsert::Duplicate => {
                return Err(context_error("AMTQ Reliable Block ID was reused"));
            }
            IdInsert::RangeLimit => {
                return Err(ProtocolError::new(
                    ApplicationError::ExcessiveLoad,
                    "too many disjoint AMTQ Reliable Block IDs",
                ));
            }
        }
        Ok(())
    }

    pub fn handle_reliable_data(
        &self,
        context_id: u64,
        block_id: u64,
        message: &[u8],
    ) -> Result<Option<Vec<u8>>, ProtocolError> {
        let context = self.contexts.get(&context_id).ok_or_else(|| {
            context_error("Reliable Data Record uses an unknown or closed context")
        })?;
        if context.mode != DataMode::ReliableBlock || !context.seen_blocks.contains(block_id) {
            return Err(context_error(
                "Reliable Data Record does not belong to an accepted block",
            ));
        }
        if message.is_empty() || message.len() > MAX_AMT_DATA_MESSAGE {
            return Err(ProtocolError::new(
                ApplicationError::Protocol,
                "invalid AMTQ Reliable Data Record length",
            ));
        }
        Ok(
            validate_received_data(message, self.protocol, &self.requested)
                .then(|| message.to_vec()),
        )
    }

    pub fn finish_reliable_block(
        &mut self,
        context_id: u64,
        block_id: u64,
    ) -> Result<bool, ProtocolError> {
        let context = self.contexts.get_mut(&context_id).ok_or_else(|| {
            context_error("completed Reliable Data Block uses an unknown context")
        })?;
        if !context.seen_blocks.contains(block_id) {
            return Err(context_error(
                "AMTQ Reliable Data Block completed without a matching open block",
            ));
        }
        match context
            .completed_blocks
            .insert(block_id, self.max_reliable_block_ranges_per_context)
        {
            IdInsert::Inserted => {}
            IdInsert::Duplicate => {
                return Err(context_error(
                    "AMTQ Reliable Data Block completed more than once",
                ));
            }
            IdInsert::RangeLimit => {
                return Err(ProtocolError::new(
                    ApplicationError::ExcessiveLoad,
                    "too many disjoint completed AMTQ Reliable Blocks",
                ));
            }
        }
        let closed = context.reliable_close_complete();
        if closed {
            self.contexts.remove(&context_id);
        }
        Ok(closed)
    }

    pub fn close_drain_expired(&self, context_id: u64) -> Result<(), ProtocolError> {
        let Some(context) = self.contexts.get(&context_id) else {
            return Ok(());
        };
        if matches!(context.phase, GatewayContextPhase::Closing { .. }) {
            Err(context_error("AMTQ context close-drain timer expired"))
        } else {
            Ok(())
        }
    }

    fn handle_amt_control(&mut self, bytes: &[u8]) -> Result<GatewayEvent, ProtocolError> {
        validate_amt_reserved_bits(bytes, EndpointRole::Relay)?;
        let message = Message::decode(bytes).map_err(amt_decode_error)?;
        let Message::MembershipQuery {
            response_mac,
            request_nonce,
            gateway,
            general_query,
            ..
        } = message
        else {
            return Err(ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ Relay sent a disallowed AMT control message",
            ));
        };
        if response_mac != ResponseMac::ZERO || gateway.is_some() {
            return Err(ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ Membership Query has a MAC or Gateway Address",
            ));
        }
        let expected = self.outstanding_request.ok_or_else(|| {
            ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ Membership Query arrived without an outstanding Request",
            )
        })?;
        if request_nonce != expected {
            return Err(ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ Membership Query Request Nonce does not match",
            ));
        }
        let protocol = self
            .protocol
            .expect("outstanding Request selected protocol");
        validate_general_query(protocol, general_query).map_err(|_| {
            ProtocolError::new(
                ApplicationError::AmtMessage,
                "invalid AMTQ General Membership Query",
            )
        })?;
        self.outstanding_request = None;
        self.current_query_nonce = Some(request_nonce);
        Ok(GatewayEvent::MembershipQuery {
            protocol,
            request_nonce,
            general_query: general_query.to_vec(),
        })
    }

    fn open_context(&mut self, context: Context) -> Result<GatewayEvent, ProtocolError> {
        validate_new_context_id(self.last_context_id, context.id)?;
        let mode = DataMode::from_value(context.mode)
            .ok_or_else(|| context_error("AMTQ CONTEXT selected an unsupported Data Mode"))?;
        if !self.negotiation.supports(mode) {
            return Err(context_error(
                "AMTQ CONTEXT selected an unnegotiated Data Mode",
            ));
        }
        if self.contexts.len() >= MAX_OPEN_CONTEXTS {
            return Err(ProtocolError::new(
                ApplicationError::ExcessiveLoad,
                "too many AMTQ Delivery Contexts are open",
            ));
        }
        let mut acknowledgement = Vec::new();
        ControlRecord::ContextAck { id: context.id }
            .encode(EndpointRole::Gateway, &mut acknowledgement)
            .map_err(internal_wire_error)?;
        self.last_context_id = Some(context.id);
        self.contexts.insert(
            context.id,
            GatewayContext {
                mode,
                phase: GatewayContextPhase::Active,
                seen_blocks: IdRanges::default(),
                completed_blocks: IdRanges::default(),
            },
        );
        Ok(GatewayEvent::ContextOpened {
            context,
            acknowledgement,
        })
    }

    fn close_context(&mut self, close: ContextClose) -> Result<GatewayEvent, ProtocolError> {
        let context = self
            .contexts
            .get_mut(&close.id)
            .ok_or_else(|| context_error("CONTEXT_CLOSE uses an unknown or inactive context"))?;
        if !matches!(context.phase, GatewayContextPhase::Active) {
            return Err(context_error("AMTQ context is already closing"));
        }
        match context.mode {
            DataMode::Datagram => {
                if close.final_block_id.is_some() {
                    return Err(context_error(
                        "Datagram Mode CONTEXT_CLOSE contains a Final Block ID",
                    ));
                }
                self.contexts.remove(&close.id);
                self.reassembler.discard_context(close.id);
                Ok(GatewayEvent::ContextClosed {
                    context_id: close.id,
                })
            }
            DataMode::ReliableBlock => {
                let final_block_id = close.final_block_id.ok_or_else(|| {
                    context_error("Reliable CONTEXT_CLOSE is missing Final Block ID")
                })?;
                if context
                    .seen_blocks
                    .last()
                    .is_some_and(|seen| seen > final_block_id)
                {
                    return Err(context_error(
                        "Final Block ID is smaller than a received block",
                    ));
                }
                context.phase = GatewayContextPhase::Closing { final_block_id };
                if context.reliable_close_complete() {
                    self.contexts.remove(&close.id);
                    Ok(GatewayEvent::ContextClosed {
                        context_id: close.id,
                    })
                } else {
                    Ok(GatewayEvent::ContextClosing {
                        context_id: close.id,
                        final_block_id,
                    })
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct RelaySession {
    negotiation: Negotiation,
    membership_limits: RelayLimits,
    gateway_initial_max_streams_uni: u64,
    protocol: Option<MembershipProtocol>,
    pending_request: Option<(u32, MembershipProtocol)>,
    current_query_nonce: Option<u32>,
    requested: ReceptionState,
    authorized: ReceptionState,
    pending_update_generation: Option<u64>,
    next_update_generation: u64,
    contexts: BTreeMap<u64, RelayContext>,
    last_context_id: Option<u64>,
    max_inflight_reliable_blocks_per_context: usize,
}

impl RelaySession {
    pub fn new(config: RelaySessionConfig) -> Result<Self, ProtocolError> {
        config
            .settings
            .validate(EndpointRole::Relay)
            .map_err(settings_error)?;
        if config
            .gateway_max_datagram_frame_size
            .is_none_or(|size| size < MIN_GATEWAY_DATAGRAM_SIZE)
        {
            return Err(ProtocolError::new(
                ApplicationError::Settings,
                "AMTQ Gateway did not advertise the required DATAGRAM size",
            ));
        }
        Ok(Self {
            negotiation: Negotiation::new(config.settings),
            membership_limits: config.membership_limits,
            gateway_initial_max_streams_uni: config.gateway_initial_max_streams_uni,
            protocol: None,
            pending_request: None,
            current_query_nonce: None,
            requested: ReceptionState::default(),
            authorized: ReceptionState::default(),
            pending_update_generation: None,
            next_update_generation: 0,
            contexts: BTreeMap::new(),
            last_context_id: None,
            max_inflight_reliable_blocks_per_context: config
                .max_inflight_reliable_blocks_per_context,
        })
    }

    pub fn settings_record(&mut self) -> Result<Vec<u8>, ProtocolError> {
        self.negotiation.settings_record(EndpointRole::Relay)
    }

    pub const fn requested_state(&self) -> &ReceptionState {
        &self.requested
    }

    pub const fn authorized_state(&self) -> &ReceptionState {
        &self.authorized
    }

    pub fn handle_control(
        &mut self,
        record: ControlRecord<'_>,
    ) -> Result<RelayEvent, ProtocolError> {
        if self.pending_update_generation.is_some() {
            return Err(ProtocolError::new(
                ApplicationError::Internal,
                "AMTQ membership authorization was not committed",
            ));
        }
        match record {
            ControlRecord::Settings(settings) => {
                settings
                    .validate(EndpointRole::Gateway)
                    .map_err(settings_error)?;
                if settings.supports(DataMode::ReliableBlock)
                    && self.gateway_initial_max_streams_uni == 0
                {
                    return Err(ProtocolError::new(
                        ApplicationError::Settings,
                        "AMTQ Gateway advertised Reliable Block Mode without stream credit",
                    ));
                }
                self.negotiation
                    .receive_settings(settings, EndpointRole::Gateway)?;
                Ok(RelayEvent::SettingsReceived)
            }
            _ if !self.negotiation.ready() => Err(ProtocolError::new(
                ApplicationError::Protocol,
                "AMTQ control record arrived before SETTINGS completed",
            )),
            ControlRecord::AmtControl(message) => self.handle_amt_control(message),
            ControlRecord::ContextAck { id } => self.acknowledge_context(id),
            ControlRecord::Context(_) | ControlRecord::ContextClose(_) => Err(ProtocolError::new(
                ApplicationError::Protocol,
                "AMTQ Relay received a Relay-only context record",
            )),
            ControlRecord::Unknown { .. } => Ok(RelayEvent::Ignored),
        }
    }

    pub fn membership_query(&mut self, general_query: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let (request_nonce, protocol) = self.pending_request.ok_or_else(|| {
            ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ Membership Query has no pending Request",
            )
        })?;
        validate_general_query(protocol, general_query).map_err(|_| {
            ProtocolError::new(
                ApplicationError::AmtMessage,
                "invalid AMTQ General Membership Query",
            )
        })?;
        let encoded = encode_control_message(
            EndpointRole::Relay,
            &Message::MembershipQuery {
                response_mac: ResponseMac::ZERO,
                request_nonce,
                limit: false,
                gateway: None,
                general_query,
            },
        )?;
        self.pending_request = None;
        self.current_query_nonce = Some(request_nonce);
        Ok(encoded)
    }

    pub fn authorize_all(&mut self, pending: PendingMembershipUpdate) -> Result<(), ProtocolError> {
        let authorized = pending.requested.clone();
        self.commit_membership_update(pending, authorized)
    }

    pub fn commit_membership_update(
        &mut self,
        pending: PendingMembershipUpdate,
        authorized: ReceptionState,
    ) -> Result<(), ProtocolError> {
        if self.pending_update_generation != Some(pending.generation) {
            return Err(ProtocolError::new(
                ApplicationError::Internal,
                "stale AMTQ membership authorization result",
            ));
        }
        if !authorized.is_subset_of(&pending.requested) {
            return Err(ProtocolError::new(
                ApplicationError::Internal,
                "authorized AMTQ state is not a subset of requested state",
            ));
        }
        self.requested = pending.requested;
        self.authorized = authorized;
        self.pending_update_generation = None;
        Ok(())
    }

    pub fn open_context(&mut self, context: Context) -> Result<Vec<u8>, ProtocolError> {
        self.negotiation.ensure_ready()?;
        validate_new_context_id(self.last_context_id, context.id)?;
        let mode = DataMode::from_value(context.mode)
            .ok_or_else(|| context_error("unsupported AMTQ context Data Mode"))?;
        if !self.negotiation.supports(mode) {
            return Err(context_error("AMTQ context Data Mode was not negotiated"));
        }
        if self.contexts.len() >= MAX_OPEN_CONTEXTS {
            return Err(ProtocolError::new(
                ApplicationError::ExcessiveLoad,
                "too many AMTQ Delivery Contexts are open",
            ));
        }
        let mut encoded = Vec::new();
        ControlRecord::Context(context)
            .encode(EndpointRole::Relay, &mut encoded)
            .map_err(internal_wire_error)?;
        self.last_context_id = Some(context.id);
        self.contexts.insert(
            context.id,
            RelayContext {
                mode,
                pending: true,
                next_packet_id: 1,
                last_block_id: 0,
                open_blocks: BTreeSet::new(),
            },
        );
        Ok(encoded)
    }

    pub fn close_context(&mut self, context_id: u64) -> Result<Vec<u8>, ProtocolError> {
        let context = self
            .contexts
            .get(&context_id)
            .ok_or_else(|| context_error("cannot close an unknown AMTQ context"))?;
        if context.pending {
            return Err(context_error("cannot close a pending AMTQ context"));
        }
        if !context.open_blocks.is_empty() {
            return Err(context_error(
                "cannot close an AMTQ context before all reliable blocks finish",
            ));
        }
        let close = ContextClose {
            id: context_id,
            final_block_id: (context.mode == DataMode::ReliableBlock)
                .then_some(context.last_block_id),
        };
        let mut encoded = Vec::new();
        ControlRecord::ContextClose(close)
            .encode(EndpointRole::Relay, &mut encoded)
            .map_err(internal_wire_error)?;
        self.contexts.remove(&context_id);
        Ok(encoded)
    }

    pub fn datagrams_for_message(
        &mut self,
        context_id: u64,
        message: &[u8],
        max_datagram_size: usize,
    ) -> Result<Vec<Vec<u8>>, ProtocolError> {
        validate_outgoing_data(message, self.protocol, &self.authorized)?;
        let context = self
            .contexts
            .get_mut(&context_id)
            .ok_or_else(|| context_error("data uses an unknown AMTQ context"))?;
        if context.pending || context.mode != DataMode::Datagram {
            return Err(context_error(
                "data uses a pending or non-Datagram AMTQ context",
            ));
        }
        let mut complete = Vec::new();
        datagram::encode_complete(context_id, message, &mut complete)
            .map_err(protocol_wire_error)?;
        if complete.len() <= max_datagram_size {
            return Ok(vec![complete]);
        }
        let packet_id = context.next_packet_id;
        if packet_id > MAX_VARINT {
            return Err(context_error(
                "AMTQ fragmented Packet ID space is exhausted",
            ));
        }
        let datagrams =
            datagram::fragment_message(context_id, packet_id, message, max_datagram_size)
                .map_err(protocol_wire_error)?;
        context.next_packet_id = packet_id.saturating_add(1);
        Ok(datagrams)
    }

    pub fn open_reliable_block(
        &mut self,
        context_id: u64,
    ) -> Result<(u64, Vec<u8>), ProtocolError> {
        let context = self
            .contexts
            .get_mut(&context_id)
            .ok_or_else(|| context_error("reliable block uses an unknown AMTQ context"))?;
        if context.pending || context.mode != DataMode::ReliableBlock {
            return Err(context_error(
                "reliable block uses a pending or non-reliable context",
            ));
        }
        if context.open_blocks.len() >= self.max_inflight_reliable_blocks_per_context {
            return Err(ProtocolError::new(
                ApplicationError::ExcessiveLoad,
                "too many AMTQ Reliable Data Blocks are in flight",
            ));
        }
        let block_id = context
            .last_block_id
            .checked_add(1)
            .filter(|block_id| *block_id <= MAX_VARINT)
            .ok_or_else(|| context_error("AMTQ Reliable Block ID space is exhausted"))?;
        context.last_block_id = block_id;
        context.open_blocks.insert(block_id);
        let mut header = Vec::new();
        reliable::encode_stream_header(context_id, block_id, &mut header)
            .map_err(internal_wire_error)?;
        Ok((block_id, header))
    }

    pub fn reliable_data_record(
        &self,
        context_id: u64,
        block_id: u64,
        message: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        validate_outgoing_data(message, self.protocol, &self.authorized)?;
        let context = self
            .contexts
            .get(&context_id)
            .ok_or_else(|| context_error("data uses an unknown AMTQ context"))?;
        if context.mode != DataMode::ReliableBlock || !context.open_blocks.contains(&block_id) {
            return Err(context_error(
                "data uses an unopened AMTQ Reliable Data Block",
            ));
        }
        let mut encoded = Vec::new();
        reliable::encode_data_record(message, &mut encoded).map_err(protocol_wire_error)?;
        Ok(encoded)
    }

    pub fn finish_reliable_block(
        &mut self,
        context_id: u64,
        block_id: u64,
    ) -> Result<(), ProtocolError> {
        let context = self
            .contexts
            .get_mut(&context_id)
            .ok_or_else(|| context_error("finished block uses an unknown AMTQ context"))?;
        if !context.open_blocks.remove(&block_id) {
            return Err(context_error(
                "finished block was not open in the AMTQ context",
            ));
        }
        Ok(())
    }

    fn handle_amt_control(&mut self, bytes: &[u8]) -> Result<RelayEvent, ProtocolError> {
        validate_amt_reserved_bits(bytes, EndpointRole::Gateway)?;
        let message = Message::decode(bytes).map_err(amt_decode_error)?;
        match message {
            Message::Request {
                request_nonce,
                protocol,
                ecn_capable,
            } => {
                if ecn_capable {
                    return Err(ProtocolError::new(
                        ApplicationError::AmtMessage,
                        "AMTQ Request has the ECN capability flag set",
                    ));
                }
                if self.pending_request.is_some() {
                    return Err(ProtocolError::new(
                        ApplicationError::AmtMessage,
                        "AMTQ Request arrived while a previous Request is pending",
                    ));
                }
                if self.protocol.is_some_and(|selected| selected != protocol) {
                    return Err(ProtocolError::new(
                        ApplicationError::AmtMessage,
                        "AMTQ connection membership protocol changed",
                    ));
                }
                self.protocol = Some(protocol);
                self.pending_request = Some((request_nonce, protocol));
                Ok(RelayEvent::Request {
                    protocol,
                    request_nonce,
                })
            }
            Message::MembershipUpdate {
                response_mac,
                request_nonce,
                membership_update,
            } => {
                if self.pending_request.is_some() {
                    return Err(ProtocolError::new(
                        ApplicationError::AmtMessage,
                        "AMTQ Membership Update arrived while a Request is pending",
                    ));
                }
                if response_mac != ResponseMac::ZERO
                    || self.current_query_nonce != Some(request_nonce)
                {
                    return Err(ProtocolError::new(
                        ApplicationError::AmtMessage,
                        "AMTQ Membership Update MAC or Request Nonce is invalid",
                    ));
                }
                let protocol = self
                    .protocol
                    .expect("query nonce implies selected protocol");
                let report = parse_report(membership_update, protocol, &self.membership_limits)?;
                let mut requested = self.requested.clone();
                requested.apply_report_limited(&report, &self.membership_limits)?;
                let generation = self.next_update_generation;
                self.next_update_generation =
                    self.next_update_generation.checked_add(1).ok_or_else(|| {
                        ProtocolError::new(
                            ApplicationError::Internal,
                            "AMTQ membership generation space exhausted",
                        )
                    })?;
                self.pending_update_generation = Some(generation);
                Ok(RelayEvent::MembershipUpdate(PendingMembershipUpdate {
                    generation,
                    requested,
                    report,
                }))
            }
            _ => Err(ProtocolError::new(
                ApplicationError::AmtMessage,
                "AMTQ Gateway sent a disallowed AMT control message",
            )),
        }
    }

    fn acknowledge_context(&mut self, context_id: u64) -> Result<RelayEvent, ProtocolError> {
        let context = self
            .contexts
            .get_mut(&context_id)
            .ok_or_else(|| context_error("CONTEXT_ACK uses an unknown context"))?;
        if !context.pending {
            return Err(context_error("CONTEXT_ACK uses an active context"));
        }
        context.pending = false;
        Ok(RelayEvent::ContextAcknowledged { context_id })
    }
}

#[derive(Debug)]
struct Negotiation {
    local: Settings,
    local_sent: bool,
    peer: Option<Settings>,
}

impl Negotiation {
    const fn new(local: Settings) -> Self {
        Self {
            local,
            local_sent: false,
            peer: None,
        }
    }

    fn settings_record(&mut self, role: EndpointRole) -> Result<Vec<u8>, ProtocolError> {
        if self.local_sent {
            return Err(ProtocolError::new(
                ApplicationError::Settings,
                "AMTQ SETTINGS was already sent",
            ));
        }
        let mut encoded = Vec::new();
        ControlRecord::Settings(self.local.clone())
            .encode(role, &mut encoded)
            .map_err(settings_error)?;
        self.local_sent = true;
        Ok(encoded)
    }

    fn receive_settings(
        &mut self,
        settings: Settings,
        sender: EndpointRole,
    ) -> Result<(), ProtocolError> {
        if self.peer.is_some() {
            return Err(ProtocolError::new(
                ApplicationError::Settings,
                "peer sent a second AMTQ SETTINGS record",
            ));
        }
        settings.validate(sender).map_err(settings_error)?;
        self.peer = Some(settings);
        Ok(())
    }

    const fn ready(&self) -> bool {
        self.local_sent && self.peer.is_some()
    }

    fn ensure_ready(&self) -> Result<(), ProtocolError> {
        if self.ready() {
            Ok(())
        } else {
            Err(ProtocolError::new(
                ApplicationError::Protocol,
                "AMTQ SETTINGS exchange is not complete",
            ))
        }
    }

    fn supports(&self, mode: DataMode) -> bool {
        self.local.supports(mode)
            && self
                .peer
                .as_ref()
                .is_some_and(|settings| settings.supports(mode))
    }
}

#[derive(Debug)]
struct GatewayContext {
    mode: DataMode,
    phase: GatewayContextPhase,
    seen_blocks: IdRanges,
    completed_blocks: IdRanges,
}

impl GatewayContext {
    fn reliable_close_complete(&self) -> bool {
        let GatewayContextPhase::Closing { final_block_id } = self.phase else {
            return false;
        };
        final_block_id == 0 || self.completed_blocks.contains_range(1, final_block_id)
    }
}

#[derive(Debug, Clone, Copy)]
enum GatewayContextPhase {
    Active,
    Closing { final_block_id: u64 },
}

#[derive(Debug)]
struct RelayContext {
    mode: DataMode,
    pending: bool,
    next_packet_id: u64,
    last_block_id: u64,
    open_blocks: BTreeSet<u64>,
}

#[derive(Debug, Default)]
struct IdRanges {
    ranges: BTreeMap<u64, u64>,
}

impl IdRanges {
    fn insert(&mut self, value: u64, max_ranges: usize) -> IdInsert {
        let previous = self
            .ranges
            .range(..=value)
            .next_back()
            .map(|(start, end)| (*start, *end));
        if previous.is_some_and(|(_, end)| value <= end) {
            return IdInsert::Duplicate;
        }
        let next = self
            .ranges
            .range(value..)
            .next()
            .map(|(start, end)| (*start, *end));
        let joins_previous = previous.is_some_and(|(_, end)| end.checked_add(1) == Some(value));
        let joins_next = next.is_some_and(|(start, _)| value.checked_add(1) == Some(start));

        match (joins_previous, joins_next) {
            (true, true) => {
                let (previous_start, _) = previous.expect("joining previous range");
                let (next_start, next_end) = next.expect("joining next range");
                self.ranges.insert(previous_start, next_end);
                self.ranges.remove(&next_start);
            }
            (true, false) => {
                let (previous_start, _) = previous.expect("joining previous range");
                self.ranges.insert(previous_start, value);
            }
            (false, true) => {
                let (next_start, next_end) = next.expect("joining next range");
                self.ranges.remove(&next_start);
                self.ranges.insert(value, next_end);
            }
            (false, false) => {
                if self.ranges.len() >= max_ranges {
                    return IdInsert::RangeLimit;
                }
                self.ranges.insert(value, value);
            }
        }
        IdInsert::Inserted
    }

    fn contains(&self, value: u64) -> bool {
        self.ranges
            .range(..=value)
            .next_back()
            .is_some_and(|(_, end)| value <= *end)
    }

    fn contains_range(&self, start: u64, end: u64) -> bool {
        self.ranges
            .range(..=start)
            .next_back()
            .is_some_and(|(_, range_end)| end <= *range_end)
    }

    fn last(&self) -> Option<u64> {
        self.ranges.last_key_value().map(|(_, end)| *end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdInsert {
    Inserted,
    Duplicate,
    RangeLimit,
}

fn parse_report(
    packet: &[u8],
    protocol: MembershipProtocol,
    limits: &RelayLimits,
) -> Result<MembershipReport, ProtocolError> {
    let report = parse_membership_report_with_limits(
        packet,
        MembershipParseLimits {
            max_records: limits.max_records_per_report,
            max_sources_per_record: limits.max_sources_per_group,
        },
    )
    .map_err(|_| {
        ProtocolError::new(
            ApplicationError::AmtMessage,
            "invalid AMTQ membership report",
        )
    })?;
    if report.protocol != protocol {
        return Err(ProtocolError::new(
            ApplicationError::AmtMessage,
            "AMTQ membership report uses the wrong address family",
        ));
    }
    Ok(report)
}

fn encode_control_message(
    sender: EndpointRole,
    message: &Message<'_>,
) -> Result<Vec<u8>, ProtocolError> {
    let message = encode(message);
    let mut record = Vec::new();
    ControlRecord::AmtControl(&message)
        .encode(sender, &mut record)
        .map_err(protocol_wire_error)?;
    Ok(record)
}

fn validate_amt_reserved_bits(bytes: &[u8], sender: EndpointRole) -> Result<(), ProtocolError> {
    let Some((&message_type, rest)) = bytes.split_first() else {
        return Err(amt_decode_error(amt::DecodeError::Truncated {
            message_type: None,
            expected_at_least: 1,
            actual: 0,
        }));
    };
    let valid = match (sender, message_type) {
        (EndpointRole::Gateway, 0x03) => {
            rest.len() >= 3 && rest[0] & !0x03 == 0 && rest[1..3] == [0, 0]
        }
        (EndpointRole::Gateway, 0x05) => !rest.is_empty() && rest[0] == 0,
        (EndpointRole::Relay, 0x04) => !rest.is_empty() && rest[0] & !0x03 == 0,
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(ProtocolError::new(
            ApplicationError::AmtMessage,
            "AMTQ AMT control message has non-zero reserved bits",
        ))
    }
}

fn validate_received_data(
    message: &[u8],
    protocol: Option<MembershipProtocol>,
    requested: &ReceptionState,
) -> bool {
    validate_data_message(message, protocol)
        .is_some_and(|(source, group)| requested.wants(source, group))
}

fn validate_outgoing_data(
    message: &[u8],
    protocol: Option<MembershipProtocol>,
    authorized: &ReceptionState,
) -> Result<(), ProtocolError> {
    let (source, group) = validate_data_message(message, protocol).ok_or_else(|| {
        ProtocolError::new(
            ApplicationError::AmtMessage,
            "invalid AMTQ Multicast Data message",
        )
    })?;
    if !authorized.wants(source, group) {
        return Err(ProtocolError::new(
            ApplicationError::Internal,
            "multicast packet is outside Authorized Reception State",
        ));
    }
    Ok(())
}

fn validate_data_message(
    message: &[u8],
    protocol: Option<MembershipProtocol>,
) -> Option<(IpAddr, IpAddr)> {
    if message.len() > MAX_AMT_DATA_MESSAGE
        || message.first() != Some(&0x06)
        || message.get(1) != Some(&0)
    {
        return None;
    }
    let Message::MulticastData { packet } = Message::decode(message).ok()? else {
        return None;
    };
    let parsed = parse_multicast_packet(packet).ok()?;
    let family_matches = matches!(
        (protocol?, parsed.group),
        (MembershipProtocol::Igmpv3, IpAddr::V4(_)) | (MembershipProtocol::Mldv2, IpAddr::V6(_))
    );
    (family_matches && is_amt_forwardable_group(parsed.group))
        .then_some((parsed.source, parsed.group))
}

fn interest_is_subset(authorized: &GroupInterest, requested: &GroupInterest) -> bool {
    match (authorized.mode, requested.mode) {
        (FilterMode::Include, FilterMode::Include) => {
            authorized.sources.is_subset(&requested.sources)
        }
        (FilterMode::Include, FilterMode::Exclude) => authorized
            .sources
            .iter()
            .all(|source| !requested.sources.contains(source)),
        (FilterMode::Exclude, FilterMode::Exclude) => {
            requested.sources.is_subset(&authorized.sources)
        }
        (FilterMode::Exclude, FilterMode::Include) => false,
    }
}

fn validate_new_context_id(
    last_context_id: Option<u64>,
    context_id: u64,
) -> Result<(), ProtocolError> {
    if context_id > MAX_VARINT {
        return Err(context_error(
            "AMTQ Context ID exceeds the QUIC varint range",
        ));
    }
    match last_context_id {
        None if context_id != 0 => Err(context_error("AMTQ Context ID 0 must be created first")),
        Some(last) if context_id <= last => {
            Err(context_error("AMTQ Context ID was reused or decreased"))
        }
        _ => Ok(()),
    }
}

fn settings_error(_: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(
        ApplicationError::Settings,
        "invalid AMTQ SETTINGS or transport capability",
    )
}

fn protocol_wire_error(_: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(ApplicationError::Protocol, "invalid AMTQ wire value")
}

fn internal_wire_error(_: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(
        ApplicationError::Internal,
        "failed to encode local AMTQ protocol value",
    )
}

fn amt_decode_error(_: amt::DecodeError) -> ProtocolError {
    ProtocolError::new(
        ApplicationError::AmtMessage,
        "invalid AMTQ AMT control message",
    )
}

const fn context_error(reason: &'static str) -> ProtocolError {
    ProtocolError::new(ApplicationError::Context, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use amt::membership::build_membership_report;
    use amt::query::{GeneralQueryConfig, build_general_query};
    use amt::{MembershipRecord, MembershipRecordKind};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn decode_one(bytes: &[u8], sender: EndpointRole) -> ControlRecord<'_> {
        crate::control::decode_record(bytes, sender).unwrap().0
    }

    fn establish_settings(
        gateway: &mut GatewaySession,
        relay: &mut RelaySession,
    ) -> (Vec<u8>, Vec<u8>) {
        let gateway_settings = gateway.settings_record().unwrap();
        let relay_settings = relay.settings_record().unwrap();
        assert_eq!(
            relay
                .handle_control(decode_one(&gateway_settings, EndpointRole::Gateway))
                .unwrap(),
            RelayEvent::SettingsReceived
        );
        assert_eq!(
            gateway
                .handle_control(decode_one(&relay_settings, EndpointRole::Relay))
                .unwrap(),
            GatewayEvent::SettingsReceived
        );
        (gateway_settings, relay_settings)
    }

    fn report(group: IpAddr, source: Option<IpAddr>) -> Vec<u8> {
        let protocol = if group.is_ipv4() {
            MembershipProtocol::Igmpv3
        } else {
            MembershipProtocol::Mldv2
        };
        build_membership_report(&MembershipReport {
            protocol,
            records: vec![MembershipRecord {
                kind: if source.is_some() {
                    MembershipRecordKind::ModeIsInclude
                } else {
                    MembershipRecordKind::ModeIsExclude
                },
                group,
                sources: source.into_iter().collect(),
            }],
        })
        .unwrap()
    }

    fn ipv4_multicast_data(source: Ipv4Addr, group: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[8] = 16;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&group.octets());
        let mut sum = 0u32;
        for pair in packet[..20].chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        encode(&Message::MulticastData { packet: &packet })
    }

    #[test]
    fn reception_state_intersection_preserves_only_still_requested_packets() {
        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let source_a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let source_b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let source_c = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
        let state = |kind, sources| {
            let mut state = ReceptionState::default();
            state.apply_report(&MembershipReport {
                protocol: MembershipProtocol::Igmpv3,
                records: vec![MembershipRecord {
                    kind,
                    group,
                    sources,
                }],
            });
            state
        };

        let authorized = state(MembershipRecordKind::ModeIsExclude, vec![source_c]);
        let requested = state(
            MembershipRecordKind::ModeIsInclude,
            vec![source_a, source_c],
        );
        let retained = authorized.intersection(&requested);

        assert!(retained.wants(source_a, group));
        assert!(!retained.wants(source_b, group));
        assert!(!retained.wants(source_c, group));
        assert!(retained.is_subset_of(&requested));

        let left = state(MembershipRecordKind::ModeIsExclude, vec![source_a]);
        let right = state(MembershipRecordKind::ModeIsExclude, vec![source_b]);
        let intersection = left.intersection(&right);
        assert!(!intersection.wants(source_a, group));
        assert!(!intersection.wants(source_b, group));
        assert!(intersection.wants(source_c, group));
    }

    #[test]
    fn datagram_mode_exchange_is_transactional_and_filters_data() {
        let mut gateway = GatewaySession::new(GatewaySessionConfig::default()).unwrap();
        let mut relay = RelaySession::new(RelaySessionConfig::default()).unwrap();
        establish_settings(&mut gateway, &mut relay);

        let request = gateway
            .begin_request(0x0102_0304, MembershipProtocol::Igmpv3)
            .unwrap();
        assert!(matches!(
            relay
                .handle_control(decode_one(&request, EndpointRole::Gateway))
                .unwrap(),
            RelayEvent::Request { .. }
        ));
        let query = build_general_query(MembershipProtocol::Igmpv3, &GeneralQueryConfig::for_amt());
        let query_record = relay.membership_query(&query).unwrap();
        assert!(matches!(
            gateway
                .handle_control(decode_one(&query_record, EndpointRole::Relay))
                .unwrap(),
            GatewayEvent::MembershipQuery { .. }
        ));

        let group = IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3));
        let membership = report(group, None);
        let update = gateway.membership_update(&membership).unwrap();
        let RelayEvent::MembershipUpdate(pending) = relay
            .handle_control(decode_one(&update, EndpointRole::Gateway))
            .unwrap()
        else {
            panic!("expected membership update");
        };
        assert!(!relay.requested_state().has_interests());
        relay.authorize_all(pending).unwrap();
        assert!(relay.authorized_state().has_interests());

        let context = Context {
            id: 0,
            mode: DataMode::Datagram.value(),
        };
        let open = relay.open_context(context).unwrap();
        let GatewayEvent::ContextOpened {
            acknowledgement, ..
        } = gateway
            .handle_control(decode_one(&open, EndpointRole::Relay))
            .unwrap()
        else {
            panic!("expected context");
        };
        relay
            .handle_control(decode_one(&acknowledgement, EndpointRole::Gateway))
            .unwrap();

        let message = ipv4_multicast_data(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(239, 1, 2, 3));
        let datagrams = relay.datagrams_for_message(0, &message, 1_200).unwrap();
        assert_eq!(datagrams.len(), 1);
        assert_eq!(
            gateway
                .handle_datagram(&datagrams[0], Instant::now())
                .unwrap(),
            Some(message)
        );
    }

    #[test]
    fn request_and_query_state_is_strict() {
        let mut gateway = GatewaySession::new(GatewaySessionConfig::default()).unwrap();
        let mut relay = RelaySession::new(RelaySessionConfig::default()).unwrap();
        establish_settings(&mut gateway, &mut relay);

        gateway
            .begin_request(1, MembershipProtocol::Igmpv3)
            .unwrap();
        assert!(
            gateway
                .begin_request(2, MembershipProtocol::Igmpv3)
                .is_err()
        );

        let unsolicited = encode_control_message(
            EndpointRole::Relay,
            &Message::MembershipQuery {
                response_mac: ResponseMac::ZERO,
                request_nonce: 2,
                limit: false,
                gateway: None,
                general_query: &build_general_query(
                    MembershipProtocol::Igmpv3,
                    &GeneralQueryConfig::for_amt(),
                ),
            },
        )
        .unwrap();
        assert!(
            gateway
                .handle_control(decode_one(&unsolicited, EndpointRole::Relay))
                .is_err()
        );
    }

    #[test]
    fn zero_mac_and_address_family_are_enforced() {
        let mut gateway = GatewaySession::new(GatewaySessionConfig::default()).unwrap();
        let mut relay = RelaySession::new(RelaySessionConfig::default()).unwrap();
        establish_settings(&mut gateway, &mut relay);
        let request = gateway
            .begin_request(7, MembershipProtocol::Igmpv3)
            .unwrap();
        relay
            .handle_control(decode_one(&request, EndpointRole::Gateway))
            .unwrap();

        let query = build_general_query(MembershipProtocol::Igmpv3, &GeneralQueryConfig::for_amt());
        let bad = encode_control_message(
            EndpointRole::Relay,
            &Message::MembershipQuery {
                response_mac: ResponseMac::new([1; 6]),
                request_nonce: 7,
                limit: false,
                gateway: None,
                general_query: &query,
            },
        )
        .unwrap();
        assert!(
            gateway
                .handle_control(decode_one(&bad, EndpointRole::Relay))
                .is_err()
        );

        let ipv6_group = IpAddr::V6(Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1234));
        assert!(
            gateway
                .membership_update(&report(ipv6_group, None))
                .is_err()
        );
    }

    #[test]
    fn contexts_are_monotonic_and_mode_specific() {
        let settings = Settings::gateway(
            DataMode::Datagram.bit() | DataMode::ReliableBlock.bit(),
            Some(DataMode::ReliableBlock.value()),
        );
        let mut gateway = GatewaySession::new(GatewaySessionConfig {
            settings,
            gateway_initial_max_streams_uni: 4,
            ..GatewaySessionConfig::default()
        })
        .unwrap();
        let mut relay = RelaySession::new(RelaySessionConfig {
            settings: Settings {
                data_modes: DataMode::Datagram.bit() | DataMode::ReliableBlock.bit(),
                preferred_data_mode: None,
            },
            gateway_initial_max_streams_uni: 4,
            ..RelaySessionConfig::default()
        })
        .unwrap();
        establish_settings(&mut gateway, &mut relay);

        let context = Context {
            id: 0,
            mode: DataMode::ReliableBlock.value(),
        };
        let open = relay.open_context(context).unwrap();
        let GatewayEvent::ContextOpened {
            acknowledgement, ..
        } = gateway
            .handle_control(decode_one(&open, EndpointRole::Relay))
            .unwrap()
        else {
            panic!("expected context");
        };
        relay
            .handle_control(decode_one(&acknowledgement, EndpointRole::Gateway))
            .unwrap();
        assert!(relay.open_context(context).is_err());

        let (block_id, _) = relay.open_reliable_block(0).unwrap();
        gateway.begin_reliable_block(0, block_id).unwrap();
        relay.finish_reliable_block(0, block_id).unwrap();
        gateway.finish_reliable_block(0, block_id).unwrap();
        let close = relay.close_context(0).unwrap();
        assert_eq!(
            gateway
                .handle_control(decode_one(&close, EndpointRole::Relay))
                .unwrap(),
            GatewayEvent::ContextClosed { context_id: 0 }
        );
    }

    #[test]
    fn context_zero_is_mandatory_and_reliable_close_emits_drain_event() {
        let settings = Settings::gateway(
            DataMode::Datagram.bit() | DataMode::ReliableBlock.bit(),
            Some(DataMode::ReliableBlock.value()),
        );
        let mut gateway = GatewaySession::new(GatewaySessionConfig {
            settings,
            gateway_initial_max_streams_uni: 4,
            ..GatewaySessionConfig::default()
        })
        .unwrap();
        let mut relay = RelaySession::new(RelaySessionConfig {
            settings: Settings {
                data_modes: DataMode::Datagram.bit() | DataMode::ReliableBlock.bit(),
                preferred_data_mode: None,
            },
            gateway_initial_max_streams_uni: 4,
            ..RelaySessionConfig::default()
        })
        .unwrap();
        establish_settings(&mut gateway, &mut relay);

        assert!(
            relay
                .open_context(Context {
                    id: 1,
                    mode: DataMode::ReliableBlock.value(),
                })
                .is_err()
        );
        assert!(
            gateway
                .handle_control(ControlRecord::Context(Context {
                    id: 1,
                    mode: DataMode::ReliableBlock.value(),
                }))
                .is_err()
        );

        let open = relay
            .open_context(Context {
                id: 0,
                mode: DataMode::ReliableBlock.value(),
            })
            .unwrap();
        let GatewayEvent::ContextOpened {
            acknowledgement, ..
        } = gateway
            .handle_control(decode_one(&open, EndpointRole::Relay))
            .unwrap()
        else {
            panic!("expected context");
        };
        relay
            .handle_control(decode_one(&acknowledgement, EndpointRole::Gateway))
            .unwrap();

        let (block_id, _) = relay.open_reliable_block(0).unwrap();
        gateway.begin_reliable_block(0, block_id).unwrap();
        relay.finish_reliable_block(0, block_id).unwrap();
        let close = relay.close_context(0).unwrap();
        assert_eq!(
            gateway
                .handle_control(decode_one(&close, EndpointRole::Relay))
                .unwrap(),
            GatewayEvent::ContextClosing {
                context_id: 0,
                final_block_id: 1,
            }
        );
        assert!(gateway.close_drain_expired(0).is_err());
        assert!(gateway.finish_reliable_block(0, 1).unwrap());
        assert_eq!(gateway.close_drain_expired(0), Ok(()));
    }

    #[test]
    fn reliable_block_id_ranges_are_bounded_without_penalizing_contiguous_ids() {
        let mut ranges = IdRanges::default();
        for value in 1..=10_000 {
            assert_eq!(ranges.insert(value, 1), IdInsert::Inserted);
        }
        assert_eq!(ranges.ranges.len(), 1);
        assert!(ranges.contains_range(1, 10_000));
        assert_eq!(ranges.insert(20_000, 1), IdInsert::RangeLimit);
        assert_eq!(ranges.insert(5_000, 1), IdInsert::Duplicate);
    }

    #[test]
    fn transport_capabilities_are_checked_before_state() {
        assert!(
            GatewaySession::new(GatewaySessionConfig {
                relay_initial_max_streams_bidi: 0,
                ..GatewaySessionConfig::default()
            })
            .is_err()
        );
        assert!(
            RelaySession::new(RelaySessionConfig {
                gateway_max_datagram_frame_size: Some(MIN_GATEWAY_DATAGRAM_SIZE - 1),
                ..RelaySessionConfig::default()
            })
            .is_err()
        );
    }
}
