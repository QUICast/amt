use crate::protocol::MembershipProtocol;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const IGMP_PROTOCOL: u8 = 2;
const IPV6_HOP_BY_HOP: u8 = 0;
const ICMPV6_PROTOCOL: u8 = 58;

const IGMPV1_MEMBERSHIP_REPORT: u8 = 0x12;
const IGMPV2_MEMBERSHIP_REPORT: u8 = 0x16;
const IGMPV2_LEAVE_GROUP: u8 = 0x17;
const IGMPV3_MEMBERSHIP_REPORT: u8 = 0x22;

const MLDV1_LISTENER_REPORT: u8 = 131;
const MLDV1_LISTENER_DONE: u8 = 132;
const MLDV2_LISTENER_REPORT: u8 = 143;

const IGMPV3_REPORT_DESTINATION: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 22);
const MLDV2_REPORT_DESTINATION: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);
const IPV4_ROUTER_ALERT_HEADER_LEN: usize = 24;
const IPV6_HOP_BY_HOP_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipReport {
    pub protocol: MembershipProtocol,
    pub records: Vec<MembershipRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRecord {
    pub kind: MembershipRecordKind,
    pub group: IpAddr,
    pub sources: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRecordKind {
    ModeIsInclude,
    ModeIsExclude,
    ChangeToInclude,
    ChangeToExclude,
    AllowNewSources,
    BlockOldSources,
    LegacyReport,
    LegacyLeave,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipParseError {
    Truncated {
        context: &'static str,
        expected_at_least: usize,
        actual: usize,
    },
    InvalidIpVersion(u8),
    InvalidIpv4HeaderLength(usize),
    InvalidTotalLength {
        total_length: usize,
        available: usize,
    },
    InvalidProtocol {
        expected: u8,
        actual: u8,
    },
    InvalidChecksum(&'static str),
    MissingIpv6RouterAlert,
    UnsupportedMembershipMessage(u8),
    UnknownRecordType(u8),
    InvalidMulticastGroup(IpAddr),
    MixedAddressFamilies,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipBuildError {
    EmptyReport,
    TooManyRecords(usize),
    TooManySources(usize),
    PacketTooLong(usize),
    UnsupportedRecordKind(MembershipRecordKind),
    InvalidMulticastGroup(IpAddr),
    MixedAddressFamilies,
    ProtocolAddressFamilyMismatch {
        protocol: MembershipProtocol,
        group: IpAddr,
    },
}

impl fmt::Display for MembershipParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                context,
                expected_at_least,
                actual,
            } => write!(
                f,
                "truncated {context}: expected at least {expected_at_least} bytes, got {actual}"
            ),
            Self::InvalidIpVersion(version) => write!(f, "invalid IP version {version}"),
            Self::InvalidIpv4HeaderLength(len) => write!(f, "invalid IPv4 header length {len}"),
            Self::InvalidTotalLength {
                total_length,
                available,
            } => write!(
                f,
                "invalid IP total length {total_length}; only {available} bytes available"
            ),
            Self::InvalidProtocol { expected, actual } => {
                write!(f, "invalid IP protocol {actual}; expected {expected}")
            }
            Self::InvalidChecksum(context) => write!(f, "invalid {context} checksum"),
            Self::MissingIpv6RouterAlert => write!(f, "missing IPv6 Router Alert option"),
            Self::UnsupportedMembershipMessage(kind) => {
                write!(f, "unsupported membership message type {kind}")
            }
            Self::UnknownRecordType(kind) => write!(f, "unknown membership record type {kind}"),
            Self::InvalidMulticastGroup(group) => write!(f, "invalid multicast group {group}"),
            Self::MixedAddressFamilies => write!(f, "record group/source address family mismatch"),
        }
    }
}

impl std::error::Error for MembershipParseError {}

impl fmt::Display for MembershipBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyReport => write!(f, "membership report has no records"),
            Self::TooManyRecords(count) => {
                write!(f, "too many membership records: {count}")
            }
            Self::TooManySources(count) => write!(f, "too many membership sources: {count}"),
            Self::PacketTooLong(len) => write!(f, "membership report packet too long: {len} bytes"),
            Self::UnsupportedRecordKind(kind) => {
                write!(
                    f,
                    "membership record kind {kind:?} cannot be encoded in v3/v2 reports"
                )
            }
            Self::InvalidMulticastGroup(group) => write!(f, "invalid multicast group {group}"),
            Self::MixedAddressFamilies => write!(f, "record group/source address family mismatch"),
            Self::ProtocolAddressFamilyMismatch { protocol, group } => {
                write!(f, "{protocol:?} cannot encode membership for group {group}")
            }
        }
    }
}

impl std::error::Error for MembershipBuildError {}

pub fn parse_membership_report(packet: &[u8]) -> Result<MembershipReport, MembershipParseError> {
    let first = *packet.first().ok_or(MembershipParseError::Truncated {
        context: "IP packet",
        expected_at_least: 1,
        actual: 0,
    })?;

    match first >> 4 {
        4 => parse_ipv4_membership_report(packet),
        6 => parse_ipv6_membership_report(packet),
        version => Err(MembershipParseError::InvalidIpVersion(version)),
    }
}

pub fn build_membership_report(report: &MembershipReport) -> Result<Vec<u8>, MembershipBuildError> {
    match report.protocol {
        MembershipProtocol::Igmpv3 => build_igmpv3_membership_report(&report.records),
        MembershipProtocol::Mldv2 => build_mldv2_membership_report(&report.records),
    }
}

pub fn build_igmpv3_membership_report(
    records: &[MembershipRecord],
) -> Result<Vec<u8>, MembershipBuildError> {
    validate_build_records(MembershipProtocol::Igmpv3, records)?;
    let records_len = records.iter().try_fold(0usize, |len, record| {
        let source_len = checked_mul_sources(record.sources.len(), 4)?;
        len.checked_add(8 + source_len)
            .ok_or(MembershipBuildError::PacketTooLong(usize::MAX))
    })?;
    let igmp_len = 8 + records_len;
    let total_len = IPV4_ROUTER_ALERT_HEADER_LEN + igmp_len;
    if total_len > u16::MAX.into() {
        return Err(MembershipBuildError::PacketTooLong(total_len));
    }

    let mut packet = vec![0; total_len];
    packet[0] = 0x46;
    packet[1] = 0xc0;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 1;
    packet[9] = IGMP_PROTOCOL;
    packet[12..16].copy_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
    packet[16..20].copy_from_slice(&IGMPV3_REPORT_DESTINATION.octets());
    packet[20..24].copy_from_slice(&[0x94, 0x04, 0, 0]);

    let igmp = &mut packet[IPV4_ROUTER_ALERT_HEADER_LEN..];
    igmp[0] = IGMPV3_MEMBERSHIP_REPORT;
    igmp[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    let mut offset = 8;
    for record in records {
        let group = match record.group {
            IpAddr::V4(group) => group,
            IpAddr::V6(_) => unreachable!("validated address family"),
        };
        igmp[offset] = encode_record_kind(record.kind)?;
        igmp[offset + 2..offset + 4].copy_from_slice(&(record.sources.len() as u16).to_be_bytes());
        igmp[offset + 4..offset + 8].copy_from_slice(&group.octets());
        offset += 8;
        for source in &record.sources {
            let source = match source {
                IpAddr::V4(source) => *source,
                IpAddr::V6(_) => unreachable!("validated address family"),
            };
            igmp[offset..offset + 4].copy_from_slice(&source.octets());
            offset += 4;
        }
    }
    let igmp_checksum = checksum(igmp);
    igmp[2..4].copy_from_slice(&igmp_checksum.to_be_bytes());

    let header_checksum = checksum(&packet[..IPV4_ROUTER_ALERT_HEADER_LEN]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    Ok(packet)
}

pub fn build_mldv2_membership_report(
    records: &[MembershipRecord],
) -> Result<Vec<u8>, MembershipBuildError> {
    validate_build_records(MembershipProtocol::Mldv2, records)?;
    let records_len = records.iter().try_fold(0usize, |len, record| {
        let source_len = checked_mul_sources(record.sources.len(), 16)?;
        len.checked_add(20 + source_len)
            .ok_or(MembershipBuildError::PacketTooLong(usize::MAX))
    })?;
    let mld_len = 8 + records_len;
    let payload_len = IPV6_HOP_BY_HOP_LEN + mld_len;
    if payload_len > u16::MAX.into() {
        return Err(MembershipBuildError::PacketTooLong(
            IPV6_HEADER_LEN + payload_len,
        ));
    }

    let total_len = IPV6_HEADER_LEN + payload_len;
    let mut packet = vec![0; total_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    packet[6] = IPV6_HOP_BY_HOP;
    packet[7] = 1;
    let source = Ipv6Addr::UNSPECIFIED.octets();
    let destination = MLDV2_REPORT_DESTINATION.octets();
    packet[8..24].copy_from_slice(&source);
    packet[24..40].copy_from_slice(&destination);
    packet[40..48].copy_from_slice(&[ICMPV6_PROTOCOL, 0, 5, 2, 0, 0, 1, 0]);

    let mld_offset = IPV6_HEADER_LEN + IPV6_HOP_BY_HOP_LEN;
    let mld = &mut packet[mld_offset..];
    mld[0] = MLDV2_LISTENER_REPORT;
    mld[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    let mut offset = 8;
    for record in records {
        let group = match record.group {
            IpAddr::V6(group) => group,
            IpAddr::V4(_) => unreachable!("validated address family"),
        };
        mld[offset] = encode_record_kind(record.kind)?;
        mld[offset + 2..offset + 4].copy_from_slice(&(record.sources.len() as u16).to_be_bytes());
        mld[offset + 4..offset + 20].copy_from_slice(&group.octets());
        offset += 20;
        for source in &record.sources {
            let source = match source {
                IpAddr::V6(source) => *source,
                IpAddr::V4(_) => unreachable!("validated address family"),
            };
            mld[offset..offset + 16].copy_from_slice(&source.octets());
            offset += 16;
        }
    }

    let mld_checksum = icmpv6_checksum(&source, &destination, ICMPV6_PROTOCOL, mld);
    mld[2..4].copy_from_slice(&mld_checksum.to_be_bytes());

    Ok(packet)
}

fn parse_ipv4_membership_report(packet: &[u8]) -> Result<MembershipReport, MembershipParseError> {
    require_len("IPv4 header", packet, IPV4_MIN_HEADER_LEN)?;

    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < IPV4_MIN_HEADER_LEN {
        return Err(MembershipParseError::InvalidIpv4HeaderLength(ihl));
    }
    require_len("IPv4 header", packet, ihl)?;

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || total_len > packet.len() {
        return Err(MembershipParseError::InvalidTotalLength {
            total_length: total_len,
            available: packet.len(),
        });
    }

    if packet[9] != IGMP_PROTOCOL {
        return Err(MembershipParseError::InvalidProtocol {
            expected: IGMP_PROTOCOL,
            actual: packet[9],
        });
    }

    if ones_complement_sum(&packet[..ihl]) != 0xffff {
        return Err(MembershipParseError::InvalidChecksum("IPv4 header"));
    }

    let igmp = &packet[ihl..total_len];
    require_len("IGMP message", igmp, 8)?;
    if ones_complement_sum(igmp) != 0xffff {
        return Err(MembershipParseError::InvalidChecksum("IGMP"));
    }

    let records = match igmp[0] {
        IGMPV1_MEMBERSHIP_REPORT | IGMPV2_MEMBERSHIP_REPORT => {
            vec![legacy_record(
                MembershipRecordKind::LegacyReport,
                IpAddr::V4(read_ipv4(igmp, 4)),
            )]
        }
        IGMPV2_LEAVE_GROUP => {
            vec![legacy_record(
                MembershipRecordKind::LegacyLeave,
                IpAddr::V4(read_ipv4(igmp, 4)),
            )]
        }
        IGMPV3_MEMBERSHIP_REPORT => parse_igmpv3_records(igmp)?,
        kind => return Err(MembershipParseError::UnsupportedMembershipMessage(kind)),
    };
    validate_records(&records)?;

    Ok(MembershipReport {
        protocol: MembershipProtocol::Igmpv3,
        records,
    })
}

fn parse_ipv6_membership_report(packet: &[u8]) -> Result<MembershipReport, MembershipParseError> {
    require_len("IPv6 header", packet, IPV6_HEADER_LEN)?;

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN + payload_len;
    if total_len > packet.len() {
        return Err(MembershipParseError::InvalidTotalLength {
            total_length: total_len,
            available: packet.len(),
        });
    }

    if packet[7] != 1 {
        return Err(MembershipParseError::InvalidProtocol {
            expected: 1,
            actual: packet[7],
        });
    }

    let src = read_ipv6(packet, 8).octets();
    let dst = read_ipv6(packet, 24).octets();
    let mut next_header = packet[6];
    let mut offset = IPV6_HEADER_LEN;
    let mut saw_router_alert = false;

    if next_header == IPV6_HOP_BY_HOP {
        require_len("IPv6 hop-by-hop header", &packet[offset..total_len], 8)?;
        next_header = packet[offset];
        let extension_len = (usize::from(packet[offset + 1]) + 1) * 8;
        require_len(
            "IPv6 hop-by-hop header",
            &packet[offset..total_len],
            extension_len,
        )?;
        saw_router_alert = has_router_alert(&packet[offset + 2..offset + extension_len]);
        offset += extension_len;
    }

    if !saw_router_alert {
        return Err(MembershipParseError::MissingIpv6RouterAlert);
    }

    if next_header != ICMPV6_PROTOCOL {
        return Err(MembershipParseError::InvalidProtocol {
            expected: ICMPV6_PROTOCOL,
            actual: next_header,
        });
    }

    let icmp = &packet[offset..total_len];
    require_len("MLD message", icmp, 8)?;
    if icmpv6_checksum(&src, &dst, ICMPV6_PROTOCOL, icmp) != 0 {
        return Err(MembershipParseError::InvalidChecksum("ICMPv6"));
    }

    let records = match icmp[0] {
        MLDV1_LISTENER_REPORT => {
            require_len("MLDv1 Listener Report", icmp, 24)?;
            vec![legacy_record(
                MembershipRecordKind::LegacyReport,
                IpAddr::V6(read_ipv6(icmp, 8)),
            )]
        }
        MLDV1_LISTENER_DONE => {
            require_len("MLDv1 Listener Done", icmp, 24)?;
            vec![legacy_record(
                MembershipRecordKind::LegacyLeave,
                IpAddr::V6(read_ipv6(icmp, 8)),
            )]
        }
        MLDV2_LISTENER_REPORT => parse_mldv2_records(icmp)?,
        kind => return Err(MembershipParseError::UnsupportedMembershipMessage(kind)),
    };
    validate_records(&records)?;

    Ok(MembershipReport {
        protocol: MembershipProtocol::Mldv2,
        records,
    })
}

fn parse_igmpv3_records(igmp: &[u8]) -> Result<Vec<MembershipRecord>, MembershipParseError> {
    require_len("IGMPv3 Membership Report", igmp, 8)?;
    let count = usize::from(u16::from_be_bytes([igmp[6], igmp[7]]));
    let mut records = Vec::with_capacity(count);
    let mut offset = 8;

    for _ in 0..count {
        require_len("IGMPv3 group record", &igmp[offset..], 8)?;
        let kind = record_kind(igmp[offset])?;
        let aux_len = usize::from(igmp[offset + 1]) * 4;
        let source_count = usize::from(u16::from_be_bytes([igmp[offset + 2], igmp[offset + 3]]));
        let group = IpAddr::V4(read_ipv4(igmp, offset + 4));
        let sources_offset = offset + 8;
        let record_len = 8 + (source_count * 4) + aux_len;
        require_len("IGMPv3 group record", &igmp[offset..], record_len)?;

        let mut sources = Vec::with_capacity(source_count);
        for i in 0..source_count {
            sources.push(IpAddr::V4(read_ipv4(igmp, sources_offset + (i * 4))));
        }
        validate_record(group, &sources)?;
        records.push(MembershipRecord {
            kind,
            group,
            sources,
        });
        offset += record_len;
    }

    Ok(records)
}

fn parse_mldv2_records(icmp: &[u8]) -> Result<Vec<MembershipRecord>, MembershipParseError> {
    require_len("MLDv2 Listener Report", icmp, 8)?;
    let count = usize::from(u16::from_be_bytes([icmp[6], icmp[7]]));
    let mut records = Vec::with_capacity(count);
    let mut offset = 8;

    for _ in 0..count {
        require_len("MLDv2 multicast address record", &icmp[offset..], 20)?;
        let kind = record_kind(icmp[offset])?;
        let aux_len = usize::from(icmp[offset + 1]) * 4;
        let source_count = usize::from(u16::from_be_bytes([icmp[offset + 2], icmp[offset + 3]]));
        let group = IpAddr::V6(read_ipv6(icmp, offset + 4));
        let sources_offset = offset + 20;
        let record_len = 20 + (source_count * 16) + aux_len;
        require_len(
            "MLDv2 multicast address record",
            &icmp[offset..],
            record_len,
        )?;

        let mut sources = Vec::with_capacity(source_count);
        for i in 0..source_count {
            sources.push(IpAddr::V6(read_ipv6(icmp, sources_offset + (i * 16))));
        }
        validate_record(group, &sources)?;
        records.push(MembershipRecord {
            kind,
            group,
            sources,
        });
        offset += record_len;
    }

    Ok(records)
}

fn record_kind(value: u8) -> Result<MembershipRecordKind, MembershipParseError> {
    match value {
        1 => Ok(MembershipRecordKind::ModeIsInclude),
        2 => Ok(MembershipRecordKind::ModeIsExclude),
        3 => Ok(MembershipRecordKind::ChangeToInclude),
        4 => Ok(MembershipRecordKind::ChangeToExclude),
        5 => Ok(MembershipRecordKind::AllowNewSources),
        6 => Ok(MembershipRecordKind::BlockOldSources),
        other => Err(MembershipParseError::UnknownRecordType(other)),
    }
}

fn legacy_record(kind: MembershipRecordKind, group: IpAddr) -> MembershipRecord {
    MembershipRecord {
        kind,
        group,
        sources: Vec::new(),
    }
}

fn validate_record(group: IpAddr, sources: &[IpAddr]) -> Result<(), MembershipParseError> {
    if !group.is_multicast() {
        return Err(MembershipParseError::InvalidMulticastGroup(group));
    }

    if sources
        .iter()
        .any(|source| !same_family(group, *source) || source.is_multicast())
    {
        return Err(MembershipParseError::MixedAddressFamilies);
    }

    Ok(())
}

fn validate_build_records(
    protocol: MembershipProtocol,
    records: &[MembershipRecord],
) -> Result<(), MembershipBuildError> {
    if records.is_empty() {
        return Err(MembershipBuildError::EmptyReport);
    }
    if records.len() > u16::MAX.into() {
        return Err(MembershipBuildError::TooManyRecords(records.len()));
    }

    for record in records {
        encode_record_kind(record.kind)?;
        if !record.group.is_multicast() {
            return Err(MembershipBuildError::InvalidMulticastGroup(record.group));
        }
        match (protocol, record.group) {
            (MembershipProtocol::Igmpv3, IpAddr::V4(_))
            | (MembershipProtocol::Mldv2, IpAddr::V6(_)) => {}
            _ => {
                return Err(MembershipBuildError::ProtocolAddressFamilyMismatch {
                    protocol,
                    group: record.group,
                });
            }
        }
        if record.sources.len() > u16::MAX.into() {
            return Err(MembershipBuildError::TooManySources(record.sources.len()));
        }
        if record
            .sources
            .iter()
            .any(|source| !same_family(record.group, *source) || source.is_multicast())
        {
            return Err(MembershipBuildError::MixedAddressFamilies);
        }
    }

    Ok(())
}

fn checked_mul_sources(
    source_count: usize,
    source_len: usize,
) -> Result<usize, MembershipBuildError> {
    if source_count > u16::MAX.into() {
        return Err(MembershipBuildError::TooManySources(source_count));
    }
    source_count
        .checked_mul(source_len)
        .ok_or(MembershipBuildError::PacketTooLong(usize::MAX))
}

fn encode_record_kind(kind: MembershipRecordKind) -> Result<u8, MembershipBuildError> {
    match kind {
        MembershipRecordKind::ModeIsInclude => Ok(1),
        MembershipRecordKind::ModeIsExclude => Ok(2),
        MembershipRecordKind::ChangeToInclude => Ok(3),
        MembershipRecordKind::ChangeToExclude => Ok(4),
        MembershipRecordKind::AllowNewSources => Ok(5),
        MembershipRecordKind::BlockOldSources => Ok(6),
        MembershipRecordKind::LegacyReport | MembershipRecordKind::LegacyLeave => {
            Err(MembershipBuildError::UnsupportedRecordKind(kind))
        }
    }
}

fn validate_records(records: &[MembershipRecord]) -> Result<(), MembershipParseError> {
    for record in records {
        validate_record(record.group, &record.sources)?;
    }
    Ok(())
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn has_router_alert(options: &[u8]) -> bool {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => offset += 1,
            5 => {
                if offset + 4 > options.len() {
                    return false;
                }
                if options[offset + 1] == 2 && options[offset + 2] == 0 && options[offset + 3] == 0
                {
                    return true;
                }
                offset += 2 + usize::from(options[offset + 1]);
            }
            _ => {
                if offset + 2 > options.len() {
                    return false;
                }
                offset += 2 + usize::from(options[offset + 1]);
            }
        }
    }
    false
}

fn require_len(
    context: &'static str,
    bytes: &[u8],
    expected_at_least: usize,
) -> Result<(), MembershipParseError> {
    if bytes.len() < expected_at_least {
        Err(MembershipParseError::Truncated {
            context,
            expected_at_least,
            actual: bytes.len(),
        })
    } else {
        Ok(())
    }
}

fn read_ipv4(bytes: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    )
}

fn read_ipv6(bytes: &[u8], offset: usize) -> Ipv6Addr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&bytes[offset..offset + 16]);
    Ipv6Addr::from(octets)
}

pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    !ones_complement_sum(bytes)
}

pub(crate) fn ones_complement_sum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if let [high, low] = chunk {
            u16::from_be_bytes([*high, *low])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }

    sum as u16
}

pub(crate) fn icmpv6_checksum(
    src: &[u8; 16],
    dst: &[u8; 16],
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + payload.len());
    pseudo_header.extend_from_slice(src);
    pseudo_header.extend_from_slice(dst);
    pseudo_header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo_header.extend_from_slice(payload);
    checksum(&pseudo_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_igmpv3_membership_report() {
        let packet = ipv4_packet(igmpv3_report(&[igmpv3_record(
            1,
            Ipv4Addr::new(232, 1, 2, 3),
            &[Ipv4Addr::new(192, 0, 2, 1)],
        )]));

        let report = parse_membership_report(&packet).unwrap();

        assert_eq!(report.protocol, MembershipProtocol::Igmpv3);
        assert_eq!(
            report.records,
            vec![MembershipRecord {
                kind: MembershipRecordKind::ModeIsInclude,
                group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                sources: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            }]
        );
    }

    #[test]
    fn parses_igmpv2_leave() {
        let packet = ipv4_packet(igmpv2_message(
            IGMPV2_LEAVE_GROUP,
            Ipv4Addr::new(239, 1, 2, 3),
        ));

        let report = parse_membership_report(&packet).unwrap();

        assert_eq!(
            report.records,
            vec![MembershipRecord {
                kind: MembershipRecordKind::LegacyLeave,
                group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
                sources: Vec::new(),
            }]
        );
    }

    #[test]
    fn parses_mldv2_listener_report() {
        let packet = ipv6_packet(mldv2_report(&[mldv2_record(
            4,
            "ff3e::8000:1234".parse().unwrap(),
            &["2001:db8::1".parse().unwrap()],
        )]));

        let report = parse_membership_report(&packet).unwrap();

        assert_eq!(report.protocol, MembershipProtocol::Mldv2);
        assert_eq!(
            report.records,
            vec![MembershipRecord {
                kind: MembershipRecordKind::ChangeToExclude,
                group: IpAddr::V6("ff3e::8000:1234".parse().unwrap()),
                sources: vec![IpAddr::V6("2001:db8::1".parse().unwrap())],
            }]
        );
    }

    #[test]
    fn rejects_bad_igmp_checksum() {
        let mut packet = ipv4_packet(igmpv2_message(
            IGMPV2_MEMBERSHIP_REPORT,
            Ipv4Addr::new(239, 1, 2, 3),
        ));
        let offset = IPV4_MIN_HEADER_LEN + 2;
        packet[offset] ^= 0xff;

        assert_eq!(
            parse_membership_report(&packet),
            Err(MembershipParseError::InvalidChecksum("IGMP"))
        );
    }

    #[test]
    fn rejects_truncated_igmpv3_record_after_checksum_validation() {
        let packet = ipv4_packet(igmpv3_report(&[]));
        let mut packet = packet;
        let igmp_offset = IPV4_MIN_HEADER_LEN;
        packet[igmp_offset + 6..igmp_offset + 8].copy_from_slice(&1u16.to_be_bytes());
        packet[igmp_offset + 2..igmp_offset + 4].copy_from_slice(&[0, 0]);
        let checksum = checksum(&packet[igmp_offset..]);
        packet[igmp_offset + 2..igmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());

        assert_eq!(
            parse_membership_report(&packet),
            Err(MembershipParseError::Truncated {
                context: "IGMPv3 group record",
                expected_at_least: 8,
                actual: 0
            })
        );
    }

    #[test]
    fn builds_parseable_igmpv3_membership_report() {
        let report = MembershipReport {
            protocol: MembershipProtocol::Igmpv3,
            records: vec![MembershipRecord {
                kind: MembershipRecordKind::ModeIsInclude,
                group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                sources: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            }],
        };

        let packet = build_membership_report(&report).unwrap();

        assert_eq!(packet[0], 0x46);
        assert_eq!(&packet[16..20], &IGMPV3_REPORT_DESTINATION.octets());
        assert_eq!(parse_membership_report(&packet).unwrap(), report);
    }

    #[test]
    fn builds_parseable_mldv2_membership_report() {
        let report = MembershipReport {
            protocol: MembershipProtocol::Mldv2,
            records: vec![MembershipRecord {
                kind: MembershipRecordKind::ChangeToExclude,
                group: IpAddr::V6("ff3e::8000:1234".parse().unwrap()),
                sources: vec![IpAddr::V6("2001:db8::1".parse().unwrap())],
            }],
        };

        let packet = build_membership_report(&report).unwrap();

        assert_eq!(packet[0], 0x60);
        assert_eq!(&packet[24..40], &MLDV2_REPORT_DESTINATION.octets());
        assert_eq!(parse_membership_report(&packet).unwrap(), report);
    }

    #[test]
    fn build_rejects_empty_reports() {
        let report = MembershipReport {
            protocol: MembershipProtocol::Igmpv3,
            records: Vec::new(),
        };

        assert_eq!(
            build_membership_report(&report),
            Err(MembershipBuildError::EmptyReport)
        );
    }

    #[test]
    fn build_rejects_multicast_sources() {
        let report = MembershipReport {
            protocol: MembershipProtocol::Igmpv3,
            records: vec![MembershipRecord {
                kind: MembershipRecordKind::ModeIsInclude,
                group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
                sources: vec![IpAddr::V4(Ipv4Addr::new(239, 1, 2, 4))],
            }],
        };

        assert_eq!(
            build_membership_report(&report),
            Err(MembershipBuildError::MixedAddressFamilies)
        );
    }

    pub(crate) fn ipv4_packet(mut payload: Vec<u8>) -> Vec<u8> {
        let total_len = IPV4_MIN_HEADER_LEN + payload.len();
        let mut packet = vec![0; IPV4_MIN_HEADER_LEN];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 1;
        packet[9] = IGMP_PROTOCOL;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 1).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(224, 0, 0, 22).octets());
        let checksum = checksum(&packet);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.append(&mut payload);
        packet
    }

    pub(crate) fn igmpv2_message(kind: u8, group: Ipv4Addr) -> Vec<u8> {
        let mut payload = vec![0; 8];
        payload[0] = kind;
        payload[4..8].copy_from_slice(&group.octets());
        let checksum = checksum(&payload);
        payload[2..4].copy_from_slice(&checksum.to_be_bytes());
        payload
    }

    pub(crate) fn igmpv3_report(records: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = vec![0; 8];
        payload[0] = IGMPV3_MEMBERSHIP_REPORT;
        payload[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            payload.extend_from_slice(record);
        }
        let checksum = checksum(&payload);
        payload[2..4].copy_from_slice(&checksum.to_be_bytes());
        payload
    }

    pub(crate) fn igmpv3_record(kind: u8, group: Ipv4Addr, sources: &[Ipv4Addr]) -> Vec<u8> {
        let mut record = vec![0; 8];
        record[0] = kind;
        record[2..4].copy_from_slice(&(sources.len() as u16).to_be_bytes());
        record[4..8].copy_from_slice(&group.octets());
        for source in sources {
            record.extend_from_slice(&source.octets());
        }
        record
    }

    pub(crate) fn ipv6_packet(mut icmp: Vec<u8>) -> Vec<u8> {
        let payload_len = 8 + icmp.len();
        let total_len = IPV6_HEADER_LEN + payload_len;
        let mut packet = vec![0; total_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = IPV6_HOP_BY_HOP;
        packet[7] = 1;
        let src = Ipv6Addr::LOCALHOST.octets();
        let dst = "ff02::16".parse::<Ipv6Addr>().unwrap().octets();
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);
        packet[40..48].copy_from_slice(&[ICMPV6_PROTOCOL, 0, 5, 2, 0, 0, 1, 0]);
        let checksum = icmpv6_checksum(&src, &dst, ICMPV6_PROTOCOL, &icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
        packet[48..].copy_from_slice(&icmp);
        packet
    }

    pub(crate) fn mldv2_report(records: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = vec![0; 8];
        payload[0] = MLDV2_LISTENER_REPORT;
        payload[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for record in records {
            payload.extend_from_slice(record);
        }
        payload
    }

    pub(crate) fn mldv2_record(kind: u8, group: Ipv6Addr, sources: &[Ipv6Addr]) -> Vec<u8> {
        let mut record = vec![0; 20];
        record[0] = kind;
        record[2..4].copy_from_slice(&(sources.len() as u16).to_be_bytes());
        record[4..20].copy_from_slice(&group.octets());
        for source in sources {
            record.extend_from_slice(&source.octets());
        }
        record
    }
}
