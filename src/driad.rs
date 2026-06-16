//! DNS Reverse IP AMT Discovery (DRIAD), as defined by RFC 8777.
//!
//! The resolver is intentionally small and blocking. It sends a standard DNS
//! query for AMTRELAY (`TYPE260`) records and parses only the fields needed to
//! select an AMT relay for a known SSM source.

use crate::AMT_PORT;
use getrandom::fill as fill_random;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const AMTRELAY_RRTYPE: u16 = 260;

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_DNAME: u16 = 39;
const DNS_HEADER_LEN: usize = 12;
const MAX_DNS_DATAGRAM: usize = 4096;
const MAX_ALIAS_DEPTH: usize = 8;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_ATTEMPTS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmtRelayRecord {
    pub precedence: u8,
    pub discovery_optional: bool,
    pub target: AmtRelayTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmtRelayTarget {
    NoRelay,
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Name(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriadRelaySelection {
    pub source: IpAddr,
    pub query_name: String,
    pub record: AmtRelayRecord,
    pub relay: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriadResolverConfig {
    pub resolvers: Vec<SocketAddr>,
    pub timeout: Duration,
    pub attempts: usize,
}

impl DriadResolverConfig {
    pub fn new(resolvers: Vec<SocketAddr>) -> Self {
        Self {
            resolvers,
            timeout: DEFAULT_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
        }
    }

    pub fn system() -> Result<Self, DriadError> {
        let resolvers = system_resolvers()?;
        Ok(Self::new(resolvers))
    }
}

#[derive(Debug, Clone)]
pub struct DriadResolver {
    config: DriadResolverConfig,
}

impl DriadResolver {
    pub fn new(config: DriadResolverConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &DriadResolverConfig {
        &self.config
    }

    pub fn resolve_source(&self, source: IpAddr) -> Result<DriadRelaySelection, DriadError> {
        if self.config.resolvers.is_empty() {
            return Err(DriadError::NoResolvers);
        }

        let query_name = reverse_source_name(source);
        let records = self.lookup_amtrelay_following_aliases(&query_name)?;
        let (record, relay) = select_relay(&records)?;

        Ok(DriadRelaySelection {
            source,
            query_name,
            record,
            relay,
        })
    }

    fn lookup_amtrelay_following_aliases(
        &self,
        query_name: &str,
    ) -> Result<Vec<AmtRelayRecord>, DriadError> {
        let mut current = query_name.to_string();
        let mut visited = HashSet::new();

        for _ in 0..MAX_ALIAS_DEPTH {
            if !visited.insert(current.to_ascii_lowercase()) {
                return Err(DriadError::AliasLoop(current));
            }

            let response = self.lookup_amtrelay_name(&current)?;
            if !response.records.is_empty() {
                return Ok(response.records);
            }

            let Some(alias) = response.aliases.into_iter().next() else {
                return Err(DriadError::NoRecords(current));
            };
            current = alias;
        }

        Err(DriadError::AliasDepthExceeded(query_name.to_string()))
    }

    fn lookup_amtrelay_name(&self, name: &str) -> Result<DnsAmtRelayResponse, DriadError> {
        let mut last_error = None;

        for _ in 0..self.config.attempts.max(1) {
            for resolver in &self.config.resolvers {
                match self.query_resolver(*resolver, name) {
                    Ok(response) => return Ok(response),
                    Err(error) => last_error = Some(error),
                }
            }
        }

        Err(last_error.unwrap_or(DriadError::NoResolvers))
    }

    fn query_resolver(
        &self,
        resolver: SocketAddr,
        name: &str,
    ) -> Result<DnsAmtRelayResponse, DriadError> {
        let id = random_dns_id();
        let query = build_dns_query(id, name, AMTRELAY_RRTYPE)?;
        let bind = match resolver {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let socket = UdpSocket::bind(bind)
            .map_err(|error| DriadError::Io(format!("failed to bind DNS socket: {error}")))?;
        socket
            .set_read_timeout(Some(self.config.timeout))
            .map_err(|error| DriadError::Io(format!("failed to set DNS read timeout: {error}")))?;
        socket
            .set_write_timeout(Some(self.config.timeout))
            .map_err(|error| DriadError::Io(format!("failed to set DNS write timeout: {error}")))?;
        socket
            .send_to(&query, resolver)
            .map_err(|error| DriadError::Io(format!("failed to send DNS query: {error}")))?;

        let mut buf = [0; MAX_DNS_DATAGRAM];
        let (len, _) = socket
            .recv_from(&mut buf)
            .map_err(|error| DriadError::Io(format!("failed to receive DNS response: {error}")))?;
        parse_dns_response(id, name, &buf[..len])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsAmtRelayResponse {
    records: Vec<AmtRelayRecord>,
    aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriadError {
    NoResolvers,
    NoRecords(String),
    NoUsableRelay,
    NoRelayPresent,
    AliasLoop(String),
    AliasDepthExceeded(String),
    Truncated(&'static str),
    InvalidDnsName(String),
    InvalidDnsPointer,
    InvalidResponseId {
        expected: u16,
        actual: u16,
    },
    DnsResponseCode(u8),
    InvalidRelayType(u8),
    InvalidRelayLength {
        relay_type: u8,
        expected: usize,
        actual: usize,
    },
    InvalidRelayName,
    Io(String),
}

impl fmt::Display for DriadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoResolvers => write!(f, "no DRIAD DNS resolvers are configured"),
            Self::NoRecords(name) => write!(f, "no AMTRELAY records found for {name}"),
            Self::NoUsableRelay => write!(f, "AMTRELAY records did not contain a usable relay"),
            Self::NoRelayPresent => write!(f, "AMTRELAY record says no relay is present"),
            Self::AliasLoop(name) => write!(f, "DNS alias loop while resolving {name}"),
            Self::AliasDepthExceeded(name) => {
                write!(f, "too many DNS aliases while resolving {name}")
            }
            Self::Truncated(context) => write!(f, "truncated DRIAD {context}"),
            Self::InvalidDnsName(name) => write!(f, "invalid DNS name '{name}'"),
            Self::InvalidDnsPointer => write!(f, "invalid compressed DNS name pointer"),
            Self::InvalidResponseId { expected, actual } => write!(
                f,
                "unexpected DNS response id {actual:#x}; expected {expected:#x}"
            ),
            Self::DnsResponseCode(code) => write!(f, "DNS response returned rcode {code}"),
            Self::InvalidRelayType(relay_type) => {
                write!(f, "unsupported AMTRELAY target type {relay_type}")
            }
            Self::InvalidRelayLength {
                relay_type,
                expected,
                actual,
            } => write!(
                f,
                "invalid AMTRELAY target type {relay_type} length {actual}; expected {expected}"
            ),
            Self::InvalidRelayName => write!(f, "invalid AMTRELAY domain-name target"),
            Self::Io(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for DriadError {}

pub fn reverse_source_name(source: IpAddr) -> String {
    match source {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(addr) => {
            let mut nibbles = Vec::with_capacity(32);
            for byte in addr.octets().iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0f));
                nibbles.push(format!("{:x}", byte >> 4));
            }
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

pub fn parse_resolver_addr(value: &str) -> Result<SocketAddr, DriadError> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(addr) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(addr, 53));
    }
    Err(DriadError::InvalidDnsName(value.to_string()))
}

pub fn system_resolvers() -> Result<Vec<SocketAddr>, DriadError> {
    #[cfg(unix)]
    {
        let contents = std::fs::read_to_string("/etc/resolv.conf")
            .map_err(|error| DriadError::Io(format!("failed to read /etc/resolv.conf: {error}")))?;
        let resolvers = contents
            .lines()
            .filter_map(|line| {
                let line = line.split('#').next()?.trim();
                let mut parts = line.split_whitespace();
                (parts.next()? == "nameserver")
                    .then(|| parts.next())
                    .flatten()
            })
            .map(parse_resolver_addr)
            .collect::<Result<Vec<_>, _>>()?;
        if resolvers.is_empty() {
            return Err(DriadError::NoResolvers);
        }
        Ok(resolvers)
    }
    #[cfg(not(unix))]
    {
        Err(DriadError::NoResolvers)
    }
}

pub fn parse_amtrelay_rdata(rdata: &[u8]) -> Result<AmtRelayRecord, DriadError> {
    if rdata.len() < 2 {
        return Err(DriadError::Truncated("AMTRELAY RDATA"));
    }

    let precedence = rdata[0];
    let discovery_optional = (rdata[1] & 0x80) != 0;
    let relay_type = rdata[1] & 0x7f;
    let relay = &rdata[2..];
    let target = match relay_type {
        0 => {
            require_relay_len(relay_type, relay, 0)?;
            AmtRelayTarget::NoRelay
        }
        1 => {
            require_relay_len(relay_type, relay, 4)?;
            AmtRelayTarget::Ipv4(Ipv4Addr::new(relay[0], relay[1], relay[2], relay[3]))
        }
        2 => {
            require_relay_len(relay_type, relay, 16)?;
            let mut octets = [0; 16];
            octets.copy_from_slice(relay);
            AmtRelayTarget::Ipv6(Ipv6Addr::from(octets))
        }
        3 => {
            let (name, consumed) = parse_dns_name(rdata, 2)?;
            if consumed != rdata.len() || name.is_empty() {
                return Err(DriadError::InvalidRelayName);
            }
            AmtRelayTarget::Name(name)
        }
        other => return Err(DriadError::InvalidRelayType(other)),
    };

    Ok(AmtRelayRecord {
        precedence,
        discovery_optional,
        target,
    })
}

fn select_relay(records: &[AmtRelayRecord]) -> Result<(AmtRelayRecord, SocketAddr), DriadError> {
    let mut records = records.to_vec();
    records.sort_by_key(|record| record.precedence);

    for record in records {
        match relay_socket_addr(&record.target) {
            Ok(relay) => return Ok((record, relay)),
            Err(DriadError::NoRelayPresent) => return Err(DriadError::NoRelayPresent),
            Err(_) => continue,
        }
    }

    Err(DriadError::NoUsableRelay)
}

fn relay_socket_addr(target: &AmtRelayTarget) -> Result<SocketAddr, DriadError> {
    match target {
        AmtRelayTarget::NoRelay => Err(DriadError::NoRelayPresent),
        AmtRelayTarget::Ipv4(addr) => Ok(SocketAddr::new(IpAddr::V4(*addr), AMT_PORT)),
        AmtRelayTarget::Ipv6(addr) => Ok(SocketAddr::new(IpAddr::V6(*addr), AMT_PORT)),
        AmtRelayTarget::Name(name) => (name.as_str(), AMT_PORT)
            .to_socket_addrs()
            .map_err(|error| DriadError::Io(format!("failed to resolve {name}: {error}")))?
            .next()
            .ok_or(DriadError::NoUsableRelay),
    }
}

fn require_relay_len(relay_type: u8, relay: &[u8], expected: usize) -> Result<(), DriadError> {
    if relay.len() == expected {
        Ok(())
    } else {
        Err(DriadError::InvalidRelayLength {
            relay_type,
            expected,
            actual: relay.len(),
        })
    }
}

fn build_dns_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, DriadError> {
    let mut out = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    put_dns_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(out)
}

fn parse_dns_response(
    expected_id: u16,
    query_name: &str,
    response: &[u8],
) -> Result<DnsAmtRelayResponse, DriadError> {
    if response.len() < DNS_HEADER_LEN {
        return Err(DriadError::Truncated("DNS header"));
    }
    let actual_id = read_u16(response, 0)?;
    if actual_id != expected_id {
        return Err(DriadError::InvalidResponseId {
            expected: expected_id,
            actual: actual_id,
        });
    }

    let flags = read_u16(response, 2)?;
    let rcode = (flags & 0x000f) as u8;
    if rcode != 0 {
        return Err(DriadError::DnsResponseCode(rcode));
    }

    let qdcount = read_u16(response, 4)? as usize;
    let ancount = read_u16(response, 6)? as usize;
    let mut offset = DNS_HEADER_LEN;
    for _ in 0..qdcount {
        let (_, next) = parse_dns_name(response, offset)?;
        offset = next
            .checked_add(4)
            .ok_or(DriadError::Truncated("question"))?;
        if offset > response.len() {
            return Err(DriadError::Truncated("question"));
        }
    }

    let mut records = Vec::new();
    let mut aliases = Vec::new();
    for _ in 0..ancount {
        let (owner, next) = parse_dns_name(response, offset)?;
        offset = next;
        if offset + 10 > response.len() {
            return Err(DriadError::Truncated("answer"));
        }
        let rrtype = read_u16(response, offset)?;
        let class = read_u16(response, offset + 2)?;
        let rdlen = read_u16(response, offset + 8)? as usize;
        offset += 10;
        let rdata_end = offset
            .checked_add(rdlen)
            .ok_or(DriadError::Truncated("answer RDATA"))?;
        if rdata_end > response.len() {
            return Err(DriadError::Truncated("answer RDATA"));
        }

        if class == DNS_CLASS_IN && rrtype == AMTRELAY_RRTYPE {
            records.push(parse_amtrelay_rdata(&response[offset..rdata_end])?);
        } else if class == DNS_CLASS_IN && rrtype == DNS_TYPE_CNAME {
            let (alias, _) = parse_dns_name(response, offset)?;
            aliases.push(alias);
        } else if class == DNS_CLASS_IN && rrtype == DNS_TYPE_DNAME {
            let (target, _) = parse_dns_name(response, offset)?;
            if let Some(alias) = apply_dname(query_name, &owner, &target) {
                aliases.push(alias);
            }
        }

        offset = rdata_end;
    }

    Ok(DnsAmtRelayResponse { records, aliases })
}

fn put_dns_name(out: &mut Vec<u8>, name: &str) -> Result<(), DriadError> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return Ok(());
    }
    if name.len() > 253 {
        return Err(DriadError::InvalidDnsName(name.to_string()));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DriadError::InvalidDnsName(name.to_string()));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn parse_dns_name(message: &[u8], offset: usize) -> Result<(String, usize), DriadError> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut next_offset = None;

    for _ in 0..128 {
        let len = *message
            .get(cursor)
            .ok_or(DriadError::Truncated("DNS name"))?;
        match len & 0xc0 {
            0x00 => {
                cursor += 1;
                if len == 0 {
                    return Ok((labels.join("."), next_offset.unwrap_or(cursor)));
                }
                let label_end = cursor
                    .checked_add(len as usize)
                    .ok_or(DriadError::Truncated("DNS label"))?;
                let label = message
                    .get(cursor..label_end)
                    .ok_or(DriadError::Truncated("DNS label"))?;
                labels.push(
                    std::str::from_utf8(label)
                        .map_err(|_| DriadError::InvalidRelayName)?
                        .to_string(),
                );
                cursor = label_end;
            }
            0xc0 => {
                let pointer_tail = *message
                    .get(cursor + 1)
                    .ok_or(DriadError::Truncated("DNS pointer"))?;
                let pointer = (((len & 0x3f) as usize) << 8) | pointer_tail as usize;
                if pointer >= message.len() {
                    return Err(DriadError::InvalidDnsPointer);
                }
                next_offset.get_or_insert(cursor + 2);
                cursor = pointer;
            }
            _ => return Err(DriadError::InvalidDnsPointer),
        }
    }

    Err(DriadError::InvalidDnsPointer)
}

fn apply_dname(query_name: &str, owner: &str, target: &str) -> Option<String> {
    let query = query_name.trim_end_matches('.');
    let owner = owner.trim_end_matches('.');
    let target = target.trim_end_matches('.');
    if query.eq_ignore_ascii_case(owner) {
        return Some(target.to_string());
    }
    let suffix = format!(".{owner}");
    query
        .to_ascii_lowercase()
        .ends_with(&suffix.to_ascii_lowercase())
        .then(|| {
            let prefix_len = query.len() - suffix.len();
            format!("{}.{}", &query[..prefix_len], target)
        })
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, DriadError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(DriadError::Truncated("u16"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn random_dns_id() -> u16 {
    let mut bytes = [0; 2];
    if fill_random(&mut bytes).is_ok() {
        return u16::from_be_bytes(bytes);
    }

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_match_ipv4_and_ipv6_sources() {
        assert_eq!(
            reverse_source_name(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12))),
            "12.100.51.198.in-addr.arpa"
        );
        assert_eq!(
            reverse_source_name(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
    }

    #[test]
    fn parses_amtrelay_ipv4_ipv6_name_and_no_relay() {
        assert_eq!(
            parse_amtrelay_rdata(&[10, 1, 203, 0, 113, 15]),
            Ok(AmtRelayRecord {
                precedence: 10,
                discovery_optional: false,
                target: AmtRelayTarget::Ipv4(Ipv4Addr::new(203, 0, 113, 15)),
            })
        );

        let mut ipv6 = vec![10, 2];
        ipv6.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert_eq!(
            parse_amtrelay_rdata(&ipv6).unwrap().target,
            AmtRelayTarget::Ipv6(Ipv6Addr::LOCALHOST)
        );

        let mut name = vec![128, 0x83];
        put_dns_name(&mut name, "amtrelays.example.com").unwrap();
        assert_eq!(
            parse_amtrelay_rdata(&name),
            Ok(AmtRelayRecord {
                precedence: 128,
                discovery_optional: true,
                target: AmtRelayTarget::Name("amtrelays.example.com".to_string()),
            })
        );

        assert_eq!(
            parse_amtrelay_rdata(&[0, 0]),
            Ok(AmtRelayRecord {
                precedence: 0,
                discovery_optional: false,
                target: AmtRelayTarget::NoRelay,
            })
        );
    }

    #[test]
    fn rejects_bad_amtrelay_lengths() {
        assert_eq!(
            parse_amtrelay_rdata(&[10, 1, 203, 0, 113]),
            Err(DriadError::InvalidRelayLength {
                relay_type: 1,
                expected: 4,
                actual: 3,
            })
        );
        assert_eq!(
            parse_amtrelay_rdata(&[10, 4]),
            Err(DriadError::InvalidRelayType(4))
        );
    }

    #[test]
    fn parses_dns_response_with_amtrelay_answer() {
        let name = "12.100.51.198.in-addr.arpa";
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        put_dns_name(&mut response, name).unwrap();
        response.extend_from_slice(&AMTRELAY_RRTYPE.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&AMTRELAY_RRTYPE.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&6u16.to_be_bytes());
        response.extend_from_slice(&[10, 1, 203, 0, 113, 15]);

        let parsed = parse_dns_response(0x1234, name, &response).unwrap();

        assert_eq!(
            parsed.records,
            vec![AmtRelayRecord {
                precedence: 10,
                discovery_optional: false,
                target: AmtRelayTarget::Ipv4(Ipv4Addr::new(203, 0, 113, 15)),
            }]
        );
    }

    #[test]
    fn follows_cname_answers() {
        let name = "12.100.51.198.in-addr.arpa";
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        put_dns_name(&mut response, name).unwrap();
        response.extend_from_slice(&AMTRELAY_RRTYPE.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&DNS_TYPE_CNAME.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        let rdlen_offset = response.len();
        response.extend_from_slice(&0u16.to_be_bytes());
        let rdata_offset = response.len();
        put_dns_name(&mut response, "relay.example.com").unwrap();
        let rdlen = (response.len() - rdata_offset) as u16;
        response[rdlen_offset..rdlen_offset + 2].copy_from_slice(&rdlen.to_be_bytes());

        let parsed = parse_dns_response(0x1234, name, &response).unwrap();

        assert_eq!(parsed.aliases, vec!["relay.example.com"]);
    }

    #[test]
    fn applies_dname_suffix_rewrite() {
        assert_eq!(
            apply_dname(
                "12.100.51.198.in-addr.arpa",
                "100.51.198.in-addr.arpa",
                "example.net",
            ),
            Some("12.example.net".to_string())
        );
    }
}
