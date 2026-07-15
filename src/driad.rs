//! DNS Reverse IP AMT Discovery (DRIAD), as defined by RFC 8777.
//!
//! The resolver is intentionally small and blocking. It sends a standard DNS
//! query for AMTRELAY (`TYPE260`) records and parses only the fields needed to
//! select an AMT relay for a known SSM source.

use crate::AMT_PORT;
use getrandom::fill as fill_random;
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const AMTRELAY_RRTYPE: u16 = 260;
pub const AMT_ANYCAST_IPV4: Ipv4Addr = Ipv4Addr::new(192, 52, 193, 1);
pub const AMT_ANYCAST_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 1);

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_DNAME: u16 = 39;
const DNS_HEADER_LEN: usize = 12;
const MAX_DNS_DATAGRAM: usize = 4096;
const MAX_ALIAS_DEPTH: usize = 8;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_ATTEMPTS: usize = 2;
const DEFAULT_MAX_CANDIDATES: usize = 64;
const DEFAULT_DNS_QUERIES_PER_WINDOW: usize = 10;
const DEFAULT_DNS_QUERY_WINDOW: Duration = Duration::from_millis(100);

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
    /// Minimum DNS lifetime across the AMTRELAY, alias, and address records.
    pub ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriadResolverConfig {
    pub resolvers: Vec<SocketAddr>,
    pub timeout: Duration,
    pub attempts: usize,
    pub allow_insecure_dns: bool,
    pub max_candidates: usize,
    pub max_queries_per_window: usize,
    pub query_rate_window: Duration,
}

impl DriadResolverConfig {
    pub fn new(resolvers: Vec<SocketAddr>) -> Self {
        Self {
            resolvers,
            timeout: DEFAULT_TIMEOUT,
            attempts: DEFAULT_ATTEMPTS,
            allow_insecure_dns: false,
            max_candidates: DEFAULT_MAX_CANDIDATES,
            max_queries_per_window: DEFAULT_DNS_QUERIES_PER_WINDOW,
            query_rate_window: DEFAULT_DNS_QUERY_WINDOW,
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
    query_limiter: Arc<Mutex<DnsQueryLimiter>>,
}

impl DriadResolver {
    pub fn new(config: DriadResolverConfig) -> Self {
        let query_limiter = DnsQueryLimiter::new(
            config.max_queries_per_window.max(1),
            config.query_rate_window.max(Duration::from_millis(1)),
        );
        Self {
            config,
            query_limiter: Arc::new(Mutex::new(query_limiter)),
        }
    }

    pub fn config(&self) -> &DriadResolverConfig {
        &self.config
    }

    pub fn validate(&self) -> Result<(), DriadError> {
        if self.config.resolvers.is_empty() {
            return Err(DriadError::NoResolvers);
        }
        if !self.config.allow_insecure_dns
            && let Some(resolver) = self
                .config
                .resolvers
                .iter()
                .find(|resolver| !resolver.ip().is_loopback())
        {
            return Err(DriadError::InsecureResolver(*resolver));
        }
        if self.config.timeout.is_zero() {
            return Err(DriadError::InvalidConfig("timeout must not be zero"));
        }
        if self.config.attempts == 0 {
            return Err(DriadError::InvalidConfig("attempts must not be zero"));
        }
        if self.config.max_candidates == 0 {
            return Err(DriadError::InvalidConfig(
                "maximum candidate count must not be zero",
            ));
        }
        if self.config.max_queries_per_window == 0 {
            return Err(DriadError::InvalidConfig(
                "DNS query limit must not be zero",
            ));
        }
        if self.config.query_rate_window.is_zero() {
            return Err(DriadError::InvalidConfig(
                "DNS query-rate window must not be zero",
            ));
        }
        Ok(())
    }

    pub fn resolve_source(&self, source: IpAddr) -> Result<DriadRelaySelection, DriadError> {
        self.resolve_source_candidates(source)?
            .into_iter()
            .next()
            .ok_or(DriadError::NoUsableRelay)
    }

    pub fn resolve_source_candidates(
        &self,
        source: IpAddr,
    ) -> Result<Vec<DriadRelaySelection>, DriadError> {
        self.validate()?;

        let query_name = reverse_source_name(source);
        let mut records = self.lookup_amtrelay_following_aliases(&query_name)?;
        if records
            .iter()
            .any(|record| matches!(record.value.target, AmtRelayTarget::NoRelay))
        {
            return Err(DriadError::NoRelayPresent);
        }
        records.sort_by_key(|record| record.value.precedence);
        let mut selections = Vec::new();
        for record in records.into_iter().take(self.config.max_candidates.max(1)) {
            let Ok(relays) = self.relay_socket_addrs(&record.value.target) else {
                continue;
            };
            for relay in relays {
                if !is_usable_relay_address(relay.value.ip()) {
                    continue;
                }
                if selections
                    .iter()
                    .any(|selection: &DriadRelaySelection| selection.relay == relay.value)
                {
                    continue;
                }
                selections.push(DriadRelaySelection {
                    source,
                    query_name: query_name.clone(),
                    record: record.value.clone(),
                    relay: relay.value,
                    ttl: record.ttl.min(relay.ttl),
                });
                if selections.len() >= self.config.max_candidates.max(1) {
                    break;
                }
            }
            if selections.len() >= self.config.max_candidates.max(1) {
                break;
            }
        }
        if selections.is_empty() {
            Err(DriadError::NoUsableRelay)
        } else {
            order_relay_candidates(&mut selections);
            Ok(selections)
        }
    }

    fn lookup_amtrelay_following_aliases(
        &self,
        query_name: &str,
    ) -> Result<Vec<Timed<AmtRelayRecord>>, DriadError> {
        let mut current = query_name.to_string();
        let mut visited = HashSet::new();
        let mut alias_ttl = Duration::MAX;

        for _ in 0..MAX_ALIAS_DEPTH {
            if !visited.insert(current.to_ascii_lowercase()) {
                return Err(DriadError::AliasLoop(current));
            }

            let response = self.lookup_amtrelay_name(&current)?;
            if !response.records.is_empty() {
                return Ok(response
                    .records
                    .into_iter()
                    .map(|record| Timed {
                        value: record.value,
                        ttl: record.ttl.min(alias_ttl),
                    })
                    .collect());
            }

            let Some(alias) = response.aliases.into_iter().next() else {
                return Err(DriadError::NoRecords(current));
            };
            alias_ttl = alias_ttl.min(alias.ttl);
            current = alias.value;
        }

        Err(DriadError::AliasDepthExceeded(query_name.to_string()))
    }

    fn lookup_amtrelay_name(&self, name: &str) -> Result<DnsAmtRelayResponse, DriadError> {
        let mut last_error = None;

        for attempt in 0..self.config.attempts.max(1) {
            let timeout = self.retry_timeout(attempt);
            for resolver in &self.config.resolvers {
                match self.query_resolver(*resolver, name, timeout) {
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
        timeout: Duration,
    ) -> Result<DnsAmtRelayResponse, DriadError> {
        let (id, response) = self.query_wire(resolver, name, AMTRELAY_RRTYPE, timeout)?;
        parse_dns_response(id, name, &response)
    }

    fn query_wire(
        &self,
        resolver: SocketAddr,
        name: &str,
        query_type: u16,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>), DriadError> {
        self.wait_for_query_budget()?;
        let id = random_dns_id()?;
        let query = build_dns_query(id, name, query_type)?;
        let bind = match resolver {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let socket = UdpSocket::bind(bind)
            .map_err(|error| DriadError::Io(format!("failed to bind DNS socket: {error}")))?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|error| DriadError::Io(format!("failed to set DNS read timeout: {error}")))?;
        socket
            .set_write_timeout(Some(timeout))
            .map_err(|error| DriadError::Io(format!("failed to set DNS write timeout: {error}")))?;
        socket
            .connect(resolver)
            .map_err(|error| DriadError::Io(format!("failed to connect DNS socket: {error}")))?;
        socket
            .send(&query)
            .map_err(|error| DriadError::Io(format!("failed to send DNS query: {error}")))?;

        let mut buf = [0; MAX_DNS_DATAGRAM];
        let len = socket
            .recv(&mut buf)
            .map_err(|error| DriadError::Io(format!("failed to receive DNS response: {error}")))?;
        if len >= 4 && u16::from_be_bytes([buf[2], buf[3]]) & 0x0200 != 0 {
            return self
                .query_tcp(resolver, &query, timeout)
                .map(|response| (id, response));
        }
        Ok((id, buf[..len].to_vec()))
    }

    fn query_tcp(
        &self,
        resolver: SocketAddr,
        query: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DriadError> {
        self.wait_for_query_budget()?;
        let mut stream = TcpStream::connect_timeout(&resolver, timeout).map_err(|error| {
            DriadError::Io(format!("failed to connect DNS TCP socket: {error}"))
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| DriadError::Io(format!("failed to set DNS TCP timeout: {error}")))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| DriadError::Io(format!("failed to set DNS TCP timeout: {error}")))?;
        let query_len = u16::try_from(query.len())
            .map_err(|_| DriadError::Io("DNS query is too large for TCP framing".to_string()))?;
        stream
            .write_all(&query_len.to_be_bytes())
            .and_then(|_| stream.write_all(query))
            .map_err(|error| DriadError::Io(format!("failed to send DNS TCP query: {error}")))?;

        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .map_err(|error| DriadError::Io(format!("failed to read DNS TCP length: {error}")))?;
        let response_len = usize::from(u16::from_be_bytes(length));
        if response_len < DNS_HEADER_LEN {
            return Err(DriadError::Truncated("DNS TCP response"));
        }
        let mut response = vec![0u8; response_len];
        stream
            .read_exact(&mut response)
            .map_err(|error| DriadError::Io(format!("failed to read DNS TCP response: {error}")))?;
        Ok(response)
    }

    fn retry_timeout(&self, attempt: usize) -> Duration {
        let multiplier = 1u32 << attempt.min(6);
        let maximum = Duration::from_secs(120);
        let upper = self
            .config
            .timeout
            .checked_mul(multiplier)
            .unwrap_or(maximum)
            .min(maximum);
        randomized_duration(self.config.timeout.min(upper), upper)
    }

    fn wait_for_query_budget(&self) -> Result<(), DriadError> {
        loop {
            let wait = self
                .query_limiter
                .lock()
                .map_err(|_| DriadError::Io("DRIAD DNS query limiter is poisoned".to_string()))?
                .reserve_at(Instant::now());
            let Some(wait) = wait else {
                return Ok(());
            };
            thread::sleep(wait);
        }
    }

    fn relay_socket_addrs(
        &self,
        target: &AmtRelayTarget,
    ) -> Result<Vec<Timed<SocketAddr>>, DriadError> {
        match target {
            AmtRelayTarget::NoRelay => Err(DriadError::NoRelayPresent),
            AmtRelayTarget::Ipv4(addr) => Ok(vec![Timed {
                value: SocketAddr::new(IpAddr::V4(*addr), AMT_PORT),
                ttl: Duration::MAX,
            }]),
            AmtRelayTarget::Ipv6(addr) => Ok(vec![Timed {
                value: SocketAddr::new(IpAddr::V6(*addr), AMT_PORT),
                ttl: Duration::MAX,
            }]),
            AmtRelayTarget::Name(name) => {
                let addresses = self
                    .lookup_host(name)?
                    .into_iter()
                    .map(|address| Timed {
                        value: SocketAddr::new(address.value, AMT_PORT),
                        ttl: address.ttl,
                    })
                    .collect::<Vec<_>>();
                if addresses.is_empty() {
                    Err(DriadError::NoUsableRelay)
                } else {
                    Ok(addresses)
                }
            }
        }
    }

    fn lookup_host(&self, name: &str) -> Result<Vec<Timed<IpAddr>>, DriadError> {
        let mut addresses = Vec::new();
        for query_type in [DNS_TYPE_A, DNS_TYPE_AAAA] {
            if let Ok(found) = self.lookup_host_type(name, query_type) {
                for address in found {
                    if !addresses
                        .iter()
                        .any(|existing: &Timed<IpAddr>| existing.value == address.value)
                    {
                        addresses.push(address);
                    }
                }
            }
        }
        if addresses.is_empty() {
            Err(DriadError::NoUsableRelay)
        } else {
            Ok(addresses)
        }
    }

    fn lookup_host_type(
        &self,
        name: &str,
        query_type: u16,
    ) -> Result<Vec<Timed<IpAddr>>, DriadError> {
        let mut current = name.to_string();
        let mut visited = HashSet::new();
        let mut alias_ttl = Duration::MAX;
        for _ in 0..MAX_ALIAS_DEPTH {
            if !visited.insert(current.to_ascii_lowercase()) {
                return Err(DriadError::AliasLoop(current));
            }
            let mut last_error = DriadError::NoRecords(current.clone());
            let mut alias = None;
            'queries: for attempt in 0..self.config.attempts.max(1) {
                let timeout = self.retry_timeout(attempt);
                for resolver in &self.config.resolvers {
                    match self
                        .query_wire(*resolver, &current, query_type, timeout)
                        .and_then(|(id, response)| {
                            parse_address_response(id, &current, query_type, &response)
                        }) {
                        Ok(response) if !response.addresses.is_empty() => {
                            return Ok(response
                                .addresses
                                .into_iter()
                                .map(|address| Timed {
                                    value: address.value,
                                    ttl: address.ttl.min(alias_ttl),
                                })
                                .collect());
                        }
                        Ok(DnsAddressResponse {
                            alias: Some(next_alias),
                            ..
                        }) => {
                            alias = Some(next_alias);
                            break 'queries;
                        }
                        Ok(DnsAddressResponse { alias: None, .. }) => {}
                        Err(error) => last_error = error,
                    }
                }
            }
            if let Some(alias) = alias {
                alias_ttl = alias_ttl.min(alias.ttl);
                current = alias.value;
            } else {
                return Err(last_error);
            }
        }
        Err(DriadError::AliasDepthExceeded(name.to_string()))
    }
}

impl PartialEq for DriadResolver {
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl Eq for DriadResolver {}

#[derive(Debug)]
struct DnsQueryLimiter {
    maximum: usize,
    window: Duration,
    queries: VecDeque<Instant>,
}

impl DnsQueryLimiter {
    fn new(maximum: usize, window: Duration) -> Self {
        Self {
            maximum,
            window,
            queries: VecDeque::with_capacity(maximum),
        }
    }

    fn reserve_at(&mut self, now: Instant) -> Option<Duration> {
        while self
            .queries
            .front()
            .is_some_and(|query| now.saturating_duration_since(*query) >= self.window)
        {
            self.queries.pop_front();
        }
        if self.queries.len() < self.maximum {
            self.queries.push_back(now);
            return None;
        }
        self.queries.front().map(|query| {
            self.window
                .saturating_sub(now.saturating_duration_since(*query))
        })
    }
}

fn order_relay_candidates(selections: &mut [DriadRelaySelection]) {
    selections.sort_by_key(|selection| selection.record.precedence);
    let mut start = 0;
    while start < selections.len() {
        let precedence = selections[start].record.precedence;
        let end = selections[start..]
            .iter()
            .position(|selection| selection.record.precedence != precedence)
            .map_or(selections.len(), |offset| start + offset);
        shuffle_and_interleave_families(&mut selections[start..end]);
        start = end;
    }
}

fn shuffle_and_interleave_families(selections: &mut [DriadRelaySelection]) {
    if selections.len() < 2 {
        return;
    }
    let mut random = random_u64_best_effort();
    for index in (1..selections.len()).rev() {
        random = xorshift64(random);
        selections.swap(index, random as usize % (index + 1));
    }

    let prefer_ipv6 = selections[0].relay.is_ipv6();
    let mut ipv4 = selections
        .iter()
        .filter(|selection| selection.relay.is_ipv4())
        .cloned()
        .collect::<VecDeque<_>>();
    let mut ipv6 = selections
        .iter()
        .filter(|selection| selection.relay.is_ipv6())
        .cloned()
        .collect::<VecDeque<_>>();
    for (index, selection) in selections.iter_mut().enumerate() {
        let take_ipv6 = (index % 2 == 0) == prefer_ipv6;
        *selection = if take_ipv6 {
            ipv6.pop_front().or_else(|| ipv4.pop_front())
        } else {
            ipv4.pop_front().or_else(|| ipv6.pop_front())
        }
        .expect("one ordered DRIAD candidate remains");
    }
}

fn random_u64_best_effort() -> u64 {
    let mut bytes = [0u8; 8];
    if fill_random(&mut bytes).is_ok() {
        u64::from_ne_bytes(bytes)
    } else {
        0x9e37_79b9_7f4a_7c15
    }
}

const fn xorshift64(mut value: u64) -> u64 {
    if value == 0 {
        value = 0x2545_f491_4f6c_dd1d;
    }
    value ^= value << 13;
    value ^= value >> 7;
    value ^ (value << 17)
}

fn is_usable_relay_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_unicast_link_local()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsAmtRelayResponse {
    records: Vec<Timed<AmtRelayRecord>>,
    aliases: Vec<Timed<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsAddressResponse {
    addresses: Vec<Timed<IpAddr>>,
    alias: Option<Timed<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Timed<T> {
    value: T,
    ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriadError {
    NoResolvers,
    InsecureResolver(SocketAddr),
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
    InvalidDnsFlags(u16),
    InvalidQuestion,
    InvalidRelayType(u8),
    InvalidRelayLength {
        relay_type: u8,
        expected: usize,
        actual: usize,
    },
    InvalidRelayName,
    InvalidConfig(&'static str),
    Randomness(String),
    Io(String),
}

impl fmt::Display for DriadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoResolvers => write!(f, "no DRIAD DNS resolvers are configured"),
            Self::InsecureResolver(resolver) => write!(
                f,
                "DRIAD resolver {resolver} is not on loopback; use a validating local resolver or explicitly allow insecure DNS"
            ),
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
            Self::InvalidDnsFlags(flags) => write!(f, "invalid DNS response flags {flags:#x}"),
            Self::InvalidQuestion => f.write_str("DNS response question does not match query"),
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
            Self::InvalidConfig(error) => write!(f, "invalid DRIAD configuration: {error}"),
            Self::Randomness(error) => write!(f, "failed to generate DNS query ID: {error}"),
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
            let (name, consumed) = parse_uncompressed_dns_name(relay)?;
            if consumed != relay.len() || name.is_empty() {
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

fn parse_uncompressed_dns_name(input: &[u8]) -> Result<(String, usize), DriadError> {
    let mut labels = Vec::new();
    let mut cursor = 0;
    for _ in 0..128 {
        let len = *input
            .get(cursor)
            .ok_or(DriadError::Truncated("AMTRELAY domain name"))?;
        if len & 0xc0 != 0 {
            return Err(DriadError::InvalidRelayName);
        }
        cursor += 1;
        if len == 0 {
            if cursor > 255 {
                return Err(DriadError::InvalidRelayName);
            }
            return Ok((labels.join("."), cursor));
        }
        let label_end = cursor
            .checked_add(usize::from(len))
            .ok_or(DriadError::InvalidRelayName)?;
        let label = input
            .get(cursor..label_end)
            .ok_or(DriadError::Truncated("AMTRELAY domain label"))?;
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| DriadError::InvalidRelayName)?
                .to_string(),
        );
        cursor = label_end;
        if cursor >= 255 {
            return Err(DriadError::InvalidRelayName);
        }
    }
    Err(DriadError::InvalidRelayName)
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
    let (ancount, mut offset) =
        validate_dns_response(expected_id, query_name, AMTRELAY_RRTYPE, response)?;

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
        let ttl = Duration::from_secs(u64::from(read_u32(response, offset + 4)?));
        let rdlen = read_u16(response, offset + 8)? as usize;
        offset += 10;
        let rdata_end = offset
            .checked_add(rdlen)
            .ok_or(DriadError::Truncated("answer RDATA"))?;
        if rdata_end > response.len() {
            return Err(DriadError::Truncated("answer RDATA"));
        }

        if class == DNS_CLASS_IN && rrtype == AMTRELAY_RRTYPE && dns_name_eq(&owner, query_name) {
            if let Ok(record) = parse_amtrelay_rdata(&response[offset..rdata_end]) {
                records.push(Timed { value: record, ttl });
            }
        } else if class == DNS_CLASS_IN
            && rrtype == DNS_TYPE_CNAME
            && dns_name_eq(&owner, query_name)
        {
            let (alias, consumed) = parse_dns_name(response, offset)?;
            if consumed == rdata_end {
                aliases.push(Timed { value: alias, ttl });
            }
        } else if class == DNS_CLASS_IN && rrtype == DNS_TYPE_DNAME {
            let (target, consumed) = parse_dns_name(response, offset)?;
            if consumed == rdata_end
                && let Some(alias) = apply_dname(query_name, &owner, &target)
            {
                aliases.push(Timed { value: alias, ttl });
            }
        }

        offset = rdata_end;
    }

    Ok(DnsAmtRelayResponse { records, aliases })
}

fn parse_address_response(
    expected_id: u16,
    query_name: &str,
    query_type: u16,
    response: &[u8],
) -> Result<DnsAddressResponse, DriadError> {
    let (ancount, mut offset) =
        validate_dns_response(expected_id, query_name, query_type, response)?;
    let mut addresses = Vec::new();
    let mut alias = None;
    for _ in 0..ancount {
        let (owner, next) = parse_dns_name(response, offset)?;
        offset = next;
        if offset + 10 > response.len() {
            return Err(DriadError::Truncated("address answer"));
        }
        let rrtype = read_u16(response, offset)?;
        let class = read_u16(response, offset + 2)?;
        let ttl = Duration::from_secs(u64::from(read_u32(response, offset + 4)?));
        let rdlen = read_u16(response, offset + 8)? as usize;
        offset += 10;
        let rdata_end = offset
            .checked_add(rdlen)
            .ok_or(DriadError::Truncated("address answer RDATA"))?;
        if rdata_end > response.len() {
            return Err(DriadError::Truncated("address answer RDATA"));
        }

        if class == DNS_CLASS_IN && dns_name_eq(&owner, query_name) {
            match (rrtype, rdlen) {
                (DNS_TYPE_A, 4) if query_type == DNS_TYPE_A => addresses.push(Timed {
                    value: IpAddr::V4(Ipv4Addr::new(
                        response[offset],
                        response[offset + 1],
                        response[offset + 2],
                        response[offset + 3],
                    )),
                    ttl,
                }),
                (DNS_TYPE_AAAA, 16) if query_type == DNS_TYPE_AAAA => {
                    let mut octets = [0; 16];
                    octets.copy_from_slice(&response[offset..rdata_end]);
                    addresses.push(Timed {
                        value: IpAddr::V6(Ipv6Addr::from(octets)),
                        ttl,
                    });
                }
                (DNS_TYPE_CNAME, _) => {
                    let (name, consumed) = parse_dns_name(response, offset)?;
                    if consumed == rdata_end {
                        alias = Some(Timed { value: name, ttl });
                    }
                }
                _ => {}
            }
        }
        offset = rdata_end;
    }
    Ok(DnsAddressResponse { addresses, alias })
}

fn validate_dns_response(
    expected_id: u16,
    query_name: &str,
    query_type: u16,
    response: &[u8],
) -> Result<(usize, usize), DriadError> {
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
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0 || flags & 0x0040 != 0 {
        return Err(DriadError::InvalidDnsFlags(flags));
    }
    let rcode = (flags & 0x000f) as u8;
    if rcode != 0 {
        return Err(DriadError::DnsResponseCode(rcode));
    }
    if read_u16(response, 4)? != 1 {
        return Err(DriadError::InvalidQuestion);
    }

    let (actual_name, next) = parse_dns_name(response, DNS_HEADER_LEN)?;
    if next + 4 > response.len()
        || !dns_name_eq(&actual_name, query_name)
        || read_u16(response, next)? != query_type
        || read_u16(response, next + 2)? != DNS_CLASS_IN
    {
        return Err(DriadError::InvalidQuestion);
    }
    Ok((read_u16(response, 6)? as usize, next + 4))
}

fn dns_name_eq(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
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

fn read_u32(input: &[u8], offset: usize) -> Result<u32, DriadError> {
    let bytes = input
        .get(offset..offset + 4)
        .ok_or(DriadError::Truncated("u32"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn random_dns_id() -> Result<u16, DriadError> {
    let mut bytes = [0; 2];
    fill_random(&mut bytes).map_err(|error| DriadError::Randomness(error.to_string()))?;
    Ok(u16::from_be_bytes(bytes))
}

fn randomized_duration(lower: Duration, upper: Duration) -> Duration {
    let lower_ms = lower.as_millis() as u64;
    let upper_ms = upper.as_millis() as u64;
    if lower_ms >= upper_ms {
        return lower;
    }
    let mut bytes = [0u8; 8];
    let random = if fill_random(&mut bytes).is_ok() {
        u64::from_ne_bytes(bytes)
    } else {
        upper_ms
    };
    Duration::from_millis(lower_ms + random % (upper_ms - lower_ms + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selection(precedence: u8, relay: SocketAddr) -> DriadRelaySelection {
        DriadRelaySelection {
            source: "192.0.2.1".parse().unwrap(),
            query_name: "1.2.0.192.in-addr.arpa".to_string(),
            record: AmtRelayRecord {
                precedence,
                discovery_optional: false,
                target: match relay.ip() {
                    IpAddr::V4(address) => AmtRelayTarget::Ipv4(address),
                    IpAddr::V6(address) => AmtRelayTarget::Ipv6(address),
                },
            },
            relay,
            ttl: Duration::from_secs(60),
        }
    }

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
    fn candidate_order_preserves_precedence_and_interleaves_families() {
        let mut candidates = vec![
            selection(20, "[2001:db8::2]:2268".parse().unwrap()),
            selection(10, "192.0.2.1:2268".parse().unwrap()),
            selection(10, "[2001:db8::1]:2268".parse().unwrap()),
            selection(10, "192.0.2.2:2268".parse().unwrap()),
            selection(10, "[2001:db8::3]:2268".parse().unwrap()),
        ];

        order_relay_candidates(&mut candidates);

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.record.precedence)
                .collect::<Vec<_>>(),
            vec![10, 10, 10, 10, 20]
        );
        assert!(
            candidates[..4]
                .windows(2)
                .all(|pair| { pair[0].relay.is_ipv4() != pair[1].relay.is_ipv4() })
        );
    }

    #[test]
    fn dns_query_limiter_bounds_each_window() {
        let start = Instant::now();
        let mut limiter = DnsQueryLimiter::new(2, Duration::from_millis(100));

        assert_eq!(limiter.reserve_at(start), None);
        assert_eq!(limiter.reserve_at(start), None);
        assert_eq!(limiter.reserve_at(start), Some(Duration::from_millis(100)));
        assert_eq!(
            limiter.reserve_at(start + Duration::from_millis(99)),
            Some(Duration::from_millis(1))
        );
        assert_eq!(limiter.reserve_at(start + Duration::from_millis(100)), None);
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
        assert_eq!(
            parse_amtrelay_rdata(&[10, 3, 0xc0, 0x00]),
            Err(DriadError::InvalidRelayName)
        );
    }

    #[test]
    fn resolver_configuration_rejects_zero_limits() {
        let mut config = DriadResolverConfig::new(vec!["127.0.0.1:53".parse().unwrap()]);
        config.max_candidates = 0;
        assert!(matches!(
            DriadResolver::new(config).validate(),
            Err(DriadError::InvalidConfig(_))
        ));
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
            vec![Timed {
                value: AmtRelayRecord {
                    precedence: 10,
                    discovery_optional: false,
                    target: AmtRelayTarget::Ipv4(Ipv4Addr::new(203, 0, 113, 15)),
                },
                ttl: Duration::from_secs(60),
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

        assert_eq!(
            parsed.aliases,
            vec![Timed {
                value: "relay.example.com".to_string(),
                ttl: Duration::from_secs(60),
            }]
        );
    }

    #[test]
    fn parses_address_ttl_for_named_relay() {
        let name = "relay.example.com";
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        put_dns_name(&mut response, name).unwrap();
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&30u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[203, 0, 113, 15]);

        let parsed = parse_address_response(0x1234, name, DNS_TYPE_A, &response).unwrap();

        assert_eq!(
            parsed.addresses,
            vec![Timed {
                value: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 15)),
                ttl: Duration::from_secs(30),
            }]
        );
        assert_eq!(parsed.alias, None);
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

    #[test]
    fn rejects_untrusted_remote_resolver_by_default() {
        let resolver = SocketAddr::from(([192, 0, 2, 53], 53));
        let driad = DriadResolver::new(DriadResolverConfig::new(vec![resolver]));

        assert_eq!(
            driad.resolve_source(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12))),
            Err(DriadError::InsecureResolver(resolver))
        );
    }

    #[test]
    fn resolver_returns_effective_amtrelay_ttl() {
        let dns = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let resolver_addr = dns.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut query = [0u8; 512];
            let (len, peer) = dns.recv_from(&mut query).unwrap();
            let query = &query[..len];
            let (_, question_end) = parse_dns_name(query, DNS_HEADER_LEN).unwrap();
            let question_end = question_end + 4;

            let mut response = Vec::new();
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&query[DNS_HEADER_LEN..question_end]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&AMTRELAY_RRTYPE.to_be_bytes());
            response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
            response.extend_from_slice(&2u32.to_be_bytes());
            response.extend_from_slice(&6u16.to_be_bytes());
            response.extend_from_slice(&[10, 1, 203, 0, 113, 15]);
            dns.send_to(&response, peer).unwrap();
        });
        let mut config = DriadResolverConfig::new(vec![resolver_addr]);
        config.timeout = Duration::from_secs(1);
        config.attempts = 1;
        let resolver = DriadResolver::new(config);

        let selection = resolver
            .resolve_source(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)))
            .unwrap();

        responder.join().unwrap();
        assert_eq!(
            selection.relay,
            SocketAddr::from(([203, 0, 113, 15], AMT_PORT))
        );
        assert_eq!(selection.ttl, Duration::from_secs(2));
    }

    #[test]
    fn resolver_retries_truncated_udp_answer_over_tcp() {
        let tcp = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let resolver_addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(resolver_addr).unwrap();
        let responder = std::thread::spawn(move || {
            let mut udp_query = [0u8; 512];
            let (len, peer) = udp.recv_from(&mut udp_query).unwrap();
            let query = &udp_query[..len];
            let mut truncated = [0u8; DNS_HEADER_LEN];
            truncated[..2].copy_from_slice(&query[..2]);
            truncated[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
            truncated[4..6].copy_from_slice(&1u16.to_be_bytes());
            udp.send_to(&truncated, peer).unwrap();

            let (mut stream, _) = tcp.accept().unwrap();
            let mut length = [0u8; 2];
            stream.read_exact(&mut length).unwrap();
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut query).unwrap();
            let (_, question_end) = parse_dns_name(&query, DNS_HEADER_LEN).unwrap();
            let question_end = question_end + 4;

            let mut response = Vec::new();
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&query[DNS_HEADER_LEN..question_end]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&AMTRELAY_RRTYPE.to_be_bytes());
            response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
            response.extend_from_slice(&5u32.to_be_bytes());
            response.extend_from_slice(&6u16.to_be_bytes());
            response.extend_from_slice(&[10, 1, 203, 0, 113, 16]);
            stream
                .write_all(&(response.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let mut config = DriadResolverConfig::new(vec![resolver_addr]);
        config.timeout = Duration::from_secs(1);
        config.attempts = 1;
        let resolver = DriadResolver::new(config);

        let selection = resolver
            .resolve_source(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)))
            .unwrap();

        responder.join().unwrap();
        assert_eq!(
            selection.relay,
            SocketAddr::from(([203, 0, 113, 16], AMT_PORT))
        );
        assert_eq!(selection.ttl, Duration::from_secs(5));
    }

    #[test]
    fn rejects_dns_response_with_mismatched_question() {
        let expected_name = "12.100.51.198.in-addr.arpa";
        let mut response = Vec::new();
        response.extend_from_slice(&0x1234u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        put_dns_name(&mut response, "13.100.51.198.in-addr.arpa").unwrap();
        response.extend_from_slice(&AMTRELAY_RRTYPE.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(
            parse_dns_response(0x1234, expected_name, &response),
            Err(DriadError::InvalidQuestion)
        );
    }
}
