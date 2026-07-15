use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub relay: Option<RelayFileConfig>,
    pub gateway: Option<GatewayFileConfig>,
    pub metrics: Option<MetricsFileConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayFileConfig {
    pub bind: Option<SocketAddr>,
    pub ecn: Option<bool>,
    #[serde(default, alias = "advertise", alias = "relay_addresses")]
    pub relay_address: Option<OneOrMany<IpAddr>>,
    pub upstream_interface: Option<IpAddr>,
    #[serde(alias = "upstream_ifindex")]
    pub upstream_interface_index: Option<u32>,
    pub gateway_idle_timeout_secs: Option<u64>,
    pub gateway_prune_interval_secs: Option<u64>,
    pub secret_rotation_secs: Option<u64>,
    pub path_mtu: Option<usize>,
    pub pmtu_feedback: Option<bool>,
    pub limits: Option<RelayLimitsFileConfig>,
    pub rate_limit: Option<RateLimitFileConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayLimitsFileConfig {
    pub max_endpoints: Option<usize>,
    pub max_endpoints_per_ip: Option<usize>,
    pub max_groups_per_endpoint: Option<usize>,
    pub max_sources_per_group: Option<usize>,
    pub max_total_endpoint_groups: Option<usize>,
    pub max_total_sources: Option<usize>,
    pub max_upstream_subscriptions: Option<usize>,
    pub max_records_per_report: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitFileConfig {
    pub per_source_per_second: Option<u32>,
    pub per_source_burst: Option<u32>,
    pub global_per_second: Option<u32>,
    pub global_burst: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GatewayFileConfig {
    pub bind: Option<SocketAddr>,
    pub ecn: Option<bool>,
    pub relay: Option<SocketAddr>,
    pub relay_discovery: Option<String>,
    pub protocol: Option<String>,
    pub group: Option<IpAddr>,
    pub source: Option<IpAddr>,
    pub transparent: Option<bool>,
    pub no_downstream: Option<bool>,
    pub downstream: Option<DownstreamFileConfig>,
    pub local_membership: Option<LocalMembershipFileConfig>,
    pub local_query_interval_secs: Option<u64>,
    pub membership_refresh_interval_secs: Option<u64>,
    pub driad: Option<DriadFileConfig>,
    #[serde(default, alias = "join")]
    pub joins: Vec<GatewayJoinFileConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DriadFileConfig {
    #[serde(default, alias = "nameserver", alias = "resolver")]
    pub resolvers: Option<OneOrMany<String>>,
    pub timeout_ms: Option<u64>,
    pub attempts: Option<usize>,
    pub allow_insecure_dns: Option<bool>,
    pub max_candidates: Option<usize>,
    pub max_queries_per_window: Option<usize>,
    pub query_rate_window_ms: Option<u64>,
    pub happy_eyeballs_delay_ms: Option<u64>,
    pub relay_hold_down_secs: Option<u64>,
    pub traffic_hold_down_secs: Option<u64>,
    pub initial_traffic_timeout_secs: Option<u64>,
    pub maximum_traffic_timeout_secs: Option<u64>,
    pub max_source_tunnels: Option<usize>,
    pub max_concurrent_probes: Option<usize>,
    pub max_dns_workers: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayJoinFileConfig {
    pub group: IpAddr,
    pub source: Option<IpAddr>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DownstreamFileConfig {
    pub interface: Option<IpAddr>,
    #[serde(alias = "ifindex")]
    pub interface_index: Option<u32>,
    pub ttl: Option<u8>,
    pub loopback: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalMembershipFileConfig {
    pub interface: Option<IpAddr>,
    #[serde(alias = "ifindex")]
    pub interface_index: Option<u32>,
    pub query_interval_secs: Option<u64>,
    pub reporter_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetricsFileConfig {
    #[serde(alias = "metrics_dir")]
    pub output_dir: Option<PathBuf>,
    pub node_id: Option<String>,
    #[serde(alias = "sample_interval_ms")]
    pub interval_ms: Option<u64>,
    pub max_file_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

pub fn load_file_config(path: impl AsRef<Path>) -> Result<FileConfig, String> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("failed to read config {}: {error}", path.display()))?;
    toml::from_str(&contents)
        .map_err(|error| format!("failed to parse config {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_relay_config_with_one_or_many_addresses() {
        let config: FileConfig = toml::from_str(
            r#"
            [relay]
            bind = "0.0.0.0:2268"
            ecn = true
            relay_addresses = ["203.0.113.10", "2001:db8::10"]
            upstream_interface = "192.0.2.10"
            upstream_ifindex = 7
            gateway_idle_timeout_secs = 120
            path_mtu = 1500
            pmtu_feedback = true

            [relay.limits]
            max_endpoints = 100
            max_endpoints_per_ip = 25

            [relay.rate_limit]
            per_source_per_second = 5

            [metrics]
            output_dir = "/tmp/heimdall"
            node_id = "amt-relay-a"
            interval_ms = 500
            "#,
        )
        .unwrap();

        let relay = config.relay.unwrap();
        assert_eq!(relay.bind.unwrap(), "0.0.0.0:2268".parse().unwrap());
        assert_eq!(relay.ecn, Some(true));
        assert_eq!(relay.relay_address.unwrap().into_vec().len(), 2);
        assert_eq!(relay.upstream_interface_index, Some(7));
        assert_eq!(relay.path_mtu, Some(1500));
        assert_eq!(relay.pmtu_feedback, Some(true));
        let limits = relay.limits.unwrap();
        assert_eq!(limits.max_endpoints, Some(100));
        assert_eq!(limits.max_endpoints_per_ip, Some(25));
        assert_eq!(relay.rate_limit.unwrap().per_source_per_second, Some(5));
        assert_eq!(config.metrics.unwrap().interval_ms, Some(500));
    }

    #[test]
    fn parses_gateway_config_with_nested_sections() {
        let config: FileConfig = toml::from_str(
            r#"
            [gateway]
            relay = "203.0.113.10:2268"
            ecn = true
            relay_discovery = "static"
            protocol = "igmpv3"
            transparent = true
            membership_refresh_interval_secs = 30

            [gateway.driad]
            resolver = ["192.0.2.53:53"]
            timeout_ms = 500
            attempts = 2
            max_candidates = 32
            max_queries_per_window = 8
            query_rate_window_ms = 100
            happy_eyeballs_delay_ms = 200
            relay_hold_down_secs = 600
            traffic_hold_down_secs = 300
            initial_traffic_timeout_secs = 4
            maximum_traffic_timeout_secs = 120
            max_source_tunnels = 128
            max_concurrent_probes = 3
            max_dns_workers = 6

            [gateway.downstream]
            interface = "192.168.1.20"
            ttl = 16

            [gateway.local_membership]
            ifindex = 4
            query_interval_secs = 15

            [[gateway.joins]]
            group = "239.1.2.3"
            source = "192.0.2.10"
            "#,
        )
        .unwrap();

        let gateway = config.gateway.unwrap();
        assert_eq!(gateway.relay.unwrap(), "203.0.113.10:2268".parse().unwrap());
        assert_eq!(gateway.ecn, Some(true));
        assert_eq!(gateway.relay_discovery.as_deref(), Some("static"));
        let driad = gateway.driad.unwrap();
        assert_eq!(driad.attempts, Some(2));
        assert_eq!(driad.max_source_tunnels, Some(128));
        assert_eq!(driad.max_concurrent_probes, Some(3));
        assert_eq!(driad.max_dns_workers, Some(6));
        assert_eq!(gateway.joins.len(), 1);
        assert_eq!(gateway.downstream.unwrap().ttl, Some(16));
        assert_eq!(gateway.local_membership.unwrap().interface_index, Some(4));
    }
}
