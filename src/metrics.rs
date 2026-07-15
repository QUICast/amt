#[cfg(feature = "metrics")]
use mcrx_core::jsonl::{
    append_jsonl_sample_row, ensure_single_header, header_json, unix_timestamp_secs,
};
#[cfg(feature = "metrics")]
use serde_json::{Map, Value};
use std::io;
use std::path::PathBuf;
use std::time::Duration;
#[cfg(feature = "metrics")]
use std::time::{Instant, SystemTime};

pub const AMT_RELAY_ARTIFACT_TYPE: &str = "amt-relay";
pub const AMT_GATEWAY_ARTIFACT_TYPE: &str = "amt-gateway";
pub const AMT_METRICS_PRODUCER: &str = "amt";

#[cfg(feature = "metrics")]
pub type MetricsFlags = Map<String, Value>;

#[cfg(not(feature = "metrics"))]
pub type MetricsFlags = ();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfig {
    pub output_dir: Option<PathBuf>,
    pub node_id: String,
    pub sample_interval: Duration,
    pub max_file_bytes: Option<u64>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            output_dir: None,
            node_id: "amt".to_string(),
            sample_interval: Duration::from_secs(1),
            max_file_bytes: Some(64 * 1024 * 1024),
        }
    }
}

impl MetricsConfig {
    pub fn requested(&self) -> bool {
        self.output_dir.is_some() && !self.sample_interval.is_zero()
    }

    pub fn is_enabled(&self) -> bool {
        cfg!(feature = "metrics") && self.requested()
    }

    #[cfg(feature = "metrics")]
    fn validate(&self) -> io::Result<()> {
        if self.node_id.is_empty()
            || self.node_id == "."
            || self.node_id == ".."
            || self.node_id.contains(['/', '\\', '\0'])
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "metrics node_id must be a non-empty path component",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AmtMetricsCounters {
    pub control_datagrams_received_total: u64,
    pub control_datagrams_invalid_total: u64,
    pub control_datagrams_ignored_total: u64,
    pub control_datagrams_rate_limited_total: u64,
    pub resource_limit_rejections_total: u64,
    pub control_responses_sent_total: u64,
    pub control_response_bytes_sent_total: u64,
    pub send_errors_total: u64,
    pub membership_updates_accepted_total: u64,
    pub membership_records_applied_total: u64,
    pub teardowns_accepted_total: u64,
    pub auth_rejections_total: u64,
    pub gateways_expired_total: u64,
    pub upstream_subscription_adds_total: u64,
    pub upstream_subscription_removes_total: u64,
    pub upstream_reconcile_failures_total: u64,
    pub upstream_packets_received_total: u64,
    pub upstream_bytes_received_total: u64,
    pub upstream_packets_forwarded_total: u64,
    pub upstream_bytes_forwarded_total: u64,
    pub upstream_unmatched_packets_total: u64,
    pub upstream_forward_errors_total: u64,
    pub upstream_mtu_drops_total: u64,
    pub upstream_fragments_sent_total: u64,
    pub upstream_pmtu_feedback_sent_total: u64,
    pub upstream_pmtu_feedback_bytes_sent_total: u64,
    pub upstream_pmtu_feedback_rate_limited_total: u64,
    pub upstream_pmtu_feedback_suppressed_total: u64,
    pub upstream_pmtu_feedback_unavailable_total: u64,
    pub upstream_pmtu_feedback_errors_total: u64,
    pub relay_ecn_normal_mode_datagrams_sent_total: u64,
    pub gateway_discoveries_sent_total: u64,
    pub gateway_membership_queries_received_total: u64,
    pub gateway_membership_updates_sent_total: u64,
    pub gateway_membership_refreshes_total: u64,
    pub gateway_teardowns_sent_total: u64,
    pub driad_refreshes_started_total: u64,
    pub driad_refreshes_succeeded_total: u64,
    pub driad_refreshes_failed_total: u64,
    pub driad_candidate_changes_total: u64,
    pub driad_no_relay_withdrawals_total: u64,
    pub driad_probes_started_total: u64,
    pub driad_probe_timeouts_total: u64,
    pub driad_probe_errors_total: u64,
    pub driad_connections_established_total: u64,
    pub driad_loaded_hold_downs_total: u64,
    pub driad_no_traffic_hold_downs_total: u64,
    pub driad_query_timeouts_total: u64,
    pub multicast_data_received_total: u64,
    pub multicast_data_bytes_received_total: u64,
    pub gateway_ecn_ce_received_total: u64,
    pub gateway_ecn_ce_propagated_total: u64,
    pub gateway_ecn_currently_unused_total: u64,
    pub gateway_ecn_invalid_drops_total: u64,
    pub downstream_packets_forwarded_total: u64,
    pub downstream_bytes_forwarded_total: u64,
    pub downstream_non_multicast_packets_total: u64,
    pub downstream_forward_errors_total: u64,
    pub local_queries_sent_total: u64,
    pub local_membership_reports_total: u64,
    pub local_membership_parse_errors_total: u64,
}

impl AmtMetricsCounters {
    #[cfg(feature = "metrics")]
    fn delta_since(&self, earlier: &Self) -> Self {
        Self {
            control_datagrams_received_total: self
                .control_datagrams_received_total
                .saturating_sub(earlier.control_datagrams_received_total),
            control_datagrams_invalid_total: self
                .control_datagrams_invalid_total
                .saturating_sub(earlier.control_datagrams_invalid_total),
            control_datagrams_ignored_total: self
                .control_datagrams_ignored_total
                .saturating_sub(earlier.control_datagrams_ignored_total),
            control_datagrams_rate_limited_total: self
                .control_datagrams_rate_limited_total
                .saturating_sub(earlier.control_datagrams_rate_limited_total),
            resource_limit_rejections_total: self
                .resource_limit_rejections_total
                .saturating_sub(earlier.resource_limit_rejections_total),
            control_responses_sent_total: self
                .control_responses_sent_total
                .saturating_sub(earlier.control_responses_sent_total),
            control_response_bytes_sent_total: self
                .control_response_bytes_sent_total
                .saturating_sub(earlier.control_response_bytes_sent_total),
            send_errors_total: self
                .send_errors_total
                .saturating_sub(earlier.send_errors_total),
            membership_updates_accepted_total: self
                .membership_updates_accepted_total
                .saturating_sub(earlier.membership_updates_accepted_total),
            membership_records_applied_total: self
                .membership_records_applied_total
                .saturating_sub(earlier.membership_records_applied_total),
            teardowns_accepted_total: self
                .teardowns_accepted_total
                .saturating_sub(earlier.teardowns_accepted_total),
            auth_rejections_total: self
                .auth_rejections_total
                .saturating_sub(earlier.auth_rejections_total),
            gateways_expired_total: self
                .gateways_expired_total
                .saturating_sub(earlier.gateways_expired_total),
            upstream_subscription_adds_total: self
                .upstream_subscription_adds_total
                .saturating_sub(earlier.upstream_subscription_adds_total),
            upstream_subscription_removes_total: self
                .upstream_subscription_removes_total
                .saturating_sub(earlier.upstream_subscription_removes_total),
            upstream_reconcile_failures_total: self
                .upstream_reconcile_failures_total
                .saturating_sub(earlier.upstream_reconcile_failures_total),
            upstream_packets_received_total: self
                .upstream_packets_received_total
                .saturating_sub(earlier.upstream_packets_received_total),
            upstream_bytes_received_total: self
                .upstream_bytes_received_total
                .saturating_sub(earlier.upstream_bytes_received_total),
            upstream_packets_forwarded_total: self
                .upstream_packets_forwarded_total
                .saturating_sub(earlier.upstream_packets_forwarded_total),
            upstream_bytes_forwarded_total: self
                .upstream_bytes_forwarded_total
                .saturating_sub(earlier.upstream_bytes_forwarded_total),
            upstream_unmatched_packets_total: self
                .upstream_unmatched_packets_total
                .saturating_sub(earlier.upstream_unmatched_packets_total),
            upstream_forward_errors_total: self
                .upstream_forward_errors_total
                .saturating_sub(earlier.upstream_forward_errors_total),
            upstream_mtu_drops_total: self
                .upstream_mtu_drops_total
                .saturating_sub(earlier.upstream_mtu_drops_total),
            upstream_fragments_sent_total: self
                .upstream_fragments_sent_total
                .saturating_sub(earlier.upstream_fragments_sent_total),
            upstream_pmtu_feedback_sent_total: self
                .upstream_pmtu_feedback_sent_total
                .saturating_sub(earlier.upstream_pmtu_feedback_sent_total),
            upstream_pmtu_feedback_bytes_sent_total: self
                .upstream_pmtu_feedback_bytes_sent_total
                .saturating_sub(earlier.upstream_pmtu_feedback_bytes_sent_total),
            upstream_pmtu_feedback_rate_limited_total: self
                .upstream_pmtu_feedback_rate_limited_total
                .saturating_sub(earlier.upstream_pmtu_feedback_rate_limited_total),
            upstream_pmtu_feedback_suppressed_total: self
                .upstream_pmtu_feedback_suppressed_total
                .saturating_sub(earlier.upstream_pmtu_feedback_suppressed_total),
            upstream_pmtu_feedback_unavailable_total: self
                .upstream_pmtu_feedback_unavailable_total
                .saturating_sub(earlier.upstream_pmtu_feedback_unavailable_total),
            upstream_pmtu_feedback_errors_total: self
                .upstream_pmtu_feedback_errors_total
                .saturating_sub(earlier.upstream_pmtu_feedback_errors_total),
            relay_ecn_normal_mode_datagrams_sent_total: self
                .relay_ecn_normal_mode_datagrams_sent_total
                .saturating_sub(earlier.relay_ecn_normal_mode_datagrams_sent_total),
            gateway_discoveries_sent_total: self
                .gateway_discoveries_sent_total
                .saturating_sub(earlier.gateway_discoveries_sent_total),
            gateway_membership_queries_received_total: self
                .gateway_membership_queries_received_total
                .saturating_sub(earlier.gateway_membership_queries_received_total),
            gateway_membership_updates_sent_total: self
                .gateway_membership_updates_sent_total
                .saturating_sub(earlier.gateway_membership_updates_sent_total),
            gateway_membership_refreshes_total: self
                .gateway_membership_refreshes_total
                .saturating_sub(earlier.gateway_membership_refreshes_total),
            gateway_teardowns_sent_total: self
                .gateway_teardowns_sent_total
                .saturating_sub(earlier.gateway_teardowns_sent_total),
            driad_refreshes_started_total: self
                .driad_refreshes_started_total
                .saturating_sub(earlier.driad_refreshes_started_total),
            driad_refreshes_succeeded_total: self
                .driad_refreshes_succeeded_total
                .saturating_sub(earlier.driad_refreshes_succeeded_total),
            driad_refreshes_failed_total: self
                .driad_refreshes_failed_total
                .saturating_sub(earlier.driad_refreshes_failed_total),
            driad_candidate_changes_total: self
                .driad_candidate_changes_total
                .saturating_sub(earlier.driad_candidate_changes_total),
            driad_no_relay_withdrawals_total: self
                .driad_no_relay_withdrawals_total
                .saturating_sub(earlier.driad_no_relay_withdrawals_total),
            driad_probes_started_total: self
                .driad_probes_started_total
                .saturating_sub(earlier.driad_probes_started_total),
            driad_probe_timeouts_total: self
                .driad_probe_timeouts_total
                .saturating_sub(earlier.driad_probe_timeouts_total),
            driad_probe_errors_total: self
                .driad_probe_errors_total
                .saturating_sub(earlier.driad_probe_errors_total),
            driad_connections_established_total: self
                .driad_connections_established_total
                .saturating_sub(earlier.driad_connections_established_total),
            driad_loaded_hold_downs_total: self
                .driad_loaded_hold_downs_total
                .saturating_sub(earlier.driad_loaded_hold_downs_total),
            driad_no_traffic_hold_downs_total: self
                .driad_no_traffic_hold_downs_total
                .saturating_sub(earlier.driad_no_traffic_hold_downs_total),
            driad_query_timeouts_total: self
                .driad_query_timeouts_total
                .saturating_sub(earlier.driad_query_timeouts_total),
            multicast_data_received_total: self
                .multicast_data_received_total
                .saturating_sub(earlier.multicast_data_received_total),
            multicast_data_bytes_received_total: self
                .multicast_data_bytes_received_total
                .saturating_sub(earlier.multicast_data_bytes_received_total),
            gateway_ecn_ce_received_total: self
                .gateway_ecn_ce_received_total
                .saturating_sub(earlier.gateway_ecn_ce_received_total),
            gateway_ecn_ce_propagated_total: self
                .gateway_ecn_ce_propagated_total
                .saturating_sub(earlier.gateway_ecn_ce_propagated_total),
            gateway_ecn_currently_unused_total: self
                .gateway_ecn_currently_unused_total
                .saturating_sub(earlier.gateway_ecn_currently_unused_total),
            gateway_ecn_invalid_drops_total: self
                .gateway_ecn_invalid_drops_total
                .saturating_sub(earlier.gateway_ecn_invalid_drops_total),
            downstream_packets_forwarded_total: self
                .downstream_packets_forwarded_total
                .saturating_sub(earlier.downstream_packets_forwarded_total),
            downstream_bytes_forwarded_total: self
                .downstream_bytes_forwarded_total
                .saturating_sub(earlier.downstream_bytes_forwarded_total),
            downstream_non_multicast_packets_total: self
                .downstream_non_multicast_packets_total
                .saturating_sub(earlier.downstream_non_multicast_packets_total),
            downstream_forward_errors_total: self
                .downstream_forward_errors_total
                .saturating_sub(earlier.downstream_forward_errors_total),
            local_queries_sent_total: self
                .local_queries_sent_total
                .saturating_sub(earlier.local_queries_sent_total),
            local_membership_reports_total: self
                .local_membership_reports_total
                .saturating_sub(earlier.local_membership_reports_total),
            local_membership_parse_errors_total: self
                .local_membership_parse_errors_total
                .saturating_sub(earlier.local_membership_parse_errors_total),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayMetricsGauges {
    pub active_gateways: u64,
    pub active_upstream_subscriptions: u64,
    pub upstream_capture_sockets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayMetricsGauges {
    pub relay_connected: bool,
    pub downstream_enabled: bool,
    pub transparent_enabled: bool,
    pub configured_joins: u64,
    pub driad_source_tunnels: u64,
    pub driad_active_tunnels: u64,
    pub driad_candidate_probes: u64,
    pub driad_held_down_relays: u64,
}

#[cfg(feature = "metrics")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetricsGauges {
    Relay(RelayMetricsGauges),
    Gateway(GatewayMetricsGauges),
}

#[cfg(feature = "metrics")]
#[derive(Debug, Clone, PartialEq)]
struct MetricsSnapshot {
    captured_at: SystemTime,
    counters: AmtMetricsCounters,
    gauges: MetricsGauges,
}

#[cfg(feature = "metrics")]
#[derive(Debug)]
struct MetricsWriter {
    path: PathBuf,
    header: Value,
    sample_interval: Duration,
    next_emit_at: Instant,
    previous: Option<MetricsSnapshot>,
    max_file_bytes: Option<u64>,
}

#[derive(Debug)]
pub struct MetricsRecorder {
    counters: AmtMetricsCounters,
    #[cfg(feature = "metrics")]
    writer: Option<MetricsWriter>,
}

impl MetricsRecorder {
    pub fn relay(config: &MetricsConfig, flags: MetricsFlags) -> io::Result<Self> {
        Self::new(config, AMT_RELAY_ARTIFACT_TYPE, "amt-relay.jsonl", flags)
    }

    pub fn gateway(config: &MetricsConfig, flags: MetricsFlags) -> io::Result<Self> {
        Self::new(
            config,
            AMT_GATEWAY_ARTIFACT_TYPE,
            "amt-gateway.jsonl",
            flags,
        )
    }

    #[cfg(feature = "metrics")]
    fn new(
        config: &MetricsConfig,
        artifact_type: &'static str,
        file_name: &str,
        flags: MetricsFlags,
    ) -> io::Result<Self> {
        config.validate()?;
        let writer = if config.is_enabled() {
            let Some(output_dir) = config.output_dir.as_ref() else {
                return Ok(Self {
                    counters: AmtMetricsCounters::default(),
                    writer: None,
                });
            };
            let path = output_dir.join(&config.node_id).join(file_name);
            let header = header_json(
                artifact_type,
                AMT_METRICS_PRODUCER,
                &config.node_id,
                SystemTime::now(),
                &flags,
            );
            match ensure_single_header(&path, &header) {
                Ok(()) => Some(MetricsWriter {
                    path,
                    header,
                    sample_interval: config.sample_interval,
                    next_emit_at: Instant::now() + config.sample_interval,
                    previous: None,
                    max_file_bytes: config.max_file_bytes,
                }),
                Err(error) => {
                    eprintln!("metrics disabled after output initialization failed: {error}");
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            counters: AmtMetricsCounters::default(),
            writer,
        })
    }

    #[cfg(not(feature = "metrics"))]
    fn new(
        _config: &MetricsConfig,
        _artifact_type: &'static str,
        _file_name: &str,
        _flags: MetricsFlags,
    ) -> io::Result<Self> {
        Ok(Self {
            counters: AmtMetricsCounters::default(),
        })
    }

    #[cfg(feature = "metrics")]
    pub fn path(&self) -> Option<&PathBuf> {
        self.writer.as_ref().map(|writer| &writer.path)
    }

    #[cfg(not(feature = "metrics"))]
    pub fn path(&self) -> Option<&PathBuf> {
        None
    }

    pub fn counters_mut(&mut self) -> &mut AmtMetricsCounters {
        &mut self.counters
    }

    pub fn counters(&self) -> &AmtMetricsCounters {
        &self.counters
    }

    #[cfg(feature = "metrics")]
    pub fn maybe_emit_relay(&mut self, gauges: RelayMetricsGauges) -> io::Result<bool> {
        self.maybe_emit(MetricsGauges::Relay(gauges))
    }

    #[cfg(not(feature = "metrics"))]
    pub fn maybe_emit_relay(&mut self, _gauges: RelayMetricsGauges) -> io::Result<bool> {
        Ok(false)
    }

    #[cfg(feature = "metrics")]
    pub fn maybe_emit_gateway(&mut self, gauges: GatewayMetricsGauges) -> io::Result<bool> {
        self.maybe_emit(MetricsGauges::Gateway(gauges))
    }

    #[cfg(not(feature = "metrics"))]
    pub fn maybe_emit_gateway(&mut self, _gauges: GatewayMetricsGauges) -> io::Result<bool> {
        Ok(false)
    }

    #[cfg(feature = "metrics")]
    fn maybe_emit(&mut self, gauges: MetricsGauges) -> io::Result<bool> {
        let Some(writer) = self.writer.as_mut() else {
            return Ok(false);
        };

        let now = Instant::now();
        if writer.previous.is_none() {
            writer.previous = Some(MetricsSnapshot {
                captured_at: SystemTime::now(),
                counters: self.counters.clone(),
                gauges,
            });
            writer.next_emit_at = now + writer.sample_interval;
            return Ok(false);
        }

        if now < writer.next_emit_at {
            return Ok(false);
        }

        let snapshot = MetricsSnapshot {
            captured_at: SystemTime::now(),
            counters: self.counters.clone(),
            gauges,
        };

        let Some(previous) = writer.previous.as_ref() else {
            return Ok(false);
        };
        let sample = metrics_sample_json(previous, &snapshot);
        let result = rotate_metrics_if_needed(writer)
            .and_then(|()| append_jsonl_sample_row(&writer.path, &writer.header, &sample));
        writer.previous = Some(snapshot);
        writer.next_emit_at = now + writer.sample_interval;

        match result {
            Ok(()) => Ok(true),
            Err(error) => {
                self.writer = None;
                Err(error)
            }
        }
    }
}

#[cfg(feature = "metrics")]
fn rotate_metrics_if_needed(writer: &MetricsWriter) -> io::Result<()> {
    let Some(max_file_bytes) = writer.max_file_bytes else {
        return Ok(());
    };
    if max_file_bytes == 0 {
        return Ok(());
    }
    let Ok(metadata) = std::fs::metadata(&writer.path) else {
        return Ok(());
    };
    if metadata.len() < max_file_bytes {
        return Ok(());
    }

    let rotated = writer.path.with_extension("jsonl.1");
    match std::fs::remove_file(&rotated) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::rename(&writer.path, rotated)?;
    ensure_single_header(&writer.path, &writer.header)
}

#[cfg(feature = "metrics")]
pub fn base_flags(role: &str, node_id: &str) -> MetricsFlags {
    let mut flags = Map::new();
    flags.insert("role".to_string(), role.into());
    flags.insert("node_id".to_string(), node_id.into());
    flags
}

#[cfg(not(feature = "metrics"))]
pub fn base_flags(_role: &str, _node_id: &str) -> MetricsFlags {}

#[cfg(feature = "metrics")]
fn metrics_sample_json(previous: &MetricsSnapshot, current: &MetricsSnapshot) -> Value {
    let interval_secs = current
        .captured_at
        .duration_since(previous.captured_at)
        .unwrap_or(Duration::from_secs(1))
        .as_secs_f64()
        .max(0.001);
    let delta = current.counters.delta_since(&previous.counters);
    let mut sample = Map::new();

    sample.insert(
        "ts".to_string(),
        unix_timestamp_secs(current.captured_at).into(),
    );
    sample.insert("interval_secs".to_string(), interval_secs.into());
    extend_gauges(&mut sample, current.gauges);
    extend_counters(&mut sample, &current.counters, &delta, interval_secs);

    Value::Object(sample)
}

#[cfg(feature = "metrics")]
fn extend_gauges(sample: &mut Map<String, Value>, gauges: MetricsGauges) {
    match gauges {
        MetricsGauges::Relay(gauges) => {
            sample.insert("active_gateways".to_string(), gauges.active_gateways.into());
            sample.insert(
                "active_upstream_subscriptions".to_string(),
                gauges.active_upstream_subscriptions.into(),
            );
            sample.insert(
                "upstream_capture_sockets".to_string(),
                gauges.upstream_capture_sockets.into(),
            );
        }
        MetricsGauges::Gateway(gauges) => {
            sample.insert(
                "relay_connected".to_string(),
                u8::from(gauges.relay_connected).into(),
            );
            sample.insert(
                "downstream_enabled".to_string(),
                u8::from(gauges.downstream_enabled).into(),
            );
            sample.insert(
                "transparent_enabled".to_string(),
                u8::from(gauges.transparent_enabled).into(),
            );
            sample.insert(
                "configured_joins".to_string(),
                gauges.configured_joins.into(),
            );
            sample.insert(
                "driad_source_tunnels".to_string(),
                gauges.driad_source_tunnels.into(),
            );
            sample.insert(
                "driad_active_tunnels".to_string(),
                gauges.driad_active_tunnels.into(),
            );
            sample.insert(
                "driad_candidate_probes".to_string(),
                gauges.driad_candidate_probes.into(),
            );
            sample.insert(
                "driad_held_down_relays".to_string(),
                gauges.driad_held_down_relays.into(),
            );
        }
    }
}

#[cfg(feature = "metrics")]
fn extend_counters(
    sample: &mut Map<String, Value>,
    total: &AmtMetricsCounters,
    delta: &AmtMetricsCounters,
    interval_secs: f64,
) {
    counter(
        sample,
        "control_datagrams_received",
        total.control_datagrams_received_total,
        delta.control_datagrams_received_total,
        interval_secs,
    );
    counter(
        sample,
        "control_datagrams_invalid",
        total.control_datagrams_invalid_total,
        delta.control_datagrams_invalid_total,
        interval_secs,
    );
    counter(
        sample,
        "control_datagrams_ignored",
        total.control_datagrams_ignored_total,
        delta.control_datagrams_ignored_total,
        interval_secs,
    );
    counter(
        sample,
        "control_datagrams_rate_limited",
        total.control_datagrams_rate_limited_total,
        delta.control_datagrams_rate_limited_total,
        interval_secs,
    );
    counter(
        sample,
        "resource_limit_rejections",
        total.resource_limit_rejections_total,
        delta.resource_limit_rejections_total,
        interval_secs,
    );
    counter(
        sample,
        "control_responses_sent",
        total.control_responses_sent_total,
        delta.control_responses_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "control_response_bytes_sent",
        total.control_response_bytes_sent_total,
        delta.control_response_bytes_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "send_errors",
        total.send_errors_total,
        delta.send_errors_total,
        interval_secs,
    );
    counter(
        sample,
        "membership_updates_accepted",
        total.membership_updates_accepted_total,
        delta.membership_updates_accepted_total,
        interval_secs,
    );
    counter(
        sample,
        "membership_records_applied",
        total.membership_records_applied_total,
        delta.membership_records_applied_total,
        interval_secs,
    );
    counter(
        sample,
        "teardowns_accepted",
        total.teardowns_accepted_total,
        delta.teardowns_accepted_total,
        interval_secs,
    );
    counter(
        sample,
        "auth_rejections",
        total.auth_rejections_total,
        delta.auth_rejections_total,
        interval_secs,
    );
    counter(
        sample,
        "gateways_expired",
        total.gateways_expired_total,
        delta.gateways_expired_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_subscription_adds",
        total.upstream_subscription_adds_total,
        delta.upstream_subscription_adds_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_subscription_removes",
        total.upstream_subscription_removes_total,
        delta.upstream_subscription_removes_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_reconcile_failures",
        total.upstream_reconcile_failures_total,
        delta.upstream_reconcile_failures_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_packets_received",
        total.upstream_packets_received_total,
        delta.upstream_packets_received_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_bytes_received",
        total.upstream_bytes_received_total,
        delta.upstream_bytes_received_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_packets_forwarded",
        total.upstream_packets_forwarded_total,
        delta.upstream_packets_forwarded_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_bytes_forwarded",
        total.upstream_bytes_forwarded_total,
        delta.upstream_bytes_forwarded_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_unmatched_packets",
        total.upstream_unmatched_packets_total,
        delta.upstream_unmatched_packets_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_forward_errors",
        total.upstream_forward_errors_total,
        delta.upstream_forward_errors_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_mtu_drops",
        total.upstream_mtu_drops_total,
        delta.upstream_mtu_drops_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_fragments_sent",
        total.upstream_fragments_sent_total,
        delta.upstream_fragments_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_pmtu_feedback_sent",
        total.upstream_pmtu_feedback_sent_total,
        delta.upstream_pmtu_feedback_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_pmtu_feedback_bytes_sent",
        total.upstream_pmtu_feedback_bytes_sent_total,
        delta.upstream_pmtu_feedback_bytes_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_pmtu_feedback_rate_limited",
        total.upstream_pmtu_feedback_rate_limited_total,
        delta.upstream_pmtu_feedback_rate_limited_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_pmtu_feedback_suppressed",
        total.upstream_pmtu_feedback_suppressed_total,
        delta.upstream_pmtu_feedback_suppressed_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_pmtu_feedback_unavailable",
        total.upstream_pmtu_feedback_unavailable_total,
        delta.upstream_pmtu_feedback_unavailable_total,
        interval_secs,
    );
    counter(
        sample,
        "upstream_pmtu_feedback_errors",
        total.upstream_pmtu_feedback_errors_total,
        delta.upstream_pmtu_feedback_errors_total,
        interval_secs,
    );
    counter(
        sample,
        "relay_ecn_normal_mode_datagrams_sent",
        total.relay_ecn_normal_mode_datagrams_sent_total,
        delta.relay_ecn_normal_mode_datagrams_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_discoveries_sent",
        total.gateway_discoveries_sent_total,
        delta.gateway_discoveries_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_membership_queries_received",
        total.gateway_membership_queries_received_total,
        delta.gateway_membership_queries_received_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_membership_updates_sent",
        total.gateway_membership_updates_sent_total,
        delta.gateway_membership_updates_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_membership_refreshes",
        total.gateway_membership_refreshes_total,
        delta.gateway_membership_refreshes_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_teardowns_sent",
        total.gateway_teardowns_sent_total,
        delta.gateway_teardowns_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_refreshes_started",
        total.driad_refreshes_started_total,
        delta.driad_refreshes_started_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_refreshes_succeeded",
        total.driad_refreshes_succeeded_total,
        delta.driad_refreshes_succeeded_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_refreshes_failed",
        total.driad_refreshes_failed_total,
        delta.driad_refreshes_failed_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_candidate_changes",
        total.driad_candidate_changes_total,
        delta.driad_candidate_changes_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_no_relay_withdrawals",
        total.driad_no_relay_withdrawals_total,
        delta.driad_no_relay_withdrawals_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_probes_started",
        total.driad_probes_started_total,
        delta.driad_probes_started_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_probe_timeouts",
        total.driad_probe_timeouts_total,
        delta.driad_probe_timeouts_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_probe_errors",
        total.driad_probe_errors_total,
        delta.driad_probe_errors_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_connections_established",
        total.driad_connections_established_total,
        delta.driad_connections_established_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_loaded_hold_downs",
        total.driad_loaded_hold_downs_total,
        delta.driad_loaded_hold_downs_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_no_traffic_hold_downs",
        total.driad_no_traffic_hold_downs_total,
        delta.driad_no_traffic_hold_downs_total,
        interval_secs,
    );
    counter(
        sample,
        "driad_query_timeouts",
        total.driad_query_timeouts_total,
        delta.driad_query_timeouts_total,
        interval_secs,
    );
    counter(
        sample,
        "multicast_data_received",
        total.multicast_data_received_total,
        delta.multicast_data_received_total,
        interval_secs,
    );
    counter(
        sample,
        "multicast_data_bytes_received",
        total.multicast_data_bytes_received_total,
        delta.multicast_data_bytes_received_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_ecn_ce_received",
        total.gateway_ecn_ce_received_total,
        delta.gateway_ecn_ce_received_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_ecn_ce_propagated",
        total.gateway_ecn_ce_propagated_total,
        delta.gateway_ecn_ce_propagated_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_ecn_currently_unused",
        total.gateway_ecn_currently_unused_total,
        delta.gateway_ecn_currently_unused_total,
        interval_secs,
    );
    counter(
        sample,
        "gateway_ecn_invalid_drops",
        total.gateway_ecn_invalid_drops_total,
        delta.gateway_ecn_invalid_drops_total,
        interval_secs,
    );
    counter(
        sample,
        "downstream_packets_forwarded",
        total.downstream_packets_forwarded_total,
        delta.downstream_packets_forwarded_total,
        interval_secs,
    );
    counter(
        sample,
        "downstream_bytes_forwarded",
        total.downstream_bytes_forwarded_total,
        delta.downstream_bytes_forwarded_total,
        interval_secs,
    );
    counter(
        sample,
        "downstream_non_multicast_packets",
        total.downstream_non_multicast_packets_total,
        delta.downstream_non_multicast_packets_total,
        interval_secs,
    );
    counter(
        sample,
        "downstream_forward_errors",
        total.downstream_forward_errors_total,
        delta.downstream_forward_errors_total,
        interval_secs,
    );
    counter(
        sample,
        "local_queries_sent",
        total.local_queries_sent_total,
        delta.local_queries_sent_total,
        interval_secs,
    );
    counter(
        sample,
        "local_membership_reports",
        total.local_membership_reports_total,
        delta.local_membership_reports_total,
        interval_secs,
    );
    counter(
        sample,
        "local_membership_parse_errors",
        total.local_membership_parse_errors_total,
        delta.local_membership_parse_errors_total,
        interval_secs,
    );
}

#[cfg(feature = "metrics")]
fn counter(
    sample: &mut Map<String, Value>,
    name: &str,
    total: u64,
    delta: u64,
    interval_secs: f64,
) {
    sample.insert(format!("{name}_total"), total.into());
    sample.insert(format!("{name}_delta"), delta.into());
    sample.insert(
        format!("{name}_per_sec"),
        rate_per_sec(delta, interval_secs).into(),
    );
}

#[cfg(feature = "metrics")]
fn rate_per_sec(count: u64, interval_secs: f64) -> f64 {
    if interval_secs > 0.0 {
        count as f64 / interval_secs
    } else {
        0.0
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Instant;

    #[test]
    fn sample_json_reports_totals_deltas_rates_and_gauges() {
        let previous = MetricsSnapshot {
            captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            counters: AmtMetricsCounters {
                upstream_packets_received_total: 10,
                upstream_bytes_received_total: 1000,
                upstream_pmtu_feedback_sent_total: 1,
                driad_refreshes_succeeded_total: 1,
                gateway_ecn_ce_propagated_total: 2,
                ..AmtMetricsCounters::default()
            },
            gauges: MetricsGauges::Relay(RelayMetricsGauges {
                active_gateways: 1,
                active_upstream_subscriptions: 1,
                upstream_capture_sockets: 1,
            }),
        };
        let current = MetricsSnapshot {
            captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(12),
            counters: AmtMetricsCounters {
                upstream_packets_received_total: 14,
                upstream_bytes_received_total: 1400,
                upstream_pmtu_feedback_sent_total: 3,
                driad_refreshes_succeeded_total: 3,
                gateway_ecn_ce_propagated_total: 5,
                ..AmtMetricsCounters::default()
            },
            gauges: MetricsGauges::Relay(RelayMetricsGauges {
                active_gateways: 2,
                active_upstream_subscriptions: 3,
                upstream_capture_sockets: 1,
            }),
        };

        let sample = metrics_sample_json(&previous, &current);

        assert_eq!(sample["active_gateways"], 2);
        assert_eq!(sample["active_upstream_subscriptions"], 3);
        assert_eq!(sample["upstream_capture_sockets"], 1);
        assert_eq!(sample["upstream_packets_received_total"], 14);
        assert_eq!(sample["upstream_packets_received_delta"], 4);
        assert_eq!(sample["upstream_packets_received_per_sec"], 2.0);
        assert_eq!(sample["upstream_bytes_received_per_sec"], 200.0);
        assert_eq!(sample["upstream_pmtu_feedback_sent_delta"], 2);
        assert_eq!(sample["driad_refreshes_succeeded_delta"], 2);
        assert_eq!(sample["gateway_ecn_ce_propagated_delta"], 3);
    }

    #[test]
    fn gateway_sample_reports_driad_runtime_state() {
        let previous = MetricsSnapshot {
            captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            counters: AmtMetricsCounters {
                driad_probes_started_total: 2,
                driad_loaded_hold_downs_total: 1,
                ..AmtMetricsCounters::default()
            },
            gauges: MetricsGauges::Gateway(GatewayMetricsGauges {
                relay_connected: false,
                downstream_enabled: true,
                transparent_enabled: true,
                configured_joins: 0,
                driad_source_tunnels: 1,
                driad_active_tunnels: 0,
                driad_candidate_probes: 2,
                driad_held_down_relays: 1,
            }),
        };
        let current = MetricsSnapshot {
            captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(12),
            counters: AmtMetricsCounters {
                driad_probes_started_total: 5,
                driad_loaded_hold_downs_total: 2,
                driad_connections_established_total: 1,
                ..AmtMetricsCounters::default()
            },
            gauges: MetricsGauges::Gateway(GatewayMetricsGauges {
                relay_connected: true,
                downstream_enabled: true,
                transparent_enabled: true,
                configured_joins: 0,
                driad_source_tunnels: 3,
                driad_active_tunnels: 2,
                driad_candidate_probes: 1,
                driad_held_down_relays: 2,
            }),
        };

        let sample = metrics_sample_json(&previous, &current);

        assert_eq!(sample["relay_connected"], 1);
        assert_eq!(sample["driad_source_tunnels"], 3);
        assert_eq!(sample["driad_active_tunnels"], 2);
        assert_eq!(sample["driad_candidate_probes"], 1);
        assert_eq!(sample["driad_held_down_relays"], 2);
        assert_eq!(sample["driad_probes_started_delta"], 3);
        assert_eq!(sample["driad_loaded_hold_downs_delta"], 1);
        assert_eq!(sample["driad_connections_established_total"], 1);
    }

    #[test]
    fn failed_sample_write_disables_metrics() {
        let now = Instant::now();
        let bad_parent = std::env::temp_dir().join(format!(
            "amt_metrics_bad_parent_{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::write(&bad_parent, b"not a directory").unwrap();
        let previous = MetricsSnapshot {
            captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10),
            counters: AmtMetricsCounters::default(),
            gauges: MetricsGauges::Relay(RelayMetricsGauges {
                active_gateways: 1,
                active_upstream_subscriptions: 1,
                upstream_capture_sockets: 1,
            }),
        };
        let mut recorder = MetricsRecorder {
            counters: AmtMetricsCounters {
                upstream_packets_received_total: 1,
                ..AmtMetricsCounters::default()
            },
            writer: Some(MetricsWriter {
                path: bad_parent.join("amt-relay.jsonl"),
                header: Value::Object(Map::new()),
                sample_interval: Duration::from_secs(60),
                next_emit_at: now - Duration::from_secs(1),
                previous: Some(previous),
                max_file_bytes: None,
            }),
        };

        assert!(
            recorder
                .maybe_emit_relay(RelayMetricsGauges {
                    active_gateways: 1,
                    active_upstream_subscriptions: 1,
                    upstream_capture_sockets: 1,
                })
                .is_err()
        );
        assert!(recorder.writer.is_none());
        assert!(
            !recorder
                .maybe_emit_relay(RelayMetricsGauges {
                    active_gateways: 1,
                    active_upstream_subscriptions: 1,
                    upstream_capture_sockets: 1,
                })
                .unwrap()
        );
    }

    #[test]
    fn rejects_node_id_path_traversal() {
        let config = MetricsConfig {
            node_id: "../outside".to_string(),
            ..MetricsConfig::default()
        };

        assert_eq!(
            config.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
