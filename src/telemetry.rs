use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufWriter, Write};
use std::net::TcpStream;
#[cfg(feature = "telemetry")]
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{
    Arc, Mutex,
    mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fast_telemetry::Counter;
#[cfg(feature = "telemetry")]
use fast_telemetry::{
    DeriveLabel, Gauge, Histogram, LabeledCounter, MaxGauge, MetricScope, RegisteredMetrics, Span,
    SpanAttribute, SpanCollector, SpanKind, SpanStatus,
};
use serde::{Deserialize, Serialize};

use crate::crypto::PubKey;
use crate::group::ConsensusGroupId;
use crate::hash::HashType;
use crate::nonce::Nonce;

pub const TELEMETRY_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TelemetryEventKind {
    Event,
    SpanStart,
    SpanEnd,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetrySeverity {
    Info,
    Warn,
    Error,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TelemetryEvent {
    pub schema_version: u16,
    pub kind: TelemetryEventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<u64>,
    pub timestamp_micros: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<PubKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<ConsensusGroupId>,
    pub stage: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_epoch: Option<HashType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Nonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<PubKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl TelemetryEvent {
    pub fn new(
        kind: TelemetryEventKind,
        stage: impl Into<String>,
        event: impl Into<String>,
    ) -> Self {
        Self::new_with_timestamp_micros(kind, stage, event, timestamp_micros())
    }

    pub fn new_with_timestamp_micros(
        kind: TelemetryEventKind,
        stage: impl Into<String>,
        event: impl Into<String>,
        timestamp_micros: u128,
    ) -> Self {
        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            kind,
            span_id: None,
            parent_span_id: None,
            timestamp_micros,
            node: None,
            group_id: None,
            stage: stage.into(),
            event: event.into(),
            last_epoch: None,
            nonce: None,
            round: None,
            peer: None,
            message_kind: None,
            outcome: None,
            error: None,
            fields: BTreeMap::new(),
        }
    }

    pub fn span_start(span_id: u64, stage: impl Into<String>, event: impl Into<String>) -> Self {
        let mut event = Self::new(TelemetryEventKind::SpanStart, stage, event);
        event.span_id = Some(span_id);
        event
    }

    pub fn span_start_with_timestamp_micros(
        span_id: u64,
        stage: impl Into<String>,
        event: impl Into<String>,
        timestamp_micros: u128,
    ) -> Self {
        let mut event = Self::new_with_timestamp_micros(
            TelemetryEventKind::SpanStart,
            stage,
            event,
            timestamp_micros,
        );
        event.span_id = Some(span_id);
        event
    }

    pub fn span_end(span_id: u64, stage: impl Into<String>, event: impl Into<String>) -> Self {
        let mut event = Self::new(TelemetryEventKind::SpanEnd, stage, event);
        event.span_id = Some(span_id);
        event
    }

    pub fn span_end_with_timestamp_micros(
        span_id: u64,
        stage: impl Into<String>,
        event: impl Into<String>,
        timestamp_micros: u128,
    ) -> Self {
        let mut event = Self::new_with_timestamp_micros(
            TelemetryEventKind::SpanEnd,
            stage,
            event,
            timestamp_micros,
        );
        event.span_id = Some(span_id);
        event
    }

    pub fn with_node(mut self, node: PubKey) -> Self {
        self.node = Some(node);
        self
    }

    pub fn with_group_id(mut self, group_id: ConsensusGroupId) -> Self {
        self.group_id = Some(group_id);
        self
    }

    pub fn with_target(mut self, last_epoch: HashType, nonce: Nonce) -> Self {
        self.last_epoch = Some(last_epoch);
        self.nonce = Some(nonce);
        self
    }

    pub fn with_round(mut self, round: u8) -> Self {
        self.round = Some(round);
        self
    }

    pub fn with_peer(mut self, peer: PubKey) -> Self {
        self.peer = Some(peer);
        self
    }

    pub fn with_message_kind(mut self, message_kind: impl Into<String>) -> Self {
        self.message_kind = Some(message_kind.into());
        self
    }

    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    pub fn with_timestamp_micros(mut self, timestamp_micros: u128) -> Self {
        self.timestamp_micros = timestamp_micros;
        self
    }

    pub fn severity(&self) -> TelemetrySeverity {
        let outcome = self.outcome.as_deref().unwrap_or_default();
        if self.error.is_some()
            || matches!(outcome, "error" | "failed" | "corrupt" | "violation")
            || contains_any(
                &self.event,
                &["corrupt", "diverged", "equivocation", "violation"],
            )
        {
            TelemetrySeverity::Error
        } else if matches!(
            outcome,
            "unknown" | "blocked" | "stalled" | "degraded" | "unavailable"
        ) || contains_any(
            &self.event,
            &[
                "drop",
                "missing",
                "partition",
                "retry",
                "stall",
                "suspend",
                "timeout",
                "unresponsive",
            ],
        ) {
            TelemetrySeverity::Warn
        } else {
            TelemetrySeverity::Info
        }
    }
}

pub trait TelemetrySink: Send + Sync + 'static {
    fn record(&self, event: TelemetryEvent);
}

#[derive(Clone)]
pub struct TelemetryHandle {
    sink: Arc<dyn TelemetrySink>,
    enabled: bool,
}

impl TelemetryHandle {
    pub fn new(sink: Arc<dyn TelemetrySink>) -> Self {
        Self {
            sink,
            enabled: true,
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[inline]
    pub fn record(&self, event: TelemetryEvent) {
        if self.enabled {
            self.sink.record(event);
        }
    }

    pub fn record_milestone(&self, event: &crate::active_active::MilestoneEvent) {
        if !self.enabled {
            return;
        }
        let milestone = match event.milestone {
            crate::active_active::Milestone::AcceptedLocal => "accepted_local",
            crate::active_active::Milestone::Available => "available",
            crate::active_active::Milestone::Finalized => "finalized",
            crate::active_active::Milestone::Applied => "applied",
            crate::active_active::Milestone::Sealed => "sealed",
        };
        let mut telemetry = TelemetryEvent::new_with_timestamp_micros(
            TelemetryEventKind::Event,
            "milestone",
            milestone,
            event.timestamp_micros,
        )
        .with_outcome("ok")
        .with_field("protocol", event.protocol.clone())
        .with_field("reference_hash", event.reference_hash.to_string());
        if let Some(watermark) = event.watermark {
            telemetry = telemetry.with_field("watermark", watermark.position.to_string());
        }
        self.record(telemetry);
    }

    pub fn record_trusted_operational_status(
        &self,
        node: PubKey,
        group_id: ConsensusGroupId,
        status: &crate::runtime::TrustedOperationalStatus,
    ) {
        if !self.enabled {
            return;
        }
        self.record(
            TelemetryEvent::new(TelemetryEventKind::Event, "service", "trusted_status")
                .with_node(node)
                .with_group_id(group_id)
                .with_target(status.head_hash, status.head_nonce)
                .with_outcome(format!("{:?}", status.health).to_ascii_lowercase())
                .with_field("durable", status.durable.to_string())
                .with_field(
                    "durable_epoch_count",
                    status.durable_epoch_count.to_string(),
                )
                .with_field("accepts_writes", status.accepts_writes.to_string())
                .with_field(
                    "expected_round_members",
                    status.expected_round_members.to_string(),
                )
                .with_field(
                    "observed_dispatch_members",
                    status.observed_dispatch_members.to_string(),
                )
                .with_field(
                    "required_acknowledgements",
                    status.required_acknowledgements.to_string(),
                )
                .with_field(
                    "observed_matching_acknowledgements",
                    status.observed_matching_acknowledgements.to_string(),
                )
                .with_field(
                    "required_confirmations",
                    status.required_confirmations.to_string(),
                )
                .with_field(
                    "observed_matching_confirmations",
                    status.observed_matching_confirmations.to_string(),
                )
                .with_field("directives", format!("{:?}", status.directives)),
        );
    }

    pub fn record_trusted_failure(
        &self,
        node: PubKey,
        group_id: ConsensusGroupId,
        error: &crate::BlossomError,
        assessment: &crate::trusted_log::TrustedFailureAssessment,
    ) {
        if !self.enabled {
            return;
        }
        self.record(
            TelemetryEvent::new(TelemetryEventKind::Event, "service", "trusted_failure")
                .with_node(node)
                .with_group_id(group_id)
                .with_outcome("error")
                .with_error(error.to_string())
                .with_field("class", format!("{:?}", assessment.class))
                .with_field("retry_in_process", assessment.retry_in_process.to_string())
                .with_field("directives", format!("{:?}", assessment.directives)),
        );
    }

    #[cfg(feature = "high-availability")]
    pub fn record_ha_operational_status(
        &self,
        node: PubKey,
        group_id: ConsensusGroupId,
        head_hash: HashType,
        head_nonce: Nonce,
        status: &crate::high_availability::HaOperationalStatus,
    ) {
        if !self.enabled {
            return;
        }
        self.record(
            TelemetryEvent::new(TelemetryEventKind::Event, "service", "ha_status")
                .with_node(node)
                .with_group_id(group_id)
                .with_target(head_hash, head_nonce)
                .with_outcome(format!("{:?}", status.health).to_ascii_lowercase())
                .with_field("active_nodes", status.active_nodes.to_string())
                .with_field("responsive_nodes", status.responsive_nodes.to_string())
                .with_field("required_nodes", status.required_nodes.to_string())
                .with_field("accepts_writes", status.accepts_writes.to_string())
                .with_field(
                    "strict_reads_through",
                    status.strict_reads_through.position.to_string(),
                )
                .with_field("directives", format!("{:?}", status.directives)),
        );
    }
}

impl Default for TelemetryHandle {
    fn default() -> Self {
        Self {
            sink: Arc::new(NoopTelemetrySink),
            enabled: false,
        }
    }
}

impl fmt::Debug for TelemetryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelemetryHandle").finish_non_exhaustive()
    }
}

pub struct NoopTelemetrySink;

impl TelemetrySink for NoopTelemetrySink {
    fn record(&self, _event: TelemetryEvent) {}
}

#[derive(Debug, Default)]
pub struct InMemoryTelemetrySink {
    events: Mutex<Vec<TelemetryEvent>>,
}

impl InMemoryTelemetrySink {
    pub fn events(&self) -> Vec<TelemetryEvent> {
        self.events
            .lock()
            .expect("telemetry events lock poisoned")
            .clone()
    }
}

impl TelemetrySink for InMemoryTelemetrySink {
    fn record(&self, event: TelemetryEvent) {
        self.events
            .lock()
            .expect("telemetry events lock poisoned")
            .push(event);
    }
}

#[derive(Default)]
pub struct FanoutTelemetrySink {
    sinks: Vec<Arc<dyn TelemetrySink>>,
}

impl FanoutTelemetrySink {
    pub fn new(sinks: Vec<Arc<dyn TelemetrySink>>) -> Self {
        Self { sinks }
    }

    pub fn push(&mut self, sink: Arc<dyn TelemetrySink>) {
        self.sinks.push(sink);
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }
}

impl fmt::Debug for FanoutTelemetrySink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FanoutTelemetrySink")
            .field("sink_count", &self.sinks.len())
            .finish()
    }
}

impl TelemetrySink for FanoutTelemetrySink {
    fn record(&self, event: TelemetryEvent) {
        for sink in &self.sinks {
            sink.record(event.clone());
        }
    }
}

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveLabel)]
#[label_name = "kind"]
enum MetricEventKind {
    Event,
    SpanStart,
    SpanEnd,
}

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveLabel)]
#[label_name = "stage"]
enum MetricStage {
    Dispatch,
    Acknowledge,
    Confirm,
    Finality,
    Apply,
    Seal,
    Membership,
    Recovery,
    Storage,
    Transport,
    Service,
    Simulation,
    Other,
}

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, DeriveLabel)]
#[label_name = "outcome"]
enum MetricOutcome {
    Ok,
    Error,
    Unknown,
    Blocked,
    Other,
}

#[cfg(feature = "telemetry")]
#[derive(fast_telemetry::ExportMetrics)]
#[metric_prefix = "blossom"]
pub struct BlossomTelemetryMetrics {
    #[help = "Total Blossom telemetry records"]
    records_total: Counter,
    #[help = "Blossom telemetry records by event kind"]
    records_by_kind: LabeledCounter<MetricEventKind>,
    #[help = "Blossom telemetry records by bounded protocol stage"]
    records_by_stage: LabeledCounter<MetricStage>,
    #[help = "Blossom telemetry outcomes"]
    outcomes_total: LabeledCounter<MetricOutcome>,
    #[help = "Blossom telemetry records classified as errors"]
    errors_total: Counter,
    #[help = "Ambiguous or unknown Blossom client outcomes"]
    unknown_outcomes_total: Counter,
    #[help = "Blossom service directive records"]
    service_directives_total: Counter,
    #[help = "Blossom recovery records"]
    recovery_events_total: Counter,
    #[help = "Blossom fault, partition, corruption, or failure records"]
    fault_events_total: Counter,
    #[help = "Bytes reported by Blossom protocol events"]
    reported_bytes_total: Counter,
    #[help = "Blossom protocol span duration in microseconds"]
    span_duration_micros: Histogram,
    #[help = "Current open Blossom protocol spans"]
    open_spans: Gauge,
    #[help = "Highest observed Blossom nonce"]
    last_nonce: MaxGauge,
    #[help = "Latest observed Blossom round"]
    last_round: Gauge,
}

#[cfg(feature = "telemetry")]
impl BlossomTelemetryMetrics {
    pub fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            records_total: Counter::new(shard_count),
            records_by_kind: LabeledCounter::new(shard_count),
            records_by_stage: LabeledCounter::new(shard_count),
            outcomes_total: LabeledCounter::new(shard_count),
            errors_total: Counter::new(shard_count),
            unknown_outcomes_total: Counter::new(shard_count),
            service_directives_total: Counter::new(shard_count),
            recovery_events_total: Counter::new(shard_count),
            fault_events_total: Counter::new(shard_count),
            reported_bytes_total: Counter::new(shard_count),
            span_duration_micros: Histogram::with_latency_buckets(shard_count),
            open_spans: Gauge::new(),
            last_nonce: MaxGauge::new(shard_count),
            last_round: Gauge::new(),
        }
    }

    pub fn snapshot(&self) -> BlossomTelemetryMetricsSnapshot {
        BlossomTelemetryMetricsSnapshot {
            records_total: counter_sum_u64(&self.records_total),
            span_starts: labeled_counter_sum(&self.records_by_kind, MetricEventKind::SpanStart),
            span_ends: labeled_counter_sum(&self.records_by_kind, MetricEventKind::SpanEnd),
            errors_total: counter_sum_u64(&self.errors_total),
            unknown_outcomes_total: counter_sum_u64(&self.unknown_outcomes_total),
            service_directives_total: counter_sum_u64(&self.service_directives_total),
            recovery_events_total: counter_sum_u64(&self.recovery_events_total),
            fault_events_total: counter_sum_u64(&self.fault_events_total),
            reported_bytes_total: counter_sum_u64(&self.reported_bytes_total),
            span_samples: self.span_duration_micros.count(),
            span_duration_micros_sum: self.span_duration_micros.sum(),
            open_spans: self.open_spans.get(),
            last_nonce: self.last_nonce.get(),
            last_round: self.last_round.get(),
        }
    }

    pub fn prometheus(&self) -> String {
        let mut output = String::new();
        self.export_prometheus(&mut output);
        output
    }
}

#[cfg(feature = "telemetry")]
impl Default for BlossomTelemetryMetrics {
    fn default() -> Self {
        Self::new(64)
    }
}

#[cfg(feature = "telemetry")]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomTelemetryMetricsSnapshot {
    pub records_total: u64,
    pub span_starts: u64,
    pub span_ends: u64,
    pub errors_total: u64,
    pub unknown_outcomes_total: u64,
    pub service_directives_total: u64,
    pub recovery_events_total: u64,
    pub fault_events_total: u64,
    pub reported_bytes_total: u64,
    pub span_samples: u64,
    pub span_duration_micros_sum: u64,
    pub open_spans: i64,
    pub last_nonce: i64,
    pub last_round: i64,
}

#[cfg(feature = "telemetry")]
struct ActiveFastSpan {
    started_micros: u128,
    span: Span,
}

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FastSpanKey {
    node: Option<PubKey>,
    group_id: Option<ConsensusGroupId>,
    span_id: u64,
}

#[cfg(feature = "telemetry")]
impl FastSpanKey {
    fn from_event(event: &TelemetryEvent, span_id: u64) -> Self {
        Self {
            node: event.node,
            group_id: event.group_id,
            span_id,
        }
    }
}

#[cfg(feature = "telemetry")]
pub struct FastTelemetrySink {
    metrics: Arc<BlossomTelemetryMetrics>,
    collector: Arc<SpanCollector>,
    active_spans: Mutex<BTreeMap<FastSpanKey, ActiveFastSpan>>,
    open_spans: AtomicI64,
}

#[cfg(feature = "telemetry")]
impl fmt::Debug for FastTelemetrySink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FastTelemetrySink")
            .field("metrics", &self.metrics.snapshot())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "telemetry")]
impl FastTelemetrySink {
    fn new(metrics: Arc<BlossomTelemetryMetrics>, collector: Arc<SpanCollector>) -> Self {
        Self {
            metrics,
            collector,
            active_spans: Mutex::new(BTreeMap::new()),
            open_spans: AtomicI64::new(0),
        }
    }

    pub fn metrics(&self) -> &Arc<BlossomTelemetryMetrics> {
        &self.metrics
    }

    fn record_metrics(&self, event: &TelemetryEvent) {
        self.metrics.records_total.inc();
        self.metrics
            .records_by_kind
            .inc(metric_event_kind(&event.kind));
        let stage = metric_stage(event);
        self.metrics.records_by_stage.inc(stage);
        if stage == MetricStage::Recovery {
            self.metrics.recovery_events_total.inc();
        }
        if event.fields.contains_key("directives") {
            self.metrics.service_directives_total.inc();
        }
        if event.severity() == TelemetrySeverity::Error {
            self.metrics.errors_total.inc();
        }
        if contains_any(
            &format!("{} {}", event.stage, event.event),
            &["fault", "partition", "corrupt", "failure", "torn"],
        ) {
            self.metrics.fault_events_total.inc();
        }
        if let Some(outcome) = event.outcome.as_deref() {
            let outcome = metric_outcome(outcome);
            self.metrics.outcomes_total.inc(outcome);
            if outcome == MetricOutcome::Unknown {
                self.metrics.unknown_outcomes_total.inc();
            }
        }
        for (key, value) in &event.fields {
            if (key == "bytes" || key.ends_with("_bytes"))
                && let Ok(bytes) = value.parse::<u64>()
            {
                self.metrics.reported_bytes_total.add(isize_from_u64(bytes));
            }
        }
        if let Some(nonce) = event.nonce {
            self.metrics
                .last_nonce
                .observe(i64::try_from(nonce.value()).unwrap_or(i64::MAX));
        }
        if let Some(round) = event.round {
            self.metrics.last_round.set(i64::from(round));
        }
    }

    fn start_span(&self, event: &TelemetryEvent, span_id: u64) {
        let mut span = self.collector.start_span(
            format!("blossom.{}.{}", event.stage, event.event),
            SpanKind::Internal,
        );
        apply_fast_span_attributes(&mut span, event);
        let active = ActiveFastSpan {
            started_micros: event.timestamp_micros,
            span,
        };
        if let Ok(mut spans) = self.active_spans.lock() {
            let key = FastSpanKey::from_event(event, span_id);
            if spans.insert(key, active).is_some() {
                self.metrics.errors_total.inc();
            } else {
                let open = self.open_spans.fetch_add(1, Ordering::Relaxed) + 1;
                self.metrics.open_spans.set(open);
            }
        }
    }

    fn finish_span(&self, event: &TelemetryEvent, span_id: u64) {
        let key = FastSpanKey::from_event(event, span_id);
        let active = self
            .active_spans
            .lock()
            .ok()
            .and_then(|mut spans| spans.remove(&key));
        let Some(mut active) = active else {
            self.metrics.errors_total.inc();
            return;
        };
        apply_fast_span_attributes(&mut active.span, event);
        active
            .span
            .set_status(if event.severity() == TelemetrySeverity::Error {
                SpanStatus::Error {
                    message: event
                        .error
                        .clone()
                        .unwrap_or_else(|| event.event.clone())
                        .into(),
                }
            } else {
                SpanStatus::Ok
            });
        let duration = event.timestamp_micros.saturating_sub(active.started_micros);
        self.metrics
            .span_duration_micros
            .record(u64::try_from(duration).unwrap_or(u64::MAX));
        active.span.end();
        let open = self.open_spans.fetch_sub(1, Ordering::Relaxed) - 1;
        self.metrics.open_spans.set(open.max(0));
    }
}

#[cfg(feature = "telemetry")]
impl TelemetrySink for FastTelemetrySink {
    fn record(&self, event: TelemetryEvent) {
        self.record_metrics(&event);
        match (event.kind.clone(), event.span_id) {
            (TelemetryEventKind::SpanStart, Some(span_id)) => self.start_span(&event, span_id),
            (TelemetryEventKind::SpanEnd, Some(span_id)) => self.finish_span(&event, span_id),
            _ => {}
        }
    }
}

#[cfg(feature = "telemetry")]
pub struct FastTelemetryRegistration {
    registered: RegisteredMetrics<BlossomTelemetryMetrics>,
    sink: Arc<FastTelemetrySink>,
}

#[cfg(feature = "telemetry")]
impl FastTelemetryRegistration {
    pub fn register(runtime: &Arc<fast_telemetry::Runtime>) -> Self {
        let registered = runtime.register_metrics(
            MetricScope::new("blossom"),
            BlossomTelemetryMetrics::default(),
        );
        let sink = Arc::new(FastTelemetrySink::new(
            Arc::clone(registered.metrics()),
            Arc::clone(runtime.span_collector()),
        ));
        Self { registered, sink }
    }

    pub fn metrics(&self) -> &RegisteredMetrics<BlossomTelemetryMetrics> {
        &self.registered
    }

    pub fn sink(&self) -> Arc<dyn TelemetrySink> {
        self.sink.clone()
    }

    pub fn handle(&self) -> TelemetryHandle {
        TelemetryHandle::new(self.sink())
    }

    pub fn snapshot(&self) -> BlossomTelemetryMetricsSnapshot {
        self.registered.snapshot()
    }

    pub fn prometheus(&self) -> String {
        self.registered.prometheus()
    }
}

#[cfg(feature = "eden-logger")]
#[derive(Debug, Default, Clone, Copy)]
pub struct EdenLoggerTelemetrySink;

#[cfg(feature = "eden-logger")]
impl EdenLoggerTelemetrySink {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(feature = "eden-logger")]
impl TelemetrySink for EdenLoggerTelemetrySink {
    fn record(&self, event: TelemetryEvent) {
        let mut context = eden_logger::LogContext::<()>::new()
            .with_feature("blossom")
            .with_function(event.stage.clone())
            .with_additional("schema_version", event.schema_version.to_string())
            .with_additional("event_kind", format!("{:?}", event.kind))
            .with_additional("event_timestamp_micros", event.timestamp_micros.to_string());
        if let Some(span_id) = event.span_id {
            context = context
                .with_span_id(span_id.to_string())
                .with_additional("blossom_span_id", span_id.to_string());
        }
        if let Some(parent_span_id) = event.parent_span_id {
            context = context.with_additional("blossom_parent_span_id", parent_span_id.to_string());
        }
        if let Some(node) = event.node {
            context = context.with_additional("node", node.to_string());
        }
        if let Some(group_id) = event.group_id {
            context = context.with_additional("group_id", group_id.to_string());
        }
        if let Some(last_epoch) = event.last_epoch {
            context = context.with_additional("last_epoch", last_epoch.to_string());
        }
        if let Some(nonce) = event.nonce {
            context = context.with_additional("nonce", nonce.to_string());
        }
        if let Some(round) = event.round {
            context = context.with_additional("round", round.to_string());
        }
        if let Some(peer) = event.peer {
            context = context.with_additional("peer", peer.to_string());
        }
        if let Some(message_kind) = &event.message_kind {
            context = context.with_additional("message_kind", message_kind.clone());
        }
        if let Some(outcome) = &event.outcome {
            context = context.with_additional("outcome", outcome.clone());
        }
        if let Some(error) = &event.error {
            context = context
                .with_error_category("blossom")
                .with_additional("error", error.clone());
        }
        for (key, value) in &event.fields {
            context = context.with_additional(key.clone(), value.clone());
        }
        let level = match event.severity() {
            TelemetrySeverity::Info => eden_logger::LogLevel::Info,
            TelemetrySeverity::Warn => eden_logger::LogLevel::Warn,
            TelemetrySeverity::Error => eden_logger::LogLevel::Error,
        };
        eden_logger::emit_direct(
            level,
            &event.event,
            &context,
            eden_logger::LogAudience::Internal,
            &[],
            None,
            None,
        );
    }
}

#[cfg(feature = "telemetry")]
fn metric_event_kind(kind: &TelemetryEventKind) -> MetricEventKind {
    match kind {
        TelemetryEventKind::Event => MetricEventKind::Event,
        TelemetryEventKind::SpanStart => MetricEventKind::SpanStart,
        TelemetryEventKind::SpanEnd => MetricEventKind::SpanEnd,
    }
}

#[cfg(feature = "telemetry")]
fn metric_stage(event: &TelemetryEvent) -> MetricStage {
    let stage = event.stage.to_ascii_lowercase();
    let name = event.event.to_ascii_lowercase();
    if contains_any(&stage, &["dispatch"]) {
        MetricStage::Dispatch
    } else if contains_any(&stage, &["acknowledge", "acknowledgement", "availability"]) {
        MetricStage::Acknowledge
    } else if contains_any(&stage, &["confirm"]) {
        MetricStage::Confirm
    } else if contains_any(&stage, &["final", "commit", "order"]) {
        MetricStage::Finality
    } else if contains_any(&stage, &["apply"]) {
        MetricStage::Apply
    } else if contains_any(&stage, &["seal"]) || contains_any(&name, &["sealed"]) {
        MetricStage::Seal
    } else if contains_any(&stage, &["member", "suspend", "reactivat"]) {
        MetricStage::Membership
    } else if contains_any(&stage, &["recover", "repair", "catch_up", "reconcile"]) {
        MetricStage::Recovery
    } else if contains_any(&stage, &["storage", "persist", "fsync", "snapshot"]) {
        MetricStage::Storage
    } else if contains_any(&stage, &["tcp", "transport", "wire", "network"]) {
        MetricStage::Transport
    } else if contains_any(&stage, &["service", "health", "status", "directive"]) {
        MetricStage::Service
    } else if contains_any(&stage, &["simulation", "campaign", "fault"]) {
        MetricStage::Simulation
    } else {
        MetricStage::Other
    }
}

#[cfg(feature = "telemetry")]
fn metric_outcome(outcome: &str) -> MetricOutcome {
    match outcome.to_ascii_lowercase().as_str() {
        "ok" | "success" | "ready" | "accepted" => MetricOutcome::Ok,
        "error" | "failed" | "corrupt" | "violation" => MetricOutcome::Error,
        "unknown" | "ambiguous" => MetricOutcome::Unknown,
        "blocked" | "stalled" | "unavailable" | "degraded" => MetricOutcome::Blocked,
        _ => MetricOutcome::Other,
    }
}

#[cfg(feature = "telemetry")]
fn apply_fast_span_attributes(span: &mut Span, event: &TelemetryEvent) {
    span.set_attribute("blossom.stage", event.stage.clone());
    span.set_attribute("blossom.event", event.event.clone());
    if let Some(node) = event.node {
        span.set_attribute("blossom.node", node.to_string());
    }
    if let Some(group_id) = event.group_id {
        span.set_attribute("blossom.group_id", group_id.to_string());
    }
    if let Some(nonce) = event.nonce {
        span.set_attribute(
            "blossom.nonce",
            i64::try_from(nonce.value()).unwrap_or(i64::MAX),
        );
    }
    if let Some(round) = event.round {
        span.set_attribute("blossom.round", i64::from(round));
    }
    if let Some(outcome) = &event.outcome {
        span.set_attribute("blossom.outcome", outcome.clone());
    }
    if let Some(error) = &event.error {
        span.add_event(
            "blossom.error",
            vec![SpanAttribute::new("error.message", error.clone())],
        );
    }
}

#[cfg(feature = "telemetry")]
fn labeled_counter_sum<L: fast_telemetry::LabelEnum>(counter: &LabeledCounter<L>, label: L) -> u64 {
    u64::try_from(counter.get(label)).unwrap_or_default()
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    let value = value.to_ascii_lowercase();
    needles.iter().any(|needle| value.contains(needle))
}

#[cfg(feature = "telemetry")]
fn isize_from_u64(value: u64) -> isize {
    isize::try_from(value).unwrap_or(isize::MAX)
}

#[derive(Debug, Clone)]
pub struct JsonlTcpTelemetrySinkConfig {
    pub channel_capacity: usize,
    pub max_batch_events: usize,
    pub max_batch_bytes: usize,
    pub writer_capacity_bytes: usize,
    pub max_batch_delay: Duration,
    pub max_flush_delay: Duration,
}

impl Default for JsonlTcpTelemetrySinkConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 65_536,
            max_batch_events: 1024,
            max_batch_bytes: 1 << 20,
            writer_capacity_bytes: 1 << 20,
            max_batch_delay: Duration::from_micros(50),
            max_flush_delay: Duration::from_millis(10),
        }
    }
}

impl JsonlTcpTelemetrySinkConfig {
    fn normalized(mut self) -> Self {
        self.channel_capacity = self.channel_capacity.max(1);
        self.max_batch_events = self.max_batch_events.max(1);
        self.max_batch_bytes = self.max_batch_bytes.max(1024);
        self.writer_capacity_bytes = self.writer_capacity_bytes.max(1024);
        self.max_batch_delay = self.max_batch_delay.max(Duration::from_micros(1));
        self.max_flush_delay = self.max_flush_delay.max(Duration::from_millis(1));
        self
    }
}

pub struct JsonlTcpTelemetrySink {
    sender: SyncSender<TelemetryEvent>,
    worker: Mutex<Option<JoinHandle<()>>>,
    dropped_events: Counter,
}

impl JsonlTcpTelemetrySink {
    pub fn connect(addr: impl AsRef<str>) -> std::io::Result<Self> {
        Self::connect_with_config(addr, JsonlTcpTelemetrySinkConfig::default())
    }

    pub fn connect_with_config(
        addr: impl AsRef<str>,
        config: JsonlTcpTelemetrySinkConfig,
    ) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr.as_ref())?;
        let _ = stream.set_nodelay(true);
        let config = config.normalized();
        let (sender, receiver) = sync_channel(config.channel_capacity);
        let worker = thread::Builder::new()
            .name("blossom-jsonl-telemetry-exporter".to_string())
            .spawn(move || run_jsonl_tcp_exporter(stream, receiver, config))?;
        Ok(Self {
            sender,
            worker: Mutex::new(Some(worker)),
            dropped_events: Counter::new(64),
        })
    }

    pub fn dropped_events(&self) -> u64 {
        counter_sum_u64(&self.dropped_events)
    }
}

impl TelemetrySink for JsonlTcpTelemetrySink {
    fn record(&self, event: TelemetryEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped_events.inc();
            }
        }
    }
}

fn counter_sum_u64(counter: &Counter) -> u64 {
    u64::try_from(counter.sum()).unwrap_or_default()
}

impl Drop for JsonlTcpTelemetrySink {
    fn drop(&mut self) {
        let (replacement, replacement_receiver) = sync_channel(1);
        let sender = std::mem::replace(&mut self.sender, replacement);
        drop(sender);
        drop(replacement_receiver);
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
    }
}

fn run_jsonl_tcp_exporter(
    stream: TcpStream,
    receiver: Receiver<TelemetryEvent>,
    config: JsonlTcpTelemetrySinkConfig,
) {
    let mut writer = BufWriter::with_capacity(config.writer_capacity_bytes, stream);
    let mut batch = Vec::with_capacity(config.max_batch_bytes.min(config.writer_capacity_bytes));
    let mut last_flush = Instant::now();
    while let Ok(event) = receiver.recv() {
        batch.clear();
        let mut batch_events = 0usize;
        if append_jsonl_event(&mut batch, &event).is_ok() {
            batch_events += 1;
        }

        let batch_started = Instant::now();
        let mut disconnected = false;
        while batch_events < config.max_batch_events && batch.len() < config.max_batch_bytes {
            match receiver.try_recv() {
                Ok(event) => {
                    if append_jsonl_event(&mut batch, &event).is_ok() {
                        batch_events += 1;
                    }
                }
                Err(TryRecvError::Empty) => {
                    let elapsed = batch_started.elapsed();
                    if elapsed >= config.max_batch_delay {
                        break;
                    }
                    match receiver.recv_timeout(config.max_batch_delay - elapsed) {
                        Ok(event) => {
                            if append_jsonl_event(&mut batch, &event).is_ok() {
                                batch_events += 1;
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => {
                            disconnected = true;
                            break;
                        }
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }

        if !batch.is_empty() && writer.write_all(&batch).is_err() {
            break;
        }
        if last_flush.elapsed() >= config.max_flush_delay {
            if writer.flush().is_err() {
                break;
            }
            last_flush = Instant::now();
        }
        if disconnected {
            break;
        }
    }
    let _ = writer.flush();
}

fn append_jsonl_event(batch: &mut Vec<u8>, event: &TelemetryEvent) -> Result<(), ()> {
    if append_fast_span_jsonl_event(batch, event)? {
        return Ok(());
    }
    serde_json::to_writer(&mut *batch, event).map_err(|_| ())?;
    batch.write_all(b"\n").map_err(|_| ())
}

fn append_fast_span_jsonl_event(batch: &mut Vec<u8>, event: &TelemetryEvent) -> Result<bool, ()> {
    let kind = match event.kind {
        TelemetryEventKind::SpanStart => "SpanStart",
        TelemetryEventKind::SpanEnd => "SpanEnd",
        TelemetryEventKind::Event => return Ok(false),
    };
    if event.parent_span_id.is_some()
        || event.peer.is_some()
        || event.message_kind.is_some()
        || event.outcome.is_some()
        || event.error.is_some()
        || !event.fields.is_empty()
    {
        return Ok(false);
    }

    batch.write_all(b"{").map_err(|_| ())?;
    append_json_u16_field(batch, "schema_version", event.schema_version, false)?;
    append_json_str_field(batch, "kind", kind, true)?;
    if let Some(span_id) = event.span_id {
        append_json_u64_field(batch, "span_id", span_id, true)?;
    }
    append_json_u128_field(batch, "timestamp_micros", event.timestamp_micros, true)?;
    if let Some(node) = event.node {
        append_json_hex_field(batch, "node", node.as_ref(), true)?;
    }
    if let Some(group_id) = event.group_id {
        append_json_hex_field(batch, "group_id", group_id.as_ref(), true)?;
    }
    append_json_str_field(batch, "stage", &event.stage, true)?;
    append_json_str_field(batch, "event", &event.event, true)?;
    if let Some(last_epoch) = event.last_epoch {
        append_json_hex_field(batch, "last_epoch", last_epoch.as_ref(), true)?;
    }
    if let Some(nonce) = event.nonce {
        append_json_u64_field(batch, "nonce", nonce.value(), true)?;
    }
    if let Some(round) = event.round {
        append_json_u8_field(batch, "round", round, true)?;
    }
    batch.write_all(b"}\n").map_err(|_| ())?;
    Ok(true)
}

fn append_json_field_prefix(batch: &mut Vec<u8>, name: &str, comma: bool) -> Result<(), ()> {
    if comma {
        batch.write_all(b",").map_err(|_| ())?;
    }
    batch.write_all(b"\"").map_err(|_| ())?;
    batch.write_all(name.as_bytes()).map_err(|_| ())?;
    batch.write_all(b"\":").map_err(|_| ())
}

fn append_json_str_field(
    batch: &mut Vec<u8>,
    name: &str,
    value: &str,
    comma: bool,
) -> Result<(), ()> {
    append_json_field_prefix(batch, name, comma)?;
    serde_json::to_writer(&mut *batch, value).map_err(|_| ())
}

fn append_json_hex_field(
    batch: &mut Vec<u8>,
    name: &str,
    value: &[u8],
    comma: bool,
) -> Result<(), ()> {
    append_json_field_prefix(batch, name, comma)?;
    batch.write_all(b"\"").map_err(|_| ())?;
    let start = batch.len();
    batch.resize(start + value.len() * 2, 0);
    hex::encode_to_slice(value, &mut batch[start..]).map_err(|_| ())?;
    batch.write_all(b"\"").map_err(|_| ())
}

fn append_json_u8_field(batch: &mut Vec<u8>, name: &str, value: u8, comma: bool) -> Result<(), ()> {
    append_json_field_prefix(batch, name, comma)?;
    append_json_integer(batch, value);
    Ok(())
}

fn append_json_u16_field(
    batch: &mut Vec<u8>,
    name: &str,
    value: u16,
    comma: bool,
) -> Result<(), ()> {
    append_json_field_prefix(batch, name, comma)?;
    append_json_integer(batch, value);
    Ok(())
}

fn append_json_u64_field(
    batch: &mut Vec<u8>,
    name: &str,
    value: u64,
    comma: bool,
) -> Result<(), ()> {
    append_json_field_prefix(batch, name, comma)?;
    append_json_integer(batch, value);
    Ok(())
}

fn append_json_u128_field(
    batch: &mut Vec<u8>,
    name: &str,
    value: u128,
    comma: bool,
) -> Result<(), ()> {
    append_json_field_prefix(batch, name, comma)?;
    append_json_integer(batch, value);
    Ok(())
}

fn append_json_integer<T: itoa::Integer>(batch: &mut Vec<u8>, value: T) {
    let mut buffer = itoa::Buffer::new();
    batch.extend_from_slice(buffer.format(value).as_bytes());
}

fn timestamp_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn default_handle_disables_event_construction_paths() {
        assert!(!TelemetryHandle::default().is_enabled());

        let sink = Arc::new(InMemoryTelemetrySink::default());
        assert!(TelemetryHandle::new(sink).is_enabled());
    }

    #[test]
    fn severity_classifies_actionable_failures_and_degradation() {
        assert_eq!(
            TelemetryEvent::new(TelemetryEventKind::Event, "transport", "connected").severity(),
            TelemetrySeverity::Info
        );
        assert_eq!(
            TelemetryEvent::new(TelemetryEventKind::Event, "service", "quorum_stalled")
                .with_outcome("blocked")
                .severity(),
            TelemetrySeverity::Warn
        );
        assert_eq!(
            TelemetryEvent::new(TelemetryEventKind::Event, "storage", "write_failed")
                .with_error("fsync failed")
                .severity(),
            TelemetrySeverity::Error
        );
    }

    #[test]
    fn fanout_delivers_identical_events_to_every_sink() {
        let first = Arc::new(InMemoryTelemetrySink::default());
        let second = Arc::new(InMemoryTelemetrySink::default());
        let sink = FanoutTelemetrySink::new(vec![
            first.clone() as Arc<dyn TelemetrySink>,
            second.clone() as Arc<dyn TelemetrySink>,
        ]);
        let event =
            TelemetryEvent::new(TelemetryEventKind::Event, "service", "ready").with_outcome("ok");

        sink.record(event.clone());

        assert_eq!(first.events(), vec![event.clone()]);
        assert_eq!(second.events(), vec![event]);
    }

    #[cfg(feature = "telemetry")]
    #[test]
    fn fast_telemetry_records_bounded_metrics_and_completed_spans() {
        let runtime = fast_telemetry::Runtime::new(fast_telemetry::RuntimeConfig::default());
        let registration = FastTelemetryRegistration::register(&runtime);
        let handle = registration.handle();

        handle.record(
            TelemetryEvent::span_start_with_timestamp_micros(7, "dispatch", "ha_dispatch", 1_000)
                .with_node(PubKey([1; 32]))
                .with_target(HashType::default(), Nonce::new(9))
                .with_round(2),
        );
        handle.record(
            TelemetryEvent::span_end_with_timestamp_micros(7, "dispatch", "ha_dispatch", 1_250)
                .with_node(PubKey([1; 32]))
                .with_round(2)
                .with_outcome("ok")
                .with_field("payload_bytes", "64"),
        );
        handle.record(
            TelemetryEvent::span_start_with_timestamp_micros(7, "dispatch", "ha_dispatch", 2_000)
                .with_node(PubKey([2; 32]))
                .with_target(HashType::default(), Nonce::new(4))
                .with_round(2),
        );
        handle.record(
            TelemetryEvent::span_end_with_timestamp_micros(7, "dispatch", "ha_dispatch", 2_100)
                .with_node(PubKey([2; 32]))
                .with_round(2)
                .with_outcome("ok"),
        );
        handle.record(
            TelemetryEvent::new(TelemetryEventKind::Event, "transport", "response_lost")
                .with_outcome("unknown"),
        );
        handle.record(
            TelemetryEvent::new(TelemetryEventKind::Event, "recovery", "repair_started")
                .with_outcome("ok")
                .with_field("directives", "[FetchRecoveryState]")
                .with_field("bytes", "32"),
        );

        runtime.flush_local_spans();
        let snapshot = registration.snapshot();
        assert_eq!(snapshot.records_total, 6);
        assert_eq!(snapshot.span_starts, 2);
        assert_eq!(snapshot.span_ends, 2);
        assert_eq!(snapshot.unknown_outcomes_total, 1);
        assert_eq!(snapshot.service_directives_total, 1);
        assert_eq!(snapshot.recovery_events_total, 1);
        assert_eq!(snapshot.reported_bytes_total, 96);
        assert_eq!(snapshot.span_samples, 2);
        assert_eq!(snapshot.span_duration_micros_sum, 350);
        assert_eq!(snapshot.open_spans, 0);
        assert_eq!(snapshot.last_nonce, 9);
        assert_eq!(snapshot.last_round, 2);

        let mut spans = Vec::new();
        runtime.drain_spans_into(&mut spans);
        assert_eq!(spans.len(), 2);
        assert!(
            spans
                .iter()
                .all(|span| span.name == "blossom.dispatch.ha_dispatch")
        );

        let prometheus = registration.prometheus();
        assert!(prometheus.contains("blossom_records_total"));
        assert!(prometheus.contains("blossom_span_duration_micros"));
    }

    #[test]
    fn fast_span_jsonl_event_round_trips() {
        let event = TelemetryEvent::span_end_with_timestamp_micros(
            42,
            "reconciliation",
            "block_set_round",
            1_700_000_000_000_000,
        )
        .with_node(PubKey([7; 32]))
        .with_group_id(ConsensusGroupId::root())
        .with_target(HashType([9; 32]), Nonce::new(11))
        .with_round(3);

        let mut batch = Vec::new();
        append_jsonl_event(&mut batch, &event).unwrap();

        let serialized = std::str::from_utf8(&batch).unwrap();
        assert!(!serialized.contains("null"));
        assert!(!serialized.contains("\"fields\""));

        let decoded: TelemetryEvent = serde_json::from_str(serialized.trim()).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn jsonl_tcp_sink_batches_and_flushes_on_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut lines = Vec::new();
            loop {
                let mut line = String::new();
                let bytes = reader.read_line(&mut line).unwrap();
                if bytes == 0 {
                    break;
                }
                lines.push(line);
            }
            lines
        });

        let sink = JsonlTcpTelemetrySink::connect_with_config(
            addr.to_string(),
            JsonlTcpTelemetrySinkConfig {
                channel_capacity: 16,
                max_batch_events: 8,
                max_batch_bytes: 4096,
                writer_capacity_bytes: 4096,
                max_batch_delay: Duration::from_millis(1),
                max_flush_delay: Duration::from_millis(10),
            },
        )
        .unwrap();

        for span_id in 1..=4 {
            sink.record(TelemetryEvent::span_start(
                span_id,
                "dispatch",
                "round_delivered",
            ));
        }
        assert_eq!(sink.dropped_events(), 0);
        drop(sink);

        let lines = reader.join().unwrap();
        assert_eq!(lines.len(), 4);
        for (index, line) in lines.iter().enumerate() {
            let event: TelemetryEvent = serde_json::from_str(line).unwrap();
            assert_eq!(event.kind, TelemetryEventKind::SpanStart);
            assert_eq!(event.span_id, Some(index as u64 + 1));
            assert_eq!(event.stage, "dispatch");
            assert_eq!(event.event, "round_delivered");
        }
    }
}
