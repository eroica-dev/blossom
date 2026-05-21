use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use blossom::{TelemetryEvent, TelemetryEventKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default)]
pub struct ObserverCollector {
    events: Mutex<Vec<TelemetryEvent>>,
}

impl ObserverCollector {
    pub fn record(&self, event: TelemetryEvent) {
        self.events
            .lock()
            .expect("observer event lock poisoned")
            .push(event);
    }

    pub fn ingest_json_line(&self, line: &str) -> serde_json::Result<()> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        self.record(serde_json::from_str(trimmed)?);
        Ok(())
    }

    pub fn events(&self) -> Vec<TelemetryEvent> {
        self.events
            .lock()
            .expect("observer event lock poisoned")
            .clone()
    }

    pub fn analysis(&self) -> ObserverAnalysis {
        analyze_events(&self.events())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ObserverAnalysis {
    pub total_events: usize,
    pub span_starts: usize,
    pub span_ends: usize,
    pub event_records: usize,
    pub error_events: usize,
    pub dropped_node_events: usize,
    pub reconnected_node_events: usize,
    pub reconnect_catchup_proofs: u64,
    pub reconnect_stale_proofs: u64,
    pub reconnect_identity_rejections: u64,
    pub block_transfer_attempts: u64,
    pub accepted_blocks: u64,
    pub denied_blocks: u64,
    pub accepted_block_bytes: u64,
    pub denied_block_bytes: u64,
    pub incomplete_spans: usize,
    pub orphan_span_ends: usize,
    pub nodes: usize,
    pub stages: BTreeMap<String, usize>,
    pub events_by_stage: BTreeMap<String, usize>,
    pub events_by_node: BTreeMap<String, usize>,
    pub span_starts_by_node: BTreeMap<String, usize>,
    pub span_ends_by_node: BTreeMap<String, usize>,
    pub errors_by_node: BTreeMap<String, usize>,
    pub dropped_nodes_by_node: BTreeMap<String, usize>,
    pub reconnected_nodes_by_node: BTreeMap<String, usize>,
    pub incomplete_spans_by_node: BTreeMap<String, usize>,
    pub orphan_span_ends_by_node: BTreeMap<String, usize>,
    pub last_event_timestamp_micros_by_node: BTreeMap<String, u128>,
    pub errors_by_stage: BTreeMap<String, usize>,
    pub span_durations_by_stage: BTreeMap<String, SpanDurationStats>,
    pub span_durations_by_stage_event: BTreeMap<String, SpanDurationStats>,
    pub span_durations_by_node_stage: BTreeMap<String, SpanDurationStats>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SpanDurationStats {
    pub count: usize,
    pub total_micros: u128,
    pub min_micros: u128,
    pub max_micros: u128,
    pub avg_micros: u128,
}

impl SpanDurationStats {
    fn record(&mut self, duration_micros: u128) {
        if self.count == 0 {
            self.min_micros = duration_micros;
            self.max_micros = duration_micros;
        } else {
            self.min_micros = self.min_micros.min(duration_micros);
            self.max_micros = self.max_micros.max(duration_micros);
        }
        self.count += 1;
        self.total_micros += duration_micros;
        self.avg_micros = self.total_micros / self.count as u128;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SpanKey {
    node: Option<String>,
    group_id: Option<String>,
    span_id: u64,
}

pub fn analyze_events(events: &[TelemetryEvent]) -> ObserverAnalysis {
    let mut analysis = ObserverAnalysis {
        total_events: events.len(),
        ..ObserverAnalysis::default()
    };
    let mut nodes = BTreeSet::new();
    let mut open_spans = BTreeMap::<SpanKey, &TelemetryEvent>::new();

    for event in events {
        let node = event.node.map(|node| node.to_string());
        *analysis.stages.entry(event.stage.clone()).or_default() += 1;
        *analysis
            .events_by_stage
            .entry(format!("{}:{}", event.stage, event.event))
            .or_default() += 1;
        if let Some(node) = node.as_ref() {
            nodes.insert(node.clone());
            *analysis.events_by_node.entry(node.clone()).or_default() += 1;
            analysis
                .last_event_timestamp_micros_by_node
                .entry(node.clone())
                .and_modify(|timestamp| *timestamp = (*timestamp).max(event.timestamp_micros))
                .or_insert(event.timestamp_micros);
        }
        if event.error.is_some() || event.outcome.as_deref() == Some("error") {
            analysis.error_events += 1;
            *analysis
                .errors_by_stage
                .entry(event.stage.clone())
                .or_default() += 1;
            if let Some(node) = node.as_ref() {
                *analysis.errors_by_node.entry(node.clone()).or_default() += 1;
            }
        }
        if event.kind == TelemetryEventKind::Event
            && (event.outcome.as_deref() == Some("dropped")
                || (event.stage == "membership_pruning" && event.event == "node_dropped"))
        {
            analysis.dropped_node_events += 1;
            if let Some(node) = node.as_ref() {
                *analysis
                    .dropped_nodes_by_node
                    .entry(node.clone())
                    .or_default() += 1;
            }
        }
        if event.kind == TelemetryEventKind::Event
            && (event.outcome.as_deref() == Some("reconnected")
                || (event.stage == "membership_reconnect" && event.event == "node_reconnected"))
        {
            analysis.reconnected_node_events += 1;
            if let Some(node) = node.as_ref() {
                *analysis
                    .reconnected_nodes_by_node
                    .entry(node.clone())
                    .or_default() += 1;
            }
        }
        if event.kind == TelemetryEventKind::Event {
            analysis.reconnect_catchup_proofs += field_u64(event, "reconnect_catchup_proofs");
            analysis.reconnect_stale_proofs += field_u64(event, "reconnect_stale_proofs");
            analysis.reconnect_identity_rejections +=
                field_u64(event, "reconnect_identity_rejections");
            analysis.block_transfer_attempts += field_u64(event, "block_transfer_attempts");
            analysis.accepted_blocks += field_u64(event, "accepted_blocks");
            analysis.denied_blocks += field_u64(event, "denied_blocks");
            analysis.accepted_block_bytes += field_u64(event, "accepted_block_bytes");
            analysis.denied_block_bytes += field_u64(event, "denied_block_bytes");
        }

        match event.kind {
            TelemetryEventKind::Event => analysis.event_records += 1,
            TelemetryEventKind::SpanStart => {
                analysis.span_starts += 1;
                if let Some(node) = node.as_ref() {
                    *analysis
                        .span_starts_by_node
                        .entry(node.clone())
                        .or_default() += 1;
                }
                if let Some(span_id) = event.span_id {
                    open_spans.insert(span_key(event, span_id), event);
                }
            }
            TelemetryEventKind::SpanEnd => {
                analysis.span_ends += 1;
                if let Some(node) = node.as_ref() {
                    *analysis.span_ends_by_node.entry(node.clone()).or_default() += 1;
                }
                if let Some(span_id) = event.span_id {
                    if let Some(start) = open_spans.remove(&span_key(event, span_id)) {
                        let duration = event
                            .timestamp_micros
                            .saturating_sub(start.timestamp_micros);
                        record_duration(
                            &mut analysis.span_durations_by_stage,
                            &event.stage,
                            duration,
                        );
                        record_duration(
                            &mut analysis.span_durations_by_stage_event,
                            &format!("{}:{}", event.stage, event.event),
                            duration,
                        );
                        if let Some(node) = event.node.or(start.node) {
                            record_duration(
                                &mut analysis.span_durations_by_node_stage,
                                &format!("{node}:{}", event.stage),
                                duration,
                            );
                        }
                    } else {
                        analysis.orphan_span_ends += 1;
                        if let Some(node) = node.as_ref() {
                            *analysis
                                .orphan_span_ends_by_node
                                .entry(node.clone())
                                .or_default() += 1;
                        }
                    }
                } else {
                    analysis.orphan_span_ends += 1;
                    if let Some(node) = node.as_ref() {
                        *analysis
                            .orphan_span_ends_by_node
                            .entry(node.clone())
                            .or_default() += 1;
                    }
                }
            }
        }
    }

    analysis.incomplete_spans = open_spans.len();
    for start in open_spans.values() {
        if let Some(node) = start.node {
            *analysis
                .incomplete_spans_by_node
                .entry(node.to_string())
                .or_default() += 1;
        }
    }
    analysis.nodes = nodes.len();
    analysis
}

fn field_u64(event: &TelemetryEvent, key: &str) -> u64 {
    event
        .fields
        .get(key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default()
}

fn span_key(event: &TelemetryEvent, span_id: u64) -> SpanKey {
    SpanKey {
        node: event.node.map(|node| node.to_string()),
        group_id: event.group_id.map(|group_id| group_id.to_string()),
        span_id,
    }
}

fn record_duration(
    durations: &mut BTreeMap<String, SpanDurationStats>,
    key: &str,
    duration_micros: u128,
) {
    durations
        .entry(key.to_string())
        .or_default()
        .record(duration_micros);
}

#[cfg(test)]
mod tests {
    use super::*;
    use blossom::{PubKey, TelemetryEvent, TelemetryEventKind};

    #[test]
    fn analysis_tracks_spans_errors_and_stages() {
        let mut dispatch_start = TelemetryEvent::span_start(1, "dispatch", "dispatch_received");
        dispatch_start.timestamp_micros = 100;
        let mut dispatch_end =
            TelemetryEvent::span_end(1, "dispatch", "dispatch_received").with_outcome("ok");
        dispatch_end.timestamp_micros = 175;
        let mut commit_start = TelemetryEvent::span_start(2, "commit", "commit_received");
        commit_start.timestamp_micros = 200;
        let events = vec![
            dispatch_start,
            dispatch_end,
            commit_start,
            TelemetryEvent::new(TelemetryEventKind::Event, "reconciliation", "started")
                .with_error("test error"),
        ];

        let analysis = analyze_events(&events);
        assert_eq!(analysis.total_events, 4);
        assert_eq!(analysis.span_starts, 2);
        assert_eq!(analysis.span_ends, 1);
        assert_eq!(analysis.incomplete_spans, 1);
        assert_eq!(analysis.error_events, 1);
        assert_eq!(analysis.dropped_node_events, 0);
        assert_eq!(analysis.reconnected_node_events, 0);
        assert_eq!(analysis.stages["dispatch"], 2);
        assert_eq!(analysis.errors_by_stage["reconciliation"], 1);
        assert_eq!(analysis.span_durations_by_stage["dispatch"].count, 1);
        assert_eq!(analysis.span_durations_by_stage["dispatch"].avg_micros, 75);
    }

    #[test]
    fn collector_ingests_json_lines() {
        let collector = ObserverCollector::default();
        let event = TelemetryEvent::span_start(7, "verification", "verification_received");
        collector
            .ingest_json_line(&serde_json::to_string(&event).unwrap())
            .unwrap();

        let analysis = collector.analysis();
        assert_eq!(analysis.total_events, 1);
        assert_eq!(analysis.span_starts, 1);
    }

    #[test]
    fn analysis_matches_node_local_span_ids_without_collisions() {
        let node_a = PubKey([1; 32]);
        let node_b = PubKey([2; 32]);
        let mut a_start = TelemetryEvent::span_start(1, "verification", "verification_received")
            .with_node(node_a);
        a_start.timestamp_micros = 1_000;
        let mut b_start = TelemetryEvent::span_start(1, "verification", "verification_received")
            .with_node(node_b);
        b_start.timestamp_micros = 2_000;
        let mut a_end =
            TelemetryEvent::span_end(1, "verification", "verification_received").with_node(node_a);
        a_end.timestamp_micros = 1_050;
        let mut b_end =
            TelemetryEvent::span_end(1, "verification", "verification_received").with_node(node_b);
        b_end.timestamp_micros = 2_080;

        let analysis = analyze_events(&[a_start, b_start, a_end, b_end]);
        assert_eq!(analysis.orphan_span_ends, 0);
        assert_eq!(analysis.incomplete_spans, 0);
        assert_eq!(analysis.span_durations_by_stage["verification"].count, 2);
        assert_eq!(
            analysis.span_durations_by_stage["verification"].total_micros,
            130
        );
        assert_eq!(
            analysis.span_durations_by_node_stage[&format!("{node_a}:verification")].avg_micros,
            50
        );
        assert_eq!(
            analysis.span_durations_by_node_stage[&format!("{node_b}:verification")].avg_micros,
            80
        );
        assert_eq!(analysis.span_starts_by_node[&node_a.to_string()], 1);
        assert_eq!(analysis.span_ends_by_node[&node_a.to_string()], 1);
        assert_eq!(analysis.span_starts_by_node[&node_b.to_string()], 1);
        assert_eq!(analysis.span_ends_by_node[&node_b.to_string()], 1);
    }

    #[test]
    fn analysis_tracks_dropped_nodes() {
        let node = PubKey([9; 32]);
        let event = TelemetryEvent::new(
            TelemetryEventKind::Event,
            "membership_pruning",
            "node_dropped",
        )
        .with_node(node)
        .with_outcome("dropped");

        let analysis = analyze_events(&[event]);
        assert_eq!(analysis.dropped_node_events, 1);
        assert_eq!(analysis.dropped_nodes_by_node[&node.to_string()], 1);
        assert_eq!(analysis.error_events, 0);
    }

    #[test]
    fn analysis_tracks_reconnected_nodes() {
        let node = PubKey([8; 32]);
        let event = TelemetryEvent::new(
            TelemetryEventKind::Event,
            "membership_reconnect",
            "node_reconnected",
        )
        .with_node(node)
        .with_outcome("reconnected");

        let analysis = analyze_events(&[event]);
        assert_eq!(analysis.reconnected_node_events, 1);
        assert_eq!(analysis.reconnected_nodes_by_node[&node.to_string()], 1);
        assert_eq!(analysis.error_events, 0);
    }

    #[test]
    fn analysis_tracks_block_flow_metrics() {
        let event = TelemetryEvent::new(
            TelemetryEventKind::Event,
            "dispatch",
            "round_delivered_metrics",
        )
        .with_field("block_transfer_attempts", "9")
        .with_field("accepted_blocks", "7")
        .with_field("denied_blocks", "2")
        .with_field("accepted_block_bytes", "1400")
        .with_field("denied_block_bytes", "400");

        let analysis = analyze_events(&[event]);
        assert_eq!(analysis.block_transfer_attempts, 9);
        assert_eq!(analysis.accepted_blocks, 7);
        assert_eq!(analysis.denied_blocks, 2);
        assert_eq!(analysis.accepted_block_bytes, 1400);
        assert_eq!(analysis.denied_block_bytes, 400);
    }
}
