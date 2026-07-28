//! Telemetry event, adapter, and bounded-export tests.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use super::*;
use crate::crypto::Keypair;

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
    let node = Keypair::generate().public;
    let event = TelemetryEvent::span_end_with_timestamp_micros(
        42,
        "reconciliation",
        "block_set_round",
        1_700_000_000_000_000,
    )
    .with_node(node)
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
