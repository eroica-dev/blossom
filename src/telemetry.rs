use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufWriter, Write};
use std::net::TcpStream;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
    mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
}

pub trait TelemetrySink: Send + Sync + 'static {
    fn record(&self, event: TelemetryEvent);
}

#[derive(Clone)]
pub struct TelemetryHandle {
    sink: Arc<dyn TelemetrySink>,
}

impl TelemetryHandle {
    pub fn new(sink: Arc<dyn TelemetrySink>) -> Self {
        Self { sink }
    }

    pub fn record(&self, event: TelemetryEvent) {
        self.sink.record(event);
    }
}

impl Default for TelemetryHandle {
    fn default() -> Self {
        Self::new(Arc::new(NoopTelemetrySink))
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
    dropped_events: Arc<AtomicU64>,
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
            dropped_events: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }
}

impl TelemetrySink for JsonlTcpTelemetrySink {
    fn record(&self, event: TelemetryEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
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
    match event.span_id {
        Some(span_id) => append_json_u64_field(batch, "span_id", span_id, true)?,
        None => {}
    }
    append_json_u128_field(batch, "timestamp_micros", event.timestamp_micros, true)?;
    match event.node {
        Some(node) => append_json_hex_field(batch, "node", node.as_ref(), true)?,
        None => {}
    }
    match event.group_id {
        Some(group_id) => append_json_hex_field(batch, "group_id", group_id.as_ref(), true)?,
        None => {}
    }
    append_json_str_field(batch, "stage", &event.stage, true)?;
    append_json_str_field(batch, "event", &event.event, true)?;
    match event.last_epoch {
        Some(last_epoch) => append_json_hex_field(batch, "last_epoch", last_epoch.as_ref(), true)?,
        None => {}
    }
    match event.nonce {
        Some(nonce) => append_json_u64_field(batch, "nonce", nonce.value(), true)?,
        None => {}
    }
    match event.round {
        Some(round) => append_json_u8_field(batch, "round", round, true)?,
        None => {}
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
    use std::thread;

    use super::*;

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
