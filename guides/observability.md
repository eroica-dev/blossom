# Observability

Blossom exposes one event pipeline that embedding services can fan out to:

- bounded-cardinality metrics and protocol spans through `fast-telemetry`;
- structured operational logs through `eden-logger`;
- the existing JSONL observer stream; and
- application-owned sinks implementing `TelemetrySink`.

Observability is opt-in. Blossom does not install a global logger, start an
export server, or choose a service's metrics backend. The embedding service owns
those process-wide decisions and passes the resulting `TelemetryHandle` to each
Blossom runtime.

## Features

```toml
[dependencies]
blossom = { version = "2.0.0-pre-release", features = [
    "high-availability",
    "observability",
] }
eden_logger = { version = "0.1.2" }
fast-telemetry = { version = "0.9.0", features = ["runtime"] }
```

The features may also be selected independently:

- `telemetry` enables the Fast Telemetry metric group and span adapter.
- `eden-logger` enables the structured-log adapter.
- `observability` enables both adapters.

The base `TelemetryEvent`, `TelemetryHandle`, JSONL sink, in-memory sink, and
custom-sink trait remain available without these features.

The default `TelemetryHandle` is disabled. Protocol hot paths check that state
before constructing event payloads, so applications that do not opt in do not
pay for event allocation or sink dispatch.

When the bundled `blossom-node` binary is compiled with an adapter feature, it
initializes the selected logger adapter and/or in-process Fast Telemetry
registration. It does not start a metrics or span exporter. A hosting service
must retain the Fast Telemetry runtime and expose or drain its data.
`BLOSSOM_OBSERVER_ADDR` is composed with those adapters instead of replacing
them.

## Service Setup

Initialize the process-wide logger once, create or reuse the service's shared
Fast Telemetry runtime, and compose the sinks:

```rust
use std::sync::Arc;

use blossom::{
    EdenLoggerTelemetrySink, FanoutTelemetrySink, FastTelemetryRegistration,
    HighAvailabilityRuntime, RuntimeConfig, TelemetryHandle, TelemetrySink,
};

eden_logger::init(eden_logger::WriterConfig {
    format: eden_logger::LogFormat::Json,
    ..Default::default()
});
eden_logger::init_from_env();

let metrics_runtime =
    fast_telemetry::Runtime::new(fast_telemetry::RuntimeConfig::default());
let blossom_metrics = FastTelemetryRegistration::register(&metrics_runtime);

let sinks: Vec<Arc<dyn TelemetrySink>> = vec![
    blossom_metrics.sink(),
    Arc::new(EdenLoggerTelemetrySink::new()),
];
let telemetry =
    TelemetryHandle::new(Arc::new(FanoutTelemetrySink::new(sinks)));

// General or trusted Global Blossom.
let mut config = RuntimeConfig::new(node_identity);
config.telemetry = telemetry.clone();

// Small-cluster trusted HA.
let ha = HighAvailabilityRuntime::new(
    group_id,
    local_key,
    members,
    ha_parameters,
)?
.with_telemetry(telemetry.clone());
# Ok::<(), blossom::BlossomError>(())
```

The service must keep `metrics_runtime` and `blossom_metrics` alive. It may:

- export all shared metrics with `metrics_runtime.visit_metrics(...)`;
- export just Blossom's Prometheus text with
  `blossom_metrics.prometheus()`;
- drain completed protocol spans with
  `metrics_runtime.drain_spans_into(...)`; and
- install an `eden-logger` structured sink for its log backend.

`NodeRuntime::telemetry()` and `HighAvailabilityRuntime::telemetry()` let a
service attach its own lifecycle events to the same pipeline. The explicit
`emit_telemetry_failure()` APIs cover service dependencies and transport
failures without changing protocol recovery state.

## Signal Coverage

Protocol records include stable identity and ordering context where available:
node, consensus group, epoch hash, nonce, round, peer, message kind, outcome,
error, membership generation, quorum configuration, and byte counts.

The instrumented lifecycle includes:

- Dispatch, acknowledgement, confirmation, and finality.
- Local acceptance, availability, ordered finalization, application, and
  sealing milestones.
- Trusted and HA health states, write availability, and service directives.
- Membership suspension/reactivation and HA recovery snapshots.
- Transport failures, consensus-driver retries, repair, and head-of-line
  availability faults.
- Deterministic campaign start/completion and every protocol cell.

Fast Telemetry uses fixed label enums for event kind, protocol stage, and
outcome. Node IDs, hashes, nonces, and error strings are log/span attributes,
not metric labels, so cluster growth cannot create unbounded metric
cardinality.

Eden Logger records are `Internal` audience logs. Their severity is derived
from the protocol event: ordinary progress is `Info`, degraded/stalled/
unresponsive conditions are `Warn`, and protocol, storage, corruption, or
explicit failures are `Error`. `EDEN_LOG_LEVEL` remains the service's runtime
filter.

## Deterministic Campaigns

`scripts/deterministic-campaign.sh` builds the campaign with `observability`.
Each run writes:

- its normal replay and correctness artifacts;
- structured Eden logs to the configured logger target; and
- `metrics.prom` beside the campaign report.

The short PR campaign may be run before an overnight fault campaign:

```bash
scripts/deterministic-campaign.sh --profile pr --budget 10m
```

Generated observability artifacts remain under `target/` and are not committed.
