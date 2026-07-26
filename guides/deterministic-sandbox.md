# Deterministic Verification Sandbox

Blossom uses the independent
[`deterministic-simulation`](https://github.com/eden-dev-inc/deterministic-simulation)
framework through a revision-pinned dependency. `deterministic-test-env` is a
compatibility facade that re-exports the shared core API; Blossom-specific
adapters and properties live in `blossom-sim`. This keeps the scheduler, fault
model, trace format, and replay machinery reusable by databases and production
services without making the framework depend on Blossom.

The design applies controlled-nondeterminism and replay techniques described by
[Antithesis deterministic simulation
testing](https://antithesis.com/docs/resources/deterministic_simulation_testing/),
[FoundationDB simulation](https://apple.github.io/foundationdb/testing.html),
[Turso's simulator](https://github.com/tursodatabase/turso/blob/main/testing/simulator/README.md),
and [Pierre Zemb's FoundationDB simulation
overview](https://pierrezemb.fr/posts/diving-into-foundationdb-simulation/).
These are design influences, not runtime dependencies.

## Adapter Contract

The product-owned `blossom/protocol-v1` adapter implements the framework's
versioned JSON-lines adapter protocol. It describes its capabilities before a
run and rejects profiles that request unsupported execution or fault modes.
Internally, the HA simulation implements `DeterministicNode` and converts each
`NodeEvent` into explicit effects:

- protocol and repair messages;
- client responses;
- virtual timers;
- persistence and deletion operations.

The engine schedules one enabled event at a time. `NodeContext` supplies virtual
microsecond time and stable, seeded choices. Protocol code used in an adapter
must not read wall-clock time or operating-system entropy for replay-relevant
decisions.

Framework preflight audits
`crates/blossom-sim/src/deterministic.rs`, the protocol scheduling surface.
Durable campaigns intentionally use production redb files; the host disk
replacement boundary is isolated in `deterministic_durable.rs` and is not
claimed as logical exact replay. The adapter instead replays each logical trace
internally and rejects divergent protocol state, history, or property outcomes.

`ChoiceId` uses `{domain, actor, operation, occurrence}` identity. This prevents
an unrelated earlier event from renumbering every later random choice.

## Scenarios And Run Modes

`Scenario` is a serializable, versioned description of topology, seed, event and
virtual-time bounds, permitted fault depth, and scheduled actions.

The three run modes are:

- `Random`: seeded exploration with stable choices.
- `Replay`: exact execution from recorded `ChoiceRecord` values.
- `Systematic`: bounded schedule exploration with dependency-aware pruning.

`ExecutionTrace` records every selected choice, event disposition, client
history, state digest, property result, fault combination, and stop reason.
`ReplayManifest` binds the scenario and trace hashes to the Git revision,
configuration hash, and exact replay command.

Requests and responses are separate events. If a response is lost after a
successful commit, the client receives `ClientOutcome::Unknown`, not an assumed
failure. Adapters and history checkers must resolve that outcome through
idempotent retry or a later read.

## Fault Model

Directed links can independently drop, delay, duplicate, jam, or corrupt
traffic, while the scheduler can reorder independently enabled deliveries.
Nodes can pause, throttle, stop, crash, and restart. Storage operations can be
delayed or fail with full-disk, I/O, fsync, torn-write, corruption, and modeled
disk-replacement faults.

A crash removes volatile adapter state. Durable protocol adapters must reopen
their real per-node store on restart. A quiet recovery phase heals links,
restarts eligible nodes, stops fault injection, and advances virtual time until
the declared convergence properties pass or their deadline expires.

## Properties And Reduction

`GlobalObserver` evaluates cluster-wide state through four property kinds:

| Kind | Meaning |
| --- | --- |
| `Always` | Safety invariant that must hold after every observed transition. |
| `Reachable` | A required state must be reached during the scenario. |
| `Sometimes` | Coverage objective expected in at least one explored schedule. |
| `EventuallyAfterQuiescence` | Recovery or convergence must occur after faults and workload stop. |

`SystematicExplorer` bounds event count, schedule count, branch width, and fault
depth. It prunes independent event interleavings with resource and protocol
keys. `TraceReducer` removes scheduled workload and fault actions from a failing
scenario while preserving the violation. The Blossom HA adapter replays a
failure twice with the same state hashes before reporting it; minimized
scenarios are then retained as regressions.

## Blossom Adapters

The HA adapter delivers dispatches, acknowledgements, confirmations,
amendments, membership actions, and recovery independently against the real
`HighAvailabilityRuntime`. Trusted Global Blossom exercises the durable
sequential log, checkpoint DAG, repair, and catch-up paths. Parallel-network
cells keep HA and Global Blossom membership and progress independent.

OpenRaft is a harness-only active-passive control. It is not linked into
Blossom core. Verified/trustless Blossom remains outside the new fault adapter
and runs as an unchanged regression baseline.

The framework exposes distinct execution modes and does not overstate their
guarantees:

| Mode | Use | Replay guarantee |
| --- | --- | --- |
| Protocol | In-process Blossom adapter with virtual time and explicit effects | Exact internal replay |
| Native process | Linux process lifecycle and host fault validation | Seeded campaign replay |
| KVM | Guest isolation, snapshots, process crash, network outage, and disk stall | Snapshot/restore, not instruction replay |
| TCG record/replay | CPU and device event recording for a fixed guest run | QEMU record/replay |

Disk replacement is modeled inside the protocol campaign. A destructive,
real-root-disk replacement is intentionally not advertised by the protocol
adapter; VM profiles use isolated guest images and explicit KVM/TCG capability
admission.

## Running Campaigns

Run the merge-sized deterministic gate:

```sh
./scripts/deterministic-pr-gate.sh
```

Run the scheduled-equivalent two-hour campaign:

```sh
./scripts/deterministic-campaign.sh --profile nightly --budget 2h
```

Run the manual release soak:

```sh
./scripts/deterministic-campaign.sh --profile release --budget 12h
```

Validate the shared framework, product adapter, Linux host, and selected
profile before an external run:

```sh
DETERMINISTIC_SIM_ROOT=/opt/deterministic-simulation \
  ./scripts/deterministic-framework-preflight.sh \
  simulation/profiles/blossom-protocol-pr.json
```

Run a profile through the shared framework:

```sh
DETERMINISTIC_SIM_ROOT=/opt/deterministic-simulation \
  ./scripts/deterministic-framework-campaign.sh pr
```

Build and exercise the isolated Blossom guest on a Linux KVM host:

```sh
./simulation/vm/build-blossom-guest.sh /opt/deterministic-simulation
./scripts/deterministic-vm-campaign.sh \
  /opt/deterministic-simulation kvm
./simulation/vm/exercise-blossom-kvm.sh \
  /opt/deterministic-simulation
```

Formal and dynamic-analysis gates are separate from schedule exploration:

```sh
BLOSSOM_FORMAL_REQUIRED_TOOLS=kani,quint ./verification/run-formal.sh
./scripts/rust-dynamic-analysis.sh miri
./scripts/rust-dynamic-analysis.sh asan
./scripts/rust-dynamic-analysis.sh tsan
```

The Miri and sanitizer commands are Linux/nightly gates. Required formal tools
fail closed instead of silently skipping; tools not named in
`BLOSSOM_FORMAL_REQUIRED_TOOLS` remain optional for local development.
When the framework dependency is not available through the configured Git
credentials, set `DETERMINISTIC_SIM_ROOT=/opt/deterministic-simulation` for
these commands as well. The launcher then patches Cargo to the exact local
`deterministic-sim-core` and `deterministic-sim-engine` sources.

Each campaign writes beneath `target/deterministic-sandbox/`. A run contains
its report, scenarios, replay manifests, state-digest and event streams, client
histories, property and fault coverage, observability output, and minimized
failure traces. Only minimized regression scenarios under
`tests/deterministic/regressions/` belong in source control.

Performance results are publishable only after the same topology passes safety,
replay, recovery, durability, and history checks.
