# Deterministic Verification Sandbox

`deterministic-test-env` is a protocol-independent, deterministic
discrete-event framework for databases, replication protocols, and production
service components. Blossom's adapters live in `blossom-sim`; the framework
itself does not depend on Blossom or on an external simulation service.

The design applies controlled-nondeterminism and replay techniques described by
[Antithesis deterministic simulation
testing](https://antithesis.com/docs/resources/deterministic_simulation_testing/),
[FoundationDB simulation](https://apple.github.io/foundationdb/testing.html),
[Turso's simulator](https://github.com/tursodatabase/turso/blob/main/testing/simulator/README.md),
and [Pierre Zemb's FoundationDB simulation
overview](https://pierrezemb.fr/posts/diving-into-foundationdb-simulation/).
These are design influences, not runtime dependencies.

## Adapter Contract

An adapter implements `DeterministicNode` and converts each `NodeEvent` into
explicit effects:

- protocol and repair messages;
- client responses;
- virtual timers;
- persistence and deletion operations.

The engine schedules one enabled event at a time. `NodeContext` supplies virtual
microsecond time and stable, seeded choices. Protocol code used in an adapter
must not read wall-clock time or operating-system entropy for replay-relevant
decisions.

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
delayed or fail with full-disk, I/O, fsync, torn-write, and corruption faults.

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

Each campaign writes beneath `target/deterministic-sandbox/`. A run contains
its report, scenarios, replay manifests, state-digest and event streams, client
histories, property and fault coverage, observability output, and minimized
failure traces. Only minimized regression scenarios under
`tests/deterministic/regressions/` belong in source control.

Performance results are publishable only after the same topology passes safety,
replay, recovery, durability, and history checks.
