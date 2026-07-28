# OpenRaft Production Testing

Blossom's first-party OpenRaft harness runs the shipped state machine, OpenRaft
runtime, and ShardLog-backed durable stores. It complements the authoritative
schedule exploration in `eden-dev-inc/deterministic-simulation`: Blossom owns
production integration and protocol controls; the simulation repository owns
virtual time, systematic exploration, minimization, and exact replay tiers.

## Quick Start

Run the pull-request profile on Linux:

```sh
scripts/openraft-production-campaign.sh pr
```

The runner uses multiple Tokio worker threads and executes independent matrix
cells concurrently. It defaults to at most eight jobs. Set the exact parallelism
for a machine such as Adam:

```sh
BLOSSOM_RAFT_JOBS=16 scripts/openraft-production-campaign.sh nightly
```

Every run writes a versioned JSON report under
`target/openraft-production/<profile>/report.json` and prints one summary line
per completed matrix cell. Artifact schema version 3 records
`replay_level="deterministic-inputs-native-schedule"` and
`exact_task_schedule_replay=false`.

## Profiles

| Profile | Nodes | Storage | Commands per cell | Faults |
| --- | --- | --- | ---: | --- |
| `pr` | 3 | memory and durable | 8 | no fault plus every scripted request/response fault |
| `nightly` | 2 through 7 | memory and durable | 100 | complete matrix |
| `release` | 2 through 7 | memory and durable | 1,001 | complete matrix |

The nightly workflow is
`.github/workflows/openraft-production-campaign.yml`. The PR profile is also
part of `scripts/active-passive-production-validation.sh` and therefore the
mandatory merge gate.

## Custom Runs

All profile values can be overridden without editing Blossom:

```sh
BLOSSOM_RAFT_NODES=3,5,7 \
BLOSSOM_RAFT_STORAGE=durable \
BLOSSOM_RAFT_COMMANDS=250 \
BLOSSOM_RAFT_FAULTS=append-request-loss,append-response-loss,vote-response-loss \
BLOSSOM_RAFT_JOBS=12 \
BLOSSOM_RAFT_SEED=4242 \
scripts/openraft-production-campaign.sh nightly
```

The binary can also be invoked directly:

```sh
cargo run --release -p blossom-bench-harness \
  --bin blossom-raft-deterministic -- \
  --nodes 3,5 \
  --storage both \
  --fault append-request-loss,duplicate-append-request \
  --commands 100 \
  --jobs 4 \
  --seed 4242 \
  --output target/openraft-production/custom/report.json
```

Use `--help` for the complete option and fault list.

## Production Fault Controls

`InProcessNetworkControl` supports persistent link health, blocking, and delay,
plus deterministic one-shot RPC faults with stable IDs:

- request loss after matching but before delivery;
- response loss after the target has processed the request;
- duplicate request delivery;
- request delay;
- response delay;
- exact source and target or any-route matching;
- AppendEntries, Vote, and InstallSnapshot selection; and
- data-bearing matching so heartbeats cannot consume a write fault.

The coverage report records total RPCs by kind, data-bearing appends, link
blocks and delays, each scripted action count, and configured versus executed
fault IDs. It also retains each configured fault specification and the actual
source, target, RPC kind, payload class, and action of every execution. A
campaign cell fails admission if any scripted fault did not fire.

Focused integration tests additionally cover:

- all AppendEntries actions followed by full state-machine convergence;
- request and response loss during elections;
- joint-consensus voter replacement while an AppendEntries response is lost;
- durable snapshot installation where the applied response is lost;
- real durable leader and follower kill/restart; and
- a 1,001-write restart soak.

Every campaign checks linearizable reads, the operation history, ambiguous
outcome resolution, state-machine convergence, and protocol index ordering
(`purged <= snapshot <= applied <= max(snapshot, last retained log)` when the
compared indexes exist).

The campaign installs a process-wide panic recorder before starting Tokio.
Every panic records its thread, payload, source location, and the matrix cells
that were active at that instant in `observed_panics`. A panic makes
`safety_passed=false` and the command exits unsuccessfully even if all
state-machine checks happen to finish green. This prevents a detached
replication task failure from being hidden by a healthy final value.

## Reproduction

The JSON artifact records the base seed and the derived seed for every cell.
Rerun the same profile with `BLOSSOM_RAFT_SEED` and the recorded profile
overrides to reproduce the same workload and injected fault identities.

Native Tokio execution is intentionally a production concurrency test; OS task
scheduling and heartbeat counts are not byte-for-byte deterministic. Exact
schedule replay belongs to `deterministic-simulation`. Use its simulated runtime
for capability-level replay and its Linux TCG tier when the exact production
machine execution must be replayed. A native Blossom report must not be
presented as an exact replay artifact.
