# blossom benchmarks

Performance benchmarks for Blossom protocol primitives and simulated node
behavior. These are developer-facing benchmarks, separate from the correctness
test suite.

## Modes

| Mode | Driver | Question |
| --- | --- | --- |
| `criterion` | Rust Criterion microbenchmarks | How fast are core protocol operations in isolation? |
| `harness` | Local TCP simulation | How expensive is a full node scenario: spawn cluster, register block service, submit block, dispatch, deliver? |
| `harness-matrix` | Shell matrix over harness parameters | How does the full scenario change with node count and transaction count? |
| `load` | Large local TCP simulation | What happens when a block carries hundreds of thousands or millions of transactions, and how many framed bytes move? |
| `gossip` | Local TCP availability-gossip simulation | How many rounds, messages, bytes, and microseconds does filtered-payload gossip plus fetch take? |
| `chaos` | `blossom-sim` TCP harness with fault injection | How does the wire layer behave with controlled latency, jitter, drops, and connection crashes? |
| `epoch-chaos` | `blossom-sim` epoch convergence under transport faults | How many nodes finish on the correct epoch hash after jitter, long delays, spikes, drops, and fuzz? |
| `sim-fuzz` | `blossom-sim` deterministic node I/O fuzzing | Do valid, malformed, truncated, oversized, and random frames leave nodes alive? |
| `sim-hermetic` | `blossom-sim` hermetic simulator | Can we replay latency, node down/up, and seeded drops without kernel/socket timing? |
| `profile-matrix` | Hermetic simulator with node profiling | Which nodes saturate CPU, queue work, or show high handler cost under replayable network and hardware conditions? |
| `sim-container` | VM-like container runner for `blossom-sim` | Can we run simulations in a contained process/network boundary with only results mounted out? |
| `epoch-depth` | In-memory protocol simulation | How do paper-aligned quorum rounds behave across consecutive epochs? |

## Commands

Run the Criterion microbenchmarks:

```bash
./benchmarks/scripts/run-criterion.sh
```

Run a single full harness benchmark:

```bash
ITERATIONS=10 NODES=6 TRANSACTIONS=3 TX_BYTES=32 ./benchmarks/scripts/run-harness.sh
```

Run a small matrix:

```bash
NODE_COUNTS="1 6 12" TRANSACTION_COUNTS="0 3 32" ITERATIONS=5 \
  ./benchmarks/scripts/run-harness-matrix.sh
```

Run a million-transaction load benchmark:

```bash
TRANSACTIONS=1000000 TX_BYTES=32 NODES=6 ITERATIONS=1 \
  ./benchmarks/scripts/run-load.sh
```

Run a filtered-payload availability-gossip benchmark:

```bash
NODES=36 ENTRIES=128 PAYLOAD_BYTES=4096 FANOUT=6 TARGETS_PER_ENTRY=6 \
  ./benchmarks/scripts/run-gossip.sh
```

Run a gossip validation matrix across odd/even node counts, sparse/all-target
delivery, verified/trusted mode, and a small single-fetch equivalence case:

```bash
ITERATIONS=2 WARMUP=0 ./benchmarks/scripts/run-gossip-matrix.sh
```

Run deterministic failure-mode probes:

```bash
./benchmarks/scripts/run-gossip-failures.sh
```

Run the enclosed TCP chaos harness from the `blossom-sim` crate:

```bash
LATENCY_MS=5 JITTER_MS=2 DROP_PPM=10000 CONNECT_CRASH_PPM=5000 \
  RESPONSE_CRASH_PPM=5000 REQUESTS=1000 PAYLOAD_BYTES=1024 \
  DATA_PATTERN=splitmix ./benchmarks/scripts/run-chaos.sh
```

Run deterministic node I/O fuzzing from the `blossom-sim` crate:

```bash
CASES=512 MAX_PAYLOAD_BYTES=8192 DATA_PATTERN=splitmix \
  ./benchmarks/scripts/run-sim-fuzz.sh
```

Run deterministic epoch convergence under TCP-like jitter, delay spikes, drops,
and fuzz:

```bash
NODES=36 EPOCHS=8 TXS_PER_NODE=32 TX_BYTES=64 \
  LATENCY_MS=5 JITTER_MS=25 ROUND_TIMEOUT_MS=120 \
  DROP_PPM=500 FUZZ_PPM=250 SPIKE_PPM=5000 SPIKE_LATENCY_MS=250 \
  REPAIR_ROUNDS=6 REPAIR_FANOUT=35 REPAIR_QUORUM=24 REPAIR_TIMEOUT_MS=500 \
  SHUFFLE=1 ./benchmarks/scripts/run-epoch-chaos.sh
```

Run a hermetic, socket-free simulation with slow nodes and node down/up:

```bash
SLOW_NODES=2,3 SLOW_LATENCY_MS=50 DOWN_NODES=4 DOWN_AT_MS=10 \
  UP_AT_MS=60 REQUESTS=100 PAYLOAD_BYTES=256 ./benchmarks/scripts/run-sim-hermetic.sh
```

Run the same scenario with deterministic auto-restart instead of an absolute
return time:

```bash
DOWN_NODES=4 DOWN_AT_MS=10 RESTART_AFTER_MS=50 \
  REQUESTS=100 PAYLOAD_BYTES=256 ./benchmarks/scripts/run-sim-hermetic.sh
```

Run the same simulation with a bug-candidate latency budget:

```bash
BUG_LATENCY_BUDGET_MS=40 SLOW_NODES=2,3 SLOW_LATENCY_MS=50 \
  DOWN_NODES=4 DOWN_AT_MS=10 UP_AT_MS=60 \
  REQUESTS=100 PAYLOAD_BYTES=256 ./benchmarks/scripts/run-sim-hermetic.sh
```

Run a deterministic profile matrix. This emits summary, event, perf, profile,
and bug-candidate files for each scenario. `TARGET_NODE` isolates a single hot
node, while `CPU_NODES`, CPU delay/stall knobs, and hardware fault knobs let the
same network workload be replayed with controlled resource pressure:

```bash
TRUST_MODES="verified trusted" NODES_LIST="16 64" LATENCIES="0 25 100" \
  CPU_DELAYS="0 1 5" REQUESTS=10000 PAYLOAD_BYTES=1024 \
  ./benchmarks/scripts/run-profile-matrix.sh
```

Run the same simulation modes inside a VM-like container boundary. The runtime
container has external networking disabled, a read-only root filesystem, all
Linux capabilities dropped, and only `benchmarks/results/` mounted as writable
state. When Docker is unavailable, `SIM_BACKEND=auto` falls back to the native
hermetic backend for `sim`, which still has deterministic replay and no socket
or wall-clock dependency:

```bash
SLOW_NODES=2,3 SLOW_LATENCY_MS=50 DOWN_NODES=4 DOWN_AT_MS=10 \
  UP_AT_MS=60 REQUESTS=100 PAYLOAD_BYTES=256 \
  ./benchmarks/scripts/run-sim-container.sh sim
```

Run real TCP chaos inside that contained environment:

```bash
MODE=chaos LATENCY_MS=5 JITTER_MS=2 DROP_PPM=10000 REQUESTS=1000 \
  ./benchmarks/scripts/run-sim-container.sh
```

Run a longer gossip soak. The default duration is 30 minutes:

```bash
DURATION_SECONDS=1800 ./benchmarks/scripts/run-gossip-soak.sh
```

Run the same TCP harness in known-member trusted mode:

```bash
TRUSTED=1 BLOSSOM_HOT_WIRE_CODEC=1 TRANSACTIONS=1000000 TX_BYTES=32 \
  NODES=6 ITERATIONS=1 ./benchmarks/scripts/run-load.sh
```

Run the trusted harness with application-supplied transaction identifiers:

```bash
BLOSSOM_HOT_WIRE_CODEC=1 BLOSSOM_MAX_FRAME_SIZE=1073741824 \
  cargo run --release --features external-transaction-hashes,insecure-fast-hash \
  --bin blossom-harness-bench -- --nodes 6 --transactions 1000000 \
  --transaction-bytes 32 --iterations 1 --warmup 0 \
  --delivery-mode first-accepted --trusted --external-transaction-hashes
```

Run the focused transport optimization matrix. This compares trustless SHA,
trusted SHA, trusted XXH3, and trusted XXH3 with application-supplied
transaction identifiers, and can also sweep bounded write chunk sizes:

```bash
NODE_COUNTS="6" TRANSACTION_COUNTS="200000" TX_BYTES_LIST="1024" \
  WRITE_CHUNK_BYTES_LIST="0 65536 1048576" \
  ./benchmarks/scripts/run-transport-optimization-matrix.sh
```

Propagation policies are split out behind feature gates so latency and
bandwidth optimizations do not silently change trustless safety assumptions.
`propagation-push` exposes the full-block push policy, `propagation-inventory`
exposes inventory-then-missing policy validation, and `propagation-adaptive`
enables the cost model that chooses between them. Trustless inventory plans must
use authenticated manifests and enough redundant holders to survive configured
Byzantine withholding; otherwise validation rejects the plan before the
simulator or runtime can use it.

Run a paper-aligned epoch-depth benchmark:

```bash
EPOCH_DEPTH=3 NODES=36 TXS_PER_NODE=1000 TX_BYTES=32 \
  ./benchmarks/scripts/run-epoch-depth.sh
```

Run the 100-epoch latency/quorum matrix. By default this tests quorum sizes
`3`, `4`, `5`, and `6` with `q*q` nodes, trusted and trustless paths, and both
fixed/even and deterministic random pairwise latency:

```bash
./benchmarks/scripts/run-epoch-latency-matrix.sh
```

Subset-gossip CSV rows include both application throughput and protocol request
pressure. `full_tps` and `subset_payload_ready_tps` report modeled application
commands per second; `full_req_per_sec` and
`subset_payload_ready_req_per_sec` report modeled Blossom wire request-equivalents
per second using the same latency denominator. Component counters such as
`prefill_requests`, `full_dispatch_requests`, `subset_dispatch_requests`,
`control_requests`, and `subset_repair_requests` show which stage creates the
request load.

Add block-header application-state load to either harness:

```bash
APP_STATE_BYTES=4096 EPOCH_DEPTH=1 NODES=36 TXS_PER_NODE=1000 \
  ./benchmarks/scripts/run-epoch-depth.sh
```

Run the trusted known-member fast path directly:

```bash
cargo run --release --bin blossom-epoch-bench -- \
  --nodes 36 --target-transactions 1000000 \
  --transactions-per-node 1000 --transaction-bytes 32 --trusted
```

Run the same scenario with non-cryptographic XXH3 protocol hashing:

```bash
cargo run --release --features insecure-fast-hash --bin blossom-epoch-bench -- \
  --nodes 36 --target-transactions 1000000 \
  --transactions-per-node 1000 --transaction-bytes 32 --trusted
```

Derive epoch depth from a target input volume:

```bash
TARGET_TRANSACTIONS=1000000 NODES=36 TXS_PER_NODE=1000 \
  ./benchmarks/scripts/run-epoch-depth.sh
```

Results are written to `benchmarks/results/`, which is intentionally ignored
by git.

By default the shell scripts run the harness benchmark through
`cargo run --release`. Set `DIRECT=1` to invoke the already-built
`target/release/blossom-harness-bench` binary directly, which is useful in
unsandboxed local runs where direct binary socket binding is allowed.

## Notes

The harness benchmarks bind local ephemeral TCP ports and use the same
`WireRequest`/`WireResponse` framing as the deployable node. Each measured
iteration creates a fresh simulated cluster so the scenario can submit nonce
`1` without relying on hidden state reset. Within an iteration, the driver
reuses one persistent TCP connection to node 0 for registration, nonce lookup,
submission, and dispatch so the measured loop reflects the steady-state node
protocol rather than repeated connection setup.

Use at least six nodes when the benchmark needs accepted peer delivery; six is
the current Blossom quorum size.

Harness CSVs include the exact frame sizes counted for each phase:
`register_wire_bytes`, `next_nonce_wire_bytes`, `submit_wire_bytes`,
`dispatch_wire_bytes`, `deliver_wire_bytes`, and `total_wire_bytes`. They also
record `tx_payload_bytes`, `application_state_bytes`,
`accepted_application_state_bytes`, `block_bytes`, `trusted`, and
`external_transaction_hashes`, so a run can distinguish raw transaction payload,
piggy-backed coordination state, protocol overhead, trust-boundary mode, and
whether per-transaction identifiers were computed by Blossom or supplied by the
application.

The runtime defaults to a 32 MiB maximum frame. Large load runs need a larger
limit because one million 32-byte transactions produces a submit frame of
roughly 68 MiB before dispatch and peer delivery. `run-load.sh` sets
`BLOSSOM_MAX_FRAME_SIZE=1073741824` by default. Override it when you want to
test a lower or higher ceiling. Frame and raw-dispatch limits are read once at
process startup, so set these environment variables before launching the
benchmark or node process.

`BLOSSOM_HOT_WIRE_CODEC=1` opts outgoing TCP submit-block, send-block, and
dispatch frames into the experimental BLSM v1 codec. Decoders accept both Borsh
and BLSM frames so mixed read-side tests stay compatible. Dispatch receivers can
authenticate the header and keep the block payload raw until consensus
verification actually needs it. In trusted mode the receiver now scans raw
dispatch payloads to validate block hashes, Merkle roots, epoch targeting, and
the signature-tree commitment without materializing owned block objects.
Submit/send-block still materialize owned blocks after parsing, but avoid
Borsh's generic collection overhead on large payloads.

The hot encoder preallocates exact frame sizes with checked length calculators
before writing payload bytes. That avoids large buffer growth copies during
million-transaction dispatches while preserving the same configured frame-size
limit.

`blossom-harness-bench` defaults to Tokio's multi-thread runtime. Use
`--runtime-flavor current-thread` to isolate the single-core path, or
`--runtime-worker-threads N` with the default multi-thread runtime to test a
fixed worker count. This is useful when separating protocol CPU cost from
scheduler churn in local TCP load profiles.

TCP client and server streams set `TCP_NODELAY` by default, which keeps small
control-plane responses from sitting behind Nagle delays while the hot wire path
is moving large frames.

`BLOSSOM_FRAME_WRITE_CHUNK_BYTES=N` makes encoded-frame writes use bounded
write slices without changing the wire format. The default writes the whole
frame slice and remains the compatibility baseline. Use this knob to profile
whether a host benefits from smaller write calls before adopting a true chunked
wire format.

Raw hot dispatches are still resource-bounded after authentication. The quorum
state rejects duplicate pending dispatches from the same `(sender, signature)`
and caps stored raw payload bytes with
`BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES` and
`BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER`. The defaults are 512 MiB
per quorum and 128 MiB per sender; raise them only for intentionally larger
trusted load tests.

`DELIVERY_MODE=all-peers` measures dispatch delivery to every peer in the
cluster. `DELIVERY_MODE=first-accepted` stops after the first accepting peer,
which is the default for `run-load.sh` so million-transaction runs profile one
successful peer hop without multiplying loopback traffic across the quorum.

`run-gossip.sh` uses the real TCP harness to model filtered-payload
availability gossip. Node 0 submits filtered payloads, one signed metadata
gossip message is pushed through deterministic fanout rounds until the cluster
is informed, and each authorized target fetches and stores its payload unless
`SKIP_FETCH=1` is set. Fetches are batched per target by default; set
`SINGLE_FETCH=1` to measure the older one-payload-per-request flow. The CSV
separates metadata wire bytes from payload-fetch wire bytes so the gossip
control plane and data plane can be analyzed independently.

Set `EXPECT_COMPLETE=1` to fail a gossip benchmark if metadata does not reach
all nodes or any target-authorized payload fetch is not delivered. Set
`DROP_GOSSIP_EVERY=N` to deterministically drop every Nth gossip send before
the TCP request is opened; this is intended for validation and failure probes,
not throughput reporting. `run-gossip-matrix.sh` always enables the completion
assertion, while `run-gossip-failures.sh` intentionally checks an incomplete
blackout scenario.

`run-chaos.sh` runs the separate `crates/blossom-sim` package, which depends on
the public Blossom crate and wraps the simulated TCP cluster with deterministic
fault injection. `LATENCY_MS` is applied as one-way delay before request write
and before response read; `JITTER_MS` adds deterministic per-request jitter to
each direction. `DROP_PPM`, `CONNECT_CRASH_PPM`, and `RESPONSE_CRASH_PPM` are
rates over one million attempts. `CHAOS_SEED` makes the same profile
reproducible. `PAYLOAD_BYTES` and `DATA_PATTERN` control the exact bytes sent
inside each node I/O request. Supported data patterns are `zero`,
`incrementing`, `alternating`, and `splitmix`. The CSV records successes,
failures, injected delay, dropped attempts, and connection-crash counts.

`run-sim-fuzz.sh` feeds deterministic raw TCP inputs into node I/O. It cycles
through valid pings, random framed payloads, zero-length frames, oversized
length prefixes, truncated payloads, and partial prefixes. The runner checks
that the node still answers health after the fuzz corpus. `FUZZ_SEED`,
`DATA_PATTERN`, and `MAX_PAYLOAD_BYTES` make the generated corpus reproducible
and controllable.

`run-epoch-chaos.sh` is the deterministic epoch-convergence path. It uses the
real Blossom block, hash, transaction, and topology primitives, then runs
message propagation through a TCP-like logical transport with
`LATENCY_MS`, `JITTER_MS`, `ROUND_TIMEOUT_MS`, `DROP_PPM`, `FUZZ_PPM`,
`SPIKE_PPM`, and `SPIKE_LATENCY_MS`. `ROUND_TIMEOUT_MS=0` is the default and
disables the round-latency cutoff, which lets the model exercise distance
without turning latency into packet loss. A positive `ROUND_TIMEOUT_MS` records
messages whose sampled latency exceeds the timeout as late and ignores them for
that round; a fuzzed message is treated as corrupted and discarded. The summary
CSV reports
`final_correct_nodes`, `final_incorrect_nodes`, `final_unique_epoch_hashes`,
and final canonical epoch hash/nonce. The per-epoch CSV shows where divergence
first appears. The stage-progress CSV emits one row per modeled protocol
checkpoint, including block formation, membership/topology selection, each
dispatch round, recovery rounds, reconciliation rounds, and finality, so a run
can be inspected by stage without reconstructing it from aggregate counters. The
Markdown bug log records replay details and convergence bug candidates.

`REPAIR_ROUNDS` enables restart catch-up in the epoch-chaos model. Each
incorrect node pings `REPAIR_FANOUT` deterministic random peers, receives only
their epoch hash/nonce summary, and adopts a state only after
`REPAIR_QUORUM` matching summaries. A quorum value of `0` means the Blossom
network supermajority for the configured node count; a fanout value of `0`
means all known peers. After the handshake quorum forms, the node performs one
modeled catch-up fetch from a peer in that quorum; that fetch is also subject
to latency, drops, fuzzing, spikes, and `REPAIR_TIMEOUT_MS`. If no certified
summary quorum exists, the model falls back to block-set reconciliation: nodes
gather validator-signed source blocks for the contested parent and nonce across
repair rounds, then rebuild the canonical epoch once the deterministic source
set is available. Set `REQUIRE_RECONCILIATION=1` to make the runner fail
nonzero unless the run exercises at least one divergent epoch, executes
reconciliation rounds, and finishes every divergent epoch with all nodes on one
canonical hash. Set `OBSERVER_ADDR=host:port` to export per-node stage spans to
a running `blossom-observer` service while the epoch-chaos run executes.

`run-sim-hermetic.sh` is the hermetic path. It does not open sockets and does not use
wall-clock sleeps. Instead it runs virtual nodes through a deterministic event
queue with logical time. `SLOW_NODES`, `SLOW_AT_MS`, and `SLOW_LATENCY_MS`
change inbound latency for a collection of nodes; `DOWN_NODES`, `DOWN_AT_MS`,
and `UP_AT_MS` simulate nodes leaving and returning. `RESTART_AFTER_MS`
schedules a deterministic auto-restart for each down node at
`DOWN_AT_MS + RESTART_AFTER_MS` when `UP_AT_MS` is not set. `SIM_SEED`,
`JITTER_MS`, and `DROP_PPM` control repeatable scheduler jitter and request
drops. The runner writes a summary CSV, an event-log CSV, and a Markdown bug log
so a bug can be reproduced from the same seed and scenario. The bug log includes
the exact replay command, the fault plan, aggregate counters, and grouped bug
candidates for protocol errors, unexpected drops, unavailable nodes, accounting
mismatches, and requests that exceed `BUG_LATENCY_BUDGET_MS` when that budget is
set.

`run-sim-container.sh` can use `SIM_BACKEND=docker`, `SIM_BACKEND=native`, or
the default `SIM_BACKEND=auto`. The Docker backend builds
`crates/blossom-sim/container/Dockerfile` and runs one of the same simulation modes
(`sim`, `chaos`, `fuzz`, or `all`) in a contained runtime. By default the
container runs with `--network none`, `--read-only`, `--cap-drop ALL`,
`--security-opt no-new-privileges`, and a `/tmp` tmpfs. This is not a full
hardware VM, but it gives the simulator a VM-like boundary: no external network path,
no writable source tree, no ambient Linux capabilities, and a single mounted
results directory. Set `MEMORY`, `CPUS`, or `SERVER_CPUSET` to constrain
resources, `BLOSSOM_SIM_FEATURES` to build crate features into the image, and
`DRY_RUN=1` to print the Docker commands without executing them.

The native backend exists for machines where Docker is unavailable. It is
fully appropriate for `sim`, because the hermetic simulator never opens sockets
and uses logical time instead of wall-clock sleeps. Native `chaos` and `fuzz`
are intentionally blocked by default because they use real loopback TCP; set
`ALLOW_NATIVE_TCP=1` only when you explicitly want to run those without OS
containment.

`run-epoch-depth.sh` is intentionally in-memory. It models the paper's epoch
shape before transport costs are introduced: every node creates one capped
block, every quorum round performs a union of peer block sets, and convergence
means all nodes finish the epoch with the same ordered block set. `EPOCH_DEPTH`
measures consecutive epochs; `TARGET_TRANSACTIONS` derives the required depth
from `NODES * TXS_PER_NODE`.

`APP_STATE_BYTES` adds an opaque per-block application-state payload to
measure the cost of piggy-backed coordination data. Blossom's default hard
limit is 8 KiB per block.

With `--trusted`, `blossom-epoch-bench` still computes the same deterministic
quorum unions, but it seals blocks without Ed25519 signatures and counts only
dispatch fanout for each quorum. This models a private deployment where
membership is known out of band and consensus can skip echo, verification,
proposal, and commit traffic.

With `--trusted`, `blossom-harness-bench` spawns trusted TCP nodes and seals the
submitted benchmark block without Ed25519 work. It still uses the same address
book, block-service registration, frame limits, dispatch delivery, duplicate
dispatch checks, and raw hot-dispatch caps.

The `external-transaction-hashes` feature enables
`Transaction::from_external_hash` and `Transaction::from_external_hash_u64`.
This is meant for systems such as fast-cache/FCNP, where every key already has
a stable `u64` XXH3 `hash_key`. In that mode Blossom skips the per-transaction
payload hash and commits to the supplied transaction id plus the ordered
transaction bytes at the block level. The Merkle root is then over external
application ids, not Blossom-computed payload hashes.

The `insecure-fast-hash` feature is deliberately separate from `--trusted`.
It swaps SHA-256 protocol commitments for XXH3 so benchmark runs can isolate
hash cost from signature and message-pattern cost. Treat results from that
feature as trusted-environment throughput numbers, not verified-protocol
security numbers.
