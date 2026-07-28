# blossom benchmarks

Performance benchmarks for Blossom protocol primitives and runtime behavior.
These are developer-facing benchmarks, separate from the correctness test
suite. Simulation benchmarks have moved to
[`eden-dev-inc/deterministic-simulation`](https://github.com/eden-dev-inc/deterministic-simulation).

The current trusted active-active critical path and its prioritized
1,000-plus-node optimization checklist are documented in
[`TRUSTED_PATH_OPTIMIZATION.md`](TRUSTED_PATH_OPTIMIZATION.md). Smoke benchmark
rows include non-overlapping per-stage timings under
`rows[].blossom.trusted_path`.

## Modes

| Mode | Driver | Question |
| --- | --- | --- |
| `criterion` | Rust Criterion microbenchmarks | How fast are core protocol operations in isolation? |
| `harness` | Local TCP simulation | How expensive is a full node scenario: spawn cluster, register block service, submit block, dispatch, deliver? |
| `harness-matrix` | Shell matrix over harness parameters | How does the full scenario change with node count and transaction count? |
| `load` | Large local TCP simulation | What happens when a block carries hundreds of thousands or millions of transactions, and how many framed bytes move? |
| `gossip` | Local TCP availability-gossip simulation | How many rounds, messages, bytes, and microseconds does filtered-payload gossip plus fetch take? |
| `epoch-depth` | In-memory protocol simulation | How do paper-aligned quorum rounds behave across consecutive epochs? |
| `active-active-matrix` | Safety manifest generator plus shared Blossom/OpenRaft harness | Which q=3k and 3/5/7-voter rows are safety-equivalent, and which are footprint-only scaling rows? |
| `ha-head-to-head` | Fixed-slot HA and OpenRaft protocol-core harness | How do leaderless active-active Blossom HA and leader-based active-passive Raft compare at 2–7 physical nodes? |

## Small-cluster HA versus OpenRaft

Run every supported two-through-seven-node footprint:

```bash
ITERATIONS=3 PAYLOAD_BYTES=256 \
  ./benchmarks/scripts/run-ha-head-to-head.sh
```

Set `WAIT_FOR_SEAL=1` to include Blossom's six-successor sealed visibility
latency. The harness uses all Blossom members as parallel writers. Raft uses
two voters at a two-node footprint, then 3/5/7 voters with learners filling
even footprints. Results are protocol-core diagnostics and remain explicitly
non-publishable until the full methodology gates are run.

## Active-active Blossom versus OpenRaft

Generate the accepted topology matrices and one safety manifest per row:

```bash
BLOSSOM_QUORUM_SIZE=6 cargo run -p blossom-bench-harness \
  --bin blossom-benchmark-matrix -- \
  --output benchmarks/manifests/active_active
```

Run the configurable-quorum properties, active-active Hegel suite, OpenRaft
storage/recovery harness, manifest generator, and available formal tools as one
gate:

```bash
BLOSSOM_QUORUM_SIZE=6 ./benchmarks/scripts/run-active-active-gates.sh
```

Exercise both implementations through `Applied` over the equal-fault rows:

```bash
ITERATIONS=3 MODE=equal-fault \
  ./benchmarks/scripts/run-active-active-smoke-matrix.sh
```

Use `MODE=equal-footprint BLOSSOM_QUORUM_SIZE=6` for the 6–72-machine topology
matrix. Smoke artifacts are always marked `publishable: false`: the command is
an executable integration and result-equivalence check, not a substitute for
the full repetition, steady-state, fault, or confidence-interval gates. It
uses native TCP for Blossom and OpenRaft's in-process network, while giving
both protocols embedded shard-stream storage; those transport timings are
therefore diagnostic and are not a scored comparison.

The shared harness pins OpenRaft 0.9.24 and an exact shard-stream revision. It
uses the same command/result model for Blossom and OpenRaft, records milestone
events separately, checks conflicting histories independently for
linearizability, and implements hierarchical bootstrap resampling over runs
and one-second blocks.

`benchmarks/manifests/active_active/matrix.json` is configuration evidence, not
a performance result. A performance row is publishable only after twelve paired
AB/BA repetitions, five minutes of steady state, at least 100,000 `Applied`
samples, and all safety, history, durability, replay, and recovery gates pass.
Validate a completed result bundle with:

```bash
cargo run -p blossom-bench-harness --bin blossom-benchmark-gate -- \
  --artifact path/to/performance-artifact.json
```

The gate also requires non-empty raw milestone events, histories, environment
and configuration snapshots, safety manifests, fault traces, dependency
versions, and a summary report. Durable OpenRaft profiles use separate
`BlossomLogStore` directories for votes/log entries and for state-machine
application/snapshots; the kill/restart path reconstructs a new OpenRaft node
from that persisted state.

## Commands

Run the Criterion microbenchmarks:

```bash
./benchmarks/scripts/run-criterion.sh
```

Run the embedded persistence benchmark (durable commit latency, materialized
reads, checkpointing, and replay):

```bash
cargo bench --bench log_store
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

Simulation chaos, fuzzing, hermetic profiling, container, and node/core matrix
commands now live under `deterministic-simulation/scripts/blossom/`.

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
`3`, `6`, `9`, and `12` with `q*q` nodes, trusted and trustless paths, and both
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

The full option and artifact contracts for the migrated simulation benchmark
scripts are documented beside them in the deterministic-simulation repository.

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
