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

Run a paper-aligned epoch-depth benchmark:

```bash
EPOCH_DEPTH=3 NODES=36 TXS_PER_NODE=1000 TX_BYTES=32 \
  ./benchmarks/scripts/run-epoch-depth.sh
```

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

`BLOSSOM_HOT_WIRE_CODEC=1` opts outgoing TCP dispatch frames into the
experimental BLSM v1 codec. Decoders accept both Borsh and BLSM frames so mixed
read-side tests stay compatible, and explicit hot helpers still exist for
block-frame microbenchmarks. Runtime writers keep submit/send-block on Borsh
because those paths must materialize owned blocks today; BLSM is selected for
dispatch where receivers can authenticate the header and keep the block payload
raw until consensus verification actually needs it.

The hot encoder preallocates exact frame sizes with checked length calculators
before writing payload bytes. That avoids large buffer growth copies during
million-transaction dispatches while preserving the same configured frame-size
limit.

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
