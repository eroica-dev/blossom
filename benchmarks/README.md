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

Run a paper-aligned epoch-depth benchmark:

```bash
EPOCH_DEPTH=3 NODES=36 TXS_PER_NODE=1000 TX_BYTES=32 \
  ./benchmarks/scripts/run-epoch-depth.sh
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
`1` without relying on hidden state reset.

Use at least six nodes when the benchmark needs accepted peer delivery; six is
the current Blossom quorum size.

Harness CSVs include the exact Borsh frame sizes counted for each phase:
`register_wire_bytes`, `next_nonce_wire_bytes`, `submit_wire_bytes`,
`dispatch_wire_bytes`, `deliver_wire_bytes`, and `total_wire_bytes`. They also
record `tx_payload_bytes` and `block_bytes`, so a run can distinguish raw
transaction payload from protocol overhead.

The runtime defaults to a 32 MiB maximum frame. Large load runs need a larger
limit because one million 32-byte transactions produces a submit frame of
roughly 68 MiB before dispatch and peer delivery. `run-load.sh` sets
`BLOSSOM_MAX_FRAME_SIZE=1073741824` by default. Override it when you want to
test a lower or higher ceiling.

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
