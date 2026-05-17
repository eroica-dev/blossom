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

## Commands

Run the Criterion microbenchmarks:

```bash
./benchmarks/scripts/run-criterion.sh
```

Run a single full harness benchmark:

```bash
ITERATIONS=10 NODES=6 TRANSACTIONS=3 ./benchmarks/scripts/run-harness.sh
```

Run a small matrix:

```bash
NODE_COUNTS="1 6 12" TRANSACTION_COUNTS="0 3 32" ITERATIONS=5 \
  ./benchmarks/scripts/run-harness-matrix.sh
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
