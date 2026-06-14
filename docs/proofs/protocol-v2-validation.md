# Protocol V2 Validation

This note records the latest v1/v2 validation pass for subset block propagation
and prefill dispatch. It documents simulator-backed protocol evidence, not a
claim that the deployable TCP node currently runs every consensus stage
autonomously in production.

## Run Artifacts

- Main comparison: `benchmarks/results/v2_v1_validation_20260522_0350`
- Route-withholder safety: `benchmarks/results/prefill_safety_validation_20260522_0340`
- Frontier targeted safety: `benchmarks/results/prefill_frontier_targeted_20260523_053309`
- q6 performance spot check: `benchmarks/results/prefill_perf_spot_20260523_053856`
- Post-removal smoke: `benchmarks/results/prefill_frontier_targeted_smoke_current3`
- Post-removal safety smoke: `benchmarks/results/prefill_safety_smoke_current2`
- Comparison CSV: `subset_gossip_v2_vs_v1.csv`
- Safety manifest: `prefill_safety_manifest.csv`

Both matrices were run on `adam` with `q = 6`, three repeats, 50 epochs per run,
256 commands per node, 1024-byte commands, verified and trusted modes in the
main comparison, and even/random latency profiles.

## Main Result

V2 is stronger on correctness for non-trivial targeted payload propagation:

- 10,800 modeled v1/v2 epochs completed.
- 216/216 run groups completed after their configured correctness gate.
- For all target fanouts greater than one, v2 delivered target payloads before
  repair in 24/24 comparison groups.
- In those same groups, v1 needed repair, with missing-before-repair rates up to
  52.56%.

V2 is also faster on finality/throughput:

- Across all 36 comparison groups, v2 reduced modeled payload-ready latency by
  45.53% on average.
- For target fanouts greater than one, v2 reduced modeled payload-ready latency
  by 49.25% on average and improved modeled TPS by 97.42% on average.
- For 36- and 64-node target fanouts greater than one, v2 passed both the safety
  and performance claim in 16/16 groups.

Bandwidth is workload-dependent:

- For 36- and 64-node target fanouts greater than one, v2 reduced wire by 33.64%
  on average, with a minimum reduction of 9.72%.
- For very small 12-node sparse workloads, v2 can use more wire than v1 because
  the one-hop prefill stage is proportionally large. This is a real tradeoff,
  not a correctness issue.

## Future-Quorum Withholder Safety

The withholder matrix covers the trustless concern that a scheduled holder may
have data but refuse to forward it later.

- 1,800 modeled v2 withholder epochs completed.
- 36/36 positive withholder run groups completed without repair.
- The unsafe no-prefill-coverage negative control failed as expected.
- The matrix includes `n = 36`, `n = 64`, and `n = 72`, target fanouts 3 and 6,
  even/random latency, and one configured withholder per future quorum.

During validation, the first safety run exposed a real gap for `n = 64`: the
fast contact budget was using the truncated topology depth and selected too few
future contacts for one seed. The implementation now uses `ceil(log_q(n))` for
the prefill budget.

The 2026-05-23 frontier run was useful but is now superseded as a protocol
claim. That run modeled a configurable per-quorum holder multiplier; the
protocol no longer has that feature because it duplicates the role of quorum
membership and makes the safety claim ambiguous. Current prefill-dispatch
derives its contact set from the sender's deterministic future route frontier:

```text
R = ceil(log_q(n))
f = declared Byzantine withholders per branch
w = route width, equal to 1 with no declared withholders and f + 1 otherwise

prefill_fanout = min(n - 1, (q - 1) + q * w * (R - 1))
```

The no-withholder case is still the simple `qR - 1` rule. For trustless
withholder runs, the future route frontier widens to `f + 1` holders per active
branch so one live holder remains after the declared Byzantine withholders.
Byzantine withholding is still checked against the quorum fault model. The
implementation now fails closed for trustless prefill-dispatch when Byzantine
withholding is configured and either:

- `q < 5`, because the route is too narrow for the current prefill strategy.
- configured withholders exceed the quorum's tolerated Byzantine count.

This makes the current v2 claim cleaner: `q` is the redundancy dial, and route
width is derived from the declared Byzantine withholding bound. There is no
independent per-quorum multiplier to tune or misconfigure.

## 2026-05-23 Performance Spot Check

The Adam spot check used 36 nodes, `q = 6`, 100 epochs, 256 commands per node,
1024-byte commands, target fanout 3, and 150 ms even latency:

| mode | wire / epoch | payload-ready latency | modeled TPS | repair |
| --- | ---: | ---: | ---: | ---: |
| v1 trustless push | 93.117 MB | 1800 ms | 5,120 | 16.843 MB |
| v2 prefill, no withholding | 77.238 MB | 900 ms | 10,240 | 0 |

The important tradeoff is now explicit. V2 without Byzantine withholding is both
faster and lower-wire than v1. Trustless withholder performance should be read
from runs produced after the per-quorum multiplier removal because older
withholder spot checks included the superseded multiplier.

## Current Claim

The validated claim is:

```text
For q = 6 and the tested non-Byzantine or smaller withholder node sizes, v2
gives stronger correctness than v1 for targeted payload propagation because
target payloads are complete before repair. It also improves modeled finality
and TPS by replacing the old first consensus round with deterministic
future-quorum prefill. For larger trustless Byzantine deployments, the current
validated path is to increase q so the quorum itself carries the required fault
tolerance, or fail closed before execution.
```

That is a good result, but not a blanket statement that v2 is lower-bandwidth in
every possible workload. In particular, Byzantine withholding tolerance can
trade bandwidth for correctness.

## Public Readiness Notes

- The simulator and proof harnesses validate the prefill-dispatch safety and
  performance claims under the listed workloads.
- The runtime still exposes protocol intake and validation primitives rather
  than a complete autonomous production round driver.
- Trusted and trustless modes remain separate. `insecure-fast-hash` is a
  trusted/performance experiment and is not part of the verified default path.
