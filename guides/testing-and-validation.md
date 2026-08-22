# Testing And Validation

## Release Gate

```sh
scripts/release-gate.sh
```

The release gate runs:

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo test --workspace --all-features`
- `cargo test -p blossom-consensus --no-default-features`
- standalone `active-passive` compile check
- `cargo test -p blossom-consensus --features insecure-fast-hash`
- standalone `telemetry`, `eden-logger`, and combined
  `observability,high-availability,trusted-checkpoint-dag` compile checks
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`
- `scripts/active-passive-production-validation.sh`
- `scripts/trusted-production-validation.sh`
- `scripts/ha-production-validation.sh`
- `verification/run-formal.sh`

The GitHub Actions workflow `HA Merge Gate` runs this complete command on every
pull request and push to `main`. Repository branch protection must require its
`Release and HA production gate` job.

Authoritative Blossom simulation gates run in
[`eden-dev-inc/deterministic-simulation`](https://github.com/eden-dev-inc/deterministic-simulation)
against a full pinned Blossom revision. That repository owns the adapter,
profiles, fault campaigns, VM specifications, and regression corpus.

## Production Validation

```sh
scripts/production-validation.sh
```

This runs the broader non-simulation protocol validation matrix, including TCP
finality and proof-validation throughput workloads.

The trusted-network gate includes immediate-durability ENOSPC/fsync fault
injection, crash/restart recovery, quorum-intersection and dispatch-mask
properties, and atomic multi-reference finalization. It also verifies that
parallel HA/Global Blossom coordination never merges memberships or quorum
votes:

```sh
scripts/trusted-production-validation.sh
```

The native benchmark adapter has explicit multi-epoch lifecycle regressions.
Its manual TCP driver is target bounded: after a node finalizes the requested
nonce, later manual ticks for that nonce must not advance it into empty
epochs, and an in-flight tick stops when finality changes its captured target.
Exact dispatch replay is idempotent while a conflicting replay is rejected.
A cluster-wide prefill wave is followed by a second activation-barrier pass,
covering validators whose last required dispatch arrived after their own
broadcast task checked the barrier. The native finality timeout is an
inactivity bound: signed round progress refreshes it, while an actually stalled
round still fails with per-node consensus, prefill, dissemination, and traffic
diagnostics.
A validator may acknowledge or confirm only after its complete current-round
dispatch set is present; validators in earlier hierarchy rounds continue
dispatching independently. The active-active regression executes 16
consecutive universal-writer epochs through admission, availability, ordering,
application, and all-node convergence. These tests protect against
schedule-sensitive validator drift and conflicting trusted epoch hashes that
one-epoch smoke tests cannot observe:

```sh
cargo test -p blossom-bench-harness \
  blossom_adapter::tests::manual_driver_never_advances_beyond_the_requested_epoch
cargo test -p blossom-bench-harness \
  blossom_adapter::tests::active_active_cluster_remains_bounded_across_many_epochs
```

The external native scale gate additionally requires a supermajority of
validators to publish the same globally certified epoch at 24 and 36 nodes.
The product TCP helper and benchmark adapter enforce the same threshold and
validate the exact-hash certificate against the previous verifier set. These
regressions cover final-share collection, authenticated newer-head hints,
per-recipient hint retries, exact dispatch replay after transient rejection,
exact prefill replay and writer-payload inclusion, certified-suffix
installation, and bounded manual-driver dissemination.

The request-driven TCP regression uses the production combination of
event-driven wakeups and the local-pending-block gate for 3-, 5-, and
7-validator committees. It requires every validator to install the same
certified epoch, then proves idle ticks do not dispatch a follow-on empty epoch.
This distinguishes quorum request completion from eventual all-member recovery.

The focused HA gate also includes 1,001+ epoch durability tests, authenticated
subprocess kill/restart, ENOSPC and fsync atomicity, and Hegel properties:

```sh
scripts/ha-production-validation.sh
```

The active-passive gate runs the native OpenRaft election, contract-fence,
learner, joint-consensus replacement, failover, and read-barrier integration
test. It also runs message-aware request loss, response loss, duplication,
delay, election, membership-change, and durable snapshot scenarios. Every
scripted fault has a stable ID and must appear in the executed-fault coverage;
a configured fault that never reaches a matching RPC fails the gate.

The gate then performs 1,001 opaque writes while repeatedly killing and
restarting leaders and followers against the shipped ShardLog-backed log:

```sh
scripts/active-passive-production-validation.sh
```

The standalone multi-core campaign runner has `pr`, `nightly`, and `release`
profiles:

```sh
scripts/openraft-production-campaign.sh pr
BLOSSOM_RAFT_JOBS=16 scripts/openraft-production-campaign.sh nightly
```

Its report fails admission on any observed process or Tokio task panic, even
when the final state converges. The report explicitly records deterministic
inputs with `exact_task_schedule_replay=false`; native Tokio scheduling is not
an exact replay guarantee.

See [OpenRaft Production Testing](openraft-production-testing.md) for profile
sizes, custom fault selection, artifacts, coverage admission, and the boundary
between repeatable native runs and exact simulation replay.

## Benchmarks

Product benchmark entry points live under `benchmarks/scripts/`.

Useful starting points:

```sh
benchmarks/scripts/run-prefill-head-to-head.sh
benchmarks/scripts/run-proof-validation-matrix.sh
```
## Deterministic protocol exploration

The simulation repository owns `blossom-sim`, the protocol-v1 process adapter,
PR/nightly/release profiles, deterministic fault and recovery models, VM tiers,
and minimized regression scenarios. See
[Deterministic Verification Sandbox](deterministic-sandbox.md) for the
ownership boundary and canonical commands.
