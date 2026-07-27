# Deterministic Verification Sandbox

All Blossom simulation testing is owned by
[`eden-dev-inc/deterministic-simulation`](https://github.com/eden-dev-inc/deterministic-simulation).
Blossom no longer vendors the framework or carries simulation crates, profiles,
adapters, campaign scripts, VM specifications, or deterministic regressions.

The simulation repository pins the exact Blossom commit under test and owns:

- the `blossom-sim` protocol, HA, trusted-DAG, recovery, chaos, and fuzz models;
- the `blossom/protocol-v1` process adapter;
- PR, nightly, and release profiles;
- Linux admission and evidence-retention gates;
- KVM and TCG guest specifications; and
- the minimized Blossom regression corpus.

From a Linux checkout of `deterministic-simulation`, run:

```sh
scripts/blossom/pr-gate.sh
scripts/blossom/run-campaign.sh nightly 1 7200
scripts/blossom/run-campaign.sh release 1 43200
```

The Blossom repository continues to own ordinary unit and integration tests,
TCP end-to-end tests, Hegel properties, OpenRaft comparison controls, formal
models, and production-code dynamic analysis. A new profile, simulated fault,
simulation container, VM test, or replay regression belongs in the simulation
repository.
