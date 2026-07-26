# Blossom

Blossom is a Rust implementation of the Blossom v2 consensus protocol: a
deterministic quorum protocol for distributing node-local blocks, committing the
same epoch view on every correct node, and testing that behavior under latency,
faults, and Byzantine pressure.

Current release: `2.0.0-pre-release`.

Minimum supported Rust version: `1.90`.

Whitepaper: [Blossom Consensus Protocol v2](Blossom-Consensus-Protocol-v2-Whitepaper.pdf).

## What Is Included

- Protocol core for blocks, deterministic quorums, messages, membership, and
  finality.
- TCP node surface, service clients, local block intake, and restart/catch-up
  primitives.
- v2 prefill dispatch, recovery, reconciliation, fair block ordering, and
  trusted/trustless execution paths.
- Durable active-active admission and ordered-application APIs for embedding
  directly in storage and streaming services.
- A separate trusted, fixed-membership HA protocol for leaderless active-active
  replication across 2–7 nodes.
- Global trusted checkpoint-DAG and parallel-network APIs for coordinating
  state across independent HA groups without merging their memberships.
- A revision-pinned integration with the reusable deterministic-simulation
  framework, product-owned protocol fault adapters, OpenRaft comparison
  harness, profiling, and telemetry observer crates.

Blossom is not a turnkey blockchain, database, wallet, public discovery network,
or validator marketplace. Applications own their transaction bytes and domain
semantics.

## Start Here

- [Quick Start](guides/quick-start.md)
- [Protocol Overview](guides/protocol-overview.md)
- [Feature Flags](guides/feature-flags.md)
- [Operations](guides/operations.md)
- [Observability](guides/observability.md)
- [Testing And Validation](guides/testing-and-validation.md)
- [Deterministic Verification Sandbox](guides/deterministic-sandbox.md)
- [Direct Active-Active Integration](guides/active-active-integration.md)
- [Trusted Network Durability and Recovery](guides/trusted-network-durability.md)
- [Small-Cluster High Availability](guides/high-availability.md)
- [Parallel HA and Global Blossom Networks](guides/parallel-ha-global-blossom.md)

## Workspace

| Crate | Purpose |
| --- | --- |
| `blossom` | Protocol core, runtime, TCP node, wire protocol, blocks, membership, telemetry events, and benchmarks. |
| `blossom-bench-harness` | Shared command model and correctness-gated Blossom HA/OpenRaft comparison harness. |
| `blossom-propagation` | Feature-gated push, inventory, and adaptive propagation policy primitives. |
| `blossom-sim` | Deterministic Blossom simulation environment for epochs, faults, churn, reconnects, and profiling. |
| `blossom-observer` | Telemetry collector and analyzer for multi-node stage/span health. |
| `deterministic-test-env` | Compatibility facade over the pinned shared deterministic-simulation core API. |

## Release Status

`2.0.0-pre-release` is public pre-release protocol software. The core protocol
paths are covered by unit tests, TCP end-to-end tests, deterministic
simulations, formal threshold checks, and release-gate validation.

Stable public trustless deployments still require independent security review,
deployment-specific key management, monitoring, public-join abuse controls, and
multi-host soak testing.
