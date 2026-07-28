# Blossom

Blossom is a Rust implementation of the Blossom v2 consensus protocol: a
deterministic quorum protocol for distributing node-local blocks, committing the
same epoch view on every correct node, and testing that behavior under latency,
faults, and Byzantine pressure.

Current release: `2.0.0`.

Minimum supported Rust version: `1.93`. This applies to the full workspace,
including the HA adapter and benchmark bridge.

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
- Native OpenRaft active-passive replication with opaque application
  commands/results, linearizable-read barriers, learners, joint-consensus
  cutover, snapshots, and an embedded ShardLog store.
- Global trusted checkpoint-DAG and parallel-network APIs for coordinating
  state across independent HA groups without merging their memberships.
- Feature-gated full-push, inventory, and adaptive data-plane propagation
  policies.
- Active-active/OpenRaft comparison harness, formal verification, profiling,
  and telemetry observer crates. Authoritative simulation testing is maintained
  in [`eden-dev-inc/deterministic-simulation`](https://github.com/eden-dev-inc/deterministic-simulation).

Blossom is not a turnkey blockchain, database, wallet, public discovery network,
or validator marketplace. Applications own their transaction bytes and domain
semantics.

## Start Here

- [Quick Start](guides/quick-start.md)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)
- [Release Procedure](RELEASING.md)
- [Protocol Overview](guides/protocol-overview.md)
- [Code Organization and Maintenance](guides/code-organization.md)
- [Feature Flags](guides/feature-flags.md)
- [Operations](guides/operations.md)
- [Observability](guides/observability.md)
- [Testing And Validation](guides/testing-and-validation.md)
- [OpenRaft Production Testing](guides/openraft-production-testing.md)
- [Deterministic Verification Sandbox](guides/deterministic-sandbox.md)
- [Direct Active-Active Integration](guides/active-active-integration.md)
- [Embedded Blossom LogStore](guides/log-store.md)
- [Verified Membership and Discovery](guides/verified-membership-and-discovery.md)
- [Trusted Network Durability and Recovery](guides/trusted-network-durability.md)
- [Small-Cluster High Availability](guides/high-availability.md)
- [Parallel HA and Global Blossom Networks](guides/parallel-ha-global-blossom.md)

## Workspace

| Crate | Purpose |
| --- | --- |
| `blossom-consensus` (`blossom` in Rust) | Protocol core, runtime, TCP node, wire protocol, blocks, membership, telemetry events, and benchmarks. |
| `blossom-bench-harness` | Shared command model and correctness-gated Blossom HA/OpenRaft comparison harness. |
| `blossom-observer` | Telemetry collector and analyzer for multi-node stage/span health. |

Only `blossom-consensus` is published. The observer and benchmark harness are
repository tooling; protocol components and propagation strategies are selected
through the feature flags documented below.

## Release Status

`2.0.0` is the first public package release, including crash-safe
direct coordination between durable active-active lifecycle admission and
globally ordered application. The core protocol paths are covered by unit
tests, TCP end-to-end tests, externally owned deterministic simulations,
formal threshold checks, and release-gate validation. Verified 24-node and
36-node regressions require both a global certificate and publication by a
validator supermajority.

Stable public trustless deployments still require independent security review,
deployment-specific key management, monitoring, public-join abuse controls, and
multi-host soak testing.
