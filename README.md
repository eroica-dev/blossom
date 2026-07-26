# Blossom

Blossom is a Rust implementation of the Blossom v2 consensus protocol: a
deterministic quorum protocol for distributing node-local blocks, committing the
same epoch view on every correct node, and testing that behavior under latency,
faults, and Byzantine pressure.

Current release: `2.0.0-pre-release`.

Whitepaper: [Blossom Consensus Protocol v2](Blossom-Consensus-Protocol-v2-Whitepaper.pdf).

## What Is Included

- Protocol core for blocks, deterministic quorums, messages, membership, and
  finality.
- TCP node surface, service clients, local block intake, and restart/catch-up
  primitives.
- v2 prefill dispatch, recovery, reconciliation, fair block ordering, and
  trusted/trustless execution paths.
- Deterministic simulation, fault injection, profiling, and telemetry observer
  crates.

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
- [Direct Active-Active Integration](guides/active-active-integration.md)
- [Trusted Network Durability and Recovery](guides/trusted-network-durability.md)
- [Small-Cluster High Availability](guides/high-availability.md)
- [Parallel HA and Global Blossom Networks](guides/parallel-ha-global-blossom.md)

## Workspace

| Crate | Purpose |
| --- | --- |
| `blossom` | Protocol core, runtime, TCP node, wire protocol, blocks, membership, telemetry events, and benchmarks. |
| `blossom-propagation` | Feature-gated push, inventory, and adaptive propagation policy primitives. |
| `blossom-sim` | Deterministic Blossom simulation environment for epochs, faults, churn, reconnects, and profiling. |
| `blossom-observer` | Telemetry collector and analyzer for multi-node stage/span health. |
| `deterministic-test-env` | Generic deterministic network, CPU, hardware-fault, and replay primitives used by the simulator. |

## Release Status

`2.0.0-pre-release` is public pre-release protocol software. The core protocol
paths are covered by unit tests, TCP end-to-end tests, deterministic
simulations, formal threshold checks, and release-gate validation.

Stable public trustless deployments still require independent security review,
deployment-specific key management, monitoring, public-join abuse controls, and
multi-host soak testing.
