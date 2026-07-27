# Feature Flags

| Feature | Default | Use |
| --- | ---: | --- |
| `fair-block-ordering` | yes | Default trustless fair epoch block ordering for ledger-style execution. |
| `filtered-transactions` | no | Commit canonical filtered slots while allowing target nodes to keep full payloads and non-targets to keep tombstones. |
| `availability-gossip` | no | Gossip and fetch filtered payload availability. Enables `filtered-transactions`. |
| `external-transaction-hashes` | no | Allow applications to provide stable transaction ids while payload bytes remain block-committed. |
| `propagation-push` | no | Enable latency-first full-block push planning. |
| `propagation-inventory` | no | Enable inventory-then-missing planning for bandwidth-sensitive propagation. |
| `propagation-adaptive` | no | Enable adaptive propagation policy selection. |
| `high-availability` | no | Enable trusted, fixed-slot, leaderless active-active replication for 2–7 fixed node identities. |
| `active-passive` | no | Enable native OpenRaft leader-based active-passive replication and its ShardLog-backed Raft log adapter. Enables `high-availability`. |
| `trusted-checkpoint-dag` | no | Experiment with append-only DAG dissemination under Global Blossom's sequential quorum ordering. Global Blossom requires at least six logical members. |
| `parallel-networks` | no | Enable application-level coordination records between independent HA and Global Blossom networks. Enables `high-availability` and `trusted-checkpoint-dag`. |
| `telemetry` | no | Register bounded Blossom metrics and protocol spans with a service-owned `fast-telemetry` runtime. |
| `eden-logger` | no | Convert Blossom protocol, health, recovery, and failure events into structured internal `eden-logger` records. |
| `observability` | no | Enable both `telemetry` and `eden-logger` adapters. |
| `insecure-fast-hash` | no | Replace SHA-256 protocol commitments with XXH3 for trusted/performance experiments only. |

Trustless deployments should keep `fair-block-ordering` enabled and should not
use `insecure-fast-hash`.

`high-availability` is a separate trusted wire and state profile. It does not
consult `BLOSSOM_QUORUM_SIZE`, and it does not provide Byzantine or Sybil
protection. `active-passive` adds Blossom's pinned OpenRaft implementation;
applications still provide their authenticated RPC transport and application
state machine.

`parallel-networks` does not merge either protocol's membership or quorum. It
only allows sealed HA state references to be ordered as application records by
an independent Global Blossom network.

The observability features do not install global exporters or logger state.
Embedding services own that setup and pass a composed `TelemetryHandle` to
Blossom. See [Observability](observability.md).
