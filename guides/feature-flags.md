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
| `insecure-fast-hash` | no | Replace SHA-256 protocol commitments with XXH3 for trusted/performance experiments only. |

Trustless deployments should keep `fair-block-ordering` enabled and should not
use `insecure-fast-hash`.
