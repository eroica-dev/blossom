# Fair Block Ordering

Financial and exchange-like applications should not derive execution priority
from raw block hashes. If the final epoch tree sorts directly by `Block.hash`, a
participant can grind transaction bytes until its block receives a lower hash
than competing blocks.

Blossom now derives the epoch block tree from fair-order commitments:

1. Count every transaction across the accepted block set for the consensus
   stage.
2. Build a domain-separated seed by walking every canonical block byte and
   mixing each byte with `byte_index mod total_transaction_count`.
3. Derive one fair-order key per block from the seed, total transaction count,
   raw block hash, validator key, and per-block transaction count.
4. Sort final block commitments by those fair-order keys, using raw block hash
   only as a deterministic tie-breaker.
5. Commit those ordered fair keys into the epoch Merkle root.

This behavior is behind the `fair-block-ordering` compile-time feature:

```sh
cargo build --features fair-block-ordering
```

Every validator in the same network must be compiled with the same ordering
feature set. Builds that enable fair ordering advertise a different protocol
hash profile, for example `sha256+fair-block-ordering`, so health and ping
compatibility checks can reject mixed raw-order/fair-order fleets before they
try to agree on an epoch.

Consensus-affecting features also have stable numeric feature codes. The
profile is rendered as readable labels, but the canonical feature-code byte
sequence is:

```text
version: u8
feature_count: u16 big endian
feature_id[0]: u16 big endian
...
feature_id[n]: u16 big endian
```

Feature id `0x0000` is reserved. `fair-block-ordering` is feature id `0x0001`.
Feature ids are sorted in ascending order before profile construction. The
format leaves 65,535 usable feature ids overall, 65,534 future feature ids after
fair ordering, and up to 65,535 active features in one encoded profile. The
readable profile remains intentionally human-friendly, for example
`sha256+fair-block-ordering`, while the byte-code profile gives future
extensions a compact deterministic compatibility namespace.

Each consensus-affecting feature is also registered in the protocol feature
registry with a stable feature id and label, dependency ids, conflict ids, and
the consensus surface touched by the feature. The compiled feature profile is
validated before its byte-code sequence is emitted. This rejects reserved ids,
duplicate ids, unregistered ids, mismatched labels, missing dependencies,
conflicts, and non-ascending feature lists.

A combination of independent features is represented by the sorted set of
feature ids. A combination needs its own feature id only when the combined
behavior is a new consensus rule rather than the independent composition of the
two features.

The raw block hash remains the signed block identity. Validators still verify
the block hash, Merkle root, transaction commitments, and block signature before
the block enters the accepted set. The fair-order key is only the final
epoch-ordering commitment. The final order is signed off through the normal
epoch hash: the epoch body commits the fair-order Merkle root, and validators
sign that epoch hash once consensus reaches the accepted block set.

This prevents a participant from knowing its final tree position by simply
constructing a lower raw block hash. The final order depends on all accepted
block bytes and the aggregate transaction count, so the ordering seed is not
known from any one participant's local block alone.

Applications that execute ledger-style transactions should consume epoch blocks
through `EpochBody::ordered_blocks()`. With `fair-block-ordering` enabled this
returns fair-order sequence; without the feature it returns the historical raw
block-hash sequence. Applications that require fair ordering should compile
with the feature and can call `EpochBody::fair_ordered_blocks()` directly.

## Validation

The fair-order seed path streams canonical block bytes directly into the modulo
hasher instead of allocating one encoded block buffer per block. Regression
tests compare the streaming transcript against the previous materialized byte
transcript and repeatedly compute the same accepted block set from multiple
threads to catch hidden ordering or shared-state bugs.

Local Criterion measurements for `cargo bench --bench protocol --features
fair-block-ordering fair_block_ordering -- --warm-up-time 1 --measurement-time 2
--sample-size 10`:

| Blocks | Transactions | Raw leaf hash | Fair seed | Fair commitments |
| ---: | ---: | ---: | ---: | ---: |
| 6 | 1,536 | 0.49 us | 1.87 ms | 1.86 ms |
| 36 | 4,608 | 2.29 us | 5.66 ms | 5.89 ms |
| 216 | 13,824 | 12.81 us | 18.18 ms | 17.68 ms |

The modulo fair-order path is intentionally much more expensive than raw
block-hash ordering because it commits the accepted block byte field into a
global transaction-count residue stream. In practice this is an epoch-finality
cost, not a per-message or per-transaction hot-path cost.

This is not a mempool fairness system, encrypted order flow, or MEV auction.
Applications that need those properties still need application-layer rules for
transaction admission, validity, and economic policy.
