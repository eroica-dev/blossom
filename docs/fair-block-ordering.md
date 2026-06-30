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

The raw block hash remains the signed block identity. Validators still verify
the block hash, Merkle root, transaction commitments, and block signature before
the block enters the accepted set. The fair-order key is only the final
epoch-ordering commitment.

This prevents a participant from knowing its final tree position by simply
constructing a lower raw block hash. The final order depends on all accepted
block bytes and the aggregate transaction count, so the ordering seed is not
known from any one participant's local block alone.

Applications that execute ledger-style transactions should consume epoch blocks
through `EpochBody::fair_ordered_blocks()` instead of iterating the raw
`BTreeMap<HashType, Block>` directly.

This is not a mempool fairness system, encrypted order flow, or MEV auction.
Applications that need those properties still need application-layer rules for
transaction admission, validity, and economic policy.
