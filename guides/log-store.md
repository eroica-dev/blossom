# Embedded Blossom LogStore

`BlossomLogStore` is Blossom's public transactional persistence surface. It
uses the embedded `shardlog::ShardLog` crate, materializes named ordered byte
tables in memory, and serializes durable writes. A successful transaction is
visible only after its complete extent group has reached `sync_data()`.

## Identity and directories

Open a store with `BlossomLogStoreConfig` and a
`BlossomLogStoreIdentity`. The identity contains only:

- format version 1;
- a public store kind;
- public scope bytes;
- a generation.

Signing material is not accepted by the identity API. Every independently
recoverable subsystem must use its own directory and public scope. A directory
has one exclusive process owner. Opening it with another identity fails
closed. A legacy database file is an explicit reset/recovery boundary and is
never overwritten.

## Transactions

`transaction` provides serializable reads and staged writes over named ordered
tables. The closure can get or scan values, insert and remove keys, remove an
ordered range, or clear a table. Returning an error aborts without changing
durable or materialized state.

Successful writes are encoded as versioned chunks followed by a hash-committed
marker. Recovery applies a complete transaction or none of it. A complete
chunk-only crash tail is durably marked aborted before the store accepts
another write. If storage reports an ambiguous write or sync error, the handle
is poisoned and must be reopened. Callers should use their protocol command
identity or deduplication key to resolve the possible complete transaction
after recovery.

Names, keys, values, transactions, chunks, and checkpoints are bounded before
durable mutation. Reads use immutable in-memory values. Async integrations
should perform `transaction`, `checkpoint`, `replace_from_checkpoint`, and
`shutdown` on a blocking durability worker rather than a Tokio worker thread.

## Checkpoints

`checkpoint` writes the full materialized table state, identity, revision, and
state hash as a committed chunk group. Only after that marker is durable may
sealed packs older than the checkpoint be garbage-collected. Cleanup failures
do not invalidate the checkpoint; retained history is safe to retry.

Automatic checkpoints run after configurable transaction or byte thresholds.
`replace_from_checkpoint` verifies the public identity before atomically
installing a snapshot. `durability_metrics` reports transactions, fsyncs,
bytes, checkpoints, and replayed transactions. Call `shutdown` during an
orderly service stop.

Protocol history compaction remains separate. For example, an HA certified
history checkpoint decides which consensus evidence may be pruned;
`BlossomLogStore::checkpoint` only compacts that subsystem's local
representation.

## Active-passive application state

`ShardStreamRaftLogStore` uses `BlossomLogStore` for OpenRaft votes, committed
and purged metadata, and indexed entries. The active-passive application state
machine remains application-defined.

An application may open a second `BlossomLogStore` directory and atomically
persist its applied log ID, membership, domain mutation, opaque result,
deduplication record, active contract, and snapshots in one transaction. The
Raft log and application store must not share a directory or identity scope.
