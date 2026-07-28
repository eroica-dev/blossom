# Direct Active-Active Integration

`shard-kv` and `shard-stream` should import Blossom as a library. There is no
bridge crate and Blossom does not own the application's network transport or
storage schema.

```toml
[dependencies]
blossom = { package = "blossom-consensus", version = "2.1.0" }
```

## Trusted-direct flow

For a trusted network, `shard-kv` and `shard-stream` can use the protocol
without the durable-reference engine:

1. Build one `Block` per member and place the application's opaque
   `Transaction` payloads in it.
2. Call `Block::seal_unsigned(writer_public_key)`.
3. Submit it to `NodeRuntime`/`TcpNode`. In production, configure
   `RuntimeConfig::with_trusted_epoch_log_path` so acceptance, confirmation locks,
   and epochs use ShardLog-backed `BlossomLogStore` transactions.
4. Blossom propagates blocks and broadcasts a monotonic acknowledgement after
   `N - floor(N / 3)` dispatches. A matching acknowledgement quorum permits
   one durable confirmation; a matching confirmation quorum advances the
   hierarchy or commits the BTree block-hash order at its final round. The
   durable log advances before the in-memory head or commit notification. A
   locally accepted writer block omitted by another valid quorum is atomically
   retargeted to the next epoch.
5. Read the committed `Epoch` from the runtime and call
   `Epoch::trusted_ordered_transactions()`.
6. Apply those payloads in the returned order and atomically persist the
   application's epoch/watermark.

There is no leader, proposer, signature, signed proposal/commit phase,
`OrderStatement`, or portable `OrderCertificate` on this path. Unsigned
acknowledgements and confirmations are authenticated by the trusted transport.
Confirmations act as crash-fault decisions. The epoch already binds the
previous epoch hash and nonce. Up to
`floor(N / 3)` members may be inactive; losing more stops progress until
recovery or an explicit membership transition.

## Durable-reference flow

Applications that need site-local acknowledgement before every member has the
payload can opt into the stronger asynchronous durable-reference flow:

1. Open a `DurableAdmissionStore` for every local holder with its site and store
   generation.
2. For compatibility, a single command can use
   `DurableAdmissionStore::admit` and `LocalAdmissionCertificate`. Production
   shard pipelines should use `admit_command_batch(shard, batch, epoch)` and
   combine the one signed receipt from each holder into a
   `LocalAdmissionBatchCertificate`. The certificate binds the shard id and
   canonical batch hash, so one signature covers every command without
   weakening local durability or equivocation detection.
3. Build a `CommandBatch` and cryptographic `BatchReference`, replicate the
   bytes, and collect `AuthenticatedAvailabilityReceipt` values. Reference
   format/codec v2 commits both `route_generation` and the application's
   `command_spec_version`; changing either changes the signed reference hash.
4. Verify and submit the resulting `AvailabilityCertificate` with
   `GlobalOrderedEngine::mark_available_with_batch`. This stores the exact
   certified batch bytes before availability can reach finality. Encode compact
   references with `BatchReference::to_transaction`. A trusted epoch may
   contain one reference from every active writer.
5. Once the Blossom epoch is finalized,
   `GlobalOrderedEngine::order_statement_for_finalized_epoch` deterministically
   derives its hash-chain position when the epoch carries a portable signature
   certificate. Trusted deployments call `finalize_trusted_epoch` after
   observing the epoch in their local committed chain; this installs every
   reference in BTree order without signatures or votes. The single-reference
   `order_statement_for_trusted_finalized_epoch` plus `finalize_trusted` API is
   retained for compatibility. Verified deployments collect `OrderVote`
   values, construct `OrderCertificate`, and call `GlobalOrderedEngine::finalize`.
6. Implement `OrderedApplication` and call
   `GlobalOrderedEngine::apply_contiguous_to` or `apply_through_to`.

The application owns transport. It sends command bytes and availability data
using its existing authenticated connections, then supplies the decoded
objects to these APIs. A production adapter must authenticate the remote node
identity, bind it to the expected cluster/group and membership generation, and
reject replayed session sequence numbers before passing a message to Blossom.
Mutual TLS or another service-owned authenticated channel may provide this
contract. An unauthenticated generic application connection is not a trusted
Blossom transport. Trusted ordering uses that verified connection identity and
unsigned receipts; portable signed order certificates are a verified-mode
concern.

`DurableAdmissionStore` persists its holder key, site, store generation, and
schema identity on first open. The first stored batch also binds the database
to its cluster and consensus group. Reopening with different identity or scope
fails closed, and pre-identity stores require fresh initialization.

### Sharded HA throughput path

Hashing, batch-certificate verification, and holder admission are shard-local.
Each shard worker should:

1. Build one contiguous `CommandBatch`.
2. Durably admit it on the shard's local holder stores and collect a
   `LocalAdmissionBatchCertificate`.
3. Call `verify_and_bind` and prepare a
   `PreparedActiveActiveHaShardBatch`.

The coordinator passes all ready shard batches to
`ActiveActiveGlobalCoordinator::accept_prepared_shard_batches`. Blossom commits
the combined lifecycle delta once, then
`GlobalOrderedEngine::accept_verified_local_command_batches` commits one
accepted-local milestone per shard batch once. Shard order is preserved inside
each batch; the later Blossom reference order remains the authority for
cross-shard conflicts. Route, command-spec, and membership cutovers remain
global barriers and must not be activated independently by a shard.

Do not put every shard in an independently flushed HA lifecycle database.
That multiplies `fsync` contention and loses the shared cutover boundary. The
intended layout is parallel shard preparation feeding one bounded group commit.

### Direct lifecycle and order coordination

Production integrations open both durable engines and construct
`ActiveActiveGlobalCoordinator`. Construction fails unless lifecycle state,
the HA runtime, ordered state, and application completions are all
production-durable. It also completes the recoverable half of a route/spec
cutover when the ordered store committed before a crash but the lifecycle store
did not.

For each accepted batch:

1. Call `accept_prepared_shard_batches`.
2. Replicate the command batches to holders and obtain availability evidence.
3. Call `mark_available(batch, certificate)` so local bytes precede
   availability.
4. Deliver verified or trusted finality through the coordinator's `finalize`
   or `finalize_trusted` method.
5. Call `complete_globally_applied(reference, batch, timeout, application)`.

The coordinator checks every command identity against the durable accepted-hash
index. It removes accepted lifecycle records only after the ordered store has
durably committed `Applied`. A timeout or crash leaves those records available
for idempotent retry. Application-contract cutovers must use the coordinator's
begin, recertify/abort, cancel, and activate methods; callers must not activate
the ordered and lifecycle engines independently.

## Apply contract

Blossom invokes `OrderedApplication::apply_ordered` in immutable certificate
order. The callback receives:

- The batch-reference hash.
- The complete committed reference.
- The verified command batch.
- The global watermark.

The pair `(reference_hash, watermark)` is a stable replay key. The application
must atomically persist this key with its KV or stream mutations. A process can
fail after the application transaction commits but before Blossom commits its
own LogStore transaction, so the callback is intentionally at-least-once
across crash recovery. Commands are opaque `ApplicationCommand` bytes. The callback
returns exactly one opaque `ApplicationResult` per command and owns all command
semantics, state, result encoding, and replay deduplication. Blossom validates
only byte bounds and result cardinality; it does not execute a second state
machine or compare application results with a built-in KV specification.

Blossom records `Applied` only after the callback succeeds and Blossom durably
commits the opaque results, finality-chain metadata, and milestone event.
`AppliedCompletion` is the explicit terminal result. `status(reference_hash)`
is an indexed bounded lookup, while `wait_for(reference_hash, milestone,
timeout)` always requires a timeout (capped at five minutes). The global-order
profile has no `Sealed` or `Converged` milestone; `Applied` is terminal.
`WriteMode::GlobalApplied` is the convenience write policy for this behavior:
`complete_write(reference_hash, WriteMode::GlobalApplied, timeout,
application)` drives contiguous application after finality is visible and
returns `Reached` only after the completion is durable. Callers that drive
application separately can use the equivalent bounded
`wait_for(reference_hash, Milestone::Applied, timeout)`.
Route or command-spec changes call `activate_application_contract` at a
quiescent boundary where every finalized reference is applied. The selected
generations are durable startup parameters and every subsequent reference must
commit them.

See
[`examples/active_active_application.rs`](../examples/active_active_application.rs)
for one adapter that handles both KV writes and stream appends.

## Reads

- `ReadConsistency::Local` reads the local application state immediately.
- `ReadConsistency::AtLeast(watermark)` first calls
  `satisfy_read_consistency_to`.
- `ReadConsistency::Linearizable` creates a new `ReadBarrierRequest`, gathers
  validator votes for the identical `ReadBarrierStatement`, constructs a
  supermajority `ReadBarrierCertificate`, and supplies the resulting
  `CertifiedReadBarrier` to `satisfy_read_consistency_to`. The certificate
  commits the caller challenge, cluster/group, validator and route generations,
  command-spec version, global position, and order-certificate tail hash.
  Minority partitions, stale local tails, and raw watermarks do not satisfy
  this API.

The embedding service is responsible for broadcasting the fresh challenge and
collecting votes through its Blossom consensus driver. A partitioned minority
cannot issue a new barrier. Challenges are bearer nonces: reusing one permits
certificate replay, so the service must create a new `ReadBarrierRequest` for
every linearizable read attempt. The API never treats local admission,
availability, or a locally cached finalized tail as proof of freshness.

## Bounds and persistence

Command batches are limited to 4,096 commands and 64 MiB of canonical encoded
bytes. Individual opaque commands and the combined result bytes in one applied
completion are each bounded at 64 MiB. Application replay/deduplication bounds
belong to the embedding service.

Ordered state uses normalized `BlossomLogStore` tables for availability certificates,
finalized positions, position-to-reference mappings, origin-chain tails,
indexed status, opaque applied completions, and a small metadata record. Each
transition updates only changed records in one transaction with its milestone
event. Blossom persists no application state-machine snapshot.
`DurableAdmissionStore::durability_metrics` reports process-local commit,
fsync, checkpoint, and byte counts.

The HA service lifecycle has a separate immediate-durability contract. Use
`ActiveActiveHaEngine::open` on a node-local ShardLog directory distinct from
the `HighAvailabilityRuntime::open` directory. It restores accepted writes,
translated command bytes and hashes, the active route/spec contract, and any
prepared cutover before serving traffic. In-memory
`ActiveActiveHaEngine::new` is not a production write profile. The lifecycle
store bounds in-flight accepted state to 65,536 writes, 256 prepared shard
lanes, and 64 MiB of command bytes. Use
`ActiveActiveGlobalCoordinator::durability` for process-local lifecycle and
ordered-store durability inspection.

## Configuration

Resolve `--quorum-size`, then `BLOSSOM_QUORUM_SIZE`, then the default of six
with `QuorumSize::resolve_startup`. Only values `q >= 3` divisible by three are
accepted. Once a cluster has committed `ConsensusParameters`, joining and
restored nodes must use those committed parameters.

Trusted production nodes must also configure a node-local epoch log:

```sh
BLOSSOM_TRUSTED=true
BLOSSOM_TRUSTED_EPOCH_LOG=/var/lib/my-service/blossom-trusted
```

The equivalent CLI option is `--trusted-epoch-log`. A trusted runtime without
this option remains available for protocol-core simulation and compatibility,
but `trusted_operational_status()` reports it unavailable for production
writes. Supplying the option in verified mode is rejected, so verified startup
and persistence behavior remain unchanged.

See [Trusted Network Durability and Recovery](trusted-network-durability.md)
for the crash contract and service operations API.

`HolderMembership` currently requires exactly three non-empty sites. The
causal and conflict-only consistency modes remain existing baselines;
`GlobalOrderedEngine` supports only `active-sync-global-ordered`.
