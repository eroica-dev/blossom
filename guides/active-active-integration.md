# Direct Active-Active Integration

`shard-kv` and `shard-stream` should import Blossom as a library. There is no
bridge crate and Blossom does not own the application's network transport or
storage schema.

```toml
[dependencies]
blossom = { path = "../blossom" }
```

## Trusted-direct flow

For a trusted network, `shard-kv` and `shard-stream` can use the protocol
without the durable-reference engine:

1. Build one `Block` per member and place the application's opaque
   `Transaction` payloads in it.
2. Call `Block::seal_unsigned(writer_public_key)`.
3. Submit it to `NodeRuntime`/`TcpNode`. In production, configure
   `RuntimeConfig::with_trusted_epoch_log_path` so acceptance, confirmation locks,
   and epochs use immediate-durability redb transactions.
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
2. Persist commands with `DurableAdmissionStore::admit` and combine signed
   receipts into a `LocalAdmissionCertificate`.
3. Build a `CommandBatch` and cryptographic `BatchReference`, replicate the
   bytes, and collect `AuthenticatedAvailabilityReceipt` values.
4. Verify and submit the resulting `AvailabilityCertificate` with
   `GlobalOrderedEngine::mark_available`. Encode compact references with
   `BatchReference::to_transaction`. A trusted epoch may contain one reference
   from every active writer.
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
objects to these APIs. Trusted ordering uses connection identity and unsigned
receipts; portable signed order certificates are a verified-mode concern.

## Apply contract

Blossom invokes `OrderedApplication::apply_ordered` in immutable certificate
order. The callback receives:

- The batch-reference hash.
- The complete committed reference.
- The verified command batch.
- The global watermark.
- Results produced by Blossom's shared command state machine.

The pair `(reference_hash, watermark)` is a stable replay key. The application
must atomically persist this key with its KV or stream mutations. A process can
fail after the application transaction commits but before Blossom commits its
own redb transaction, so the callback is intentionally at-least-once across
crash recovery. The callback returns one `CommandResult` per command; Blossom
rejects the apply if those results differ from the shared sequential
specification.

Blossom records `Applied` only after the callback succeeds and Blossom durably
commits its state machine, finality-chain metadata, and milestone event.

See
[`examples/active_active_application.rs`](../examples/active_active_application.rs)
for one adapter that handles both KV writes and stream appends.

## Reads

- `ReadConsistency::Local` reads the local application state immediately.
- `ReadConsistency::AtLeast(watermark)` first calls
  `satisfy_read_consistency_to`.
- `ReadConsistency::Linearizable` supplies a fresh Blossom order/read barrier
  to `satisfy_read_consistency_to`, then reads from the application state.

The embedding service is responsible for acquiring the barrier through its
Blossom consensus driver. The barrier API never treats local admission or data
availability as global finality.

## Configuration

Resolve `--quorum-size`, then `BLOSSOM_QUORUM_SIZE`, then the default of six
with `QuorumSize::resolve_startup`. Only values `q >= 3` divisible by three are
accepted. Once a cluster has committed `ConsensusParameters`, joining and
restored nodes must use those committed parameters.

Trusted production nodes must also configure a node-local epoch log:

```sh
BLOSSOM_TRUSTED=true
BLOSSOM_TRUSTED_EPOCH_LOG=/var/lib/my-service/blossom-trusted.redb
```

The equivalent CLI option is `--trusted-epoch-log`. A trusted runtime without
this option remains available for protocol-core simulation and compatibility,
but `trusted_operational_status()` reports it unavailable for production
writes. Supplying the option in verified mode is rejected, so verified startup
and persistence behavior remain unchanged.

See [Trusted Network Durability and Recovery](trusted-network-durability.md)
for the crash contract and service operations API.
