# Trusted Network Durability and Recovery

This contract applies only to `TrustMode::Trusted`. It does not alter verified
message validation, signatures, proposals, commits, snapshots, catch-up, or
finality.

## Production configuration

Every production writer must use a node-local trusted epoch log:

```sh
BLOSSOM_TRUSTED=true
BLOSSOM_TRUSTED_EPOCH_LOG=/var/lib/my-service/blossom-trusted.redb
```

Library users set `RuntimeConfig::with_trusted_epoch_log_path`. The log uses
redb immediate durability and commits:

- A versioned manifest binding the group, local identity, genesis, consensus
  parameters, and deterministic membership-removal policy.
- The local writer block accepted for the next epoch.
- At most one confirmation/candidate lock per hierarchical round.
- Immutable epochs keyed by nonce.
- The durable head nonce and hash.

A trusted log cannot be opened under another identity, genesis, group, or
parameter set. Startup scans and validates the stored stable prefix, then treats
it as authoritative over a shorter compatibility snapshot.

## Crash contract

For each epoch:

1. A local writer block is fsynced before submission returns success.
2. After `N - floor(N / 3)` expected members dispatch valid blocks, the node
   broadcasts a mutable acknowledgement. Its acknowledged block mask may only
   grow.
3. The node forms a candidate only when that threshold currently acknowledges
   the same block set.
4. It fsyncs one immutable confirmation lock before broadcasting the
   confirmation. It advances a hierarchical round or finalizes only after the
   same threshold confirms the candidate.
5. The final epoch append, head update, all round-lock removals, and local-block
   disposition commit in one immediate-durability transaction.
6. The in-memory head and application commit notification advance only after
   that transaction succeeds.

An ENOSPC, fsync, encoding, or consistency failure therefore exposes neither a
new confirmation nor a new epoch head. A restart retransmits the highest
existing confirmation lock exactly; it never chooses a second candidate for
that round.

When a trusted TCP fanout reports one or more failed peers, the autonomous
driver schedules that stage for retry. Dispatch retries reuse the exact cached
block message, acknowledgement retries use the latest monotonic block mask,
and confirmation retries reuse the immutable local confirmation. Verified
message-production behavior is unchanged.

The durable transaction rejects stale local submissions and confirmation locks
that race with a head change. Hierarchical locks must be contiguous and each
candidate must preserve the prior round's block set. Catch-up cannot clear a
lock unless the incoming epoch includes every locally confirmed block; local
finalization additionally requires an exact match with the final-round lock.

Two conflicting candidates cannot both finalize when members follow this
trusted crash-fault contract: two two-thirds quorums intersect, and every
member durably confirms at most one candidate. Mutable acknowledgements avoid
prematurely locking different subsets as blocks arrive in different orders.

## Slow and recovering writers

Every committed member remains a universal writer. An epoch may omit up to
`floor(N / 3)` inactive members without changing membership or thresholds.
Losing more members stops progress.

If another valid quorum commits without this node's already accepted local
block, catch-up atomically removes the stale submission, updates its previous
epoch hash and nonce, reseals it unsigned, and retains it for the next epoch.
Accepted local work is not silently discarded.

Catch-up accepts either a complete chain containing the local stable prefix or
a contiguous suffix beginning immediately after the local head. Every
extension validates hash/nonce linkage, block integrity, the Merkle root,
consensus parameters, and the deterministic membership transition. The entire
suffix is committed before the in-memory chain changes. Conflicting prefixes
fail closed.

## Log scaling

The trusted direct commit path reads only the durable head and appends one
epoch. It no longer serializes or rewrites the full historical chain on every
commit. Steady-state storage work scales with the new epoch bytes plus the redb
index; full-history validation occurs at startup and explicit recovery.

The optional durable-reference engine also commits every reference and
milestone from one trusted multi-writer epoch in a single transaction. Replaying
that epoch is idempotent and cannot append duplicate order positions.

Consensus history remains append-only. Applications should retain their own
atomically applied watermark and use an externally coordinated backup or
checkpoint policy; Blossom does not delete consensus evidence automatically.

## Service operations

Embedding services should expose `NodeRuntime::trusted_operational_status()` in
readiness and administrative endpoints. It reports:

- `Ready`, `Degraded`, or `Unavailable`.
- Whether the trusted log is configured and matches the in-memory head.
- The durable nonce, hash, and epoch count.
- A pending confirmation lock.
- Expected and observed dispatch counts, plus required and observed matching
  acknowledgement and confirmation counts.
- Whether the node should accept writes.
- Service directives such as drain writes, notify operators/users, await a
  confirmation quorum, quarantine a peer, or restart/redeploy.

Pass returned protocol errors to `NodeRuntime::assess_trusted_failure()` for a
stable `TrustedFailureClass`, retry policy, and directives. A missing or
mismatched durable log is `Unavailable` for production writes. A durable
candidate awaiting confirmations is `Degraded`, not data loss.

## Validation

The trusted production gate includes:

- Fault-injected ENOSPC and fsync failures.
- Crash/restart confirmation-lock, hierarchical-round, and local-submission
  recovery.
- Stale-write races, lock/epoch conflicts, live catch-up retargeting, and
  semantic epoch corruption.
- Conflicting-candidate and quorum-intersection properties.
- Exhaustive dispatch masks and Hegel-generated thresholds.
- Atomic, idempotent multi-reference epoch finalization.
- A 1,001-epoch append/reopen stable-prefix test.
- Deterministic long-running trusted simulations with delay, reordering,
  packet loss, partitions, and recovery.

Run it with:

```sh
scripts/trusted-production-validation.sh
```
