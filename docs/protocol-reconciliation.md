# Protocol Reconciliation Process

Reconciliation is the recovery path used when an epoch cannot be safely
advanced by ordinary dispatch, echo, verification, proposal, and commit, and
when simple summary catch-up cannot find a certified quorum for one epoch hash.
It is not a fork-choice shortcut. It rebuilds the lowest unresolved epoch from
signed evidence, commits that rebuilt body through the normal consensus
threshold, then restates speculative local state on top of the committed result.

## Trigger

A node enters reconciliation for `(last_epoch, nonce)` when any of these are
true:

- It times out waiting for a commit certificate for the epoch.
- It observes multiple epoch summaries for the same parent and nonce.
- It restarts with local state ahead of its last durable commit certificate.
- A peer presents a higher nonce but cannot provide a valid certificate chain
  from the receiver's last durable commit.

The node freezes speculative advancement at the first unresolved nonce. Later
local epochs remain tentative and can be discarded.

## Messages

The protocol should expose recovery messages distinct from ordinary block
availability fetches:

- `ReconcileAppraisal`: signed statement of the sender's last durable
  certificate, contested parent, contested nonce, local candidate epoch hash,
  candidate block-manifest hash, and offered block/proof ranges.
- `ReconcileRequest`: signed request for missing appraisals, commit
  certificates, block manifests, or blocks for one parent and nonce.
- `ReconcileResponse`: signed response carrying the requested certificates,
  manifests, blocks, and equivocation evidence.
- `ReconcileCommit`: ordinary commit-stage output for the rebuilt body. This is
  not a new finality rule; it is the normal commit certificate over a recovered
  epoch body.

Every reconciliation message must bind sender, parent epoch hash, nonce, round
or attempt number, message kind, and body commitment.

## Algorithm

1. **Find the common checkpoint.** Use the highest durable commit certificate
   shared by a supermajority of current verifiers. If a peer advertises a
   higher checkpoint, it must provide the certificate chain from the receiver's
   checkpoint.
2. **Select the lowest unresolved nonce.** Reconcile only one nonce above the
   common checkpoint. Do not reconcile later speculative epochs first.
3. **Collect appraisals.** Gather signed appraisals from the current verifier
   set. A matching appraisal quorum for an already committed epoch hash is the
   fast path: fetch missing data and adopt the certified epoch.
4. **Rebuild the candidate body.** If no certified summary quorum exists,
   collect manifests and blocks for the checkpoint parent and unresolved nonce.
   Accept only blocks signed by current verifiers, targeting exactly that parent
   and nonce, with valid body hashes and Merkle roots.
5. **Handle equivocation deterministically.** If one validator signs multiple
   valid blocks for the same parent and nonce, exclude that validator's blocks
   from the rebuilt body and carry the equivocation evidence into the epoch.
6. **Commit the rebuilt body.** Run verification, proposal, and commit over the
   deterministic rebuilt block set. A node may adopt the result only after it
   has the normal commit threshold for the exact parent, nonce, and body hash.
7. **Restate local state.** Replace the contested local epoch with the committed
   rebuilt epoch, discard speculative descendants, and resume block formation at
   the next nonce.

## Deterministic Body Rule

For the first implementation, the rebuilt body is:

```text
sorted valid blocks from current verifiers for (parent, nonce)
- all blocks from equivocal validators
```

The production protocol can later add deterministic absence records for
validators whose blocks remain unavailable after the reconciliation timeout.
Those records must be signed by a supermajority and committed in the rebuilt
epoch so all honest nodes derive the same body.

## Safety Sketch

A node never adopts a reconciliation result from summaries alone unless the
summary carries a valid commit certificate chain. Otherwise it only adopts after
the rebuilt body receives the normal commit threshold. Since every candidate
block is signed for one parent and nonce, replayed or stale blocks cannot enter
the rebuilt body. Since equivocal validator blocks are excluded
deterministically, honest nodes that see the same evidence compute the same
candidate body. Two conflicting reconciliation commits for the same parent and
nonce would require two supermajorities to sign different body hashes, which
intersect in at least one honest verifier under the standard less-than-one-third
Byzantine assumption.

## Progress Sketch

Under eventual synchrony, if at least a supermajority of current verifiers can
serve either a commit certificate or the signed blocks/evidence they hold, every
honest recovering node eventually obtains the same checkpoint and enough data to
verify the rebuilt body. Once the rebuilt body is deterministic, the ordinary
verification, proposal, and commit stages provide the same progress condition as
normal epoch finality. Nodes that were ahead can restate to the committed epoch
and rejoin the next nonce.

## Simulation Model

`blossom-sim` models this as a two-path recovery stage:

- **Summary catch-up:** a node adopts a state only when the summary represents
  the modeled certified epoch hash.
- **Block-set reconciliation:** if no summary quorum exists, the node gathers
  validator-signed source blocks for the contested parent and nonce across
  repair rounds. Once it has the deterministic source set, it rebuilds and
  adopts the canonical epoch state.
- **Pending nonce freeze:** if a full partition prevents reconciliation in the
  same simulator tick, the unresolved epoch remains pending. Later ticks retry
  reconciliation for the same parent and nonce, and ordinary block formation
  resumes only after the pending epoch converges.

The model intentionally treats the rebuilt body certificate as the canonical
hash supplied by the simulation. Runtime work still needs concrete
`Reconcile*` messages and commit-certificate validation.
