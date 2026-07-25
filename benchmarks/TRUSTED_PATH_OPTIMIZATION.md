# Trusted Active-Active Critical Path

Trusted Blossom has two deliberately separate benchmark profiles:

- `trusted-direct`: every epoch member may send one unsigned block. A node
  broadcasts a mutable acknowledgement after receiving a two-thirds dispatch
  quorum. Once two thirds acknowledge the same block set, it durably locks and
  broadcasts one immutable confirmation, then advances after two thirds
  confirm that candidate. There is no leader, proposal, signed vote,
  `OrderStatement`, or portable `OrderCertificate`.
- `trusted-durable-references`: the stronger asynchronous active-active profile
  with site-local admission, two-site payload custody, compact references, and
  durable visibility milestones.

The direct profile is the protocol described by Blossom's trusted-network
contract. The durable-reference profile must not be placed on its critical path
or presented as the cost of trusted ordering itself.

Artifacts also record the holder population, trusted threshold, per-site
liveness fault bound, and required certified-site count. Results with different
holder envelopes must not be presented as safety-equivalent comparisons.

The target for 1,000-plus validators is:

- parallel ingress from every writer, without a leader or sequencer;
- event-driven dissemination with bounded per-node fanout;
- direct unsigned trusted finality; portable certificates remain a verified-mode concern;
- one amortized durable commit per epoch at each applying replica;
- `Applied` independent of all-node convergence.

The feature-gated `trusted-checkpoint-dag` experiment evaluates immutable
per-writer origin chains and compact frontier digests beneath this same
sequential quorum ordering. It does not add an alternative finality path:
every frontier must still pass through each selected hierarchical
acknowledgement/confirmation round before a linear checkpoint advances. See
[`TRUSTED_CHECKPOINT_DAG_EXPERIMENT.md`](TRUSTED_CHECKPOINT_DAG_EXPERIMENT.md).

The universal-writer diagnostic is
`blossom-universal-writer-smoke`. It sends independent clients to OpenRaft
concurrently and validates exact non-conflicting final state after both
protocols reach `Applied`.

## Trusted-direct protocol

For one fixed membership epoch:

1. Every member creates at most one block for the next nonce. Empty blocks are
   permitted for idle members.
2. Members propagate blocks over the configured overlay. Blocks are sealed
   with their writer identity but carry no signature.
3. A node waits until it possesses exactly one valid block from at least
   `N - floor(N / 3)` expected members.
4. It broadcasts its unsigned acknowledgement of the received block set to
   every round peer. This acknowledgement may only grow as delayed blocks
   arrive.
5. After `N - floor(N / 3)` current acknowledgements name the same set, it
   durably locks and broadcasts one immutable confirmation for that candidate.
   It cannot confirm a second candidate for the same round, including after
   restart.
   Failed trusted fanouts are retried with the exact cached dispatch or locked
   confirmation; acknowledgements retry their latest monotonic block mask.
6. It commits the epoch only after the same threshold confirms that candidate.
   Hierarchical topologies carry the confirmed set into the next round; the
   final round atomically commits the epoch and append-only log head before the
   new head is exposed. The epoch hash binds the block set, previous epoch
   hash, and previous epoch nonce.
7. Applications consume `Epoch::trusted_ordered_transactions()`, which returns
   opaque payloads in BTree block-hash order, and atomically advance their local
   watermark.

The acknowledgement is mutable availability evidence. The confirmation is an
authenticated trusted-network crash-fault decision, not a Byzantine signature
or portable proof. Two finalized candidates cannot conflict because two
two-thirds confirmation quorums intersect and each trusted member durably
locks only one candidate. Up to `floor(N / 3)` inactive members can be omitted
from an epoch; losing more than that stops liveness until recovery or an
explicit membership transition.

This design distributes ingress and CPU across writers, but it does not make
replicating `N` distinct blocks to all `N` nodes sub-quadratic in aggregate
bytes. The overlay can reduce origin fanout and critical-path depth; it cannot
remove the `N × N` payload-delivery lower bound when every node must possess
every writer's payload. Head-to-head reports therefore include aggregate
network bytes, maximum per-node load, and leader load—not only latency.

## Non-negotiable universal-writer contract

1. Every eligible node is a writer; no leader, proposer, sequencer, or
   leader-forwarding hop assigns its position.
2. Every member remains eligible to send one block per epoch, and real writer
   blocks are not replaced by one reference plus synthetic benchmark blocks.
3. Ordering is the BTree order of block hashes from the finalized dispatch
   quorum.
4. The epoch commits its previous epoch nonce and hash, extending one immutable
   local stable prefix.
5. Trusted mode carries no signatures or portable certificate. Verified mode
   remains a separate protocol and result label.
6. `Applied` and all-node convergence are distinct observations.
7. Non-conflicting workloads require exact final-state equality with Raft.
8. Up to the committed crash-fault bound may be absent without silently
   changing membership. More than one-third missing members is a visible
   head-of-line liveness fault until recovery or membership change.

`N` below is the validator population, `H_s` is the holder population in one
site, `q` is the configured Blossom branching factor, and `B` is commands per
ordered batch. In trusted mode, "approval" means an unsigned,
transport-authenticated confirmation for one durably locked block set; it is
not a Byzantine consensus vote.

| # | Current operation | Synchronous boundary | Current work | Optimization |
|---:|---|---|---|---|
| 0 | Drive parallel commands from active validators | Implemented diagnostic | Supports 1 through `N` real writers and exact-state checks | Add balanced, site-hot, and Zipf arrival processes plus fixed-total and fixed-per-writer offered load. |
| 1 | Validate and hash one command | CPU | `O(command bytes)` | Validate once and retain canonical bytes and hashes. |
| 2 | Select the origin-site members | CPU | Cached `O(H_s)` committee | Retain immutable committee handles and precomputed policy hashes by membership epoch. |
| 3 | Replicate command bytes to an origin-site supermajority | Durable I/O + signatures | `O(H_s)` holders | Use a fixed-size holder committee, batch commands, and group-commit one WAL append. |
| 4 | Assemble and verify `LocalAdmissionCertificate` | CPU | `O(H_s)` receipts | Cache the policy; use authenticated-channel receipts or an aggregate certificate in trusted mode. |
| 5 | Persist `AcceptedLocal` as a separate milestone | Durable I/O | One additional immediate commit | Commit admission data and the milestone in the same transaction. |
| 6 | Build a one-command batch, Merkle root, and hash-chained reference | CPU | `O(B)`; currently `B=1` | Fill windows by byte/command/linger limits and reuse canonical bytes and hashes. |
| 7 | Select two holder-site committees | CPU | Cached committee lookup | Retain immutable committee handles and rotate choices according to policy. |
| 8 | Replicate the batch to supermajorities in two sites | Durable I/O + signatures | `O(H_s)` in each site | Use fixed-size holder committees, shared immutable bytes, and group commit. |
| 9 | Assemble and verify the availability certificate | CPU | `O(H_s)` receipts | Use a compact aggregate or MAC certificate while retaining SHA-256 payload commitments. |
| 10 | Persist the whole ordered-engine state for `Available` | Serialization + durable I/O | Grows with retained history | Store a delta keyed by reference hash; do not rewrite the state machine or every map. |
| 11 | Resolve the next epoch target | Local state | Constant after removing an `O(N)` serial agreement scan | Use the locally committed previous epoch nonce/hash; remote validators reject stale targets. |
| 12 | Submit one unsigned block per member; active writers carry real references | Network | `O(N)` blocks; every origin submits only its own block | Drive activation and completion from runtime events, retain bounded overlay fanout, and benchmark direct payload blocks separately from durable references. |
| 13 | Receive a two-thirds dispatch quorum, exchange monotonic block-set acknowledgements, durably lock one confirmation, then advance after a matching confirmation quorum | Network + durable I/O + CPU | One acknowledgement and one confirmation wave per overlay level; no proposal or signed commit vote | Keep control messages compact, event-driven completion, pre-encoded immutable confirmations, and pipelined windows. |
| 14 | Poll validator chains for benchmark observation | Network + decoding | Trusted `Finalized` is the origin node's local commit; convergence is measured separately | Subscribe to the local epoch-commit event and keep all-node observation off the critical path. |
| 15 | Derive an `OrderStatement` from the finalized epoch | CPU | Constant plus repeated hashing | Put position, reference hash, previous order-certificate hash, and generation in the Blossom-finalized statement. |
| 16 | Trusted order-vote wave | None | Removed: trusted mode finalizes directly from its locally committed epoch | Keep signed anti-equivocation votes only in verified mode. |
| 17 | Trusted `OrderCertificate` assembly | None | Removed | Keep portable certificate verification only in verified mode. |
| 18 | Persist the whole ordered-engine state for `Finalized` | Serialization + durable I/O | Grows with retained history | Append only the position/reference/certificate delta and chain tail. |
| 19 | Load and reverify the batch | Read I/O + hashing | `O(batch bytes)` | Cache a verified immutable batch until apply; reverify only after restart or repair. |
| 20 | Clone and apply the whole in-memory state machine | CPU + memory | Grows with application state | Stage only touched keys and dedup-session deltas. |
| 21 | Serialize the entire state machine and ordered state for `Applied` | Serialization + durable I/O | Grows with application state and history | Persist key/session deltas and watermark atomically; create periodic snapshots separately. |
| 22 | Poll and catch up every lagging validator | Network + CPU | `O(N)` and currently serializes benchmark writes | Keep this off the `Applied` path; repair asynchronously while up to eight windows remain in flight. |

Rows 2–10 and 15–21 describe the optional durable-reference/application
profile. They are not required by `trusted-direct`.

## Current diagnostic baseline

These local results are non-publishable and exist only to guide optimization:

- The older durable-reference wrapper measured 184.26 ms at 6 nodes/6 writers
  and 2,406.92 ms at 72 nodes/72 writers. The 72-writer row issued 720
  immediate redb commits; block submission plus trusted receipt/order itself
  took 111.23 ms.
- `trusted-direct` plus local commit notifications reduced 6-node/6-writer
  warm `Applied` to 1.09 ms. Concurrent in-memory OpenRaft measured 0.20 ms.
- At 72 nodes with `q=9`, Blossom warm `Applied` stayed between 18.71 and
  21.08 ms as active writers increased from 1 to 72. Aggregate warm throughput
  therefore rose from 47.9 to 3,615 commands/s without a leader. In-process
  OpenRaft remained faster, but that transport-unequal row is not a winner
  claim.
- At 240 nodes/240 writers, `q=15` was the best tested branching factor:
  194.51 ms and 1,234 commands/s warm, versus 435.83 ms and 551 commands/s at
  `q=9`. `q=24` regressed to 818.97 ms.
- A 1,002-node single-host TCP run exhausted the macOS local socket/address
  envelope before producing a sample. The next 1,000-node gate is bounded
  connection multiplexing or protocol-core simulation, followed by
  multi-host validation.

The immediate optimization target is therefore not another trusted consensus
shortcut: that phase is already gone. It is to benchmark and expose the direct
epoch API, then coalesce or bypass the optional durable-reference transactions.

## Optimization order

### P0: remove membership-sized work from the trusted critical path

1. Keep the implemented universal-writer/multi-reference epoch path free of a
   coordinator and trusted certificate.
2. Add a `trusted-direct` benchmark adapter that applies
   `Epoch::trusted_ordered_transactions()` with one atomic epoch commit,
   bypassing local-admission, two-site-availability, and order-certificate
   storage.
3. Retain at most one block per expected member and require the committed
   two-thirds threshold. Durably carry a local writer block forward when a
   competing quorum omits it; never discard accepted local work silently.
4. Replace benchmark chain polling with a local epoch-commit notification.
5. Keep convergence and repair asynchronous after `Applied`.

The stronger durable-reference profile continues to use fixed holder
committees and separately documented durability boundaries.

### P1: amortize durability and consensus

1. Batch multiple commands and references per availability/finality window.
2. Coalesce command admission and `AcceptedLocal` in one transaction.
3. Replace whole-state persistence with append-only ordered deltas.
4. Persist application key/session deltas with the applied watermark.
5. Group commit by byte/command/linger limits while preserving the documented
   `LocalAsync` and `GlobalFinalized` durability boundaries.

### P2: reduce trusted cryptographic and encoding cost

1. Keep domain-separated SHA-256 for finalized commitments.
2. On authenticated trusted links, replace per-hop Ed25519 receipts with keyed
   authentication or compact aggregate certificates.
3. Cache canonical Borsh bytes, Merkle roots, reference hashes, and dispatch
   frames.
4. Share immutable batch bytes across holder tasks instead of cloning batches.

### P3: runtime and topology tuning

1. Keep the implemented message-driven consensus driver and local epoch-commit
   notification; remove remaining periodic fallback work from steady state.
2. Reuse/multiplex a bounded number of connections per overlay neighbor. A
   1,002-node single-host run currently exhausts the local socket/address
   envelope.
3. Split global locks into per-epoch and per-round state; profile scheduler and
   lock wait separately from handler CPU.
4. Tune `q` by population and topology. At 240 nodes, `q=15` more than doubled
   warm throughput relative to `q=9`, while `q=24` regressed.
5. Run protocol-core simulations at 1,000-plus nodes before expensive
   multi-process trials, then validate selected cells on real hosts.

## Universal-writer benchmark matrix

For each selected node count and `q`, run:

- writer counts: 1, 3, 10%, 50%, and 100% of nodes;
- writer placement: balanced across sites, one-site hot, and Zipf-skewed;
- fixed total offered load, to compare protocol overhead;
- fixed offered load per writer, to expose aggregate ingress scaling;
- blind writes/appends separately from CAS;
- one reference per writer and byte-normalized multi-command batches;
- 1, 2, 4, and 8 availability-certified windows in flight.

Report aggregate Applied throughput, per-writer throughput, p50/p95/p99
milestones, stable-visibility lag, Jain fairness, pending bytes, hierarchy
fanout, maximum per-node CPU/network/durable-write load, and convergence lag.

For Raft, accept clients at every physical node and include forwarding to the
current leader. Report leader load separately. A representative 5- or 7-voter
Raft group with learners remains distinct from an all-voter Raft group.

## Required gates

Each optimization must preserve:

- availability before finality;
- uniqueness and stable-prefix order certificates;
- previous-epoch nonce and previous-order-certificate hash continuity;
- crash/restart durability at the advertised acknowledgement milestone;
- exact-once deduplication under reordered client sequences;
- partition/heal convergence and deterministic replay.

Benchmark rows remain non-publishable until the correctness, durability, fault,
sample-count, steady-state, and confidence-interval gates pass.
