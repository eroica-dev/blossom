# Protocol Alignment Audit

This audit compares the current Rust extraction and benchmark harness against
the Blossom whitepaper under `paper/`. It is intended as a gate before
performance optimization: optimize the measured shape only after confirming the
shape matches the protocol we intend to prove.

## Reference Expectations

The paper defines Blossom as three serialized stages:

1. Block formation
2. Block propagation
3. Transaction validation

Important protocol expectations from the paper:

- Every validator receives transactions and forms its own block in parallel.
- Blocks close at a configured cap, described as 1 MB in the protocol section
  and as an ideal 1,000 transactions per node per epoch in the benchmark
  section.
- Block propagation is structured, not all-to-all. Consensus traffic is routed
  through deterministic quorums of size 6.
- A 36-node network has two quorum rounds: a first set of 6-node quorums and a
  transposed second set. A node should accept dispatches from its current
  quorum peers, not from every node in the network.
- The normal propagation message sequence is:

  ```text
  Dispatch -> Echo -> Verification -> Proposal -> Commit
  ```

- After propagation, every non-Byzantine node should hold the same preliminary
  epoch: the ordered union of all valid blocks for that epoch.
- Transaction validation and final epoch hashing happen after propagation and
  require deterministic block and transaction order.
- Distribution-failure recovery is a second recursion with:

  ```text
  Appraisal -> Echo -> Verification -> Proposal -> Request -> Commit
  ```

## What Aligns Today

- The quorum constants match the paper: `QUORUM_SIZE = 6` and supermajority is
  `total - total / 3`, so a 6-node quorum requires 4 votes.
- The quorum scheduler matches the paper's base-6 tree shape. For 36 nodes it
  returns two rounds, corresponding to row-like then column-like quorums when
  membership is unshuffled.
- The crate uses deterministic ordered maps for epoch/block sets and signature
  trees, which matches the state determinism requirement.
- Dispatch, echo, verification, proposal, and commit message structures exist.
- Runtime message intake verifies signatures and rejects senders that are not
  members of the current node's quorum for the message round.
- The 36-node profile result of `5/35` accepted peer deliveries is consistent
  with the current round-0 quorum rule: node 0 has 5 peer members in its quorum,
  while the other 30 nodes are not intended recipients for that dispatch.

## Partial Or Prototype Behavior

These points are public-readiness boundaries, not hidden assumptions. Blossom's
current release surface is the protocol core, simulation environment, observer,
and benchmark harness. The deployable TCP node validates protocol messages and
supports service wiring, but it is not yet a complete autonomous production
driver for every consensus stage.

- Block formation exists as primitives (`Transaction`, `Block`, `LocalBlock`,
  `SubmitBlock`), but the benchmark builds one block for one node. The paper's
  benchmark model floods every node and expects every node to contribute one
  block per epoch.
- The deployable node accepts protocol messages, but it does not yet orchestrate
  a complete round by automatically producing and broadcasting echo,
  verification, proposal, and commit messages.
- `TempQuorum::verify`, proposal counting, commit tracking, and epoch
  advancement exist, but the TCP runtime does not yet drive them through a full
  end-to-end epoch finality loop.
- The harness measures one dispatch response and peer delivery. It does not yet
  measure "all nodes finish every quorum round and finalize the same epoch."
- Address-book support is local to a node process. The paper's benchmark setup
  assumes every node discovers the full network membership before processing.
  The crate currently relies on genesis configuration in the simulated cluster
  rather than a production discovery/DHT layer.
- Blocks and block sets are ordered, but transactions inside a block are a
  `Vec<Transaction>`, not the B+ tree / transaction map described for final
  validation.

## Not Yet Implemented

- Full transaction semantics, pre-validation against ledger state, transaction
  tagging, derivative epoch hashing, append-only ledger updates, and historical
  query behavior.
- Full primary propagation orchestration:

  ```text
  dispatch all quorum blocks
  echo observed dispatches
  verify accepted block sets
  propose the quorum result
  commit the outgoing result
  advance to the next quorum round
  ```

- Full 36-node epoch convergence where every node starts with its own block,
  completes both quorum rounds, and ends with all 36 valid blocks.
- Distribution-failure recovery (`Appraisal`, recovery `Request`, and
  request/response block repair).
- Reinitialization / restate after failed global finality.
- Byzantine pruning/wait policy beyond basic invalid-sender and invalid-signature
  rejection.
- Production membership discovery and durable storage.

## Benchmark Alignment

The million-transaction load benchmark we just ran is useful, but it is not a
whitepaper benchmark. It is a large-frame transport and serialization stress
test:

- It puts 1,000,000 transactions into one block on one node.
- It exceeds the paper's per-block/epoch model.
- It measures repeated movement of one large dispatch frame.
- In 36-node `all_peers` mode, it sends one node's round-0 dispatch to every
  peer, even though only that node's 5 quorum peers are intended recipients.

A whitepaper-aligned 36-node benchmark should instead:

- Spawn 36 nodes with shared genesis membership.
- Give every node its own block for the same epoch nonce.
- Use a block cap mode matching the paper: either 1 MB or 1,000 transactions per
  node per epoch.
- Execute round 0 across the six first-round quorums.
- Execute round 1 across the six transposed quorums.
- Treat completion as: every non-Byzantine node has accepted/finalized the same
  36-block preliminary epoch.
- Report per-round and whole-epoch metrics:
  - block formation time
  - dispatch/echo/verification/proposal/commit time
  - bytes sent per message kind
  - blocks and transactions accumulated per node
  - final epoch hash equality
  - failed, missing, or repaired blocks

For million-transaction testing that still aligns with the paper, the load
should be modeled as network input saturation across epochs, not one giant
single-node block. For example:

- 36 nodes x 1,000 tx/node/epoch = 36,000 tx/epoch.
- 1,000,000 submitted tx requires roughly 28 epochs at that cap.
- The final metric should be total submitted/accepted/finalized transactions
  across those epochs, plus per-epoch finality distribution.

## Optimization Gate

Before cutting into hot code paths, add a whitepaper-aligned epoch harness. The
current hotspots are real for the current transport stress test, but optimizing
them first risks improving a workload that the protocol is not supposed to run.

The stage-by-stage closure plan now lives in
`docs/protocol-stage-checklist.md`. Use that checklist as the implementation
gate for protocol work: each stage needs a written spec, proof sketch, unit
tests, runtime tests, TCP tests where applicable, and model tests before it is
considered complete.

The first version of that gate is `src/bin/blossom-epoch-bench.rs`. It adds
`--epoch-depth` and `--target-transactions` so we can measure consecutive
paper-shaped epochs instead of one oversized single-node dispatch. It is
in-memory by design: the benchmark isolates the quorum topology, block-set
union, message shape, and serialized byte estimates before TCP transport is
added back in.

Suggested next implementation order:

1. Add a protocol-level simulation harness that can execute full quorum rounds
   in memory first, without TCP. Initial implementation:
   `src/bin/blossom-epoch-bench.rs`.
2. Add a TCP version of the same harness so transport cost is separable from
   protocol cost.
3. Add a 36-node deterministic convergence test: every node starts with one
   block, all nodes end with the same 36-block epoch.
4. Add a benchmark mode for paper caps: `--transactions-per-node 1000` and/or
   `--block-byte-cap 1048576`.
5. Add a saturation runner that processes 1,000,000+ transactions over as many
   epochs as the cap requires.
6. Profile the whitepaper-aligned runs, then optimize the dominant costs.
