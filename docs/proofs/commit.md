# Commit Threshold Gate

This note captures the current Stage 8 commit-admission gate. It does not yet
drive epoch advancement through the deployable runtime; it closes the local
safety hole where one accepted true commit could make the commit decision
visible.

## Accepted Input

An honest runtime accepts a commit message into local commit accounting only
when:

- The commit message signature verifies for sender, epoch, nonce, round,
  message kind, and commit body.
- The sender is a member of the addressed round.
- A true commit is accepted only after this node has already accepted a true
  proposal supermajority for the same quorum.
- The commit body is counted under the sender's current vote.

`commit_senders` records peers that have sent any accepted commit message for
missing-signature diagnostics. `commit_true_senders` records the latest senders
whose accepted commit vote is `consensus = true`. If a sender later sends
`consensus = false`, that sender is removed from the true-vote set.

The runtime-visible commit decision is true only when there is a local true
proposal supermajority and `commit_true_senders` contains at least the quorum
supermajority threshold.

## Safety Sketch

The commit signature binds the consensus bit and signature-tree insert keys, so
a vote signed for false cannot be replayed as a true commit. Sender membership
checks prevent outside identities from contributing to the threshold. The true
commit set is keyed by public key, so duplicate commits from one Byzantine node
cannot inflate the count. A later accepted vote from the same sender replaces
the sender's previous true contribution.

Therefore a single Byzantine commit cannot mark the commit decision visible.
Reaching the true decision requires a distinct quorum supermajority of accepted
true commit votes, each gated behind the receiver's local proposal
supermajority. This keeps commit accounting downstream of the proposal proof
gate instead of letting commit messages introduce a finality decision by
themselves.

## Current Tests

- `cargo test -q receive_commit`
- `cargo test -q commit`
