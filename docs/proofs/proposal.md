# Proposal Proof Gate

This note captures the current Stage 7 proposal-admission gate. It is not the
full round driver yet; it proves the local safety condition for accepting a
`consensus = true` proposal into runtime proposal accounting.

## Accepted Input

An honest runtime accepts a true consensus proposal only when all of these hold:

- The proposal message signature verifies for sender, epoch, nonce, round,
  message kind, and proposal body.
- The sender is a member of the addressed round.
- `approved_blocks.hash()` equals `approved_hash`.
- The optional signature-tree commitment is internally consistent.
- The approved block set equals the receiver's locally verified dispatch block
  set for the quorum, and the approved hash equals that local verified-set hash.
- The proposal carries at least the quorum supermajority number of distinct
  verification signatures.
- Every embedded verification signer is a member of the quorum.
- Every embedded verification signature verifies as a `Verification` message
  over the same epoch, nonce, round, approved block set, and approved hash.

False proposals are still admitted as negative votes after normal message
signature and sender membership checks. They do not claim an approved block set
and cannot increment any approved-hash count.

## Safety Sketch

The proposal signature binds the consensus decision and every embedded proof
field, so an adversary cannot reuse a signed false proposal as a true proposal
or swap the approved block set after signing. Runtime then reconstructs the
`VerificationBody` from the proposed approved block set and verifies each
embedded verifier signature under the verification message domain. Because the
signature domain includes message kind, epoch, nonce, round, sender, and body,
old verification votes and votes for other stages cannot be replayed into this
proposal.

Distinct-sender counting prevents one Byzantine verifier from satisfying the
threshold with duplicate entries. Quorum-membership checks prevent outside
keys from contributing to the proof. Under the standard supermajority
intersection assumption, two conflicting true proposal proofs for the same
quorum would require at least one honest verifier to sign conflicting
verification bodies for the same epoch, nonce, and round.

The local verified-block-set check adds a receiver-side guard: even a
cryptographically valid proof is not counted if the node has not independently
verified the referenced dispatch blocks. This keeps proposal accounting behind
dispatch verification instead of letting proposal messages import unverified
block commitments.

## Progress Sketch

If a supermajority of honest quorum members verify the same block set and their
verification signatures are delivered, any honest proposer can aggregate those
signatures into a true proposal proof. Every honest receiver that has verified
the same dispatch block set accepts that proposal. Delayed receivers reject or
defer true proposal accounting until dispatch recovery has supplied and
verified the referenced block set, preserving safety while allowing recovery to
restore progress.

## Current Tests

- `cargo test -q proposal`
- `cargo test -q receive_proposal`
- `cargo test -q --test e2e_tcp protocol_message_variants_are_accepted_over_tcp`

