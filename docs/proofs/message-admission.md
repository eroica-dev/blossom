# Message Admission Gate

This note covers the runtime gate that decides whether a consensus message can
affect quorum accounting.

## Rule

A received consensus message is admitted only if all of these checks pass:

- The message header references the current chain tip and next expected nonce.
  Unknown epoch hashes are rejected as unknown, and finalized-but-known epoch
  hashes are rejected as stale.
- In verified mode, the signature verifies over message kind, sender, epoch
  hash, nonce, round, and body commitment.
- The sender is a current verifier assigned to the addressed round.
- The body-specific validation for that message kind succeeds before sender
  progress is recorded.

If any check fails, the message is rejected before it can create or update
dispatch, verification, proposal, commit, epoch-started, or recovery accounting.

## Trusted Mode

Trusted mode can skip cryptographic signature verification for local operational
testing, but it still requires the current consensus target and round
membership. Trusted mode therefore models accidental faults in a controlled
membership set, not
Byzantine security.

## Executable Coverage

- `receive_message_rejects_unknown_sender_and_bad_signature` covers dispatch
  rejection for unknown senders and invalid signatures.
- `consensus_messages_reject_known_members_in_wrong_round_without_accounting`
  covers dispatch, echo response, verification, proposal, commit,
  epoch-started, echo request, and echo redispatch messages from a known
  validator addressed to a wrong round.
- `consensus_messages_reject_non_members_without_accounting` covers the same
  message kinds from a non-member identity.
- `tcp_consensus_messages_reject_wrong_round_members` and
  `tcp_consensus_messages_reject_non_members` cover the same gate over the real
  TCP request path.
- The multi-group runtime test rejects a message signed for a different known
  group because its epoch hash is unknown to the target runtime.
- `receive_message_rejects_stale_epoch_target_after_finality` covers replayed
  consensus messages for an epoch that is already finalized locally.

Together these tests pin the invariant that malformed or out-of-membership
traffic cannot inflate quorum progress.
