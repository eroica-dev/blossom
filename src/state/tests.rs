//! Epoch-chain, quorum-state, and certified-suffix tests.

use super::*;
use bytes::Bytes;

use crate::block::Transaction;
use crate::blossom::{
    Dispatch, DispatchBody, Header, Proposal, ProposalBody, SignatureTree, TrustedAcknowledgement,
    Verification, VerificationBody,
};
use crate::crypto::{Keypair, SecKey, Signature};
use crate::encounter::{EncounterOutcome, EncounterPhase, EncounterRecord, EncounterRecordBody};
use crate::membership::ConsensusNodeRemovalPolicy;
use crate::messages::Msg;
use crate::wire::{EncodedFrame, FRAME_PREFIX_BYTES, WireRequest, WireRequestFrame};

#[cfg(feature = "fair-block-ordering")]
fn sealed_epoch_block(label: &str, txs: &[&str]) -> Block {
    let mut block = Block::default();
    block.body.created = 42;
    block.body.nonce = Nonce::new(1);
    for tx in txs {
        block
            .body
            .txs
            .push(Transaction::new(format!("{label}:{tx}")));
    }
    block.seal_unsigned(PubKey(HashType::hash(label.as_bytes()).0));
    block
}

fn node(index: u8) -> NodeIdentity {
    NodeIdentity::new(
        PubKey([index; 32]),
        None,
        "tcp",
        format!("node-{index}"),
        8000 + index as u16,
        false,
    )
}

fn genesis(self_index: u8) -> (NodeIdentity, Epoch) {
    let mut verifiers = IndexTreeMap::new();
    for index in 0..6 {
        let node = node(index);
        verifiers.insert(node.public_key(), node);
    }
    let mut epoch = Epoch {
        body: EpochBody {
            verifiers,
            nonce: Nonce::new(0),
            ..Default::default()
        },
        ..Default::default()
    };
    epoch.set_hash();
    (node(self_index), epoch)
}

fn signed_epoch(verifier_count: u8, signature_count: u8) -> Epoch {
    let mut verifiers = IndexTreeMap::new();
    let mut secrets = BTreeMap::new();
    for index in 0..verifier_count {
        let keypair = Keypair::generate();
        verifiers.insert(
            keypair.public,
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                format!("node-{index}"),
                9000 + index as u16,
                false,
            ),
        );
        secrets.insert(keypair.public, keypair.secret);
    }

    let mut epoch = Epoch {
        body: EpochBody {
            verifiers,
            nonce: Nonce::new(1),
            ..Default::default()
        },
        ..Default::default()
    };
    epoch.set_hash();

    for index in 0..signature_count as usize {
        let public_key = epoch.body.verifiers.get_key_from_index(index).unwrap();
        let secret_key = secrets.get(public_key).unwrap();
        epoch
            .signatures
            .insert(index, Signature::sign(&epoch.hash.to_bytes(), secret_key));
    }

    epoch
}

fn hot_pending_dispatch(sender: PubKey, signature: Signature) -> PendingDispatch {
    let blocks = BTreeMap::<HashType, Block>::default();
    let blocks_hash = blocks.hash();
    let signature_tree = SignatureTree::default();
    let dispatch = Dispatch {
        header: Header {
            sender,
            signature,
            ..Default::default()
        },
        body: DispatchBody {
            blocks_hash,
            blocks,
            signature_tree_hash: signature_tree.hash(),
            signature_tree,
        },
    };
    let frame =
        EncodedFrame::encode_hot_wire_request(&WireRequest::Message(Msg::Dispatch(dispatch)))
            .unwrap()
            .unwrap();
    match crate::wire::decode_wire_request_frame(Bytes::copy_from_slice(
        &frame.as_bytes()[FRAME_PREFIX_BYTES..],
    ))
    .unwrap()
    {
        WireRequestFrame::HotDispatch(raw) => PendingDispatch::Hot(raw),
        request => panic!("expected hot dispatch, got {request:?}"),
    }
}

fn valid_public_key(seed: u8) -> PubKey {
    Keypair::from_secret(SecKey([seed; 32])).public
}

#[test]
fn get_mut_quorum_is_stable() {
    let (self_node, genesis) = genesis(0);
    let mut state = LocalState::new(self_node, genesis);
    let last = state.epochchain.epochchain.last().unwrap().clone();
    let round = 0;

    let quorum = state.get_mut_quorum(&last.hash, last.body.nonce.new_next(), round);
    quorum.dispatch_status = Some(false);

    assert_eq!(
        state
            .get_mut_quorum(&last.hash, last.body.nonce.new_next(), round)
            .dispatch_status,
        Some(false)
    );
}

#[test]
fn epoch_approval_requires_supermajority_signatures() {
    assert!(signed_epoch(6, 4).epoch_approved().is_ok());
    assert_eq!(
        signed_epoch(6, 3).epoch_approved(),
        Err(BlossomError::FailedConsensus)
    );
}

#[test]
fn certified_epoch_requires_complete_validator_set_supermajority() {
    let keypairs = (0..24).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let mut verifiers = IndexTreeMap::new();
    for (index, keypair) in keypairs.iter().enumerate() {
        verifiers.insert(
            keypair.public,
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                format!("node-{index}"),
                9000 + index as u16,
                false,
            ),
        );
    }
    let mut previous = Epoch {
        body: EpochBody {
            verifiers: verifiers.clone(),
            nonce: Nonce::new(0),
            ..Default::default()
        },
        ..Default::default()
    };
    previous.set_hash();
    let mut next = Epoch {
        body: EpochBody {
            verifiers,
            last_epoch: previous.hash,
            previous_nonce: Some(previous.body.nonce),
            nonce: Nonce::new(1),
            ..Default::default()
        },
        ..Default::default()
    };
    next.set_hash();

    for index in 0..supermajority_count(keypairs.len()) - 1 {
        let public_key = previous.body.verifiers.get_key_from_index(index).unwrap();
        let keypair = keypairs
            .iter()
            .find(|keypair| keypair.public == *public_key)
            .unwrap();
        next.signatures
            .insert(index, keypair.signer().sign(next.hash.as_ref()));
    }
    assert_eq!(
        next.verify_certificate(&previous),
        Err(BlossomError::FailedConsensus)
    );

    let threshold_index = supermajority_count(keypairs.len()) - 1;
    let threshold_public_key = previous
        .body
        .verifiers
        .get_key_from_index(threshold_index)
        .unwrap();
    let threshold_keypair = keypairs
        .iter()
        .find(|keypair| keypair.public == *threshold_public_key)
        .unwrap();
    next.signatures.insert(
        threshold_index,
        threshold_keypair.signer().sign(next.hash.as_ref()),
    );
    next.verify_certificate(&previous).unwrap();
}

#[test]
#[cfg(not(feature = "fair-block-ordering"))]
fn block_merkle_root_uses_raw_hash_without_fair_order_feature() {
    let block = Block::empty_with_nonce(Nonce::new(1));
    let hash = block.hash();
    let mut blocks = BTreeMap::new();
    blocks.insert(hash, block);

    assert_eq!(block_merkle_root(&blocks), hash);
}

#[test]
#[cfg(feature = "fair-block-ordering")]
fn block_merkle_root_uses_fair_order_commitments() {
    let block = Block::empty_with_nonce(Nonce::new(1));
    let hash = block.hash();
    let mut blocks = BTreeMap::new();
    blocks.insert(hash, block);

    assert_eq!(
        block_merkle_root(&blocks),
        fair_ordered_block_commitments(&blocks)[0]
    );
    assert_ne!(block_merkle_root(&blocks), hash);
}

#[test]
#[cfg(feature = "fair-block-ordering")]
fn fair_ordered_epoch_hash_is_consistent_across_arrival_order() {
    let first = sealed_epoch_block("first", &["a", "b"]);
    let second = sealed_epoch_block("second", &["c"]);
    let mut first_arrival = BTreeMap::new();
    first_arrival.insert(first.hash, first.clone());
    first_arrival.insert(second.hash, second.clone());
    let mut second_arrival = BTreeMap::new();
    second_arrival.insert(second.hash, second);
    second_arrival.insert(first.hash, first);

    assert_eq!(
        fair_ordered_block_commitments(&first_arrival),
        fair_ordered_block_commitments(&second_arrival)
    );

    let mut first_epoch = Epoch {
        hash: HashType::default(),
        signatures: BTreeMap::default(),
        body: EpochBody {
            last_epoch: HashType([1; 32]),
            nonce: Nonce::new(2),
            merkle_root: block_merkle_root(&first_arrival),
            blocks: first_arrival,
            ..Default::default()
        },
    };
    first_epoch.set_hash();

    let mut second_epoch = Epoch {
        hash: HashType::default(),
        signatures: BTreeMap::default(),
        body: EpochBody {
            last_epoch: HashType([1; 32]),
            nonce: Nonce::new(2),
            merkle_root: block_merkle_root(&second_arrival),
            blocks: second_arrival,
            ..Default::default()
        },
    };
    second_epoch.set_hash();

    assert_eq!(first_epoch.body.merkle_root, second_epoch.body.merkle_root);
    assert_eq!(first_epoch.hash, second_epoch.hash);
    assert_ne!(first_epoch.body.merkle_root, first_epoch.body.blocks.hash());
}

#[test]
fn trusted_quorum_verify_accepts_unsigned_dispatch_blocks() {
    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.nonce = Nonce::new(1);
    block.body.txs.push(Transaction::new("tx"));
    block.seal_unsigned(keypair.public);
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block.clone());
    let dispatch = Dispatch {
        header: Header {
            sender: keypair.public,
            nonce: Nonce::new(1),
            signature: Signature::default(),
            ..Default::default()
        },
        body: DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree: SignatureTree::default(),
            signature_tree_hash: SignatureTree::default().hash(),
        },
    };

    let mut verified_quorum = TempQuorum {
        pending_dispatches: vec![PendingDispatch::Decoded(dispatch.clone())],
        ..Default::default()
    };
    verified_quorum.verify();
    assert!(verified_quorum.verified_blocks.is_empty());

    let mut trusted_quorum = TempQuorum {
        pending_dispatches: vec![PendingDispatch::Decoded(dispatch)],
        ..Default::default()
    };
    trusted_quorum.verify_trusted();
    assert_eq!(trusted_quorum.verified_blocks.len(), 1);
    assert!(trusted_quorum.verified_blocks.contains_key(&block.hash));
}

#[test]
fn pending_dispatch_rejects_duplicate_sender_signature() {
    let pending = hot_pending_dispatch(valid_public_key(7), Signature([1; 64]));
    let raw_len = pending.raw_payload_len().unwrap();
    let mut quorum = TempQuorum::default();

    quorum
        .try_push_pending_dispatch(pending.clone(), raw_len * 2, raw_len * 2)
        .unwrap();
    let err = quorum
        .try_push_pending_dispatch(pending, raw_len * 2, raw_len * 2)
        .unwrap_err();

    assert!(matches!(
        err,
        BlossomError::WireProtocol(message) if message.contains("duplicate pending dispatch")
    ));
    assert_eq!(quorum.pending_dispatches.len(), 1);
    assert_eq!(quorum.pending_raw_dispatch_bytes(), raw_len);
}

#[test]
fn pending_dispatch_enforces_raw_quorum_and_sender_caps() {
    let sender = valid_public_key(8);
    let first = hot_pending_dispatch(sender, Signature([1; 64]));
    let second = hot_pending_dispatch(sender, Signature([2; 64]));
    let raw_len = first.raw_payload_len().unwrap();

    let mut quorum_cap = TempQuorum::default();
    let err = quorum_cap
        .try_push_pending_dispatch(first.clone(), raw_len - 1, raw_len)
        .unwrap_err();
    assert!(matches!(
        err,
        BlossomError::WireProtocol(message) if message.contains("quorum cap")
    ));
    assert!(quorum_cap.pending_dispatches.is_empty());

    let mut sender_cap = TempQuorum::default();
    sender_cap
        .try_push_pending_dispatch(first, raw_len * 2, raw_len)
        .unwrap();
    let err = sender_cap
        .try_push_pending_dispatch(second, raw_len * 2, raw_len)
        .unwrap_err();
    assert!(matches!(
        err,
        BlossomError::WireProtocol(message) if message.contains("sender cap")
    ));
    assert_eq!(sender_cap.pending_raw_dispatch_bytes(), raw_len);
    assert_eq!(
        sender_cap.pending_raw_dispatch_bytes_for_sender(&sender),
        raw_len
    );
}

#[test]
fn quorum_verify_skips_already_verified_blocks() {
    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.last_epoch = HashType([2; 32]);
    block.body.nonce = Nonce::new(1);
    block.body.txs.push(Transaction::new("tx"));
    block.sign(&keypair.secret);
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block.clone());
    let dispatch = Dispatch {
        header: Header {
            sender: keypair.public,
            last_epoch: HashType([2; 32]),
            nonce: Nonce::new(1),
            signature: Signature::default(),
            ..Default::default()
        },
        body: DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree: SignatureTree::default(),
            signature_tree_hash: SignatureTree::default().hash(),
        },
    };
    let mut quorum = TempQuorum {
        pending_dispatches: vec![
            PendingDispatch::Decoded(dispatch.clone()),
            PendingDispatch::Decoded(dispatch),
        ],
        ..Default::default()
    };

    quorum.verify();

    assert_eq!(quorum.verified_blocks.len(), 1);
    assert_eq!(quorum.timers.verified_tx, 1);
}

#[test]
fn quorum_verify_drops_equivocating_validator_blocks() {
    let keypair = Keypair::generate();
    let mut first_block = Block::default();
    first_block.body.last_epoch = HashType([2; 32]);
    first_block.body.nonce = Nonce::new(1);
    first_block.body.txs.push(Transaction::new("first"));
    first_block.sign(&keypair.secret);

    let mut second_block = Block::default();
    second_block.body.last_epoch = HashType([2; 32]);
    second_block.body.nonce = Nonce::new(1);
    second_block.body.txs.push(Transaction::new("second"));
    second_block.sign(&keypair.secret);

    let mut blocks = BTreeMap::new();
    blocks.insert(first_block.hash, first_block);
    blocks.insert(second_block.hash, second_block);
    let dispatch = Dispatch {
        header: Header {
            sender: keypair.public,
            last_epoch: HashType([2; 32]),
            nonce: Nonce::new(1),
            signature: Signature::default(),
            ..Default::default()
        },
        body: DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree: SignatureTree::default(),
            signature_tree_hash: SignatureTree::default().hash(),
        },
    };
    let mut quorum = TempQuorum {
        pending_dispatches: vec![PendingDispatch::Decoded(dispatch)],
        ..Default::default()
    };

    quorum.verify();

    assert!(quorum.verified_blocks().is_empty());
    assert!(quorum.canonical_verified_blocks().is_empty());
    assert!(quorum.equivocating_validators.contains(&keypair.public));
    assert_eq!(quorum.timers.verified_tx, 0);
    assert_eq!(
        quorum.verified_blocks_hash,
        Some(BTreeMap::<HashType, Block>::new().hash())
    );
}

#[test]
fn verified_blocks_hash_excludes_directly_inserted_equivocations() {
    let keypair = Keypair::generate();
    let mut first_block = Block::default();
    first_block.body.last_epoch = HashType([2; 32]);
    first_block.body.nonce = Nonce::new(1);
    first_block.body.txs.push(Transaction::new("first"));
    first_block.sign(&keypair.secret);

    let mut second_block = Block::default();
    second_block.body.last_epoch = HashType([2; 32]);
    second_block.body.nonce = Nonce::new(1);
    second_block.body.txs.push(Transaction::new("second"));
    second_block.sign(&keypair.secret);

    let mut quorum = TempQuorum::default();
    quorum.verified_blocks.insert(first_block.hash, first_block);
    quorum
        .verified_blocks
        .insert(second_block.hash, second_block);

    assert!(quorum.verified_blocks().is_empty());
    assert_eq!(
        quorum.verified_blocks_hash(),
        BTreeMap::<HashType, Block>::new().hash()
    );
}

#[test]
fn quorum_verify_rejects_dispatch_blocks_for_different_epoch_target() {
    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.last_epoch = HashType([2; 32]);
    block.body.nonce = Nonce::new(2);
    block.body.txs.push(Transaction::new("tx"));
    block.sign(&keypair.secret);
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let dispatch = Dispatch {
        header: Header {
            sender: keypair.public,
            last_epoch: HashType([2; 32]),
            nonce: Nonce::new(1),
            signature: Signature::default(),
            ..Default::default()
        },
        body: DispatchBody {
            blocks_hash: blocks.hash(),
            blocks,
            signature_tree: SignatureTree::default(),
            signature_tree_hash: SignatureTree::default().hash(),
        },
    };
    let mut quorum = TempQuorum {
        pending_dispatches: vec![PendingDispatch::Decoded(dispatch)],
        ..Default::default()
    };

    quorum.verify();

    assert!(quorum.verified_blocks.is_empty());
    assert_eq!(
        quorum.verified_blocks_hash,
        Some(BTreeMap::<HashType, Block>::new().hash())
    );
}

#[test]
fn advance_epoch_with_consensus_commits_verified_blocks() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let mut verifiers = IndexTreeMap::new();
    for (index, keypair) in keypairs.iter().enumerate() {
        let identity = NodeIdentity::new(
            keypair.public,
            (index == 0).then_some(keypair.secret.clone()),
            "tcp",
            format!("node-{index}"),
            8000 + index as u16,
            false,
        );
        verifiers.insert(identity.public_key(), identity.public_only());
    }
    let mut genesis = Epoch {
        body: EpochBody {
            members: MemberSet::from_verifiers(&verifiers),
            verifiers,
            ..Default::default()
        },
        ..Default::default()
    };
    genesis.set_hash();
    let self_node = NodeIdentity::new(
        keypairs[0].public,
        Some(keypairs[0].secret.clone()),
        "tcp",
        "node-0",
        8000,
        false,
    );
    let mut state = LocalState::new(self_node, genesis.clone());
    let next_nonce = genesis.body.nonce.new_next();
    let mut block = Block::empty_with_nonce(next_nonce);
    block.body.last_epoch = genesis.hash;
    block.set_hash();
    let block_hash = block.hash;
    state
        .get_mut_quorum(&genesis.hash, next_nonce, 0)
        .verified_blocks
        .insert(block_hash, block);
    let epoch_hash = state
        .prepare_verified_epoch(&genesis.hash, next_nonce, 0)
        .unwrap()
        .unwrap()
        .hash;
    for signer in &keypairs[..4] {
        state
            .get_mut_quorum(&genesis.hash, next_nonce, 0)
            .epoch_signatures
            .insert(signer.public, signer.signer().sign(epoch_hash.as_ref()));
    }

    assert!(state.advance_epoch(&genesis.hash, next_nonce, 0, true));
    let latest = state.epochchain.epochchain.last().unwrap();
    assert_eq!(latest.body.last_epoch, genesis.hash);
    assert_eq!(latest.body.previous_nonce, Some(genesis.body.nonce));
    assert_eq!(latest.body.nonce, next_nonce);
    assert!(latest.body.blocks.contains_key(&block_hash));
}

#[test]
fn epoch_hash_commits_the_previous_nonce() {
    let mut epoch = Epoch {
        body: EpochBody {
            last_epoch: HashType([1; 32]),
            previous_nonce: Some(Nonce::new(7)),
            nonce: Nonce::new(8),
            ..Default::default()
        },
        ..Default::default()
    };
    epoch.set_hash();
    let first_hash = epoch.hash;

    epoch.body.previous_nonce = Some(Nonce::new(6));
    epoch.set_hash();
    assert_ne!(epoch.hash, first_hash);
}

#[test]
fn advance_epoch_removes_node_with_supermajority_failure_evidence() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let mut verifiers = IndexTreeMap::new();
    for (index, keypair) in keypairs.iter().enumerate() {
        let node = NodeIdentity::new(
            keypair.public,
            None,
            "tcp",
            format!("node-{index}"),
            8000 + index as u16,
            false,
        );
        verifiers.insert(node.public_key(), node);
    }
    let mut genesis = Epoch {
        body: EpochBody {
            verifiers,
            nonce: Nonce::new(0),
            ..Default::default()
        },
        ..Default::default()
    };
    genesis.set_hash();

    let mut state = LocalState::new_with_consensus_node_removal_policy(
        NodeIdentity::new(
            keypairs[0].public,
            Some(keypairs[0].secret.clone()),
            "tcp",
            "node-0",
            8000,
            false,
        ),
        genesis.clone(),
        ConsensusNodeRemovalPolicy::supermajority(),
    );
    let next_nonce = genesis.body.nonce.new_next();
    let subject = keypairs[5].public;

    for observer in &keypairs[..4] {
        let record = EncounterRecord::signed(
            EncounterRecordBody::new(
                observer.public,
                subject,
                genesis.hash,
                next_nonce,
                0,
                EncounterPhase::Verification,
                EncounterOutcome::MissingSignature,
            ),
            &observer.signer(),
        )
        .unwrap();
        let mut block = Block::default();
        block.body.last_epoch = genesis.hash;
        block.body.nonce = next_nonce;
        block.body.encounter_records.push(record);
        block.sign(&observer.secret);
        state
            .get_mut_quorum(&genesis.hash, next_nonce, 0)
            .verified_blocks
            .insert(block.hash, block);
    }
    let epoch_hash = state
        .prepare_verified_epoch(&genesis.hash, next_nonce, 0)
        .unwrap()
        .unwrap()
        .hash;
    for signer in &keypairs[..4] {
        state
            .get_mut_quorum(&genesis.hash, next_nonce, 0)
            .epoch_signatures
            .insert(signer.public, signer.signer().sign(epoch_hash.as_ref()));
    }

    assert!(state.advance_epoch(&genesis.hash, next_nonce, 0, true));
    let latest = state.epochchain.epochchain.last().unwrap();
    assert!(!latest.body.verifiers.contains_key(&subject));
    assert_eq!(latest.body.verifiers.len(), 5);
}

#[test]
fn advance_epoch_without_consensus_creates_empty_epoch() {
    let (self_node, genesis) = genesis(0);
    let mut state = LocalState::new(self_node, genesis.clone());
    let next_nonce = genesis.body.nonce.new_next();
    state.get_mut_quorum(&genesis.hash, next_nonce, 0);

    assert!(state.advance_epoch(&genesis.hash, next_nonce, 0, false));
    let latest = state.epochchain.epochchain.last().unwrap();
    assert_eq!(latest.body.last_epoch, genesis.hash);
    assert!(latest.body.blocks.is_empty());
    assert_eq!(latest.body.merkle_root, HashType::default());
}

#[test]
fn advance_epoch_rejects_mismatched_epoch_or_nonce() {
    let (self_node, genesis) = genesis(0);
    let mut state = LocalState::new(self_node, genesis.clone());

    assert!(!state.advance_epoch(&HashType([9; 32]), genesis.body.nonce.new_next(), 0, true));
    assert!(!state.advance_epoch(&genesis.hash, Nonce::new(99), 0, true));
    assert_eq!(state.epochchain.epochchain.len(), 1);
}

#[test]
fn verification_count_tracks_consensus_hash() {
    let mut count = init_verifications(6);
    let blocks_hash = HashType([3; 32]);

    for index in 0..4 {
        count.record(Verification {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash,
                blocks: BTreeMap::new(),
            },
        });
    }

    assert_eq!(count.consensus_hash(), Some(blocks_hash));
}

#[test]
fn verification_count_only_becomes_impossible_after_enough_conflicting_votes() {
    let first = HashType([3; 32]);
    let second = HashType([4; 32]);
    let mut count = init_verifications(9);

    for index in 0..4 {
        count.record(Verification {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash: first,
                blocks: BTreeMap::new(),
            },
        });
    }
    assert!(count.consensus_is_still_possible());

    for index in 4..9 {
        count.record(Verification {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash: second,
                blocks: BTreeMap::new(),
            },
        });
    }
    assert!(!count.consensus_is_still_possible());
}

#[test]
fn split_prefill_equivocation_cannot_certify_two_block_sets() {
    let first_blocks_hash = HashType([3; 32]);
    let second_blocks_hash = HashType([4; 32]);
    let mut split = init_verifications(6);

    for index in 0..3 {
        split.record(Verification {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash: first_blocks_hash,
                blocks: BTreeMap::new(),
            },
        });
    }
    for index in 3..6 {
        split.record(Verification {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash: second_blocks_hash,
                blocks: BTreeMap::new(),
            },
        });
    }

    assert_eq!(split.count.get(&first_blocks_hash), Some(&3));
    assert_eq!(split.count.get(&second_blocks_hash), Some(&3));
    assert_eq!(split.consensus_hash(), None);

    let mut converged = init_verifications(6);
    for index in 0..4 {
        converged.record(Verification {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash: first_blocks_hash,
                blocks: BTreeMap::new(),
            },
        });
    }
    for index in 4..6 {
        converged.record(Verification {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash: second_blocks_hash,
                blocks: BTreeMap::new(),
            },
        });
    }

    assert_eq!(converged.consensus_hash(), Some(first_blocks_hash));
}

#[test]
fn proposal_count_reports_true_false_or_pending() {
    let mut count = init_proposals(6);
    let approved = HashType([4; 32]);
    assert_eq!(count.consensus(), None);

    for index in 0..4 {
        count.record(Proposal {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: ProposalBody {
                consensus: true,
                approved_hash: Some(approved),
                ..Default::default()
            },
        });
    }
    assert_eq!(count.consensus(), Some(true));

    let mut failed = init_proposals(6);
    for index in 0..4 {
        failed.record(Proposal {
            header: Header {
                sender: PubKey([index; 32]),
                ..Default::default()
            },
            body: ProposalBody::default(),
        });
    }
    assert_eq!(failed.consensus(), Some(false));
}

#[test]
fn verification_count_replaces_duplicate_sender_vote() {
    let mut count = init_verifications(6);
    let first = HashType([3; 32]);
    let second = HashType([4; 32]);
    let sender = PubKey([1; 32]);

    count.record(Verification {
        header: Header {
            sender,
            ..Default::default()
        },
        body: VerificationBody {
            blocks_hash: first,
            blocks: BTreeMap::new(),
        },
    });
    count.record(Verification {
        header: Header {
            sender,
            ..Default::default()
        },
        body: VerificationBody {
            blocks_hash: second,
            blocks: BTreeMap::new(),
        },
    });

    assert_eq!(count.count.get(&first), None);
    assert_eq!(count.count.get(&second), Some(&1));
    assert_eq!(count.verifications.len(), 1);
}

#[test]
fn trusted_acknowledgements_must_converge_before_confirmation() {
    let a = PubKey([1; 32]);
    let b = PubKey([2; 32]);
    let block_a = HashType([0xA1; 32]);
    let block_b = HashType([0xB1; 32]);
    let block_c = HashType([0xC1; 32]);
    let ab = BTreeMap::from([(block_a, ()), (block_b, ())]);
    let abc = BTreeMap::from([(block_a, ()), (block_b, ()), (block_c, ())]);
    let acknowledgement = |sender, blocks: &BTreeMap<HashType, ()>| TrustedAcknowledgement {
        header: Header {
            sender,
            ..Default::default()
        },
        body: VerificationBody {
            blocks_hash: blocks.hash(),
            blocks: blocks.clone(),
        },
    };
    let mut count = init_trusted_acknowledgements(3);

    count.record(acknowledgement(a, &ab)).unwrap();
    count.record(acknowledgement(b, &ab)).unwrap();
    assert_eq!(count.consensus_hash(), Some(ab.hash()));

    count.record(acknowledgement(b, &abc)).unwrap();
    assert_eq!(count.consensus_hash(), None);
    count.record(acknowledgement(a, &abc)).unwrap();
    assert_eq!(count.consensus_hash(), Some(abc.hash()));

    assert!(count.record(acknowledgement(a, &ab)).is_err());
}

#[test]
fn proposal_count_replaces_duplicate_sender_vote() {
    let mut count = init_proposals(6);
    let first = HashType([3; 32]);
    let second = HashType([4; 32]);
    let sender = PubKey([1; 32]);

    count.record(Proposal {
        header: Header {
            sender,
            ..Default::default()
        },
        body: ProposalBody {
            consensus: true,
            approved_hash: Some(first),
            ..Default::default()
        },
    });
    count.record(Proposal {
        header: Header {
            sender,
            ..Default::default()
        },
        body: ProposalBody {
            consensus: true,
            approved_hash: Some(second),
            ..Default::default()
        },
    });

    assert_eq!(count.count.get(&first), None);
    assert_eq!(count.count.get(&second), Some(&1));
    assert_eq!(count.proposals.len(), 1);
}
