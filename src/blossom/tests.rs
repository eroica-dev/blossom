//! Consensus message validation and transition tests.

use super::*;
use crate::block::{Block, Transaction};
use crate::crypto::Keypair;
use crate::error::BlossomError;
use crate::node::NodeIdentity;
use crate::nonce::Nonce;

fn node(keypair: &Keypair) -> NodeIdentity {
    NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    )
}

fn signed_block(keypair: &Keypair) -> Block {
    let mut block = Block::default();
    block.body.nonce = Nonce::new(1);
    block.body.txs.push(Transaction::new("tx"));
    block.sign(&keypair.secret);
    block
}

#[test]
fn signature_tree_insert_verify_get_and_remove() {
    let keypair = Keypair::generate();
    let mut blocks = BTreeMap::new();
    blocks.insert(HashType([1; 32]), ());
    let blocks_hash = blocks.hash();
    let signature = Signature::sign(blocks_hash.as_ref(), &keypair.secret);
    let mut tree = SignatureTree::default();

    tree.insert(&keypair.public, &signature, &blocks);

    assert_eq!(tree.len(), 1);
    assert!(!tree.is_empty());
    assert!(tree.verify());
    assert!(tree.get(&blocks_hash).is_some());
    assert!(tree.remove(&blocks_hash).is_some());
    assert!(tree.is_empty());
}

#[test]
fn signature_tree_rejects_bad_hashes_and_signatures() {
    let keypair = Keypair::generate();
    let mut blocks = BTreeMap::new();
    blocks.insert(HashType([1; 32]), ());
    let signature = Signature::sign(HashType([9; 32]).as_ref(), &keypair.secret);
    let mut tree = SignatureTree::default();
    tree.0
        .insert(blocks.hash(), (vec![(keypair.public, signature)], blocks));

    assert!(!tree.verify());
}

#[test]
fn dispatch_body_accepts_valid_blocks_and_rejects_bad_body_hash() {
    let keypair = Keypair::generate();
    let block = signed_block(&keypair);
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block.clone());
    let body = DispatchBody {
        blocks_hash: blocks.hash(),
        blocks: blocks.clone(),
        signature_tree: SignatureTree::default(),
        signature_tree_hash: SignatureTree::default().hash(),
    };

    assert!(body.validate().is_ok());
    let (accepted, accepted_hash, tree, tree_hash) = body.verify_body(&BTreeMap::new());
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted.get(&block.hash).unwrap().hash, block.hash);
    assert_eq!(accepted_hash, accepted.hash());
    assert_eq!(tree_hash, tree.hash());

    let mut bad_body = body;
    bad_body.blocks_hash = HashType([9; 32]);
    assert!(matches!(
        bad_body.validate(),
        Err(BlossomError::WireProtocol(message))
            if message.contains("dispatch blocks hash")
    ));
    let (accepted, accepted_hash, _, tree_hash) = bad_body.verify_body(&BTreeMap::new());
    assert!(accepted.is_empty());
    assert_eq!(accepted_hash, HashType::default());
    assert_eq!(tree_hash, HashType::default());
}

#[test]
fn dispatch_body_rejects_bad_signature_tree_hash() {
    let keypair = Keypair::generate();
    let block = signed_block(&keypair);
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let body = DispatchBody {
        blocks_hash: blocks.hash(),
        blocks,
        signature_tree: SignatureTree::default(),
        signature_tree_hash: HashType([9; 32]),
    };

    assert!(matches!(
        body.validate(),
        Err(BlossomError::WireProtocol(message))
            if message.contains("dispatch signature-tree hash")
    ));
}

#[test]
fn verified_dispatch_rejects_signed_blocks_with_bad_merkle_roots() {
    let keypair = Keypair::generate();
    let signer = keypair.signer();
    let mut block = Block::default();
    block.body.validator = keypair.public;
    block.body.nonce = Nonce::new(1);
    block.body.txs.push(Transaction::new("tx"));
    block.body.merkle_root = HashType([9; 32]);
    block.hash = block.body.hash();
    block.signature = signer.sign(block.hash.as_ref());

    assert!(block.verify_signature().is_ok());
    assert_eq!(
        block.verify_integrity(),
        Err(BlossomError::InvalidBlockHash)
    );

    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let body = DispatchBody {
        blocks_hash: blocks.hash(),
        blocks,
        signature_tree: SignatureTree::default(),
        signature_tree_hash: SignatureTree::default().hash(),
    };

    let (accepted, accepted_hash, _, _) = body.verify_body(&BTreeMap::new());

    assert!(accepted.is_empty());
    assert_eq!(accepted_hash, accepted.hash());
}

#[test]
fn trusted_dispatch_body_accepts_unsigned_integrity_checked_blocks() {
    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.nonce = Nonce::new(1);
    block.body.txs.push(Transaction::new("tx"));
    block.seal_unsigned(keypair.public);
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block.clone());
    let body = DispatchBody {
        blocks_hash: blocks.hash(),
        blocks,
        signature_tree: SignatureTree::default(),
        signature_tree_hash: SignatureTree::default().hash(),
    };

    let (verified, _, _, _) = body.verify_body(&BTreeMap::new());
    assert!(verified.is_empty());

    let (trusted, trusted_hash, _, _) = body.verify_body_trusted(&BTreeMap::new());
    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted.get(&block.hash).unwrap().hash, block.hash);
    assert_eq!(trusted_hash, trusted.hash());
}

#[test]
fn dispatch_add_blocks_skips_empty_blocks() {
    let keypair = Keypair::generate();
    let full = signed_block(&keypair);
    let mut empty = Block::default();
    empty.body.nonce = Nonce::new(1);
    empty.sign(&keypair.secret);
    let mut incoming = BTreeMap::new();
    incoming.insert(full.hash, full.clone());
    incoming.insert(empty.hash, empty);
    let mut pending = BTreeMap::new();

    Dispatch::add_blocks(&mut pending, &incoming);

    assert_eq!(pending.len(), 1);
    assert!(pending.contains_key(&full.hash));
}

#[test]
fn body_signatures_verify_against_sender_identity() {
    let keypair = Keypair::generate();
    let node = node(&keypair);
    let body = VerificationBody {
        blocks_hash: HashType([3; 32]),
        blocks: BTreeMap::new(),
    };
    let signature = body.signature(&node).unwrap();

    assert!(body.verify(&signature, &keypair.public).is_ok());
    assert!(body.verify(&signature, &PubKey([9; 32])).is_err());
}

#[test]
fn header_signature_binds_message_context() {
    let keypair = Keypair::generate();
    let body = VerificationBody {
        blocks_hash: HashType([3; 32]),
        blocks: BTreeMap::new(),
    };
    let last_epoch = HashType([2; 32]);
    let nonce = Nonce::new(7);
    let round = 1;
    let signature_hash = Header::signature_hash_for_body(
        &keypair.public,
        &last_epoch,
        nonce,
        round,
        MSGKey::Verification,
        &body,
    );
    let header = Header {
        sender: keypair.public,
        last_epoch,
        nonce,
        round,
        signature: keypair.signer().sign(signature_hash.as_ref()),
    };

    assert!(header.verify_signature(MSGKey::Verification, &body).is_ok());

    let mut replayed = header;
    replayed.round = 2;
    assert!(
        replayed
            .verify_signature(MSGKey::Verification, &body)
            .is_err()
    );
}

#[test]
fn header_signature_binds_verification_block_set() {
    let keypair = Keypair::generate();
    let mut blocks = BTreeMap::new();
    blocks.insert(HashType([1; 32]), ());
    let body = VerificationBody {
        blocks_hash: blocks.hash(),
        blocks,
    };
    let header = Header {
        sender: keypair.public,
        last_epoch: HashType([2; 32]),
        nonce: Nonce::new(7),
        round: 1,
        signature: keypair.signer().sign(
            Header::signature_hash_for_body(
                &keypair.public,
                &HashType([2; 32]),
                Nonce::new(7),
                1,
                MSGKey::Verification,
                &body,
            )
            .as_ref(),
        ),
    };
    let mut tampered = body.clone();
    tampered.blocks.insert(HashType([9; 32]), ());

    assert!(header.verify_signature(MSGKey::Verification, &body).is_ok());
    assert!(
        header
            .verify_signature(MSGKey::Verification, &tampered)
            .is_err()
    );
}

#[test]
fn verification_body_validate_rejects_mismatched_block_hash() {
    let mut blocks = BTreeMap::new();
    blocks.insert(HashType([1; 32]), ());
    let body = VerificationBody {
        blocks_hash: HashType([9; 32]),
        blocks,
    };

    assert!(matches!(
        body.validate(),
        Err(BlossomError::WireProtocol(message))
            if message.contains("verification blocks hash")
    ));
}

#[test]
fn proposal_signature_binds_embedded_proof_fields() {
    let keypair = Keypair::generate();
    let mut approved_blocks = BTreeMap::new();
    approved_blocks.insert(HashType([1; 32]), ());
    let body = ProposalBody {
        consensus: true,
        approved_hash: Some(approved_blocks.hash()),
        approved_blocks: Some(approved_blocks.clone()),
        verif: Some(vec![(keypair.public, Signature([7; 64]))]),
        signature_tree: Some(approved_blocks.clone()),
        signature_tree_hash: Some(approved_blocks.hash()),
    };
    let header = signed_header_for_body(&keypair, MSGKey::Proposal, &body);
    let mut tampered = body.clone();
    tampered.verif = Some(vec![(keypair.public, Signature([8; 64]))]);

    assert!(body.validate().is_ok());
    assert!(header.verify_signature(MSGKey::Proposal, &body).is_ok());
    assert!(
        header
            .verify_signature(MSGKey::Proposal, &tampered)
            .is_err()
    );
}

#[test]
fn proposal_body_validate_rejects_missing_and_mismatched_proofs() {
    let missing_blocks = ProposalBody {
        consensus: true,
        approved_blocks: None,
        approved_hash: Some(HashType([1; 32])),
        verif: None,
        signature_tree: None,
        signature_tree_hash: None,
    };
    assert!(matches!(
        missing_blocks.validate(),
        Err(BlossomError::WireProtocol(message))
            if message.contains("approved blocks")
    ));

    let mut approved_blocks = BTreeMap::new();
    approved_blocks.insert(HashType([1; 32]), ());
    let mismatched_hash = ProposalBody {
        consensus: true,
        approved_blocks: Some(approved_blocks.clone()),
        approved_hash: Some(HashType([9; 32])),
        verif: None,
        signature_tree: None,
        signature_tree_hash: None,
    };
    assert!(matches!(
        mismatched_hash.validate(),
        Err(BlossomError::WireProtocol(message))
            if message.contains("approved hash")
    ));

    let mismatched_tree = ProposalBody {
        consensus: true,
        approved_hash: Some(approved_blocks.hash()),
        approved_blocks: Some(approved_blocks.clone()),
        verif: None,
        signature_tree: Some(approved_blocks),
        signature_tree_hash: Some(HashType([8; 32])),
    };
    assert!(matches!(
        mismatched_tree.validate(),
        Err(BlossomError::WireProtocol(message))
            if message.contains("signature-tree hash")
    ));
}

#[test]
fn commit_signature_binds_consensus_decision() {
    let keypair = Keypair::generate();
    let body = CommitBody {
        consensus: true,
        signature_tree_insert: None,
        epoch_hash: None,
        epoch_signature: None,
    };
    let header = signed_header_for_body(&keypair, MSGKey::Commit, &body);
    let tampered = CommitBody {
        consensus: false,
        signature_tree_insert: None,
        epoch_hash: None,
        epoch_signature: None,
    };

    assert!(header.verify_signature(MSGKey::Commit, &body).is_ok());
    assert!(header.verify_signature(MSGKey::Commit, &tampered).is_err());
}

#[test]
fn echo_recovery_signatures_bind_requested_and_redispatched_blocks() {
    let keypair = Keypair::generate();
    let mut requested = BTreeMap::new();
    requested.insert(HashType([1; 32]), ());
    let request_header = signed_header_for_body(&keypair, MSGKey::EchoRequest, &requested);
    let mut tampered_requested = requested.clone();
    tampered_requested.insert(HashType([2; 32]), ());

    assert!(
        request_header
            .verify_signature(MSGKey::EchoRequest, &requested)
            .is_ok()
    );
    assert!(
        request_header
            .verify_signature(MSGKey::EchoRequest, &tampered_requested)
            .is_err()
    );

    let block = signed_block(&keypair);
    let mut redispatched = BTreeMap::new();
    redispatched.insert(block.hash, block.clone());
    let redispatch_header = signed_header_for_body(&keypair, MSGKey::EchoReDispatch, &redispatched);
    let mut tampered_block = block;
    tampered_block.body.txs.push(Transaction::new("tamper"));
    let mut tampered_redispatched = BTreeMap::new();
    tampered_redispatched.insert(tampered_block.hash, tampered_block);

    assert!(
        redispatch_header
            .verify_signature(MSGKey::EchoReDispatch, &redispatched)
            .is_ok()
    );
    assert!(
        redispatch_header
            .verify_signature(MSGKey::EchoReDispatch, &tampered_redispatched)
            .is_err()
    );
}

fn signed_header_for_body<T: BlossomBody>(keypair: &Keypair, kind: MSGKey, body: &T) -> Header {
    let last_epoch = HashType([2; 32]);
    let nonce = Nonce::new(7);
    let round = 1;
    Header {
        sender: keypair.public,
        last_epoch,
        nonce,
        round,
        signature: keypair.signer().sign(
            Header::signature_hash_for_body(&keypair.public, &last_epoch, nonce, round, kind, body)
                .as_ref(),
        ),
    }
}
