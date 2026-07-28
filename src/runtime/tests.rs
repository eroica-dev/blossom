//! Shared runtime test fixtures and responsibility-focused test modules.

use super::*;

#[cfg(feature = "availability-gossip")]
use crate::FilteredPayloadDeliveryItem;
use crate::blossom::{
    BlossomBody, CommitBody, DispatchBody, EchoResponseBody, EpochStartedBody, ProposalBody,
    ReconcileCommit, ReconcileCommitBody, ReconcileResponse, ReconcileResponseBody,
    RoundSkipCertificateBody, RoundSkipCertificateMessage, VerificationBody,
};
use crate::crypto::Keypair;
use crate::round_skip::{RoundSkipCertificate, RoundSkipVote};
use crate::telemetry::InMemoryTelemetrySink;
use std::time::{SystemTime, UNIX_EPOCH};

fn runtime() -> (NodeRuntime, Keypair) {
    let keypair = Keypair::generate();
    let node = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );
    (NodeRuntime::new(RuntimeConfig::new(node)), keypair)
}

fn runtime_with_peers() -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
    runtime_with_peers_mode(TrustMode::Verified)
}

fn runtime_with_peers_mode(trust_mode: TrustMode) -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
    runtime_with_peers_mode_and_telemetry(trust_mode, None)
}

fn runtime_with_peers_mode_and_telemetry(
    trust_mode: TrustMode,
    telemetry: Option<TelemetryHandle>,
) -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8000 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(nodes.clone());
    let mut config = RuntimeConfig::new(nodes[0].clone());
    config.genesis = Some(genesis.clone());
    config.trust_mode = trust_mode;
    if let Some(telemetry) = telemetry {
        config.telemetry = telemetry;
    }
    let runtime = NodeRuntime::new(config);
    let target = EpochTarget {
        group_id: genesis.body.group_id,
        last_epoch: genesis.hash,
        nonce: genesis.body.nonce.new_next(),
    };
    (runtime, keypairs, target)
}

fn runtime_with_node_count(node_count: usize) -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
    runtime_with_node_count_mode(node_count, TrustMode::Verified)
}

fn runtime_with_node_count_mode(
    node_count: usize,
    trust_mode: TrustMode,
) -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
    runtime_with_node_count_mode_and_quorum(node_count, trust_mode, QuorumSize::DEFAULT)
}

fn runtime_with_node_count_mode_and_quorum(
    node_count: usize,
    trust_mode: TrustMode,
    quorum_size: QuorumSize,
) -> (NodeRuntime, Vec<Keypair>, EpochTarget) {
    let keypairs = (0..node_count)
        .map(|_| Keypair::generate())
        .collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8200 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch_for_group_with_parameters(
        ConsensusGroupId::root(),
        nodes.clone(),
        ConsensusParameters::new(quorum_size),
    );
    let mut config = RuntimeConfig::new(nodes[0].clone()).with_quorum_size(quorum_size);
    config.genesis = Some(genesis.clone());
    config.trust_mode = trust_mode;
    let runtime = NodeRuntime::new(config);
    let target = EpochTarget {
        group_id: genesis.body.group_id,
        last_epoch: genesis.hash,
        nonce: genesis.body.nonce.new_next(),
    };
    (runtime, keypairs, target)
}

fn establish_trusted_acknowledgement_quorum(
    runtime: &NodeRuntime,
    target: &EpochTarget,
    round: u8,
    peers: &[PubKey],
) -> TrustedAcknowledgement {
    let local = runtime
        .try_produce_trusted_acknowledgement(round)
        .unwrap()
        .expect("trusted dispatch threshold should produce an acknowledgement");
    let required_peers = supermajority_count(peers.len() + 1).saturating_sub(1);
    for peer in peers.iter().take(required_peers) {
        runtime
            .receive_message(Msg::TrustedAcknowledgement(TrustedAcknowledgement {
                header: Header {
                    sender: *peer,
                    last_epoch: target.last_epoch,
                    nonce: target.nonce,
                    round,
                    signature: Signature::default(),
                },
                body: local.body.clone(),
            }))
            .unwrap();
    }
    local
}

fn signed_test_header<T: BlossomBody>(
    signer: &Keypair,
    target: &EpochTarget,
    kind: MSGKey,
    body: &T,
) -> Header {
    signed_test_header_for_round(signer, target, 0, kind, body)
}

fn signed_test_header_for_round<T: BlossomBody>(
    signer: &Keypair,
    target: &EpochTarget,
    round: u8,
    kind: MSGKey,
    body: &T,
) -> Header {
    let signature_hash = Header::signature_hash_for_body(
        &signer.public,
        &target.last_epoch,
        target.nonce,
        round,
        kind,
        body,
    );
    Header {
        sender: signer.public,
        last_epoch: target.last_epoch,
        nonce: target.nonce,
        round,
        signature: signer.signer().sign(signature_hash.as_ref()),
    }
}

fn certified_commit_body(
    runtime: &NodeRuntime,
    signer: &Keypair,
    target: &EpochTarget,
    round: u8,
) -> CommitBody {
    let epoch_hash = runtime
        .inner
        .state
        .read()
        .expect("state lock poisoned")
        .prepare_verified_epoch(&target.last_epoch, target.nonce, round)
        .unwrap()
        .unwrap()
        .hash;
    CommitBody {
        consensus: true,
        signature_tree_insert: None,
        epoch_hash: Some(epoch_hash),
        epoch_signature: Some(signer.signer().sign(epoch_hash.as_ref())),
    }
}

fn round_signer<'a>(
    runtime: &NodeRuntime,
    keypairs: &'a [Keypair],
    target: &EpochTarget,
    round: u8,
) -> &'a Keypair {
    let sender = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(round)
            .into_iter()
            .next()
            .expect("round should include a peer")
    };
    keypairs
        .iter()
        .find(|keypair| keypair.public == sender)
        .expect("round sender should have a test keypair")
}

fn signed_block_for_target(
    signer: &Keypair,
    target: &EpochTarget,
    payload: impl Into<Vec<u8>>,
) -> Block {
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.body.txs.push(crate::block::Transaction::new(payload));
    block.sign(&signer.secret);
    block
}

fn signed_dispatch_for_blocks(
    signer: &Keypair,
    target: &EpochTarget,
    blocks: BTreeMap<HashType, Block>,
) -> Dispatch {
    signed_dispatch_for_blocks_round(signer, target, 0, blocks)
}

fn signed_dispatch_for_blocks_round(
    signer: &Keypair,
    target: &EpochTarget,
    round: u8,
    blocks: BTreeMap<HashType, Block>,
) -> Dispatch {
    let body = DispatchBody {
        blocks_hash: blocks.hash(),
        blocks,
        signature_tree: crate::SignatureTree::default(),
        signature_tree_hash: crate::SignatureTree::default().hash(),
    };
    Dispatch {
        header: signed_test_header_for_round(signer, target, round, MSGKey::Dispatch, &body),
        body,
    }
}

fn receive_valid_dispatch(
    runtime: &NodeRuntime,
    keypairs: &[Keypair],
    target: &EpochTarget,
    payload: impl Into<Vec<u8>>,
) -> (Dispatch, BTreeMap<HashType, ()>) {
    let signer = round_signer(runtime, keypairs, target, 0);
    let block = signed_block_for_target(signer, target, payload);
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let dispatch = signed_dispatch_for_blocks(signer, target, blocks);
    runtime
        .receive_message(Msg::Dispatch(dispatch.clone()))
        .unwrap();
    let approved_blocks = dispatch
        .body
        .blocks
        .keys()
        .map(|hash| (*hash, ()))
        .collect::<BTreeMap<_, _>>();
    (dispatch, approved_blocks)
}

fn verification_proof_for(
    keypairs: &[Keypair],
    target: &EpochTarget,
    round: u8,
    approved_blocks: &BTreeMap<HashType, ()>,
    signers: &[PubKey],
) -> Vec<(PubKey, Signature)> {
    let verification_body = VerificationBody {
        blocks_hash: approved_blocks.hash(),
        blocks: approved_blocks.clone(),
    };
    signers
        .iter()
        .map(|signer| {
            let keypair = keypairs
                .iter()
                .find(|keypair| keypair.public == *signer)
                .expect("proof signer should have a test keypair");
            (
                *signer,
                signed_test_header_for_round(
                    keypair,
                    target,
                    round,
                    MSGKey::Verification,
                    &verification_body,
                )
                .signature,
            )
        })
        .collect()
}

fn consensus_proposal_body(
    approved_blocks: &BTreeMap<HashType, ()>,
    verif: Option<Vec<(PubKey, Signature)>>,
) -> ProposalBody {
    ProposalBody {
        consensus: true,
        approved_blocks: Some(approved_blocks.clone()),
        approved_hash: Some(approved_blocks.hash()),
        verif,
        signature_tree: Some(approved_blocks.clone()),
        signature_tree_hash: Some(approved_blocks.hash()),
    }
}

fn receive_proposal_supermajority(
    runtime: &NodeRuntime,
    keypairs: &[Keypair],
    target: &EpochTarget,
    payload: impl Into<Vec<u8>>,
) -> (Dispatch, BTreeMap<HashType, ()>) {
    let (dispatch, approved_blocks) = receive_valid_dispatch(runtime, keypairs, target, payload);
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(dispatch.header.round)
    };
    let proof = verification_proof_for(
        keypairs,
        target,
        dispatch.header.round,
        &approved_blocks,
        &round_peers[..4],
    );

    for peer in round_peers.iter().take(4) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let body = consensus_proposal_body(&approved_blocks, Some(proof.clone()));
        runtime
            .receive_message(Msg::Proposal(Proposal {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    dispatch.header.round,
                    MSGKey::Proposal,
                    &body,
                ),
                body,
            }))
            .unwrap();
    }

    (dispatch, approved_blocks)
}

fn consensus_messages_for_target(
    signer: &Keypair,
    target: &EpochTarget,
    round: u8,
) -> Vec<(&'static str, Msg)> {
    let dispatch_body = DispatchBody::default();
    let echo_response_body = EchoResponseBody::default();
    let verification_body = VerificationBody::default();
    let proposal_body = ProposalBody::default();
    let commit_body = CommitBody::default();
    let epoch_started_body = EpochStartedBody::default();
    let requested_blocks = BTreeMap::new();
    let redispatched_blocks = BTreeMap::new();

    vec![
        (
            "dispatch",
            Msg::Dispatch(Dispatch {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    round,
                    MSGKey::Dispatch,
                    &dispatch_body,
                ),
                body: dispatch_body,
            }),
        ),
        (
            "echo_response",
            Msg::EchoResponse(EchoResponse {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    round,
                    MSGKey::EchoResponse,
                    &echo_response_body,
                ),
                body: echo_response_body,
            }),
        ),
        (
            "verification",
            Msg::Verification(Verification {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    round,
                    MSGKey::Verification,
                    &verification_body,
                ),
                body: verification_body,
            }),
        ),
        (
            "proposal",
            Msg::Proposal(Proposal {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    round,
                    MSGKey::Proposal,
                    &proposal_body,
                ),
                body: proposal_body,
            }),
        ),
        (
            "commit",
            Msg::Commit(Commit {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    round,
                    MSGKey::Commit,
                    &commit_body,
                ),
                body: commit_body,
            }),
        ),
        (
            "epoch_started",
            Msg::EpochStarted(EpochStarted {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    round,
                    MSGKey::EpochStarted,
                    &epoch_started_body,
                ),
                body: epoch_started_body,
            }),
        ),
        (
            "echo_request",
            Msg::EchoRequest(EchoRequest {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    round,
                    MSGKey::EchoRequest,
                    &requested_blocks,
                ),
                requested_blocks,
            }),
        ),
        (
            "echo_redispatch",
            Msg::EchoReDispatch(EchoReDispatch {
                header: signed_test_header_for_round(
                    signer,
                    target,
                    round,
                    MSGKey::EchoReDispatch,
                    &redispatched_blocks,
                ),
                redispatched_blocks,
            }),
        ),
    ]
}

mod gossip;
mod membership;
mod snapshots;
mod topology;
mod trusted_consensus;
mod verified_consensus;
