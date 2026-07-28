//! Round-skip evidence, threshold, and assistance tests.

use super::*;
use crate::Keypair;

fn keypairs(count: usize) -> Vec<Keypair> {
    (1..=count)
        .map(|seed| Keypair::from_secret(SecKey([seed as u8; 32])))
        .collect()
}

fn manifest(last_certified_round: Option<u8>) -> DataDisseminationManifest {
    let source_nodes = keypairs(6)
        .into_iter()
        .map(|keypair| keypair.public)
        .collect::<BTreeSet<_>>();
    let carried_block = HashType([11; 32]);
    let carried_blocks = [carried_block].into_iter().collect();
    let replica_holders = [(carried_block, source_nodes.clone())]
        .into_iter()
        .collect();
    DataDisseminationManifest {
        last_epoch: HashType([1; 32]),
        nonce: Nonce::new(7),
        first_fanout_round: 0,
        last_certified_round,
        certified_blocks_hash: HashType([2; 32]),
        carried_blocks,
        dropped_local_blocks: BTreeSet::new(),
        source_nodes,
        replica_holders,
    }
}

fn signed_votes(
    keypairs: &[Keypair],
    last_epoch: HashType,
    nonce: Nonce,
    from_round: u8,
    to_round: u8,
    manifest_hash: HashType,
    count: usize,
) -> Vec<RoundSkipVote> {
    keypairs
        .iter()
        .take(count)
        .map(|keypair| {
            RoundSkipVote::sign(
                keypair.public,
                &keypair.secret,
                last_epoch,
                nonce,
                from_round,
                to_round,
                manifest_hash,
            )
        })
        .collect()
}

#[test]
fn first_fanout_manifest_controls_local_block_carry_forward() {
    let local_block = HashType([11; 32]);

    assert_eq!(
        manifest(None).local_block_decision(&local_block),
        FutureRoundAssistDecision::AssistDroppingLocalBlock
    );
    assert_eq!(
        manifest(Some(0)).local_block_decision(&local_block),
        FutureRoundAssistDecision::Assist
    );

    let mut missing_replica = manifest(Some(0));
    missing_replica.replica_holders.clear();
    assert_eq!(
        missing_replica.local_block_decision(&local_block),
        FutureRoundAssistDecision::ServeDataBeforeAssist
    );
}

#[test]
fn carried_blocks_require_replica_evidence() {
    let mut manifest = manifest(Some(0));
    assert!(manifest.every_carried_block_has_replica());

    manifest.replica_holders.clear();
    assert!(!manifest.every_carried_block_has_replica());
}

#[test]
fn manifest_can_reconstruct_from_distributed_replicas_without_full_holder() {
    let signers = keypairs(3);
    let block_a = HashType([21; 32]);
    let block_b = HashType([22; 32]);
    let manifest = DataDisseminationManifest {
        carried_blocks: [block_a, block_b].into_iter().collect(),
        source_nodes: signers
            .iter()
            .map(|keypair| keypair.public)
            .collect::<BTreeSet<_>>(),
        replica_holders: [
            (block_a, [signers[0].public].into_iter().collect()),
            (block_b, [signers[1].public].into_iter().collect()),
        ]
        .into_iter()
        .collect(),
        ..manifest(Some(0))
    };

    assert!(manifest.full_data_holders().is_empty());
    assert!(
        manifest
            .can_reconstruct_from(&[signers[0].public, signers[1].public].into_iter().collect())
    );
    assert!(!manifest.can_reconstruct_from(&[signers[0].public].into_iter().collect()));
}

#[test]
fn byzantine_safe_replica_threshold_requires_one_more_than_fault_bound() {
    let signers = keypairs(4);
    let block = HashType([31; 32]);
    let manifest = DataDisseminationManifest {
        carried_blocks: [block].into_iter().collect(),
        source_nodes: signers
            .iter()
            .map(|keypair| keypair.public)
            .collect::<BTreeSet<_>>(),
        replica_holders: [(
            block,
            [signers[0].public, signers[1].public].into_iter().collect(),
        )]
        .into_iter()
        .collect(),
        ..manifest(Some(0))
    };

    assert_eq!(
        DataDisseminationManifest::byzantine_safe_replica_threshold(1),
        2
    );
    assert!(manifest.every_carried_block_has_byzantine_safe_replica(1));
    assert!(!manifest.every_carried_block_has_byzantine_safe_replica(2));
    assert!(manifest.can_reconstruct_from_byzantine_safe_sources(
        &[signers[0].public, signers[1].public].into_iter().collect(),
        1,
    ));
    assert!(!manifest.can_reconstruct_from_byzantine_safe_sources(
        &[signers[0].public].into_iter().collect(),
        1,
    ));
}

#[test]
fn manifest_availability_validation_rejects_insufficient_byzantine_replicas() {
    let signers = keypairs(6);
    let validators = signers
        .iter()
        .map(|keypair| keypair.public)
        .collect::<Vec<_>>();
    let mut manifest = manifest(Some(0));
    let carried_block = *manifest
        .carried_blocks
        .iter()
        .next()
        .expect("manifest should carry a block");
    manifest
        .replica_holders
        .insert(carried_block, [signers[0].public].into_iter().collect());

    assert!(manifest.validate_availability(&validators, 1).is_ok());
    let error = manifest.validate_availability(&validators, 2).unwrap_err();
    assert!(
        matches!(error, BlossomError::WireProtocol(message) if message.contains("fewer than 2"))
    );
}

#[test]
fn manifest_availability_validation_rejects_ineligible_replica_holders() {
    let signers = keypairs(7);
    let validators = signers[..6]
        .iter()
        .map(|keypair| keypair.public)
        .collect::<Vec<_>>();
    let mut manifest = manifest(Some(0));
    let carried_block = *manifest
        .carried_blocks
        .iter()
        .next()
        .expect("manifest should carry a block");
    manifest
        .replica_holders
        .insert(carried_block, [signers[6].public].into_iter().collect());

    let error = manifest.validate_availability(&validators, 1).unwrap_err();
    assert!(
        matches!(error, BlossomError::WireProtocol(message) if message.contains("replica holder"))
    );
}

#[test]
fn assist_decision_requires_skip_certificates_for_each_gap() {
    let decision = future_round_assist_decision(FutureRoundAssistInput {
        kind: FutureRoundAssistKind::RoundChangeSkip,
        last_certified_round: Some(1),
        target_round: 4,
        skip_certificates: 1,
        first_fanout_completed: true,
        local_block_in_candidate: false,
        local_block_replicated: true,
        parent_data_replicated: true,
        parent_data_repairable: true,
        holds_unreplicated_parent_data: false,
        future_body_validated: false,
    });

    assert_eq!(decision, FutureRoundAssistDecision::BufferForCertificates);
}

#[test]
fn assist_decision_serves_unreplicated_local_block_after_first_fanout() {
    let decision = future_round_assist_decision(FutureRoundAssistInput {
        kind: FutureRoundAssistKind::RoundChangeSkip,
        last_certified_round: Some(0),
        target_round: 2,
        skip_certificates: 1,
        first_fanout_completed: true,
        local_block_in_candidate: true,
        local_block_replicated: false,
        parent_data_replicated: true,
        parent_data_repairable: true,
        holds_unreplicated_parent_data: false,
        future_body_validated: false,
    });

    assert_eq!(decision, FutureRoundAssistDecision::ServeDataBeforeAssist);
}

#[test]
fn data_bearing_assist_requires_validated_future_body() {
    let decision = future_round_assist_decision(FutureRoundAssistInput {
        kind: FutureRoundAssistKind::DataBearing,
        last_certified_round: Some(1),
        target_round: 3,
        skip_certificates: 1,
        first_fanout_completed: true,
        local_block_in_candidate: false,
        local_block_replicated: true,
        parent_data_replicated: true,
        parent_data_repairable: true,
        holds_unreplicated_parent_data: false,
        future_body_validated: false,
    });

    assert_eq!(
        decision,
        FutureRoundAssistDecision::RejectDataVoteUntilValidated
    );
}

#[test]
fn certificate_counts_only_distinct_current_signed_votes() {
    let signers = keypairs(7);
    let validators = signers[..6]
        .iter()
        .map(|keypair| keypair.public)
        .collect::<Vec<_>>();
    let manifest = manifest(Some(0));
    let manifest_hash = manifest.hash();
    let mut votes = signed_votes(
        &signers,
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
        4,
    );
    votes.push(votes[0].clone());
    votes.push(RoundSkipVote::sign(
        signers[6].public,
        &signers[6].secret,
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
    ));
    let certificate = RoundSkipCertificate::new(
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
        votes,
    );

    assert_eq!(certificate.required_votes(&validators), 4);
    assert_eq!(certificate.valid_vote_count(&validators), 4);
    assert!(certificate.reaches_supermajority(&validators));
    assert_eq!(
        certificate
            .validate_against_epoch(&validators, manifest.last_epoch, manifest.nonce)
            .unwrap(),
        RoundSkipCertificateValidation {
            valid_distinct_votes: 4,
            required_votes: 4,
        }
    );
}

#[test]
fn certificate_manifest_validation_binds_hash_and_availability_threshold() {
    let signers = keypairs(6);
    let validators = signers
        .iter()
        .map(|keypair| keypair.public)
        .collect::<Vec<_>>();
    let mut manifest = manifest(Some(0));
    let carried_block = *manifest
        .carried_blocks
        .iter()
        .next()
        .expect("manifest should carry a block");
    manifest.replica_holders.insert(
        carried_block,
        [signers[0].public, signers[1].public].into_iter().collect(),
    );
    let manifest_hash = manifest.hash();
    let certificate = RoundSkipCertificate::new(
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
        signed_votes(
            &signers,
            manifest.last_epoch,
            manifest.nonce,
            1,
            2,
            manifest_hash,
            4,
        ),
    );

    assert!(
        certificate
            .validate_against_epoch_and_manifest(
                &validators,
                manifest.last_epoch,
                manifest.nonce,
                &manifest,
                DataDisseminationManifest::byzantine_safe_replica_threshold(1),
            )
            .is_ok()
    );

    let error = certificate
        .validate_against_epoch_and_manifest(
            &validators,
            manifest.last_epoch,
            manifest.nonce,
            &manifest,
            DataDisseminationManifest::byzantine_safe_replica_threshold(2),
        )
        .unwrap_err();
    assert!(
        matches!(error, BlossomError::WireProtocol(message) if message.contains("fewer than 3"))
    );

    let mut tampered_manifest = manifest.clone();
    tampered_manifest
        .dropped_local_blocks
        .insert(HashType([99; 32]));
    let error = certificate
        .validate_against_epoch_and_manifest(
            &validators,
            manifest.last_epoch,
            manifest.nonce,
            &tampered_manifest,
            1,
        )
        .unwrap_err();
    assert!(
        matches!(error, BlossomError::WireProtocol(message) if message.contains("manifest hash"))
    );
}

#[test]
fn duplicate_votes_cannot_reach_supermajority() {
    let signers = keypairs(6);
    let validators = signers
        .iter()
        .map(|keypair| keypair.public)
        .collect::<Vec<_>>();
    let manifest = manifest(Some(0));
    let manifest_hash = manifest.hash();
    let vote = RoundSkipVote::sign(
        signers[0].public,
        &signers[0].secret,
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
    );
    let certificate = RoundSkipCertificate::new(
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
        vec![vote.clone(), vote.clone(), vote.clone(), vote],
    );

    assert_eq!(certificate.valid_vote_count(&validators), 1);
    assert!(!certificate.reaches_supermajority(&validators));
}

#[test]
fn stale_certificate_is_rejected_even_with_valid_votes() {
    let signers = keypairs(6);
    let validators = signers
        .iter()
        .map(|keypair| keypair.public)
        .collect::<Vec<_>>();
    let manifest = manifest(Some(0));
    let manifest_hash = manifest.hash();
    let certificate = RoundSkipCertificate::new(
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
        signed_votes(
            &signers,
            manifest.last_epoch,
            manifest.nonce,
            1,
            2,
            manifest_hash,
            4,
        ),
    );

    assert!(
        certificate
            .validate_against_epoch(&validators, manifest.last_epoch, Nonce::new(8))
            .is_err()
    );
}

#[test]
fn malformed_or_mismatched_votes_do_not_count() {
    let signers = keypairs(6);
    let validators = signers
        .iter()
        .map(|keypair| keypair.public)
        .collect::<Vec<_>>();
    let manifest = manifest(Some(0));
    let manifest_hash = manifest.hash();
    let mut votes = signed_votes(
        &signers,
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
        4,
    );
    votes[3].manifest_hash = HashType([99; 32]);
    let certificate = RoundSkipCertificate::new(
        manifest.last_epoch,
        manifest.nonce,
        1,
        2,
        manifest_hash,
        votes,
    );

    assert_eq!(certificate.valid_vote_count(&validators), 3);
    assert!(!certificate.reaches_supermajority(&validators));
}
