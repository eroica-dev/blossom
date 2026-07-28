//! Member registry, capability, lease, and transition tests.

use super::*;
use crate::address_book::{Service, ServiceKind};
use crate::admission::NodeAdmission;
use crate::algorithm::select_quorums_from_index_tree;
use crate::crypto::Keypair;
use crate::encounter::{EncounterPhase, EncounterRecord, EncounterRecordBody};

fn verifier_set(keypairs: &[Keypair]) -> IndexTreeMap<PubKey, NodeIdentity> {
    let mut verifiers = IndexTreeMap::new();
    for (index, keypair) in keypairs.iter().enumerate() {
        verifiers.insert(
            keypair.public,
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                "127.0.0.1",
                9000 + index as u16,
                false,
            ),
        );
    }
    verifiers
}

fn evidence_block(
    observer: &Keypair,
    subject: PubKey,
    last_epoch: HashType,
    nonce: Nonce,
    outcome: EncounterOutcome,
) -> Block {
    let record = EncounterRecord::signed(
        EncounterRecordBody::new(
            observer.public,
            subject,
            last_epoch,
            nonce,
            0,
            EncounterPhase::Verification,
            outcome,
        ),
        &observer.signer(),
    )
    .unwrap();

    let mut block = Block::default();
    block.body.last_epoch = last_epoch;
    block.body.nonce = nonce;
    block.body.encounter_records.push(record);
    block.sign(&observer.secret);
    block
}

fn admission_block(
    observer: &Keypair,
    admission: crate::admission::NodeAdmission,
    last_epoch: HashType,
    nonce: Nonce,
) -> Block {
    admission_block_with_created(observer, admission, last_epoch, nonce, 0)
}

fn admission_block_with_created(
    observer: &Keypair,
    admission: crate::admission::NodeAdmission,
    last_epoch: HashType,
    nonce: Nonce,
    created: u128,
) -> Block {
    let mut block = Block::default();
    block.body.last_epoch = last_epoch;
    block.body.nonce = nonce;
    block.body.created = created;
    block.body.node_admissions.push(admission);
    block.sign(&observer.secret);
    block
}

fn signed_admission(keypair: &Keypair, last_epoch: HashType, nonce: Nonce) -> NodeAdmission {
    let service = Service::new(
        ServiceKind::Consensus,
        keypair.public,
        "tcp",
        "127.0.0.1",
        9100,
    );
    NodeAdmission::signed_for_consensus_service(service, last_epoch, nonce, &keypair.signer())
        .unwrap()
}

#[test]
fn committed_registry_separates_clients_relays_and_validators() {
    let validator = Keypair::generate();
    let client = Keypair::generate();
    let relay = Keypair::generate();
    let rotated = Keypair::generate();
    let verifiers = verifier_set(std::slice::from_ref(&validator));
    let mut members = MemberSet::from_verifiers(&verifiers);

    let client_record = MemberRecord::new(
        NodeIdentity::new(
            client.public,
            Some(client.secret.clone()),
            "tcp",
            "client",
            7000,
            false,
        ),
        [MemberCapability::Client],
        1,
    )
    .unwrap();
    members
        .apply(&MemberOperation::Add(client_record.clone()))
        .unwrap();
    assert!(
        !members
            .get(&client.public)
            .unwrap()
            .identity
            .has_signing_material()
    );
    assert!(members.active_validators().contains_key(&validator.public));
    assert!(!members.active_validators().contains_key(&client.public));

    let relay_record = MemberRecord::new(
        NodeIdentity::new(relay.public, None, "tcp", "relay", 7001, false),
        [MemberCapability::Relay],
        1,
    )
    .unwrap();
    members.apply(&MemberOperation::Add(relay_record)).unwrap();
    members
        .apply(&MemberOperation::Suspend {
            public_key: relay.public,
            generation: 2,
        })
        .unwrap();
    assert!(
        !members
            .get(&relay.public)
            .unwrap()
            .is_active_with(MemberCapability::Relay)
    );

    let rotated_record = MemberRecord::new(
        NodeIdentity::new(rotated.public, None, "tcp", "client-rotated", 7002, false),
        [MemberCapability::Client],
        2,
    )
    .unwrap();
    members
        .apply(&MemberOperation::RotateKey {
            old_public_key: client.public,
            new_record: rotated_record,
        })
        .unwrap();
    assert_eq!(
        members.get(&client.public).unwrap().status,
        MemberStatus::Revoked
    );
    assert!(
        members
            .get(&rotated.public)
            .unwrap()
            .is_active_with(MemberCapability::Client)
    );

    let committed = CommittedMemberOperation {
        group_id: ConsensusGroupId::named("registry-test"),
        parent_epoch_hash: HashType([7; 32]),
        operation: MemberOperation::Revoke {
            public_key: rotated.public,
            generation: 3,
        },
    };
    let transaction = committed.to_transaction().unwrap();
    assert_eq!(
        CommittedMemberOperation::from_transaction(&transaction)
            .unwrap()
            .unwrap(),
        committed
    );
}

#[test]
fn committed_member_operation_cannot_grant_validator_capability() {
    let validator = Keypair::generate();
    let candidate = Keypair::generate();
    let verifiers = verifier_set(std::slice::from_ref(&validator));
    let previous = MemberSet::from_verifiers(&verifiers);
    let group_id = ConsensusGroupId::named("validator-admission-boundary");
    let parent_epoch_hash = HashType([11; 32]);
    let candidate_record = MemberRecord::new(
        NodeIdentity::new(candidate.public, None, "tcp", "candidate", 7100, false),
        [MemberCapability::Validator],
        1,
    )
    .unwrap();
    let transaction = CommittedMemberOperation {
        group_id,
        parent_epoch_hash,
        operation: MemberOperation::Add(candidate_record),
    }
    .to_transaction()
    .unwrap();
    let mut block = Block::default();
    block.body.last_epoch = parent_epoch_hash;
    block.body.nonce = Nonce::new(1);
    block.body.txs.push(transaction);
    block.sign(&validator.secret);
    let blocks = [(block.hash, block)].into_iter().collect();

    let (next_members, next_validators) = apply_epoch_member_registry_transition(
        &previous,
        &verifiers,
        &blocks,
        group_id,
        parent_epoch_hash,
    );

    assert!(next_members.get(&candidate.public).is_none());
    assert!(!next_validators.contains_key(&candidate.public));
    assert_eq!(next_validators.len(), verifiers.len());
}

#[test]
fn member_key_rotation_cannot_bypass_validator_admission() {
    let validator = Keypair::generate();
    let client = Keypair::generate();
    let rotated = Keypair::generate();
    let mut members = MemberSet::from_verifiers(&verifier_set(std::slice::from_ref(&validator)));
    members
        .apply(&MemberOperation::Add(
            MemberRecord::new(
                NodeIdentity::new(client.public, None, "tcp", "client", 7101, false),
                [MemberCapability::Client],
                1,
            )
            .unwrap(),
        ))
        .unwrap();

    let result = members.apply(&MemberOperation::RotateKey {
        old_public_key: client.public,
        new_record: MemberRecord::new(
            NodeIdentity::new(rotated.public, None, "tcp", "rotated", 7102, false),
            [MemberCapability::Client, MemberCapability::Validator],
            2,
        )
        .unwrap(),
    });

    assert!(matches!(
        result,
        Err(BlossomError::InvalidConfiguration(message))
            if message.contains("certified node-admission")
    ));
    assert!(members.get(&rotated.public).is_none());
}

#[test]
fn supermajority_evidence_plans_node_removal() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let verifiers = verifier_set(&keypairs);
    let subject = keypairs[5].public;
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let blocks = keypairs[..4]
        .iter()
        .map(|observer| {
            let block = evidence_block(
                observer,
                subject,
                last_epoch,
                nonce,
                EncounterOutcome::MissingSignature,
            );
            (block.hash, block)
        })
        .collect::<BTreeMap<_, _>>();

    let plan = derive_consensus_node_removal_plan(
        &verifiers,
        &blocks,
        last_epoch,
        nonce,
        ConsensusNodeRemovalPolicy::supermajority(),
    );

    assert_eq!(plan.retained_verifier_count, 5);
    assert_eq!(plan.decisions.len(), 1);
    assert_eq!(plan.decisions[0].subject, subject);
    assert_eq!(plan.decisions[0].observer_count, 4);
    assert_eq!(plan.decisions[0].required_observers, 4);
}

#[test]
fn disabled_policy_never_removes_nodes() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let verifiers = verifier_set(&keypairs);
    let subject = keypairs[5].public;
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let blocks = keypairs[..4]
        .iter()
        .map(|observer| {
            let block = evidence_block(
                observer,
                subject,
                last_epoch,
                nonce,
                EncounterOutcome::MissingSignature,
            );
            (block.hash, block)
        })
        .collect::<BTreeMap<_, _>>();

    let plan = derive_consensus_node_removal_plan(
        &verifiers,
        &blocks,
        last_epoch,
        nonce,
        ConsensusNodeRemovalPolicy::disabled(),
    );

    assert!(plan.is_empty());
    assert_eq!(plan.retained_verifier_count, 6);
}

#[test]
fn required_observer_override_cannot_lower_supermajority_threshold() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let verifiers = verifier_set(&keypairs);
    let subject = keypairs[5].public;
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let blocks = keypairs[..3]
        .iter()
        .map(|observer| {
            let block = evidence_block(
                observer,
                subject,
                last_epoch,
                nonce,
                EncounterOutcome::MissingSignature,
            );
            (block.hash, block)
        })
        .collect::<BTreeMap<_, _>>();
    let policy = ConsensusNodeRemovalPolicy::supermajority().with_required_observers(2);

    let plan = derive_consensus_node_removal_plan(&verifiers, &blocks, last_epoch, nonce, policy);

    assert_eq!(policy.required_observers_for(verifiers.len()), 4);
    assert!(plan.is_empty());
}

#[test]
fn stale_duplicate_or_unknown_evidence_does_not_count() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let unknown = Keypair::generate();
    let verifiers = verifier_set(&keypairs);
    let subject = keypairs[5].public;
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let mut blocks = BTreeMap::new();

    let first = evidence_block(
        &keypairs[0],
        subject,
        last_epoch,
        nonce,
        EncounterOutcome::MissingSignature,
    );
    let duplicate = evidence_block(
        &keypairs[0],
        subject,
        last_epoch,
        nonce,
        EncounterOutcome::InvalidSignature,
    );
    let stale = evidence_block(
        &keypairs[1],
        subject,
        last_epoch,
        Nonce::new(1),
        EncounterOutcome::MissingSignature,
    );
    let outsider = evidence_block(
        &unknown,
        subject,
        last_epoch,
        nonce,
        EncounterOutcome::MissingSignature,
    );

    blocks.insert(first.hash, first);
    blocks.insert(duplicate.hash, duplicate);
    blocks.insert(stale.hash, stale);
    blocks.insert(outsider.hash, outsider);

    let plan = derive_consensus_node_removal_plan(
        &verifiers,
        &blocks,
        last_epoch,
        nonce,
        ConsensusNodeRemovalPolicy::supermajority(),
    );

    assert!(plan.is_empty());
    assert_eq!(plan.retained_verifier_count, 6);
}

#[test]
fn policy_caps_removals_and_preserves_minimum_verifiers() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let verifiers = verifier_set(&keypairs);
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let mut blocks = BTreeMap::new();

    for subject in [keypairs[4].public, keypairs[5].public] {
        for observer in &keypairs[..4] {
            let block = evidence_block(
                observer,
                subject,
                last_epoch,
                nonce,
                EncounterOutcome::MissingSignature,
            );
            blocks.insert(block.hash, block);
        }
    }

    let policy = ConsensusNodeRemovalPolicy {
        enabled: true,
        min_remaining_verifiers: 5,
        max_removals_per_epoch: 2,
        required_observers: None,
    };
    let plan = derive_consensus_node_removal_plan(&verifiers, &blocks, last_epoch, nonce, policy);

    assert_eq!(plan.decisions.len(), 1);
    assert_eq!(plan.retained_verifier_count, 5);
}

#[test]
fn pruned_verifier_set_produces_compatible_round_schedules() {
    let keypairs = (0..13).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let verifiers = verifier_set(&keypairs);
    let last_epoch = HashType([7; 32]);
    let nonce = Nonce::new(3);
    let removed_subjects = [keypairs[11].public, keypairs[12].public];
    let mut blocks = BTreeMap::new();

    for subject in removed_subjects {
        for observer in &keypairs[..9] {
            let block = evidence_block(
                observer,
                subject,
                last_epoch,
                nonce,
                EncounterOutcome::MissingSignature,
            );
            blocks.insert(block.hash, block);
        }
    }

    let (next_verifiers, plan) = apply_epoch_membership_transition(
        &verifiers,
        &blocks,
        last_epoch,
        nonce,
        ConsensusNodeRemovalPolicy::supermajority()
            .with_min_remaining_verifiers(6)
            .with_max_removals_per_epoch(2),
    );

    assert_eq!(plan.decisions.len(), 2);
    assert_eq!(next_verifiers.len(), 11);
    for subject in removed_subjects {
        assert!(!next_verifiers.contains_key(&subject));
    }

    let seed = HashType::hash(b"post-prune-round-schedule");
    for self_key in next_verifiers.keys().copied().collect::<Vec<_>>() {
        let self_quorums = select_quorums_from_index_tree(&next_verifiers, &self_key, seed, true);
        assert!(!self_quorums.is_empty());
        for (round, quorum) in self_quorums.iter().enumerate() {
            assert!(quorum.contains(&self_key));
            for peer in quorum {
                let peer_quorums =
                    select_quorums_from_index_tree(&next_verifiers, peer, seed, true);
                assert_eq!(
                    peer_quorums.get(round),
                    Some(quorum),
                    "round {round} self {self_key} peer {peer}"
                );
            }
        }
    }
}

#[test]
fn deterministic_order_prefers_invalid_signature_evidence() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let verifiers = verifier_set(&keypairs);
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let invalid_subject = keypairs[4].public;
    let missing_subject = keypairs[5].public;
    let mut blocks = BTreeMap::new();

    for observer in &keypairs[..4] {
        let invalid_block = evidence_block(
            observer,
            invalid_subject,
            last_epoch,
            nonce,
            EncounterOutcome::InvalidSignature,
        );
        blocks.insert(invalid_block.hash, invalid_block);

        let missing_block = evidence_block(
            observer,
            missing_subject,
            last_epoch,
            nonce,
            EncounterOutcome::MissingSignature,
        );
        blocks.insert(missing_block.hash, missing_block);
    }

    let plan = derive_consensus_node_removal_plan(
        &verifiers,
        &blocks,
        last_epoch,
        nonce,
        ConsensusNodeRemovalPolicy::supermajority(),
    );

    assert_eq!(plan.decisions.len(), 1);
    assert_eq!(plan.decisions[0].subject, invalid_subject);
    assert_eq!(plan.decisions[0].invalid_signature_count, 4);
}

#[test]
fn single_validator_signed_node_admission_adds_new_verifier() {
    let keypairs = [Keypair::generate()];
    let joiner = Keypair::generate();
    let verifiers = verifier_set(&keypairs);
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let admission = signed_admission(&joiner, last_epoch, nonce);
    let block = admission_block(&keypairs[0], admission, last_epoch, nonce);
    let blocks = [(block.hash, block)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let (next_verifiers, removal_plan) = apply_epoch_membership_transition(
        &verifiers,
        &blocks,
        last_epoch,
        nonce,
        ConsensusNodeRemovalPolicy::disabled(),
    );

    assert!(removal_plan.is_empty());
    assert!(next_verifiers.contains_key(&joiner.public));
    assert_eq!(next_verifiers.len(), verifiers.len() + 1);
}

#[test]
fn signed_node_admission_requires_supermajority_of_current_verifiers() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let joiner = Keypair::generate();
    let verifiers = verifier_set(&keypairs);
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let admission = signed_admission(&joiner, last_epoch, nonce);
    let blocks = keypairs[..3]
        .iter()
        .map(|observer| {
            let block = admission_block(observer, admission.clone(), last_epoch, nonce);
            (block.hash, block)
        })
        .collect::<BTreeMap<_, _>>();

    let plan = derive_consensus_node_admission_plan(&verifiers, &blocks, last_epoch, nonce);

    assert_eq!(plan.required_observers, 4);
    assert!(plan.is_empty());
}

#[test]
fn duplicate_admission_votes_from_one_validator_do_not_satisfy_quorum() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let joiner = Keypair::generate();
    let verifiers = verifier_set(&keypairs);
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let admission = signed_admission(&joiner, last_epoch, nonce);
    let blocks = (0..4)
        .map(|index| {
            let block = admission_block_with_created(
                &keypairs[0],
                admission.clone(),
                last_epoch,
                nonce,
                index,
            );
            (block.hash, block)
        })
        .collect::<BTreeMap<_, _>>();

    let plan = derive_consensus_node_admission_plan(&verifiers, &blocks, last_epoch, nonce);

    assert_eq!(plan.required_observers, 4);
    assert!(plan.is_empty());
}

#[test]
fn supermajority_signed_node_admission_adds_new_verifier() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let joiner = Keypair::generate();
    let verifiers = verifier_set(&keypairs);
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let admission = signed_admission(&joiner, last_epoch, nonce);
    let blocks = keypairs[..4]
        .iter()
        .map(|observer| {
            let block = admission_block(observer, admission.clone(), last_epoch, nonce);
            (block.hash, block)
        })
        .collect::<BTreeMap<_, _>>();

    let (next_verifiers, removal_plan) = apply_epoch_membership_transition(
        &verifiers,
        &blocks,
        last_epoch,
        nonce,
        ConsensusNodeRemovalPolicy::disabled(),
    );

    assert!(removal_plan.is_empty());
    assert!(next_verifiers.contains_key(&joiner.public));
    assert_eq!(next_verifiers.len(), verifiers.len() + 1);
    let plan = derive_consensus_node_admission_plan(&verifiers, &blocks, last_epoch, nonce);
    assert_eq!(plan.decisions.len(), 1);
    assert_eq!(plan.decisions[0].observer_count, 4);
    assert_eq!(plan.decisions[0].required_observers, 4);
}

#[test]
fn stale_or_unsigned_node_admissions_do_not_add_verifiers() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let joiner = Keypair::generate();
    let verifiers = verifier_set(&keypairs);
    let last_epoch = HashType([1; 32]);
    let nonce = Nonce::new(2);
    let stale = signed_admission(&joiner, last_epoch, Nonce::new(1));
    let block = admission_block(&keypairs[0], stale, last_epoch, nonce);
    let blocks = [(block.hash, block)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    let plan = derive_consensus_node_admission_plan(&verifiers, &blocks, last_epoch, nonce);

    assert!(plan.is_empty());
}
