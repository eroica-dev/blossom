//! Parallel HA/global-network coordination and snapshot tests.

use super::*;
use crate::algorithm::{QuorumSize, supermajority_count};
use crate::block::Transaction;
use crate::trusted_dag::{
    TrustedDagIngestOutcome, TrustedDagRoundCompletion, TrustedDagVertex, TrustedDagVertexBody,
};

fn public_key(value: u16) -> PubKey {
    let mut bytes = [0u8; 32];
    bytes[..2].copy_from_slice(&value.to_be_bytes());
    PubKey(bytes)
}

fn identities(base: u16, count: usize) -> Vec<NodeIdentity> {
    (0..count)
        .map(|offset| {
            NodeIdentity::new(
                public_key(base + offset as u16),
                None,
                "tcp",
                "127.0.0.1",
                10_000 + base + offset as u16,
                false,
            )
        })
        .collect()
}

fn ha_runtimes() -> Vec<HighAvailabilityRuntime> {
    let members = identities(100, 3);
    let group_id = ConsensusGroupId::named("parallel-ha");
    members
        .iter()
        .map(|member| {
            HighAvailabilityRuntime::new(
                group_id,
                member.public_key(),
                members.clone(),
                HighAvailabilityParameters::default(),
            )
            .unwrap()
        })
        .collect()
}

fn finalize_ha_epoch(runtimes: &mut [HighAvailabilityRuntime], label: &str) {
    let participants = 0..runtimes.len();
    let dispatches = participants
        .clone()
        .map(|index| {
            (
                index,
                runtimes[index]
                    .build_dispatch(vec![Transaction::new(format!("{label}-{index}"))])
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    for (sender, dispatch) in &dispatches {
        for receiver in participants.clone() {
            if receiver != *sender {
                runtimes[receiver]
                    .receive_dispatch(dispatch.clone())
                    .unwrap();
            }
        }
    }
    let acknowledgements = participants
        .clone()
        .map(|index| (index, runtimes[index].acknowledge().unwrap()))
        .collect::<Vec<_>>();
    for (sender, acknowledgement) in &acknowledgements {
        for receiver in participants.clone() {
            if receiver != *sender {
                runtimes[receiver]
                    .receive_acknowledgement(acknowledgement.clone())
                    .unwrap();
            }
        }
    }
    let confirmations = participants
        .clone()
        .map(|index| (index, runtimes[index].confirm().unwrap().0))
        .collect::<Vec<_>>();
    for (sender, confirmation) in confirmations {
        for receiver in participants.clone() {
            if receiver != sender {
                runtimes[receiver]
                    .receive_confirmation(confirmation.clone())
                    .unwrap();
            }
        }
    }
    let head = runtimes[0].head().hash;
    assert!(runtimes.iter().all(|runtime| runtime.head().hash == head));
}

fn global_dag(scope: ConsensusGroupId) -> (TrustedCheckpointDag, Vec<PubKey>) {
    let members = (0..6)
        .map(|index| public_key(1_000 + index))
        .collect::<Vec<_>>();
    (
        TrustedCheckpointDag::new(
            members[0],
            members.clone(),
            scope,
            1,
            QuorumSize::new(6).unwrap(),
            false,
        )
        .unwrap(),
        members,
    )
}

fn event_vertex(
    dag: &TrustedCheckpointDag,
    origin: PubKey,
    sequence: u64,
    parent: Option<HashType>,
    event: &ParallelNetworkEvent,
) -> TrustedDagVertex {
    TrustedDagVertex::new(TrustedDagVertexBody {
        group_id: dag.head().body.group_id,
        membership_generation: dag.head().body.membership_generation,
        origin,
        origin_sequence: sequence,
        origin_parent: parent,
        anchor_checkpoint_hash: dag.head().hash,
        anchor_checkpoint_nonce: dag.head().body.nonce,
        payload_root: event.hash().unwrap(),
        command_count: 1,
        byte_length: borsh::to_vec(event).unwrap().len() as u64,
    })
    .unwrap()
}

fn finalize_global_vertex(
    dag: &mut TrustedCheckpointDag,
    vertex: TrustedDagVertex,
) -> (TrustedDagCheckpoint, Vec<HashType>) {
    assert!(matches!(
        dag.ingest_vertex(vertex.clone()).unwrap(),
        TrustedDagIngestOutcome::Stored { activated: 1 }
    ));
    let candidate = dag.build_candidate([vertex.hash]).unwrap();
    let expected = dag.expected_round_members(0).unwrap();
    let threshold = supermajority_count(expected.len());
    for member in expected.iter().take(threshold) {
        dag.record_acknowledgement(0, *member, candidate.clone())
            .unwrap();
    }
    let lock = dag.try_lock_round(0).unwrap().unwrap();
    for member in expected.iter().take(threshold) {
        dag.record_confirmation(0, *member, lock.candidate.digest)
            .unwrap();
    }
    match dag.try_complete_round(0).unwrap() {
        TrustedDagRoundCompletion::Finalized {
            checkpoint,
            ordered_vertices,
        } => (*checkpoint, ordered_vertices),
        completion => panic!("single-round global network did not finalize: {completion:?}"),
    }
}

#[test]
fn ha_and_global_memberships_remain_independent() {
    let scope = ConsensusGroupId::named("parallel-global");
    let (mut dag, global_members) = global_dag(scope);
    let runtimes = ha_runtimes();
    let registration = HaGroupRegistration::from_runtime(scope, &runtimes[0]).unwrap();

    let selected = dag.expected_round_members(0).unwrap();
    assert!(
        selected
            .iter()
            .all(|member| global_members.contains(member))
    );
    assert!(
        registration
            .members
            .iter()
            .all(|member| !selected.contains(member))
    );

    let event = ParallelNetworkEvent::RegisterHaGroup(registration.clone());
    let vertex = event_vertex(&dag, global_members[0], 1, None, &event);
    let vertex_hash = vertex.hash;
    let (checkpoint, order) = finalize_global_vertex(&mut dag, vertex);
    let mut events = BTreeMap::new();
    events.insert(vertex_hash, event);
    let mut coordinator = ParallelNetworkCoordinator::new(scope);
    coordinator
        .apply_global_checkpoint(&dag, &checkpoint, &order, &events)
        .unwrap();

    assert_eq!(coordinator.status().registered_ha_groups, 1);
    assert_eq!(coordinator.status().ha_groups_with_global_state, 0);
    assert_eq!(runtimes[0].head().nonce, Nonce::default());
}

#[test]
fn sealed_ha_state_is_ordered_globally_without_cross_advancing_either_network() {
    let scope = ConsensusGroupId::named("parallel-state");
    let (mut dag, global_members) = global_dag(scope);
    let mut runtimes = ha_runtimes();
    let registration = HaGroupRegistration::from_runtime(scope, &runtimes[0]).unwrap();
    let registration_event = ParallelNetworkEvent::RegisterHaGroup(registration.clone());
    let registration_vertex = event_vertex(&dag, global_members[0], 1, None, &registration_event);
    let registration_vertex_hash = registration_vertex.hash;
    let (registration_checkpoint, registration_order) =
        finalize_global_vertex(&mut dag, registration_vertex);
    let mut registration_events = BTreeMap::new();
    registration_events.insert(registration_vertex_hash, registration_event);
    let mut coordinator = ParallelNetworkCoordinator::new(scope);
    coordinator
        .apply_global_checkpoint(
            &dag,
            &registration_checkpoint,
            &registration_order,
            &registration_events,
        )
        .unwrap();

    assert!(
        HaGroupStateReference::from_runtime(
            &registration,
            &runtimes[0],
            HashType::hash(b"unsealed"),
            None,
        )
        .is_err()
    );
    for epoch in 0..7 {
        finalize_ha_epoch(&mut runtimes, &format!("ha-{epoch}"));
    }
    let ha_head_before_global = runtimes[0].head().hash;
    let state_reference = HaGroupStateReference::from_runtime(
        &registration,
        &runtimes[0],
        HashType::hash(b"sealed-state"),
        None,
    )
    .unwrap();
    let state_event = ParallelNetworkEvent::PublishHaState(Box::new(state_reference.clone()));
    let state_vertex = event_vertex(
        &dag,
        global_members[0],
        2,
        Some(registration_vertex_hash),
        &state_event,
    );
    let state_vertex_hash = state_vertex.hash;
    let (state_checkpoint, state_order) = finalize_global_vertex(&mut dag, state_vertex);
    let mut state_events = BTreeMap::new();
    state_events.insert(state_vertex_hash, state_event);
    coordinator
        .apply_global_checkpoint(&dag, &state_checkpoint, &state_order, &state_events)
        .unwrap();

    assert_eq!(
        coordinator.state_head(registration.ha_group_id).unwrap(),
        &state_reference
    );
    assert_eq!(coordinator.status().ha_groups_with_global_state, 1);
    assert_eq!(runtimes[0].head().hash, ha_head_before_global);
    assert_eq!(dag.head().body.nonce, Nonce::new(2));

    let encoded = borsh::to_vec(&coordinator.snapshot().unwrap()).unwrap();
    let snapshot = borsh::from_slice::<ParallelNetworkSnapshot>(&encoded).unwrap();
    let restored = ParallelNetworkCoordinator::from_snapshot(snapshot.clone()).unwrap();
    assert_eq!(restored.status(), coordinator.status());
    assert_eq!(
        restored.state_head(registration.ha_group_id),
        coordinator.state_head(registration.ha_group_id)
    );

    let mut corrupted = snapshot;
    corrupted.hash = HashType::hash(b"corrupt");
    assert!(ParallelNetworkCoordinator::from_snapshot(corrupted).is_err());
}

#[test]
fn globally_ordered_state_without_registration_is_rejected_transactionally() {
    let scope = ConsensusGroupId::named("parallel-invalid");
    let (mut dag, global_members) = global_dag(scope);
    let mut runtimes = ha_runtimes();
    let registration = HaGroupRegistration::from_runtime(scope, &runtimes[0]).unwrap();
    for epoch in 0..7 {
        finalize_ha_epoch(&mut runtimes, &format!("ha-{epoch}"));
    }
    let reference = HaGroupStateReference::from_runtime(
        &registration,
        &runtimes[0],
        HashType::hash(b"state"),
        None,
    )
    .unwrap();
    let event = ParallelNetworkEvent::PublishHaState(Box::new(reference));
    let vertex = event_vertex(&dag, global_members[0], 1, None, &event);
    let vertex_hash = vertex.hash;
    let (checkpoint, order) = finalize_global_vertex(&mut dag, vertex);
    let mut events = BTreeMap::new();
    events.insert(vertex_hash, event);
    let mut coordinator = ParallelNetworkCoordinator::new(scope);

    assert!(
        coordinator
            .apply_global_checkpoint(&dag, &checkpoint, &order, &events)
            .is_err()
    );
    assert_eq!(coordinator.status().registered_ha_groups, 0);
    assert_eq!(coordinator.status().global_checkpoint_nonce, None);
}

#[test]
fn thousand_reference_fault_soak_preserves_parallel_prefixes() {
    let scope = ConsensusGroupId::named("parallel-1001-soak");
    let (mut dag, global_members) = global_dag(scope);
    let mut runtimes = ha_runtimes();
    let registration = HaGroupRegistration::from_runtime(scope, &runtimes[0]).unwrap();
    let registration_event = ParallelNetworkEvent::RegisterHaGroup(registration.clone());
    let registration_vertex = event_vertex(&dag, global_members[0], 1, None, &registration_event);
    let mut global_parent = registration_vertex.hash;
    let (registration_checkpoint, registration_order) =
        finalize_global_vertex(&mut dag, registration_vertex);
    let mut registration_events = BTreeMap::new();
    registration_events.insert(global_parent, registration_event.clone());
    let mut coordinator = ParallelNetworkCoordinator::new(scope);
    coordinator
        .apply_global_checkpoint(
            &dag,
            &registration_checkpoint,
            &registration_order,
            &registration_events,
        )
        .unwrap();

    for epoch in 0..7 {
        finalize_ha_epoch(&mut runtimes, &format!("warmup-{epoch}"));
    }
    let mut previous_reference = None;
    for sequence in 1..=1_001u64 {
        let reference = HaGroupStateReference::from_runtime(
            &registration,
            &runtimes[0],
            HashType::hash(&sequence.to_le_bytes()),
            previous_reference.as_ref(),
        )
        .unwrap();
        let event = ParallelNetworkEvent::PublishHaState(Box::new(reference.clone()));
        let vertex = event_vertex(
            &dag,
            global_members[0],
            sequence + 1,
            Some(global_parent),
            &event,
        );
        let vertex_hash = vertex.hash;
        let (checkpoint, order) = finalize_global_vertex(&mut dag, vertex);
        let status_before = coordinator.status();

        if sequence % 97 == 0 {
            let mut wrong_events = BTreeMap::new();
            wrong_events.insert(vertex_hash, registration_event.clone());
            assert!(
                coordinator
                    .apply_global_checkpoint(&dag, &checkpoint, &order, &wrong_events)
                    .is_err()
            );
            assert_eq!(coordinator.status(), status_before);
        }

        let mut events = BTreeMap::new();
        events.insert(vertex_hash, event);
        coordinator
            .apply_global_checkpoint(&dag, &checkpoint, &order, &events)
            .unwrap();
        assert_eq!(
            coordinator
                .state_head(registration.ha_group_id)
                .unwrap()
                .body
                .export_sequence,
            sequence
        );

        if sequence % 113 == 0 {
            let committed = coordinator.status();
            assert!(
                coordinator
                    .apply_global_checkpoint(&dag, &checkpoint, &order, &events)
                    .is_err()
            );
            assert_eq!(coordinator.status(), committed);
        }

        previous_reference = Some(reference);
        global_parent = vertex_hash;
        if sequence < 1_001 {
            finalize_ha_epoch(&mut runtimes, &format!("advance-{sequence}"));
        }
    }

    assert_eq!(runtimes[0].sealed_watermark().position, 1_001);
    assert_eq!(dag.head().body.nonce, Nonce::new(1_002));
    assert_eq!(
        coordinator.status().global_checkpoint_nonce,
        Some(Nonce::new(1_002))
    );
}
