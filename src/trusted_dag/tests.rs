//! Trusted checkpoint-DAG validation and recovery tests.

use super::*;

fn members(count: usize) -> Vec<PubKey> {
    experiment_members(count)
}

fn engine(count: usize, quorum_size: usize) -> TrustedCheckpointDag {
    let members = members(count);
    TrustedCheckpointDag::new(
        members[0],
        members,
        ConsensusGroupId::named("trusted-dag-test"),
        7,
        QuorumSize::new(quorum_size).unwrap(),
        false,
    )
    .unwrap()
}

fn vertex(
    engine: &TrustedCheckpointDag,
    origin: PubKey,
    sequence: u64,
    parent: Option<HashType>,
    salt: u64,
) -> TrustedDagVertex {
    TrustedDagVertex::new(TrustedDagVertexBody {
        group_id: engine.group_id,
        membership_generation: engine.membership_generation,
        origin,
        origin_sequence: sequence,
        origin_parent: parent,
        anchor_checkpoint_hash: engine.checkpoints[0].hash,
        anchor_checkpoint_nonce: engine.checkpoints[0].body.nonce,
        payload_root: HashType::hash(&salt.to_le_bytes()),
        command_count: 1,
        byte_length: 32,
    })
    .unwrap()
}

fn lock_and_complete_round(
    engine: &mut TrustedCheckpointDag,
    round: u8,
    candidate: &TrustedDagCandidate,
) -> TrustedDagRoundCompletion {
    let expected = engine.expected_round_members(round).unwrap();
    let threshold = supermajority_count(expected.len());
    for member in expected.iter().take(threshold) {
        engine
            .record_acknowledgement(round, *member, candidate.clone())
            .unwrap();
    }
    let lock = engine.try_lock_round(round).unwrap().unwrap();
    for member in expected.iter().take(threshold) {
        engine
            .record_confirmation(round, *member, lock.candidate.digest)
            .unwrap();
    }
    engine.try_complete_round(round).unwrap()
}

fn finalize_candidate(
    engine: &mut TrustedCheckpointDag,
    candidate: &TrustedDagCandidate,
) -> (TrustedDagCheckpoint, Vec<HashType>) {
    let last_round = engine.sequential_round_count() - 1;
    for round in 0..=last_round {
        match lock_and_complete_round(engine, round, candidate) {
            TrustedDagRoundCompletion::Advanced { next_round } => {
                assert_eq!(next_round, round + 1);
            }
            TrustedDagRoundCompletion::Finalized {
                checkpoint,
                ordered_vertices,
            } => return (*checkpoint, ordered_vertices),
            TrustedDagRoundCompletion::Pending => panic!("round should complete"),
        }
    }
    panic!("topology did not finalize");
}

#[test]
fn parent_before_child_and_child_before_parent_converge() {
    let mut first = engine(6, 6);
    let origin = first.members[0];
    let first_vertex = vertex(&first, origin, 1, None, 1);
    let second_vertex = vertex(&first, origin, 2, Some(first_vertex.hash), 2);

    assert_eq!(
        first.ingest_vertex(second_vertex.clone()).unwrap(),
        TrustedDagIngestOutcome::PendingParent
    );
    assert_eq!(first.pending_vertex_count(), 1);
    assert_eq!(
        first.ingest_vertex(first_vertex.clone()).unwrap(),
        TrustedDagIngestOutcome::Stored { activated: 2 }
    );
    assert_eq!(first.pending_vertex_count(), 0);

    let mut second = engine(6, 6);
    second.ingest_vertex(first_vertex).unwrap();
    second.ingest_vertex(second_vertex).unwrap();
    assert_eq!(first.origin_index, second.origin_index);
}

#[test]
fn origin_sequence_equivocation_is_rejected() {
    let mut dag = engine(6, 6);
    let origin = dag.members[0];
    dag.ingest_vertex(vertex(&dag, origin, 1, None, 1)).unwrap();
    let error = dag
        .ingest_vertex(vertex(&dag, origin, 1, None, 2))
        .unwrap_err();
    assert!(matches!(error, BlossomError::InvalidConfiguration(_)));
}

#[test]
fn acknowledgements_are_monotonic_and_round_locks_are_immutable() {
    let mut dag = engine(6, 6);
    let origins = dag.members.clone();
    let first_vertex = vertex(&dag, origins[0], 1, None, 1);
    let second_vertex = vertex(&dag, origins[1], 1, None, 2);
    dag.ingest_vertex(first_vertex.clone()).unwrap();
    dag.ingest_vertex(second_vertex.clone()).unwrap();
    let first = dag.build_candidate([first_vertex.hash]).unwrap();
    let second = dag
        .build_candidate([first_vertex.hash, second_vertex.hash])
        .unwrap();
    let sender = dag.expected_round_members(0).unwrap()[0];
    dag.record_acknowledgement(0, sender, first.clone())
        .unwrap();
    dag.record_acknowledgement(0, sender, second.clone())
        .unwrap();
    assert!(dag.record_acknowledgement(0, sender, first).is_err());

    let expected = dag.expected_round_members(0).unwrap();
    let threshold = supermajority_count(expected.len());
    for member in expected.iter().take(threshold) {
        dag.record_acknowledgement(0, *member, second.clone())
            .unwrap();
    }
    dag.try_lock_round(0).unwrap().unwrap();
    let smaller = dag.build_candidate([first_vertex.hash]).unwrap();
    assert!(
        dag.record_acknowledgement(0, expected[threshold], smaller)
            .is_err()
    );
}

#[test]
fn confirmation_threshold_is_required_before_advancing() {
    let mut dag = engine(12, 6);
    let origin = dag.members[0];
    let vertex = vertex(&dag, origin, 1, None, 1);
    dag.ingest_vertex(vertex.clone()).unwrap();
    let candidate = dag.build_candidate([vertex.hash]).unwrap();
    let expected = dag.expected_round_members(0).unwrap();
    let threshold = supermajority_count(expected.len());
    for member in expected.iter().take(threshold) {
        dag.record_acknowledgement(0, *member, candidate.clone())
            .unwrap();
    }
    let lock = dag.try_lock_round(0).unwrap().unwrap();
    for member in expected.iter().take(threshold.saturating_sub(1)) {
        dag.record_confirmation(0, *member, lock.candidate.digest)
            .unwrap();
    }
    assert_eq!(
        dag.try_complete_round(0).unwrap(),
        TrustedDagRoundCompletion::Pending
    );
    dag.record_confirmation(0, expected[threshold - 1], lock.candidate.digest)
        .unwrap();
    assert_eq!(
        dag.try_complete_round(0).unwrap(),
        TrustedDagRoundCompletion::Advanced { next_round: 1 }
    );
}

#[test]
fn later_round_must_carry_the_confirmed_frontier() {
    let mut dag = engine(12, 6);
    let origins = dag.members.clone();
    let first_vertex = vertex(&dag, origins[0], 1, None, 1);
    let second_vertex = vertex(&dag, origins[1], 1, None, 2);
    dag.ingest_vertex(first_vertex.clone()).unwrap();
    dag.ingest_vertex(second_vertex).unwrap();
    let first = dag.build_candidate([first_vertex.hash]).unwrap();
    assert!(matches!(
        lock_and_complete_round(&mut dag, 0, &first),
        TrustedDagRoundCompletion::Advanced { .. }
    ));
    let empty = dag.build_candidate([]).unwrap();
    let sender = dag.expected_round_members(1).unwrap()[0];
    assert!(dag.record_acknowledgement(1, sender, empty).is_err());
}

#[test]
fn stable_topological_order_preserves_each_origin_chain() {
    let mut dag = engine(6, 6);
    let origins = dag.members.clone();
    let a1 = vertex(&dag, origins[0], 1, None, 1);
    let a2 = vertex(&dag, origins[0], 2, Some(a1.hash), 2);
    let b1 = vertex(&dag, origins[1], 1, None, 3);
    for vertex in [b1.clone(), a1.clone(), a2.clone()] {
        dag.ingest_vertex(vertex).unwrap();
    }
    let candidate = dag.build_candidate([a2.hash, a1.hash, b1.hash]).unwrap();
    let permuted = dag.build_candidate([b1.hash, a1.hash, a2.hash]).unwrap();
    assert_eq!(candidate, permuted);
    let (_, order) = finalize_candidate(&mut dag, &candidate);
    let a1_position = order.iter().position(|hash| *hash == a1.hash).unwrap();
    let a2_position = order.iter().position(|hash| *hash == a2.hash).unwrap();
    assert!(a1_position < a2_position);
    assert_eq!(order.len(), 3);
}

#[test]
fn late_vertex_keeps_its_original_anchor_and_enters_a_later_checkpoint() {
    let mut dag = engine(6, 6);
    let origins = dag.members.clone();
    let early = vertex(&dag, origins[0], 1, None, 1);
    let late = vertex(&dag, origins[1], 1, None, 2);
    let genesis_hash = late.body.anchor_checkpoint_hash;
    dag.ingest_vertex(early.clone()).unwrap();
    dag.ingest_vertex(late.clone()).unwrap();

    let first = dag.build_candidate([early.hash]).unwrap();
    let (_, first_order) = finalize_candidate(&mut dag, &first);
    assert_eq!(first_order, vec![early.hash]);

    let second = dag.build_candidate([late.hash]).unwrap();
    let (checkpoint, second_order) = finalize_candidate(&mut dag, &second);
    assert_eq!(late.body.anchor_checkpoint_hash, genesis_hash);
    assert_eq!(second_order, vec![late.hash]);
    assert_eq!(
        checkpoint.body.previous_checkpoint_nonce,
        Some(Nonce::new(1))
    );
    assert_eq!(checkpoint.body.nonce, Nonce::new(2));
}

#[test]
fn serialized_round_lock_restarts_without_permitting_a_second_candidate() {
    let mut original = engine(6, 6);
    let origin = original.members[0];
    let first_vertex = vertex(&original, origin, 1, None, 1);
    original.ingest_vertex(first_vertex.clone()).unwrap();
    let candidate = original.build_candidate([first_vertex.hash]).unwrap();
    let expected = original.expected_round_members(0).unwrap();
    let threshold = supermajority_count(expected.len());
    for member in expected.iter().take(threshold) {
        original
            .record_acknowledgement(0, *member, candidate.clone())
            .unwrap();
    }
    let lock = original.try_lock_round(0).unwrap().unwrap();
    let encoded = borsh::to_vec(&lock).unwrap();
    let decoded = borsh::from_slice::<TrustedDagRoundLock>(&encoded).unwrap();

    let mut restarted = engine(6, 6);
    restarted.ingest_vertex(first_vertex).unwrap();
    restarted.restore_round_lock(decoded.clone()).unwrap();
    restarted.restore_round_lock(decoded).unwrap();

    let other_origin = restarted.members[1];
    let other = vertex(&restarted, other_origin, 1, None, 2);
    restarted.ingest_vertex(other.clone()).unwrap();
    let conflicting = restarted.build_candidate([other.hash]).unwrap();
    assert!(
        restarted
            .record_acknowledgement(0, expected[threshold], conflicting)
            .is_err()
    );
}

#[test]
fn contiguous_hierarchical_locks_restore_through_the_highest_round() {
    let mut original = engine(12, 6);
    let origin = original.members[0];
    let first_vertex = vertex(&original, origin, 1, None, 1);
    original.ingest_vertex(first_vertex.clone()).unwrap();
    let candidate = original.build_candidate([first_vertex.hash]).unwrap();
    assert!(matches!(
        lock_and_complete_round(&mut original, 0, &candidate),
        TrustedDagRoundCompletion::Advanced { next_round: 1 }
    ));
    let expected = original.expected_round_members(1).unwrap();
    let threshold = supermajority_count(expected.len());
    for member in expected.iter().take(threshold) {
        original
            .record_acknowledgement(1, *member, candidate.clone())
            .unwrap();
    }
    let second_lock = original.try_lock_round(1).unwrap().unwrap();
    let first_lock = original.round_states[&0].lock.clone().unwrap();

    let mut restarted = engine(12, 6);
    restarted.ingest_vertex(first_vertex).unwrap();
    restarted.restore_round_lock(first_lock).unwrap();
    restarted.restore_round_lock(second_lock.clone()).unwrap();
    assert_eq!(restarted.round_states[&1].lock.as_ref(), Some(&second_lock));
    assert!(restarted.round_states[&0].completed);
}

#[test]
fn scale_reducer_converges_through_real_sequential_quorums() {
    for (nodes, quorum) in [(6, 6), (72, 6), (1_000, 6), (1_000, 9)] {
        let report = run_sequential_quorum_dag_experiment(
            nodes,
            QuorumSize::new(quorum).unwrap(),
            1_024,
            true,
        )
        .unwrap();
        assert!(report.all_nodes_converged, "{report:#?}");
        assert_eq!(report.finalized_vertex_count, nodes);
        assert!(report.sequential_rounds >= 1);
        assert!(
            report.compact_frontier_control_bytes
                < report.materialized_payload_bytes_on_sequential_path
        );
    }
}

#[test]
fn thousand_and_one_checkpoint_fault_soak_preserves_prefix_and_order() {
    let mut dag = engine(6, 6);
    let origins = dag.members.clone();
    let mut origin_heads = BTreeMap::<PubKey, HashType>::new();
    let mut origin_sequences = BTreeMap::<PubKey, u64>::new();
    let mut previous_checkpoint = dag.head().clone();
    let mut random = 0x8391_1634_8196_3729u64;

    for epoch in 1..=1_001u64 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let omitted_a = (random as usize) % origins.len();
        let omitted_b = ((random >> 16) as usize) % origins.len();
        let mut heads = Vec::new();
        for (index, origin) in origins.iter().copied().enumerate() {
            if index == omitted_a || index == omitted_b {
                continue;
            }
            let sequence = origin_sequences.get(&origin).copied().unwrap_or_default() + 1;
            let next = vertex(
                &dag,
                origin,
                sequence,
                origin_heads.get(&origin).copied(),
                epoch ^ index as u64,
            );
            dag.ingest_vertex(next.clone()).unwrap();
            origin_sequences.insert(origin, sequence);
            origin_heads.insert(origin, next.hash);
            heads.push(next.hash);
        }
        let candidate = dag.build_candidate(heads).unwrap();
        let (checkpoint, order) = finalize_candidate(&mut dag, &candidate);
        checkpoint.validate_hash().unwrap();
        assert_eq!(
            checkpoint.body.previous_checkpoint_hash,
            previous_checkpoint.hash
        );
        assert_eq!(
            checkpoint.body.previous_checkpoint_nonce,
            Some(previous_checkpoint.body.nonce)
        );
        assert_eq!(checkpoint.body.nonce, Nonce::new(epoch));
        assert_eq!(
            checkpoint.body.ordered_delta_root,
            protocol_commitment(ORDER_DOMAIN, &order).unwrap()
        );
        previous_checkpoint = checkpoint;
    }
    assert_eq!(dag.head().body.nonce, Nonce::new(1_001));
    assert_eq!(dag.checkpoints().len(), 1_002);
}
