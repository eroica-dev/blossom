#![cfg(feature = "trusted-checkpoint-dag")]

use blossom::{
    ConsensusGroupId, HashType, PubKey, QuorumSize, TrustedCheckpointDag, TrustedDagIngestOutcome,
    TrustedDagVertex, TrustedDagVertexBody, find_round_number_with_size,
    run_sequential_quorum_dag_experiment,
};
use hegel::TestCase;
use hegel::generators as gs;

fn members(count: usize) -> Vec<PubKey> {
    (0..count)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
            PubKey(bytes)
        })
        .collect()
}

#[hegel::test(test_cases = 120)]
fn arbitrary_scale_topologies_converge_through_every_sequential_round(tc: TestCase) {
    let quorum_multiplier = tc.draw(gs::integers::<u8>().min_value(1).max_value(8)) as usize;
    let quorum_size = QuorumSize::new(quorum_multiplier * 3).unwrap();
    let minimum_nodes = quorum_size.get().max(6);
    let node_count = tc.draw(
        gs::integers::<u16>()
            .min_value(minimum_nodes as u16)
            .max_value(256),
    ) as usize;
    let payload_bytes = tc.draw(gs::integers::<u16>().min_value(64).max_value(u16::MAX)) as usize;
    let shuffle = tc.draw(gs::booleans());

    let report =
        run_sequential_quorum_dag_experiment(node_count, quorum_size, payload_bytes, shuffle)
            .unwrap();
    let (_, expected_rounds) = find_round_number_with_size(node_count, quorum_size);
    assert!(report.all_nodes_converged, "{report:#?}");
    assert_eq!(report.finalized_vertex_count, node_count);
    assert_eq!(report.sequential_rounds, expected_rounds);
    assert_eq!(
        report.effective_quorum_size,
        quorum_size.effective(node_count)
    );
}

#[hegel::test(test_cases = 200)]
fn reordered_origin_chain_activates_only_after_contiguous_parent_closure(tc: TestCase) {
    let count = tc.draw(gs::integers::<u8>().min_value(6).max_value(24)) as usize;
    let identities = members(count);
    let group_id = ConsensusGroupId::named("hegel-trusted-dag");
    let mut dag = TrustedCheckpointDag::new(
        identities[0],
        identities.clone(),
        group_id,
        1,
        QuorumSize::new(6).unwrap(),
        true,
    )
    .unwrap();
    let anchor = dag.head().clone();
    let first = TrustedDagVertex::new(TrustedDagVertexBody {
        group_id,
        membership_generation: 1,
        origin: identities[0],
        origin_sequence: 1,
        origin_parent: None,
        anchor_checkpoint_hash: anchor.hash,
        anchor_checkpoint_nonce: anchor.body.nonce,
        payload_root: HashType::hash(b"first"),
        command_count: 1,
        byte_length: 5,
    })
    .unwrap();
    let second = TrustedDagVertex::new(TrustedDagVertexBody {
        group_id,
        membership_generation: 1,
        origin: identities[0],
        origin_sequence: 2,
        origin_parent: Some(first.hash),
        anchor_checkpoint_hash: anchor.hash,
        anchor_checkpoint_nonce: anchor.body.nonce,
        payload_root: HashType::hash(b"second"),
        command_count: 1,
        byte_length: 6,
    })
    .unwrap();
    let child_first = tc.draw(gs::booleans());

    if child_first {
        assert_eq!(
            dag.ingest_vertex(second.clone()).unwrap(),
            TrustedDagIngestOutcome::PendingParent
        );
        assert_eq!(
            dag.ingest_vertex(first.clone()).unwrap(),
            TrustedDagIngestOutcome::Stored { activated: 2 }
        );
    } else {
        assert_eq!(
            dag.ingest_vertex(first.clone()).unwrap(),
            TrustedDagIngestOutcome::Stored { activated: 1 }
        );
        assert_eq!(
            dag.ingest_vertex(second.clone()).unwrap(),
            TrustedDagIngestOutcome::Stored { activated: 1 }
        );
    }
    assert_eq!(dag.pending_vertex_count(), 0);
    assert_eq!(dag.vertex_count(), 2);
    let candidate = dag.build_candidate([second.hash]).unwrap();
    assert_eq!(candidate.body.frontier.len(), 1);
    assert_eq!(candidate.body.frontier[0].sequence, 2);
}
