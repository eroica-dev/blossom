//! Epoch benchmark argument and scenario tests.

use super::*;

fn key(index: u8) -> PubKey {
    PubKey([index; 32])
}

#[test]
fn thirty_six_nodes_have_two_rounds_of_six_quorums() {
    let keys = (0..36).map(key).collect::<Vec<_>>();
    let rounds = round_quorums(&keys, HashType::default(), false, 6);

    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[0].len(), 6);
    assert_eq!(rounds[1].len(), 6);
    assert!(rounds.iter().flatten().all(|quorum| quorum.len() == 6));
}

#[test]
fn target_transactions_derives_epoch_depth() {
    let args = Args {
        nodes: 36,
        quorum_size: 6,
        epoch_depth: 1,
        target_transactions: Some(1_000_000),
        transactions_per_node: 1_000,
        transaction_bytes: 32,
        application_state_bytes: 0,
        shuffle: false,
        trusted: false,
        latency_distribution: LatencyDistribution::Even,
        latency_ms: 1,
        latency_min_ms: 1,
        latency_max_ms: 300,
        latency_seed: 0,
        csv: None,
        append: false,
    };

    assert_eq!(epoch_depth(&args), 28);
}

#[test]
fn dispatch_profile_len_matches_full_wire_dispatch() {
    let nodes = build_nodes(1);
    let last_epoch = HashType::hash(b"epoch");
    let nonce = Nonce::new(9);
    let block = signed_block(
        &nodes[0],
        last_epoch,
        nonce,
        transactions(0, 0, 3, 32),
        0,
        false,
    );
    let block = BlockHandle::new(block).unwrap();
    let mut blocks = BlockIndex::new();
    blocks.insert(block.hash(), block);

    let profile = dispatch_profile_for(&nodes[0], &blocks, last_epoch, nonce, 0, false).unwrap();
    let dispatch = dispatch_for(
        &nodes[0],
        materialize_blocks(&blocks),
        last_epoch,
        nonce,
        0,
        false,
    )
    .unwrap();
    let framed = framed_len(&WireRequest::Message(Msg::Dispatch(dispatch))).unwrap();

    assert_eq!(profile.framed_len, framed);
}

#[test]
fn trusted_epoch_counts_dispatch_only_and_converges() {
    let nodes = build_nodes(36);
    let row = run_epoch(
        0,
        1,
        &nodes,
        HashType::default(),
        Nonce::new(1),
        6,
        2,
        8,
        64,
        false,
        true,
        LatencyProfile {
            distribution: LatencyDistribution::Even,
            latency_ms: 10,
            min_ms: 1,
            max_ms: 300,
            seed: 0,
        },
    )
    .unwrap();

    assert!(row.trusted);
    assert_eq!(row.application_state_bytes_per_block, 64);
    assert_eq!(row.epoch_application_state_bytes, 36 * 64);
    assert!(row.converged);
    assert!(row.dispatch_messages > 0);
    assert_eq!(row.echo_messages, 0);
    assert_eq!(row.verification_messages, 0);
    assert_eq!(row.proposal_messages, 0);
    assert_eq!(row.commit_messages, 0);
    assert_eq!(row.total_messages, row.dispatch_messages);
    assert_eq!(row.modeled_latency_ms, row.rounds as u64 * 10);
    assert_eq!(row.modeled_finality_latency_ms, row.rounds as u64 * 10);
}

#[test]
fn configurable_square_quorum_sizes_have_two_rounds() {
    for quorum_size in [3, 4, 5, 6] {
        let keys = (0..quorum_size * quorum_size)
            .map(|index| key(index as u8))
            .collect::<Vec<_>>();
        let rounds = round_quorums(&keys, HashType::default(), false, quorum_size);

        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0].len(), quorum_size);
        assert_eq!(rounds[1].len(), quorum_size);
        assert!(
            rounds
                .iter()
                .flatten()
                .all(|quorum| quorum.len() == quorum_size)
        );
    }
}

#[test]
fn trustless_mode_models_five_network_stages_per_round() {
    let nodes = build_nodes(9);
    let row = run_epoch(
        0,
        1,
        &nodes,
        HashType::default(),
        Nonce::new(1),
        3,
        2,
        8,
        0,
        false,
        false,
        LatencyProfile {
            distribution: LatencyDistribution::Even,
            latency_ms: 7,
            min_ms: 1,
            max_ms: 300,
            seed: 0,
        },
    )
    .unwrap();

    assert!(!row.trusted);
    assert!(row.converged);
    assert_eq!(row.rounds, 2);
    assert_eq!(row.modeled_dispatch_latency_ms, 14);
    assert_eq!(row.modeled_echo_latency_ms, 14);
    assert_eq!(row.modeled_verification_latency_ms, 14);
    assert_eq!(row.modeled_proposal_latency_ms, 14);
    assert_eq!(row.modeled_commit_latency_ms, 14);
    assert_eq!(row.modeled_latency_ms, 70);
    assert_eq!(row.modeled_finality_latency_ms, 70);
}

#[test]
fn finality_latency_uses_slowest_safe_supermajority_not_slowest_node() {
    let quorum = [0, 1, 2, 3, 4, 5];
    let recipient_latency = [10, 20, 30, 40, 500, 900];

    let finality_latency = quorum_stage_finality_latency_ms_with(&quorum, |_sender, recipient| {
        recipient_latency[recipient]
    });

    assert_eq!(finality_latency, 40);
}
