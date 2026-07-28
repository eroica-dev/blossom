//! Subset-gossip model, scheduling, and report tests.

use super::*;

#[test]
fn target_selection_is_deterministic_and_includes_owner() {
    let config = SubsetGossipConfig {
        nodes: 12,
        targets_per_command: 3,
        ..SubsetGossipConfig::default()
    };
    let first = targets_for_command(7, 2, 9, &config);
    let second = targets_for_command(7, 2, 9, &config);

    assert_eq!(first, second);
    assert!(first.binary_search(&2).is_ok());
    assert_eq!(first.len(), 3);
}

#[test]
fn synthetic_payload_commitment_is_stable_and_length_sensitive() {
    let first = command_payload_hash(1, 2, 3, 1024);
    let second = command_payload_hash(1, 2, 3, 1024);
    let different_len = command_payload_hash(1, 2, 3, 2048);
    let different_command = command_payload_hash(1, 2, 4, 1024);

    assert_eq!(first, second);
    assert_ne!(first, different_len);
    assert_ne!(first, different_command);
}

#[test]
fn subset_gossip_converges_metadata_and_repairs_payloads() {
    let config = SubsetGossipConfig {
        nodes: 12,
        epochs: 2,
        quorum_size: 3,
        commands_per_node: 8,
        command_bytes: 64,
        targets_per_command: 2,
        repair_missing: true,
        ..SubsetGossipConfig::default()
    };

    let report = run_subset_gossip(config).unwrap();

    assert_eq!(report.rows.len(), 2);
    for row in report.rows {
        assert!(row.metadata_converged);
        assert!(row.subset_payloads_complete_after_repair);
        assert_eq!(row.subset_missing_payloads_after_repair, 0);
        assert!(row.subset_wire_bytes <= row.full_wire_bytes);
    }
}

#[test]
fn protocol_v1_profile_preserves_old_repair_path() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        ..SubsetGossipConfig::for_protocol_version(SubsetGossipProtocolVersion::V1)
    };

    let row = run_subset_gossip_v1(config).unwrap().rows.remove(0);

    assert_eq!(row.protocol_version, SubsetGossipProtocolVersion::V1);
    assert_eq!(row.prefill_mode, SubsetPrefillMode::None);
    assert_eq!(row.prefill_skip_rounds, 0);
    assert!(row.repair_missing);
    assert!(row.metadata_converged);
    assert!(row.subset_missing_payloads_before_repair > 0);
    assert_eq!(row.subset_missing_payloads_after_repair, 0);
    assert!(row.subset_repair_batches > 0);
}

#[test]
fn protocol_v2_profile_preserves_prefill_dispatch_path() {
    let config = SubsetGossipConfig {
        nodes: 72,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        ..SubsetGossipConfig::for_protocol_version(SubsetGossipProtocolVersion::V2)
    };

    let row = run_subset_gossip_v2(config).unwrap().rows.remove(0);

    assert_eq!(row.protocol_version, SubsetGossipProtocolVersion::V2);
    assert_eq!(row.prefill_mode, SubsetPrefillMode::PrefillDispatch);
    assert_eq!(row.prefill_skip_rounds, 1);
    assert_eq!(row.prefill_fanout, 17);
    assert!(!row.repair_missing);
    assert!(row.metadata_converged);
    assert!(row.subset_payloads_complete_before_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
    assert_eq!(row.subset_repair_batches, 0);
}

#[test]
fn experimental_knobs_are_labeled_custom() {
    let config = SubsetGossipConfig {
        nodes: 12,
        epochs: 1,
        quorum_size: 3,
        commands_per_node: 8,
        command_bytes: 64,
        targets_per_command: 2,
        prefill_mode: SubsetPrefillMode::Random,
        prefill_fanout: 3,
        repair_missing: true,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert_eq!(row.protocol_version, SubsetGossipProtocolVersion::Custom);
    assert_eq!(row.prefill_mode, SubsetPrefillMode::Random);
}

#[test]
fn sparse_inline_subset_can_need_repair() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 2,
        repair_missing: false,
        ..SubsetGossipConfig::default()
    };

    let report = run_subset_gossip(config).unwrap();
    let row = &report.rows[0];

    assert!(row.metadata_converged);
    assert!(row.subset_missing_payloads_before_repair > 0);
    assert!(!row.subset_payloads_complete_after_repair);
}

#[test]
fn random_prefill_replicates_each_local_block_to_configured_fanout() {
    let config = SubsetGossipConfig {
        nodes: 12,
        epochs: 1,
        quorum_size: 3,
        commands_per_node: 8,
        command_bytes: 64,
        targets_per_command: 2,
        prefill_mode: SubsetPrefillMode::Random,
        prefill_fanout: 3,
        repair_missing: true,
        ..SubsetGossipConfig::default()
    };

    let report = run_subset_gossip(config).unwrap();
    let row = &report.rows[0];

    assert_eq!(row.prefill_mode, SubsetPrefillMode::Random);
    assert_eq!(row.prefill_recipients, row.nodes * row.prefill_fanout);
    assert!(row.prefill_expected_hashes > row.nodes);
    assert!(row.prefill_bytes > 0);
    assert_eq!(row.subset_missing_payloads_after_repair, 0);
}

#[test]
fn scheduled_prefill_hash_advertise_suppresses_duplicate_blocks() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        prefill_mode: SubsetPrefillMode::Scheduled,
        hash_advertise: true,
        repair_missing: true,
        ..SubsetGossipConfig::default()
    };

    let report = run_subset_gossip(config).unwrap();
    let row = &report.rows[0];

    assert_eq!(row.prefill_mode, SubsetPrefillMode::Scheduled);
    assert!(row.prefill_recipients > 0);
    assert!(row.hash_advertise_messages > 0);
    assert!(row.hash_advertise_bytes > 0);
    assert!(row.duplicate_suppressed_blocks > 0);
    assert!(row.metadata_converged);
    assert_eq!(row.subset_missing_payloads_after_repair, 0);
}

#[test]
fn random_prefill_reduces_round0_drop_payload_loss() {
    let baseline = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        drop_round0_dispatch: true,
        ..SubsetGossipConfig::default()
    };
    let random_prefill = SubsetGossipConfig {
        prefill_mode: SubsetPrefillMode::Random,
        prefill_fanout: 6,
        ..baseline.clone()
    };

    let baseline_row = run_subset_gossip(baseline).unwrap().rows.remove(0);
    let random_row = run_subset_gossip(random_prefill).unwrap().rows.remove(0);

    assert!(baseline_row.subset_missing_payloads_before_repair > 0);
    assert!(
        random_row.subset_missing_payloads_before_repair
            < baseline_row.subset_missing_payloads_before_repair
    );
    assert!(random_row.prefill_bytes > 0);
}

#[test]
fn prefill_dispatch_replaces_first_consensus_round() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert_eq!(row.prefill_mode, SubsetPrefillMode::PrefillDispatch);
    assert_eq!(row.prefill_skip_rounds, 1);
    assert_eq!(row.rounds, 1);
    assert_eq!(row.prefill_fanout, 11);
    assert_eq!(row.prefill_recipients, row.nodes * row.prefill_fanout);
    assert_eq!(
        row.prefill_expected_hashes,
        row.nodes * (row.prefill_fanout + 1)
    );
    assert_eq!(row.hash_advertise_bytes, 0);
    assert!(row.metadata_converged);
    assert!(row.subset_payloads_complete_before_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
    assert_eq!(row.duplicate_suppressed_blocks, 0);
    assert!(row.subset_dispatch_bytes > 0);
}

#[test]
fn modeled_latency_uses_parallel_quorums_within_round() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        repair_missing: false,
        trusted: true,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert_eq!(row.quorums, 6);
    assert_eq!(row.modeled_prefill_latency_ms, 150);
    assert_eq!(row.modeled_dispatch_latency_ms, 150);
    assert_eq!(row.modeled_control_latency_ms, 0);
    assert_eq!(row.subset_payload_ready_latency_ms, 300);
}

#[test]
fn trustless_mode_models_control_once_per_parallel_round() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        repair_missing: false,
        trusted: false,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert_eq!(row.quorums, 6);
    assert_eq!(row.modeled_prefill_latency_ms, 150);
    assert_eq!(row.modeled_dispatch_latency_ms, 150);
    assert_eq!(row.modeled_control_latency_ms, 600);
    assert_eq!(row.subset_payload_ready_latency_ms, 900);
}

#[test]
fn prefill_dispatch_fanout_scales_with_log_rounds() {
    let config = SubsetGossipConfig {
        nodes: 1000,
        quorum_size: 6,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };

    let (_, rounds) = find_round_number(config.nodes, config.quorum_size);

    assert_eq!(rounds, 4);
    assert_eq!(prefill_dispatch_fanout(&config, rounds), 23);
}

#[test]
fn prefill_dispatch_fanout_uses_ceil_depth_for_non_ideal_networks() {
    let config = SubsetGossipConfig {
        nodes: 64,
        quorum_size: 6,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };
    let (_, topology_rounds) = find_round_number(config.nodes, config.quorum_size);

    assert_eq!(topology_rounds, 2);
    assert_eq!(ceil_log_rounds(config.nodes, config.quorum_size), 3);
    assert_eq!(prefill_dispatch_fanout(&config, topology_rounds), 17);
}

#[test]
fn prefill_dispatch_fanout_is_derived_from_quorum_schedule() {
    let config = SubsetGossipConfig {
        nodes: 64,
        quorum_size: 6,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };
    let (_, topology_rounds) = find_round_number(config.nodes, config.quorum_size);

    assert_eq!(prefill_dispatch_fanout(&config, topology_rounds), 17);
}

#[test]
fn prefill_dispatch_boundary_sizes_use_ceil_log_depth() {
    let cases = [
        (5usize, 1usize, 4usize),
        (6, 1, 5),
        (7, 2, 6),
        (35, 2, 11),
        (36, 2, 11),
        (37, 3, 17),
        (215, 3, 17),
        (216, 3, 17),
        (217, 4, 23),
        (1_000, 4, 23),
        (1_296, 4, 23),
        (1_297, 5, 29),
    ];

    for (nodes, expected_rounds, expected_fanout) in cases {
        let config = SubsetGossipConfig {
            nodes,
            quorum_size: 6,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };
        let rounds = ceil_log_rounds(config.nodes, config.quorum_size);

        assert_eq!(rounds, expected_rounds, "nodes={nodes}");
        assert_eq!(
            prefill_dispatch_fanout(&config, rounds),
            expected_fanout,
            "nodes={nodes}"
        );
    }
}

#[test]
fn prefill_dispatch_non_ideal_boundary_sizes_complete_without_repair() {
    for nodes in [35usize, 36, 37, 64, 72] {
        let row = run_subset_gossip(SubsetGossipConfig {
            seed: 0x626f_756e_6461_7279 ^ nodes as u64,
            nodes,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 4,
            command_bytes: 32,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        })
        .unwrap()
        .rows
        .remove(0);

        assert!(row.metadata_converged, "nodes={nodes}");
        assert!(row.subset_payloads_complete_before_repair, "nodes={nodes}");
        assert_eq!(
            row.subset_missing_payloads_before_repair, 0,
            "nodes={nodes}"
        );
        assert_eq!(row.subset_repair_batches, 0, "nodes={nodes}");
    }
}

#[test]
fn prefill_expected_hashes_reject_stale_epoch_replay() {
    let config = SubsetGossipConfig {
        nodes: 36,
        quorum_size: 6,
        commands_per_node: 4,
        command_bytes: 32,
        targets_per_command: 3,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };
    let nodes = build_nodes(config.seed, config.nodes);
    let topology = round_quorums(
        &nodes
            .iter()
            .map(|node| node.keypair.public)
            .collect::<Vec<_>>(),
        HashType::default(),
        config.shuffle,
        config.quorum_size,
    );
    let consensus_start_round = consensus_start_round(&config, topology.len());
    let stale_blocks =
        build_epoch_blocks(0, &config, &nodes, HashType::default(), Nonce::new(1)).unwrap();
    let current_blocks =
        build_epoch_blocks(1, &config, &nodes, HashType::default(), Nonce::new(2)).unwrap();
    let current_plan = build_prefill_plan(
        1,
        &config,
        &nodes,
        &current_blocks,
        &topology,
        consensus_start_round,
    );
    let recipient = current_plan.recipients_by_sender[0][0];
    let expected = &current_plan.expected_by_node[&nodes[recipient].keypair.public];

    assert!(expected.contains(&current_blocks[0].hash));
    assert!(!expected.contains(&stale_blocks[0].hash));
}

#[test]
fn prefill_expected_hashes_reject_equivocated_payload_commitment() {
    let config = SubsetGossipConfig {
        nodes: 36,
        quorum_size: 6,
        commands_per_node: 4,
        command_bytes: 32,
        targets_per_command: 3,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };
    let equivocated_config = SubsetGossipConfig {
        command_bytes: 33,
        ..config.clone()
    };
    let nodes = build_nodes(config.seed, config.nodes);
    let topology = round_quorums(
        &nodes
            .iter()
            .map(|node| node.keypair.public)
            .collect::<Vec<_>>(),
        HashType::default(),
        config.shuffle,
        config.quorum_size,
    );
    let consensus_start_round = consensus_start_round(&config, topology.len());
    let honest_blocks =
        build_epoch_blocks(0, &config, &nodes, HashType::default(), Nonce::new(1)).unwrap();
    let equivocated_blocks = build_epoch_blocks(
        0,
        &equivocated_config,
        &nodes,
        HashType::default(),
        Nonce::new(1),
    )
    .unwrap();
    let honest_plan = build_prefill_plan(
        0,
        &config,
        &nodes,
        &honest_blocks,
        &topology,
        consensus_start_round,
    );
    let recipient = honest_plan.recipients_by_sender[0][0];
    let expected = &honest_plan.expected_by_node[&nodes[recipient].keypair.public];

    assert!(expected.contains(&honest_blocks[0].hash));
    assert_ne!(honest_blocks[0].hash, equivocated_blocks[0].hash);
    assert!(!expected.contains(&equivocated_blocks[0].hash));
}

#[test]
fn prefill_dispatch_fanout_widens_route_for_declared_withholders() {
    let config = SubsetGossipConfig {
        nodes: 64,
        quorum_size: 6,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_byzantine_withholders_per_branch: 1,
        ..SubsetGossipConfig::default()
    };
    let (_, topology_rounds) = find_round_number(config.nodes, config.quorum_size);

    assert_eq!(topology_rounds, 2);
    assert_eq!(ceil_log_rounds(config.nodes, config.quorum_size), 3);
    assert_eq!(prefill_dispatch_fanout(&config, topology_rounds), 29);
}

#[test]
fn prefill_dispatch_routes_subtree_payloads_without_repair() {
    let config = SubsetGossipConfig {
        nodes: 72,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert_eq!(row.prefill_fanout, 17);
    assert!(row.metadata_converged);
    assert!(row.subset_payloads_complete_before_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
}

#[test]
fn prefill_dispatch_survives_one_byzantine_route_withholder() {
    let config = SubsetGossipConfig {
        nodes: 72,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_byzantine_withholders_per_branch: 1,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert!(row.subset_payloads_complete_before_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
}

#[test]
fn prefill_dispatch_survives_two_byzantine_route_withholders_for_q8() {
    let config = SubsetGossipConfig {
        nodes: 144,
        epochs: 1,
        quorum_size: 8,
        commands_per_node: 8,
        command_bytes: 64,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_byzantine_withholders_per_branch: 2,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert_eq!(row.prefill_fanout, 55);
    assert!(row.metadata_converged);
    assert!(row.subset_payloads_complete_before_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
}

#[test]
fn prefill_dispatch_survives_three_byzantine_route_withholders_for_q12() {
    let config = SubsetGossipConfig {
        nodes: 144,
        epochs: 1,
        quorum_size: 12,
        commands_per_node: 8,
        command_bytes: 64,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_byzantine_withholders_per_branch: 3,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert_eq!(row.prefill_fanout, 59);
    assert!(row.metadata_converged);
    assert!(row.subset_payloads_complete_before_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
}

#[test]
fn prefill_dispatch_survives_one_withholder_for_non_ideal_network_size() {
    let config = SubsetGossipConfig {
        seed: 109742935629,
        nodes: 64,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_byzantine_withholders_per_branch: 1,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert_eq!(row.prefill_fanout, 29);
    assert!(row.subset_payloads_complete_before_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
}

#[test]
fn bft_prefill_rejects_deep_small_quorum_with_withholding() {
    let config = SubsetGossipConfig {
        seed: 109741012189,
        nodes: 72,
        epochs: 1,
        quorum_size: 4,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_byzantine_withholders_per_branch: 1,
        ..SubsetGossipConfig::default()
    };

    let err = run_subset_gossip(config).unwrap_err();
    assert!(
        err.to_string().contains("requires quorum size at least 5"),
        "{err}"
    );
}

#[test]
fn prefill_dispatch_start_is_always_one_round() {
    let config = SubsetGossipConfig {
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };

    assert_eq!(consensus_start_round(&config, 0), 0);
    assert_eq!(consensus_start_round(&config, 1), 0);
    for topology_rounds in [2, 3, 4, 8] {
        assert_eq!(consensus_start_round(&config, topology_rounds), 1);
    }
}

#[test]
fn prefill_dispatch_rejects_multi_round_skip_override() {
    let config = SubsetGossipConfig {
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_skip_rounds: 2,
        ..SubsetGossipConfig::default()
    };

    assert!(config.validate().is_err());
}

#[test]
fn precomputed_inventory_routes_pick_one_holder_for_missing_payloads() {
    let config = SubsetGossipConfig {
        nodes: 4,
        quorum_size: 4,
        commands_per_node: 4,
        ..SubsetGossipConfig::default()
    };
    let mut target_masks = vec![PayloadMask::empty(4); 4];
    target_masks[1].set(0);
    target_masks[1].set(1);
    let block = BlockMeta {
        hash: HashType::default(),
        owner: 0,
        full_block_len: 0,
        tombstone_block_len: 0,
        target_masks,
        target_payload_deliveries: 2,
        slots: Vec::new(),
    };
    let mut states = (0..4).map(|_| NodeSubsetState::new(4)).collect::<Vec<_>>();
    states[0].insert_local_block(0, 4);
    states[2].merge_block(0, PayloadMask::full(4));
    states[3].merge_block(0, PayloadMask::full(4));
    let future_reachability = vec![
        vec![vec![0], vec![1], vec![2], vec![3]],
        vec![vec![0], vec![1], vec![2], vec![3]],
    ];

    let routes = precomputed_inventory_routes_for_quorum(
        &config,
        0,
        &[0, 1, 2, 3],
        &[block],
        &states,
        &future_reachability,
    );
    let payload_routes = routes
        .iter()
        .filter(|((_, recipient, owner), _)| *recipient == 1 && *owner == 0)
        .collect::<Vec<_>>();

    assert_eq!(payload_routes.len(), 1);
    assert_eq!(routes.get(&(0, 1, 0)).map(|route| route.attempt), Some(0));
    assert!(!routes.contains_key(&(2, 1, 0)));
    assert!(!routes.contains_key(&(3, 1, 0)));
}

#[test]
fn precomputed_inventory_routes_ignore_metadata_only_false_holders() {
    let config = SubsetGossipConfig {
        nodes: 4,
        quorum_size: 4,
        commands_per_node: 4,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        ..SubsetGossipConfig::default()
    };
    let mut target_masks = vec![PayloadMask::empty(4); 4];
    target_masks[1].set(0);
    target_masks[1].set(1);
    let block = BlockMeta {
        hash: HashType::default(),
        owner: 0,
        full_block_len: 0,
        tombstone_block_len: 0,
        target_masks,
        target_payload_deliveries: 2,
        slots: Vec::new(),
    };
    let mut states = (0..4).map(|_| NodeSubsetState::new(4)).collect::<Vec<_>>();
    states[0].insert_local_block(0, 4);
    states[2].insert_block_metadata(0, 4);
    states[3].merge_block(0, PayloadMask::full(4));
    let future_reachability = vec![
        vec![vec![0], vec![1], vec![2], vec![3]],
        vec![vec![0], vec![1], vec![2], vec![3]],
    ];

    let routes = precomputed_inventory_routes_for_quorum(
        &config,
        0,
        &[1, 2, 3],
        &[block],
        &states,
        &future_reachability,
    );

    assert_eq!(routes.get(&(3, 1, 0)).map(|route| route.attempt), Some(0));
    assert!(!routes.contains_key(&(2, 1, 0)));
}

#[cfg(any(
    feature = "propagation-adaptive",
    feature = "propagation-inventory",
    feature = "propagation-push"
))]
#[test]
fn propagation_policy_rejects_trustless_inventory_without_prefill_coverage() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::None,
        hash_advertise: true,
        prefill_byzantine_withholders_per_branch: 1,
        ..SubsetGossipConfig::default()
    };

    let err = run_subset_gossip(config).unwrap_err();
    assert!(err.to_string().contains("invalid propagation policy"));
}

#[cfg(any(
    feature = "propagation-adaptive",
    feature = "propagation-inventory",
    feature = "propagation-push"
))]
#[test]
fn propagation_policy_rejects_withholding_above_quorum_tolerance() {
    let config = SubsetGossipConfig {
        nodes: 72,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_byzantine_withholders_per_branch: 2,
        ..SubsetGossipConfig::default()
    };

    let err = run_subset_gossip(config).unwrap_err();
    assert!(
        err.to_string().contains("exceeds quorum tolerance"),
        "{err}"
    );
}

#[test]
fn bft_prefill_survives_one_byzantine_withholder_per_branch() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_byzantine_withholders_per_branch: 1,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert!(row.subset_payloads_complete_before_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
    assert_eq!(row.prefill_byzantine_withholders_per_branch, 1);
}

#[test]
fn scheduled_prefill_covers_round0_drop_without_repair() {
    let config = SubsetGossipConfig {
        nodes: 36,
        epochs: 1,
        quorum_size: 6,
        commands_per_node: 16,
        command_bytes: 128,
        targets_per_command: 3,
        repair_missing: false,
        drop_round0_dispatch: true,
        prefill_mode: SubsetPrefillMode::Scheduled,
        hash_advertise: true,
        ..SubsetGossipConfig::default()
    };

    let row = run_subset_gossip(config).unwrap().rows.remove(0);

    assert!(row.metadata_converged);
    assert!(row.subset_payloads_complete_before_repair);
    assert!(row.subset_payloads_complete_after_repair);
    assert_eq!(row.subset_missing_payloads_before_repair, 0);
    assert!(row.prefill_recipients > row.nodes);
    assert!(row.duplicate_suppressed_blocks > 0);
}
