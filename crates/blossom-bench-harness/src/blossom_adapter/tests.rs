//! Native Global Blossom and active-active benchmark adapter tests.

use std::time::{SystemTime, UNIX_EPOCH};

use blossom::{
    AdmittedCommand, BatchReferenceMetadata, ClientEpoch, ClientId, CommandBatch, CommandIdentity,
    CommandSpecVersion, ConsensusGroupId, Keypair, ReplicaMembershipEpoch, RouteGeneration,
    ValidatorGeneration,
};

use super::*;
use crate::{CommandOperation, active_active_command};

static NATIVE_CLUSTER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn reference(origin: blossom::PubKey) -> BatchReference {
    let batch = CommandBatch {
        commands: vec![AdmittedCommand {
            origin_sequence: 1,
            command: active_active_command(
                CommandIdentity {
                    client_id: ClientId([1; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 1,
                },
                CommandOperation::BlindWrite {
                    key: b"benchmark-key".to_vec(),
                    value: b"benchmark-value".to_vec(),
                },
            )
            .unwrap(),
        }],
    };
    BatchReference::for_batch(
        &batch,
        BatchReferenceMetadata {
            cluster_id: HashType([9; 32]),
            consensus_group_id: ConsensusGroupId::root(),
            shard: b"benchmark-shard".to_vec(),
            route_generation: RouteGeneration(1),
            command_spec_version: CommandSpecVersion(1),
            origin,
            origin_incarnation: 1,
            origin_key_generation: 1,
            data_holder_membership_epoch: ReplicaMembershipEpoch(1),
            validator_generation: ValidatorGeneration(1),
            previous_origin_reference_hash: HashType::default(),
        },
    )
    .unwrap()
}

#[tokio::test]
async fn native_tcp_cluster_finalizes_one_compact_reference_at_global_threshold() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    let origin = Keypair::generate();
    let reference = reference(origin.public);
    let cluster = BlossomTcpOrderCluster::start(3, QuorumSize::new(3).unwrap())
        .await
        .unwrap();

    let (epoch, sample, finalized_nodes) = cluster.finalize_reference(&reference).await.unwrap();

    assert_eq!(
        ordered_batch_references_trusted(&epoch).unwrap(),
        vec![reference]
    );
    assert_eq!(sample.nonce, Nonce::new(1));
    assert_eq!(sample.finalized_nodes, finalized_nodes.len());
    assert!(finalized_nodes.contains(&0));
    assert_eq!(sample.finalized_block_count, 3);
    assert!(sample.finalized_nanos >= sample.blocks_submitted_nanos);
    assert!(
        sample
            .node_traffic
            .iter()
            .all(|metrics| metrics.requests > 0)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn verified_scale_clusters_publish_finality_to_a_supermajority() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    for participants in [24, 36] {
        let cluster = BlossomTcpOrderCluster::start_with_options(
            participants,
            QuorumSize::DEFAULT,
            TrustMode::Verified,
            ConsensusDriverConfig {
                interval: Duration::from_millis(20),
                event_driven: false,
                max_round: 1,
                // Verified multi-round consensus must safely override this
                // compatibility setting to obtain one global epoch hash.
                drive_prefill: false,
                drive_dispatch: true,
                require_local_pending_block: false,
                continue_after_error: true,
            },
            // This is a correctness gate, not a latency SLA. A 36-node
            // verified cluster exchanges O(n²) signed messages, so leave
            // enough scheduling headroom for shared two-core CI runners.
            Duration::from_secs(90),
        )
        .await
        .unwrap();

        for sequence in 1..=3 {
            let member_transactions = (0..12)
                .map(|writer| {
                    vec![Transaction::new(vec![
                        u8::try_from(writer + sequence)
                            .unwrap();
                        4_096
                    ])]
                })
                .collect::<Vec<_>>();
            let (epoch, sample, finalized_nodes) = cluster
                .finalize_transactions(&member_transactions)
                .await
                .unwrap();
            assert_eq!(epoch.body.nonce, Nonce::new(sequence as u64));
            epoch.epoch_approved().unwrap();
            let ordered_transactions = epoch
                .body
                .ordered_blocks()
                .iter()
                .flat_map(|(_, block)| &block.body.txs)
                .collect::<Vec<_>>();
            assert_eq!(
                ordered_transactions.len(),
                member_transactions.len(),
                "{participants}-node verified epoch dropped submitted transactions"
            );
            assert!(
                ordered_transactions
                    .iter()
                    .all(|transaction| transaction.payload().len() == 4_096)
            );
            assert_eq!(sample.finalized_nodes, finalized_nodes.len());
            assert!(
                finalized_nodes.len() >= supermajority_count(participants),
                "{participants}-node verified epoch was published by only {} validators",
                finalized_nodes.len()
            );
        }
    }
}

#[tokio::test]
async fn manual_driver_never_advances_beyond_the_requested_epoch() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    let origin = Keypair::generate();
    let reference = reference(origin.public);
    let cluster = BlossomTcpOrderCluster::start(3, QuorumSize::new(3).unwrap())
        .await
        .unwrap();

    let (_epoch, sample, _finalized_nodes) = cluster.finalize_reference(&reference).await.unwrap();
    for _ in 0..64 {
        cluster.drive_cluster_once(sample.nonce).await.unwrap();
    }

    let expected_next = sample.nonce.new_next();
    for (index, node) in cluster.cluster.nodes().iter().enumerate() {
        assert_eq!(
            node.runtime.next_epoch_target().unwrap().nonce,
            expected_next,
            "node {index} advanced without work after finalizing {}",
            sample.nonce
        );
    }
}

#[tokio::test]
async fn trusted_tcp_cluster_orders_all_parallel_writer_blocks_by_hash() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    let origins = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let references = origins
        .iter()
        .map(|origin| reference(origin.public))
        .collect::<Vec<_>>();
    let expected_hashes = references
        .iter()
        .map(BatchReference::hash)
        .collect::<Result<BTreeSet<_>, _>>()
        .unwrap();
    let cluster = BlossomTcpOrderCluster::start(6, QuorumSize::new(3).unwrap())
        .await
        .unwrap();

    let (epoch, sample, finalized_nodes) = cluster.finalize_references(&references).await.unwrap();
    let ordered = ordered_batch_references_trusted(&epoch).unwrap();

    assert_eq!(ordered.len(), 6);
    assert_eq!(
        ordered
            .iter()
            .map(BatchReference::hash)
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap(),
        expected_hashes
    );
    assert_eq!(sample.reference_hashes.len(), 6);
    assert_eq!(sample.finalized_block_count, 6);
    assert!(finalized_nodes.contains(&0));
    assert!(
        epoch
            .body
            .ordered_blocks()
            .into_iter()
            .all(|(_, block)| block.signature == blossom::Signature::default())
    );
}

#[tokio::test]
async fn trusted_direct_cluster_applies_unsigned_writer_payloads_without_certificates() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    let mut cluster = BlossomTrustedDirectCluster::start(6, QuorumSize::new(3).unwrap())
        .await
        .unwrap();
    let commands = (0..6)
        .map(|writer| {
            active_active_command(
                CommandIdentity {
                    client_id: ClientId([40 + writer as u8; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 1,
                },
                CommandOperation::BlindWrite {
                    key: format!("direct-key-{writer}").into_bytes(),
                    value: vec![writer as u8; 32],
                },
            )
            .unwrap()
        })
        .collect();

    let sample = cluster.client_write_universal(commands).await.unwrap();

    assert_eq!(sample.active_writers, 6);
    assert_eq!(sample.results, vec![CommandResult::Written; 6]);
    assert_eq!(sample.finality.reference_hashes.len(), 6);
    assert_eq!(cluster.read_local(b"direct-key-5"), Some(vec![5; 32]));
    assert_eq!(
        sample.finality.node_traffic.len(),
        cluster.order_cluster.participant_count()
    );
}

#[tokio::test]
async fn active_active_cluster_runs_every_milestone_through_applied() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "blossom-active-benchmark-{}-{suffix}",
        std::process::id()
    ));
    let mut cluster = BlossomActiveActiveCluster::start_with_holders_per_site(
        6,
        QuorumSize::new(3).unwrap(),
        1,
        &root,
    )
    .await
    .unwrap();
    let command = active_active_command(
        CommandIdentity {
            client_id: ClientId([7; 16]),
            client_epoch: ClientEpoch(1),
            sequence: 1,
        },
        CommandOperation::BlindWrite {
            key: b"complete-path".to_vec(),
            value: b"value".to_vec(),
        },
    )
    .unwrap();

    let sample = cluster.client_write(command).await.unwrap();

    assert_eq!(sample.result, CommandResult::Written);
    assert_eq!(sample.watermark, Watermark { position: 1 });
    assert!(sample.available_nanos >= sample.accepted_local_nanos);
    assert!(sample.finalized_nanos >= sample.available_nanos);
    assert!(sample.applied_nanos >= sample.finalized_nanos);
    assert!(sample.converged_nanos >= sample.applied_nanos);
    assert!(sample.finality.converged_nanos.is_some());
    assert_eq!(sample.finality.converged_nodes, 6);
    assert_eq!(sample.trusted_path.origin_site_members, 1);
    assert_eq!(sample.trusted_path.admission_receipts, 1);
    assert_eq!(sample.trusted_path.availability_sites, 2);
    assert_eq!(sample.trusted_path.availability_receipts, 2);
    assert_eq!(sample.trusted_path.validator_block_submissions, 6);
    assert_eq!(sample.trusted_path.order_votes, 0);
    assert_eq!(
        sample.trusted_path.immediate_durable_commits,
        sample.trusted_path.admission_receipts
            + sample.trusted_path.availability_receipts
            + sample.trusted_path.order_votes
            + 4
    );
    drop(cluster);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn active_active_cluster_applies_parallel_universal_writers() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "blossom-universal-writer-benchmark-{}-{suffix}",
        std::process::id()
    ));
    let mut cluster = BlossomActiveActiveCluster::start_with_holders_per_site(
        6,
        QuorumSize::new(3).unwrap(),
        1,
        &root,
    )
    .await
    .unwrap();
    let commands = (0..6)
        .map(|writer| {
            active_active_command(
                CommandIdentity {
                    client_id: ClientId([30 + writer as u8; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 1,
                },
                CommandOperation::BlindWrite {
                    key: format!("parallel-key-{writer}").into_bytes(),
                    value: vec![writer as u8; 32],
                },
            )
            .unwrap()
        })
        .collect();

    let sample = cluster.client_write_universal(commands).await.unwrap();

    assert_eq!(sample.active_writers, 6);
    assert_eq!(sample.first_watermark, Watermark { position: 1 });
    assert_eq!(sample.last_watermark, Watermark { position: 6 });
    assert_eq!(sample.results, vec![CommandResult::Written; 6]);
    assert_eq!(sample.finality.reference_hashes.len(), 6);
    assert_eq!(sample.trusted_path.validator_block_submissions, 6);
    assert_eq!(sample.trusted_path.order_votes, 0);
    assert!(sample.available_nanos >= sample.accepted_local_nanos);
    assert!(sample.finalized_nanos >= sample.available_nanos);
    assert!(sample.applied_nanos >= sample.finalized_nanos);

    drop(cluster);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn active_active_cluster_remains_bounded_across_many_epochs() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "blossom-bounded-epochs-{}-{suffix}",
        std::process::id()
    ));
    let mut cluster = BlossomActiveActiveCluster::start_with_holders_per_site(
        6,
        QuorumSize::new(3).unwrap(),
        1,
        &root,
    )
    .await
    .unwrap();

    for sequence in 1..=16 {
        let commands = (0..3)
            .map(|writer| {
                active_active_command(
                    CommandIdentity {
                        client_id: ClientId([50 + writer as u8; 16]),
                        client_epoch: ClientEpoch(1),
                        sequence,
                    },
                    CommandOperation::BlindWrite {
                        key: format!("bounded-key-{writer}").into_bytes(),
                        value: sequence.to_le_bytes().to_vec(),
                    },
                )
                .unwrap()
            })
            .collect();

        let sample = cluster.client_write_universal(commands).await.unwrap();
        assert_eq!(sample.results, vec![CommandResult::Written; 3]);
        assert_eq!(sample.finality.nonce, Nonce::new(sequence));
        assert_eq!(sample.finality.converged_nodes, 6);
    }

    for writer in 0..3 {
        assert_eq!(
            cluster
                .read_local(format!("bounded-key-{writer}").as_bytes())
                .unwrap(),
            Some(16u64.to_le_bytes().to_vec())
        );
    }
    drop(cluster);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn active_active_q3_q6_q9_paths_finalize_and_apply() {
    let _test_guard = NATIVE_CLUSTER_TEST_LOCK.lock().await;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for quorum_size in [3usize, 6, 9] {
        let participant_count = quorum_size.max(6);
        let root = std::env::temp_dir().join(format!(
            "blossom-active-q-matrix-{}-{suffix}-{quorum_size}",
            std::process::id()
        ));
        let mut cluster = BlossomActiveActiveCluster::start_with_holders_per_site(
            participant_count,
            QuorumSize::new(quorum_size).unwrap(),
            1,
            &root,
        )
        .await
        .unwrap();
        let sample = cluster
            .client_write(
                active_active_command(
                    CommandIdentity {
                        client_id: ClientId([quorum_size as u8; 16]),
                        client_epoch: ClientEpoch(1),
                        sequence: 1,
                    },
                    CommandOperation::BlindWrite {
                        key: b"q-matrix".to_vec(),
                        value: vec![quorum_size as u8],
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sample.result, CommandResult::Written);
        assert_eq!(sample.watermark, Watermark { position: 1 });
        assert_eq!(
            cluster.read_local(b"q-matrix"),
            Ok(Some(vec![quorum_size as u8]))
        );
        drop(cluster);
        std::fs::remove_dir_all(root).unwrap();
    }
}
