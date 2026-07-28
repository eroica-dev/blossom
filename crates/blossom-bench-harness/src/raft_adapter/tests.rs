//! Native OpenRaft adapter unit, integration, and restart-soak tests.

use blossom::{ClientEpoch, ClientId, CommandIdentity};

use super::*;
use crate::{CommandOperation, active_active_command};

fn test_write_command(client: u8, sequence: u64, key: &[u8], value: &[u8]) -> ActiveActiveCommand {
    active_active_command(
        CommandIdentity {
            client_id: ClientId([client; 16]),
            client_epoch: ClientEpoch(1),
            sequence,
        },
        CommandOperation::BlindWrite {
            key: key.to_vec(),
            value: value.to_vec(),
        },
    )
    .expect("test command is valid")
}

#[test]
fn protocol_invariant_accepts_a_fully_purged_snapshot_tail() {
    let state = RaftNodeProtocolState {
        node_id: 1,
        running: true,
        current_term: 3,
        current_leader: Some(1),
        last_log_index: None,
        last_applied_index: Some(12),
        snapshot_index: Some(12),
        purged_index: Some(12),
        voter_ids: BTreeSet::from([1, 2, 3]),
    };

    assert!(state.invariants_hold());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openraft_client_write_waits_through_state_machine_application() {
    let mut cluster = InProcessRaftCluster::start(3, 2).await.unwrap();
    let command = active_active_command(
        CommandIdentity {
            client_id: ClientId([1; 16]),
            client_epoch: ClientEpoch(1),
            sequence: 1,
        },
        CommandOperation::BlindWrite {
            key: b"key".to_vec(),
            value: b"value".to_vec(),
        },
    )
    .unwrap();
    let response = cluster.client_write(command).await.unwrap();
    assert_eq!(response.data.application_error, None);
    assert_eq!(response.data.result, Some(CommandResult::Written));

    let leader = cluster.ensure_linearizable().await.unwrap();
    assert_eq!(
        cluster.state_machines[&leader].get(b"key").await,
        Some(b"value".to_vec())
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openraft_concurrent_clients_all_wait_through_application() {
    let mut cluster = InProcessRaftCluster::start(3, 0).await.unwrap();
    let commands = (0..6)
        .map(|writer| {
            active_active_command(
                CommandIdentity {
                    client_id: ClientId([20 + writer as u8; 16]),
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

    let responses = cluster.client_write_concurrent(commands).await.unwrap();

    assert_eq!(responses.len(), 6);
    assert!(
        responses
            .iter()
            .all(|response| response.application_error.is_none()
                && response.result == Some(CommandResult::Written))
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openraft_concurrent_clients_are_admitted_in_input_order() {
    let mut cluster = InProcessRaftCluster::start(3, 0).await.unwrap();
    let key = b"ordered-concurrent-key".to_vec();
    let commands = (1..=64)
        .map(|sequence| {
            active_active_command(
                CommandIdentity {
                    client_id: ClientId([21; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence,
                },
                CommandOperation::Append {
                    key: key.clone(),
                    value: vec![sequence as u8],
                },
            )
            .unwrap()
        })
        .collect();

    let responses = cluster.client_write_concurrent(commands).await.unwrap();

    assert_eq!(responses.len(), 64);
    assert_eq!(
        cluster.read_linearizable(&key).await.unwrap(),
        Some((1..=64).map(|sequence| sequence as u8).collect())
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_append_faults_fire_on_data_and_recover_without_state_loss() {
    let mut cluster = InProcessRaftCluster::start(3, 0).await.unwrap();
    let actions = [
        RaftRpcFaultAction::DropRequest,
        RaftRpcFaultAction::DropResponse,
        RaftRpcFaultAction::DuplicateRequest,
        RaftRpcFaultAction::DelayRequest { millis: 40 },
        RaftRpcFaultAction::DelayResponse { millis: 40 },
    ];
    for (index, action) in actions.into_iter().enumerate() {
        let sequence = u64::try_from(index).unwrap() + 1;
        let leader = cluster.current_leader().await.unwrap();
        let follower = *cluster
            .voters
            .iter()
            .find(|node_id| **node_id != leader)
            .unwrap();
        cluster
            .network_control
            .script_rpc_fault(ScriptedRaftRpcFault::between(
                format!("append-action-{sequence}"),
                leader,
                follower,
                RaftRpcKind::AppendEntries,
                RaftRpcMatch::DataBearing,
                action,
            ))
            .await
            .unwrap();
        let key = format!("scripted-append-{sequence}").into_bytes();
        let value = sequence.to_le_bytes();
        let response = cluster
            .client_write(test_write_command(0x31, sequence, &key, &value))
            .await
            .unwrap();
        assert_eq!(response.data.application_error, None);
        assert_eq!(response.data.result, Some(CommandResult::Written));
        cluster
            .wait_for_value_on_all_nodes(&key, &value, Duration::from_secs(5))
            .await
            .unwrap();
    }

    let coverage = cluster.network_control.coverage().await;
    assert!(coverage.all_scripted_faults_fired(), "{coverage:?}");
    assert_eq!(coverage.configured_fault_ids.len(), actions.len());
    assert_eq!(coverage.request_drops, 1);
    assert_eq!(coverage.response_drops, 1);
    assert_eq!(coverage.duplicate_requests, 1);
    assert_eq!(coverage.request_delays, 1);
    assert_eq!(coverage.response_delays, 1);
    assert_eq!(coverage.executed_faults.len(), actions.len());
    assert!(
        coverage
            .executed_faults
            .iter()
            .all(|event| event.rpc == RaftRpcKind::AppendEntries && event.data_bearing)
    );
    assert!(coverage.data_bearing_append_entries_rpcs >= actions.len() as u64);
    assert!(
        cluster
            .wait_for_protocol_invariants(Duration::from_secs(2))
            .await,
        "append-fault recovery violated protocol indexes: {:?}",
        cluster.protocol_state()
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scripted_vote_request_and_response_loss_delay_but_do_not_prevent_recovery() {
    for (index, (id, action)) in [
        ("vote-request-loss", RaftRpcFaultAction::DropRequest),
        ("vote-response-loss", RaftRpcFaultAction::DropResponse),
    ]
    .into_iter()
    .enumerate()
    {
        let mut cluster = InProcessRaftCluster::start(3, 0).await.unwrap();
        let leader = cluster.current_leader().await.unwrap();
        cluster
            .network_control
            .script_rpc_fault(ScriptedRaftRpcFault::any_route(
                id,
                RaftRpcKind::Vote,
                RaftRpcMatch::Any,
                action,
            ))
            .await
            .unwrap();
        cluster.pause_node(leader).await.unwrap();
        let replacement = cluster
            .wait_for_leader(Duration::from_secs(10))
            .await
            .unwrap();
        assert_ne!(replacement, leader);
        cluster.resume_node(leader).await.unwrap();

        let key = format!("vote-loss-recovery-{index}").into_bytes();
        let response = deterministic_raft_write(
            &mut cluster,
            test_write_command(0x32, 1, &key, b"committed"),
        )
        .await
        .unwrap();
        assert_eq!(response.result, Some(CommandResult::Written));
        cluster
            .wait_for_value_on_all_nodes(&key, b"committed", Duration::from_secs(5))
            .await
            .unwrap();
        let coverage = cluster.network_control.coverage().await;
        assert!(coverage.all_scripted_faults_fired(), "{coverage:?}");
        match action {
            RaftRpcFaultAction::DropRequest => assert_eq!(coverage.request_drops, 1),
            RaftRpcFaultAction::DropResponse => assert_eq!(coverage.response_drops, 1),
            _ => unreachable!("test only injects vote loss"),
        }
        assert_eq!(coverage.executed_faults.len(), 1);
        assert_eq!(coverage.executed_faults[0].rpc, RaftRpcKind::Vote);
        assert!(coverage.vote_rpcs >= 2);
        assert!(
            cluster
                .wait_for_protocol_invariants(Duration::from_secs(2))
                .await,
            "vote-fault recovery violated protocol indexes: {:?}",
            cluster.protocol_state()
        );
        cluster.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joint_consensus_completes_when_a_membership_append_response_is_lost() {
    let mut cluster = InProcessRaftCluster::start(3, 1).await.unwrap();
    let leader = cluster.current_leader().await.unwrap();
    let removed = *cluster
        .voters
        .iter()
        .find(|node_id| **node_id != leader)
        .unwrap();
    let replacement = *cluster.learners.iter().next().unwrap();
    let expected_voters = cluster
        .voters
        .iter()
        .copied()
        .filter(|node_id| *node_id != removed)
        .chain(std::iter::once(replacement))
        .collect::<BTreeSet<_>>();
    cluster
        .network_control
        .script_rpc_fault(ScriptedRaftRpcFault::any_route(
            "membership-append-response-loss",
            RaftRpcKind::AppendEntries,
            RaftRpcMatch::DataBearing,
            RaftRpcFaultAction::DropResponse,
        ))
        .await
        .unwrap();
    cluster
        .replace_voters(expected_voters.clone(), true)
        .await
        .unwrap();
    cluster
        .wait_for_voters(&expected_voters, Duration::from_secs(10))
        .await
        .unwrap();
    cluster
        .client_write(test_write_command(
            0x33,
            1,
            b"membership-recovery",
            b"committed",
        ))
        .await
        .unwrap();
    cluster
        .wait_for_value_on_all_nodes(b"membership-recovery", b"committed", Duration::from_secs(5))
        .await
        .unwrap();
    let coverage = cluster.network_control.coverage().await;
    assert!(coverage.all_scripted_faults_fired(), "{coverage:?}");
    assert_eq!(coverage.response_drops, 1);
    assert!(
        cluster
            .wait_for_protocol_invariants(Duration::from_secs(2))
            .await,
        "membership recovery violated protocol indexes: {:?}",
        cluster.protocol_state()
    );
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_snapshot_install_response_loss_preserves_the_applied_snapshot() {
    let root = std::env::temp_dir().join(format!(
        "blossom-openraft-snapshot-fault-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let config = Config {
        heartbeat_interval: 50,
        election_timeout_min: 1_000,
        election_timeout_max: 2_000,
        snapshot_policy: openraft::SnapshotPolicy::Never,
        replication_lag_threshold: 1,
        max_in_snapshot_log_to_keep: 0,
        ..Default::default()
    };
    let mut cluster = InProcessRaftCluster::start_with_storage_and_config(
        3,
        0,
        RaftStorageProfile::DurableShardStream { root: root.clone() },
        config,
    )
    .await
    .unwrap();
    let leader = cluster.current_leader().await.unwrap();
    let follower = *cluster
        .voters
        .iter()
        .find(|node_id| **node_id != leader)
        .unwrap();
    cluster.pause_node(follower).await.unwrap();
    for sequence in 1..=12 {
        cluster
            .client_write(test_write_command(
                0x34,
                sequence,
                b"snapshot-fault",
                &sequence.to_le_bytes(),
            ))
            .await
            .unwrap();
    }
    cluster.trigger_snapshot_and_purge().await.unwrap();
    cluster
        .network_control
        .script_rpc_fault(ScriptedRaftRpcFault::between(
            "snapshot-response-loss",
            leader,
            follower,
            RaftRpcKind::InstallSnapshot,
            RaftRpcMatch::DataBearing,
            RaftRpcFaultAction::DropResponse,
        ))
        .await
        .unwrap();
    cluster.resume_node(follower).await.unwrap();
    cluster
        .wait_for_value_on_all_nodes(
            b"snapshot-fault",
            &12u64.to_le_bytes(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
    let coverage = cluster.network_control.coverage().await;
    assert!(coverage.all_scripted_faults_fired(), "{coverage:?}");
    assert!(coverage.install_snapshot_rpcs >= 1, "{coverage:?}");
    assert_eq!(coverage.response_drops, 1);
    assert_eq!(coverage.executed_faults.len(), 1);
    assert_eq!(
        coverage.executed_faults[0].rpc,
        RaftRpcKind::InstallSnapshot
    );
    assert!(
        cluster
            .wait_for_protocol_invariants(Duration::from_secs(2))
            .await,
        "snapshot response-loss recovery violated protocol indexes: {:?}",
        cluster.protocol_state()
    );
    cluster.shutdown().await;
    std::fs::remove_dir_all(root).ok();
}

async fn assert_partition_catchup(
    voters: usize,
    learners: usize,
    isolate_learner: bool,
    force_snapshot_install: bool,
) {
    let config = Config {
        heartbeat_interval: 50,
        election_timeout_min: 150,
        election_timeout_max: 300,
        enable_heartbeat: false,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(10_000),
        max_in_snapshot_log_to_keep: 0,
        ..Default::default()
    };
    let mut cluster = InProcessRaftCluster::start_with_storage_and_config(
        voters,
        learners,
        RaftStorageProfile::InMemory,
        config,
    )
    .await
    .unwrap();
    let key = b"snapshot-catchup".to_vec();
    for batch in 0..15 {
        let commands = ((batch * 16 + 1)..=(batch + 1) * 16)
            .map(|sequence| {
                active_active_command(
                    CommandIdentity {
                        client_id: ClientId([22; 16]),
                        client_epoch: ClientEpoch(1),
                        sequence,
                    },
                    CommandOperation::Append {
                        key: key.clone(),
                        value: vec![sequence as u8],
                    },
                )
                .unwrap()
            })
            .collect();
        cluster.client_write_concurrent(commands).await.unwrap();
    }

    let leader = cluster.current_leader().await.unwrap();
    let lagging = if isolate_learner {
        *cluster.learners.iter().next().unwrap()
    } else {
        *cluster.voters.iter().find(|node| **node != leader).unwrap()
    };
    let isolated = BTreeSet::from([lagging]);
    let connected = cluster
        .nodes
        .keys()
        .copied()
        .filter(|node| *node != lagging)
        .collect();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if cluster.state_machines[&lagging]
                .get(&key)
                .await
                .is_some_and(|bytes| bytes.len() == 240)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "node {lagging} did not reach the pre-partition watermark; final metrics: {:?}",
            cluster.raft_metrics()
        )
    });
    cluster
        .network_control
        .partition(&isolated, &connected)
        .await;
    if !isolate_learner {
        // Let the isolated voter advance its term so healing must repair
        // both replication and leadership, matching the retained Adam
        // failure rather than only exercising a short dropped RPC.
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    let final_commands = (241..=256)
        .map(|sequence| {
            active_active_command(
                CommandIdentity {
                    client_id: ClientId([22; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence,
                },
                CommandOperation::Append {
                    key: key.clone(),
                    value: vec![sequence as u8],
                },
            )
            .unwrap()
        })
        .collect();
    cluster
        .client_write_concurrent(final_commands)
        .await
        .unwrap();
    assert_eq!(
        cluster.state_machines[&lagging]
            .get(&key)
            .await
            .unwrap()
            .len(),
        240
    );

    let installed_snapshot_index = if force_snapshot_install {
        cluster.trigger_snapshot().await.unwrap();
        let leader = cluster.current_leader().await.unwrap();
        let snapshot = cluster.raft_metrics()[&leader].snapshot.unwrap();
        cluster.nodes[&leader]
            .trigger()
            .purge_log(snapshot.index)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if cluster.raft_metrics()[&leader]
                    .purged
                    .is_some_and(|purged| purged.index >= snapshot.index)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "leader did not purge through snapshot; final metrics: {:?}",
                cluster.raft_metrics()
            )
        });
        Some(snapshot.index)
    } else {
        None
    };

    cluster.network_control.heal().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if cluster.state_machines[&lagging]
                .get(&key)
                .await
                .is_some_and(|bytes| bytes.len() == 256)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "node {lagging} did not catch up after the partition healed; final metrics: {:?}",
            cluster.raft_metrics()
        )
    });
    if let Some(snapshot_index) = installed_snapshot_index {
        assert!(
            cluster.raft_metrics()[&lagging]
                .snapshot
                .is_some_and(|installed| installed.index >= snapshot_index),
            "node {lagging} caught up without publishing the installed snapshot watermark: {:?}",
            cluster.raft_metrics()
        );
    } else {
        assert!(
            cluster.raft_metrics()[&lagging].snapshot.is_none(),
            "ordinary append regression unexpectedly installed a snapshot: {:?}",
            cluster.raft_metrics()
        );
    }
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seven_voter_snapshot_catchup_wakes_after_partition_heals() {
    assert_partition_catchup(7, 0, false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn learner_snapshot_catchup_wakes_after_partition_heals() {
    assert_partition_catchup(3, 1, true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seven_voter_append_catchup_wakes_after_partition_heals_without_purge() {
    assert_partition_catchup(7, 0, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn learner_append_catchup_wakes_after_partition_heals_without_purge() {
    assert_partition_catchup(3, 1, true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openraft_re_elects_after_current_leader_is_paused() {
    let mut cluster = InProcessRaftCluster::start(3, 0).await.unwrap();
    let first = cluster.current_leader().await.unwrap();
    cluster.pause_node(first).await.unwrap();
    let second = cluster.current_leader().await.unwrap();
    assert_ne!(first, second);
    cluster.resume_node(first).await.unwrap();
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_write_retries_while_leadership_is_transitioning() {
    let mut cluster = InProcessRaftCluster::start(3, 0).await.unwrap();
    let first = cluster.current_leader().await.unwrap();
    cluster.pause_node(first).await.unwrap();

    let response = cluster
        .client_write(test_write_command(
            0x30,
            1,
            b"leader-transition",
            b"committed",
        ))
        .await
        .unwrap();

    assert_eq!(response.data.application_error, None);
    assert_eq!(response.data.result, Some(CommandResult::Written));
    let replacement = cluster.current_leader().await.unwrap();
    assert_ne!(replacement, first);
    cluster.resume_node(first).await.unwrap();
    cluster
        .wait_for_value_on_all_nodes(b"leader-transition", b"committed", Duration::from_secs(5))
        .await
        .unwrap();
    cluster.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shard_stream_vote_log_state_machine_and_snapshot_survive_restart() {
    let path = std::env::temp_dir().join(format!(
        "blossom-openraft-durable-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let config = Arc::new(
        Config {
            heartbeat_interval: 50,
            election_timeout_min: 150,
            election_timeout_max: 300,
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(1),
            ..Default::default()
        }
        .validate()
        .unwrap(),
    );
    let routes = Arc::new(RwLock::new(BTreeMap::new()));
    let control = InProcessNetworkControl::default();
    let BenchmarkDurableStores {
        log_store,
        state_machine,
    } = BenchmarkDurableStores::open(&path, 64, 1, &config.cluster_name).unwrap();
    let raft = BenchmarkRaft::new(
        1,
        config.clone(),
        InProcessNetworkFactory {
            source: 1,
            routes: routes.clone(),
            control: control.clone(),
        },
        log_store,
        state_machine.clone(),
    )
    .await
    .unwrap();
    routes.write().await.insert(1, raft.clone());
    raft.initialize(BTreeMap::from([(
        1,
        BasicNode {
            addr: "in-process://1".to_string(),
        },
    )]))
    .await
    .unwrap();
    let mut metrics = raft.metrics();
    tokio::time::timeout(Duration::from_secs(5), async {
        while metrics.borrow().current_leader != Some(1) {
            metrics.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    raft.client_write(
        active_active_command(
            CommandIdentity {
                client_id: ClientId([7; 16]),
                client_epoch: ClientEpoch(1),
                sequence: 1,
            },
            CommandOperation::BlindWrite {
                key: b"durable".to_vec(),
                value: b"value".to_vec(),
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    raft.trigger().snapshot().await.unwrap();
    raft.shutdown().await.unwrap();
    routes.write().await.clear();
    drop(raft);
    drop(state_machine);

    let (log_store, state_machine) = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match BenchmarkDurableStores::open(&path, 64, 1, &config.cluster_name) {
                Ok(stores) => break (stores.log_store, stores.state_machine),
                Err(error) if error.to_string().contains("already") => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("reopen durable OpenRaft store: {error}"),
            }
        }
    })
    .await
    .expect("OpenRaft released shard-stream storage after shutdown");
    assert_eq!(state_machine.get(b"durable").await, Some(b"value".to_vec()));
    assert!(state_machine.last_applied().await.is_some());
    let restarted = BenchmarkRaft::new(
        1,
        config,
        InProcessNetworkFactory {
            source: 1,
            routes: routes.clone(),
            control,
        },
        log_store,
        state_machine.clone(),
    )
    .await
    .unwrap();
    routes.write().await.insert(1, restarted.clone());
    restarted.shutdown().await.unwrap();
    routes.write().await.clear();
    drop(restarted);
    drop(state_machine);
    std::fs::remove_dir_all(path).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_cluster_kill_restart_and_catch_up_is_a_real_restart() {
    let root = std::env::temp_dir().join(format!(
        "blossom-openraft-cluster-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut cluster = InProcessRaftCluster::start_with_storage(
        3,
        0,
        RaftStorageProfile::DurableShardStream { root: root.clone() },
    )
    .await
    .unwrap();
    let leader = cluster.current_leader().await.unwrap();
    let follower = *cluster.voters.iter().find(|node| **node != leader).unwrap();
    cluster
        .client_write(
            active_active_command(
                CommandIdentity {
                    client_id: ClientId([8; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 1,
                },
                CommandOperation::BlindWrite {
                    key: b"restart".to_vec(),
                    value: b"before".to_vec(),
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    cluster.kill_and_restart_node(follower).await.unwrap();
    cluster
        .client_write(
            active_active_command(
                CommandIdentity {
                    client_id: ClientId([8; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 2,
                },
                CommandOperation::BlindWrite {
                    key: b"restart".to_vec(),
                    value: b"after".to_vec(),
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if cluster.state_machines[&follower].get(b"restart").await == Some(b"after".to_vec()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    cluster.shutdown().await;
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "production durability soak; run explicitly with BLOSSOM_RAFT_SOAK_COMMANDS"]
async fn durable_openraft_survives_thousand_write_leader_and_follower_restart_soak() {
    let commands = std::env::var("BLOSSOM_RAFT_SOAK_COMMANDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_001);
    assert!(
        commands >= 1_001,
        "production OpenRaft soak must run 1,001+ writes"
    );
    let root = std::env::temp_dir().join(format!(
        "blossom-openraft-soak-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut cluster = InProcessRaftCluster::start_with_storage(
        3,
        0,
        RaftStorageProfile::DurableShardStream { root: root.clone() },
    )
    .await
    .unwrap();
    let key = b"raft-soak".to_vec();

    for sequence in 1..=commands {
        if sequence.is_multiple_of(211) {
            let leader = cluster.current_leader().await.unwrap();
            cluster.kill_and_restart_node(leader).await.unwrap();
            cluster
                .wait_for_leader(Duration::from_secs(10))
                .await
                .unwrap();
        } else if sequence.is_multiple_of(97) {
            let leader = cluster.current_leader().await.unwrap();
            let follower = *cluster.voters.iter().find(|node| **node != leader).unwrap();
            cluster.kill_and_restart_node(follower).await.unwrap();
        }

        let value = sequence.to_le_bytes().to_vec();
        let response = cluster
            .client_write(
                active_active_command(
                    CommandIdentity {
                        client_id: ClientId([0x5A; 16]),
                        client_epoch: ClientEpoch(1),
                        sequence,
                    },
                    CommandOperation::BlindWrite {
                        key: key.clone(),
                        value: value.clone(),
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.data.application_error, None);
        assert_eq!(response.data.result, Some(CommandResult::Written));

        if sequence.is_multiple_of(101) {
            assert_eq!(cluster.read_linearizable(&key).await.unwrap(), Some(value));
        }
    }

    let expected = commands.to_le_bytes().to_vec();
    cluster.trigger_snapshot().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut converged = true;
            for machine in cluster.state_machines.values() {
                if machine.get(&key).await != Some(expected.clone()) {
                    converged = false;
                    break;
                }
            }
            if converged {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("OpenRaft followers did not converge after the restart soak");
    assert_eq!(
        cluster.read_linearizable(&key).await.unwrap(),
        Some(expected)
    );
    cluster.shutdown().await;
    std::fs::remove_dir_all(root).ok();
}
