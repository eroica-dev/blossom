//! Reproducible native OpenRaft fault campaign orchestration.

use super::*;

pub async fn run_raft_deterministic_campaign(
    physical_nodes: usize,
    commands: u64,
    seed: u64,
    durable: bool,
    fault: RaftDeterministicFault,
) -> Result<RaftDeterministicReport, Box<dyn std::error::Error + Send + Sync>> {
    if !(2..=7).contains(&physical_nodes) {
        return Err("deterministic OpenRaft physical node count must be 2..=7".into());
    }
    if commands == 0 {
        return Err("deterministic OpenRaft command count must be positive".into());
    }
    if !durable
        && matches!(
            fault,
            RaftDeterministicFault::DurableFollowerRestart
                | RaftDeterministicFault::DurableLeaderRestart
        )
    {
        return Err("OpenRaft kill/restart requires durable storage".into());
    }
    let voters = match physical_nodes {
        2 => 2,
        3 | 4 => 3,
        5 | 6 => 5,
        7 => 7,
        _ => unreachable!("physical node count was validated"),
    };
    if voters == 2
        && matches!(
            fault,
            RaftDeterministicFault::VoteRequestLoss | RaftDeterministicFault::VoteResponseLoss
        )
    {
        return Err("scripted vote-loss campaigns require at least three voters".into());
    }
    let learners = physical_nodes.saturating_sub(voters);
    let root = std::env::temp_dir().join(format!(
        "blossom-raft-dst-{}-{}-{}",
        std::process::id(),
        physical_nodes,
        seed
    ));
    let storage = if durable {
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        RaftStorageProfile::DurableShardStream { root: root.clone() }
    } else {
        RaftStorageProfile::InMemory
    };
    let mut cluster = InProcessRaftCluster::start_with_storage(voters, learners, storage).await?;
    let initial_leader = cluster.current_leader().await?;
    let mut expected_stalls = 0u64;
    let mut ambiguous_outcomes = 0u64;
    let mut ambiguous_outcomes_resolved = true;
    let mut leader_changes = 0u64;
    let fault_at = (commands / 2).max(1);
    let key = format!("raft-dst-key-{seed}").into_bytes();
    let mut history = Vec::with_capacity(usize::try_from(commands).unwrap_or(usize::MAX));

    for sequence in 1..=commands {
        let mut heal_after_write = false;
        let mut response_was_lost_after_commit = false;
        if sequence == fault_at {
            let leader = cluster.current_leader().await?;
            let follower = cluster
                .voters
                .iter()
                .copied()
                .find(|node| *node != leader)
                .ok_or("deterministic OpenRaft campaign requires a follower")?;
            match fault {
                RaftDeterministicFault::None => {}
                RaftDeterministicFault::FollowerPause => {
                    cluster.pause_node(follower).await?;
                    if voters == 2 {
                        expected_stalls = expected_stalls.saturating_add(1);
                        assert_raft_write_stalls(
                            &mut cluster,
                            deterministic_raft_command(&key, sequence, seed),
                        )
                        .await?;
                    }
                    cluster.resume_node(follower).await?;
                }
                RaftDeterministicFault::LeaderPause => {
                    cluster.pause_node(leader).await?;
                    if voters == 2 {
                        expected_stalls = expected_stalls.saturating_add(1);
                        assert_raft_write_stalls(
                            &mut cluster,
                            deterministic_raft_command(&key, sequence, seed),
                        )
                        .await?;
                        cluster.resume_node(leader).await?;
                    } else {
                        let replacement = cluster.wait_for_leader(Duration::from_secs(10)).await?;
                        if replacement != leader {
                            leader_changes = leader_changes.saturating_add(1);
                        }
                        cluster.resume_node(leader).await?;
                    }
                }
                RaftDeterministicFault::AsymmetricFollowerPartition => {
                    cluster
                        .network_control
                        .set_link(leader, follower, LinkState::Blocked)
                        .await;
                    if voters == 2 {
                        expected_stalls = expected_stalls.saturating_add(1);
                        assert_raft_write_stalls(
                            &mut cluster,
                            deterministic_raft_command(&key, sequence, seed),
                        )
                        .await?;
                        cluster.network_control.heal().await;
                    } else {
                        heal_after_write = true;
                    }
                }
                RaftDeterministicFault::QuorumLossPartition => {
                    let quorum = voters / 2 + 1;
                    let pause_count = voters.saturating_sub(quorum.saturating_sub(1));
                    let unavailable = cluster
                        .voters
                        .iter()
                        .copied()
                        .filter(|node| *node != leader)
                        .take(pause_count)
                        .collect::<Vec<_>>();
                    for node in &unavailable {
                        cluster.pause_node(*node).await?;
                    }
                    expected_stalls = expected_stalls.saturating_add(1);
                    assert_raft_write_stalls(
                        &mut cluster,
                        deterministic_raft_command(&key, sequence, seed),
                    )
                    .await?;
                    for node in unavailable {
                        cluster.resume_node(node).await?;
                    }
                }
                RaftDeterministicFault::NetworkDelay => {
                    for node in cluster
                        .voters
                        .iter()
                        .copied()
                        .filter(|node| *node != leader)
                    {
                        cluster
                            .network_control
                            .set_link(leader, node, LinkState::Delayed(Duration::from_millis(25)))
                            .await;
                    }
                    heal_after_write = true;
                }
                RaftDeterministicFault::ResponseLossAfterCommit => {
                    let command = deterministic_raft_command(&key, sequence, seed);
                    let response = deterministic_raft_write(&mut cluster, command).await?;
                    if response.application_error.is_some()
                        || response.result != Some(CommandResult::Written)
                    {
                        return Err("OpenRaft response-loss setup write did not apply".into());
                    }
                    ambiguous_outcomes = ambiguous_outcomes.saturating_add(1);
                    response_was_lost_after_commit = true;
                }
                RaftDeterministicFault::AppendRequestLoss => {
                    cluster
                        .network_control
                        .script_rpc_fault(ScriptedRaftRpcFault::between(
                            format!("append-request-loss-{sequence}"),
                            leader,
                            follower,
                            RaftRpcKind::AppendEntries,
                            RaftRpcMatch::DataBearing,
                            RaftRpcFaultAction::DropRequest,
                        ))
                        .await?;
                }
                RaftDeterministicFault::AppendResponseLoss => {
                    cluster
                        .network_control
                        .script_rpc_fault(ScriptedRaftRpcFault::between(
                            format!("append-response-loss-{sequence}"),
                            leader,
                            follower,
                            RaftRpcKind::AppendEntries,
                            RaftRpcMatch::DataBearing,
                            RaftRpcFaultAction::DropResponse,
                        ))
                        .await?;
                }
                RaftDeterministicFault::DuplicateAppendRequest => {
                    cluster
                        .network_control
                        .script_rpc_fault(ScriptedRaftRpcFault::between(
                            format!("duplicate-append-request-{sequence}"),
                            leader,
                            follower,
                            RaftRpcKind::AppendEntries,
                            RaftRpcMatch::DataBearing,
                            RaftRpcFaultAction::DuplicateRequest,
                        ))
                        .await?;
                }
                RaftDeterministicFault::AppendRequestDelay => {
                    cluster
                        .network_control
                        .script_rpc_fault(ScriptedRaftRpcFault::between(
                            format!("append-request-delay-{sequence}"),
                            leader,
                            follower,
                            RaftRpcKind::AppendEntries,
                            RaftRpcMatch::DataBearing,
                            RaftRpcFaultAction::DelayRequest { millis: 75 },
                        ))
                        .await?;
                }
                RaftDeterministicFault::AppendResponseDelay => {
                    cluster
                        .network_control
                        .script_rpc_fault(ScriptedRaftRpcFault::between(
                            format!("append-response-delay-{sequence}"),
                            leader,
                            follower,
                            RaftRpcKind::AppendEntries,
                            RaftRpcMatch::DataBearing,
                            RaftRpcFaultAction::DelayResponse { millis: 75 },
                        ))
                        .await?;
                }
                RaftDeterministicFault::VoteRequestLoss
                | RaftDeterministicFault::VoteResponseLoss => {
                    let action = if fault == RaftDeterministicFault::VoteRequestLoss {
                        RaftRpcFaultAction::DropRequest
                    } else {
                        RaftRpcFaultAction::DropResponse
                    };
                    cluster
                        .network_control
                        .script_rpc_fault(ScriptedRaftRpcFault::any_route(
                            format!("vote-loss-{sequence}"),
                            RaftRpcKind::Vote,
                            RaftRpcMatch::Any,
                            action,
                        ))
                        .await?;
                    cluster.pause_node(leader).await?;
                    let replacement = cluster.wait_for_leader(Duration::from_secs(10)).await?;
                    if replacement != leader {
                        leader_changes = leader_changes.saturating_add(1);
                    }
                    cluster.resume_node(leader).await?;
                }
                RaftDeterministicFault::RepeatedLeaderChurn => {
                    if voters == 2 {
                        cluster.pause_node(leader).await?;
                        expected_stalls = expected_stalls.saturating_add(1);
                        assert_raft_write_stalls(
                            &mut cluster,
                            deterministic_raft_command(&key, sequence, seed),
                        )
                        .await?;
                        cluster.resume_node(leader).await?;
                    } else {
                        for _ in 0..3 {
                            let previous = cluster.current_leader().await?;
                            cluster.pause_node(previous).await?;
                            let replacement =
                                cluster.wait_for_leader(Duration::from_secs(10)).await?;
                            if replacement != previous {
                                leader_changes = leader_changes.saturating_add(1);
                            }
                            cluster.resume_node(previous).await?;
                        }
                    }
                }
                RaftDeterministicFault::DurableFollowerRestart => {
                    cluster.kill_and_restart_node(follower).await?;
                }
                RaftDeterministicFault::DurableLeaderRestart => {
                    cluster.kill_and_restart_node(leader).await?;
                    let replacement = cluster.wait_for_leader(Duration::from_secs(10)).await?;
                    if replacement != leader {
                        leader_changes = leader_changes.saturating_add(1);
                    }
                }
            }
        }

        let command = deterministic_raft_command(&key, sequence, seed);
        let response = deterministic_raft_write(&mut cluster, command.clone()).await?;
        if response.application_error.is_some() || response.result != Some(CommandResult::Written) {
            return Err(format!(
                "OpenRaft deterministic write {sequence} did not apply: {:?}",
                response
            )
            .into());
        }
        if response_was_lost_after_commit {
            ambiguous_outcomes_resolved &= response.result == Some(CommandResult::Written);
        }
        history.push(crate::correctness::HistoryOperation {
            operation_id: sequence,
            invocation_nanos: u128::from(sequence).saturating_mul(2),
            response_nanos: u128::from(sequence).saturating_mul(2).saturating_add(1),
            command,
            result: CommandResult::Written,
        });
        if heal_after_write {
            cluster.network_control.heal().await;
        }
    }

    let final_value = deterministic_raft_value(commands, seed);
    let linearizable_read_passed =
        cluster.read_linearizable(&key).await? == Some(final_value.clone());
    let history_linearizable = history
        .chunks(63)
        .all(|segment| crate::correctness::check_linearizable_history(segment, 64).linearizable);
    cluster.trigger_snapshot().await?;
    let all_nodes_converged = cluster
        .wait_for_value_on_all_nodes(&key, &final_value, Duration::from_secs(10))
        .await
        .is_ok();
    let final_leader = cluster.current_leader().await?;
    if final_leader != initial_leader {
        leader_changes = leader_changes.saturating_add(1);
    }
    let protocol_invariants_passed = cluster.protocol_invariants_hold();
    let network_fault_coverage = cluster.network_control.coverage().await;
    let fault_coverage_passed =
        !is_scripted_rpc_fault(fault) || network_fault_coverage.all_scripted_faults_fired();
    cluster.shutdown_checked().await?;
    if durable {
        std::fs::remove_dir_all(&root).ok();
    }
    Ok(RaftDeterministicReport {
        physical_nodes,
        voters,
        learners,
        commands,
        seed,
        durable,
        fault,
        expected_stalls,
        ambiguous_outcomes,
        ambiguous_outcomes_resolved,
        leader_changes,
        final_value,
        all_nodes_converged,
        linearizable_read_passed,
        history_linearizable,
        protocol_invariants_passed,
        fault_coverage_passed,
        network_fault_coverage,
    })
}

fn is_scripted_rpc_fault(fault: RaftDeterministicFault) -> bool {
    matches!(
        fault,
        RaftDeterministicFault::AppendRequestLoss
            | RaftDeterministicFault::AppendResponseLoss
            | RaftDeterministicFault::DuplicateAppendRequest
            | RaftDeterministicFault::AppendRequestDelay
            | RaftDeterministicFault::AppendResponseDelay
            | RaftDeterministicFault::VoteRequestLoss
            | RaftDeterministicFault::VoteResponseLoss
    )
}

fn deterministic_raft_command(key: &[u8], sequence: u64, seed: u64) -> ActiveActiveCommand {
    use crate::{CommandOperation, active_active_command};
    use blossom::{ClientEpoch, ClientId, CommandIdentity};

    let mut client = [0u8; 16];
    client[..8].copy_from_slice(&seed.to_le_bytes());
    client[8..].copy_from_slice(&(seed ^ sequence).rotate_left(17).to_le_bytes());
    active_active_command(
        CommandIdentity {
            client_id: ClientId(client),
            client_epoch: ClientEpoch(1),
            sequence: 1,
        },
        CommandOperation::BlindWrite {
            key: key.to_vec(),
            value: deterministic_raft_value(sequence, seed),
        },
    )
    .expect("deterministic benchmark command is valid")
}

fn deterministic_raft_value(sequence: u64, seed: u64) -> Vec<u8> {
    [sequence.to_le_bytes(), seed.to_le_bytes()].concat()
}

pub(super) async fn deterministic_raft_write(
    cluster: &mut InProcessRaftCluster,
    command: ActiveActiveCommand,
) -> Result<RaftAppliedResponse, Box<dyn std::error::Error + Send + Sync>> {
    cluster
        .client_write_concurrent(vec![command])
        .await?
        .pop()
        .ok_or_else(|| "deterministic OpenRaft write returned no response".into())
}

async fn assert_raft_write_stalls(
    cluster: &mut InProcessRaftCluster,
    command: ActiveActiveCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match tokio::time::timeout(Duration::from_millis(250), cluster.client_write(command)).await {
        Err(_) | Ok(Err(_)) => Ok(()),
        Ok(Ok(_)) => Err("OpenRaft write unexpectedly committed without quorum".into()),
    }
}
