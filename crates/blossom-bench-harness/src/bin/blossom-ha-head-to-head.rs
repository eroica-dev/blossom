use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use blossom::{
    ActiveActiveCommand, ClientEpoch, ClientId, CommandIdentity, CommandOperation, CommandResult,
    HaReplicationMode, HaServiceTopology, HashType, HighAvailabilityParameters,
    high_availability_fault_tolerance, high_availability_majority,
};
use blossom_bench_harness::{
    FixedSlotHaCluster, HaAppliedSample, InProcessRaftCluster, OPENRAFT_VERSION, PairedRunOrder,
    REDB_VERSION, RaftAppliedResponse, RaftStorageProfile, paired_run_order,
};
use clap::Parser;
use serde::Serialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-ha-head-to-head",
    about = "Compare fixed-slot active-active Blossom HA with active-passive OpenRaft at 2-7 nodes"
)]
struct Args {
    #[arg(long, default_value_t = 3)]
    iterations: usize,
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    #[arg(long, default_value_t = 42)]
    seed: u64,
    #[arg(long, default_value_t = false)]
    wait_for_seal: bool,
    #[arg(long, default_value_t = false)]
    durable: bool,
    #[arg(long, default_value = "benchmarks/results/ha-head-to-head/result.json")]
    output: PathBuf,
}

#[derive(Serialize)]
struct HaHeadToHeadArtifact {
    schema_version: u16,
    publishable: bool,
    not_publishable_reasons: Vec<&'static str>,
    build_profile: &'static str,
    blossom_profile: &'static str,
    raft_profile: &'static str,
    blossom_replication_mode: HaReplicationMode,
    raft_replication_mode: HaReplicationMode,
    openraft_version: &'static str,
    redb_version: &'static str,
    ha_parameters: HighAvailabilityParameters,
    ha_parameters_hash: HashType,
    iterations_per_footprint: usize,
    payload_bytes_per_writer: usize,
    rows: Vec<FootprintRow>,
}

#[derive(Serialize)]
struct FootprintRow {
    physical_nodes: usize,
    blossom_topology: HaServiceTopology,
    raft_topology: HaServiceTopology,
    blossom_fixed_membership_hash: HashType,
    blossom_active_writers: usize,
    blossom_required: usize,
    blossom_tolerated_inactive: usize,
    raft_voters: usize,
    raft_learners: usize,
    raft_required: usize,
    raft_tolerated_inactive_voters: usize,
    repetitions: Vec<PairedRepetition>,
}

#[derive(Serialize)]
struct PairedRepetition {
    iteration: usize,
    order: PairedRunOrder,
    blossom: HaAppliedSample,
    raft: RaftSample,
    exact_non_conflicting_state_equal: bool,
}

#[derive(Serialize)]
struct RaftSample {
    applied_nanos: u64,
    writer_count: usize,
    command_count: usize,
    results: Vec<RaftAppliedResponse>,
}

struct WorkloadEntry {
    command: ActiveActiveCommand,
    key: Vec<u8>,
    value: Vec<u8>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    if args.iterations == 0 || args.payload_bytes == 0 {
        return Err("iterations and payload bytes must be non-zero".into());
    }
    let parent = args
        .output
        .parent()
        .ok_or("benchmark output must have a parent directory")?;
    fs::create_dir_all(parent)?;
    let storage_root = if args.durable {
        let run_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Some(parent.join(format!(
            "ha-head-to-head-storage-{}-{run_id}",
            std::process::id()
        )))
    } else {
        None
    };

    let parameters = HighAvailabilityParameters::default();
    let mut rows = Vec::with_capacity(6);
    for physical_nodes in 2..=7 {
        let (raft_voters, raft_learners) = raft_layout(physical_nodes);
        let blossom_topology = HaServiceTopology::active_active(physical_nodes)?;
        let raft_topology = HaServiceTopology::active_passive(physical_nodes, raft_voters)?;
        let mut blossom = match &storage_root {
            Some(root) => FixedSlotHaCluster::with_durable_storage(
                physical_nodes,
                parameters,
                root.join(format!("blossom-{physical_nodes}")),
            )?,
            None => FixedSlotHaCluster::with_parameters(physical_nodes, parameters)?,
        };
        let raft_storage = match &storage_root {
            Some(root) => RaftStorageProfile::DurableRedbImmediate {
                root: root.join(format!("openraft-{physical_nodes}")),
            },
            None => RaftStorageProfile::InMemory,
        };
        let mut raft =
            InProcessRaftCluster::start_with_storage(raft_voters, raft_learners, raft_storage)
                .await?;
        let mut repetitions = Vec::with_capacity(args.iterations);

        for iteration in 0..args.iterations {
            let workload = workload(physical_nodes, iteration, args.payload_bytes)?;
            let commands = workload
                .iter()
                .map(|entry| entry.command.clone())
                .collect::<Vec<_>>();
            let order = paired_run_order(args.seed ^ u64::try_from(physical_nodes)?, iteration);
            let (blossom_sample, raft_sample) = match order {
                PairedRunOrder::BlossomThenRaft => {
                    let blossom_sample =
                        blossom.client_write_universal(commands.clone(), args.wait_for_seal)?;
                    let raft_sample = raft_write(&mut raft, commands).await?;
                    (blossom_sample, raft_sample)
                }
                PairedRunOrder::RaftThenBlossom => {
                    let raft_sample = raft_write(&mut raft, commands.clone()).await?;
                    let blossom_sample =
                        blossom.client_write_universal(commands, args.wait_for_seal)?;
                    (blossom_sample, raft_sample)
                }
            };

            verify_results(&blossom_sample, &raft_sample, iteration)?;
            for entry in &workload {
                let blossom_value = blossom.state_machine().get(&entry.key);
                let raft_value = raft.read_linearizable(&entry.key).await?;
                if blossom_value != Some(entry.value.as_slice())
                    || raft_value.as_deref() != blossom_value
                {
                    return Err(format!(
                        "state mismatch at {physical_nodes} nodes, iteration {iteration}"
                    )
                    .into());
                }
            }
            repetitions.push(PairedRepetition {
                iteration,
                order,
                blossom: blossom_sample,
                raft: raft_sample,
                exact_non_conflicting_state_equal: true,
            });
        }
        raft.shutdown().await;
        rows.push(FootprintRow {
            physical_nodes,
            blossom_topology,
            raft_topology,
            blossom_fixed_membership_hash: blossom.fixed_membership_hash(),
            blossom_active_writers: physical_nodes,
            blossom_required: high_availability_majority(physical_nodes),
            blossom_tolerated_inactive: high_availability_fault_tolerance(physical_nodes),
            raft_voters,
            raft_learners,
            raft_required: raft_voters / 2 + 1,
            raft_tolerated_inactive_voters: (raft_voters - 1) / 2,
            repetitions,
        });
    }

    let mut not_publishable_reasons = vec![
        "protocol-core smoke benchmark, not a multi-process transport profile",
        "does not satisfy a five-minute steady-state window",
        "does not satisfy 100,000 Applied samples per cell",
        "fault, restart, and hierarchical-bootstrap gates are not run by this command",
    ];
    if args.iterations < 12 {
        not_publishable_reasons.push("does not satisfy twelve paired repetitions");
    }
    let artifact = HaHeadToHeadArtifact {
        schema_version: 3,
        publishable: false,
        not_publishable_reasons,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        blossom_profile: if args.durable {
            "leaderless-active-active-fixed-slot-redb-immediate"
        } else {
            "leaderless-active-active-fixed-slot-in-memory"
        },
        raft_profile: if args.durable {
            "leader-based-active-passive-in-process-redb-immediate"
        } else {
            "leader-based-active-passive-in-process-in-memory"
        },
        blossom_replication_mode: HaReplicationMode::LeaderlessActiveActive,
        raft_replication_mode: HaReplicationMode::MajorityLeaderActivePassive,
        openraft_version: OPENRAFT_VERSION,
        redb_version: REDB_VERSION,
        ha_parameters: parameters,
        ha_parameters_hash: parameters.hash(),
        iterations_per_footprint: args.iterations,
        payload_bytes_per_writer: args.payload_bytes,
        rows,
    };
    fs::write(&args.output, serde_json::to_vec_pretty(&artifact)?)?;
    if let Some(root) = storage_root {
        fs::remove_dir_all(root)?;
    }
    println!("{}", args.output.display());
    Ok(())
}

fn raft_layout(physical_nodes: usize) -> (usize, usize) {
    match physical_nodes {
        2 => (2, 0),
        3 => (3, 0),
        4 => (3, 1),
        5 => (5, 0),
        6 => (5, 1),
        7 => (7, 0),
        _ => unreachable!("HA benchmark supports only 2..=7 nodes"),
    }
}

fn workload(
    physical_nodes: usize,
    iteration: usize,
    payload_bytes: usize,
) -> Result<Vec<WorkloadEntry>, BoxError> {
    let sequence = u64::try_from(iteration)?
        .checked_add(1)
        .ok_or("command sequence overflow")?;
    let mut workload = Vec::with_capacity(physical_nodes);
    for writer in 0..physical_nodes {
        let mut client_id = [0u8; 16];
        client_id[..8].copy_from_slice(&u64::try_from(physical_nodes)?.to_le_bytes());
        client_id[8..].copy_from_slice(&u64::try_from(writer)?.to_le_bytes());
        let key = format!("ha-{physical_nodes}-{iteration}-{writer}").into_bytes();
        let mut value = vec![0u8; payload_bytes];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = sequence
                .wrapping_add(u64::try_from(writer)?)
                .wrapping_add(u64::try_from(index)?)
                .to_le_bytes()[0];
        }
        workload.push(WorkloadEntry {
            command: ActiveActiveCommand {
                identity: CommandIdentity {
                    client_id: ClientId(client_id),
                    client_epoch: ClientEpoch(1),
                    sequence,
                },
                operation: CommandOperation::BlindWrite {
                    key: key.clone(),
                    value: value.clone(),
                },
            },
            key,
            value,
        });
    }
    Ok(workload)
}

async fn raft_write(
    raft: &mut InProcessRaftCluster,
    commands: Vec<ActiveActiveCommand>,
) -> Result<RaftSample, BoxError> {
    let writer_count = commands.len();
    let started = Instant::now();
    let results = raft.client_write_concurrent(commands).await?;
    Ok(RaftSample {
        applied_nanos: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        writer_count,
        command_count: writer_count,
        results,
    })
}

fn verify_results(
    blossom: &HaAppliedSample,
    raft: &RaftSample,
    iteration: usize,
) -> Result<(), BoxError> {
    if blossom
        .results
        .iter()
        .any(|result| *result != CommandResult::Written)
        || raft.results.iter().any(|response| {
            response.application_error.is_some() || response.result != Some(CommandResult::Written)
        })
    {
        return Err(format!("application result mismatch at iteration {iteration}").into());
    }
    Ok(())
}
