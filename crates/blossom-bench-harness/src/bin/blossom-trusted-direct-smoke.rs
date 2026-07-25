use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use blossom::{
    ActiveActiveCommand, ClientEpoch, ClientId, CommandIdentity, CommandOperation, CommandResult,
    QuorumSize,
};
use blossom_bench_harness::{
    BlossomTrustedDirectCluster, BlossomTrustedDirectSample, InProcessRaftCluster, PairedRunOrder,
    RaftAppliedResponse, paired_run_order,
};
use clap::Parser;
use serde::Serialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-trusted-direct-smoke",
    about = "Compare direct unsigned trusted Blossom with concurrent in-memory OpenRaft"
)]
struct Args {
    #[arg(long, env = "BLOSSOM_QUORUM_SIZE", default_value = "6")]
    quorum_size: QuorumSize,
    #[arg(long, default_value_t = 6)]
    blossom_nodes: usize,
    #[arg(long)]
    active_writers: Option<usize>,
    #[arg(long, default_value_t = 5)]
    raft_voters: usize,
    #[arg(long)]
    raft_learners: Option<usize>,
    /// Run only Blossom for large-node scalability diagnostics.
    #[arg(long)]
    blossom_only: bool,
    #[arg(long, default_value_t = 3)]
    iterations: usize,
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    #[arg(long, default_value_t = 42)]
    seed: u64,
    #[arg(
        long,
        default_value = "benchmarks/results/trusted-direct-smoke/result.json"
    )]
    output: PathBuf,
}

#[derive(Serialize)]
struct DirectArtifact {
    schema_version: u16,
    profile: &'static str,
    comparison: &'static str,
    publishable: bool,
    not_publishable_reasons: Vec<&'static str>,
    blossom_quorum_size: usize,
    blossom_nodes: usize,
    active_writers: usize,
    raft_voters: usize,
    raft_learners: usize,
    iterations: usize,
    payload_bytes_per_writer: usize,
    rows: Vec<DirectRow>,
}

#[derive(Serialize)]
struct DirectRow {
    iteration: usize,
    order: PairedRunOrder,
    blossom: BlossomTrustedDirectSample,
    raft_applied_nanos: Option<u64>,
    raft_results: Option<Vec<RaftAppliedResponse>>,
    exact_final_state_equal: Option<bool>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    if args.iterations == 0 || args.payload_bytes == 0 {
        return Err("iterations and payload bytes must be non-zero".into());
    }
    if args.blossom_nodes < 3 || !args.blossom_nodes.is_multiple_of(3) {
        return Err("Blossom nodes must form three equal non-empty sites".into());
    }
    let active_writers = args.active_writers.unwrap_or(args.blossom_nodes);
    if active_writers == 0 || active_writers > args.blossom_nodes {
        return Err(format!(
            "active writers must be in 1..={}, got {active_writers}",
            args.blossom_nodes
        )
        .into());
    }
    let raft_learners = args
        .raft_learners
        .unwrap_or_else(|| args.blossom_nodes.saturating_sub(args.raft_voters));
    let output_parent = args
        .output
        .parent()
        .ok_or("benchmark output must have a parent directory")?;
    fs::create_dir_all(output_parent)?;
    let mut blossom =
        BlossomTrustedDirectCluster::start(args.blossom_nodes, args.quorum_size).await?;
    let mut raft = if args.blossom_only {
        None
    } else {
        Some(InProcessRaftCluster::start(args.raft_voters, raft_learners).await?)
    };

    let mut rows = Vec::with_capacity(args.iterations);
    for iteration in 0..args.iterations {
        let workload = workload(iteration, active_writers, args.payload_bytes)?;
        let commands = workload
            .iter()
            .map(|entry| entry.command.clone())
            .collect::<Vec<_>>();
        let order = paired_run_order(args.seed, iteration);
        let (blossom_sample, raft_applied_nanos, raft_results) = match raft.as_mut() {
            Some(raft) => match order {
                PairedRunOrder::BlossomThenRaft => {
                    let blossom_sample = blossom.client_write_universal(commands.clone()).await?;
                    let (nanos, results) = raft_write(raft, commands).await?;
                    (blossom_sample, Some(nanos), Some(results))
                }
                PairedRunOrder::RaftThenBlossom => {
                    let (nanos, results) = raft_write(raft, commands.clone()).await?;
                    let blossom_sample = blossom.client_write_universal(commands).await?;
                    (blossom_sample, Some(nanos), Some(results))
                }
            },
            None => (blossom.client_write_universal(commands).await?, None, None),
        };
        if blossom_sample
            .results
            .iter()
            .any(|result| *result != CommandResult::Written)
            || raft_results.as_ref().is_some_and(|results| {
                results.iter().any(|response| {
                    response.application_error.is_some()
                        || response.result != Some(CommandResult::Written)
                })
            })
        {
            return Err(
                format!("protocol application result diverged at iteration {iteration}").into(),
            );
        }
        for entry in &workload {
            let blossom_value = blossom.read_local(&entry.key);
            if blossom_value.as_deref() != Some(entry.value.as_slice()) {
                return Err(format!(
                    "Blossom final state diverged at iteration {iteration}, writer {}",
                    entry.writer
                )
                .into());
            }
            if let Some(raft) = raft.as_mut() {
                let raft_value = raft.read_linearizable(&entry.key).await?;
                if raft_value != blossom_value {
                    return Err(format!(
                        "protocol final state diverged at iteration {iteration}, writer {}",
                        entry.writer
                    )
                    .into());
                }
            }
        }
        rows.push(DirectRow {
            iteration,
            order,
            blossom: blossom_sample,
            raft_applied_nanos,
            raft_results,
            exact_final_state_equal: raft.as_ref().map(|_| true),
        });
    }
    if let Some(raft) = raft {
        raft.shutdown().await;
    }

    let artifact = DirectArtifact {
        schema_version: 1,
        profile: "in-memory-protocol-core",
        comparison: if args.blossom_only {
            "blossom-scale-only"
        } else {
            "blossom-vs-openraft"
        },
        publishable: false,
        not_publishable_reasons: if args.blossom_only {
            vec![
                "Blossom-only scale row has no head-to-head protocol comparison",
                "diagnostic does not satisfy twelve paired repetitions",
                "diagnostic does not satisfy the five-minute steady-state window",
                "diagnostic does not satisfy 100,000 Applied samples per cell",
                "fault, recovery, and confidence-interval gates are not run by this command",
            ]
        } else {
            vec![
                "diagnostic uses native Blossom TCP and OpenRaft's in-process network",
                "diagnostic does not satisfy twelve paired repetitions",
                "diagnostic does not satisfy the five-minute steady-state window",
                "diagnostic does not satisfy 100,000 Applied samples per cell",
                "fault, recovery, and confidence-interval gates are not run by this command",
            ]
        },
        blossom_quorum_size: args.quorum_size.get(),
        blossom_nodes: args.blossom_nodes,
        active_writers,
        raft_voters: args.raft_voters,
        raft_learners,
        iterations: args.iterations,
        payload_bytes_per_writer: args.payload_bytes,
        rows,
    };
    fs::write(&args.output, serde_json::to_vec_pretty(&artifact)?)?;
    println!("{}", args.output.display());
    Ok(())
}

struct WorkloadEntry {
    writer: usize,
    command: ActiveActiveCommand,
    key: Vec<u8>,
    value: Vec<u8>,
}

fn workload(
    iteration: usize,
    active_writers: usize,
    payload_bytes: usize,
) -> Result<Vec<WorkloadEntry>, BoxError> {
    let sequence = u64::try_from(iteration)?
        .checked_add(1)
        .ok_or("command sequence overflow")?;
    let mut workload = Vec::with_capacity(active_writers);
    for writer in 0..active_writers {
        let mut client_id = [0u8; 16];
        client_id[..8].copy_from_slice(&u64::try_from(writer)?.to_le_bytes());
        client_id[8..].copy_from_slice(&0x74727573746564_u64.to_le_bytes());
        let key = format!("trusted-direct-key-{iteration}-{writer}").into_bytes();
        let mut value = vec![0u8; payload_bytes];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = sequence
                .wrapping_add(u64::try_from(writer)?)
                .wrapping_add(u64::try_from(index)?)
                .to_le_bytes()[0];
        }
        workload.push(WorkloadEntry {
            writer,
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
) -> Result<(u64, Vec<RaftAppliedResponse>), BoxError> {
    let started = Instant::now();
    let responses = raft.client_write_concurrent(commands).await?;
    Ok((
        u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        responses,
    ))
}
