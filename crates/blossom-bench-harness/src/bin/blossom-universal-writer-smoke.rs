use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use blossom::{
    ActiveActiveCommand, ClientEpoch, ClientId, CommandIdentity, QuorumSize, supermajority_count,
};
use blossom_bench_harness::{
    BlossomActiveActiveCluster, BlossomUniversalWriterSample, CommandOperation, CommandResult,
    InProcessRaftCluster, PairedRunOrder, RaftAppliedResponse, RaftStorageProfile,
    active_active_command, paired_run_order,
};
use clap::Parser;
use serde::Serialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-universal-writer-smoke",
    about = "Compare one trusted Blossom universal-writer epoch with concurrent OpenRaft clients"
)]
struct Args {
    #[arg(long, env = "BLOSSOM_QUORUM_SIZE", default_value = "6")]
    quorum_size: QuorumSize,
    #[arg(long, default_value_t = 6)]
    blossom_nodes: usize,
    /// Number of nodes that place a real command block in each Blossom epoch.
    #[arg(long)]
    active_writers: Option<usize>,
    #[arg(long, default_value_t = 5)]
    raft_voters: usize,
    #[arg(long)]
    raft_learners: Option<usize>,
    #[arg(long, env = "BLOSSOM_HOLDERS_PER_SITE")]
    holders_per_site: Option<usize>,
    #[arg(long, default_value_t = 3)]
    iterations: usize,
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    #[arg(long, default_value_t = 42)]
    seed: u64,
    #[arg(
        long,
        default_value = "benchmarks/results/universal-writer-smoke/result.json"
    )]
    output: PathBuf,
}

#[derive(Serialize)]
struct UniversalWriterArtifact {
    schema_version: u16,
    publishable: bool,
    not_publishable_reasons: Vec<&'static str>,
    blossom_quorum_size: usize,
    blossom_nodes: usize,
    active_writers: usize,
    blossom_holders_per_site: usize,
    blossom_holder_threshold_per_site: usize,
    raft_voters: usize,
    raft_learners: usize,
    iterations: usize,
    payload_bytes_per_writer: usize,
    logical_commands_per_iteration: usize,
    rows: Vec<UniversalWriterRow>,
}

#[derive(Serialize)]
struct UniversalWriterRow {
    iteration: usize,
    order: PairedRunOrder,
    blossom: BlossomUniversalWriterSample,
    raft_applied_nanos: u64,
    raft_results: Vec<RaftAppliedResponse>,
    exact_final_state_equal: bool,
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
    let holders_per_site = args.holders_per_site.unwrap_or(args.blossom_nodes / 3);
    let output_parent = args
        .output
        .parent()
        .ok_or("benchmark output must have a parent directory")?;
    fs::create_dir_all(output_parent)?;
    let run_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let storage_root = output_parent.join(format!("universal-writer-storage-{run_id}"));
    let mut blossom = BlossomActiveActiveCluster::start_with_holders_per_site(
        args.blossom_nodes,
        args.quorum_size,
        holders_per_site,
        storage_root.join("blossom"),
    )
    .await?;
    let mut raft = InProcessRaftCluster::start_with_storage(
        args.raft_voters,
        raft_learners,
        RaftStorageProfile::DurableShardStream {
            root: storage_root.join("openraft"),
        },
    )
    .await?;

    let mut rows = Vec::with_capacity(args.iterations);
    for iteration in 0..args.iterations {
        let workload = workload(iteration, active_writers, args.payload_bytes)?;
        let commands = workload
            .iter()
            .map(|entry| entry.command.clone())
            .collect::<Vec<_>>();
        let order = paired_run_order(args.seed, iteration);
        let (blossom_sample, raft_applied_nanos, raft_results) = match order {
            PairedRunOrder::BlossomThenRaft => {
                let blossom_sample = blossom.client_write_universal(commands.clone()).await?;
                let (nanos, results) = raft_write(&mut raft, commands).await?;
                (blossom_sample, nanos, results)
            }
            PairedRunOrder::RaftThenBlossom => {
                let (nanos, results) = raft_write(&mut raft, commands.clone()).await?;
                let blossom_sample = blossom.client_write_universal(commands).await?;
                (blossom_sample, nanos, results)
            }
        };
        if blossom_sample
            .results
            .iter()
            .any(|result| *result != CommandResult::Written)
            || raft_results.iter().any(|response| {
                response.application_error.is_some()
                    || response.result != Some(CommandResult::Written)
            })
        {
            return Err(
                format!("protocol application result diverged at iteration {iteration}").into(),
            );
        }
        for entry in &workload {
            let blossom_value = blossom.read_local(&entry.key)?;
            let raft_value = raft.read_linearizable(&entry.key).await?;
            if blossom_value.as_deref() != Some(entry.value.as_slice())
                || raft_value != blossom_value
            {
                return Err(format!(
                    "protocol final state diverged at iteration {iteration}, writer {}",
                    entry.writer
                )
                .into());
            }
        }
        rows.push(UniversalWriterRow {
            iteration,
            order,
            blossom: blossom_sample,
            raft_applied_nanos,
            raft_results,
            exact_final_state_equal: true,
        });
    }
    raft.shutdown().await;
    drop(blossom);

    let artifact = UniversalWriterArtifact {
        schema_version: 1,
        publishable: false,
        not_publishable_reasons: vec![
            "diagnostic uses native Blossom TCP and OpenRaft's in-process network",
            "diagnostic does not satisfy twelve paired repetitions",
            "diagnostic does not satisfy the five-minute steady-state window",
            "diagnostic does not satisfy 100,000 Applied samples per cell",
            "fault, recovery, and confidence-interval gates are not run by this command",
        ],
        blossom_quorum_size: args.quorum_size.get(),
        blossom_nodes: args.blossom_nodes,
        active_writers,
        blossom_holders_per_site: holders_per_site,
        blossom_holder_threshold_per_site: supermajority_count(holders_per_site),
        raft_voters: args.raft_voters,
        raft_learners,
        iterations: args.iterations,
        payload_bytes_per_writer: args.payload_bytes,
        logical_commands_per_iteration: active_writers,
        rows,
    };
    fs::write(&args.output, serde_json::to_vec_pretty(&artifact)?)?;
    if storage_root.exists() {
        fs::remove_dir_all(&storage_root)?;
    }
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
        client_id[8..].copy_from_slice(&0x626c6f73736f6d_u64.to_le_bytes());
        let key = format!("universal-key-{iteration}-{writer}").into_bytes();
        let mut value = vec![0u8; payload_bytes];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = sequence
                .wrapping_add(u64::try_from(writer)?)
                .wrapping_add(u64::try_from(index)?)
                .to_le_bytes()[0];
        }
        workload.push(WorkloadEntry {
            writer,
            command: active_active_command(
                CommandIdentity {
                    client_id: ClientId(client_id),
                    client_epoch: ClientEpoch(1),
                    sequence,
                },
                CommandOperation::BlindWrite {
                    key: key.clone(),
                    value: value.clone(),
                },
            )?,
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
