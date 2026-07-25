use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use blossom::{
    ActiveActiveCommand, ClientEpoch, ClientId, CommandIdentity, CommandOperation, CommandResult,
    QuorumSize, supermajority_count,
};
use blossom_bench_harness::{
    BlossomActiveActiveCluster, BlossomAppliedSample, InProcessRaftCluster, PairedRunOrder,
    RaftStorageProfile, paired_run_order,
};
use clap::Parser;
use serde::Serialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-benchmark-smoke",
    about = "Exercise Blossom and OpenRaft through Applied without publishing a performance claim"
)]
struct Args {
    #[arg(long, env = "BLOSSOM_QUORUM_SIZE", default_value = "6")]
    quorum_size: QuorumSize,
    #[arg(long, default_value_t = 6)]
    blossom_nodes: usize,
    #[arg(long, default_value_t = 5)]
    raft_voters: usize,
    #[arg(long)]
    raft_learners: Option<usize>,
    /// Durable data holders selected in each of the three sites.
    ///
    /// Defaults to every validator in the site for the equal-footprint
    /// baseline. Set this explicitly to model a fixed holder committee.
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
        default_value = "benchmarks/results/active-active-smoke/result.json"
    )]
    output: PathBuf,
}

#[derive(Serialize)]
struct SmokeArtifact {
    schema_version: u16,
    publishable: bool,
    not_publishable_reasons: Vec<&'static str>,
    blossom_quorum_size: usize,
    blossom_nodes: usize,
    blossom_holders_per_site: usize,
    blossom_holder_threshold_per_site: usize,
    blossom_holder_liveness_fault_bound_per_site: usize,
    blossom_certified_sites_required: usize,
    raft_voters: usize,
    raft_learners: usize,
    iterations: usize,
    payload_bytes: usize,
    rows: Vec<SmokeRow>,
}

#[derive(Serialize)]
struct SmokeRow {
    iteration: usize,
    order: PairedRunOrder,
    blossom: BlossomAppliedSample,
    raft_applied_nanos: u64,
    raft_result: Option<CommandResult>,
    exact_result_equal: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    if args.iterations == 0 || args.payload_bytes == 0 {
        return Err("iterations and payload bytes must be non-zero".into());
    }
    if args.blossom_nodes < 3 || args.blossom_nodes % 3 != 0 {
        return Err("Blossom nodes must form three equal non-empty sites".into());
    }
    let raft_learners = args
        .raft_learners
        .unwrap_or_else(|| args.blossom_nodes.saturating_sub(args.raft_voters));
    let holders_per_site = args.holders_per_site.unwrap_or(args.blossom_nodes / 3);
    let holder_threshold_per_site = supermajority_count(holders_per_site);
    let output_parent = args
        .output
        .parent()
        .ok_or("smoke output must have a parent directory")?;
    fs::create_dir_all(output_parent)?;
    let run_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let storage_root = output_parent.join(format!("storage-{run_id}"));
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
        RaftStorageProfile::DurableRedbImmediate {
            root: storage_root.join("openraft"),
        },
    )
    .await?;

    let mut rows = Vec::with_capacity(args.iterations);
    for iteration in 0..args.iterations {
        let command = command(iteration, args.payload_bytes)?;
        let order = paired_run_order(args.seed, iteration);
        let (blossom_sample, raft_nanos, raft_result) = match order {
            PairedRunOrder::BlossomThenRaft => {
                let blossom_sample = blossom.client_write(command.clone()).await?;
                let (raft_nanos, raft_result) = raft_write(&mut raft, command).await?;
                (blossom_sample, raft_nanos, raft_result)
            }
            PairedRunOrder::RaftThenBlossom => {
                let (raft_nanos, raft_result) = raft_write(&mut raft, command.clone()).await?;
                let blossom_sample = blossom.client_write(command).await?;
                (blossom_sample, raft_nanos, raft_result)
            }
        };
        let exact_result_equal = raft_result.as_ref() == Some(&blossom_sample.result);
        if !exact_result_equal {
            return Err(format!("protocol results diverged at iteration {iteration}").into());
        }
        rows.push(SmokeRow {
            iteration,
            order,
            blossom: blossom_sample,
            raft_applied_nanos: raft_nanos,
            raft_result,
            exact_result_equal,
        });
    }
    raft.shutdown().await;

    let artifact = SmokeArtifact {
        schema_version: 2,
        publishable: false,
        not_publishable_reasons: vec![
            "smoke run uses native Blossom TCP and OpenRaft's in-process network",
            "smoke run does not satisfy twelve paired repetitions",
            "smoke run does not satisfy the five-minute steady-state window",
            "smoke run does not satisfy 100,000 Applied samples per cell",
            "fault, recovery, and confidence-interval gates are not run by this command",
        ],
        blossom_quorum_size: args.quorum_size.get(),
        blossom_nodes: args.blossom_nodes,
        blossom_holders_per_site: holders_per_site,
        blossom_holder_threshold_per_site: holder_threshold_per_site,
        blossom_holder_liveness_fault_bound_per_site: holders_per_site
            .saturating_sub(holder_threshold_per_site),
        blossom_certified_sites_required: 2,
        raft_voters: args.raft_voters,
        raft_learners,
        iterations: args.iterations,
        payload_bytes: args.payload_bytes,
        rows,
    };
    fs::write(&args.output, serde_json::to_vec_pretty(&artifact)?)?;
    println!("{}", args.output.display());
    Ok(())
}

fn command(iteration: usize, payload_bytes: usize) -> Result<ActiveActiveCommand, BoxError> {
    let sequence = u64::try_from(iteration)?
        .checked_add(1)
        .ok_or("command sequence overflow")?;
    let mut value = vec![0u8; payload_bytes];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = (sequence.wrapping_add(index as u64) & 0xff) as u8;
    }
    Ok(ActiveActiveCommand {
        identity: CommandIdentity {
            client_id: ClientId([0x5a; 16]),
            client_epoch: ClientEpoch(1),
            sequence,
        },
        operation: CommandOperation::BlindWrite {
            key: format!("smoke-key-{iteration}").into_bytes(),
            value,
        },
    })
}

async fn raft_write(
    raft: &mut InProcessRaftCluster,
    command: ActiveActiveCommand,
) -> Result<(u64, Option<CommandResult>), BoxError> {
    let started = Instant::now();
    let response = raft.client_write(command).await?;
    if let Some(error) = response.data.application_error {
        return Err(format!("OpenRaft state-machine application failed: {error}").into());
    }
    Ok((
        u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        response.data.result,
    ))
}
