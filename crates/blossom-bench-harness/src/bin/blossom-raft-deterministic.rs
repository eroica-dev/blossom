use std::fs;
use std::path::PathBuf;

use blossom_bench_harness::{
    RaftDeterministicFault, RaftDeterministicReport, run_raft_deterministic_campaign,
};
use clap::Parser;
use serde::Serialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Parser)]
#[command(
    name = "blossom-raft-deterministic",
    about = "Run deterministic active-passive OpenRaft control campaigns"
)]
struct Args {
    #[arg(long, default_value_t = 50)]
    commands: u64,
    #[arg(long, default_value_t = 0x7261_6674_5f64_7374)]
    seed: u64,
    #[arg(long, default_value = "target/deterministic-sandbox/raft/report.json")]
    output: PathBuf,
}

#[derive(Debug, Serialize)]
struct Artifact {
    schema_version: u16,
    safety_passed: bool,
    reports: Vec<RaftDeterministicReport>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let faults = [
        RaftDeterministicFault::None,
        RaftDeterministicFault::FollowerPause,
        RaftDeterministicFault::LeaderPause,
        RaftDeterministicFault::AsymmetricFollowerPartition,
        RaftDeterministicFault::QuorumLossPartition,
        RaftDeterministicFault::NetworkDelay,
        RaftDeterministicFault::ResponseLossAfterCommit,
        RaftDeterministicFault::RepeatedLeaderChurn,
        RaftDeterministicFault::DurableFollowerRestart,
        RaftDeterministicFault::DurableLeaderRestart,
    ];
    let mut reports = Vec::new();
    for physical_nodes in 2..=7 {
        for durable in [false, true] {
            for fault in faults {
                if !durable
                    && matches!(
                        fault,
                        RaftDeterministicFault::DurableFollowerRestart
                            | RaftDeterministicFault::DurableLeaderRestart
                    )
                {
                    continue;
                }
                reports.push(
                    run_raft_deterministic_campaign(
                        physical_nodes,
                        args.commands,
                        args.seed ^ physical_nodes as u64 ^ ((fault as u64) << 32),
                        durable,
                        fault,
                    )
                    .await?,
                );
            }
        }
    }
    let safety_passed = reports.iter().all(|report| {
        report.all_nodes_converged
            && report.linearizable_read_passed
            && report.history_linearizable
            && report.ambiguous_outcomes_resolved
    });
    let artifact = Artifact {
        schema_version: 1,
        safety_passed,
        reports,
    };
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.output, serde_json::to_vec_pretty(&artifact)?)?;
    println!("{}", args.output.display());
    if !safety_passed {
        return Err("deterministic OpenRaft campaign failed".into());
    }
    Ok(())
}
