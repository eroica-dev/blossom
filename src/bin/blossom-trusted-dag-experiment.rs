#[cfg(feature = "trusted-checkpoint-dag")]
use std::fs;
#[cfg(feature = "trusted-checkpoint-dag")]
use std::path::PathBuf;

#[cfg(feature = "trusted-checkpoint-dag")]
use blossom::{QuorumSize, SequentialQuorumDagReport, run_sequential_quorum_dag_experiment};
#[cfg(feature = "trusted-checkpoint-dag")]
use clap::Parser;
#[cfg(feature = "trusted-checkpoint-dag")]
use serde::Serialize;

#[cfg(feature = "trusted-checkpoint-dag")]
#[derive(Debug, Parser)]
#[command(
    name = "blossom-trusted-dag-experiment",
    about = "Measure compact append-only DAG frontiers over Blossom's sequential quorum topology"
)]
struct Args {
    /// Comma-separated physical node counts.
    #[arg(long, value_delimiter = ',', default_value = "6,72,256,1000")]
    nodes: Vec<usize>,

    /// Blossom hierarchical quorum branching factor.
    #[arg(long, default_value_t = 6)]
    quorum_size: usize,

    /// Logical bytes referenced by every writer vertex.
    #[arg(long, default_value_t = 1024)]
    payload_bytes: usize,

    /// Deterministically shuffle topology slots from the checkpoint seed.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    shuffle: bool,

    /// Optional JSON artifact path. JSON is always printed to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[cfg(feature = "trusted-checkpoint-dag")]
#[derive(Debug, Serialize)]
struct ExperimentArtifact {
    schema: &'static str,
    profile: &'static str,
    ordering_contract: &'static str,
    payload_contract: &'static str,
    reports: Vec<SequentialQuorumDagReport>,
}

#[cfg(feature = "trusted-checkpoint-dag")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let quorum_size = QuorumSize::new(args.quorum_size)?;
    let reports = args
        .nodes
        .iter()
        .map(|nodes| {
            run_sequential_quorum_dag_experiment(
                *nodes,
                quorum_size,
                args.payload_bytes,
                args.shuffle,
            )
        })
        .collect::<blossom::Result<Vec<_>>>()?;
    let artifact = ExperimentArtifact {
        schema: "blossom/trusted-checkpoint-dag-experiment/v1",
        profile: "trusted-checkpoint-dag",
        ordering_contract: "immutable writer vertices; sequential hierarchical quorum frontiers; linear hash/nonce checkpoint",
        payload_contract: "all-node payload delivery remains a separately reported N-by-N lower bound",
        reports,
    };
    let encoded = serde_json::to_string_pretty(&artifact)?;
    if let Some(output) = args.output {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output, encoded.as_bytes())?;
    }
    println!("{encoded}");
    Ok(())
}

#[cfg(not(feature = "trusted-checkpoint-dag"))]
fn main() {
    eprintln!("blossom-trusted-dag-experiment requires --features trusted-checkpoint-dag");
    std::process::exit(2);
}
