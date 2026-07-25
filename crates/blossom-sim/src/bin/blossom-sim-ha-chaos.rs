use std::fs;
use std::path::PathBuf;

use blossom_sim::{HaChaosConfig, HaChaosReport, run_ha_chaos_campaign};
use clap::Parser;
use serde::Serialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Parser)]
#[command(
    name = "blossom-sim-ha-chaos",
    about = "Run deterministic 2-7 node Blossom HA production-readiness fault campaigns"
)]
struct Args {
    #[arg(long, default_value_t = 1_200)]
    epochs: usize,
    #[arg(long, default_value_t = 0x6861_5f63_6861_6f73)]
    seed: u64,
    #[arg(long, default_value_t = 200_000)]
    drop_ppm: u32,
    #[arg(long, default_value_t = 100_000)]
    duplicate_ppm: u32,
    #[arg(
        long,
        default_value = "benchmarks/results/ha-fault-tolerance/report.json"
    )]
    output: PathBuf,
}

#[derive(Serialize)]
struct CampaignArtifact {
    schema_version: u16,
    production_gate_passed: bool,
    reports: Vec<HaChaosReport>,
}

fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let mut reports = Vec::with_capacity(6);
    for nodes in 2..=7 {
        let report = run_ha_chaos_campaign(HaChaosConfig {
            nodes,
            epochs: args.epochs,
            seed: args.seed ^ nodes as u64,
            drop_ppm: args.drop_ppm,
            duplicate_ppm: args.duplicate_ppm,
            ..HaChaosConfig::default()
        })?;
        if report.unexpected_stalls != 0 || !report.safety_violations.is_empty() {
            return Err(format!("HA fault campaign failed for {nodes} nodes").into());
        }
        reports.push(report);
    }
    let artifact = CampaignArtifact {
        schema_version: 1,
        production_gate_passed: true,
        reports,
    };
    if let Some(parent) = args.output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&args.output, serde_json::to_vec_pretty(&artifact)?)?;
    println!("{}", args.output.display());
    Ok(())
}
