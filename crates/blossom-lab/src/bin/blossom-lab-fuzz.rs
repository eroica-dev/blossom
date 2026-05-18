use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

use blossom::BlossomError;
use blossom_lab::{DataPattern, FuzzConfig, FuzzReport, LabCluster, NetworkChaosConfig};
use clap::Parser;

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-lab-fuzz",
    about = "Deterministically fuzz Blossom node TCP I/O with valid and malformed frames"
)]
struct Args {
    #[arg(long, default_value_t = 1)]
    nodes: usize,
    #[arg(long, default_value_t = 256)]
    cases: usize,
    #[arg(long, default_value_t = 4096)]
    max_payload_bytes: usize,
    #[arg(long, default_value_t = DataPattern::SplitMix)]
    data_pattern: DataPattern,
    #[arg(long, default_value_t = true)]
    include_valid: bool,
    #[arg(long, default_value_t = 100)]
    read_timeout_ms: u64,
    #[arg(long, default_value_t = 0x6675_7a7a_5f62_6c31)]
    seed: u64,
    #[arg(long, default_value_t = false)]
    expect_alive: bool,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    append: bool,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    if args.nodes == 0 {
        return Err(BlossomError::WireProtocol(
            "fuzz benchmark requires at least one node".to_string(),
        )
        .into());
    }

    let cluster = LabCluster::spawn(args.nodes, NetworkChaosConfig::default()).await?;
    let config = FuzzConfig {
        seed: args.seed,
        cases: args.cases,
        max_payload_bytes: args.max_payload_bytes,
        payload_pattern: args.data_pattern,
        include_valid: args.include_valid,
        read_timeout_ms: args.read_timeout_ms,
    };
    let report = blossom_lab::run_node_io_fuzz(&cluster, &config).await?;
    if args.expect_alive && !report.node_health_ok {
        return Err(
            BlossomError::WireProtocol("node health check failed after fuzz".to_string()).into(),
        );
    }

    println!("{}", to_csv(&args, &report));
    if let Some(path) = args.csv.as_ref() {
        write_csv(path, args.append, &args, &report)?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

fn write_csv(path: &PathBuf, append: bool, args: &Args, report: &FuzzReport) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let write_header = !append || !path.exists() || path.metadata()?.len() == 0;
    let mut file = OpenOptions::new()
        .create(true)
        .append(append)
        .write(true)
        .truncate(!append)
        .open(path)?;

    if write_header {
        writeln!(
            file,
            "nodes,cases,max_payload_bytes,data_pattern,include_valid,read_timeout_ms,seed,valid_cases,malformed_cases,accepted,rejected,io_errors,timeouts,node_health_ok,bytes_sent"
        )?;
    }
    writeln!(file, "{}", to_csv(args, report))?;
    Ok(())
}

fn to_csv(args: &Args, report: &FuzzReport) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        args.nodes,
        report.cases,
        args.max_payload_bytes,
        args.data_pattern,
        args.include_valid,
        args.read_timeout_ms,
        args.seed,
        report.valid_cases,
        report.malformed_cases,
        report.accepted,
        report.rejected,
        report.io_errors,
        report.timeouts,
        report.node_health_ok,
        report.bytes_sent,
    )
}
