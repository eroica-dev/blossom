use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use blossom::{BlossomError, NodePing, TrustMode, WireRequest, WireResponse};
use blossom_lab::{DataPattern, DeterministicData, LabCluster, NetworkChaosConfig};
use clap::Parser;

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-lab-chaos",
    about = "Benchmark Blossom TCP behavior in the lab crate with deterministic fault injection"
)]
struct Args {
    #[arg(long, default_value_t = 6)]
    nodes: usize,
    #[arg(long, default_value_t = 1000)]
    requests: usize,
    #[arg(long, default_value_t = 0)]
    payload_bytes: usize,
    #[arg(long, default_value_t = DataPattern::SplitMix)]
    data_pattern: DataPattern,
    #[arg(long, default_value_t = 1)]
    iterations: usize,
    #[arg(long, default_value_t = 0)]
    warmup: usize,
    #[arg(long, default_value_t = 0)]
    latency_ms: u64,
    #[arg(long, default_value_t = 0)]
    jitter_ms: u64,
    #[arg(long, default_value_t = 0)]
    drop_ppm: u32,
    #[arg(long, default_value_t = 0)]
    connect_crash_ppm: u32,
    #[arg(long, default_value_t = 0)]
    response_crash_ppm: u32,
    #[arg(long, default_value_t = 0x626c_6f73_736f_6d31)]
    seed: u64,
    #[arg(long, default_value_t = false)]
    trusted: bool,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    append: bool,
}

#[derive(Debug, Clone)]
struct ChaosBenchRow {
    iteration: usize,
    nodes: usize,
    requests: usize,
    payload_bytes: usize,
    data_pattern: DataPattern,
    latency_ms: u64,
    jitter_ms: u64,
    drop_ppm: u32,
    connect_crash_ppm: u32,
    response_crash_ppm: u32,
    seed: u64,
    trusted: bool,
    successes: usize,
    failures: usize,
    attempts: u64,
    dropped: u64,
    connect_crashes: u64,
    response_crashes: u64,
    injected_delay_ms: u64,
    total_us: u128,
    avg_request_us: u128,
    min_request_us: u128,
    max_request_us: u128,
}

#[derive(Debug, Clone)]
struct IterationConfig {
    nodes: usize,
    requests: usize,
    payload_bytes: usize,
    data_pattern: DataPattern,
    trusted: bool,
    chaos: NetworkChaosConfig,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let config = IterationConfig {
        nodes: args.nodes,
        requests: args.requests,
        payload_bytes: args.payload_bytes,
        data_pattern: args.data_pattern,
        trusted: args.trusted,
        chaos: NetworkChaosConfig {
            seed: args.seed,
            latency_ms: args.latency_ms,
            jitter_ms: args.jitter_ms,
            drop_ppm: args.drop_ppm,
            connect_crash_ppm: args.connect_crash_ppm,
            response_crash_ppm: args.response_crash_ppm,
        },
    };

    for _ in 0..args.warmup {
        run_iteration(0, config.clone()).await?;
    }

    let mut rows = Vec::with_capacity(args.iterations);
    for iteration in 0..args.iterations {
        let row = run_iteration(iteration, config.clone()).await?;
        println!("{}", row.to_csv());
        rows.push(row);
    }

    if let Some(path) = args.csv {
        write_csv(&path, args.append, &rows)?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

async fn run_iteration(iteration: usize, config: IterationConfig) -> MainResult<ChaosBenchRow> {
    if config.nodes == 0 {
        return Err(BlossomError::WireProtocol(
            "chaos benchmark requires at least one node".to_string(),
        )
        .into());
    }

    let cluster = LabCluster::spawn_with_trust_mode(
        config.nodes,
        if config.trusted {
            TrustMode::Trusted
        } else {
            TrustMode::Verified
        },
        config.chaos.clone(),
    )
    .await?;

    let total_start = Instant::now();
    let data = DeterministicData::new(config.chaos.seed, config.data_pattern);
    let mut successes = 0usize;
    let mut failures = 0usize;
    let mut total_request_us = 0u128;
    let mut min_request_us = u128::MAX;
    let mut max_request_us = 0u128;

    for request_index in 0..config.requests {
        let target = request_index % config.nodes;
        let started = Instant::now();
        let response = cluster
            .request(
                target,
                WireRequest::Ping(NodePing::with_payload(
                    request_index as u64,
                    data.bytes(config.payload_bytes, target as u64, request_index as u64),
                )),
            )
            .await;
        let elapsed_us = started.elapsed().as_micros();
        total_request_us += elapsed_us;
        min_request_us = min_request_us.min(elapsed_us);
        max_request_us = max_request_us.max(elapsed_us);

        match response {
            Ok(WireResponse::Pong(pong)) if pong.nonce == request_index as u64 => {
                successes += 1;
            }
            Ok(response) => {
                failures += 1;
                eprintln!(
                    "iteration {iteration} request {request_index}: unexpected response {}",
                    response.kind()
                );
            }
            Err(_) => {
                failures += 1;
            }
        }
    }

    let report = cluster.network_report();
    let avg_request_us = if config.requests == 0 {
        0
    } else {
        total_request_us / config.requests as u128
    };

    Ok(ChaosBenchRow {
        iteration,
        nodes: config.nodes,
        requests: config.requests,
        payload_bytes: config.payload_bytes,
        data_pattern: config.data_pattern,
        latency_ms: config.chaos.latency_ms,
        jitter_ms: config.chaos.jitter_ms,
        drop_ppm: config.chaos.drop_ppm,
        connect_crash_ppm: config.chaos.connect_crash_ppm,
        response_crash_ppm: config.chaos.response_crash_ppm,
        seed: config.chaos.seed,
        trusted: config.trusted,
        successes,
        failures,
        attempts: report.attempts,
        dropped: report.dropped,
        connect_crashes: report.connect_crashes,
        response_crashes: report.response_crashes,
        injected_delay_ms: report.injected_delay_ms,
        total_us: total_start.elapsed().as_micros(),
        avg_request_us,
        min_request_us: if min_request_us == u128::MAX {
            0
        } else {
            min_request_us
        },
        max_request_us,
    })
}

fn write_csv(path: &PathBuf, append: bool, rows: &[ChaosBenchRow]) -> MainResult<()> {
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
            "iteration,nodes,requests,payload_bytes,data_pattern,latency_ms,jitter_ms,drop_ppm,connect_crash_ppm,response_crash_ppm,seed,trusted,successes,failures,attempts,dropped,connect_crashes,response_crashes,injected_delay_ms,total_us,avg_request_us,min_request_us,max_request_us"
        )?;
    }
    for row in rows {
        writeln!(file, "{}", row.to_csv())?;
    }
    Ok(())
}

impl ChaosBenchRow {
    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.iteration,
            self.nodes,
            self.requests,
            self.payload_bytes,
            self.data_pattern,
            self.latency_ms,
            self.jitter_ms,
            self.drop_ppm,
            self.connect_crash_ppm,
            self.response_crash_ppm,
            self.seed,
            self.trusted,
            self.successes,
            self.failures,
            self.attempts,
            self.dropped,
            self.connect_crashes,
            self.response_crashes,
            self.injected_delay_ms,
            self.total_us,
            self.avg_request_us,
            self.min_request_us,
            self.max_request_us,
        )
    }
}
