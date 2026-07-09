use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use blossom::{
    BlossomError, NodePing, TcpNodeMetricsSnapshot, TrustMode, WireRequest, WireResponse,
};
use blossom_sim::{
    DataPattern, DeterministicData, NetworkChaos, NetworkChaosConfig, SimTcpCluster,
};
use clap::Parser;
use tokio::task::JoinSet;

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-sim-chaos",
    about = "Benchmark Blossom TCP behavior in the simulation crate with deterministic fault injection"
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
    #[arg(long, default_value_t = 1)]
    concurrency: usize,
    #[arg(long, default_value_t = 0)]
    cpu_cores: usize,
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
    node_perf_csv: Option<PathBuf>,
    #[arg(long)]
    append: bool,
}

#[derive(Debug, Clone)]
struct ChaosBenchRow {
    iteration: usize,
    nodes: usize,
    requests: usize,
    concurrency: usize,
    cpu_cores: usize,
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
    requests_per_second: f64,
    payload_mib_per_second: f64,
}

#[derive(Debug, Clone)]
struct IterationConfig {
    nodes: usize,
    requests: usize,
    concurrency: usize,
    cpu_cores: usize,
    payload_bytes: usize,
    data_pattern: DataPattern,
    trusted: bool,
    chaos: NetworkChaosConfig,
}

#[derive(Debug, Clone)]
struct ChaosBenchIteration {
    row: ChaosBenchRow,
    node_rows: Vec<NodePerfBenchRow>,
}

#[derive(Debug, Clone)]
struct NodePerfBenchRow {
    iteration: usize,
    node: usize,
    connections: u64,
    requests: u64,
    responses: u64,
    errors: u64,
    handler_nanos: u64,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    if args.concurrency == 0 {
        return Err(BlossomError::WireProtocol(
            "chaos benchmark concurrency must be at least one".to_string(),
        )
        .into());
    }
    let config = IterationConfig {
        nodes: args.nodes,
        requests: args.requests,
        concurrency: args.concurrency,
        cpu_cores: args.cpu_cores,
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
    let mut node_rows = Vec::with_capacity(args.iterations.saturating_mul(args.nodes));
    for iteration in 0..args.iterations {
        let iteration = run_iteration(iteration, config.clone()).await?;
        println!("{}", iteration.row.to_csv());
        node_rows.extend(iteration.node_rows);
        rows.push(iteration.row);
    }

    if let Some(path) = args.csv {
        write_csv(&path, args.append, &rows)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = args.node_perf_csv {
        write_node_perf_csv(&path, args.append, &node_rows)?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

async fn run_iteration(
    iteration: usize,
    config: IterationConfig,
) -> MainResult<ChaosBenchIteration> {
    if config.nodes == 0 {
        return Err(BlossomError::WireProtocol(
            "chaos benchmark requires at least one node".to_string(),
        )
        .into());
    }

    let cluster = SimTcpCluster::spawn_with_trust_mode(
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
    let network = cluster.network().clone();
    let addrs = cluster
        .nodes()
        .iter()
        .map(|node| node.addr())
        .collect::<Vec<_>>();
    let mut join_set = JoinSet::new();
    let mut next_request = 0usize;
    let mut successes = 0usize;
    let mut failures = 0usize;
    let mut total_request_us = 0u128;
    let mut min_request_us = u128::MAX;
    let mut max_request_us = 0u128;

    while next_request < config.requests || !join_set.is_empty() {
        while next_request < config.requests && join_set.len() < config.concurrency {
            let request_index = next_request;
            let target = request_index % config.nodes;
            let payload = data.bytes(config.payload_bytes, target as u64, request_index as u64);
            let addr = addrs[target].clone();
            let network = network.clone();
            join_set.spawn(async move {
                run_request(network, target, request_index, addr, payload).await
            });
            next_request += 1;
        }

        match join_set.join_next().await {
            Some(Ok(result)) => {
                total_request_us += result.elapsed_us;
                min_request_us = min_request_us.min(result.elapsed_us);
                max_request_us = max_request_us.max(result.elapsed_us);
                match result.outcome {
                    RequestOutcome::Success => {
                        successes += 1;
                    }
                    RequestOutcome::Unexpected(response_kind) => {
                        failures += 1;
                        eprintln!(
                            "iteration {iteration} request {}: unexpected response {response_kind}",
                            result.request_index
                        );
                    }
                    RequestOutcome::Error => {
                        failures += 1;
                    }
                }
            }
            Some(Err(err)) => {
                failures += 1;
                eprintln!("iteration {iteration}: request task failed: {err}");
            }
            None => {}
        }
    }

    let report = cluster.network_report();
    let total_us = total_start.elapsed().as_micros();
    let avg_request_us = if config.requests == 0 {
        0
    } else {
        total_request_us / config.requests as u128
    };
    let total_seconds = total_us as f64 / 1_000_000.0;
    let requests_per_second = match total_seconds > 0.0 {
        true => successes as f64 / total_seconds,
        false => 0.0,
    };
    let payload_mib_per_second = match total_seconds > 0.0 {
        true => (successes * config.payload_bytes) as f64 / (1024.0 * 1024.0) / total_seconds,
        false => 0.0,
    };

    let node_rows = cluster
        .node_metrics()
        .into_iter()
        .enumerate()
        .map(|(node, metrics)| NodePerfBenchRow::from_snapshot(iteration, node, metrics))
        .collect();
    let row = ChaosBenchRow {
        iteration,
        nodes: config.nodes,
        requests: config.requests,
        concurrency: config.concurrency,
        cpu_cores: config.cpu_cores,
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
        total_us,
        avg_request_us,
        min_request_us: if min_request_us == u128::MAX {
            0
        } else {
            min_request_us
        },
        max_request_us,
        requests_per_second,
        payload_mib_per_second,
    };

    Ok(ChaosBenchIteration { row, node_rows })
}

#[derive(Debug)]
struct RequestBenchResult {
    request_index: usize,
    elapsed_us: u128,
    outcome: RequestOutcome,
}

#[derive(Debug)]
enum RequestOutcome {
    Success,
    Unexpected(&'static str),
    Error,
}

async fn run_request(
    network: NetworkChaos,
    target: usize,
    request_index: usize,
    addr: String,
    payload: Vec<u8>,
) -> RequestBenchResult {
    let started = Instant::now();
    let request = WireRequest::Ping(NodePing::with_payload(request_index as u64, payload));
    let response = network
        .request_with_ordinal(target, request_index as u64 + 1, addr, &request)
        .await;
    let elapsed_us = started.elapsed().as_micros();
    let outcome = match response {
        Ok(WireResponse::Pong(pong)) if pong.nonce == request_index as u64 => {
            RequestOutcome::Success
        }
        Ok(response) => RequestOutcome::Unexpected(response.kind()),
        Err(_) => RequestOutcome::Error,
    };
    RequestBenchResult {
        request_index,
        elapsed_us,
        outcome,
    }
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
            "iteration,nodes,requests,concurrency,cpu_cores,payload_bytes,data_pattern,latency_ms,jitter_ms,drop_ppm,connect_crash_ppm,response_crash_ppm,seed,trusted,successes,failures,attempts,dropped,connect_crashes,response_crashes,injected_delay_ms,total_us,avg_request_us,min_request_us,max_request_us,requests_per_second,payload_mib_per_second"
        )?;
    }
    for row in rows {
        writeln!(file, "{}", row.to_csv())?;
    }
    Ok(())
}

fn write_node_perf_csv(path: &PathBuf, append: bool, rows: &[NodePerfBenchRow]) -> MainResult<()> {
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
            "iteration,node,connections,requests,responses,errors,handler_nanos,handler_nanos_per_request"
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
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.3},{:.3}",
            self.iteration,
            self.nodes,
            self.requests,
            self.concurrency,
            self.cpu_cores,
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
            self.requests_per_second,
            self.payload_mib_per_second,
        )
    }
}

impl NodePerfBenchRow {
    fn from_snapshot(
        iteration: usize,
        node: usize,
        snapshot: TcpNodeMetricsSnapshot,
    ) -> NodePerfBenchRow {
        NodePerfBenchRow {
            iteration,
            node,
            connections: snapshot.connections,
            requests: snapshot.requests,
            responses: snapshot.responses,
            errors: snapshot.errors,
            handler_nanos: snapshot.handler_nanos,
        }
    }

    fn to_csv(&self) -> String {
        let nanos_per_request = match self.requests {
            0 => 0,
            requests => self.handler_nanos / requests,
        };
        format!(
            "{},{},{},{},{},{},{},{}",
            self.iteration,
            self.node,
            self.connections,
            self.requests,
            self.responses,
            self.errors,
            self.handler_nanos,
            nanos_per_request,
        )
    }
}
