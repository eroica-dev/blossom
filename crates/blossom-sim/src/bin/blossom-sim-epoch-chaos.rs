use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use blossom::{
    InMemoryTelemetrySink, JsonlTcpTelemetrySink, TelemetryHandle, TelemetrySink, TrustMode,
    algorithm::supermajority_count,
};
use blossom_sim::{
    EpochChaosConfig, EpochChaosReport, EpochStageProgressRecord, run_epoch_chaos,
    run_epoch_chaos_with_telemetry,
};
use clap::Parser;

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-sim-epoch-chaos",
    about = "Run deterministic Blossom epoch convergence under TCP-like jitter, delay spikes, drops, and fuzz"
)]
struct Args {
    #[arg(long, default_value_t = 36)]
    nodes: usize,
    #[arg(long, default_value_t = 4)]
    epochs: usize,
    #[arg(long, default_value_t = 16)]
    transactions_per_node: usize,
    #[arg(long, default_value_t = 32)]
    transaction_bytes: usize,
    #[arg(long, default_value_t = 1)]
    latency_ms: u64,
    #[arg(long, default_value_t = 0)]
    jitter_ms: u64,
    #[arg(long, default_value_t = 0)]
    round_timeout_ms: u64,
    #[arg(long, default_value_t = 0)]
    drop_ppm: u32,
    #[arg(long, default_value_t = 0)]
    fuzz_ppm: u32,
    #[arg(long, default_value_t = 0)]
    spike_ppm: u32,
    #[arg(long, default_value_t = 0)]
    spike_latency_ms: u64,
    #[arg(long, default_value_t = 0)]
    repair_rounds: usize,
    #[arg(long, default_value_t = 0)]
    repair_fanout: usize,
    #[arg(long, default_value_t = 0)]
    repair_quorum: usize,
    #[arg(long, default_value_t = 500)]
    repair_timeout_ms: u64,
    #[arg(long, default_value_t = 0)]
    faulty_nodes: usize,
    #[arg(long, default_value_t = 0)]
    byzantine_nodes: usize,
    #[arg(long, default_value_t = 0)]
    byzantine_reconnect_replay_ppm: u32,
    #[arg(long, default_value_t = 0)]
    byzantine_reconnect_stale_proof_ppm: u32,
    #[arg(long, default_value_t = 0)]
    byzantine_reconnect_sybil_ppm: u32,
    #[arg(long, default_value_t = 0)]
    byzantine_duplicate_vote_copies: usize,
    #[arg(long, default_value_t = 1)]
    drop_faulty_after_epochs: usize,
    #[arg(long, default_value_t = 1)]
    max_dropped_nodes_per_epoch: usize,
    #[arg(long, default_value_t = 1)]
    min_active_nodes: usize,
    #[arg(long, default_value_t = 0)]
    reconnect_dropped_after_epochs: usize,
    #[arg(long, default_value_t = 0)]
    reconnect_ping_fanout: usize,
    #[arg(long, default_value_t = 0)]
    reconnect_ping_quorum: usize,
    #[arg(long, default_value_t = 0)]
    reconnect_approval_quorum: usize,
    #[arg(long, default_value_t = 500)]
    reconnect_timeout_ms: u64,
    #[arg(long, default_value_t = 1)]
    max_reconnected_nodes_per_epoch: usize,
    #[arg(long)]
    partition_start_epoch: Option<usize>,
    #[arg(long)]
    partition_end_epoch: Option<usize>,
    #[arg(long, default_value_t = 0)]
    partition_left_nodes: usize,
    #[arg(long, default_value_t = false)]
    partition_reconnect_only: bool,
    #[arg(long)]
    assist_after_skipped_round: Option<usize>,
    #[arg(long, default_value_t = 0x6570_6f63_685f_6368)]
    seed: u64,
    #[arg(long, default_value_t = false)]
    trusted: bool,
    #[arg(long, default_value_t = false)]
    shuffle: bool,
    #[arg(long, default_value_t = false)]
    require_reconciliation: bool,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    epoch_log: Option<PathBuf>,
    #[arg(long)]
    stage_log: Option<PathBuf>,
    #[arg(long)]
    bug_log: Option<PathBuf>,
    #[arg(long)]
    observer_addr: Option<String>,
    #[arg(long, default_value_t = false)]
    measure_telemetry_cost: bool,
    #[arg(long, default_value_t = 3)]
    telemetry_cost_runs: usize,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let config = config_from_args(&args);
    let (report, telemetry_cost) = if args.measure_telemetry_cost {
        let (report, cost) = measure_telemetry_cost(&args, config)?;
        (report, Some(cost))
    } else {
        (run_epoch_chaos_once(&args, config)?, None)
    };
    println!("{}", summary_csv(&report));
    if let Some(cost) = telemetry_cost.as_ref() {
        eprintln!("{}", cost.summary_line());
    }

    if let Some(path) = args.csv.as_ref() {
        write_summary_csv(path, &report)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = args.epoch_log.as_ref() {
        write_epoch_csv(path, &report)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = args.stage_log.as_ref() {
        write_stage_csv(path, &report)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = args.bug_log.as_ref() {
        write_bug_log(path, &args, &report)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(addr) = args.observer_addr.as_ref() {
        eprintln!("streamed runtime telemetry to {addr}");
    }
    if args.require_reconciliation {
        let check = report.check_runtime_reconciliation()?;
        eprintln!(
            "runtime reconciliation check passed: divergent_epochs={}, reconciliation_epochs={}, reconciled_nodes={}, final_active_nodes={}, final_dropped_nodes={}, final_correct_nodes={}, final_unique_epoch_hashes={}",
            check.divergent_epochs,
            check.reconciliation_epochs,
            check.reconciled_nodes,
            check.final_active_nodes,
            check.final_dropped_nodes,
            check.final_correct_nodes,
            check.final_unique_epoch_hashes
        );
    }

    Ok(())
}

fn run_epoch_chaos_once(args: &Args, config: EpochChaosConfig) -> MainResult<EpochChaosReport> {
    match args.observer_addr.as_ref() {
        Some(addr) => {
            let sink = JsonlTcpTelemetrySink::connect(addr)?;
            Ok(run_epoch_chaos_with_telemetry(
                config,
                TelemetryHandle::new(Arc::new(sink)),
            )?)
        }
        None => Ok(run_epoch_chaos(config)?),
    }
}

#[derive(Debug)]
struct TelemetryCostReport {
    runs: usize,
    sink: &'static str,
    baseline_total: Duration,
    telemetry_total: Duration,
    telemetry_events: u64,
}

impl TelemetryCostReport {
    fn summary_line(&self) -> String {
        let baseline_avg = duration_micros_per_run(self.baseline_total, self.runs);
        let telemetry_avg = duration_micros_per_run(self.telemetry_total, self.runs);
        let overhead_avg = telemetry_avg.saturating_sub(baseline_avg);
        let overhead_pct = if baseline_avg == 0 {
            0.0
        } else {
            (overhead_avg as f64 / baseline_avg as f64) * 100.0
        };
        let events_per_run = self.telemetry_events / self.runs as u64;
        format!(
            "telemetry cost: runs={}, sink={}, baseline_avg_ms={:.3}, telemetry_avg_ms={:.3}, overhead_avg_ms={:.3}, overhead_pct={:.2}, telemetry_events_per_run={}",
            self.runs,
            self.sink,
            micros_to_millis(baseline_avg),
            micros_to_millis(telemetry_avg),
            micros_to_millis(overhead_avg),
            overhead_pct,
            events_per_run,
        )
    }
}

fn measure_telemetry_cost(
    args: &Args,
    config: EpochChaosConfig,
) -> MainResult<(EpochChaosReport, TelemetryCostReport)> {
    if args.telemetry_cost_runs == 0 {
        return Err("telemetry_cost_runs must be greater than zero".into());
    }

    let mut baseline_total = Duration::ZERO;
    let mut telemetry_total = Duration::ZERO;
    let mut baseline_report = None;
    let mut telemetry_report = None;
    let mut telemetry_events = 0u64;
    let sink = if args.observer_addr.is_some() {
        "jsonl_tcp"
    } else {
        "in_memory"
    };

    for _ in 0..args.telemetry_cost_runs {
        let started = Instant::now();
        let report = run_epoch_chaos(config.clone())?;
        baseline_total += started.elapsed();
        match baseline_report.as_ref() {
            Some(reference) => ensure_matching_outcome(reference, &report, "baseline")?,
            None => baseline_report = Some(report),
        }
    }

    let baseline_reference = baseline_report
        .as_ref()
        .expect("baseline report should exist after at least one run");
    for _ in 0..args.telemetry_cost_runs {
        let counter = counting_sink(args)?;
        let started = Instant::now();
        let report =
            run_epoch_chaos_with_telemetry(config.clone(), TelemetryHandle::new(counter.clone()))?;
        let events = counter.events();
        drop(counter);
        telemetry_total += started.elapsed();
        telemetry_events += events;
        ensure_matching_outcome(baseline_reference, &report, "telemetry")?;
        telemetry_report = Some(report);
    }

    Ok((
        telemetry_report.expect("telemetry report should exist after at least one run"),
        TelemetryCostReport {
            runs: args.telemetry_cost_runs,
            sink,
            baseline_total,
            telemetry_total,
            telemetry_events,
        },
    ))
}

fn counting_sink(args: &Args) -> MainResult<Arc<CountingTelemetrySink>> {
    let inner: Arc<dyn TelemetrySink> = match args.observer_addr.as_ref() {
        Some(addr) => Arc::new(JsonlTcpTelemetrySink::connect(addr)?),
        None => Arc::new(InMemoryTelemetrySink::default()),
    };
    Ok(Arc::new(CountingTelemetrySink::new(inner)))
}

struct CountingTelemetrySink {
    inner: Arc<dyn TelemetrySink>,
    events: AtomicU64,
}

impl CountingTelemetrySink {
    fn new(inner: Arc<dyn TelemetrySink>) -> Self {
        Self {
            inner,
            events: AtomicU64::new(0),
        }
    }

    fn events(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }
}

impl TelemetrySink for CountingTelemetrySink {
    fn record(&self, event: blossom::TelemetryEvent) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.inner.record(event);
    }
}

fn ensure_matching_outcome(
    expected: &EpochChaosReport,
    actual: &EpochChaosReport,
    label: &str,
) -> MainResult<()> {
    if expected.total_messages != actual.total_messages
        || expected.delivered_messages != actual.delivered_messages
        || expected.dropped_messages != actual.dropped_messages
        || expected.fuzzed_messages != actual.fuzzed_messages
        || expected.late_messages != actual.late_messages
        || expected.spiked_messages != actual.spiked_messages
        || expected.repair_attempts != actual.repair_attempts
        || expected.repair_successes != actual.repair_successes
        || expected.reconnect_attempts != actual.reconnect_attempts
        || expected.reconnect_approvals != actual.reconnect_approvals
        || expected.reconnect_catchup_proofs != actual.reconnect_catchup_proofs
        || expected.reconnect_replays != actual.reconnect_replays
        || expected.reconnect_stale_proofs != actual.reconnect_stale_proofs
        || expected.reconnect_duplicate_votes != actual.reconnect_duplicate_votes
        || expected.reconnect_identity_rejections != actual.reconnect_identity_rejections
        || expected.reconnect_successes != actual.reconnect_successes
        || expected.block_transfer_attempts != actual.block_transfer_attempts
        || expected.accepted_blocks != actual.accepted_blocks
        || expected.denied_blocks != actual.denied_blocks
        || expected.accepted_block_bytes != actual.accepted_block_bytes
        || expected.denied_block_bytes != actual.denied_block_bytes
        || expected.final_active_nodes != actual.final_active_nodes
        || expected.final_dropped_nodes != actual.final_dropped_nodes
        || expected.dropped_node_keys != actual.dropped_node_keys
        || expected.reconnected_node_keys != actual.reconnected_node_keys
        || expected.byzantine_node_keys != actual.byzantine_node_keys
        || expected.final_correct_nodes != actual.final_correct_nodes
        || expected.final_incorrect_nodes != actual.final_incorrect_nodes
        || expected.final_unique_epoch_hashes != actual.final_unique_epoch_hashes
        || expected.final_correct_epoch_hash != actual.final_correct_epoch_hash
    {
        return Err(format!("non-deterministic {label} telemetry cost run outcome").into());
    }
    Ok(())
}

fn duration_micros_per_run(duration: Duration, runs: usize) -> u128 {
    duration.as_micros() / runs as u128
}

fn micros_to_millis(micros: u128) -> f64 {
    micros as f64 / 1_000.0
}

fn config_from_args(args: &Args) -> EpochChaosConfig {
    EpochChaosConfig {
        seed: args.seed,
        nodes: args.nodes,
        epochs: args.epochs,
        transactions_per_node: args.transactions_per_node,
        transaction_bytes: args.transaction_bytes,
        latency_ms: args.latency_ms,
        jitter_ms: args.jitter_ms,
        round_timeout_ms: args.round_timeout_ms,
        drop_ppm: args.drop_ppm,
        fuzz_ppm: args.fuzz_ppm,
        spike_ppm: args.spike_ppm,
        spike_latency_ms: args.spike_latency_ms,
        repair_rounds: args.repair_rounds,
        repair_fanout: args.repair_fanout,
        repair_quorum: args.repair_quorum,
        repair_timeout_ms: args.repair_timeout_ms,
        faulty_nodes: args.faulty_nodes,
        byzantine_nodes: args.byzantine_nodes,
        byzantine_reconnect_replay_ppm: args.byzantine_reconnect_replay_ppm,
        byzantine_reconnect_stale_proof_ppm: args.byzantine_reconnect_stale_proof_ppm,
        byzantine_reconnect_sybil_ppm: args.byzantine_reconnect_sybil_ppm,
        byzantine_duplicate_vote_copies: args.byzantine_duplicate_vote_copies,
        drop_faulty_after_epochs: args.drop_faulty_after_epochs,
        max_dropped_nodes_per_epoch: args.max_dropped_nodes_per_epoch,
        min_active_nodes: args.min_active_nodes,
        reconnect_dropped_after_epochs: args.reconnect_dropped_after_epochs,
        reconnect_ping_fanout: args.reconnect_ping_fanout,
        reconnect_ping_quorum: args.reconnect_ping_quorum,
        reconnect_approval_quorum: args.reconnect_approval_quorum,
        reconnect_timeout_ms: args.reconnect_timeout_ms,
        max_reconnected_nodes_per_epoch: args.max_reconnected_nodes_per_epoch,
        partition_start_epoch: args.partition_start_epoch,
        partition_end_epoch: args.partition_end_epoch,
        partition_left_nodes: args.partition_left_nodes,
        partition_reconnect_only: args.partition_reconnect_only,
        assist_after_skipped_round: args.assist_after_skipped_round,
        trust_mode: if args.trusted {
            TrustMode::Trusted
        } else {
            TrustMode::Verified
        },
        shuffle: args.shuffle,
    }
}

fn write_summary_csv(path: &PathBuf, report: &EpochChaosReport) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(
        file,
        "nodes,epochs,transactions_per_node,transaction_bytes,latency_ms,jitter_ms,round_timeout_ms,drop_ppm,fuzz_ppm,spike_ppm,spike_latency_ms,repair_rounds,repair_fanout,repair_quorum,repair_timeout_ms,faulty_nodes,byzantine_nodes,byzantine_reconnect_replay_ppm,byzantine_reconnect_stale_proof_ppm,byzantine_reconnect_sybil_ppm,byzantine_duplicate_vote_copies,drop_faulty_after_epochs,max_dropped_nodes_per_epoch,min_active_nodes,reconnect_dropped_after_epochs,reconnect_ping_fanout,reconnect_ping_quorum,reconnect_approval_quorum,reconnect_timeout_ms,max_reconnected_nodes_per_epoch,partition_start_epoch,partition_end_epoch,partition_left_nodes,partition_reconnect_only,assist_after_skipped_round,seed,trusted,shuffle,total_messages,delivered,dropped,fuzzed,late,spiked,repair_attempts,repair_successes,reconnect_attempts,reconnect_approvals,reconnect_catchup_proofs,reconnect_replays,reconnect_stale_proofs,reconnect_duplicate_votes,reconnect_identity_rejections,reconnect_successes,block_transfer_attempts,accepted_blocks,denied_blocks,accepted_block_bytes,denied_block_bytes,future_round_assists,future_round_skipped_messages,future_round_dropped_local_blocks,future_round_carried_forward_blocks,valid_local_blocks,intentionally_dropped_local_blocks,incorrectly_lost_local_blocks,max_byzantine_nodes_for_safety,byzantine_tolerance_exceeded,final_active_nodes,final_dropped_nodes,final_correct_nodes,final_incorrect_nodes,final_data_available_nodes,final_data_unavailable_nodes,final_unique_epoch_hashes,final_correct_epoch_nonce,final_correct_epoch_hash"
    )?;
    writeln!(file, "{}", summary_csv(report))?;
    Ok(())
}

fn write_epoch_csv(path: &PathBuf, report: &EpochChaosReport) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(
        file,
        "epoch,nonce,start_active_nodes,start_dropped_nodes,active_nodes,dropped_nodes,reconnected_nodes,correct_start_nodes,pre_repair_correct_nodes,repaired_nodes,correct_nodes,incorrect_nodes,data_available_nodes,data_unavailable_nodes,unique_epoch_hashes,min_blocks_per_node,max_blocks_per_node,valid_local_blocks,intentionally_dropped_local_blocks,incorrectly_lost_local_blocks,canonical_blocks,canonical_epoch_hash,total_messages,delivered,dropped,fuzzed,late,spiked,repair_attempts,repair_successes,reconnect_attempts,reconnect_approvals,reconnect_catchup_proofs,reconnect_replays,reconnect_stale_proofs,reconnect_duplicate_votes,reconnect_identity_rejections,reconnect_successes,block_transfer_attempts,accepted_blocks,denied_blocks,accepted_block_bytes,denied_block_bytes,future_round_assists,future_round_skipped_messages,future_round_dropped_local_blocks,future_round_carried_forward_blocks"
    )?;
    for epoch in &report.epochs {
        writeln!(file, "{}", epoch_csv(epoch))?;
    }
    Ok(())
}

fn write_stage_csv(path: &PathBuf, report: &EpochChaosReport) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(
        file,
        "epoch,nonce,round,stage,event,nodes,dropped_nodes,reconnected_nodes,quorums,correct_nodes,incorrect_nodes,data_available_nodes,data_unavailable_nodes,unique_epoch_hashes,canonical_blocks,min_blocks_per_node,max_blocks_per_node,repaired_nodes,total_messages,delivered,dropped,fuzzed,late,spiked,repair_attempts,repair_successes,reconnect_attempts,reconnect_approvals,reconnect_catchup_proofs,reconnect_replays,reconnect_stale_proofs,reconnect_duplicate_votes,reconnect_identity_rejections,reconnect_successes,block_transfer_attempts,accepted_blocks,denied_blocks,accepted_block_bytes,denied_block_bytes,future_round_assists,future_round_skipped_messages,future_round_dropped_local_blocks,future_round_carried_forward_blocks,canonical_epoch_hash"
    )?;
    for record in &report.stage_progress {
        writeln!(file, "{}", stage_record_csv(record))?;
    }
    Ok(())
}

fn stage_record_csv(record: &EpochStageProgressRecord) -> String {
    let round = record
        .round
        .map(|round| round.to_string())
        .unwrap_or_default();
    vec![
        record.epoch.to_string(),
        record.nonce.to_string(),
        round,
        record.stage.to_string(),
        record.event.to_string(),
        record.nodes.to_string(),
        record.dropped_nodes.to_string(),
        record.reconnected_nodes.to_string(),
        record.quorums.to_string(),
        record.correct_nodes.to_string(),
        record.incorrect_nodes.to_string(),
        record.data_available_nodes.to_string(),
        record.data_unavailable_nodes.to_string(),
        record.unique_epoch_hashes.to_string(),
        record.canonical_blocks.to_string(),
        record.min_blocks_per_node.to_string(),
        record.max_blocks_per_node.to_string(),
        record.repaired_nodes.to_string(),
        record.messages.total.to_string(),
        record.messages.delivered.to_string(),
        record.messages.dropped.to_string(),
        record.messages.fuzzed.to_string(),
        record.messages.late.to_string(),
        record.messages.spiked.to_string(),
        record.messages.repair_attempts.to_string(),
        record.messages.repair_successes.to_string(),
        record.messages.reconnect_attempts.to_string(),
        record.messages.reconnect_approvals.to_string(),
        record.messages.reconnect_catchup_proofs.to_string(),
        record.messages.reconnect_replays.to_string(),
        record.messages.reconnect_stale_proofs.to_string(),
        record.messages.reconnect_duplicate_votes.to_string(),
        record.messages.reconnect_identity_rejections.to_string(),
        record.messages.reconnect_successes.to_string(),
        record.messages.block_transfer_attempts.to_string(),
        record.messages.accepted_blocks.to_string(),
        record.messages.denied_blocks.to_string(),
        record.messages.accepted_block_bytes.to_string(),
        record.messages.denied_block_bytes.to_string(),
        record.messages.future_round_assists.to_string(),
        record.messages.future_round_skipped_messages.to_string(),
        record
            .messages
            .future_round_dropped_local_blocks
            .to_string(),
        record
            .messages
            .future_round_carried_forward_blocks
            .to_string(),
        record.canonical_epoch_hash.to_string(),
    ]
    .join(",")
}

fn epoch_csv(epoch: &blossom_sim::EpochChaosEpochReport) -> String {
    vec![
        epoch.epoch.to_string(),
        epoch.nonce.to_string(),
        epoch.start_active_nodes.to_string(),
        epoch.start_dropped_nodes.to_string(),
        epoch.active_nodes.to_string(),
        epoch.dropped_nodes.to_string(),
        epoch.reconnected_nodes.to_string(),
        epoch.correct_start_nodes.to_string(),
        epoch.pre_repair_correct_nodes.to_string(),
        epoch.repaired_nodes.to_string(),
        epoch.correct_nodes.to_string(),
        epoch.incorrect_nodes.to_string(),
        epoch.data_available_nodes.to_string(),
        epoch.data_unavailable_nodes.to_string(),
        epoch.unique_epoch_hashes.to_string(),
        epoch.min_blocks_per_node.to_string(),
        epoch.max_blocks_per_node.to_string(),
        epoch.valid_local_blocks.to_string(),
        epoch.intentionally_dropped_local_blocks.to_string(),
        epoch.incorrectly_lost_local_blocks.to_string(),
        epoch.canonical_blocks.to_string(),
        epoch.canonical_epoch_hash.to_string(),
        epoch.messages.total.to_string(),
        epoch.messages.delivered.to_string(),
        epoch.messages.dropped.to_string(),
        epoch.messages.fuzzed.to_string(),
        epoch.messages.late.to_string(),
        epoch.messages.spiked.to_string(),
        epoch.messages.repair_attempts.to_string(),
        epoch.messages.repair_successes.to_string(),
        epoch.messages.reconnect_attempts.to_string(),
        epoch.messages.reconnect_approvals.to_string(),
        epoch.messages.reconnect_catchup_proofs.to_string(),
        epoch.messages.reconnect_replays.to_string(),
        epoch.messages.reconnect_stale_proofs.to_string(),
        epoch.messages.reconnect_duplicate_votes.to_string(),
        epoch.messages.reconnect_identity_rejections.to_string(),
        epoch.messages.reconnect_successes.to_string(),
        epoch.messages.block_transfer_attempts.to_string(),
        epoch.messages.accepted_blocks.to_string(),
        epoch.messages.denied_blocks.to_string(),
        epoch.messages.accepted_block_bytes.to_string(),
        epoch.messages.denied_block_bytes.to_string(),
        epoch.messages.future_round_assists.to_string(),
        epoch.messages.future_round_skipped_messages.to_string(),
        epoch.messages.future_round_dropped_local_blocks.to_string(),
        epoch
            .messages
            .future_round_carried_forward_blocks
            .to_string(),
    ]
    .join(",")
}

fn write_bug_log(path: &PathBuf, args: &Args, report: &EpochChaosReport) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    writeln!(file, "# Blossom Epoch Chaos Bug Log")?;
    writeln!(file)?;
    writeln!(file, "## Reproduce")?;
    writeln!(file)?;
    writeln!(file, "```bash")?;
    writeln!(file, "{}", replay_command(args))?;
    writeln!(file, "```")?;
    writeln!(file)?;
    writeln!(file, "## Summary")?;
    writeln!(file)?;
    writeln!(file, "- nodes: {}", report.config.nodes)?;
    writeln!(file, "- epochs: {}", report.config.epochs)?;
    writeln!(file, "- repair_rounds: {}", report.config.repair_rounds)?;
    writeln!(file, "- repair_fanout: {}", report.config.repair_fanout)?;
    writeln!(
        file,
        "- effective_repair_fanout: {}",
        if report.config.repair_fanout == 0 {
            report.config.nodes.saturating_sub(1)
        } else {
            report
                .config
                .repair_fanout
                .min(report.config.nodes.saturating_sub(1))
        }
    )?;
    writeln!(file, "- repair_quorum: {}", report.config.repair_quorum)?;
    writeln!(
        file,
        "- effective_repair_quorum: {}",
        if report.config.repair_quorum == 0 {
            supermajority_count(report.config.nodes)
        } else {
            report.config.repair_quorum
        }
    )?;
    writeln!(
        file,
        "- repair_timeout_ms: {}",
        report.config.repair_timeout_ms
    )?;
    writeln!(file, "- faulty_nodes: {}", report.config.faulty_nodes)?;
    writeln!(file, "- byzantine_nodes: {}", report.config.byzantine_nodes)?;
    writeln!(
        file,
        "- max_byzantine_nodes_for_safety: {}",
        report.max_byzantine_nodes_for_safety
    )?;
    writeln!(
        file,
        "- byzantine_tolerance_exceeded: {}",
        report.byzantine_tolerance_exceeded
    )?;
    writeln!(
        file,
        "- byzantine_reconnect_replay_ppm: {}",
        report.config.byzantine_reconnect_replay_ppm
    )?;
    writeln!(
        file,
        "- byzantine_reconnect_stale_proof_ppm: {}",
        report.config.byzantine_reconnect_stale_proof_ppm
    )?;
    writeln!(
        file,
        "- byzantine_reconnect_sybil_ppm: {}",
        report.config.byzantine_reconnect_sybil_ppm
    )?;
    writeln!(
        file,
        "- byzantine_duplicate_vote_copies: {}",
        report.config.byzantine_duplicate_vote_copies
    )?;
    writeln!(
        file,
        "- drop_faulty_after_epochs: {}",
        report.config.drop_faulty_after_epochs
    )?;
    writeln!(
        file,
        "- max_dropped_nodes_per_epoch: {}",
        report.config.max_dropped_nodes_per_epoch
    )?;
    writeln!(
        file,
        "- min_active_nodes: {}",
        report.config.min_active_nodes
    )?;
    writeln!(
        file,
        "- reconnect_dropped_after_epochs: {}",
        report.config.reconnect_dropped_after_epochs
    )?;
    writeln!(
        file,
        "- reconnect_ping_fanout: {}",
        report.config.reconnect_ping_fanout
    )?;
    writeln!(
        file,
        "- reconnect_ping_quorum: {}",
        report.config.reconnect_ping_quorum
    )?;
    writeln!(
        file,
        "- reconnect_approval_quorum: {}",
        report.config.reconnect_approval_quorum
    )?;
    writeln!(
        file,
        "- reconnect_timeout_ms: {}",
        report.config.reconnect_timeout_ms
    )?;
    writeln!(
        file,
        "- max_reconnected_nodes_per_epoch: {}",
        report.config.max_reconnected_nodes_per_epoch
    )?;
    writeln!(
        file,
        "- partition_start_epoch: {}",
        option_csv(report.config.partition_start_epoch)
    )?;
    writeln!(
        file,
        "- partition_end_epoch: {}",
        option_csv(report.config.partition_end_epoch)
    )?;
    writeln!(
        file,
        "- partition_left_nodes: {}",
        report.config.partition_left_nodes
    )?;
    writeln!(
        file,
        "- partition_reconnect_only: {}",
        report.config.partition_reconnect_only
    )?;
    writeln!(
        file,
        "- assist_after_skipped_round: {}",
        option_csv(report.config.assist_after_skipped_round)
    )?;
    writeln!(file, "- final_active_nodes: {}", report.final_active_nodes)?;
    writeln!(
        file,
        "- final_dropped_nodes: {}",
        report.final_dropped_nodes
    )?;
    writeln!(
        file,
        "- final_correct_nodes: {}",
        report.final_correct_nodes
    )?;
    writeln!(
        file,
        "- final_incorrect_nodes: {}",
        report.final_incorrect_nodes
    )?;
    writeln!(
        file,
        "- final_data_available_nodes: {}",
        report.final_data_available_nodes
    )?;
    writeln!(
        file,
        "- final_data_unavailable_nodes: {}",
        report.final_data_unavailable_nodes
    )?;
    writeln!(
        file,
        "- final_unique_epoch_hashes: {}",
        report.final_unique_epoch_hashes
    )?;
    writeln!(
        file,
        "- final_correct_epoch_nonce: {}",
        report.final_correct_epoch_nonce
    )?;
    writeln!(
        file,
        "- final_correct_epoch_hash: {}",
        report.final_correct_epoch_hash
    )?;
    writeln!(file, "- total_messages: {}", report.total_messages)?;
    writeln!(file, "- delivered_messages: {}", report.delivered_messages)?;
    writeln!(file, "- dropped_messages: {}", report.dropped_messages)?;
    writeln!(file, "- fuzzed_messages: {}", report.fuzzed_messages)?;
    writeln!(file, "- late_messages: {}", report.late_messages)?;
    writeln!(file, "- spiked_messages: {}", report.spiked_messages)?;
    writeln!(file, "- repair_attempts: {}", report.repair_attempts)?;
    writeln!(file, "- repair_successes: {}", report.repair_successes)?;
    writeln!(file, "- reconnect_attempts: {}", report.reconnect_attempts)?;
    writeln!(
        file,
        "- reconnect_approvals: {}",
        report.reconnect_approvals
    )?;
    writeln!(
        file,
        "- reconnect_catchup_proofs: {}",
        report.reconnect_catchup_proofs
    )?;
    writeln!(file, "- reconnect_replays: {}", report.reconnect_replays)?;
    writeln!(
        file,
        "- reconnect_stale_proofs: {}",
        report.reconnect_stale_proofs
    )?;
    writeln!(
        file,
        "- reconnect_duplicate_votes: {}",
        report.reconnect_duplicate_votes
    )?;
    writeln!(
        file,
        "- reconnect_identity_rejections: {}",
        report.reconnect_identity_rejections
    )?;
    writeln!(
        file,
        "- reconnect_successes: {}",
        report.reconnect_successes
    )?;
    writeln!(
        file,
        "- block_transfer_attempts: {}",
        report.block_transfer_attempts
    )?;
    writeln!(file, "- accepted_blocks: {}", report.accepted_blocks)?;
    writeln!(file, "- denied_blocks: {}", report.denied_blocks)?;
    writeln!(
        file,
        "- accepted_block_bytes: {}",
        report.accepted_block_bytes
    )?;
    writeln!(file, "- denied_block_bytes: {}", report.denied_block_bytes)?;
    writeln!(
        file,
        "- future_round_assists: {}",
        report.future_round_assists
    )?;
    writeln!(
        file,
        "- future_round_skipped_messages: {}",
        report.future_round_skipped_messages
    )?;
    writeln!(
        file,
        "- future_round_dropped_local_blocks: {}",
        report.future_round_dropped_local_blocks
    )?;
    writeln!(
        file,
        "- future_round_carried_forward_blocks: {}",
        report.future_round_carried_forward_blocks
    )?;
    writeln!(file, "- valid_local_blocks: {}", report.valid_local_blocks)?;
    writeln!(
        file,
        "- intentionally_dropped_local_blocks: {}",
        report.intentionally_dropped_local_blocks
    )?;
    writeln!(
        file,
        "- incorrectly_lost_local_blocks: {}",
        report.incorrectly_lost_local_blocks
    )?;
    match report.check_runtime_reconciliation() {
        Ok(check) => {
            writeln!(file, "- reconciliation_check: passed")?;
            writeln!(
                file,
                "- reconciliation_divergent_epochs: {}",
                check.divergent_epochs
            )?;
            writeln!(
                file,
                "- reconciliation_epochs: {}",
                check.reconciliation_epochs
            )?;
            writeln!(
                file,
                "- reconciliation_repaired_nodes: {}",
                check.reconciled_nodes
            )?;
        }
        Err(err) => {
            writeln!(file, "- reconciliation_check: failed")?;
            writeln!(file, "- reconciliation_check_error: {err}")?;
        }
    }
    writeln!(file)?;
    writeln!(file, "## Epochs")?;
    writeln!(file)?;
    for epoch in &report.epochs {
        writeln!(
            file,
            "- epoch {}: start_active_nodes={}, active_nodes={}, dropped_nodes={}, reconnected_nodes={}, start_correct={}, pre_repair_correct={}, repaired_nodes={}, correct_nodes={}, incorrect_nodes={}, data_available_nodes={}, data_unavailable_nodes={}, unique_hashes={}, valid_local_blocks={}, intentionally_dropped_local_blocks={}, incorrectly_lost_local_blocks={}, canonical_blocks={}, dropped={}, fuzzed={}, late={}, spiked={}, repair_attempts={}, repair_successes={}, reconnect_attempts={}, reconnect_approvals={}, reconnect_replays={}, reconnect_duplicate_votes={}, reconnect_successes={}, block_transfer_attempts={}, accepted_blocks={}, denied_blocks={}, accepted_block_bytes={}, denied_block_bytes={}, future_round_assists={}, future_round_skipped_messages={}, future_round_dropped_local_blocks={}, future_round_carried_forward_blocks={}",
            epoch.epoch,
            epoch.start_active_nodes,
            epoch.active_nodes,
            epoch.dropped_nodes,
            epoch.reconnected_nodes,
            epoch.correct_start_nodes,
            epoch.pre_repair_correct_nodes,
            epoch.repaired_nodes,
            epoch.correct_nodes,
            epoch.incorrect_nodes,
            epoch.data_available_nodes,
            epoch.data_unavailable_nodes,
            epoch.unique_epoch_hashes,
            epoch.valid_local_blocks,
            epoch.intentionally_dropped_local_blocks,
            epoch.incorrectly_lost_local_blocks,
            epoch.canonical_blocks,
            epoch.messages.dropped,
            epoch.messages.fuzzed,
            epoch.messages.late,
            epoch.messages.spiked,
            epoch.messages.repair_attempts,
            epoch.messages.repair_successes,
            epoch.messages.reconnect_attempts,
            epoch.messages.reconnect_approvals,
            epoch.messages.reconnect_replays,
            epoch.messages.reconnect_duplicate_votes,
            epoch.messages.reconnect_successes,
            epoch.messages.block_transfer_attempts,
            epoch.messages.accepted_blocks,
            epoch.messages.denied_blocks,
            epoch.messages.accepted_block_bytes,
            epoch.messages.denied_block_bytes,
            epoch.messages.future_round_assists,
            epoch.messages.future_round_skipped_messages,
            epoch.messages.future_round_dropped_local_blocks,
            epoch.messages.future_round_carried_forward_blocks,
        )?;
    }
    writeln!(file)?;
    writeln!(file, "## Bug Candidates")?;
    writeln!(file)?;
    if report.final_incorrect_nodes == 0
        && report.final_data_unavailable_nodes == 0
        && report.incorrectly_lost_local_blocks == 0
        && report.final_unique_epoch_hashes == 1
    {
        writeln!(file, "No epoch convergence bug candidates were detected.")?;
    } else {
        writeln!(file, "### Final Epoch Divergence")?;
        writeln!(file)?;
        writeln!(file, "- severity: high")?;
        writeln!(
            file,
            "- final_correct_nodes: {}",
            report.final_correct_nodes
        )?;
        writeln!(
            file,
            "- final_incorrect_nodes: {}",
            report.final_incorrect_nodes
        )?;
        writeln!(
            file,
            "- final_data_available_nodes: {}",
            report.final_data_available_nodes
        )?;
        writeln!(
            file,
            "- final_data_unavailable_nodes: {}",
            report.final_data_unavailable_nodes
        )?;
        writeln!(
            file,
            "- incorrectly_lost_local_blocks: {}",
            report.incorrectly_lost_local_blocks
        )?;
        writeln!(
            file,
            "- final_unique_epoch_hashes: {}",
            report.final_unique_epoch_hashes
        )?;
        writeln!(
            file,
            "- note: Some nodes did not end at the canonical epoch hash under this transport profile."
        )?;
        writeln!(file)?;
    }
    if report.incorrectly_lost_local_blocks > 0 {
        writeln!(file, "### Incorrect Data Loss")?;
        writeln!(file)?;
        writeln!(file, "- severity: critical")?;
        writeln!(
            file,
            "- incorrectly_lost_local_blocks: {}",
            report.incorrectly_lost_local_blocks
        )?;
        writeln!(
            file,
            "- note: Valid local blocks were neither intentionally dropped by an explicit protocol boundary nor included in the canonical branch."
        )?;
        writeln!(file)?;
    }
    if report.late_messages > 0 {
        writeln!(file, "### Late Messages")?;
        writeln!(file)?;
        writeln!(file, "- severity: info")?;
        writeln!(file, "- count: {}", report.late_messages)?;
        writeln!(
            file,
            "- note: Messages exceeded round_timeout_ms and were ignored for their round; round_timeout_ms=0 disables this cutoff."
        )?;
        writeln!(file)?;
    }
    if report.fuzzed_messages > 0 {
        writeln!(file, "### Fuzzed Messages")?;
        writeln!(file)?;
        writeln!(file, "- severity: info")?;
        writeln!(file, "- count: {}", report.fuzzed_messages)?;
        writeln!(
            file,
            "- note: Fuzzed/corrupted transport messages were discarded before epoch merge."
        )?;
        writeln!(file)?;
    }
    if report.dropped_messages > 0 {
        writeln!(file, "### Dropped Messages")?;
        writeln!(file)?;
        writeln!(file, "- severity: info")?;
        writeln!(file, "- count: {}", report.dropped_messages)?;
        writeln!(
            file,
            "- note: Dropped transport messages were intentionally injected by drop_ppm."
        )?;
        writeln!(file)?;
    }
    Ok(())
}

fn summary_csv(report: &EpochChaosReport) -> String {
    vec![
        report.config.nodes.to_string(),
        report.config.epochs.to_string(),
        report.config.transactions_per_node.to_string(),
        report.config.transaction_bytes.to_string(),
        report.config.latency_ms.to_string(),
        report.config.jitter_ms.to_string(),
        report.config.round_timeout_ms.to_string(),
        report.config.drop_ppm.to_string(),
        report.config.fuzz_ppm.to_string(),
        report.config.spike_ppm.to_string(),
        report.config.spike_latency_ms.to_string(),
        report.config.repair_rounds.to_string(),
        report.config.repair_fanout.to_string(),
        report.config.repair_quorum.to_string(),
        report.config.repair_timeout_ms.to_string(),
        report.config.faulty_nodes.to_string(),
        report.config.byzantine_nodes.to_string(),
        report.config.byzantine_reconnect_replay_ppm.to_string(),
        report
            .config
            .byzantine_reconnect_stale_proof_ppm
            .to_string(),
        report.config.byzantine_reconnect_sybil_ppm.to_string(),
        report.config.byzantine_duplicate_vote_copies.to_string(),
        report.config.drop_faulty_after_epochs.to_string(),
        report.config.max_dropped_nodes_per_epoch.to_string(),
        report.config.min_active_nodes.to_string(),
        report.config.reconnect_dropped_after_epochs.to_string(),
        report.config.reconnect_ping_fanout.to_string(),
        report.config.reconnect_ping_quorum.to_string(),
        report.config.reconnect_approval_quorum.to_string(),
        report.config.reconnect_timeout_ms.to_string(),
        report.config.max_reconnected_nodes_per_epoch.to_string(),
        option_csv(report.config.partition_start_epoch),
        option_csv(report.config.partition_end_epoch),
        report.config.partition_left_nodes.to_string(),
        report.config.partition_reconnect_only.to_string(),
        option_csv(report.config.assist_after_skipped_round),
        report.config.seed.to_string(),
        report.config.trust_mode.is_trusted().to_string(),
        report.config.shuffle.to_string(),
        report.total_messages.to_string(),
        report.delivered_messages.to_string(),
        report.dropped_messages.to_string(),
        report.fuzzed_messages.to_string(),
        report.late_messages.to_string(),
        report.spiked_messages.to_string(),
        report.repair_attempts.to_string(),
        report.repair_successes.to_string(),
        report.reconnect_attempts.to_string(),
        report.reconnect_approvals.to_string(),
        report.reconnect_catchup_proofs.to_string(),
        report.reconnect_replays.to_string(),
        report.reconnect_stale_proofs.to_string(),
        report.reconnect_duplicate_votes.to_string(),
        report.reconnect_identity_rejections.to_string(),
        report.reconnect_successes.to_string(),
        report.block_transfer_attempts.to_string(),
        report.accepted_blocks.to_string(),
        report.denied_blocks.to_string(),
        report.accepted_block_bytes.to_string(),
        report.denied_block_bytes.to_string(),
        report.future_round_assists.to_string(),
        report.future_round_skipped_messages.to_string(),
        report.future_round_dropped_local_blocks.to_string(),
        report.future_round_carried_forward_blocks.to_string(),
        report.valid_local_blocks.to_string(),
        report.intentionally_dropped_local_blocks.to_string(),
        report.incorrectly_lost_local_blocks.to_string(),
        report.max_byzantine_nodes_for_safety.to_string(),
        report.byzantine_tolerance_exceeded.to_string(),
        report.final_active_nodes.to_string(),
        report.final_dropped_nodes.to_string(),
        report.final_correct_nodes.to_string(),
        report.final_incorrect_nodes.to_string(),
        report.final_data_available_nodes.to_string(),
        report.final_data_unavailable_nodes.to_string(),
        report.final_unique_epoch_hashes.to_string(),
        report.final_correct_epoch_nonce.to_string(),
        report.final_correct_epoch_hash.to_string(),
    ]
    .join(",")
}

fn replay_command(args: &Args) -> String {
    let mut parts = vec![
        "cargo".to_string(),
        "run".to_string(),
        "--release".to_string(),
        "-p".to_string(),
        "blossom-sim".to_string(),
        "--bin".to_string(),
        "blossom-sim-epoch-chaos".to_string(),
        "--".to_string(),
    ];
    push_arg(&mut parts, "--nodes", args.nodes);
    push_arg(&mut parts, "--epochs", args.epochs);
    push_arg(
        &mut parts,
        "--transactions-per-node",
        args.transactions_per_node,
    );
    push_arg(&mut parts, "--transaction-bytes", args.transaction_bytes);
    push_arg(&mut parts, "--latency-ms", args.latency_ms);
    push_arg(&mut parts, "--jitter-ms", args.jitter_ms);
    push_arg(&mut parts, "--round-timeout-ms", args.round_timeout_ms);
    push_arg(&mut parts, "--drop-ppm", args.drop_ppm);
    push_arg(&mut parts, "--fuzz-ppm", args.fuzz_ppm);
    push_arg(&mut parts, "--spike-ppm", args.spike_ppm);
    push_arg(&mut parts, "--spike-latency-ms", args.spike_latency_ms);
    push_arg(&mut parts, "--repair-rounds", args.repair_rounds);
    push_arg(&mut parts, "--repair-fanout", args.repair_fanout);
    push_arg(&mut parts, "--repair-quorum", args.repair_quorum);
    push_arg(&mut parts, "--repair-timeout-ms", args.repair_timeout_ms);
    push_arg(&mut parts, "--faulty-nodes", args.faulty_nodes);
    push_arg(&mut parts, "--byzantine-nodes", args.byzantine_nodes);
    push_arg(
        &mut parts,
        "--byzantine-reconnect-replay-ppm",
        args.byzantine_reconnect_replay_ppm,
    );
    push_arg(
        &mut parts,
        "--byzantine-reconnect-stale-proof-ppm",
        args.byzantine_reconnect_stale_proof_ppm,
    );
    push_arg(
        &mut parts,
        "--byzantine-reconnect-sybil-ppm",
        args.byzantine_reconnect_sybil_ppm,
    );
    push_arg(
        &mut parts,
        "--byzantine-duplicate-vote-copies",
        args.byzantine_duplicate_vote_copies,
    );
    push_arg(
        &mut parts,
        "--drop-faulty-after-epochs",
        args.drop_faulty_after_epochs,
    );
    push_arg(
        &mut parts,
        "--max-dropped-nodes-per-epoch",
        args.max_dropped_nodes_per_epoch,
    );
    push_arg(&mut parts, "--min-active-nodes", args.min_active_nodes);
    push_arg(
        &mut parts,
        "--reconnect-dropped-after-epochs",
        args.reconnect_dropped_after_epochs,
    );
    push_arg(
        &mut parts,
        "--reconnect-ping-fanout",
        args.reconnect_ping_fanout,
    );
    push_arg(
        &mut parts,
        "--reconnect-ping-quorum",
        args.reconnect_ping_quorum,
    );
    push_arg(
        &mut parts,
        "--reconnect-approval-quorum",
        args.reconnect_approval_quorum,
    );
    push_arg(
        &mut parts,
        "--reconnect-timeout-ms",
        args.reconnect_timeout_ms,
    );
    push_arg(
        &mut parts,
        "--max-reconnected-nodes-per-epoch",
        args.max_reconnected_nodes_per_epoch,
    );
    push_arg(&mut parts, "--seed", args.seed);
    if let Some(epoch) = args.partition_start_epoch {
        push_arg(&mut parts, "--partition-start-epoch", epoch);
    }
    if let Some(epoch) = args.partition_end_epoch {
        push_arg(&mut parts, "--partition-end-epoch", epoch);
    }
    push_arg(
        &mut parts,
        "--partition-left-nodes",
        args.partition_left_nodes,
    );
    if args.partition_reconnect_only {
        parts.push("--partition-reconnect-only".to_string());
    }
    if let Some(round) = args.assist_after_skipped_round {
        push_arg(&mut parts, "--assist-after-skipped-round", round);
    }
    if args.trusted {
        parts.push("--trusted".to_string());
    }
    if args.shuffle {
        parts.push("--shuffle".to_string());
    }
    if args.require_reconciliation {
        parts.push("--require-reconciliation".to_string());
    }
    if args.measure_telemetry_cost {
        parts.push("--measure-telemetry-cost".to_string());
        push_arg(
            &mut parts,
            "--telemetry-cost-runs",
            args.telemetry_cost_runs,
        );
    }
    if let Some(addr) = args.observer_addr.as_ref() {
        parts.push("--observer-addr".to_string());
        parts.push(addr.clone());
    }
    parts.join(" ")
}

fn push_arg(parts: &mut Vec<String>, name: &str, value: impl ToString) {
    parts.push(name.to_string());
    parts.push(value.to_string());
}

fn option_csv(value: Option<usize>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}
