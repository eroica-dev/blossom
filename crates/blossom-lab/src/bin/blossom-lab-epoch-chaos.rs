use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

use blossom::{TrustMode, algorithm::supermajority_count};
use blossom_lab::{EpochChaosConfig, EpochChaosReport, run_epoch_chaos};
use clap::Parser;

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-lab-epoch-chaos",
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
    #[arg(long, default_value_t = 50)]
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
    #[arg(long, default_value_t = 0x6570_6f63_685f_6368)]
    seed: u64,
    #[arg(long, default_value_t = false)]
    trusted: bool,
    #[arg(long, default_value_t = false)]
    shuffle: bool,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    epoch_log: Option<PathBuf>,
    #[arg(long)]
    bug_log: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let report = run_epoch_chaos(config_from_args(&args))?;
    println!("{}", summary_csv(&report));

    if let Some(path) = args.csv.as_ref() {
        write_summary_csv(path, &report)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = args.epoch_log.as_ref() {
        write_epoch_csv(path, &report)?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = args.bug_log.as_ref() {
        write_bug_log(path, &args, &report)?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
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
        "nodes,epochs,transactions_per_node,transaction_bytes,latency_ms,jitter_ms,round_timeout_ms,drop_ppm,fuzz_ppm,spike_ppm,spike_latency_ms,repair_rounds,repair_fanout,repair_quorum,repair_timeout_ms,seed,trusted,shuffle,total_messages,delivered,dropped,fuzzed,late,spiked,repair_attempts,repair_successes,final_correct_nodes,final_incorrect_nodes,final_unique_epoch_hashes,final_correct_epoch_nonce,final_correct_epoch_hash"
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
        "epoch,nonce,correct_start_nodes,pre_repair_correct_nodes,repaired_nodes,correct_nodes,incorrect_nodes,unique_epoch_hashes,min_blocks_per_node,max_blocks_per_node,canonical_blocks,canonical_epoch_hash,total_messages,delivered,dropped,fuzzed,late,spiked,repair_attempts,repair_successes"
    )?;
    for epoch in &report.epochs {
        writeln!(
            file,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            epoch.epoch,
            epoch.nonce,
            epoch.correct_start_nodes,
            epoch.pre_repair_correct_nodes,
            epoch.repaired_nodes,
            epoch.correct_nodes,
            epoch.incorrect_nodes,
            epoch.unique_epoch_hashes,
            epoch.min_blocks_per_node,
            epoch.max_blocks_per_node,
            epoch.canonical_blocks,
            epoch.canonical_epoch_hash,
            epoch.messages.total,
            epoch.messages.delivered,
            epoch.messages.dropped,
            epoch.messages.fuzzed,
            epoch.messages.late,
            epoch.messages.spiked,
            epoch.messages.repair_attempts,
            epoch.messages.repair_successes,
        )?;
    }
    Ok(())
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
    writeln!(file)?;
    writeln!(file, "## Epochs")?;
    writeln!(file)?;
    for epoch in &report.epochs {
        writeln!(
            file,
            "- epoch {}: start_correct={}, pre_repair_correct={}, repaired_nodes={}, correct_nodes={}, incorrect_nodes={}, unique_hashes={}, canonical_blocks={}, dropped={}, fuzzed={}, late={}, spiked={}, repair_attempts={}, repair_successes={}",
            epoch.epoch,
            epoch.correct_start_nodes,
            epoch.pre_repair_correct_nodes,
            epoch.repaired_nodes,
            epoch.correct_nodes,
            epoch.incorrect_nodes,
            epoch.unique_epoch_hashes,
            epoch.canonical_blocks,
            epoch.messages.dropped,
            epoch.messages.fuzzed,
            epoch.messages.late,
            epoch.messages.spiked,
            epoch.messages.repair_attempts,
            epoch.messages.repair_successes,
        )?;
    }
    writeln!(file)?;
    writeln!(file, "## Bug Candidates")?;
    writeln!(file)?;
    if report.final_incorrect_nodes == 0 && report.final_unique_epoch_hashes == 1 {
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
            "- final_unique_epoch_hashes: {}",
            report.final_unique_epoch_hashes
        )?;
        writeln!(
            file,
            "- note: Some nodes did not end at the canonical epoch hash under this transport profile."
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
            "- note: Messages exceeded round_timeout_ms and were ignored for their round."
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
    format!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
        report.config.nodes,
        report.config.epochs,
        report.config.transactions_per_node,
        report.config.transaction_bytes,
        report.config.latency_ms,
        report.config.jitter_ms,
        report.config.round_timeout_ms,
        report.config.drop_ppm,
        report.config.fuzz_ppm,
        report.config.spike_ppm,
        report.config.spike_latency_ms,
        report.config.repair_rounds,
        report.config.repair_fanout,
        report.config.repair_quorum,
        report.config.repair_timeout_ms,
        report.config.seed,
        report.config.trust_mode.is_trusted(),
        report.config.shuffle,
        report.total_messages,
        report.delivered_messages,
        report.dropped_messages,
        report.fuzzed_messages,
        report.late_messages,
        report.spiked_messages,
        report.repair_attempts,
        report.repair_successes,
        report.final_correct_nodes,
        report.final_incorrect_nodes,
        report.final_unique_epoch_hashes,
        report.final_correct_epoch_nonce,
        report.final_correct_epoch_hash,
    )
}

fn replay_command(args: &Args) -> String {
    let mut parts = vec![
        "cargo".to_string(),
        "run".to_string(),
        "--release".to_string(),
        "-p".to_string(),
        "blossom-lab".to_string(),
        "--bin".to_string(),
        "blossom-lab-epoch-chaos".to_string(),
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
    push_arg(&mut parts, "--seed", args.seed);
    if args.trusted {
        parts.push("--trusted".to_string());
    }
    if args.shuffle {
        parts.push("--shuffle".to_string());
    }
    parts.join(" ")
}

fn push_arg(parts: &mut Vec<String>, name: &str, value: impl ToString) {
    parts.push(name.to_string());
    parts.push(value.to_string());
}
