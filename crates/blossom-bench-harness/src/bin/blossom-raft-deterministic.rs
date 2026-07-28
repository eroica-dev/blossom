//! Deterministic OpenRaft workload and restart scenario runner.

use std::fs;
use std::panic;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use blossom_bench_harness::{
    RaftDeterministicFault, RaftDeterministicReport, run_raft_deterministic_campaign,
};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

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
    #[arg(
        long,
        value_delimiter = ',',
        help = "Physical node counts to run; defaults to every supported count from 2 through 7"
    )]
    nodes: Vec<usize>,
    #[arg(
        long = "fault",
        value_enum,
        value_delimiter = ',',
        help = "Fault cells to run; defaults to the full fault matrix"
    )]
    faults: Vec<FaultArg>,
    #[arg(long, value_enum, default_value_t = StorageArg::Both)]
    storage: StorageArg,
    #[arg(
        long,
        default_value_t = 1,
        help = "Maximum campaign cells to execute concurrently"
    )]
    jobs: usize,
}

#[derive(Debug, Serialize)]
struct Artifact {
    schema_version: u16,
    commands: u64,
    base_seed: u64,
    requested_jobs: usize,
    replay_level: &'static str,
    exact_task_schedule_replay: bool,
    safety_passed: bool,
    observed_panics: Vec<ObservedPanic>,
    reports: Vec<RaftDeterministicReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ActiveCell {
    physical_nodes: usize,
    durable: bool,
    fault: RaftDeterministicFault,
    seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ObservedPanic {
    thread: String,
    message: String,
    location: Option<String>,
    active_cells: Vec<ActiveCell>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StorageArg {
    Memory,
    Durable,
    Both,
}

impl StorageArg {
    fn durability(self) -> &'static [bool] {
        match self {
            Self::Memory => &[false],
            Self::Durable => &[true],
            Self::Both => &[false, true],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FaultArg {
    None,
    FollowerPause,
    LeaderPause,
    AsymmetricFollowerPartition,
    QuorumLossPartition,
    NetworkDelay,
    ResponseLossAfterCommit,
    AppendRequestLoss,
    AppendResponseLoss,
    DuplicateAppendRequest,
    AppendRequestDelay,
    AppendResponseDelay,
    VoteRequestLoss,
    VoteResponseLoss,
    RepeatedLeaderChurn,
    DurableFollowerRestart,
    DurableLeaderRestart,
}

impl FaultArg {
    fn fault(self) -> RaftDeterministicFault {
        match self {
            Self::None => RaftDeterministicFault::None,
            Self::FollowerPause => RaftDeterministicFault::FollowerPause,
            Self::LeaderPause => RaftDeterministicFault::LeaderPause,
            Self::AsymmetricFollowerPartition => {
                RaftDeterministicFault::AsymmetricFollowerPartition
            }
            Self::QuorumLossPartition => RaftDeterministicFault::QuorumLossPartition,
            Self::NetworkDelay => RaftDeterministicFault::NetworkDelay,
            Self::ResponseLossAfterCommit => RaftDeterministicFault::ResponseLossAfterCommit,
            Self::AppendRequestLoss => RaftDeterministicFault::AppendRequestLoss,
            Self::AppendResponseLoss => RaftDeterministicFault::AppendResponseLoss,
            Self::DuplicateAppendRequest => RaftDeterministicFault::DuplicateAppendRequest,
            Self::AppendRequestDelay => RaftDeterministicFault::AppendRequestDelay,
            Self::AppendResponseDelay => RaftDeterministicFault::AppendResponseDelay,
            Self::VoteRequestLoss => RaftDeterministicFault::VoteRequestLoss,
            Self::VoteResponseLoss => RaftDeterministicFault::VoteResponseLoss,
            Self::RepeatedLeaderChurn => RaftDeterministicFault::RepeatedLeaderChurn,
            Self::DurableFollowerRestart => RaftDeterministicFault::DurableFollowerRestart,
            Self::DurableLeaderRestart => RaftDeterministicFault::DurableLeaderRestart,
        }
    }
}

fn all_faults() -> Vec<RaftDeterministicFault> {
    [
        FaultArg::None,
        FaultArg::FollowerPause,
        FaultArg::LeaderPause,
        FaultArg::AsymmetricFollowerPartition,
        FaultArg::QuorumLossPartition,
        FaultArg::NetworkDelay,
        FaultArg::ResponseLossAfterCommit,
        FaultArg::AppendRequestLoss,
        FaultArg::AppendResponseLoss,
        FaultArg::DuplicateAppendRequest,
        FaultArg::AppendRequestDelay,
        FaultArg::AppendResponseDelay,
        FaultArg::VoteRequestLoss,
        FaultArg::VoteResponseLoss,
        FaultArg::RepeatedLeaderChurn,
        FaultArg::DurableFollowerRestart,
        FaultArg::DurableLeaderRestart,
    ]
    .into_iter()
    .map(FaultArg::fault)
    .collect()
}

fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    if args.jobs == 0 {
        return Err("--jobs must be positive".into());
    }
    let active_cells = Arc::new(Mutex::new(Vec::new()));
    let observed_panics = install_panic_recorder(active_cells.clone());
    let worker_threads = args.jobs.max(2);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?
        .block_on(run(args, active_cells, observed_panics))
}

async fn run(
    args: Args,
    active_cells: Arc<Mutex<Vec<ActiveCell>>>,
    observed_panics: Arc<Mutex<Vec<ObservedPanic>>>,
) -> Result<(), BoxError> {
    let nodes = if args.nodes.is_empty() {
        (2..=7).collect::<Vec<_>>()
    } else {
        args.nodes.clone()
    };
    if nodes.iter().any(|nodes| !(2..=7).contains(nodes)) {
        return Err("--nodes values must be between 2 and 7".into());
    }
    let faults = if args.faults.is_empty() {
        all_faults()
    } else {
        args.faults.iter().copied().map(FaultArg::fault).collect()
    };
    let mut cells = Vec::new();
    for physical_nodes in nodes {
        for durable in args.storage.durability().iter().copied() {
            for fault in &faults {
                let fault = *fault;
                if !durable
                    && matches!(
                        fault,
                        RaftDeterministicFault::DurableFollowerRestart
                            | RaftDeterministicFault::DurableLeaderRestart
                    )
                {
                    continue;
                }
                if physical_nodes == 2
                    && matches!(
                        fault,
                        RaftDeterministicFault::VoteRequestLoss
                            | RaftDeterministicFault::VoteResponseLoss
                    )
                {
                    continue;
                }
                let seed = args.seed ^ physical_nodes as u64 ^ (fault_salt(fault) << 32);
                cells.push((physical_nodes, durable, fault, seed));
            }
        }
    }

    let semaphore = Arc::new(Semaphore::new(args.jobs));
    let mut tasks = JoinSet::new();
    for (index, (physical_nodes, durable, fault, seed)) in cells.into_iter().enumerate() {
        let semaphore = semaphore.clone();
        let active_cells = active_cells.clone();
        let commands = args.commands;
        tasks.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|_| "OpenRaft campaign semaphore closed")?;
            let cell = ActiveCell {
                physical_nodes,
                durable,
                fault,
                seed,
            };
            lock_unpoisoned(&active_cells).push(cell.clone());
            let result =
                run_raft_deterministic_campaign(physical_nodes, commands, seed, durable, fault)
                    .await;
            lock_unpoisoned(&active_cells).retain(|active| active != &cell);
            result.map(|report| (index, report))
        });
    }
    let mut indexed_reports = Vec::new();
    while let Some(result) = tasks.join_next().await {
        let (index, report) = result??;
        println!(
            "nodes={} durable={} fault={:?} seed={} rpcs={} scripted={}/{} safety={} coverage={}",
            report.physical_nodes,
            report.durable,
            report.fault,
            report.seed,
            report.network_fault_coverage.total_rpcs,
            report.network_fault_coverage.executed_fault_ids.len(),
            report.network_fault_coverage.configured_fault_ids.len(),
            report.all_nodes_converged
                && report.linearizable_read_passed
                && report.history_linearizable
                && report.protocol_invariants_passed,
            report.fault_coverage_passed,
        );
        indexed_reports.push((index, report));
    }
    indexed_reports.sort_by_key(|(index, _)| *index);
    let reports = indexed_reports
        .into_iter()
        .map(|(_, report)| report)
        .collect::<Vec<_>>();
    let observed_panics = lock_unpoisoned(&observed_panics).clone();
    let safety_passed = observed_panics.is_empty()
        && reports.iter().all(|report| {
            report.all_nodes_converged
                && report.linearizable_read_passed
                && report.history_linearizable
                && report.ambiguous_outcomes_resolved
                && report.protocol_invariants_passed
                && report.fault_coverage_passed
        });
    let artifact = Artifact {
        schema_version: 3,
        commands: args.commands,
        base_seed: args.seed,
        requested_jobs: args.jobs,
        replay_level: "deterministic-inputs-native-schedule",
        exact_task_schedule_replay: false,
        safety_passed,
        observed_panics,
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

fn install_panic_recorder(
    active_cells: Arc<Mutex<Vec<ActiveCell>>>,
) -> Arc<Mutex<Vec<ObservedPanic>>> {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let recorded = observed.clone();
    let previous = panic::take_hook();
    panic::set_hook(Box::new(move |information| {
        let payload = information.payload();
        let message = payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        let location = information.location().map(|location| {
            format!(
                "{}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            )
        });
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        let mut active = lock_unpoisoned(&active_cells).clone();
        active.sort_by_key(|cell| {
            (
                cell.physical_nodes,
                cell.durable,
                format!("{:?}", cell.fault),
                cell.seed,
            )
        });
        lock_unpoisoned(&recorded).push(ObservedPanic {
            thread,
            message,
            location,
            active_cells: active,
        });
        previous(information);
    }));
    observed
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn fault_salt(fault: RaftDeterministicFault) -> u64 {
    match fault {
        RaftDeterministicFault::None => 0,
        RaftDeterministicFault::FollowerPause => 1,
        RaftDeterministicFault::LeaderPause => 2,
        RaftDeterministicFault::AsymmetricFollowerPartition => 3,
        RaftDeterministicFault::QuorumLossPartition => 4,
        RaftDeterministicFault::NetworkDelay => 5,
        RaftDeterministicFault::ResponseLossAfterCommit => 6,
        RaftDeterministicFault::RepeatedLeaderChurn => 7,
        RaftDeterministicFault::DurableFollowerRestart => 8,
        RaftDeterministicFault::DurableLeaderRestart => 9,
        RaftDeterministicFault::AppendRequestLoss => 10,
        RaftDeterministicFault::AppendResponseLoss => 11,
        RaftDeterministicFault::DuplicateAppendRequest => 12,
        RaftDeterministicFault::AppendRequestDelay => 13,
        RaftDeterministicFault::AppendResponseDelay => 14,
        RaftDeterministicFault::VoteRequestLoss => 15,
        RaftDeterministicFault::VoteResponseLoss => 16,
    }
}
