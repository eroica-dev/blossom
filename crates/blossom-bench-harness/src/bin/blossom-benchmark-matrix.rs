use std::fs;
use std::path::PathBuf;

use blossom::{Milestone, QuorumSize};
use blossom_bench_harness::{
    BenchmarkMethodology, ExecutionProfile, FaultScenario, MilestoneBarrier, NormalizedWorkload,
    OPENRAFT_VERSION, SHARD_STREAM_REVISION, build_equal_fault_tolerance_matrix,
    build_equal_physical_footprint_matrix,
};
use clap::Parser;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-benchmark-matrix",
    about = "Generate safety-gated Blossom/OpenRaft benchmark matrices"
)]
struct Args {
    #[arg(long, env = "BLOSSOM_QUORUM_SIZE", default_value = "6")]
    quorum_size: QuorumSize,
    #[arg(long, default_value = "benchmarks/results/active_active_matrix")]
    output: PathBuf,
}

#[derive(Serialize)]
struct MatrixArtifact {
    schema_version: u16,
    blossom_quorum_size: usize,
    openraft_version: &'static str,
    shard_stream_revision: &'static str,
    hegeltest_version: &'static str,
    methodology: BenchmarkMethodology,
    normalized_workload: NormalizedWorkload,
    execution_profiles: Vec<ExecutionProfile>,
    deterministic_fault_scenarios: Vec<FaultScenario>,
    equal_fault_tolerance: Vec<blossom_bench_harness::BenchmarkCell>,
    equal_physical_footprint: Vec<blossom_bench_harness::BenchmarkCell>,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    fs::create_dir_all(&args.output)?;
    let artifact = MatrixArtifact {
        schema_version: 1,
        blossom_quorum_size: args.quorum_size.get(),
        openraft_version: OPENRAFT_VERSION,
        shard_stream_revision: SHARD_STREAM_REVISION,
        hegeltest_version: "0.28.2",
        methodology: BenchmarkMethodology::default(),
        normalized_workload: NormalizedWorkload {
            logical_commands: 100_000,
            payload_bytes_per_command: 256,
            producer_linger_micros: 1_000,
            maximum_in_flight: 256,
            pending_byte_limit: 64 << 20,
            persistent_connections_per_node: 1,
            tls_enabled: false,
        },
        execution_profiles: vec![
            ExecutionProfile::InMemoryProtocolCore,
            ExecutionProfile::PersistentConnectionMultiProcess,
            ExecutionProfile::DurableShardStream,
            ExecutionProfile::SnapshotCompactionRestartCatchUp,
            ExecutionProfile::Rustls,
        ],
        deterministic_fault_scenarios: fault_scenarios(),
        equal_fault_tolerance: build_equal_fault_tolerance_matrix()?,
        equal_physical_footprint: build_equal_physical_footprint_matrix(args.quorum_size)?,
    };
    fs::write(
        args.output.join("matrix.json"),
        serde_json::to_vec_pretty(&artifact)?,
    )?;
    for cell in artifact
        .equal_fault_tolerance
        .iter()
        .chain(&artifact.equal_physical_footprint)
    {
        let matrix = match cell.matrix {
            blossom_bench_harness::MatrixKind::EqualFaultTolerance => "equal-fault",
            blossom_bench_harness::MatrixKind::EqualPhysicalFootprint => "equal-footprint",
        };
        cell.safety_manifest.write_json(args.output.join(format!(
            "safety-{matrix}-n{}-q{}-raft{}.json",
            cell.physical_machines, cell.blossom_quorum_size, cell.raft_voters
        )))?;
    }
    println!("{}", args.output.join("matrix.json").display());
    Ok(())
}

fn fault_scenarios() -> Vec<FaultScenario> {
    let barrier = || MilestoneBarrier {
        milestone: Milestone::Applied,
        after_commands: 50_000,
    };
    vec![
        FaultScenario::RandomFollowerLoss(barrier()),
        FaultScenario::CurrentRaftLeaderLoss(barrier()),
        FaultScenario::OneSiteLoss(barrier()),
        FaultScenario::MinorityPartition(barrier()),
        FaultScenario::MajorityPartition(barrier()),
        FaultScenario::AsymmetricOneWayPartition(barrier()),
        FaultScenario::PacketReordering(barrier()),
        FaultScenario::SlowCpu(barrier()),
        FaultScenario::SlowDisk(barrier()),
        FaultScenario::MembershipChurn(barrier()),
        FaultScenario::StorageExhaustion(barrier()),
        FaultScenario::FsyncFailure(barrier()),
        FaultScenario::Corruption(barrier()),
        FaultScenario::PowerLoss(barrier()),
        FaultScenario::BlossomEquivocation(barrier()),
        FaultScenario::BlossomWithholding(barrier()),
        FaultScenario::BlossomReplay(barrier()),
        FaultScenario::ConflictingRangeClaim(barrier()),
        FaultScenario::FinalizedUnavailableHeadOfLine(barrier()),
    ]
}
