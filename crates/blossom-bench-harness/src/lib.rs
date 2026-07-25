//! Safety-labeled benchmark harness shared by Blossom and OpenRaft.

pub mod blossom_adapter;
pub mod correctness;
pub mod ha_adapter;
pub mod harness;
pub mod raft_adapter;
mod raft_log_store;

pub const OPENRAFT_VERSION: &str = "0.9.24";
pub const REDB_VERSION: &str = "4.1.0";

pub use blossom_adapter::{
    BlossomActiveActiveCluster, BlossomAppliedSample, BlossomFinalitySample, BlossomNodeTraffic,
    BlossomTcpOrderCluster, BlossomTrustedDirectCluster, BlossomTrustedDirectSample,
    BlossomTrustedPathSample, BlossomUniversalWriterSample,
};
pub use correctness::{
    HistoryOperation, LinearizabilityReport, check_certified_application_order,
    check_linearizable_history, compare_non_conflicting_final_states,
};
pub use ha_adapter::{FixedSlotHaCluster, HaAppliedSample};
pub use harness::{
    ArtifactInventory, BenchmarkCell, BenchmarkEvent, BenchmarkMethodology, BenchmarkProtocol,
    CorrectnessGates, DeterministicBarrierTracker, ExecutionProfile, FaultScenario, MatrixKind,
    MilestoneBarrier, NormalizedWorkload, PairedRunOrder, PerformanceArtifact,
    build_equal_fault_tolerance_matrix, build_equal_physical_footprint_matrix,
    hierarchical_bootstrap_mean_ci, paired_run_order,
};
pub use raft_adapter::{
    BenchmarkDurableStores, BenchmarkRaft, BenchmarkRaftConfig, BenchmarkRedbLogStore,
    BenchmarkStateMachineStore, InProcessNetworkControl, InProcessRaftCluster, LinkState,
    RaftAppliedResponse, RaftDeterministicFault, RaftDeterministicReport, RaftStorageProfile,
    run_raft_deterministic_campaign,
};
