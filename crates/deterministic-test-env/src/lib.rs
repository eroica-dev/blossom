//! Protocol-independent deterministic testing primitives.
//!
//! New adapters implement [`DeterministicNode`] and return explicit [`Effect`]s
//! for protocol messages, responses, timers, and persistence. A
//! [`DeterministicCluster`] controls virtual time, event order, directed-link
//! faults, process lifecycle, storage faults, replay, and global properties.
//! [`SystematicExplorer`] and [`TraceReducer`] provide bounded schedule
//! exploration and failure minimization.
//!
//! [`HermeticPlan`] and [`HermeticCluster`] remain available as compatibility
//! wrappers for existing request-level simulators. `blossom-sim` supplies the
//! Blossom-specific HA, trusted, and parallel-network adapters; this crate has
//! no dependency on Blossom.

mod chaos;
mod hermetic;
mod profile;
mod resources;

pub use chaos::{
    CHAOS_RATE_DENOMINATOR, ChaosSample, NetworkChaos, NetworkChaosConfig, NetworkChaosReport,
};
pub use deterministic_sim_core::*;
pub use hermetic::{
    HermeticActionRecord, HermeticCluster, HermeticEventLog, HermeticEventRecord, HermeticNode,
    HermeticNodeFuture, HermeticOutcome, HermeticPerfReport, HermeticPlan, HermeticRunReport,
    HermeticSimConfig, NodePerfReport, PlannedAction, replay_matches_with, run_plan_with,
    run_plan_with_perf,
};
pub use profile::{ClusterProfile, NodeProfile};
pub use resources::{CpuProfile, HardwareFaultConfig, HardwareFaultKind};
