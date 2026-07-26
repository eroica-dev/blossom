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
mod deterministic;
mod error;
mod hermetic;
mod profile;
mod resources;
mod rng;

pub use chaos::{
    CHAOS_RATE_DENOMINATOR, ChaosSample, NetworkChaos, NetworkChaosConfig, NetworkChaosReport,
};
pub use deterministic::{
    ChoiceId, ChoiceRecord, ClientHistoryEvent, ClientOutcome, ClusterView, DeterministicCluster,
    DeterministicNode, Effect, EventDisposition, EventKey, ExecutionTrace, ExplorationBounds,
    ExplorationReport, FaultCoverage, GlobalObserver, LinkFault, LinkState, NodeContext, NodeEvent,
    NodeFault, NodeLifecycle, PropertyKind, PropertyObservation, PropertyRegistry, PropertyReport,
    PropertyStatus, ReducedTrace, ReplayManifest, RunMode, Scenario, ScenarioAction,
    ScenarioActionKind, SimChannel, SimEvent, SimEventKind, SimTime, StorageFault,
    SystematicExplorer, TraceEvent, TraceReducer, event_keys_dependent,
};
pub use error::{Result, SimEnvError};
pub use hermetic::{
    HermeticActionRecord, HermeticCluster, HermeticEventLog, HermeticEventRecord, HermeticNode,
    HermeticNodeFuture, HermeticOutcome, HermeticPerfReport, HermeticPlan, HermeticRunReport,
    HermeticSimConfig, NodePerfReport, PlannedAction, replay_matches_with, run_plan_with,
    run_plan_with_perf,
};
pub use profile::{ClusterProfile, NodeProfile};
pub use resources::{CpuProfile, HardwareFaultConfig, HardwareFaultKind};
pub use rng::splitmix64;
