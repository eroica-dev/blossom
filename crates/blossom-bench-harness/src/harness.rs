use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use blossom::{
    CommitteeParticipant, ConsensusParameters, HashType, Milestone, QuorumSize, SafetyManifest,
    SiteId, generate_safety_manifest,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BenchmarkProtocol {
    CausalEventualActiveSync,
    ConflictOnlyBlossom,
    GloballyOrderedBlossom,
    OpenRaft,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixKind {
    EqualFaultTolerance,
    EqualPhysicalFootprint,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionProfile {
    InMemoryProtocolCore,
    PersistentConnectionMultiProcess,
    DurableShardStream,
    SnapshotCompactionRestartCatchUp,
    Rustls,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkCell {
    pub matrix: MatrixKind,
    pub physical_machines: usize,
    pub blossom_quorum_size: usize,
    pub raft_voters: usize,
    pub raft_learners: usize,
    pub safety_equivalent: bool,
    pub publishable_as_safety_equivalent: bool,
    pub safety_manifest: SafetyManifest,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NormalizedWorkload {
    pub logical_commands: u64,
    pub payload_bytes_per_command: usize,
    pub producer_linger_micros: u64,
    pub maximum_in_flight: usize,
    pub pending_byte_limit: usize,
    pub persistent_connections_per_node: usize,
    pub tls_enabled: bool,
}

impl NormalizedWorkload {
    pub fn validate(&self) -> Result<(), String> {
        if self.logical_commands == 0
            || self.maximum_in_flight == 0
            || self.pending_byte_limit < self.payload_bytes_per_command
            || self.persistent_connections_per_node == 0
        {
            return Err(
                "workload normalization values must be non-zero and internally consistent"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkEvent {
    pub run_id: String,
    pub protocol: BenchmarkProtocol,
    pub node_id: String,
    pub command_id: String,
    pub milestone: Milestone,
    pub timestamp_nanos: u128,
    pub payload_bytes: u64,
    pub reference_bytes: u64,
    pub control_bytes: u64,
    pub configured_quorum_size: Option<usize>,
    pub effective_quorum_size: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MilestoneBarrier {
    pub milestone: Milestone,
    pub after_commands: u64,
}

#[derive(Debug, Clone)]
pub struct DeterministicBarrierTracker {
    barrier: MilestoneBarrier,
    reached_commands: BTreeSet<String>,
    fired: bool,
}

impl DeterministicBarrierTracker {
    pub fn new(barrier: MilestoneBarrier) -> Self {
        Self {
            barrier,
            reached_commands: BTreeSet::new(),
            fired: false,
        }
    }

    /// Returns true exactly once, when the requested number of distinct
    /// commands has reached the configured milestone.
    pub fn observe(&mut self, event: &BenchmarkEvent) -> bool {
        if self.fired || event.milestone != self.barrier.milestone {
            return false;
        }
        self.reached_commands.insert(event.command_id.clone());
        if self.reached_commands.len() as u64 >= self.barrier.after_commands {
            self.fired = true;
            return true;
        }
        false
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum FaultScenario {
    RandomFollowerLoss(MilestoneBarrier),
    CurrentRaftLeaderLoss(MilestoneBarrier),
    OneSiteLoss(MilestoneBarrier),
    MinorityPartition(MilestoneBarrier),
    MajorityPartition(MilestoneBarrier),
    AsymmetricOneWayPartition(MilestoneBarrier),
    PacketReordering(MilestoneBarrier),
    SlowCpu(MilestoneBarrier),
    SlowDisk(MilestoneBarrier),
    MembershipChurn(MilestoneBarrier),
    StorageExhaustion(MilestoneBarrier),
    FsyncFailure(MilestoneBarrier),
    Corruption(MilestoneBarrier),
    PowerLoss(MilestoneBarrier),
    BlossomEquivocation(MilestoneBarrier),
    BlossomWithholding(MilestoneBarrier),
    BlossomReplay(MilestoneBarrier),
    ConflictingRangeClaim(MilestoneBarrier),
    FinalizedUnavailableHeadOfLine(MilestoneBarrier),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BenchmarkMethodology {
    pub paired_repetitions: usize,
    pub steady_state: Duration,
    pub minimum_applied_samples_per_cell: u64,
    pub bootstrap_resamples: usize,
    pub block_duration: Duration,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CorrectnessGates {
    pub quorum_agreement: bool,
    pub safety: bool,
    pub durability: bool,
    pub history: bool,
    pub deterministic_replay: bool,
    pub recovery: bool,
}

impl CorrectnessGates {
    pub fn all_passed(&self) -> bool {
        self.quorum_agreement
            && self.safety
            && self.durability
            && self.history
            && self.deterministic_replay
            && self.recovery
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInventory {
    pub milestone_events: String,
    pub histories: String,
    pub environment_snapshot: String,
    pub configuration_snapshot: String,
    pub safety_manifest: String,
    pub fault_trace: String,
    pub dependency_versions: String,
    pub summary_report: String,
}

impl ArtifactInventory {
    fn missing(&self) -> Vec<&'static str> {
        [
            ("milestone events", &self.milestone_events),
            ("histories", &self.histories),
            ("environment snapshot", &self.environment_snapshot),
            ("configuration snapshot", &self.configuration_snapshot),
            ("safety manifest", &self.safety_manifest),
            ("fault trace", &self.fault_trace),
            ("dependency versions", &self.dependency_versions),
            ("summary report", &self.summary_report),
        ]
        .into_iter()
        .filter_map(|(name, path)| path.trim().is_empty().then_some(name))
        .collect()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PerformanceArtifact {
    pub schema_version: u16,
    pub cell: BenchmarkCell,
    pub protocol: BenchmarkProtocol,
    pub profile: ExecutionProfile,
    pub workload: NormalizedWorkload,
    pub methodology: BenchmarkMethodology,
    pub completed_paired_repetitions: usize,
    pub applied_samples: u64,
    pub paired_orders: Vec<PairedRunOrder>,
    pub correctness: CorrectnessGates,
    pub artifacts: ArtifactInventory,
    pub dependency_versions: BTreeMap<String, String>,
}

impl PerformanceArtifact {
    pub const SCHEMA_VERSION: u16 = 1;

    pub fn validate_for_publication(&self) -> Result<(), Vec<String>> {
        let mut failures = Vec::new();
        if self.schema_version != Self::SCHEMA_VERSION {
            failures.push("unsupported performance artifact schema".to_string());
        }
        if let Err(error) = self.workload.validate() {
            failures.push(error);
        }
        if let Err(error) = self.methodology.validate() {
            failures.push(error);
        }
        if self.completed_paired_repetitions < self.methodology.paired_repetitions
            || self.paired_orders.len() < self.methodology.paired_repetitions
        {
            failures.push("paired AB/BA repetitions are incomplete".to_string());
        }
        if self.applied_samples < self.methodology.minimum_applied_samples_per_cell {
            failures.push("Applied sample gate is incomplete".to_string());
        }
        if !self.correctness.all_passed() {
            failures.push(
                "quorum, safety, durability, history, replay, or recovery gate failed".to_string(),
            );
        }
        let missing = self.artifacts.missing();
        if !missing.is_empty() {
            failures.push(format!(
                "raw artifact inventory is missing {}",
                missing.join(", ")
            ));
        }
        for (dependency, expected) in [
            ("openraft", "0.9.24"),
            ("shard-stream", "03ef769a46d574622a838fca7b4884a93ba24177"),
            ("hegeltest", "0.28.2"),
        ] {
            if self
                .dependency_versions
                .get(dependency)
                .is_none_or(|actual| actual != expected)
            {
                failures.push(format!(
                    "dependency manifest does not pin {dependency}={expected}"
                ));
            }
        }
        if self.cell.matrix == MatrixKind::EqualFaultTolerance
            && !self.cell.publishable_as_safety_equivalent
        {
            failures.push("equal-fault row did not pass its safety manifest".to_string());
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
}

impl Default for BenchmarkMethodology {
    fn default() -> Self {
        Self {
            paired_repetitions: 12,
            steady_state: Duration::from_secs(300),
            minimum_applied_samples_per_cell: 100_000,
            bootstrap_resamples: 10_000,
            block_duration: Duration::from_secs(1),
        }
    }
}

impl BenchmarkMethodology {
    pub fn validate(&self) -> Result<(), String> {
        if self.paired_repetitions < 12
            || self.steady_state < Duration::from_secs(300)
            || self.minimum_applied_samples_per_cell < 100_000
            || self.bootstrap_resamples < 1_000
            || self.block_duration != Duration::from_secs(1)
        {
            return Err(
                "methodology is below the accepted repetition, duration, sample, or bootstrap gate"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairedRunOrder {
    BlossomThenRaft,
    RaftThenBlossom,
}

pub fn paired_run_order(seed: u64, repetition: usize) -> PairedRunOrder {
    if splitmix64(seed ^ repetition as u64) & 1 == 0 {
        PairedRunOrder::BlossomThenRaft
    } else {
        PairedRunOrder::RaftThenBlossom
    }
}

pub fn build_equal_fault_tolerance_matrix() -> Result<Vec<BenchmarkCell>, String> {
    [(3, 3), (6, 5), (9, 7)]
        .into_iter()
        .map(|(quorum_size, raft_voters)| {
            build_cell(
                MatrixKind::EqualFaultTolerance,
                quorum_size,
                quorum_size,
                raft_voters,
                0,
                true,
            )
        })
        .collect()
}

pub fn build_equal_physical_footprint_matrix(
    quorum_size: QuorumSize,
) -> Result<Vec<BenchmarkCell>, String> {
    [6, 12, 24, 36, 72]
        .into_iter()
        .map(|machines| {
            let raft_voters = match machines {
                0..=6 => 3,
                7..=24 => 5,
                _ => 7,
            };
            build_cell(
                MatrixKind::EqualPhysicalFootprint,
                machines,
                quorum_size.get(),
                raft_voters,
                machines - raft_voters,
                false,
            )
        })
        .collect()
}

fn build_cell(
    matrix: MatrixKind,
    physical_machines: usize,
    blossom_quorum_size: usize,
    raft_voters: usize,
    raft_learners: usize,
    require_equivalence: bool,
) -> Result<BenchmarkCell, String> {
    let quorum_size = QuorumSize::new(blossom_quorum_size).map_err(|error| error.to_string())?;
    let participants = (0..physical_machines)
        .map(|index| CommitteeParticipant {
            node: blossom::PubKey([index as u8; 32]),
            site: Some(SiteId(format!("site-{}", index % 3))),
        })
        .collect::<Vec<_>>();
    let safety_manifest = generate_safety_manifest(
        ConsensusParameters::new(quorum_size),
        participants,
        HashType::hash(format!("{matrix:?}/{physical_machines}/{blossom_quorum_size}").as_bytes()),
        0,
        true,
    )
    .map_err(|error| error.to_string())?;
    let raft_crash_tolerance = raft_voters.saturating_sub(1) / 2;
    let safety_equivalent = safety_manifest.max_validator_liveness_omissions
        == raft_crash_tolerance
        && safety_manifest.site_loss_tolerance;
    if require_equivalence && !safety_equivalent {
        return Err(format!(
            "safety manifest rejected q={blossom_quorum_size} versus {raft_voters} Raft voters"
        ));
    }
    Ok(BenchmarkCell {
        matrix,
        physical_machines,
        blossom_quorum_size,
        raft_voters,
        raft_learners,
        safety_equivalent,
        publishable_as_safety_equivalent: require_equivalence && safety_equivalent,
        safety_manifest,
    })
}

/// Hierarchical bootstrap over runs and one-second blocks.
pub fn hierarchical_bootstrap_mean_ci(
    runs: &[Vec<f64>],
    resamples: usize,
    confidence: f64,
    seed: u64,
) -> Option<(f64, f64, f64)> {
    if runs.is_empty()
        || runs.iter().any(Vec::is_empty)
        || resamples == 0
        || !(0.0 < confidence && confidence < 1.0)
    {
        return None;
    }
    let observed =
        runs.iter().flatten().sum::<f64>() / runs.iter().map(Vec::len).sum::<usize>() as f64;
    let mut state = seed;
    let mut estimates = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let mut sum = 0.0;
        let mut count = 0usize;
        for _ in 0..runs.len() {
            state = splitmix64(state);
            let run = &runs[state as usize % runs.len()];
            for _ in 0..run.len() {
                state = splitmix64(state);
                sum += run[state as usize % run.len()];
                count += 1;
            }
        }
        estimates.push(sum / count as f64);
    }
    estimates.sort_by(f64::total_cmp);
    let tail = (1.0 - confidence) / 2.0;
    let lower_index = ((resamples - 1) as f64 * tail).floor() as usize;
    let upper_index = ((resamples - 1) as f64 * (1.0 - tail)).ceil() as usize;
    Some((
        observed,
        estimates[lower_index],
        estimates[upper_index.min(resamples - 1)],
    ))
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_fault_tolerance_rows_pass_the_manifest_gate() {
        let rows = build_equal_fault_tolerance_matrix().unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.safety_equivalent));
        assert!(rows.iter().all(|row| row.publishable_as_safety_equivalent));
    }

    #[test]
    fn physical_footprint_rows_use_learners_and_are_not_scored_as_equivalent() {
        let rows = build_equal_physical_footprint_matrix(QuorumSize::new(6).unwrap()).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.physical_machines)
                .collect::<Vec<_>>(),
            vec![6, 12, 24, 36, 72]
        );
        assert!(rows.iter().all(|row| row.raft_learners > 0));
        assert!(rows.iter().all(|row| !row.publishable_as_safety_equivalent));
    }

    #[test]
    fn hierarchical_bootstrap_is_deterministic_and_contains_observed_mean() {
        let runs = vec![vec![1.0, 2.0, 3.0], vec![2.0, 3.0, 4.0]];
        let first = hierarchical_bootstrap_mean_ci(&runs, 2_000, 0.95, 7).unwrap();
        let second = hierarchical_bootstrap_mean_ci(&runs, 2_000, 0.95, 7).unwrap();
        assert_eq!(first, second);
        assert!(first.1 <= first.0 && first.0 <= first.2);
    }

    #[test]
    fn deterministic_fault_barrier_fires_once_for_distinct_commands() {
        let mut tracker = DeterministicBarrierTracker::new(MilestoneBarrier {
            milestone: Milestone::Applied,
            after_commands: 2,
        });
        let event = |command_id: &str| BenchmarkEvent {
            run_id: "run".to_string(),
            protocol: BenchmarkProtocol::OpenRaft,
            node_id: "node-1".to_string(),
            command_id: command_id.to_string(),
            milestone: Milestone::Applied,
            timestamp_nanos: 0,
            payload_bytes: 1,
            reference_bytes: 0,
            control_bytes: 1,
            configured_quorum_size: None,
            effective_quorum_size: None,
        };
        assert!(!tracker.observe(&event("one")));
        assert!(!tracker.observe(&event("one")));
        assert!(tracker.observe(&event("two")));
        assert!(!tracker.observe(&event("three")));
    }

    #[test]
    fn publication_gate_rejects_incomplete_or_failed_results() {
        let cell = build_equal_fault_tolerance_matrix().unwrap().remove(0);
        let artifact = PerformanceArtifact {
            schema_version: PerformanceArtifact::SCHEMA_VERSION,
            cell,
            protocol: BenchmarkProtocol::GloballyOrderedBlossom,
            profile: ExecutionProfile::DurableShardStream,
            workload: NormalizedWorkload {
                logical_commands: 100_000,
                payload_bytes_per_command: 32,
                producer_linger_micros: 0,
                maximum_in_flight: 64,
                pending_byte_limit: 1 << 20,
                persistent_connections_per_node: 1,
                tls_enabled: false,
            },
            methodology: BenchmarkMethodology::default(),
            completed_paired_repetitions: 1,
            applied_samples: 1,
            paired_orders: vec![PairedRunOrder::BlossomThenRaft],
            correctness: CorrectnessGates {
                quorum_agreement: true,
                safety: true,
                durability: false,
                history: true,
                deterministic_replay: true,
                recovery: true,
            },
            artifacts: ArtifactInventory {
                milestone_events: String::new(),
                histories: String::new(),
                environment_snapshot: String::new(),
                configuration_snapshot: String::new(),
                safety_manifest: String::new(),
                fault_trace: String::new(),
                dependency_versions: String::new(),
                summary_report: String::new(),
            },
            dependency_versions: BTreeMap::new(),
        };
        let failures = artifact.validate_for_publication().unwrap_err();
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("repetitions"))
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("durability"))
        );
        assert!(failures.iter().any(|failure| failure.contains("inventory")));
    }
}
