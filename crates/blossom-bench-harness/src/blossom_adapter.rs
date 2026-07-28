//! Adapter that drives Blossom's native active-active runtime in benchmarks.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroUsize;
use std::path::Path;
use std::time::{Duration, Instant};

use blossom::{
    ActiveActiveCommand, ActiveActiveConsistencyMode, AdmittedCommand, ApplyProgress,
    AvailabilityCertificate, AvailabilityTrust, BatchReference, BatchReferenceMetadata, Block,
    CommandBatch, CommandSpecVersion, ConsensusDriverConfig, ConsensusGroupId,
    DurableAdmissionStore, Epoch, GlobalOrderedEngine, HashType, HolderMembership,
    LocalAdmissionCertificate, LocalAdmissionPolicy, Nonce, QuorumSize, ReplicaMembershipEpoch,
    RouteGeneration, SimulatedCluster, SiteId, StoreGeneration, TcpNode, TcpNodeMetricsSnapshot,
    TcpServiceClient, Transaction, TrustMode, ValidatorGeneration, Watermark, WireRequest,
    WireResponse, find_round_number_with_size, ordered_batch_references,
    ordered_batch_references_trusted, supermajority_count,
};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::application::{CommandResult, SharedStateMachine, decode_result};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
const TRUSTED_DIRECT_COMMAND_DOMAIN: &[u8] = b"blossom/benchmark/trusted-direct-command/v1";
const VERIFIED_SIMULATION_WIDE_CLUSTER_MAX_CONNECTIONS: usize = 4;

fn verified_simulation_max_connections(participant_count: usize) -> NonZeroUsize {
    let peer_count = participant_count.saturating_sub(1).max(1);
    let limit = if participant_count <= 6 {
        peer_count
    } else {
        VERIFIED_SIMULATION_WIDE_CLUSTER_MAX_CONNECTIONS
    };
    NonZeroUsize::new(limit).expect("verified simulation pool size is non-zero")
}

/// A native Blossom TCP cluster used by the comparison harness.
///
/// The adapter submits availability-certified compact references at their
/// writers and empty blocks at the remaining validators before manually
/// driving consensus. This admission barrier makes universal-writer benchmark
/// epochs deterministic without weakening the protocol's quorum finality.
pub struct BlossomTcpOrderCluster {
    cluster: SimulatedCluster,
    drivers: Vec<TcpNode>,
    driver: ConsensusDriverConfig,
    finality_timeout: Duration,
    trust_mode: TrustMode,
    max_round: u8,
}

/// Protocol-core trusted Blossom with opaque commands carried directly in each
/// writer's unsigned block.
pub struct BlossomTrustedDirectCluster {
    order_cluster: BlossomTcpOrderCluster,
    state_machine: SharedStateMachine,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlossomNodeTraffic {
    pub connections: u64,
    pub requests: u64,
    pub responses: u64,
    pub errors: u64,
    pub handler_nanos: u64,
}

impl From<TcpNodeMetricsSnapshot> for BlossomNodeTraffic {
    fn from(metrics: TcpNodeMetricsSnapshot) -> Self {
        Self {
            connections: metrics.connections,
            requests: metrics.requests,
            responses: metrics.responses,
            errors: metrics.errors,
            handler_nanos: metrics.handler_nanos,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomFinalitySample {
    pub nonce: Nonce,
    pub epoch_hash: HashType,
    pub target_resolution_nanos: u64,
    pub blocks_submitted_nanos: u64,
    pub finalized_nanos: u64,
    pub finalized_nodes: usize,
    pub converged_nanos: Option<u64>,
    pub converged_nodes: usize,
    pub finalized_block_count: usize,
    pub reference_hash: HashType,
    pub reference_hashes: Vec<HashType>,
    pub node_traffic: Vec<BlossomNodeTraffic>,
}

/// Complete `AcceptedLocal` through `Applied` timings for one globally ordered
/// active-active command.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomAppliedSample {
    pub accepted_local_nanos: u64,
    pub available_nanos: u64,
    pub finalized_nanos: u64,
    pub applied_nanos: u64,
    pub converged_nanos: u64,
    pub watermark: Watermark,
    pub result: CommandResult,
    pub finality: BlossomFinalitySample,
    pub trusted_path: BlossomTrustedPathSample,
}

/// Barrier timings for one epoch containing one real block from every active
/// writer. Results follow the epoch's BTree block-hash order, not caller order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomUniversalWriterSample {
    pub active_writers: usize,
    pub accepted_local_nanos: u64,
    pub available_nanos: u64,
    pub finalized_nanos: u64,
    pub applied_nanos: u64,
    pub converged_nanos: u64,
    pub first_watermark: Watermark,
    pub last_watermark: Watermark,
    pub results: Vec<CommandResult>,
    pub finality: BlossomFinalitySample,
    pub trusted_path: BlossomTrustedPathSample,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomTrustedDirectSample {
    pub active_writers: usize,
    pub finalized_nanos: u64,
    pub applied_nanos: u64,
    pub converged_nanos: u64,
    pub command_prepare_nanos: u64,
    pub block_submission_nanos: u64,
    pub receipt_and_order_nanos: u64,
    pub apply_nanos: u64,
    pub convergence_nanos: u64,
    pub results: Vec<CommandResult>,
    pub finality: BlossomFinalitySample,
}

/// Non-overlapping trusted-mode stages and work amplification for one write.
///
/// The milestone fields on [`BlossomAppliedSample`] are cumulative from the
/// start of the write. These fields are individual stage durations, so their
/// sum explains end-to-end latency and exposes work that grows with the
/// validator or holder population.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomTrustedPathSample {
    pub command_prepare_nanos: u64,
    pub admission_replication_nanos: u64,
    pub accepted_transition_nanos: u64,
    pub reference_build_nanos: u64,
    pub availability_replication_nanos: u64,
    pub available_transition_nanos: u64,
    pub target_resolution_nanos: u64,
    pub block_submission_nanos: u64,
    pub receipt_and_order_nanos: u64,
    pub order_statement_nanos: u64,
    pub order_vote_nanos: u64,
    pub finalized_transition_nanos: u64,
    pub apply_nanos: u64,
    pub convergence_nanos: u64,
    pub origin_site_members: usize,
    pub admission_receipts: usize,
    pub availability_sites: usize,
    pub availability_receipts: usize,
    pub validator_block_submissions: usize,
    pub hierarchy_rounds: usize,
    pub finalized_nodes: usize,
    pub order_votes: usize,
    /// Immediate shard-stream commits issued by the benchmark path for this write.
    ///
    /// Independent replica commits run concurrently. This count still makes
    /// write amplification visible and separates batching gains from
    /// consensus gains.
    pub immediate_durable_commits: usize,
}

/// Complete trusted active-active Blossom stack for executable benchmarks.
///
/// A configured subset of validators also serves as three-site data holders.
/// The default uses every validator for the equal-footprint baseline. The
/// driver exercises durable admission, availability certification, native TCP
/// trusted block receipt/order, and state-machine apply.
pub struct BlossomActiveActiveCluster {
    order_cluster: BlossomTcpOrderCluster,
    stores: Vec<DurableAdmissionStore>,
    holder_indices_by_site: BTreeMap<SiteId, Vec<usize>>,
    engine: GlobalOrderedEngine,
    application: SharedStateMachine,
    membership_epoch: ReplicaMembershipEpoch,
    validator_generation: ValidatorGeneration,
    next_origin_sequences: Vec<u64>,
    previous_origin_reference_hashes: Vec<HashType>,
}

mod active_cluster;
mod order_cluster;
mod trusted_cluster;

fn elapsed_nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn traffic_delta(
    before: &[BlossomNodeTraffic],
    after: &[BlossomNodeTraffic],
) -> Vec<BlossomNodeTraffic> {
    after
        .iter()
        .enumerate()
        .map(|(index, after)| {
            let before = before.get(index).copied().unwrap_or_default();
            BlossomNodeTraffic {
                connections: after.connections.saturating_sub(before.connections),
                requests: after.requests.saturating_sub(before.requests),
                responses: after.responses.saturating_sub(before.responses),
                errors: after.errors.saturating_sub(before.errors),
                handler_nanos: after.handler_nanos.saturating_sub(before.handler_nanos),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
