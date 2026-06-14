#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use blossom::algorithm::{select_quorums, supermajority_count};
use blossom::{
    Block, ConsensusGroupId, DoHash, FutureRoundAssistDecision, HashType, Keypair, Nonce, PubKey,
    Result, SecKey, TelemetryEvent, TelemetryHandle, Transaction, TrustMode,
    skipped_round_assist_decision,
};

use crate::chaos::CHAOS_RATE_DENOMINATOR;
use crate::data::splitmix64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochChaosConfig {
    pub seed: u64,
    pub nodes: usize,
    pub epochs: usize,
    pub transactions_per_node: usize,
    pub transaction_bytes: usize,
    pub latency_ms: u64,
    pub jitter_ms: u64,
    pub round_timeout_ms: u64,
    pub drop_ppm: u32,
    pub fuzz_ppm: u32,
    pub spike_ppm: u32,
    pub spike_latency_ms: u64,
    pub repair_rounds: usize,
    pub repair_fanout: usize,
    pub repair_quorum: usize,
    pub repair_timeout_ms: u64,
    pub faulty_nodes: usize,
    pub byzantine_nodes: usize,
    pub byzantine_reconnect_replay_ppm: u32,
    pub byzantine_reconnect_stale_proof_ppm: u32,
    pub byzantine_reconnect_sybil_ppm: u32,
    pub byzantine_duplicate_vote_copies: usize,
    pub drop_faulty_after_epochs: usize,
    pub max_dropped_nodes_per_epoch: usize,
    pub min_active_nodes: usize,
    pub reconnect_dropped_after_epochs: usize,
    pub reconnect_ping_fanout: usize,
    pub reconnect_ping_quorum: usize,
    pub reconnect_approval_quorum: usize,
    pub reconnect_timeout_ms: u64,
    pub max_reconnected_nodes_per_epoch: usize,
    pub partition_start_epoch: Option<usize>,
    pub partition_end_epoch: Option<usize>,
    pub partition_left_nodes: usize,
    pub partition_reconnect_only: bool,
    pub assist_after_skipped_round: Option<usize>,
    pub trust_mode: TrustMode,
    pub shuffle: bool,
}

impl Default for EpochChaosConfig {
    fn default() -> Self {
        Self {
            seed: 0x6570_6f63_685f_6368,
            nodes: 36,
            epochs: 4,
            transactions_per_node: 16,
            transaction_bytes: 32,
            latency_ms: 1,
            jitter_ms: 0,
            round_timeout_ms: 0,
            drop_ppm: 0,
            fuzz_ppm: 0,
            spike_ppm: 0,
            spike_latency_ms: 0,
            repair_rounds: 0,
            repair_fanout: 0,
            repair_quorum: 0,
            repair_timeout_ms: 500,
            faulty_nodes: 0,
            byzantine_nodes: 0,
            byzantine_reconnect_replay_ppm: 0,
            byzantine_reconnect_stale_proof_ppm: 0,
            byzantine_reconnect_sybil_ppm: 0,
            byzantine_duplicate_vote_copies: 0,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 1,
            reconnect_dropped_after_epochs: 0,
            reconnect_ping_fanout: 0,
            reconnect_ping_quorum: 0,
            reconnect_approval_quorum: 0,
            reconnect_timeout_ms: 500,
            max_reconnected_nodes_per_epoch: 1,
            partition_start_epoch: None,
            partition_end_epoch: None,
            partition_left_nodes: 0,
            partition_reconnect_only: false,
            assist_after_skipped_round: None,
            trust_mode: TrustMode::Verified,
            shuffle: false,
        }
    }
}

impl EpochChaosConfig {
    pub fn validate(&self) -> Result<()> {
        if self.nodes == 0 {
            return Err(blossom::BlossomError::WireProtocol(
                "epoch chaos simulation requires at least one node".to_string(),
            ));
        }
        if self.epochs == 0 {
            return Err(blossom::BlossomError::WireProtocol(
                "epoch chaos simulation requires at least one epoch".to_string(),
            ));
        }
        if self.faulty_nodes > self.nodes {
            return Err(blossom::BlossomError::WireProtocol(format!(
                "faulty_nodes ({}) must be <= nodes ({})",
                self.faulty_nodes, self.nodes
            )));
        }
        if self.byzantine_nodes > self.nodes {
            return Err(blossom::BlossomError::WireProtocol(format!(
                "byzantine_nodes ({}) must be <= nodes ({})",
                self.byzantine_nodes, self.nodes
            )));
        }
        if self.faulty_nodes + self.byzantine_nodes > self.nodes {
            return Err(blossom::BlossomError::WireProtocol(format!(
                "faulty_nodes + byzantine_nodes ({}) must be <= nodes ({})",
                self.faulty_nodes + self.byzantine_nodes,
                self.nodes
            )));
        }
        if self.trust_mode.is_trusted() {
            if self.byzantine_nodes > 0
                || self.byzantine_reconnect_replay_ppm > 0
                || self.byzantine_reconnect_stale_proof_ppm > 0
                || self.byzantine_reconnect_sybil_ppm > 0
                || self.byzantine_duplicate_vote_copies > 0
            {
                return Err(blossom::BlossomError::WireProtocol(
                    "trusted mode models accidental faults; Byzantine attack knobs require verified/trustless mode".to_string(),
                ));
            }
        } else if self.byzantine_nodes > self.max_byzantine_nodes_for_safety() {
            return Err(blossom::BlossomError::WireProtocol(format!(
                "trustless mode supports at most {} Byzantine nodes for {} validators; got {}",
                self.max_byzantine_nodes_for_safety(),
                self.nodes,
                self.byzantine_nodes
            )));
        }
        if self.min_active_nodes == 0 || self.min_active_nodes > self.nodes {
            return Err(blossom::BlossomError::WireProtocol(format!(
                "min_active_nodes ({}) must be between 1 and nodes ({})",
                self.min_active_nodes, self.nodes
            )));
        }
        for (label, value) in [
            ("drop_ppm", self.drop_ppm),
            ("fuzz_ppm", self.fuzz_ppm),
            ("spike_ppm", self.spike_ppm),
            (
                "byzantine_reconnect_replay_ppm",
                self.byzantine_reconnect_replay_ppm,
            ),
            (
                "byzantine_reconnect_stale_proof_ppm",
                self.byzantine_reconnect_stale_proof_ppm,
            ),
            (
                "byzantine_reconnect_sybil_ppm",
                self.byzantine_reconnect_sybil_ppm,
            ),
        ] {
            if value > CHAOS_RATE_DENOMINATOR {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "{label} must be <= {CHAOS_RATE_DENOMINATOR}"
                )));
            }
        }
        if self.partition_end_epoch.is_some() && self.partition_start_epoch.is_none() {
            return Err(blossom::BlossomError::WireProtocol(
                "partition_end_epoch requires partition_start_epoch".to_string(),
            ));
        }
        if let Some(start) = self.partition_start_epoch {
            let Some(end) = self.partition_end_epoch else {
                return Err(blossom::BlossomError::WireProtocol(
                    "partition_start_epoch requires partition_end_epoch".to_string(),
                ));
            };
            if end <= start {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "partition_end_epoch ({end}) must be greater than partition_start_epoch ({start})"
                )));
            }
            let left_nodes = self.effective_partition_left_nodes();
            if left_nodes == 0 || left_nodes >= self.nodes {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "partition_left_nodes ({left_nodes}) must split the network into two non-empty sides"
                )));
            }
        }
        if self.repair_rounds > 0 {
            let max_peers = self.nodes.saturating_sub(1);
            let fanout = self.effective_repair_fanout();
            let quorum = self.effective_repair_quorum();
            let trustless_repair_quorum = supermajority_count(self.nodes);
            if fanout == 0 {
                return Err(blossom::BlossomError::WireProtocol(
                    "repair requires at least two nodes".to_string(),
                ));
            }
            if quorum > fanout {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "repair_quorum ({quorum}) must be <= effective repair_fanout ({fanout}); max fanout is nodes - 1 ({max_peers})"
                )));
            }
            if !self.trust_mode.is_trusted() && quorum < trustless_repair_quorum {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "trustless repair_quorum ({quorum}) must be >= Byzantine-safe supermajority ({trustless_repair_quorum})"
                )));
            }
            if !self.trust_mode.is_trusted()
                && self.byzantine_nodes > 0
                && quorum <= self.byzantine_nodes
            {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "trustless repair_quorum ({quorum}) must exceed possible Byzantine repair responders ({})",
                    self.byzantine_nodes
                )));
            }
        }
        if self.reconnect_dropped_after_epochs > 0 && self.max_reconnected_nodes_per_epoch > 0 {
            let max_peers = self.nodes.saturating_sub(1);
            let ping_fanout = self.effective_reconnect_ping_fanout_for(max_peers);
            let ping_quorum = self.effective_reconnect_ping_quorum_for(max_peers);
            let approval_quorum = self.effective_reconnect_approval_quorum_for(max_peers);
            let trustless_reconnect_quorum = supermajority_count(max_peers);
            if max_peers == 0 || ping_fanout == 0 {
                return Err(blossom::BlossomError::WireProtocol(
                    "reconnect requires at least two nodes".to_string(),
                ));
            }
            if ping_quorum > ping_fanout {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "reconnect_ping_quorum ({ping_quorum}) must be <= effective reconnect_ping_fanout ({ping_fanout}); max fanout is active peers ({max_peers})"
                )));
            }
            if approval_quorum > max_peers {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "reconnect_approval_quorum ({approval_quorum}) must be <= active peers ({max_peers})"
                )));
            }
            if !self.trust_mode.is_trusted() && ping_quorum < trustless_reconnect_quorum {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "trustless reconnect_ping_quorum ({ping_quorum}) must be >= Byzantine-safe supermajority ({trustless_reconnect_quorum})"
                )));
            }
            if !self.trust_mode.is_trusted() && approval_quorum < trustless_reconnect_quorum {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "trustless reconnect_approval_quorum ({approval_quorum}) must be >= Byzantine-safe supermajority ({trustless_reconnect_quorum})"
                )));
            }
            let max_byzantine_voters = self.byzantine_nodes.min(max_peers);
            if self.byzantine_nodes > 0 && ping_quorum <= max_byzantine_voters {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "reconnect_ping_quorum ({ping_quorum}) must exceed possible Byzantine responders ({max_byzantine_voters})"
                )));
            }
            if self.byzantine_nodes > 0 && approval_quorum <= max_byzantine_voters {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "reconnect_approval_quorum ({approval_quorum}) must exceed possible Byzantine voters ({max_byzantine_voters})"
                )));
            }
        }
        Ok(())
    }

    fn effective_repair_fanout(&self) -> usize {
        self.effective_repair_fanout_for(self.nodes)
    }

    fn effective_repair_fanout_for(&self, nodes: usize) -> usize {
        if self.repair_fanout == 0 {
            nodes.saturating_sub(1)
        } else {
            self.repair_fanout.min(nodes.saturating_sub(1))
        }
    }

    fn effective_repair_quorum(&self) -> usize {
        self.effective_repair_quorum_for(self.nodes)
    }

    fn effective_repair_quorum_for(&self, nodes: usize) -> usize {
        if self.repair_quorum == 0 {
            supermajority_count(nodes)
        } else {
            self.repair_quorum
        }
    }

    fn effective_reconnect_ping_fanout_for(&self, active_peers: usize) -> usize {
        if self.reconnect_ping_fanout == 0 {
            active_peers
        } else {
            self.reconnect_ping_fanout.min(active_peers)
        }
    }

    fn effective_reconnect_ping_quorum_for(&self, active_peers: usize) -> usize {
        if self.reconnect_ping_quorum == 0 {
            supermajority_count(active_peers)
        } else {
            self.reconnect_ping_quorum
        }
    }

    fn effective_reconnect_approval_quorum_for(&self, active_peers: usize) -> usize {
        if self.reconnect_approval_quorum == 0 {
            supermajority_count(active_peers)
        } else {
            self.reconnect_approval_quorum
        }
    }

    pub fn max_byzantine_nodes_for_safety(&self) -> usize {
        max_byzantine_nodes_for_safety(self.nodes)
    }

    fn effective_partition_left_nodes(&self) -> usize {
        if self.partition_left_nodes == 0 {
            self.nodes / 2
        } else {
            self.partition_left_nodes
        }
    }

    fn partition_blocks_transport(
        &self,
        phase: u64,
        epoch: usize,
        sender: usize,
        recipient: usize,
    ) -> bool {
        let Some(start) = self.partition_start_epoch else {
            return false;
        };
        let Some(end) = self.partition_end_epoch else {
            return false;
        };
        if epoch < start || epoch >= end {
            return false;
        }
        if self.partition_reconnect_only && !matches!(phase, 4..=6) {
            return false;
        }
        let left_nodes = self.effective_partition_left_nodes();
        (sender < left_nodes) != (recipient < left_nodes)
    }
}

fn quorum_message_edges(quorums: &[Vec<usize>]) -> u64 {
    quorums
        .iter()
        .map(|quorum| quorum.len().saturating_mul(quorum.len().saturating_sub(1)) as u64)
        .sum()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochChaosReport {
    pub config: EpochChaosConfig,
    pub node_keys: Vec<PubKey>,
    pub epochs: Vec<EpochChaosEpochReport>,
    pub stage_progress: Vec<EpochStageProgressRecord>,
    pub total_messages: u64,
    pub delivered_messages: u64,
    pub dropped_messages: u64,
    pub fuzzed_messages: u64,
    pub late_messages: u64,
    pub spiked_messages: u64,
    pub repair_attempts: u64,
    pub repair_successes: u64,
    pub reconnect_attempts: u64,
    pub reconnect_approvals: u64,
    pub reconnect_catchup_proofs: u64,
    pub reconnect_replays: u64,
    pub reconnect_stale_proofs: u64,
    pub reconnect_duplicate_votes: u64,
    pub reconnect_identity_rejections: u64,
    pub reconnect_successes: u64,
    pub block_transfer_attempts: u64,
    pub accepted_blocks: u64,
    pub denied_blocks: u64,
    pub accepted_block_bytes: u64,
    pub denied_block_bytes: u64,
    pub future_round_assists: u64,
    pub future_round_skipped_messages: u64,
    pub future_round_dropped_local_blocks: u64,
    pub future_round_carried_forward_blocks: u64,
    pub max_byzantine_nodes_for_safety: usize,
    pub byzantine_tolerance_exceeded: bool,
    pub final_active_nodes: usize,
    pub final_dropped_nodes: usize,
    pub dropped_node_keys: Vec<PubKey>,
    pub reconnected_node_keys: Vec<PubKey>,
    pub byzantine_node_keys: Vec<PubKey>,
    pub final_correct_nodes: usize,
    pub final_incorrect_nodes: usize,
    pub final_data_available_nodes: usize,
    pub final_data_unavailable_nodes: usize,
    pub final_unique_epoch_hashes: usize,
    pub final_correct_epoch_hash: HashType,
    pub final_correct_epoch_nonce: Nonce,
    pub valid_local_blocks: u64,
    pub intentionally_dropped_local_blocks: u64,
    pub incorrectly_lost_local_blocks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochReconciliationCheck {
    pub divergent_epochs: usize,
    pub reconciliation_epochs: usize,
    pub reconciled_nodes: usize,
    pub final_active_nodes: usize,
    pub final_dropped_nodes: usize,
    pub final_correct_nodes: usize,
    pub final_data_available_nodes: usize,
    pub final_data_unavailable_nodes: usize,
    pub final_unique_epoch_hashes: usize,
}

impl EpochChaosReport {
    pub fn check_runtime_reconciliation(&self) -> Result<EpochReconciliationCheck> {
        let divergent_epochs = self
            .epochs
            .iter()
            .filter(|epoch| epoch.pre_repair_correct_nodes < epoch.active_nodes)
            .collect::<Vec<_>>();
        if divergent_epochs.is_empty() {
            return Err(blossom::BlossomError::WireProtocol(
                "runtime reconciliation check did not exercise a divergent epoch".to_string(),
            ));
        }

        for epoch in &divergent_epochs {
            let eventually_reconciled = self.epochs.iter().any(|candidate| {
                candidate.epoch >= epoch.epoch
                    && candidate.nonce == epoch.nonce
                    && candidate.canonical_epoch_hash == epoch.canonical_epoch_hash
                    && candidate.correct_nodes == candidate.active_nodes
                    && candidate.incorrect_nodes == 0
                    && candidate.unique_epoch_hashes == 1
            });
            if !eventually_reconciled {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "runtime reconciliation failed for epoch {}: correct_nodes={}, incorrect_nodes={}, unique_epoch_hashes={}",
                    epoch.epoch,
                    epoch.correct_nodes,
                    epoch.incorrect_nodes,
                    epoch.unique_epoch_hashes
                )));
            }
        }

        let reconciliation_epochs = self
            .stage_progress
            .iter()
            .filter(|record| {
                record.stage == "reconciliation"
                    && record.event == "block_set_round"
                    && record.messages.repair_attempts > 0
            })
            .map(|record| record.epoch)
            .collect::<BTreeSet<_>>();
        if reconciliation_epochs.is_empty() {
            return Err(blossom::BlossomError::WireProtocol(
                "runtime reconciliation check did not execute reconciliation rounds".to_string(),
            ));
        }

        let reconciled_nodes = self
            .stage_progress
            .iter()
            .filter(|record| record.stage == "reconciliation")
            .map(|record| record.repaired_nodes)
            .sum::<usize>();
        if reconciled_nodes == 0 {
            return Err(blossom::BlossomError::WireProtocol(
                "runtime reconciliation check did not repair any nodes through reconciliation"
                    .to_string(),
            ));
        }

        if self.final_correct_nodes != self.final_active_nodes
            || self.final_incorrect_nodes != 0
            || self.final_data_available_nodes != self.final_correct_nodes
            || self.final_data_unavailable_nodes != 0
            || self.incorrectly_lost_local_blocks != 0
            || self.final_unique_epoch_hashes != 1
        {
            return Err(blossom::BlossomError::WireProtocol(format!(
                "runtime reconciliation check failed final convergence: final_correct_nodes={}, final_incorrect_nodes={}, final_data_available_nodes={}, final_data_unavailable_nodes={}, incorrectly_lost_local_blocks={}, final_unique_epoch_hashes={}",
                self.final_correct_nodes,
                self.final_incorrect_nodes,
                self.final_data_available_nodes,
                self.final_data_unavailable_nodes,
                self.incorrectly_lost_local_blocks,
                self.final_unique_epoch_hashes
            )));
        }

        Ok(EpochReconciliationCheck {
            divergent_epochs: divergent_epochs.len(),
            reconciliation_epochs: reconciliation_epochs.len(),
            reconciled_nodes,
            final_active_nodes: self.final_active_nodes,
            final_dropped_nodes: self.final_dropped_nodes,
            final_correct_nodes: self.final_correct_nodes,
            final_data_available_nodes: self.final_data_available_nodes,
            final_data_unavailable_nodes: self.final_data_unavailable_nodes,
            final_unique_epoch_hashes: self.final_unique_epoch_hashes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochChaosEpochReport {
    pub epoch: usize,
    pub nonce: Nonce,
    pub start_active_nodes: usize,
    pub start_dropped_nodes: usize,
    pub active_nodes: usize,
    pub dropped_nodes: usize,
    pub reconnected_nodes: usize,
    pub correct_start_nodes: usize,
    pub correct_nodes: usize,
    pub incorrect_nodes: usize,
    pub data_available_nodes: usize,
    pub data_unavailable_nodes: usize,
    pub unique_epoch_hashes: usize,
    pub min_blocks_per_node: usize,
    pub max_blocks_per_node: usize,
    pub valid_local_blocks: usize,
    pub intentionally_dropped_local_blocks: usize,
    pub incorrectly_lost_local_blocks: usize,
    pub canonical_blocks: usize,
    pub canonical_epoch_hash: HashType,
    pub pre_repair_correct_nodes: usize,
    pub repaired_nodes: usize,
    pub messages: EpochTransportTotals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochStageProgressRecord {
    pub epoch: usize,
    pub nonce: Nonce,
    pub round: Option<usize>,
    pub stage: &'static str,
    pub event: &'static str,
    pub nodes: usize,
    pub dropped_nodes: usize,
    pub reconnected_nodes: usize,
    pub quorums: usize,
    pub correct_nodes: usize,
    pub incorrect_nodes: usize,
    pub data_available_nodes: usize,
    pub data_unavailable_nodes: usize,
    pub unique_epoch_hashes: usize,
    pub canonical_blocks: usize,
    pub min_blocks_per_node: usize,
    pub max_blocks_per_node: usize,
    pub repaired_nodes: usize,
    pub canonical_epoch_hash: HashType,
    pub messages: EpochTransportTotals,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EpochTransportTotals {
    pub total: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub fuzzed: u64,
    pub late: u64,
    pub spiked: u64,
    pub repair_attempts: u64,
    pub repair_successes: u64,
    pub reconnect_attempts: u64,
    pub reconnect_approvals: u64,
    pub reconnect_catchup_proofs: u64,
    pub reconnect_replays: u64,
    pub reconnect_stale_proofs: u64,
    pub reconnect_duplicate_votes: u64,
    pub reconnect_identity_rejections: u64,
    pub reconnect_successes: u64,
    pub block_transfer_attempts: u64,
    pub accepted_blocks: u64,
    pub denied_blocks: u64,
    pub accepted_block_bytes: u64,
    pub denied_block_bytes: u64,
    pub future_round_assists: u64,
    pub future_round_skipped_messages: u64,
    pub future_round_dropped_local_blocks: u64,
    pub future_round_carried_forward_blocks: u64,
}

#[derive(Debug, Clone)]
struct BenchNode {
    keypair: Keypair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct NodeEpochState {
    last_epoch: HashType,
    nonce: Nonce,
}

#[derive(Debug, Clone)]
struct PendingEpochReconciliation {
    nonce: Nonce,
    canonical_hash: HashType,
    canonical_blocks: usize,
    canonical_block_sources: BTreeSet<usize>,
    expected_canonical_block_hashes: BTreeSet<HashType>,
    canonical_data_holders: BTreeSet<usize>,
    canonical_block_replicas: BTreeMap<HashType, BTreeSet<usize>>,
    valid_local_blocks: usize,
    intentionally_dropped_local_blocks: usize,
    min_blocks_per_node: usize,
    max_blocks_per_node: usize,
}

struct EpochTelemetryEmitter {
    handle: Option<TelemetryHandle>,
    next_span_ids: BTreeMap<PubKey, u64>,
}

struct EpochTelemetrySpan {
    stage: &'static str,
    event: &'static str,
    node_span_ids: Vec<(PubKey, u64)>,
}

impl EpochTelemetryEmitter {
    fn disabled(node_keys: &[PubKey]) -> Self {
        Self {
            handle: None,
            next_span_ids: node_keys.iter().map(|node| (*node, 1)).collect(),
        }
    }

    fn enabled(node_keys: &[PubKey], handle: TelemetryHandle) -> Self {
        Self {
            handle: Some(handle),
            next_span_ids: node_keys.iter().map(|node| (*node, 1)).collect(),
        }
    }

    fn start_stage(
        &mut self,
        node_keys: &[PubKey],
        _epoch: usize,
        _nonce: Nonce,
        round: Option<usize>,
        stage: &'static str,
        event: &'static str,
        _nodes: usize,
    ) -> Option<EpochTelemetrySpan> {
        let handle = self.handle.as_ref()?;
        let timestamp = current_timestamp_micros();
        let mut node_span_ids = Vec::with_capacity(node_keys.len());
        for node in node_keys {
            let next_span_id = self.next_span_ids.entry(*node).or_insert(1);
            let span_id = *next_span_id;
            *next_span_id += 1;
            node_span_ids.push((*node, span_id));
            let mut telemetry =
                TelemetryEvent::span_start_with_timestamp_micros(span_id, stage, event, timestamp)
                    .with_node(*node)
                    .with_group_id(ConsensusGroupId::root());
            telemetry = match round.and_then(|round| u8::try_from(round).ok()) {
                Some(round) => telemetry.with_round(round),
                None => telemetry,
            };
            handle.record(telemetry);
        }
        Some(EpochTelemetrySpan {
            stage,
            event,
            node_span_ids,
        })
    }

    fn finish_stage(&self, span: Option<EpochTelemetrySpan>, record: &EpochStageProgressRecord) {
        let (Some(handle), Some(span)) = (self.handle.as_ref(), span) else {
            return;
        };
        handle.record(stage_metric_event(record));
        let timestamp = current_timestamp_micros();
        for (node, span_id) in span.node_span_ids {
            let mut telemetry = TelemetryEvent::span_end_with_timestamp_micros(
                span_id, span.stage, span.event, timestamp,
            )
            .with_node(node)
            .with_group_id(ConsensusGroupId::root())
            .with_target(record.canonical_epoch_hash, record.nonce);
            telemetry = match record.round.and_then(|round| u8::try_from(round).ok()) {
                Some(round) => telemetry.with_round(round),
                None => telemetry,
            };
            handle.record(telemetry);
        }
    }

    fn emit_node_dropped(
        &self,
        epoch: usize,
        nonce: Nonce,
        canonical_hash: HashType,
        node: PubKey,
        active_nodes: usize,
        dropped_nodes: usize,
    ) {
        let Some(handle) = self.handle.as_ref() else {
            return;
        };
        handle.record(
            TelemetryEvent::new_with_timestamp_micros(
                blossom::TelemetryEventKind::Event,
                "membership_pruning",
                "node_dropped",
                current_timestamp_micros(),
            )
            .with_node(node)
            .with_group_id(ConsensusGroupId::root())
            .with_outcome("dropped")
            .with_field("epoch", epoch.to_string())
            .with_field("active_nodes", active_nodes.to_string())
            .with_field("dropped_nodes", dropped_nodes.to_string())
            .with_target(canonical_hash, nonce),
        );
    }

    fn emit_node_reconnected(
        &self,
        epoch: usize,
        nonce: Nonce,
        canonical_hash: HashType,
        node: PubKey,
        active_nodes: usize,
        dropped_nodes: usize,
        ping_responses: usize,
        catchup_proofs: usize,
        approvals: usize,
    ) {
        let Some(handle) = self.handle.as_ref() else {
            return;
        };
        handle.record(
            TelemetryEvent::new_with_timestamp_micros(
                blossom::TelemetryEventKind::Event,
                "membership_reconnect",
                "node_reconnected",
                current_timestamp_micros(),
            )
            .with_node(node)
            .with_group_id(ConsensusGroupId::root())
            .with_outcome("reconnected")
            .with_field("epoch", epoch.to_string())
            .with_field("active_nodes", active_nodes.to_string())
            .with_field("dropped_nodes", dropped_nodes.to_string())
            .with_field("ping_responses", ping_responses.to_string())
            .with_field("catchup_proofs", catchup_proofs.to_string())
            .with_field("approvals", approvals.to_string())
            .with_target(canonical_hash, nonce),
        );
    }
}

fn stage_metric_event(record: &EpochStageProgressRecord) -> TelemetryEvent {
    let mut event = TelemetryEvent::new_with_timestamp_micros(
        blossom::TelemetryEventKind::Event,
        record.stage,
        format!("{}_metrics", record.event),
        current_timestamp_micros(),
    )
    .with_group_id(ConsensusGroupId::root())
    .with_outcome(if record.incorrect_nodes == 0 {
        "ok"
    } else {
        "partial"
    })
    .with_field("epoch", record.epoch.to_string())
    .with_field("nodes", record.nodes.to_string())
    .with_field("dropped_nodes", record.dropped_nodes.to_string())
    .with_field("quorums", record.quorums.to_string())
    .with_field("correct_nodes", record.correct_nodes.to_string())
    .with_field("incorrect_nodes", record.incorrect_nodes.to_string())
    .with_field(
        "data_available_nodes",
        record.data_available_nodes.to_string(),
    )
    .with_field(
        "data_unavailable_nodes",
        record.data_unavailable_nodes.to_string(),
    )
    .with_field(
        "unique_epoch_hashes",
        record.unique_epoch_hashes.to_string(),
    )
    .with_field("canonical_blocks", record.canonical_blocks.to_string())
    .with_field(
        "min_blocks_per_node",
        record.min_blocks_per_node.to_string(),
    )
    .with_field(
        "max_blocks_per_node",
        record.max_blocks_per_node.to_string(),
    )
    .with_field("repaired_nodes", record.repaired_nodes.to_string())
    .with_field("reconnected_nodes", record.reconnected_nodes.to_string())
    .with_field("total_messages", record.messages.total.to_string())
    .with_field("delivered", record.messages.delivered.to_string())
    .with_field("dropped", record.messages.dropped.to_string())
    .with_field("fuzzed", record.messages.fuzzed.to_string())
    .with_field("late", record.messages.late.to_string())
    .with_field("spiked", record.messages.spiked.to_string())
    .with_field(
        "repair_attempts",
        record.messages.repair_attempts.to_string(),
    )
    .with_field(
        "repair_successes",
        record.messages.repair_successes.to_string(),
    )
    .with_field(
        "reconnect_attempts",
        record.messages.reconnect_attempts.to_string(),
    )
    .with_field(
        "reconnect_approvals",
        record.messages.reconnect_approvals.to_string(),
    )
    .with_field(
        "reconnect_catchup_proofs",
        record.messages.reconnect_catchup_proofs.to_string(),
    )
    .with_field(
        "reconnect_replays",
        record.messages.reconnect_replays.to_string(),
    )
    .with_field(
        "reconnect_stale_proofs",
        record.messages.reconnect_stale_proofs.to_string(),
    )
    .with_field(
        "reconnect_duplicate_votes",
        record.messages.reconnect_duplicate_votes.to_string(),
    )
    .with_field(
        "reconnect_identity_rejections",
        record.messages.reconnect_identity_rejections.to_string(),
    )
    .with_field(
        "reconnect_successes",
        record.messages.reconnect_successes.to_string(),
    )
    .with_field(
        "block_transfer_attempts",
        record.messages.block_transfer_attempts.to_string(),
    )
    .with_field(
        "accepted_blocks",
        record.messages.accepted_blocks.to_string(),
    )
    .with_field("denied_blocks", record.messages.denied_blocks.to_string())
    .with_field(
        "accepted_block_bytes",
        record.messages.accepted_block_bytes.to_string(),
    )
    .with_field(
        "denied_block_bytes",
        record.messages.denied_block_bytes.to_string(),
    )
    .with_field(
        "future_round_assists",
        record.messages.future_round_assists.to_string(),
    )
    .with_field(
        "future_round_skipped_messages",
        record.messages.future_round_skipped_messages.to_string(),
    )
    .with_field(
        "future_round_dropped_local_blocks",
        record
            .messages
            .future_round_dropped_local_blocks
            .to_string(),
    )
    .with_field(
        "future_round_carried_forward_blocks",
        record
            .messages
            .future_round_carried_forward_blocks
            .to_string(),
    )
    .with_target(record.canonical_epoch_hash, record.nonce);
    event = match record.round.and_then(|round| u8::try_from(round).ok()) {
        Some(round) => event.with_round(round),
        None => event,
    };
    event
}

fn push_stage_progress(
    stage_progress: &mut Vec<EpochStageProgressRecord>,
    telemetry: &EpochTelemetryEmitter,
    span: Option<EpochTelemetrySpan>,
    record: EpochStageProgressRecord,
) {
    telemetry.finish_stage(span, &record);
    stage_progress.push(record);
}

fn current_timestamp_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros())
        .unwrap_or_default()
}

pub fn run_epoch_chaos(config: EpochChaosConfig) -> Result<EpochChaosReport> {
    run_epoch_chaos_inner(config, None)
}

pub fn run_epoch_chaos_with_telemetry(
    config: EpochChaosConfig,
    telemetry: TelemetryHandle,
) -> Result<EpochChaosReport> {
    run_epoch_chaos_inner(config, Some(telemetry))
}

fn run_epoch_chaos_inner(
    config: EpochChaosConfig,
    telemetry: Option<TelemetryHandle>,
) -> Result<EpochChaosReport> {
    config.validate()?;
    let nodes = build_nodes(config.nodes, config.seed);
    let keys = nodes
        .iter()
        .map(|node| node.keypair.public)
        .collect::<Vec<_>>();
    let mut states = vec![
        NodeEpochState {
            last_epoch: HashType::default(),
            nonce: Nonce::default(),
        };
        config.nodes
    ];
    let mut canonical_last_epoch = HashType::default();
    let mut canonical_nonce = Nonce::default();
    let mut transport = TransportSampler::new(config.clone());
    let mut epoch_reports = Vec::with_capacity(config.epochs);
    let mut stage_progress = Vec::new();
    let mut telemetry = match telemetry {
        Some(handle) => EpochTelemetryEmitter::enabled(&keys, handle),
        None => EpochTelemetryEmitter::disabled(&keys),
    };
    let faulty_node_indexes =
        select_faulty_node_indexes(config.nodes, config.faulty_nodes, config.seed);
    let byzantine_node_indexes = select_byzantine_node_indexes(
        config.nodes,
        config.byzantine_nodes,
        config.seed,
        &faulty_node_indexes,
    );
    let byzantine_node_keys = byzantine_node_indexes
        .iter()
        .map(|index| keys[*index])
        .collect::<Vec<_>>();
    let mut active = vec![true; config.nodes];
    let mut dropped_since_epoch = vec![None; config.nodes];
    let mut recovered_node_indexes = BTreeSet::new();
    let mut dropped_node_keys = Vec::new();
    let mut reconnected_node_keys = Vec::new();
    let mut pending_reconciliation: Option<PendingEpochReconciliation> = None;
    let mut latest_canonical_data_holders = (0..config.nodes).collect::<BTreeSet<_>>();

    for epoch in 0..config.epochs {
        let active_indices = collect_active_indices(&active);
        let active_node_keys = collect_active_node_keys(&keys, &active_indices);
        let active_nodes = active_indices.len();
        let dropped_nodes = config.nodes.saturating_sub(active_nodes);
        if let Some(pending) = pending_reconciliation.clone() {
            let mut canonical_data_holders = pending
                .canonical_data_holders
                .iter()
                .copied()
                .filter(|index| active.get(*index).copied().unwrap_or(false))
                .collect::<BTreeSet<_>>();
            let mut canonical_block_replicas = pending.canonical_block_replicas.clone();
            retain_active_replicas(&mut canonical_block_replicas, &active);
            let correct_start_nodes = count_active_correct(
                &states,
                &active_indices,
                pending.canonical_hash,
                pending.nonce,
            );
            if correct_start_nodes < active_nodes {
                let mut totals = EpochTransportTotals::default();
                let repaired_nodes = repair_epoch(
                    &config,
                    &mut transport,
                    epoch,
                    pending.nonce,
                    &mut states,
                    pending.canonical_hash,
                    &mut totals,
                    &mut stage_progress,
                    pending.canonical_blocks,
                    &pending.canonical_block_sources,
                    &mut canonical_data_holders,
                    &mut canonical_block_replicas,
                    pending.min_blocks_per_node,
                    pending.max_blocks_per_node,
                    &active_indices,
                    &active_node_keys,
                    dropped_nodes,
                    &mut telemetry,
                );
                let correct_nodes = count_active_correct(
                    &states,
                    &active_indices,
                    pending.canonical_hash,
                    pending.nonce,
                );
                let unique_epoch_hashes = unique_active_epoch_hashes(&states, &active_indices);
                let data_available_nodes = count_active_data_available(
                    &states,
                    &active_indices,
                    pending.canonical_hash,
                    pending.nonce,
                    &canonical_data_holders,
                );

                let incorrectly_lost_local_blocks = count_incorrectly_lost_local_blocks(
                    &pending.expected_canonical_block_hashes,
                    &canonical_block_replicas,
                );

                epoch_reports.push(EpochChaosEpochReport {
                    epoch,
                    nonce: pending.nonce,
                    start_active_nodes: active_nodes,
                    start_dropped_nodes: dropped_nodes,
                    active_nodes,
                    dropped_nodes,
                    reconnected_nodes: 0,
                    correct_start_nodes,
                    correct_nodes,
                    incorrect_nodes: active_nodes.saturating_sub(correct_nodes),
                    data_available_nodes,
                    data_unavailable_nodes: data_unavailable_nodes(
                        active_nodes,
                        data_available_nodes,
                    ),
                    unique_epoch_hashes,
                    min_blocks_per_node: pending.min_blocks_per_node,
                    max_blocks_per_node: pending.max_blocks_per_node,
                    valid_local_blocks: pending.valid_local_blocks,
                    intentionally_dropped_local_blocks: pending.intentionally_dropped_local_blocks,
                    incorrectly_lost_local_blocks,
                    canonical_blocks: pending.canonical_blocks,
                    canonical_epoch_hash: pending.canonical_hash,
                    pre_repair_correct_nodes: correct_start_nodes,
                    repaired_nodes,
                    messages: totals,
                });
                latest_canonical_data_holders = canonical_data_holders.clone();
                if correct_nodes == active_nodes
                    && data_available_nodes == active_nodes
                    && unique_epoch_hashes == 1
                {
                    pending_reconciliation = None;
                } else {
                    pending_reconciliation = Some(PendingEpochReconciliation {
                        canonical_data_holders,
                        canonical_block_replicas,
                        ..pending
                    });
                }
                continue;
            }
        }
        let nonce = canonical_nonce.new_next();
        let correct_start_nodes = active_indices
            .iter()
            .filter(|state| {
                states[**state].last_epoch == canonical_last_epoch
                    && states[**state].nonce == canonical_nonce
            })
            .count();
        let block_formation_span = telemetry.start_stage(
            &active_node_keys,
            epoch,
            nonce,
            None,
            "block_formation",
            "formed",
            active_nodes,
        );
        let mut local_blocks = vec![None; config.nodes];
        for node_index in active_indices.iter().copied() {
            let node = &nodes[node_index];
            let state = &states[node_index];
            let block_last_epoch = if faulty_node_indexes.contains(&node_index)
                && !recovered_node_indexes.contains(&node_index)
            {
                faulty_last_epoch(config.seed, epoch, node_index, canonical_last_epoch)
            } else {
                state.last_epoch
            };
            local_blocks[node_index] = Some(signed_block(
                node,
                epoch,
                node_index,
                block_last_epoch,
                state.nonce.new_next(),
                config.transactions_per_node,
                config.transaction_bytes,
                config.trust_mode,
            ));
        }

        let mut totals = EpochTransportTotals::default();
        let skipped_round_assist = config
            .assist_after_skipped_round
            .map(skipped_round_assist_decision);
        let dropped_local_block_sources =
            if skipped_round_assist == Some(FutureRoundAssistDecision::AssistDroppingLocalBlock) {
                active_indices.iter().copied().collect::<BTreeSet<_>>()
            } else {
                BTreeSet::new()
            };
        if !dropped_local_block_sources.is_empty() {
            totals.future_round_dropped_local_blocks = dropped_local_block_sources.len() as u64;
        }

        let valid_local_block_sources = active_indices
            .iter()
            .filter_map(|index| {
                let state = &states[*index];
                let block = local_blocks[*index].as_ref()?;
                (state.last_epoch == canonical_last_epoch
                    && state.nonce == canonical_nonce
                    && block.body.last_epoch == canonical_last_epoch
                    && block.body.nonce == nonce)
                    .then_some(*index)
            })
            .collect::<BTreeSet<_>>();
        let intentionally_dropped_local_blocks = valid_local_block_sources
            .intersection(&dropped_local_block_sources)
            .count();

        let canonical_blocks = active_indices
            .iter()
            .filter_map(|index| {
                if dropped_local_block_sources.contains(index) {
                    return None;
                }
                let state = &states[*index];
                let block = local_blocks[*index].as_ref()?;
                (state.last_epoch == canonical_last_epoch
                    && state.nonce == canonical_nonce
                    && block.body.last_epoch == canonical_last_epoch
                    && block.body.nonce == nonce)
                    .then_some((block.hash, block.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let canonical_block_sources = active_indices
            .iter()
            .filter_map(|index| {
                if dropped_local_block_sources.contains(index) {
                    return None;
                }
                let block = local_blocks[*index].as_ref()?;
                (states[*index].last_epoch == canonical_last_epoch
                    && states[*index].nonce == canonical_nonce
                    && block.body.last_epoch == canonical_last_epoch
                    && block.body.nonce == nonce)
                    .then_some(*index)
            })
            .collect::<BTreeSet<_>>();
        let expected_canonical_block_hashes = valid_local_block_sources
            .iter()
            .filter_map(|index| {
                if dropped_local_block_sources.contains(index) {
                    return None;
                }
                local_blocks[*index].as_ref().map(|block| block.hash)
            })
            .collect::<BTreeSet<_>>();
        let canonical_hash = epoch_hash(canonical_last_epoch, nonce, canonical_blocks.hash());
        let initial_data_available_nodes = if canonical_blocks.is_empty() {
            active_nodes
        } else {
            0
        };
        push_stage_progress(
            &mut stage_progress,
            &telemetry,
            block_formation_span,
            EpochStageProgressRecord {
                epoch,
                nonce,
                round: None,
                stage: "block_formation",
                event: "formed",
                nodes: active_nodes,
                dropped_nodes,
                quorums: 0,
                correct_nodes: correct_start_nodes,
                incorrect_nodes: active_nodes.saturating_sub(correct_start_nodes),
                data_available_nodes: initial_data_available_nodes,
                data_unavailable_nodes: data_unavailable_nodes(
                    active_nodes,
                    initial_data_available_nodes,
                ),
                unique_epoch_hashes: unique_active_epoch_hashes(&states, &active_indices),
                canonical_blocks: canonical_blocks.len(),
                min_blocks_per_node: 1,
                max_blocks_per_node: 1,
                repaired_nodes: 0,
                reconnected_nodes: 0,
                canonical_epoch_hash: canonical_hash,
                messages: EpochTransportTotals {
                    future_round_dropped_local_blocks: dropped_local_block_sources.len() as u64,
                    ..EpochTransportTotals::default()
                },
            },
        );

        let mut known_blocks = vec![BTreeMap::new(); config.nodes];
        for index in active_indices.iter().copied() {
            if dropped_local_block_sources.contains(&index) {
                continue;
            }
            if let Some(block) = local_blocks[index].as_ref() {
                known_blocks[index].insert(block.hash, block.clone());
            }
        }

        let topology_span = telemetry.start_stage(
            &active_node_keys,
            epoch,
            nonce,
            None,
            "membership_topology",
            "selected",
            active_nodes,
        );
        let topology = round_quorums(&active_node_keys, canonical_last_epoch, config.shuffle);
        push_stage_progress(
            &mut stage_progress,
            &telemetry,
            topology_span,
            EpochStageProgressRecord {
                epoch,
                nonce,
                round: None,
                stage: "membership_topology",
                event: "selected",
                nodes: active_nodes,
                dropped_nodes,
                quorums: topology.iter().map(Vec::len).sum(),
                correct_nodes: correct_start_nodes,
                incorrect_nodes: active_nodes.saturating_sub(correct_start_nodes),
                data_available_nodes: initial_data_available_nodes,
                data_unavailable_nodes: data_unavailable_nodes(
                    active_nodes,
                    initial_data_available_nodes,
                ),
                unique_epoch_hashes: unique_active_epoch_hashes(&states, &active_indices),
                canonical_blocks: canonical_blocks.len(),
                min_blocks_per_node: 1,
                max_blocks_per_node: 1,
                repaired_nodes: 0,
                reconnected_nodes: 0,
                canonical_epoch_hash: canonical_hash,
                messages: EpochTransportTotals::default(),
            },
        );
        for (round, quorums) in topology.iter().enumerate() {
            let dispatch_span = telemetry.start_stage(
                &active_node_keys,
                epoch,
                nonce,
                Some(round),
                "dispatch",
                "round_delivered",
                active_nodes,
            );
            let before_totals = totals.clone();
            if config.assist_after_skipped_round == Some(round) {
                let skipped_messages = quorum_message_edges(quorums);
                totals.total += skipped_messages;
                totals.future_round_skipped_messages += skipped_messages;
                if matches!(
                    skipped_round_assist_decision(round),
                    FutureRoundAssistDecision::Assist
                        | FutureRoundAssistDecision::AssistDroppingLocalBlock
                ) {
                    totals.future_round_assists += active_nodes as u64;
                }
                if skipped_round_assist_decision(round) == FutureRoundAssistDecision::Assist {
                    totals.future_round_carried_forward_blocks += canonical_blocks.len() as u64;
                }
                let (min_blocks_per_node, max_blocks_per_node) =
                    active_block_count_stats(&known_blocks, &active_indices);
                let round_data_holders = canonical_data_holders_for(
                    &known_blocks,
                    &active_indices,
                    canonical_blocks.hash(),
                    canonical_blocks.len(),
                );
                let data_available_nodes = round_data_holders.len();
                push_stage_progress(
                    &mut stage_progress,
                    &telemetry,
                    dispatch_span,
                    EpochStageProgressRecord {
                        epoch,
                        nonce,
                        round: Some(round),
                        stage: "dispatch",
                        event: "round_skipped_assist",
                        nodes: active_nodes,
                        dropped_nodes,
                        quorums: quorums.len(),
                        correct_nodes: correct_start_nodes,
                        incorrect_nodes: active_nodes.saturating_sub(correct_start_nodes),
                        data_available_nodes,
                        data_unavailable_nodes: data_unavailable_nodes(
                            active_nodes,
                            data_available_nodes,
                        ),
                        unique_epoch_hashes: unique_active_epoch_hashes(&states, &active_indices),
                        canonical_blocks: canonical_blocks.len(),
                        min_blocks_per_node,
                        max_blocks_per_node,
                        repaired_nodes: 0,
                        reconnected_nodes: 0,
                        canonical_epoch_hash: canonical_hash,
                        messages: transport_delta(&totals, &before_totals),
                    },
                );
                continue;
            }
            let before_round = known_blocks.clone();
            for quorum in quorums {
                for sender_position in quorum {
                    let sender = active_indices[*sender_position];
                    for recipient_position in quorum {
                        let recipient = active_indices[*recipient_position];
                        if sender == recipient {
                            continue;
                        }
                        let outcome = transport.sample(epoch, round, sender, recipient);
                        totals.total += 1;
                        if outcome.spiked {
                            totals.spiked += 1;
                        }
                        if outcome.dropped {
                            totals.dropped += 1;
                            continue;
                        }
                        if outcome.fuzzed {
                            totals.fuzzed += 1;
                            continue;
                        }
                        let timed_out = config.round_timeout_ms > 0
                            && outcome.delay_ms > config.round_timeout_ms;
                        if timed_out {
                            totals.late += 1;
                            continue;
                        }
                        totals.delivered += 1;
                        let recipient_next_nonce = states[recipient].nonce.new_next();
                        let recipient_last_epoch = states[recipient].last_epoch;
                        let mut deliverable = Vec::new();
                        for (hash, block) in &before_round[sender] {
                            totals.block_transfer_attempts += 1;
                            let block_bytes = estimated_block_wire_bytes(block) as u64;
                            if block.body.last_epoch == recipient_last_epoch
                                && block.body.nonce == recipient_next_nonce
                            {
                                totals.accepted_blocks += 1;
                                totals.accepted_block_bytes += block_bytes;
                                deliverable.push((*hash, block.clone()));
                            } else {
                                totals.denied_blocks += 1;
                                totals.denied_block_bytes += block_bytes;
                            }
                        }
                        known_blocks[recipient].extend(deliverable);
                    }
                }
            }
            let (min_blocks_per_node, max_blocks_per_node) =
                active_block_count_stats(&known_blocks, &active_indices);
            let round_data_holders = canonical_data_holders_for(
                &known_blocks,
                &active_indices,
                canonical_blocks.hash(),
                canonical_blocks.len(),
            );
            let data_available_nodes = round_data_holders.len();
            push_stage_progress(
                &mut stage_progress,
                &telemetry,
                dispatch_span,
                EpochStageProgressRecord {
                    epoch,
                    nonce,
                    round: Some(round),
                    stage: "dispatch",
                    event: "round_delivered",
                    nodes: active_nodes,
                    dropped_nodes,
                    quorums: quorums.len(),
                    correct_nodes: correct_start_nodes,
                    incorrect_nodes: active_nodes.saturating_sub(correct_start_nodes),
                    data_available_nodes,
                    data_unavailable_nodes: data_unavailable_nodes(
                        active_nodes,
                        data_available_nodes,
                    ),
                    unique_epoch_hashes: unique_active_epoch_hashes(&states, &active_indices),
                    canonical_blocks: canonical_blocks.len(),
                    min_blocks_per_node,
                    max_blocks_per_node,
                    repaired_nodes: 0,
                    reconnected_nodes: 0,
                    canonical_epoch_hash: canonical_hash,
                    messages: transport_delta(&totals, &before_totals),
                },
            );
        }

        let mut pre_repair_correct_nodes = 0usize;
        let pre_repair_span = telemetry.start_stage(
            &active_node_keys,
            epoch,
            nonce,
            None,
            "epoch_finality",
            "pre_repair",
            active_nodes,
        );
        let (min_blocks_per_node, max_blocks_per_node) =
            active_block_count_stats(&known_blocks, &active_indices);
        let mut canonical_block_replicas =
            canonical_block_replicas_for(&known_blocks, &active_indices, &canonical_blocks);
        let mut canonical_data_holders = full_data_holders_from_replicas(
            &canonical_block_replicas,
            &active_indices,
            canonical_blocks.len(),
        );
        for index in active_indices.iter().copied() {
            let blocks = &known_blocks[index];
            let node_hash = epoch_hash(
                states[index].last_epoch,
                states[index].nonce.new_next(),
                blocks.hash(),
            );
            if node_hash == canonical_hash {
                pre_repair_correct_nodes += 1;
            }
            states[index].last_epoch = node_hash;
            states[index].nonce = states[index].nonce.new_next();
        }
        let pre_repair_hashes = unique_active_epoch_hashes(&states, &active_indices);
        let pre_repair_data_available_nodes = count_active_data_available(
            &states,
            &active_indices,
            canonical_hash,
            nonce,
            &canonical_data_holders,
        );
        push_stage_progress(
            &mut stage_progress,
            &telemetry,
            pre_repair_span,
            EpochStageProgressRecord {
                epoch,
                nonce,
                round: None,
                stage: "epoch_finality",
                event: "pre_repair",
                nodes: active_nodes,
                dropped_nodes,
                quorums: 0,
                correct_nodes: pre_repair_correct_nodes,
                incorrect_nodes: active_nodes.saturating_sub(pre_repair_correct_nodes),
                data_available_nodes: pre_repair_data_available_nodes,
                data_unavailable_nodes: data_unavailable_nodes(
                    active_nodes,
                    pre_repair_data_available_nodes,
                ),
                unique_epoch_hashes: pre_repair_hashes,
                canonical_blocks: canonical_blocks.len(),
                min_blocks_per_node,
                max_blocks_per_node,
                repaired_nodes: 0,
                reconnected_nodes: 0,
                canonical_epoch_hash: canonical_hash,
                messages: EpochTransportTotals::default(),
            },
        );

        let repaired_nodes = repair_epoch(
            &config,
            &mut transport,
            epoch,
            nonce,
            &mut states,
            canonical_hash,
            &mut totals,
            &mut stage_progress,
            canonical_blocks.len(),
            &canonical_block_sources,
            &mut canonical_data_holders,
            &mut canonical_block_replicas,
            min_blocks_per_node,
            max_blocks_per_node,
            &active_indices,
            &active_node_keys,
            dropped_nodes,
            &mut telemetry,
        );
        let finalized_span = telemetry.start_stage(
            &active_node_keys,
            epoch,
            nonce,
            None,
            "epoch_finality",
            "finalized",
            active_nodes,
        );
        let correct_nodes = count_active_correct(&states, &active_indices, canonical_hash, nonce);
        let hashes = unique_active_epoch_hashes(&states, &active_indices);
        let finalized_data_available_nodes = count_active_data_available(
            &states,
            &active_indices,
            canonical_hash,
            nonce,
            &canonical_data_holders,
        );
        push_stage_progress(
            &mut stage_progress,
            &telemetry,
            finalized_span,
            EpochStageProgressRecord {
                epoch,
                nonce,
                round: None,
                stage: "epoch_finality",
                event: "finalized",
                nodes: active_nodes,
                dropped_nodes,
                quorums: 0,
                correct_nodes,
                incorrect_nodes: active_nodes.saturating_sub(correct_nodes),
                data_available_nodes: finalized_data_available_nodes,
                data_unavailable_nodes: data_unavailable_nodes(
                    active_nodes,
                    finalized_data_available_nodes,
                ),
                unique_epoch_hashes: hashes,
                canonical_blocks: canonical_blocks.len(),
                min_blocks_per_node,
                max_blocks_per_node,
                repaired_nodes,
                reconnected_nodes: 0,
                canonical_epoch_hash: canonical_hash,
                messages: EpochTransportTotals::default(),
            },
        );

        let removed_nodes = drop_faulty_nodes_for_epoch(
            &config,
            epoch,
            &faulty_node_indexes,
            &recovered_node_indexes,
            &mut active,
            &states,
            canonical_hash,
            nonce,
        );
        for index in &removed_nodes {
            dropped_node_keys.push(keys[*index]);
            dropped_since_epoch[*index] = Some(epoch);
        }
        canonical_data_holders.retain(|index| active.get(*index).copied().unwrap_or(false));
        retain_active_replicas(&mut canonical_block_replicas, &active);
        let post_drop_active_indices = collect_active_indices(&active);
        let post_drop_active_node_keys = collect_active_node_keys(&keys, &post_drop_active_indices);
        let post_drop_active_nodes = post_drop_active_indices.len();
        let post_drop_dropped_nodes = config.nodes.saturating_sub(post_drop_active_nodes);
        let post_drop_correct_nodes =
            count_active_correct(&states, &post_drop_active_indices, canonical_hash, nonce);
        let post_drop_hashes = unique_active_epoch_hashes(&states, &post_drop_active_indices);
        let post_drop_data_available_nodes = count_active_data_available(
            &states,
            &post_drop_active_indices,
            canonical_hash,
            nonce,
            &canonical_data_holders,
        );
        if !removed_nodes.is_empty() {
            let pruning_span = telemetry.start_stage(
                &post_drop_active_node_keys,
                epoch,
                nonce,
                None,
                "membership_pruning",
                "node_dropped",
                post_drop_active_nodes,
            );
            for index in &removed_nodes {
                telemetry.emit_node_dropped(
                    epoch,
                    nonce,
                    canonical_hash,
                    keys[*index],
                    post_drop_active_nodes,
                    post_drop_dropped_nodes,
                );
            }
            push_stage_progress(
                &mut stage_progress,
                &telemetry,
                pruning_span,
                EpochStageProgressRecord {
                    epoch,
                    nonce,
                    round: None,
                    stage: "membership_pruning",
                    event: "node_dropped",
                    nodes: post_drop_active_nodes,
                    dropped_nodes: post_drop_dropped_nodes,
                    quorums: 0,
                    correct_nodes: post_drop_correct_nodes,
                    incorrect_nodes: post_drop_active_nodes.saturating_sub(post_drop_correct_nodes),
                    data_available_nodes: post_drop_data_available_nodes,
                    data_unavailable_nodes: data_unavailable_nodes(
                        post_drop_active_nodes,
                        post_drop_data_available_nodes,
                    ),
                    unique_epoch_hashes: post_drop_hashes,
                    canonical_blocks: canonical_blocks.len(),
                    min_blocks_per_node,
                    max_blocks_per_node,
                    repaired_nodes: 0,
                    reconnected_nodes: 0,
                    canonical_epoch_hash: canonical_hash,
                    messages: EpochTransportTotals::default(),
                },
            );
        }

        let reconnected_nodes = reconnect_dropped_nodes_for_epoch(
            &config,
            &mut transport,
            epoch,
            nonce,
            &mut states,
            canonical_hash,
            &mut totals,
            &mut stage_progress,
            canonical_blocks.len(),
            min_blocks_per_node,
            max_blocks_per_node,
            &mut canonical_data_holders,
            &mut canonical_block_replicas,
            &keys,
            &mut active,
            &mut dropped_since_epoch,
            &mut recovered_node_indexes,
            &byzantine_node_indexes,
            &mut telemetry,
        );
        for admission in &reconnected_nodes {
            reconnected_node_keys.push(keys[admission.node_index]);
        }
        let final_active_indices = collect_active_indices(&active);
        let final_active_nodes = final_active_indices.len();
        let final_dropped_nodes = config.nodes.saturating_sub(final_active_nodes);
        let final_correct_nodes =
            count_active_correct(&states, &final_active_indices, canonical_hash, nonce);
        let final_data_available_nodes = count_active_data_available(
            &states,
            &final_active_indices,
            canonical_hash,
            nonce,
            &canonical_data_holders,
        );
        let final_hashes = unique_active_epoch_hashes(&states, &final_active_indices);
        let incorrectly_lost_local_blocks = count_incorrectly_lost_local_blocks(
            &expected_canonical_block_hashes,
            &canonical_block_replicas,
        );

        let report = EpochChaosEpochReport {
            epoch,
            nonce,
            start_active_nodes: active_nodes,
            start_dropped_nodes: dropped_nodes,
            active_nodes: final_active_nodes,
            dropped_nodes: final_dropped_nodes,
            reconnected_nodes: reconnected_nodes.len(),
            correct_start_nodes,
            correct_nodes: final_correct_nodes,
            incorrect_nodes: final_active_nodes.saturating_sub(final_correct_nodes),
            data_available_nodes: final_data_available_nodes,
            data_unavailable_nodes: data_unavailable_nodes(
                final_active_nodes,
                final_data_available_nodes,
            ),
            unique_epoch_hashes: final_hashes,
            min_blocks_per_node,
            max_blocks_per_node,
            valid_local_blocks: valid_local_block_sources.len(),
            intentionally_dropped_local_blocks,
            incorrectly_lost_local_blocks,
            canonical_blocks: canonical_blocks.len(),
            canonical_epoch_hash: canonical_hash,
            pre_repair_correct_nodes,
            repaired_nodes,
            messages: totals,
        };
        latest_canonical_data_holders = canonical_data_holders.clone();
        canonical_last_epoch = canonical_hash;
        canonical_nonce = nonce;
        let active_unrecovered_faults = final_active_indices.iter().any(|index| {
            faulty_node_indexes.contains(index) && !recovered_node_indexes.contains(index)
        });
        if (final_correct_nodes == final_active_nodes
            && final_data_available_nodes == final_active_nodes
            && final_hashes == 1)
            || active_unrecovered_faults
        {
            pending_reconciliation = None;
        } else {
            pending_reconciliation = Some(PendingEpochReconciliation {
                nonce,
                canonical_hash,
                canonical_blocks: canonical_blocks.len(),
                canonical_block_sources: canonical_block_sources.clone(),
                expected_canonical_block_hashes: expected_canonical_block_hashes.clone(),
                canonical_data_holders: canonical_data_holders.clone(),
                canonical_block_replicas: canonical_block_replicas.clone(),
                valid_local_blocks: valid_local_block_sources.len(),
                intentionally_dropped_local_blocks,
                min_blocks_per_node,
                max_blocks_per_node,
            });
        }
        epoch_reports.push(report);
    }

    let final_correct_epoch_hash = canonical_last_epoch;
    let final_correct_epoch_nonce = canonical_nonce;
    let final_active_indices = collect_active_indices(&active);
    let final_active_nodes = final_active_indices.len();
    let final_dropped_nodes = config.nodes.saturating_sub(final_active_nodes);
    let final_correct_nodes = count_active_correct(
        &states,
        &final_active_indices,
        final_correct_epoch_hash,
        final_correct_epoch_nonce,
    );
    let final_data_available_nodes = count_active_data_available(
        &states,
        &final_active_indices,
        final_correct_epoch_hash,
        final_correct_epoch_nonce,
        &latest_canonical_data_holders,
    );
    let final_unique_epoch_hashes = unique_active_epoch_hashes(&states, &final_active_indices);
    let max_byzantine_nodes_for_safety = config.max_byzantine_nodes_for_safety();
    let byzantine_tolerance_exceeded = config.byzantine_nodes > max_byzantine_nodes_for_safety;
    let mut report = EpochChaosReport {
        config,
        node_keys: keys.clone(),
        epochs: epoch_reports,
        stage_progress,
        total_messages: 0,
        delivered_messages: 0,
        dropped_messages: 0,
        fuzzed_messages: 0,
        late_messages: 0,
        spiked_messages: 0,
        repair_attempts: 0,
        repair_successes: 0,
        reconnect_attempts: 0,
        reconnect_approvals: 0,
        reconnect_catchup_proofs: 0,
        reconnect_replays: 0,
        reconnect_stale_proofs: 0,
        reconnect_duplicate_votes: 0,
        reconnect_identity_rejections: 0,
        reconnect_successes: 0,
        block_transfer_attempts: 0,
        accepted_blocks: 0,
        denied_blocks: 0,
        accepted_block_bytes: 0,
        denied_block_bytes: 0,
        future_round_assists: 0,
        future_round_skipped_messages: 0,
        future_round_dropped_local_blocks: 0,
        future_round_carried_forward_blocks: 0,
        max_byzantine_nodes_for_safety,
        byzantine_tolerance_exceeded,
        final_active_nodes,
        final_dropped_nodes,
        dropped_node_keys,
        reconnected_node_keys,
        byzantine_node_keys,
        final_correct_nodes,
        final_incorrect_nodes: final_active_nodes.saturating_sub(final_correct_nodes),
        final_data_available_nodes,
        final_data_unavailable_nodes: data_unavailable_nodes(
            final_active_nodes,
            final_data_available_nodes,
        ),
        final_unique_epoch_hashes,
        final_correct_epoch_hash,
        final_correct_epoch_nonce,
        valid_local_blocks: 0,
        intentionally_dropped_local_blocks: 0,
        incorrectly_lost_local_blocks: 0,
    };

    for epoch in &report.epochs {
        report.total_messages += epoch.messages.total;
        report.delivered_messages += epoch.messages.delivered;
        report.dropped_messages += epoch.messages.dropped;
        report.fuzzed_messages += epoch.messages.fuzzed;
        report.late_messages += epoch.messages.late;
        report.spiked_messages += epoch.messages.spiked;
        report.repair_attempts += epoch.messages.repair_attempts;
        report.repair_successes += epoch.messages.repair_successes;
        report.reconnect_attempts += epoch.messages.reconnect_attempts;
        report.reconnect_approvals += epoch.messages.reconnect_approvals;
        report.reconnect_catchup_proofs += epoch.messages.reconnect_catchup_proofs;
        report.reconnect_replays += epoch.messages.reconnect_replays;
        report.reconnect_stale_proofs += epoch.messages.reconnect_stale_proofs;
        report.reconnect_duplicate_votes += epoch.messages.reconnect_duplicate_votes;
        report.reconnect_identity_rejections += epoch.messages.reconnect_identity_rejections;
        report.reconnect_successes += epoch.messages.reconnect_successes;
        report.block_transfer_attempts += epoch.messages.block_transfer_attempts;
        report.accepted_blocks += epoch.messages.accepted_blocks;
        report.denied_blocks += epoch.messages.denied_blocks;
        report.accepted_block_bytes += epoch.messages.accepted_block_bytes;
        report.denied_block_bytes += epoch.messages.denied_block_bytes;
        report.future_round_assists += epoch.messages.future_round_assists;
        report.future_round_skipped_messages += epoch.messages.future_round_skipped_messages;
        report.future_round_dropped_local_blocks +=
            epoch.messages.future_round_dropped_local_blocks;
        report.future_round_carried_forward_blocks +=
            epoch.messages.future_round_carried_forward_blocks;
        report.valid_local_blocks += epoch.valid_local_blocks as u64;
        report.intentionally_dropped_local_blocks +=
            epoch.intentionally_dropped_local_blocks as u64;
        report.incorrectly_lost_local_blocks += epoch.incorrectly_lost_local_blocks as u64;
    }

    Ok(report)
}

fn collect_active_indices(active: &[bool]) -> Vec<usize> {
    active
        .iter()
        .enumerate()
        .filter_map(|(index, is_active)| is_active.then_some(index))
        .collect()
}

fn collect_active_node_keys(keys: &[PubKey], active_indices: &[usize]) -> Vec<PubKey> {
    active_indices.iter().map(|index| keys[*index]).collect()
}

fn count_active_correct(
    states: &[NodeEpochState],
    active_indices: &[usize],
    canonical_hash: HashType,
    nonce: Nonce,
) -> usize {
    active_indices
        .iter()
        .filter(|index| {
            states[**index].last_epoch == canonical_hash && states[**index].nonce == nonce
        })
        .count()
}

fn canonical_data_holders_for(
    known_blocks: &[BTreeMap<HashType, Block>],
    active_indices: &[usize],
    canonical_blocks_hash: HashType,
    canonical_blocks: usize,
) -> BTreeSet<usize> {
    if canonical_blocks == 0 {
        return active_indices.iter().copied().collect();
    }
    active_indices
        .iter()
        .filter(|index| known_blocks[**index].hash() == canonical_blocks_hash)
        .copied()
        .collect()
}

fn canonical_block_replicas_for(
    known_blocks: &[BTreeMap<HashType, Block>],
    active_indices: &[usize],
    canonical_blocks: &BTreeMap<HashType, Block>,
) -> BTreeMap<HashType, BTreeSet<usize>> {
    canonical_blocks
        .keys()
        .map(|hash| {
            let holders = active_indices
                .iter()
                .filter(|index| known_blocks[**index].contains_key(hash))
                .copied()
                .collect::<BTreeSet<_>>();
            (*hash, holders)
        })
        .collect()
}

fn full_data_holders_from_replicas(
    canonical_block_replicas: &BTreeMap<HashType, BTreeSet<usize>>,
    active_indices: &[usize],
    canonical_blocks: usize,
) -> BTreeSet<usize> {
    if canonical_blocks == 0 {
        return active_indices.iter().copied().collect();
    }
    active_indices
        .iter()
        .filter(|index| {
            canonical_block_replicas
                .values()
                .all(|holders| holders.contains(index))
        })
        .copied()
        .collect()
}

fn retain_active_replicas(
    canonical_block_replicas: &mut BTreeMap<HashType, BTreeSet<usize>>,
    active: &[bool],
) {
    for holders in canonical_block_replicas.values_mut() {
        holders.retain(|index| active.get(*index).copied().unwrap_or(false));
    }
}

fn count_incorrectly_lost_local_blocks(
    expected_canonical_block_hashes: &BTreeSet<HashType>,
    canonical_block_replicas: &BTreeMap<HashType, BTreeSet<usize>>,
) -> usize {
    expected_canonical_block_hashes
        .iter()
        .filter(|hash| {
            canonical_block_replicas
                .get(hash)
                .map(BTreeSet::is_empty)
                .unwrap_or(true)
        })
        .count()
}

fn can_reconstruct_canonical_data(
    canonical_block_replicas: &BTreeMap<HashType, BTreeSet<usize>>,
    candidate_sources: &BTreeSet<usize>,
    canonical_blocks: usize,
) -> bool {
    canonical_blocks == 0
        || canonical_block_replicas.values().all(|holders| {
            holders
                .iter()
                .any(|holder| candidate_sources.contains(holder))
        })
}

fn add_full_data_holder(
    canonical_data_holders: &mut BTreeSet<usize>,
    canonical_block_replicas: &mut BTreeMap<HashType, BTreeSet<usize>>,
    node: usize,
) {
    canonical_data_holders.insert(node);
    for holders in canonical_block_replicas.values_mut() {
        holders.insert(node);
    }
}

fn count_active_data_available(
    states: &[NodeEpochState],
    active_indices: &[usize],
    canonical_hash: HashType,
    nonce: Nonce,
    canonical_data_holders: &BTreeSet<usize>,
) -> usize {
    active_indices
        .iter()
        .filter(|index| {
            canonical_data_holders.contains(index)
                && states[**index].last_epoch == canonical_hash
                && states[**index].nonce == nonce
        })
        .count()
}

fn data_unavailable_nodes(total_nodes: usize, data_available_nodes: usize) -> usize {
    total_nodes.saturating_sub(data_available_nodes)
}

fn unique_active_epoch_hashes(states: &[NodeEpochState], active_indices: &[usize]) -> usize {
    active_indices
        .iter()
        .map(|index| states[*index].last_epoch)
        .collect::<BTreeSet<_>>()
        .len()
}

fn active_block_count_stats(
    known_blocks: &[BTreeMap<HashType, Block>],
    active_indices: &[usize],
) -> (usize, usize) {
    let mut counts = active_indices
        .iter()
        .map(|index| known_blocks[*index].len())
        .collect::<Vec<_>>();
    counts.sort_unstable();
    (
        counts.first().copied().unwrap_or_default(),
        counts.last().copied().unwrap_or_default(),
    )
}

fn estimated_block_wire_bytes(block: &Block) -> usize {
    const HASH_BYTES: usize = 32;
    const SIGNATURE_BYTES: usize = 64;
    const NONCE_BYTES: usize = 8;
    const TIMESTAMP_BYTES: usize = 16;
    const LEN_PREFIX_BYTES: usize = 4;

    HASH_BYTES // block.hash
        + SIGNATURE_BYTES
        + HASH_BYTES // validator
        + HASH_BYTES // last_epoch
        + NONCE_BYTES
        + TIMESTAMP_BYTES // created
        + TIMESTAMP_BYTES // dispatched
        + HASH_BYTES // merkle_root
        + LEN_PREFIX_BYTES
        + block.body.application_state.as_slice().len()
        + LEN_PREFIX_BYTES
        + block.body.encounter_records.len() * HASH_BYTES
        + LEN_PREFIX_BYTES
        + block
            .body
            .txs
            .iter()
            .map(|tx| HASH_BYTES + LEN_PREFIX_BYTES + tx.payload.len())
            .sum::<usize>()
}

fn reconnect_stage_node_keys(
    keys: &[PubKey],
    active_indices: &[usize],
    candidate_indices: &[usize],
) -> Vec<PubKey> {
    let mut indexes = active_indices.to_vec();
    indexes.extend_from_slice(candidate_indices);
    indexes.sort_unstable();
    indexes.dedup();
    indexes.iter().map(|index| keys[*index]).collect()
}

fn max_byzantine_nodes_for_safety(node_count: usize) -> usize {
    node_count.saturating_sub(1) / 3
}

fn select_faulty_node_indexes(
    node_count: usize,
    faulty_nodes: usize,
    seed: u64,
) -> BTreeSet<usize> {
    let mut indexes = (0..node_count).collect::<Vec<_>>();
    indexes.sort_by_key(|index| {
        splitmix64(seed ^ (*index as u64).rotate_left(17) ^ 0xfa17_ed50_11d0_0d55)
    });
    indexes.truncate(faulty_nodes.min(node_count));
    indexes.into_iter().collect()
}

fn select_byzantine_node_indexes(
    node_count: usize,
    byzantine_nodes: usize,
    seed: u64,
    excluded: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    let mut indexes = (0..node_count)
        .filter(|index| !excluded.contains(index))
        .collect::<Vec<_>>();
    indexes.sort_by_key(|index| {
        splitmix64(seed ^ (*index as u64).rotate_left(19) ^ 0xb12a_7711_e5ad_0001)
    });
    indexes.truncate(byzantine_nodes.min(indexes.len()));
    indexes.into_iter().collect()
}

fn faulty_last_epoch(
    seed: u64,
    epoch: usize,
    node_index: usize,
    canonical_last_epoch: HashType,
) -> HashType {
    let mut bytes = Vec::with_capacity(56);
    bytes.extend_from_slice(canonical_last_epoch.as_ref());
    bytes.extend_from_slice(&seed.to_le_bytes());
    bytes.extend_from_slice(&(epoch as u64).to_le_bytes());
    bytes.extend_from_slice(&(node_index as u64).to_le_bytes());
    HashType::hash(&bytes)
}

#[allow(clippy::too_many_arguments)]
fn drop_faulty_nodes_for_epoch(
    config: &EpochChaosConfig,
    epoch: usize,
    faulty_node_indexes: &BTreeSet<usize>,
    recovered_node_indexes: &BTreeSet<usize>,
    active: &mut [bool],
    states: &[NodeEpochState],
    canonical_hash: HashType,
    nonce: Nonce,
) -> Vec<usize> {
    if config.faulty_nodes == 0
        || config.max_dropped_nodes_per_epoch == 0
        || epoch + 1 < config.drop_faulty_after_epochs
    {
        return Vec::new();
    }

    let active_nodes = active.iter().filter(|is_active| **is_active).count();
    let removal_capacity = active_nodes.saturating_sub(config.min_active_nodes);
    if removal_capacity == 0 {
        return Vec::new();
    }
    if !config.trust_mode.is_trusted() {
        let observer_quorum = supermajority_count(active_nodes);
        let canonical_observers = active
            .iter()
            .enumerate()
            .filter(|(index, is_active)| {
                **is_active
                    && states.get(*index).is_some_and(|state| {
                        state.last_epoch == canonical_hash && state.nonce == nonce
                    })
            })
            .count();
        if canonical_observers < observer_quorum {
            return Vec::new();
        }
    }

    let mut candidates = faulty_node_indexes
        .iter()
        .copied()
        .filter(|index| !recovered_node_indexes.contains(index))
        .filter(|index| active.get(*index).copied().unwrap_or(false))
        .collect::<Vec<_>>();
    candidates.truncate(config.max_dropped_nodes_per_epoch.min(removal_capacity));
    for index in &candidates {
        active[*index] = false;
    }
    candidates
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconnectAdmission {
    node_index: usize,
    ping_responses: usize,
    catchup_proofs: usize,
    approvals: usize,
}

#[allow(clippy::too_many_arguments)]
fn reconnect_dropped_nodes_for_epoch(
    config: &EpochChaosConfig,
    transport: &mut TransportSampler,
    epoch: usize,
    nonce: Nonce,
    states: &mut [NodeEpochState],
    canonical_hash: HashType,
    totals: &mut EpochTransportTotals,
    stage_progress: &mut Vec<EpochStageProgressRecord>,
    canonical_blocks: usize,
    min_blocks_per_node: usize,
    max_blocks_per_node: usize,
    canonical_data_holders: &mut BTreeSet<usize>,
    canonical_block_replicas: &mut BTreeMap<HashType, BTreeSet<usize>>,
    keys: &[PubKey],
    active: &mut [bool],
    dropped_since_epoch: &mut [Option<usize>],
    recovered_node_indexes: &mut BTreeSet<usize>,
    byzantine_node_indexes: &BTreeSet<usize>,
    telemetry: &mut EpochTelemetryEmitter,
) -> Vec<ReconnectAdmission> {
    if config.reconnect_dropped_after_epochs == 0 || config.max_reconnected_nodes_per_epoch == 0 {
        return Vec::new();
    }

    let active_indices = collect_active_indices(active);
    if active_indices.is_empty() {
        return Vec::new();
    }
    let active_nodes = active_indices.len();
    let dropped_nodes = active.len().saturating_sub(active_nodes);
    let ping_fanout = config.effective_reconnect_ping_fanout_for(active_nodes);
    let ping_quorum = config
        .effective_reconnect_ping_quorum_for(active_nodes)
        .min(ping_fanout);
    let approval_quorum = config
        .effective_reconnect_approval_quorum_for(active_nodes)
        .min(active_nodes);
    if ping_fanout == 0 || ping_quorum == 0 || approval_quorum == 0 {
        return Vec::new();
    }

    let mut candidates = dropped_since_epoch
        .iter()
        .enumerate()
        .filter_map(|(index, dropped_at)| {
            let dropped_at = (*dropped_at)?;
            (!active[index]
                && epoch.saturating_sub(dropped_at) >= config.reconnect_dropped_after_epochs)
                .then_some((dropped_at, index))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(dropped_at, index)| (*dropped_at, *index));
    candidates.truncate(config.max_reconnected_nodes_per_epoch);
    if candidates.is_empty() {
        return Vec::new();
    }
    let candidate_indices = candidates
        .iter()
        .map(|(_, index)| *index)
        .collect::<Vec<_>>();
    let reconnect_node_keys = reconnect_stage_node_keys(keys, &active_indices, &candidate_indices);

    let ping_span = telemetry.start_stage(
        &reconnect_node_keys,
        epoch,
        nonce,
        None,
        "membership_reconnect",
        "peer_ping",
        active_nodes,
    );
    let mut ping_totals = EpochTransportTotals::default();
    let mut admission_candidates = Vec::<ReconnectAdmission>::new();
    for (_, node_index) in &candidates {
        let mut ping_responses = 0usize;
        for peer in restart_ping_peers(
            &active_indices,
            ping_fanout,
            config.seed ^ 0x7265_6a6f_696e_7067,
            epoch,
            0,
            *node_index,
        ) {
            let outcome = transport.sample_reconnect_ping(epoch, *node_index, peer);
            let (mut delta, delivered) =
                reconnect_outcome_delta(&outcome, config.reconnect_timeout_ms);
            let replayed = delivered
                && byzantine_node_indexes.contains(&peer)
                && byzantine_replays_reconnect_evidence(config, epoch, peer, *node_index, 0);
            if replayed {
                delta.reconnect_replays = 1;
            }
            merge_transport_totals(totals, &delta);
            merge_transport_totals(&mut ping_totals, &delta);
            if delivered
                && !replayed
                && states[peer].last_epoch == canonical_hash
                && states[peer].nonce == nonce
            {
                ping_responses += 1;
            }
        }
        if ping_responses >= ping_quorum {
            admission_candidates.push(ReconnectAdmission {
                node_index: *node_index,
                ping_responses,
                catchup_proofs: 0,
                approvals: 0,
            });
        }
    }
    push_stage_progress(
        stage_progress,
        telemetry,
        ping_span,
        EpochStageProgressRecord {
            epoch,
            nonce,
            round: None,
            stage: "membership_reconnect",
            event: "peer_ping",
            nodes: active_nodes,
            dropped_nodes,
            reconnected_nodes: 0,
            quorums: ping_fanout,
            correct_nodes: count_active_correct(states, &active_indices, canonical_hash, nonce),
            incorrect_nodes: active_nodes.saturating_sub(count_active_correct(
                states,
                &active_indices,
                canonical_hash,
                nonce,
            )),
            data_available_nodes: count_active_data_available(
                states,
                &active_indices,
                canonical_hash,
                nonce,
                canonical_data_holders,
            ),
            data_unavailable_nodes: data_unavailable_nodes(
                active_nodes,
                count_active_data_available(
                    states,
                    &active_indices,
                    canonical_hash,
                    nonce,
                    canonical_data_holders,
                ),
            ),
            unique_epoch_hashes: unique_active_epoch_hashes(states, &active_indices),
            canonical_blocks,
            min_blocks_per_node,
            max_blocks_per_node,
            repaired_nodes: 0,
            canonical_epoch_hash: canonical_hash,
            messages: ping_totals,
        },
    );

    if admission_candidates.is_empty() {
        return Vec::new();
    }

    let proof_quorum = approval_quorum;
    let proof_span = telemetry.start_stage(
        &reconnect_node_keys,
        epoch,
        nonce,
        None,
        "membership_reconnect",
        "catchup_proof",
        active_nodes,
    );
    let mut proof_totals = EpochTransportTotals::default();
    let mut proof_candidates = Vec::<ReconnectAdmission>::new();
    for mut candidate in admission_candidates {
        if reconnect_candidate_uses_sybil_identity(config, epoch, candidate.node_index) {
            let delta = EpochTransportTotals {
                reconnect_identity_rejections: 1,
                ..EpochTransportTotals::default()
            };
            merge_transport_totals(totals, &delta);
            merge_transport_totals(&mut proof_totals, &delta);
            continue;
        }
        if reconnect_candidate_offers_stale_proof(config, epoch, candidate.node_index) {
            let delta = EpochTransportTotals {
                reconnect_stale_proofs: 1,
                ..EpochTransportTotals::default()
            };
            merge_transport_totals(totals, &delta);
            merge_transport_totals(&mut proof_totals, &delta);
            continue;
        }

        let mut proof_sources = BTreeSet::<usize>::new();
        for peer in &active_indices {
            let outcome = transport.sample_reconnect_catchup(epoch, *peer, candidate.node_index);
            let (mut delta, delivered) =
                reconnect_outcome_delta(&outcome, config.reconnect_timeout_ms);
            let replayed = delivered
                && byzantine_node_indexes.contains(peer)
                && byzantine_replays_reconnect_evidence(
                    config,
                    epoch,
                    *peer,
                    candidate.node_index,
                    2,
                );
            if replayed {
                delta.reconnect_replays = 1;
            }
            if delivered
                && !replayed
                && states[*peer].last_epoch == canonical_hash
                && states[*peer].nonce == nonce
            {
                proof_sources.insert(*peer);
            }
            merge_transport_totals(totals, &delta);
            merge_transport_totals(&mut proof_totals, &delta);
        }

        let has_data_source = canonical_blocks == 0
            || can_reconstruct_canonical_data(
                canonical_block_replicas,
                &proof_sources,
                canonical_blocks,
            );
        if proof_sources.len() >= proof_quorum && has_data_source {
            candidate.catchup_proofs = proof_sources.len();
            states[candidate.node_index] = NodeEpochState {
                last_epoch: canonical_hash,
                nonce,
            };
            add_full_data_holder(
                canonical_data_holders,
                canonical_block_replicas,
                candidate.node_index,
            );
            let delta = EpochTransportTotals {
                reconnect_catchup_proofs: 1,
                ..EpochTransportTotals::default()
            };
            merge_transport_totals(totals, &delta);
            merge_transport_totals(&mut proof_totals, &delta);
            proof_candidates.push(candidate);
        }
    }
    push_stage_progress(
        stage_progress,
        telemetry,
        proof_span,
        EpochStageProgressRecord {
            epoch,
            nonce,
            round: None,
            stage: "membership_reconnect",
            event: "catchup_proof",
            nodes: active_nodes,
            dropped_nodes,
            reconnected_nodes: 0,
            quorums: proof_quorum,
            correct_nodes: count_active_correct(states, &active_indices, canonical_hash, nonce),
            incorrect_nodes: active_nodes.saturating_sub(count_active_correct(
                states,
                &active_indices,
                canonical_hash,
                nonce,
            )),
            data_available_nodes: count_active_data_available(
                states,
                &active_indices,
                canonical_hash,
                nonce,
                canonical_data_holders,
            ),
            data_unavailable_nodes: data_unavailable_nodes(
                active_nodes,
                count_active_data_available(
                    states,
                    &active_indices,
                    canonical_hash,
                    nonce,
                    canonical_data_holders,
                ),
            ),
            unique_epoch_hashes: unique_active_epoch_hashes(states, &active_indices),
            canonical_blocks,
            min_blocks_per_node,
            max_blocks_per_node,
            repaired_nodes: 0,
            canonical_epoch_hash: canonical_hash,
            messages: proof_totals,
        },
    );

    if proof_candidates.is_empty() {
        return Vec::new();
    }

    let approval_span = telemetry.start_stage(
        &reconnect_node_keys,
        epoch,
        nonce,
        None,
        "membership_reconnect",
        "admission_vote",
        active_nodes,
    );
    let mut approval_totals = EpochTransportTotals::default();
    let mut admissions = Vec::new();
    for mut candidate in proof_candidates {
        let mut approvals = BTreeSet::<usize>::new();
        for voter in &active_indices {
            let vote_copies = if byzantine_node_indexes.contains(voter) {
                1 + config.byzantine_duplicate_vote_copies
            } else {
                1
            };
            for copy in 0..vote_copies {
                let outcome = transport.sample_reconnect_vote(epoch, *voter, candidate.node_index);
                let (mut delta, delivered) =
                    reconnect_outcome_delta(&outcome, config.reconnect_timeout_ms);
                let replayed = delivered
                    && byzantine_node_indexes.contains(voter)
                    && byzantine_replays_reconnect_evidence(
                        config,
                        epoch,
                        *voter,
                        candidate.node_index,
                        1,
                    );
                if copy > 0 {
                    delta.reconnect_duplicate_votes = 1;
                }
                if replayed {
                    delta.reconnect_replays = 1;
                }
                if delivered
                    && !replayed
                    && states[*voter].last_epoch == canonical_hash
                    && states[*voter].nonce == nonce
                    && states[candidate.node_index].last_epoch == canonical_hash
                    && states[candidate.node_index].nonce == nonce
                    && approvals.insert(*voter)
                {
                    delta.reconnect_approvals = 1;
                }
                merge_transport_totals(totals, &delta);
                merge_transport_totals(&mut approval_totals, &delta);
            }
        }

        if approvals.len() >= approval_quorum
            && admissions.len() < config.max_reconnected_nodes_per_epoch
        {
            candidate.approvals = approvals.len();
            active[candidate.node_index] = true;
            dropped_since_epoch[candidate.node_index] = None;
            recovered_node_indexes.insert(candidate.node_index);
            totals.reconnect_successes += 1;
            approval_totals.reconnect_successes += 1;
            admissions.push(candidate);
        }
    }

    let post_active_indices = collect_active_indices(active);
    let post_active_nodes = post_active_indices.len();
    let post_dropped_nodes = active.len().saturating_sub(post_active_nodes);
    for admission in &admissions {
        telemetry.emit_node_reconnected(
            epoch,
            nonce,
            canonical_hash,
            keys[admission.node_index],
            post_active_nodes,
            post_dropped_nodes,
            admission.ping_responses,
            admission.catchup_proofs,
            admission.approvals,
        );
    }
    let post_correct_nodes =
        count_active_correct(states, &post_active_indices, canonical_hash, nonce);
    let post_data_available_nodes = count_active_data_available(
        states,
        &post_active_indices,
        canonical_hash,
        nonce,
        canonical_data_holders,
    );
    push_stage_progress(
        stage_progress,
        telemetry,
        approval_span,
        EpochStageProgressRecord {
            epoch,
            nonce,
            round: None,
            stage: "membership_reconnect",
            event: "admission_vote",
            nodes: post_active_nodes,
            dropped_nodes: post_dropped_nodes,
            reconnected_nodes: admissions.len(),
            quorums: approval_quorum,
            correct_nodes: post_correct_nodes,
            incorrect_nodes: post_active_nodes.saturating_sub(post_correct_nodes),
            data_available_nodes: post_data_available_nodes,
            data_unavailable_nodes: data_unavailable_nodes(
                post_active_nodes,
                post_data_available_nodes,
            ),
            unique_epoch_hashes: unique_active_epoch_hashes(states, &post_active_indices),
            canonical_blocks,
            min_blocks_per_node,
            max_blocks_per_node,
            repaired_nodes: 0,
            canonical_epoch_hash: canonical_hash,
            messages: approval_totals,
        },
    );

    admissions
}

fn repair_epoch(
    config: &EpochChaosConfig,
    transport: &mut TransportSampler,
    epoch: usize,
    nonce: Nonce,
    states: &mut [NodeEpochState],
    canonical_hash: HashType,
    totals: &mut EpochTransportTotals,
    stage_progress: &mut Vec<EpochStageProgressRecord>,
    canonical_blocks: usize,
    _canonical_block_sources: &BTreeSet<usize>,
    canonical_data_holders: &mut BTreeSet<usize>,
    canonical_block_replicas: &mut BTreeMap<HashType, BTreeSet<usize>>,
    min_blocks_per_node: usize,
    max_blocks_per_node: usize,
    active_indices: &[usize],
    active_node_keys: &[PubKey],
    dropped_nodes: usize,
    telemetry: &mut EpochTelemetryEmitter,
) -> usize {
    if config.repair_rounds == 0 {
        return 0;
    }
    let active_nodes = active_indices.len();
    let fanout = config.effective_repair_fanout_for(active_nodes);
    let quorum = config.effective_repair_quorum_for(active_nodes).min(fanout);
    if fanout == 0 || quorum == 0 {
        return 0;
    }

    let mut repaired = 0usize;
    let mut reconciliation_sources = vec![BTreeSet::<usize>::new(); states.len()];
    for source in canonical_data_holders.iter() {
        if *source < reconciliation_sources.len() {
            reconciliation_sources[*source].insert(*source);
        }
    }

    for repair_round in 0..config.repair_rounds {
        let mut summary_totals = EpochTransportTotals::default();
        let mut reconciliation_totals = EpochTransportTotals::default();
        let mut summary_repaired = 0usize;
        let mut reconciled = 0usize;
        let round_states = states.to_vec();
        let incorrect_nodes = active_indices
            .iter()
            .filter_map(|index| {
                let state = round_states[*index];
                (state.last_epoch != canonical_hash || state.nonce != nonce).then_some(*index)
            })
            .collect::<Vec<_>>();
        if incorrect_nodes.is_empty() {
            break;
        }

        let recovery_span = telemetry.start_stage(
            active_node_keys,
            epoch,
            nonce,
            Some(repair_round),
            "recovery",
            "repair_round",
            active_nodes,
        );
        for recipient in incorrect_nodes {
            // Restart handshake: peers return only their epoch summary. The
            // modeled catch-up transfer happens later, after a certified
            // summary quorum.
            let summary_peers = restart_ping_peers(
                active_indices,
                fanout,
                config.seed,
                epoch,
                repair_round,
                recipient,
            );
            let mut returned_summaries = BTreeMap::<NodeEpochState, Vec<usize>>::new();
            for sender in summary_peers {
                let outcome = transport.sample_repair(epoch, repair_round, sender, recipient);
                let (delta, delivered) = repair_outcome_delta(&outcome, config.repair_timeout_ms);
                merge_transport_totals(totals, &delta);
                merge_transport_totals(&mut summary_totals, &delta);
                if !delivered {
                    continue;
                }
                let peer_state = round_states[sender];
                if peer_state.nonce >= round_states[recipient].nonce {
                    returned_summaries
                        .entry(peer_state)
                        .or_default()
                        .push(sender);
                }
            }

            if let Some((state, peers)) = returned_summaries
                .into_iter()
                .filter(|(state, peers)| {
                    peers.len() >= quorum
                        && state.last_epoch == canonical_hash
                        && state.nonce == nonce
                })
                .max_by(|(left_state, left_peers), (right_state, right_peers)| {
                    left_peers
                        .len()
                        .cmp(&right_peers.len())
                        .then_with(|| left_state.nonce.cmp(&right_state.nonce))
                        .then_with(|| left_state.last_epoch.cmp(&right_state.last_epoch))
                })
            {
                let peer_sources = peers.iter().copied().collect::<BTreeSet<_>>();
                let Some(sender) = peers
                    .iter()
                    .copied()
                    .find(|peer| canonical_blocks == 0 || canonical_data_holders.contains(peer))
                    .or_else(|| {
                        can_reconstruct_canonical_data(
                            canonical_block_replicas,
                            &peer_sources,
                            canonical_blocks,
                        )
                        .then_some(peers[0])
                    })
                else {
                    continue;
                };
                let outcome = transport.sample_repair_fetch(epoch, repair_round, sender, recipient);
                let (delta, delivered) = repair_outcome_delta(&outcome, config.repair_timeout_ms);
                merge_transport_totals(totals, &delta);
                merge_transport_totals(&mut summary_totals, &delta);
                if !delivered {
                    continue;
                }
                totals.repair_successes += 1;
                summary_totals.repair_successes += 1;
                states[recipient] = state;
                add_full_data_holder(canonical_data_holders, canonical_block_replicas, recipient);
                repaired += 1;
                summary_repaired += 1;
            }
        }

        let correct_after_summary =
            count_active_correct(states, active_indices, canonical_hash, nonce);
        let data_available_after_summary = count_active_data_available(
            states,
            active_indices,
            canonical_hash,
            nonce,
            canonical_data_holders,
        );
        let unique_after_summary = unique_active_epoch_hashes(states, active_indices);
        push_stage_progress(
            stage_progress,
            telemetry,
            recovery_span,
            EpochStageProgressRecord {
                epoch,
                nonce,
                round: Some(repair_round),
                stage: "recovery",
                event: "repair_round",
                nodes: active_nodes,
                dropped_nodes,
                quorums: 0,
                correct_nodes: correct_after_summary,
                incorrect_nodes: active_nodes.saturating_sub(correct_after_summary),
                data_available_nodes: data_available_after_summary,
                data_unavailable_nodes: data_unavailable_nodes(
                    active_nodes,
                    data_available_after_summary,
                ),
                unique_epoch_hashes: unique_after_summary,
                canonical_blocks,
                min_blocks_per_node,
                max_blocks_per_node,
                repaired_nodes: summary_repaired,
                reconnected_nodes: 0,
                canonical_epoch_hash: canonical_hash,
                messages: summary_totals,
            },
        );

        if canonical_blocks > 0
            && !canonical_block_replicas
                .values()
                .all(|holders| !holders.is_empty())
        {
            continue;
        }

        let remaining_incorrect = active_indices
            .iter()
            .filter_map(|index| {
                let state = states[*index];
                (state.last_epoch != canonical_hash || state.nonce != nonce).then_some(*index)
            })
            .collect::<Vec<_>>();

        let reconciliation_span = (!remaining_incorrect.is_empty()).then(|| {
            telemetry.start_stage(
                active_node_keys,
                epoch,
                nonce,
                Some(repair_round),
                "reconciliation",
                "block_set_round",
                active_nodes,
            )
        });
        for recipient in remaining_incorrect {
            reconciliation_sources[recipient].insert(recipient);

            for sender in restart_ping_peers(
                active_indices,
                fanout,
                config.seed ^ 0x7265_636f_6e63_696c,
                epoch,
                repair_round,
                recipient,
            ) {
                let outcome =
                    transport.sample_reconciliation(epoch, repair_round, sender, recipient);
                let (delta, delivered) = repair_outcome_delta(&outcome, config.repair_timeout_ms);
                merge_transport_totals(totals, &delta);
                merge_transport_totals(&mut reconciliation_totals, &delta);
                if delivered {
                    reconciliation_sources[recipient].insert(sender);
                }
            }

            if can_reconstruct_canonical_data(
                canonical_block_replicas,
                &reconciliation_sources[recipient],
                canonical_blocks,
            ) {
                states[recipient] = NodeEpochState {
                    last_epoch: canonical_hash,
                    nonce,
                };
                add_full_data_holder(canonical_data_holders, canonical_block_replicas, recipient);
                totals.repair_successes += 1;
                reconciliation_totals.repair_successes += 1;
                repaired += 1;
                reconciled += 1;
            }
        }

        let correct_nodes = count_active_correct(states, active_indices, canonical_hash, nonce);
        let data_available_nodes = count_active_data_available(
            states,
            active_indices,
            canonical_hash,
            nonce,
            canonical_data_holders,
        );
        let unique_epoch_hashes = unique_active_epoch_hashes(states, active_indices);
        if reconciliation_totals.repair_attempts > 0 {
            push_stage_progress(
                stage_progress,
                telemetry,
                reconciliation_span.flatten(),
                EpochStageProgressRecord {
                    epoch,
                    nonce,
                    round: Some(repair_round),
                    stage: "reconciliation",
                    event: "block_set_round",
                    nodes: active_nodes,
                    dropped_nodes,
                    quorums: 0,
                    correct_nodes,
                    incorrect_nodes: active_nodes.saturating_sub(correct_nodes),
                    data_available_nodes,
                    data_unavailable_nodes: data_unavailable_nodes(
                        active_nodes,
                        data_available_nodes,
                    ),
                    unique_epoch_hashes,
                    canonical_blocks,
                    min_blocks_per_node,
                    max_blocks_per_node,
                    repaired_nodes: reconciled,
                    reconnected_nodes: 0,
                    canonical_epoch_hash: canonical_hash,
                    messages: reconciliation_totals,
                },
            );
        }
    }
    repaired
}

fn repair_outcome_delta(
    outcome: &TransportOutcome,
    timeout_ms: u64,
) -> (EpochTransportTotals, bool) {
    let mut delta = EpochTransportTotals {
        total: 1,
        repair_attempts: 1,
        ..EpochTransportTotals::default()
    };
    if outcome.spiked {
        delta.spiked = 1;
    }
    if outcome.dropped {
        delta.dropped = 1;
        return (delta, false);
    }
    if outcome.fuzzed {
        delta.fuzzed = 1;
        return (delta, false);
    }
    if outcome.delay_ms > timeout_ms {
        delta.late = 1;
        return (delta, false);
    }
    delta.delivered = 1;
    (delta, true)
}

fn reconnect_outcome_delta(
    outcome: &TransportOutcome,
    timeout_ms: u64,
) -> (EpochTransportTotals, bool) {
    let mut delta = EpochTransportTotals {
        total: 1,
        reconnect_attempts: 1,
        ..EpochTransportTotals::default()
    };
    if outcome.spiked {
        delta.spiked = 1;
    }
    if outcome.dropped {
        delta.dropped = 1;
        return (delta, false);
    }
    if outcome.fuzzed {
        delta.fuzzed = 1;
        return (delta, false);
    }
    if outcome.delay_ms > timeout_ms {
        delta.late = 1;
        return (delta, false);
    }
    delta.delivered = 1;
    (delta, true)
}

fn merge_transport_totals(target: &mut EpochTransportTotals, delta: &EpochTransportTotals) {
    target.total += delta.total;
    target.delivered += delta.delivered;
    target.dropped += delta.dropped;
    target.fuzzed += delta.fuzzed;
    target.late += delta.late;
    target.spiked += delta.spiked;
    target.repair_attempts += delta.repair_attempts;
    target.repair_successes += delta.repair_successes;
    target.reconnect_attempts += delta.reconnect_attempts;
    target.reconnect_approvals += delta.reconnect_approvals;
    target.reconnect_catchup_proofs += delta.reconnect_catchup_proofs;
    target.reconnect_replays += delta.reconnect_replays;
    target.reconnect_stale_proofs += delta.reconnect_stale_proofs;
    target.reconnect_duplicate_votes += delta.reconnect_duplicate_votes;
    target.reconnect_identity_rejections += delta.reconnect_identity_rejections;
    target.reconnect_successes += delta.reconnect_successes;
    target.block_transfer_attempts += delta.block_transfer_attempts;
    target.accepted_blocks += delta.accepted_blocks;
    target.denied_blocks += delta.denied_blocks;
    target.accepted_block_bytes += delta.accepted_block_bytes;
    target.denied_block_bytes += delta.denied_block_bytes;
    target.future_round_assists += delta.future_round_assists;
    target.future_round_skipped_messages += delta.future_round_skipped_messages;
    target.future_round_dropped_local_blocks += delta.future_round_dropped_local_blocks;
    target.future_round_carried_forward_blocks += delta.future_round_carried_forward_blocks;
}

fn transport_delta(
    after: &EpochTransportTotals,
    before: &EpochTransportTotals,
) -> EpochTransportTotals {
    EpochTransportTotals {
        total: after.total.saturating_sub(before.total),
        delivered: after.delivered.saturating_sub(before.delivered),
        dropped: after.dropped.saturating_sub(before.dropped),
        fuzzed: after.fuzzed.saturating_sub(before.fuzzed),
        late: after.late.saturating_sub(before.late),
        spiked: after.spiked.saturating_sub(before.spiked),
        repair_attempts: after.repair_attempts.saturating_sub(before.repair_attempts),
        repair_successes: after
            .repair_successes
            .saturating_sub(before.repair_successes),
        reconnect_attempts: after
            .reconnect_attempts
            .saturating_sub(before.reconnect_attempts),
        reconnect_approvals: after
            .reconnect_approvals
            .saturating_sub(before.reconnect_approvals),
        reconnect_catchup_proofs: after
            .reconnect_catchup_proofs
            .saturating_sub(before.reconnect_catchup_proofs),
        reconnect_replays: after
            .reconnect_replays
            .saturating_sub(before.reconnect_replays),
        reconnect_stale_proofs: after
            .reconnect_stale_proofs
            .saturating_sub(before.reconnect_stale_proofs),
        reconnect_duplicate_votes: after
            .reconnect_duplicate_votes
            .saturating_sub(before.reconnect_duplicate_votes),
        reconnect_identity_rejections: after
            .reconnect_identity_rejections
            .saturating_sub(before.reconnect_identity_rejections),
        reconnect_successes: after
            .reconnect_successes
            .saturating_sub(before.reconnect_successes),
        block_transfer_attempts: after
            .block_transfer_attempts
            .saturating_sub(before.block_transfer_attempts),
        accepted_blocks: after.accepted_blocks.saturating_sub(before.accepted_blocks),
        denied_blocks: after.denied_blocks.saturating_sub(before.denied_blocks),
        accepted_block_bytes: after
            .accepted_block_bytes
            .saturating_sub(before.accepted_block_bytes),
        denied_block_bytes: after
            .denied_block_bytes
            .saturating_sub(before.denied_block_bytes),
        future_round_assists: after
            .future_round_assists
            .saturating_sub(before.future_round_assists),
        future_round_skipped_messages: after
            .future_round_skipped_messages
            .saturating_sub(before.future_round_skipped_messages),
        future_round_dropped_local_blocks: after
            .future_round_dropped_local_blocks
            .saturating_sub(before.future_round_dropped_local_blocks),
        future_round_carried_forward_blocks: after
            .future_round_carried_forward_blocks
            .saturating_sub(before.future_round_carried_forward_blocks),
    }
}

fn restart_ping_peers(
    active_indices: &[usize],
    repair_fanout: usize,
    seed: u64,
    epoch: usize,
    repair_round: usize,
    recipient: usize,
) -> Vec<usize> {
    let mut peers = active_indices
        .iter()
        .copied()
        .filter(|index| *index != recipient)
        .collect::<Vec<_>>();
    if peers.is_empty() {
        return peers;
    }

    let mut state = seed
        ^ (epoch as u64).rotate_left(11)
        ^ (repair_round as u64).rotate_left(23)
        ^ (recipient as u64).rotate_left(37)
        ^ 0x9a7c_4831_b10c_cafe;
    for index in (1..peers.len()).rev() {
        state = splitmix64(state);
        peers.swap(index, (state as usize) % (index + 1));
    }
    peers.truncate(repair_fanout.min(peers.len()));
    peers
}

fn build_nodes(count: usize, seed: u64) -> Vec<BenchNode> {
    (0..count)
        .map(|index| {
            let mut secret = [0u8; 32];
            let mut state = seed ^ ((index as u64) << 32) ^ 0xb10c_5011_5eed_f00d;
            for chunk in secret.chunks_mut(8) {
                state = splitmix64(state);
                let bytes = state.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            BenchNode {
                keypair: Keypair::from_secret(SecKey(secret)),
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn signed_block(
    node: &BenchNode,
    epoch: usize,
    node_index: usize,
    last_epoch: HashType,
    nonce: Nonce,
    transactions_per_node: usize,
    transaction_bytes: usize,
    trust_mode: TrustMode,
) -> Block {
    let mut block = Block::default();
    block.body.validator = node.keypair.public;
    block.body.last_epoch = last_epoch;
    block.body.nonce = nonce;
    block.body.created = ((epoch as u128) << 64) | node_index as u128;
    block.body.dispatched = 0;
    block.body.txs = transactions(epoch, node_index, transactions_per_node, transaction_bytes);
    if trust_mode.is_trusted() {
        block.seal_unsigned(node.keypair.public);
    } else {
        block.sign(&node.keypair.secret);
    }
    block
}

fn transactions(
    epoch: usize,
    node_index: usize,
    count: usize,
    transaction_bytes: usize,
) -> Vec<Transaction> {
    (0..count)
        .map(|tx_index| {
            let mut bytes = vec![0; transaction_bytes];
            let mut state = ((epoch as u64) << 48)
                ^ ((node_index as u64) << 24)
                ^ tx_index as u64
                ^ 0x7478_7061_796c_6f61;
            for chunk in bytes.chunks_mut(8) {
                state = splitmix64(state);
                let state_bytes = state.to_le_bytes();
                chunk.copy_from_slice(&state_bytes[..chunk.len()]);
            }
            Transaction::new(bytes)
        })
        .collect()
}

fn round_quorums(keys: &[PubKey], seed: HashType, shuffle: bool) -> Vec<Vec<Vec<usize>>> {
    let index_by_key = keys
        .iter()
        .enumerate()
        .map(|(index, key)| (*key, index))
        .collect::<BTreeMap<_, _>>();
    let mut rounds: Vec<BTreeSet<Vec<usize>>> = Vec::new();

    for key in keys {
        for (round_index, quorum) in select_quorums(keys.iter().copied(), key, seed, shuffle)
            .into_iter()
            .enumerate()
        {
            if round_index >= rounds.len() {
                rounds.push(BTreeSet::new());
            }
            let mut members = quorum
                .iter()
                .filter_map(|key| index_by_key.get(key).copied())
                .collect::<Vec<_>>();
            members.sort_unstable();
            members.dedup();
            rounds[round_index].insert(members);
        }
    }

    rounds
        .into_iter()
        .map(|round| round.into_iter().collect())
        .collect()
}

fn epoch_hash(last_epoch: HashType, nonce: Nonce, blocks_hash: HashType) -> HashType {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(last_epoch.as_ref());
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(blocks_hash.as_ref());
    HashType::hash(&bytes)
}

struct TransportSampler {
    config: EpochChaosConfig,
    sequence: u64,
}

impl TransportSampler {
    fn new(config: EpochChaosConfig) -> Self {
        Self {
            config,
            sequence: 0,
        }
    }

    fn sample(
        &mut self,
        epoch: usize,
        round: usize,
        sender: usize,
        recipient: usize,
    ) -> TransportOutcome {
        self.sample_with_phase(0, epoch, round, sender, recipient)
    }

    fn sample_repair(
        &mut self,
        epoch: usize,
        repair_round: usize,
        sender: usize,
        recipient: usize,
    ) -> TransportOutcome {
        self.sample_with_phase(1, epoch, repair_round, sender, recipient)
    }

    fn sample_repair_fetch(
        &mut self,
        epoch: usize,
        repair_round: usize,
        sender: usize,
        recipient: usize,
    ) -> TransportOutcome {
        self.sample_with_phase(2, epoch, repair_round, sender, recipient)
    }

    fn sample_reconciliation(
        &mut self,
        epoch: usize,
        repair_round: usize,
        sender: usize,
        recipient: usize,
    ) -> TransportOutcome {
        self.sample_with_phase(3, epoch, repair_round, sender, recipient)
    }

    fn sample_reconnect_ping(
        &mut self,
        epoch: usize,
        reconnecting_node: usize,
        peer: usize,
    ) -> TransportOutcome {
        self.sample_with_phase(4, epoch, 0, reconnecting_node, peer)
    }

    fn sample_reconnect_vote(
        &mut self,
        epoch: usize,
        voter: usize,
        reconnecting_node: usize,
    ) -> TransportOutcome {
        self.sample_with_phase(5, epoch, 0, voter, reconnecting_node)
    }

    fn sample_reconnect_catchup(
        &mut self,
        epoch: usize,
        peer: usize,
        reconnecting_node: usize,
    ) -> TransportOutcome {
        self.sample_with_phase(6, epoch, 0, peer, reconnecting_node)
    }

    fn sample_with_phase(
        &mut self,
        phase: u64,
        epoch: usize,
        round: usize,
        sender: usize,
        recipient: usize,
    ) -> TransportOutcome {
        self.sequence += 1;
        let seed = self.config.seed
            ^ phase.rotate_left(3)
            ^ self.sequence.rotate_left(7)
            ^ (epoch as u64).rotate_left(17)
            ^ (round as u64).rotate_left(29)
            ^ (sender as u64).rotate_left(41)
            ^ (recipient as u64).rotate_left(53);
        let jitter = if self.config.jitter_ms == 0 {
            0
        } else {
            splitmix64(seed ^ 0x11) % (self.config.jitter_ms + 1)
        };
        let spiked = sample_rate(seed, 0x22, self.config.spike_ppm);
        let spike = if spiked {
            self.config.spike_latency_ms
        } else {
            0
        };
        let partition_dropped = self
            .config
            .partition_blocks_transport(phase, epoch, sender, recipient);
        TransportOutcome {
            delay_ms: self.config.latency_ms + jitter + spike,
            dropped: partition_dropped || sample_rate(seed, 0x33, self.config.drop_ppm),
            fuzzed: sample_rate(seed, 0x44, self.config.fuzz_ppm),
            spiked,
        }
    }
}

struct TransportOutcome {
    delay_ms: u64,
    dropped: bool,
    fuzzed: bool,
    spiked: bool,
}

fn byzantine_replays_reconnect_evidence(
    config: &EpochChaosConfig,
    epoch: usize,
    source: usize,
    candidate: usize,
    phase: u64,
) -> bool {
    let seed = config.seed
        ^ phase.rotate_left(5)
        ^ (epoch as u64).rotate_left(17)
        ^ (source as u64).rotate_left(31)
        ^ (candidate as u64).rotate_left(47)
        ^ 0xbad0_5e1f_5afe_f00d;
    sample_rate(seed, 0x55, config.byzantine_reconnect_replay_ppm)
}

fn reconnect_candidate_offers_stale_proof(
    config: &EpochChaosConfig,
    epoch: usize,
    candidate: usize,
) -> bool {
    let seed = config.seed
        ^ (epoch as u64).rotate_left(13)
        ^ (candidate as u64).rotate_left(47)
        ^ 0x57a1_e9d0_f00d_beef;
    sample_rate(seed, 0x66, config.byzantine_reconnect_stale_proof_ppm)
}

fn reconnect_candidate_uses_sybil_identity(
    config: &EpochChaosConfig,
    epoch: usize,
    candidate: usize,
) -> bool {
    let seed = config.seed
        ^ (epoch as u64).rotate_left(19)
        ^ (candidate as u64).rotate_left(43)
        ^ 0x51b1_1d00_d15c_a2d5;
    sample_rate(seed, 0x77, config.byzantine_reconnect_sybil_ppm)
}

fn sample_rate(seed: u64, salt: u64, ppm: u32) -> bool {
    ppm > 0 && (splitmix64(seed ^ salt) % CHAOS_RATE_DENOMINATOR as u64) < ppm as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use blossom::{FutureRoundAssistInput, FutureRoundAssistKind, future_round_assist_decision};

    enum ScenarioExpectation {
        Report(fn(&EpochChaosReport)),
        WireProtocol(&'static str),
    }

    struct DeterministicEpochScenario {
        name: &'static str,
        config: EpochChaosConfig,
        expectation: ScenarioExpectation,
    }

    #[test]
    fn deterministic_epoch_vulnerability_scenarios_run_sequentially() {
        let scenarios = vec![
            DeterministicEpochScenario {
                name: "baseline_no_faults",
                config: EpochChaosConfig {
                    nodes: 12,
                    epochs: 3,
                    transactions_per_node: 2,
                    transaction_bytes: 8,
                    seed: 0x5c31_0001,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_baseline_converges),
            },
            DeterministicEpochScenario {
                name: "trusted_accidental_fault_reconnect",
                config: EpochChaosConfig {
                    nodes: 12,
                    epochs: 5,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 3,
                    drop_faulty_after_epochs: 1,
                    max_dropped_nodes_per_epoch: 1,
                    min_active_nodes: 8,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 8,
                    reconnect_ping_quorum: 6,
                    reconnect_approval_quorum: 6,
                    max_reconnected_nodes_per_epoch: 1,
                    trust_mode: TrustMode::Trusted,
                    seed: 0x5c31_0002,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_trusted_reconnects_all_faults),
            },
            DeterministicEpochScenario {
                name: "byzantine_duplicate_votes_deduped",
                config: EpochChaosConfig {
                    nodes: 16,
                    epochs: 3,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 1,
                    byzantine_nodes: 5,
                    byzantine_duplicate_vote_copies: 3,
                    drop_faulty_after_epochs: 1,
                    max_dropped_nodes_per_epoch: 1,
                    min_active_nodes: 10,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 15,
                    reconnect_ping_quorum: 10,
                    reconnect_approval_quorum: 11,
                    max_reconnected_nodes_per_epoch: 1,
                    seed: 0x5c31_0003,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_duplicate_votes_deduped),
            },
            DeterministicEpochScenario {
                name: "replay_evidence_blocked",
                config: EpochChaosConfig {
                    nodes: 16,
                    epochs: 3,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 1,
                    byzantine_nodes: 5,
                    byzantine_reconnect_replay_ppm: CHAOS_RATE_DENOMINATOR,
                    drop_faulty_after_epochs: 1,
                    max_dropped_nodes_per_epoch: 1,
                    min_active_nodes: 10,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 15,
                    reconnect_ping_quorum: 11,
                    reconnect_approval_quorum: 11,
                    max_reconnected_nodes_per_epoch: 1,
                    seed: 0x5c31_0004,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_replay_blocks_reconnect),
            },
            DeterministicEpochScenario {
                name: "stale_catchup_proof_blocked",
                config: EpochChaosConfig {
                    nodes: 16,
                    epochs: 3,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 1,
                    byzantine_nodes: 5,
                    byzantine_reconnect_stale_proof_ppm: CHAOS_RATE_DENOMINATOR,
                    byzantine_duplicate_vote_copies: 3,
                    drop_faulty_after_epochs: 1,
                    max_dropped_nodes_per_epoch: 1,
                    min_active_nodes: 10,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 15,
                    reconnect_ping_quorum: 10,
                    reconnect_approval_quorum: 10,
                    max_reconnected_nodes_per_epoch: 1,
                    seed: 0x5c31_0005,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_stale_proof_blocks_reconnect),
            },
            DeterministicEpochScenario {
                name: "sybil_identity_blocked",
                config: EpochChaosConfig {
                    nodes: 16,
                    epochs: 3,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 1,
                    byzantine_nodes: 5,
                    byzantine_reconnect_sybil_ppm: CHAOS_RATE_DENOMINATOR,
                    drop_faulty_after_epochs: 1,
                    max_dropped_nodes_per_epoch: 1,
                    min_active_nodes: 10,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 15,
                    reconnect_ping_quorum: 10,
                    reconnect_approval_quorum: 10,
                    max_reconnected_nodes_per_epoch: 1,
                    seed: 0x5c31_0006,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_sybil_identity_blocked),
            },
            DeterministicEpochScenario {
                name: "partitioned_reconnect_waits_until_merge",
                config: EpochChaosConfig {
                    nodes: 12,
                    epochs: 5,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 1,
                    drop_faulty_after_epochs: 1,
                    max_dropped_nodes_per_epoch: 1,
                    min_active_nodes: 8,
                    repair_rounds: 3,
                    repair_fanout: 11,
                    repair_quorum: 8,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 11,
                    reconnect_ping_quorum: 8,
                    reconnect_approval_quorum: 8,
                    max_reconnected_nodes_per_epoch: 1,
                    partition_start_epoch: Some(1),
                    partition_end_epoch: Some(3),
                    partition_left_nodes: 6,
                    partition_reconnect_only: true,
                    seed: 0x5c31_0007,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_partition_reconnects_after_merge),
            },
            DeterministicEpochScenario {
                name: "dos_reconnect_pressure_rate_limited",
                config: EpochChaosConfig {
                    nodes: 24,
                    epochs: 3,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 8,
                    drop_faulty_after_epochs: 1,
                    max_dropped_nodes_per_epoch: 8,
                    min_active_nodes: 12,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 23,
                    reconnect_ping_quorum: 16,
                    reconnect_approval_quorum: 16,
                    max_reconnected_nodes_per_epoch: 2,
                    seed: 0x5c31_0008,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_reconnect_dos_rate_limited),
            },
            DeterministicEpochScenario {
                name: "simultaneous_drop_reconnect_under_load",
                config: EpochChaosConfig {
                    nodes: 24,
                    epochs: 6,
                    transactions_per_node: 4,
                    transaction_bytes: 16,
                    faulty_nodes: 8,
                    drop_faulty_after_epochs: 1,
                    max_dropped_nodes_per_epoch: 2,
                    min_active_nodes: 12,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 23,
                    reconnect_ping_quorum: 16,
                    reconnect_approval_quorum: 16,
                    max_reconnected_nodes_per_epoch: 2,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::Report(assert_simultaneous_churn_consistent),
            },
            DeterministicEpochScenario {
                name: "unsafe_low_reconnect_quorum_rejected",
                config: EpochChaosConfig {
                    nodes: 16,
                    epochs: 3,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 1,
                    byzantine_nodes: 5,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 15,
                    reconnect_ping_quorum: 6,
                    reconnect_approval_quorum: 5,
                    seed: 0x5c31_000a,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::WireProtocol("trustless reconnect_ping_quorum"),
            },
            DeterministicEpochScenario {
                name: "impossible_high_reconnect_quorum_rejected",
                config: EpochChaosConfig {
                    nodes: 8,
                    epochs: 2,
                    transactions_per_node: 1,
                    transaction_bytes: 8,
                    faulty_nodes: 1,
                    reconnect_dropped_after_epochs: 1,
                    reconnect_ping_fanout: 7,
                    reconnect_ping_quorum: 8,
                    reconnect_approval_quorum: 7,
                    seed: 0x5c31_000b,
                    ..EpochChaosConfig::default()
                },
                expectation: ScenarioExpectation::WireProtocol("reconnect_ping_quorum"),
            },
        ];

        for scenario in scenarios {
            match scenario.expectation {
                ScenarioExpectation::Report(assertion) => {
                    println!("scenario {}: running", scenario.name);
                    let first = run_epoch_chaos(scenario.config.clone())
                        .unwrap_or_else(|error| panic!("{} failed: {error:?}", scenario.name));
                    let second = run_epoch_chaos(scenario.config).unwrap_or_else(|error| {
                        panic!("{} failed on replay: {error:?}", scenario.name)
                    });
                    assert_eq!(first, second, "{} was not deterministic", scenario.name);
                    assertion(&first);
                    println!("scenario {}: passed", scenario.name);
                }
                ScenarioExpectation::WireProtocol(expected) => {
                    println!("scenario {}: running", scenario.name);
                    let first = wire_protocol_error(scenario.name, scenario.config.clone());
                    let second = wire_protocol_error(scenario.name, scenario.config);
                    assert_eq!(
                        first, second,
                        "{} error was not deterministic",
                        scenario.name
                    );
                    assert!(
                        first.contains(expected),
                        "{} error did not contain {expected:?}: {first}",
                        scenario.name
                    );
                    println!("scenario {}: passed with expected error", scenario.name);
                }
            }
        }
    }

    fn wire_protocol_error(name: &str, config: EpochChaosConfig) -> String {
        match run_epoch_chaos(config) {
            Ok(report) => panic!("{name} unexpectedly succeeded: {report:?}"),
            Err(blossom::BlossomError::WireProtocol(message)) => message,
            Err(error) => panic!("{name} returned unexpected error: {error:?}"),
        }
    }

    fn validation_wire_protocol_error(name: &str, config: EpochChaosConfig) -> String {
        match config.validate() {
            Ok(()) => panic!("{name} unexpectedly validated: {config:?}"),
            Err(blossom::BlossomError::WireProtocol(message)) => message,
            Err(error) => panic!("{name} returned unexpected error: {error:?}"),
        }
    }

    fn default_future_round_assist_input() -> FutureRoundAssistInput {
        FutureRoundAssistInput {
            kind: FutureRoundAssistKind::RoundChangeSkip,
            last_certified_round: Some(1),
            target_round: 3,
            skip_certificates: 1,
            first_fanout_completed: true,
            local_block_in_candidate: false,
            local_block_replicated: true,
            parent_data_replicated: true,
            parent_data_repairable: true,
            holds_unreplicated_parent_data: false,
            future_body_validated: false,
        }
    }

    #[test]
    fn incorrectly_lost_local_blocks_counts_expected_hashes_without_replicas() {
        let retained = HashType([1; 32]);
        let empty_replica = HashType([2; 32]);
        let missing_replica = HashType([3; 32]);
        let expected = [retained, empty_replica, missing_replica]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let replicas = [
            (retained, [0usize].into_iter().collect::<BTreeSet<_>>()),
            (empty_replica, BTreeSet::new()),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>();

        assert_eq!(count_incorrectly_lost_local_blocks(&expected, &replicas), 2);
    }

    #[test]
    fn first_round_skip_drops_unshared_local_block_before_future_assist() {
        let decision = future_round_assist_decision(FutureRoundAssistInput {
            last_certified_round: None,
            target_round: 1,
            skip_certificates: 1,
            first_fanout_completed: false,
            local_block_in_candidate: true,
            local_block_replicated: false,
            parent_data_replicated: true,
            parent_data_repairable: true,
            ..default_future_round_assist_input()
        });

        assert_eq!(
            decision,
            FutureRoundAssistDecision::AssistDroppingLocalBlock
        );
    }

    #[test]
    fn round_three_assist_carries_round_one_without_round_two_data() {
        let decision = future_round_assist_decision(default_future_round_assist_input());

        assert_eq!(decision, FutureRoundAssistDecision::Assist);
    }

    #[test]
    fn future_round_assist_buffers_when_skip_certificate_is_missing() {
        let decision = future_round_assist_decision(FutureRoundAssistInput {
            skip_certificates: 0,
            ..default_future_round_assist_input()
        });

        assert_eq!(decision, FutureRoundAssistDecision::BufferForCertificates);
    }

    #[test]
    fn future_round_assist_buffers_when_parent_data_is_not_repairable() {
        let decision = future_round_assist_decision(FutureRoundAssistInput {
            parent_data_replicated: false,
            parent_data_repairable: false,
            ..default_future_round_assist_input()
        });

        assert_eq!(decision, FutureRoundAssistDecision::BufferForRepair);
    }

    #[test]
    fn future_round_assist_serves_unreplicated_certified_data_before_voting() {
        let decision = future_round_assist_decision(FutureRoundAssistInput {
            parent_data_replicated: false,
            parent_data_repairable: true,
            holds_unreplicated_parent_data: true,
            ..default_future_round_assist_input()
        });

        assert_eq!(decision, FutureRoundAssistDecision::ServeDataBeforeAssist);
    }

    #[test]
    fn data_bearing_future_round_assist_requires_validated_body() {
        let decision = future_round_assist_decision(FutureRoundAssistInput {
            kind: FutureRoundAssistKind::DataBearing,
            future_body_validated: false,
            ..default_future_round_assist_input()
        });

        assert_eq!(
            decision,
            FutureRoundAssistDecision::RejectDataVoteUntilValidated
        );
    }

    #[test]
    fn skipped_first_fanout_drops_unshared_local_blocks_in_epoch_sim() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 1,
            transactions_per_node: 1,
            transaction_bytes: 8,
            assist_after_skipped_round: Some(0),
            ..EpochChaosConfig::default()
        })
        .unwrap();
        let epoch = &report.epochs[0];

        assert_eq!(epoch.canonical_blocks, 0);
        assert_eq!(epoch.min_blocks_per_node, 0);
        assert_eq!(epoch.max_blocks_per_node, 0);
        assert_eq!(report.future_round_assists, 12);
        assert_eq!(report.future_round_dropped_local_blocks, 12);
        assert_eq!(report.future_round_carried_forward_blocks, 0);
        assert_eq!(report.valid_local_blocks, 12);
        assert_eq!(report.intentionally_dropped_local_blocks, 12);
        assert_eq!(report.incorrectly_lost_local_blocks, 0);
        assert_eq!(epoch.valid_local_blocks, 12);
        assert_eq!(epoch.intentionally_dropped_local_blocks, 12);
        assert_eq!(epoch.incorrectly_lost_local_blocks, 0);
        assert!(report.future_round_skipped_messages > 0);
        assert_eq!(report.final_correct_nodes, 12);
        assert_eq!(report.final_data_available_nodes, 12);
        assert_eq!(report.final_data_unavailable_nodes, 0);
        assert_eq!(epoch.data_available_nodes, 12);
        assert_eq!(epoch.data_unavailable_nodes, 0);
        assert_eq!(report.final_unique_epoch_hashes, 1);
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "dispatch"
                && record.event == "round_skipped_assist"
                && record.round == Some(0)
                && record.messages.future_round_dropped_local_blocks == 0
                && record.messages.future_round_assists == 12
        }));
    }

    #[test]
    fn skipped_later_round_preserves_blocks_after_first_fanout() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 1,
            transactions_per_node: 1,
            transaction_bytes: 8,
            assist_after_skipped_round: Some(1),
            repair_rounds: 4,
            repair_fanout: 11,
            repair_quorum: 8,
            repair_timeout_ms: 100,
            ..EpochChaosConfig::default()
        })
        .unwrap();
        let epoch = &report.epochs[0];

        assert_eq!(epoch.canonical_blocks, 12);
        assert_eq!(report.future_round_dropped_local_blocks, 0);
        assert_eq!(report.future_round_carried_forward_blocks, 12);
        assert_eq!(report.valid_local_blocks, 12);
        assert_eq!(report.intentionally_dropped_local_blocks, 0);
        assert_eq!(report.incorrectly_lost_local_blocks, 0);
        assert_eq!(epoch.valid_local_blocks, 12);
        assert_eq!(epoch.intentionally_dropped_local_blocks, 0);
        assert_eq!(epoch.incorrectly_lost_local_blocks, 0);
        assert_eq!(report.future_round_assists, 12);
        assert!(report.future_round_skipped_messages > 0);
        assert_eq!(report.final_correct_nodes, 12);
        assert_eq!(report.final_data_available_nodes, 12);
        assert_eq!(report.final_data_unavailable_nodes, 0);
        assert_eq!(epoch.data_available_nodes, 12);
        assert_eq!(epoch.data_unavailable_nodes, 0);
        assert_eq!(report.final_unique_epoch_hashes, 1);
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "dispatch"
                && record.event == "round_skipped_assist"
                && record.round == Some(1)
                && record.messages.future_round_assists == 12
                && record.messages.future_round_carried_forward_blocks == 12
        }));
    }

    fn assert_baseline_converges(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        assert_eq!(report.final_active_nodes, report.config.nodes);
        assert_eq!(report.final_dropped_nodes, 0);
        assert_eq!(report.final_correct_nodes, report.config.nodes);
        assert_eq!(report.final_incorrect_nodes, 0);
        assert_eq!(report.final_unique_epoch_hashes, 1);
    }

    fn assert_trusted_reconnects_all_faults(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        assert_eq!(report.dropped_node_keys.len(), 3);
        assert_eq!(report.reconnected_node_keys.len(), 3);
        assert_eq!(report.reconnect_successes, 3);
        assert_eq!(report.final_active_nodes, 12);
        assert_eq!(report.final_correct_nodes, 12);
    }

    fn assert_duplicate_votes_deduped(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        assert_eq!(report.reconnect_successes, 1);
        assert!(report.reconnect_duplicate_votes > 0);
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "membership_reconnect"
                && record.event == "admission_vote"
                && record.messages.reconnect_duplicate_votes > 0
                && record.messages.reconnect_approvals <= record.nodes as u64
        }));
    }

    fn assert_replay_blocks_reconnect(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        assert!(report.reconnect_replays > 0);
        assert_eq!(report.reconnect_successes, 0);
        assert_eq!(report.final_dropped_nodes, 1);
    }

    fn assert_stale_proof_blocks_reconnect(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        assert!(report.reconnect_stale_proofs > 0);
        assert_eq!(report.reconnect_catchup_proofs, 0);
        assert_eq!(report.reconnect_successes, 0);
        assert_eq!(report.final_dropped_nodes, 1);
    }

    fn assert_sybil_identity_blocked(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        assert!(report.reconnect_identity_rejections > 0);
        assert_eq!(report.reconnect_catchup_proofs, 0);
        assert_eq!(report.reconnect_successes, 0);
        assert_eq!(report.final_dropped_nodes, 1);
    }

    fn assert_partition_reconnects_after_merge(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        let reconnect_epoch = report
            .stage_progress
            .iter()
            .find(|record| {
                record.stage == "membership_reconnect"
                    && record.event == "admission_vote"
                    && record.reconnected_nodes > 0
            })
            .map(|record| record.epoch)
            .expect("node should reconnect after partition merge");
        assert!(reconnect_epoch >= 3);
        assert_eq!(report.reconnect_successes, 1);
        assert_eq!(report.final_active_nodes, 12);
        assert_eq!(report.final_dropped_nodes, 0);
    }

    fn assert_reconnect_dos_rate_limited(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        assert_eq!(report.dropped_node_keys.len(), 8);
        assert_eq!(report.reconnect_successes, 4);
        assert_eq!(report.final_dropped_nodes, 4);
        assert!(
            report
                .epochs
                .iter()
                .all(|epoch| epoch.reconnected_nodes <= 2)
        );
    }

    fn assert_simultaneous_churn_consistent(report: &EpochChaosReport) {
        assert_no_incorrect_data_loss(report);
        let pruning_epochs = report
            .stage_progress
            .iter()
            .filter(|record| record.stage == "membership_pruning")
            .map(|record| record.epoch)
            .collect::<BTreeSet<_>>();
        let reconnect_epochs = report
            .stage_progress
            .iter()
            .filter(|record| {
                record.stage == "membership_reconnect"
                    && record.event == "admission_vote"
                    && record.reconnected_nodes > 0
            })
            .map(|record| record.epoch)
            .collect::<BTreeSet<_>>();
        assert!(
            pruning_epochs
                .iter()
                .any(|epoch| reconnect_epochs.contains(epoch))
        );
        assert_eq!(report.final_correct_nodes, report.final_active_nodes);
        assert_eq!(report.final_unique_epoch_hashes, 1);
    }

    fn assert_no_incorrect_data_loss(report: &EpochChaosReport) {
        assert_eq!(report.incorrectly_lost_local_blocks, 0);
        assert!(report.epochs.iter().all(|epoch| {
            epoch.incorrectly_lost_local_blocks == 0
                && epoch.valid_local_blocks
                    == epoch.intentionally_dropped_local_blocks + epoch.canonical_blocks
        }));
    }

    #[test]
    fn no_fault_epoch_chaos_converges() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 3,
            transactions_per_node: 2,
            transaction_bytes: 8,
            ..EpochChaosConfig::default()
        })
        .unwrap();
        assert_eq!(report.final_correct_nodes, 12);
        assert_eq!(report.final_unique_epoch_hashes, 1);
        assert!(report.block_transfer_attempts > 0);
        assert_eq!(report.denied_blocks, 0);
        assert_eq!(report.denied_block_bytes, 0);
        assert_eq!(report.block_transfer_attempts, report.accepted_blocks);
        assert!(report.accepted_block_bytes > 0);
    }

    #[test]
    fn stage_progress_records_epoch_checkpoints() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 1,
            transactions_per_node: 1,
            transaction_bytes: 8,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "block_formation"
                && record.event == "formed"
                && record.canonical_blocks == 12
        }));
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "membership_topology"
                && record.event == "selected"
                && record.quorums > 0
        }));
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "dispatch"
                && record.event == "round_delivered"
                && record.round.is_some()
                && record.messages.total > 0
        }));
        let finality = report
            .stage_progress
            .iter()
            .find(|record| record.stage == "epoch_finality" && record.event == "finalized")
            .expect("finality checkpoint should be logged");
        assert_eq!(finality.correct_nodes, report.final_correct_nodes);
        assert_eq!(
            finality.unique_epoch_hashes,
            report.final_unique_epoch_hashes
        );
        assert_eq!(
            finality.canonical_epoch_hash,
            report.final_correct_epoch_hash
        );
    }

    #[test]
    fn faulty_nodes_are_dropped_from_active_membership() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 4,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 3,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 8,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.final_active_nodes, 9);
        assert_eq!(report.final_dropped_nodes, 3);
        assert_eq!(report.dropped_node_keys.len(), 3);
        assert_eq!(report.final_correct_nodes, report.final_active_nodes);
        assert_eq!(report.final_unique_epoch_hashes, 1);

        let pruning = report
            .stage_progress
            .iter()
            .filter(|record| record.stage == "membership_pruning" && record.event == "node_dropped")
            .collect::<Vec<_>>();
        assert_eq!(pruning.len(), 3);
        assert_eq!(
            pruning
                .iter()
                .map(|record| record.nodes)
                .collect::<Vec<_>>(),
            vec![11, 10, 9]
        );
        assert_eq!(
            pruning
                .iter()
                .map(|record| record.dropped_nodes)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(
            report
                .epochs
                .iter()
                .all(|epoch| epoch.active_nodes + epoch.dropped_nodes == 12)
        );
    }

    #[test]
    fn bad_sub_quorum_member_blocks_are_denied_and_measured() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 1,
            transactions_per_node: 2,
            transaction_bytes: 16,
            faulty_nodes: 1,
            drop_faulty_after_epochs: 99,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.final_active_nodes, 12);
        assert_eq!(report.final_dropped_nodes, 0);
        assert!(report.accepted_blocks > 0);
        assert!(report.denied_blocks > 0);
        assert!(report.accepted_block_bytes > 0);
        assert!(report.denied_block_bytes > 0);
        assert_eq!(
            report.block_transfer_attempts,
            report.accepted_blocks + report.denied_blocks
        );
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "dispatch"
                && record.event == "round_delivered"
                && record.messages.denied_blocks > 0
        }));
    }

    #[test]
    fn trusted_dropped_nodes_reconnect_after_peer_ping_and_admission_vote() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 5,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 3,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 8,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 8,
            reconnect_ping_quorum: 6,
            reconnect_approval_quorum: 6,
            max_reconnected_nodes_per_epoch: 1,
            trust_mode: TrustMode::Trusted,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.dropped_node_keys.len(), 3);
        assert_eq!(report.reconnected_node_keys.len(), 3);
        assert_eq!(report.final_active_nodes, 12);
        assert_eq!(report.final_dropped_nodes, 0);
        assert_eq!(report.final_correct_nodes, 12);
        assert_eq!(report.final_unique_epoch_hashes, 1);
        assert!(report.reconnect_attempts > 0);
        assert!(report.reconnect_approvals > 0);
        assert_eq!(report.reconnect_successes, 3);
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "membership_reconnect"
                && record.event == "peer_ping"
                && record.messages.reconnect_attempts > 0
        }));
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "membership_reconnect"
                && record.event == "admission_vote"
                && record.reconnected_nodes > 0
        }));
    }

    #[test]
    fn trustless_dropped_nodes_reconnect_with_byzantine_safe_quorums() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 5,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 2,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 8,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 11,
            reconnect_ping_quorum: 8,
            reconnect_approval_quorum: 8,
            max_reconnected_nodes_per_epoch: 1,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.dropped_node_keys.len(), 2);
        assert_eq!(report.reconnected_node_keys.len(), 2);
        assert_eq!(report.final_active_nodes, 12);
        assert_eq!(report.final_dropped_nodes, 0);
        assert_eq!(report.final_correct_nodes, 12);
        assert_eq!(report.reconnect_successes, 2);
        assert_eq!(report.reconnect_catchup_proofs, 2);
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "membership_reconnect"
                && record.event == "catchup_proof"
                && record.messages.reconnect_catchup_proofs > 0
        }));
    }

    #[test]
    fn byzantine_admission_abuse_cannot_approve_stale_node() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 16,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 1,
            byzantine_nodes: 5,
            byzantine_reconnect_stale_proof_ppm: CHAOS_RATE_DENOMINATOR,
            byzantine_duplicate_vote_copies: 3,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 10,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 15,
            reconnect_ping_quorum: 10,
            reconnect_approval_quorum: 10,
            max_reconnected_nodes_per_epoch: 1,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert!(report.reconnect_attempts > 0);
        assert!(report.reconnect_stale_proofs > 0);
        assert_eq!(report.reconnect_catchup_proofs, 0);
        assert_eq!(report.reconnect_successes, 0);
        assert_eq!(report.final_dropped_nodes, 1);
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "membership_reconnect"
                && record.event == "catchup_proof"
                && record.messages.reconnect_stale_proofs > 0
                && record.messages.reconnect_catchup_proofs == 0
        }));
    }

    #[test]
    fn reconnect_rejects_sybil_identity_attempts() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 16,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 1,
            byzantine_nodes: 5,
            byzantine_reconnect_sybil_ppm: CHAOS_RATE_DENOMINATOR,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 10,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 15,
            reconnect_ping_quorum: 10,
            reconnect_approval_quorum: 10,
            max_reconnected_nodes_per_epoch: 1,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert!(report.reconnect_identity_rejections > 0);
        assert_eq!(report.reconnect_catchup_proofs, 0);
        assert_eq!(report.reconnect_successes, 0);
        assert_eq!(report.final_dropped_nodes, 1);
    }

    #[test]
    fn partitioned_reconnect_waits_until_merge() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 5,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 1,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 8,
            repair_rounds: 3,
            repair_fanout: 11,
            repair_quorum: 8,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 11,
            reconnect_ping_quorum: 8,
            reconnect_approval_quorum: 8,
            max_reconnected_nodes_per_epoch: 1,
            partition_start_epoch: Some(1),
            partition_end_epoch: Some(3),
            partition_left_nodes: 6,
            partition_reconnect_only: true,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        let reconnect_epoch = report
            .stage_progress
            .iter()
            .find(|record| {
                record.stage == "membership_reconnect"
                    && record.event == "admission_vote"
                    && record.reconnected_nodes > 0
            })
            .map(|record| record.epoch)
            .expect("node should reconnect after partition merge");
        assert!(reconnect_epoch >= 3);
        assert_eq!(report.reconnect_successes, 1);
        assert_eq!(report.final_active_nodes, 12);
        assert_eq!(report.final_dropped_nodes, 0);
    }

    #[test]
    fn many_dropped_nodes_reconnect_are_rate_limited() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 24,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 8,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 8,
            min_active_nodes: 12,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 23,
            reconnect_ping_quorum: 16,
            reconnect_approval_quorum: 16,
            max_reconnected_nodes_per_epoch: 2,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.dropped_node_keys.len(), 8);
        assert_eq!(report.reconnect_successes, 4);
        assert_eq!(report.final_dropped_nodes, 4);
        assert!(
            report
                .epochs
                .iter()
                .all(|epoch| epoch.reconnected_nodes <= 2)
        );
    }

    #[test]
    fn simultaneous_drop_and_reconnect_under_load_remains_consistent() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 24,
            epochs: 6,
            transactions_per_node: 4,
            transaction_bytes: 16,
            faulty_nodes: 8,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 2,
            min_active_nodes: 12,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 23,
            reconnect_ping_quorum: 16,
            reconnect_approval_quorum: 16,
            max_reconnected_nodes_per_epoch: 2,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        let pruning_epochs = report
            .stage_progress
            .iter()
            .filter(|record| record.stage == "membership_pruning")
            .map(|record| record.epoch)
            .collect::<BTreeSet<_>>();
        let reconnect_epochs = report
            .stage_progress
            .iter()
            .filter(|record| {
                record.stage == "membership_reconnect"
                    && record.event == "admission_vote"
                    && record.reconnected_nodes > 0
            })
            .map(|record| record.epoch)
            .collect::<BTreeSet<_>>();
        assert!(
            pruning_epochs
                .iter()
                .any(|epoch| reconnect_epochs.contains(epoch))
        );
        assert_eq!(report.final_correct_nodes, report.final_active_nodes);
        assert_eq!(report.final_unique_epoch_hashes, 1);
    }

    #[test]
    fn byzantine_nodes_are_assigned_deterministically_and_reported() {
        let config = EpochChaosConfig {
            nodes: 16,
            epochs: 1,
            transactions_per_node: 1,
            transaction_bytes: 8,
            byzantine_nodes: 5,
            ..EpochChaosConfig::default()
        };
        let first = run_epoch_chaos(config.clone()).unwrap();
        let second = run_epoch_chaos(config).unwrap();

        assert_eq!(first.byzantine_node_keys.len(), 5);
        assert_eq!(first.byzantine_node_keys, second.byzantine_node_keys);
        assert_eq!(first.max_byzantine_nodes_for_safety, 5);
        assert!(!first.byzantine_tolerance_exceeded);
    }

    #[test]
    fn trusted_mode_rejects_byzantine_attack_knobs() {
        let error = run_epoch_chaos(EpochChaosConfig {
            nodes: 10,
            epochs: 1,
            transactions_per_node: 1,
            transaction_bytes: 8,
            byzantine_nodes: 1,
            trust_mode: TrustMode::Trusted,
            ..EpochChaosConfig::default()
        })
        .unwrap_err();

        match error {
            blossom::BlossomError::WireProtocol(message) => {
                assert!(message.contains("trusted mode models accidental faults"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn trustless_mode_rejects_byzantine_tolerance_excess() {
        let error = run_epoch_chaos(EpochChaosConfig {
            nodes: 10,
            epochs: 1,
            transactions_per_node: 1,
            transaction_bytes: 8,
            byzantine_nodes: 4,
            ..EpochChaosConfig::default()
        })
        .unwrap_err();

        match error {
            blossom::BlossomError::WireProtocol(message) => {
                assert!(message.contains("at most 3 Byzantine nodes"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn trustless_byzantine_threshold_accepts_max_and_rejects_next() {
        for nodes in 1..=96 {
            let max_byzantine = max_byzantine_nodes_for_safety(nodes);
            let safe_config = EpochChaosConfig {
                nodes,
                epochs: 1,
                transactions_per_node: 1,
                transaction_bytes: 1,
                byzantine_nodes: max_byzantine,
                ..EpochChaosConfig::default()
            };
            safe_config.validate().unwrap_or_else(|error| {
                panic!("nodes={nodes} max_byzantine={max_byzantine}: {error:?}")
            });

            if max_byzantine < nodes {
                let unsafe_config = EpochChaosConfig {
                    byzantine_nodes: max_byzantine + 1,
                    ..safe_config
                };
                let message =
                    validation_wire_protocol_error("byzantine threshold excess", unsafe_config);
                assert!(
                    message.contains("trustless mode supports at most"),
                    "nodes={nodes} max_byzantine={max_byzantine}: {message}"
                );
            }
        }

        for nodes in [4usize, 10, 16, 31, 64] {
            let max_byzantine = max_byzantine_nodes_for_safety(nodes);
            let report = run_epoch_chaos(EpochChaosConfig {
                nodes,
                epochs: 1,
                transactions_per_node: 1,
                transaction_bytes: 1,
                byzantine_nodes: max_byzantine,
                seed: nodes as u64,
                ..EpochChaosConfig::default()
            })
            .unwrap();

            assert_eq!(report.byzantine_node_keys.len(), max_byzantine);
            assert_eq!(report.max_byzantine_nodes_for_safety, max_byzantine);
            assert!(!report.byzantine_tolerance_exceeded);
        }
    }

    #[test]
    fn trustless_repair_quorum_threshold_boundary_is_enforced() {
        for nodes in [4usize, 5, 6, 7, 10, 16, 31, 64] {
            let quorum = supermajority_count(nodes);
            let safe_config = EpochChaosConfig {
                nodes,
                epochs: 1,
                transactions_per_node: 1,
                transaction_bytes: 1,
                repair_rounds: 1,
                repair_fanout: nodes - 1,
                repair_quorum: quorum,
                ..EpochChaosConfig::default()
            };
            safe_config
                .validate()
                .unwrap_or_else(|error| panic!("nodes={nodes} quorum={quorum}: {error:?}"));

            let unsafe_config = EpochChaosConfig {
                repair_quorum: quorum - 1,
                ..safe_config
            };
            let message =
                validation_wire_protocol_error("repair quorum below supermajority", unsafe_config);
            assert!(
                message.contains("trustless repair_quorum"),
                "nodes={nodes} quorum={quorum}: {message}"
            );
        }
    }

    #[test]
    fn trustless_reconnect_quorum_threshold_boundary_is_enforced() {
        for nodes in [4usize, 5, 6, 7, 10, 16, 31, 64] {
            let active_peers = nodes - 1;
            let quorum = supermajority_count(active_peers);
            let safe_config = EpochChaosConfig {
                nodes,
                epochs: 1,
                transactions_per_node: 1,
                transaction_bytes: 1,
                reconnect_dropped_after_epochs: 1,
                reconnect_ping_fanout: active_peers,
                reconnect_ping_quorum: quorum,
                reconnect_approval_quorum: quorum,
                ..EpochChaosConfig::default()
            };
            safe_config.validate().unwrap_or_else(|error| {
                panic!("nodes={nodes} active_peers={active_peers} quorum={quorum}: {error:?}")
            });

            let low_ping_config = EpochChaosConfig {
                reconnect_ping_quorum: quorum - 1,
                ..safe_config.clone()
            };
            let message = validation_wire_protocol_error(
                "reconnect ping quorum below supermajority",
                low_ping_config,
            );
            assert!(
                message.contains("trustless reconnect_ping_quorum"),
                "nodes={nodes} active_peers={active_peers} quorum={quorum}: {message}"
            );

            let low_approval_config = EpochChaosConfig {
                reconnect_approval_quorum: quorum - 1,
                ..safe_config
            };
            let message = validation_wire_protocol_error(
                "reconnect approval quorum below supermajority",
                low_approval_config,
            );
            assert!(
                message.contains("trustless reconnect_approval_quorum"),
                "nodes={nodes} active_peers={active_peers} quorum={quorum}: {message}"
            );
        }
    }

    #[test]
    fn trustless_reconnect_succeeds_at_exact_supermajority_threshold() {
        for nodes in [8usize, 12, 16] {
            let active_peers = nodes - 1;
            let quorum = supermajority_count(active_peers);
            let report = run_epoch_chaos(EpochChaosConfig {
                nodes,
                epochs: 4,
                transactions_per_node: 1,
                transaction_bytes: 8,
                faulty_nodes: 1,
                drop_faulty_after_epochs: 1,
                max_dropped_nodes_per_epoch: 1,
                reconnect_dropped_after_epochs: 1,
                reconnect_ping_fanout: active_peers,
                reconnect_ping_quorum: quorum,
                reconnect_approval_quorum: quorum,
                max_reconnected_nodes_per_epoch: 1,
                seed: nodes as u64,
                ..EpochChaosConfig::default()
            })
            .unwrap();

            assert_eq!(report.reconnect_successes, 1, "nodes={nodes}");
            assert_eq!(report.final_dropped_nodes, 0, "nodes={nodes}");
            assert_eq!(report.final_correct_nodes, nodes, "nodes={nodes}");
        }
    }

    #[test]
    fn byzantine_duplicate_reconnect_votes_are_deduplicated() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 16,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 1,
            byzantine_nodes: 5,
            byzantine_duplicate_vote_copies: 3,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 10,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 15,
            reconnect_ping_quorum: 10,
            reconnect_approval_quorum: 11,
            max_reconnected_nodes_per_epoch: 1,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.reconnect_successes, 1);
        assert!(report.reconnect_duplicate_votes > 0);
        let admission = report
            .stage_progress
            .iter()
            .find(|record| {
                record.stage == "membership_reconnect" && record.event == "admission_vote"
            })
            .expect("admission vote stage should be recorded");
        assert!(admission.messages.reconnect_duplicate_votes > 0);
        assert!(admission.messages.reconnect_approvals <= admission.nodes as u64);
    }

    #[test]
    fn byzantine_replayed_reconnect_evidence_does_not_satisfy_ping_quorum() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 16,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 1,
            byzantine_nodes: 5,
            byzantine_reconnect_replay_ppm: CHAOS_RATE_DENOMINATOR,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 10,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 15,
            reconnect_ping_quorum: 11,
            reconnect_approval_quorum: 11,
            max_reconnected_nodes_per_epoch: 1,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert!(report.reconnect_attempts > 0);
        assert!(report.reconnect_replays > 0);
        assert_eq!(report.reconnect_successes, 0);
        assert!(report.reconnected_node_keys.is_empty());
        assert_eq!(report.final_active_nodes, 15);
        assert_eq!(report.final_dropped_nodes, 1);
    }

    #[test]
    fn trustless_reconnect_requires_supermajority_quorums() {
        let error = run_epoch_chaos(EpochChaosConfig {
            nodes: 16,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 1,
            byzantine_nodes: 5,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 15,
            reconnect_ping_quorum: 6,
            reconnect_approval_quorum: 5,
            ..EpochChaosConfig::default()
        })
        .unwrap_err();

        match error {
            blossom::BlossomError::WireProtocol(message) => {
                assert!(message.contains("trustless reconnect_ping_quorum"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn reconnect_rejects_impossible_high_quorums() {
        let error = run_epoch_chaos(EpochChaosConfig {
            nodes: 8,
            epochs: 2,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 1,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 7,
            reconnect_ping_quorum: 8,
            reconnect_approval_quorum: 7,
            ..EpochChaosConfig::default()
        })
        .unwrap_err();

        match error {
            blossom::BlossomError::WireProtocol(message) => {
                assert!(message.contains("reconnect_ping_quorum"));
                assert!(message.contains("must be <="));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn trustless_drop_waits_for_canonical_observer_quorum() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 3,
            drop_ppm: CHAOS_RATE_DENOMINATOR,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 8,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.dropped_node_keys.len(), 0);
        assert_eq!(report.final_active_nodes, 12);
        assert_eq!(report.final_dropped_nodes, 0);
        assert!(report.final_incorrect_nodes > 0);
    }

    #[test]
    fn epoch_chaos_emits_runtime_telemetry_spans() {
        let config = EpochChaosConfig {
            nodes: 8,
            epochs: 1,
            transactions_per_node: 1,
            transaction_bytes: 8,
            ..EpochChaosConfig::default()
        };
        let sink = std::sync::Arc::new(blossom::InMemoryTelemetrySink::default());
        let report = run_epoch_chaos_with_telemetry(
            config.clone(),
            blossom::TelemetryHandle::new(sink.clone()),
        )
        .unwrap();

        let events = sink.events();
        assert_eq!(
            events.len(),
            report.stage_progress.len() * (config.nodes * 2 + 1)
        );
        let span_starts = events
            .iter()
            .filter(|event| event.kind == blossom::TelemetryEventKind::SpanStart)
            .count();
        let span_ends = events
            .iter()
            .filter(|event| event.kind == blossom::TelemetryEventKind::SpanEnd)
            .count();
        assert_eq!(span_starts, span_ends);
        assert_eq!(span_starts, report.stage_progress.len() * config.nodes);

        let observed_nodes = events
            .iter()
            .filter_map(|event| event.node)
            .collect::<BTreeSet<_>>();
        assert_eq!(observed_nodes.len(), config.nodes);

        let block_start = events
            .iter()
            .find(|event| {
                event.kind == blossom::TelemetryEventKind::SpanStart
                    && event.stage == "block_formation"
                    && event.event == "formed"
            })
            .expect("block formation start span should be emitted");
        let block_end = events
            .iter()
            .find(|event| {
                event.kind == blossom::TelemetryEventKind::SpanEnd
                    && event.stage == "block_formation"
                    && event.event == "formed"
                    && event.node == block_start.node
                    && event.span_id == block_start.span_id
            })
            .expect("block formation end span should be emitted");
        assert!(block_end.timestamp_micros >= block_start.timestamp_micros);
        assert!(block_end.fields.is_empty());

        let block_metrics = events
            .iter()
            .find(|event| {
                event.kind == blossom::TelemetryEventKind::Event
                    && event.stage == "block_formation"
                    && event.event == "formed_metrics"
            })
            .expect("block formation metric event should be emitted");
        assert_eq!(
            block_metrics.fields["canonical_blocks"],
            config.nodes.to_string()
        );
    }

    #[test]
    fn epoch_chaos_emits_dropped_node_telemetry() {
        let config = EpochChaosConfig {
            nodes: 8,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 2,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            ..EpochChaosConfig::default()
        };
        let sink = std::sync::Arc::new(blossom::InMemoryTelemetrySink::default());
        let report =
            run_epoch_chaos_with_telemetry(config, blossom::TelemetryHandle::new(sink.clone()))
                .unwrap();

        let dropped_events = sink
            .events()
            .into_iter()
            .filter(|event| {
                event.kind == blossom::TelemetryEventKind::Event
                    && event.stage == "membership_pruning"
                    && event.event == "node_dropped"
                    && event.outcome.as_deref() == Some("dropped")
            })
            .collect::<Vec<_>>();
        assert_eq!(dropped_events.len(), report.final_dropped_nodes);
        assert_eq!(report.final_active_nodes, 6);
        assert_eq!(report.final_dropped_nodes, 2);
    }

    #[test]
    fn epoch_chaos_emits_reconnected_node_telemetry() {
        let config = EpochChaosConfig {
            nodes: 8,
            epochs: 4,
            transactions_per_node: 1,
            transaction_bytes: 8,
            faulty_nodes: 2,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 5,
            reconnect_ping_quorum: 4,
            reconnect_approval_quorum: 4,
            max_reconnected_nodes_per_epoch: 1,
            trust_mode: TrustMode::Trusted,
            ..EpochChaosConfig::default()
        };
        let sink = std::sync::Arc::new(blossom::InMemoryTelemetrySink::default());
        let report =
            run_epoch_chaos_with_telemetry(config, blossom::TelemetryHandle::new(sink.clone()))
                .unwrap();

        let reconnected_events = sink
            .events()
            .into_iter()
            .filter(|event| {
                event.kind == blossom::TelemetryEventKind::Event
                    && event.stage == "membership_reconnect"
                    && event.event == "node_reconnected"
                    && event.outcome.as_deref() == Some("reconnected")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reconnected_events.len(),
            report.reconnect_successes as usize
        );
        assert_eq!(report.final_active_nodes, 8);
        assert_eq!(report.final_dropped_nodes, 0);
        assert_eq!(report.reconnect_successes, 2);
    }

    #[test]
    fn short_timeout_with_spikes_can_diverge_deterministically() {
        let config = EpochChaosConfig {
            nodes: 12,
            epochs: 2,
            transactions_per_node: 1,
            transaction_bytes: 8,
            round_timeout_ms: 10,
            spike_ppm: 500_000,
            spike_latency_ms: 50,
            ..EpochChaosConfig::default()
        };
        let first = run_epoch_chaos(config.clone()).unwrap();
        let second = run_epoch_chaos(config).unwrap();
        assert_eq!(first, second);
        assert!(first.late_messages > 0);
    }

    #[test]
    fn zero_round_timeout_disables_late_message_cutoff() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 24,
            epochs: 4,
            transactions_per_node: 4,
            transaction_bytes: 16,
            latency_ms: 300,
            jitter_ms: 100,
            round_timeout_ms: 0,
            repair_rounds: 0,
            seed: 0x6e6f_5f74_696d_656f,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.late_messages, 0);
        assert_eq!(report.repair_attempts, 0);
        assert_eq!(report.repair_successes, 0);
        assert_eq!(report.final_correct_nodes, 24);
        assert_eq!(report.final_incorrect_nodes, 0);
        assert_eq!(report.final_unique_epoch_hashes, 1);
        assert!(report.epochs.iter().all(|epoch| {
            epoch.correct_nodes == epoch.active_nodes
                && epoch.incorrect_nodes == 0
                && epoch.unique_epoch_hashes == 1
        }));
    }

    #[test]
    fn repair_rounds_can_restore_epoch_convergence() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 3,
            transactions_per_node: 1,
            transaction_bytes: 8,
            round_timeout_ms: 10,
            spike_ppm: 100_000,
            spike_latency_ms: 50,
            repair_rounds: 4,
            repair_fanout: 8,
            repair_quorum: 8,
            repair_timeout_ms: 100,
            ..EpochChaosConfig::default()
        })
        .unwrap();
        assert_eq!(report.final_correct_nodes, 12);
        assert!(report.repair_successes > 0);
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "recovery"
                && record.event == "repair_round"
                && record.messages.repair_attempts > 0
        }));
    }

    #[test]
    fn reconciliation_rebuilds_epoch_when_summary_quorum_is_unavailable() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 2,
            transactions_per_node: 1,
            transaction_bytes: 8,
            latency_ms: 2,
            round_timeout_ms: 1,
            repair_rounds: 2,
            repair_fanout: 11,
            repair_quorum: 8,
            repair_timeout_ms: 10,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        assert_eq!(report.final_correct_nodes, 12);
        assert_eq!(report.final_unique_epoch_hashes, 1);
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "reconciliation"
                && record.event == "block_set_round"
                && record.repaired_nodes > 0
        }));
    }

    #[test]
    fn runtime_reconciliation_check_passes_long_faulted_epoch_run() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 36,
            epochs: 12,
            transactions_per_node: 4,
            transaction_bytes: 16,
            latency_ms: 1,
            jitter_ms: 8,
            round_timeout_ms: 35,
            drop_ppm: 20_000,
            fuzz_ppm: 10_000,
            spike_ppm: 60_000,
            spike_latency_ms: 80,
            repair_rounds: 5,
            repair_fanout: 35,
            repair_quorum: 24,
            repair_timeout_ms: 160,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        let check = report.check_runtime_reconciliation().unwrap();
        assert_eq!(check.final_correct_nodes, 36);
        assert_eq!(check.final_unique_epoch_hashes, 1);
        assert!(check.divergent_epochs > 0);
        assert!(check.reconciliation_epochs > 0);
        assert!(check.reconciled_nodes > 0);
    }

    #[test]
    fn partial_synchrony_progress_recovers_after_late_messages() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 24,
            epochs: 8,
            transactions_per_node: 2,
            transaction_bytes: 8,
            latency_ms: 1,
            jitter_ms: 10,
            round_timeout_ms: 8,
            spike_ppm: 120_000,
            spike_latency_ms: 35,
            repair_rounds: 5,
            repair_fanout: 23,
            repair_quorum: 16,
            repair_timeout_ms: 120,
            seed: 67_890,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        let check = report.check_runtime_reconciliation().unwrap();
        assert!(report.late_messages > 0);
        assert!(report.spiked_messages > 0);
        assert!(report.repair_successes > 0);
        assert_eq!(check.final_active_nodes, 24);
        assert_eq!(check.final_correct_nodes, 24);
        assert_eq!(check.final_unique_epoch_hashes, 1);
        assert!(report.epochs.iter().all(|epoch| {
            epoch.correct_nodes == epoch.active_nodes
                && epoch.incorrect_nodes == 0
                && epoch.unique_epoch_hashes == 1
        }));
    }

    #[test]
    fn healed_full_partition_reconciles_pending_epoch_before_resuming() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 24,
            epochs: 8,
            transactions_per_node: 2,
            transaction_bytes: 8,
            latency_ms: 1,
            round_timeout_ms: 20,
            repair_rounds: 4,
            repair_fanout: 23,
            repair_quorum: 16,
            repair_timeout_ms: 200,
            partition_start_epoch: Some(1),
            partition_end_epoch: Some(5),
            partition_left_nodes: 12,
            seed: 12_345,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        let check = report.check_runtime_reconciliation().unwrap();
        assert_eq!(check.final_active_nodes, 24);
        assert_eq!(check.final_correct_nodes, 24);
        assert_eq!(check.final_unique_epoch_hashes, 1);
        assert!(check.divergent_epochs >= 4);
        assert!(check.reconciled_nodes > 0);

        let pending = report
            .epochs
            .iter()
            .find(|epoch| epoch.epoch == 1)
            .expect("partitioned epoch should be reported");
        assert!(pending.incorrect_nodes > 0);
        assert!(report.epochs.iter().any(|epoch| {
            epoch.epoch >= 5
                && epoch.nonce == pending.nonce
                && epoch.canonical_epoch_hash == pending.canonical_epoch_hash
                && epoch.correct_nodes == epoch.active_nodes
                && epoch.unique_epoch_hashes == 1
        }));
        assert!(!report.stage_progress.iter().any(|record| {
            record.stage == "block_formation" && record.epoch > 1 && record.epoch < 5
        }));
        assert!(report.stage_progress.iter().any(|record| {
            record.stage == "reconciliation" && record.epoch >= 5 && record.repaired_nodes > 0
        }));
    }

    #[test]
    fn byzantine_churn_under_threshold_preserves_epoch_progress() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 31,
            epochs: 10,
            transactions_per_node: 2,
            transaction_bytes: 8,
            latency_ms: 1,
            jitter_ms: 8,
            round_timeout_ms: 10,
            spike_ppm: 60_000,
            spike_latency_ms: 35,
            repair_rounds: 5,
            repair_fanout: 30,
            repair_quorum: 21,
            repair_timeout_ms: 150,
            faulty_nodes: 6,
            byzantine_nodes: 8,
            byzantine_duplicate_vote_copies: 2,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 23,
            reconnect_dropped_after_epochs: 1,
            reconnect_ping_fanout: 30,
            reconnect_ping_quorum: 20,
            reconnect_approval_quorum: 20,
            max_reconnected_nodes_per_epoch: 1,
            seed: 424_242,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        let check = report.check_runtime_reconciliation().unwrap();
        assert_eq!(report.byzantine_node_keys.len(), 8);
        assert!(!report.byzantine_tolerance_exceeded);
        assert_eq!(report.dropped_node_keys.len(), 6);
        assert_eq!(report.reconnect_successes, 6);
        assert!(report.reconnect_duplicate_votes > 0);
        assert!(report.late_messages > 0);
        assert!(report.repair_successes > 0);
        assert_eq!(check.final_active_nodes, 31);
        assert_eq!(check.final_dropped_nodes, 0);
        assert_eq!(check.final_correct_nodes, 31);
        assert_eq!(check.final_unique_epoch_hashes, 1);
    }

    #[test]
    fn runtime_reconciliation_check_accepts_dropped_faulty_nodes() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 16,
            epochs: 5,
            transactions_per_node: 1,
            transaction_bytes: 8,
            latency_ms: 2,
            round_timeout_ms: 1,
            repair_rounds: 2,
            repair_fanout: 15,
            repair_quorum: 11,
            repair_timeout_ms: 10,
            faulty_nodes: 2,
            drop_faulty_after_epochs: 1,
            max_dropped_nodes_per_epoch: 1,
            min_active_nodes: 10,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        let check = report.check_runtime_reconciliation().unwrap();
        assert_eq!(check.final_active_nodes, 14);
        assert_eq!(check.final_dropped_nodes, 2);
        assert_eq!(check.final_correct_nodes, 14);
        assert_eq!(check.final_unique_epoch_hashes, 1);
        assert!(check.reconciled_nodes > 0);
    }

    #[test]
    fn runtime_reconciliation_check_rejects_unexercised_runs() {
        let report = run_epoch_chaos(EpochChaosConfig {
            nodes: 12,
            epochs: 2,
            transactions_per_node: 1,
            transaction_bytes: 8,
            ..EpochChaosConfig::default()
        })
        .unwrap();

        let error = report.check_runtime_reconciliation().unwrap_err();
        match error {
            blossom::BlossomError::WireProtocol(message) => {
                assert!(message.contains("did not exercise"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
