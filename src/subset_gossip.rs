use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::algorithm::supermajority_order_statistic;
use crate::availability::{
    FilteredPayloadBatchDelivery, FilteredPayloadBatchDeliveryBody, FilteredPayloadBatchFetch,
    FilteredPayloadBatchFetchBody, FilteredPayloadDeliveryItem, FilteredPayloadRequest,
};
use crate::block::{FilteredDeliveryPolicy, FilteredTransactionSlot};
use crate::wire::FRAME_PREFIX_BYTES;
use crate::{
    Block, BlossomError, Commit, CommitBody, DoHash, EchoResponse, EchoResponseBody, HashType,
    Header, Keypair, Msg, Nonce, Proposal, ProposalBody, PubKey, Result, SecKey, SecretSigner,
    Signature, SignatureTree, Transaction, Verification, VerificationBody, WireRequest,
    WireResponse, encoded_len, framed_len,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsetLatencyDistribution {
    Even,
    Random,
}

impl SubsetLatencyDistribution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Even => "even",
            Self::Random => "random",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsetPrefillMode {
    None,
    Random,
    PrefillDispatch,
    Scheduled,
}

impl SubsetPrefillMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Random => "random",
            Self::PrefillDispatch => "prefill-dispatch",
            Self::Scheduled => "scheduled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsetGossipProtocolVersion {
    V1,
    V2,
    Custom,
}

impl SubsetGossipProtocolVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubsetLatencyProfile {
    pub distribution: SubsetLatencyDistribution,
    pub latency_ms: u64,
    pub min_ms: u64,
    pub max_ms: u64,
    pub seed: u64,
}

impl Default for SubsetLatencyProfile {
    fn default() -> Self {
        Self {
            distribution: SubsetLatencyDistribution::Even,
            latency_ms: 150,
            min_ms: 1,
            max_ms: 300,
            seed: 0x0073_7562_7365_7431,
        }
    }
}

impl SubsetLatencyProfile {
    pub fn validate(self) -> Result<()> {
        if self.min_ms > self.max_ms {
            return Err(BlossomError::WireProtocol(
                "latency min must be <= latency max".to_string(),
            ));
        }
        Ok(())
    }

    pub fn edge_latency_ms(self, sender: usize, recipient: usize) -> u64 {
        match self.distribution {
            SubsetLatencyDistribution::Even => self.latency_ms,
            SubsetLatencyDistribution::Random => {
                let span = self.max_ms.saturating_sub(self.min_ms).saturating_add(1);
                let sample = splitmix64(
                    self.seed
                        ^ ((sender as u64) << 32)
                        ^ (recipient as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15),
                );
                self.min_ms + (sample % span)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsetGossipConfig {
    pub seed: u64,
    pub nodes: usize,
    pub epochs: usize,
    pub quorum_size: usize,
    pub commands_per_node: usize,
    pub command_bytes: usize,
    pub targets_per_command: usize,
    pub trusted: bool,
    pub shuffle: bool,
    pub repair_missing: bool,
    pub prefill_mode: SubsetPrefillMode,
    pub prefill_fanout: usize,
    pub prefill_skip_rounds: usize,
    pub prefill_byzantine_withholders_per_branch: usize,
    pub hash_advertise: bool,
    pub drop_round0_dispatch: bool,
    pub latency: SubsetLatencyProfile,
}

impl Default for SubsetGossipConfig {
    fn default() -> Self {
        Self {
            seed: 0x626c_6f73_736f_6d31,
            nodes: 36,
            epochs: 100,
            quorum_size: 6,
            commands_per_node: 256,
            command_bytes: 1024,
            targets_per_command: 3,
            trusted: false,
            shuffle: false,
            repair_missing: true,
            prefill_mode: SubsetPrefillMode::None,
            prefill_fanout: 0,
            prefill_skip_rounds: 0,
            prefill_byzantine_withholders_per_branch: 0,
            hash_advertise: false,
            drop_round0_dispatch: false,
            latency: SubsetLatencyProfile::default(),
        }
    }
}

impl SubsetGossipConfig {
    pub fn for_protocol_version(version: SubsetGossipProtocolVersion) -> Self {
        match version {
            SubsetGossipProtocolVersion::V1 => Self {
                prefill_mode: SubsetPrefillMode::None,
                prefill_fanout: 0,
                prefill_skip_rounds: 0,
                repair_missing: true,
                hash_advertise: false,
                ..Self::default()
            },
            SubsetGossipProtocolVersion::V2 => Self {
                prefill_mode: SubsetPrefillMode::PrefillDispatch,
                prefill_fanout: 0,
                prefill_skip_rounds: 0,
                repair_missing: false,
                hash_advertise: false,
                ..Self::default()
            },
            SubsetGossipProtocolVersion::Custom => Self::default(),
        }
    }

    pub fn protocol_version(&self) -> SubsetGossipProtocolVersion {
        if self.prefill_mode == SubsetPrefillMode::None
            && self.repair_missing
            && self.prefill_skip_rounds == 0
            && !self.hash_advertise
        {
            return SubsetGossipProtocolVersion::V1;
        }

        if self.prefill_mode == SubsetPrefillMode::PrefillDispatch
            && !self.repair_missing
            && self.prefill_skip_rounds <= 1
            && !self.hash_advertise
        {
            return SubsetGossipProtocolVersion::V2;
        }

        SubsetGossipProtocolVersion::Custom
    }

    pub fn validate(&self) -> Result<()> {
        if self.nodes == 0 {
            return Err(BlossomError::WireProtocol(
                "subset gossip requires at least one node".to_string(),
            ));
        }
        if self.epochs == 0 {
            return Err(BlossomError::WireProtocol(
                "subset gossip requires at least one epoch".to_string(),
            ));
        }
        if self.quorum_size < 2 {
            return Err(BlossomError::WireProtocol(
                "quorum size must be at least two".to_string(),
            ));
        }
        if self.commands_per_node == 0 {
            return Err(BlossomError::WireProtocol(
                "commands per node must be greater than zero".to_string(),
            ));
        }
        if self.targets_per_command == 0 {
            return Err(BlossomError::WireProtocol(
                "targets per command must be greater than zero".to_string(),
            ));
        }
        if matches!(self.prefill_mode, SubsetPrefillMode::PrefillDispatch)
            && self.prefill_skip_rounds > 1
        {
            return Err(BlossomError::WireProtocol(
                "prefill-dispatch can skip at most one consensus round".to_string(),
            ));
        }
        if matches!(self.prefill_mode, SubsetPrefillMode::PrefillDispatch)
            && !self.trusted
            && self.prefill_byzantine_withholders_per_branch > 0
            && self.quorum_size < 5
        {
            return Err(BlossomError::WireProtocol(
                "prefill-dispatch with Byzantine withholding requires quorum size at least 5"
                    .to_string(),
            ));
        }
        self.latency.validate()?;
        self.validate_propagation_policy()
    }

    #[cfg(any(
        feature = "propagation-adaptive",
        feature = "propagation-inventory",
        feature = "propagation-push"
    ))]
    fn validate_propagation_policy(&self) -> Result<()> {
        let uses_inventory = self.hash_advertise || prefill_inventory_is_precomputed(self);
        let strategy = match uses_inventory {
            true => crate::propagation::PropagationStrategy::InventoryThenMissing,
            false => crate::propagation::PropagationStrategy::PushFullBlocks,
        };
        let tolerated_byzantine = (self.quorum_size.saturating_sub(1)) / 3;
        let trust_boundary = match self.trusted {
            true => crate::propagation::TrustBoundary::Trusted,
            false => crate::propagation::TrustBoundary::Trustless {
                quorum_size: self.quorum_size,
                tolerated_byzantine,
            },
        };
        let manifest_authentication = match (self.trusted, uses_inventory) {
            (true, true) => crate::propagation::ManifestAuthentication::HashOnly,
            (false, true) => crate::propagation::ManifestAuthentication::HolderSigned,
            (_, false) => crate::propagation::ManifestAuthentication::None,
        };
        let redundancy = match (uses_inventory, self.prefill_mode) {
            (true, SubsetPrefillMode::PrefillDispatch | SubsetPrefillMode::Scheduled) => {
                crate::propagation::RedundancyPlan::new(
                    self.quorum_size,
                    self.prefill_byzantine_withholders_per_branch,
                )
            }
            (true, _) => crate::propagation::RedundancyPlan::new(1, 0),
            (false, _) => crate::propagation::RedundancyPlan::new(1, 0),
        };

        crate::propagation::PropagationPlan {
            strategy,
            trust_boundary,
            manifest_authentication,
            redundancy,
            during_consensus: true,
        }
        .validate()
        .map(|_| ())
        .map_err(|err| BlossomError::WireProtocol(format!("invalid propagation policy: {err}")))
    }

    #[cfg(not(any(
        feature = "propagation-adaptive",
        feature = "propagation-inventory",
        feature = "propagation-push"
    )))]
    fn validate_propagation_policy(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct SubsetGossipReport {
    pub rows: Vec<SubsetGossipEpochRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubsetGossipEpochRow {
    pub epoch: usize,
    pub epoch_depth: usize,
    pub protocol_version: SubsetGossipProtocolVersion,
    pub nodes: usize,
    pub quorum_size: usize,
    pub rounds: usize,
    pub quorums: usize,
    pub trusted: bool,
    pub shuffle: bool,
    pub repair_missing: bool,
    pub prefill_mode: SubsetPrefillMode,
    pub prefill_fanout: usize,
    pub prefill_skip_rounds: usize,
    pub prefill_byzantine_withholders_per_branch: usize,
    pub hash_advertise: bool,
    pub drop_round0_dispatch: bool,
    pub latency_distribution: SubsetLatencyDistribution,
    pub latency_ms: u64,
    pub latency_min_ms: u64,
    pub latency_max_ms: u64,
    pub commands_per_node: usize,
    pub command_bytes: usize,
    pub targets_per_command: usize,
    pub total_commands: usize,
    pub target_payload_deliveries: usize,
    pub metadata_converged_nodes: usize,
    pub metadata_converged: bool,
    pub subset_payloads_complete_before_repair: bool,
    pub subset_payloads_complete_after_repair: bool,
    pub subset_missing_payloads_before_repair: usize,
    pub subset_missing_payloads_after_repair: usize,
    pub subset_delivered_payloads_before_repair: usize,
    pub subset_delivered_payloads_after_repair: usize,
    pub subset_repair_batches: usize,
    pub subset_repair_bytes: usize,
    pub subset_repair_latency_ms: u64,
    pub prefill_requests: usize,
    pub prefill_recipients: usize,
    pub prefill_expected_hashes: usize,
    pub prefill_bytes: usize,
    pub hash_advertise_messages: usize,
    pub hash_advertise_bytes: usize,
    pub duplicate_suppressed_blocks: usize,
    pub full_dispatch_requests: usize,
    pub subset_dispatch_requests: usize,
    pub control_requests: usize,
    pub subset_repair_requests: usize,
    pub full_requests: usize,
    pub subset_requests: usize,
    pub modeled_prefill_latency_ms: u64,
    pub modeled_hash_advertise_latency_ms: u64,
    pub modeled_finality_latency_ms: u64,
    pub modeled_dispatch_latency_ms: u64,
    pub modeled_control_latency_ms: u64,
    pub subset_payload_ready_latency_ms: u64,
    pub full_block_bytes: usize,
    pub full_dispatch_bytes: usize,
    pub subset_dispatch_bytes: usize,
    pub control_bytes: usize,
    pub full_wire_bytes: usize,
    pub subset_wire_bytes: usize,
    pub full_amplification: f64,
    pub subset_amplification: f64,
    pub subset_savings_pct: f64,
    pub full_tps: f64,
    pub subset_payload_ready_tps: f64,
    pub full_req_per_sec: f64,
    pub subset_payload_ready_req_per_sec: f64,
    pub full_total_gbps: f64,
    pub subset_total_gbps: f64,
    pub full_per_node_gbps: f64,
    pub subset_per_node_gbps: f64,
}

#[derive(Debug, Clone)]
struct BenchNode {
    keypair: Keypair,
    signer: SecretSigner,
}

#[derive(Debug, Clone)]
struct BlockMeta {
    hash: HashType,
    owner: usize,
    full_block_len: usize,
    tombstone_block_len: usize,
    target_masks: Vec<PayloadMask>,
    target_payload_deliveries: usize,
    slots: Vec<FilteredTransactionSlot>,
}

#[derive(Debug, Clone)]
struct NodeSubsetState {
    blocks: Vec<Option<PayloadMask>>,
}

impl NodeSubsetState {
    fn new(node_count: usize) -> Self {
        Self {
            blocks: vec![None; node_count],
        }
    }

    fn insert_local_block(&mut self, owner: usize, command_count: usize) {
        self.blocks[owner] = Some(PayloadMask::full(command_count));
    }

    fn insert_block_metadata(&mut self, owner: usize, command_count: usize) {
        if let Some(slot @ None) = self.blocks.get_mut(owner) {
            *slot = Some(PayloadMask::empty(command_count));
        }
    }

    fn known_block_count(&self) -> usize {
        self.blocks.iter().filter(|block| block.is_some()).count()
    }

    fn merge_block(&mut self, owner: usize, incoming_full: PayloadMask) {
        match self.blocks.get_mut(owner) {
            Some(Some(existing)) => {
                existing.or_assign(&incoming_full);
            }
            Some(slot @ None) => {
                *slot = Some(incoming_full);
            }
            None => {}
        }
    }

    fn merge_targeted_payloads(
        &mut self,
        owner: usize,
        sender_full: &PayloadMask,
        target_mask: &PayloadMask,
    ) -> usize {
        match self.blocks.get_mut(owner) {
            Some(Some(existing)) => existing.or_intersection_assign_count(sender_full, target_mask),
            Some(slot @ None) => {
                let (incoming, count) =
                    PayloadMask::intersection_with_count(sender_full, target_mask);
                if count > 0 {
                    *slot = Some(incoming);
                }
                count
            }
            None => 0,
        }
    }

    fn merge_missing_targeted_payloads(
        &mut self,
        owner: usize,
        sender_full: &PayloadMask,
        target_mask: &PayloadMask,
    ) -> usize {
        match self.blocks.get_mut(owner) {
            Some(Some(existing)) => {
                existing.or_missing_intersection_assign_count(sender_full, target_mask)
            }
            Some(slot @ None) => {
                let (incoming, count) =
                    PayloadMask::intersection_with_count(sender_full, target_mask);
                if count > 0 {
                    *slot = Some(incoming);
                }
                count
            }
            None => 0,
        }
    }

    fn delivered_target_payloads(&self, owner: usize, target_mask: &PayloadMask) -> usize {
        self.blocks
            .get(owner)
            .and_then(Option::as_ref)
            .map_or(0, |commands| commands.intersection_popcount(target_mask))
    }

    fn missing_target_payloads(&self, owner: usize, target_mask: &PayloadMask) -> PayloadMask {
        match self.blocks.get(owner).and_then(Option::as_ref) {
            Some(commands) => target_mask.difference(commands),
            None => target_mask.clone(),
        }
    }

    fn mark_full_payloads(&mut self, owner: usize, payloads: PayloadMask) {
        if !payloads.is_empty() {
            self.merge_block(owner, payloads);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PayloadMask {
    words: Vec<u64>,
    len: usize,
}

impl PayloadMask {
    fn empty(len: usize) -> Self {
        Self {
            words: vec![0; len.div_ceil(64)],
            len,
        }
    }

    fn full(len: usize) -> Self {
        let mut mask = Self {
            words: vec![u64::MAX; len.div_ceil(64)],
            len,
        };
        mask.clear_trailing_bits();
        mask
    }

    fn set(&mut self, index: usize) {
        if index < self.len {
            self.words[index / 64] |= 1u64 << (index % 64);
        }
    }

    fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    fn popcount(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    fn intersection_popcount(&self, other: &Self) -> usize {
        debug_assert_eq!(self.len, other.len);
        self.words
            .iter()
            .zip(&other.words)
            .map(|(left, right)| (left & right).count_ones() as usize)
            .sum()
    }

    fn intersection_with_count(left: &Self, right: &Self) -> (Self, usize) {
        debug_assert_eq!(left.len, right.len);
        let mut count = 0usize;
        let words = left
            .words
            .iter()
            .zip(&right.words)
            .map(|(left_word, right_word)| {
                let word = left_word & right_word;
                count += word.count_ones() as usize;
                word
            })
            .collect();
        (
            Self {
                words,
                len: left.len,
            },
            count,
        )
    }

    fn difference(&self, other: &Self) -> Self {
        debug_assert_eq!(self.len, other.len);
        Self {
            words: self
                .words
                .iter()
                .zip(&other.words)
                .map(|(left, right)| left & !right)
                .collect(),
            len: self.len,
        }
    }

    fn or_assign(&mut self, other: &Self) {
        debug_assert_eq!(self.len, other.len);
        for (left, right) in self.words.iter_mut().zip(&other.words) {
            *left |= right;
        }
    }

    fn or_intersection_assign_count(&mut self, left: &Self, right: &Self) -> usize {
        debug_assert_eq!(self.len, left.len);
        debug_assert_eq!(left.len, right.len);
        let mut count = 0usize;
        for ((target, left_word), right_word) in
            self.words.iter_mut().zip(&left.words).zip(&right.words)
        {
            let word = left_word & right_word;
            count += word.count_ones() as usize;
            *target |= word;
        }
        count
    }

    fn or_missing_intersection_assign_count(&mut self, left: &Self, right: &Self) -> usize {
        debug_assert_eq!(self.len, left.len);
        debug_assert_eq!(left.len, right.len);
        let mut count = 0usize;
        for ((target, left_word), right_word) in
            self.words.iter_mut().zip(&left.words).zip(&right.words)
        {
            let word = left_word & right_word & !*target;
            count += word.count_ones() as usize;
            *target |= word;
        }
        count
    }

    fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(word_index, word)| {
                let mut word = *word;
                std::iter::from_fn(move || {
                    if word == 0 {
                        return None;
                    }
                    let bit = word.trailing_zeros() as usize;
                    word &= word - 1;
                    Some((word_index * 64) + bit)
                })
            })
            .filter(|index| *index < self.len)
    }

    fn clear_trailing_bits(&mut self) {
        let trailing = self.len % 64;
        match (trailing, self.words.last_mut()) {
            (0, _) | (_, None) => {}
            (trailing, Some(last)) => *last &= (1u64 << trailing) - 1,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct EpochByteTotals {
    prefill_bytes: usize,
    full_dispatch_bytes: usize,
    subset_dispatch_bytes: usize,
    hash_advertise_bytes: usize,
    control_bytes: usize,
    prefill_requests: usize,
    full_dispatch_requests: usize,
    subset_dispatch_requests: usize,
    hash_advertise_messages: usize,
    control_requests: usize,
    duplicate_suppressed_blocks: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct EpochLatencyTotals {
    prefill_ms: u64,
    dispatch_ms: u64,
    hash_advertise_ms: u64,
    control_ms: u64,
}

#[derive(Debug, Clone)]
struct PrecomputedInventoryRoute {
    attempt: usize,
    payloads: PayloadMask,
}

#[derive(Debug, Clone, Default)]
struct PrefillPlan {
    recipients_by_sender: Vec<Vec<usize>>,
    expected_by_node: HashMap<PubKey, BTreeSet<HashType>>,
}

pub fn run_subset_gossip(config: SubsetGossipConfig) -> Result<SubsetGossipReport> {
    config.validate()?;
    let nodes = build_nodes(config.seed, config.nodes);
    let mut last_epoch = HashType::default();
    let mut rows = Vec::with_capacity(config.epochs);

    for epoch in 0..config.epochs {
        let nonce = Nonce::new((epoch + 1) as u64);
        let (row, next_epoch) = run_subset_epoch(epoch, &config, &nodes, last_epoch, nonce)?;
        last_epoch = next_epoch;
        rows.push(row);
    }

    Ok(SubsetGossipReport { rows })
}

pub fn run_subset_gossip_v1(config: SubsetGossipConfig) -> Result<SubsetGossipReport> {
    let config = SubsetGossipConfig {
        prefill_mode: SubsetPrefillMode::None,
        prefill_fanout: 0,
        prefill_skip_rounds: 0,
        repair_missing: true,
        hash_advertise: false,
        ..config
    };
    run_subset_gossip(config)
}

pub fn run_subset_gossip_v2(config: SubsetGossipConfig) -> Result<SubsetGossipReport> {
    let config = SubsetGossipConfig {
        prefill_mode: SubsetPrefillMode::PrefillDispatch,
        prefill_fanout: 0,
        prefill_skip_rounds: 0,
        repair_missing: false,
        hash_advertise: false,
        ..config
    };
    run_subset_gossip(config)
}

fn run_subset_epoch(
    epoch: usize,
    config: &SubsetGossipConfig,
    nodes: &[BenchNode],
    last_epoch: HashType,
    nonce: Nonce,
) -> Result<(SubsetGossipEpochRow, HashType)> {
    let blocks = build_epoch_blocks(epoch, config, nodes, last_epoch, nonce)?;
    let full_block_bytes = blocks
        .iter()
        .map(|block| block.full_block_len)
        .sum::<usize>();
    let topology = round_quorums(
        &nodes
            .iter()
            .map(|node| node.keypair.public)
            .collect::<Vec<_>>(),
        last_epoch,
        config.shuffle,
        config.quorum_size,
    );
    let future_reachability = build_future_reachability(&topology, config.nodes);

    let mut full_known = vec![vec![false; config.nodes]; config.nodes];
    let mut subset_states = (0..config.nodes)
        .map(|_| NodeSubsetState::new(config.nodes))
        .collect::<Vec<_>>();
    for node in 0..config.nodes {
        full_known[node][node] = true;
        subset_states[node].insert_local_block(node, config.commands_per_node);
    }

    let header_len = encoded_len(&Header {
        sender: nodes[0].keypair.public,
        last_epoch,
        nonce,
        round: 0,
        signature: Signature::default(),
    })?;
    let signature_tree_len = encoded_len(&SignatureTree::default())?;
    let mut byte_totals = EpochByteTotals::default();
    let mut latency_totals = EpochLatencyTotals::default();
    let consensus_start_round = consensus_start_round(config, topology.len());
    let prefill_plan = build_prefill_plan(
        epoch,
        config,
        nodes,
        &blocks,
        &topology,
        consensus_start_round,
    );
    apply_prefill(
        PrefillApplyContext {
            config,
            nodes,
            blocks: &blocks,
            plan: &prefill_plan,
            header_len,
            signature_tree_len,
            future_reachability: &future_reachability,
            consensus_start_round,
        },
        &mut subset_states,
        &mut byte_totals,
        &mut latency_totals,
    )?;
    if prefill_inventory_is_precomputed(config) {
        apply_precomputed_inventory_metadata(config, &mut subset_states);
    }

    for (round, quorums) in topology.iter().enumerate().skip(consensus_start_round) {
        let before_full = full_known.clone();
        let before_subset = subset_states.clone();
        let mut next_full = full_known.clone();
        let mut next_subset = subset_states.clone();
        let mut round_dispatch_ms = 0u64;
        let mut round_hash_advertise_ms = 0u64;
        let mut round_control_ms = 0u64;
        let drop_dispatch_round = config.drop_round0_dispatch && round == 0;
        let full_dispatch_len_by_sender = before_full
            .iter()
            .map(|known_blocks| {
                let mut block_count = 0usize;
                let mut block_bytes = 0usize;
                for (owner, known) in known_blocks.iter().enumerate() {
                    if *known {
                        block_count += 1;
                        block_bytes += blocks[owner].full_block_len;
                    }
                }
                dispatch_len_for_block_stats(
                    header_len,
                    signature_tree_len,
                    block_count,
                    block_bytes,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        for quorum in quorums {
            if drop_dispatch_round {
                continue;
            }
            let stage_latency = quorum_stage_finality_latency_ms(quorum, config.latency);
            round_dispatch_ms = round_dispatch_ms.max(stage_latency);
            if config.hash_advertise {
                round_hash_advertise_ms = round_hash_advertise_ms.max(stage_latency);
            }
            if !config.trusted {
                round_control_ms = round_control_ms.max(stage_latency * 4);
                byte_totals.control_bytes += control_bytes_for_quorum(
                    round as u8,
                    quorum,
                    nodes,
                    &before_full,
                    &blocks,
                    last_epoch,
                    nonce,
                )?;
                byte_totals.control_requests += control_requests_for_quorum(quorum.len());
            }
            let precomputed_inventory_routes = if prefill_inventory_is_precomputed(config) {
                Some(precomputed_inventory_routes_for_quorum(
                    config,
                    round,
                    quorum,
                    &blocks,
                    &before_subset,
                    &future_reachability,
                ))
            } else {
                None
            };

            for sender in quorum {
                for recipient in quorum {
                    if recipient == sender {
                        continue;
                    }

                    byte_totals.full_dispatch_bytes += full_dispatch_len_by_sender[*sender];
                    byte_totals.full_dispatch_requests += 1;
                    if config.hash_advertise {
                        byte_totals.hash_advertise_messages += 1;
                        byte_totals.hash_advertise_bytes += hash_advertise_len_for_block_count(
                            header_len,
                            before_subset[*sender].known_block_count(),
                        )?;
                    }

                    let mut subset_block_count = 0usize;
                    let mut subset_block_bytes = 0usize;
                    let mut payload_delivery_items = Vec::new();
                    for block in &blocks {
                        if let Some(routes) = &precomputed_inventory_routes {
                            let route = match routes.get(&(*sender, *recipient, block.owner)) {
                                Some(route)
                                    if route.attempt
                                        >= config.prefill_byzantine_withholders_per_branch
                                        && !route.payloads.is_empty() =>
                                {
                                    route
                                }
                                _ => continue,
                            };
                            let sender_full =
                                match before_subset[*sender].blocks[block.owner].as_ref() {
                                    Some(sender_full) => sender_full,
                                    None => continue,
                                };
                            let (incoming, full_count) =
                                PayloadMask::intersection_with_count(sender_full, &route.payloads);
                            if full_count == 0 {
                                continue;
                            }
                            next_subset[*recipient]
                                .mark_full_payloads(block.owner, incoming.clone());
                            payload_delivery_items.extend(incoming.indices().map(|command| {
                                FilteredPayloadDeliveryItem {
                                    slot_hash: block.slots[command].hash(),
                                    slot: block.slots[command].clone(),
                                    payload: Vec::new(),
                                }
                            }));
                            continue;
                        }
                        let Some(sender_full) = before_subset[*sender].blocks[block.owner].as_ref()
                        else {
                            continue;
                        };
                        let target_mask = if prefill_routes_full_blocks(config) {
                            None
                        } else {
                            Some(&block.target_masks[*recipient])
                        };
                        let dedupe_from_inventory =
                            config.hash_advertise || prefill_inventory_is_precomputed(config);

                        let target_mask =
                            target_mask.expect("non-prefill routing uses target mask");
                        let recipient_had_metadata =
                            next_subset[*recipient].blocks[block.owner].is_some();
                        let full_count = if dedupe_from_inventory {
                            next_subset[*recipient].merge_missing_targeted_payloads(
                                block.owner,
                                sender_full,
                                target_mask,
                            )
                        } else {
                            next_subset[*recipient].merge_targeted_payloads(
                                block.owner,
                                sender_full,
                                target_mask,
                            )
                        };
                        if dedupe_from_inventory && recipient_had_metadata && full_count == 0 {
                            byte_totals.duplicate_suppressed_blocks += 1;
                            continue;
                        }
                        subset_block_count += 1;
                        subset_block_bytes +=
                            block.tombstone_block_len + (full_count * config.command_bytes);
                        if full_count == 0
                            && before_subset[*recipient].blocks[block.owner].is_none()
                        {
                            next_subset[*recipient]
                                .insert_block_metadata(block.owner, config.commands_per_node);
                        }
                    }

                    let subset_dispatch_bytes = if prefill_inventory_is_precomputed(config) {
                        filtered_payload_batch_delivery_len(
                            nodes[*sender].keypair.public,
                            payload_delivery_items,
                            config.command_bytes,
                        )?
                    } else {
                        dispatch_len_for_block_stats(
                            header_len,
                            signature_tree_len,
                            subset_block_count,
                            subset_block_bytes,
                        )?
                    };
                    if subset_dispatch_bytes > 0 {
                        byte_totals.subset_dispatch_requests += 1;
                    }
                    byte_totals.subset_dispatch_bytes += subset_dispatch_bytes;
                }
            }

            let mut union = vec![false; config.nodes];
            for member in quorum {
                for (owner, known) in before_full[*member].iter().enumerate() {
                    union[owner] |= *known;
                }
            }
            for member in quorum {
                for (owner, known) in union.iter().enumerate() {
                    next_full[*member][owner] |= *known;
                }
            }
        }

        latency_totals.dispatch_ms += round_dispatch_ms;
        latency_totals.hash_advertise_ms += round_hash_advertise_ms;
        latency_totals.control_ms += round_control_ms;
        full_known = next_full;
        subset_states = next_subset;
    }

    let target_payload_deliveries = target_payload_delivery_count(&blocks);
    let subset_delivered_payloads_before_repair =
        count_delivered_target_payloads(&subset_states, &blocks);
    let subset_missing_payloads_before_repair =
        target_payload_deliveries - subset_delivered_payloads_before_repair;

    let (subset_repair_batches, subset_repair_bytes, subset_repair_latency_ms) =
        if config.repair_missing && subset_missing_payloads_before_repair > 0 {
            repair_missing_payloads(&mut subset_states, &blocks, nodes, config)?
        } else {
            (0, 0, 0)
        };

    let subset_delivered_payloads_after_repair =
        count_delivered_target_payloads(&subset_states, &blocks);
    let subset_missing_payloads_after_repair =
        target_payload_deliveries - subset_delivered_payloads_after_repair;
    let metadata_converged_nodes = subset_states
        .iter()
        .filter(|state| state.known_block_count() == config.nodes)
        .count();
    let metadata_converged = metadata_converged_nodes == config.nodes;

    let modeled_finality_latency_ms = latency_totals.dispatch_ms + latency_totals.control_ms;
    let subset_payload_ready_latency_ms = modeled_finality_latency_ms
        + latency_totals.prefill_ms
        + latency_totals.hash_advertise_ms
        + subset_repair_latency_ms;
    let full_wire_bytes = byte_totals.full_dispatch_bytes + byte_totals.control_bytes;
    let subset_wire_bytes = byte_totals.prefill_bytes
        + byte_totals.subset_dispatch_bytes
        + byte_totals.hash_advertise_bytes
        + byte_totals.control_bytes
        + subset_repair_bytes;
    let total_commands = config.nodes * config.commands_per_node;
    let full_requests = byte_totals.full_dispatch_requests + byte_totals.control_requests;
    let subset_requests = byte_totals.prefill_requests
        + byte_totals.subset_dispatch_requests
        + byte_totals.hash_advertise_messages
        + byte_totals.control_requests
        + subset_repair_batches;

    let epoch_hash = epoch_hash(
        last_epoch,
        nonce,
        blocks
            .iter()
            .map(|block| (block.hash, ()))
            .collect::<BTreeMap<_, _>>()
            .hash(),
    );

    Ok((
        SubsetGossipEpochRow {
            epoch,
            epoch_depth: config.epochs,
            protocol_version: config.protocol_version(),
            nodes: config.nodes,
            quorum_size: config.quorum_size,
            rounds: topology.len().saturating_sub(consensus_start_round),
            quorums: topology
                .iter()
                .skip(consensus_start_round)
                .map(Vec::len)
                .sum(),
            trusted: config.trusted,
            shuffle: config.shuffle,
            repair_missing: config.repair_missing,
            prefill_mode: config.prefill_mode,
            prefill_fanout: prefill_plan
                .recipients_by_sender
                .iter()
                .map(Vec::len)
                .max()
                .unwrap_or_default(),
            prefill_skip_rounds: consensus_start_round,
            prefill_byzantine_withholders_per_branch: config
                .prefill_byzantine_withholders_per_branch,
            hash_advertise: config.hash_advertise,
            drop_round0_dispatch: config.drop_round0_dispatch,
            latency_distribution: config.latency.distribution,
            latency_ms: config.latency.latency_ms,
            latency_min_ms: config.latency.min_ms,
            latency_max_ms: config.latency.max_ms,
            commands_per_node: config.commands_per_node,
            command_bytes: config.command_bytes,
            targets_per_command: config.targets_per_command.min(config.nodes),
            total_commands,
            target_payload_deliveries,
            metadata_converged_nodes,
            metadata_converged,
            subset_payloads_complete_before_repair: subset_missing_payloads_before_repair == 0,
            subset_payloads_complete_after_repair: subset_missing_payloads_after_repair == 0,
            subset_missing_payloads_before_repair,
            subset_missing_payloads_after_repair,
            subset_delivered_payloads_before_repair,
            subset_delivered_payloads_after_repair,
            subset_repair_batches,
            subset_repair_bytes,
            subset_repair_latency_ms,
            prefill_requests: byte_totals.prefill_requests,
            prefill_recipients: prefill_plan.recipients_by_sender.iter().map(Vec::len).sum(),
            prefill_expected_hashes: prefill_plan
                .expected_by_node
                .values()
                .map(BTreeSet::len)
                .sum(),
            prefill_bytes: byte_totals.prefill_bytes,
            hash_advertise_messages: byte_totals.hash_advertise_messages,
            hash_advertise_bytes: byte_totals.hash_advertise_bytes,
            duplicate_suppressed_blocks: byte_totals.duplicate_suppressed_blocks,
            full_dispatch_requests: byte_totals.full_dispatch_requests,
            subset_dispatch_requests: byte_totals.subset_dispatch_requests,
            control_requests: byte_totals.control_requests,
            subset_repair_requests: subset_repair_batches,
            full_requests,
            subset_requests,
            modeled_prefill_latency_ms: latency_totals.prefill_ms,
            modeled_hash_advertise_latency_ms: latency_totals.hash_advertise_ms,
            modeled_finality_latency_ms,
            modeled_dispatch_latency_ms: latency_totals.dispatch_ms,
            modeled_control_latency_ms: latency_totals.control_ms,
            subset_payload_ready_latency_ms,
            full_block_bytes,
            full_dispatch_bytes: byte_totals.full_dispatch_bytes,
            subset_dispatch_bytes: byte_totals.subset_dispatch_bytes,
            control_bytes: byte_totals.control_bytes,
            full_wire_bytes,
            subset_wire_bytes,
            full_amplification: ratio(full_wire_bytes, full_block_bytes),
            subset_amplification: ratio(subset_wire_bytes, full_block_bytes),
            subset_savings_pct: pct(
                full_wire_bytes.saturating_sub(subset_wire_bytes),
                full_wire_bytes,
            ),
            full_tps: tps(total_commands, modeled_finality_latency_ms),
            subset_payload_ready_tps: tps(total_commands, subset_payload_ready_latency_ms),
            full_req_per_sec: per_second(full_requests, modeled_finality_latency_ms),
            subset_payload_ready_req_per_sec: per_second(
                subset_requests,
                subset_payload_ready_latency_ms,
            ),
            full_total_gbps: gbps(full_wire_bytes, modeled_finality_latency_ms),
            subset_total_gbps: gbps(subset_wire_bytes, subset_payload_ready_latency_ms),
            full_per_node_gbps: gbps(full_wire_bytes, modeled_finality_latency_ms)
                / config.nodes as f64,
            subset_per_node_gbps: gbps(subset_wire_bytes, subset_payload_ready_latency_ms)
                / config.nodes as f64,
        },
        epoch_hash,
    ))
}

fn build_nodes(seed: u64, count: usize) -> Vec<BenchNode> {
    (0..count)
        .map(|index| {
            let keypair = deterministic_keypair(seed, index);
            let signer = keypair.signer();
            BenchNode { keypair, signer }
        })
        .collect()
}

fn deterministic_keypair(seed: u64, index: usize) -> Keypair {
    let mut bytes = [0u8; 32];
    let mut state = seed ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for chunk in bytes.chunks_mut(8) {
        state = splitmix64(state);
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    Keypair::from_secret(SecKey(bytes))
}

fn build_epoch_blocks(
    epoch: usize,
    config: &SubsetGossipConfig,
    nodes: &[BenchNode],
    last_epoch: HashType,
    nonce: Nonce,
) -> Result<Vec<BlockMeta>> {
    (0..config.nodes)
        .map(|owner| build_block_meta(epoch, owner, config, nodes, last_epoch, nonce))
        .collect()
}

fn build_block_meta(
    epoch: usize,
    owner: usize,
    config: &SubsetGossipConfig,
    nodes: &[BenchNode],
    last_epoch: HashType,
    nonce: Nonce,
) -> Result<BlockMeta> {
    let mut block = Block::default();
    block.body.validator = nodes[owner].keypair.public;
    block.body.last_epoch = last_epoch;
    block.body.nonce = nonce;
    block.body.created = ((epoch as u128) << 64) | owner as u128;

    let mut target_masks = vec![PayloadMask::empty(config.commands_per_node); config.nodes];
    let mut target_payload_deliveries = 0usize;
    let mut slots = Vec::with_capacity(config.commands_per_node);
    for command in 0..config.commands_per_node {
        let target_indices = targets_for_command(epoch, owner, command, config);
        for target in &target_indices {
            target_masks[*target].set(command);
        }
        target_payload_deliveries += target_indices.len();
        let target_keys = target_indices
            .iter()
            .map(|index| nodes[*index].keypair.public)
            .collect::<Vec<_>>();
        let slot = FilteredTransactionSlot::new(
            command_key_hash(epoch, owner, command),
            1,
            target_keys,
            command_payload_hash(epoch, owner, command, config.command_bytes),
            config.command_bytes as u64,
            FilteredDeliveryPolicy::Gossip,
        )?;
        let tx = Transaction::filtered_tombstone(slot.clone())?;
        slots.push(slot);
        block.body.txs.push(tx);
    }

    if config.trusted {
        block.seal_unsigned(nodes[owner].keypair.public);
    } else {
        block.sign_with(&nodes[owner].signer);
    }

    let tombstone_block_len = encoded_len(&block)?;
    let full_block_len = tombstone_block_len + (config.commands_per_node * config.command_bytes);

    Ok(BlockMeta {
        hash: block.hash,
        owner,
        full_block_len,
        tombstone_block_len,
        target_masks,
        target_payload_deliveries,
        slots,
    })
}

fn consensus_start_round(config: &SubsetGossipConfig, topology_rounds: usize) -> usize {
    if matches!(config.prefill_mode, SubsetPrefillMode::PrefillDispatch) {
        let requested = config.prefill_skip_rounds.max(1);
        return requested.min(topology_rounds.saturating_sub(1));
    }
    let requested = config.prefill_skip_rounds;
    requested.min(topology_rounds)
}

fn prefill_inventory_is_precomputed(config: &SubsetGossipConfig) -> bool {
    matches!(config.prefill_mode, SubsetPrefillMode::PrefillDispatch)
}

fn prefill_routes_full_blocks(config: &SubsetGossipConfig) -> bool {
    matches!(config.prefill_mode, SubsetPrefillMode::PrefillDispatch)
}

fn prefill_requires_full_payload_redundancy(config: &SubsetGossipConfig) -> bool {
    prefill_routes_full_blocks(config)
        && !config.trusted
        && config.prefill_byzantine_withholders_per_branch > 0
}

fn effective_prefill_fanout(config: &SubsetGossipConfig) -> usize {
    let requested = if config.prefill_fanout == 0 {
        config.quorum_size
    } else {
        config.prefill_fanout
    };
    requested.min(config.nodes.saturating_sub(1))
}

fn prefill_dispatch_fanout(config: &SubsetGossipConfig, topology_rounds: usize) -> usize {
    if topology_rounds == 0 {
        return 0;
    }

    let network_rounds = ceil_log_rounds(config.nodes, config.quorum_size).max(topology_rounds);
    let route_width = prefill_dispatch_route_width(config);
    let planned = config.quorum_size.saturating_sub(1).saturating_add(
        config
            .quorum_size
            .saturating_mul(route_width)
            .saturating_mul(network_rounds.saturating_sub(1)),
    );
    let requested = if config.prefill_fanout == 0 {
        planned
    } else {
        config.prefill_fanout
    };
    requested.min(config.nodes.saturating_sub(1))
}

fn ceil_log_rounds(network_size: usize, quorum_size: usize) -> usize {
    if network_size == 0 || quorum_size < 2 {
        return 0;
    }

    let mut rounds = 0usize;
    let mut covered = 1usize;
    while covered < network_size {
        rounds = rounds.saturating_add(1);
        match covered.checked_mul(quorum_size) {
            Some(next) => covered = next,
            None => return rounds,
        }
    }

    rounds.max(1)
}

fn prefill_dispatch_route_width(config: &SubsetGossipConfig) -> usize {
    if prefill_requires_full_payload_redundancy(config) {
        return config
            .prefill_byzantine_withholders_per_branch
            .saturating_add(1);
    }
    1
}

fn build_prefill_plan(
    epoch: usize,
    config: &SubsetGossipConfig,
    nodes: &[BenchNode],
    blocks: &[BlockMeta],
    topology: &[Vec<Vec<usize>>],
    consensus_start_round: usize,
) -> PrefillPlan {
    let mut recipients_by_sender = vec![Vec::new(); config.nodes];
    match config.prefill_mode {
        SubsetPrefillMode::None => {}
        SubsetPrefillMode::Random => {
            let fanout = effective_prefill_fanout(config);
            for (sender, recipients) in recipients_by_sender.iter_mut().enumerate() {
                let mut state = config.seed
                    ^ (epoch as u64).wrapping_mul(0x98a2_c64f_15b8_3d21)
                    ^ (sender as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
                while recipients.len() < fanout {
                    state = splitmix64(state);
                    let recipient = (state as usize) % config.nodes;
                    if recipient != sender && !recipients.contains(&recipient) {
                        recipients.push(recipient);
                    }
                }
                recipients.sort_unstable();
            }
        }
        SubsetPrefillMode::PrefillDispatch => {
            let mut recipient_sets = vec![BTreeSet::new(); config.nodes];
            let fanout = prefill_dispatch_fanout(config, topology.len());
            for (sender, recipients) in recipient_sets.iter_mut().enumerate() {
                *recipients = prefill_dispatch_recipients(epoch, config, topology, sender, fanout);
            }
            recipients_by_sender = recipient_sets
                .into_iter()
                .map(|recipients| recipients.into_iter().collect())
                .collect();
        }
        SubsetPrefillMode::Scheduled => {
            let mut recipient_sets = vec![BTreeSet::new(); config.nodes];
            for quorums in topology.iter().skip(consensus_start_round) {
                for quorum in quorums {
                    for sender in quorum {
                        for recipient in quorum {
                            if recipient != sender {
                                recipient_sets[*sender].insert(*recipient);
                            }
                        }
                    }
                }
            }
            recipients_by_sender = recipient_sets
                .into_iter()
                .map(|recipients| recipients.into_iter().collect())
                .collect();
        }
    }

    let mut expected_by_node: HashMap<PubKey, BTreeSet<HashType>> = nodes
        .iter()
        .map(|node| (node.keypair.public, BTreeSet::new()))
        .collect();
    for (owner, block) in blocks.iter().enumerate() {
        expected_by_node
            .entry(nodes[owner].keypair.public)
            .or_default()
            .insert(block.hash);
        for recipient in &recipients_by_sender[owner] {
            expected_by_node
                .entry(nodes[*recipient].keypair.public)
                .or_default()
                .insert(block.hash);
        }
    }

    PrefillPlan {
        recipients_by_sender,
        expected_by_node,
    }
}

fn prefill_dispatch_recipients(
    epoch: usize,
    config: &SubsetGossipConfig,
    topology: &[Vec<Vec<usize>>],
    sender: usize,
    max_fanout: usize,
) -> BTreeSet<usize> {
    let mut recipients = BTreeSet::new();
    if max_fanout == 0 {
        return recipients;
    }

    let Some(first_quorum) = topology
        .first()
        .and_then(|quorums| quorum_containing_member(quorums, sender))
    else {
        return recipients;
    };

    let mut route_frontier = first_quorum.to_vec();
    for recipient in first_quorum {
        if *recipient != sender {
            recipients.insert(*recipient);
            if recipients.len() >= max_fanout {
                return recipients;
            }
        }
    }

    for (round, quorums) in topology.iter().enumerate().skip(1) {
        if recipients.len() >= max_fanout {
            break;
        }

        route_frontier.sort_unstable();
        route_frontier.dedup();
        let mut next_frontier = Vec::new();

        for frontier_holder in &route_frontier {
            if recipients.len() >= max_fanout {
                break;
            }

            let Some(quorum) = quorum_containing_member(quorums, *frontier_holder) else {
                next_frontier.push(*frontier_holder);
                continue;
            };
            let route_width = prefill_dispatch_route_width(config);

            let mut candidates = quorum
                .iter()
                .copied()
                .filter(|candidate| *candidate != sender && !recipients.contains(candidate))
                .collect::<Vec<_>>();
            candidates.sort_by_key(|candidate| {
                prefill_dispatch_score(
                    config.seed,
                    epoch,
                    sender,
                    round,
                    *frontier_holder,
                    *candidate,
                )
            });

            let mut added = 0usize;
            for candidate in candidates.into_iter().take(route_width) {
                if recipients.len() >= max_fanout {
                    break;
                }
                if recipients.insert(candidate) {
                    next_frontier.push(candidate);
                    added += 1;
                }
            }

            if added == 0 {
                next_frontier.push(*frontier_holder);
            }
        }

        route_frontier = next_frontier;
    }

    recipients
}

fn quorum_containing_member(quorums: &[Vec<usize>], member: usize) -> Option<&[usize]> {
    quorums
        .iter()
        .find(|quorum| quorum.binary_search(&member).is_ok())
        .map(Vec::as_slice)
}

fn prefill_dispatch_score(
    seed: u64,
    epoch: usize,
    sender: usize,
    round: usize,
    frontier_holder: usize,
    candidate: usize,
) -> u64 {
    splitmix64(
        seed ^ (epoch as u64).wrapping_mul(0x98a2_c64f_15b8_3d21)
            ^ (sender as u64).wrapping_mul(0xd6e8_feb8_6659_fd93)
            ^ (round as u64).wrapping_mul(0xa076_1d64_78bd_642f)
            ^ (frontier_holder as u64).wrapping_mul(0xe703_7ed1_a0b4_28db)
            ^ (candidate as u64).wrapping_mul(0x8ebc_6af0_9c88_c6e3),
    )
}

fn build_future_reachability(
    topology: &[Vec<Vec<usize>>],
    node_count: usize,
) -> Vec<Vec<Vec<usize>>> {
    let mut by_start_round = vec![vec![Vec::new(); node_count]; topology.len() + 1];
    for (start_round, per_source) in by_start_round.iter_mut().enumerate() {
        for (source, slot) in per_source.iter_mut().enumerate().take(node_count) {
            let mut holders = BTreeSet::new();
            holders.insert(source);
            for quorums in topology.iter().skip(start_round) {
                let mut next = holders.clone();
                for quorum in quorums {
                    if quorum.iter().any(|member| holders.contains(member)) {
                        next.extend(quorum.iter().copied());
                    }
                }
                holders = next;
            }
            *slot = holders.into_iter().collect();
        }
    }
    by_start_round
}

fn route_interest_mask(
    config: &SubsetGossipConfig,
    block: &BlockMeta,
    reachable_targets: &[usize],
) -> PayloadMask {
    let mut mask = PayloadMask::empty(config.commands_per_node);
    for target_mask in reachable_targets
        .iter()
        .filter_map(|target| block.target_masks.get(*target))
    {
        mask.or_assign(target_mask);
    }
    mask
}

struct PrefillApplyContext<'a> {
    config: &'a SubsetGossipConfig,
    nodes: &'a [BenchNode],
    blocks: &'a [BlockMeta],
    plan: &'a PrefillPlan,
    header_len: usize,
    signature_tree_len: usize,
    future_reachability: &'a [Vec<Vec<usize>>],
    consensus_start_round: usize,
}

fn apply_prefill(
    ctx: PrefillApplyContext<'_>,
    states: &mut [NodeSubsetState],
    byte_totals: &mut EpochByteTotals,
    latency_totals: &mut EpochLatencyTotals,
) -> Result<()> {
    let config = ctx.config;
    for (sender, recipients) in ctx.plan.recipients_by_sender.iter().enumerate() {
        let block = &ctx.blocks[sender];
        for recipient in recipients {
            let payloads = if prefill_requires_full_payload_redundancy(config) {
                PayloadMask::full(config.commands_per_node)
            } else if prefill_routes_full_blocks(config) {
                route_interest_mask(
                    config,
                    block,
                    &ctx.future_reachability[ctx.consensus_start_round][*recipient],
                )
            } else {
                PayloadMask::full(config.commands_per_node)
            };
            let payload_count = payloads.popcount();
            if payload_count == 0 {
                continue;
            }
            let prefill_len = dispatch_len_for_block_stats(
                ctx.header_len,
                ctx.signature_tree_len,
                1,
                block.tombstone_block_len + (payload_count * config.command_bytes),
            )?;
            states[*recipient].merge_block(sender, payloads);
            byte_totals.prefill_bytes += prefill_len;
            byte_totals.prefill_requests += 1;
            latency_totals.prefill_ms = latency_totals
                .prefill_ms
                .max(config.latency.edge_latency_ms(sender, *recipient));
        }
    }
    debug_assert_eq!(ctx.nodes.len(), states.len());
    Ok(())
}

fn apply_precomputed_inventory_metadata(
    config: &SubsetGossipConfig,
    states: &mut [NodeSubsetState],
) {
    for state in states {
        for owner in 0..config.nodes {
            state.insert_block_metadata(owner, config.commands_per_node);
        }
    }
}

fn precomputed_inventory_routes_for_quorum(
    config: &SubsetGossipConfig,
    round: usize,
    quorum: &[usize],
    blocks: &[BlockMeta],
    states: &[NodeSubsetState],
    future_reachability: &[Vec<Vec<usize>>],
) -> BTreeMap<(usize, usize, usize), PrecomputedInventoryRoute> {
    let mut routes = BTreeMap::new();

    for recipient in quorum {
        for block in blocks {
            let recipient_state = states[*recipient].blocks[block.owner].as_ref();
            let target_mask = if prefill_routes_full_blocks(config) {
                route_interest_mask(
                    config,
                    block,
                    &future_reachability[round.saturating_add(1)][*recipient],
                )
            } else {
                block.target_masks[*recipient].clone()
            };
            let missing_payloads = recipient_state
                .map(|known| target_mask.difference(known))
                .unwrap_or(target_mask);

            if missing_payloads.is_empty() {
                continue;
            }

            let mut candidates = quorum
                .iter()
                .copied()
                .filter(|candidate| candidate != recipient)
                .filter_map(|candidate| {
                    let held_payloads = states[candidate].blocks[block.owner].as_ref()?;
                    let coverage = held_payloads.intersection_popcount(&missing_payloads);
                    if !missing_payloads.is_empty() && coverage == 0 {
                        return None;
                    }
                    Some((candidate, coverage))
                })
                .collect::<Vec<_>>();

            candidates.sort_by(|(left, left_coverage), (right, right_coverage)| {
                right_coverage
                    .cmp(left_coverage)
                    .then_with(|| {
                        config
                            .latency
                            .edge_latency_ms(*left, *recipient)
                            .cmp(&config.latency.edge_latency_ms(*right, *recipient))
                    })
                    .then_with(|| left.cmp(right))
            });

            let mut remaining = missing_payloads;
            for (attempt, (sender, _)) in candidates.into_iter().enumerate() {
                if remaining.is_empty() {
                    break;
                }
                let Some(held_payloads) = states[sender].blocks[block.owner].as_ref() else {
                    continue;
                };
                if held_payloads.intersection_popcount(&remaining) == 0 {
                    continue;
                }
                let (payloads, _) = PayloadMask::intersection_with_count(held_payloads, &remaining);
                routes.insert(
                    (sender, *recipient, block.owner),
                    PrecomputedInventoryRoute { attempt, payloads },
                );
                if attempt >= config.prefill_byzantine_withholders_per_branch {
                    remaining = remaining.difference(held_payloads);
                }
            }
        }
    }

    routes
}

fn targets_for_command(
    epoch: usize,
    owner: usize,
    command: usize,
    config: &SubsetGossipConfig,
) -> Vec<usize> {
    let target_count = config.targets_per_command.min(config.nodes);
    let mut targets = Vec::with_capacity(target_count);
    targets.push(owner);
    let mut state = config.seed
        ^ (epoch as u64).wrapping_mul(0xd6e8_feb8_6659_fd93)
        ^ (owner as u64).wrapping_mul(0xa076_1d64_78bd_642f)
        ^ (command as u64).wrapping_mul(0xe703_7ed1_a0b4_28db);
    while targets.len() < target_count {
        state = splitmix64(state);
        let target = (state as usize) % config.nodes;
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets.sort_unstable();
    targets
}

fn target_payload_delivery_count(blocks: &[BlockMeta]) -> usize {
    blocks
        .iter()
        .map(|block| block.target_payload_deliveries)
        .sum()
}

fn count_delivered_target_payloads(states: &[NodeSubsetState], blocks: &[BlockMeta]) -> usize {
    let mut delivered = 0usize;
    for block in blocks {
        for (target, target_mask) in block.target_masks.iter().enumerate() {
            delivered += states[target].delivered_target_payloads(block.owner, target_mask);
        }
    }
    delivered
}

fn repair_missing_payloads(
    states: &mut [NodeSubsetState],
    blocks: &[BlockMeta],
    nodes: &[BenchNode],
    config: &SubsetGossipConfig,
) -> Result<(usize, usize, u64)> {
    let mut batches = 0usize;
    let mut bytes = 0usize;
    let mut latency_ms = 0u64;

    for block in blocks {
        for (target, target_mask) in block.target_masks.iter().enumerate() {
            if target_mask.is_empty() {
                continue;
            }
            let missing = states[target].missing_target_payloads(block.owner, target_mask);
            if missing.is_empty() {
                continue;
            }
            let commands = missing.indices().collect::<Vec<_>>();
            let requester = nodes[target].keypair.public;
            let requests = commands
                .iter()
                .map(|command| {
                    FilteredPayloadRequest::new(
                        block.slots[*command].hash(),
                        block.slots[*command].payload_commitment,
                    )
                })
                .collect::<Vec<_>>();
            let fetch_body = FilteredPayloadBatchFetchBody {
                scope: crate::ConsensusGroupId::root(),
                requester,
                requests,
            };
            let fetch = FilteredPayloadBatchFetch {
                body: fetch_body,
                signature: Signature::default(),
            };
            bytes += framed_len(&WireRequest::GetFilteredPayloadBatch(fetch))?;

            let items = commands
                .iter()
                .map(|command| FilteredPayloadDeliveryItem {
                    slot_hash: block.slots[*command].hash(),
                    slot: block.slots[*command].clone(),
                    payload: Vec::new(),
                })
                .collect::<Vec<_>>();
            let delivery_body = FilteredPayloadBatchDeliveryBody {
                scope: crate::ConsensusGroupId::root(),
                holder: nodes[block.owner].keypair.public,
                items,
            };
            let delivered_payload_bytes = commands.len() * config.command_bytes;
            let delivery = FilteredPayloadBatchDelivery {
                body: delivery_body,
                signature: Signature::default(),
            };
            bytes += framed_len(&WireResponse::FilteredPayloadBatch(delivery))?
                + delivered_payload_bytes;

            states[target].mark_full_payloads(block.owner, missing);
            batches += 1;
            latency_ms = latency_ms.max(2 * config.latency.edge_latency_ms(target, block.owner));
        }
    }

    Ok((batches, bytes, latency_ms))
}

fn filtered_payload_batch_delivery_len(
    holder: PubKey,
    items: Vec<FilteredPayloadDeliveryItem>,
    payload_bytes: usize,
) -> Result<usize> {
    if items.is_empty() {
        return Ok(0);
    }
    let payload_len = items.len() * payload_bytes;
    let delivery = FilteredPayloadBatchDelivery {
        body: FilteredPayloadBatchDeliveryBody {
            scope: crate::ConsensusGroupId::root(),
            holder,
            items,
        },
        signature: Signature::default(),
    };
    Ok(framed_len(&WireResponse::FilteredPayloadBatch(delivery))? + payload_len)
}

fn dispatch_len_for_block_stats(
    header_len: usize,
    signature_tree_len: usize,
    block_count: usize,
    block_bytes: usize,
) -> Result<usize> {
    const BORSH_ENUM_TAG_BYTES: usize = 1;
    const BORSH_MAP_LEN_BYTES: usize = 4;
    const HASH_BYTES: usize = 32;

    let blocks_len = BORSH_MAP_LEN_BYTES
        + block_count
            .checked_mul(HASH_BYTES)
            .and_then(|sum| sum.checked_add(block_bytes))
            .ok_or_else(|| BlossomError::WireProtocol("dispatch length overflow".to_string()))?;
    let len = FRAME_PREFIX_BYTES
        + BORSH_ENUM_TAG_BYTES
        + BORSH_ENUM_TAG_BYTES
        + header_len
        + HASH_BYTES
        + blocks_len
        + signature_tree_len
        + HASH_BYTES;
    if block_count == 0 {
        return Ok(0);
    }
    Ok(len)
}

fn hash_advertise_len_for_block_count(header_len: usize, block_count: usize) -> Result<usize> {
    const BORSH_ENUM_TAG_BYTES: usize = 1;
    const BORSH_VEC_LEN_BYTES: usize = 4;
    const HASH_BYTES: usize = 32;

    let hashes_len = block_count
        .checked_mul(HASH_BYTES)
        .and_then(|sum| sum.checked_add(BORSH_VEC_LEN_BYTES))
        .ok_or_else(|| BlossomError::WireProtocol("hash advertise length overflow".to_string()))?;
    Ok(FRAME_PREFIX_BYTES + BORSH_ENUM_TAG_BYTES + header_len + hashes_len)
}

fn control_bytes_for_quorum(
    round: u8,
    quorum: &[usize],
    nodes: &[BenchNode],
    before_full: &[Vec<bool>],
    blocks: &[BlockMeta],
    last_epoch: HashType,
    nonce: Nonce,
) -> Result<usize> {
    let mut bytes = 0usize;
    let known_blocks = quorum_known_blocks(quorum, before_full, blocks);
    let known_hash = known_blocks.hash();
    let signature_tree_hash = SignatureTree::default().hash();

    for dispatch_sender in quorum {
        for echo_sender in quorum {
            if echo_sender == dispatch_sender {
                continue;
            }
            let echo = echo_for(
                &nodes[*echo_sender],
                nodes[*dispatch_sender].keypair.public,
                known_hash,
                signature_tree_hash,
                last_epoch,
                nonce,
                round,
            )?;
            let echo_len = framed_len(&WireRequest::Message(Msg::EchoResponse(echo)))?;
            bytes += echo_len * quorum.len().saturating_sub(1);
        }
    }

    for sender in quorum {
        let verification = verification_for(
            &nodes[*sender],
            &known_blocks,
            known_hash,
            last_epoch,
            nonce,
            round,
        )?;
        bytes += framed_len(&WireRequest::Message(Msg::Verification(verification)))?
            * quorum.len().saturating_sub(1);

        let proposal = proposal_for(
            &nodes[*sender],
            &known_blocks,
            known_hash,
            last_epoch,
            nonce,
            round,
        )?;
        bytes += framed_len(&WireRequest::Message(Msg::Proposal(proposal)))?
            * quorum.len().saturating_sub(1);

        let commit = commit_for(&nodes[*sender], last_epoch, nonce, round)?;
        bytes += framed_len(&WireRequest::Message(Msg::Commit(commit)))?
            * quorum.len().saturating_sub(1);
    }

    Ok(bytes)
}

fn control_requests_for_quorum(quorum_len: usize) -> usize {
    let peers = quorum_len.saturating_sub(1);
    let echo_requests = quorum_len.saturating_mul(peers).saturating_mul(peers);
    let decision_requests = 3usize.saturating_mul(quorum_len).saturating_mul(peers);
    echo_requests.saturating_add(decision_requests)
}

fn quorum_known_blocks(
    quorum: &[usize],
    before_full: &[Vec<bool>],
    blocks: &[BlockMeta],
) -> BTreeMap<HashType, ()> {
    let mut known = BTreeMap::new();
    for member in quorum {
        for block in blocks {
            if before_full[*member][block.owner] {
                known.insert(block.hash, ());
            }
        }
    }
    known
}

fn echo_for(
    node: &BenchNode,
    dispatch_sender: PubKey,
    blocks_hash: HashType,
    signature_tree_hash: HashType,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
) -> Result<EchoResponse> {
    let body = EchoResponseBody {
        sender: dispatch_sender,
        blocks_hash,
        signature_tree_hash,
    };
    Ok(EchoResponse {
        header: modeled_header(node, last_epoch, nonce, round),
        body,
    })
}

fn verification_for(
    node: &BenchNode,
    blocks: &BTreeMap<HashType, ()>,
    blocks_hash: HashType,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
) -> Result<Verification> {
    let body = VerificationBody {
        blocks_hash,
        blocks: blocks.clone(),
    };
    Ok(Verification {
        header: modeled_header(node, last_epoch, nonce, round),
        body,
    })
}

fn proposal_for(
    node: &BenchNode,
    blocks: &BTreeMap<HashType, ()>,
    blocks_hash: HashType,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
) -> Result<Proposal> {
    let body = ProposalBody {
        consensus: true,
        approved_blocks: Some(blocks.clone()),
        approved_hash: Some(blocks_hash),
        verif: None,
        signature_tree: Some(blocks.clone()),
        signature_tree_hash: Some(blocks.hash()),
    };
    Ok(Proposal {
        header: modeled_header(node, last_epoch, nonce, round),
        body,
    })
}

fn commit_for(node: &BenchNode, last_epoch: HashType, nonce: Nonce, round: u8) -> Result<Commit> {
    let body = CommitBody {
        consensus: true,
        signature_tree_insert: None,
        epoch_hash: None,
        epoch_signature: None,
    };
    Ok(Commit {
        header: modeled_header(node, last_epoch, nonce, round),
        body,
    })
}

fn modeled_header(node: &BenchNode, last_epoch: HashType, nonce: Nonce, round: u8) -> Header {
    Header {
        sender: node.keypair.public,
        last_epoch,
        nonce,
        round,
        signature: Signature::default(),
    }
}

fn epoch_hash(last_epoch: HashType, nonce: Nonce, blocks_hash: HashType) -> HashType {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(last_epoch.as_ref());
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(blocks_hash.as_ref());
    HashType::hash(&bytes)
}

fn round_quorums(
    keys: &[PubKey],
    seed: HashType,
    shuffle: bool,
    quorum_size: usize,
) -> Vec<Vec<Vec<usize>>> {
    let mut rounds: Vec<BTreeSet<Vec<usize>>> = Vec::new();

    for self_index in 0..keys.len() {
        for (round_index, quorum) in
            select_quorums_for_index(keys, self_index, seed, shuffle, quorum_size)
                .into_iter()
                .enumerate()
        {
            if round_index >= rounds.len() {
                rounds.push(BTreeSet::new());
            }
            let mut members = quorum;
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

fn select_quorums_for_index(
    keys: &[PubKey],
    self_index: usize,
    seed: HashType,
    shuffle: bool,
    quorum_size: usize,
) -> Vec<Vec<usize>> {
    if keys.is_empty() || quorum_size < 2 || self_index >= keys.len() {
        return Vec::new();
    }

    let (optimal_network_size, rounds) = find_round_number(keys.len(), quorum_size);
    if optimal_network_size == 0 || rounds == 0 {
        return Vec::new();
    }

    let mut ordered_indices = (0..keys.len()).collect::<Vec<_>>();
    ordered_indices.sort_by_key(|index| keys[*index]);
    if shuffle {
        deterministic_shuffle(&mut ordered_indices, seed);
    }

    let Some(self_position) = ordered_indices
        .iter()
        .position(|index| *index == self_index)
    else {
        return Vec::new();
    };

    quorum_algorithm(
        &ordered_indices,
        self_position,
        optimal_network_size,
        rounds,
        quorum_size,
    )
}

fn quorum_algorithm(
    ordered_indices: &[usize],
    mut self_position: usize,
    optimal_network_size: usize,
    rounds: usize,
    quorum_size: usize,
) -> Vec<Vec<usize>> {
    let mut quorum_members_matrix = Vec::new();
    if ordered_indices.is_empty() || optimal_network_size == 0 || quorum_size < 2 {
        return quorum_members_matrix;
    }

    self_position = if self_position >= optimal_network_size {
        self_position % optimal_network_size
    } else {
        self_position
    };

    for mut round in 0..rounds {
        let mut ceiling_network_size = quorum_size.pow(round as u32 + 1);
        let mut max_network_size = ceiling_network_size;
        let mut size_multiple = 1;

        if ceiling_network_size > optimal_network_size {
            ceiling_network_size = quorum_size.pow(round as u32);
            round = round.saturating_sub(1);
            max_network_size = optimal_network_size;
            size_multiple = (optimal_network_size / ceiling_network_size).max(1);
        }

        let offset = quorum_size.pow(round as u32);
        let first_quorum_member = (self_position - (self_position % max_network_size))
            + (self_position % (size_multiple * offset));

        let mut quorum = Vec::new();
        extend_quorum_indices(
            &mut quorum,
            ordered_indices,
            first_quorum_member,
            size_multiple,
            offset,
            quorum_size,
        );

        if ordered_indices.len() >= optimal_network_size {
            extend_quorum_indices(
                &mut quorum,
                ordered_indices,
                optimal_network_size + first_quorum_member,
                size_multiple,
                offset,
                quorum_size,
            );
        }

        quorum.sort_unstable();
        quorum.dedup();
        quorum_members_matrix.push(quorum);
    }

    quorum_members_matrix
}

fn extend_quorum_indices(
    quorum: &mut Vec<usize>,
    ordered_indices: &[usize],
    first_quorum_member: usize,
    size_multiple: usize,
    offset: usize,
    quorum_size: usize,
) {
    quorum.extend((0..quorum_size).filter_map(|quorum_member| {
        let index = first_quorum_member + (quorum_member * size_multiple * offset);
        ordered_indices.get(index).copied()
    }));
}

fn find_round_number(network_size: usize, quorum_size: usize) -> (usize, usize) {
    if network_size == 0 || quorum_size < 2 {
        return (0, 0);
    }
    if network_size <= quorum_size {
        return (network_size, 1);
    }

    let base = quorum_size as f64;
    let network_size_logarithm = float_tolerance((network_size as f64).log(base));
    let logarithm_floor = network_size_logarithm.floor();
    let base_network_size = f64::powf(base, logarithm_floor);
    let optimal_network_size =
        base_network_size * (network_size as f64 / base_network_size).floor();
    let rounds = float_tolerance(optimal_network_size.log(base)).ceil();

    (optimal_network_size as usize, rounds as usize)
}

fn float_tolerance(value: f64) -> f64 {
    const EPSILON: f64 = 1e-10;
    if (value - value.round()).abs() < EPSILON {
        value.round()
    } else {
        value
    }
}

fn deterministic_shuffle(indices: &mut [usize], seed: HashType) {
    let mut state = u64::from_le_bytes(seed.0[0..8].try_into().unwrap_or([1; 8]));
    if state == 0 {
        state = 0x9e37_79b9_7f4a_7c15;
    }

    for i in (1..indices.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state as usize) % (i + 1);
        indices.swap(i, j);
    }
}

fn quorum_stage_finality_latency_ms(quorum: &[usize], latency: SubsetLatencyProfile) -> u64 {
    let receiver_ceilings = quorum.iter().map(|recipient| {
        let arrivals = quorum.iter().map(|sender| {
            if sender == recipient {
                0
            } else {
                latency.edge_latency_ms(*sender, *recipient)
            }
        });
        supermajority_order_statistic(arrivals, quorum.len()).unwrap_or_default()
    });

    supermajority_order_statistic(receiver_ceilings, quorum.len()).unwrap_or_default()
}

fn command_key_hash(epoch: usize, owner: usize, command: usize) -> HashType {
    let mut bytes = [0u8; 24];
    bytes[..8].copy_from_slice(&(epoch as u64).to_le_bytes());
    bytes[8..16].copy_from_slice(&(owner as u64).to_le_bytes());
    bytes[16..24].copy_from_slice(&(command as u64).to_le_bytes());
    HashType::hash(&bytes)
}

fn command_payload_hash(epoch: usize, owner: usize, command: usize, len: usize) -> HashType {
    // The subset-gossip model accounts for payload bytes in wire totals but
    // never materializes payload bodies. Use a stable synthetic commitment so
    // large bandwidth sweeps scale with graph size, not fake byte hashing.
    let mut bytes = [0u8; 32];
    let mut state = (epoch as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add((owner as u64) << 32)
        .wrapping_add(command as u64)
        ^ (len as u64).rotate_left(17)
        ^ 0x5ab5_e7a1_da7a_0001;
    for chunk in bytes.chunks_mut(8) {
        state = splitmix64(state);
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    HashType(bytes)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn pct(numerator: usize, denominator: usize) -> f64 {
    ratio(numerator, denominator) * 100.0
}

fn tps(commands: usize, latency_ms: u64) -> f64 {
    per_second(commands, latency_ms)
}

fn per_second(count: usize, latency_ms: u64) -> f64 {
    if latency_ms == 0 {
        0.0
    } else {
        count as f64 / (latency_ms as f64 / 1000.0)
    }
}

fn gbps(bytes: usize, latency_ms: u64) -> f64 {
    if latency_ms == 0 {
        0.0
    } else {
        bytes as f64 * 8.0 / (latency_ms as f64 / 1000.0) / 1_000_000_000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_selection_is_deterministic_and_includes_owner() {
        let config = SubsetGossipConfig {
            nodes: 12,
            targets_per_command: 3,
            ..SubsetGossipConfig::default()
        };
        let first = targets_for_command(7, 2, 9, &config);
        let second = targets_for_command(7, 2, 9, &config);

        assert_eq!(first, second);
        assert!(first.binary_search(&2).is_ok());
        assert_eq!(first.len(), 3);
    }

    #[test]
    fn synthetic_payload_commitment_is_stable_and_length_sensitive() {
        let first = command_payload_hash(1, 2, 3, 1024);
        let second = command_payload_hash(1, 2, 3, 1024);
        let different_len = command_payload_hash(1, 2, 3, 2048);
        let different_command = command_payload_hash(1, 2, 4, 1024);

        assert_eq!(first, second);
        assert_ne!(first, different_len);
        assert_ne!(first, different_command);
    }

    #[test]
    fn subset_gossip_converges_metadata_and_repairs_payloads() {
        let config = SubsetGossipConfig {
            nodes: 12,
            epochs: 2,
            quorum_size: 3,
            commands_per_node: 8,
            command_bytes: 64,
            targets_per_command: 2,
            repair_missing: true,
            ..SubsetGossipConfig::default()
        };

        let report = run_subset_gossip(config).unwrap();

        assert_eq!(report.rows.len(), 2);
        for row in report.rows {
            assert!(row.metadata_converged);
            assert!(row.subset_payloads_complete_after_repair);
            assert_eq!(row.subset_missing_payloads_after_repair, 0);
            assert!(row.subset_wire_bytes <= row.full_wire_bytes);
        }
    }

    #[test]
    fn protocol_v1_profile_preserves_old_repair_path() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            ..SubsetGossipConfig::for_protocol_version(SubsetGossipProtocolVersion::V1)
        };

        let row = run_subset_gossip_v1(config).unwrap().rows.remove(0);

        assert_eq!(row.protocol_version, SubsetGossipProtocolVersion::V1);
        assert_eq!(row.prefill_mode, SubsetPrefillMode::None);
        assert_eq!(row.prefill_skip_rounds, 0);
        assert!(row.repair_missing);
        assert!(row.metadata_converged);
        assert!(row.subset_missing_payloads_before_repair > 0);
        assert_eq!(row.subset_missing_payloads_after_repair, 0);
        assert!(row.subset_repair_batches > 0);
    }

    #[test]
    fn protocol_v2_profile_preserves_prefill_dispatch_path() {
        let config = SubsetGossipConfig {
            nodes: 72,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            ..SubsetGossipConfig::for_protocol_version(SubsetGossipProtocolVersion::V2)
        };

        let row = run_subset_gossip_v2(config).unwrap().rows.remove(0);

        assert_eq!(row.protocol_version, SubsetGossipProtocolVersion::V2);
        assert_eq!(row.prefill_mode, SubsetPrefillMode::PrefillDispatch);
        assert_eq!(row.prefill_skip_rounds, 1);
        assert_eq!(row.prefill_fanout, 17);
        assert!(!row.repair_missing);
        assert!(row.metadata_converged);
        assert!(row.subset_payloads_complete_before_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
        assert_eq!(row.subset_repair_batches, 0);
    }

    #[test]
    fn experimental_knobs_are_labeled_custom() {
        let config = SubsetGossipConfig {
            nodes: 12,
            epochs: 1,
            quorum_size: 3,
            commands_per_node: 8,
            command_bytes: 64,
            targets_per_command: 2,
            prefill_mode: SubsetPrefillMode::Random,
            prefill_fanout: 3,
            repair_missing: true,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert_eq!(row.protocol_version, SubsetGossipProtocolVersion::Custom);
        assert_eq!(row.prefill_mode, SubsetPrefillMode::Random);
    }

    #[test]
    fn sparse_inline_subset_can_need_repair() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 2,
            repair_missing: false,
            ..SubsetGossipConfig::default()
        };

        let report = run_subset_gossip(config).unwrap();
        let row = &report.rows[0];

        assert!(row.metadata_converged);
        assert!(row.subset_missing_payloads_before_repair > 0);
        assert!(!row.subset_payloads_complete_after_repair);
    }

    #[test]
    fn random_prefill_replicates_each_local_block_to_configured_fanout() {
        let config = SubsetGossipConfig {
            nodes: 12,
            epochs: 1,
            quorum_size: 3,
            commands_per_node: 8,
            command_bytes: 64,
            targets_per_command: 2,
            prefill_mode: SubsetPrefillMode::Random,
            prefill_fanout: 3,
            repair_missing: true,
            ..SubsetGossipConfig::default()
        };

        let report = run_subset_gossip(config).unwrap();
        let row = &report.rows[0];

        assert_eq!(row.prefill_mode, SubsetPrefillMode::Random);
        assert_eq!(row.prefill_recipients, row.nodes * row.prefill_fanout);
        assert!(row.prefill_expected_hashes > row.nodes);
        assert!(row.prefill_bytes > 0);
        assert_eq!(row.subset_missing_payloads_after_repair, 0);
    }

    #[test]
    fn scheduled_prefill_hash_advertise_suppresses_duplicate_blocks() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            prefill_mode: SubsetPrefillMode::Scheduled,
            hash_advertise: true,
            repair_missing: true,
            ..SubsetGossipConfig::default()
        };

        let report = run_subset_gossip(config).unwrap();
        let row = &report.rows[0];

        assert_eq!(row.prefill_mode, SubsetPrefillMode::Scheduled);
        assert!(row.prefill_recipients > 0);
        assert!(row.hash_advertise_messages > 0);
        assert!(row.hash_advertise_bytes > 0);
        assert!(row.duplicate_suppressed_blocks > 0);
        assert!(row.metadata_converged);
        assert_eq!(row.subset_missing_payloads_after_repair, 0);
    }

    #[test]
    fn random_prefill_reduces_round0_drop_payload_loss() {
        let baseline = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            drop_round0_dispatch: true,
            ..SubsetGossipConfig::default()
        };
        let random_prefill = SubsetGossipConfig {
            prefill_mode: SubsetPrefillMode::Random,
            prefill_fanout: 6,
            ..baseline.clone()
        };

        let baseline_row = run_subset_gossip(baseline).unwrap().rows.remove(0);
        let random_row = run_subset_gossip(random_prefill).unwrap().rows.remove(0);

        assert!(baseline_row.subset_missing_payloads_before_repair > 0);
        assert!(
            random_row.subset_missing_payloads_before_repair
                < baseline_row.subset_missing_payloads_before_repair
        );
        assert!(random_row.prefill_bytes > 0);
    }

    #[test]
    fn prefill_dispatch_replaces_first_consensus_round() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert_eq!(row.prefill_mode, SubsetPrefillMode::PrefillDispatch);
        assert_eq!(row.prefill_skip_rounds, 1);
        assert_eq!(row.rounds, 1);
        assert_eq!(row.prefill_fanout, 11);
        assert_eq!(row.prefill_recipients, row.nodes * row.prefill_fanout);
        assert_eq!(
            row.prefill_expected_hashes,
            row.nodes * (row.prefill_fanout + 1)
        );
        assert_eq!(row.hash_advertise_bytes, 0);
        assert!(row.metadata_converged);
        assert!(row.subset_payloads_complete_before_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
        assert_eq!(row.duplicate_suppressed_blocks, 0);
        assert!(row.subset_dispatch_bytes > 0);
    }

    #[test]
    fn modeled_latency_uses_parallel_quorums_within_round() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            repair_missing: false,
            trusted: true,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert_eq!(row.quorums, 6);
        assert_eq!(row.modeled_prefill_latency_ms, 150);
        assert_eq!(row.modeled_dispatch_latency_ms, 150);
        assert_eq!(row.modeled_control_latency_ms, 0);
        assert_eq!(row.subset_payload_ready_latency_ms, 300);
    }

    #[test]
    fn trustless_mode_models_control_once_per_parallel_round() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            repair_missing: false,
            trusted: false,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert_eq!(row.quorums, 6);
        assert_eq!(row.modeled_prefill_latency_ms, 150);
        assert_eq!(row.modeled_dispatch_latency_ms, 150);
        assert_eq!(row.modeled_control_latency_ms, 600);
        assert_eq!(row.subset_payload_ready_latency_ms, 900);
    }

    #[test]
    fn prefill_dispatch_fanout_scales_with_log_rounds() {
        let config = SubsetGossipConfig {
            nodes: 1000,
            quorum_size: 6,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };

        let (_, rounds) = find_round_number(config.nodes, config.quorum_size);

        assert_eq!(rounds, 4);
        assert_eq!(prefill_dispatch_fanout(&config, rounds), 23);
    }

    #[test]
    fn prefill_dispatch_fanout_uses_ceil_depth_for_non_ideal_networks() {
        let config = SubsetGossipConfig {
            nodes: 64,
            quorum_size: 6,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };
        let (_, topology_rounds) = find_round_number(config.nodes, config.quorum_size);

        assert_eq!(topology_rounds, 2);
        assert_eq!(ceil_log_rounds(config.nodes, config.quorum_size), 3);
        assert_eq!(prefill_dispatch_fanout(&config, topology_rounds), 17);
    }

    #[test]
    fn prefill_dispatch_fanout_is_derived_from_quorum_schedule() {
        let config = SubsetGossipConfig {
            nodes: 64,
            quorum_size: 6,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };
        let (_, topology_rounds) = find_round_number(config.nodes, config.quorum_size);

        assert_eq!(prefill_dispatch_fanout(&config, topology_rounds), 17);
    }

    #[test]
    fn prefill_dispatch_boundary_sizes_use_ceil_log_depth() {
        let cases = [
            (5usize, 1usize, 4usize),
            (6, 1, 5),
            (7, 2, 6),
            (35, 2, 11),
            (36, 2, 11),
            (37, 3, 17),
            (215, 3, 17),
            (216, 3, 17),
            (217, 4, 23),
            (1_000, 4, 23),
            (1_296, 4, 23),
            (1_297, 5, 29),
        ];

        for (nodes, expected_rounds, expected_fanout) in cases {
            let config = SubsetGossipConfig {
                nodes,
                quorum_size: 6,
                prefill_mode: SubsetPrefillMode::PrefillDispatch,
                ..SubsetGossipConfig::default()
            };
            let rounds = ceil_log_rounds(config.nodes, config.quorum_size);

            assert_eq!(rounds, expected_rounds, "nodes={nodes}");
            assert_eq!(
                prefill_dispatch_fanout(&config, rounds),
                expected_fanout,
                "nodes={nodes}"
            );
        }
    }

    #[test]
    fn prefill_dispatch_non_ideal_boundary_sizes_complete_without_repair() {
        for nodes in [35usize, 36, 37, 64, 72] {
            let row = run_subset_gossip(SubsetGossipConfig {
                seed: 0x626f_756e_6461_7279 ^ nodes as u64,
                nodes,
                epochs: 1,
                quorum_size: 6,
                commands_per_node: 4,
                command_bytes: 32,
                targets_per_command: 3,
                repair_missing: false,
                prefill_mode: SubsetPrefillMode::PrefillDispatch,
                ..SubsetGossipConfig::default()
            })
            .unwrap()
            .rows
            .remove(0);

            assert!(row.metadata_converged, "nodes={nodes}");
            assert!(row.subset_payloads_complete_before_repair, "nodes={nodes}");
            assert_eq!(
                row.subset_missing_payloads_before_repair, 0,
                "nodes={nodes}"
            );
            assert_eq!(row.subset_repair_batches, 0, "nodes={nodes}");
        }
    }

    #[test]
    fn prefill_expected_hashes_reject_stale_epoch_replay() {
        let config = SubsetGossipConfig {
            nodes: 36,
            quorum_size: 6,
            commands_per_node: 4,
            command_bytes: 32,
            targets_per_command: 3,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };
        let nodes = build_nodes(config.seed, config.nodes);
        let topology = round_quorums(
            &nodes
                .iter()
                .map(|node| node.keypair.public)
                .collect::<Vec<_>>(),
            HashType::default(),
            config.shuffle,
            config.quorum_size,
        );
        let consensus_start_round = consensus_start_round(&config, topology.len());
        let stale_blocks =
            build_epoch_blocks(0, &config, &nodes, HashType::default(), Nonce::new(1)).unwrap();
        let current_blocks =
            build_epoch_blocks(1, &config, &nodes, HashType::default(), Nonce::new(2)).unwrap();
        let current_plan = build_prefill_plan(
            1,
            &config,
            &nodes,
            &current_blocks,
            &topology,
            consensus_start_round,
        );
        let recipient = current_plan.recipients_by_sender[0][0];
        let expected = &current_plan.expected_by_node[&nodes[recipient].keypair.public];

        assert!(expected.contains(&current_blocks[0].hash));
        assert!(!expected.contains(&stale_blocks[0].hash));
    }

    #[test]
    fn prefill_expected_hashes_reject_equivocated_payload_commitment() {
        let config = SubsetGossipConfig {
            nodes: 36,
            quorum_size: 6,
            commands_per_node: 4,
            command_bytes: 32,
            targets_per_command: 3,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };
        let equivocated_config = SubsetGossipConfig {
            command_bytes: 33,
            ..config.clone()
        };
        let nodes = build_nodes(config.seed, config.nodes);
        let topology = round_quorums(
            &nodes
                .iter()
                .map(|node| node.keypair.public)
                .collect::<Vec<_>>(),
            HashType::default(),
            config.shuffle,
            config.quorum_size,
        );
        let consensus_start_round = consensus_start_round(&config, topology.len());
        let honest_blocks =
            build_epoch_blocks(0, &config, &nodes, HashType::default(), Nonce::new(1)).unwrap();
        let equivocated_blocks = build_epoch_blocks(
            0,
            &equivocated_config,
            &nodes,
            HashType::default(),
            Nonce::new(1),
        )
        .unwrap();
        let honest_plan = build_prefill_plan(
            0,
            &config,
            &nodes,
            &honest_blocks,
            &topology,
            consensus_start_round,
        );
        let recipient = honest_plan.recipients_by_sender[0][0];
        let expected = &honest_plan.expected_by_node[&nodes[recipient].keypair.public];

        assert!(expected.contains(&honest_blocks[0].hash));
        assert_ne!(honest_blocks[0].hash, equivocated_blocks[0].hash);
        assert!(!expected.contains(&equivocated_blocks[0].hash));
    }

    #[test]
    fn prefill_dispatch_fanout_widens_route_for_declared_withholders() {
        let config = SubsetGossipConfig {
            nodes: 64,
            quorum_size: 6,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_byzantine_withholders_per_branch: 1,
            ..SubsetGossipConfig::default()
        };
        let (_, topology_rounds) = find_round_number(config.nodes, config.quorum_size);

        assert_eq!(topology_rounds, 2);
        assert_eq!(ceil_log_rounds(config.nodes, config.quorum_size), 3);
        assert_eq!(prefill_dispatch_fanout(&config, topology_rounds), 29);
    }

    #[test]
    fn prefill_dispatch_routes_subtree_payloads_without_repair() {
        let config = SubsetGossipConfig {
            nodes: 72,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert_eq!(row.prefill_fanout, 17);
        assert!(row.metadata_converged);
        assert!(row.subset_payloads_complete_before_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
    }

    #[test]
    fn prefill_dispatch_survives_one_byzantine_route_withholder() {
        let config = SubsetGossipConfig {
            nodes: 72,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_byzantine_withholders_per_branch: 1,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert!(row.subset_payloads_complete_before_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
    }

    #[test]
    fn prefill_dispatch_survives_two_byzantine_route_withholders_for_q8() {
        let config = SubsetGossipConfig {
            nodes: 144,
            epochs: 1,
            quorum_size: 8,
            commands_per_node: 8,
            command_bytes: 64,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_byzantine_withholders_per_branch: 2,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert_eq!(row.prefill_fanout, 55);
        assert!(row.metadata_converged);
        assert!(row.subset_payloads_complete_before_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
    }

    #[test]
    fn prefill_dispatch_survives_three_byzantine_route_withholders_for_q12() {
        let config = SubsetGossipConfig {
            nodes: 144,
            epochs: 1,
            quorum_size: 12,
            commands_per_node: 8,
            command_bytes: 64,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_byzantine_withholders_per_branch: 3,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert_eq!(row.prefill_fanout, 59);
        assert!(row.metadata_converged);
        assert!(row.subset_payloads_complete_before_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
    }

    #[test]
    fn prefill_dispatch_survives_one_withholder_for_non_ideal_network_size() {
        let config = SubsetGossipConfig {
            seed: 109742935629,
            nodes: 64,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_byzantine_withholders_per_branch: 1,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert_eq!(row.prefill_fanout, 29);
        assert!(row.subset_payloads_complete_before_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
    }

    #[test]
    fn bft_prefill_rejects_deep_small_quorum_with_withholding() {
        let config = SubsetGossipConfig {
            seed: 109741012189,
            nodes: 72,
            epochs: 1,
            quorum_size: 4,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_byzantine_withholders_per_branch: 1,
            ..SubsetGossipConfig::default()
        };

        let err = run_subset_gossip(config).unwrap_err();
        assert!(
            err.to_string().contains("requires quorum size at least 5"),
            "{err}"
        );
    }

    #[test]
    fn prefill_dispatch_start_is_always_one_round() {
        let config = SubsetGossipConfig {
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };

        assert_eq!(consensus_start_round(&config, 0), 0);
        assert_eq!(consensus_start_round(&config, 1), 0);
        for topology_rounds in [2, 3, 4, 8] {
            assert_eq!(consensus_start_round(&config, topology_rounds), 1);
        }
    }

    #[test]
    fn prefill_dispatch_rejects_multi_round_skip_override() {
        let config = SubsetGossipConfig {
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_skip_rounds: 2,
            ..SubsetGossipConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn precomputed_inventory_routes_pick_one_holder_for_missing_payloads() {
        let config = SubsetGossipConfig {
            nodes: 4,
            quorum_size: 4,
            commands_per_node: 4,
            ..SubsetGossipConfig::default()
        };
        let mut target_masks = vec![PayloadMask::empty(4); 4];
        target_masks[1].set(0);
        target_masks[1].set(1);
        let block = BlockMeta {
            hash: HashType::default(),
            owner: 0,
            full_block_len: 0,
            tombstone_block_len: 0,
            target_masks,
            target_payload_deliveries: 2,
            slots: Vec::new(),
        };
        let mut states = (0..4).map(|_| NodeSubsetState::new(4)).collect::<Vec<_>>();
        states[0].insert_local_block(0, 4);
        states[2].merge_block(0, PayloadMask::full(4));
        states[3].merge_block(0, PayloadMask::full(4));
        let future_reachability = vec![
            vec![vec![0], vec![1], vec![2], vec![3]],
            vec![vec![0], vec![1], vec![2], vec![3]],
        ];

        let routes = precomputed_inventory_routes_for_quorum(
            &config,
            0,
            &[0, 1, 2, 3],
            &[block],
            &states,
            &future_reachability,
        );
        let payload_routes = routes
            .iter()
            .filter(|((_, recipient, owner), _)| *recipient == 1 && *owner == 0)
            .collect::<Vec<_>>();

        assert_eq!(payload_routes.len(), 1);
        assert_eq!(routes.get(&(0, 1, 0)).map(|route| route.attempt), Some(0));
        assert!(!routes.contains_key(&(2, 1, 0)));
        assert!(!routes.contains_key(&(3, 1, 0)));
    }

    #[test]
    fn precomputed_inventory_routes_ignore_metadata_only_false_holders() {
        let config = SubsetGossipConfig {
            nodes: 4,
            quorum_size: 4,
            commands_per_node: 4,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            ..SubsetGossipConfig::default()
        };
        let mut target_masks = vec![PayloadMask::empty(4); 4];
        target_masks[1].set(0);
        target_masks[1].set(1);
        let block = BlockMeta {
            hash: HashType::default(),
            owner: 0,
            full_block_len: 0,
            tombstone_block_len: 0,
            target_masks,
            target_payload_deliveries: 2,
            slots: Vec::new(),
        };
        let mut states = (0..4).map(|_| NodeSubsetState::new(4)).collect::<Vec<_>>();
        states[0].insert_local_block(0, 4);
        states[2].insert_block_metadata(0, 4);
        states[3].merge_block(0, PayloadMask::full(4));
        let future_reachability = vec![
            vec![vec![0], vec![1], vec![2], vec![3]],
            vec![vec![0], vec![1], vec![2], vec![3]],
        ];

        let routes = precomputed_inventory_routes_for_quorum(
            &config,
            0,
            &[1, 2, 3],
            &[block],
            &states,
            &future_reachability,
        );

        assert_eq!(routes.get(&(3, 1, 0)).map(|route| route.attempt), Some(0));
        assert!(!routes.contains_key(&(2, 1, 0)));
    }

    #[cfg(any(
        feature = "propagation-adaptive",
        feature = "propagation-inventory",
        feature = "propagation-push"
    ))]
    #[test]
    fn propagation_policy_rejects_trustless_inventory_without_prefill_coverage() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::None,
            hash_advertise: true,
            prefill_byzantine_withholders_per_branch: 1,
            ..SubsetGossipConfig::default()
        };

        let err = run_subset_gossip(config).unwrap_err();
        assert!(err.to_string().contains("invalid propagation policy"));
    }

    #[cfg(any(
        feature = "propagation-adaptive",
        feature = "propagation-inventory",
        feature = "propagation-push"
    ))]
    #[test]
    fn propagation_policy_rejects_withholding_above_quorum_tolerance() {
        let config = SubsetGossipConfig {
            nodes: 72,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_byzantine_withholders_per_branch: 2,
            ..SubsetGossipConfig::default()
        };

        let err = run_subset_gossip(config).unwrap_err();
        assert!(
            err.to_string().contains("exceeds quorum tolerance"),
            "{err}"
        );
    }

    #[test]
    fn bft_prefill_survives_one_byzantine_withholder_per_branch() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            prefill_mode: SubsetPrefillMode::PrefillDispatch,
            prefill_byzantine_withholders_per_branch: 1,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert!(row.subset_payloads_complete_before_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
        assert_eq!(row.prefill_byzantine_withholders_per_branch, 1);
    }

    #[test]
    fn scheduled_prefill_covers_round0_drop_without_repair() {
        let config = SubsetGossipConfig {
            nodes: 36,
            epochs: 1,
            quorum_size: 6,
            commands_per_node: 16,
            command_bytes: 128,
            targets_per_command: 3,
            repair_missing: false,
            drop_round0_dispatch: true,
            prefill_mode: SubsetPrefillMode::Scheduled,
            hash_advertise: true,
            ..SubsetGossipConfig::default()
        };

        let row = run_subset_gossip(config).unwrap().rows.remove(0);

        assert!(row.metadata_converged);
        assert!(row.subset_payloads_complete_before_repair);
        assert!(row.subset_payloads_complete_after_repair);
        assert_eq!(row.subset_missing_payloads_before_repair, 0);
        assert!(row.prefill_recipients > row.nodes);
        assert!(row.duplicate_suppressed_blocks > 0);
    }
}
