use std::collections::{BTreeMap, BTreeSet};

use crate::algorithm::supermajority_order_statistic;
use crate::availability::{
    FilteredPayloadBatchDelivery, FilteredPayloadBatchDeliveryBody, FilteredPayloadBatchFetch,
    FilteredPayloadBatchFetchBody, FilteredPayloadDeliveryItem, FilteredPayloadRequest,
};
use crate::block::{FilteredDeliveryPolicy, FilteredTransactionSlot};
use crate::hash::ProtocolHasher;
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
            seed: 0x7375_6273_6574_31,
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
            latency: SubsetLatencyProfile::default(),
        }
    }
}

impl SubsetGossipConfig {
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
        self.latency.validate()
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
    pub nodes: usize,
    pub quorum_size: usize,
    pub rounds: usize,
    pub quorums: usize,
    pub trusted: bool,
    pub shuffle: bool,
    pub repair_missing: bool,
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
        if let Some(slot) = self.blocks.get_mut(owner) {
            if slot.is_none() {
                *slot = Some(PayloadMask::empty(command_count));
            }
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
        if trailing == 0 {
            return;
        }
        if let Some(last) = self.words.last_mut() {
            *last &= (1u64 << trailing) - 1;
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct EpochByteTotals {
    full_dispatch_bytes: usize,
    subset_dispatch_bytes: usize,
    control_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct EpochLatencyTotals {
    dispatch_ms: u64,
    control_ms: u64,
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

    for (round, quorums) in topology.iter().enumerate() {
        let before_full = full_known.clone();
        let before_subset = subset_states.clone();
        let mut next_full = full_known.clone();
        let mut next_subset = subset_states.clone();
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
            let stage_latency = quorum_stage_finality_latency_ms(quorum, config.latency);
            latency_totals.dispatch_ms += stage_latency;
            if !config.trusted {
                latency_totals.control_ms += stage_latency * 4;
                byte_totals.control_bytes += control_bytes_for_quorum(
                    round as u8,
                    quorum,
                    nodes,
                    &before_full,
                    &blocks,
                    last_epoch,
                    nonce,
                )?;
            }

            for sender in quorum {
                for recipient in quorum {
                    if recipient == sender {
                        continue;
                    }

                    byte_totals.full_dispatch_bytes += full_dispatch_len_by_sender[*sender];

                    let mut subset_block_count = 0usize;
                    let mut subset_block_bytes = 0usize;
                    for block in &blocks {
                        let Some(sender_full) = before_subset[*sender].blocks[block.owner].as_ref()
                        else {
                            continue;
                        };
                        subset_block_count += 1;
                        let target_mask = &block.target_masks[*recipient];
                        let full_count = next_subset[*recipient].merge_targeted_payloads(
                            block.owner,
                            sender_full,
                            target_mask,
                        );
                        subset_block_bytes +=
                            block.tombstone_block_len + (full_count * config.command_bytes);
                        if full_count == 0
                            && before_subset[*recipient].blocks[block.owner].is_none()
                        {
                            next_subset[*recipient]
                                .insert_block_metadata(block.owner, config.commands_per_node);
                        }
                    }

                    byte_totals.subset_dispatch_bytes += dispatch_len_for_block_stats(
                        header_len,
                        signature_tree_len,
                        subset_block_count,
                        subset_block_bytes,
                    )?;
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
    let subset_payload_ready_latency_ms = modeled_finality_latency_ms + subset_repair_latency_ms;
    let full_wire_bytes = byte_totals.full_dispatch_bytes + byte_totals.control_bytes;
    let subset_wire_bytes =
        byte_totals.subset_dispatch_bytes + byte_totals.control_bytes + subset_repair_bytes;
    let total_commands = config.nodes * config.commands_per_node;

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
            nodes: config.nodes,
            quorum_size: config.quorum_size,
            rounds: topology.len(),
            quorums: topology.iter().map(Vec::len).sum(),
            trusted: config.trusted,
            shuffle: config.shuffle,
            repair_missing: config.repair_missing,
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
        return Ok(len);
    }
    Ok(len)
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
        for quorum_member in 0..quorum_size {
            let index = first_quorum_member + (quorum_member * size_multiple * offset);
            if let Some(member) = ordered_indices.get(index) {
                quorum.push(*member);
            }
        }

        if ordered_indices.len() >= optimal_network_size {
            for quorum_member in 0..quorum_size {
                let index = optimal_network_size
                    + first_quorum_member
                    + (quorum_member * size_multiple * offset);
                if let Some(member) = ordered_indices.get(index) {
                    quorum.push(*member);
                }
            }
        }

        quorum.sort_unstable();
        quorum.dedup();
        quorum_members_matrix.push(quorum);
    }

    quorum_members_matrix
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
    const HASH_CHUNK_BYTES: usize = 64;

    let mut hasher = ProtocolHasher::new();
    let mut state = (epoch as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add((owner as u64) << 32)
        .wrapping_add(command as u64);

    let mut remaining = len;
    let mut buffer = [0u8; HASH_CHUNK_BYTES];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        let mut filled = 0usize;
        while filled < take {
            state = splitmix64(state);
            let state_bytes = state.to_le_bytes();
            let copy_len = (take - filled).min(state_bytes.len());
            buffer[filled..filled + copy_len].copy_from_slice(&state_bytes[..copy_len]);
            filled += copy_len;
        }
        hasher.update(&buffer[..take]);
        remaining -= take;
    }
    hasher.finalize()
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
    if latency_ms == 0 {
        0.0
    } else {
        commands as f64 / (latency_ms as f64 / 1000.0)
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
}
