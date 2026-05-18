use std::collections::{BTreeMap, BTreeSet};

use blossom::algorithm::{select_quorums, supermajority_count};
use blossom::{
    Block, DoHash, HashType, Keypair, Nonce, PubKey, Result, SecKey, Transaction, TrustMode,
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
            round_timeout_ms: 50,
            drop_ppm: 0,
            fuzz_ppm: 0,
            spike_ppm: 0,
            spike_latency_ms: 0,
            repair_rounds: 0,
            repair_fanout: 0,
            repair_quorum: 0,
            repair_timeout_ms: 500,
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
        for (label, value) in [
            ("drop_ppm", self.drop_ppm),
            ("fuzz_ppm", self.fuzz_ppm),
            ("spike_ppm", self.spike_ppm),
        ] {
            if value > CHAOS_RATE_DENOMINATOR {
                return Err(blossom::BlossomError::WireProtocol(format!(
                    "{label} must be <= {CHAOS_RATE_DENOMINATOR}"
                )));
            }
        }
        if self.repair_rounds > 0 {
            let max_peers = self.nodes.saturating_sub(1);
            let fanout = self.effective_repair_fanout();
            let quorum = self.effective_repair_quorum();
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
        }
        Ok(())
    }

    fn effective_repair_fanout(&self) -> usize {
        if self.repair_fanout == 0 {
            self.nodes.saturating_sub(1)
        } else {
            self.repair_fanout.min(self.nodes.saturating_sub(1))
        }
    }

    fn effective_repair_quorum(&self) -> usize {
        if self.repair_quorum == 0 {
            supermajority_count(self.nodes)
        } else {
            self.repair_quorum
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochChaosReport {
    pub config: EpochChaosConfig,
    pub epochs: Vec<EpochChaosEpochReport>,
    pub total_messages: u64,
    pub delivered_messages: u64,
    pub dropped_messages: u64,
    pub fuzzed_messages: u64,
    pub late_messages: u64,
    pub spiked_messages: u64,
    pub repair_attempts: u64,
    pub repair_successes: u64,
    pub final_correct_nodes: usize,
    pub final_incorrect_nodes: usize,
    pub final_unique_epoch_hashes: usize,
    pub final_correct_epoch_hash: HashType,
    pub final_correct_epoch_nonce: Nonce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochChaosEpochReport {
    pub epoch: usize,
    pub nonce: Nonce,
    pub correct_start_nodes: usize,
    pub correct_nodes: usize,
    pub incorrect_nodes: usize,
    pub unique_epoch_hashes: usize,
    pub min_blocks_per_node: usize,
    pub max_blocks_per_node: usize,
    pub canonical_blocks: usize,
    pub canonical_epoch_hash: HashType,
    pub pre_repair_correct_nodes: usize,
    pub repaired_nodes: usize,
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

pub fn run_epoch_chaos(config: EpochChaosConfig) -> Result<EpochChaosReport> {
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

    for epoch in 0..config.epochs {
        let nonce = canonical_nonce.new_next();
        let correct_start_nodes = states
            .iter()
            .filter(|state| {
                state.last_epoch == canonical_last_epoch && state.nonce == canonical_nonce
            })
            .count();
        let local_blocks = nodes
            .iter()
            .enumerate()
            .map(|(node_index, node)| {
                let state = &states[node_index];
                signed_block(
                    node,
                    epoch,
                    node_index,
                    state.last_epoch,
                    state.nonce.new_next(),
                    config.transactions_per_node,
                    config.transaction_bytes,
                    config.trust_mode,
                )
            })
            .collect::<Vec<_>>();

        let canonical_blocks = local_blocks
            .iter()
            .enumerate()
            .filter(|(index, block)| {
                states[*index].last_epoch == canonical_last_epoch
                    && states[*index].nonce == canonical_nonce
                    && block.body.last_epoch == canonical_last_epoch
                    && block.body.nonce == nonce
            })
            .map(|(_, block)| (block.hash, block.clone()))
            .collect::<BTreeMap<_, _>>();
        let canonical_hash = epoch_hash(canonical_last_epoch, nonce, canonical_blocks.hash());

        let mut known_blocks = local_blocks
            .iter()
            .map(|block| BTreeMap::from([(block.hash, block.clone())]))
            .collect::<Vec<_>>();

        let topology = round_quorums(&keys, canonical_last_epoch, config.shuffle);
        let mut totals = EpochTransportTotals::default();
        for (round, quorums) in topology.iter().enumerate() {
            let before_round = known_blocks.clone();
            for quorum in quorums {
                for sender in quorum {
                    for recipient in quorum {
                        if sender == recipient {
                            continue;
                        }
                        let outcome = transport.sample(epoch, round, *sender, *recipient);
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
                        if outcome.delay_ms > config.round_timeout_ms {
                            totals.late += 1;
                            continue;
                        }
                        totals.delivered += 1;
                        let recipient_next_nonce = states[*recipient].nonce.new_next();
                        let recipient_last_epoch = states[*recipient].last_epoch;
                        let deliverable = before_round[*sender]
                            .iter()
                            .filter(|(_, block)| {
                                block.body.last_epoch == recipient_last_epoch
                                    && block.body.nonce == recipient_next_nonce
                            })
                            .map(|(hash, block)| (*hash, block.clone()))
                            .collect::<Vec<_>>();
                        known_blocks[*recipient].extend(deliverable);
                    }
                }
            }
        }

        let mut pre_repair_correct_nodes = 0usize;
        let block_counts = known_blocks.iter().map(BTreeMap::len).collect::<Vec<_>>();
        for (index, blocks) in known_blocks.iter().enumerate() {
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

        let repaired_nodes = repair_epoch(
            &config,
            &mut transport,
            epoch,
            &mut states,
            canonical_hash,
            nonce,
            &mut totals,
        );
        let correct_nodes = states
            .iter()
            .filter(|state| state.last_epoch == canonical_hash && state.nonce == nonce)
            .count();
        let hashes = states
            .iter()
            .map(|state| state.last_epoch)
            .collect::<BTreeSet<_>>();

        let report = EpochChaosEpochReport {
            epoch,
            nonce,
            correct_start_nodes,
            correct_nodes,
            incorrect_nodes: config.nodes.saturating_sub(correct_nodes),
            unique_epoch_hashes: hashes.len(),
            min_blocks_per_node: block_counts.iter().copied().min().unwrap_or_default(),
            max_blocks_per_node: block_counts.iter().copied().max().unwrap_or_default(),
            canonical_blocks: canonical_blocks.len(),
            canonical_epoch_hash: canonical_hash,
            pre_repair_correct_nodes,
            repaired_nodes,
            messages: totals,
        };
        canonical_last_epoch = canonical_hash;
        canonical_nonce = nonce;
        epoch_reports.push(report);
    }

    let final_correct_epoch_hash = canonical_last_epoch;
    let final_correct_epoch_nonce = canonical_nonce;
    let final_correct_nodes = states
        .iter()
        .filter(|state| {
            state.last_epoch == final_correct_epoch_hash && state.nonce == final_correct_epoch_nonce
        })
        .count();
    let final_unique_epoch_hashes = states
        .iter()
        .map(|state| state.last_epoch)
        .collect::<BTreeSet<_>>()
        .len();
    let mut report = EpochChaosReport {
        config,
        epochs: epoch_reports,
        total_messages: 0,
        delivered_messages: 0,
        dropped_messages: 0,
        fuzzed_messages: 0,
        late_messages: 0,
        spiked_messages: 0,
        repair_attempts: 0,
        repair_successes: 0,
        final_correct_nodes,
        final_incorrect_nodes: states.len().saturating_sub(final_correct_nodes),
        final_unique_epoch_hashes,
        final_correct_epoch_hash,
        final_correct_epoch_nonce,
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
    }

    Ok(report)
}

fn repair_epoch(
    config: &EpochChaosConfig,
    transport: &mut TransportSampler,
    epoch: usize,
    states: &mut [NodeEpochState],
    canonical_hash: HashType,
    canonical_nonce: Nonce,
    totals: &mut EpochTransportTotals,
) -> usize {
    if config.repair_rounds == 0 {
        return 0;
    }
    let fanout = config.effective_repair_fanout();
    let quorum = config.effective_repair_quorum();
    if fanout == 0 || quorum == 0 {
        return 0;
    }

    let mut repaired = 0usize;
    for repair_round in 0..config.repair_rounds {
        let round_states = states.to_vec();
        let incorrect_nodes = round_states
            .iter()
            .enumerate()
            .filter_map(|(index, state)| {
                (state.last_epoch != canonical_hash || state.nonce != canonical_nonce)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        if incorrect_nodes.is_empty() {
            break;
        }

        for recipient in incorrect_nodes {
            // Restart handshake: peers return only their epoch summary. The
            // modeled catch-up transfer happens later, after a summary quorum.
            let fanout = restart_ping_peers(
                states.len(),
                fanout,
                config.seed,
                epoch,
                repair_round,
                recipient,
            );
            let mut returned_summaries = BTreeMap::<NodeEpochState, Vec<usize>>::new();
            for sender in fanout {
                let outcome = transport.sample_repair(epoch, repair_round, sender, recipient);
                totals.total += 1;
                totals.repair_attempts += 1;
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
                if outcome.delay_ms > config.repair_timeout_ms {
                    totals.late += 1;
                    continue;
                }
                totals.delivered += 1;
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
                .filter(|(_, peers)| peers.len() >= quorum)
                .max_by(|(left_state, left_peers), (right_state, right_peers)| {
                    left_peers
                        .len()
                        .cmp(&right_peers.len())
                        .then_with(|| left_state.nonce.cmp(&right_state.nonce))
                        .then_with(|| left_state.last_epoch.cmp(&right_state.last_epoch))
                })
            {
                let sender = peers[0];
                let outcome = transport.sample_repair_fetch(epoch, repair_round, sender, recipient);
                totals.total += 1;
                totals.repair_attempts += 1;
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
                if outcome.delay_ms > config.repair_timeout_ms {
                    totals.late += 1;
                    continue;
                }
                totals.delivered += 1;
                totals.repair_successes += 1;
                states[recipient] = state;
                repaired += 1;
            }
        }
    }
    repaired
}

fn restart_ping_peers(
    node_count: usize,
    repair_fanout: usize,
    seed: u64,
    epoch: usize,
    repair_round: usize,
    recipient: usize,
) -> Vec<usize> {
    let mut peers = (0..node_count)
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
        TransportOutcome {
            delay_ms: self.config.latency_ms + jitter + spike,
            dropped: sample_rate(seed, 0x33, self.config.drop_ppm),
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

fn sample_rate(seed: u64, salt: u64, ppm: u32) -> bool {
    ppm > 0 && (splitmix64(seed ^ salt) % CHAOS_RATE_DENOMINATOR as u64) < ppm as u64
}

#[cfg(test)]
mod tests {
    use super::*;

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
            repair_quorum: 5,
            repair_timeout_ms: 100,
            ..EpochChaosConfig::default()
        })
        .unwrap();
        assert_eq!(report.final_correct_nodes, 12);
        assert!(report.repair_successes > 0);
    }
}
