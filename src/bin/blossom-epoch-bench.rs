use std::collections::{BTreeMap, BTreeSet};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, ValueEnum};

use blossom::wire::FRAME_PREFIX_BYTES;
use blossom::{
    Block, BlockHandle, BlockIndex, BlossomBody, Commit, CommitBody, DoHash, EchoResponse,
    EchoResponseBody, HashType, Header, Keypair, MSGKey, Msg, Nonce, Proposal, ProposalBody,
    PubKey, QuorumSize, SecretSigner, Signature, SignatureTree, Transaction, Verification,
    VerificationBody, WireRequest, encoded_len, framed_len, supermajority_order_statistic,
};

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(
    name = "blossom-epoch-bench",
    about = "Benchmark paper-aligned Blossom epoch propagation depth"
)]
struct Args {
    #[arg(long, default_value_t = 36)]
    nodes: usize,
    #[arg(long, default_value_t = 6)]
    quorum_size: usize,
    #[arg(long, default_value_t = 1, alias = "epochs")]
    epoch_depth: usize,
    #[arg(long)]
    target_transactions: Option<usize>,
    #[arg(long, default_value_t = 1000)]
    transactions_per_node: usize,
    #[arg(long, default_value_t = 32)]
    transaction_bytes: usize,
    #[arg(long, default_value_t = 0)]
    application_state_bytes: usize,
    #[arg(long, default_value_t = false)]
    shuffle: bool,
    #[arg(long, default_value_t = false)]
    trusted: bool,
    #[arg(long, value_enum, default_value_t = LatencyDistribution::Even)]
    latency_distribution: LatencyDistribution,
    #[arg(long, default_value_t = 1)]
    latency_ms: u64,
    #[arg(long, default_value_t = 1)]
    latency_min_ms: u64,
    #[arg(long, default_value_t = 300)]
    latency_max_ms: u64,
    #[arg(long, default_value_t = 0x6c61_7465_6e63_7931)]
    latency_seed: u64,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    append: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LatencyDistribution {
    Even,
    Random,
}

impl LatencyDistribution {
    fn as_str(self) -> &'static str {
        match self {
            Self::Even => "even",
            Self::Random => "random",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LatencyProfile {
    distribution: LatencyDistribution,
    latency_ms: u64,
    min_ms: u64,
    max_ms: u64,
    seed: u64,
}

impl LatencyProfile {
    fn from_args(args: &Args) -> MainResult<Self> {
        QuorumSize::new(args.quorum_size)?;
        if args.latency_min_ms > args.latency_max_ms {
            return Err("latency-min-ms must be <= latency-max-ms".into());
        }
        Ok(Self {
            distribution: args.latency_distribution,
            latency_ms: args.latency_ms,
            min_ms: args.latency_min_ms,
            max_ms: args.latency_max_ms,
            seed: args.latency_seed,
        })
    }

    fn edge_latency_ms(self, sender: usize, recipient: usize) -> u64 {
        match self.distribution {
            LatencyDistribution::Even => self.latency_ms,
            LatencyDistribution::Random => {
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

#[derive(Debug, Clone)]
struct BenchNode {
    keypair: Keypair,
    signer: SecretSigner,
}

#[derive(Debug, Clone)]
struct NodeEpochState {
    blocks: BlockIndex,
}

#[derive(Debug, Clone)]
struct DispatchProfile {
    sender: PubKey,
    blocks_hash: HashType,
    signature_tree_hash: HashType,
    framed_len: usize,
}

#[derive(Debug, Clone, Default)]
struct MessageTotals {
    dispatch_messages: usize,
    echo_messages: usize,
    verification_messages: usize,
    proposal_messages: usize,
    commit_messages: usize,
    dispatch_bytes: usize,
    echo_bytes: usize,
    verification_bytes: usize,
    proposal_bytes: usize,
    commit_bytes: usize,
}

impl MessageTotals {
    fn total_messages(&self) -> usize {
        self.dispatch_messages
            + self.echo_messages
            + self.verification_messages
            + self.proposal_messages
            + self.commit_messages
    }

    fn total_bytes(&self) -> usize {
        self.dispatch_bytes
            + self.echo_bytes
            + self.verification_bytes
            + self.proposal_bytes
            + self.commit_bytes
    }
}

#[derive(Debug, Clone, Default)]
struct ModeledLatencyTotals {
    dispatch_ms: u64,
    echo_ms: u64,
    verification_ms: u64,
    proposal_ms: u64,
    commit_ms: u64,
}

impl ModeledLatencyTotals {
    fn total_ms(&self) -> u64 {
        self.dispatch_ms + self.echo_ms + self.verification_ms + self.proposal_ms + self.commit_ms
    }
}

#[derive(Debug, Clone, Default)]
struct StageMaxLatency {
    dispatch_ms: u64,
    echo_ms: u64,
    verification_ms: u64,
    proposal_ms: u64,
    commit_ms: u64,
}

impl StageMaxLatency {
    fn merge(&mut self, other: Self) {
        self.dispatch_ms = self.dispatch_ms.max(other.dispatch_ms);
        self.echo_ms = self.echo_ms.max(other.echo_ms);
        self.verification_ms = self.verification_ms.max(other.verification_ms);
        self.proposal_ms = self.proposal_ms.max(other.proposal_ms);
        self.commit_ms = self.commit_ms.max(other.commit_ms);
    }
}

#[derive(Debug, Clone, Default)]
struct StageModeledLatency {
    convergence: StageMaxLatency,
    finality: StageMaxLatency,
}

impl StageModeledLatency {
    fn merge(&mut self, other: Self) {
        self.convergence.merge(other.convergence);
        self.finality.merge(other.finality);
    }
}

#[derive(Debug, Clone)]
struct EpochBenchRow {
    epoch: usize,
    epoch_depth: usize,
    nodes: usize,
    quorum_size: usize,
    rounds: usize,
    quorums: usize,
    shuffle: bool,
    trusted: bool,
    latency_distribution: LatencyDistribution,
    latency_ms: u64,
    latency_min_ms: u64,
    latency_max_ms: u64,
    transactions_per_node: usize,
    transaction_bytes: usize,
    application_state_bytes_per_block: usize,
    epoch_application_state_bytes: usize,
    epoch_transactions: usize,
    cumulative_transactions: usize,
    block_count: usize,
    min_blocks_per_node: usize,
    max_blocks_per_node: usize,
    unique_epoch_hashes: usize,
    converged: bool,
    block_build_us: u128,
    propagation_us: u128,
    finalize_us: u128,
    total_us: u128,
    modeled_latency_ms: u64,
    modeled_dispatch_latency_ms: u64,
    modeled_echo_latency_ms: u64,
    modeled_verification_latency_ms: u64,
    modeled_proposal_latency_ms: u64,
    modeled_commit_latency_ms: u64,
    modeled_finality_latency_ms: u64,
    modeled_finality_dispatch_latency_ms: u64,
    modeled_finality_echo_latency_ms: u64,
    modeled_finality_verification_latency_ms: u64,
    modeled_finality_proposal_latency_ms: u64,
    modeled_finality_commit_latency_ms: u64,
    block_bytes: usize,
    dispatch_messages: usize,
    echo_messages: usize,
    verification_messages: usize,
    proposal_messages: usize,
    commit_messages: usize,
    total_messages: usize,
    dispatch_bytes: usize,
    echo_bytes: usize,
    verification_bytes: usize,
    proposal_bytes: usize,
    commit_bytes: usize,
    total_wire_bytes: usize,
    epoch_hash: HashType,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let latency = LatencyProfile::from_args(&args)?;
    let nodes = build_nodes(args.nodes);
    let epoch_depth = epoch_depth(&args);
    let mut last_epoch = HashType::default();
    let mut rows = Vec::with_capacity(epoch_depth);

    for epoch in 0..epoch_depth {
        let row = run_epoch(
            epoch,
            epoch_depth,
            &nodes,
            last_epoch,
            Nonce::new((epoch + 1) as u64),
            args.quorum_size,
            args.transactions_per_node,
            args.transaction_bytes,
            args.application_state_bytes,
            args.shuffle,
            args.trusted,
            latency,
        )?;
        last_epoch = row.epoch_hash;
        println!("{}", row.to_csv());
        rows.push(row);
    }

    if let Some(path) = args.csv {
        write_csv(&path, args.append, &rows)?;
        eprintln!("wrote {}", path.display());
    }

    Ok(())
}

fn epoch_depth(args: &Args) -> usize {
    match args.target_transactions {
        Some(target) => {
            let per_epoch = args.nodes.saturating_mul(args.transactions_per_node).max(1);
            target.div_ceil(per_epoch).max(1)
        }
        None => args.epoch_depth.max(1),
    }
}

fn build_nodes(count: usize) -> Vec<BenchNode> {
    (0..count)
        .map(|_| {
            let keypair = Keypair::generate();
            let signer = keypair.signer();
            BenchNode { keypair, signer }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn run_epoch(
    epoch: usize,
    epoch_depth: usize,
    nodes: &[BenchNode],
    last_epoch: HashType,
    nonce: Nonce,
    quorum_size: usize,
    transactions_per_node: usize,
    transaction_bytes: usize,
    application_state_bytes: usize,
    shuffle: bool,
    trusted: bool,
    latency: LatencyProfile,
) -> MainResult<EpochBenchRow> {
    let total_start = Instant::now();

    let block_start = Instant::now();
    let mut states = nodes
        .iter()
        .enumerate()
        .map(|(node_index, node)| {
            let block = signed_block(
                node,
                last_epoch,
                nonce,
                transactions(epoch, node_index, transactions_per_node, transaction_bytes),
                application_state_bytes,
                trusted,
            );
            let block = BlockHandle::new(block)?;
            let mut blocks = BlockIndex::new();
            blocks.insert(block.hash(), block);
            Ok(NodeEpochState { blocks })
        })
        .collect::<MainResult<Vec<_>>>()?;
    let block_build_us = block_start.elapsed().as_micros();
    let block_bytes = states
        .iter()
        .map(|state| {
            state
                .blocks
                .values_ref()
                .map(encoded_block_len)
                .sum::<MainResult<usize>>()
        })
        .sum::<MainResult<usize>>()?;

    let topology = round_quorums(
        &nodes
            .iter()
            .map(|node| node.keypair.public)
            .collect::<Vec<_>>(),
        last_epoch,
        shuffle,
        quorum_size,
    );
    let quorums = topology.iter().map(Vec::len).sum();

    let propagation_start = Instant::now();
    let mut totals = MessageTotals::default();
    let mut modeled_convergence_latency = ModeledLatencyTotals::default();
    let mut modeled_finality_latency = ModeledLatencyTotals::default();
    for (round, quorums) in topology.iter().enumerate() {
        let before_round = states.clone();
        let mut round_latency = StageModeledLatency::default();
        for quorum in quorums {
            let stage_latency = count_quorum_messages(
                round as u8,
                quorum,
                nodes,
                &before_round,
                last_epoch,
                nonce,
                trusted,
                latency,
                &mut totals,
            )?;
            round_latency.merge(stage_latency);

            let Some((first, rest)) = quorum.split_first() else {
                continue;
            };
            let union = before_round[*first]
                .blocks
                .union_from(rest.iter().map(|member| &before_round[*member].blocks));
            for member in quorum {
                states[*member].blocks = union.clone();
            }
        }
        modeled_convergence_latency.dispatch_ms += round_latency.convergence.dispatch_ms;
        modeled_convergence_latency.echo_ms += round_latency.convergence.echo_ms;
        modeled_convergence_latency.verification_ms += round_latency.convergence.verification_ms;
        modeled_convergence_latency.proposal_ms += round_latency.convergence.proposal_ms;
        modeled_convergence_latency.commit_ms += round_latency.convergence.commit_ms;
        modeled_finality_latency.dispatch_ms += round_latency.finality.dispatch_ms;
        modeled_finality_latency.echo_ms += round_latency.finality.echo_ms;
        modeled_finality_latency.verification_ms += round_latency.finality.verification_ms;
        modeled_finality_latency.proposal_ms += round_latency.finality.proposal_ms;
        modeled_finality_latency.commit_ms += round_latency.finality.commit_ms;
    }
    let propagation_us = propagation_start.elapsed().as_micros();

    let finalize_start = Instant::now();
    let hashes = states
        .iter()
        .map(|state| state.blocks.hash())
        .collect::<BTreeSet<_>>();
    let block_counts = states
        .iter()
        .map(|state| state.blocks.len())
        .collect::<Vec<_>>();
    let min_blocks_per_node = block_counts.iter().copied().min().unwrap_or_default();
    let max_blocks_per_node = block_counts.iter().copied().max().unwrap_or_default();
    let epoch_hash = hashes
        .iter()
        .next()
        .map(|blocks_hash| epoch_hash(last_epoch, nonce, *blocks_hash))
        .unwrap_or_else(HashType::default);
    let converged = hashes.len() == 1 && min_blocks_per_node == nodes.len();
    let finalize_us = finalize_start.elapsed().as_micros();

    Ok(EpochBenchRow {
        epoch,
        epoch_depth,
        nodes: nodes.len(),
        quorum_size,
        rounds: topology.len(),
        quorums,
        shuffle,
        trusted,
        latency_distribution: latency.distribution,
        latency_ms: latency.latency_ms,
        latency_min_ms: latency.min_ms,
        latency_max_ms: latency.max_ms,
        transactions_per_node,
        transaction_bytes,
        application_state_bytes_per_block: application_state_bytes,
        epoch_application_state_bytes: nodes.len() * application_state_bytes,
        epoch_transactions: nodes.len() * transactions_per_node,
        cumulative_transactions: (epoch + 1) * nodes.len() * transactions_per_node,
        block_count: nodes.len(),
        min_blocks_per_node,
        max_blocks_per_node,
        unique_epoch_hashes: hashes.len(),
        converged,
        block_build_us,
        propagation_us,
        finalize_us,
        total_us: total_start.elapsed().as_micros(),
        modeled_latency_ms: modeled_convergence_latency.total_ms(),
        modeled_dispatch_latency_ms: modeled_convergence_latency.dispatch_ms,
        modeled_echo_latency_ms: modeled_convergence_latency.echo_ms,
        modeled_verification_latency_ms: modeled_convergence_latency.verification_ms,
        modeled_proposal_latency_ms: modeled_convergence_latency.proposal_ms,
        modeled_commit_latency_ms: modeled_convergence_latency.commit_ms,
        modeled_finality_latency_ms: modeled_finality_latency.total_ms(),
        modeled_finality_dispatch_latency_ms: modeled_finality_latency.dispatch_ms,
        modeled_finality_echo_latency_ms: modeled_finality_latency.echo_ms,
        modeled_finality_verification_latency_ms: modeled_finality_latency.verification_ms,
        modeled_finality_proposal_latency_ms: modeled_finality_latency.proposal_ms,
        modeled_finality_commit_latency_ms: modeled_finality_latency.commit_ms,
        block_bytes,
        dispatch_messages: totals.dispatch_messages,
        echo_messages: totals.echo_messages,
        verification_messages: totals.verification_messages,
        proposal_messages: totals.proposal_messages,
        commit_messages: totals.commit_messages,
        total_messages: totals.total_messages(),
        dispatch_bytes: totals.dispatch_bytes,
        echo_bytes: totals.echo_bytes,
        verification_bytes: totals.verification_bytes,
        proposal_bytes: totals.proposal_bytes,
        commit_bytes: totals.commit_bytes,
        total_wire_bytes: totals.total_bytes(),
        epoch_hash,
    })
}

fn signed_block(
    node: &BenchNode,
    last_epoch: HashType,
    nonce: Nonce,
    txs: Vec<Transaction>,
    application_state_bytes: usize,
    trusted: bool,
) -> Block {
    let mut block = Block::default();
    block.body.validator = node.keypair.public;
    block.body.last_epoch = last_epoch;
    block.body.nonce = nonce;
    if application_state_bytes > 0 {
        block
            .set_application_state(application_state_payload(
                node.keypair.public,
                nonce,
                application_state_bytes,
            ))
            .expect("benchmark application-state payload should fit");
    }
    block.body.txs = txs;
    if trusted {
        block.seal_unsigned(node.keypair.public);
    } else {
        block.sign_with(&node.signer);
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
            Transaction::new(transaction_payload(
                epoch,
                node_index,
                tx_index,
                transaction_bytes,
            ))
        })
        .collect()
}

fn transaction_payload(epoch: usize, node_index: usize, tx_index: usize, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    let mut seed = (epoch as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add((node_index as u64) << 32)
        .wrapping_add(tx_index as u64);

    for chunk in bytes.chunks_mut(8) {
        seed = splitmix64(seed);
        let seed_bytes = seed.to_le_bytes();
        let take = chunk.len();
        chunk.copy_from_slice(&seed_bytes[..take]);
    }

    bytes
}

fn application_state_payload(public_key: PubKey, nonce: Nonce, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    let mut seed = u64::from_le_bytes(public_key.as_ref()[..8].try_into().unwrap_or([0; 8]))
        ^ nonce.value()
        ^ 0xa076_1d64_78bd_642f;

    for chunk in bytes.chunks_mut(8) {
        seed = splitmix64(seed);
        let seed_bytes = seed.to_le_bytes();
        let take = chunk.len();
        chunk.copy_from_slice(&seed_bytes[..take]);
    }

    bytes
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
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

fn quorum_stage_finality_latency_ms(quorum: &[usize], latency: LatencyProfile) -> u64 {
    quorum_stage_finality_latency_ms_with(quorum, |sender, recipient| {
        latency.edge_latency_ms(sender, recipient)
    })
}

fn quorum_stage_finality_latency_ms_with(
    quorum: &[usize],
    mut edge_latency_ms: impl FnMut(usize, usize) -> u64,
) -> u64 {
    let receiver_ceilings = quorum.iter().map(|recipient| {
        let arrivals = quorum.iter().map(|sender| {
            if sender == recipient {
                0
            } else {
                edge_latency_ms(*sender, *recipient)
            }
        });
        supermajority_order_statistic(arrivals, quorum.len()).unwrap_or_default()
    });

    supermajority_order_statistic(receiver_ceilings, quorum.len()).unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn count_quorum_messages(
    round: u8,
    quorum: &[usize],
    nodes: &[BenchNode],
    states: &[NodeEpochState],
    last_epoch: HashType,
    nonce: Nonce,
    trusted: bool,
    latency: LatencyProfile,
    totals: &mut MessageTotals,
) -> MainResult<StageModeledLatency> {
    let mut stage_latency = StageModeledLatency::default();
    let finality_stage_latency_ms = quorum_stage_finality_latency_ms(quorum, latency);
    for sender in quorum {
        let dispatch = dispatch_profile_for(
            &nodes[*sender],
            &states[*sender].blocks,
            last_epoch,
            nonce,
            round,
            trusted,
        )?;
        for recipient in quorum {
            if recipient == sender {
                continue;
            }
            stage_latency.convergence.dispatch_ms = stage_latency
                .convergence
                .dispatch_ms
                .max(latency.edge_latency_ms(*sender, *recipient));
            totals.dispatch_messages += 1;
            totals.dispatch_bytes += dispatch.framed_len;
        }
        stage_latency.finality.dispatch_ms = finality_stage_latency_ms;

        if trusted {
            continue;
        }

        for echo_sender in quorum {
            if echo_sender == sender {
                continue;
            }
            let echo = echo_for(&nodes[*echo_sender], &dispatch, last_epoch, nonce, round)?;
            let echo_len = framed_len(&WireRequest::Message(Msg::EchoResponse(echo)))?;
            for recipient in quorum {
                if recipient == echo_sender {
                    continue;
                }
                stage_latency.convergence.echo_ms = stage_latency
                    .convergence
                    .echo_ms
                    .max(latency.edge_latency_ms(*echo_sender, *recipient));
                totals.echo_messages += 1;
                totals.echo_bytes += echo_len;
            }
        }
        stage_latency.finality.echo_ms = finality_stage_latency_ms;
    }

    if trusted {
        return Ok(stage_latency);
    }

    let union = quorum
        .iter()
        .flat_map(|member| {
            states[*member]
                .blocks
                .iter_ref()
                .map(|(hash, _)| (*hash, ()))
        })
        .collect::<BTreeMap<_, _>>();
    let union_hash = union.hash();

    for sender in quorum {
        let verification = verification_for(
            &nodes[*sender],
            &union,
            union_hash,
            last_epoch,
            nonce,
            round,
        )?;
        let verification_len = framed_len(&WireRequest::Message(Msg::Verification(verification)))?;
        for recipient in quorum {
            if recipient == sender {
                continue;
            }
            stage_latency.convergence.verification_ms = stage_latency
                .convergence
                .verification_ms
                .max(latency.edge_latency_ms(*sender, *recipient));
            totals.verification_messages += 1;
            totals.verification_bytes += verification_len;
        }
        stage_latency.finality.verification_ms = finality_stage_latency_ms;

        let proposal = proposal_for(
            &nodes[*sender],
            &union,
            union_hash,
            last_epoch,
            nonce,
            round,
        )?;
        let proposal_len = framed_len(&WireRequest::Message(Msg::Proposal(proposal)))?;
        for recipient in quorum {
            if recipient == sender {
                continue;
            }
            stage_latency.convergence.proposal_ms = stage_latency
                .convergence
                .proposal_ms
                .max(latency.edge_latency_ms(*sender, *recipient));
            totals.proposal_messages += 1;
            totals.proposal_bytes += proposal_len;
        }
        stage_latency.finality.proposal_ms = finality_stage_latency_ms;

        let commit = commit_for(&nodes[*sender], last_epoch, nonce, round)?;
        let commit_len = framed_len(&WireRequest::Message(Msg::Commit(commit)))?;
        for recipient in quorum {
            if recipient == sender {
                continue;
            }
            stage_latency.convergence.commit_ms = stage_latency
                .convergence
                .commit_ms
                .max(latency.edge_latency_ms(*sender, *recipient));
            totals.commit_messages += 1;
            totals.commit_bytes += commit_len;
        }
        stage_latency.finality.commit_ms = finality_stage_latency_ms;
    }

    Ok(stage_latency)
}

fn dispatch_profile_for(
    node: &BenchNode,
    blocks: &BlockIndex,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
    trusted: bool,
) -> MainResult<DispatchProfile> {
    let signature_tree = SignatureTree::default();
    let signature_tree_hash = signature_tree.hash();
    let blocks_hash = blocks.hash();
    let header = signed_header_bytes(
        node,
        MSGKey::Dispatch,
        last_epoch,
        nonce,
        round,
        &dispatch_body_bytes(blocks_hash, signature_tree_hash),
        trusted,
    )?;
    let framed_len = framed_dispatch_len(&header, blocks, &signature_tree)?;

    Ok(DispatchProfile {
        sender: header.sender,
        blocks_hash,
        signature_tree_hash,
        framed_len,
    })
}

#[cfg(test)]
fn dispatch_for(
    node: &BenchNode,
    blocks: BTreeMap<HashType, Block>,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
    trusted: bool,
) -> MainResult<blossom::Dispatch> {
    let signature_tree = SignatureTree::default();
    let signature_tree_hash = signature_tree.hash();
    let body = blossom::DispatchBody {
        blocks_hash: blocks.hash(),
        blocks,
        signature_tree,
        signature_tree_hash,
    };
    Ok(blossom::Dispatch {
        header: signed_header(
            node,
            MSGKey::Dispatch,
            last_epoch,
            nonce,
            round,
            &body,
            trusted,
        )?,
        body,
    })
}

fn echo_for(
    node: &BenchNode,
    dispatch: &DispatchProfile,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
) -> MainResult<EchoResponse> {
    let body = EchoResponseBody {
        sender: dispatch.sender,
        blocks_hash: dispatch.blocks_hash,
        signature_tree_hash: dispatch.signature_tree_hash,
    };
    Ok(EchoResponse {
        header: signed_header(
            node,
            MSGKey::EchoResponse,
            last_epoch,
            nonce,
            round,
            &body,
            false,
        )?,
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
) -> MainResult<Verification> {
    let body = VerificationBody {
        blocks_hash,
        blocks: blocks.clone(),
    };
    Ok(Verification {
        header: signed_header(
            node,
            MSGKey::Verification,
            last_epoch,
            nonce,
            round,
            &body,
            false,
        )?,
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
) -> MainResult<Proposal> {
    let body = ProposalBody {
        consensus: true,
        approved_blocks: Some(blocks.clone()),
        approved_hash: Some(blocks_hash),
        verif: None,
        signature_tree: Some(blocks.clone()),
        signature_tree_hash: Some(blocks.hash()),
    };
    Ok(Proposal {
        header: signed_header(
            node,
            MSGKey::Proposal,
            last_epoch,
            nonce,
            round,
            &body,
            false,
        )?,
        body,
    })
}

fn commit_for(
    node: &BenchNode,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
) -> MainResult<Commit> {
    let body = CommitBody {
        consensus: true,
        signature_tree_insert: None,
        epoch_hash: None,
        epoch_signature: None,
    };
    Ok(Commit {
        header: signed_header(node, MSGKey::Commit, last_epoch, nonce, round, &body, false)?,
        body,
    })
}

fn signed_header<T: BlossomBody>(
    node: &BenchNode,
    kind: MSGKey,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
    body: &T,
    trusted: bool,
) -> MainResult<Header> {
    let signature = if trusted {
        Signature::default()
    } else {
        let message_hash = Header::signature_hash_for_body(
            &node.keypair.public,
            &last_epoch,
            nonce,
            round,
            kind,
            body,
        );
        node.signer.sign(message_hash.as_ref())
    };
    Ok(Header {
        sender: node.keypair.public,
        last_epoch,
        nonce,
        round,
        signature,
    })
}

fn signed_header_bytes(
    node: &BenchNode,
    kind: MSGKey,
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
    body_bytes: &[u8],
    trusted: bool,
) -> MainResult<Header> {
    let signature = if trusted {
        Signature::default()
    } else {
        let message_hash = Header::signature_hash_for_bytes(
            &node.keypair.public,
            &last_epoch,
            nonce,
            round,
            kind,
            body_bytes,
        );
        node.signer.sign(message_hash.as_ref())
    };
    Ok(Header {
        sender: node.keypair.public,
        last_epoch,
        nonce,
        round,
        signature,
    })
}

fn encoded_block_len(block: &BlockHandle) -> MainResult<usize> {
    Ok(block.encoded_len())
}

fn dispatch_body_bytes(blocks_hash: HashType, signature_tree_hash: HashType) -> Vec<u8> {
    [blocks_hash.as_ref(), signature_tree_hash.as_ref()].concat()
}

fn framed_dispatch_len(
    header: &Header,
    blocks: &BlockIndex,
    signature_tree: &SignatureTree,
) -> MainResult<usize> {
    const BORSH_ENUM_TAG_BYTES: usize = 1;
    const BORSH_MAP_LEN_BYTES: usize = 4;
    const HASH_BYTES: usize = 32;

    let blocks_len = BORSH_MAP_LEN_BYTES
        + blocks
            .values_ref()
            .map(|block| HASH_BYTES + block.encoded_len())
            .sum::<usize>();

    Ok(FRAME_PREFIX_BYTES
        + BORSH_ENUM_TAG_BYTES
        + BORSH_ENUM_TAG_BYTES
        + encoded_len(header)?
        + blocks_len
        + HASH_BYTES
        + encoded_len(signature_tree)?
        + HASH_BYTES)
}

#[cfg(test)]
fn materialize_blocks(blocks: &BlockIndex) -> BTreeMap<HashType, Block> {
    blocks
        .iter_ref()
        .map(|(hash, block)| (*hash, block.to_owned_block()))
        .collect()
}

fn epoch_hash(last_epoch: HashType, nonce: Nonce, blocks_hash: HashType) -> HashType {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(last_epoch.as_ref());
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(blocks_hash.as_ref());
    HashType::hash(&bytes)
}

fn write_csv(path: &PathBuf, append: bool, rows: &[EpochBenchRow]) -> MainResult<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let write_header = !append || !path.exists() || path.metadata()?.len() == 0;
    let mut file = OpenOptions::new()
        .create(true)
        .append(append)
        .write(true)
        .truncate(!append)
        .open(path)?;

    if write_header {
        writeln!(
            file,
            "epoch,epoch_depth,nodes,quorum_size,rounds,quorums,shuffle,trusted,latency_distribution,latency_ms,latency_min_ms,latency_max_ms,transactions_per_node,transaction_bytes,application_state_bytes_per_block,epoch_application_state_bytes,epoch_transactions,cumulative_transactions,block_count,min_blocks_per_node,max_blocks_per_node,unique_epoch_hashes,converged,block_build_us,propagation_us,finalize_us,total_us,modeled_latency_ms,modeled_dispatch_latency_ms,modeled_echo_latency_ms,modeled_verification_latency_ms,modeled_proposal_latency_ms,modeled_commit_latency_ms,block_bytes,dispatch_messages,echo_messages,verification_messages,proposal_messages,commit_messages,total_messages,dispatch_bytes,echo_bytes,verification_bytes,proposal_bytes,commit_bytes,total_wire_bytes,epoch_hash,modeled_finality_latency_ms,modeled_finality_dispatch_latency_ms,modeled_finality_echo_latency_ms,modeled_finality_verification_latency_ms,modeled_finality_proposal_latency_ms,modeled_finality_commit_latency_ms"
        )?;
    }
    for row in rows {
        writeln!(file, "{}", row.to_csv())?;
    }
    Ok(())
}

impl EpochBenchRow {
    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.epoch,
            self.epoch_depth,
            self.nodes,
            self.quorum_size,
            self.rounds,
            self.quorums,
            self.shuffle,
            self.trusted,
            self.latency_distribution.as_str(),
            self.latency_ms,
            self.latency_min_ms,
            self.latency_max_ms,
            self.transactions_per_node,
            self.transaction_bytes,
            self.application_state_bytes_per_block,
            self.epoch_application_state_bytes,
            self.epoch_transactions,
            self.cumulative_transactions,
            self.block_count,
            self.min_blocks_per_node,
            self.max_blocks_per_node,
            self.unique_epoch_hashes,
            self.converged,
            self.block_build_us,
            self.propagation_us,
            self.finalize_us,
            self.total_us,
            self.modeled_latency_ms,
            self.modeled_dispatch_latency_ms,
            self.modeled_echo_latency_ms,
            self.modeled_verification_latency_ms,
            self.modeled_proposal_latency_ms,
            self.modeled_commit_latency_ms,
            self.block_bytes,
            self.dispatch_messages,
            self.echo_messages,
            self.verification_messages,
            self.proposal_messages,
            self.commit_messages,
            self.total_messages,
            self.dispatch_bytes,
            self.echo_bytes,
            self.verification_bytes,
            self.proposal_bytes,
            self.commit_bytes,
            self.total_wire_bytes,
            self.epoch_hash,
            self.modeled_finality_latency_ms,
            self.modeled_finality_dispatch_latency_ms,
            self.modeled_finality_echo_latency_ms,
            self.modeled_finality_verification_latency_ms,
            self.modeled_finality_proposal_latency_ms,
            self.modeled_finality_commit_latency_ms
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: u8) -> PubKey {
        PubKey([index; 32])
    }

    #[test]
    fn thirty_six_nodes_have_two_rounds_of_six_quorums() {
        let keys = (0..36).map(key).collect::<Vec<_>>();
        let rounds = round_quorums(&keys, HashType::default(), false, 6);

        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0].len(), 6);
        assert_eq!(rounds[1].len(), 6);
        assert!(rounds.iter().flatten().all(|quorum| quorum.len() == 6));
    }

    #[test]
    fn target_transactions_derives_epoch_depth() {
        let args = Args {
            nodes: 36,
            quorum_size: 6,
            epoch_depth: 1,
            target_transactions: Some(1_000_000),
            transactions_per_node: 1_000,
            transaction_bytes: 32,
            application_state_bytes: 0,
            shuffle: false,
            trusted: false,
            latency_distribution: LatencyDistribution::Even,
            latency_ms: 1,
            latency_min_ms: 1,
            latency_max_ms: 300,
            latency_seed: 0,
            csv: None,
            append: false,
        };

        assert_eq!(epoch_depth(&args), 28);
    }

    #[test]
    fn dispatch_profile_len_matches_full_wire_dispatch() {
        let nodes = build_nodes(1);
        let last_epoch = HashType::hash(b"epoch");
        let nonce = Nonce::new(9);
        let block = signed_block(
            &nodes[0],
            last_epoch,
            nonce,
            transactions(0, 0, 3, 32),
            0,
            false,
        );
        let block = BlockHandle::new(block).unwrap();
        let mut blocks = BlockIndex::new();
        blocks.insert(block.hash(), block);

        let profile =
            dispatch_profile_for(&nodes[0], &blocks, last_epoch, nonce, 0, false).unwrap();
        let dispatch = dispatch_for(
            &nodes[0],
            materialize_blocks(&blocks),
            last_epoch,
            nonce,
            0,
            false,
        )
        .unwrap();
        let framed = framed_len(&WireRequest::Message(Msg::Dispatch(dispatch))).unwrap();

        assert_eq!(profile.framed_len, framed);
    }

    #[test]
    fn trusted_epoch_counts_dispatch_only_and_converges() {
        let nodes = build_nodes(36);
        let row = run_epoch(
            0,
            1,
            &nodes,
            HashType::default(),
            Nonce::new(1),
            6,
            2,
            8,
            64,
            false,
            true,
            LatencyProfile {
                distribution: LatencyDistribution::Even,
                latency_ms: 10,
                min_ms: 1,
                max_ms: 300,
                seed: 0,
            },
        )
        .unwrap();

        assert!(row.trusted);
        assert_eq!(row.application_state_bytes_per_block, 64);
        assert_eq!(row.epoch_application_state_bytes, 36 * 64);
        assert!(row.converged);
        assert!(row.dispatch_messages > 0);
        assert_eq!(row.echo_messages, 0);
        assert_eq!(row.verification_messages, 0);
        assert_eq!(row.proposal_messages, 0);
        assert_eq!(row.commit_messages, 0);
        assert_eq!(row.total_messages, row.dispatch_messages);
        assert_eq!(row.modeled_latency_ms, row.rounds as u64 * 10);
        assert_eq!(row.modeled_finality_latency_ms, row.rounds as u64 * 10);
    }

    #[test]
    fn configurable_square_quorum_sizes_have_two_rounds() {
        for quorum_size in [3, 4, 5, 6] {
            let keys = (0..quorum_size * quorum_size)
                .map(|index| key(index as u8))
                .collect::<Vec<_>>();
            let rounds = round_quorums(&keys, HashType::default(), false, quorum_size);

            assert_eq!(rounds.len(), 2);
            assert_eq!(rounds[0].len(), quorum_size);
            assert_eq!(rounds[1].len(), quorum_size);
            assert!(
                rounds
                    .iter()
                    .flatten()
                    .all(|quorum| quorum.len() == quorum_size)
            );
        }
    }

    #[test]
    fn trustless_mode_models_five_network_stages_per_round() {
        let nodes = build_nodes(9);
        let row = run_epoch(
            0,
            1,
            &nodes,
            HashType::default(),
            Nonce::new(1),
            3,
            2,
            8,
            0,
            false,
            false,
            LatencyProfile {
                distribution: LatencyDistribution::Even,
                latency_ms: 7,
                min_ms: 1,
                max_ms: 300,
                seed: 0,
            },
        )
        .unwrap();

        assert!(!row.trusted);
        assert!(row.converged);
        assert_eq!(row.rounds, 2);
        assert_eq!(row.modeled_dispatch_latency_ms, 14);
        assert_eq!(row.modeled_echo_latency_ms, 14);
        assert_eq!(row.modeled_verification_latency_ms, 14);
        assert_eq!(row.modeled_proposal_latency_ms, 14);
        assert_eq!(row.modeled_commit_latency_ms, 14);
        assert_eq!(row.modeled_latency_ms, 70);
        assert_eq!(row.modeled_finality_latency_ms, 70);
    }

    #[test]
    fn finality_latency_uses_slowest_safe_supermajority_not_slowest_node() {
        let quorum = [0, 1, 2, 3, 4, 5];
        let recipient_latency = [10, 20, 30, 40, 500, 900];

        let finality_latency =
            quorum_stage_finality_latency_ms_with(&quorum, |_sender, recipient| {
                recipient_latency[recipient]
            });

        assert_eq!(finality_latency, 40);
    }
}
