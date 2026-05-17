use std::collections::{BTreeMap, BTreeSet};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;

use blossom::algorithm::select_quorums;
use blossom::wire::FRAME_PREFIX_BYTES;
use blossom::{
    Block, BlockHandle, BlockIndex, BlossomBody, Commit, CommitBody, DoHash, EchoResponse,
    EchoResponseBody, HashType, Header, Keypair, MSGKey, Msg, Nonce, Proposal, ProposalBody,
    PubKey, SecretSigner, Signature, SignatureTree, Transaction, Verification, VerificationBody,
    WireRequest, encoded_len, framed_len,
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
    #[arg(long, default_value_t = 1, alias = "epochs")]
    epoch_depth: usize,
    #[arg(long)]
    target_transactions: Option<usize>,
    #[arg(long, default_value_t = 1000)]
    transactions_per_node: usize,
    #[arg(long, default_value_t = 32)]
    transaction_bytes: usize,
    #[arg(long, default_value_t = false)]
    shuffle: bool,
    #[arg(long, default_value_t = false)]
    trusted: bool,
    #[arg(long)]
    csv: Option<PathBuf>,
    #[arg(long)]
    append: bool,
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

#[derive(Debug, Clone)]
struct EpochBenchRow {
    epoch: usize,
    epoch_depth: usize,
    nodes: usize,
    rounds: usize,
    quorums: usize,
    shuffle: bool,
    trusted: bool,
    transactions_per_node: usize,
    transaction_bytes: usize,
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
            args.transactions_per_node,
            args.transaction_bytes,
            args.shuffle,
            args.trusted,
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

fn run_epoch(
    epoch: usize,
    epoch_depth: usize,
    nodes: &[BenchNode],
    last_epoch: HashType,
    nonce: Nonce,
    transactions_per_node: usize,
    transaction_bytes: usize,
    shuffle: bool,
    trusted: bool,
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
    );
    let quorums = topology.iter().map(Vec::len).sum();

    let propagation_start = Instant::now();
    let mut totals = MessageTotals::default();
    for (round, quorums) in topology.iter().enumerate() {
        let before_round = states.clone();
        for quorum in quorums {
            count_quorum_messages(
                round as u8,
                quorum,
                nodes,
                &before_round,
                last_epoch,
                nonce,
                trusted,
                &mut totals,
            )?;

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
        rounds: topology.len(),
        quorums,
        shuffle,
        trusted,
        transactions_per_node,
        transaction_bytes,
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
    trusted: bool,
) -> Block {
    let mut block = Block::default();
    block.body.validator = node.keypair.public;
    block.body.last_epoch = last_epoch;
    block.body.nonce = nonce;
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

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
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

fn count_quorum_messages(
    round: u8,
    quorum: &[usize],
    nodes: &[BenchNode],
    states: &[NodeEpochState],
    last_epoch: HashType,
    nonce: Nonce,
    trusted: bool,
    totals: &mut MessageTotals,
) -> MainResult<()> {
    for sender in quorum {
        let dispatch = dispatch_profile_for(
            &nodes[*sender],
            &states[*sender].blocks,
            last_epoch,
            nonce,
            round,
            trusted,
        )?;
        totals.dispatch_messages += quorum.len().saturating_sub(1);
        totals.dispatch_bytes += dispatch.framed_len * quorum.len().saturating_sub(1);

        if trusted {
            continue;
        }

        for echo_sender in quorum {
            if echo_sender == sender {
                continue;
            }
            let echo = echo_for(&nodes[*echo_sender], &dispatch, last_epoch, nonce, round)?;
            let echo_len = framed_len(&WireRequest::Message(Msg::EchoResponse(echo)))?;
            totals.echo_messages += quorum.len().saturating_sub(1);
            totals.echo_bytes += echo_len * quorum.len().saturating_sub(1);
        }
    }

    if trusted {
        return Ok(());
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
        totals.verification_messages += quorum.len().saturating_sub(1);
        totals.verification_bytes += verification_len * quorum.len().saturating_sub(1);

        let proposal = proposal_for(
            &nodes[*sender],
            &union,
            union_hash,
            last_epoch,
            nonce,
            round,
        )?;
        let proposal_len = framed_len(&WireRequest::Message(Msg::Proposal(proposal)))?;
        totals.proposal_messages += quorum.len().saturating_sub(1);
        totals.proposal_bytes += proposal_len * quorum.len().saturating_sub(1);

        let commit = commit_for(&nodes[*sender], last_epoch, nonce, round)?;
        let commit_len = framed_len(&WireRequest::Message(Msg::Commit(commit)))?;
        totals.commit_messages += quorum.len().saturating_sub(1);
        totals.commit_bytes += commit_len * quorum.len().saturating_sub(1);
    }

    Ok(())
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
            "epoch,epoch_depth,nodes,rounds,quorums,shuffle,trusted,transactions_per_node,transaction_bytes,epoch_transactions,cumulative_transactions,block_count,min_blocks_per_node,max_blocks_per_node,unique_epoch_hashes,converged,block_build_us,propagation_us,finalize_us,total_us,block_bytes,dispatch_messages,echo_messages,verification_messages,proposal_messages,commit_messages,total_messages,dispatch_bytes,echo_bytes,verification_bytes,proposal_bytes,commit_bytes,total_wire_bytes,epoch_hash"
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
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            self.epoch,
            self.epoch_depth,
            self.nodes,
            self.rounds,
            self.quorums,
            self.shuffle,
            self.trusted,
            self.transactions_per_node,
            self.transaction_bytes,
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
            self.epoch_hash
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
        let rounds = round_quorums(&keys, HashType::default(), false);

        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0].len(), 6);
        assert_eq!(rounds[1].len(), 6);
        assert!(rounds.iter().flatten().all(|quorum| quorum.len() == 6));
    }

    #[test]
    fn target_transactions_derives_epoch_depth() {
        let args = Args {
            nodes: 36,
            epoch_depth: 1,
            target_transactions: Some(1_000_000),
            transactions_per_node: 1_000,
            transaction_bytes: 32,
            shuffle: false,
            trusted: false,
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
            2,
            8,
            false,
            true,
        )
        .unwrap();

        assert!(row.trusted);
        assert!(row.converged);
        assert!(row.dispatch_messages > 0);
        assert_eq!(row.echo_messages, 0);
        assert_eq!(row.verification_messages, 0);
        assert_eq!(row.proposal_messages, 0);
        assert_eq!(row.commit_messages, 0);
        assert_eq!(row.total_messages, row.dispatch_messages);
    }
}
