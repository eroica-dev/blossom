use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use indextreemap::IndexTreeMap;
use rs_merkle::{MerkleTree, algorithms::Sha256};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::algorithm::{select_quorums_from_index_tree, supermajority_count};
use crate::block::Block;
use crate::blossom::{
    Commit, Dispatch, EchoReDispatch, EchoRequest, EchoResponse, Proposal, SignatureTree,
    SignaturesForHash, Verification,
};
use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::hash::{DoHash, HashType};
use crate::node::{NodeIdentity, NodeType};
use crate::nonce::Nonce;
use crate::register::MessageMatrix;

#[derive(Serialize, Debug, Clone, Default)]
pub struct LocalState {
    pub self_node: NodeIdentity,
    pub epochchain: EpochChain,
    pub consensus: HashMap<EpochNonce, TempConsensus>,
    pub nonce: Nonce,
}

impl LocalState {
    pub fn new(self_node: NodeIdentity, genesis: Epoch) -> Self {
        Self {
            self_node,
            epochchain: EpochChain {
                epochchain: vec![genesis],
            },
            consensus: HashMap::new(),
            nonce: Nonce::default(),
        }
    }

    pub fn get_consensus(&self, epoch: &HashType, nonce: Nonce) -> Option<&TempConsensus> {
        self.consensus.get(&EpochNonce(*epoch, nonce))
    }

    pub fn get_mut_consensus(&mut self, epoch: &HashType, nonce: Nonce) -> &mut TempConsensus {
        if *epoch == HashType::default() && nonce.value() > 1 {
            panic!("invalid epoch when nonce > 1");
        }

        if !self.consensus.contains_key(&EpochNonce(*epoch, nonce)) {
            let peers = self.peers_in_consensus(epoch);
            let self_key = self.self_node.public_key();
            self.consensus
                .insert(EpochNonce(*epoch, nonce), init_consensus(peers, &self_key));
        }

        self.consensus.get_mut(&EpochNonce(*epoch, nonce)).unwrap()
    }

    pub fn get_quorum(&self, epoch: &HashType, nonce: Nonce, round: u8) -> Option<&TempQuorum> {
        self.get_consensus(epoch, nonce)?.quorum.get(&round)
    }

    pub fn get_mut_quorum(&mut self, epoch: &HashType, nonce: Nonce, round: u8) -> &mut TempQuorum {
        if *epoch == HashType::default() && nonce.value() > 1 {
            panic!("invalid epoch when nonce > 1");
        }

        let consensus = self.get_mut_consensus(epoch, nonce);
        let peers = consensus.peers_with_us(round);
        let nodes_in_quorum = peers.len() as u32;
        consensus
            .quorum
            .entry(round)
            .or_insert_with(|| init_quorum(nodes_in_quorum, &peers, &consensus.self_key))
    }

    pub fn num_pending_dispatches(&self, epoch: &HashType, nonce: Nonce, round: u8) -> usize {
        self.consensus
            .get(&EpochNonce(*epoch, nonce))
            .and_then(|consensus| consensus.quorum.get(&round))
            .map(|quorum| quorum.pending_dispatches.len())
            .unwrap_or_default()
    }

    pub fn advance_epoch(
        &mut self,
        proposed_last_epoch_hash: &HashType,
        proposed_new_epoch_nonce: Nonce,
        current_round: u8,
        consensus: bool,
    ) -> bool {
        let Some(last_epoch) = self.epochchain.epochchain.last() else {
            return false;
        };
        let expected_nonce = last_epoch.body.nonce.new_next();
        if last_epoch.hash != *proposed_last_epoch_hash
            || expected_nonce != proposed_new_epoch_nonce
        {
            log::info!(
                "epoch mismatch: chain {}/{} != proposed {}/{}",
                last_epoch.hash,
                expected_nonce,
                proposed_last_epoch_hash,
                proposed_new_epoch_nonce
            );
            return false;
        }

        let Some(current_consensus) = self.consensus.get_mut(&EpochNonce(
            *proposed_last_epoch_hash,
            proposed_new_epoch_nonce,
        )) else {
            return false;
        };

        if !consensus {
            if let Some(quorum) = current_consensus.quorum.get_mut(&current_round) {
                quorum.verified_blocks.clear();
            }
        }

        if current_consensus.peers.len() > current_round as usize + 1 {
            current_consensus.round = current_round + 1;
            return true;
        }

        let last_epoch = self.epochchain.epochchain.last().unwrap().clone();
        let mut new_epoch = if consensus {
            let quorum = current_consensus.quorum.get(&current_round).unwrap();
            let blocks = quorum.verified_blocks.clone();
            Epoch {
                hash: HashType::default(),
                signatures: BTreeMap::default(),
                body: EpochBody {
                    verifiers: last_epoch.body.verifiers.clone(),
                    last_epoch: *proposed_last_epoch_hash,
                    nonce: expected_nonce,
                    merkle_root: block_merkle_root(&blocks),
                    blocks,
                },
            }
        } else {
            Epoch {
                hash: HashType::default(),
                signatures: BTreeMap::default(),
                body: EpochBody {
                    verifiers: last_epoch.body.verifiers.clone(),
                    last_epoch: last_epoch.hash,
                    nonce: expected_nonce,
                    merkle_root: HashType::default(),
                    blocks: BTreeMap::default(),
                },
            }
        };

        new_epoch.set_hash();
        self.consensus
            .retain(|EpochNonce(_, nonce), _| nonce.value() + 1 >= new_epoch.body.nonce.value());
        self.epochchain.epochchain.push(new_epoch);
        true
    }

    fn peers_in_consensus(&self, epoch_hash: &HashType) -> Vec<BTreeMap<PubKey, NodeType>> {
        let Some(last_epoch) = self.epochchain.epochchain.last() else {
            return Vec::new();
        };

        let peer_rounds = select_quorums_from_index_tree(
            &last_epoch.body.verifiers,
            &self.self_node.public_key(),
            *epoch_hash,
            self.self_node.shuffle,
        );

        peer_rounds
            .into_iter()
            .map(|round| {
                round
                    .into_iter()
                    .filter(|peer| *peer != self.self_node.public_key())
                    .map(|peer| (peer, NodeType::Validator))
                    .collect()
            })
            .collect()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EpochChain {
    pub epochchain: Vec<Epoch>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Epoch {
    pub hash: HashType,
    pub signatures: BTreeMap<usize, crate::crypto::Signature>,
    pub body: EpochBody,
}

impl Epoch {
    pub fn set_hash(&mut self) {
        self.hash = HashType::hash(&self.body.to_bytes());
    }

    pub fn epoch_approved(&self) -> Result<()> {
        let verifier_count = self.body.verifiers.len();
        if verifier_count == 0 || self.signatures.len() < supermajority_count(verifier_count) {
            return Err(BlossomError::FailedConsensus);
        }

        let message = self.hash.to_bytes();
        for (index, signature) in &self.signatures {
            let public_key = self
                .body
                .verifiers
                .get_key_from_index(*index)
                .ok_or(BlossomError::UnknownSender)?;
            signature.verify(&message, public_key)?;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EpochBody {
    pub verifiers: IndexTreeMap<PubKey, NodeIdentity>,
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub merkle_root: HashType,
    pub blocks: BTreeMap<HashType, Block>,
}

impl EpochBody {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.last_epoch.as_ref());
        bytes.extend_from_slice(&self.nonce.to_bytes());
        bytes.extend_from_slice(self.merkle_root.as_ref());
        for key in self.verifiers.keys() {
            bytes.extend_from_slice(key.as_ref());
        }
        for key in self.blocks.keys() {
            bytes.extend_from_slice(key.as_ref());
        }
        bytes
    }
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct TempConsensus {
    pub self_key: PubKey,
    pub round: u8,
    pub peers: Vec<BTreeMap<PubKey, NodeType>>,
    pub log: ConsensusMessageLog,
    pub quorum: HashMap<u8, TempQuorum>,
}

impl TempConsensus {
    pub fn is_peer_member_of_round(&self, sender: &PubKey, round: u8) -> bool {
        if round as usize >= self.peers.len() {
            return false;
        }
        self.peers[round as usize].contains_key(sender)
    }

    pub fn peers(&self, round: u8) -> Vec<PubKey> {
        if round as usize >= self.peers.len() {
            return Vec::new();
        }
        self.peers[round as usize].keys().copied().collect()
    }

    pub fn peers_with_us(&self, round: u8) -> Vec<PubKey> {
        let mut peers = vec![self.self_key];
        peers.extend(self.peers(round));
        peers.sort_unstable();
        peers.dedup();
        peers
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct EpochNonce(pub HashType, pub Nonce);

impl Serialize for EpochNonce {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("({},{})", self.0, self.1))
    }
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct TempQuorum {
    pub dispatch_status: Option<bool>,
    pub received_dispatches: Vec<PubKey>,
    pub pending_dispatches: Vec<Dispatch>,
    pub verified_signature_trees: BTreeMap<HashType, SignaturesForHash>,
    pub pending_blocks: BTreeMap<HashType, Block>,
    pub verified_blocks: BTreeMap<HashType, Block>,
    pub verified_blocks_hash: Option<HashType>,
    pub processed_txs: HashMap<String, bool>,
    pub last_signature_tree: SignatureTree,
    pub verifications: VerifCount,
    pub verification_sent: bool,
    pub proposals: PropCount,
    pub proposal_sent: bool,
    pub commit_sent: bool,
    pub round_status: Option<u128>,
    pub timers: Timers,
    pub msg_matrix: MessageMatrix,
}

impl TempQuorum {
    pub fn verify(&mut self) {
        let mut processed_dispatches = HashMap::new();
        for dispatch in &self.pending_dispatches {
            if dispatch.body.signature_tree.verify() {
                for (sent_block_hash, block) in &dispatch.body.blocks {
                    let block_hash = block.hash();
                    if *sent_block_hash == block_hash && block.verify_signature().is_ok() {
                        self.verified_blocks.insert(*sent_block_hash, block.clone());
                        self.timers.verified_tx += block.body.txs.len();
                    }
                }
            }
            processed_dispatches.insert((dispatch.header.sender, dispatch.header.signature), ());
        }

        self.pending_dispatches.retain(|dispatch| {
            !processed_dispatches.contains_key(&(dispatch.header.sender, dispatch.header.signature))
        });
        self.verified_blocks_hash = Some(self.verified_blocks_hash());
    }

    pub fn verified_blocks(&self) -> BTreeMap<HashType, ()> {
        self.verified_blocks
            .keys()
            .map(|hash| (*hash, ()))
            .collect()
    }

    pub fn verified_blocks_hash(&self) -> HashType {
        self.verified_blocks.hash()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VerifCount {
    pub verifications: BTreeMap<PubKey, Verification>,
    pub count: BTreeMap<HashType, u8>,
    pub quorum: u32,
    pub supermajority: u32,
}

impl VerifCount {
    pub fn record(&mut self, verification: Verification) {
        *self.count.entry(verification.body.blocks_hash).or_default() += 1;
        self.verifications
            .insert(verification.header.sender, verification);
    }

    pub fn consensus_hash(&self) -> Option<HashType> {
        self.count
            .iter()
            .find_map(|(hash, count)| (*count as u32 >= self.supermajority).then_some(*hash))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PropCount {
    pub proposals: BTreeMap<PubKey, Proposal>,
    pub count: BTreeMap<HashType, u32>,
    pub quorum: u32,
    pub supermajority: u32,
}

impl PropCount {
    pub fn consensus(&self) -> Option<bool> {
        let len = self.proposals.len() as u32;
        if len < self.supermajority {
            return None;
        }

        let mut still_possible = false;
        for count in self.count.values() {
            if *count >= self.supermajority {
                return Some(true);
            }
            if *count + (self.quorum - len) >= self.supermajority {
                still_possible = true;
            }
        }

        if still_possible { None } else { Some(false) }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EpochSignatures {
    pub true_block: HashMap<String, (Vec<String>, Vec<String>)>,
    pub false_block: HashMap<String, (Vec<String>, Vec<String>)>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ConsensusMessageLog {
    pub mailbox: HashMap<u8, HashMap<String, Log>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Log {
    pub dispatch: Option<Dispatch>,
    pub echo_response: Option<EchoResponse>,
    pub echo_request: Option<EchoRequest>,
    pub echo_redispatch: Option<EchoReDispatch>,
    pub verification: Vec<Option<Verification>>,
    pub proposal: Option<Proposal>,
    pub commit: Option<Commit>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SharedState {
    pub last_epoch: String,
    pub epoch: String,
    pub epoch_blocks: EpochSignatures,
}

#[derive(Debug, Clone)]
pub struct Timers {
    pub quorum_created: Instant,
    pub dispatch_sent: Duration,
    pub dispatch_received_first: Duration,
    pub dispatch_received_last: Duration,
    pub dispatch_count: usize,
    pub verification_sent: Duration,
    pub verification_received_first: Duration,
    pub verification_received_last: Duration,
    pub verification_count: usize,
    pub proposal_sent: Duration,
    pub proposal_received_first: Duration,
    pub proposal_received_last: Duration,
    pub proposal_count: usize,
    pub commit_sent: Duration,
    pub commit_received_first: Duration,
    pub commit_received_last: Duration,
    pub commit_count: usize,
    pub dispatched_blocks: usize,
    pub dispatched_tx: usize,
    pub verified_blocks: usize,
    pub verified_tx: usize,
}

impl Serialize for Timers {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut t = serializer.serialize_struct("Timers", 16)?;
        t.serialize_field("dispatch_sent", &self.dispatch_sent.as_millis())?;
        t.serialize_field(
            "dispatch_received_first",
            &self.dispatch_received_first.as_millis(),
        )?;
        t.serialize_field(
            "dispatch_received_last",
            &self.dispatch_received_last.as_millis(),
        )?;
        t.serialize_field("dispatch_count", &self.dispatch_count)?;
        t.serialize_field("verification_sent", &self.verification_sent.as_millis())?;
        t.serialize_field(
            "verification_received_first",
            &self.verification_received_first.as_millis(),
        )?;
        t.serialize_field(
            "verification_received_last",
            &self.verification_received_last.as_millis(),
        )?;
        t.serialize_field("verification_count", &self.verification_count)?;
        t.serialize_field("proposal_sent", &self.proposal_sent.as_millis())?;
        t.serialize_field(
            "proposal_received_first",
            &self.proposal_received_first.as_millis(),
        )?;
        t.serialize_field(
            "proposal_received_last",
            &self.proposal_received_last.as_millis(),
        )?;
        t.serialize_field("proposal_count", &self.proposal_count)?;
        t.serialize_field("commit_sent", &self.commit_sent.as_millis())?;
        t.serialize_field(
            "commit_received_first",
            &self.commit_received_first.as_millis(),
        )?;
        t.serialize_field(
            "commit_received_last",
            &self.commit_received_last.as_millis(),
        )?;
        t.serialize_field("commit_count", &self.commit_count)?;
        t.end()
    }
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            quorum_created: Instant::now(),
            dispatch_sent: Duration::default(),
            dispatch_received_first: Duration::default(),
            dispatch_received_last: Duration::default(),
            dispatch_count: usize::default(),
            verification_sent: Duration::default(),
            verification_received_first: Duration::default(),
            verification_received_last: Duration::default(),
            verification_count: usize::default(),
            proposal_sent: Duration::default(),
            proposal_received_first: Duration::default(),
            proposal_received_last: Duration::default(),
            proposal_count: usize::default(),
            commit_sent: Duration::default(),
            commit_received_first: Duration::default(),
            commit_received_last: Duration::default(),
            commit_count: usize::default(),
            dispatched_blocks: usize::default(),
            dispatched_tx: usize::default(),
            verified_blocks: usize::default(),
            verified_tx: usize::default(),
        }
    }
}

pub fn init_quorum(quorum: u32, peers: &[PubKey], self_key: &PubKey) -> TempQuorum {
    TempQuorum {
        dispatch_status: None,
        received_dispatches: vec![],
        pending_dispatches: vec![],
        pending_blocks: BTreeMap::new(),
        verified_signature_trees: BTreeMap::new(),
        verified_blocks: BTreeMap::new(),
        processed_txs: HashMap::new(),
        last_signature_tree: Default::default(),
        verified_blocks_hash: Default::default(),
        verifications: init_verifications(quorum),
        verification_sent: false,
        proposals: init_proposals(quorum),
        proposal_sent: false,
        commit_sent: false,
        round_status: None,
        timers: Default::default(),
        msg_matrix: MessageMatrix::new(peers, self_key),
    }
}

pub fn init_consensus(peers: Vec<BTreeMap<PubKey, NodeType>>, self_key: &PubKey) -> TempConsensus {
    TempConsensus {
        self_key: *self_key,
        round: 0,
        peers,
        log: ConsensusMessageLog {
            mailbox: HashMap::new(),
        },
        quorum: HashMap::new(),
    }
}

pub fn init_verifications(quorum: u32) -> VerifCount {
    VerifCount {
        verifications: BTreeMap::new(),
        count: BTreeMap::new(),
        quorum,
        supermajority: supermajority_count(quorum as usize) as u32,
    }
}

pub fn init_proposals(quorum: u32) -> PropCount {
    PropCount {
        proposals: BTreeMap::new(),
        count: BTreeMap::new(),
        quorum,
        supermajority: supermajority_count(quorum as usize) as u32,
    }
}

fn block_merkle_root(blocks: &BTreeMap<HashType, Block>) -> HashType {
    let leaves = blocks.keys().map(|hash| hash.0).collect::<Vec<_>>();
    HashType::from_byte_hash(
        MerkleTree::<Sha256>::from_leaves(&leaves)
            .root()
            .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blossom::{Header, Proposal, ProposalBody, Verification, VerificationBody};
    use crate::crypto::{Keypair, Signature};

    fn node(index: u8) -> NodeIdentity {
        NodeIdentity::new(
            PubKey([index; 32]),
            None,
            "tcp",
            format!("node-{index}"),
            8000 + index as u16,
            false,
        )
    }

    fn genesis(self_index: u8) -> (NodeIdentity, Epoch) {
        let mut verifiers = IndexTreeMap::new();
        for index in 0..6 {
            let node = node(index);
            verifiers.insert(node.public_key(), node);
        }
        let mut epoch = Epoch {
            body: EpochBody {
                verifiers,
                nonce: Nonce::new(0),
                ..Default::default()
            },
            ..Default::default()
        };
        epoch.set_hash();
        (node(self_index), epoch)
    }

    fn signed_epoch(verifier_count: u8, signature_count: u8) -> Epoch {
        let mut verifiers = IndexTreeMap::new();
        let mut secrets = BTreeMap::new();
        for index in 0..verifier_count {
            let keypair = Keypair::generate();
            verifiers.insert(
                keypair.public,
                NodeIdentity::new(
                    keypair.public,
                    None,
                    "tcp",
                    format!("node-{index}"),
                    9000 + index as u16,
                    false,
                ),
            );
            secrets.insert(keypair.public, keypair.secret);
        }

        let mut epoch = Epoch {
            body: EpochBody {
                verifiers,
                nonce: Nonce::new(1),
                ..Default::default()
            },
            ..Default::default()
        };
        epoch.set_hash();

        for index in 0..signature_count as usize {
            let public_key = epoch.body.verifiers.get_key_from_index(index).unwrap();
            let secret_key = secrets.get(public_key).unwrap();
            epoch
                .signatures
                .insert(index, Signature::sign(&epoch.hash.to_bytes(), secret_key));
        }

        epoch
    }

    #[test]
    fn get_mut_quorum_is_stable() {
        let (self_node, genesis) = genesis(0);
        let mut state = LocalState::new(self_node, genesis);
        let last = state.epochchain.epochchain.last().unwrap().clone();
        let round = 0;

        let quorum = state.get_mut_quorum(&last.hash, last.body.nonce.new_next(), round);
        quorum.dispatch_status = Some(false);

        assert_eq!(
            state
                .get_mut_quorum(&last.hash, last.body.nonce.new_next(), round)
                .dispatch_status,
            Some(false)
        );
    }

    #[test]
    fn epoch_approval_requires_supermajority_signatures() {
        assert!(signed_epoch(6, 4).epoch_approved().is_ok());
        assert_eq!(
            signed_epoch(6, 3).epoch_approved(),
            Err(BlossomError::FailedConsensus)
        );
    }

    #[test]
    fn block_merkle_root_matches_single_block_leaf() {
        let block = Block::empty_with_nonce(Nonce::new(1));
        let hash = block.hash();
        let mut blocks = BTreeMap::new();
        blocks.insert(hash, block);

        assert_eq!(block_merkle_root(&blocks), hash);
    }

    #[test]
    fn advance_epoch_with_consensus_commits_verified_blocks() {
        let (self_node, genesis) = genesis(0);
        let mut state = LocalState::new(self_node, genesis.clone());
        let next_nonce = genesis.body.nonce.new_next();
        let mut block = Block::empty_with_nonce(next_nonce);
        block.body.last_epoch = genesis.hash;
        block.set_hash();
        let block_hash = block.hash;
        state
            .get_mut_quorum(&genesis.hash, next_nonce, 0)
            .verified_blocks
            .insert(block_hash, block);

        assert!(state.advance_epoch(&genesis.hash, next_nonce, 0, true));
        let latest = state.epochchain.epochchain.last().unwrap();
        assert_eq!(latest.body.last_epoch, genesis.hash);
        assert_eq!(latest.body.nonce, next_nonce);
        assert!(latest.body.blocks.contains_key(&block_hash));
    }

    #[test]
    fn advance_epoch_without_consensus_creates_empty_epoch() {
        let (self_node, genesis) = genesis(0);
        let mut state = LocalState::new(self_node, genesis.clone());
        let next_nonce = genesis.body.nonce.new_next();
        state.get_mut_quorum(&genesis.hash, next_nonce, 0);

        assert!(state.advance_epoch(&genesis.hash, next_nonce, 0, false));
        let latest = state.epochchain.epochchain.last().unwrap();
        assert_eq!(latest.body.last_epoch, genesis.hash);
        assert!(latest.body.blocks.is_empty());
        assert_eq!(latest.body.merkle_root, HashType::default());
    }

    #[test]
    fn advance_epoch_rejects_mismatched_epoch_or_nonce() {
        let (self_node, genesis) = genesis(0);
        let mut state = LocalState::new(self_node, genesis.clone());

        assert!(!state.advance_epoch(&HashType([9; 32]), genesis.body.nonce.new_next(), 0, true));
        assert!(!state.advance_epoch(&genesis.hash, Nonce::new(99), 0, true));
        assert_eq!(state.epochchain.epochchain.len(), 1);
    }

    #[test]
    fn verification_count_tracks_consensus_hash() {
        let mut count = init_verifications(6);
        let blocks_hash = HashType([3; 32]);

        for index in 0..4 {
            count.record(Verification {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: VerificationBody {
                    blocks_hash,
                    blocks: BTreeMap::new(),
                },
            });
        }

        assert_eq!(count.consensus_hash(), Some(blocks_hash));
    }

    #[test]
    fn proposal_count_reports_true_false_or_pending() {
        let mut count = init_proposals(6);
        let approved = HashType([4; 32]);
        assert_eq!(count.consensus(), None);

        for index in 0..4 {
            count.proposals.insert(
                PubKey([index; 32]),
                Proposal {
                    header: Header {
                        sender: PubKey([index; 32]),
                        ..Default::default()
                    },
                    body: ProposalBody {
                        consensus: true,
                        approved_hash: Some(approved),
                        ..Default::default()
                    },
                },
            );
            *count.count.entry(approved).or_default() += 1;
        }
        assert_eq!(count.consensus(), Some(true));

        let mut failed = init_proposals(6);
        for index in 0..4 {
            failed.proposals.insert(
                PubKey([index; 32]),
                Proposal {
                    header: Header {
                        sender: PubKey([index; 32]),
                        ..Default::default()
                    },
                    body: ProposalBody::default(),
                },
            );
        }
        assert_eq!(failed.consensus(), Some(false));
    }
}
