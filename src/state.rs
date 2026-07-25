use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
#[cfg(not(feature = "insecure-fast-hash"))]
use rs_merkle::{MerkleTree, algorithms::Sha256};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};

use crate::algorithm::{
    ConsensusParameters, select_quorums_from_index_tree_with_size, supermajority_count,
};
use crate::block::{Block, Transaction};
#[cfg(feature = "fair-block-ordering")]
use crate::block::{fair_ordered_block_commitments, fair_ordered_blocks};
use crate::blossom::{
    Commit, Dispatch, EchoReDispatch, EchoRequest, EchoResponse, Proposal, SignatureTree,
    SignaturesForHash, Verification,
};
use crate::crypto::{PubKey, Signature};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{DoHash, HashType};
use crate::membership::{ConsensusNodeRemovalPolicy, apply_epoch_membership_transition};
use crate::node::{NodeIdentity, NodeType};
use crate::nonce::Nonce;
use crate::register::MessageMatrix;
use crate::round_skip::{DataDisseminationManifest, RoundSkipCertificate, RoundSkipVote};
use crate::wire::HotDispatch;

pub const DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES: usize = 512 * 1024 * 1024;
pub const DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER: usize = 128 * 1024 * 1024;
pub const MAX_PENDING_RAW_DISPATCH_BYTES_ENV: &str = "BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES";
pub const MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER_ENV: &str =
    "BLOSSOM_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER";
static CONFIGURED_MAX_PENDING_RAW_DISPATCH_BYTES: OnceLock<usize> = OnceLock::new();
static CONFIGURED_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER: OnceLock<usize> = OnceLock::new();

#[derive(Serialize, Debug, Clone, Default)]
pub struct LocalState {
    pub self_node: NodeIdentity,
    pub epochchain: EpochChain,
    pub consensus: HashMap<EpochNonce, TempConsensus>,
    pub prefill_dispatches: HashMap<EpochNonce, BTreeMap<PubKey, PrefillDispatchRecord>>,
    pub nonce: Nonce,
    pub consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
}

impl LocalState {
    pub fn new(self_node: NodeIdentity, genesis: Epoch) -> Self {
        Self::new_with_consensus_node_removal_policy(
            self_node,
            genesis,
            ConsensusNodeRemovalPolicy::disabled(),
        )
    }

    pub fn new_with_consensus_node_removal_policy(
        self_node: NodeIdentity,
        genesis: Epoch,
        consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    ) -> Self {
        Self {
            self_node,
            epochchain: EpochChain {
                epochchain: vec![genesis],
            },
            consensus: HashMap::new(),
            prefill_dispatches: HashMap::new(),
            nonce: Nonce::default(),
            consensus_node_removal_policy,
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

    pub fn record_prefill_dispatch(&mut self, dispatch: &Dispatch) -> Result<usize> {
        let key = EpochNonce(dispatch.header.last_epoch, dispatch.header.nonce);
        let records = self.prefill_dispatches.entry(key).or_default();
        match records.get(&dispatch.header.sender) {
            Some(existing) if existing.blocks_hash == dispatch.body.blocks_hash => {
                Ok(existing.blocks.len())
            }
            Some(_) => Err(BlossomError::WireProtocol(format!(
                "equivocated prefill dispatch from {}",
                dispatch.header.sender
            ))),
            None => {
                let record = PrefillDispatchRecord {
                    sender: dispatch.header.sender,
                    round: dispatch.header.round,
                    blocks_hash: dispatch.body.blocks_hash,
                    blocks: dispatch.body.blocks.clone(),
                };
                let count = record.blocks.len();
                records.insert(dispatch.header.sender, record);
                Ok(count)
            }
        }
    }

    pub fn prefill_dispatches(
        &self,
        epoch: &HashType,
        nonce: Nonce,
    ) -> Option<&BTreeMap<PubKey, PrefillDispatchRecord>> {
        self.prefill_dispatches.get(&EpochNonce(*epoch, nonce))
    }

    pub fn seed_prefill_dispatches_into_quorum(
        &mut self,
        epoch: &HashType,
        nonce: Nonce,
        round: u8,
    ) -> usize {
        if round == 0 {
            return 0;
        }
        let Some(records) = self
            .prefill_dispatches
            .get(&EpochNonce(*epoch, nonce))
            .cloned()
        else {
            return 0;
        };

        let quorum = self.get_mut_quorum(epoch, nonce, round);
        let mut inserted = 0usize;
        for record in records.values() {
            for (hash, block) in &record.blocks {
                if block.body.last_epoch != *epoch || block.body.nonce != nonce {
                    continue;
                }
                inserted += usize::from(quorum.record_verified_block(*hash, block.clone()));
            }
        }
        if inserted > 0 {
            quorum.verified_blocks_hash = Some(quorum.verified_blocks_hash());
        }
        inserted
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

        if !consensus && let Some(quorum) = current_consensus.quorum.get_mut(&current_round) {
            quorum.clear_verified_blocks();
        }

        if current_consensus.peers.len() > current_round as usize + 1 {
            let next_round = current_round + 1;
            let carried_blocks = current_consensus
                .quorum
                .get(&current_round)
                .map(TempQuorum::canonical_verified_blocks)
                .unwrap_or_default();
            let next_peers = current_consensus.peers_with_us(next_round);
            let next_quorum = current_consensus
                .quorum
                .entry(next_round)
                .or_insert_with(|| {
                    init_quorum(
                        next_peers.len() as u32,
                        &next_peers,
                        &current_consensus.self_key,
                    )
                });
            for (hash, block) in carried_blocks {
                next_quorum.record_verified_block(hash, block);
            }
            next_quorum.verified_blocks_hash = Some(next_quorum.verified_blocks_hash());
            current_consensus.round = next_round;
            return true;
        }

        let last_epoch = self.epochchain.epochchain.last().unwrap().clone();
        let mut new_epoch = if consensus {
            let quorum = current_consensus.quorum.get(&current_round).unwrap();
            let blocks = quorum.canonical_verified_blocks();
            // Membership changes are derived only from the block set this
            // consensus round is committing into the next epoch.
            let (verifiers, _) = apply_epoch_membership_transition(
                &last_epoch.body.verifiers,
                &blocks,
                *proposed_last_epoch_hash,
                expected_nonce,
                self.consensus_node_removal_policy,
            );
            Epoch {
                hash: HashType::default(),
                signatures: BTreeMap::default(),
                body: EpochBody {
                    group_id: last_epoch.body.group_id,
                    verifiers,
                    last_epoch: *proposed_last_epoch_hash,
                    previous_nonce: Some(last_epoch.body.nonce),
                    nonce: expected_nonce,
                    merkle_root: block_merkle_root(&blocks),
                    blocks,
                    consensus_parameters: Some(last_epoch.body.effective_consensus_parameters()),
                },
            }
        } else {
            Epoch {
                hash: HashType::default(),
                signatures: BTreeMap::default(),
                body: EpochBody {
                    group_id: last_epoch.body.group_id,
                    verifiers: last_epoch.body.verifiers.clone(),
                    last_epoch: last_epoch.hash,
                    previous_nonce: Some(last_epoch.body.nonce),
                    nonce: expected_nonce,
                    merkle_root: HashType::default(),
                    blocks: BTreeMap::default(),
                    consensus_parameters: Some(last_epoch.body.effective_consensus_parameters()),
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

        let peer_rounds = select_quorums_from_index_tree_with_size(
            &last_epoch.body.verifiers,
            &self.self_node.public_key(),
            *epoch_hash,
            self.self_node.shuffle,
            last_epoch.body.effective_consensus_parameters().quorum_size,
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

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct EpochChain {
    pub epochchain: Vec<Epoch>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct Epoch {
    pub hash: HashType,
    pub signatures: BTreeMap<usize, crate::crypto::Signature>,
    pub body: EpochBody,
}

/// One opaque application transaction in a trusted epoch's deterministic
/// BTree block-hash order.
///
/// The caller must obtain the epoch from its local trusted
/// [`crate::NodeRuntime`] committed chain. This value is a replay/apply cursor,
/// not a portable consensus certificate.
#[derive(Debug, Clone)]
pub struct TrustedOrderedTransaction {
    pub epoch_hash: HashType,
    pub epoch_nonce: Nonce,
    pub previous_epoch_nonce: Option<Nonce>,
    pub block_hash: HashType,
    pub writer: PubKey,
    pub transaction_index: u32,
    pub transaction: Transaction,
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

    /// Returns trusted application payloads in their immutable order.
    ///
    /// Trusted mode requires no block signatures or epoch certificate. Block
    /// hashes, Merkle roots, and the epoch hash are still checked so accidental
    /// corruption cannot silently alter the local order.
    pub fn trusted_ordered_transactions(&self) -> Result<Vec<TrustedOrderedTransaction>> {
        if self.hash != HashType::hash(&self.body.to_bytes()) {
            return Err(BlossomError::InvalidBlockHash);
        }
        let transaction_count = self
            .body
            .blocks
            .values()
            .map(|block| block.body.txs.len())
            .sum();
        let mut ordered = Vec::with_capacity(transaction_count);
        for (block_hash, block) in self.body.ordered_blocks() {
            block.verify_unsigned_integrity_with_hash(*block_hash)?;
            for (transaction_index, transaction) in block.body.txs.iter().enumerate() {
                ordered.push(TrustedOrderedTransaction {
                    epoch_hash: self.hash,
                    epoch_nonce: self.body.nonce,
                    previous_epoch_nonce: self.body.previous_nonce,
                    block_hash: *block_hash,
                    writer: block.body.validator,
                    transaction_index: u32::try_from(transaction_index).map_err(|_| {
                        BlossomError::InvalidConfiguration(
                            "trusted block contains more than u32::MAX transactions".to_string(),
                        )
                    })?,
                    transaction: transaction.clone(),
                });
            }
        }
        Ok(ordered)
    }
}

#[derive(Debug, Clone, Default)]
pub struct EpochBody {
    pub group_id: ConsensusGroupId,
    pub verifiers: IndexTreeMap<PubKey, NodeIdentity>,
    pub last_epoch: HashType,
    /// Explicit nonce linkage for every non-genesis epoch.
    ///
    /// `None` is retained only while decoding legacy epochs whose hash predates
    /// this field. Newly-created non-genesis epochs always store `Some`.
    pub previous_nonce: Option<Nonce>,
    pub nonce: Nonce,
    pub merkle_root: HashType,
    pub blocks: BTreeMap<HashType, Block>,
    /// `None` is reserved for pre-parameter snapshots and means the legacy
    /// branching factor of six. Newly-created epochs always store `Some`.
    pub consensus_parameters: Option<ConsensusParameters>,
}

#[derive(Serialize, Deserialize)]
struct EpochBodySerde {
    group_id: ConsensusGroupId,
    verifiers: Vec<NodeIdentity>,
    last_epoch: HashType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_nonce: Option<Nonce>,
    nonce: Nonce,
    merkle_root: HashType,
    blocks: BTreeMap<HashType, Block>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consensus_parameters: Option<ConsensusParameters>,
}

impl Serialize for EpochBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        EpochBodySerde {
            group_id: self.group_id,
            verifiers: self.verifiers.values().cloned().collect(),
            last_epoch: self.last_epoch,
            previous_nonce: self.previous_nonce,
            nonce: self.nonce,
            merkle_root: self.merkle_root,
            blocks: self.blocks.clone(),
            consensus_parameters: self.consensus_parameters,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EpochBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let decoded = EpochBodySerde::deserialize(deserializer)?;
        let mut verifiers = IndexTreeMap::new();
        for node in decoded.verifiers {
            verifiers.insert(node.public_key(), node);
        }
        Ok(Self {
            group_id: decoded.group_id,
            verifiers,
            last_epoch: decoded.last_epoch,
            previous_nonce: decoded.previous_nonce,
            nonce: decoded.nonce,
            merkle_root: decoded.merkle_root,
            blocks: decoded.blocks,
            consensus_parameters: decoded.consensus_parameters,
        })
    }
}

impl BorshSerialize for EpochBody {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.group_id, writer)?;
        let verifiers = self.verifiers.values().cloned().collect::<Vec<_>>();
        BorshSerialize::serialize(&verifiers, writer)?;
        BorshSerialize::serialize(&self.last_epoch, writer)?;
        BorshSerialize::serialize(&self.previous_nonce, writer)?;
        BorshSerialize::serialize(&self.nonce, writer)?;
        BorshSerialize::serialize(&self.merkle_root, writer)?;
        BorshSerialize::serialize(&self.blocks, writer)?;
        BorshSerialize::serialize(&self.consensus_parameters, writer)
    }
}

impl BorshDeserialize for EpochBody {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let group_id = ConsensusGroupId::deserialize_reader(reader)?;
        let verifier_nodes = Vec::<NodeIdentity>::deserialize_reader(reader)?;
        let mut verifiers = IndexTreeMap::new();
        for node in verifier_nodes {
            verifiers.insert(node.public_key(), node);
        }
        let last_epoch = HashType::deserialize_reader(reader)?;
        let previous_nonce = Option::<Nonce>::deserialize_reader(reader)?;
        let nonce = Nonce::deserialize_reader(reader)?;
        let merkle_root = HashType::deserialize_reader(reader)?;
        let blocks = BTreeMap::<HashType, Block>::deserialize_reader(reader)?;
        let consensus_parameters = Option::<ConsensusParameters>::deserialize_reader(reader)?;
        Ok(Self {
            group_id,
            verifiers,
            last_epoch,
            previous_nonce,
            nonce,
            merkle_root,
            blocks,
            consensus_parameters,
        })
    }
}

impl EpochBody {
    pub fn effective_consensus_parameters(&self) -> ConsensusParameters {
        self.consensus_parameters.unwrap_or_default()
    }

    pub fn application_states(&self) -> impl Iterator<Item = (&HashType, &PubKey, &[u8])> {
        #[cfg(feature = "fair-block-ordering")]
        {
            fair_ordered_blocks(&self.blocks)
                .into_iter()
                .map(|(hash, block)| {
                    (
                        hash,
                        &block.body.validator,
                        block.body.application_state.as_slice(),
                    )
                })
        }

        #[cfg(not(feature = "fair-block-ordering"))]
        self.blocks.iter().map(|(hash, block)| {
            (
                hash,
                &block.body.validator,
                block.body.application_state.as_slice(),
            )
        })
    }

    pub fn ordered_blocks(&self) -> Vec<(&HashType, &Block)> {
        #[cfg(feature = "fair-block-ordering")]
        {
            fair_ordered_blocks(&self.blocks)
        }

        #[cfg(not(feature = "fair-block-ordering"))]
        self.blocks.iter().collect()
    }

    #[cfg(feature = "fair-block-ordering")]
    pub fn fair_ordered_blocks(&self) -> Vec<(&HashType, &Block)> {
        fair_ordered_blocks(&self.blocks)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.group_id.as_ref());
        bytes.extend_from_slice(self.last_epoch.as_ref());
        if let Some(previous_nonce) = self.previous_nonce {
            bytes.extend_from_slice(b"blossom/epoch-previous-nonce/v1");
            bytes.extend_from_slice(&previous_nonce.to_le_bytes());
        }
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(self.merkle_root.as_ref());
        for key in self.verifiers.keys() {
            bytes.extend_from_slice(key.as_ref());
        }
        for key in self.blocks.keys() {
            bytes.extend_from_slice(key.as_ref());
        }
        if let Some(parameters) = self.consensus_parameters {
            bytes.extend_from_slice(b"blossom/epoch-consensus-parameters/v1");
            bytes.extend_from_slice(&parameters.version.to_le_bytes());
            bytes.extend_from_slice(&(parameters.quorum_size.get() as u64).to_le_bytes());
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
    pub round_skip_votes: BTreeMap<RoundSkipKey, BTreeMap<PubKey, RoundSkipVote>>,
    pub round_skip_certificates: BTreeMap<RoundSkipKey, RoundSkipCertificate>,
    pub round_skip_manifests: BTreeMap<HashType, DataDisseminationManifest>,
}

#[derive(Serialize, Debug, Clone)]
pub struct PrefillDispatchRecord {
    pub sender: PubKey,
    pub round: u8,
    pub blocks_hash: HashType,
    pub blocks: BTreeMap<HashType, Block>,
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

#[derive(Serialize, Deserialize, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct RoundSkipKey {
    pub from_round: u8,
    pub to_round: u8,
    pub manifest_hash: HashType,
}

impl RoundSkipKey {
    pub fn new(from_round: u8, to_round: u8, manifest_hash: HashType) -> Self {
        Self {
            from_round,
            to_round,
            manifest_hash,
        }
    }
}

impl Serialize for EpochNonce {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("({},{})", self.0, self.1))
    }
}

#[derive(Serialize, Debug, Clone)]
pub enum PendingDispatch {
    Decoded(Dispatch),
    Hot(HotDispatch),
}

impl PendingDispatch {
    fn sender_and_signature(&self) -> (PubKey, Signature) {
        match self {
            Self::Decoded(dispatch) => (dispatch.header.sender, dispatch.header.signature),
            Self::Hot(dispatch) => (dispatch.header.sender, dispatch.header.signature),
        }
    }

    fn sender(&self) -> PubKey {
        self.sender_and_signature().0
    }

    fn raw_payload_len(&self) -> Option<usize> {
        match self {
            Self::Decoded(_) => None,
            Self::Hot(dispatch) => Some(dispatch.payload_len()),
        }
    }
}

impl From<Dispatch> for PendingDispatch {
    fn from(value: Dispatch) -> Self {
        Self::Decoded(value)
    }
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct TempQuorum {
    pub dispatch_status: Option<bool>,
    pub received_dispatches: Vec<PubKey>,
    pub pending_dispatches: Vec<PendingDispatch>,
    pub verified_signature_trees: BTreeMap<HashType, SignaturesForHash>,
    pub verified_signature_tree_hashes: BTreeMap<HashType, ()>,
    pub pending_blocks: BTreeMap<HashType, Block>,
    pub verified_blocks: BTreeMap<HashType, Block>,
    pub equivocating_validators: BTreeSet<PubKey>,
    pub verified_blocks_hash: Option<HashType>,
    pub processed_txs: HashMap<String, bool>,
    pub last_signature_tree: SignatureTree,
    pub verifications: VerifCount,
    pub verification_sent: bool,
    pub proposals: PropCount,
    pub proposal_sent: bool,
    pub pending_proposals: BTreeMap<PubKey, Proposal>,
    pub pending_commits: BTreeMap<PubKey, Commit>,
    pub commit_senders: BTreeSet<PubKey>,
    pub commit_true_senders: BTreeSet<PubKey>,
    pub commit_sent: bool,
    pub epoch_started_senders: BTreeSet<PubKey>,
    pub round_status: Option<u128>,
    pub timers: Timers,
    pub msg_matrix: MessageMatrix,
}

impl TempQuorum {
    pub fn try_push_pending_dispatch(
        &mut self,
        dispatch: PendingDispatch,
        max_raw_dispatch_bytes: usize,
        max_raw_dispatch_bytes_per_sender: usize,
    ) -> Result<()> {
        let dispatch_key = dispatch.sender_and_signature();
        if self
            .pending_dispatches
            .iter()
            .any(|pending| pending.sender_and_signature() == dispatch_key)
        {
            return Err(BlossomError::WireProtocol(format!(
                "duplicate pending dispatch from {}",
                dispatch_key.0
            )));
        }

        if let Some(raw_payload_len) = dispatch.raw_payload_len() {
            let pending_raw_bytes = self.pending_raw_dispatch_bytes();
            let next_raw_bytes =
                pending_raw_bytes
                    .checked_add(raw_payload_len)
                    .ok_or_else(|| {
                        BlossomError::WireProtocol("pending raw dispatch byte overflow".to_string())
                    })?;
            if next_raw_bytes > max_raw_dispatch_bytes {
                return Err(BlossomError::WireProtocol(format!(
                    "pending raw dispatch bytes exceed quorum cap: {next_raw_bytes} > {max_raw_dispatch_bytes}"
                )));
            }

            let sender = dispatch.sender();
            let pending_sender_raw_bytes = self.pending_raw_dispatch_bytes_for_sender(&sender);
            let next_sender_raw_bytes = pending_sender_raw_bytes
                .checked_add(raw_payload_len)
                .ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "pending raw dispatch sender byte overflow".to_string(),
                    )
                })?;
            if next_sender_raw_bytes > max_raw_dispatch_bytes_per_sender {
                return Err(BlossomError::WireProtocol(format!(
                    "pending raw dispatch bytes exceed sender cap: {next_sender_raw_bytes} > {max_raw_dispatch_bytes_per_sender}"
                )));
            }
        }

        self.pending_dispatches.push(dispatch);
        Ok(())
    }

    pub fn pending_raw_dispatch_bytes(&self) -> usize {
        self.pending_dispatches
            .iter()
            .filter_map(PendingDispatch::raw_payload_len)
            .fold(0usize, usize::saturating_add)
    }

    pub fn pending_raw_dispatch_bytes_for_sender(&self, sender: &PubKey) -> usize {
        self.pending_dispatches
            .iter()
            .filter(|dispatch| dispatch.sender() == *sender)
            .filter_map(PendingDispatch::raw_payload_len)
            .fold(0usize, usize::saturating_add)
    }

    pub fn verify(&mut self) {
        self.verify_with_signature_checks(true);
    }

    pub fn verify_trusted(&mut self) {
        self.verify_with_signature_checks(false);
    }

    fn verify_with_signature_checks(&mut self, verify_signatures: bool) {
        let mut processed_dispatches = HashMap::new();
        let mut verified_block_candidates = Vec::new();
        for pending in &self.pending_dispatches {
            let decoded_dispatch;
            let dispatch = match pending {
                PendingDispatch::Decoded(decoded) => decoded,
                PendingDispatch::Hot(raw) => match raw.to_dispatch() {
                    Ok(decoded) => {
                        decoded_dispatch = decoded;
                        &decoded_dispatch
                    }
                    Err(_) => {
                        processed_dispatches.insert((raw.header.sender, raw.header.signature), ());
                        continue;
                    }
                },
            };

            let signature_tree_hash = dispatch.body.signature_tree_hash;
            let signature_tree_ok = if verify_signatures {
                match self
                    .verified_signature_tree_hashes
                    .entry(signature_tree_hash)
                {
                    std::collections::btree_map::Entry::Occupied(_) => true,
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        if dispatch.body.signature_tree.verify() {
                            entry.insert(());
                            true
                        } else {
                            false
                        }
                    }
                }
            } else {
                dispatch.body.signature_tree.hash() == signature_tree_hash
            };
            if signature_tree_ok {
                for (sent_block_hash, block) in &dispatch.body.blocks {
                    if self.verified_blocks.contains_key(sent_block_hash) {
                        continue;
                    }
                    if block.body.last_epoch != dispatch.header.last_epoch
                        || block.body.nonce != dispatch.header.nonce
                    {
                        continue;
                    }
                    let block_ok = if verify_signatures {
                        block.verify_integrity_with_hash(*sent_block_hash).is_ok()
                    } else {
                        block
                            .verify_unsigned_integrity_with_hash(*sent_block_hash)
                            .is_ok()
                    };
                    if block_ok {
                        verified_block_candidates.push((*sent_block_hash, block.clone()));
                    }
                }
            }
            processed_dispatches.insert((dispatch.header.sender, dispatch.header.signature), ());
        }

        self.pending_dispatches.retain(|dispatch| {
            !processed_dispatches.contains_key(&dispatch.sender_and_signature())
        });
        for (block_hash, block) in verified_block_candidates {
            self.record_verified_block(block_hash, block);
        }
        self.verified_blocks_hash = Some(self.verified_blocks_hash());
    }

    pub fn verified_blocks(&self) -> BTreeMap<HashType, ()> {
        self.canonical_verified_blocks()
            .keys()
            .map(|hash| (*hash, ()))
            .collect()
    }

    pub fn verified_blocks_hash(&self) -> HashType {
        self.canonical_verified_blocks().hash()
    }

    pub fn clear_verified_blocks(&mut self) {
        self.verified_blocks.clear();
        self.equivocating_validators.clear();
        self.verified_blocks_hash = None;
        self.timers.verified_tx = 0;
    }

    pub fn has_complete_dispatch_set(&self) -> bool {
        self.dispatch_status == Some(true)
            && self.received_dispatches.len().saturating_add(1)
                >= self.msg_matrix.quorum_nodes.len()
    }

    pub fn record_verified_block(&mut self, block_hash: HashType, block: Block) -> bool {
        let validator = block.body.validator;
        if self.equivocating_validators.contains(&validator)
            || self.verified_blocks.contains_key(&block_hash)
        {
            return false;
        }

        let conflicting_hash = self
            .verified_blocks
            .iter()
            .find_map(|(existing_hash, existing)| {
                (existing.body.validator == validator && *existing_hash != block_hash)
                    .then_some(*existing_hash)
            });

        if let Some(conflicting_hash) = conflicting_hash {
            if let Some(removed) = self.verified_blocks.remove(&conflicting_hash) {
                self.timers.verified_tx = self
                    .timers
                    .verified_tx
                    .saturating_sub(removed.body.txs.len());
            }
            self.equivocating_validators.insert(validator);
            return false;
        }

        self.timers.verified_tx += block.body.txs.len();
        self.verified_blocks.insert(block_hash, block);
        true
    }

    pub fn canonical_verified_blocks(&self) -> BTreeMap<HashType, Block> {
        let mut first_hash_by_validator = BTreeMap::<PubKey, HashType>::new();
        let mut equivocating_validators = self.equivocating_validators.clone();
        for (block_hash, block) in &self.verified_blocks {
            match first_hash_by_validator.insert(block.body.validator, *block_hash) {
                Some(existing_hash) if existing_hash != *block_hash => {
                    equivocating_validators.insert(block.body.validator);
                }
                _ => {}
            }
        }

        self.verified_blocks
            .iter()
            .filter(|(_, block)| !equivocating_validators.contains(&block.body.validator))
            .map(|(hash, block)| (*hash, block.clone()))
            .collect()
    }
}

pub fn configured_max_pending_raw_dispatch_bytes() -> usize {
    *CONFIGURED_MAX_PENDING_RAW_DISPATCH_BYTES.get_or_init(|| {
        configured_pending_raw_dispatch_limit(
            MAX_PENDING_RAW_DISPATCH_BYTES_ENV,
            DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES,
        )
    })
}

pub fn configured_max_pending_raw_dispatch_bytes_per_sender() -> usize {
    *CONFIGURED_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER.get_or_init(|| {
        configured_pending_raw_dispatch_limit(
            MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER_ENV,
            DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER,
        )
    })
}

fn configured_pending_raw_dispatch_limit(env_name: &str, default: usize) -> usize {
    env::var(env_name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
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
        let sender = verification.header.sender;
        let blocks_hash = verification.body.blocks_hash;
        if let Some(previous) = self.verifications.insert(sender, verification) {
            decrement_count_u8(&mut self.count, previous.body.blocks_hash);
        }
        *self.count.entry(blocks_hash).or_default() += 1;
    }

    pub fn consensus_hash(&self) -> Option<HashType> {
        self.count
            .iter()
            .find_map(|(hash, count)| (*count as u32 >= self.supermajority).then_some(*hash))
    }

    /// Returns true while some verification hash can still reach the required
    /// supermajority after every validator that has not voted casts a vote.
    pub fn consensus_is_still_possible(&self) -> bool {
        if self.consensus_hash().is_some() {
            return true;
        }
        let received = self.verifications.len() as u32;
        let remaining = self.quorum.saturating_sub(received);
        if self.count.is_empty() {
            return remaining >= self.supermajority;
        }
        self.count
            .values()
            .any(|count| u32::from(*count).saturating_add(remaining) >= self.supermajority)
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
    pub fn record(&mut self, proposal: Proposal) {
        let sender = proposal.header.sender;
        let approved_hash = proposal.body.approved_hash;
        if let Some(previous_hash) = self
            .proposals
            .insert(sender, proposal)
            .and_then(|previous| previous.body.approved_hash)
        {
            decrement_count_u32(&mut self.count, previous_hash);
        }
        if let Some(hash) = approved_hash {
            *self.count.entry(hash).or_default() += 1;
        }
    }

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

fn decrement_count_u8(counts: &mut BTreeMap<HashType, u8>, hash: HashType) {
    match counts.entry(hash) {
        std::collections::btree_map::Entry::Occupied(mut entry) if *entry.get() > 1 => {
            *entry.get_mut() -= 1;
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            entry.remove();
        }
        std::collections::btree_map::Entry::Vacant(_) => {}
    }
}

fn decrement_count_u32(counts: &mut BTreeMap<HashType, u32>, hash: HashType) {
    match counts.entry(hash) {
        std::collections::btree_map::Entry::Occupied(mut entry) if *entry.get() > 1 => {
            *entry.get_mut() -= 1;
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            entry.remove();
        }
        std::collections::btree_map::Entry::Vacant(_) => {}
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
        verified_signature_tree_hashes: BTreeMap::new(),
        verified_blocks: BTreeMap::new(),
        equivocating_validators: BTreeSet::new(),
        processed_txs: HashMap::new(),
        last_signature_tree: Default::default(),
        verified_blocks_hash: Default::default(),
        verifications: init_verifications(quorum),
        verification_sent: false,
        proposals: init_proposals(quorum),
        proposal_sent: false,
        pending_proposals: BTreeMap::new(),
        pending_commits: BTreeMap::new(),
        commit_senders: BTreeSet::new(),
        commit_true_senders: BTreeSet::new(),
        commit_sent: false,
        epoch_started_senders: BTreeSet::new(),
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
        round_skip_votes: BTreeMap::new(),
        round_skip_certificates: BTreeMap::new(),
        round_skip_manifests: BTreeMap::new(),
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
    #[cfg(feature = "fair-block-ordering")]
    let leaves = fair_ordered_block_commitments(blocks);

    #[cfg(not(feature = "fair-block-ordering"))]
    let leaves = blocks.keys().copied().collect::<Vec<_>>();

    #[cfg(feature = "insecure-fast-hash")]
    {
        if leaves.is_empty() {
            return HashType::default();
        }
        if let Some(hash) = leaves.first().copied().filter(|_| leaves.len() == 1) {
            return hash;
        }
        HashType::hash_slices(leaves.iter().map(AsRef::as_ref))
    }

    #[cfg(not(feature = "insecure-fast-hash"))]
    {
        let leaves = leaves.iter().map(|hash| hash.0).collect::<Vec<_>>();
        HashType::from_byte_hash(
            MerkleTree::<Sha256>::from_leaves(&leaves)
                .root()
                .unwrap_or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    use crate::block::Transaction;
    use crate::blossom::{
        Dispatch, DispatchBody, Header, Proposal, ProposalBody, SignatureTree, Verification,
        VerificationBody,
    };
    use crate::crypto::{Keypair, Signature};
    use crate::encounter::{
        EncounterOutcome, EncounterPhase, EncounterRecord, EncounterRecordBody,
    };
    use crate::membership::ConsensusNodeRemovalPolicy;
    use crate::messages::Msg;
    use crate::wire::{EncodedFrame, FRAME_PREFIX_BYTES, WireRequest, WireRequestFrame};

    #[cfg(feature = "fair-block-ordering")]
    fn sealed_epoch_block(label: &str, txs: &[&str]) -> Block {
        let mut block = Block::default();
        block.body.created = 42;
        block.body.nonce = Nonce::new(1);
        for tx in txs {
            block
                .body
                .txs
                .push(Transaction::new(format!("{label}:{tx}")));
        }
        block.seal_unsigned(PubKey(HashType::hash(label.as_bytes()).0));
        block
    }

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

    fn hot_pending_dispatch(sender: PubKey, signature: Signature) -> PendingDispatch {
        let blocks = BTreeMap::<HashType, Block>::default();
        let blocks_hash = blocks.hash();
        let signature_tree = SignatureTree::default();
        let dispatch = Dispatch {
            header: Header {
                sender,
                signature,
                ..Default::default()
            },
            body: DispatchBody {
                blocks_hash,
                blocks,
                signature_tree_hash: signature_tree.hash(),
                signature_tree,
            },
        };
        let frame =
            EncodedFrame::encode_hot_wire_request(&WireRequest::Message(Msg::Dispatch(dispatch)))
                .unwrap()
                .unwrap();
        match crate::wire::decode_wire_request_frame(Bytes::copy_from_slice(
            &frame.as_bytes()[FRAME_PREFIX_BYTES..],
        ))
        .unwrap()
        {
            WireRequestFrame::HotDispatch(raw) => PendingDispatch::Hot(raw),
            request => panic!("expected hot dispatch, got {request:?}"),
        }
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
    #[cfg(not(feature = "fair-block-ordering"))]
    fn block_merkle_root_uses_raw_hash_without_fair_order_feature() {
        let block = Block::empty_with_nonce(Nonce::new(1));
        let hash = block.hash();
        let mut blocks = BTreeMap::new();
        blocks.insert(hash, block);

        assert_eq!(block_merkle_root(&blocks), hash);
    }

    #[test]
    #[cfg(feature = "fair-block-ordering")]
    fn block_merkle_root_uses_fair_order_commitments() {
        let block = Block::empty_with_nonce(Nonce::new(1));
        let hash = block.hash();
        let mut blocks = BTreeMap::new();
        blocks.insert(hash, block);

        assert_eq!(
            block_merkle_root(&blocks),
            fair_ordered_block_commitments(&blocks)[0]
        );
        assert_ne!(block_merkle_root(&blocks), hash);
    }

    #[test]
    #[cfg(feature = "fair-block-ordering")]
    fn fair_ordered_epoch_hash_is_consistent_across_arrival_order() {
        let first = sealed_epoch_block("first", &["a", "b"]);
        let second = sealed_epoch_block("second", &["c"]);
        let mut first_arrival = BTreeMap::new();
        first_arrival.insert(first.hash, first.clone());
        first_arrival.insert(second.hash, second.clone());
        let mut second_arrival = BTreeMap::new();
        second_arrival.insert(second.hash, second);
        second_arrival.insert(first.hash, first);

        assert_eq!(
            fair_ordered_block_commitments(&first_arrival),
            fair_ordered_block_commitments(&second_arrival)
        );

        let mut first_epoch = Epoch {
            hash: HashType::default(),
            signatures: BTreeMap::default(),
            body: EpochBody {
                last_epoch: HashType([1; 32]),
                nonce: Nonce::new(2),
                merkle_root: block_merkle_root(&first_arrival),
                blocks: first_arrival,
                ..Default::default()
            },
        };
        first_epoch.set_hash();

        let mut second_epoch = Epoch {
            hash: HashType::default(),
            signatures: BTreeMap::default(),
            body: EpochBody {
                last_epoch: HashType([1; 32]),
                nonce: Nonce::new(2),
                merkle_root: block_merkle_root(&second_arrival),
                blocks: second_arrival,
                ..Default::default()
            },
        };
        second_epoch.set_hash();

        assert_eq!(first_epoch.body.merkle_root, second_epoch.body.merkle_root);
        assert_eq!(first_epoch.hash, second_epoch.hash);
        assert_ne!(first_epoch.body.merkle_root, first_epoch.body.blocks.hash());
    }

    #[test]
    fn trusted_quorum_verify_accepts_unsigned_dispatch_blocks() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.nonce = Nonce::new(1);
        block.body.txs.push(Transaction::new("tx"));
        block.seal_unsigned(keypair.public);
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block.clone());
        let dispatch = Dispatch {
            header: Header {
                sender: keypair.public,
                nonce: Nonce::new(1),
                signature: Signature::default(),
                ..Default::default()
            },
            body: DispatchBody {
                blocks_hash: blocks.hash(),
                blocks,
                signature_tree: SignatureTree::default(),
                signature_tree_hash: SignatureTree::default().hash(),
            },
        };

        let mut verified_quorum = TempQuorum {
            pending_dispatches: vec![PendingDispatch::Decoded(dispatch.clone())],
            ..Default::default()
        };
        verified_quorum.verify();
        assert!(verified_quorum.verified_blocks.is_empty());

        let mut trusted_quorum = TempQuorum {
            pending_dispatches: vec![PendingDispatch::Decoded(dispatch)],
            ..Default::default()
        };
        trusted_quorum.verify_trusted();
        assert_eq!(trusted_quorum.verified_blocks.len(), 1);
        assert!(trusted_quorum.verified_blocks.contains_key(&block.hash));
    }

    #[test]
    fn pending_dispatch_rejects_duplicate_sender_signature() {
        let pending = hot_pending_dispatch(PubKey([7; 32]), Signature([1; 64]));
        let raw_len = pending.raw_payload_len().unwrap();
        let mut quorum = TempQuorum::default();

        quorum
            .try_push_pending_dispatch(pending.clone(), raw_len * 2, raw_len * 2)
            .unwrap();
        let err = quorum
            .try_push_pending_dispatch(pending, raw_len * 2, raw_len * 2)
            .unwrap_err();

        assert!(matches!(
            err,
            BlossomError::WireProtocol(message) if message.contains("duplicate pending dispatch")
        ));
        assert_eq!(quorum.pending_dispatches.len(), 1);
        assert_eq!(quorum.pending_raw_dispatch_bytes(), raw_len);
    }

    #[test]
    fn pending_dispatch_enforces_raw_quorum_and_sender_caps() {
        let sender = PubKey([8; 32]);
        let first = hot_pending_dispatch(sender, Signature([1; 64]));
        let second = hot_pending_dispatch(sender, Signature([2; 64]));
        let raw_len = first.raw_payload_len().unwrap();

        let mut quorum_cap = TempQuorum::default();
        let err = quorum_cap
            .try_push_pending_dispatch(first.clone(), raw_len - 1, raw_len)
            .unwrap_err();
        assert!(matches!(
            err,
            BlossomError::WireProtocol(message) if message.contains("quorum cap")
        ));
        assert!(quorum_cap.pending_dispatches.is_empty());

        let mut sender_cap = TempQuorum::default();
        sender_cap
            .try_push_pending_dispatch(first, raw_len * 2, raw_len)
            .unwrap();
        let err = sender_cap
            .try_push_pending_dispatch(second, raw_len * 2, raw_len)
            .unwrap_err();
        assert!(matches!(
            err,
            BlossomError::WireProtocol(message) if message.contains("sender cap")
        ));
        assert_eq!(sender_cap.pending_raw_dispatch_bytes(), raw_len);
        assert_eq!(
            sender_cap.pending_raw_dispatch_bytes_for_sender(&sender),
            raw_len
        );
    }

    #[test]
    fn quorum_verify_skips_already_verified_blocks() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.last_epoch = HashType([2; 32]);
        block.body.nonce = Nonce::new(1);
        block.body.txs.push(Transaction::new("tx"));
        block.sign(&keypair.secret);
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block.clone());
        let dispatch = Dispatch {
            header: Header {
                sender: keypair.public,
                last_epoch: HashType([2; 32]),
                nonce: Nonce::new(1),
                signature: Signature::default(),
                ..Default::default()
            },
            body: DispatchBody {
                blocks_hash: blocks.hash(),
                blocks,
                signature_tree: SignatureTree::default(),
                signature_tree_hash: SignatureTree::default().hash(),
            },
        };
        let mut quorum = TempQuorum {
            pending_dispatches: vec![
                PendingDispatch::Decoded(dispatch.clone()),
                PendingDispatch::Decoded(dispatch),
            ],
            ..Default::default()
        };

        quorum.verify();

        assert_eq!(quorum.verified_blocks.len(), 1);
        assert_eq!(quorum.timers.verified_tx, 1);
    }

    #[test]
    fn quorum_verify_drops_equivocating_validator_blocks() {
        let keypair = Keypair::generate();
        let mut first_block = Block::default();
        first_block.body.last_epoch = HashType([2; 32]);
        first_block.body.nonce = Nonce::new(1);
        first_block.body.txs.push(Transaction::new("first"));
        first_block.sign(&keypair.secret);

        let mut second_block = Block::default();
        second_block.body.last_epoch = HashType([2; 32]);
        second_block.body.nonce = Nonce::new(1);
        second_block.body.txs.push(Transaction::new("second"));
        second_block.sign(&keypair.secret);

        let mut blocks = BTreeMap::new();
        blocks.insert(first_block.hash, first_block);
        blocks.insert(second_block.hash, second_block);
        let dispatch = Dispatch {
            header: Header {
                sender: keypair.public,
                last_epoch: HashType([2; 32]),
                nonce: Nonce::new(1),
                signature: Signature::default(),
                ..Default::default()
            },
            body: DispatchBody {
                blocks_hash: blocks.hash(),
                blocks,
                signature_tree: SignatureTree::default(),
                signature_tree_hash: SignatureTree::default().hash(),
            },
        };
        let mut quorum = TempQuorum {
            pending_dispatches: vec![PendingDispatch::Decoded(dispatch)],
            ..Default::default()
        };

        quorum.verify();

        assert!(quorum.verified_blocks().is_empty());
        assert!(quorum.canonical_verified_blocks().is_empty());
        assert!(quorum.equivocating_validators.contains(&keypair.public));
        assert_eq!(quorum.timers.verified_tx, 0);
        assert_eq!(
            quorum.verified_blocks_hash,
            Some(BTreeMap::<HashType, Block>::new().hash())
        );
    }

    #[test]
    fn verified_blocks_hash_excludes_directly_inserted_equivocations() {
        let keypair = Keypair::generate();
        let mut first_block = Block::default();
        first_block.body.last_epoch = HashType([2; 32]);
        first_block.body.nonce = Nonce::new(1);
        first_block.body.txs.push(Transaction::new("first"));
        first_block.sign(&keypair.secret);

        let mut second_block = Block::default();
        second_block.body.last_epoch = HashType([2; 32]);
        second_block.body.nonce = Nonce::new(1);
        second_block.body.txs.push(Transaction::new("second"));
        second_block.sign(&keypair.secret);

        let mut quorum = TempQuorum::default();
        quorum.verified_blocks.insert(first_block.hash, first_block);
        quorum
            .verified_blocks
            .insert(second_block.hash, second_block);

        assert!(quorum.verified_blocks().is_empty());
        assert_eq!(
            quorum.verified_blocks_hash(),
            BTreeMap::<HashType, Block>::new().hash()
        );
    }

    #[test]
    fn quorum_verify_rejects_dispatch_blocks_for_different_epoch_target() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.last_epoch = HashType([2; 32]);
        block.body.nonce = Nonce::new(2);
        block.body.txs.push(Transaction::new("tx"));
        block.sign(&keypair.secret);
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let dispatch = Dispatch {
            header: Header {
                sender: keypair.public,
                last_epoch: HashType([2; 32]),
                nonce: Nonce::new(1),
                signature: Signature::default(),
                ..Default::default()
            },
            body: DispatchBody {
                blocks_hash: blocks.hash(),
                blocks,
                signature_tree: SignatureTree::default(),
                signature_tree_hash: SignatureTree::default().hash(),
            },
        };
        let mut quorum = TempQuorum {
            pending_dispatches: vec![PendingDispatch::Decoded(dispatch)],
            ..Default::default()
        };

        quorum.verify();

        assert!(quorum.verified_blocks.is_empty());
        assert_eq!(
            quorum.verified_blocks_hash,
            Some(BTreeMap::<HashType, Block>::new().hash())
        );
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
        assert_eq!(latest.body.previous_nonce, Some(genesis.body.nonce));
        assert_eq!(latest.body.nonce, next_nonce);
        assert!(latest.body.blocks.contains_key(&block_hash));
    }

    #[test]
    fn epoch_hash_commits_the_previous_nonce() {
        let mut epoch = Epoch {
            body: EpochBody {
                last_epoch: HashType([1; 32]),
                previous_nonce: Some(Nonce::new(7)),
                nonce: Nonce::new(8),
                ..Default::default()
            },
            ..Default::default()
        };
        epoch.set_hash();
        let first_hash = epoch.hash;

        epoch.body.previous_nonce = Some(Nonce::new(6));
        epoch.set_hash();
        assert_ne!(epoch.hash, first_hash);
    }

    #[test]
    fn advance_epoch_removes_node_with_supermajority_failure_evidence() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let mut verifiers = IndexTreeMap::new();
        for (index, keypair) in keypairs.iter().enumerate() {
            let node = NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                format!("node-{index}"),
                8000 + index as u16,
                false,
            );
            verifiers.insert(node.public_key(), node);
        }
        let mut genesis = Epoch {
            body: EpochBody {
                verifiers,
                nonce: Nonce::new(0),
                ..Default::default()
            },
            ..Default::default()
        };
        genesis.set_hash();

        let mut state = LocalState::new_with_consensus_node_removal_policy(
            NodeIdentity::new(
                keypairs[0].public,
                Some(keypairs[0].secret),
                "tcp",
                "node-0",
                8000,
                false,
            ),
            genesis.clone(),
            ConsensusNodeRemovalPolicy::supermajority(),
        );
        let next_nonce = genesis.body.nonce.new_next();
        let subject = keypairs[5].public;

        for observer in &keypairs[..4] {
            let record = EncounterRecord::signed(
                EncounterRecordBody::new(
                    observer.public,
                    subject,
                    genesis.hash,
                    next_nonce,
                    0,
                    EncounterPhase::Verification,
                    EncounterOutcome::MissingSignature,
                ),
                &observer.signer(),
            )
            .unwrap();
            let mut block = Block::default();
            block.body.last_epoch = genesis.hash;
            block.body.nonce = next_nonce;
            block.body.encounter_records.push(record);
            block.sign(&observer.secret);
            state
                .get_mut_quorum(&genesis.hash, next_nonce, 0)
                .verified_blocks
                .insert(block.hash, block);
        }

        assert!(state.advance_epoch(&genesis.hash, next_nonce, 0, true));
        let latest = state.epochchain.epochchain.last().unwrap();
        assert!(!latest.body.verifiers.contains_key(&subject));
        assert_eq!(latest.body.verifiers.len(), 5);
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
    fn verification_count_only_becomes_impossible_after_enough_conflicting_votes() {
        let first = HashType([3; 32]);
        let second = HashType([4; 32]);
        let mut count = init_verifications(9);

        for index in 0..4 {
            count.record(Verification {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: VerificationBody {
                    blocks_hash: first,
                    blocks: BTreeMap::new(),
                },
            });
        }
        assert!(count.consensus_is_still_possible());

        for index in 4..9 {
            count.record(Verification {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: VerificationBody {
                    blocks_hash: second,
                    blocks: BTreeMap::new(),
                },
            });
        }
        assert!(!count.consensus_is_still_possible());
    }

    #[test]
    fn split_prefill_equivocation_cannot_certify_two_block_sets() {
        let first_blocks_hash = HashType([3; 32]);
        let second_blocks_hash = HashType([4; 32]);
        let mut split = init_verifications(6);

        for index in 0..3 {
            split.record(Verification {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: VerificationBody {
                    blocks_hash: first_blocks_hash,
                    blocks: BTreeMap::new(),
                },
            });
        }
        for index in 3..6 {
            split.record(Verification {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: VerificationBody {
                    blocks_hash: second_blocks_hash,
                    blocks: BTreeMap::new(),
                },
            });
        }

        assert_eq!(split.count.get(&first_blocks_hash), Some(&3));
        assert_eq!(split.count.get(&second_blocks_hash), Some(&3));
        assert_eq!(split.consensus_hash(), None);

        let mut converged = init_verifications(6);
        for index in 0..4 {
            converged.record(Verification {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: VerificationBody {
                    blocks_hash: first_blocks_hash,
                    blocks: BTreeMap::new(),
                },
            });
        }
        for index in 4..6 {
            converged.record(Verification {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: VerificationBody {
                    blocks_hash: second_blocks_hash,
                    blocks: BTreeMap::new(),
                },
            });
        }

        assert_eq!(converged.consensus_hash(), Some(first_blocks_hash));
    }

    #[test]
    fn proposal_count_reports_true_false_or_pending() {
        let mut count = init_proposals(6);
        let approved = HashType([4; 32]);
        assert_eq!(count.consensus(), None);

        for index in 0..4 {
            count.record(Proposal {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: ProposalBody {
                    consensus: true,
                    approved_hash: Some(approved),
                    ..Default::default()
                },
            });
        }
        assert_eq!(count.consensus(), Some(true));

        let mut failed = init_proposals(6);
        for index in 0..4 {
            failed.record(Proposal {
                header: Header {
                    sender: PubKey([index; 32]),
                    ..Default::default()
                },
                body: ProposalBody::default(),
            });
        }
        assert_eq!(failed.consensus(), Some(false));
    }

    #[test]
    fn verification_count_replaces_duplicate_sender_vote() {
        let mut count = init_verifications(6);
        let first = HashType([3; 32]);
        let second = HashType([4; 32]);
        let sender = PubKey([1; 32]);

        count.record(Verification {
            header: Header {
                sender,
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash: first,
                blocks: BTreeMap::new(),
            },
        });
        count.record(Verification {
            header: Header {
                sender,
                ..Default::default()
            },
            body: VerificationBody {
                blocks_hash: second,
                blocks: BTreeMap::new(),
            },
        });

        assert_eq!(count.count.get(&first), None);
        assert_eq!(count.count.get(&second), Some(&1));
        assert_eq!(count.verifications.len(), 1);
    }

    #[test]
    fn proposal_count_replaces_duplicate_sender_vote() {
        let mut count = init_proposals(6);
        let first = HashType([3; 32]);
        let second = HashType([4; 32]);
        let sender = PubKey([1; 32]);

        count.record(Proposal {
            header: Header {
                sender,
                ..Default::default()
            },
            body: ProposalBody {
                consensus: true,
                approved_hash: Some(first),
                ..Default::default()
            },
        });
        count.record(Proposal {
            header: Header {
                sender,
                ..Default::default()
            },
            body: ProposalBody {
                consensus: true,
                approved_hash: Some(second),
                ..Default::default()
            },
        });

        assert_eq!(count.count.get(&first), None);
        assert_eq!(count.count.get(&second), Some(&1));
        assert_eq!(count.proposals.len(), 1);
    }
}
