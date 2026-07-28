//! Finalized epoch chains and transient per-round consensus state.

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
    SignaturesForHash, TrustedAcknowledgement, Verification, VerificationBody,
};
use crate::crypto::{PubKey, Signature};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{DoHash, HashType};
use crate::membership::{
    ConsensusNodeRemovalPolicy, MemberSet, apply_epoch_member_registry_transition,
    apply_epoch_membership_transition,
};
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
            build_verified_epoch(&last_epoch, blocks, self.consensus_node_removal_policy)
        } else {
            Epoch {
                hash: HashType::default(),
                signatures: BTreeMap::default(),
                body: EpochBody {
                    group_id: last_epoch.body.group_id,
                    members: last_epoch.body.members.clone(),
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
        if consensus {
            let quorum = current_consensus.quorum.get(&current_round).unwrap();
            for (validator, signature) in &quorum.epoch_signatures {
                if let Some(index) = last_epoch.body.verifiers.get_index_from_key(validator) {
                    new_epoch.signatures.insert(index, *signature);
                }
            }
            if new_epoch.verify_certificate(&last_epoch).is_err() {
                return false;
            }
        }
        self.consensus
            .retain(|EpochNonce(_, nonce), _| nonce.value() + 1 >= new_epoch.body.nonce.value());
        self.epochchain.epochchain.push(new_epoch);
        true
    }

    pub(crate) fn prepare_verified_epoch(
        &self,
        proposed_last_epoch_hash: &HashType,
        proposed_new_epoch_nonce: Nonce,
        current_round: u8,
    ) -> Result<Option<Epoch>> {
        let previous = self
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if previous.hash != *proposed_last_epoch_hash
            || previous.body.nonce.new_next() != proposed_new_epoch_nonce
        {
            return Err(BlossomError::InvalidEpochNonce);
        }
        let consensus = self
            .consensus
            .get(&EpochNonce(
                *proposed_last_epoch_hash,
                proposed_new_epoch_nonce,
            ))
            .ok_or(BlossomError::FailedConsensus)?;
        if consensus.peers.len() > usize::from(current_round) + 1 {
            return Ok(None);
        }
        let blocks = consensus
            .quorum
            .get(&current_round)
            .ok_or(BlossomError::FailedConsensus)?
            .canonical_verified_blocks();
        let mut epoch = build_verified_epoch(previous, blocks, self.consensus_node_removal_policy);
        epoch.set_hash();
        Ok(Some(epoch))
    }

    /// Builds the immutable epoch a trusted confirmation quorum would commit without
    /// mutating the local stable prefix.
    ///
    /// Trusted runtimes use this to fsync the epoch log before exposing the new
    /// head. The verified protocol continues to use [`Self::advance_epoch`].
    pub(crate) fn prepare_trusted_epoch(
        &self,
        proposed_last_epoch_hash: &HashType,
        proposed_new_epoch_nonce: Nonce,
        current_round: u8,
        confirmed_blocks: &BTreeMap<HashType, ()>,
    ) -> Result<Epoch> {
        let last_epoch = self
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let expected_nonce = last_epoch.body.nonce.new_next();
        if last_epoch.hash != *proposed_last_epoch_hash
            || expected_nonce != proposed_new_epoch_nonce
        {
            return Err(BlossomError::InvalidEpochNonce);
        }
        let current_consensus = self
            .consensus
            .get(&EpochNonce(
                *proposed_last_epoch_hash,
                proposed_new_epoch_nonce,
            ))
            .ok_or(BlossomError::FailedConsensus)?;
        if current_consensus.peers.len() > current_round as usize + 1 {
            return Err(BlossomError::FailedConsensus);
        }
        let quorum = current_consensus
            .quorum
            .get(&current_round)
            .ok_or(BlossomError::FailedConsensus)?;
        let blocks = quorum
            .trusted_candidate_blocks(&VerificationBody {
                blocks_hash: confirmed_blocks.hash(),
                blocks: confirmed_blocks.clone(),
            })
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted confirmation references unavailable local blocks".to_string(),
                )
            })?;
        let (legacy_verifiers, _) = apply_epoch_membership_transition(
            &last_epoch.body.verifiers,
            &blocks,
            *proposed_last_epoch_hash,
            expected_nonce,
            self.consensus_node_removal_policy,
        );
        let (members, verifiers) = apply_epoch_member_registry_transition(
            &last_epoch.body.members,
            &legacy_verifiers,
            &blocks,
            last_epoch.body.group_id,
            *proposed_last_epoch_hash,
        );
        let mut epoch = Epoch {
            hash: HashType::default(),
            signatures: BTreeMap::default(),
            body: EpochBody {
                group_id: last_epoch.body.group_id,
                members,
                verifiers,
                last_epoch: *proposed_last_epoch_hash,
                previous_nonce: Some(last_epoch.body.nonce),
                nonce: expected_nonce,
                merkle_root: block_merkle_root(&blocks),
                blocks,
                consensus_parameters: Some(last_epoch.body.effective_consensus_parameters()),
            },
        };
        epoch.set_hash();
        Ok(epoch)
    }

    /// Carries one confirmed trusted candidate into the next hierarchical
    /// quorum round without changing the immutable epoch chain.
    pub(crate) fn advance_trusted_round(
        &mut self,
        proposed_last_epoch_hash: &HashType,
        proposed_new_epoch_nonce: Nonce,
        current_round: u8,
        confirmed_blocks: &BTreeMap<HashType, ()>,
    ) -> Result<bool> {
        let last_epoch = self
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if last_epoch.hash != *proposed_last_epoch_hash
            || last_epoch.body.nonce.new_next() != proposed_new_epoch_nonce
        {
            return Err(BlossomError::InvalidEpochNonce);
        }
        let consensus = self
            .consensus
            .get_mut(&EpochNonce(
                *proposed_last_epoch_hash,
                proposed_new_epoch_nonce,
            ))
            .ok_or(BlossomError::FailedConsensus)?;
        if consensus.peers.len() <= current_round as usize + 1 {
            return Ok(false);
        }
        let current = consensus
            .quorum
            .get(&current_round)
            .ok_or(BlossomError::FailedConsensus)?;
        let carried_blocks = current
            .trusted_candidate_blocks(&VerificationBody {
                blocks_hash: confirmed_blocks.hash(),
                blocks: confirmed_blocks.clone(),
            })
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted round confirmation references unavailable blocks".to_string(),
                )
            })?;
        let next_round = current_round.checked_add(1).ok_or_else(|| {
            BlossomError::InvalidConfiguration("trusted round overflow".to_string())
        })?;
        let next_peers = consensus.peers_with_us(next_round);
        let next_quorum = consensus.quorum.entry(next_round).or_insert_with(|| {
            init_quorum(next_peers.len() as u32, &next_peers, &consensus.self_key)
        });
        for (hash, block) in carried_blocks {
            next_quorum.record_verified_block(hash, block);
        }
        next_quorum.verified_blocks_hash = Some(next_quorum.verified_blocks_hash());
        consensus.round = next_round;
        Ok(true)
    }

    /// Installs an epoch that was already durably appended by the trusted
    /// runtime.
    pub(crate) fn install_trusted_epoch(&mut self, epoch: Epoch) -> Result<bool> {
        let current = self
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if epoch.body.last_epoch != current.hash
            || epoch.body.previous_nonce != Some(current.body.nonce)
            || epoch.body.nonce != current.body.nonce.new_next()
            || epoch.hash != HashType::hash(&epoch.body.to_bytes())
        {
            return Err(BlossomError::InvalidConfiguration(
                "durable trusted epoch does not extend the in-memory stable prefix".to_string(),
            ));
        }
        self.consensus
            .retain(|EpochNonce(_, nonce), _| nonce.value() + 1 >= epoch.body.nonce.value());
        self.epochchain.epochchain.push(epoch);
        Ok(true)
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

pub const CERTIFIED_EPOCH_SUFFIX_VERSION: u16 = 1;
pub const MAX_CERTIFIED_EPOCH_SUFFIX: usize = 4096;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct CertifiedEpochSuffix {
    pub version: u16,
    pub group_id: ConsensusGroupId,
    pub anchor_hash: HashType,
    pub anchor_nonce: Nonce,
    pub epochs: Vec<Epoch>,
}

impl CertifiedEpochSuffix {
    pub fn validate_from(
        &self,
        anchor: &Epoch,
        removal_policy: ConsensusNodeRemovalPolicy,
    ) -> Result<()> {
        if self.version != CERTIFIED_EPOCH_SUFFIX_VERSION
            || self.group_id != anchor.body.group_id
            || self.anchor_hash != anchor.hash
            || self.anchor_nonce != anchor.body.nonce
            || self.epochs.len() > MAX_CERTIFIED_EPOCH_SUFFIX
        {
            return Err(BlossomError::InvalidEpochNonce);
        }
        let mut previous = anchor;
        for epoch in &self.epochs {
            validate_certified_extension(previous, epoch, removal_policy)?;
            previous = epoch;
        }
        Ok(())
    }
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

    /// Verifies this epoch's exact-hash quorum certificate against the
    /// validator set that authorized the transition.
    pub fn verify_certificate(&self, previous: &Epoch) -> Result<()> {
        let validator_count = previous.body.verifiers.len();
        if validator_count == 0 || self.signatures.len() < supermajority_count(validator_count) {
            return Err(BlossomError::FailedConsensus);
        }
        let message = self.hash.to_bytes();
        for (index, signature) in &self.signatures {
            let public_key = previous
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
    pub members: MemberSet,
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
    #[serde(default)]
    members: MemberSet,
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
            members: self.members.clone(),
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
            members: decoded.members,
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
        BorshSerialize::serialize(&self.members, writer)?;
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
        let members = MemberSet::deserialize_reader(reader)?;
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
            members,
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
        bytes.extend_from_slice(b"blossom/epoch-members/v1");
        bytes.extend_from_slice(
            &borsh::to_vec(&self.members).expect("member set serialization is infallible"),
        );
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
    pub received_dispatch_identities: BTreeMap<PubKey, (Signature, HashType)>,
    pub pending_dispatches: Vec<PendingDispatch>,
    pub verified_signature_trees: BTreeMap<HashType, SignaturesForHash>,
    pub verified_signature_tree_hashes: BTreeMap<HashType, ()>,
    pub pending_blocks: BTreeMap<HashType, Block>,
    pub verified_blocks: BTreeMap<HashType, Block>,
    pub equivocating_validators: BTreeSet<PubKey>,
    pub verified_blocks_hash: Option<HashType>,
    pub processed_txs: HashMap<String, bool>,
    pub last_signature_tree: SignatureTree,
    pub local_dispatch: Option<Dispatch>,
    pub dispatch_retry: bool,
    pub trusted_acknowledgements: TrustedAcknowledgementCount,
    pub trusted_confirmations: TrustedConfirmationCount,
    pub pending_trusted_acknowledgements: BTreeMap<PubKey, TrustedAcknowledgement>,
    pub pending_trusted_confirmations: BTreeMap<PubKey, Verification>,
    pub last_trusted_acknowledgement_hash: Option<HashType>,
    pub trusted_acknowledgement_retry: Option<HashType>,
    pub trusted_confirmation_retry: Option<HashType>,
    pub verifications: VerifCount,
    pub verification_sent: bool,
    pub verification_retry: bool,
    pub proposals: PropCount,
    pub proposal_sent: bool,
    pub proposal_retry: bool,
    pub pending_proposals: BTreeMap<PubKey, Proposal>,
    pub pending_commits: BTreeMap<PubKey, Commit>,
    pub local_commit: Option<Commit>,
    pub commit_senders: BTreeSet<PubKey>,
    pub commit_true_senders: BTreeSet<PubKey>,
    pub epoch_signatures: BTreeMap<PubKey, Signature>,
    pub commit_sent: bool,
    pub epoch_started_senders: BTreeSet<PubKey>,
    pub round_status: Option<u128>,
    pub timers: Timers,
    pub msg_matrix: MessageMatrix,
}

impl TempQuorum {
    pub(crate) fn trusted_candidate_blocks(
        &self,
        body: &VerificationBody,
    ) -> Option<BTreeMap<HashType, Block>> {
        let verified = self.canonical_verified_blocks();
        body.blocks
            .keys()
            .map(|hash| verified.get(hash).cloned().map(|block| (*hash, block)))
            .collect()
    }

    pub(crate) fn activate_pending_trusted_messages(&mut self) -> Result<()> {
        let acknowledgement_senders = self
            .pending_trusted_acknowledgements
            .iter()
            .filter_map(|(sender, acknowledgement)| {
                self.trusted_candidate_blocks(&acknowledgement.body)
                    .is_some()
                    .then_some(*sender)
            })
            .collect::<Vec<_>>();
        for sender in acknowledgement_senders {
            let acknowledgement = self
                .pending_trusted_acknowledgements
                .remove(&sender)
                .expect("pending trusted acknowledgement sender exists");
            self.trusted_acknowledgements.record(acknowledgement)?;
        }

        let confirmation_senders = self
            .pending_trusted_confirmations
            .iter()
            .filter_map(|(sender, confirmation)| {
                self.trusted_candidate_blocks(&confirmation.body)
                    .is_some()
                    .then_some(*sender)
            })
            .collect::<Vec<_>>();
        for sender in confirmation_senders {
            let confirmation = self
                .pending_trusted_confirmations
                .remove(&sender)
                .expect("pending trusted confirmation sender exists");
            self.trusted_confirmations.record(confirmation)?;
        }
        Ok(())
    }

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

    /// Returns true once enough trusted members have dispatched to preserve
    /// quorum intersection even if the remaining members are inactive.
    pub fn has_trusted_dispatch_quorum(&self) -> bool {
        let members = self.msg_matrix.quorum_nodes.len();
        self.dispatch_status == Some(true)
            && self.received_dispatches.len().saturating_add(1) >= supermajority_count(members)
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TrustedAcknowledgementCount {
    pub acknowledgements: BTreeMap<PubKey, TrustedAcknowledgement>,
    pub count: BTreeMap<HashType, u32>,
    pub quorum: u32,
    pub supermajority: u32,
}

impl TrustedAcknowledgementCount {
    pub fn validate_update(&self, acknowledgement: &TrustedAcknowledgement) -> Result<bool> {
        let sender = acknowledgement.header.sender;
        let blocks_hash = acknowledgement.body.blocks_hash;
        if let Some(previous) = self.acknowledgements.get(&sender) {
            if !previous
                .body
                .blocks
                .keys()
                .all(|hash| acknowledgement.body.blocks.contains_key(hash))
            {
                return Err(BlossomError::WireProtocol(
                    "trusted acknowledgement masks may only grow".to_string(),
                ));
            }
            if previous.body.blocks_hash == blocks_hash {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn record(&mut self, acknowledgement: TrustedAcknowledgement) -> Result<bool> {
        if !self.validate_update(&acknowledgement)? {
            return Ok(false);
        }
        let sender = acknowledgement.header.sender;
        let blocks_hash = acknowledgement.body.blocks_hash;
        if let Some(previous) = self.acknowledgements.insert(sender, acknowledgement) {
            decrement_count_u32(&mut self.count, previous.body.blocks_hash);
        }
        let count = self.count.entry(blocks_hash).or_default();
        *count = count.checked_add(1).ok_or_else(|| {
            BlossomError::InvalidConfiguration("trusted acknowledgement count overflow".to_string())
        })?;
        Ok(true)
    }

    pub fn consensus_hash(&self) -> Option<HashType> {
        self.count
            .iter()
            .find_map(|(hash, count)| (*count >= self.supermajority).then_some(*hash))
    }

    pub fn consensus_body(&self) -> Option<&VerificationBody> {
        let hash = self.consensus_hash()?;
        self.acknowledgements
            .values()
            .find(|acknowledgement| acknowledgement.body.blocks_hash == hash)
            .map(|acknowledgement| &acknowledgement.body)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TrustedConfirmationCount {
    pub confirmations: BTreeMap<PubKey, Verification>,
    pub count: BTreeMap<HashType, u32>,
    pub quorum: u32,
    pub supermajority: u32,
}

impl TrustedConfirmationCount {
    pub fn validate_update(&self, confirmation: &Verification) -> Result<bool> {
        let sender = confirmation.header.sender;
        let blocks_hash = confirmation.body.blocks_hash;
        if let Some(previous) = self.confirmations.get(&sender) {
            if previous.body.blocks_hash != blocks_hash
                || previous.body.blocks != confirmation.body.blocks
            {
                return Err(BlossomError::WireProtocol(
                    "trusted member confirmed two candidates for one round".to_string(),
                ));
            }
            return Ok(false);
        }
        Ok(true)
    }

    pub fn record(&mut self, confirmation: Verification) -> Result<bool> {
        if !self.validate_update(&confirmation)? {
            return Ok(false);
        }
        let sender = confirmation.header.sender;
        let blocks_hash = confirmation.body.blocks_hash;
        self.confirmations.insert(sender, confirmation);
        let count = self.count.entry(blocks_hash).or_default();
        *count = count.checked_add(1).ok_or_else(|| {
            BlossomError::InvalidConfiguration("trusted confirmation count overflow".to_string())
        })?;
        Ok(true)
    }

    pub fn consensus_hash(&self) -> Option<HashType> {
        self.count
            .iter()
            .find_map(|(hash, count)| (*count >= self.supermajority).then_some(*hash))
    }
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
        received_dispatch_identities: BTreeMap::new(),
        pending_dispatches: vec![],
        pending_blocks: BTreeMap::new(),
        verified_signature_trees: BTreeMap::new(),
        verified_signature_tree_hashes: BTreeMap::new(),
        verified_blocks: BTreeMap::new(),
        equivocating_validators: BTreeSet::new(),
        processed_txs: HashMap::new(),
        last_signature_tree: Default::default(),
        verified_blocks_hash: Default::default(),
        local_dispatch: None,
        dispatch_retry: false,
        trusted_acknowledgements: init_trusted_acknowledgements(quorum),
        trusted_confirmations: init_trusted_confirmations(quorum),
        pending_trusted_acknowledgements: BTreeMap::new(),
        pending_trusted_confirmations: BTreeMap::new(),
        last_trusted_acknowledgement_hash: None,
        trusted_acknowledgement_retry: None,
        trusted_confirmation_retry: None,
        verifications: init_verifications(quorum),
        verification_sent: false,
        verification_retry: false,
        proposals: init_proposals(quorum),
        proposal_sent: false,
        proposal_retry: false,
        pending_proposals: BTreeMap::new(),
        pending_commits: BTreeMap::new(),
        local_commit: None,
        commit_senders: BTreeSet::new(),
        commit_true_senders: BTreeSet::new(),
        epoch_signatures: BTreeMap::new(),
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

pub fn init_trusted_acknowledgements(quorum: u32) -> TrustedAcknowledgementCount {
    TrustedAcknowledgementCount {
        acknowledgements: BTreeMap::new(),
        count: BTreeMap::new(),
        quorum,
        supermajority: supermajority_count(quorum as usize) as u32,
    }
}

pub fn init_trusted_confirmations(quorum: u32) -> TrustedConfirmationCount {
    TrustedConfirmationCount {
        confirmations: BTreeMap::new(),
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

pub(crate) fn block_merkle_root(blocks: &BTreeMap<HashType, Block>) -> HashType {
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

fn build_verified_epoch(
    previous: &Epoch,
    blocks: BTreeMap<HashType, Block>,
    removal_policy: ConsensusNodeRemovalPolicy,
) -> Epoch {
    let nonce = previous.body.nonce.new_next();
    let (legacy_verifiers, _) = apply_epoch_membership_transition(
        &previous.body.verifiers,
        &blocks,
        previous.hash,
        nonce,
        removal_policy,
    );
    let (members, verifiers) = apply_epoch_member_registry_transition(
        &previous.body.members,
        &legacy_verifiers,
        &blocks,
        previous.body.group_id,
        previous.hash,
    );
    Epoch {
        hash: HashType::default(),
        signatures: BTreeMap::new(),
        body: EpochBody {
            group_id: previous.body.group_id,
            members,
            verifiers,
            last_epoch: previous.hash,
            previous_nonce: Some(previous.body.nonce),
            nonce,
            merkle_root: block_merkle_root(&blocks),
            blocks,
            consensus_parameters: Some(previous.body.effective_consensus_parameters()),
        },
    }
}

pub(crate) fn validate_genesis_anchor(
    genesis: &Epoch,
    expected_group: ConsensusGroupId,
) -> Result<()> {
    if genesis.body.group_id != expected_group
        || genesis.body.nonce != Nonce::default()
        || genesis.body.previous_nonce.is_some()
        || genesis.body.last_epoch != HashType::default()
        || genesis.hash != HashType::hash(&genesis.body.to_bytes())
        || genesis.body.merkle_root != block_merkle_root(&genesis.body.blocks)
        || !verifier_sets_equal(
            &genesis.body.members.active_validators(),
            &genesis.body.verifiers,
        )
    {
        return Err(BlossomError::WireProtocol(
            "invalid genesis anchor".to_string(),
        ));
    }
    for (hash, block) in &genesis.body.blocks {
        block.verify_integrity_with_hash(*hash)?;
    }
    Ok(())
}

pub(crate) fn validate_certified_extension(
    previous: &Epoch,
    epoch: &Epoch,
    removal_policy: ConsensusNodeRemovalPolicy,
) -> Result<()> {
    if epoch.body.group_id != previous.body.group_id
        || epoch.body.last_epoch != previous.hash
        || epoch.body.previous_nonce != Some(previous.body.nonce)
        || epoch.body.nonce != previous.body.nonce.new_next()
        || epoch.body.effective_consensus_parameters()
            != previous.body.effective_consensus_parameters()
    {
        return Err(BlossomError::InvalidEpochNonce);
    }
    for (hash, block) in &epoch.body.blocks {
        if block.body.last_epoch != previous.hash
            || block.body.nonce != epoch.body.nonce
            || !previous.body.verifiers.contains_key(&block.body.validator)
        {
            return Err(BlossomError::UnknownSender);
        }
        block.verify_integrity_with_hash(*hash)?;
    }
    if epoch.body.merkle_root != block_merkle_root(&epoch.body.blocks) {
        return Err(BlossomError::InvalidBlockHash);
    }
    let expected = build_verified_epoch(previous, epoch.body.blocks.clone(), removal_policy);
    if epoch.body.members != expected.body.members
        || !verifier_sets_equal(&epoch.body.verifiers, &expected.body.verifiers)
    {
        return Err(BlossomError::WireProtocol(
            "certified epoch membership transition mismatch".to_string(),
        ));
    }
    if epoch.hash != HashType::hash(&epoch.body.to_bytes()) {
        return Err(BlossomError::InvalidBlockHash);
    }
    epoch.verify_certificate(previous)
}

fn verifier_sets_equal(
    left: &IndexTreeMap<PubKey, NodeIdentity>,
    right: &IndexTreeMap<PubKey, NodeIdentity>,
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right.iter()).all(
            |((left_key, left_value), (right_key, right_value))| {
                left_key == right_key && left_value.public_only() == right_value.public_only()
            },
        )
}

#[cfg(test)]
mod tests;
