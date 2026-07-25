//! Experimental append-only DAG storage beneath trusted Blossom ordering.
//!
//! This module deliberately does not define an alternative finality protocol.
//! Immutable per-writer vertices are disseminated independently, while compact
//! frontier candidates still pass through Blossom's sequential hierarchical
//! acknowledgement and confirmation rounds. Only the final configured round
//! may append a hash/nonce-linked checkpoint.
//!
//! The experiment is feature-gated and has no wire integration. Verified
//! Blossom, trusted-direct epochs, and the high-availability protocol do not
//! consult these types.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::time::Instant;

use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use serde::{Deserialize, Serialize};

use crate::algorithm::{
    QuorumSize, find_round_number_with_size, select_quorums_from_index_tree_with_size,
    select_quorums_with_size, supermajority_count,
};
use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{HashType, ProtocolHasher};
use crate::nonce::Nonce;

const VERTEX_DOMAIN: &[u8] = b"blossom/trusted-checkpoint-dag/vertex/v1";
const CANDIDATE_DOMAIN: &[u8] = b"blossom/trusted-checkpoint-dag/candidate/v1";
const FRONTIER_DOMAIN: &[u8] = b"blossom/trusted-checkpoint-dag/frontier/v1";
const ORDER_DOMAIN: &[u8] = b"blossom/trusted-checkpoint-dag/order/v1";
const CHECKPOINT_DOMAIN: &[u8] = b"blossom/trusted-checkpoint-dag/checkpoint/v1";
const MEMBERSHIP_DOMAIN: &[u8] = b"blossom/trusted-checkpoint-dag/membership/v1";
const EXPERIMENT_VERTEX_DOMAIN: &[u8] = b"blossom/trusted-checkpoint-dag/experiment-vertex/v1";

/// Smallest logical population supported by Global Blossom.
///
/// Only committed Global Blossom member identities count toward this
/// population. HA memberships are independent and never contribute votes to
/// this threshold. Six is the base trusted quorum width.
pub const MIN_GLOBAL_BLOSSOM_PARTICIPANTS: usize = 6;

/// One immutable payload reference in an origin's append-only chain.
///
/// `origin_parent` imposes only per-writer order. It intentionally does not
/// contain an `O(N)` list of previous-round DAG parents. Global order is
/// assigned later by the sequential quorum checkpoint.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrustedDagVertexBody {
    pub group_id: ConsensusGroupId,
    pub membership_generation: u64,
    pub origin: PubKey,
    pub origin_sequence: u64,
    pub origin_parent: Option<HashType>,
    pub anchor_checkpoint_hash: HashType,
    pub anchor_checkpoint_nonce: Nonce,
    pub payload_root: HashType,
    pub command_count: u32,
    pub byte_length: u64,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrustedDagVertex {
    pub hash: HashType,
    pub body: TrustedDagVertexBody,
}

impl TrustedDagVertex {
    pub fn new(body: TrustedDagVertexBody) -> Result<Self> {
        let hash = protocol_commitment(VERTEX_DOMAIN, &body)?;
        Ok(Self { hash, body })
    }

    pub fn validate_hash(&self) -> Result<()> {
        if self.hash != protocol_commitment(VERTEX_DOMAIN, &self.body)? {
            return Err(BlossomError::InvalidBlockHash);
        }
        Ok(())
    }
}

/// Highest contiguous vertex committed for one writer.
#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct TrustedDagFrontierEntry {
    pub origin: PubKey,
    pub sequence: u64,
    pub head_hash: HashType,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrustedDagCandidateBody {
    pub group_id: ConsensusGroupId,
    pub membership_generation: u64,
    pub previous_checkpoint_hash: HashType,
    pub previous_checkpoint_nonce: Nonce,
    pub checkpoint_nonce: Nonce,
    /// Full frontier, sorted by origin. Entries for origins with no committed
    /// vertex are omitted.
    pub frontier: Vec<TrustedDagFrontierEntry>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrustedDagCandidate {
    pub digest: HashType,
    pub body: TrustedDagCandidateBody,
}

impl TrustedDagCandidate {
    fn new(body: TrustedDagCandidateBody) -> Result<Self> {
        let digest = protocol_commitment(CANDIDATE_DOMAIN, &body)?;
        Ok(Self { digest, body })
    }

    pub fn validate_digest(&self) -> Result<()> {
        if self.digest != protocol_commitment(CANDIDATE_DOMAIN, &self.body)? {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG candidate digest does not bind its frontier".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrustedDagCheckpointBody {
    pub group_id: ConsensusGroupId,
    pub membership_generation: u64,
    pub membership_root: HashType,
    pub previous_checkpoint_hash: HashType,
    pub previous_checkpoint_nonce: Option<Nonce>,
    pub nonce: Nonce,
    pub candidate_digest: HashType,
    pub frontier_root: HashType,
    pub ordered_delta_root: HashType,
    pub ordered_vertex_count: u64,
    pub configured_quorum_size: u64,
    pub sequential_rounds: u8,
    pub frontier: Vec<TrustedDagFrontierEntry>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrustedDagCheckpoint {
    pub hash: HashType,
    pub body: TrustedDagCheckpointBody,
}

impl TrustedDagCheckpoint {
    fn new(body: TrustedDagCheckpointBody) -> Result<Self> {
        let hash = protocol_commitment(CHECKPOINT_DOMAIN, &body)?;
        Ok(Self { hash, body })
    }

    pub fn validate_hash(&self) -> Result<()> {
        if self.hash != protocol_commitment(CHECKPOINT_DOMAIN, &self.body)? {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG checkpoint hash does not bind its body".to_string(),
            ));
        }
        Ok(())
    }

    /// Validates the exact ordered vertex delta returned with finalization.
    ///
    /// This lets application-level coordination layers consume Global Blossom
    /// output without becoming part of Blossom's quorum or round state.
    pub fn validate_ordered_delta(&self, ordered_vertices: &[HashType]) -> Result<()> {
        let ordered_vertex_count = u64::try_from(ordered_vertices.len()).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "trusted DAG ordered delta is too large for its checkpoint".to_string(),
            )
        })?;
        if self.body.ordered_vertex_count != ordered_vertex_count
            || self.body.ordered_delta_root
                != protocol_commitment(ORDER_DOMAIN, &ordered_vertices.to_vec())?
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG ordered vertex delta does not match its checkpoint".to_string(),
            ));
        }
        Ok(())
    }
}

/// The only durable choice a trusted member may make in one sequential
/// hierarchical round.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrustedDagRoundLock {
    pub previous_checkpoint_hash: HashType,
    pub previous_checkpoint_nonce: Nonce,
    pub checkpoint_nonce: Nonce,
    pub round: u8,
    pub candidate: TrustedDagCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedDagIngestOutcome {
    Stored { activated: usize },
    PendingParent,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedDagRoundCompletion {
    Pending,
    Advanced {
        next_round: u8,
    },
    Finalized {
        checkpoint: Box<TrustedDagCheckpoint>,
        ordered_vertices: Vec<HashType>,
    },
}

#[derive(Debug, Clone)]
struct TrustedDagRoundState {
    expected_members: Vec<PubKey>,
    acknowledgements: BTreeMap<PubKey, TrustedDagCandidate>,
    acknowledgement_counts: BTreeMap<HashType, usize>,
    lock: Option<TrustedDagRoundLock>,
    confirmations: BTreeMap<PubKey, HashType>,
    confirmation_counts: BTreeMap<HashType, usize>,
    completed: bool,
}

impl TrustedDagRoundState {
    fn new(expected_members: Vec<PubKey>) -> Self {
        Self {
            expected_members,
            acknowledgements: BTreeMap::new(),
            acknowledgement_counts: BTreeMap::new(),
            lock: None,
            confirmations: BTreeMap::new(),
            confirmation_counts: BTreeMap::new(),
            completed: false,
        }
    }

    fn threshold(&self) -> usize {
        supermajority_count(self.expected_members.len())
    }
}

/// In-memory protocol experiment for one trusted Blossom member.
///
/// The type intentionally models persistence boundaries through serializable
/// [`TrustedDagRoundLock`] values but does not replace `TrustedEpochLog`.
/// Production wire/storage integration is a separate gate after this
/// experiment demonstrates useful scaling.
#[derive(Debug, Clone)]
pub struct TrustedCheckpointDag {
    local_member: PubKey,
    members: Vec<PubKey>,
    group_id: ConsensusGroupId,
    membership_generation: u64,
    membership_root: HashType,
    quorum_size: QuorumSize,
    shuffle: bool,
    vertices: BTreeMap<HashType, TrustedDagVertex>,
    origin_index: BTreeMap<(PubKey, u64), HashType>,
    pending_vertices: BTreeMap<HashType, TrustedDagVertex>,
    pending_origins: BTreeMap<(PubKey, u64), HashType>,
    pending_by_parent: BTreeMap<HashType, BTreeSet<HashType>>,
    checkpoints: Vec<TrustedDagCheckpoint>,
    round_states: BTreeMap<u8, TrustedDagRoundState>,
}

impl TrustedCheckpointDag {
    pub fn new(
        local_member: PubKey,
        members: impl IntoIterator<Item = PubKey>,
        group_id: ConsensusGroupId,
        membership_generation: u64,
        quorum_size: QuorumSize,
        shuffle: bool,
    ) -> Result<Self> {
        let mut members = members.into_iter().collect::<Vec<_>>();
        members.sort_unstable();
        members.dedup();
        if members.is_empty() || !members.contains(&local_member) {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG membership must contain the local member".to_string(),
            ));
        }
        QuorumSize::new(quorum_size.get())?;
        let minimum_members = quorum_size.get().max(MIN_GLOBAL_BLOSSOM_PARTICIPANTS);
        if members.len() < minimum_members {
            return Err(BlossomError::InvalidConfiguration(format!(
                "Global Blossom requires at least {minimum_members} logical participants \
                     (minimum six and at least the configured quorum branching factor); use HA \
                     for smaller clusters"
            )));
        }
        let membership_root = protocol_commitment(MEMBERSHIP_DOMAIN, &members)?;
        let sequential_rounds = round_count(members.len(), quorum_size)?;
        let frontier = Vec::new();
        let body = TrustedDagCheckpointBody {
            group_id,
            membership_generation,
            membership_root,
            previous_checkpoint_hash: HashType::default(),
            previous_checkpoint_nonce: None,
            nonce: Nonce::new(0),
            candidate_digest: HashType::default(),
            frontier_root: protocol_commitment(FRONTIER_DOMAIN, &frontier)?,
            ordered_delta_root: protocol_commitment(ORDER_DOMAIN, &Vec::<HashType>::new())?,
            ordered_vertex_count: 0,
            configured_quorum_size: u64::try_from(quorum_size.get()).map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "trusted DAG quorum size does not fit checkpoint encoding".to_string(),
                )
            })?,
            sequential_rounds,
            frontier,
        };
        let genesis = TrustedDagCheckpoint::new(body)?;
        Ok(Self {
            local_member,
            members,
            group_id,
            membership_generation,
            membership_root,
            quorum_size,
            shuffle,
            vertices: BTreeMap::new(),
            origin_index: BTreeMap::new(),
            pending_vertices: BTreeMap::new(),
            pending_origins: BTreeMap::new(),
            pending_by_parent: BTreeMap::new(),
            checkpoints: vec![genesis],
            round_states: BTreeMap::new(),
        })
    }

    pub fn head(&self) -> &TrustedDagCheckpoint {
        self.checkpoints
            .last()
            .expect("trusted DAG always contains its genesis checkpoint")
    }

    pub fn checkpoints(&self) -> &[TrustedDagCheckpoint] {
        &self.checkpoints
    }

    pub fn vertex(&self, hash: &HashType) -> Option<&TrustedDagVertex> {
        self.vertices.get(hash)
    }

    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }

    pub fn pending_vertex_count(&self) -> usize {
        self.pending_vertices.len()
    }

    pub fn sequential_round_count(&self) -> u8 {
        self.head().body.sequential_rounds
    }

    pub fn expected_round_members(&self, round: u8) -> Result<Vec<PubKey>> {
        let rounds = select_quorums_with_size(
            self.members.iter().copied(),
            &self.local_member,
            self.head().hash,
            self.shuffle,
            self.quorum_size,
        );
        rounds.get(usize::from(round)).cloned().ok_or_else(|| {
            BlossomError::InvalidConfiguration(format!(
                "trusted DAG round {round} is outside the sequential topology"
            ))
        })
    }

    pub fn round_threshold(&self, round: u8) -> Result<usize> {
        self.expected_round_members(round)
            .map(|members| supermajority_count(members.len()))
    }

    pub fn ingest_vertex(&mut self, vertex: TrustedDagVertex) -> Result<TrustedDagIngestOutcome> {
        vertex.validate_hash()?;
        self.validate_vertex_envelope(&vertex)?;
        let identity = (vertex.body.origin, vertex.body.origin_sequence);
        if let Some(existing) = self
            .origin_index
            .get(&identity)
            .or_else(|| self.pending_origins.get(&identity))
        {
            if *existing == vertex.hash {
                return Ok(TrustedDagIngestOutcome::Duplicate);
            }
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG origin reused one sequence for conflicting bytes".to_string(),
            ));
        }
        if self.vertices.contains_key(&vertex.hash)
            || self.pending_vertices.contains_key(&vertex.hash)
        {
            return Ok(TrustedDagIngestOutcome::Duplicate);
        }

        if vertex.body.origin_sequence > 1 {
            let parent = vertex
                .body
                .origin_parent
                .expect("non-initial vertex parent checked by envelope validation");
            if !self.vertices.contains_key(&parent) {
                self.pending_origins.insert(identity, vertex.hash);
                self.pending_by_parent
                    .entry(parent)
                    .or_default()
                    .insert(vertex.hash);
                self.pending_vertices.insert(vertex.hash, vertex);
                return Ok(TrustedDagIngestOutcome::PendingParent);
            }
        }

        let activated = self.activate_vertex_and_descendants(vertex)?;
        Ok(TrustedDagIngestOutcome::Stored { activated })
    }

    pub fn build_candidate(
        &self,
        proposed_heads: impl IntoIterator<Item = HashType>,
    ) -> Result<TrustedDagCandidate> {
        let mut frontier = frontier_map(&self.head().body.frontier);
        for hash in proposed_heads {
            let vertex = self.vertices.get(&hash).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted DAG candidate references an unavailable vertex".to_string(),
                )
            })?;
            match frontier.get(&vertex.body.origin) {
                Some(previous) if previous.sequence > vertex.body.origin_sequence => {
                    let proposed_ancestor = TrustedDagFrontierEntry {
                        origin: vertex.body.origin,
                        sequence: vertex.body.origin_sequence,
                        head_hash: hash,
                    };
                    self.require_descendant(previous, Some(proposed_ancestor))?;
                }
                Some(previous) if previous.sequence == vertex.body.origin_sequence => {
                    if previous.head_hash != hash {
                        return Err(BlossomError::InvalidConfiguration(
                            "trusted DAG candidate conflicts at one origin sequence".to_string(),
                        ));
                    }
                }
                _ => {
                    frontier.insert(
                        vertex.body.origin,
                        TrustedDagFrontierEntry {
                            origin: vertex.body.origin,
                            sequence: vertex.body.origin_sequence,
                            head_hash: hash,
                        },
                    );
                }
            }
        }
        let body = TrustedDagCandidateBody {
            group_id: self.group_id,
            membership_generation: self.membership_generation,
            previous_checkpoint_hash: self.head().hash,
            previous_checkpoint_nonce: self.head().body.nonce,
            checkpoint_nonce: self.head().body.nonce.new_next(),
            frontier: frontier.into_values().collect(),
        };
        let candidate = TrustedDagCandidate::new(body)?;
        self.validate_candidate(&candidate)?;
        Ok(candidate)
    }

    pub fn merge_candidates<'a>(
        &self,
        candidates: impl IntoIterator<Item = &'a TrustedDagCandidate>,
    ) -> Result<TrustedDagCandidate> {
        let mut heads = BTreeMap::<PubKey, TrustedDagFrontierEntry>::new();
        for candidate in candidates {
            self.validate_candidate(candidate)?;
            for entry in &candidate.body.frontier {
                match heads.get(&entry.origin) {
                    Some(existing) if existing.sequence > entry.sequence => {}
                    Some(existing) if existing.sequence == entry.sequence => {
                        if existing.head_hash != entry.head_hash {
                            return Err(BlossomError::InvalidConfiguration(
                                "trusted DAG candidates conflict at one frontier position"
                                    .to_string(),
                            ));
                        }
                    }
                    _ => {
                        heads.insert(entry.origin, *entry);
                    }
                }
            }
        }
        self.build_candidate(heads.into_values().map(|entry| entry.head_hash))
    }

    /// Records a mutable, monotonic acknowledgement for one exact frontier.
    pub fn record_acknowledgement(
        &mut self,
        round: u8,
        sender: PubKey,
        candidate: TrustedDagCandidate,
    ) -> Result<bool> {
        self.validate_candidate(&candidate)?;
        self.validate_round_progression(round, &candidate)?;
        self.ensure_round_state(round)?;

        let previous = self
            .round_states
            .get(&round)
            .and_then(|state| state.acknowledgements.get(&sender))
            .cloned();
        {
            let state = self
                .round_states
                .get(&round)
                .expect("trusted DAG round state initialized above");
            if !state.expected_members.contains(&sender) {
                return Err(BlossomError::UnknownSender);
            }
            if let Some(lock) = &state.lock
                && lock.candidate.digest != candidate.digest
            {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG acknowledgement changed after the local round lock".to_string(),
                ));
            }
        }
        if let Some(previous) = &previous {
            if previous.digest == candidate.digest {
                return Ok(false);
            }
            if !self.candidate_extends(previous, &candidate)? {
                return Err(BlossomError::WireProtocol(
                    "trusted DAG acknowledgement frontier may only grow".to_string(),
                ));
            }
        }

        let state = self
            .round_states
            .get_mut(&round)
            .expect("trusted DAG round state initialized above");
        if let Some(previous) = state.acknowledgements.insert(sender, candidate.clone()) {
            decrement_count(&mut state.acknowledgement_counts, previous.digest);
        }
        *state
            .acknowledgement_counts
            .entry(candidate.digest)
            .or_default() += 1;
        Ok(true)
    }

    /// Creates the local immutable confirmation lock after an acknowledgement
    /// supermajority names one exact candidate.
    pub fn try_lock_round(&mut self, round: u8) -> Result<Option<TrustedDagRoundLock>> {
        self.ensure_round_state(round)?;
        if let Some(lock) = self
            .round_states
            .get(&round)
            .and_then(|state| state.lock.clone())
        {
            return Ok(Some(lock));
        }
        let (digest, candidate) = {
            let state = self
                .round_states
                .get(&round)
                .expect("trusted DAG round state initialized above");
            let Some(digest) = state
                .acknowledgement_counts
                .iter()
                .find_map(|(digest, count)| (*count >= state.threshold()).then_some(*digest))
            else {
                return Ok(None);
            };
            let candidate = state
                .acknowledgements
                .values()
                .find(|candidate| candidate.digest == digest)
                .cloned()
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "trusted DAG acknowledgement count is missing its candidate".to_string(),
                    )
                })?;
            (digest, candidate)
        };
        let lock = TrustedDagRoundLock {
            previous_checkpoint_hash: self.head().hash,
            previous_checkpoint_nonce: self.head().body.nonce,
            checkpoint_nonce: self.head().body.nonce.new_next(),
            round,
            candidate,
        };
        let local_member = self.local_member;
        let state = self
            .round_states
            .get_mut(&round)
            .expect("trusted DAG round state initialized above");
        state.lock = Some(lock.clone());
        state.confirmations.insert(local_member, digest);
        *state.confirmation_counts.entry(digest).or_default() += 1;
        Ok(Some(lock))
    }

    /// Restores a previously fsynced local lock. Restoring round `r > 0`
    /// implies that the persisted lower round was completed before round `r`
    /// could have been entered, matching the existing trusted epoch log.
    pub fn restore_round_lock(&mut self, lock: TrustedDagRoundLock) -> Result<()> {
        self.validate_candidate(&lock.candidate)?;
        if lock.round >= self.sequential_round_count() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG restored round is outside the sequential topology".to_string(),
            ));
        }
        if lock.previous_checkpoint_hash != self.head().hash
            || lock.previous_checkpoint_nonce != self.head().body.nonce
            || lock.checkpoint_nonce != self.head().body.nonce.new_next()
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG round lock targets a different checkpoint".to_string(),
            ));
        }
        if lock.round > 0 {
            let previous_lock = self
                .round_states
                .get(&(lock.round - 1))
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "trusted DAG restored locks must be contiguous".to_string(),
                    )
                })?
                .lock
                .as_ref()
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "trusted DAG restored round is missing its predecessor lock".to_string(),
                    )
                })?
                .clone();
            if !self.candidate_extends(&previous_lock.candidate, &lock.candidate)? {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG restored round did not carry its predecessor frontier".to_string(),
                ));
            }
            self.round_states
                .get_mut(&(lock.round - 1))
                .expect("trusted DAG predecessor checked above")
                .completed = true;
        }
        self.ensure_round_state(lock.round)?;
        let local_member = self.local_member;
        let state = self
            .round_states
            .get_mut(&lock.round)
            .expect("trusted DAG restored round initialized above");
        if let Some(existing) = &state.lock {
            if existing != &lock {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG restart attempted to replace an immutable round lock".to_string(),
                ));
            }
            return Ok(());
        }
        let digest = lock.candidate.digest;
        state.lock = Some(lock);
        state.confirmations.insert(local_member, digest);
        *state.confirmation_counts.entry(digest).or_default() += 1;
        Ok(())
    }

    /// Records one member's immutable confirmation. A member may not replace
    /// its digest for the round.
    pub fn record_confirmation(
        &mut self,
        round: u8,
        sender: PubKey,
        candidate_digest: HashType,
    ) -> Result<bool> {
        self.ensure_round_state(round)?;
        let state = self
            .round_states
            .get_mut(&round)
            .expect("trusted DAG round state initialized above");
        if !state.expected_members.contains(&sender) {
            return Err(BlossomError::UnknownSender);
        }
        if let Some(previous) = state.confirmations.get(&sender) {
            if *previous != candidate_digest {
                return Err(BlossomError::WireProtocol(
                    "trusted DAG member confirmed two candidates for one round".to_string(),
                ));
            }
            return Ok(false);
        }
        state.confirmations.insert(sender, candidate_digest);
        *state
            .confirmation_counts
            .entry(candidate_digest)
            .or_default() += 1;
        Ok(true)
    }

    pub fn try_complete_round(&mut self, round: u8) -> Result<TrustedDagRoundCompletion> {
        self.ensure_round_state(round)?;
        let (candidate, complete) = {
            let state = self
                .round_states
                .get(&round)
                .expect("trusted DAG round state initialized above");
            let Some(lock) = &state.lock else {
                return Ok(TrustedDagRoundCompletion::Pending);
            };
            let count = state
                .confirmation_counts
                .get(&lock.candidate.digest)
                .copied()
                .unwrap_or_default();
            (lock.candidate.clone(), count >= state.threshold())
        };
        if !complete {
            return Ok(TrustedDagRoundCompletion::Pending);
        }
        self.round_states
            .get_mut(&round)
            .expect("trusted DAG round state initialized above")
            .completed = true;

        let final_round = self.sequential_round_count().saturating_sub(1);
        if round < final_round {
            return Ok(TrustedDagRoundCompletion::Advanced {
                next_round: round + 1,
            });
        }
        if round != final_round {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG attempted to complete a round beyond the topology".to_string(),
            ));
        }

        let ordered_vertices = self.ordered_delta(&candidate)?;
        let checkpoint = self.checkpoint_for_candidate(&candidate, &ordered_vertices)?;
        self.checkpoints.push(checkpoint.clone());
        self.round_states.clear();
        Ok(TrustedDagRoundCompletion::Finalized {
            checkpoint: Box::new(checkpoint),
            ordered_vertices,
        })
    }

    fn validate_vertex_envelope(&self, vertex: &TrustedDagVertex) -> Result<()> {
        if vertex.body.group_id != self.group_id
            || vertex.body.membership_generation != self.membership_generation
            || !self.members.contains(&vertex.body.origin)
            || vertex.body.origin_sequence == 0
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG vertex is outside the committed group or membership".to_string(),
            ));
        }
        let anchor_exists = self.checkpoints.iter().any(|checkpoint| {
            checkpoint.hash == vertex.body.anchor_checkpoint_hash
                && checkpoint.body.nonce == vertex.body.anchor_checkpoint_nonce
        });
        if !anchor_exists {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG vertex references an unknown checkpoint anchor".to_string(),
            ));
        }
        match (vertex.body.origin_sequence, vertex.body.origin_parent) {
            (1, None) => Ok(()),
            (1, Some(_)) => Err(BlossomError::InvalidConfiguration(
                "trusted DAG first origin vertex must not have a parent".to_string(),
            )),
            (_, Some(_)) => Ok(()),
            (_, None) => Err(BlossomError::InvalidConfiguration(
                "trusted DAG non-initial origin vertex is missing its parent".to_string(),
            )),
        }
    }

    fn activate_vertex_and_descendants(&mut self, vertex: TrustedDagVertex) -> Result<usize> {
        let mut stack = vec![vertex];
        let mut activated = 0usize;
        while let Some(vertex) = stack.pop() {
            self.validate_parent_link(&vertex)?;
            let identity = (vertex.body.origin, vertex.body.origin_sequence);
            self.pending_origins.remove(&identity);
            self.pending_vertices.remove(&vertex.hash);
            self.origin_index.insert(identity, vertex.hash);
            let hash = vertex.hash;
            self.vertices.insert(hash, vertex);
            activated = activated.saturating_add(1);

            let children = self.pending_by_parent.remove(&hash).unwrap_or_default();
            for child_hash in children {
                if let Some(child) = self.pending_vertices.remove(&child_hash) {
                    stack.push(child);
                }
            }
        }
        Ok(activated)
    }

    fn validate_parent_link(&self, vertex: &TrustedDagVertex) -> Result<()> {
        if vertex.body.origin_sequence == 1 {
            return Ok(());
        }
        let parent_hash = vertex.body.origin_parent.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted DAG non-initial vertex is missing its parent".to_string(),
            )
        })?;
        let parent = self.vertices.get(&parent_hash).ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted DAG vertex parent is not available".to_string(),
            )
        })?;
        if parent.body.origin != vertex.body.origin
            || parent.body.membership_generation != vertex.body.membership_generation
            || parent.body.origin_sequence.checked_add(1) != Some(vertex.body.origin_sequence)
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG origin parent does not immediately precede its child".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_candidate(&self, candidate: &TrustedDagCandidate) -> Result<()> {
        candidate.validate_digest()?;
        if candidate.body.group_id != self.group_id
            || candidate.body.membership_generation != self.membership_generation
            || candidate.body.previous_checkpoint_hash != self.head().hash
            || candidate.body.previous_checkpoint_nonce != self.head().body.nonce
            || candidate.body.checkpoint_nonce != self.head().body.nonce.new_next()
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG candidate does not extend the current checkpoint".to_string(),
            ));
        }
        let mut previous_origin = None;
        for entry in &candidate.body.frontier {
            if previous_origin.is_some_and(|origin| origin >= entry.origin) {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG candidate frontier must be strictly origin-sorted".to_string(),
                ));
            }
            previous_origin = Some(entry.origin);
            if !self.members.contains(&entry.origin) {
                return Err(BlossomError::UnknownSender);
            }
            let vertex = self.vertices.get(&entry.head_hash).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted DAG candidate frontier head is unavailable".to_string(),
                )
            })?;
            if vertex.body.origin != entry.origin || vertex.body.origin_sequence != entry.sequence {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG frontier entry conflicts with its vertex".to_string(),
                ));
            }
        }
        self.validate_frontier_delta(&candidate.body.frontier)
    }

    fn validate_frontier_delta(&self, frontier: &[TrustedDagFrontierEntry]) -> Result<()> {
        let previous = frontier_map(&self.head().body.frontier);
        let proposed = frontier_map(frontier);
        for previous_entry in previous.values() {
            let Some(next) = proposed.get(&previous_entry.origin) else {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG candidate omitted a committed frontier".to_string(),
                ));
            };
            if next.sequence < previous_entry.sequence
                || (next.sequence == previous_entry.sequence
                    && next.head_hash != previous_entry.head_hash)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG candidate regresses a committed frontier".to_string(),
                ));
            }
        }
        for next in proposed.values() {
            let base = previous.get(&next.origin).copied();
            self.require_descendant(next, base)?;
        }
        Ok(())
    }

    fn require_descendant(
        &self,
        next: &TrustedDagFrontierEntry,
        base: Option<TrustedDagFrontierEntry>,
    ) -> Result<()> {
        if let Some(base) = base
            && next.sequence == base.sequence
        {
            if next.head_hash == base.head_hash {
                return Ok(());
            }
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG frontier conflicts at a committed sequence".to_string(),
            ));
        }
        if base.is_some_and(|base| next.sequence < base.sequence) {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG frontier sequence regressed".to_string(),
            ));
        }

        let mut cursor_hash = next.head_hash;
        let stop_sequence = base.map_or(0, |base| base.sequence);
        loop {
            let cursor = self.vertices.get(&cursor_hash).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted DAG frontier has a missing origin ancestor".to_string(),
                )
            })?;
            if cursor.body.origin != next.origin {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG frontier crossed origin chains".to_string(),
                ));
            }
            if cursor.body.origin_sequence == stop_sequence {
                if base.is_some_and(|base| base.head_hash != cursor_hash) {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted DAG frontier does not descend from its prior head".to_string(),
                    ));
                }
                return Ok(());
            }
            if cursor.body.origin_sequence <= stop_sequence {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted DAG frontier skipped its prior head".to_string(),
                ));
            }
            match cursor.body.origin_parent {
                Some(parent) => cursor_hash = parent,
                None if stop_sequence == 0 && cursor.body.origin_sequence == 1 => return Ok(()),
                None => {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted DAG frontier chain ended before its prior head".to_string(),
                    ));
                }
            }
        }
    }

    fn candidate_extends(
        &self,
        base: &TrustedDagCandidate,
        next: &TrustedDagCandidate,
    ) -> Result<bool> {
        self.validate_candidate(base)?;
        self.validate_candidate(next)?;
        let next_frontier = frontier_map(&next.body.frontier);
        for base_entry in &base.body.frontier {
            let Some(next_entry) = next_frontier.get(&base_entry.origin) else {
                return Ok(false);
            };
            if next_entry.sequence < base_entry.sequence {
                return Ok(false);
            }
            if self
                .require_descendant(next_entry, Some(*base_entry))
                .is_err()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validate_round_progression(&self, round: u8, candidate: &TrustedDagCandidate) -> Result<()> {
        if round >= self.sequential_round_count() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG round is outside the sequential quorum topology".to_string(),
            ));
        }
        if round == 0 {
            return Ok(());
        }
        let previous = self.round_states.get(&(round - 1)).ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted DAG round is missing its sequential predecessor".to_string(),
            )
        })?;
        if !previous.completed {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG cannot skip an incomplete sequential quorum round".to_string(),
            ));
        }
        let lock = previous.lock.as_ref().ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted DAG completed predecessor is missing its durable lock".to_string(),
            )
        })?;
        if !self.candidate_extends(&lock.candidate, candidate)? {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG next round did not carry the confirmed frontier".to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_round_state(&mut self, round: u8) -> Result<()> {
        if self.round_states.contains_key(&round) {
            return Ok(());
        }
        if round >= self.sequential_round_count() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG round is outside the sequential quorum topology".to_string(),
            ));
        }
        let expected_members = self.expected_round_members(round)?;
        self.round_states
            .insert(round, TrustedDagRoundState::new(expected_members));
        Ok(())
    }

    fn ordered_delta(&self, candidate: &TrustedDagCandidate) -> Result<Vec<HashType>> {
        self.validate_candidate(candidate)?;
        let previous = frontier_map(&self.head().body.frontier);
        let mut paths = BTreeMap::<PubKey, Vec<HashType>>::new();
        for entry in &candidate.body.frontier {
            let stop = previous
                .get(&entry.origin)
                .map_or(0, |entry| entry.sequence);
            if entry.sequence == stop {
                continue;
            }
            let mut reverse_path = Vec::new();
            let mut cursor_hash = entry.head_hash;
            loop {
                let cursor = self.vertices.get(&cursor_hash).ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "trusted DAG ordering encountered a missing vertex".to_string(),
                    )
                })?;
                if cursor.body.origin_sequence <= stop {
                    break;
                }
                reverse_path.push(cursor_hash);
                let Some(parent) = cursor.body.origin_parent else {
                    break;
                };
                cursor_hash = parent;
            }
            reverse_path.reverse();
            paths.insert(entry.origin, reverse_path);
        }

        let mut eligible = BinaryHeap::<Reverse<(HashType, PubKey, usize)>>::new();
        for (origin, path) in &paths {
            if let Some(first) = path.first() {
                eligible.push(Reverse((*first, *origin, 0)));
            }
        }
        let expected_count = paths.values().map(Vec::len).sum();
        let mut ordered = Vec::with_capacity(expected_count);
        while let Some(Reverse((hash, origin, index))) = eligible.pop() {
            ordered.push(hash);
            let next_index = index + 1;
            if let Some(next) = paths.get(&origin).and_then(|path| path.get(next_index)) {
                eligible.push(Reverse((*next, origin, next_index)));
            }
        }
        if ordered.len() != expected_count {
            return Err(BlossomError::InvalidConfiguration(
                "trusted DAG deterministic ordering did not cover the candidate closure"
                    .to_string(),
            ));
        }
        Ok(ordered)
    }

    fn checkpoint_for_candidate(
        &self,
        candidate: &TrustedDagCandidate,
        ordered_vertices: &[HashType],
    ) -> Result<TrustedDagCheckpoint> {
        self.validate_candidate(candidate)?;
        let ordered_vertex_count = u64::try_from(ordered_vertices.len()).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "trusted DAG ordered delta is too large for its checkpoint".to_string(),
            )
        })?;
        let body = TrustedDagCheckpointBody {
            group_id: self.group_id,
            membership_generation: self.membership_generation,
            membership_root: self.membership_root,
            previous_checkpoint_hash: self.head().hash,
            previous_checkpoint_nonce: Some(self.head().body.nonce),
            nonce: self.head().body.nonce.new_next(),
            candidate_digest: candidate.digest,
            frontier_root: protocol_commitment(FRONTIER_DOMAIN, &candidate.body.frontier)?,
            ordered_delta_root: protocol_commitment(ORDER_DOMAIN, &ordered_vertices.to_vec())?,
            ordered_vertex_count,
            configured_quorum_size: u64::try_from(self.quorum_size.get()).map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "trusted DAG quorum size does not fit checkpoint encoding".to_string(),
                )
            })?,
            sequential_rounds: self.sequential_round_count(),
            frontier: candidate.body.frontier.clone(),
        };
        TrustedDagCheckpoint::new(body)
    }
}

/// Logical scale report for carrying immutable vertex references through the
/// existing sequential quorum topology.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SequentialQuorumDagReport {
    pub node_count: usize,
    pub configured_quorum_size: usize,
    pub effective_quorum_size: usize,
    pub sequential_rounds: usize,
    pub all_nodes_converged: bool,
    pub finalized_vertex_count: usize,
    pub max_candidate_vertices: usize,
    pub candidate_vertex_occurrences: u128,
    pub all_node_payload_delivery_bytes: u128,
    pub materialized_payload_bytes_on_sequential_path: u128,
    pub hash_reference_bytes_on_sequential_path: u128,
    pub compact_frontier_control_bytes: u128,
    pub hash_reference_path_payload_bytes_avoided: u128,
    pub compact_frontier_path_payload_bytes_avoided: u128,
    pub final_order_root: HashType,
    pub topology_build_nanos: u128,
    pub sequential_reduce_nanos: u128,
}

/// Models one all-writer checkpoint over the real Blossom quorum-selection
/// topology. Vertices begin as independent per-writer bits. Every round unions
/// the candidates held by that round's selected quorum, so the final bitmap is
/// the same exact closure that a compact frontier digest would bind.
pub fn run_sequential_quorum_dag_experiment(
    node_count: usize,
    quorum_size: QuorumSize,
    payload_bytes_per_vertex: usize,
    shuffle: bool,
) -> Result<SequentialQuorumDagReport> {
    let minimum_members = quorum_size.get().max(MIN_GLOBAL_BLOSSOM_PARTICIPANTS);
    if node_count < minimum_members {
        return Err(BlossomError::InvalidConfiguration(format!(
            "Global Blossom scale experiment requires at least {minimum_members} logical participants"
        )));
    }
    QuorumSize::new(quorum_size.get())?;
    let members = experiment_members(node_count);
    let mut member_map = IndexTreeMap::new();
    let mut index_by_member = BTreeMap::new();
    for (index, member) in members.iter().copied().enumerate() {
        member_map.insert(member, ());
        index_by_member.insert(member, index);
    }
    let seed = HashType::hash_slices([
        b"blossom/trusted-checkpoint-dag/experiment-seed/v1".as_slice(),
        &(node_count as u64).to_le_bytes(),
        &(quorum_size.get() as u64).to_le_bytes(),
    ]);

    let topology_started = Instant::now();
    let topologies = members
        .iter()
        .map(|member| {
            select_quorums_from_index_tree_with_size(
                &member_map,
                member,
                seed,
                shuffle,
                quorum_size,
            )
            .into_iter()
            .map(|round| {
                round
                    .into_iter()
                    .map(|member| {
                        index_by_member.get(&member).copied().ok_or_else(|| {
                            BlossomError::InvalidConfiguration(
                                "trusted DAG topology selected an unknown member".to_string(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let topology_build_nanos = topology_started.elapsed().as_nanos();
    let sequential_rounds = topologies.first().map_or(0, Vec::len);
    if sequential_rounds == 0
        || topologies
            .iter()
            .any(|topology| topology.len() != sequential_rounds)
    {
        return Err(BlossomError::InvalidConfiguration(
            "trusted DAG topology does not have a consistent sequential depth".to_string(),
        ));
    }

    let words = node_count.div_ceil(64);
    let mut candidates = vec![vec![0u64; words]; node_count];
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate[index / 64] |= 1u64 << (index % 64);
    }

    let reduce_started = Instant::now();
    let mut candidate_vertex_occurrences = 0u128;
    let mut max_candidate_vertices = 0usize;
    for round in 0..sequential_rounds {
        let mut next = vec![vec![0u64; words]; node_count];
        for node in 0..node_count {
            for peer in &topologies[node][round] {
                for word in 0..words {
                    next[node][word] |= candidates[*peer][word];
                }
            }
            let count = next[node]
                .iter()
                .map(|word| word.count_ones() as usize)
                .sum::<usize>();
            max_candidate_vertices = max_candidate_vertices.max(count);
            candidate_vertex_occurrences =
                candidate_vertex_occurrences.saturating_add(count as u128);
        }
        candidates = next;
    }
    let sequential_reduce_nanos = reduce_started.elapsed().as_nanos();

    let finalized_vertex_count = candidates[0]
        .iter()
        .map(|word| word.count_ones() as usize)
        .sum();
    let all_nodes_converged = candidates
        .iter()
        .all(|candidate| candidate == &candidates[0])
        && finalized_vertex_count == node_count;
    let mut ordered_hashes = members
        .iter()
        .map(|member| {
            HashType::hash_slices([EXPERIMENT_VERTEX_DOMAIN, member.as_ref(), seed.as_ref()])
        })
        .collect::<Vec<_>>();
    ordered_hashes.sort_unstable();
    let final_order_root = protocol_commitment(ORDER_DOMAIN, &ordered_hashes)?;

    let payload_bytes = payload_bytes_per_vertex as u128;
    let all_node_payload_delivery_bytes = (node_count as u128)
        .saturating_mul(node_count as u128)
        .saturating_mul(payload_bytes);
    let materialized_payload_bytes_on_sequential_path =
        candidate_vertex_occurrences.saturating_mul(payload_bytes);
    let hash_reference_bytes_on_sequential_path = candidate_vertex_occurrences.saturating_mul(32);
    // One acknowledgement and one confirmation candidate per member and
    // round. Each carries a full membership bitmap plus one digest.
    let candidate_messages = (node_count as u128)
        .saturating_mul(sequential_rounds as u128)
        .saturating_mul(2);
    let compact_candidate_bytes = (words as u128).saturating_mul(8).saturating_add(32);
    let compact_frontier_control_bytes = candidate_messages.saturating_mul(compact_candidate_bytes);

    Ok(SequentialQuorumDagReport {
        node_count,
        configured_quorum_size: quorum_size.get(),
        effective_quorum_size: quorum_size.effective(node_count),
        sequential_rounds,
        all_nodes_converged,
        finalized_vertex_count,
        max_candidate_vertices,
        candidate_vertex_occurrences,
        all_node_payload_delivery_bytes,
        materialized_payload_bytes_on_sequential_path,
        hash_reference_bytes_on_sequential_path,
        compact_frontier_control_bytes,
        hash_reference_path_payload_bytes_avoided: materialized_payload_bytes_on_sequential_path
            .saturating_sub(hash_reference_bytes_on_sequential_path),
        compact_frontier_path_payload_bytes_avoided: materialized_payload_bytes_on_sequential_path
            .saturating_sub(compact_frontier_control_bytes),
        final_order_root,
        topology_build_nanos,
        sequential_reduce_nanos,
    })
}

fn protocol_commitment<T: BorshSerialize>(domain: &[u8], value: &T) -> Result<HashType> {
    let bytes = borsh::to_vec(value).map_err(|error| {
        BlossomError::InvalidConfiguration(format!(
            "trusted DAG commitment encoding failed: {error}"
        ))
    })?;
    let mut hasher = ProtocolHasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(hasher.finalize())
}

fn frontier_map(entries: &[TrustedDagFrontierEntry]) -> BTreeMap<PubKey, TrustedDagFrontierEntry> {
    entries.iter().map(|entry| (entry.origin, *entry)).collect()
}

fn decrement_count(counts: &mut BTreeMap<HashType, usize>, digest: HashType) {
    match counts.entry(digest) {
        std::collections::btree_map::Entry::Occupied(mut entry) if *entry.get() > 1 => {
            *entry.get_mut() -= 1;
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            entry.remove();
        }
        std::collections::btree_map::Entry::Vacant(_) => {}
    }
}

fn round_count(node_count: usize, quorum_size: QuorumSize) -> Result<u8> {
    let (_, rounds) = find_round_number_with_size(node_count, quorum_size);
    u8::try_from(rounds).map_err(|_| {
        BlossomError::InvalidConfiguration(
            "trusted DAG sequential topology exceeds u8 round encoding".to_string(),
        )
    })
}

fn experiment_members(count: usize) -> Vec<PubKey> {
    let mut members = (0..count)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
            PubKey(bytes)
        })
        .collect::<Vec<_>>();
    members.sort_unstable();
    members
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(count: usize) -> Vec<PubKey> {
        experiment_members(count)
    }

    fn engine(count: usize, quorum_size: usize) -> TrustedCheckpointDag {
        let members = members(count);
        TrustedCheckpointDag::new(
            members[0],
            members,
            ConsensusGroupId::named("trusted-dag-test"),
            7,
            QuorumSize::new(quorum_size).unwrap(),
            false,
        )
        .unwrap()
    }

    fn vertex(
        engine: &TrustedCheckpointDag,
        origin: PubKey,
        sequence: u64,
        parent: Option<HashType>,
        salt: u64,
    ) -> TrustedDagVertex {
        TrustedDagVertex::new(TrustedDagVertexBody {
            group_id: engine.group_id,
            membership_generation: engine.membership_generation,
            origin,
            origin_sequence: sequence,
            origin_parent: parent,
            anchor_checkpoint_hash: engine.checkpoints[0].hash,
            anchor_checkpoint_nonce: engine.checkpoints[0].body.nonce,
            payload_root: HashType::hash(&salt.to_le_bytes()),
            command_count: 1,
            byte_length: 32,
        })
        .unwrap()
    }

    fn lock_and_complete_round(
        engine: &mut TrustedCheckpointDag,
        round: u8,
        candidate: &TrustedDagCandidate,
    ) -> TrustedDagRoundCompletion {
        let expected = engine.expected_round_members(round).unwrap();
        let threshold = supermajority_count(expected.len());
        for member in expected.iter().take(threshold) {
            engine
                .record_acknowledgement(round, *member, candidate.clone())
                .unwrap();
        }
        let lock = engine.try_lock_round(round).unwrap().unwrap();
        for member in expected.iter().take(threshold) {
            engine
                .record_confirmation(round, *member, lock.candidate.digest)
                .unwrap();
        }
        engine.try_complete_round(round).unwrap()
    }

    fn finalize_candidate(
        engine: &mut TrustedCheckpointDag,
        candidate: &TrustedDagCandidate,
    ) -> (TrustedDagCheckpoint, Vec<HashType>) {
        let last_round = engine.sequential_round_count() - 1;
        for round in 0..=last_round {
            match lock_and_complete_round(engine, round, candidate) {
                TrustedDagRoundCompletion::Advanced { next_round } => {
                    assert_eq!(next_round, round + 1);
                }
                TrustedDagRoundCompletion::Finalized {
                    checkpoint,
                    ordered_vertices,
                } => return (*checkpoint, ordered_vertices),
                TrustedDagRoundCompletion::Pending => panic!("round should complete"),
            }
        }
        panic!("topology did not finalize");
    }

    #[test]
    fn parent_before_child_and_child_before_parent_converge() {
        let mut first = engine(6, 6);
        let origin = first.members[0];
        let first_vertex = vertex(&first, origin, 1, None, 1);
        let second_vertex = vertex(&first, origin, 2, Some(first_vertex.hash), 2);

        assert_eq!(
            first.ingest_vertex(second_vertex.clone()).unwrap(),
            TrustedDagIngestOutcome::PendingParent
        );
        assert_eq!(first.pending_vertex_count(), 1);
        assert_eq!(
            first.ingest_vertex(first_vertex.clone()).unwrap(),
            TrustedDagIngestOutcome::Stored { activated: 2 }
        );
        assert_eq!(first.pending_vertex_count(), 0);

        let mut second = engine(6, 6);
        second.ingest_vertex(first_vertex).unwrap();
        second.ingest_vertex(second_vertex).unwrap();
        assert_eq!(first.origin_index, second.origin_index);
    }

    #[test]
    fn origin_sequence_equivocation_is_rejected() {
        let mut dag = engine(6, 6);
        let origin = dag.members[0];
        dag.ingest_vertex(vertex(&dag, origin, 1, None, 1)).unwrap();
        let error = dag
            .ingest_vertex(vertex(&dag, origin, 1, None, 2))
            .unwrap_err();
        assert!(matches!(error, BlossomError::InvalidConfiguration(_)));
    }

    #[test]
    fn acknowledgements_are_monotonic_and_round_locks_are_immutable() {
        let mut dag = engine(6, 6);
        let origins = dag.members.clone();
        let first_vertex = vertex(&dag, origins[0], 1, None, 1);
        let second_vertex = vertex(&dag, origins[1], 1, None, 2);
        dag.ingest_vertex(first_vertex.clone()).unwrap();
        dag.ingest_vertex(second_vertex.clone()).unwrap();
        let first = dag.build_candidate([first_vertex.hash]).unwrap();
        let second = dag
            .build_candidate([first_vertex.hash, second_vertex.hash])
            .unwrap();
        let sender = dag.expected_round_members(0).unwrap()[0];
        dag.record_acknowledgement(0, sender, first.clone())
            .unwrap();
        dag.record_acknowledgement(0, sender, second.clone())
            .unwrap();
        assert!(dag.record_acknowledgement(0, sender, first).is_err());

        let expected = dag.expected_round_members(0).unwrap();
        let threshold = supermajority_count(expected.len());
        for member in expected.iter().take(threshold) {
            dag.record_acknowledgement(0, *member, second.clone())
                .unwrap();
        }
        dag.try_lock_round(0).unwrap().unwrap();
        let smaller = dag.build_candidate([first_vertex.hash]).unwrap();
        assert!(
            dag.record_acknowledgement(0, expected[threshold], smaller)
                .is_err()
        );
    }

    #[test]
    fn confirmation_threshold_is_required_before_advancing() {
        let mut dag = engine(12, 6);
        let origin = dag.members[0];
        let vertex = vertex(&dag, origin, 1, None, 1);
        dag.ingest_vertex(vertex.clone()).unwrap();
        let candidate = dag.build_candidate([vertex.hash]).unwrap();
        let expected = dag.expected_round_members(0).unwrap();
        let threshold = supermajority_count(expected.len());
        for member in expected.iter().take(threshold) {
            dag.record_acknowledgement(0, *member, candidate.clone())
                .unwrap();
        }
        let lock = dag.try_lock_round(0).unwrap().unwrap();
        for member in expected.iter().take(threshold.saturating_sub(1)) {
            dag.record_confirmation(0, *member, lock.candidate.digest)
                .unwrap();
        }
        assert_eq!(
            dag.try_complete_round(0).unwrap(),
            TrustedDagRoundCompletion::Pending
        );
        dag.record_confirmation(0, expected[threshold - 1], lock.candidate.digest)
            .unwrap();
        assert_eq!(
            dag.try_complete_round(0).unwrap(),
            TrustedDagRoundCompletion::Advanced { next_round: 1 }
        );
    }

    #[test]
    fn later_round_must_carry_the_confirmed_frontier() {
        let mut dag = engine(12, 6);
        let origins = dag.members.clone();
        let first_vertex = vertex(&dag, origins[0], 1, None, 1);
        let second_vertex = vertex(&dag, origins[1], 1, None, 2);
        dag.ingest_vertex(first_vertex.clone()).unwrap();
        dag.ingest_vertex(second_vertex).unwrap();
        let first = dag.build_candidate([first_vertex.hash]).unwrap();
        assert!(matches!(
            lock_and_complete_round(&mut dag, 0, &first),
            TrustedDagRoundCompletion::Advanced { .. }
        ));
        let empty = dag.build_candidate([]).unwrap();
        let sender = dag.expected_round_members(1).unwrap()[0];
        assert!(dag.record_acknowledgement(1, sender, empty).is_err());
    }

    #[test]
    fn stable_topological_order_preserves_each_origin_chain() {
        let mut dag = engine(6, 6);
        let origins = dag.members.clone();
        let a1 = vertex(&dag, origins[0], 1, None, 1);
        let a2 = vertex(&dag, origins[0], 2, Some(a1.hash), 2);
        let b1 = vertex(&dag, origins[1], 1, None, 3);
        for vertex in [b1.clone(), a1.clone(), a2.clone()] {
            dag.ingest_vertex(vertex).unwrap();
        }
        let candidate = dag.build_candidate([a2.hash, a1.hash, b1.hash]).unwrap();
        let permuted = dag.build_candidate([b1.hash, a1.hash, a2.hash]).unwrap();
        assert_eq!(candidate, permuted);
        let (_, order) = finalize_candidate(&mut dag, &candidate);
        let a1_position = order.iter().position(|hash| *hash == a1.hash).unwrap();
        let a2_position = order.iter().position(|hash| *hash == a2.hash).unwrap();
        assert!(a1_position < a2_position);
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn late_vertex_keeps_its_original_anchor_and_enters_a_later_checkpoint() {
        let mut dag = engine(6, 6);
        let origins = dag.members.clone();
        let early = vertex(&dag, origins[0], 1, None, 1);
        let late = vertex(&dag, origins[1], 1, None, 2);
        let genesis_hash = late.body.anchor_checkpoint_hash;
        dag.ingest_vertex(early.clone()).unwrap();
        dag.ingest_vertex(late.clone()).unwrap();

        let first = dag.build_candidate([early.hash]).unwrap();
        let (_, first_order) = finalize_candidate(&mut dag, &first);
        assert_eq!(first_order, vec![early.hash]);

        let second = dag.build_candidate([late.hash]).unwrap();
        let (checkpoint, second_order) = finalize_candidate(&mut dag, &second);
        assert_eq!(late.body.anchor_checkpoint_hash, genesis_hash);
        assert_eq!(second_order, vec![late.hash]);
        assert_eq!(
            checkpoint.body.previous_checkpoint_nonce,
            Some(Nonce::new(1))
        );
        assert_eq!(checkpoint.body.nonce, Nonce::new(2));
    }

    #[test]
    fn serialized_round_lock_restarts_without_permitting_a_second_candidate() {
        let mut original = engine(6, 6);
        let origin = original.members[0];
        let first_vertex = vertex(&original, origin, 1, None, 1);
        original.ingest_vertex(first_vertex.clone()).unwrap();
        let candidate = original.build_candidate([first_vertex.hash]).unwrap();
        let expected = original.expected_round_members(0).unwrap();
        let threshold = supermajority_count(expected.len());
        for member in expected.iter().take(threshold) {
            original
                .record_acknowledgement(0, *member, candidate.clone())
                .unwrap();
        }
        let lock = original.try_lock_round(0).unwrap().unwrap();
        let encoded = borsh::to_vec(&lock).unwrap();
        let decoded = borsh::from_slice::<TrustedDagRoundLock>(&encoded).unwrap();

        let mut restarted = engine(6, 6);
        restarted.ingest_vertex(first_vertex).unwrap();
        restarted.restore_round_lock(decoded.clone()).unwrap();
        restarted.restore_round_lock(decoded).unwrap();

        let other_origin = restarted.members[1];
        let other = vertex(&restarted, other_origin, 1, None, 2);
        restarted.ingest_vertex(other.clone()).unwrap();
        let conflicting = restarted.build_candidate([other.hash]).unwrap();
        assert!(
            restarted
                .record_acknowledgement(0, expected[threshold], conflicting)
                .is_err()
        );
    }

    #[test]
    fn contiguous_hierarchical_locks_restore_through_the_highest_round() {
        let mut original = engine(12, 6);
        let origin = original.members[0];
        let first_vertex = vertex(&original, origin, 1, None, 1);
        original.ingest_vertex(first_vertex.clone()).unwrap();
        let candidate = original.build_candidate([first_vertex.hash]).unwrap();
        assert!(matches!(
            lock_and_complete_round(&mut original, 0, &candidate),
            TrustedDagRoundCompletion::Advanced { next_round: 1 }
        ));
        let expected = original.expected_round_members(1).unwrap();
        let threshold = supermajority_count(expected.len());
        for member in expected.iter().take(threshold) {
            original
                .record_acknowledgement(1, *member, candidate.clone())
                .unwrap();
        }
        let second_lock = original.try_lock_round(1).unwrap().unwrap();
        let first_lock = original.round_states[&0].lock.clone().unwrap();

        let mut restarted = engine(12, 6);
        restarted.ingest_vertex(first_vertex).unwrap();
        restarted.restore_round_lock(first_lock).unwrap();
        restarted.restore_round_lock(second_lock.clone()).unwrap();
        assert_eq!(restarted.round_states[&1].lock.as_ref(), Some(&second_lock));
        assert!(restarted.round_states[&0].completed);
    }

    #[test]
    fn scale_reducer_converges_through_real_sequential_quorums() {
        for (nodes, quorum) in [(6, 6), (72, 6), (1_000, 6), (1_000, 9)] {
            let report = run_sequential_quorum_dag_experiment(
                nodes,
                QuorumSize::new(quorum).unwrap(),
                1_024,
                true,
            )
            .unwrap();
            assert!(report.all_nodes_converged, "{report:#?}");
            assert_eq!(report.finalized_vertex_count, nodes);
            assert!(report.sequential_rounds >= 1);
            assert!(
                report.compact_frontier_control_bytes
                    < report.materialized_payload_bytes_on_sequential_path
            );
        }
    }

    #[test]
    fn thousand_and_one_checkpoint_fault_soak_preserves_prefix_and_order() {
        let mut dag = engine(6, 6);
        let origins = dag.members.clone();
        let mut origin_heads = BTreeMap::<PubKey, HashType>::new();
        let mut origin_sequences = BTreeMap::<PubKey, u64>::new();
        let mut previous_checkpoint = dag.head().clone();
        let mut random = 0x8391_1634_8196_3729u64;

        for epoch in 1..=1_001u64 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let omitted_a = (random as usize) % origins.len();
            let omitted_b = ((random >> 16) as usize) % origins.len();
            let mut heads = Vec::new();
            for (index, origin) in origins.iter().copied().enumerate() {
                if index == omitted_a || index == omitted_b {
                    continue;
                }
                let sequence = origin_sequences.get(&origin).copied().unwrap_or_default() + 1;
                let next = vertex(
                    &dag,
                    origin,
                    sequence,
                    origin_heads.get(&origin).copied(),
                    epoch ^ index as u64,
                );
                dag.ingest_vertex(next.clone()).unwrap();
                origin_sequences.insert(origin, sequence);
                origin_heads.insert(origin, next.hash);
                heads.push(next.hash);
            }
            let candidate = dag.build_candidate(heads).unwrap();
            let (checkpoint, order) = finalize_candidate(&mut dag, &candidate);
            checkpoint.validate_hash().unwrap();
            assert_eq!(
                checkpoint.body.previous_checkpoint_hash,
                previous_checkpoint.hash
            );
            assert_eq!(
                checkpoint.body.previous_checkpoint_nonce,
                Some(previous_checkpoint.body.nonce)
            );
            assert_eq!(checkpoint.body.nonce, Nonce::new(epoch));
            assert_eq!(
                checkpoint.body.ordered_delta_root,
                protocol_commitment(ORDER_DOMAIN, &order).unwrap()
            );
            previous_checkpoint = checkpoint;
        }
        assert_eq!(dag.head().body.nonce, Nonce::new(1_001));
        assert_eq!(dag.checkpoints().len(), 1_002);
    }
}
