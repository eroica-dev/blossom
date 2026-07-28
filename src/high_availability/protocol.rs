//! Round messages, candidates, confirmations, epochs, and amendment encoding.

use super::*;

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Consensus context that uniquely identifies one HA round.
pub struct HaRoundId {
    /// Consensus group running the round.
    pub group_id: ConsensusGroupId,
    /// Hash of the immutable slot-to-public-key assignment.
    pub fixed_membership_hash: HashType,
    /// Generation of the active membership mask.
    pub membership_generation: u64,
    /// Bitset of slots eligible to participate.
    pub active_mask: u8,
    /// Hash of the committed HA parameters.
    pub parameters_hash: HashType,
    /// Hash of the finalized predecessor epoch.
    pub previous_epoch_hash: HashType,
    /// Nonce of the finalized predecessor epoch.
    pub previous_epoch_nonce: Nonce,
    /// Nonce targeted by this round.
    pub nonce: Nonce,
    /// Attempt number within the target nonce.
    pub round: u8,
}

impl HaRoundId {
    /// Validates the round's membership context and successor nonce.
    pub fn validate_for(&self, members: &HaMemberSlots) -> Result<()> {
        if self.fixed_membership_hash != members.fixed_identity_hash()
            || self.active_mask != members.active_mask()
        {
            return Err(BlossomError::WireProtocol(
                "HA message fixed membership or active membership mask mismatch".to_string(),
            ));
        }
        if self.nonce != self.previous_epoch_nonce.new_next() {
            return Err(BlossomError::InvalidEpochNonce);
        }
        Ok(())
    }

    pub(super) fn update_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.group_id.as_ref());
        hasher.update(self.fixed_membership_hash.as_ref());
        hasher.update(self.membership_generation.to_le_bytes());
        hasher.update([self.active_mask]);
        hasher.update(self.parameters_hash.as_ref());
        hasher.update(self.previous_epoch_hash.as_ref());
        hasher.update(self.previous_epoch_nonce.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update([self.round]);
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Canonical set of blocks proposed for finalization in one HA round.
pub struct HaCandidate {
    /// Bitset of slots whose blocks are included.
    pub included_mask: u8,
    /// Bitset of active slots observed during the round.
    pub presence_mask: u8,
    /// Per-slot block hashes, zeroed outside [`Self::included_mask`].
    pub block_hashes: [HashType; MAX_HA_NODES],
    /// Domain-separated commitment to the round and candidate contents.
    pub digest: HashType,
}

impl HaCandidate {
    pub(super) fn from_round(
        round_id: HaRoundId,
        included_mask: u8,
        presence_mask: u8,
        block_hashes: [HashType; MAX_HA_NODES],
    ) -> Self {
        let digest = candidate_digest(round_id, included_mask, presence_mask, &block_hashes);
        Self {
            included_mask,
            presence_mask,
            block_hashes,
            digest,
        }
    }

    /// Verifies masks, block-hash placement, and the candidate digest.
    pub fn validate(&self, round_id: HaRoundId) -> Result<()> {
        if self.included_mask == 0 || self.included_mask & !round_id.active_mask != 0 {
            return Err(BlossomError::WireProtocol(
                "HA candidate mask is empty or references an inactive slot".to_string(),
            ));
        }
        if self.presence_mask & !round_id.active_mask != 0
            || self.presence_mask & self.included_mask != self.included_mask
        {
            return Err(BlossomError::WireProtocol(
                "HA candidate presence must include every block origin and only active members"
                    .to_string(),
            ));
        }
        for index in 0..MAX_HA_NODES {
            let included = self.included_mask & (1u8 << index) != 0;
            if !included && self.block_hashes[index] != HashType::default() {
                return Err(BlossomError::WireProtocol(
                    "HA candidate contains a hash outside its included mask".to_string(),
                ));
            }
        }
        if self.digest
            != candidate_digest(
                round_id,
                self.included_mask,
                self.presence_mask,
                &self.block_hashes,
            )
        {
            return Err(BlossomError::WireProtocol(
                "HA candidate digest mismatch".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns included slots in deterministic block-hash order.
    pub fn ordered_slots(&self) -> HaOrderedSlots {
        let mut result = HaOrderedSlots::default();
        for index in 0..MAX_HA_NODES {
            if self.included_mask & (1u8 << index) == 0 {
                continue;
            }
            let slot = index as u8;
            let mut position = result.len as usize;
            while position > 0 {
                let previous_slot = result.slots[position - 1];
                let ordering =
                    self.block_hashes[index].cmp(&self.block_hashes[usize::from(previous_slot)]);
                if ordering == Ordering::Greater
                    || (ordering == Ordering::Equal && slot >= previous_slot)
                {
                    break;
                }
                result.slots[position] = previous_slot;
                position -= 1;
            }
            result.slots[position] = slot;
            result.len += 1;
        }
        result
    }
}

pub(super) fn candidate_digest(
    round_id: HaRoundId,
    included_mask: u8,
    presence_mask: u8,
    block_hashes: &[HashType; MAX_HA_NODES],
) -> HashType {
    let mut hasher = ProtocolHasher::new();
    hasher.update(HA_CANDIDATE_HASH_DOMAIN);
    round_id.update_hash(&mut hasher);
    hasher.update([included_mask]);
    hasher.update([presence_mask]);
    for (index, block_hash) in block_hashes.iter().enumerate() {
        if included_mask & (1u8 << index) != 0 {
            hasher.update([index as u8]);
            hasher.update(block_hash.as_ref());
        }
    }
    hasher.finalize()
}

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
    Default,
)]
/// Fixed-capacity deterministic ordering of included HA member slots.
pub struct HaOrderedSlots {
    /// Number of initialized entries in [`Self::slots`].
    pub len: u8,
    /// Ordered slot indexes; entries after [`Self::len`] are ignored.
    pub slots: [u8; MAX_HA_NODES],
}

impl HaOrderedSlots {
    /// Borrows the initialized prefix of the ordered slot array.
    pub fn as_slice(&self) -> &[u8] {
        &self.slots[..usize::from(self.len)]
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
/// A member's block contribution for one HA round.
pub struct HaDispatch {
    /// Round targeted by the dispatch.
    pub round_id: HaRoundId,
    /// Fixed member slot that originated the block.
    pub sender: HaMemberSlot,
    /// Unsigned integrity hash of [`Self::block`].
    pub block_hash: HashType,
    /// Application block contributed by the sender.
    pub block: Block,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// A member's monotonic acknowledgement of received round blocks.
pub struct HaAcknowledge {
    /// Round targeted by the acknowledgement.
    pub round_id: HaRoundId,
    /// Member slot issuing the acknowledgement.
    pub sender: HaMemberSlot,
    /// Bitset of block origins observed by the sender.
    pub received_mask: u8,
    /// Hashes corresponding to the received block origins.
    pub block_hashes: [HashType; MAX_HA_NODES],
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// A member's vote to finalize one canonical round candidate.
pub struct HaConfirm {
    /// Round targeted by the confirmation.
    pub round_id: HaRoundId,
    /// Member slot issuing the confirmation.
    pub sender: HaMemberSlot,
    /// Exact candidate being confirmed.
    pub candidate: HaCandidate,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
/// Message accepted by the native active-active HA protocol.
pub enum HaMessage {
    /// Announces a peer's immutable consensus context and head.
    Handshake(HaHandshake),
    /// Votes for a suspension or checkpoint-bound reactivation.
    MembershipVote(HaMembershipVote),
    /// Contributes a block to the current round.
    Dispatch(HaDispatch),
    /// Reports the set of round blocks observed by a member.
    Acknowledge(HaAcknowledge),
    /// Confirms a canonical round candidate.
    Confirm(HaConfirm),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Result of admitting an HA block dispatch.
pub enum HaDispatchOutcome {
    /// The dispatch was accepted into the live round.
    Accepted,
    /// An identical dispatch had already been accepted.
    Duplicate,
    /// The target epoch was already finalized and needs amendment handling.
    Late {
        /// Epoch to which the late block belongs.
        target_epoch: Nonce,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Strict-majority round result from which an [`HaEpoch`] is constructed.
pub struct HaFinalizedRound {
    /// Consensus context of the finalized round.
    pub round_id: HaRoundId,
    /// Candidate agreed by a strict majority.
    pub candidate: HaCandidate,
    /// Bitset of members that confirmed the candidate.
    pub confirmation_mask: u8,
    /// Presence bitset committed by the candidate.
    pub presence_mask: u8,
    /// Deterministic application order for included blocks.
    pub ordered_slots: HaOrderedSlots,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
/// Finalized HA epoch with its strict-majority certificate and ordered blocks.
pub struct HaEpoch {
    /// Domain-separated hash of the epoch header.
    pub hash: HashType,
    /// Consensus group that finalized the epoch.
    pub group_id: ConsensusGroupId,
    /// Hash of the immutable member-slot assignment.
    pub fixed_membership_hash: HashType,
    /// Active-membership generation used to finalize the epoch.
    pub membership_generation: u64,
    /// Slots eligible to vote in this epoch.
    pub active_mask: u8,
    /// Hash of the predecessor epoch.
    pub previous_epoch_hash: HashType,
    /// Nonce of the predecessor, absent only for genesis.
    pub previous_epoch_nonce: Option<Nonce>,
    /// Monotonic epoch nonce.
    pub nonce: Nonce,
    /// Canonical candidate finalized by this epoch.
    pub candidate: HaCandidate,
    /// Strict-majority confirmation certificate as a member bitset.
    pub confirmation_mask: u8,
    /// Members observed while constructing the candidate.
    pub presence_mask: u8,
    /// Deterministic order in which included blocks are applied.
    pub ordered_slots: HaOrderedSlots,
    /// Per-slot blocks, present exactly where the candidate includes them.
    pub blocks: [Option<Block>; MAX_HA_NODES],
    /// HA parameters committed by this epoch.
    pub parameters: HighAvailabilityParameters,
    /// Hash commitment to [`Self::parameters`].
    pub parameters_hash: HashType,
}

impl HaEpoch {
    pub(super) fn from_finalized(
        finalized: HaFinalizedRound,
        blocks: &[Option<Block>; MAX_HA_NODES],
        parameters: HighAvailabilityParameters,
    ) -> Self {
        let mut epoch = Self {
            hash: HashType::default(),
            group_id: finalized.round_id.group_id,
            fixed_membership_hash: finalized.round_id.fixed_membership_hash,
            membership_generation: finalized.round_id.membership_generation,
            active_mask: finalized.round_id.active_mask,
            previous_epoch_hash: finalized.round_id.previous_epoch_hash,
            previous_epoch_nonce: Some(finalized.round_id.previous_epoch_nonce),
            nonce: finalized.round_id.nonce,
            candidate: finalized.candidate,
            confirmation_mask: finalized.confirmation_mask,
            presence_mask: finalized.presence_mask,
            ordered_slots: finalized.ordered_slots,
            blocks: array::from_fn(|index| blocks[index].clone()),
            parameters,
            parameters_hash: parameters.hash(),
        };
        epoch.hash = epoch.compute_hash();
        epoch
    }

    pub(super) fn genesis(
        group_id: ConsensusGroupId,
        members: &HaMemberSlots,
        parameters: HighAvailabilityParameters,
    ) -> Self {
        let round_id = HaRoundId {
            group_id,
            fixed_membership_hash: members.fixed_identity_hash(),
            membership_generation: 0,
            active_mask: members.active_mask(),
            parameters_hash: parameters.hash(),
            previous_epoch_hash: HashType::default(),
            previous_epoch_nonce: Nonce::default(),
            nonce: Nonce::default(),
            round: 0,
        };
        let candidate =
            HaCandidate::from_round(round_id, 1, 1, [HashType::default(); MAX_HA_NODES]);
        let mut epoch = Self {
            hash: HashType::default(),
            group_id,
            fixed_membership_hash: members.fixed_identity_hash(),
            membership_generation: 0,
            active_mask: members.active_mask(),
            previous_epoch_hash: HashType::default(),
            previous_epoch_nonce: None,
            nonce: Nonce::default(),
            candidate,
            confirmation_mask: members.active_mask(),
            presence_mask: members.active_mask(),
            ordered_slots: HaOrderedSlots::default(),
            blocks: array::from_fn(|_| None),
            parameters,
            parameters_hash: parameters.hash(),
        };
        epoch.hash = epoch.compute_hash();
        epoch
    }

    /// Recomputes the domain-separated epoch header hash.
    pub fn compute_hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_EPOCH_HASH_DOMAIN);
        hasher.update(self.group_id.as_ref());
        hasher.update(self.fixed_membership_hash.as_ref());
        hasher.update(self.membership_generation.to_le_bytes());
        hasher.update([self.active_mask]);
        hasher.update(self.previous_epoch_hash.as_ref());
        match self.previous_epoch_nonce {
            Some(nonce) => {
                hasher.update([1]);
                hasher.update(nonce.to_le_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.candidate.digest.as_ref());
        hasher.update([self.presence_mask]);
        hasher.update(self.parameters_hash.as_ref());
        hasher.finalize()
    }

    /// Iterates included blocks in their consensus-defined application order.
    pub fn ordered_blocks(&self) -> impl Iterator<Item = (HaMemberSlot, &Block)> {
        self.ordered_slots.as_slice().iter().filter_map(|slot| {
            let slot = HaMemberSlot(*slot);
            self.blocks[slot.index()]
                .as_ref()
                .map(|block| (slot, block))
        })
    }

    /// Validates the epoch certificate, linkage context, blocks, and hash.
    pub fn validate(&self, members: &HaMemberSlots) -> Result<()> {
        self.parameters.validate()?;
        if self.parameters_hash != self.parameters.hash() {
            return Err(BlossomError::InvalidConfiguration(
                "HA epoch parameters hash mismatch".to_string(),
            ));
        }
        if self.fixed_membership_hash != members.fixed_identity_hash() {
            return Err(BlossomError::InvalidConfiguration(
                "HA epoch fixed membership hash mismatch".to_string(),
            ));
        }
        if self.active_mask & !low_bits(members.member_count) != 0 {
            return Err(BlossomError::WireProtocol(
                "HA epoch active mask references an unknown member".to_string(),
            ));
        }
        if self.previous_epoch_nonce.is_some()
            && self
                .previous_epoch_nonce
                .is_none_or(|previous| previous.new_next() != self.nonce)
        {
            return Err(BlossomError::InvalidEpochNonce);
        }
        if self.hash != self.compute_hash() {
            return Err(BlossomError::InvalidBlockHash);
        }
        self.candidate.validate(HaRoundId {
            group_id: self.group_id,
            fixed_membership_hash: self.fixed_membership_hash,
            membership_generation: self.membership_generation,
            active_mask: self.active_mask,
            parameters_hash: self.parameters_hash,
            previous_epoch_hash: self.previous_epoch_hash,
            previous_epoch_nonce: self.previous_epoch_nonce.unwrap_or_default(),
            nonce: self.nonce,
            round: 0,
        })?;
        if self.confirmation_mask & !self.active_mask != 0
            || (self.confirmation_mask.count_ones() as usize)
                < high_availability_majority(self.active_mask.count_ones() as usize)
        {
            return Err(BlossomError::WireProtocol(
                "HA epoch does not carry a strict-majority confirmation certificate".to_string(),
            ));
        }
        if self.presence_mask != self.candidate.presence_mask
            || self.ordered_slots != self.candidate.ordered_slots()
        {
            return Err(BlossomError::WireProtocol(
                "HA epoch presence or fixed ordering disagrees with its candidate".to_string(),
            ));
        }
        for index in 0..MAX_HA_NODES {
            let included = self.candidate.included_mask & (1u8 << index) != 0;
            if included {
                let block = self.blocks[index].as_ref().ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "HA epoch candidate references a missing block".to_string(),
                    )
                })?;
                block.verify_unsigned_integrity_with_hash(self.candidate.block_hashes[index])?;
            } else if self.blocks[index].is_some() {
                return Err(BlossomError::WireProtocol(
                    "HA epoch stores a block outside its finalized candidate".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl HaFinalizedRound {
    /// Computes the domain-separated commitment to this finalized round.
    pub fn hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_EPOCH_HASH_DOMAIN);
        self.round_id.update_hash(&mut hasher);
        hasher.update(self.candidate.digest.as_ref());
        hasher.update([self.presence_mask]);
        hasher.finalize()
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
/// Mutable per-round state used to collect dispatches and votes.
pub struct HaRoundState {
    /// Consensus context of the round.
    pub round_id: HaRoundId,
    /// Validated blocks received for each member slot.
    pub blocks: [Option<Block>; MAX_HA_NODES],
    /// Validated block hash for each member slot.
    pub block_hashes: [HashType; MAX_HA_NODES],
    /// Bitset of slots whose blocks were received.
    pub received_mask: u8,
    /// Row `i` is the latest monotonic block-receipt mask from member `i`.
    pub acknowledgements: [u8; MAX_HA_NODES],
    /// Candidate digest confirmed by each member slot.
    pub confirmations: [Option<HashType>; MAX_HA_NODES],
    /// Candidate digest selected once local confirmation begins.
    pub confirmed_candidate: Option<HashType>,
    /// Finalized result once a strict majority confirms the candidate.
    pub finalized: Option<HaFinalizedRound>,
}

impl HaRoundState {
    /// Creates an empty round after validating its membership context.
    pub fn new(round_id: HaRoundId, members: &HaMemberSlots) -> Result<Self> {
        members.validate()?;
        round_id.validate_for(members)?;
        Ok(Self {
            round_id,
            blocks: array::from_fn(|_| None),
            block_hashes: [HashType::default(); MAX_HA_NODES],
            received_mask: 0,
            acknowledgements: [0; MAX_HA_NODES],
            confirmations: array::from_fn(|_| None),
            confirmed_candidate: None,
            finalized: None,
        })
    }

    /// Validates and records one member's block dispatch.
    pub fn receive_dispatch(
        &mut self,
        members: &HaMemberSlots,
        dispatch: HaDispatch,
    ) -> Result<HaDispatchOutcome> {
        self.validate_message_scope(members, dispatch.round_id, dispatch.sender)?;
        let slot = dispatch.sender.index();
        let expected_member = members
            .member(dispatch.sender)
            .ok_or(BlossomError::UnknownSender)?;
        if dispatch.block.body.validator != expected_member.public_key() {
            return Err(BlossomError::UnknownSender);
        }
        if dispatch.block.body.last_epoch != self.round_id.previous_epoch_hash {
            return Err(BlossomError::InvalidBlockLastEpoch);
        }
        if dispatch.block.body.nonce != self.round_id.nonce {
            return Err(BlossomError::InvalidBlockNonce {
                expected: self.round_id.nonce,
                actual: dispatch.block.body.nonce,
            });
        }
        dispatch
            .block
            .verify_unsigned_integrity_with_hash(dispatch.block_hash)?;

        if let Some(existing) = &self.blocks[slot] {
            if self.block_hashes[slot] == dispatch.block_hash
                && existing.hash == dispatch.block.hash
            {
                return Ok(HaDispatchOutcome::Duplicate);
            }
            return Err(BlossomError::WireProtocol(format!(
                "HA slot {} dispatched conflicting block bytes",
                dispatch.sender.0
            )));
        }
        if self.confirmed_candidate.is_some() || self.finalized.is_some() {
            return Ok(HaDispatchOutcome::Late {
                target_epoch: self.round_id.nonce,
            });
        }
        self.blocks[slot] = Some(dispatch.block);
        self.block_hashes[slot] = dispatch.block_hash;
        self.received_mask |= dispatch.sender.bit()?;
        Ok(HaDispatchOutcome::Accepted)
    }

    /// Builds the sender's monotonic acknowledgement of received blocks.
    pub fn acknowledge(
        &mut self,
        members: &HaMemberSlots,
        sender: HaMemberSlot,
    ) -> Result<HaAcknowledge> {
        self.validate_sender(members, sender)?;
        let acknowledgement = HaAcknowledge {
            round_id: self.round_id,
            sender,
            received_mask: self.received_mask,
            block_hashes: masked_hashes(self.received_mask, &self.block_hashes),
        };
        self.receive_acknowledgement(members, acknowledgement.clone())?;
        Ok(acknowledgement)
    }

    /// Validates and records a member's acknowledgement.
    pub fn receive_acknowledgement(
        &mut self,
        members: &HaMemberSlots,
        acknowledgement: HaAcknowledge,
    ) -> Result<()> {
        self.validate_message_scope(members, acknowledgement.round_id, acknowledgement.sender)?;
        if acknowledgement.received_mask & !self.round_id.active_mask != 0 {
            return Err(BlossomError::WireProtocol(
                "HA acknowledgement references an inactive slot".to_string(),
            ));
        }
        for index in 0..MAX_HA_NODES {
            let bit = 1u8 << index;
            if acknowledgement.received_mask & bit != 0 {
                if self.blocks[index].is_none()
                    || acknowledgement.block_hashes[index] != self.block_hashes[index]
                {
                    return Err(BlossomError::WireProtocol(
                        "HA acknowledgement references an unknown or conflicting block".to_string(),
                    ));
                }
            } else if acknowledgement.block_hashes[index] != HashType::default() {
                return Err(BlossomError::WireProtocol(
                    "HA acknowledgement contains a hash outside its receipt mask".to_string(),
                ));
            }
        }
        let row = &mut self.acknowledgements[acknowledgement.sender.index()];
        if *row & !acknowledgement.received_mask != 0 {
            return Err(BlossomError::WireProtocol(
                "HA acknowledgement attempted to retract a receipt".to_string(),
            ));
        }
        *row = acknowledgement.received_mask;
        Ok(())
    }

    /// Returns the block-origin mask observed by a strict majority.
    pub fn available_mask(&self, members: &HaMemberSlots) -> u8 {
        let required = members.majority();
        let mut available = 0u8;
        for block_slot in 0..MAX_HA_NODES {
            let block_bit = 1u8 << block_slot;
            if self.received_mask & block_bit == 0 {
                continue;
            }
            let acknowledgers = (0..MAX_HA_NODES)
                .filter(|sender| self.round_id.active_mask & (1u8 << sender) != 0)
                .filter(|sender| self.acknowledgements[*sender] & block_bit != 0)
                .count();
            if acknowledgers >= required {
                available |= block_bit;
            }
        }
        available
    }

    /// Selects and confirms the canonical candidate for `sender`.
    pub fn confirm(&mut self, members: &HaMemberSlots, sender: HaMemberSlot) -> Result<HaConfirm> {
        self.validate_sender(members, sender)?;
        let sender_index = sender.index();
        if self.received_mask == 0
            || self.available_mask(members) & self.received_mask != self.received_mask
        {
            return Err(BlossomError::FailedConsensus);
        }
        let candidate = HaCandidate::from_round(
            self.round_id,
            self.received_mask,
            self.certified_presence_candidate_mask(members),
            masked_hashes(self.received_mask, &self.block_hashes),
        );
        if let Some(existing) = self.confirmations[sender_index] {
            if existing != candidate.digest || self.confirmed_candidate != Some(candidate.digest) {
                return Err(BlossomError::WireProtocol(
                    "HA durable confirmation lock does not match recoverable round state"
                        .to_string(),
                ));
            }
            return Ok(HaConfirm {
                round_id: self.round_id,
                sender,
                candidate,
            });
        }
        let confirmation = HaConfirm {
            round_id: self.round_id,
            sender,
            candidate,
        };
        self.receive_confirmation(members, confirmation.clone())?;
        self.confirmed_candidate = Some(confirmation.candidate.digest);
        Ok(confirmation)
    }

    /// Validates and records a confirmation, finalizing on strict majority.
    pub fn receive_confirmation(
        &mut self,
        members: &HaMemberSlots,
        confirmation: HaConfirm,
    ) -> Result<Option<HaFinalizedRound>> {
        self.validate_message_scope(members, confirmation.round_id, confirmation.sender)?;
        confirmation.candidate.validate(self.round_id)?;
        if confirmation.candidate.included_mask != self.received_mask {
            return Err(BlossomError::WireProtocol(
                "HA confirmation does not contain every locally accepted pre-lock dispatch"
                    .to_string(),
            ));
        }
        if self.available_mask(members) & confirmation.candidate.included_mask
            != confirmation.candidate.included_mask
        {
            return Err(BlossomError::FailedConsensus);
        }
        for index in 0..MAX_HA_NODES {
            if confirmation.candidate.included_mask & (1u8 << index) != 0
                && confirmation.candidate.block_hashes[index] != self.block_hashes[index]
            {
                return Err(BlossomError::WireProtocol(
                    "HA confirmation block hash mismatch".to_string(),
                ));
            }
        }
        let sender_index = confirmation.sender.index();
        if let Some(existing) = self.confirmations[sender_index] {
            if existing == confirmation.candidate.digest {
                return Ok(self.finalized.clone());
            }
            return Err(BlossomError::WireProtocol(
                "HA member confirmed conflicting candidates".to_string(),
            ));
        }
        if let Some(locked) = self.confirmed_candidate
            && locked != confirmation.candidate.digest
        {
            return Err(BlossomError::WireProtocol(
                "HA local confirmation lock conflicts with received candidate".to_string(),
            ));
        }
        self.confirmations[sender_index] = Some(confirmation.candidate.digest);

        let mut confirmation_mask = 0u8;
        for index in 0..MAX_HA_NODES {
            if self.round_id.active_mask & (1u8 << index) != 0
                && self.confirmations[index] == Some(confirmation.candidate.digest)
            {
                confirmation_mask |= 1u8 << index;
            }
        }
        if confirmation_mask.count_ones() as usize >= members.majority() {
            self.confirmed_candidate = Some(confirmation.candidate.digest);
            let finalized = HaFinalizedRound {
                round_id: self.round_id,
                // Availability certifies the included dispatch origins. The
                // particular confirmation subset is arrival-order dependent
                // and is retained only as local audit evidence.
                presence_mask: confirmation.candidate.presence_mask,
                ordered_slots: confirmation.candidate.ordered_slots(),
                candidate: confirmation.candidate,
                confirmation_mask,
            };
            self.finalized = Some(finalized.clone());
            return Ok(Some(finalized));
        }
        Ok(None)
    }

    /// Returns the validated block contributed by `slot`, if present.
    pub fn block(&self, slot: HaMemberSlot) -> Option<&Block> {
        self.blocks.get(slot.index()).and_then(Option::as_ref)
    }

    pub(super) fn certified_presence_candidate_mask(&self, members: &HaMemberSlots) -> u8 {
        let mut presence = self.available_mask(members);
        for index in 0..MAX_HA_NODES {
            if self.round_id.active_mask & (1u8 << index) != 0 && self.acknowledgements[index] != 0
            {
                presence |= 1u8 << index;
            }
        }
        presence
    }

    pub(super) fn validate_message_scope(
        &self,
        members: &HaMemberSlots,
        round_id: HaRoundId,
        sender: HaMemberSlot,
    ) -> Result<()> {
        if round_id != self.round_id {
            return Err(BlossomError::WireProtocol(
                "HA message targets another epoch or round".to_string(),
            ));
        }
        round_id.validate_for(members)?;
        self.validate_sender(members, sender)
    }

    pub(super) fn validate_sender(
        &self,
        members: &HaMemberSlots,
        sender: HaMemberSlot,
    ) -> Result<()> {
        if !members.is_active(sender) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(())
    }
}

pub(super) fn masked_hashes(
    mask: u8,
    hashes: &[HashType; MAX_HA_NODES],
) -> [HashType; MAX_HA_NODES] {
    array::from_fn(|index| {
        if mask & (1u8 << index) != 0 {
            hashes[index]
        } else {
            HashType::default()
        }
    })
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Corrective application payload attached to a later mutable epoch.
pub enum AmendmentPayload {
    /// Reintroduces a block that arrived after its target epoch finalized.
    LateBlock {
        /// Unsigned integrity hash of the encoded block.
        block_hash: HashType,
        /// Borsh-encoded block bytes.
        block_bytes: Vec<u8>,
    },
    /// Applies an application-defined compensating command.
    Compensation {
        /// Opaque application command bytes.
        command_bytes: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Deduplicated amendment targeting a still-mutable finalized epoch.
pub struct AmendmentRecord {
    /// Exact hash of the epoch being amended.
    pub target_epoch_hash: HashType,
    /// Nonce of the epoch being amended.
    pub target_epoch_nonce: Nonce,
    /// Later epoch in which the amendment is committed.
    pub containing_epoch_nonce: Nonce,
    /// Member slot that originated the amendment.
    pub origin_slot: HaMemberSlot,
    /// Stable command identity used for deduplication.
    pub command_identity: CommandIdentity,
    /// Earlier command identity replaced by this amendment, if any.
    pub supersedes: Option<CommandIdentity>,
    /// Corrective payload applied by the application.
    pub payload: AmendmentPayload,
}

impl AmendmentRecord {
    /// Computes the domain-separated hash of the complete amendment record.
    pub fn hash(&self) -> Result<HashType> {
        let bytes = borsh::to_vec(self)
            .map_err(|error| BlossomError::WireProtocol(format!("encode HA amendment: {error}")))?;
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_AMENDMENT_HASH_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize())
    }
}

pub(super) fn encode_amendment_transaction(
    amendment: &AmendmentRecord,
) -> Result<crate::block::Transaction> {
    let encoded = borsh::to_vec(amendment).map_err(|error| {
        BlossomError::WireProtocol(format!("encode HA amendment transaction: {error}"))
    })?;
    let mut payload = Vec::with_capacity(HA_AMENDMENT_RECORD_PREFIX.len() + encoded.len());
    payload.extend_from_slice(HA_AMENDMENT_RECORD_PREFIX);
    payload.extend_from_slice(&encoded);
    Ok(crate::block::Transaction::new(payload))
}

pub(super) fn decode_amendment_transaction(
    transaction: &crate::block::Transaction,
) -> Result<Option<AmendmentRecord>> {
    let payload = transaction.payload();
    let Some(encoded) = payload.strip_prefix(HA_AMENDMENT_RECORD_PREFIX) else {
        return Ok(None);
    };
    borsh::from_slice(encoded).map(Some).map_err(|error| {
        BlossomError::WireProtocol(format!("decode HA amendment transaction: {error}"))
    })
}
