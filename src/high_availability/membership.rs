//! Committed amendments and fixed-slot suspension/reactivation transitions.

use super::*;

impl HighAvailabilityRuntime {
    /// Imports a finalized, transaction-committed amendment.
    pub fn append_amendment(&mut self, amendment: AmendmentRecord) -> Result<StateRevision> {
        self.state.validate_new_amendment(&amendment)?;
        let incoming_hash = amendment.hash()?;
        let target_epoch_nonce = amendment.target_epoch_nonce;
        let containing_epoch = self
            .state
            .epochs
            .iter()
            .find(|epoch| epoch.nonce == amendment.containing_epoch_nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "HA amendment containing epoch is not committed".to_string(),
                )
            })?;
        let mut committed = false;
        for (_, block) in containing_epoch.ordered_blocks() {
            for transaction in &block.body.txs {
                if decode_amendment_transaction(transaction)?
                    .as_ref()
                    .is_some_and(|candidate| candidate.hash().ok() == Some(incoming_hash))
                {
                    committed = true;
                }
            }
        }
        if !committed {
            return Err(BlossomError::InvalidConfiguration(
                "HA amendment bytes are not committed by the containing epoch".to_string(),
            ));
        }
        for existing in &self.state.amendments {
            if existing.command_identity == amendment.command_identity {
                if existing.hash()? == incoming_hash {
                    return self.revision();
                }
                return Err(BlossomError::InvalidConfiguration(
                    "conflicting HA amendment bytes for one command identity".to_string(),
                ));
            }
        }
        self.state.amendments.push(amendment);
        if let Err(error) = self.persist() {
            self.state.amendments.pop();
            return Err(error);
        }
        let revision = self.revision()?;
        self.record_telemetry(|| {
            self.telemetry_event("apply", "amendment_applied")
                .with_outcome("ok")
                .with_field("target_nonce", target_epoch_nonce.to_string())
                .with_field("amendment_hash", incoming_hash.to_string())
                .with_field("revision_hash", revision.revision_hash.to_string())
        });
        Ok(revision)
    }

    /// Encodes an amendment as a block transaction for later finalization.
    pub fn amendment_transaction(
        &self,
        amendment: &AmendmentRecord,
    ) -> Result<crate::block::Transaction> {
        self.validate_proposed_amendment(amendment, self.state.round.round_id.nonce)?;
        encode_amendment_transaction(amendment)
    }

    /// Returns committed amendments targeting one logical epoch.
    pub fn amendments_for_epoch(&self, nonce: Nonce) -> Vec<&AmendmentRecord> {
        let mut amendments = self
            .state
            .amendments
            .iter()
            .filter(|amendment| amendment.target_epoch_nonce == nonce)
            .collect::<Vec<_>>();
        amendments.sort_by_key(|amendment| amendment.hash().unwrap_or_default());
        amendments
    }

    /// Returns the base epoch hash followed by its committed amendment hashes.
    pub fn logical_epoch_record_hashes(&self, nonce: Nonce) -> Result<Vec<HashType>> {
        let epoch = self
            .state
            .epochs
            .iter()
            .find(|epoch| epoch.nonce == nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration("unknown HA epoch nonce".to_string())
            })?;
        let mut hashes = epoch
            .ordered_slots
            .as_slice()
            .iter()
            .map(|slot| epoch.candidate.block_hashes[usize::from(*slot)])
            .collect::<Vec<_>>();
        for amendment in self.amendments_for_epoch(nonce) {
            hashes.push(amendment.hash()?);
        }
        hashes.sort_unstable();
        Ok(hashes)
    }

    /// Computes the current cumulative application state revision.
    pub fn revision(&self) -> Result<StateRevision> {
        let mut accumulator = self
            .state
            .checkpoint
            .as_ref()
            .map_or(HashType::default(), |checkpoint| {
                checkpoint.history_accumulator
            });
        let skip = usize::from(self.state.checkpoint.is_some());
        for epoch in self.state.epochs.iter().skip(skip) {
            accumulator =
                accumulate_history(accumulator, self.logical_epoch_record_hashes(epoch.nonce)?);
        }
        Ok(StateRevision::from_history_accumulator(
            Watermark {
                position: self.head().nonce.value(),
            },
            self.sealed_watermark(),
            accumulator,
        ))
    }

    /// Returns availability status for one fixed member slot.
    pub fn node_status(&self, slot: HaMemberSlot) -> NodeAvailabilityStatus {
        self.state.presence.status(slot)
    }

    pub(super) fn validate_amendment_transactions(
        &self,
        transactions: &[crate::block::Transaction],
        containing_nonce: Nonce,
    ) -> Result<()> {
        let mut proposed: Vec<AmendmentRecord> = Vec::new();
        for transaction in transactions {
            let Some(amendment) = decode_amendment_transaction(transaction)? else {
                continue;
            };
            self.validate_proposed_amendment(&amendment, containing_nonce)?;
            let incoming_hash = amendment.hash()?;
            if let Some(existing) = proposed
                .iter()
                .find(|existing| existing.command_identity == amendment.command_identity)
            {
                if existing.hash()? != incoming_hash {
                    return Err(BlossomError::InvalidConfiguration(
                        "conflicting HA amendments for one command identity".to_string(),
                    ));
                }
            } else {
                proposed.push(amendment);
            }
        }
        Ok(())
    }

    pub(super) fn validate_proposed_amendment(
        &self,
        amendment: &AmendmentRecord,
        containing_nonce: Nonce,
    ) -> Result<()> {
        if amendment.containing_epoch_nonce != containing_nonce
            || amendment.containing_epoch_nonce <= amendment.target_epoch_nonce
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA amendment must name the later epoch that carries its bytes".to_string(),
            ));
        }
        if self.state.members.member(amendment.origin_slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        let target = self
            .state
            .epochs
            .iter()
            .find(|epoch| epoch.nonce == amendment.target_epoch_nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "HA amendment target epoch is not in the local chain".to_string(),
                )
            })?;
        if target.hash != amendment.target_epoch_hash {
            return Err(BlossomError::WireProtocol(
                "HA amendment target hash mismatch".to_string(),
            ));
        }
        if matches!(
            epoch_lifecycle(
                amendment.target_epoch_nonce,
                self.head().nonce,
                self.state.parameters.mutable_epoch_depth,
            ),
            EpochLifecycle::Sealed
        ) {
            return Err(BlossomError::EpochSealed {
                target: amendment.target_epoch_nonce,
                sealed: self.state.sealed_nonce(),
                writable: containing_nonce,
            });
        }
        for existing in &self.state.amendments {
            if existing.command_identity == amendment.command_identity
                && existing.hash()? != amendment.hash()?
            {
                return Err(BlossomError::InvalidConfiguration(
                    "conflicting HA amendment bytes for one command identity".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Durably votes to suspend an unresponsive slot at the next boundary.
    pub fn vote_to_suspend(
        &mut self,
        slot: HaMemberSlot,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.require_epoch_boundary_for_membership_change()?;
        let proposal = HaMembershipProposal::new(
            self.state.group_id,
            self.state.membership_generation,
            self.state.members.active_mask(),
            self.parameters_hash(),
            self.state.round.round_id.nonce,
            slot,
            HaMembershipAction::Suspend,
        );
        self.cast_membership_vote(proposal)
    }

    /// Durably votes to reactivate a slot proven caught up to the exact head.
    pub fn vote_to_reactivate(
        &mut self,
        slot: HaMemberSlot,
        caught_up_through: Nonce,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.require_epoch_boundary_for_membership_change()?;
        if caught_up_through != self.head().nonce {
            return Err(BlossomError::InvalidConfiguration(
                "HA reactivation receipt must name the exact current checkpoint".to_string(),
            ));
        }
        let proposal = HaMembershipProposal::new(
            self.state.group_id,
            self.state.membership_generation,
            self.state.members.active_mask(),
            self.parameters_hash(),
            self.state.round.round_id.nonce,
            slot,
            HaMembershipAction::Reactivate {
                caught_up_through,
                checkpoint_hash: self.head().hash,
                state_revision: self.revision()?.revision_hash,
            },
        );
        self.cast_membership_vote(proposal)
    }

    pub(super) fn cast_membership_vote(
        &mut self,
        proposal: HaMembershipProposal,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.validate_membership_proposal(&proposal)?;
        if let Some(locked) = self.state.membership_vote_lock
            && locked != proposal.digest
        {
            return Err(BlossomError::WireProtocol(
                "HA member already voted for a conflicting membership change".to_string(),
            ));
        }
        let previous_vote_lock = self.state.membership_vote_lock;
        let previous_votes = self.state.membership_votes;
        let sender = self.state.self_slot;
        self.state.membership_vote_lock = Some(proposal.digest);
        self.state.membership_votes[sender.index()] = Some(proposal.digest);
        let vote = HaMembershipVote { proposal, sender };
        let certificate = match self.try_commit_membership_proposal(proposal) {
            Ok(certificate) => certificate,
            Err(error) => {
                self.state.membership_vote_lock = previous_vote_lock;
                self.state.membership_votes = previous_votes;
                return Err(error);
            }
        };
        if certificate.is_none() {
            // The one-proposal vote lock is durable before the vote may be
            // broadcast on the trusted transport.
            if let Err(error) = self.persist() {
                self.state.membership_vote_lock = previous_vote_lock;
                self.state.membership_votes = previous_votes;
                return Err(error);
            }
        }
        Ok((vote, certificate))
    }

    /// Validates a membership vote and commits a majority certificate.
    pub fn receive_membership_vote(&mut self, vote: HaMembershipVote) -> Result<HaRuntimeEvent> {
        if vote.proposal.membership_generation < self.state.membership_generation {
            let certificate = self
                .state
                .membership_changes
                .iter()
                .find(|certificate| certificate.proposal.digest == vote.proposal.digest)
                .copied()
                .ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "stale HA membership vote has no committed certificate".to_string(),
                    )
                })?;
            return Ok(HaRuntimeEvent::MembershipChanged(certificate));
        }
        self.require_epoch_boundary_for_membership_change()?;
        self.validate_membership_proposal(&vote.proposal)?;
        if vote.proposal.active_mask & vote.sender.bit()? == 0 {
            return Err(BlossomError::UnknownSender);
        }
        let sender_index = vote.sender.index();
        if let Some(existing) = self.state.membership_votes[sender_index] {
            if existing == vote.proposal.digest {
                return Ok(HaRuntimeEvent::MembershipVoteAccepted);
            }
            return Err(BlossomError::WireProtocol(
                "HA member sent conflicting membership votes".to_string(),
            ));
        }
        let previous_vote_lock = self.state.membership_vote_lock;
        let previous_votes = self.state.membership_votes;
        self.state.membership_votes[sender_index] = Some(vote.proposal.digest);
        let certificate = match self.try_commit_membership_proposal(vote.proposal) {
            Ok(certificate) => certificate,
            Err(error) => {
                self.state.membership_vote_lock = previous_vote_lock;
                self.state.membership_votes = previous_votes;
                return Err(error);
            }
        };
        match certificate {
            Some(certificate) => Ok(HaRuntimeEvent::MembershipChanged(certificate)),
            None => Ok(HaRuntimeEvent::MembershipVoteAccepted),
        }
    }

    pub(super) fn validate_membership_proposal(
        &self,
        proposal: &HaMembershipProposal,
    ) -> Result<()> {
        if proposal.digest != proposal.compute_digest()
            || proposal.group_id != self.state.group_id
            || proposal.membership_generation != self.state.membership_generation
            || proposal.active_mask != self.state.members.active_mask()
            || proposal.parameters_hash != self.parameters_hash()
            || proposal.effective_nonce != self.state.round.round_id.nonce
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA membership proposal does not match the current epoch boundary".to_string(),
            ));
        }
        match proposal.action {
            HaMembershipAction::Suspend => {
                if self.node_status(proposal.slot) != NodeAvailabilityStatus::Unresponsive {
                    return Err(BlossomError::InvalidConfiguration(
                        "HA member is not yet unresponsive".to_string(),
                    ));
                }
                self.state.members.with_suspended(proposal.slot)?;
            }
            HaMembershipAction::Reactivate {
                caught_up_through,
                checkpoint_hash,
                state_revision,
            } => {
                if self.state.members.is_active(proposal.slot) {
                    return Err(BlossomError::InvalidConfiguration(
                        "HA member is already active".to_string(),
                    ));
                }
                if caught_up_through != self.head().nonce
                    || checkpoint_hash != self.head().hash
                    || state_revision != self.revision()?.revision_hash
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "HA reactivation is not bound to the current checkpoint hash and revision"
                            .to_string(),
                    ));
                }
                self.state.members.with_reactivated(proposal.slot)?;
            }
        }
        Ok(())
    }

    pub(super) fn try_commit_membership_proposal(
        &mut self,
        proposal: HaMembershipProposal,
    ) -> Result<Option<HaMembershipCertificate>> {
        let mut approval_mask = 0u8;
        for index in 0..MAX_HA_NODES {
            if proposal.active_mask & (1u8 << index) != 0
                && self.state.membership_votes[index] == Some(proposal.digest)
            {
                approval_mask |= 1u8 << index;
            }
        }
        if (approval_mask.count_ones() as usize) < self.state.members.majority() {
            return Ok(None);
        }
        let certificate = HaMembershipCertificate {
            proposal,
            approval_mask,
        };
        self.apply_membership_certificate(certificate)?;
        Ok(Some(certificate))
    }

    pub(super) fn apply_membership_certificate(
        &mut self,
        certificate: HaMembershipCertificate,
    ) -> Result<()> {
        self.validate_membership_proposal(&certificate.proposal)?;
        let previous_members = self.state.members.clone();
        let previous_generation = self.state.membership_generation;
        let previous_change_count = self.state.membership_changes.len();
        let previous_vote_lock = self.state.membership_vote_lock;
        let previous_votes = self.state.membership_votes;
        let previous_presence = self.state.presence.clone();
        let previous_round = self.state.round.clone();
        let proposal = certificate.proposal;
        let transition = (|| {
            self.state.members = match proposal.action {
                HaMembershipAction::Suspend => {
                    self.state
                        .presence
                        .mark_suspended(proposal.slot, proposal.effective_nonce);
                    self.state.members.with_suspended(proposal.slot)?
                }
                HaMembershipAction::Reactivate { .. } => {
                    self.state.presence.mark_reactivated(proposal.slot);
                    self.state.members.with_reactivated(proposal.slot)?
                }
            };
            self.state.membership_generation = self
                .state
                .membership_generation
                .checked_add(1)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "HA membership generation overflow".to_string(),
                    )
                })?;
            self.state.membership_changes.push(certificate);
            self.state.membership_vote_lock = None;
            self.state.membership_votes = array::from_fn(|_| None);
            self.retarget_current_round()?;
            self.persist()
        })();
        if let Err(error) = transition {
            self.state.members = previous_members;
            self.state.membership_generation = previous_generation;
            self.state
                .membership_changes
                .truncate(previous_change_count);
            self.state.membership_vote_lock = previous_vote_lock;
            self.state.membership_votes = previous_votes;
            self.state.presence = previous_presence;
            self.state.round = previous_round;
            return Err(error);
        }
        self.record_telemetry(|| {
            self.telemetry_event("membership", "membership_changed")
                .with_outcome("ok")
                .with_field("slot", proposal.slot.0.to_string())
                .with_field("action", format!("{:?}", proposal.action))
                .with_field(
                    "membership_generation",
                    self.state.membership_generation.to_string(),
                )
                .with_field("active_mask", self.state.members.active_mask().to_string())
        });
        self.record_operational_status();
        Ok(())
    }

    pub(super) fn require_epoch_boundary_for_membership_change(&self) -> Result<()> {
        let round = &self.state.round;
        if round.received_mask != 0
            || round.acknowledgements.iter().any(|mask| *mask != 0)
            || round.confirmations.iter().any(Option::is_some)
            || round.confirmed_candidate.is_some()
            || round.finalized.is_some()
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA membership changes take effect only at an empty epoch boundary".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn retarget_current_round(&mut self) -> Result<()> {
        let head = self.state.head();
        let round_id = HaRoundId {
            group_id: self.state.group_id,
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            membership_generation: self.state.membership_generation,
            active_mask: self.state.members.active_mask(),
            parameters_hash: self.state.parameters.hash(),
            previous_epoch_hash: head.hash,
            previous_epoch_nonce: head.nonce,
            nonce: head.nonce.new_next(),
            round: 0,
        };
        self.state.round = HaRoundState::new(round_id, &self.state.members)?;
        Ok(())
    }

    pub(super) fn persist(&self) -> Result<()> {
        match &self.store {
            Some(store) => store.persist(&self.state),
            // Mutating protocol methods validate their inputs and transitions
            // incrementally. A full history scan here would turn every
            // in-memory Dispatch/Ack/Confirm into work proportional to the
            // retained epoch chain. Durable reload still performs the complete
            // validation before exposing recovered state.
            None => Ok(()),
        }
    }
}
