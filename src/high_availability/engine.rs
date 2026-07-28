//! Runtime construction, status, recovery snapshots, and history checkpoints.

use super::*;

impl HighAvailabilityRuntime {
    /// Creates an in-memory HA protocol runtime.
    pub fn new(
        group_id: ConsensusGroupId,
        self_key: PubKey,
        members: Vec<NodeIdentity>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        Self::create(None, group_id, self_key, members, parameters)
    }

    /// Opens or creates a durable HA runtime directory.
    pub fn open(
        path: impl AsRef<Path>,
        group_id: ConsensusGroupId,
        self_key: PubKey,
        members: Vec<NodeIdentity>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        let durable_members = HaMemberSlots::new(members.clone())?;
        let store = HaDurableStore::open(
            path,
            group_id,
            self_key,
            durable_members.fixed_identity_hash(),
            parameters.hash(),
        )?;
        Self::open_store(store, group_id, self_key, members, parameters)
    }

    pub(super) fn open_store(
        store: HaDurableStore,
        group_id: ConsensusGroupId,
        self_key: PubKey,
        members: Vec<NodeIdentity>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        if let Some(state) = store.load()? {
            if state.group_id != group_id
                || state.parameters != parameters
                || !state
                    .members
                    .same_fixed_identities(&HaMemberSlots::new(members)?)
                || state
                    .members
                    .member(state.self_slot)
                    .is_none_or(|member| member.public_key() != self_key)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "durable HA runtime configuration mismatch".to_string(),
                ));
            }
            return Ok(Self {
                store: Some(store),
                state,
                telemetry: TelemetryHandle::default(),
            });
        }
        Self::create(Some(store), group_id, self_key, members, parameters)
    }

    pub(super) fn create(
        store: Option<HaDurableStore>,
        group_id: ConsensusGroupId,
        self_key: PubKey,
        members: Vec<NodeIdentity>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        parameters.validate()?;
        let members = HaMemberSlots::new(members)?;
        let self_slot = members
            .slot_for(&self_key)
            .ok_or(BlossomError::UnknownSender)?;
        let genesis = HaEpoch::genesis(group_id, &members, parameters);
        let round_id = HaRoundId {
            group_id,
            fixed_membership_hash: members.fixed_identity_hash(),
            membership_generation: 0,
            active_mask: members.active_mask(),
            parameters_hash: parameters.hash(),
            previous_epoch_hash: genesis.hash,
            previous_epoch_nonce: genesis.nonce,
            nonce: genesis.nonce.new_next(),
            round: 0,
        };
        let state = HighAvailabilityRuntimeState {
            group_id,
            self_slot,
            members: members.clone(),
            membership_generation: 0,
            parameters,
            checkpoint: None,
            epochs: vec![genesis],
            round: HaRoundState::new(round_id, &members)?,
            presence: HaPresenceTracker::default(),
            membership_vote_lock: None,
            membership_votes: array::from_fn(|_| None),
            membership_changes: Vec::new(),
            amendments: Vec::new(),
        };
        state.validate()?;
        let runtime = Self {
            store,
            state,
            telemetry: TelemetryHandle::default(),
        };
        runtime.persist()?;
        Ok(runtime)
    }

    /// Installs a telemetry destination and returns the runtime.
    pub fn with_telemetry(mut self, telemetry: TelemetryHandle) -> Self {
        self.telemetry = telemetry;
        self.record_operational_status();
        self
    }

    /// Replaces the telemetry destination.
    pub fn set_telemetry(&mut self, telemetry: TelemetryHandle) {
        self.telemetry = telemetry;
        self.record_operational_status();
    }

    /// Borrows the configured telemetry handle.
    pub fn telemetry(&self) -> &TelemetryHandle {
        &self.telemetry
    }

    /// Emits an HA-scoped structured failure without applying a recovery
    /// policy. Services may use this for transport and dependency failures.
    /// Emits a structured failure event for an external operation.
    pub fn emit_telemetry_failure(
        &self,
        stage: impl Into<String>,
        event: impl Into<String>,
        error: &BlossomError,
    ) {
        self.record_telemetry(|| {
            self.telemetry_event(stage, event)
                .with_outcome("error")
                .with_error(error.to_string())
        });
    }

    pub(super) fn self_public_key(&self) -> PubKey {
        self.state
            .members
            .member(self.state.self_slot)
            .expect("validated HA self slot")
            .public_key()
    }

    pub(super) fn telemetry_event(
        &self,
        stage: impl Into<String>,
        event: impl Into<String>,
    ) -> TelemetryEvent {
        TelemetryEvent::new(TelemetryEventKind::Event, stage, event)
            .with_node(self.self_public_key())
            .with_group_id(self.state.group_id)
            .with_target(self.head().hash, self.head().nonce)
            .with_round(self.state.round.round_id.round)
            .with_field("self_slot", self.state.self_slot.0.to_string())
            .with_field(
                "membership_generation",
                self.state.membership_generation.to_string(),
            )
            .with_field("active_mask", self.state.members.active_mask().to_string())
            .with_field("parameters_hash", self.state.parameters.hash().to_string())
    }

    #[inline]
    pub(super) fn record_telemetry(&self, build: impl FnOnce() -> TelemetryEvent) {
        if self.telemetry.is_enabled() {
            self.telemetry.record(build());
        }
    }

    pub(super) fn record_operational_status(&self) {
        if !self.telemetry.is_enabled() {
            return;
        }
        let Ok(status) = self.status() else {
            return;
        };
        self.telemetry.record_ha_operational_status(
            self.self_public_key(),
            self.state.group_id,
            status.head_hash,
            status.head_nonce,
            &status.operational_status(),
        );
    }

    /// Classifies an error into machine-readable HA recovery directives.
    pub fn assess_failure(&self, error: &BlossomError) -> HaFailureAssessment {
        let assessment = assess_high_availability_failure(error);
        self.record_telemetry(|| {
            self.telemetry_event("service", "ha_failure")
                .with_outcome("error")
                .with_error(error.to_string())
                .with_field("class", format!("{:?}", assessment.class))
                .with_field("retry_in_process", assessment.retry_in_process.to_string())
                .with_field("directives", format!("{:?}", assessment.directives))
        });
        assessment
    }

    /// Returns the consensus-committed HA parameters.
    pub fn parameters(&self) -> HighAvailabilityParameters {
        self.state.parameters
    }

    /// Returns the hash of consensus-committed HA parameters.
    pub fn parameters_hash(&self) -> HashType {
        self.state.parameters.hash()
    }

    /// Borrows the sorted fixed membership and active mask.
    pub fn members(&self) -> &HaMemberSlots {
        &self.state.members
    }

    /// Returns the local member's fixed slot.
    pub fn self_slot(&self) -> HaMemberSlot {
        self.state.self_slot
    }

    /// Borrows the current mutable round state.
    pub fn current_round(&self) -> &HaRoundState {
        &self.state.round
    }

    /// Returns the retained finalized epochs.
    pub fn epochs(&self) -> &[HaEpoch] {
        &self.state.epochs
    }

    /// Returns the retained finalized head epoch.
    pub fn head(&self) -> &HaEpoch {
        self.state.head()
    }

    /// Returns the highest immutable logical application watermark.
    pub fn sealed_watermark(&self) -> Watermark {
        Watermark {
            position: self.state.sealed_nonce().value(),
        }
    }

    /// Returns the lifecycle of a retained epoch nonce.
    pub fn lifecycle(&self, nonce: Nonce) -> EpochLifecycle {
        epoch_lifecycle(
            nonce,
            self.head().nonce,
            self.state.parameters.mutable_epoch_depth,
        )
    }

    /// Gates CAS results and strict/linearizable application reads on the
    /// immutable application watermark.
    /// Fails unless the local sealed watermark covers `required`.
    pub fn require_sealed(&self, required: Watermark) -> Result<()> {
        let sealed = self.sealed_watermark();
        if sealed.position < required.position {
            return Err(BlossomError::WatermarkNotSealed {
                required: required.position,
                sealed: sealed.position,
            });
        }
        Ok(())
    }

    /// Creates the parameter- and membership-bound protocol handshake.
    pub fn handshake(&self) -> HaHandshake {
        let sender = self
            .state
            .members
            .member(self.state.self_slot)
            .expect("validated HA self slot")
            .public_key();
        HaHandshake {
            group_id: self.state.group_id,
            sender,
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            membership_generation: self.state.membership_generation,
            active_mask: self.state.members.active_mask(),
            parameters_hash: self.parameters_hash(),
            head_nonce: self.head().nonce,
            head_hash: self.head().hash,
        }
    }

    /// Validates a peer handshake against committed local scope.
    pub fn validate_handshake(&self, handshake: &HaHandshake) -> Result<()> {
        if handshake.group_id != self.state.group_id
            || handshake.fixed_membership_hash != self.state.members.fixed_identity_hash()
            || handshake.membership_generation != self.state.membership_generation
            || handshake.active_mask != self.state.members.active_mask()
            || handshake.parameters_hash != self.parameters_hash()
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA handshake consensus parameters or membership mismatch".to_string(),
            ));
        }
        let sender_slot = self
            .state
            .members
            .slot_for(&handshake.sender)
            .ok_or(BlossomError::UnknownSender)?;
        if !self.state.members.is_active(sender_slot) {
            return Err(BlossomError::UnknownSender);
        }
        if handshake.head_nonce == self.head().nonce && handshake.head_hash != self.head().hash {
            return Err(BlossomError::WireProtocol(
                "HA handshake reports a conflicting hash at the local head nonce".to_string(),
            ));
        }
        Ok(())
    }

    /// Builds the complete public node status and state revision.
    pub fn status(&self) -> Result<HaNodeStatus> {
        Ok(HaNodeStatus {
            group_id: self.state.group_id,
            self_slot: self.state.self_slot,
            member_count: u8::try_from(self.state.members.member_count())
                .expect("HA membership is at most seven"),
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            active_mask: self.state.members.active_mask(),
            membership_generation: self.state.membership_generation,
            parameters: self.state.parameters,
            parameters_hash: self.parameters_hash(),
            head_nonce: self.head().nonce,
            head_hash: self.head().hash,
            sealed: self.sealed_watermark(),
            revision: self.revision()?,
            availability: array::from_fn(|index| {
                self.state.presence.status(HaMemberSlot(index as u8))
            }),
            committed_membership_changes: u64::try_from(self.state.membership_changes.len())
                .unwrap_or(u64::MAX),
        })
    }

    /// Returns machine-readable service readiness and directives.
    pub fn operational_status(&self) -> Result<HaOperationalStatus> {
        let status = self.status()?.operational_status();
        self.telemetry.record_ha_operational_status(
            self.self_public_key(),
            self.state.group_id,
            self.head().hash,
            self.head().nonce,
            &status,
        );
        Ok(status)
    }

    /// Returns the leaderless active-active replication mode.
    pub const fn replication_mode(&self) -> HaReplicationMode {
        HaReplicationMode::LeaderlessActiveActive
    }

    /// Returns the validated service topology for this membership.
    pub fn service_topology(&self) -> HaServiceTopology {
        HaServiceTopology::active_active(self.state.members.member_count())
            .expect("validated HA runtime membership is between two and seven")
    }

    /// Compares a peer status with local recovery and membership state.
    pub fn assess_peer_status(&self, peer: &HaNodeStatus) -> Result<HaPeerAssessment> {
        Ok(self.status()?.assess_peer(peer))
    }

    /// Exports finalized HA history and committed membership metadata for
    /// direct application-managed catch-up.
    /// Exports public-only finalized state for application-managed recovery.
    pub fn recovery_snapshot(&self) -> HaRecoverySnapshot {
        HaRecoverySnapshot {
            format_version: HIGH_AVAILABILITY_RECOVERY_SNAPSHOT_VERSION,
            group_id: self.state.group_id,
            members: self.state.members.public_only(),
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            membership_generation: self.state.membership_generation,
            parameters: self.state.parameters,
            parameters_hash: self.parameters_hash(),
            checkpoint: self.state.checkpoint.clone(),
            epochs: self.state.epochs.clone(),
            presence: self.state.presence.clone(),
            membership_changes: self.state.membership_changes.clone(),
            amendments: self.state.amendments.clone(),
        }
    }

    /// Returns the current certified local history checkpoint.
    pub fn history_checkpoint(&self) -> Option<&HaHistoryCheckpoint> {
        self.state.checkpoint.as_ref()
    }

    /// Returns the number of finalized epochs retained locally.
    pub fn retained_epoch_count(&self) -> usize {
        self.state.epochs.len()
    }

    /// Compacts finalized history through an exact sealed epoch.
    ///
    /// The retained first epoch is the checkpoint anchor. Membership
    /// certificates and amendments already summarized by the checkpoint are
    /// removed, while the cumulative revision remains unchanged.
    /// Certifies and compacts sealed protocol history through `through`.
    pub fn compact_history_through(&mut self, through: Nonce) -> Result<HaHistoryCheckpoint> {
        if self.lifecycle(through) != EpochLifecycle::Sealed {
            return Err(BlossomError::InvalidConfiguration(
                "HA history can only compact through a sealed epoch".to_string(),
            ));
        }
        let target_index = self
            .state
            .epochs
            .iter()
            .position(|epoch| epoch.nonce == through)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "HA checkpoint target is not in retained history".to_string(),
                )
            })?;
        if target_index == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "HA checkpoint target must advance the retained anchor".to_string(),
            ));
        }
        let revision_before = self.revision()?;
        let (membership_generation, active_mask, presence) =
            self.replay_checkpoint_state_through(target_index)?;
        let mut history_accumulator = self
            .state
            .checkpoint
            .as_ref()
            .map_or(HashType::default(), |checkpoint| {
                checkpoint.history_accumulator
            });
        let first_unaccumulated = usize::from(self.state.checkpoint.is_some());
        for epoch in self
            .state
            .epochs
            .iter()
            .take(target_index + 1)
            .skip(first_unaccumulated)
        {
            history_accumulator = accumulate_history(
                history_accumulator,
                self.logical_epoch_record_hashes(epoch.nonce)?,
            );
        }
        let through_epoch = self.state.epochs[target_index].clone();
        let mut checkpoint = HaHistoryCheckpoint {
            format_version: HIGH_AVAILABILITY_HISTORY_CHECKPOINT_VERSION,
            group_id: self.state.group_id,
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            parameters_hash: self.parameters_hash(),
            membership_generation,
            active_mask,
            presence,
            history_accumulator,
            approval_mask: through_epoch.confirmation_mask,
            through_epoch,
            checkpoint_hash: HashType::default(),
        };
        checkpoint.checkpoint_hash = checkpoint.compute_hash()?;
        checkpoint.validate(&self.state.members, self.state.parameters)?;

        let original = self.state.clone();
        self.state.epochs = self.state.epochs[target_index..].to_vec();
        self.state
            .membership_changes
            .retain(|certificate| certificate.proposal.effective_nonce > through);
        self.state
            .amendments
            .retain(|amendment| amendment.target_epoch_nonce > through);
        self.state.checkpoint = Some(checkpoint.clone());
        if let Err(error) = self
            .state
            .validate()
            .and_then(|_| {
                (self.revision()? == revision_before)
                    .then_some(())
                    .ok_or_else(|| {
                        BlossomError::WireProtocol(
                            "HA compaction changed the state revision".to_string(),
                        )
                    })
            })
            .and_then(|_| self.persist())
        {
            self.state = original;
            return Err(error);
        }
        Ok(checkpoint)
    }

    pub(super) fn replay_checkpoint_state_through(
        &self,
        target_index: usize,
    ) -> Result<(u64, u8, HaPresenceTracker)> {
        let mut members = self.state.members.clone();
        let mut generation;
        let mut presence;
        if let Some(checkpoint) = &self.state.checkpoint {
            members.active_mask = checkpoint.active_mask;
            generation = checkpoint.membership_generation;
            presence = checkpoint.presence.clone();
        } else {
            members.active_mask = low_bits(members.member_count);
            generation = 0;
            presence = HaPresenceTracker::default();
        }
        let mut change_index = 0usize;
        for epoch in self
            .state
            .epochs
            .iter()
            .enumerate()
            .skip(1)
            .take(target_index)
            .map(|(_, epoch)| epoch)
        {
            while self
                .state
                .membership_changes
                .get(change_index)
                .is_some_and(|certificate| certificate.proposal.effective_nonce == epoch.nonce)
            {
                HighAvailabilityRuntimeState::replay_membership_change(
                    &mut members,
                    &mut presence,
                    self.state.membership_changes[change_index],
                )?;
                generation = generation.checked_add(1).ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "HA membership generation overflow".to_string(),
                    )
                })?;
                change_index += 1;
            }
            presence.observe_epoch(
                &members,
                epoch.presence_mask,
                epoch.nonce,
                self.state.parameters,
            );
        }
        Ok((generation, members.active_mask(), presence))
    }

    /// Installs a trusted peer's finalized recovery snapshot. Local transient
    /// round work must be empty so accepted writes and durable vote locks are
    /// never discarded implicitly.
    /// Validates and durably installs a recovery snapshot before exposing it.
    pub fn install_recovery_snapshot(
        &mut self,
        snapshot: HaRecoverySnapshot,
    ) -> Result<StateRevision> {
        snapshot.members.validate()?;
        if snapshot.format_version != HIGH_AVAILABILITY_RECOVERY_SNAPSHOT_VERSION
            || snapshot.group_id != self.state.group_id
            || snapshot.parameters != self.state.parameters
            || snapshot.parameters_hash != snapshot.parameters.hash()
            || snapshot.fixed_membership_hash != snapshot.members.fixed_identity_hash()
            || !snapshot.members.same_fixed_identities(&self.state.members)
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA recovery snapshot configuration mismatch".to_string(),
            ));
        }
        if let Some(checkpoint) = &snapshot.checkpoint {
            checkpoint.validate(&snapshot.members, snapshot.parameters)?;
        }
        let local_head = self.head().clone();
        let snapshot_head = snapshot
            .epochs
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let checkpoint_covers_local = snapshot
            .checkpoint
            .as_ref()
            .is_some_and(|checkpoint| checkpoint.through_epoch.nonce >= local_head.nonce);
        let suffix_contains_local = snapshot
            .epochs
            .iter()
            .any(|epoch| epoch.nonce == local_head.nonce && epoch.hash == local_head.hash);
        if snapshot_head.nonce < local_head.nonce
            || (!checkpoint_covers_local && !suffix_contains_local)
        {
            return Err(BlossomError::WireProtocol(
                "HA recovery snapshot would roll back or replace finalized history".to_string(),
            ));
        }
        let round = &self.state.round;
        if round.received_mask != 0
            || round.acknowledgements.iter().any(|mask| *mask != 0)
            || round.confirmations.iter().any(Option::is_some)
            || round.confirmed_candidate.is_some()
            || round.finalized.is_some()
            || self.state.membership_vote_lock.is_some()
            || self.state.membership_votes.iter().any(Option::is_some)
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA recovery requires an empty local round with no durable vote lock".to_string(),
            ));
        }

        // Keep this process's local endpoint and secret material. Only the
        // fixed public-key identities and committed active mask cross the
        // recovery boundary.
        let mut recovered_members = self.state.members.clone();
        recovered_members.active_mask = snapshot.members.active_mask();
        recovered_members.validate()?;
        let next_round = HaRoundId {
            group_id: self.state.group_id,
            fixed_membership_hash: recovered_members.fixed_identity_hash(),
            membership_generation: snapshot.membership_generation,
            active_mask: recovered_members.active_mask(),
            parameters_hash: self.parameters_hash(),
            previous_epoch_hash: snapshot_head.hash,
            previous_epoch_nonce: snapshot_head.nonce,
            nonce: snapshot_head.nonce.new_next(),
            round: 0,
        };
        let replacement = HighAvailabilityRuntimeState {
            group_id: self.state.group_id,
            self_slot: self.state.self_slot,
            members: recovered_members.clone(),
            membership_generation: snapshot.membership_generation,
            parameters: self.state.parameters,
            checkpoint: snapshot.checkpoint,
            epochs: snapshot.epochs,
            round: HaRoundState::new(next_round, &recovered_members)?,
            presence: snapshot.presence,
            membership_vote_lock: None,
            membership_votes: array::from_fn(|_| None),
            membership_changes: snapshot.membership_changes,
            amendments: snapshot.amendments,
        };
        replacement.validate()?;
        if let Some(store) = &self.store {
            store.persist(&replacement)?;
        }
        self.state = replacement;
        let revision = self.revision()?;
        self.record_telemetry(|| {
            self.telemetry_event("recovery", "snapshot_installed")
                .with_outcome("ok")
                .with_field("revision_hash", revision.revision_hash.to_string())
                .with_field("sealed_watermark", revision.sealed.position.to_string())
        });
        self.record_operational_status();
        Ok(revision)
    }
}
