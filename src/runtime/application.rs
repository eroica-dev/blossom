//! Opaque application state and optional filtered-payload availability.
//!
//! These methods commit and expose application-owned bytes without assigning
//! them domain semantics.

use super::*;

impl NodeRuntime {
    /// Sets the opaque application state that will be piggy-backed onto this
    /// node's next dispatched block.
    ///
    /// Blossom validates only the size budget and commits these bytes into the
    /// block hash; parsing and versioning stay with the application.
    pub fn set_application_state(&self, bytes: impl Into<Vec<u8>>) -> Result<()> {
        self.ensure_consensus_mode("set application state")?;
        self.inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .set_application_state(bytes)
    }

    /// Returns the opaque application state queued for the next local block.
    pub fn application_state(&self) -> BlockApplicationState {
        self.inner
            .local_blocks
            .read()
            .expect("block lock poisoned")
            .application_state()
            .clone()
    }

    /// Adds a signed encounter record to the next locally dispatched block.
    ///
    /// Encounter records are protocol-owned evidence, not membership state.
    /// They are hash-committed into the block and independently signed by the
    /// observing node.
    pub fn add_encounter_record(&self, record: EncounterRecord) -> Result<HashType> {
        self.ensure_consensus_mode("add encounter record")?;
        let self_key = self.self_node().public_key();
        if record.body.observer != self_key {
            return Err(BlossomError::KeyMismatch);
        }
        self.inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .add_encounter_record(record)
    }

    /// Signs encounter evidence for a consensus peer and phase.
    pub fn sign_encounter_record(
        &self,
        subject: PubKey,
        round: u8,
        phase: EncounterPhase,
        outcome: EncounterOutcome,
        evidence_hash: Option<HashType>,
        observed_at_micros: u128,
    ) -> Result<EncounterRecord> {
        self.ensure_consensus_mode("sign encounter record")?;
        let self_node = self.self_node();
        let target = self.next_epoch_target()?;
        let mut body = EncounterRecordBody::new(
            self_node.public_key(),
            subject,
            target.last_epoch,
            target.nonce,
            round,
            phase,
            outcome,
        )
        .observed_at_micros(observed_at_micros);
        body.evidence_hash = evidence_hash;

        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        EncounterRecord::signed(body, signer)
    }

    /// Signs and queues one encounter record for the next local block.
    pub fn record_encounter(
        &self,
        subject: PubKey,
        round: u8,
        phase: EncounterPhase,
        outcome: EncounterOutcome,
        evidence_hash: Option<HashType>,
        observed_at_micros: u128,
    ) -> Result<HashType> {
        let record = self.sign_encounter_record(
            subject,
            round,
            phase,
            outcome,
            evidence_hash,
            observed_at_micros,
        )?;
        self.add_encounter_record(record)
    }

    /// Records that `subject` omitted a required signature in `phase`.
    pub fn record_missing_signature(
        &self,
        subject: PubKey,
        round: u8,
        phase: EncounterPhase,
        observed_at_micros: u128,
    ) -> Result<HashType> {
        self.record_encounter(
            subject,
            round,
            phase,
            EncounterOutcome::MissingSignature,
            None,
            observed_at_micros,
        )
    }

    /// Returns round members that have not produced a signed message for the
    /// requested consensus phase, from this node's current local view.
    pub fn missing_signature_subjects(
        &self,
        round: u8,
        phase: EncounterPhase,
    ) -> Result<Vec<PubKey>> {
        self.ensure_consensus_mode("inspect missing signatures")?;
        let target = self.next_epoch_target()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let consensus = state.get_mut_consensus(&target.last_epoch, target.nonce);
        let mut missing = consensus.peers(round);
        let Some(quorum) = consensus.quorum.get(&round) else {
            return Ok(missing);
        };

        missing.retain(|subject| !quorum_has_signature_from(quorum, *subject, phase));
        Ok(missing)
    }

    /// Queues signed missing-signature records for every expected peer that has
    /// not produced a signed message for the requested phase.
    pub fn record_missing_signatures(
        &self,
        round: u8,
        phase: EncounterPhase,
        observed_at_micros: u128,
    ) -> Result<Vec<HashType>> {
        let subjects = self.missing_signature_subjects(round, phase)?;
        subjects
            .into_iter()
            .map(|subject| self.record_missing_signature(subject, round, phase, observed_at_micros))
            .collect()
    }

    /// Returns encounter records queued for the next local block.
    pub fn pending_encounter_records(&self) -> Vec<EncounterRecord> {
        self.inner
            .local_blocks
            .read()
            .expect("block lock poisoned")
            .encounter_records()
            .to_vec()
    }

    /// Returns signed encounter evidence observed in committed or verified
    /// blocks. This is intentionally just evidence; membership decisions should
    /// be derived by a deterministic reducer over committed records.
    pub fn observed_encounter_records(&self) -> Vec<ObservedEncounterRecord> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let mut records = Vec::new();

        for epoch in &state.epochchain.epochchain {
            for (block_hash, block) in &epoch.body.blocks {
                record_observed_encounters(&mut records, epoch.body.group_id, *block_hash, block);
            }
        }

        for consensus in state.consensus.values() {
            for quorum in consensus.quorum.values() {
                for (block_hash, block) in &quorum.verified_blocks {
                    record_observed_encounters(
                        &mut records,
                        self.inner.group_id,
                        *block_hash,
                        block,
                    );
                }
            }
        }

        records
    }

    /// Returns the latest verified or committed application state observed for
    /// each peer.
    ///
    /// This is the read side of [`NodeRuntime::set_application_state`]: peer
    /// bytes arrive in normal consensus blocks rather than through a separate
    /// application message channel.
    pub fn peer_application_states(&self) -> BTreeMap<PubKey, PeerApplicationState> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let self_key = state.self_node.public_key();
        let mut peer_states = BTreeMap::new();

        for epoch in &state.epochchain.epochchain {
            for (block_hash, block) in &epoch.body.blocks {
                if block.body.validator != self_key {
                    record_peer_application_state(
                        &mut peer_states,
                        epoch.body.group_id,
                        *block_hash,
                        block,
                        block.body.last_epoch,
                        block.body.nonce,
                    );
                }
            }
        }

        for consensus in state.consensus.values() {
            for quorum in consensus.quorum.values() {
                for (block_hash, block) in &quorum.verified_blocks {
                    if block.body.validator != self_key {
                        record_peer_application_state(
                            &mut peer_states,
                            self.inner.group_id,
                            *block_hash,
                            block,
                            block.body.last_epoch,
                            block.body.nonce,
                        );
                    }
                }
            }
        }

        peer_states
    }

    #[cfg(feature = "availability-gossip")]
    /// Stores a filtered transaction payload addressed to the local node.
    pub fn store_filtered_payload_from_transaction(
        &self,
        tx: &crate::block::Transaction,
    ) -> Result<Option<AvailabilityEntry>> {
        let holder = self.self_node().public_key();
        self.inner
            .availability
            .write()
            .expect("availability lock poisoned")
            .store_transaction(self.inner.group_id, holder, tx)
    }

    #[cfg(feature = "availability-gossip")]
    /// Returns locally held availability entries for this consensus group.
    pub fn local_availability_entries(&self) -> Vec<AvailabilityEntry> {
        self.inner
            .availability
            .read()
            .expect("availability lock poisoned")
            .local_entries(self.inner.group_id)
    }

    #[cfg(feature = "availability-gossip")]
    /// Returns availability entries most recently advertised by peers.
    pub fn peer_availability_entries(&self) -> Vec<(PubKey, AvailabilityEntry)> {
        self.inner
            .availability
            .read()
            .expect("availability lock poisoned")
            .peer_entries()
    }

    #[cfg(feature = "availability-gossip")]
    /// Builds a signed advertisement of locally available filtered payloads.
    pub fn availability_gossip(&self) -> Result<AvailabilityGossip> {
        let self_node = self.self_node();
        let body = AvailabilityGossipBody {
            scope: self.inner.group_id,
            holder: self_node.public_key(),
            entries: self.local_availability_entries(),
        };
        if self.inner.trust_mode.is_trusted() {
            return AvailabilityGossip::trusted(body);
        }
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        AvailabilityGossip::signed(body, signer)
    }

    #[cfg(feature = "availability-gossip")]
    /// Validates and records a peer's availability advertisement.
    pub fn receive_availability_gossip(
        &self,
        gossip: AvailabilityGossip,
    ) -> Result<AvailabilityReceipt> {
        if gossip.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "availability gossip scope {} does not match runtime group {}",
                gossip.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&gossip.body.holder) {
            return Err(BlossomError::UnknownSender);
        }
        if !self.inner.trust_mode.is_trusted() {
            gossip.verify()?;
        } else {
            gossip.body.validate()?;
        }
        let accepted = self
            .inner
            .availability
            .write()
            .expect("availability lock poisoned")
            .record_gossip(&gossip)?;
        Ok(AvailabilityReceipt {
            scope: self.inner.group_id,
            holder: gossip.body.holder,
            entries_accepted: accepted,
        })
    }

    #[cfg(feature = "availability-gossip")]
    /// Builds a request for one filtered payload slot.
    pub fn filtered_payload_fetch(
        &self,
        slot_hash: HashType,
        payload_commitment: HashType,
    ) -> Result<FilteredPayloadFetch> {
        let self_node = self.self_node();
        let body = crate::availability::FilteredPayloadFetchBody {
            scope: self.inner.group_id,
            requester: self_node.public_key(),
            slot_hash,
            payload_commitment,
        };
        if self.inner.trust_mode.is_trusted() {
            return Ok(FilteredPayloadFetch::trusted(body));
        }
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        Ok(FilteredPayloadFetch::signed(body, signer))
    }

    #[cfg(feature = "availability-gossip")]
    /// Builds a bounded request for multiple filtered payload slots.
    pub fn filtered_payload_batch_fetch(
        &self,
        requests: Vec<FilteredPayloadRequest>,
    ) -> Result<FilteredPayloadBatchFetch> {
        let self_node = self.self_node();
        let body = FilteredPayloadBatchFetchBody {
            scope: self.inner.group_id,
            requester: self_node.public_key(),
            requests,
        };
        if self.inner.trust_mode.is_trusted() {
            return FilteredPayloadBatchFetch::trusted(body);
        }
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        FilteredPayloadBatchFetch::signed(body, signer)
    }

    #[cfg(feature = "availability-gossip")]
    /// Validates a fetch and returns the locally held payload, if available.
    pub fn serve_filtered_payload_fetch(
        &self,
        fetch: FilteredPayloadFetch,
    ) -> Result<Option<FilteredPayloadDelivery>> {
        if fetch.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "filtered payload fetch scope {} does not match runtime group {}",
                fetch.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&fetch.body.requester) {
            return Err(BlossomError::UnknownSender);
        }
        if !self.inner.trust_mode.is_trusted() {
            fetch.verify()?;
        }
        let Some(payload) = self
            .inner
            .availability
            .read()
            .expect("availability lock poisoned")
            .get_local_payload(
                self.inner.group_id,
                &fetch.body.slot_hash,
                &fetch.body.payload_commitment,
                &fetch.body.requester,
            )?
        else {
            return Ok(None);
        };
        let body = payload.delivery_body();
        if self.inner.trust_mode.is_trusted() {
            return FilteredPayloadDelivery::trusted(body).map(Some);
        }
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        FilteredPayloadDelivery::signed(body, signer).map(Some)
    }

    #[cfg(feature = "availability-gossip")]
    /// Validates a batch fetch and returns all locally available matches.
    pub fn serve_filtered_payload_batch_fetch(
        &self,
        fetch: FilteredPayloadBatchFetch,
    ) -> Result<FilteredPayloadBatchDelivery> {
        if fetch.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "filtered payload batch fetch scope {} does not match runtime group {}",
                fetch.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&fetch.body.requester) {
            return Err(BlossomError::UnknownSender);
        }
        if !self.inner.trust_mode.is_trusted() {
            fetch.verify()?;
        } else {
            fetch.body.validate()?;
        }

        let mut items = Vec::new();
        {
            let availability = self
                .inner
                .availability
                .read()
                .expect("availability lock poisoned");
            for request in &fetch.body.requests {
                if let Some(payload) = availability.get_local_payload(
                    self.inner.group_id,
                    &request.slot_hash,
                    &request.payload_commitment,
                    &fetch.body.requester,
                )? {
                    items.push(payload.delivery_item());
                }
            }
        }

        let body = FilteredPayloadBatchDeliveryBody {
            scope: self.inner.group_id,
            holder: self.self_node().public_key(),
            items,
        };
        if self.inner.trust_mode.is_trusted() {
            return FilteredPayloadBatchDelivery::trusted(body);
        }
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        FilteredPayloadBatchDelivery::signed(body, signer)
    }

    #[cfg(feature = "availability-gossip")]
    /// Validates and stores one filtered payload delivery for the local node.
    pub fn receive_filtered_payload(
        &self,
        delivery: FilteredPayloadDelivery,
    ) -> Result<AvailabilityReceipt> {
        if delivery.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "filtered payload scope {} does not match runtime group {}",
                delivery.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&delivery.body.holder) {
            return Err(BlossomError::UnknownSender);
        }
        if !delivery.body.slot.is_target(&self.self_node().public_key()) {
            return Err(BlossomError::WireProtocol(format!(
                "this node is not a target for filtered payload {}",
                delivery.body.slot_hash
            )));
        }
        if !self.inner.trust_mode.is_trusted() {
            delivery.verify()?;
        } else {
            delivery.body.validate()?;
        }
        let holder = self.self_node().public_key();
        self.inner
            .availability
            .write()
            .expect("availability lock poisoned")
            .store_local(
                self.inner.group_id,
                holder,
                delivery.body.slot.clone(),
                delivery.body.payload.clone(),
            )?;
        Ok(AvailabilityReceipt {
            scope: self.inner.group_id,
            holder: delivery.body.holder,
            entries_accepted: 1,
        })
    }

    #[cfg(feature = "availability-gossip")]
    /// Validates and stores a batch of filtered payload deliveries.
    pub fn receive_filtered_payload_batch(
        &self,
        delivery: FilteredPayloadBatchDelivery,
    ) -> Result<AvailabilityReceipt> {
        if delivery.body.scope != self.inner.group_id {
            return Err(BlossomError::WireProtocol(format!(
                "filtered payload batch scope {} does not match runtime group {}",
                delivery.body.scope, self.inner.group_id
            )));
        }
        if !self.is_known_member(&delivery.body.holder) {
            return Err(BlossomError::UnknownSender);
        }
        let self_key = self.self_node().public_key();
        for item in &delivery.body.items {
            if !item.slot.is_target(&self_key) {
                return Err(BlossomError::WireProtocol(format!(
                    "this node is not a target for filtered payload {}",
                    item.slot_hash
                )));
            }
        }
        if !self.inner.trust_mode.is_trusted() {
            delivery.verify()?;
        } else {
            delivery.body.validate()?;
        }

        let mut accepted = 0usize;
        let mut availability = self
            .inner
            .availability
            .write()
            .expect("availability lock poisoned");
        for item in &delivery.body.items {
            availability.store_local(
                self.inner.group_id,
                self_key,
                item.slot.clone(),
                item.payload.clone(),
            )?;
            accepted += 1;
        }
        Ok(AvailabilityReceipt {
            scope: self.inner.group_id,
            holder: delivery.body.holder,
            entries_accepted: accepted,
        })
    }
}
