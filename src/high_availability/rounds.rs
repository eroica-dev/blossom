//! Dispatch, acknowledgement, confirmation, and epoch-finalization transitions.

use super::*;

impl HighAvailabilityRuntime {
    /// Builds and durably records this member's next dispatch.
    pub fn build_dispatch(
        &mut self,
        transactions: Vec<crate::block::Transaction>,
    ) -> Result<HaDispatch> {
        self.build_dispatch_with_created(transactions, None)
    }

    /// Builds this node's dispatch with an explicit block creation timestamp.
    ///
    /// Deterministic simulations and replay verification can use this method
    /// to remove wall-clock time from the protocol input. Production callers
    /// should normally use [`Self::build_dispatch`].
    /// Builds a dispatch with an explicit deterministic creation timestamp.
    pub fn build_dispatch_at(
        &mut self,
        transactions: Vec<crate::block::Transaction>,
        created_micros: u128,
    ) -> Result<HaDispatch> {
        self.build_dispatch_with_created(transactions, Some(created_micros))
    }

    pub(super) fn build_dispatch_with_created(
        &mut self,
        transactions: Vec<crate::block::Transaction>,
        created_micros: Option<u128>,
    ) -> Result<HaDispatch> {
        self.validate_amendment_transactions(&transactions, self.state.round.round_id.nonce)?;
        let member = self
            .state
            .members
            .member(self.state.self_slot)
            .ok_or(BlossomError::UnknownSender)?;
        let mut block = Block::default();
        if let Some(created_micros) = created_micros {
            block.body.created = created_micros;
        }
        block.body.last_epoch = self.state.round.round_id.previous_epoch_hash;
        block.body.nonce = self.state.round.round_id.nonce;
        block.body.txs = transactions;
        block.seal_unsigned(member.public_key());
        let dispatch = HaDispatch {
            round_id: self.state.round.round_id,
            sender: self.state.self_slot,
            block_hash: block.hash,
            block,
        };
        self.state
            .round
            .receive_dispatch(&self.state.members, dispatch.clone())?;
        self.record_telemetry(|| {
            self.telemetry_event("dispatch", "dispatch_built")
                .with_outcome("ok")
                .with_field("slot", dispatch.sender.0.to_string())
                .with_field("block_hash", dispatch.block_hash.to_string())
                .with_field("transactions", dispatch.block.body.txs.len().to_string())
                .with_field(
                    "bytes",
                    borsh::object_length(&dispatch.block)
                        .unwrap_or_default()
                        .to_string(),
                )
        });
        // The local block becomes externally durable evidence when
        // `acknowledge()` persists the complete receipt state. A crash before
        // that point emitted no acknowledgement and may safely replay.
        Ok(dispatch)
    }

    /// Validates and incorporates one member dispatch.
    pub fn receive_dispatch(&mut self, dispatch: HaDispatch) -> Result<HaRuntimeEvent> {
        if dispatch.round_id != self.state.round.round_id {
            if dispatch.round_id.nonce < self.state.round.round_id.nonce {
                return Ok(HaRuntimeEvent::Dispatch(HaDispatchOutcome::Late {
                    target_epoch: dispatch.round_id.nonce,
                }));
            }
            return Err(BlossomError::WireProtocol(
                "future HA dispatch cannot be applied before catch-up".to_string(),
            ));
        }
        self.validate_amendment_transactions(
            &dispatch.block.body.txs,
            self.state.round.round_id.nonce,
        )?;
        let outcome = self
            .state
            .round
            .receive_dispatch(&self.state.members, dispatch)?;
        // Do not fsync each arrival. The receiver persists all accepted block
        // bytes before broadcasting its monotonic acknowledgement.
        self.record_telemetry(|| {
            self.telemetry_event("dispatch", "dispatch_received")
                .with_outcome("ok")
                .with_field("outcome", format!("{outcome:?}"))
        });
        Ok(HaRuntimeEvent::Dispatch(outcome))
    }

    /// Produces this member's monotonic received-slot acknowledgement.
    pub fn acknowledge(&mut self) -> Result<HaAcknowledge> {
        let sender_index = self.state.self_slot.index();
        let previous_acknowledgement = self.state.round.acknowledgements[sender_index];
        let acknowledgement = self
            .state
            .round
            .acknowledge(&self.state.members, self.state.self_slot)?;
        if let Err(error) = self.persist() {
            self.state.round.acknowledgements[sender_index] = previous_acknowledgement;
            return Err(error);
        }
        self.record_telemetry(|| {
            self.telemetry_event("acknowledge", "acknowledgement_persisted")
                .with_outcome("ok")
                .with_field("sender_slot", acknowledgement.sender.0.to_string())
                .with_field("received_mask", acknowledgement.received_mask.to_string())
        });
        Ok(acknowledgement)
    }

    /// Validates and incorporates one member acknowledgement.
    pub fn receive_acknowledgement(
        &mut self,
        acknowledgement: HaAcknowledge,
    ) -> Result<HaRuntimeEvent> {
        if acknowledgement.round_id.nonce < self.state.round.round_id.nonce {
            if self
                .state
                .epochs
                .iter()
                .any(|epoch| epoch.nonce == acknowledgement.round_id.nonce)
            {
                return Ok(HaRuntimeEvent::Acknowledged);
            }
            return Err(BlossomError::WireProtocol(
                "HA acknowledgement targets an unknown stale epoch".to_string(),
            ));
        }
        let sender = acknowledgement.sender;
        let received_mask = acknowledgement.received_mask;
        self.state
            .round
            .receive_acknowledgement(&self.state.members, acknowledgement)?;
        self.record_telemetry(|| {
            self.telemetry_event("acknowledge", "acknowledgement_received")
                .with_outcome("ok")
                .with_field("sender_slot", sender.0.to_string())
                .with_field("received_mask", received_mask.to_string())
        });
        // Acknowledgement observations are replayable until this node creates
        // its own durable confirmation lock.
        Ok(HaRuntimeEvent::Acknowledged)
    }

    /// Durably confirms the current candidate.
    ///
    /// If this process restarts after persisting its lock but before sending
    /// the message, calling `confirm` again reconstructs and returns the exact
    /// same confirmation. It never creates a second candidate.
    /// Durably locks and returns one candidate confirmation.
    pub fn confirm(&mut self) -> Result<(HaConfirm, Option<HaEpoch>)> {
        let previous_confirmations = self.state.round.confirmations;
        let previous_confirmed_candidate = self.state.round.confirmed_candidate;
        let previous_finalized = self.state.round.finalized.clone();
        let confirmation = self
            .state
            .round
            .confirm(&self.state.members, self.state.self_slot)?;
        // The confirmation lock is durable before the caller can broadcast.
        if let Err(error) = self.persist() {
            self.state.round.confirmations = previous_confirmations;
            self.state.round.confirmed_candidate = previous_confirmed_candidate;
            self.state.round.finalized = previous_finalized;
            return Err(error);
        }
        let epoch = self.commit_finalized_round()?;
        self.record_telemetry(|| {
            self.telemetry_event("confirm", "confirmation_persisted")
                .with_outcome("ok")
                .with_field("sender_slot", confirmation.sender.0.to_string())
                .with_field(
                    "candidate_digest",
                    confirmation.candidate.digest.to_string(),
                )
        });
        Ok((confirmation, epoch))
    }

    /// Validates one confirmation and finalizes when a majority matches.
    pub fn receive_confirmation(&mut self, confirmation: HaConfirm) -> Result<HaRuntimeEvent> {
        if confirmation.round_id.nonce < self.state.round.round_id.nonce {
            let Some(epoch) = self
                .state
                .epochs
                .iter()
                .find(|epoch| epoch.nonce == confirmation.round_id.nonce)
            else {
                return Err(BlossomError::WireProtocol(
                    "HA confirmation targets an unknown stale epoch".to_string(),
                ));
            };
            if epoch.candidate.digest != confirmation.candidate.digest {
                return Err(BlossomError::WireProtocol(
                    "stale HA confirmation conflicts with finalized candidate".to_string(),
                ));
            }
            return Ok(HaRuntimeEvent::Confirmed);
        }
        let sender = confirmation.sender;
        let candidate_digest = confirmation.candidate.digest;
        self.state
            .round
            .receive_confirmation(&self.state.members, confirmation)?;
        self.record_telemetry(|| {
            self.telemetry_event("confirm", "confirmation_received")
                .with_outcome("ok")
                .with_field("sender_slot", sender.0.to_string())
                .with_field("candidate_digest", candidate_digest.to_string())
        });
        match self.commit_finalized_round()? {
            Some(epoch) => Ok(HaRuntimeEvent::Finalized(Box::new(epoch))),
            // Peer confirmations can be retransmitted. Persisting each partial
            // count would add O(N²) fsyncs without strengthening safety.
            None => Ok(HaRuntimeEvent::Confirmed),
        }
    }

    /// Dispatches one decoded HA protocol message to its transition.
    pub fn receive_message(&mut self, message: HaMessage) -> Result<HaRuntimeEvent> {
        match message {
            HaMessage::Handshake(message) => {
                self.validate_handshake(&message)?;
                Ok(HaRuntimeEvent::HandshakeAccepted)
            }
            HaMessage::MembershipVote(message) => self.receive_membership_vote(message),
            HaMessage::Dispatch(message) => self.receive_dispatch(message),
            HaMessage::Acknowledge(message) => self.receive_acknowledgement(message),
            HaMessage::Confirm(message) => self.receive_confirmation(message),
        }
    }

    pub(super) fn commit_finalized_round(&mut self) -> Result<Option<HaEpoch>> {
        let Some(finalized) = self.state.round.finalized.clone() else {
            return Ok(None);
        };
        let mut committed_amendments = Vec::new();
        for slot in finalized.ordered_slots.as_slice() {
            let block = self.state.round.blocks[usize::from(*slot)]
                .as_ref()
                .ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "finalized HA amendment scan is missing a candidate block".to_string(),
                    )
                })?;
            for transaction in &block.body.txs {
                if let Some(amendment) = decode_amendment_transaction(transaction)? {
                    self.validate_proposed_amendment(&amendment, finalized.round_id.nonce)?;
                    let amendment_hash = amendment.hash()?;
                    if let Some(existing) =
                        committed_amendments
                            .iter()
                            .find(|existing: &&AmendmentRecord| {
                                existing.command_identity == amendment.command_identity
                            })
                    {
                        if existing.hash()? != amendment_hash {
                            return Err(BlossomError::InvalidConfiguration(
                                "conflicting HA amendments for one command identity".to_string(),
                            ));
                        }
                    } else {
                        committed_amendments.push(amendment);
                    }
                }
            }
        }
        let epoch =
            HaEpoch::from_finalized(finalized, &self.state.round.blocks, self.state.parameters);
        let next_id = HaRoundId {
            group_id: self.state.group_id,
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            membership_generation: self.state.membership_generation,
            active_mask: self.state.members.active_mask(),
            parameters_hash: self.state.parameters.hash(),
            previous_epoch_hash: epoch.hash,
            previous_epoch_nonce: epoch.nonce,
            nonce: epoch.nonce.new_next(),
            round: 0,
        };
        let next_round = HaRoundState::new(next_id, &self.state.members)?;
        let previous_presence = self.state.presence.clone();
        let previous_epoch_count = self.state.epochs.len();
        let previous_amendment_count = self.state.amendments.len();
        self.state.presence.observe_epoch(
            &self.state.members,
            epoch.presence_mask,
            epoch.nonce,
            self.state.parameters,
        );
        self.state.epochs.push(epoch.clone());
        for amendment in committed_amendments {
            if !self
                .state
                .amendments
                .iter()
                .any(|existing| existing.command_identity == amendment.command_identity)
            {
                self.state.amendments.push(amendment);
            }
        }
        let previous_round = std::mem::replace(&mut self.state.round, next_round);
        if let Err(error) = self.persist() {
            self.state.round = previous_round;
            self.state.presence = previous_presence;
            self.state.epochs.truncate(previous_epoch_count);
            self.state.amendments.truncate(previous_amendment_count);
            return Err(error);
        }
        self.record_telemetry(|| {
            self.telemetry_event("finality", "epoch_finalized")
                .with_outcome("ok")
                .with_target(epoch.hash, epoch.nonce)
                .with_field("candidate_digest", epoch.candidate.digest.to_string())
                .with_field("included_slots", epoch.candidate.included_mask.to_string())
                .with_field("presence_mask", epoch.presence_mask.to_string())
                .with_field("confirmation_mask", epoch.confirmation_mask.to_string())
        });
        let sealed = self.sealed_watermark();
        if sealed.position > 0 {
            self.record_telemetry(|| {
                self.telemetry_event("seal", "sealed_watermark_observed")
                    .with_outcome("ok")
                    .with_field("watermark", sealed.position.to_string())
            });
        }
        self.record_operational_status();
        Ok(Some(epoch))
    }
}
