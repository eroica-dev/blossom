//! Inbound message authentication, validation, buffering, and dispatch.

use super::*;

impl NodeRuntime {
    /// Validates and applies one inbound consensus protocol message.
    pub fn receive_message(&self, message: Msg) -> Result<MessageReceipt> {
        let span = self.start_telemetry_span(message_telemetry_meta(&message));
        let result = (|| {
            self.ensure_consensus_mode("receive consensus message")?;
            self.verify_message_envelope(&message)?;
            if self.buffer_future_round_message_if_needed(&message)? {
                return Ok(MessageReceipt::accepted("future_round_buffered"));
            }
            match message {
                Msg::Dispatch(message) => {
                    self.verify_message_signature(
                        &message.header,
                        MSGKey::Dispatch,
                        &message.body,
                    )?;
                    let mut state = self.inner.state.write().expect("state lock poisoned");
                    if message.header.verify_header(&mut state) == Some(false) {
                        return Err(BlossomError::UnknownSender);
                    }
                    drop(state);
                    self.verify_dispatch_payload(&message.header, &message.body)?;
                    let header = message.header.clone();
                    let verified_blocks = message.body.blocks.clone();
                    self.persist_blocks_if_configured(verified_blocks.values())?;
                    let mut state = self.inner.state.write().expect("state lock poisoned");
                    message.try_accept_into_state(&mut state)?;
                    let quorum =
                        state.get_mut_quorum(&header.last_epoch, header.nonce, header.round);
                    record_verified_dispatch_blocks(quorum, verified_blocks);
                    if self.inner.trust_mode.is_trusted() {
                        quorum.activate_pending_trusted_messages()?;
                    }
                    Ok(MessageReceipt::accepted("dispatch"))
                }
                Msg::EchoResponse(message) => self.receive_echo_response(message),
                Msg::Verification(message) => self.receive_verification(message),
                Msg::Proposal(message) => self.receive_proposal(message),
                Msg::Commit(message) => self.receive_commit(message),
                Msg::EpochStarted(message) => self.receive_epoch_started(message),
                Msg::EchoRequest(message) => self.receive_echo_request(message),
                Msg::EchoReDispatch(message) => self.receive_echo_redispatch(message),
                Msg::RoundSkipVote(message) => self.receive_round_skip_vote(message),
                Msg::RoundSkipCertificate(message) => self.receive_round_skip_certificate(message),
                Msg::ReconcileAppraisal(message) => self.receive_reconcile_appraisal(message),
                Msg::ReconcileRequest(message) => self.receive_reconcile_request(message),
                Msg::ReconcileResponse(message) => self.receive_reconcile_response(message),
                Msg::ReconcileCommit(message) => self.receive_reconcile_commit(message),
                Msg::Ok => Ok(MessageReceipt::accepted("ok")),
                Msg::Fail => Ok(MessageReceipt::accepted("fail")),
                Msg::TrustedAcknowledgement(message) => {
                    self.receive_trusted_acknowledgement(message)
                }
            }
        })();
        self.finish_telemetry_span(span, &result);
        result
    }

    pub(super) fn verify_message_envelope(&self, message: &Msg) -> Result<()> {
        match message {
            Msg::Dispatch(message) => {
                self.verify_message_signature(&message.header, MSGKey::Dispatch, &message.body)
            }
            Msg::EchoResponse(message) => {
                self.verify_message_signature(&message.header, MSGKey::EchoResponse, &message.body)
            }
            Msg::EchoRequest(message) => self.verify_message_signature(
                &message.header,
                MSGKey::EchoRequest,
                &message.requested_blocks,
            ),
            Msg::EchoReDispatch(message) => self.verify_message_signature(
                &message.header,
                MSGKey::EchoReDispatch,
                &message.redispatched_blocks,
            ),
            Msg::Verification(message) => {
                self.verify_message_signature(&message.header, MSGKey::Verification, &message.body)
            }
            Msg::TrustedAcknowledgement(message) => self.verify_message_signature(
                &message.header,
                MSGKey::TrustedAcknowledgement,
                &message.body,
            ),
            Msg::Proposal(message) => {
                self.verify_message_signature(&message.header, MSGKey::Proposal, &message.body)
            }
            Msg::Commit(message) => {
                self.verify_message_signature(&message.header, MSGKey::Commit, &message.body)
            }
            Msg::EpochStarted(message) => {
                if self.inner.trust_mode.is_trusted() {
                    self.verify_message_signature(
                        &message.header,
                        MSGKey::EpochStarted,
                        &message.body,
                    )
                } else {
                    message
                        .header
                        .verify_signature(MSGKey::EpochStarted, &message.body)
                }
            }
            Msg::RoundSkipVote(message) => {
                self.verify_message_signature(&message.header, MSGKey::RoundSkipVote, &message.body)
            }
            Msg::RoundSkipCertificate(message) => self.verify_message_signature(
                &message.header,
                MSGKey::RoundSkipCertificate,
                &message.body,
            ),
            Msg::ReconcileAppraisal(message) => self.verify_message_signature(
                &message.header,
                MSGKey::ReconcileAppraisal,
                &message.body,
            ),
            Msg::ReconcileRequest(message) => self.verify_message_signature(
                &message.header,
                MSGKey::ReconcileRequest,
                &message.body,
            ),
            Msg::ReconcileResponse(message) => self.verify_message_signature(
                &message.header,
                MSGKey::ReconcileResponse,
                &message.body,
            ),
            Msg::ReconcileCommit(message) => self.verify_message_signature(
                &message.header,
                MSGKey::ReconcileCommit,
                &message.body,
            ),
            Msg::Ok | Msg::Fail => Ok(()),
        }
    }

    pub(super) fn buffer_future_round_message_if_needed(&self, message: &Msg) -> Result<bool> {
        let Some((header, kind, body_hash)) = message_header_kind_hash(message) else {
            return Ok(false);
        };
        if matches!(
            kind,
            MSGKey::RoundSkipVote | MSGKey::RoundSkipCertificate | MSGKey::EpochStarted
        ) {
            return Ok(false);
        }

        let mut state = self.inner.state.write().expect("state lock poisoned");
        let global_final_commit = if kind == MSGKey::Commit {
            commit_sender_and_threshold(&mut state, header)
                .map(|(authorized, _)| authorized)
                .unwrap_or(false)
        } else {
            false
        };
        let consensus = state.get_mut_consensus(&header.last_epoch, header.nonce);
        if !global_final_commit && !consensus.is_peer_member_of_round(&header.sender, header.round)
        {
            return Ok(false);
        }
        if header.round <= consensus.round {
            return Ok(false);
        }
        if let Msg::Verification(verification) = message {
            state.seed_prefill_dispatches_into_quorum(
                &header.last_epoch,
                header.nonce,
                header.round,
            );
            let quorum = state.get_mut_quorum(&header.last_epoch, header.nonce, header.round);
            let verified_blocks = quorum.verified_blocks();
            if !verified_blocks.is_empty()
                && verification.body.blocks == verified_blocks
                && verification.body.blocks_hash == quorum.verified_blocks_hash()
            {
                return Ok(false);
            }
        }
        let key = FutureRoundMessageKey {
            last_epoch: header.last_epoch,
            nonce: header.nonce,
            round: header.round,
            kind,
            body_hash,
        };
        self.inner
            .future_round_messages
            .write()
            .expect("future message lock poisoned")
            .entry(key)
            .or_default()
            .push(message.clone());
        Ok(true)
    }

    /// Replays messages buffered for the now-current round.
    pub fn drain_buffered_current_round_messages(&self) -> Result<Vec<Msg>> {
        let target = self.next_epoch_target()?;
        let current_round = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .round
        };
        let mut buffered = self
            .inner
            .future_round_messages
            .write()
            .expect("future message lock poisoned");
        let keys = buffered
            .keys()
            .filter(|key| {
                key.last_epoch == target.last_epoch
                    && key.nonce == target.nonce
                    && key.round <= current_round
            })
            .copied()
            .collect::<Vec<_>>();
        let mut messages = Vec::new();
        for key in keys {
            if let Some(mut drained) = buffered.remove(&key) {
                messages.append(&mut drained);
            }
        }
        Ok(messages)
    }

    /// Validates and buffers a dispatch for the next consensus epoch.
    pub fn receive_prefill_dispatch(&self, dispatch: Dispatch) -> Result<MessageReceipt> {
        let span = self.start_telemetry_span(header_telemetry_meta(
            "prefill_dispatch",
            "receive_prefill_dispatch",
            &dispatch.header,
            Some("PrefillDispatch"),
        ));
        let result = (|| {
            self.ensure_consensus_mode("receive prefill dispatch")?;
            if dispatch.header.round != 0 {
                return Err(BlossomError::WireProtocol(
                    "prefill dispatch must be signed for round 0".to_string(),
                ));
            }
            self.verify_message_signature(&dispatch.header, MSGKey::Dispatch, &dispatch.body)?;
            if !self.is_prefill_recipient_for_sender(&dispatch.header.sender)? {
                return Err(BlossomError::UnknownSender);
            }
            for block in dispatch.body.blocks.values() {
                if block.body.validator != dispatch.header.sender {
                    return Err(BlossomError::WireProtocol(
                        "prefill dispatch may only carry sender-owned blocks".to_string(),
                    ));
                }
            }
            self.verify_dispatch_payload(&dispatch.header, &dispatch.body)?;
            self.persist_blocks_if_configured(dispatch.body.blocks.values())?;
            let mut state = self.inner.state.write().expect("state lock poisoned");
            state.record_prefill_dispatch(&dispatch)?;
            Ok(MessageReceipt::accepted("prefill_dispatch"))
        })();
        self.finish_telemetry_span(span, &result);
        result
    }

    /// Validates and applies a low-latency dispatch hint.
    pub fn receive_hot_dispatch(&self, message: HotDispatch) -> Result<MessageReceipt> {
        let span = self.start_telemetry_span(header_telemetry_meta(
            "dispatch",
            "hot_dispatch_received",
            &message.header,
            Some("HotDispatch"),
        ));
        let result = (|| {
            self.ensure_consensus_mode("receive hot dispatch")?;
            self.ensure_current_header_target(&message.header)?;
            if !self.inner.trust_mode.is_trusted() {
                message.verify_signature()?;
            }
            let mut state = self.inner.state.write().expect("state lock poisoned");
            if message.header.verify_header(&mut state) == Some(false) {
                return Err(BlossomError::UnknownSender);
            }
            drop(state);
            if self.inner.trust_mode.is_trusted() {
                let scan = message.scan_trusted()?;
                let mut state = self.inner.state.write().expect("state lock poisoned");
                let sender = message.header.sender;
                let identity = (message.header.signature, scan.blocks_hash);
                let quorum = state.get_mut_quorum(
                    &message.header.last_epoch,
                    message.header.nonce,
                    message.header.round,
                );
                if let Some(recorded) = quorum.received_dispatch_identities.get(&sender) {
                    if *recorded == identity {
                        return Ok(MessageReceipt::accepted("dispatch_replay"));
                    }
                    return Err(BlossomError::WireProtocol(format!(
                        "conflicting dispatch from {sender}"
                    )));
                }
                quorum.try_push_pending_dispatch(
                    PendingDispatch::Hot(message),
                    configured_max_pending_raw_dispatch_bytes(),
                    configured_max_pending_raw_dispatch_bytes_per_sender(),
                )?;
                quorum.msg_matrix.update_dispatch_received(true, sender);
                quorum.timers.verified_tx = quorum
                    .timers
                    .verified_tx
                    .saturating_add(scan.transaction_count);
                quorum.received_dispatch_identities.insert(sender, identity);
                quorum.received_dispatches.push(sender);
                return Ok(MessageReceipt::accepted("dispatch"));
            }
            let decoded_message = message.to_dispatch()?;
            self.verify_dispatch_payload(&decoded_message.header, &decoded_message.body)?;
            self.persist_blocks_if_configured(decoded_message.body.blocks.values())?;
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let sender = message.header.sender;
            let last_epoch = message.header.last_epoch;
            let nonce = message.header.nonce;
            let round = message.header.round;
            let identity = (message.header.signature, decoded_message.body.blocks_hash);
            let quorum = state.get_mut_quorum(&last_epoch, nonce, round);
            if let Some(recorded) = quorum.received_dispatch_identities.get(&sender) {
                if *recorded == identity {
                    return Ok(MessageReceipt::accepted("dispatch_replay"));
                }
                return Err(BlossomError::WireProtocol(format!(
                    "conflicting dispatch from {sender}"
                )));
            }
            quorum.try_push_pending_dispatch(
                PendingDispatch::Hot(message),
                configured_max_pending_raw_dispatch_bytes(),
                configured_max_pending_raw_dispatch_bytes_per_sender(),
            )?;
            quorum.msg_matrix.update_dispatch_received(true, sender);
            let verified_blocks = decoded_message.body.blocks;
            record_verified_dispatch_blocks(quorum, verified_blocks);
            quorum.received_dispatch_identities.insert(sender, identity);
            quorum.received_dispatches.push(sender);
            Ok(MessageReceipt::accepted("dispatch"))
        })();
        self.finish_telemetry_span(span, &result);
        result
    }

    pub(super) fn receive_echo_request(&self, message: EchoRequest) -> Result<MessageReceipt> {
        self.verify_message_signature(
            &message.header,
            MSGKey::EchoRequest,
            &message.requested_blocks,
        )?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("echo_request"))
    }

    pub(super) fn receive_echo_redispatch(
        &self,
        message: EchoReDispatch,
    ) -> Result<MessageReceipt> {
        self.verify_message_signature(
            &message.header,
            MSGKey::EchoReDispatch,
            &message.redispatched_blocks,
        )?;
        self.verify_redispatched_blocks(&message.redispatched_blocks)?;
        self.persist_blocks_if_configured(message.redispatched_blocks.values())?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        let mut inserted = 0usize;
        for (hash, block) in &message.redispatched_blocks {
            if block.body.last_epoch != message.header.last_epoch
                || block.body.nonce != message.header.nonce
            {
                return Err(BlossomError::WireProtocol(
                    "echo redispatch block targets the wrong epoch or nonce".to_string(),
                ));
            }
            inserted += usize::from(quorum.record_verified_block(*hash, block.clone()));
        }
        if inserted > 0 {
            quorum.verified_blocks_hash = Some(quorum.verified_blocks_hash());
        }
        Ok(MessageReceipt::accepted("echo_redispatch"))
    }

    pub(super) fn receive_round_skip_vote(
        &self,
        message: RoundSkipVoteMessage,
    ) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::RoundSkipVote, &message.body)?;
        let manifest_hash = message.body.manifest.hash();
        let vote = &message.body.vote;
        if message.header.sender != vote.voter {
            return Err(BlossomError::WireProtocol(
                "round-skip vote message sender does not match vote voter".to_string(),
            ));
        }
        if vote.manifest_hash != manifest_hash {
            return Err(BlossomError::WireProtocol(
                "round-skip vote does not bind the carried manifest".to_string(),
            ));
        }
        vote.verify_signature()?;

        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let latest = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?
            .clone();
        let current_validators = latest.body.verifiers.keys().copied().collect::<Vec<_>>();
        let min_replicas = DataDisseminationManifest::byzantine_safe_replica_threshold(
            byzantine_fault_bound(current_validators.len()),
        );
        message
            .body
            .manifest
            .validate_availability(&current_validators, min_replicas)?;
        if vote.last_epoch != latest.hash || vote.nonce != latest.body.nonce.new_next() {
            return Err(BlossomError::InvalidEpochNonce);
        }

        let consensus = state.get_mut_consensus(&vote.last_epoch, vote.nonce);
        let key = RoundSkipKey::new(vote.from_round, vote.to_round, vote.manifest_hash);
        consensus
            .round_skip_manifests
            .insert(manifest_hash, message.body.manifest);
        consensus
            .round_skip_votes
            .entry(key)
            .or_default()
            .insert(vote.voter, vote.clone());
        Ok(MessageReceipt::accepted("round_skip_vote"))
    }

    pub(super) fn receive_round_skip_certificate(
        &self,
        message: RoundSkipCertificateMessage,
    ) -> Result<MessageReceipt> {
        self.verify_message_signature(
            &message.header,
            MSGKey::RoundSkipCertificate,
            &message.body,
        )?;
        let manifest_hash = message.body.manifest.hash();
        if message.body.certificate.manifest_hash != manifest_hash {
            return Err(BlossomError::WireProtocol(
                "round-skip certificate does not bind the carried manifest".to_string(),
            ));
        }
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let latest = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?
            .clone();
        let current_validators = latest.body.verifiers.keys().copied().collect::<Vec<_>>();
        let min_replicas = DataDisseminationManifest::byzantine_safe_replica_threshold(
            byzantine_fault_bound(current_validators.len()),
        );
        message
            .body
            .certificate
            .validate_against_epoch_and_manifest(
                &current_validators,
                latest.hash,
                latest.body.nonce.new_next(),
                &message.body.manifest,
                min_replicas,
            )?;
        if message.body.certificate.from_round == 0
            && !message.body.manifest.dropped_local_blocks.is_empty()
        {
            return Err(BlossomError::WireProtocol(
                "round-0 skip certificate cannot certify private local blocks".to_string(),
            ));
        }

        let consensus = state.get_mut_consensus(&latest.hash, latest.body.nonce.new_next());
        let key = RoundSkipKey::new(
            message.body.certificate.from_round,
            message.body.certificate.to_round,
            message.body.certificate.manifest_hash,
        );
        consensus
            .round_skip_manifests
            .insert(manifest_hash, message.body.manifest);
        consensus
            .round_skip_certificates
            .insert(key, message.body.certificate);
        if consensus.round < key.to_round {
            consensus.round = key.to_round;
        }
        Ok(MessageReceipt::accepted("round_skip_certificate"))
    }

    pub(super) fn receive_reconcile_appraisal(
        &self,
        message: ReconcileAppraisal,
    ) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::ReconcileAppraisal, &message.body)?;
        if message.body.blocks.hash() != message.body.blocks_hash {
            return Err(BlossomError::WireProtocol(
                "reconcile appraisal block set hash mismatch".to_string(),
            ));
        }
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("reconcile_appraisal"))
    }

    pub(super) fn receive_reconcile_request(
        &self,
        message: ReconcileRequest,
    ) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::ReconcileRequest, &message.body)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(MessageReceipt::accepted("reconcile_request"))
    }

    pub(super) fn receive_reconcile_response(
        &self,
        message: ReconcileResponse,
    ) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::ReconcileResponse, &message.body)?;
        self.verify_redispatched_blocks(&message.body.blocks)?;
        if message
            .body
            .blocks
            .keys()
            .map(|hash| (*hash, ()))
            .collect::<BTreeMap<_, _>>()
            .hash()
            != message.body.blocks_hash
        {
            return Err(BlossomError::WireProtocol(
                "reconcile response block hash set mismatch".to_string(),
            ));
        }
        self.persist_blocks_if_configured(message.body.blocks.values())?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        for (hash, block) in message.body.blocks {
            quorum.record_verified_block(hash, block);
        }
        quorum.verified_blocks_hash = Some(quorum.verified_blocks_hash());
        Ok(MessageReceipt::accepted("reconcile_response"))
    }

    pub(super) fn receive_reconcile_commit(
        &self,
        message: ReconcileCommit,
    ) -> Result<MessageReceipt> {
        if self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted mode does not accept verified reconcile commits".to_string(),
            ));
        }
        self.verify_message_signature(&message.header, MSGKey::ReconcileCommit, &message.body)?;
        let chain_extended = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            if message.header.verify_header(&mut state) == Some(false) {
                return Err(BlossomError::UnknownSender);
            }
            let last_epoch = message.header.last_epoch;
            let nonce = message.header.nonce;
            let round = message.header.round;
            let candidate = state
                .prepare_verified_epoch(&last_epoch, nonce, round)?
                .ok_or(BlossomError::FailedConsensus)?;
            if candidate.hash != message.body.epoch_hash {
                return Err(BlossomError::InvalidBlockHash);
            }
            let quorum = state.get_mut_quorum(&last_epoch, nonce, round);
            if quorum.verified_blocks_hash() != message.body.blocks_hash {
                return Err(BlossomError::WireProtocol(
                    "reconcile commit references a block set that is not locally verified"
                        .to_string(),
                ));
            }
            let mut distinct = BTreeSet::new();
            for (signer, signature) in &message.body.signatures {
                if !quorum.msg_matrix.quorum_nodes.contains(signer) || !distinct.insert(*signer) {
                    continue;
                }
                if !self.inner.trust_mode.is_trusted() {
                    signature.verify(message.body.epoch_hash.as_ref(), signer)?;
                    quorum.epoch_signatures.insert(*signer, *signature);
                }
            }
            if distinct.len() < quorum.proposals.supermajority as usize {
                return Err(BlossomError::WireProtocol(format!(
                    "reconcile commit has {} distinct signatures, need {}",
                    distinct.len(),
                    quorum.proposals.supermajority
                )));
            }
            let before = state.epochchain.epochchain.len();
            state.advance_epoch(
                &message.header.last_epoch,
                message.header.nonce,
                message.header.round,
                true,
            );
            state.epochchain.epochchain.len() > before
        };
        if chain_extended {
            self.persist_snapshot()?;
            self.publish_epoch_commit()?;
        }
        Ok(MessageReceipt::accepted("reconcile_commit"))
    }

    /// Attempts to reconcile an externally supplied commit with local round state.
    pub fn try_reconcile_commit(&self, message: ReconcileCommit) -> Result<MessageReceipt> {
        if self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted mode does not accept verified reconcile commits".to_string(),
            ));
        }
        self.receive_reconcile_commit(message)
    }

    pub(super) fn receive_echo_response(&self, message: EchoResponse) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::EchoResponse, &message.body)?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        state.seed_prefill_dispatches_into_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        if quorum
            .msg_matrix
            .find_key_index(&message.body.sender)
            .is_none()
        {
            return Err(BlossomError::UnknownSender);
        }
        quorum.msg_matrix.update(true, Msg::EchoResponse(message));
        Ok(MessageReceipt::accepted("echo_response"))
    }

    pub(super) fn receive_verification(&self, message: Verification) -> Result<MessageReceipt> {
        self.verify_message_signature(&message.header, MSGKey::Verification, &message.body)?;
        message.body.validate()?;
        let message_round = message.header.round;
        let mut chain_extended = false;
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let (_, required_signatures) =
                commit_sender_and_threshold(&mut state, &message.header)?;
            if message.header.verify_header(&mut state) == Some(false) {
                return Err(BlossomError::UnknownSender);
            }
            let last_epoch = message.header.last_epoch;
            let nonce = message.header.nonce;
            let round = message.header.round;
            state.seed_prefill_dispatches_into_quorum(&last_epoch, nonce, round);
            let quorum = state.get_mut_quorum(&last_epoch, nonce, round);
            if self.inner.trust_mode.is_trusted()
                && !quorum.verification_sent
                && quorum.has_trusted_dispatch_quorum()
            {
                quorum.verify_trusted();
                quorum.activate_pending_trusted_messages()?;
            }
            if self.inner.trust_mode.is_trusted() {
                quorum.trusted_confirmations.validate_update(&message)?;
                if let Some(pending) = quorum
                    .pending_trusted_confirmations
                    .get(&message.header.sender)
                    && (pending.body.blocks_hash != message.body.blocks_hash
                        || pending.body.blocks != message.body.blocks)
                {
                    return Err(BlossomError::WireProtocol(
                        "trusted member confirmed two candidates for one round".to_string(),
                    ));
                }
                if quorum.trusted_candidate_blocks(&message.body).is_some() {
                    quorum.trusted_confirmations.record(message)?;
                } else {
                    quorum
                        .pending_trusted_confirmations
                        .insert(message.header.sender, message);
                }
            } else {
                if message.body.blocks != quorum.verified_blocks()
                    || message.body.blocks_hash != quorum.verified_blocks_hash()
                {
                    return Err(BlossomError::WireProtocol(
                        "verification references block set that has not been locally verified"
                            .to_string(),
                    ));
                }
                quorum.verifications.record(message);
            }
            if !self.inner.trust_mode.is_trusted() {
                activate_pending_proposals(quorum);
                activate_pending_true_commits(quorum, required_signatures);
                if quorum.commit_sent {
                    let before = state.epochchain.epochchain.len();
                    state.advance_epoch(&last_epoch, nonce, round, true);
                    chain_extended = state.epochchain.epochchain.len() > before;
                }
            }
        }
        if self.inner.trust_mode.is_trusted() {
            self.try_complete_trusted_verification(message_round)?;
            return Ok(MessageReceipt::accepted("verification"));
        }
        if chain_extended {
            self.persist_snapshot()?;
            self.publish_epoch_commit()?;
        }
        Ok(MessageReceipt::accepted("verification"))
    }

    pub(super) fn receive_trusted_acknowledgement(
        &self,
        message: TrustedAcknowledgement,
    ) -> Result<MessageReceipt> {
        if !self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "verified mode does not accept trusted acknowledgements".to_string(),
            ));
        }
        self.verify_message_signature(
            &message.header,
            MSGKey::TrustedAcknowledgement,
            &message.body,
        )?;
        message.body.validate()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        if message.header.verify_header(&mut state) == Some(false) {
            return Err(BlossomError::UnknownSender);
        }
        let quorum = state.get_mut_quorum(
            &message.header.last_epoch,
            message.header.nonce,
            message.header.round,
        );
        quorum.trusted_acknowledgements.validate_update(&message)?;
        if let Some(pending) = quorum
            .pending_trusted_acknowledgements
            .get(&message.header.sender)
            && !pending
                .body
                .blocks
                .keys()
                .all(|hash| message.body.blocks.contains_key(hash))
        {
            return Err(BlossomError::WireProtocol(
                "trusted acknowledgement masks may only grow".to_string(),
            ));
        }
        if quorum.trusted_candidate_blocks(&message.body).is_some() {
            quorum.trusted_acknowledgements.record(message)?;
        } else {
            quorum
                .pending_trusted_acknowledgements
                .insert(message.header.sender, message);
        }
        Ok(MessageReceipt::accepted("trusted_acknowledgement"))
    }

    pub(super) fn receive_proposal(&self, message: Proposal) -> Result<MessageReceipt> {
        if self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted mode does not accept proposal votes".to_string(),
            ));
        }
        self.verify_message_signature(&message.header, MSGKey::Proposal, &message.body)?;
        message.body.validate()?;
        let mut chain_extended = false;
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let (_, required_signatures) =
                commit_sender_and_threshold(&mut state, &message.header)?;
            if message.header.verify_header(&mut state) == Some(false) {
                return Err(BlossomError::UnknownSender);
            }
            let last_epoch = message.header.last_epoch;
            let nonce = message.header.nonce;
            let round = message.header.round;
            let quorum = state.get_mut_quorum(&last_epoch, nonce, round);
            self.verify_proposal_evidence(&message.header, &message.body, quorum)?;
            if message.body.consensus && !proposal_matches_verified_blocks(&message, quorum) {
                quorum
                    .pending_proposals
                    .insert(message.header.sender, message);
                return Ok(MessageReceipt::accepted("proposal_pending"));
            }
            quorum.pending_proposals.remove(&message.header.sender);
            quorum.proposals.record(message);
            activate_pending_true_commits(quorum, required_signatures);
            if quorum.commit_sent {
                let before = state.epochchain.epochchain.len();
                state.advance_epoch(&last_epoch, nonce, round, true);
                chain_extended = state.epochchain.epochchain.len() > before;
            }
        }
        if chain_extended {
            self.persist_snapshot()?;
            self.publish_epoch_commit()?;
        }
        Ok(MessageReceipt::accepted("proposal"))
    }

    pub(super) fn receive_commit(&self, message: Commit) -> Result<MessageReceipt> {
        if self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted mode does not accept commit votes".to_string(),
            ));
        }
        self.verify_message_signature(&message.header, MSGKey::Commit, &message.body)?;
        let mut chain_extended = false;
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let (sender_is_authorized, required_signatures) =
                commit_sender_and_threshold(&mut state, &message.header)?;
            if !sender_is_authorized {
                return Err(BlossomError::UnknownSender);
            }
            let last_epoch = message.header.last_epoch;
            let nonce = message.header.nonce;
            let round = message.header.round;
            validate_commit_epoch_share(&state, &message)?;
            let quorum = state.get_mut_quorum(&last_epoch, nonce, round);
            if message.body.consensus && quorum.proposals.consensus() != Some(true) {
                return Err(BlossomError::FailedConsensus);
            }
            record_commit_vote(quorum, message, required_signatures);
            if quorum.commit_sent {
                let before = state.epochchain.epochchain.len();
                state.advance_epoch(&last_epoch, nonce, round, true);
                chain_extended = state.epochchain.epochchain.len() > before;
            }
        }
        if chain_extended {
            self.persist_snapshot()?;
            self.publish_epoch_commit()?;
        }
        Ok(MessageReceipt::accepted("commit"))
    }

    pub(super) fn receive_epoch_started(&self, message: EpochStarted) -> Result<MessageReceipt> {
        if self.inner.trust_mode.is_trusted() {
            self.verify_message_signature(&message.header, MSGKey::EpochStarted, &message.body)?;
        } else {
            message
                .header
                .verify_signature(MSGKey::EpochStarted, &message.body)?;
        }
        let target = EpochTarget {
            group_id: self.inner.group_id,
            last_epoch: message.header.last_epoch,
            nonce: message.header.nonce,
        };
        let (local_target, sender_is_validator, sender_is_round_peer) = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let local_tip = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?;
            let local_target = EpochTarget {
                group_id: self.inner.group_id,
                last_epoch: local_tip.hash,
                nonce: local_tip.body.nonce.new_next(),
            };
            let sender_is_validator = local_tip
                .body
                .verifiers
                .contains_key(&message.header.sender);
            let maximum_announced_nonce = local_target
                .nonce
                .value()
                .saturating_add(MAX_CERTIFIED_EPOCH_SUFFIX as u64);
            if message.header.nonce.value() < local_target.nonce.value()
                || message.header.nonce.value() > maximum_announced_nonce
            {
                return Err(BlossomError::InvalidEpochNonce);
            }
            let sender_is_round_peer = if target == local_target {
                state
                    .get_mut_consensus(&target.last_epoch, target.nonce)
                    .is_peer_member_of_round(&message.header.sender, message.header.round)
            } else {
                false
            };
            (local_target, sender_is_validator, sender_is_round_peer)
        };
        if !sender_is_validator {
            return Err(BlossomError::UnknownSender);
        }
        if message.header.round != 0 {
            if target == local_target && !sender_is_round_peer {
                return Err(BlossomError::UnknownSender);
            }
            return Err(BlossomError::WireProtocol(
                "epoch-start announcement must use round zero".to_string(),
            ));
        }
        if target != local_target {
            let mut hints = self
                .inner
                .epoch_started_hints
                .write()
                .expect("epoch-start hint lock poisoned");
            match hints.entry(message.header.sender) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(target);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let previous = entry.get();
                    if previous.nonce == target.nonce && previous.last_epoch != target.last_epoch {
                        return Err(BlossomError::WireProtocol(
                            "validator announced conflicting epoch heads at one nonce".to_string(),
                        ));
                    }
                    if target.nonce > previous.nonce {
                        entry.insert(target);
                    }
                }
            }
            Ok(MessageReceipt::accepted("epoch_started_catch_up"))
        } else if sender_is_round_peer {
            self.inner
                .state
                .write()
                .expect("state lock poisoned")
                .get_mut_quorum(&target.last_epoch, target.nonce, 0)
                .epoch_started_senders
                .insert(message.header.sender);
            Ok(MessageReceipt::accepted("epoch_started"))
        } else {
            Ok(MessageReceipt::accepted("epoch_started_global"))
        }
    }

    pub(super) fn start_telemetry_span(
        &self,
        meta: RuntimeTelemetryMeta,
    ) -> Option<RuntimeTelemetrySpan> {
        if !self.inner.telemetry.is_enabled() {
            return None;
        }
        let span_id = self
            .inner
            .next_telemetry_span_id
            .fetch_add(1, Ordering::Relaxed);
        let mut event = TelemetryEvent::span_start(span_id, meta.stage, meta.event)
            .with_node(self.self_node().public_key())
            .with_group_id(self.inner.group_id);
        event = apply_telemetry_meta(event, &meta);
        event = self.with_quorum_telemetry(event);
        self.inner.telemetry.record(event);
        Some(RuntimeTelemetrySpan { span_id, meta })
    }

    pub(super) fn finish_telemetry_span<T>(
        &self,
        span: Option<RuntimeTelemetrySpan>,
        result: &Result<T>,
    ) {
        let Some(span) = span else {
            return;
        };
        let mut event = TelemetryEvent::span_end(span.span_id, span.meta.stage, span.meta.event)
            .with_node(self.self_node().public_key())
            .with_group_id(self.inner.group_id)
            .with_outcome(if result.is_ok() { "ok" } else { "error" });
        event = apply_telemetry_meta(event, &span.meta);
        event = self.with_quorum_telemetry(event);
        if let Err(err) = result {
            event = event.with_error(err.to_string());
        }
        self.inner.telemetry.record(event);
    }

    pub(super) fn with_quorum_telemetry(&self, event: TelemetryEvent) -> TelemetryEvent {
        let validator_count = self
            .inner
            .state
            .read()
            .expect("state lock poisoned")
            .epochchain
            .epochchain
            .last()
            .map(|epoch| epoch.body.verifiers.len())
            .unwrap_or_default();
        event
            .with_field(
                "configured_quorum_size",
                self.inner.consensus_parameters.quorum_size.to_string(),
            )
            .with_field(
                "effective_quorum_size",
                self.inner
                    .consensus_parameters
                    .quorum_size
                    .effective(validator_count)
                    .to_string(),
            )
            .with_field(
                "consensus_parameters_hash",
                self.inner.consensus_parameters.hash().to_string(),
            )
    }

    pub(super) fn target_telemetry_meta(
        &self,
        stage: &'static str,
        event: &'static str,
        target: &EpochTarget,
        round: Option<u8>,
        peer: Option<PubKey>,
        message_kind: Option<&'static str>,
    ) -> RuntimeTelemetryMeta {
        RuntimeTelemetryMeta {
            stage,
            event,
            last_epoch: Some(target.last_epoch),
            nonce: Some(target.nonce),
            round,
            peer,
            message_kind,
        }
    }

    pub(super) fn ensure_consensus_mode(&self, action: &str) -> Result<()> {
        if self.inner.mode == RuntimeMode::Overlay {
            return Err(BlossomError::WireProtocol(format!(
                "{action} requires consensus runtime mode"
            )));
        }
        Ok(())
    }

    pub(super) fn validate_block_service(&self, block: &Block) -> Result<()> {
        match self.block_service() {
            Some(service) if block.body.validator != service.public_key => {
                Err(BlossomError::UnknownSender)
            }
            _ => Ok(()),
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub(super) fn store_filtered_payloads_from_block(&self, block: &Block) -> Result<()> {
        for tx in &block.body.txs {
            self.store_filtered_payload_from_transaction(tx)?;
        }
        Ok(())
    }

    pub(super) fn block_service(&self) -> Option<Service> {
        self.inner
            .address_book
            .read()
            .expect("address book lock poisoned")
            .service(ServiceKind::Block)
            .cloned()
    }

    pub(super) fn is_current_verifier(&self, public_key: &PubKey) -> bool {
        let state = self.inner.state.read().expect("state lock poisoned");
        state
            .epochchain
            .epochchain
            .last()
            .is_some_and(|epoch| epoch.body.verifiers.keys().any(|key| key == public_key))
    }

    pub(super) fn is_prefill_recipient_for_sender(&self, sender: &PubKey) -> Result<bool> {
        let self_key = self.self_node().public_key();
        if sender == &self_key {
            return Ok(false);
        }
        let target = self.next_epoch_target()?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let Some(sender_identity) = epoch.body.verifiers.get(sender) else {
            return Ok(false);
        };
        let recipients = select_prefill_recipients_with_size(
            epoch.body.verifiers.keys().copied(),
            sender,
            target.last_epoch,
            sender_identity.shuffle,
            epoch.body.effective_consensus_parameters().quorum_size,
        );
        Ok(recipients.contains(&self_key))
    }

    #[cfg(feature = "availability-gossip")]
    pub(super) fn is_known_member(&self, public_key: &PubKey) -> bool {
        self.is_current_verifier(public_key)
    }

    pub(super) fn empty_block(
        &self,
        self_node: &NodeIdentity,
        target: &EpochTarget,
        application_state: BlockApplicationState,
        encounter_records: Vec<EncounterRecord>,
        node_admissions: Vec<NodeAdmission>,
    ) -> Result<Block> {
        let mut block = Block::default();
        block.body.last_epoch = target.last_epoch;
        block.body.nonce = target.nonce;
        block.body.application_state = application_state;
        block.body.encounter_records = encounter_records;
        block.body.node_admissions = node_admissions;
        if self.inner.trust_mode.is_trusted() {
            block.seal_unsigned(self_node.public_key());
            return Ok(block);
        }
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        block.sign_with(signer);
        Ok(block)
    }

    pub(super) fn verify_dispatch_payload(
        &self,
        header: &Header,
        body: &DispatchBody,
    ) -> Result<()> {
        body.validate()?;
        for (hash, block) in &body.blocks {
            if block.body.last_epoch != header.last_epoch {
                return Err(BlossomError::InvalidBlockLastEpoch);
            }
            if block.body.nonce != header.nonce {
                return Err(BlossomError::InvalidBlockNonce {
                    expected: header.nonce,
                    actual: block.body.nonce,
                });
            }
            if self.inner.trust_mode.is_trusted() {
                block.verify_unsigned_integrity_with_hash(*hash)?;
            } else {
                block.verify_integrity_with_hash(*hash)?;
            }
        }
        if !self.inner.trust_mode.is_trusted() && !body.signature_tree.verify() {
            return Err(BlossomError::WireProtocol(
                "dispatch signature tree failed verification".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn verify_block_integrity(&self, block: &Block) -> Result<()> {
        if self.inner.trust_mode.is_trusted() {
            block.verify_unsigned_integrity()
        } else {
            block.verify_integrity()
        }
    }

    pub(super) fn verify_redispatched_blocks(
        &self,
        blocks: &BTreeMap<HashType, Block>,
    ) -> Result<()> {
        for (hash, block) in blocks {
            if self.inner.trust_mode.is_trusted() {
                block.verify_unsigned_integrity_with_hash(*hash)?;
            } else {
                block.verify_integrity_with_hash(*hash)?;
            }
        }
        Ok(())
    }

    pub(super) fn verify_message_signature<T: BlossomBody>(
        &self,
        header: &Header,
        kind: MSGKey,
        body: &T,
    ) -> Result<()> {
        self.ensure_current_header_target(header)?;
        if self.inner.trust_mode.is_trusted() {
            Ok(())
        } else {
            header.verify_signature(kind, body)
        }
    }

    pub(super) fn verify_proposal_proof(
        &self,
        header: &Header,
        body: &ProposalBody,
        quorum: &TempQuorum,
    ) -> Result<()> {
        self.verify_proposal_evidence(header, body, quorum)?;
        if !body.consensus {
            return Ok(());
        }

        let approved_blocks = body.approved_blocks.as_ref().ok_or_else(|| {
            BlossomError::WireProtocol(
                "consensus proposal must include approved blocks".to_string(),
            )
        })?;
        let approved_hash = body.approved_hash.ok_or_else(|| {
            BlossomError::WireProtocol("consensus proposal must include approved hash".to_string())
        })?;

        if approved_blocks != &quorum.verified_blocks()
            || Some(approved_hash) != quorum.verified_blocks_hash
        {
            return Err(BlossomError::WireProtocol(
                "proposal references block set that has not been locally verified".to_string(),
            ));
        }

        Ok(())
    }

    pub(super) fn verify_proposal_evidence(
        &self,
        header: &Header,
        body: &ProposalBody,
        quorum: &TempQuorum,
    ) -> Result<()> {
        if !body.consensus {
            return Ok(());
        }

        let approved_blocks = body.approved_blocks.as_ref().ok_or_else(|| {
            BlossomError::WireProtocol(
                "consensus proposal must include approved blocks".to_string(),
            )
        })?;
        let approved_hash = body.approved_hash.ok_or_else(|| {
            BlossomError::WireProtocol("consensus proposal must include approved hash".to_string())
        })?;
        if approved_blocks.hash() != approved_hash {
            return Err(BlossomError::WireProtocol(
                "consensus proposal approved-block hash mismatch".to_string(),
            ));
        }

        let verification_proof = body.verif.as_ref().ok_or_else(|| {
            BlossomError::WireProtocol(
                "consensus proposal must include verification proof".to_string(),
            )
        })?;
        let verification_body = VerificationBody {
            blocks_hash: approved_hash,
            blocks: approved_blocks.clone(),
        };
        let mut distinct_verifiers = BTreeSet::new();

        for (verifier, signature) in verification_proof {
            if !quorum.msg_matrix.quorum_nodes.contains(verifier) {
                return Err(BlossomError::UnknownSender);
            }
            if !distinct_verifiers.insert(*verifier) {
                continue;
            }
            if !self.inner.trust_mode.is_trusted() {
                let signature_hash = Header::signature_hash_for_body(
                    verifier,
                    &header.last_epoch,
                    header.nonce,
                    header.round,
                    MSGKey::Verification,
                    &verification_body,
                );
                signature.verify(signature_hash.as_ref(), verifier)?;
            }
        }

        if distinct_verifiers.len() < quorum.proposals.supermajority as usize {
            return Err(BlossomError::WireProtocol(format!(
                "consensus proposal verification proof has {} distinct verifier signatures, need {}",
                distinct_verifiers.len(),
                quorum.proposals.supermajority
            )));
        }

        Ok(())
    }

    pub(super) fn sign_body<T: BlossomBody>(
        &self,
        self_node: &NodeIdentity,
        kind: MSGKey,
        last_epoch: HashType,
        nonce: Nonce,
        round: u8,
        body: &T,
    ) -> Result<Signature> {
        if self.inner.trust_mode.is_trusted() {
            return Ok(Signature::default());
        }

        let message_hash = Header::signature_hash_for_body(
            &self_node.public_key(),
            &last_epoch,
            nonce,
            round,
            kind,
            body,
        );
        self.inner
            .signer
            .as_ref()
            .map(|signer| signer.sign(message_hash.as_ref()))
            .ok_or(BlossomError::MissingSecretKey)
    }

    pub(super) fn signed_header_for_body<T: BlossomBody>(
        &self,
        self_node: &NodeIdentity,
        target: &EpochTarget,
        round: u8,
        kind: MSGKey,
        body: &T,
    ) -> Result<Header> {
        Ok(Header {
            sender: self_node.public_key(),
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round,
            signature: self.sign_body(
                self_node,
                kind,
                target.last_epoch,
                target.nonce,
                round,
                body,
            )?,
        })
    }

    pub(super) fn ensure_current_header_target(&self, header: &Header) -> Result<()> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let latest = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if !state
            .epochchain
            .epochchain
            .iter()
            .any(|epoch| epoch.hash == header.last_epoch)
        {
            return Err(BlossomError::WireProtocol(format!(
                "unknown consensus epoch {} for group {}",
                header.last_epoch, self.inner.group_id
            )));
        }

        let expected_nonce = latest.body.nonce.new_next();
        if header.last_epoch != latest.hash || header.nonce != expected_nonce {
            return Err(BlossomError::WireProtocol(format!(
                "stale consensus target {}/{} for group {}; current target is {}/{}",
                header.last_epoch, header.nonce, self.inner.group_id, latest.hash, expected_nonce
            )));
        }

        Ok(())
    }
}
