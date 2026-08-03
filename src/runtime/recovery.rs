//! Durable snapshots, certified epoch catch-up, and block/manifest repair.

use super::*;

impl NodeRuntime {
    /// Returns a clone of the complete locally retained epoch chain.
    pub fn epochchain(&self) -> EpochChain {
        self.inner
            .state
            .read()
            .expect("state lock poisoned")
            .epochchain
            .clone()
    }

    /// Returns a bounded raw epoch range for diagnostics or trusted-mode transfer.
    ///
    /// Verified-mode catch-up must use [`Self::certified_epoch_suffix`] so every
    /// installed epoch remains certificate-checked against its predecessor.
    pub fn epochchain_range(&self, from_nonce: Nonce, max_epochs: usize) -> EpochChain {
        let max_epochs = max_epochs.min(4096);
        let state = self.inner.state.read().expect("state lock poisoned");
        EpochChain {
            epochchain: state
                .epochchain
                .epochchain
                .iter()
                .filter(|epoch| epoch.body.nonce.value() >= from_nonce.value())
                .take(max_epochs)
                .cloned()
                .collect(),
        }
    }

    /// Returns a bounded certified suffix after an exact local anchor.
    pub fn certified_epoch_suffix(
        &self,
        anchor_hash: HashType,
        anchor_nonce: Nonce,
        max_epochs: usize,
    ) -> Result<CertifiedEpochSuffix> {
        if self.inner.trust_mode != TrustMode::Verified {
            return Err(BlossomError::InvalidConfiguration(
                "certified epoch suffixes require verified consensus mode".to_string(),
            ));
        }
        let state = self.inner.state.read().expect("state lock poisoned");
        let anchor_index = state
            .epochchain
            .epochchain
            .iter()
            .position(|epoch| epoch.hash == anchor_hash && epoch.body.nonce == anchor_nonce)
            .ok_or(BlossomError::InvalidEpochNonce)?;
        Ok(CertifiedEpochSuffix {
            version: CERTIFIED_EPOCH_SUFFIX_VERSION,
            group_id: self.inner.group_id,
            anchor_hash,
            anchor_nonce,
            epochs: state.epochchain.epochchain[anchor_index + 1..]
                .iter()
                .take(max_epochs.min(MAX_CERTIFIED_EPOCH_SUFFIX))
                .cloned()
                .collect(),
        })
    }

    /// Validates and atomically installs a certified verified-mode suffix.
    ///
    /// Returns `true` when at least one new epoch was installed.
    pub fn catch_up_certified_suffix(&self, suffix: CertifiedEpochSuffix) -> Result<bool> {
        if self.inner.trust_mode != TrustMode::Verified {
            return Err(BlossomError::InvalidConfiguration(
                "certified epoch catch-up requires verified consensus mode".to_string(),
            ));
        }
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let local_tip = state
            .epochchain
            .epochchain
            .last()
            .cloned()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if suffix.anchor_hash != local_tip.hash || suffix.anchor_nonce != local_tip.body.nonce {
            return Err(BlossomError::InvalidEpochNonce);
        }
        suffix.validate_from(&local_tip, self.inner.consensus_node_removal_policy)?;
        if suffix.epochs.is_empty() {
            return Ok(false);
        }
        state.epochchain.epochchain.extend(suffix.epochs);
        drop(state);
        self.persist_snapshot()?;
        self.publish_epoch_commit()?;
        let next_target = self.next_epoch_target()?;
        let self_key = self.self_node().public_key();
        self.inner
            .state
            .write()
            .expect("state lock poisoned")
            .get_mut_quorum(&next_target.last_epoch, next_target.nonce, 0)
            .epoch_started_senders
            .insert(self_key);
        self.prune_epoch_started_hints();
        Ok(true)
    }

    /// Returns validators that authenticated a newer committed epoch head.
    ///
    /// The announcement is only a bounded catch-up hint. Callers must fetch a
    /// [`CertifiedEpochSuffix`] from one of these services and let
    /// [`Self::catch_up_certified_suffix`] validate it before changing local
    /// committed state.
    pub fn epoch_started_catch_up_services(&self) -> Result<Vec<Service>> {
        if self.inner.trust_mode != TrustMode::Verified {
            return Ok(Vec::new());
        }
        let local_target = self.next_epoch_target()?;
        let senders = self
            .inner
            .epoch_started_hints
            .read()
            .expect("epoch-start hint lock poisoned")
            .iter()
            .filter_map(|(sender, target)| {
                (target.nonce > local_target.nonce && target.last_epoch != local_target.last_epoch)
                    .then_some(*sender)
            })
            .collect::<BTreeSet<_>>();
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        Ok(senders
            .into_iter()
            .filter_map(|sender| {
                address_book
                    .service_for(ServiceKind::Consensus, &sender)
                    .cloned()
            })
            .collect())
    }

    /// Returns authenticated catch-up hints and outstanding announcement peers.
    pub fn epoch_dissemination_status(&self) -> Result<EpochDisseminationStatus> {
        let local_target = self.next_epoch_target()?;
        let catch_up_hints = self
            .inner
            .epoch_started_hints
            .read()
            .expect("epoch-start hint lock poisoned")
            .clone();
        let (pending_validators, last_failures) = self
            .inner
            .epoch_started_retry
            .read()
            .expect("epoch-start retry lock poisoned")
            .as_ref()
            .filter(|retry| {
                retry.message.header.last_epoch == local_target.last_epoch
                    && retry.message.header.nonce == local_target.nonce
            })
            .map(|retry| {
                (
                    retry.pending_validators.clone(),
                    retry.last_failures.clone(),
                )
            })
            .unwrap_or_default();
        Ok(EpochDisseminationStatus {
            local_target,
            catch_up_hints,
            pending_validators,
            last_failures,
        })
    }

    fn prune_epoch_started_hints(&self) {
        let Ok(local_target) = self.next_epoch_target() else {
            return;
        };
        self.inner
            .epoch_started_hints
            .write()
            .expect("epoch-start hint lock poisoned")
            .retain(|_, target| {
                target.nonce > local_target.nonce
                    || (target.nonce == local_target.nonce
                        && target.last_epoch != local_target.last_epoch)
            });
    }

    /// Builds a validated public-only snapshot of the runtime.
    pub fn snapshot(&self) -> Result<RuntimeSnapshotV1> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let self_public_key = state.self_node.public_key();
        let now_unix_millis = service_unix_time_millis();
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned")
            .clone()
            .into_services();
        let signed_service_records = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned")
            .signed_records()
            .filter(|record| record.body.expires_at_unix_millis > now_unix_millis)
            .cloned()
            .collect();
        let mut membership_lease_watermarks = self
            .inner
            .membership_lease_watermarks
            .lock()
            .expect("membership lease watermark lock poisoned");
        membership_lease_watermarks
            .retain(|_, watermark| watermark.expires_at_unix_millis > now_unix_millis);
        let membership_lease_watermark_hashes = membership_lease_watermarks
            .iter()
            .map(|(challenge, watermark)| (*challenge, watermark.statement_hash))
            .collect();
        let membership_lease_watermark_expiries = membership_lease_watermarks
            .iter()
            .map(|(challenge, watermark)| (*challenge, watermark.expires_at_unix_millis))
            .collect();
        drop(membership_lease_watermarks);
        let snapshot = RuntimeSnapshotV1 {
            version: RuntimeSnapshotV1::VERSION,
            group_id: self.inner.group_id,
            self_public_key,
            epochchain: state.epochchain.clone(),
            address_book,
            signed_service_records,
            block_cap: self.inner.block_cap,
            consensus_parameters: self.inner.consensus_parameters,
            trust_mode: self.inner.trust_mode,
            mode: self.inner.mode,
            consensus_node_removal_policy: self.inner.consensus_node_removal_policy,
            membership_lease_watermarks: membership_lease_watermark_hashes,
            membership_lease_watermark_expiries,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Writes a fresh runtime snapshot atomically to `path`.
    pub fn write_snapshot(&self, path: impl AsRef<Path>) -> Result<()> {
        self.snapshot()?.write_json_atomic(path)
    }

    /// Writes a snapshot to the configured path, if one is configured.
    pub fn persist_snapshot(&self) -> Result<()> {
        let Some(path) = self.inner.snapshot_path.as_ref() else {
            return Ok(());
        };
        self.write_snapshot(path)
    }

    /// Fetches the first durable block for `nonce`, when a block store is configured.
    pub fn durable_block_by_nonce(&self, nonce: Nonce) -> Result<Option<Block>> {
        match self.inner.durable_block_store.as_ref() {
            Some(store) => store.get_first_by_nonce(nonce),
            None => Ok(None),
        }
    }

    /// Fetches every requested block currently present in durable storage.
    pub fn durable_blocks_by_hash(
        &self,
        hashes: impl IntoIterator<Item = HashType>,
    ) -> Result<BTreeMap<HashType, Block>> {
        let mut blocks = BTreeMap::new();
        let Some(store) = self.inner.durable_block_store.as_ref() else {
            return Ok(blocks);
        };
        for hash in hashes {
            if let Some(block) = store.get_by_hash(hash)? {
                blocks.insert(hash, block);
            }
        }
        Ok(blocks)
    }

    /// Finds a block in verified round state before consulting durable storage.
    pub fn verified_or_durable_block_by_hash(&self, hash: HashType) -> Result<Option<Block>> {
        {
            let state = self.inner.state.read().expect("state lock poisoned");
            for consensus in state.consensus.values() {
                for quorum in consensus.quorum.values() {
                    if let Some(block) = quorum.canonical_verified_blocks().get(&hash) {
                        return Ok(Some(block.clone()));
                    }
                }
            }
        }
        Ok(self.durable_blocks_by_hash([hash])?.remove(&hash))
    }

    /// Determines which manifest blocks are missing and which peers can supply them.
    pub fn manifest_repair_plan(
        &self,
        manifest: &DataDisseminationManifest,
    ) -> Result<ManifestRepairPlan> {
        self.validate_manifest_for_current_epoch(manifest)?;
        let mut missing_blocks = BTreeSet::new();
        for hash in &manifest.carried_blocks {
            if self.verified_or_durable_block_by_hash(*hash)?.is_none() {
                missing_blocks.insert(*hash);
            }
        }

        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        let mut requests_by_holder = BTreeMap::<PubKey, Vec<HashType>>::new();
        for hash in &missing_blocks {
            if let Some(holders) = manifest.replica_holders.get(hash) {
                for holder in holders {
                    if address_book
                        .service_for(ServiceKind::Consensus, holder)
                        .is_some()
                    {
                        requests_by_holder.entry(*holder).or_default().push(*hash);
                    }
                }
            }
        }

        Ok(ManifestRepairPlan {
            manifest_hash: manifest.hash(),
            missing_blocks,
            requests_by_holder,
        })
    }

    /// Validates and installs blocks returned by a manifest-repair operation.
    pub fn repair_manifest_blocks(
        &self,
        manifest: &DataDisseminationManifest,
        blocks: BTreeMap<HashType, Block>,
    ) -> Result<ManifestRepairReceipt> {
        self.validate_manifest_for_current_epoch(manifest)?;
        let target = self.next_epoch_target()?;
        let mut inserted_blocks = 0usize;
        self.verify_redispatched_blocks(&blocks)?;
        self.persist_blocks_if_configured(blocks.values())?;
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            for (hash, block) in blocks {
                if !manifest.carried_blocks.contains(&hash) {
                    return Err(BlossomError::WireProtocol(
                        "manifest repair block is not listed in the carried manifest".to_string(),
                    ));
                }
                if block.body.last_epoch != target.last_epoch || block.body.nonce != target.nonce {
                    return Err(BlossomError::WireProtocol(
                        "manifest repair block targets the wrong epoch or nonce".to_string(),
                    ));
                }
                let validator_is_current =
                    state.epochchain.epochchain.last().is_some_and(|epoch| {
                        epoch.body.verifiers.contains_key(&block.body.validator)
                    });
                if !validator_is_current {
                    return Err(BlossomError::WireProtocol(
                        "manifest repair block validator is not a current validator".to_string(),
                    ));
                }
                let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, 0);
                inserted_blocks += usize::from(quorum.record_verified_block(hash, block));
            }
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, 0);
            quorum.verified_blocks_hash = Some(quorum.verified_blocks_hash());
        }

        let plan = self.manifest_repair_plan(manifest)?;
        Ok(ManifestRepairReceipt {
            manifest_hash: manifest.hash(),
            inserted_blocks,
            missing_blocks: plan.missing_blocks,
        })
    }

    /// Builds a redispatch containing every locally available requested block.
    pub fn respond_to_echo_request(&self, request: &EchoRequest) -> Result<Option<EchoReDispatch>> {
        self.verify_message_signature(
            &request.header,
            MSGKey::EchoRequest,
            &request.requested_blocks,
        )?;
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            if request.header.verify_header(&mut state) == Some(false) {
                return Err(BlossomError::UnknownSender);
            }
        }
        let mut redispatched_blocks = BTreeMap::new();
        for hash in request.requested_blocks.keys() {
            if let Some(block) = self.verified_or_durable_block_by_hash(*hash)?
                && block.body.last_epoch == request.header.last_epoch
                && block.body.nonce == request.header.nonce
            {
                redispatched_blocks.insert(*hash, block);
            }
        }
        if redispatched_blocks.is_empty() {
            return Ok(None);
        }
        let self_node = self.self_node();
        let header = Header {
            sender: self_node.public_key(),
            last_epoch: request.header.last_epoch,
            nonce: request.header.nonce,
            round: request.header.round,
            signature: self.sign_body(
                &self_node,
                MSGKey::EchoReDispatch,
                request.header.last_epoch,
                request.header.nonce,
                request.header.round,
                &redispatched_blocks,
            )?,
        };
        Ok(Some(EchoReDispatch {
            header,
            redispatched_blocks,
        }))
    }

    /// Evaluates, records, and optionally emits a certified round-skip assist.
    pub fn try_round_skip_assist(
        &self,
        from_round: u8,
        to_round: u8,
        manifest: DataDisseminationManifest,
    ) -> Result<RoundSkipAssistOutcome> {
        self.ensure_consensus_mode("produce round-skip assist")?;
        let target = self.next_epoch_target()?;
        if manifest.last_epoch != target.last_epoch || manifest.nonce != target.nonce {
            return Err(BlossomError::InvalidEpochNonce);
        }
        self.validate_manifest_for_current_epoch(&manifest)?;
        let manifest_hash = manifest.hash();
        let self_node = self.self_node();
        let self_key = self_node.public_key();
        let local_block_in_candidate = {
            let state = self.inner.state.read().expect("state lock poisoned");
            state
                .consensus
                .get(&crate::state::EpochNonce(target.last_epoch, target.nonce))
                .into_iter()
                .flat_map(|consensus| consensus.quorum.values())
                .flat_map(|quorum| quorum.canonical_verified_blocks().into_values())
                .any(|block| {
                    block.body.validator == self_key
                        && manifest.carried_blocks.contains(&block.hash)
                })
        };
        let local_block_replicated = !local_block_in_candidate
            || manifest
                .replica_holders
                .values()
                .any(|holders| holders.contains(&self_key));
        let parent_data_repairable = manifest.can_reconstruct_from(&manifest.source_nodes);
        let decision = crate::round_skip::future_round_assist_decision(FutureRoundAssistInput {
            kind: FutureRoundAssistKind::RoundChangeSkip,
            last_certified_round: manifest.last_certified_round.map(usize::from),
            target_round: usize::from(to_round),
            skip_certificates: usize::from(to_round.saturating_sub(from_round)),
            first_fanout_completed: manifest.first_fanout_completed(),
            local_block_in_candidate,
            local_block_replicated,
            parent_data_replicated: manifest.every_carried_block_has_replica(),
            parent_data_repairable,
            holds_unreplicated_parent_data: local_block_in_candidate && !local_block_replicated,
            future_body_validated: true,
        });
        if !matches!(
            decision,
            FutureRoundAssistDecision::Assist | FutureRoundAssistDecision::AssistDroppingLocalBlock
        ) {
            return Ok(RoundSkipAssistOutcome {
                decision,
                message: None,
            });
        }

        {
            let state = self.inner.state.read().expect("state lock poisoned");
            let consensus = state
                .consensus
                .get(&crate::state::EpochNonce(target.last_epoch, target.nonce));
            let key = RoundSkipKey::new(from_round, to_round, manifest_hash);
            if consensus
                .and_then(|consensus| consensus.round_skip_votes.get(&key))
                .is_some_and(|votes| votes.contains_key(&self_key))
            {
                return Ok(RoundSkipAssistOutcome {
                    decision,
                    message: None,
                });
            }
        }

        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        let vote = RoundSkipVote::sign_with(
            self_key,
            signer,
            target.last_epoch,
            target.nonce,
            from_round,
            to_round,
            manifest_hash,
        );
        let body = RoundSkipVoteBody { vote, manifest };
        let message = RoundSkipVoteMessage {
            header: self.signed_header_for_body(
                &self_node,
                &target,
                from_round,
                MSGKey::RoundSkipVote,
                &body,
            )?,
            body,
        };
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let consensus = state.get_mut_consensus(&target.last_epoch, target.nonce);
            let key = RoundSkipKey::new(from_round, to_round, manifest_hash);
            consensus
                .round_skip_manifests
                .insert(manifest_hash, message.body.manifest.clone());
            consensus
                .round_skip_votes
                .entry(key)
                .or_default()
                .insert(self_key, message.body.vote.clone());
        }
        Ok(RoundSkipAssistOutcome {
            decision,
            message: Some(message),
        })
    }

    /// Classifies whether the round should wait, recover, or prove failure.
    pub fn recovery_wait_assessment(&self, round: u8) -> Result<RecoveryWaitAssessment> {
        let target = self.next_epoch_target()?;
        // Assessment is also the first recovery operation on an otherwise
        // idle driver tick. Materialize the deterministic round state instead
        // of treating its absence as evidence from an unknown sender.
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        let required_nodes = supermajority_count(quorum.msg_matrix.quorum_nodes.len());
        let passed_nodes = quorum
            .msg_matrix
            .node_status
            .iter()
            .filter(|status| matches!(status, crate::register::Status::NodePassed))
            .count();
        let pending_nodes = quorum
            .msg_matrix
            .node_status
            .iter()
            .filter(|status| matches!(status, crate::register::Status::NodePending))
            .count();
        let status = if quorum.msg_matrix.status() {
            RecoveryEvidenceStatus::Healthy
        } else if passed_nodes + pending_nodes >= required_nodes {
            RecoveryEvidenceStatus::DelayedOrMissing
        } else if !quorum.received_dispatches.is_empty() || !quorum.commit_senders.is_empty() {
            RecoveryEvidenceStatus::Unrecoverable
        } else {
            RecoveryEvidenceStatus::DelayedOrMissing
        };
        Ok(RecoveryWaitAssessment {
            round,
            status,
            passed_nodes,
            pending_nodes,
            required_nodes,
        })
    }

    /// Produces a negative proposal only when progress is provably unrecoverable.
    pub fn try_produce_false_proposal(&self, round: u8) -> Result<Option<Proposal>> {
        self.ensure_consensus_mode("produce false proposal")?;
        if self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted mode uses confirmation quorum finality, not proposals".to_string(),
            ));
        }
        if self.recovery_wait_assessment(round)?.status != RecoveryEvidenceStatus::Unrecoverable {
            return Ok(None);
        }
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        let body = ProposalBody {
            consensus: false,
            approved_blocks: None,
            approved_hash: None,
            verif: None,
            signature_tree: None,
            signature_tree_hash: None,
        };
        let message = Proposal {
            header: self.signed_header_for_body(
                &self_node,
                &target,
                round,
                MSGKey::Proposal,
                &body,
            )?,
            body,
        };
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum.proposal_sent
            || quorum.proposals.consensus() == Some(true)
            || quorum.verifications.consensus_is_still_possible()
        {
            return Ok(None);
        }
        quorum.proposal_sent = true;
        quorum.proposals.record(message.clone());
        Ok(Some(message))
    }

    /// Applies a raw epoch range only in trusted mode.
    ///
    /// Verified callers receive an error directing them to certified suffix
    /// catch-up.
    pub fn catch_up_from_epoch_started(&self, remote_chain: EpochChain) -> Result<bool> {
        if self.inner.trust_mode.is_trusted() {
            return self.catch_up_trusted_epoch_range(remote_chain);
        }
        Err(BlossomError::InvalidConfiguration(
            "verified catch-up requires (anchor hash, anchor nonce, certified suffix)".to_string(),
        ))
    }

    pub(super) fn catch_up_trusted_epoch_range(&self, remote_chain: EpochChain) -> Result<bool> {
        let _trusted_transition = self.inner.trusted_epoch_log.as_ref().map(|_| {
            self.inner
                .trusted_transition_lock
                .lock()
                .expect("trusted transition lock poisoned")
        });
        if remote_chain.epochchain.is_empty() {
            return Ok(false);
        }
        let local_tip = self
            .inner
            .state
            .read()
            .expect("state lock poisoned")
            .epochchain
            .epochchain
            .last()
            .cloned()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let suffix = if let Some(local_tip_index) = remote_chain
            .epochchain
            .iter()
            .position(|epoch| epoch.hash == local_tip.hash)
        {
            remote_chain.epochchain[local_tip_index + 1..].to_vec()
        } else {
            remote_chain.epochchain
        };
        if suffix.is_empty() {
            return Ok(false);
        }
        let mut previous = &local_tip;
        for epoch in &suffix {
            validate_trusted_extension(previous, epoch, self.inner.consensus_node_removal_policy)?;
            previous = epoch;
        }

        let durable_pending_block = if let Some(store) = self.inner.trusted_epoch_log.as_ref() {
            store.append_suffix(&suffix)?;
            store.pending_local_block()?
        } else {
            None
        };
        if self.inner.trusted_epoch_log.is_some() {
            self.inner
                .local_blocks
                .write()
                .expect("block lock poisoned")
                .reconcile_durable_pending_block(durable_pending_block)?;
        }
        let original_chain = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let current_tip = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?;
            if current_tip.hash != local_tip.hash {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted catch-up raced with local epoch advancement".to_string(),
                ));
            }
            let original = state.epochchain.clone();
            state.epochchain.epochchain.extend(suffix);
            original
        };
        if self.inner.trusted_epoch_log.is_none()
            && let Err(error) = self.persist_snapshot()
        {
            self.inner
                .state
                .write()
                .expect("state lock poisoned")
                .epochchain = original_chain;
            return Err(error);
        }
        self.publish_epoch_commit()?;
        Ok(true)
    }

    pub(super) fn persist_block_if_configured(&self, block: &Block) -> Result<()> {
        if let Some(store) = self.inner.durable_block_store.as_ref() {
            store.put(block)?;
        }
        Ok(())
    }

    pub(super) fn persist_blocks_if_configured<'a>(
        &self,
        blocks: impl IntoIterator<Item = &'a Block>,
    ) -> Result<()> {
        for block in blocks {
            self.persist_block_if_configured(block)?;
        }
        Ok(())
    }

    pub(super) fn validate_manifest_for_current_epoch(
        &self,
        manifest: &DataDisseminationManifest,
    ) -> Result<()> {
        let target = self.next_epoch_target()?;
        if manifest.last_epoch != target.last_epoch || manifest.nonce != target.nonce {
            return Err(BlossomError::InvalidEpochNonce);
        }
        let state = self.inner.state.read().expect("state lock poisoned");
        let latest = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let current_validators = latest.body.verifiers.keys().copied().collect::<Vec<_>>();
        let min_replicas = DataDisseminationManifest::byzantine_safe_replica_threshold(
            byzantine_fault_bound(current_validators.len()),
        );
        manifest.validate_availability(&current_validators, min_replicas)?;
        Ok(())
    }

    /// Returns current verifier identities with signing material stripped.
    pub fn current_verifiers(&self) -> Vec<NodeIdentity> {
        let state = self.inner.state.read().expect("state lock poisoned");
        state
            .epochchain
            .epochchain
            .last()
            .map(|epoch| {
                epoch
                    .body
                    .verifiers
                    .values()
                    .map(|node| node.public_only())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Registers or replaces a local service endpoint in this node's address book.
    ///
    /// This is reachability metadata only. It does not admit `service.public_key`
    /// into the epoch verifier set or bypass consensus-message membership checks.
    pub fn register_service(&self, service: Service) -> Option<Service> {
        self.inner
            .address_book
            .write()
            .expect("address book lock poisoned")
            .add(service)
    }

    /// Validates and applies a signed, monotonic, expiring service record.
    pub fn register_signed_service(&self, record: SignedServiceRecord) -> Result<Option<Service>> {
        let members = self
            .inner
            .state
            .read()
            .expect("state lock poisoned")
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?
            .body
            .members
            .clone();
        let previous = self
            .inner
            .address_book
            .write()
            .expect("address book lock poisoned")
            .apply_signed_record(
                record,
                self.inner.group_id,
                &members,
                service_unix_time_millis(),
            )?;
        self.republish_fresh_membership_relays(&members);
        Ok(previous)
    }

    pub(super) fn verified_relay_set(
        &self,
        members: &crate::membership::MemberSet,
        now_unix_millis: u64,
    ) -> (RelaySet, Option<u64>) {
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        let records = address_book
            .active_signed_records(self.inner.group_id, now_unix_millis)
            .filter(|record| {
                record.body.service_kind == ServiceKind::Relay
                    && members.get(&record.body.owner).is_some_and(|member| {
                        member.is_active_with(crate::membership::MemberCapability::Relay)
                    })
            })
            .collect::<Vec<_>>();
        let earliest_expiry = records
            .iter()
            .map(|record| record.body.expires_at_unix_millis)
            .min();
        let relays = records
            .into_iter()
            .map(|record| (record.body.owner, record.body.service()))
            .collect();
        (relays, earliest_expiry)
    }

    pub(super) fn republish_fresh_membership_relays(&self, members: &crate::membership::MemberSet) {
        let current = self.inner.verified_membership_tx.borrow().clone();
        let current_epoch_hash = self
            .inner
            .state
            .read()
            .expect("state lock poisoned")
            .epochchain
            .epochchain
            .last()
            .map(|epoch| epoch.hash);
        if !current.is_fresh() || Some(current.epoch_hash) != current_epoch_hash {
            return;
        }
        let now_unix_millis = service_unix_time_millis();
        let (relays, earliest_relay_expiry) = self.verified_relay_set(members, now_unix_millis);
        let now = std::time::Instant::now();
        let mut valid_until = current.valid_until;
        if let Some(relay_expiry) = earliest_relay_expiry {
            valid_until = valid_until.min(
                now + std::time::Duration::from_millis(
                    relay_expiry.saturating_sub(now_unix_millis),
                ),
            );
        }
        self.inner
            .verified_membership_tx
            .send_replace(Arc::new(VerifiedMembershipView {
                group_id: current.group_id,
                epoch_hash: current.epoch_hash,
                epoch_nonce: current.epoch_nonce,
                lease_expires_at_unix_millis: current.lease_expires_at_unix_millis,
                valid_until,
                members: Arc::new(members.clone()),
                relays: Arc::new(relays),
            }));
    }

    /// Stages a signed public-node admission into this node's next local block.
    ///
    /// The admission enters verifier membership only if that block is committed
    /// into the next epoch by consensus.
    pub fn stage_node_admission(&self, admission: NodeAdmission) -> Result<Option<NodeIdentity>> {
        self.ensure_consensus_mode("stage node admission")?;
        admission.verify()?;
        let target = self.next_epoch_target()?;
        if admission.body.last_epoch != target.last_epoch || admission.body.nonce != target.nonce {
            return Err(BlossomError::InvalidEpochNonce);
        }
        let node = admission.body.node.clone();
        if self.is_current_verifier(&node.public_key()) {
            return Ok(None);
        }
        self.inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .add_node_admission(admission)?;
        Ok(Some(node))
    }

    /// Signs a vote that binds a reconnecting candidate to the current head.
    pub fn sign_reconnect_vote(&self, admission: &NodeAdmission) -> Result<ReconnectVote> {
        self.ensure_consensus_mode("sign reconnect vote")?;
        admission.verify()?;
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let latest = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if !latest.body.verifiers.contains_key(&signer.public_key()) {
            return Err(BlossomError::UnknownSender);
        }
        if admission.body.last_epoch != latest.hash
            || admission.body.nonce != latest.body.nonce.new_next()
        {
            return Err(BlossomError::InvalidEpochNonce);
        }
        ReconnectVote::signed_for_admission(admission, latest.hash, latest.body.nonce, signer)
    }

    /// Validates reconnect evidence against the current verifier set and head.
    pub fn evaluate_reconnect_admission(
        &self,
        evidence: &ReconnectAdmissionEvidence,
    ) -> Result<ReconnectAdmissionDecision> {
        self.ensure_consensus_mode("evaluate reconnect admission")?;
        evidence.admission.verify()?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let latest = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let candidate = evidence.admission.body.node.public_key();
        let required_votes = supermajority_count(latest.body.verifiers.len());

        if evidence.admission.body.last_epoch != latest.hash
            || evidence.admission.body.nonce != latest.body.nonce.new_next()
        {
            return Ok(ReconnectAdmissionDecision {
                accepted: false,
                reason: "stale admission target".to_string(),
                distinct_votes: 0,
                required_votes,
                candidate,
            });
        }
        if latest.body.verifiers.contains_key(&candidate) {
            return Ok(ReconnectAdmissionDecision {
                accepted: false,
                reason: "candidate is already an active verifier".to_string(),
                distinct_votes: 0,
                required_votes,
                candidate,
            });
        }

        let admission_hash = evidence.admission.body.hash();
        let mut voters = BTreeSet::new();
        for vote in &evidence.votes {
            vote.verify()?;
            if vote.body.candidate != candidate
                || vote.body.admission_hash != admission_hash
                || vote.body.catchup_epoch != latest.hash
                || vote.body.catchup_nonce != latest.body.nonce
            {
                continue;
            }
            if latest.body.verifiers.contains_key(&vote.body.voter) {
                voters.insert(vote.body.voter);
            }
        }
        let distinct_votes = voters.len();
        let accepted = distinct_votes >= required_votes;
        Ok(ReconnectAdmissionDecision {
            accepted,
            reason: if accepted {
                "accepted".to_string()
            } else {
                "insufficient active-validator reconnect votes".to_string()
            },
            distinct_votes,
            required_votes,
            candidate,
        })
    }

    /// Stages an admission only when its reconnect evidence reaches quorum.
    pub fn stage_reconnect_admission(
        &self,
        evidence: ReconnectAdmissionEvidence,
    ) -> Result<ReconnectAdmissionDecision> {
        let decision = self.evaluate_reconnect_admission(&evidence)?;
        if decision.accepted {
            self.stage_node_admission(evidence.admission)?;
        }
        Ok(decision)
    }

    /// Stages an explicit capability-registry mutation in the next local block.
    pub fn stage_member_operation(&self, operation: MemberOperation) -> Result<HashType> {
        self.ensure_consensus_mode("stage member operation")?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let head = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if !head
            .body
            .verifiers
            .contains_key(&state.self_node.public_key())
        {
            return Err(BlossomError::UnknownSender);
        }
        head.body.members.validate_operation(&operation)?;
        let transaction = CommittedMemberOperation {
            group_id: self.inner.group_id,
            parent_epoch_hash: head.hash,
            operation,
        }
        .to_transaction()?;
        drop(state);
        Ok(self
            .inner
            .local_blocks
            .write()
            .expect("block lock poisoned")
            .add_transaction(transaction))
    }
}
