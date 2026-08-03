//! Transactional admission and ordered-state persistence.

use super::*;

impl DurableAdmissionStore {
    /// Opens or creates a store bound to one holder, site, and generation.
    pub fn open(
        path: impl AsRef<Path>,
        site: SiteId,
        store_generation: StoreGeneration,
        signer: SecretSigner,
    ) -> Result<Self> {
        let holder = signer.public_key();
        let public_scope =
            borsh::to_vec(&(holder, site.clone(), store_generation)).map_err(encode_error)?;
        let identity =
            BlossomLogStoreIdentity::new("active-active", public_scope, store_generation.0)?;
        let log_store = BlossomLogStore::open(BlossomLogStoreConfig::new(path.as_ref()), identity)?;
        let store = Self {
            store: log_store,
            holder,
            site,
            store_generation,
            signer,
        };
        store.initialize_identity()?;
        Ok(store)
    }

    /// Returns a clone of the underlying transactional LogStore handle.
    pub fn log_store(&self) -> BlossomLogStore {
        self.store.clone()
    }

    fn initialize_identity(&self) -> Result<()> {
        self.transact(|transaction| {
            if let Some(encoded) =
                transaction.get(STORE_IDENTITY_TABLE, STORE_IDENTITY_KEY.as_bytes())?
            {
                let identity =
                    borsh::from_slice::<DurableStoreIdentity>(&encoded).map_err(|error| {
                        BlossomError::WireProtocol(format!(
                            "decode active-active store identity: {error}"
                        ))
                    })?;
                identity.validate_startup(self.holder, &self.site, self.store_generation)?;
            } else {
                let identity = DurableStoreIdentity::new(
                    self.holder,
                    self.site.clone(),
                    self.store_generation,
                );
                transaction.insert(
                    STORE_IDENTITY_TABLE,
                    STORE_IDENTITY_KEY.as_bytes().to_vec(),
                    borsh::to_vec(&identity).map_err(encode_error)?,
                )?;
            }
            Ok(())
        })
    }

    /// Returns process-local durability counters.
    pub fn durability_metrics(&self) -> ActiveActiveDurabilityMetrics {
        let metrics = self.store.durability_metrics();
        ActiveActiveDurabilityMetrics {
            commit_count: metrics.committed_transactions,
            fsync_count: metrics.fsyncs,
        }
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut BlossomLogTransaction<'_>) -> Result<T>,
    ) -> Result<T> {
        self.store.transaction(operation).map(|(result, _)| result)
    }

    pub(super) fn bind_protocol_scope(
        &self,
        cluster_id: HashType,
        consensus_group_id: ConsensusGroupId,
    ) -> Result<()> {
        self.transact(|transaction| {
            self.bind_protocol_scope_in_transaction(transaction, cluster_id, consensus_group_id)?;
            Ok(())
        })
    }

    pub(super) fn protocol_scope(&self) -> Result<Option<(HashType, ConsensusGroupId)>> {
        let encoded = self
            .store
            .get(STORE_IDENTITY_TABLE, STORE_IDENTITY_KEY.as_bytes())?
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active store identity is missing".to_string(),
                )
            })?;
        let identity = borsh::from_slice::<DurableStoreIdentity>(&encoded).map_err(|error| {
            BlossomError::WireProtocol(format!("decode active-active store identity: {error}"))
        })?;
        identity.validate_startup(self.holder, &self.site, self.store_generation)?;
        match (identity.cluster_id, identity.consensus_group_id) {
            (Some(cluster_id), Some(consensus_group_id)) => {
                Ok(Some((cluster_id, consensus_group_id)))
            }
            (None, None) => Ok(None),
            _ => Err(BlossomError::InvalidConfiguration(
                "active-active store has a partially bound protocol scope".to_string(),
            )),
        }
    }

    fn bind_protocol_scope_in_transaction(
        &self,
        transaction: &mut BlossomLogTransaction<'_>,
        cluster_id: HashType,
        consensus_group_id: ConsensusGroupId,
    ) -> Result<bool> {
        let encoded = transaction
            .get(STORE_IDENTITY_TABLE, STORE_IDENTITY_KEY.as_bytes())?
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active store identity is missing".to_string(),
                )
            })?;
        let mut identity =
            borsh::from_slice::<DurableStoreIdentity>(&encoded).map_err(|error| {
                BlossomError::WireProtocol(format!("decode active-active store identity: {error}"))
            })?;
        identity.validate_startup(self.holder, &self.site, self.store_generation)?;
        match (identity.cluster_id, identity.consensus_group_id) {
            (None, None) => {
                identity.cluster_id = Some(cluster_id);
                identity.consensus_group_id = Some(consensus_group_id);
                transaction.insert(
                    STORE_IDENTITY_TABLE,
                    STORE_IDENTITY_KEY.as_bytes().to_vec(),
                    borsh::to_vec(&identity).map_err(encode_error)?,
                )?;
                Ok(true)
            }
            (Some(existing_cluster), Some(existing_group))
                if existing_cluster == cluster_id && existing_group == consensus_group_id =>
            {
                Ok(false)
            }
            _ => Err(BlossomError::InvalidConfiguration(
                "active-active store protocol scope does not match cluster or group".to_string(),
            )),
        }
    }

    /// Atomically admits or deduplicates one command and signs its receipt.
    pub fn admit(
        &self,
        command: &AdmittedCommand,
        membership_epoch: ReplicaMembershipEpoch,
    ) -> Result<AdmissionReceipt> {
        self.admit_batch(std::slice::from_ref(command), membership_epoch)?
            .pop()
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "single durable admission returned no receipt".to_string(),
                )
            })
    }

    /// Persists a bounded command group with one durability commit.
    pub fn admit_batch(
        &self,
        commands: &[AdmittedCommand],
        membership_epoch: ReplicaMembershipEpoch,
    ) -> Result<Vec<AdmissionReceipt>> {
        if commands.len() > DEFAULT_MAX_BATCH_COMMANDS {
            return Err(BlossomError::InvalidConfiguration(format!(
                "durable admission batch count {} exceeds maximum {}",
                commands.len(),
                DEFAULT_MAX_BATCH_COMMANDS
            )));
        }
        if commands.is_empty() {
            return Ok(Vec::new());
        }
        let encoded = commands
            .iter()
            .map(|command| {
                command.command.validate()?;
                if command.origin_sequence == 0 {
                    return Err(BlossomError::InvalidConfiguration(
                        "origin sequences start at one".to_string(),
                    ));
                }
                let command_hash = command.command.hash()?;
                let identity_key =
                    borsh::to_vec(&command.command.identity).map_err(encode_error)?;
                let command_key =
                    borsh::to_vec(&(command.origin_sequence, command.command.identity))
                        .map_err(encode_error)?;
                let command_bytes = borsh::to_vec(command).map_err(encode_error)?;
                Ok((command_hash, identity_key, command_key, command_bytes))
            })
            .collect::<Result<Vec<_>>>()?;
        self.transact(|transaction| {
            for (command_hash, identity_key, command_key, command_bytes) in &encoded {
                if let Some(existing) =
                    transaction.get(COMMAND_IDENTITIES_TABLE, identity_key.as_slice())?
                {
                    if existing.as_slice() != command_hash.as_ref() {
                        return Err(BlossomError::InvalidConfiguration(
                            "conflicting bytes for one command identity".to_string(),
                        ));
                    }
                } else {
                    transaction.insert(
                        COMMAND_IDENTITIES_TABLE,
                        identity_key.clone(),
                        command_hash.as_ref().to_vec(),
                    )?;
                }
                transaction.insert(COMMANDS_TABLE, command_key.clone(), command_bytes.clone())?;
            }
            Ok(())
        })?;
        commands
            .iter()
            .zip(encoded)
            .map(|(command, (command_hash, _, _, _))| {
                AdmissionReceipt::signed(
                    AdmissionReceiptBody {
                        command_identity: command.command.identity,
                        command_hash,
                        origin_sequence: command.origin_sequence,
                        holder: self.holder,
                        site: self.site.clone(),
                        membership_epoch,
                        durable_store_generation: self.store_generation,
                    },
                    &self.signer,
                )
            })
            .collect()
    }

    /// Persists one canonical command batch and signs one receipt for it.
    pub fn admit_command_batch(
        &self,
        shard: Vec<u8>,
        batch: &CommandBatch,
        membership_epoch: ReplicaMembershipEpoch,
    ) -> Result<AdmissionBatchReceipt> {
        validate_shard_id(&shard)?;
        let batch_bytes = batch.canonical_bytes()?;
        let command_batch_hash = batch.hash()?;
        let identities = batch
            .commands
            .iter()
            .map(|admitted| {
                Ok((
                    borsh::to_vec(&admitted.command.identity).map_err(encode_error)?,
                    admitted.command.hash()?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        self.transact(|transaction| {
            for (identity_key, command_hash) in &identities {
                if let Some(existing) =
                    transaction.get(COMMAND_IDENTITIES_TABLE, identity_key.as_slice())?
                {
                    if existing.as_slice() != command_hash.as_ref() {
                        return Err(BlossomError::InvalidConfiguration(
                            "conflicting bytes for one command identity".to_string(),
                        ));
                    }
                } else {
                    transaction.insert(
                        COMMAND_IDENTITIES_TABLE,
                        identity_key.clone(),
                        command_hash.as_ref().to_vec(),
                    )?;
                }
            }
            if let Some(existing) =
                transaction.get(ADMISSION_BATCHES_TABLE, command_batch_hash.as_ref())?
            {
                if existing != batch_bytes {
                    return Err(BlossomError::InvalidConfiguration(
                        "durable admission batch hash collision".to_string(),
                    ));
                }
            } else {
                transaction.insert(
                    ADMISSION_BATCHES_TABLE,
                    command_batch_hash.as_ref().to_vec(),
                    batch_bytes.clone(),
                )?;
            }
            Ok(())
        })?;
        let first_origin_sequence = batch
            .commands
            .first()
            .expect("validated command batch is non-empty")
            .origin_sequence;
        let last_origin_sequence = batch
            .commands
            .last()
            .expect("validated command batch is non-empty")
            .origin_sequence;
        let command_count = u32::try_from(batch.commands.len()).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "durable admission batch command count exceeds u32".to_string(),
            )
        })?;
        AdmissionBatchReceipt::signed(
            AdmissionBatchReceiptBody {
                shard,
                command_batch_hash,
                first_origin_sequence,
                last_origin_sequence,
                command_count,
                holder: self.holder,
                site: self.site.clone(),
                membership_epoch,
                durable_store_generation: self.store_generation,
            },
            &self.signer,
        )
    }

    /// Persists complete batch bytes under their verified reference hash.
    pub fn store_batch(
        &self,
        reference: &BatchReference,
        batch: &CommandBatch,
    ) -> Result<AuthenticatedAvailabilityReceipt> {
        reference.verify_batch(batch)?;
        let reference_hash = reference.hash()?;
        let bytes = batch.canonical_bytes()?;
        self.transact(|transaction| {
            self.bind_protocol_scope_in_transaction(
                transaction,
                reference.cluster_id,
                reference.consensus_group_id,
            )?;
            transaction.insert(BATCHES_TABLE, reference_hash.as_ref().to_vec(), bytes)?;
            Ok(())
        })?;

        AuthenticatedAvailabilityReceipt::signed(
            AvailabilityReceiptBody {
                reference_hash,
                holder: self.holder,
                site: self.site.clone(),
                membership_epoch: reference.data_holder_membership_epoch,
                durable_store_generation: self.store_generation,
            },
            &self.signer,
        )
    }

    /// Loads and verifies complete bytes for a reference.
    pub fn load_batch(&self, reference: &BatchReference) -> Result<Option<CommandBatch>> {
        let hash = reference.hash()?;
        let Some(bytes) = self.store.get(BATCHES_TABLE, hash.as_ref())? else {
            return Ok(None);
        };
        let batch = borsh::from_slice::<CommandBatch>(&bytes).map_err(|err| {
            BlossomError::WireProtocol(format!("decode durable command batch: {err}"))
        })?;
        reference.verify_batch(&batch)?;
        Ok(Some(batch))
    }

    /// Installs repaired batch bytes after verifying the reference commitment.
    pub fn repair_batch_from(
        &self,
        source: &DurableAdmissionStore,
        reference: &BatchReference,
    ) -> Result<AuthenticatedAvailabilityReceipt> {
        let batch = source.load_batch(reference)?.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "repair source does not possess the referenced batch".to_string(),
            )
        })?;
        self.store_batch(reference, &batch)
    }

    /// Removes locally retained batch bytes after retention evidence permits it.
    pub fn collect_batch(
        &self,
        reference: &BatchReference,
        position: Watermark,
        evidence: &RetentionEvidence,
    ) -> Result<bool> {
        if !evidence.permits_collection(position) {
            return Err(BlossomError::InvalidConfiguration(
                "batch retention evidence does not cover the applied position".to_string(),
            ));
        }
        let hash = reference.hash()?;
        let removed = self.transact(|transaction| {
            let removed = transaction.get(BATCHES_TABLE, hash.as_ref())?.is_some();
            transaction.remove(BATCHES_TABLE, hash.as_ref().to_vec())?;
            Ok(removed)
        })?;
        Ok(removed)
    }

    /// Appends a monotonic milestone and updates the indexed status atomically.
    pub fn record_milestone(&self, event: &MilestoneEvent) -> Result<u64> {
        self.record_milestones(std::slice::from_ref(event))?
            .pop()
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "single milestone commit returned no sequence".to_string(),
                )
            })
    }

    /// Durably records a bounded group of non-applied milestones in one commit.
    pub fn record_milestones(&self, events: &[MilestoneEvent]) -> Result<Vec<u64>> {
        if events.len() > DEFAULT_MAX_BATCH_COMMANDS {
            return Err(BlossomError::InvalidConfiguration(format!(
                "milestone batch count {} exceeds maximum {}",
                events.len(),
                DEFAULT_MAX_BATCH_COMMANDS
            )));
        }
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let encoded = events
            .iter()
            .map(|event| {
                if event.milestone == Milestone::Applied {
                    return Err(BlossomError::InvalidConfiguration(
                        "Applied must be recorded atomically with an applied completion"
                            .to_string(),
                    ));
                }
                borsh::to_vec(event).map_err(encode_error)
            })
            .collect::<Result<Vec<_>>>()?;
        self.transact(|transaction| {
            let mut sequence = transaction
                .get(META_TABLE, b"next_milestone_sequence")?
                .map(|value| decode_u64(&value, "next milestone sequence"))
                .transpose()?
                .unwrap_or(0);
            let mut sequences = Vec::with_capacity(events.len());
            for (event, bytes) in events.iter().zip(&encoded) {
                if let Some(existing) =
                    transaction.get(REFERENCE_STATUS_TABLE, event.reference_hash.as_ref())?
                {
                    let existing =
                        borsh::from_slice::<MilestoneEvent>(&existing).map_err(encode_error)?;
                    if existing.milestone.rank() > event.milestone.rank() {
                        return Err(BlossomError::InvalidConfiguration(
                            "reference milestone cannot regress".to_string(),
                        ));
                    }
                }
                transaction.insert(
                    MILESTONES_TABLE,
                    sequence.to_be_bytes().to_vec(),
                    bytes.clone(),
                )?;
                transaction.insert(
                    REFERENCE_STATUS_TABLE,
                    event.reference_hash.as_ref().to_vec(),
                    bytes.clone(),
                )?;
                sequences.push(sequence);
                sequence = sequence.checked_add(1).ok_or_else(|| {
                    BlossomError::InvalidConfiguration("milestone sequence overflow".to_string())
                })?;
            }
            transaction.insert(
                META_TABLE,
                b"next_milestone_sequence".to_vec(),
                sequence.to_be_bytes().to_vec(),
            )?;
            Ok(sequences)
        })
    }

    /// Durably records one validator vote before returning its signature.
    ///
    /// The `(consensus group, validator generation, position)` key may only be
    /// associated with one statement hash, including across process restarts.
    /// Durably enforces one order vote per position before signing.
    pub fn sign_order_statement(&self, statement: &OrderStatement) -> Result<OrderVote> {
        if statement.position.position == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "order positions start at one".to_string(),
            ));
        }
        let vote_key = borsh::to_vec(&(
            statement.consensus_group_id,
            statement.validator_generation,
            statement.position,
        ))
        .map_err(encode_error)?;
        let statement_hash = hash_borsh(ORDER_VOTE_HASH_DOMAIN, statement)?;
        self.transact(|transaction| {
            if let Some(existing) = transaction.get(ORDER_VOTES_TABLE, vote_key.as_slice())? {
                if existing.as_slice() != statement_hash.as_ref() {
                    return Err(BlossomError::InvalidConfiguration(
                        "validator refuses to equivocate at one order position".to_string(),
                    ));
                }
            } else {
                transaction.insert(
                    ORDER_VOTES_TABLE,
                    vote_key,
                    statement_hash.as_ref().to_vec(),
                )?;
            }
            Ok(())
        })?;
        let signature = self
            .signer
            .sign(&OrderCertificate::signing_bytes(statement)?);
        Ok(OrderVote {
            statement: statement.clone(),
            validator: self.holder,
            signature,
        })
    }

    /// Durably locks one response per caller challenge before returning a
    /// validator signature. This prevents a restarted validator from signing
    /// conflicting order heads for the same freshness challenge.
    /// Durably enforces one read-barrier vote per challenge before signing.
    pub fn sign_read_barrier_statement(
        &self,
        statement: &ReadBarrierStatement,
    ) -> Result<ReadBarrierVote> {
        let vote_key = borsh::to_vec(&(
            statement.consensus_group_id,
            statement.validator_generation,
            statement.challenge,
        ))
        .map_err(encode_error)?;
        let statement_hash = hash_borsh(READ_BARRIER_VOTE_HASH_DOMAIN, statement)?;
        self.transact(|transaction| {
            if let Some(existing) =
                transaction.get(READ_BARRIER_VOTES_TABLE, vote_key.as_slice())?
            {
                if existing.as_slice() != statement_hash.as_ref() {
                    return Err(BlossomError::InvalidConfiguration(
                        "validator refuses to equivocate for one read-barrier challenge"
                            .to_string(),
                    ));
                }
            } else {
                transaction.insert(
                    READ_BARRIER_VOTES_TABLE,
                    vote_key,
                    statement_hash.as_ref().to_vec(),
                )?;
            }
            Ok(())
        })?;
        Ok(ReadBarrierVote {
            statement: statement.clone(),
            validator: self.holder,
            signature: self
                .signer
                .sign(&ReadBarrierCertificate::signing_bytes(statement)?),
        })
    }

    pub(super) fn sign_committee_transition_statement(
        &self,
        statement: &CommitteeTransitionStatement,
    ) -> Result<CommitteeTransitionVote> {
        statement.validate()?;
        let (cluster_id, consensus_group_id) = self.protocol_scope()?.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "committee transition voting requires a bound protocol scope".to_string(),
            )
        })?;
        if statement.cluster_id != cluster_id || statement.consensus_group_id != consensus_group_id
        {
            return Err(BlossomError::InvalidConfiguration(
                "committee transition vote scope does not match the durable store".to_string(),
            ));
        }
        let statement_bytes = borsh::to_vec(statement).map_err(encode_error)?;
        let statement_hash =
            sha256_hash(COMMITTEE_TRANSITION_STATEMENT_DOMAIN, &[&statement_bytes]);
        let key = statement
            .previous_validator_generation
            .0
            .to_be_bytes()
            .to_vec();
        self.transact(|transaction| {
            if let Some(existing) =
                transaction.get(COMMITTEE_TRANSITION_VOTES_TABLE, key.as_slice())?
            {
                if existing.as_slice() != statement_hash.as_ref() {
                    return Err(BlossomError::InvalidConfiguration(
                        "validator already voted for another committee at this generation"
                            .to_string(),
                    ));
                }
            } else {
                transaction.insert(
                    COMMITTEE_TRANSITION_VOTES_TABLE,
                    key,
                    statement_hash.as_ref().to_vec(),
                )?;
            }
            Ok(())
        })?;
        CommitteeTransitionVote::signed(statement.clone(), &self.signer)
    }

    /// Returns durable milestone events in append order.
    pub fn milestones(&self) -> Result<Vec<MilestoneEvent>> {
        self.store
            .scan(MILESTONES_TABLE)?
            .into_iter()
            .map(|(_, value)| {
                borsh::from_slice(&value).map_err(|err| {
                    BlossomError::WireProtocol(format!("decode milestone event: {err}"))
                })
            })
            .collect()
    }

    /// Performs a bounded indexed lookup for one reference.
    pub fn reference_status(&self, reference_hash: HashType) -> Result<ReferenceStatus> {
        if let Some(bytes) = self
            .store
            .get(APPLIED_COMPLETIONS_TABLE, reference_hash.as_ref())?
        {
            let completion = borsh::from_slice::<AppliedCompletion>(&bytes).map_err(|error| {
                BlossomError::WireProtocol(format!("decode applied completion: {error}"))
            })?;
            completion.validate(None)?;
            if completion.reference_hash != reference_hash {
                return Err(BlossomError::InvalidConfiguration(
                    "applied-completion table key does not match its record".to_string(),
                ));
            }
            return Ok(ReferenceStatus::Applied(completion));
        }
        let Some(bytes) = self
            .store
            .get(REFERENCE_STATUS_TABLE, reference_hash.as_ref())?
        else {
            return Ok(ReferenceStatus::Unknown);
        };
        let event = borsh::from_slice::<MilestoneEvent>(&bytes).map_err(|error| {
            BlossomError::WireProtocol(format!("decode reference status: {error}"))
        })?;
        if event.reference_hash != reference_hash || event.milestone == Milestone::Applied {
            return Err(BlossomError::InvalidConfiguration(
                "reference-status table is inconsistent with its applied completion".to_string(),
            ));
        }
        Ok(ReferenceStatus::Pending(event))
    }

    /// Waits up to `timeout` for a reference to reach `target`.
    pub fn wait_for(
        &self,
        reference_hash: HashType,
        target: Milestone,
        timeout: Duration,
    ) -> Result<WaitForOutcome> {
        if timeout > MAX_WAIT_FOR_TIMEOUT {
            return Err(BlossomError::InvalidConfiguration(format!(
                "wait timeout exceeds the {} second bound",
                MAX_WAIT_FOR_TIMEOUT.as_secs()
            )));
        }
        let started = Instant::now();
        loop {
            let status = self.reference_status(reference_hash)?;
            if status.reached(target) {
                return Ok(WaitForOutcome::Reached(status));
            }
            if status.is_terminal() || started.elapsed() >= timeout {
                return Ok(WaitForOutcome::TimedOut(status));
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(WaitForOutcome::TimedOut(status));
            }
            thread::sleep(WAIT_FOR_POLL_INTERVAL.min(remaining));
        }
    }

    pub(super) fn persist_ordered_delta(
        &self,
        delta: &OrderedStateDelta,
        milestones: &[MilestoneEvent],
        completion: Option<&AppliedCompletion>,
    ) -> Result<()> {
        let completion_bytes = completion
            .map(borsh::to_vec)
            .transpose()
            .map_err(encode_error)?;
        let metadata_bytes = borsh::to_vec(&delta.metadata).map_err(encode_error)?;
        let milestone_bytes = milestones
            .iter()
            .map(borsh::to_vec)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(encode_error)?;
        self.transact(|transaction| {
            transaction.insert(
                ORDERED_METADATA_TABLE,
                ORDERED_METADATA_KEY.as_bytes().to_vec(),
                metadata_bytes,
            )?;
            for hash in &delta.available_removals {
                transaction.remove(AVAILABLE_REFERENCES_TABLE, hash.as_ref().to_vec())?;
            }
            for (hash, certificate) in &delta.available_upserts {
                transaction.insert(
                    AVAILABLE_REFERENCES_TABLE,
                    hash.as_ref().to_vec(),
                    borsh::to_vec(certificate).map_err(encode_error)?,
                )?;
            }
            for (position, certificate) in &delta.finalized_upserts {
                transaction.insert(
                    FINALIZED_POSITIONS_TABLE,
                    position.to_be_bytes().to_vec(),
                    borsh::to_vec(certificate).map_err(encode_error)?,
                )?;
            }
            for (position, reference_hash) in &delta.position_upserts {
                transaction.insert(
                    POSITION_REFERENCES_TABLE,
                    position.to_be_bytes().to_vec(),
                    borsh::to_vec(reference_hash).map_err(encode_error)?,
                )?;
            }
            for (origin, tail) in &delta.origin_tail_upserts {
                transaction.insert(
                    ORIGIN_TAILS_TABLE,
                    borsh::to_vec(origin).map_err(encode_error)?,
                    borsh::to_vec(tail).map_err(encode_error)?,
                )?;
            }
            if !milestone_bytes.is_empty() {
                let mut sequence = transaction
                    .get(META_TABLE, b"next_milestone_sequence")?
                    .map(|value| decode_u64(&value, "next milestone sequence"))
                    .transpose()?
                    .unwrap_or(0);
                for (event, event_bytes) in milestones.iter().zip(&milestone_bytes) {
                    transaction.insert(
                        MILESTONES_TABLE,
                        sequence.to_be_bytes().to_vec(),
                        event_bytes.clone(),
                    )?;
                    transaction.insert(
                        REFERENCE_STATUS_TABLE,
                        event.reference_hash.as_ref().to_vec(),
                        event_bytes.clone(),
                    )?;
                    sequence = sequence.checked_add(1).ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "milestone sequence overflow".to_string(),
                        )
                    })?;
                }
                transaction.insert(
                    META_TABLE,
                    b"next_milestone_sequence".to_vec(),
                    sequence.to_be_bytes().to_vec(),
                )?;
            }
            if let (Some(completion), Some(completion_bytes)) = (completion, completion_bytes) {
                transaction.insert(
                    APPLIED_COMPLETIONS_TABLE,
                    completion.reference_hash.as_ref().to_vec(),
                    completion_bytes,
                )?;
            }
            Ok(())
        })
    }

    pub(super) fn persist_committee_transition(
        &self,
        metadata: &DurableOrderedMetadata,
        certificate: &CommitteeTransitionCertificate,
    ) -> Result<()> {
        let metadata_bytes = borsh::to_vec(metadata).map_err(encode_error)?;
        let certificate_bytes = borsh::to_vec(certificate).map_err(encode_error)?;
        let generation = certificate
            .statement
            .next_validator_generation
            .0
            .to_be_bytes()
            .to_vec();
        self.transact(|transaction| {
            if let Some(existing) =
                transaction.get(COMMITTEE_TRANSITIONS_TABLE, generation.as_slice())?
            {
                if existing != certificate_bytes {
                    return Err(BlossomError::InvalidConfiguration(
                        "validator generation already commits another committee transition"
                            .to_string(),
                    ));
                }
            } else {
                transaction.insert(COMMITTEE_TRANSITIONS_TABLE, generation, certificate_bytes)?;
            }
            transaction.insert(
                ORDERED_METADATA_TABLE,
                ORDERED_METADATA_KEY.as_bytes().to_vec(),
                metadata_bytes,
            )?;
            Ok(())
        })
    }

    pub(super) fn load_ordered_state(&self) -> Result<Option<DurableOrderedState>> {
        let Some(metadata_bytes) = self
            .store
            .get(ORDERED_METADATA_TABLE, ORDERED_METADATA_KEY.as_bytes())?
        else {
            return Ok(None);
        };
        let metadata =
            borsh::from_slice::<DurableOrderedMetadata>(&metadata_bytes).map_err(|err| {
                BlossomError::WireProtocol(format!("decode ordered-engine metadata: {err}"))
            })?;

        let available = self
            .store
            .scan(AVAILABLE_REFERENCES_TABLE)?
            .into_iter()
            .map(|(key, value)| {
                let certificate =
                    borsh::from_slice::<AvailabilityCertificate>(&value).map_err(|error| {
                        BlossomError::WireProtocol(format!("decode available reference: {error}"))
                    })?;
                if certificate.reference.hash()?.as_ref() != key.as_slice() {
                    return Err(BlossomError::InvalidConfiguration(
                        "available-reference table key does not match certificate".to_string(),
                    ));
                }
                Ok((certificate.reference.hash()?, certificate))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let finalized = self
            .store
            .scan(FINALIZED_POSITIONS_TABLE)?
            .into_iter()
            .map(|(position, value)| {
                let position = decode_u64(&position, "finalized position")?;
                let certificate =
                    borsh::from_slice::<OrderCertificate>(&value).map_err(|error| {
                        BlossomError::WireProtocol(format!(
                            "decode finalized order certificate: {error}"
                        ))
                    })?;
                Ok((position, certificate))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let final_reference_by_position = self
            .store
            .scan(POSITION_REFERENCES_TABLE)?
            .into_iter()
            .map(|(position, value)| {
                let position = decode_u64(&position, "finalized reference position")?;
                let reference_hash = borsh::from_slice::<HashType>(&value).map_err(|error| {
                    BlossomError::WireProtocol(format!("decode finalized reference hash: {error}"))
                })?;
                Ok((position, reference_hash))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let last_origin_reference = self
            .store
            .scan(ORIGIN_TAILS_TABLE)?
            .into_iter()
            .map(|(key, value)| {
                let origin = borsh::from_slice::<(PubKey, u64, u64)>(&key).map_err(|error| {
                    BlossomError::WireProtocol(format!("decode origin-tail key: {error}"))
                })?;
                let tail = borsh::from_slice::<(HashType, u64)>(&value).map_err(|error| {
                    BlossomError::WireProtocol(format!("decode origin-tail value: {error}"))
                })?;
                Ok((origin, tail))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let committee_transitions = self
            .store
            .scan(COMMITTEE_TRANSITIONS_TABLE)?
            .into_iter()
            .map(|(generation, value)| {
                let generation = ValidatorGeneration(decode_u64(
                    &generation,
                    "committee transition generation",
                )?);
                let certificate = borsh::from_slice::<CommitteeTransitionCertificate>(&value)
                    .map_err(|error| {
                        BlossomError::WireProtocol(format!(
                            "decode committee transition certificate: {error}"
                        ))
                    })?;
                if certificate.statement.next_validator_generation != generation {
                    return Err(BlossomError::InvalidConfiguration(
                        "committee transition table key does not match certificate".to_string(),
                    ));
                }
                Ok((generation, certificate))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(Some(DurableOrderedState {
            version: metadata.version,
            holder_membership_epoch: metadata.holder_membership_epoch,
            validator_generation: metadata.validator_generation,
            route_generation: metadata.route_generation,
            command_spec_version: metadata.command_spec_version,
            available,
            finalized,
            final_reference_by_position,
            last_origin_reference,
            last_finalized_position: metadata.last_finalized_position,
            last_order_certificate_hash: metadata.last_order_certificate_hash,
            applied_watermark: metadata.applied_watermark,
            committee_transitions,
        }))
    }
}
