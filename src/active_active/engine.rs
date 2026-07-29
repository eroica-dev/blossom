//! Global-order validation, finalization, application, and read barriers.

use super::*;

impl GlobalOrderedEngine {
    /// Opens a verified global-order engine with default application generations.
    pub fn new(
        store: DurableAdmissionStore,
        mode: ActiveActiveConsistencyMode,
        holder_membership: HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: BTreeSet<PubKey>,
        _max_reorder: u64,
    ) -> Result<Self> {
        Self::new_with_application_contract(
            store,
            mode,
            holder_membership,
            validator_generation,
            validators,
            TrustMode::Verified,
            RouteGeneration(1),
            CommandSpecVersion(1),
        )
    }

    /// Opens an engine with an explicit verified or trusted order mode.
    pub fn new_with_trust_mode(
        store: DurableAdmissionStore,
        mode: ActiveActiveConsistencyMode,
        holder_membership: HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: BTreeSet<PubKey>,
        order_trust_mode: TrustMode,
        _max_reorder: u64,
    ) -> Result<Self> {
        Self::new_with_application_contract(
            store,
            mode,
            holder_membership,
            validator_generation,
            validators,
            order_trust_mode,
            RouteGeneration(1),
            CommandSpecVersion(1),
        )
    }

    #[allow(clippy::too_many_arguments)]
    /// Opens an engine bound to explicit route and command-schema generations.
    pub fn new_with_application_contract(
        store: DurableAdmissionStore,
        mode: ActiveActiveConsistencyMode,
        holder_membership: HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: BTreeSet<PubKey>,
        order_trust_mode: TrustMode,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<Self> {
        if mode != ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered {
            return Err(BlossomError::InvalidConfiguration(
                "GlobalOrderedEngine requires active-sync-global-ordered mode".to_string(),
            ));
        }
        holder_membership.validate()?;
        if holder_membership
            .members_by_site
            .get(&store.site)
            .is_none_or(|members| !members.contains(&store.holder))
            || holder_membership.store_generations.get(&store.holder)
                != Some(&store.store_generation)
        {
            return Err(BlossomError::InvalidConfiguration(
                "ordered-engine store identity is not a holder in the committed membership"
                    .to_string(),
            ));
        }
        if validators.is_empty() {
            return Err(BlossomError::InvalidConfiguration(
                "global ordering requires at least one validator".to_string(),
            ));
        }
        if validators.len() > MAX_REFERENCES_PER_ORDERING_WINDOW {
            return Err(BlossomError::InvalidConfiguration(format!(
                "validator count exceeds the per-window reference limit of \
                 {MAX_REFERENCES_PER_ORDERING_WINDOW}"
            )));
        }
        route_generation.validate()?;
        command_spec_version.validate()?;
        let loaded_ordered = store.load_ordered_state()?;
        let mut engine = Self {
            store,
            mode,
            holder_membership,
            validator_generation,
            validators,
            order_trust_mode,
            available: BTreeMap::new(),
            finalized: BTreeMap::new(),
            final_reference_by_position: BTreeMap::new(),
            finalized_reference_hashes: BTreeSet::new(),
            last_origin_reference: BTreeMap::new(),
            last_finalized_position: 0,
            last_order_certificate_hash: HashType::default(),
            applied_watermark: Watermark::default(),
            route_generation,
            command_spec_version,
            telemetry: TelemetryHandle::default(),
        };
        if let Some(state) = loaded_ordered {
            engine.validate_durable_state(&state)?;
            engine.install_durable_state(state);
        }
        Ok(engine)
    }

    /// Installs a telemetry destination and returns the engine.
    pub fn with_telemetry(mut self, telemetry: TelemetryHandle) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// Replaces the telemetry destination.
    pub fn set_telemetry(&mut self, telemetry: TelemetryHandle) {
        self.telemetry = telemetry;
    }

    /// Borrows the configured telemetry handle.
    pub fn telemetry(&self) -> &TelemetryHandle {
        &self.telemetry
    }

    /// Returns whether ordered state and application completions are durable.
    pub fn is_production_durable(&self) -> bool {
        true
    }

    /// Returns process-local durability counters for the ordered store.
    pub fn durability_metrics(&self) -> ActiveActiveDurabilityMetrics {
        self.store.durability_metrics()
    }

    /// Activates a new route and/or application command specification at a
    /// quiescent applied boundary. The next `BatchReference` must commit the
    /// new values.
    /// Atomically advances route and command-schema generations at quiescence.
    pub fn activate_application_contract(
        &mut self,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<ApplicationContractActivation> {
        route_generation.validate()?;
        command_spec_version.validate()?;
        if !self.available.is_empty()
            || self.applied_watermark.position != self.last_finalized_position
        {
            return Err(BlossomError::InvalidConfiguration(
                "application-contract activation requires no available or unapplied references"
                    .to_string(),
            ));
        }
        if route_generation.0 < self.route_generation.0
            || command_spec_version.0 < self.command_spec_version.0
            || (route_generation == self.route_generation
                && command_spec_version == self.command_spec_version)
        {
            return Err(BlossomError::InvalidConfiguration(
                "application-contract activation must monotonically advance route or command-spec version"
                    .to_string(),
            ));
        }
        let activation = ApplicationContractActivation {
            previous_route_generation: self.route_generation,
            route_generation,
            previous_command_spec_version: self.command_spec_version,
            command_spec_version,
            activated_at: self.applied_watermark,
        };
        let mut metadata = self.durable_metadata();
        metadata.route_generation = route_generation;
        metadata.command_spec_version = command_spec_version;
        self.store
            .persist_ordered_delta(&OrderedStateDelta::new(metadata), &[], None)?;
        self.route_generation = route_generation;
        self.command_spec_version = command_spec_version;
        Ok(activation)
    }

    /// Records a verified local-admission certificate.
    pub fn accept_local(&self, certificate: &LocalAdmissionCertificate) -> Result<MilestoneEvent> {
        self.accept_local_batch(std::slice::from_ref(certificate))?
            .pop()
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "single local admission returned no milestone".to_string(),
                )
            })
    }

    /// Verifies and records a bounded group of local admissions in one commit.
    pub fn accept_local_batch(
        &self,
        certificates: &[LocalAdmissionCertificate],
    ) -> Result<Vec<MilestoneEvent>> {
        if certificates.len() > DEFAULT_MAX_BATCH_COMMANDS {
            return Err(BlossomError::InvalidConfiguration(format!(
                "local admission batch count {} exceeds maximum {}",
                certificates.len(),
                DEFAULT_MAX_BATCH_COMMANDS
            )));
        }
        let events = certificates
            .iter()
            .map(|certificate| {
                certificate.verify()?;
                validate_local_admission_policy_against_membership(
                    &certificate.policy,
                    &self.holder_membership,
                )?;
                Ok(milestone_event(
                    self.mode,
                    certificate.command_hash,
                    Milestone::AcceptedLocal,
                    None,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        self.store.record_milestones(&events)?;
        for event in &events {
            self.telemetry.record_milestone(event);
        }
        Ok(events)
    }

    /// Verifies and records one locally durable command batch.
    pub fn accept_local_command_batch(
        &self,
        batch: &CommandBatch,
        certificate: &LocalAdmissionBatchCertificate,
    ) -> Result<MilestoneEvent> {
        self.accept_local_command_batches(&[(batch, certificate)])?
            .pop()
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "single local command-batch admission returned no milestone".to_string(),
                )
            })
    }

    /// Verifies shard-local certificates and records all batch milestones.
    pub fn accept_local_command_batches(
        &self,
        batches: &[(&CommandBatch, &LocalAdmissionBatchCertificate)],
    ) -> Result<Vec<MilestoneEvent>> {
        if batches.len() > DEFAULT_MAX_BATCH_COMMANDS {
            return Err(BlossomError::InvalidConfiguration(format!(
                "local command-batch admission count {} exceeds maximum {}",
                batches.len(),
                DEFAULT_MAX_BATCH_COMMANDS
            )));
        }
        let verified = batches
            .iter()
            .map(|(batch, certificate)| certificate.verify_and_bind(batch))
            .collect::<Result<Vec<_>>>()?;
        self.accept_verified_local_command_batches(&verified)
    }

    /// Records batches already verified by independent shard workers.
    pub fn accept_verified_local_command_batches(
        &self,
        batches: &[VerifiedLocalAdmissionBatch],
    ) -> Result<Vec<MilestoneEvent>> {
        if batches.len() > DEFAULT_MAX_BATCH_COMMANDS {
            return Err(BlossomError::InvalidConfiguration(format!(
                "verified local command-batch admission count {} exceeds maximum {}",
                batches.len(),
                DEFAULT_MAX_BATCH_COMMANDS
            )));
        }
        let events = batches
            .iter()
            .map(|batch| {
                validate_local_admission_policy_against_membership(
                    &batch.policy,
                    &self.holder_membership,
                )?;
                Ok(milestone_event(
                    self.mode,
                    batch.command_batch_hash,
                    Milestone::AcceptedLocal,
                    None,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        self.store.record_milestones(&events)?;
        for event in &events {
            self.telemetry.record_milestone(event);
        }
        Ok(events)
    }

    /// Persists one referenced batch and returns this holder's signed
    /// admission receipt without advancing availability.
    ///
    /// Coordinators use this to collect multi-holder availability while
    /// retaining a single durable store owner per process.
    pub fn store_batch(
        &self,
        reference: &BatchReference,
        batch: &CommandBatch,
    ) -> Result<AuthenticatedAvailabilityReceipt> {
        self.store.store_batch(reference, batch)
    }

    /// Validates and persists recoverable multi-site availability.
    pub fn mark_available_with_batch(
        &mut self,
        batch: &CommandBatch,
        certificate: AvailabilityCertificate,
    ) -> Result<MilestoneEvent> {
        certificate.reference.verify_batch(batch)?;
        self.store.store_batch(&certificate.reference, batch)?;
        self.mark_available(certificate)
    }

    /// Validates and persists recoverable multi-site availability after the
    /// referenced batch bytes are already present in this holder's store.
    pub fn mark_available(
        &mut self,
        certificate: AvailabilityCertificate,
    ) -> Result<MilestoneEvent> {
        certificate.verify(&self.holder_membership)?;
        if certificate.reference.route_generation != self.route_generation
            || certificate.reference.command_spec_version != self.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "available reference route generation or command-spec version does not match the active application contract"
                    .to_string(),
            ));
        }
        self.store.bind_protocol_scope(
            certificate.reference.cluster_id,
            certificate.reference.consensus_group_id,
        )?;
        if certificate.reference.validator_generation != self.validator_generation {
            return Err(BlossomError::InvalidConfiguration(
                "available reference validator generation mismatch".to_string(),
            ));
        }
        let reference_hash = certificate.reference.hash()?;
        if self.available.contains_key(&reference_hash) {
            let event = milestone_event(self.mode, reference_hash, Milestone::Available, None);
            self.telemetry.record_milestone(&event);
            return Ok(event);
        }
        if self
            .final_reference_by_position
            .values()
            .any(|existing| *existing == reference_hash)
        {
            let event = milestone_event(self.mode, reference_hash, Milestone::Available, None);
            self.telemetry.record_milestone(&event);
            return Ok(event);
        }
        let max_pending_references = MAX_PIPELINED_AVAILABILITY_WINDOWS
            .checked_mul(self.validators.len())
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "availability pipeline capacity overflow".to_string(),
                )
            })?;
        if self.available.len() >= max_pending_references {
            return Err(BlossomError::BlockQueueFull);
        }
        let origin_key = (
            certificate.reference.origin,
            certificate.reference.origin_incarnation,
            certificate.reference.origin_key_generation,
        );
        let (expected_previous_hash, expected_first_sequence) =
            self.last_origin_reference.get(&origin_key).map_or(
                (
                    HashType::default(),
                    certificate.reference.first_origin_sequence,
                ),
                |(hash, last_sequence)| (*hash, last_sequence.saturating_add(1)),
            );
        if certificate.reference.previous_origin_reference_hash != expected_previous_hash
            || certificate.reference.first_origin_sequence != expected_first_sequence
        {
            return Err(BlossomError::InvalidConfiguration(
                "origin reference does not extend its hash-chained contiguous range".to_string(),
            ));
        }
        for existing in self.available.values() {
            if certificate.reference.conflicts_with(&existing.reference) {
                return Err(BlossomError::InvalidConfiguration(
                    "overlapping or equivocated origin reference".to_string(),
                ));
            }
        }
        let origin_tail = (reference_hash, certificate.reference.last_origin_sequence);
        let mut delta = OrderedStateDelta::new(self.durable_metadata());
        delta.origin_tail_upserts.push((origin_key, origin_tail));
        delta
            .available_upserts
            .push((reference_hash, certificate.clone()));
        let event = milestone_event(self.mode, reference_hash, Milestone::Available, None);
        self.store
            .persist_ordered_delta(&delta, std::slice::from_ref(&event), None)?;
        self.last_origin_reference.insert(origin_key, origin_tail);
        self.available.insert(reference_hash, certificate);
        self.telemetry.record_milestone(&event);
        Ok(event)
    }

    /// Derives the next order statement from a finalized Blossom epoch.
    ///
    /// Global ordering intentionally commits one availability-certified
    /// reference transaction per Blossom epoch so every validator derives the
    /// same next hash-chain position without a leader-assigned sequence.
    /// Derives the next order statement from a cryptographically finalized epoch.
    pub fn order_statement_for_finalized_epoch(&self, epoch: &Epoch) -> Result<OrderStatement> {
        self.order_statement_for_epoch_references(ordered_batch_references(epoch)?, epoch)
    }

    /// Derives the next statement from an epoch committed by a trusted runtime.
    ///
    /// Trusted nodes do not add a second signature or consensus round. The
    /// locally committed epoch hash and deterministic BTree block order are the
    /// trusted order receipt.
    /// Derives the next order statement from a locally committed trusted epoch.
    pub fn order_statement_for_trusted_finalized_epoch(
        &self,
        epoch: &Epoch,
    ) -> Result<OrderStatement> {
        self.order_statement_for_epoch_references(ordered_batch_references_trusted(epoch)?, epoch)
    }

    /// Finalizes every availability-certified reference in one trusted epoch.
    ///
    /// References are consumed in the epoch's canonical BTree block-hash
    /// order. The committed epoch is the order authority: this method creates
    /// no signatures, votes, proposals, or additional consensus certificate.
    /// Installs every reference in a locally committed trusted epoch.
    pub fn finalize_trusted_epoch(&mut self, epoch: &Epoch) -> Result<Vec<MilestoneEvent>> {
        if !self.order_trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "unsigned trusted epoch finality requires a trusted ordered engine".to_string(),
            ));
        }
        let references = ordered_batch_references_trusted(epoch)?;
        self.validate_epoch_validator_set(epoch)?;

        // Validate the entire epoch before persisting any part of its order so
        // malformed later references cannot leave a partially installed epoch.
        let mut known_predecessors = self
            .final_reference_by_position
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let finalized_positions = self
            .final_reference_by_position
            .iter()
            .map(|(position, hash)| (*hash, *position))
            .collect::<BTreeMap<_, _>>();
        let mut epoch_references = BTreeSet::new();
        let mut existing_positions = Vec::with_capacity(references.len());
        for reference in &references {
            self.validate_orderable_reference(reference)?;
            let reference_hash = reference.hash()?;
            if !epoch_references.insert(reference_hash) {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted epoch contains a duplicate batch reference".to_string(),
                ));
            }
            if reference.previous_origin_reference_hash != HashType::default()
                && !known_predecessors.contains(&reference.previous_origin_reference_hash)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "an origin reference cannot precede its hash-chain predecessor".to_string(),
                ));
            }
            known_predecessors.insert(reference_hash);
            existing_positions.push(finalized_positions.get(&reference_hash).copied());
        }

        let existing_count = existing_positions
            .iter()
            .filter(|position| position.is_some())
            .count();
        if existing_count != 0 {
            if existing_count != references.len() {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted epoch replay is only partially present in the finality log"
                        .to_string(),
                ));
            }
            let first_position = existing_positions
                .first()
                .and_then(|position| *position)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "trusted epoch replay has no first order position".to_string(),
                    )
                })?;
            let mut events = Vec::with_capacity(references.len());
            for (index, (reference, position)) in
                references.iter().zip(existing_positions).enumerate()
            {
                let position = position.expect("all replay positions checked above");
                if position
                    != first_position
                        .checked_add(u64::try_from(index).map_err(|_| {
                            BlossomError::InvalidConfiguration(
                                "trusted epoch reference index overflow".to_string(),
                            )
                        })?)
                        .ok_or_else(|| {
                            BlossomError::InvalidConfiguration(
                                "trusted epoch replay position overflow".to_string(),
                            )
                        })?
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted epoch replay is not a contiguous canonical order".to_string(),
                    ));
                }
                let certificate = self.finalized.get(&position).ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "trusted epoch replay is missing its order receipt".to_string(),
                    )
                })?;
                certificate.verify_trusted(self.validator_generation)?;
                if certificate.statement.blossom_epoch_hash != epoch.hash
                    || certificate.statement.reference_hash != reference.hash()?
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted epoch replay conflicts with its durable order receipt".to_string(),
                    ));
                }
                events.push(milestone_event(
                    self.mode,
                    certificate.statement.reference_hash,
                    Milestone::Finalized,
                    Some(certificate.statement.position),
                ));
            }
            for event in &events {
                self.telemetry.record_milestone(event);
            }
            return Ok(events);
        }

        let mut delta = OrderedStateDelta::new(self.durable_metadata());
        let mut events = Vec::with_capacity(references.len());
        let mut next_position = self.last_finalized_position;
        let mut previous_certificate_hash = self.last_order_certificate_hash;
        for reference in references {
            let reference_hash = reference.hash()?;
            next_position = next_position.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("order position overflow".to_string())
            })?;
            let statement = OrderStatement {
                consensus_group_id: reference.consensus_group_id,
                blossom_epoch_hash: epoch.hash,
                position: Watermark {
                    position: next_position,
                },
                reference_hash,
                previous_order_certificate_hash: previous_certificate_hash,
                validator_generation: self.validator_generation,
            };
            let receipt = OrderCertificate::trusted(statement);
            receipt.verify_trusted(self.validator_generation)?;
            previous_certificate_hash = receipt.hash()?;
            delta.finalized_upserts.push((next_position, receipt));
            delta.position_upserts.push((next_position, reference_hash));
            events.push(milestone_event(
                self.mode,
                reference_hash,
                Milestone::Finalized,
                Some(Watermark {
                    position: next_position,
                }),
            ));
        }
        delta.metadata.last_finalized_position = next_position;
        delta.metadata.last_order_certificate_hash = previous_certificate_hash;
        self.store.persist_ordered_delta(&delta, &events, None)?;
        for (position, certificate) in delta.finalized_upserts {
            self.finalized.insert(position, certificate);
        }
        for (position, reference_hash) in delta.position_upserts {
            self.final_reference_by_position
                .insert(position, reference_hash);
            self.finalized_reference_hashes.insert(reference_hash);
        }
        self.last_finalized_position = next_position;
        self.last_order_certificate_hash = previous_certificate_hash;
        for event in &events {
            self.telemetry.record_milestone(event);
        }
        Ok(events)
    }

    fn order_statement_for_epoch_references(
        &self,
        references: Vec<BatchReference>,
        epoch: &Epoch,
    ) -> Result<OrderStatement> {
        self.validate_epoch_validator_set(epoch)?;
        let [reference] = references.as_slice() else {
            return Err(BlossomError::InvalidConfiguration(
                "single-reference ordering API requires exactly one batch reference transaction"
                    .to_string(),
            ));
        };
        self.order_statement_for_reference(reference, epoch.hash)
    }

    fn validate_epoch_validator_set(&self, epoch: &Epoch) -> Result<()> {
        let epoch_validators = epoch
            .body
            .verifiers
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        if epoch_validators != self.validators {
            return Err(BlossomError::InvalidConfiguration(
                "finalized Blossom epoch validator set does not match the ordering generation"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_orderable_reference(&self, reference: &BatchReference) -> Result<HashType> {
        if reference.validator_generation != self.validator_generation
            || reference.route_generation != self.route_generation
            || reference.command_spec_version != self.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "batch reference generation or application contract mismatch".to_string(),
            ));
        }
        let reference_hash = reference.hash()?;
        if !self.available.contains_key(&reference_hash) {
            return Err(BlossomError::InvalidConfiguration(
                "availability must be certified before proposing an order statement".to_string(),
            ));
        }
        Ok(reference_hash)
    }

    fn order_statement_for_reference(
        &self,
        reference: &BatchReference,
        blossom_epoch_hash: HashType,
    ) -> Result<OrderStatement> {
        let reference_hash = self.validate_orderable_reference(reference)?;
        self.ensure_origin_predecessor_finalized(reference)?;
        Ok(OrderStatement {
            consensus_group_id: reference.consensus_group_id,
            blossom_epoch_hash,
            position: Watermark {
                position: self.last_finalized_position.checked_add(1).ok_or_else(|| {
                    BlossomError::InvalidConfiguration("order position overflow".to_string())
                })?,
            },
            reference_hash,
            previous_order_certificate_hash: self.last_order_certificate_hash,
            validator_generation: self.validator_generation,
        })
    }

    /// Verifies and installs one portable order certificate.
    pub fn finalize(&mut self, certificate: OrderCertificate) -> Result<MilestoneEvent> {
        if self.order_trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted ordering must finalize directly from the committed Blossom epoch"
                    .to_string(),
            ));
        }
        certificate.verify(self.validator_generation, &self.validators)?;
        self.finalize_validated(certificate)
    }

    /// Finalizes a trusted order statement without signatures or another vote.
    /// Installs one trusted order statement without portable signatures.
    pub fn finalize_trusted(&mut self, statement: OrderStatement) -> Result<MilestoneEvent> {
        if !self.order_trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "unsigned trusted finality requires a trusted ordered engine".to_string(),
            ));
        }
        let receipt = OrderCertificate::trusted(statement);
        receipt.verify_trusted(self.validator_generation)?;
        self.finalize_validated(receipt)
    }

    fn finalize_validated(&mut self, certificate: OrderCertificate) -> Result<MilestoneEvent> {
        let statement = &certificate.statement;
        if let Some(existing) = self.finalized.get(&statement.position.position) {
            if existing.statement == certificate.statement {
                let event = milestone_event(
                    self.mode,
                    statement.reference_hash,
                    Milestone::Finalized,
                    Some(statement.position),
                );
                self.telemetry.record_milestone(&event);
                return Ok(event);
            }
            return Err(BlossomError::InvalidConfiguration(
                "two certificates assign different contents to one order position".to_string(),
            ));
        }
        let expected_position = self.last_finalized_position.checked_add(1).ok_or_else(|| {
            BlossomError::InvalidConfiguration("order position overflow".to_string())
        })?;
        if statement.position.position != expected_position
            || statement.previous_order_certificate_hash != self.last_order_certificate_hash
        {
            return Err(BlossomError::InvalidConfiguration(
                "order certificate does not extend the stable finality chain".to_string(),
            ));
        }
        if !self.available.contains_key(&statement.reference_hash) {
            return Err(BlossomError::InvalidConfiguration(
                "availability must be certified before finality".to_string(),
            ));
        }
        let available_reference = &self
            .available
            .get(&statement.reference_hash)
            .expect("checked above")
            .reference;
        if statement.consensus_group_id != available_reference.consensus_group_id
            || statement.validator_generation != available_reference.validator_generation
        {
            return Err(BlossomError::InvalidConfiguration(
                "order certificate scope does not match the available reference".to_string(),
            ));
        }
        self.ensure_origin_predecessor_finalized(available_reference)?;
        if let Some(existing) = self
            .final_reference_by_position
            .get(&statement.position.position)
            && *existing != statement.reference_hash
        {
            return Err(BlossomError::InvalidConfiguration(
                "two certificates assign different references to one order position".to_string(),
            ));
        }
        let certificate_hash = certificate.hash()?;
        let mut delta = OrderedStateDelta::new(self.durable_metadata());
        delta
            .finalized_upserts
            .push((statement.position.position, certificate.clone()));
        delta
            .position_upserts
            .push((statement.position.position, statement.reference_hash));
        delta.metadata.last_finalized_position = statement.position.position;
        delta.metadata.last_order_certificate_hash = certificate_hash;
        let event = milestone_event(
            self.mode,
            statement.reference_hash,
            Milestone::Finalized,
            Some(statement.position),
        );
        self.store
            .persist_ordered_delta(&delta, std::slice::from_ref(&event), None)?;
        let finalized_position = statement.position.position;
        let finalized_reference = statement.reference_hash;
        self.finalized.insert(finalized_position, certificate);
        self.final_reference_by_position
            .insert(finalized_position, finalized_reference);
        self.finalized_reference_hashes.insert(finalized_reference);
        self.last_finalized_position = finalized_position;
        self.last_order_certificate_hash = certificate_hash;
        self.telemetry.record_milestone(&event);
        Ok(event)
    }

    /// Applies every contiguous, locally available finalized reference.
    pub fn apply_contiguous_to<A: OrderedApplication>(
        &mut self,
        application: &mut A,
    ) -> Result<ApplyProgress> {
        let next_position = self.applied_watermark.position.saturating_add(1);
        let Some(certificate) = self.finalized.get(&next_position) else {
            return Ok(ApplyProgress::Applied {
                watermark: self.applied_watermark,
                completions: Vec::new(),
            });
        };
        let reference_hash = certificate.statement.reference_hash;
        let availability = self
            .available
            .get(&reference_hash)
            .expect("finality requires availability certificate");
        let Some(batch) = self.store.load_batch(&availability.reference)? else {
            if self.telemetry.is_enabled() {
                self.telemetry.record(
                    TelemetryEvent::new(
                        TelemetryEventKind::Event,
                        "apply",
                        "head_of_line_unavailable",
                    )
                    .with_outcome("blocked")
                    .with_field("watermark", self.applied_watermark.position.to_string())
                    .with_field("blocked_reference", reference_hash.to_string()),
                );
            }
            return Ok(ApplyProgress::HeadOfLineUnavailable {
                watermark: self.applied_watermark,
                blocked_reference: reference_hash,
            });
        };
        let next_watermark = certificate.statement.position;
        let command_count = batch.commands.len();
        let results = application.apply_ordered(&OrderedBatch {
            reference_hash,
            reference: availability.reference.clone(),
            batch,
            watermark: next_watermark,
        })?;
        let completion = AppliedCompletion {
            reference_hash,
            watermark: next_watermark,
            results,
        };
        completion.validate(Some(command_count))?;
        let mut delta = OrderedStateDelta::new(self.durable_metadata());
        delta.metadata.applied_watermark = next_watermark;
        delta.available_removals.push(reference_hash);
        let event = milestone_event(
            self.mode,
            reference_hash,
            Milestone::Applied,
            Some(next_watermark),
        );
        self.store.persist_ordered_delta(
            &delta,
            std::slice::from_ref(&event),
            Some(&completion),
        )?;
        self.applied_watermark = next_watermark;
        self.available.remove(&reference_hash);
        self.telemetry.record_milestone(&event);
        Ok(ApplyProgress::Applied {
            watermark: self.applied_watermark,
            completions: vec![completion],
        })
    }

    /// Applies contiguously through an exact target position.
    pub fn apply_through_to<A: OrderedApplication>(
        &mut self,
        target: Watermark,
        application: &mut A,
    ) -> Result<ApplyProgress> {
        let mut all_completions = Vec::new();
        while self.applied_watermark < target {
            match self.apply_contiguous_to(application)? {
                ApplyProgress::Applied {
                    watermark,
                    completions,
                } => {
                    if completions.is_empty() && watermark < target {
                        return Err(BlossomError::FailedConsensus);
                    }
                    all_completions.extend(completions);
                }
                blocked @ ApplyProgress::HeadOfLineUnavailable { .. } => return Ok(blocked),
            }
        }
        Ok(ApplyProgress::Applied {
            watermark: self.applied_watermark,
            completions: all_completions,
        })
    }

    /// Advances an embedding application to the watermark required by a read.
    ///
    /// After this method succeeds the caller can issue the actual read against
    /// its own state machine. A linearizable read requires a freshly certified
    /// Blossom order/read barrier supplied by the caller's consensus driver.
    /// Drives application progress required by a read-consistency policy.
    pub fn satisfy_read_consistency_to<A: OrderedApplication>(
        &mut self,
        consistency: ReadConsistency,
        linearizable_barrier: Option<&CertifiedReadBarrier>,
        application: &mut A,
    ) -> Result<Watermark> {
        let required = match consistency {
            ReadConsistency::Local => None,
            ReadConsistency::AtLeast(watermark) => Some(watermark),
            ReadConsistency::Linearizable => {
                let barrier = linearizable_barrier.ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "linearizable Blossom read requires a fresh certified read barrier"
                            .to_string(),
                    )
                })?;
                Some(self.acquire_read_barrier(barrier)?)
            }
        };
        if let Some(required) = required {
            match self.apply_through_to(required, application)? {
                ApplyProgress::Applied { watermark, .. } if watermark >= required => {}
                ApplyProgress::HeadOfLineUnavailable {
                    blocked_reference, ..
                } => {
                    return Err(BlossomError::InvalidConfiguration(format!(
                        "read blocked by unavailable reference {blocked_reference}"
                    )));
                }
                _ => return Err(BlossomError::FailedConsensus),
            }
        }
        Ok(self.applied_watermark)
    }

    /// Returns the highest durably applied position.
    pub fn applied_watermark(&self) -> Watermark {
        self.applied_watermark
    }

    /// Returns the active application routing generation.
    pub fn route_generation(&self) -> RouteGeneration {
        self.route_generation
    }

    /// Returns the active opaque command-schema generation.
    pub fn command_spec_version(&self) -> CommandSpecVersion {
        self.command_spec_version
    }

    /// Returns the indexed durable status of one reference.
    pub fn status(&self, reference_hash: HashType) -> Result<ReferenceStatus> {
        self.store.reference_status(reference_hash)
    }

    /// Waits up to `timeout` for one reference milestone.
    pub fn wait_for(
        &self,
        reference_hash: HashType,
        target: Milestone,
        timeout: Duration,
    ) -> Result<WaitForOutcome> {
        self.store.wait_for(reference_hash, target, timeout)
    }

    /// Completes a write according to its requested acknowledgement mode.
    ///
    /// The embedding consensus driver remains responsible for admission,
    /// availability, and finality. For [`WriteMode::GlobalApplied`], this
    /// method additionally drives contiguous application once finality is
    /// visible and does not return `Reached` until an [`AppliedCompletion`] is
    /// durable. Every mode observes the same bounded timeout contract as
    /// [`Self::wait_for`].
    /// Drives the application until the write policy is satisfied or times out.
    pub fn complete_write<A: OrderedApplication>(
        &mut self,
        reference_hash: HashType,
        mode: WriteMode,
        timeout: Duration,
        application: &mut A,
    ) -> Result<WaitForOutcome> {
        if mode != WriteMode::GlobalApplied {
            return self.wait_for(reference_hash, mode.required_milestone(), timeout);
        }
        if timeout > MAX_WAIT_FOR_TIMEOUT {
            return Err(BlossomError::InvalidConfiguration(format!(
                "wait timeout exceeds the {} second bound",
                MAX_WAIT_FOR_TIMEOUT.as_secs()
            )));
        }
        let started = Instant::now();
        loop {
            let status = self.status(reference_hash)?;
            if status.reached(Milestone::Applied) {
                return Ok(WaitForOutcome::Reached(status));
            }
            if let ReferenceStatus::Pending(event) = &status
                && event.milestone.reaches(Milestone::Finalized)
            {
                let target = event.watermark.ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "finalized reference is missing its order watermark".to_string(),
                    )
                })?;
                let _ = self.apply_through_to(target, application)?;
                let applied = self.status(reference_hash)?;
                if applied.reached(Milestone::Applied) {
                    return Ok(WaitForOutcome::Reached(applied));
                }
            }
            let status = self.status(reference_hash)?;
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

    /// Builds this validator's statement for a caller-issued freshness
    /// challenge. The statement is not a barrier until a quorum signs it.
    /// Builds the exact current-tail statement for a fresh read challenge.
    pub fn read_barrier_statement(
        &self,
        request: ReadBarrierRequest,
    ) -> Result<ReadBarrierStatement> {
        let (position, order_certificate_hash) = self.validated_local_order_tail()?;
        let (cluster_id, consensus_group_id) = self.store.protocol_scope()?.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "read barriers require a bound cluster and consensus-group scope".to_string(),
            )
        })?;
        Ok(ReadBarrierStatement {
            cluster_id,
            consensus_group_id,
            validator_generation: self.validator_generation,
            route_generation: self.route_generation,
            command_spec_version: self.command_spec_version,
            challenge: request.challenge,
            position,
            order_certificate_hash,
        })
    }

    /// Signs a fresh read-barrier request after validating the local tail.
    pub fn vote_for_read_barrier(&self, request: ReadBarrierRequest) -> Result<ReadBarrierVote> {
        if !self.validators.contains(&self.store.holder) {
            return Err(BlossomError::UnknownSender);
        }
        let statement = self.read_barrier_statement(request)?;
        self.store.sign_read_barrier_statement(&statement)
    }

    /// Validates a caller-challenge-bound quorum certificate and checks that
    /// the local finalized chain has caught up to exactly the certified tail.
    /// Verifies a quorum-certified fresh barrier against the local finalized tail.
    pub fn acquire_read_barrier(&self, barrier: &CertifiedReadBarrier) -> Result<Watermark> {
        barrier.certificate.verify(
            barrier.request.challenge,
            self.validator_generation,
            &self.validators,
        )?;
        let statement = &barrier.certificate.statement;
        let scope = self.store.protocol_scope()?.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "read barriers require a bound cluster and consensus-group scope".to_string(),
            )
        })?;
        if scope != (statement.cluster_id, statement.consensus_group_id)
            || statement.route_generation != self.route_generation
            || statement.command_spec_version != self.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "read-barrier scope or application contract does not match this engine".to_string(),
            ));
        }
        let local_tail = self.validated_local_order_tail()?;
        if local_tail != (statement.position, statement.order_certificate_hash) {
            return Err(BlossomError::InvalidConfiguration(
                "local finality chain has not caught up to the fresh consensus read barrier"
                    .to_string(),
            ));
        }
        Ok(statement.position)
    }

    fn validated_local_order_tail(&self) -> Result<(Watermark, HashType)> {
        if self.last_finalized_position == 0 {
            if self.last_order_certificate_hash != HashType::default() {
                return Err(BlossomError::InvalidConfiguration(
                    "empty finality chain has a non-empty tail hash".to_string(),
                ));
            }
            return Ok((Watermark::default(), HashType::default()));
        }
        let certificate = self
            .finalized
            .get(&self.last_finalized_position)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "current order head is missing its certificate".to_string(),
                )
            })?;
        if certificate.hash()? != self.last_order_certificate_hash {
            return Err(BlossomError::InvalidConfiguration(
                "current order head certificate does not match the durable tail".to_string(),
            ));
        }
        if self.order_trust_mode.is_trusted() {
            certificate.verify_trusted(self.validator_generation)?;
        } else {
            certificate.verify(self.validator_generation, &self.validators)?;
        }
        Ok((
            certificate.statement.position,
            self.last_order_certificate_hash,
        ))
    }

    fn ensure_origin_predecessor_finalized(&self, reference: &BatchReference) -> Result<()> {
        if reference.previous_origin_reference_hash != HashType::default()
            && !self
                .finalized_reference_hashes
                .contains(&reference.previous_origin_reference_hash)
        {
            return Err(BlossomError::InvalidConfiguration(
                "an origin reference cannot finalize before its hash-chain predecessor".to_string(),
            ));
        }
        Ok(())
    }

    fn durable_metadata(&self) -> DurableOrderedMetadata {
        DurableOrderedMetadata {
            version: DURABLE_ORDERED_STATE_VERSION,
            holder_membership_epoch: self.holder_membership.epoch,
            validator_generation: self.validator_generation,
            route_generation: self.route_generation,
            command_spec_version: self.command_spec_version,
            last_finalized_position: self.last_finalized_position,
            last_order_certificate_hash: self.last_order_certificate_hash,
            applied_watermark: self.applied_watermark,
        }
    }

    fn install_durable_state(&mut self, state: DurableOrderedState) {
        self.route_generation = state.route_generation;
        self.command_spec_version = state.command_spec_version;
        self.available = state.available;
        self.finalized = state.finalized;
        self.finalized_reference_hashes = state
            .final_reference_by_position
            .values()
            .copied()
            .collect();
        self.final_reference_by_position = state.final_reference_by_position;
        self.last_origin_reference = state.last_origin_reference;
        self.last_finalized_position = state.last_finalized_position;
        self.last_order_certificate_hash = state.last_order_certificate_hash;
        self.applied_watermark = state.applied_watermark;
    }

    fn validate_durable_state(&self, state: &DurableOrderedState) -> Result<()> {
        state.route_generation.validate()?;
        state.command_spec_version.validate()?;
        if state.version != DURABLE_ORDERED_STATE_VERSION
            || state.holder_membership_epoch != self.holder_membership.epoch
            || state.validator_generation != self.validator_generation
            || state.route_generation != self.route_generation
            || state.command_spec_version != self.command_spec_version
            || state.applied_watermark.position > state.last_finalized_position
        {
            return Err(BlossomError::InvalidConfiguration(
                "durable ordered-engine parameters do not match startup configuration".to_string(),
            ));
        }
        if state.finalized.len()
            != usize::try_from(state.last_finalized_position).unwrap_or(usize::MAX)
            || state.final_reference_by_position.len() != state.finalized.len()
        {
            return Err(BlossomError::InvalidConfiguration(
                "durable finality tables contain missing or out-of-range positions".to_string(),
            ));
        }
        for (reference_hash, availability) in &state.available {
            availability.verify(&self.holder_membership)?;
            if availability.reference.hash()? != *reference_hash
                || availability.reference.route_generation != state.route_generation
                || availability.reference.command_spec_version != state.command_spec_version
            {
                return Err(BlossomError::InvalidConfiguration(
                    "durable availability does not match its key or application contract"
                        .to_string(),
                ));
            }
            self.store.bind_protocol_scope(
                availability.reference.cluster_id,
                availability.reference.consensus_group_id,
            )?;
        }
        let mut previous_hash = HashType::default();
        for position in 1..=state.last_finalized_position {
            let certificate = state.finalized.get(&position).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "durable finality chain is not contiguous".to_string(),
                )
            })?;
            if self.order_trust_mode.is_trusted() {
                certificate.verify_trusted(self.validator_generation)?;
            } else {
                certificate.verify(self.validator_generation, &self.validators)?;
            }
            if certificate.statement.position.position != position
                || certificate.statement.previous_order_certificate_hash != previous_hash
                || state.final_reference_by_position.get(&position)
                    != Some(&certificate.statement.reference_hash)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "durable finality chain failed stable-prefix validation".to_string(),
                ));
            }
            previous_hash = certificate.hash()?;
            if position <= state.applied_watermark.position {
                let reference_hash = certificate.statement.reference_hash;
                match self.store.reference_status(reference_hash)? {
                    ReferenceStatus::Applied(completion)
                        if completion.reference_hash == reference_hash
                            && completion.watermark.position == position => {}
                    _ => {
                        return Err(BlossomError::InvalidConfiguration(
                            "durable applied watermark is missing an exact applied completion"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        if previous_hash != state.last_order_certificate_hash {
            return Err(BlossomError::InvalidConfiguration(
                "durable finality chain tail hash mismatch".to_string(),
            ));
        }
        Ok(())
    }
}
