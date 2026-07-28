//! Durable active-active benchmark cluster implementation.

use super::*;

impl BlossomActiveActiveCluster {
    pub async fn start(
        participant_count: usize,
        quorum_size: QuorumSize,
        storage_root: impl AsRef<Path>,
    ) -> Result<Self, BoxError> {
        let holders_per_site = participant_count / 3;
        Self::start_with_holders_per_site(
            participant_count,
            quorum_size,
            holders_per_site,
            storage_root,
        )
        .await
    }

    /// Starts a benchmark cluster with validator and holder populations kept
    /// separate.
    ///
    /// The default [`Self::start`] keeps every validator as a holder for the
    /// equal-footprint baseline. This constructor models a committed,
    /// fixed-size holder committee per site so trusted admission and
    /// availability work can remain bounded as validator membership grows.
    pub async fn start_with_holders_per_site(
        participant_count: usize,
        quorum_size: QuorumSize,
        holders_per_site: usize,
        storage_root: impl AsRef<Path>,
    ) -> Result<Self, BoxError> {
        if participant_count < 3 || !participant_count.is_multiple_of(3) {
            return Err(
                "active-active benchmark participants must form three equal non-empty sites".into(),
            );
        }
        let site_population = participant_count / 3;
        if holders_per_site == 0 || holders_per_site > site_population {
            return Err(format!(
                "holders per site must be in 1..={site_population}, got {holders_per_site}"
            )
            .into());
        }
        std::fs::create_dir_all(storage_root.as_ref())?;
        let order_cluster = BlossomTcpOrderCluster::start(participant_count, quorum_size).await?;
        let membership_epoch = ReplicaMembershipEpoch(1);
        let validator_generation = ValidatorGeneration(1);
        let mut stores = Vec::with_capacity(participant_count);
        let mut members_by_site = BTreeMap::<SiteId, BTreeSet<_>>::new();
        let mut holder_indices_by_site = BTreeMap::<SiteId, Vec<usize>>::new();
        let mut store_generations = BTreeMap::new();
        for (index, node) in order_cluster.cluster.nodes().iter().enumerate() {
            let site = SiteId::new(format!("site-{}", index % 3))?;
            let store_generation = StoreGeneration(1);
            let store = DurableAdmissionStore::open(
                storage_root.as_ref().join(format!("validator-{index}")),
                site.clone(),
                store_generation,
                node.keypair.signer(),
            )?;
            let site_holder_indices = holder_indices_by_site.entry(site.clone()).or_default();
            if site_holder_indices.len() < holders_per_site {
                site_holder_indices.push(index);
                members_by_site
                    .entry(site.clone())
                    .or_default()
                    .insert(node.keypair.public);
                store_generations.insert(node.keypair.public, store_generation);
            }
            stores.push(store);
        }
        let holder_membership = HolderMembership {
            epoch: membership_epoch,
            members_by_site,
            store_generations,
            holder_fault_bound: 0,
        };
        let validators = order_cluster
            .cluster
            .nodes()
            .iter()
            .map(|node| node.keypair.public)
            .collect::<BTreeSet<_>>();
        let engine = GlobalOrderedEngine::new_with_application_contract(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership,
            validator_generation,
            validators,
            TrustMode::Trusted,
            RouteGeneration(1),
            CommandSpecVersion(1),
        )?;
        Ok(Self {
            order_cluster,
            stores,
            holder_indices_by_site,
            engine,
            application: SharedStateMachine::new(4096)?,
            membership_epoch,
            validator_generation,
            next_origin_sequences: vec![1; participant_count],
            previous_origin_reference_hashes: vec![HashType::default(); participant_count],
        })
    }

    pub async fn client_write(
        &mut self,
        command: ActiveActiveCommand,
    ) -> Result<BlossomAppliedSample, BoxError> {
        let started = Instant::now();
        let phase_started = Instant::now();
        command.validate()?;
        let admitted = AdmittedCommand {
            origin_sequence: self.next_origin_sequences[0],
            command,
        };
        let command_hash = admitted.command.hash()?;
        let command_prepare_nanos = elapsed_nanos(phase_started);

        let phase_started = Instant::now();
        let (origin_site, origin_indices) = self
            .holder_indices_by_site
            .first_key_value()
            .ok_or("active-active benchmark has no holder sites")?;
        let origin_site = origin_site.clone();
        let origin_indices = origin_indices.clone();
        let admission_member_keys = origin_indices
            .iter()
            .map(|index| self.order_cluster.cluster.node(*index).keypair.public)
            .collect::<BTreeSet<_>>();
        let admission_store_generations = admission_member_keys
            .iter()
            .map(|member| (*member, StoreGeneration(1)))
            .collect::<BTreeMap<_, _>>();
        let origin_site_members = origin_indices.len();
        let required_admission_receipts = supermajority_count(origin_indices.len());
        let mut admission_tasks = JoinSet::new();
        for index in origin_indices.into_iter().take(required_admission_receipts) {
            let store = self.stores[index].clone();
            let admitted = admitted.clone();
            let membership_epoch = self.membership_epoch;
            admission_tasks.spawn_blocking(move || store.admit(&admitted, membership_epoch));
        }
        let mut admission_receipts = Vec::new();
        while let Some(receipt) = admission_tasks.join_next().await {
            admission_receipts.push(receipt??);
        }
        admission_receipts.sort_by_key(|receipt| receipt.body.holder);
        let admission_replication_nanos = elapsed_nanos(phase_started);
        let admission_receipt_count = admission_receipts.len();
        let phase_started = Instant::now();
        let admission_policy = LocalAdmissionPolicy {
            site: origin_site,
            membership_epoch: self.membership_epoch,
            members: admission_member_keys,
            store_generations: admission_store_generations,
        };
        self.engine.accept_local(&LocalAdmissionCertificate {
            policy: admission_policy,
            command_identity: admitted.command.identity,
            command_hash,
            origin_sequence: admitted.origin_sequence,
            receipts: admission_receipts,
        })?;
        let accepted_transition_nanos = elapsed_nanos(phase_started);
        let accepted_local_nanos = elapsed_nanos(started);

        let phase_started = Instant::now();
        let batch = CommandBatch {
            commands: vec![admitted],
        };
        let reference = BatchReference::for_batch(
            &batch,
            BatchReferenceMetadata {
                cluster_id: HashType([0x42; 32]),
                consensus_group_id: ConsensusGroupId::root(),
                shard: b"benchmark-shard".to_vec(),
                route_generation: RouteGeneration(1),
                command_spec_version: CommandSpecVersion(1),
                origin: self.order_cluster.cluster.node(0).keypair.public,
                origin_incarnation: 1,
                origin_key_generation: 1,
                data_holder_membership_epoch: self.membership_epoch,
                validator_generation: self.validator_generation,
                previous_origin_reference_hash: self.previous_origin_reference_hashes[0],
            },
        )?;
        let reference_hash = reference.hash()?;
        let reference_build_nanos = elapsed_nanos(phase_started);

        let phase_started = Instant::now();
        let availability_indices = self
            .holder_indices_by_site
            .values()
            .take(2)
            .flat_map(|indices| {
                indices
                    .iter()
                    .copied()
                    .take(supermajority_count(indices.len()))
            })
            .collect::<Vec<_>>();
        let availability_sites = 2;
        let mut availability_tasks = JoinSet::new();
        for index in availability_indices {
            let store = self.stores[index].clone();
            let reference = reference.clone();
            let batch = batch.clone();
            availability_tasks.spawn_blocking(move || store.store_batch(&reference, &batch));
        }
        let mut availability_receipts = Vec::new();
        while let Some(receipt) = availability_tasks.join_next().await {
            availability_receipts.push(receipt??);
        }
        availability_receipts.sort_by_key(|receipt| receipt.body.holder);
        let availability_replication_nanos = elapsed_nanos(phase_started);
        let availability_receipt_count = availability_receipts.len();
        let phase_started = Instant::now();
        self.engine.mark_available(AvailabilityCertificate {
            reference: reference.clone(),
            trust: AvailabilityTrust::Trusted,
            receipts: availability_receipts,
        })?;
        let available_transition_nanos = elapsed_nanos(phase_started);
        let available_nanos = elapsed_nanos(started);

        let (epoch, mut finality, finalized_node_indexes) =
            self.order_cluster.finalize_reference(&reference).await?;
        let block_submission_nanos = finality.blocks_submitted_nanos;
        let target_resolution_nanos = finality.target_resolution_nanos;
        let receipt_and_order_nanos = finality
            .finalized_nanos
            .saturating_sub(finality.blocks_submitted_nanos);
        let finalized_node_count = finalized_node_indexes.len();
        let finalized_returned = Instant::now();
        let phase_started = Instant::now();
        let statement = self
            .engine
            .order_statement_for_trusted_finalized_epoch(&epoch)?;
        let order_statement_nanos = elapsed_nanos(phase_started);
        let order_vote_nanos = 0;
        let order_vote_count = 0;
        let phase_started = Instant::now();
        self.engine.finalize_trusted(statement)?;
        let finalized_transition_nanos = elapsed_nanos(phase_started);
        let finalized_nanos = elapsed_nanos(started);

        let phase_started = Instant::now();
        let (watermark, result) = match self.engine.apply_contiguous_to(&mut self.application)? {
            ApplyProgress::Applied {
                watermark,
                completions,
            } => {
                let [completion] = completions.as_slice() else {
                    return Err(
                        "one-command Blossom benchmark batch produced an invalid result count"
                            .into(),
                    );
                };
                let [result] = completion.results.as_slice() else {
                    return Err(
                        "one-command Blossom benchmark completion produced an invalid result count"
                            .into(),
                    );
                };
                (watermark, decode_result(result)?)
            }
            ApplyProgress::HeadOfLineUnavailable { .. } => {
                return Err("availability-certified benchmark batch became unavailable".into());
            }
        };
        let apply_nanos = elapsed_nanos(phase_started);
        let applied_nanos = elapsed_nanos(started);
        let phase_started = Instant::now();
        self.order_cluster
            .wait_for_converged_epoch(finality.nonce, finality.epoch_hash)
            .await?;
        let convergence_nanos = elapsed_nanos(phase_started);
        finality.converged_nanos = Some(
            finality
                .finalized_nanos
                .saturating_add(elapsed_nanos(finalized_returned)),
        );
        finality.converged_nodes = self.order_cluster.participant_count();
        let converged_nanos = elapsed_nanos(started);
        self.previous_origin_reference_hashes[0] = reference_hash;
        self.next_origin_sequences[0] = self.next_origin_sequences[0]
            .checked_add(1)
            .ok_or("Blossom benchmark origin sequence overflow")?;
        let immediate_durable_commits = admission_receipt_count
            .saturating_add(1)
            .saturating_add(availability_receipt_count)
            .saturating_add(1)
            .saturating_add(order_vote_count)
            .saturating_add(1)
            .saturating_add(1);
        Ok(BlossomAppliedSample {
            accepted_local_nanos,
            available_nanos,
            finalized_nanos,
            applied_nanos,
            converged_nanos,
            watermark,
            result,
            finality,
            trusted_path: BlossomTrustedPathSample {
                command_prepare_nanos,
                admission_replication_nanos,
                accepted_transition_nanos,
                reference_build_nanos,
                availability_replication_nanos,
                available_transition_nanos,
                target_resolution_nanos,
                block_submission_nanos,
                receipt_and_order_nanos,
                order_statement_nanos,
                order_vote_nanos,
                finalized_transition_nanos,
                apply_nanos,
                convergence_nanos,
                origin_site_members,
                admission_receipts: admission_receipt_count,
                availability_sites,
                availability_receipts: availability_receipt_count,
                validator_block_submissions: self.order_cluster.participant_count(),
                hierarchy_rounds: usize::from(self.order_cluster.max_round) + 1,
                finalized_nodes: finalized_node_count,
                order_votes: order_vote_count,
                immediate_durable_commits,
            },
        })
    }

    pub fn read_local(&mut self, key: &[u8]) -> blossom::Result<Option<Vec<u8>>> {
        self.engine.satisfy_read_consistency_to(
            blossom::ReadConsistency::Local,
            None,
            &mut self.application,
        )?;
        Ok(self.application.get(key).map(<[u8]>::to_vec))
    }

    /// Runs one trusted universal-writer epoch through `Applied`.
    ///
    /// Each command has an independent origin node and is placed in that
    /// node's block. Admission and availability replication run concurrently;
    /// the epoch's BTree block-hash order determines application order.
    pub async fn client_write_universal(
        &mut self,
        commands: Vec<ActiveActiveCommand>,
    ) -> Result<BlossomUniversalWriterSample, BoxError> {
        let active_writers = commands.len();
        if active_writers == 0 || active_writers > self.order_cluster.participant_count() {
            return Err(format!(
                "active writer count must be in 1..={}, got {active_writers}",
                self.order_cluster.participant_count()
            )
            .into());
        }
        let started = Instant::now();
        let phase_started = Instant::now();
        let mut admitted_commands = Vec::with_capacity(active_writers);
        let mut command_hashes = Vec::with_capacity(active_writers);
        for (writer, command) in commands.into_iter().enumerate() {
            command.validate()?;
            let admitted = AdmittedCommand {
                origin_sequence: self.next_origin_sequences[writer],
                command,
            };
            command_hashes.push(admitted.command.hash()?);
            admitted_commands.push(admitted);
        }
        let command_prepare_nanos = elapsed_nanos(phase_started);

        let holder_sites = self
            .holder_indices_by_site
            .iter()
            .map(|(site, indices)| (site.clone(), indices.clone()))
            .collect::<Vec<_>>();
        let phase_started = Instant::now();
        let mut admission_contexts = Vec::with_capacity(active_writers);
        let mut admission_tasks = JoinSet::new();
        for writer in 0..active_writers {
            let (site, origin_indices) = &holder_sites[writer % holder_sites.len()];
            let member_keys = origin_indices
                .iter()
                .map(|index| self.order_cluster.cluster.node(*index).keypair.public)
                .collect::<BTreeSet<_>>();
            let store_generations = member_keys
                .iter()
                .map(|member| (*member, StoreGeneration(1)))
                .collect::<BTreeMap<_, _>>();
            let required = supermajority_count(origin_indices.len());
            for index in origin_indices.iter().copied().take(required) {
                let store = self.stores[index].clone();
                let admitted = admitted_commands[writer].clone();
                let membership_epoch = self.membership_epoch;
                admission_tasks.spawn_blocking(move || {
                    store
                        .admit(&admitted, membership_epoch)
                        .map(|receipt| (writer, receipt))
                });
            }
            admission_contexts.push((
                site.clone(),
                origin_indices.len(),
                member_keys,
                store_generations,
            ));
        }
        let mut admission_receipts = vec![Vec::<blossom::AdmissionReceipt>::new(); active_writers];
        while let Some(receipt) = admission_tasks.join_next().await {
            let (writer, receipt) = receipt??;
            admission_receipts[writer].push(receipt);
        }
        for receipts in &mut admission_receipts {
            receipts.sort_by_key(|receipt| receipt.body.holder);
        }
        let admission_replication_nanos = elapsed_nanos(phase_started);
        let admission_receipt_count = admission_receipts.iter().map(Vec::len).sum::<usize>();
        let origin_site_members = admission_contexts
            .iter()
            .map(|(_, member_count, _, _)| member_count)
            .sum();
        let phase_started = Instant::now();
        for writer in 0..active_writers {
            let (site, _, members, store_generations) = &admission_contexts[writer];
            self.engine.accept_local(&LocalAdmissionCertificate {
                policy: LocalAdmissionPolicy {
                    site: site.clone(),
                    membership_epoch: self.membership_epoch,
                    members: members.clone(),
                    store_generations: store_generations.clone(),
                },
                command_identity: admitted_commands[writer].command.identity,
                command_hash: command_hashes[writer],
                origin_sequence: admitted_commands[writer].origin_sequence,
                receipts: std::mem::take(&mut admission_receipts[writer]),
            })?;
        }
        let accepted_transition_nanos = elapsed_nanos(phase_started);
        let accepted_local_nanos = elapsed_nanos(started);

        let phase_started = Instant::now();
        let mut batches = Vec::with_capacity(active_writers);
        let mut references = Vec::with_capacity(active_writers);
        for (writer, admitted) in admitted_commands.iter().cloned().enumerate() {
            let batch = CommandBatch {
                commands: vec![admitted],
            };
            let reference = BatchReference::for_batch(
                &batch,
                BatchReferenceMetadata {
                    cluster_id: HashType([0x42; 32]),
                    consensus_group_id: ConsensusGroupId::root(),
                    shard: b"benchmark-shard".to_vec(),
                    route_generation: RouteGeneration(1),
                    command_spec_version: CommandSpecVersion(1),
                    origin: self.order_cluster.cluster.node(writer).keypair.public,
                    origin_incarnation: 1,
                    origin_key_generation: 1,
                    data_holder_membership_epoch: self.membership_epoch,
                    validator_generation: self.validator_generation,
                    previous_origin_reference_hash: self.previous_origin_reference_hashes[writer],
                },
            )?;
            batches.push(batch);
            references.push(reference);
        }
        let reference_build_nanos = elapsed_nanos(phase_started);

        let availability_indices = self
            .holder_indices_by_site
            .values()
            .take(2)
            .flat_map(|indices| {
                indices
                    .iter()
                    .copied()
                    .take(supermajority_count(indices.len()))
            })
            .collect::<Vec<_>>();
        let availability_sites = 2;
        let phase_started = Instant::now();
        let mut availability_tasks = JoinSet::new();
        for writer in 0..active_writers {
            for index in &availability_indices {
                let store = self.stores[*index].clone();
                let reference = references[writer].clone();
                let batch = batches[writer].clone();
                availability_tasks.spawn_blocking(move || {
                    store
                        .store_batch(&reference, &batch)
                        .map(|receipt| (writer, receipt))
                });
            }
        }
        let mut availability_receipts =
            vec![Vec::<blossom::AuthenticatedAvailabilityReceipt>::new(); active_writers];
        while let Some(receipt) = availability_tasks.join_next().await {
            let (writer, receipt) = receipt??;
            availability_receipts[writer].push(receipt);
        }
        for receipts in &mut availability_receipts {
            receipts.sort_by_key(|receipt| receipt.body.holder);
        }
        let availability_replication_nanos = elapsed_nanos(phase_started);
        let availability_receipt_count = availability_receipts.iter().map(Vec::len).sum::<usize>();
        let phase_started = Instant::now();
        for writer in 0..active_writers {
            self.engine.mark_available(AvailabilityCertificate {
                reference: references[writer].clone(),
                trust: AvailabilityTrust::Trusted,
                receipts: std::mem::take(&mut availability_receipts[writer]),
            })?;
        }
        let available_transition_nanos = elapsed_nanos(phase_started);
        let available_nanos = elapsed_nanos(started);

        let previous_watermark = self.engine.applied_watermark();
        let (epoch, mut finality, finalized_node_indexes) =
            self.order_cluster.finalize_references(&references).await?;
        let target_resolution_nanos = finality.target_resolution_nanos;
        let block_submission_nanos = finality.blocks_submitted_nanos;
        let receipt_and_order_nanos = finality
            .finalized_nanos
            .saturating_sub(finality.blocks_submitted_nanos);
        let finalized_node_count = finalized_node_indexes.len();
        let finalized_returned = Instant::now();
        let phase_started = Instant::now();
        let events = self.engine.finalize_trusted_epoch(&epoch)?;
        if events.len() != active_writers {
            return Err("trusted epoch did not finalize every active writer reference".into());
        }
        let finalized_transition_nanos = elapsed_nanos(phase_started);
        let order_statement_nanos = 0;
        let order_vote_nanos = 0;
        let order_vote_count = 0;
        let finalized_nanos = elapsed_nanos(started);

        let first_watermark = Watermark {
            position: previous_watermark
                .position
                .checked_add(1)
                .ok_or("Blossom benchmark watermark overflow")?,
        };
        let last_watermark = Watermark {
            position: previous_watermark
                .position
                .checked_add(u64::try_from(active_writers)?)
                .ok_or("Blossom benchmark watermark overflow")?,
        };
        let phase_started = Instant::now();
        let completions = match self
            .engine
            .apply_through_to(last_watermark, &mut self.application)?
        {
            ApplyProgress::Applied {
                watermark,
                completions,
            } if watermark == last_watermark => completions,
            ApplyProgress::Applied { .. } => {
                return Err("trusted universal-writer epoch stopped before its watermark".into());
            }
            ApplyProgress::HeadOfLineUnavailable { .. } => {
                return Err("availability-certified benchmark batch became unavailable".into());
            }
        };
        let results = completions
            .iter()
            .flat_map(|completion| completion.results.iter())
            .map(decode_result)
            .collect::<Result<Vec<_>, _>>()?;
        if results.len() != active_writers {
            return Err("trusted universal-writer epoch produced an invalid result count".into());
        }
        let apply_nanos = elapsed_nanos(phase_started);
        let applied_nanos = elapsed_nanos(started);

        let phase_started = Instant::now();
        self.order_cluster
            .wait_for_converged_epoch(finality.nonce, finality.epoch_hash)
            .await?;
        let convergence_nanos = elapsed_nanos(phase_started);
        finality.converged_nanos = Some(
            finality
                .finalized_nanos
                .saturating_add(elapsed_nanos(finalized_returned)),
        );
        finality.converged_nodes = self.order_cluster.participant_count();
        let converged_nanos = elapsed_nanos(started);

        for (writer, reference) in references.iter().enumerate() {
            self.previous_origin_reference_hashes[writer] = reference.hash()?;
            self.next_origin_sequences[writer] = self.next_origin_sequences[writer]
                .checked_add(1)
                .ok_or("Blossom benchmark origin sequence overflow")?;
        }
        let immediate_durable_commits = admission_receipt_count
            .saturating_add(availability_receipt_count)
            .saturating_add(active_writers.saturating_mul(4));
        Ok(BlossomUniversalWriterSample {
            active_writers,
            accepted_local_nanos,
            available_nanos,
            finalized_nanos,
            applied_nanos,
            converged_nanos,
            first_watermark,
            last_watermark,
            results,
            finality,
            trusted_path: BlossomTrustedPathSample {
                command_prepare_nanos,
                admission_replication_nanos,
                accepted_transition_nanos,
                reference_build_nanos,
                availability_replication_nanos,
                available_transition_nanos,
                target_resolution_nanos,
                block_submission_nanos,
                receipt_and_order_nanos,
                order_statement_nanos,
                order_vote_nanos,
                finalized_transition_nanos,
                apply_nanos,
                convergence_nanos,
                origin_site_members,
                admission_receipts: admission_receipt_count,
                availability_sites,
                availability_receipts: availability_receipt_count,
                validator_block_submissions: self.order_cluster.participant_count(),
                hierarchy_rounds: usize::from(self.order_cluster.max_round) + 1,
                finalized_nodes: finalized_node_count,
                order_votes: order_vote_count,
                immediate_durable_commits,
            },
        })
    }
}
