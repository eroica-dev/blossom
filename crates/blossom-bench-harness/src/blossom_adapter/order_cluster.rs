//! Global Blossom TCP ordering cluster implementation.

use super::*;

impl BlossomTcpOrderCluster {
    pub async fn start(
        participant_count: usize,
        quorum_size: QuorumSize,
    ) -> Result<Self, BoxError> {
        let (_, rounds) = find_round_number_with_size(participant_count, quorum_size);
        let max_round = u8::try_from(rounds.saturating_sub(1))
            .map_err(|_| "Blossom topology requires more than 256 consensus rounds")?;
        Self::start_with_options(
            participant_count,
            quorum_size,
            TrustMode::Trusted,
            ConsensusDriverConfig {
                interval: Duration::from_millis(5),
                event_driven: true,
                max_round,
                drive_prefill: false,
                require_local_pending_block: true,
                continue_after_error: true,
                ..ConsensusDriverConfig::default()
            },
            Duration::from_secs(30),
        )
        .await
    }

    pub async fn start_with_options(
        participant_count: usize,
        quorum_size: QuorumSize,
        trust_mode: TrustMode,
        driver: ConsensusDriverConfig,
        finality_timeout: Duration,
    ) -> Result<Self, BoxError> {
        if finality_timeout.is_zero() {
            return Err("Blossom finality timeout must be non-zero".into());
        }
        let max_round = driver.max_round;
        let cluster = SimulatedCluster::spawn_manual_with_trust_mode_and_quorum(
            participant_count,
            trust_mode,
            quorum_size,
        )
        .await?;
        let drivers = cluster
            .nodes()
            .iter()
            .map(|node| {
                let services = if trust_mode == TrustMode::Verified {
                    TcpServiceClient::with_max_connections(verified_simulation_max_connections(
                        participant_count,
                    ))
                } else {
                    node.client()
                };
                TcpNode::with_services(node.runtime.clone(), services)
            })
            .collect();
        Ok(Self {
            cluster,
            drivers,
            driver,
            finality_timeout,
            trust_mode,
            max_round,
        })
    }

    pub fn participant_count(&self) -> usize {
        self.cluster.len()
    }

    pub fn traffic(&self) -> Vec<BlossomNodeTraffic> {
        self.cluster
            .node_metrics()
            .into_iter()
            .map(BlossomNodeTraffic::from)
            .collect()
    }

    /// Finalizes exactly one compact active-active batch reference.
    ///
    /// Callers are responsible for obtaining and validating the availability
    /// certificate before invoking this ordering-only operation.
    pub async fn finalize_reference(
        &self,
        reference: &BatchReference,
    ) -> Result<(Epoch, BlossomFinalitySample, Vec<usize>), BoxError> {
        self.finalize_references(std::slice::from_ref(reference))
            .await
    }

    /// Finalizes one compact reference from each active writer in the same
    /// epoch. Every member still sends exactly one block; idle members send an
    /// empty block. Trusted blocks and receipts are unsigned.
    pub async fn finalize_references(
        &self,
        references: &[BatchReference],
    ) -> Result<(Epoch, BlossomFinalitySample, Vec<usize>), BoxError> {
        if references.is_empty() || references.len() > self.cluster.len() {
            return Err(format!(
                "active writer count must be in 1..={}, got {}",
                self.cluster.len(),
                references.len()
            )
            .into());
        }
        for reference in references {
            reference.validate()?;
        }
        let member_transactions = references
            .iter()
            .map(|reference| Ok(vec![reference.to_transaction()?]))
            .collect::<Result<Vec<_>, blossom::BlossomError>>()?;
        let (epoch, mut sample, finalized_node_indexes) =
            self.finalize_transactions(&member_transactions).await?;

        let ordered_references = match self.trust_mode {
            TrustMode::Verified => ordered_batch_references(&epoch),
            TrustMode::Trusted => ordered_batch_references_trusted(&epoch),
            TrustMode::HighAvailability => {
                return Err(
                    "use the fixed-slot HA benchmark adapter for high-availability mode".into(),
                );
            }
        }?;
        let expected_reference_hashes = references
            .iter()
            .map(BatchReference::hash)
            .collect::<Result<BTreeSet<_>, _>>()?;
        if expected_reference_hashes.len() != references.len() {
            return Err("active writers submitted duplicate batch references".into());
        }
        let observed_reference_hashes = ordered_references
            .iter()
            .map(BatchReference::hash)
            .collect::<Result<Vec<_>, _>>()?;
        if observed_reference_hashes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            != expected_reference_hashes
            || observed_reference_hashes.len() != references.len()
        {
            return Err(
                "finalized Blossom epoch did not contain the submitted reference set".into(),
            );
        }
        sample.reference_hash = *observed_reference_hashes
            .first()
            .ok_or("finalized Blossom epoch contained no active-writer references")?;
        sample.reference_hashes = observed_reference_hashes;
        Ok((epoch, sample, finalized_node_indexes))
    }

    /// Orders opaque application transactions directly in one trusted epoch.
    ///
    /// Each outer vector is the one block emitted by that member. Missing tail
    /// members emit an empty block, preserving the fixed membership barrier.
    pub async fn finalize_transactions(
        &self,
        member_transactions: &[Vec<Transaction>],
    ) -> Result<(Epoch, BlossomFinalitySample, Vec<usize>), BoxError> {
        if self.cluster.is_empty() {
            return Err("Blossom benchmark cluster contains no participants".into());
        }
        if member_transactions.len() > self.cluster.len() {
            return Err(format!(
                "member transaction sets must not exceed {}, got {}",
                self.cluster.len(),
                member_transactions.len()
            )
            .into());
        }
        let traffic_before = self.traffic();
        let target_started = Instant::now();
        let target = self.synchronized_next_epoch_target().await?;
        let target_resolution_nanos = elapsed_nanos(target_started);
        let dispatch_before_submission = self
            .cluster
            .nodes()
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let round = node.runtime.current_consensus_round()?;
                Ok::<_, blossom::BlossomError>((
                    index,
                    round,
                    node.runtime.consensus_round_status(round)?.dispatch_status,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if dispatch_before_submission
            .iter()
            .any(|(_, _, status)| status.is_some())
        {
            return Err(format!(
                "Blossom produced a dispatch before the application admission barrier; \
                 statuses: {dispatch_before_submission:?}"
            )
            .into());
        }
        let started = Instant::now();
        let mut submissions = JoinSet::new();
        for index in 0..self.cluster.len() {
            let transactions = member_transactions.get(index).cloned().unwrap_or_default();
            let mut block = Block::default();
            block.body.last_epoch = target.last_epoch;
            block.body.nonce = target.nonce;
            block.body.txs.extend(transactions);
            match self.trust_mode {
                TrustMode::Trusted => {
                    block.seal_unsigned(self.cluster.node(index).keypair.public);
                }
                TrustMode::Verified => {
                    block.sign_with(&self.cluster.node(index).keypair.signer());
                }
                TrustMode::HighAvailability => {
                    return Err(
                        "use the fixed-slot HA benchmark adapter for high-availability mode".into(),
                    );
                }
            }
            let (client, service) = self.cluster.request_handle(index);
            submissions.spawn(async move {
                let accepted = match client
                    .request(&service, &WireRequest::SubmitBlock(block))
                    .await?
                {
                    WireResponse::BlockAccepted(accepted) => Ok(accepted),
                    WireResponse::Error(message) => {
                        Err(blossom::BlossomError::ExternalService(message))
                    }
                    response => Err(blossom::BlossomError::WireProtocol(format!(
                        "expected block accepted, got {}",
                        response.kind()
                    ))),
                }?;
                Ok::<_, blossom::BlossomError>((index, accepted))
            });
        }

        let mut accepted_blocks = BTreeMap::new();
        while let Some(result) = submissions.join_next().await {
            let (index, accepted) = result??;
            if accepted.nonce != target.nonce {
                return Err("Blossom accepted a block for the wrong epoch".into());
            }
            accepted_blocks.insert(index, accepted.hash);
        }
        if accepted_blocks.len() != self.cluster.len() {
            return Err("Blossom did not acknowledge one block from every member".into());
        }
        let pending_after_submission = self
            .cluster
            .nodes()
            .iter()
            .enumerate()
            .map(|(index, node)| {
                (
                    index,
                    node.runtime.status().map(|status| status.pending_blocks),
                )
            })
            .collect::<Vec<_>>();
        if pending_after_submission
            .iter()
            .any(|(_, pending)| !matches!(pending, Ok(1)))
        {
            return Err(format!(
                "Blossom admission barrier did not retain exactly one local block per member; \
                 pending: {pending_after_submission:?}"
            )
            .into());
        }
        let blocks_submitted_nanos = elapsed_nanos(started);
        let (epoch, finalized_node_indexes) = self.wait_for_finalized_epoch(target.nonce).await?;
        let expected_blocks = accepted_blocks.values().copied().collect::<BTreeSet<_>>();
        let finalized_blocks = epoch.body.blocks.keys().copied().collect::<BTreeSet<_>>();
        if finalized_blocks != expected_blocks {
            let expected_summary = accepted_blocks
                .iter()
                .map(|(index, hash)| (*index, self.cluster.node(*index).keypair.public, *hash))
                .collect::<Vec<_>>();
            let finalized_summary = epoch
                .body
                .ordered_blocks()
                .into_iter()
                .map(|(hash, block)| (*hash, block.body.validator, block.body.txs.len()))
                .collect::<Vec<_>>();
            return Err(format!(
                "finalized Blossom epoch did not contain the exact accepted member block set; \
                 expected: {expected_summary:?}; finalized: {finalized_summary:?}"
            )
            .into());
        }
        let sample = BlossomFinalitySample {
            nonce: target.nonce,
            epoch_hash: epoch.hash,
            target_resolution_nanos,
            blocks_submitted_nanos,
            finalized_nanos: elapsed_nanos(started),
            finalized_nodes: finalized_node_indexes.len(),
            converged_nanos: None,
            converged_nodes: 0,
            finalized_block_count: epoch.body.blocks.len(),
            reference_hash: HashType::default(),
            reference_hashes: Vec::new(),
            node_traffic: traffic_delta(&traffic_before, &self.traffic()),
        };
        Ok((epoch, sample, finalized_node_indexes))
    }

    async fn synchronized_next_epoch_target(&self) -> Result<blossom::EpochTarget, BoxError> {
        let deadline = Instant::now() + self.finality_timeout;
        let mut last_drive_errors = BTreeMap::<usize, String>::new();
        loop {
            let targets = self
                .cluster
                .nodes()
                .iter()
                .map(|node| node.runtime.next_epoch_target())
                .collect::<Result<Vec<_>, _>>()?;
            let maximum_nonce = targets
                .iter()
                .map(|target| target.nonce)
                .max()
                .ok_or("Blossom benchmark cluster contains no participants")?;
            let mut maximum_targets = targets
                .iter()
                .filter(|target| target.nonce == maximum_nonce);
            let expected = maximum_targets
                .next()
                .expect("the maximum nonce came from one target")
                .clone();
            if maximum_targets.any(|target| target != &expected) {
                return Err("Blossom nodes advertised conflicting next epoch targets".into());
            }
            if targets.iter().all(|target| target == &expected) {
                return Ok(expected);
            }

            let mut drives = JoinSet::new();
            for (index, node) in self.drivers.iter().enumerate() {
                let node = node.clone();
                drives.spawn(async move { (index, node.drive_epoch_dissemination_once().await) });
            }
            while let Some(result) = drives.join_next().await {
                match result {
                    Ok((index, Ok(_))) => {
                        last_drive_errors.remove(&index);
                    }
                    Ok((index, Err(error))) if self.driver.continue_after_error => {
                        last_drive_errors.insert(index, error.to_string());
                    }
                    Ok((_index, Err(error))) => return Err(error.into()),
                    Err(error) => {
                        return Err(
                            format!("epoch-target synchronization task failed: {error}").into()
                        );
                    }
                }
            }
            if Instant::now() >= deadline {
                let diagnostics = self
                    .cluster
                    .nodes()
                    .iter()
                    .enumerate()
                    .map(|(index, node)| {
                        (
                            index,
                            node.runtime.next_epoch_target(),
                            node.runtime
                                .epoch_started_catch_up_services()
                                .map(|services| services.len()),
                            node.runtime.epoch_dissemination_status(),
                            last_drive_errors.get(&index).cloned(),
                        )
                    })
                    .collect::<Vec<_>>();
                return Err(format!(
                    "Blossom nodes did not synchronize next epoch target {maximum_nonce} before timeout; \
                     targets: {targets:?}; diagnostics: {diagnostics:?}"
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_finalized_epoch(
        &self,
        nonce: Nonce,
    ) -> Result<(Epoch, Vec<usize>), BoxError> {
        if self.trust_mode.is_trusted() {
            let mut deadline = Instant::now() + self.finality_timeout;
            let mut last_progress = self.consensus_progress()?;
            loop {
                if let Some(epoch) = self
                    .cluster
                    .node(0)
                    .runtime
                    .epochchain()
                    .epochchain
                    .into_iter()
                    .find(|epoch| epoch.body.nonce == nonce)
                {
                    return Ok((epoch, vec![0]));
                }
                let drive_errors = self.drive_cluster_once(nonce).await?;
                let progress = self.consensus_progress()?;
                if progress != last_progress {
                    last_progress = progress;
                    deadline = Instant::now() + self.finality_timeout;
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "timed out waiting for local epoch {nonce} commit; trusted progress: \
                         {last_progress:?}; last drive errors: {drive_errors:?}"
                    )
                    .into());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let mut deadline = Instant::now() + self.finality_timeout;
        let mut last_consensus_progress = self.consensus_progress()?;
        let required = supermajority_count(self.cluster.len());
        let mut last_drive_errors;
        loop {
            last_drive_errors = self.drive_cluster_once(nonce).await?;
            let mut finalized = BTreeMap::<HashType, Vec<(usize, Epoch)>>::new();
            let mut progress = Vec::with_capacity(self.cluster.len());
            for index in 0..self.cluster.len() {
                match self.cluster.request(index, WireRequest::EpochChain).await? {
                    WireResponse::EpochChain(chain) => {
                        let latest = chain.epochchain.last().map(|epoch| {
                            (
                                epoch.body.nonce,
                                epoch.hash,
                                epoch.body.previous_nonce,
                                epoch.body.blocks.len(),
                                epoch.body.merkle_root,
                            )
                        });
                        let target = chain
                            .epochchain
                            .iter()
                            .position(|epoch| epoch.body.nonce == nonce)
                            .map(|position| {
                                let previous = position
                                    .checked_sub(1)
                                    .and_then(|position| chain.epochchain.get(position));
                                (position, previous)
                            });
                        progress.push((index, latest, target.is_some()));
                        if let Some((position, Some(previous))) = target {
                            let epoch = chain
                                .epochchain
                                .get(position)
                                .expect("target epoch position came from this chain");
                            epoch.verify_certificate(previous)?;
                            finalized
                                .entry(epoch.hash)
                                .or_default()
                                .push((index, epoch.clone()));
                        }
                    }
                    response => {
                        return Err(format!(
                            "expected epoch chain from Blossom node {index}, got {}",
                            response.kind()
                        )
                        .into());
                    }
                }
            }
            if finalized.len() > 1 {
                return Err("Blossom nodes finalized conflicting epochs".into());
            }
            if let Some((_hash, nodes)) = finalized
                .into_iter()
                .find(|(_, nodes)| nodes.len() >= required)
            {
                let epoch = nodes
                    .first()
                    .map(|(_, epoch)| epoch.clone())
                    .expect("a finality quorum is non-empty");
                let indexes = nodes.into_iter().map(|(index, _)| index).collect();
                return Ok((epoch, indexes));
            }
            let consensus_progress = self.consensus_progress()?;
            if consensus_progress != last_consensus_progress {
                last_consensus_progress = consensus_progress;
                deadline = Instant::now() + self.finality_timeout;
            }
            if Instant::now() >= deadline {
                let mut statuses = Vec::with_capacity(self.cluster.len());
                for index in 0..self.cluster.len() {
                    let status = match self.cluster.request(index, WireRequest::State).await {
                        Ok(WireResponse::State(status)) => format!(
                            "node={index} next={} pending={} last={}",
                            status.next_nonce, status.pending_blocks, status.last_epoch
                        ),
                        Ok(response) => {
                            format!("node={index} unexpected_status={}", response.kind())
                        }
                        Err(error) => format!("node={index} status_error={error}"),
                    };
                    statuses.push(status);
                }
                let consensus = (0..self.cluster.len())
                    .flat_map(|index| {
                        (0..=self.max_round).map(move |round| {
                            (
                                index,
                                round,
                                self.cluster
                                    .node(index)
                                    .runtime
                                    .consensus_round_status(round),
                            )
                        })
                    })
                    .collect::<Vec<_>>();
                let prefill = self
                    .cluster
                    .nodes()
                    .iter()
                    .enumerate()
                    .map(|(index, node)| (index, node.runtime.prefill_stage_status()))
                    .collect::<Vec<_>>();
                let dissemination = self
                    .cluster
                    .nodes()
                    .iter()
                    .enumerate()
                    .map(|(index, node)| (index, node.runtime.epoch_dissemination_status()))
                    .collect::<Vec<_>>();
                return Err(format!(
                    "Blossom cluster did not reach the required finality observation for nonce {nonce} before timeout; \
                     last drive errors: {last_drive_errors:?}; \
                     per-node latest progress: {progress:?}; statuses: {statuses:?}; traffic: {:?}; \
                     consensus: {consensus:?}; prefill: {prefill:?}; dissemination: {dissemination:?}",
                    self.traffic(),
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn consensus_progress(
        &self,
    ) -> Result<Vec<(usize, u8, blossom::ConsensusRoundStatus)>, BoxError> {
        self.cluster
            .nodes()
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let round = node.runtime.current_consensus_round()?;
                let status = node.runtime.consensus_round_status(round)?;
                Ok((index, round, status))
            })
            .collect()
    }

    pub(super) async fn drive_cluster_once(&self, nonce: Nonce) -> Result<Vec<String>, BoxError> {
        let mut errors = if self.trust_mode == TrustMode::Verified && self.max_round > 0 {
            self.drive_cluster_prefill_stage_once(nonce).await?
        } else {
            Vec::new()
        };
        errors.extend(self.drive_cluster_dispatch_stage_once(nonce).await?);
        errors.extend(
            self.drive_cluster_once_with_config(nonce, self.driver.clone())
                .await?,
        );
        Ok(errors)
    }

    async fn drive_cluster_prefill_stage_once(
        &self,
        nonce: Nonce,
    ) -> Result<Vec<String>, BoxError> {
        let mut drives = JoinSet::new();
        for (index, node) in self.drivers.iter().enumerate() {
            let target = self.cluster.node(index).runtime.next_epoch_target()?;
            if target.nonce > nonce {
                continue;
            }
            if target.nonce < nonce {
                return Err(format!(
                    "Blossom node {index} is behind requested nonce {nonce}: next nonce is {}",
                    target.nonce
                )
                .into());
            }
            let node = node.clone();
            let max_round = self.max_round;
            drives.spawn(async move { node.drive_prefill_stage_once(max_round).await });
        }
        let mut errors = Vec::new();
        while let Some(result) = drives.join_next().await {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) if self.driver.continue_after_error => {
                    errors.push(error.to_string());
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(error) => {
                    return Err(format!("manual prefill-stage driver failed: {error}").into());
                }
            }
        }
        // Each node checks its activation barrier after its own broadcast.
        // A required dispatch can arrive later in the same cluster-wide wave,
        // after that node has already checked the barrier. Recheck only after
        // every broadcast task has joined so a complete prefill wave always
        // activates all ready validators before the dispatch stage begins.
        for node in self.cluster.nodes() {
            match node.runtime.try_activate_prefill_round() {
                Ok(_) => {}
                Err(error) if self.driver.continue_after_error => {
                    errors.push(error.to_string());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(errors)
    }

    async fn drive_cluster_dispatch_stage_once(
        &self,
        nonce: Nonce,
    ) -> Result<Vec<String>, BoxError> {
        let mut drives = JoinSet::new();
        for (index, node) in self.drivers.iter().enumerate() {
            let target = self.cluster.node(index).runtime.next_epoch_target()?;
            if target.nonce > nonce {
                let node = node.clone();
                drives.spawn(async move { node.drive_epoch_dissemination_once().await });
                continue;
            }
            if target.nonce < nonce {
                return Err(format!(
                    "Blossom node {index} is behind requested nonce {nonce}: next nonce is {}",
                    target.nonce
                )
                .into());
            }
            let round = self.cluster.node(index).runtime.current_consensus_round()?;
            if self.trust_mode == TrustMode::Verified && self.max_round > 0 && round == 0 {
                continue;
            }
            let status = self
                .cluster
                .node(index)
                .runtime
                .consensus_round_status(round)?;
            if status.dispatch_status == Some(true)
                && status.received_dispatches.saturating_add(1) >= status.expected_quorum_members
            {
                continue;
            }
            let node = node.clone();
            let max_round = self.max_round;
            drives.spawn(async move { node.drive_dispatch_stage_once(max_round).await });
        }
        let mut errors = Vec::new();
        while let Some(result) = drives.join_next().await {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) if self.driver.continue_after_error => {
                    errors.push(error.to_string());
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(error) => {
                    return Err(format!("manual dispatch-stage driver failed: {error}").into());
                }
            }
        }
        Ok(errors)
    }

    async fn drive_cluster_once_with_config(
        &self,
        nonce: Nonce,
        config: ConsensusDriverConfig,
    ) -> Result<Vec<String>, BoxError> {
        let mut drives = JoinSet::new();
        for (index, node) in self.drivers.iter().enumerate() {
            let target = self.cluster.node(index).runtime.next_epoch_target()?;
            if target.nonce > nonce {
                continue;
            }
            if target.nonce < nonce {
                return Err(format!(
                    "Blossom node {index} is behind requested nonce {nonce}: next nonce is {}",
                    target.nonce
                )
                .into());
            }
            let round = self.cluster.node(index).runtime.current_consensus_round()?;
            let status = self
                .cluster
                .node(index)
                .runtime
                .consensus_round_status(round)?;
            if status.dispatch_status != Some(true)
                || status.received_dispatches.saturating_add(1) < status.expected_quorum_members
            {
                continue;
            }
            let node = node.clone();
            let config = config.clone();
            drives.spawn(async move { node.drive_consensus_once(&config).await });
        }
        let mut errors = Vec::new();
        while let Some(result) = drives.join_next().await {
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(error)) if config.continue_after_error => {
                    errors.push(error.to_string());
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(error) => return Err(format!("manual consensus driver failed: {error}").into()),
            }
        }
        Ok(errors)
    }

    pub(super) async fn wait_for_converged_epoch(
        &self,
        nonce: Nonce,
        expected_hash: HashType,
    ) -> Result<(), BoxError> {
        let deadline = Instant::now() + self.finality_timeout;
        loop {
            let mut converged = 0usize;
            let mut canonical_chain = None;
            let mut lagging = Vec::new();
            for index in 0..self.cluster.len() {
                match self.cluster.request(index, WireRequest::EpochChain).await? {
                    WireResponse::EpochChain(chain) => {
                        if let Some(epoch) = chain
                            .epochchain
                            .iter()
                            .find(|epoch| epoch.body.nonce == nonce)
                        {
                            if epoch.hash != expected_hash {
                                return Err(
                                    "Blossom node converged to a conflicting finalized epoch"
                                        .into(),
                                );
                            }
                            converged += 1;
                            canonical_chain.get_or_insert(chain);
                        } else {
                            lagging.push(index);
                        }
                    }
                    response => {
                        return Err(format!(
                            "expected epoch chain from Blossom node {index}, got {}",
                            response.kind()
                        )
                        .into());
                    }
                }
            }
            if converged == self.cluster.len() {
                return Ok(());
            }
            if let Some(chain) = canonical_chain {
                for index in lagging {
                    self.cluster
                        .node(index)
                        .runtime
                        .catch_up_from_epoch_started(chain.clone())?;
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "Blossom cluster did not converge nonce {nonce} on all {} nodes before timeout",
                    self.cluster.len()
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
