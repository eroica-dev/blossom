use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use blossom::{
    ActiveActiveCommand, ActiveActiveConsistencyMode, AdmittedCommand, ApplyProgress,
    AvailabilityCertificate, AvailabilityTrust, BatchReference, BatchReferenceMetadata, Block,
    CommandBatch, CommandSpecVersion, ConsensusDriverConfig, ConsensusGroupId,
    DurableAdmissionStore, Epoch, GlobalOrderedEngine, HashType, HolderMembership,
    LocalAdmissionCertificate, LocalAdmissionPolicy, Nonce, QuorumSize, ReplicaMembershipEpoch,
    RouteGeneration, SimulatedCluster, SiteId, StoreGeneration, TcpNode, TcpNodeMetricsSnapshot,
    Transaction, TrustMode, ValidatorGeneration, Watermark, WireRequest, WireResponse,
    find_round_number_with_size, ordered_batch_references, ordered_batch_references_trusted,
    supermajority_count,
};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::application::{CommandResult, SharedStateMachine, decode_result};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
const TRUSTED_DIRECT_COMMAND_DOMAIN: &[u8] = b"blossom/benchmark/trusted-direct-command/v1";

/// A native Blossom TCP cluster used by the comparison harness.
///
/// The adapter submits availability-certified compact references at their
/// writers and empty blocks at the remaining validators before manually
/// driving consensus. This admission barrier makes universal-writer benchmark
/// epochs deterministic without weakening the protocol's quorum finality.
pub struct BlossomTcpOrderCluster {
    cluster: SimulatedCluster,
    drivers: Vec<TcpNode>,
    driver: ConsensusDriverConfig,
    finality_timeout: Duration,
    trust_mode: TrustMode,
    max_round: u8,
}

/// Protocol-core trusted Blossom with opaque commands carried directly in each
/// writer's unsigned block.
pub struct BlossomTrustedDirectCluster {
    order_cluster: BlossomTcpOrderCluster,
    state_machine: SharedStateMachine,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlossomNodeTraffic {
    pub connections: u64,
    pub requests: u64,
    pub responses: u64,
    pub errors: u64,
    pub handler_nanos: u64,
}

impl From<TcpNodeMetricsSnapshot> for BlossomNodeTraffic {
    fn from(metrics: TcpNodeMetricsSnapshot) -> Self {
        Self {
            connections: metrics.connections,
            requests: metrics.requests,
            responses: metrics.responses,
            errors: metrics.errors,
            handler_nanos: metrics.handler_nanos,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomFinalitySample {
    pub nonce: Nonce,
    pub epoch_hash: HashType,
    pub target_resolution_nanos: u64,
    pub blocks_submitted_nanos: u64,
    pub finalized_nanos: u64,
    pub finalized_nodes: usize,
    pub converged_nanos: Option<u64>,
    pub converged_nodes: usize,
    pub finalized_block_count: usize,
    pub reference_hash: HashType,
    pub reference_hashes: Vec<HashType>,
    pub node_traffic: Vec<BlossomNodeTraffic>,
}

/// Complete `AcceptedLocal` through `Applied` timings for one globally ordered
/// active-active command.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomAppliedSample {
    pub accepted_local_nanos: u64,
    pub available_nanos: u64,
    pub finalized_nanos: u64,
    pub applied_nanos: u64,
    pub converged_nanos: u64,
    pub watermark: Watermark,
    pub result: CommandResult,
    pub finality: BlossomFinalitySample,
    pub trusted_path: BlossomTrustedPathSample,
}

/// Barrier timings for one epoch containing one real block from every active
/// writer. Results follow the epoch's BTree block-hash order, not caller order.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomUniversalWriterSample {
    pub active_writers: usize,
    pub accepted_local_nanos: u64,
    pub available_nanos: u64,
    pub finalized_nanos: u64,
    pub applied_nanos: u64,
    pub converged_nanos: u64,
    pub first_watermark: Watermark,
    pub last_watermark: Watermark,
    pub results: Vec<CommandResult>,
    pub finality: BlossomFinalitySample,
    pub trusted_path: BlossomTrustedPathSample,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomTrustedDirectSample {
    pub active_writers: usize,
    pub finalized_nanos: u64,
    pub applied_nanos: u64,
    pub converged_nanos: u64,
    pub command_prepare_nanos: u64,
    pub block_submission_nanos: u64,
    pub receipt_and_order_nanos: u64,
    pub apply_nanos: u64,
    pub convergence_nanos: u64,
    pub results: Vec<CommandResult>,
    pub finality: BlossomFinalitySample,
}

/// Non-overlapping trusted-mode stages and work amplification for one write.
///
/// The milestone fields on [`BlossomAppliedSample`] are cumulative from the
/// start of the write. These fields are individual stage durations, so their
/// sum explains end-to-end latency and exposes work that grows with the
/// validator or holder population.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlossomTrustedPathSample {
    pub command_prepare_nanos: u64,
    pub admission_replication_nanos: u64,
    pub accepted_transition_nanos: u64,
    pub reference_build_nanos: u64,
    pub availability_replication_nanos: u64,
    pub available_transition_nanos: u64,
    pub target_resolution_nanos: u64,
    pub block_submission_nanos: u64,
    pub receipt_and_order_nanos: u64,
    pub order_statement_nanos: u64,
    pub order_vote_nanos: u64,
    pub finalized_transition_nanos: u64,
    pub apply_nanos: u64,
    pub convergence_nanos: u64,
    pub origin_site_members: usize,
    pub admission_receipts: usize,
    pub availability_sites: usize,
    pub availability_receipts: usize,
    pub validator_block_submissions: usize,
    pub hierarchy_rounds: usize,
    pub finalized_nodes: usize,
    pub order_votes: usize,
    /// Immediate shard-stream commits issued by the benchmark path for this write.
    ///
    /// Independent replica commits run concurrently. This count still makes
    /// write amplification visible and separates batching gains from
    /// consensus gains.
    pub immediate_durable_commits: usize,
}

/// Complete trusted active-active Blossom stack for executable benchmarks.
///
/// A configured subset of validators also serves as three-site data holders.
/// The default uses every validator for the equal-footprint baseline. The
/// driver exercises durable admission, availability certification, native TCP
/// trusted block receipt/order, and state-machine apply.
pub struct BlossomActiveActiveCluster {
    order_cluster: BlossomTcpOrderCluster,
    stores: Vec<DurableAdmissionStore>,
    holder_indices_by_site: BTreeMap<SiteId, Vec<usize>>,
    engine: GlobalOrderedEngine,
    application: SharedStateMachine,
    membership_epoch: ReplicaMembershipEpoch,
    validator_generation: ValidatorGeneration,
    next_origin_sequences: Vec<u64>,
    previous_origin_reference_hashes: Vec<HashType>,
}

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
            .map(|node| TcpNode::with_services(node.runtime.clone(), node.client()))
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
        let target = self.cluster.node(0).runtime.next_epoch_target()?;
        let target_resolution_nanos = elapsed_nanos(target_started);
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
                match client
                    .request(&service, &WireRequest::SubmitBlock(block))
                    .await?
                {
                    WireResponse::BlockAccepted(accepted) => Ok(accepted),
                    response => Err(blossom::BlossomError::WireProtocol(format!(
                        "expected block accepted, got {}",
                        response.kind()
                    ))),
                }
            });
        }

        while let Some(result) = submissions.join_next().await {
            let accepted = result??;
            if accepted.nonce != target.nonce {
                return Err("Blossom accepted a block for the wrong epoch".into());
            }
        }
        let blocks_submitted_nanos = elapsed_nanos(started);
        let (epoch, finalized_node_indexes) = self.wait_for_finalized_epoch(target.nonce).await?;
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

    async fn wait_for_finalized_epoch(
        &self,
        nonce: Nonce,
    ) -> Result<(Epoch, Vec<usize>), BoxError> {
        if self.trust_mode.is_trusted() {
            let deadline = Instant::now() + self.finality_timeout;
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
                let drive_errors = self.drive_cluster_once().await?;
                if Instant::now() >= deadline {
                    let progress =
                        self.cluster
                            .nodes()
                            .iter()
                            .enumerate()
                            .map(|(index, node)| {
                                let round = node.runtime.current_consensus_round();
                                let status = round.as_ref().ok().and_then(|round| {
                                    node.runtime.consensus_round_status(*round).ok()
                                });
                                (index, round, status)
                            })
                            .collect::<Vec<_>>();
                    return Err(format!(
                        "timed out waiting for local epoch {nonce} commit; trusted progress: \
                         {progress:?}; last drive errors: {drive_errors:?}"
                    )
                    .into());
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        let deadline = Instant::now() + self.finality_timeout;
        let required = supermajority_count(self.cluster.len());
        loop {
            let _drive_errors = self.drive_cluster_once().await?;
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
                            .find(|epoch| epoch.body.nonce == nonce)
                            .cloned();
                        progress.push((index, latest, target.is_some()));
                        if let Some(epoch) = target {
                            finalized
                                .entry(epoch.hash)
                                .or_default()
                                .push((index, epoch));
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
                epoch.epoch_approved()?;
                let indexes = nodes.into_iter().map(|(index, _)| index).collect();
                return Ok((epoch, indexes));
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
                return Err(format!(
                    "Blossom cluster did not reach the required finality observation for nonce {nonce} before timeout; \
                     per-node latest progress: {progress:?}; statuses: {statuses:?}; traffic: {:?}; \
                     consensus: {consensus:?}",
                    self.traffic(),
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn drive_cluster_once(&self) -> Result<Vec<String>, BoxError> {
        let mut errors = self.drive_cluster_dispatch_stage_once().await?;
        errors.extend(
            self.drive_cluster_once_with_config(self.driver.clone())
                .await?,
        );
        Ok(errors)
    }

    async fn drive_cluster_dispatch_stage_once(&self) -> Result<Vec<String>, BoxError> {
        let mut drives = JoinSet::new();
        for node in &self.drivers {
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
        config: ConsensusDriverConfig,
    ) -> Result<Vec<String>, BoxError> {
        let mut drives = JoinSet::new();
        for node in &self.drivers {
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

    async fn wait_for_converged_epoch(
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

impl BlossomTrustedDirectCluster {
    pub async fn start(
        participant_count: usize,
        quorum_size: QuorumSize,
    ) -> Result<Self, BoxError> {
        Ok(Self {
            order_cluster: BlossomTcpOrderCluster::start(participant_count, quorum_size).await?,
            state_machine: SharedStateMachine::new(4096)?,
        })
    }

    /// Places one command directly in each active writer's unsigned block and
    /// waits through local state-machine application.
    pub async fn client_write_universal(
        &mut self,
        commands: Vec<ActiveActiveCommand>,
    ) -> Result<BlossomTrustedDirectSample, BoxError> {
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
        let mut member_transactions = Vec::with_capacity(active_writers);
        for command in commands {
            command.validate()?;
            let encoded = borsh::to_vec(&command)?;
            let mut payload =
                Vec::with_capacity(TRUSTED_DIRECT_COMMAND_DOMAIN.len() + encoded.len());
            payload.extend_from_slice(TRUSTED_DIRECT_COMMAND_DOMAIN);
            payload.extend_from_slice(&encoded);
            member_transactions.push(vec![Transaction::new(payload)]);
        }
        let command_prepare_nanos = elapsed_nanos(phase_started);

        let (epoch, mut finality, _) = self
            .order_cluster
            .finalize_transactions(&member_transactions)
            .await?;
        let finalized_returned = Instant::now();
        let finalized_nanos = elapsed_nanos(started);
        let block_submission_nanos = finality.blocks_submitted_nanos;
        let receipt_and_order_nanos = finality
            .finalized_nanos
            .saturating_sub(finality.blocks_submitted_nanos);

        let phase_started = Instant::now();
        let ordered = epoch.trusted_ordered_transactions()?;
        if ordered.len() != active_writers {
            return Err("trusted epoch did not contain every direct writer command".into());
        }
        finality.reference_hashes = ordered
            .iter()
            .map(|ordered| ordered.transaction.hash)
            .collect();
        finality.reference_hash = finality
            .reference_hashes
            .first()
            .copied()
            .unwrap_or_default();
        let mut results = Vec::with_capacity(ordered.len());
        for ordered_transaction in ordered {
            let payload = ordered_transaction.transaction.payload.into_bytes();
            let encoded = payload
                .strip_prefix(TRUSTED_DIRECT_COMMAND_DOMAIN)
                .ok_or("trusted direct epoch contains an unknown transaction domain")?;
            let command = borsh::from_slice::<ActiveActiveCommand>(encoded)?;
            results.push(self.state_machine.apply(&command)?);
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
        Ok(BlossomTrustedDirectSample {
            active_writers,
            finalized_nanos,
            applied_nanos,
            converged_nanos: elapsed_nanos(started),
            command_prepare_nanos,
            block_submission_nanos,
            receipt_and_order_nanos,
            apply_nanos,
            convergence_nanos,
            results,
            finality,
        })
    }

    pub fn read_local(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state_machine.get(key).map(<[u8]>::to_vec)
    }
}

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

fn elapsed_nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn traffic_delta(
    before: &[BlossomNodeTraffic],
    after: &[BlossomNodeTraffic],
) -> Vec<BlossomNodeTraffic> {
    after
        .iter()
        .enumerate()
        .map(|(index, after)| {
            let before = before.get(index).copied().unwrap_or_default();
            BlossomNodeTraffic {
                connections: after.connections.saturating_sub(before.connections),
                requests: after.requests.saturating_sub(before.requests),
                responses: after.responses.saturating_sub(before.responses),
                errors: after.errors.saturating_sub(before.errors),
                handler_nanos: after.handler_nanos.saturating_sub(before.handler_nanos),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use blossom::{
        AdmittedCommand, BatchReferenceMetadata, ClientEpoch, ClientId, CommandBatch,
        CommandIdentity, CommandSpecVersion, ConsensusGroupId, Keypair, ReplicaMembershipEpoch,
        RouteGeneration, ValidatorGeneration,
    };

    use super::*;
    use crate::{CommandOperation, active_active_command};

    fn reference(origin: blossom::PubKey) -> BatchReference {
        let batch = CommandBatch {
            commands: vec![AdmittedCommand {
                origin_sequence: 1,
                command: active_active_command(
                    CommandIdentity {
                        client_id: ClientId([1; 16]),
                        client_epoch: ClientEpoch(1),
                        sequence: 1,
                    },
                    CommandOperation::BlindWrite {
                        key: b"benchmark-key".to_vec(),
                        value: b"benchmark-value".to_vec(),
                    },
                )
                .unwrap(),
            }],
        };
        BatchReference::for_batch(
            &batch,
            BatchReferenceMetadata {
                cluster_id: HashType([9; 32]),
                consensus_group_id: ConsensusGroupId::root(),
                shard: b"benchmark-shard".to_vec(),
                route_generation: RouteGeneration(1),
                command_spec_version: CommandSpecVersion(1),
                origin,
                origin_incarnation: 1,
                origin_key_generation: 1,
                data_holder_membership_epoch: ReplicaMembershipEpoch(1),
                validator_generation: ValidatorGeneration(1),
                previous_origin_reference_hash: HashType::default(),
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn native_tcp_cluster_finalizes_one_compact_reference_at_global_threshold() {
        let origin = Keypair::generate();
        let reference = reference(origin.public);
        let cluster = BlossomTcpOrderCluster::start(3, QuorumSize::new(3).unwrap())
            .await
            .unwrap();

        let (epoch, sample, finalized_nodes) =
            cluster.finalize_reference(&reference).await.unwrap();

        assert_eq!(
            ordered_batch_references_trusted(&epoch).unwrap(),
            vec![reference]
        );
        assert_eq!(sample.nonce, Nonce::new(1));
        assert_eq!(sample.finalized_nodes, finalized_nodes.len());
        assert!(finalized_nodes.contains(&0));
        assert_eq!(sample.finalized_block_count, 3);
        assert!(sample.finalized_nanos >= sample.blocks_submitted_nanos);
        assert!(
            sample
                .node_traffic
                .iter()
                .all(|metrics| metrics.requests > 0)
        );
    }

    #[tokio::test]
    async fn trusted_tcp_cluster_orders_all_parallel_writer_blocks_by_hash() {
        let origins = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let references = origins
            .iter()
            .map(|origin| reference(origin.public))
            .collect::<Vec<_>>();
        let expected_hashes = references
            .iter()
            .map(BatchReference::hash)
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        let cluster = BlossomTcpOrderCluster::start(6, QuorumSize::new(3).unwrap())
            .await
            .unwrap();

        let (epoch, sample, finalized_nodes) =
            cluster.finalize_references(&references).await.unwrap();
        let ordered = ordered_batch_references_trusted(&epoch).unwrap();

        assert_eq!(ordered.len(), 6);
        assert_eq!(
            ordered
                .iter()
                .map(BatchReference::hash)
                .collect::<Result<BTreeSet<_>, _>>()
                .unwrap(),
            expected_hashes
        );
        assert_eq!(sample.reference_hashes.len(), 6);
        assert_eq!(sample.finalized_block_count, 6);
        assert!(finalized_nodes.contains(&0));
        assert!(
            epoch
                .body
                .ordered_blocks()
                .into_iter()
                .all(|(_, block)| block.signature == blossom::Signature::default())
        );
    }

    #[tokio::test]
    async fn trusted_direct_cluster_applies_unsigned_writer_payloads_without_certificates() {
        let mut cluster = BlossomTrustedDirectCluster::start(6, QuorumSize::new(3).unwrap())
            .await
            .unwrap();
        let commands = (0..6)
            .map(|writer| {
                active_active_command(
                    CommandIdentity {
                        client_id: ClientId([40 + writer as u8; 16]),
                        client_epoch: ClientEpoch(1),
                        sequence: 1,
                    },
                    CommandOperation::BlindWrite {
                        key: format!("direct-key-{writer}").into_bytes(),
                        value: vec![writer as u8; 32],
                    },
                )
                .unwrap()
            })
            .collect();

        let sample = cluster.client_write_universal(commands).await.unwrap();

        assert_eq!(sample.active_writers, 6);
        assert_eq!(sample.results, vec![CommandResult::Written; 6]);
        assert_eq!(sample.finality.reference_hashes.len(), 6);
        assert_eq!(cluster.read_local(b"direct-key-5"), Some(vec![5; 32]));
        assert_eq!(
            sample.finality.node_traffic.len(),
            cluster.order_cluster.participant_count()
        );
    }

    #[tokio::test]
    async fn active_active_cluster_runs_every_milestone_through_applied() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "blossom-active-benchmark-{}-{suffix}",
            std::process::id()
        ));
        let mut cluster = BlossomActiveActiveCluster::start_with_holders_per_site(
            6,
            QuorumSize::new(3).unwrap(),
            1,
            &root,
        )
        .await
        .unwrap();
        let command = active_active_command(
            CommandIdentity {
                client_id: ClientId([7; 16]),
                client_epoch: ClientEpoch(1),
                sequence: 1,
            },
            CommandOperation::BlindWrite {
                key: b"complete-path".to_vec(),
                value: b"value".to_vec(),
            },
        )
        .unwrap();

        let sample = cluster.client_write(command).await.unwrap();

        assert_eq!(sample.result, CommandResult::Written);
        assert_eq!(sample.watermark, Watermark { position: 1 });
        assert!(sample.available_nanos >= sample.accepted_local_nanos);
        assert!(sample.finalized_nanos >= sample.available_nanos);
        assert!(sample.applied_nanos >= sample.finalized_nanos);
        assert!(sample.converged_nanos >= sample.applied_nanos);
        assert!(sample.finality.converged_nanos.is_some());
        assert_eq!(sample.finality.converged_nodes, 6);
        assert_eq!(sample.trusted_path.origin_site_members, 1);
        assert_eq!(sample.trusted_path.admission_receipts, 1);
        assert_eq!(sample.trusted_path.availability_sites, 2);
        assert_eq!(sample.trusted_path.availability_receipts, 2);
        assert_eq!(sample.trusted_path.validator_block_submissions, 6);
        assert_eq!(sample.trusted_path.order_votes, 0);
        assert_eq!(
            sample.trusted_path.immediate_durable_commits,
            sample.trusted_path.admission_receipts
                + sample.trusted_path.availability_receipts
                + sample.trusted_path.order_votes
                + 4
        );
        drop(cluster);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn active_active_cluster_applies_parallel_universal_writers() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "blossom-universal-writer-benchmark-{}-{suffix}",
            std::process::id()
        ));
        let mut cluster = BlossomActiveActiveCluster::start_with_holders_per_site(
            6,
            QuorumSize::new(3).unwrap(),
            1,
            &root,
        )
        .await
        .unwrap();
        let commands = (0..6)
            .map(|writer| {
                active_active_command(
                    CommandIdentity {
                        client_id: ClientId([30 + writer as u8; 16]),
                        client_epoch: ClientEpoch(1),
                        sequence: 1,
                    },
                    CommandOperation::BlindWrite {
                        key: format!("parallel-key-{writer}").into_bytes(),
                        value: vec![writer as u8; 32],
                    },
                )
                .unwrap()
            })
            .collect();

        let sample = cluster.client_write_universal(commands).await.unwrap();

        assert_eq!(sample.active_writers, 6);
        assert_eq!(sample.first_watermark, Watermark { position: 1 });
        assert_eq!(sample.last_watermark, Watermark { position: 6 });
        assert_eq!(sample.results, vec![CommandResult::Written; 6]);
        assert_eq!(sample.finality.reference_hashes.len(), 6);
        assert_eq!(sample.trusted_path.validator_block_submissions, 6);
        assert_eq!(sample.trusted_path.order_votes, 0);
        assert!(sample.available_nanos >= sample.accepted_local_nanos);
        assert!(sample.finalized_nanos >= sample.available_nanos);
        assert!(sample.applied_nanos >= sample.finalized_nanos);

        drop(cluster);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn active_active_q3_q6_q9_paths_finalize_and_apply() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for quorum_size in [3usize, 6, 9] {
            let participant_count = quorum_size.max(6);
            let root = std::env::temp_dir().join(format!(
                "blossom-active-q-matrix-{}-{suffix}-{quorum_size}",
                std::process::id()
            ));
            let mut cluster = BlossomActiveActiveCluster::start_with_holders_per_site(
                participant_count,
                QuorumSize::new(quorum_size).unwrap(),
                1,
                &root,
            )
            .await
            .unwrap();
            let sample = cluster
                .client_write(
                    active_active_command(
                        CommandIdentity {
                            client_id: ClientId([quorum_size as u8; 16]),
                            client_epoch: ClientEpoch(1),
                            sequence: 1,
                        },
                        CommandOperation::BlindWrite {
                            key: b"q-matrix".to_vec(),
                            value: vec![quorum_size as u8],
                        },
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(sample.result, CommandResult::Written);
            assert_eq!(sample.watermark, Watermark { position: 1 });
            assert_eq!(
                cluster.read_local(b"q-matrix"),
                Ok(Some(vec![quorum_size as u8]))
            );
            drop(cluster);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
