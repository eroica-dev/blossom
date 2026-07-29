//! Crash-safe coordination between active-active lifecycle and global order.
//!
//! This facade preserves accepted commands until their certified reference is
//! durably applied. Application-contract cutovers update the ordered engine
//! first and retain the lifecycle cutover manifest as a recovery intent until
//! both stores agree on the new contract.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{
    ActiveActiveCommand, ActiveActiveDurabilityMetrics, ActiveActiveHaCutoverManifest,
    ActiveActiveHaEngine, ActiveActiveHaLifecycleDurabilityMetrics, ActiveActiveHaRecoveryStatus,
    AvailabilityCertificate, BatchReference, BlossomError, CommandBatch, CommandIdentity,
    CommandSpecVersion, Epoch, GlobalOrderedEngine, HighAvailabilityRuntime, MilestoneEvent,
    OrderCertificate, OrderStatement, OrderedApplication, PreparedActiveActiveHaShardBatch,
    ReferenceStatus, Result, RouteGeneration, Transaction, WaitForOutcome, WriteMode,
};

/// Process-local inspection of both durable halves of the active-active path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveActiveCoordinatorDurability {
    /// Whether accepted-write and cutover lifecycle state is durable.
    pub lifecycle_durable: bool,
    /// Whether global order, application completion, and result state is durable.
    pub ordered_durable: bool,
    /// Lifecycle store durability counters.
    pub lifecycle: Option<ActiveActiveHaLifecycleDurabilityMetrics>,
    /// Global-order store durability counters.
    pub ordered: ActiveActiveDurabilityMetrics,
}

impl ActiveActiveCoordinatorDurability {
    /// Returns whether both stores satisfy the production durability contract.
    pub fn is_production_durable(self) -> bool {
        self.lifecycle_durable && self.ordered_durable
    }
}

/// Production coordinator for accepted lifecycle and globally ordered apply.
pub struct ActiveActiveGlobalCoordinator {
    lifecycle: ActiveActiveHaEngine,
    ordered: GlobalOrderedEngine,
}

impl ActiveActiveGlobalCoordinator {
    /// Opens a fail-closed coordinator and completes an interrupted cutover
    /// when the ordered store already durably activated its target contract.
    pub fn new(lifecycle: ActiveActiveHaEngine, ordered: GlobalOrderedEngine) -> Result<Self> {
        let mut coordinator = Self { lifecycle, ordered };
        if !coordinator.durability().is_production_durable() {
            return Err(BlossomError::InvalidConfiguration(
                "active-active global coordination requires both durable engines".to_string(),
            ));
        }
        coordinator.reconcile_application_contract()?;
        Ok(coordinator)
    }

    /// Returns process-local durability inspection for both stores.
    pub fn durability(&self) -> ActiveActiveCoordinatorDurability {
        ActiveActiveCoordinatorDurability {
            lifecycle_durable: self.lifecycle.is_production_durable(),
            ordered_durable: self.ordered.is_production_durable(),
            lifecycle: self.lifecycle.lifecycle_durability_metrics(),
            ordered: self.ordered.durability_metrics(),
        }
    }

    /// Returns the active lifecycle and membership status.
    pub fn recovery_status(&self) -> Result<ActiveActiveHaRecoveryStatus> {
        self.lifecycle.recovery_status()
    }

    /// Borrows the global-order engine for status and barrier operations.
    pub fn ordered(&self) -> &GlobalOrderedEngine {
        &self.ordered
    }

    /// Installs portable validator-signed finality without exposing unsafe
    /// independent application-contract activation.
    pub fn finalize(&mut self, certificate: OrderCertificate) -> Result<MilestoneEvent> {
        self.ordered.finalize(certificate)
    }

    /// Installs trusted finality without exposing unsafe independent
    /// application-contract activation.
    pub fn finalize_trusted(&mut self, statement: OrderStatement) -> Result<MilestoneEvent> {
        self.ordered.finalize_trusted(statement)
    }

    /// Installs every active-active reference in one trusted, already
    /// committed Blossom epoch.
    ///
    /// The ordered engine still validates the epoch's exact validator set,
    /// reference availability, origin chains, and application contract.
    pub fn finalize_trusted_epoch(&mut self, epoch: &Epoch) -> Result<Vec<MilestoneEvent>> {
        self.ordered.finalize_trusted_epoch(epoch)
    }

    /// Mutably borrows the underlying HA protocol runtime.
    pub fn ha_runtime_mut(&mut self) -> &mut HighAvailabilityRuntime {
        self.lifecycle.runtime_mut()
    }

    /// Returns the durable hash for an accepted identity.
    pub fn accepted_command_hash(&self, identity: CommandIdentity) -> Option<crate::HashType> {
        self.lifecycle.accepted_command_hash(identity)
    }

    /// Encodes one accepted command for the ordering transport.
    pub fn accepted_transaction(&self, identity: CommandIdentity) -> Result<Transaction> {
        self.lifecycle.accepted_transaction(identity)
    }

    /// Durably installs certified batch bytes before exposing their
    /// availability to finality and ordered application.
    pub fn mark_available(
        &mut self,
        batch: &CommandBatch,
        certificate: AvailabilityCertificate,
    ) -> Result<MilestoneEvent> {
        self.ordered.mark_available_with_batch(batch, certificate)
    }

    /// Durably accepts independently prepared shard lanes in one lifecycle
    /// commit. Hashes preserve lane and command order.
    pub fn accept_prepared_shard_batches(
        &mut self,
        batches: Vec<PreparedActiveActiveHaShardBatch>,
    ) -> Result<Vec<Vec<crate::HashType>>> {
        self.lifecycle.accept_prepared_shard_batches(batches)
    }

    /// Durably accepts one command without bypassing lifecycle retention.
    pub fn accept_local(&mut self, command: ActiveActiveCommand) -> Result<crate::HashType> {
        self.lifecycle.accept_local(command)
    }

    /// Drives `GlobalApplied` for one certified reference and removes its
    /// accepted lifecycle records only after durable ordered completion.
    ///
    /// A timeout leaves all accepted records intact. Retrying after a crash is
    /// idempotent whether the crash occurred before or after lifecycle cleanup.
    pub fn complete_globally_applied<A: OrderedApplication>(
        &mut self,
        reference: &BatchReference,
        batch: &CommandBatch,
        timeout: Duration,
        application: &mut A,
    ) -> Result<WaitForOutcome> {
        reference.verify_batch(batch)?;
        if reference.route_generation != self.ordered.route_generation()
            || reference.command_spec_version != self.ordered.command_spec_version()
        {
            return Err(BlossomError::InvalidConfiguration(
                "globally applied completion reference does not match the active application contract"
                    .to_string(),
            ));
        }
        let reference_hash = reference.hash()?;
        let current_status = self.ordered.status(reference_hash)?;
        let mut completions = BTreeMap::new();
        let mut present = 0usize;
        let mut absent = 0usize;
        for admitted in &batch.commands {
            let command_hash = admitted.command.hash()?;
            if let Some(existing) = completions.insert(admitted.command.identity, command_hash)
                && existing != command_hash
            {
                return Err(BlossomError::InvalidConfiguration(
                    "one globally applied batch contains conflicting command identities"
                        .to_string(),
                ));
            }
            match self
                .lifecycle
                .accepted_command_hash(admitted.command.identity)
            {
                Some(accepted_hash) if accepted_hash == command_hash => present += 1,
                Some(_) => {
                    return Err(BlossomError::InvalidConfiguration(
                        "globally applied batch does not match its accepted command hash"
                            .to_string(),
                    ));
                }
                None => absent += 1,
            }
        }
        if present != 0 && absent != 0 {
            return Err(BlossomError::InvalidConfiguration(
                "accepted lifecycle cleanup is partially present".to_string(),
            ));
        }
        if absent != 0 {
            return match current_status {
                ReferenceStatus::Applied(_) => Ok(WaitForOutcome::Reached(current_status)),
                _ => Err(BlossomError::InvalidConfiguration(
                    "globally applied completion references commands not retained by lifecycle"
                        .to_string(),
                )),
            };
        }
        let outcome = self.ordered.complete_write(
            reference_hash,
            WriteMode::GlobalApplied,
            timeout,
            application,
        )?;
        if matches!(
            &outcome,
            WaitForOutcome::Reached(status) if status.reached(crate::Milestone::Applied)
        ) {
            self.lifecycle.complete_accepted_batch(
                &completions
                    .into_iter()
                    .collect::<Vec<(CommandIdentity, crate::HashType)>>(),
            )?;
        }
        Ok(outcome)
    }

    /// Begins a durable route and command-spec cutover while fencing new
    /// accepted writes.
    pub fn begin_application_cutover(
        &mut self,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<()> {
        self.lifecycle
            .begin_application_cutover(route_generation, command_spec_version)
    }

    /// Recertifies one accepted identity without changing command bytes.
    pub fn recertify_accepted(&mut self, identity: CommandIdentity) -> Result<()> {
        self.lifecycle.recertify_accepted(identity)
    }

    /// Recertifies one accepted identity with translated command bytes.
    pub fn recertify_accepted_as(
        &mut self,
        identity: CommandIdentity,
        translated: ActiveActiveCommand,
    ) -> Result<()> {
        self.lifecycle.recertify_accepted_as(identity, translated)
    }

    /// Explicitly aborts one accepted identity during a cutover.
    pub fn abort_accepted(
        &mut self,
        identity: CommandIdentity,
        reason: impl Into<String>,
    ) -> Result<()> {
        self.lifecycle.abort_accepted(identity, reason)
    }

    /// Cancels an unactivated cutover while the ordered engine remains on the
    /// source contract.
    pub fn cancel_application_cutover(&mut self) -> Result<()> {
        let status = self.lifecycle.recovery_status()?;
        if self.ordered.route_generation() != status.route_generation
            || self.ordered.command_spec_version() != status.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "cannot cancel a cutover after ordered activation".to_string(),
            ));
        }
        self.lifecycle.cancel_application_cutover()
    }

    /// Returns the fully resolved durable lifecycle cutover manifest.
    pub fn cutover_manifest(&self) -> Result<ActiveActiveHaCutoverManifest> {
        self.lifecycle.cutover_manifest()
    }

    /// Atomically-at-recovery activates one resolved application cutover.
    ///
    /// The ordered store commits first. The lifecycle manifest remains durable
    /// until its activation commits, allowing constructor reconciliation after
    /// a crash between the two stores.
    pub fn activate_application_cutover(
        &mut self,
        manifest: &ActiveActiveHaCutoverManifest,
    ) -> Result<()> {
        let status = self.lifecycle.recovery_status()?;
        if status.cutover != Some(manifest.cutover)
            || self.ordered.route_generation() != manifest.cutover.from
            || self.ordered.command_spec_version() != manifest.cutover.from_command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "coordinated cutover does not match the active source contract".to_string(),
            ));
        }
        self.ordered.activate_application_contract(
            manifest.cutover.to,
            manifest.cutover.to_command_spec_version,
        )?;
        self.lifecycle.activate_cutover(manifest)
    }

    fn reconcile_application_contract(&mut self) -> Result<()> {
        let status = self.lifecycle.recovery_status()?;
        let ordered_route = self.ordered.route_generation();
        let ordered_spec = self.ordered.command_spec_version();
        if ordered_route == status.route_generation && ordered_spec == status.command_spec_version {
            return Ok(());
        }
        let Some(cutover) = status.cutover else {
            return Err(BlossomError::InvalidConfiguration(
                "durable active-active engines disagree without a recoverable cutover intent"
                    .to_string(),
            ));
        };
        if ordered_route != cutover.to || ordered_spec != cutover.to_command_spec_version {
            return Err(BlossomError::InvalidConfiguration(
                "durable active-active engines disagree outside the cutover target".to_string(),
            ));
        }
        let manifest = self.lifecycle.cutover_manifest()?;
        self.lifecycle.activate_cutover(&manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActiveActiveConsistencyMode, AdmittedCommand, ApplicationCommand, AvailabilityCertificate,
        AvailabilityTrust, BatchReferenceMetadata, ClientEpoch, ClientId, ConsensusGroupId,
        HolderMembership, Keypair, NodeIdentity, OrderCertificate, OrderStatement,
        ReplicaMembershipEpoch, SiteId, StoreGeneration, TrustMode, ValidatorGeneration, Watermark,
    };
    use std::collections::BTreeSet;
    use std::path::Path;

    struct NoopApplication;

    impl OrderedApplication for NoopApplication {
        fn apply_ordered(
            &mut self,
            ordered: &crate::OrderedBatch,
        ) -> Result<Vec<crate::ApplicationResult>> {
            ordered
                .batch
                .commands
                .iter()
                .map(|_| crate::ApplicationResult::new(vec![1]))
                .collect()
        }
    }

    fn members(keys: &[Keypair]) -> Vec<NodeIdentity> {
        keys.iter()
            .enumerate()
            .map(|(index, key)| {
                NodeIdentity::new(
                    key.public,
                    None,
                    "tcp",
                    "127.0.0.1",
                    25_000 + u16::try_from(index).unwrap(),
                    false,
                )
            })
            .collect()
    }

    fn open_engines(
        root: &Path,
        keys: &[Keypair],
        route: RouteGeneration,
        command_spec: CommandSpecVersion,
    ) -> (
        ActiveActiveHaEngine,
        GlobalOrderedEngine,
        Vec<crate::DurableAdmissionStore>,
    ) {
        let sites = ["site-a", "site-b", "site-c"];
        let stores = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                crate::DurableAdmissionStore::open(
                    root.join(format!("ordered-{index}")),
                    SiteId(sites[index].to_string()),
                    StoreGeneration(1),
                    key.signer(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let holder_membership = HolderMembership {
            epoch: ReplicaMembershipEpoch(1),
            members_by_site: keys
                .iter()
                .enumerate()
                .map(|(index, key)| {
                    (
                        SiteId(sites[index].to_string()),
                        [key.public].into_iter().collect(),
                    )
                })
                .collect(),
            store_generations: keys
                .iter()
                .map(|key| (key.public, StoreGeneration(1)))
                .collect(),
            holder_fault_bound: 0,
        };
        let validators = keys.iter().map(|key| key.public).collect::<BTreeSet<_>>();
        let ordered = GlobalOrderedEngine::new_with_application_contract(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership,
            ValidatorGeneration(1),
            validators,
            TrustMode::Verified,
            route,
            command_spec,
        )
        .unwrap();
        let runtime = HighAvailabilityRuntime::open(
            root.join("ha-runtime"),
            ConsensusGroupId::named("coordinator-test"),
            keys[0].public,
            members(keys),
            crate::HighAvailabilityParameters::default(),
        )
        .unwrap();
        let lifecycle =
            ActiveActiveHaEngine::open(root.join("ha-lifecycle"), runtime, route, command_spec)
                .unwrap();
        (lifecycle, ordered, stores)
    }

    fn command(sequence: u64) -> ActiveActiveCommand {
        ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([9; 16]),
                client_epoch: ClientEpoch(1),
                sequence,
            },
            command: ApplicationCommand::new(sequence.to_le_bytes().to_vec()).unwrap(),
        }
    }

    fn reference(
        batch: &CommandBatch,
        origin: crate::PubKey,
        route: RouteGeneration,
        command_spec: CommandSpecVersion,
    ) -> BatchReference {
        BatchReference::for_batch(
            batch,
            BatchReferenceMetadata {
                cluster_id: crate::HashType([7; 32]),
                consensus_group_id: ConsensusGroupId::named("coordinator-order"),
                shard: b"cache-invalidation-0".to_vec(),
                route_generation: route,
                command_spec_version: command_spec,
                origin,
                origin_incarnation: 1,
                origin_key_generation: 1,
                data_holder_membership_epoch: ReplicaMembershipEpoch(1),
                validator_generation: ValidatorGeneration(1),
                previous_origin_reference_hash: crate::HashType::default(),
            },
        )
        .unwrap()
    }

    #[test]
    fn globally_applied_completion_removes_lifecycle_only_after_apply() {
        let temporary = tempfile::tempdir().unwrap();
        let keys = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let (lifecycle, ordered, stores) = open_engines(
            temporary.path(),
            &keys,
            RouteGeneration(1),
            CommandSpecVersion(1),
        );
        let mut coordinator = ActiveActiveGlobalCoordinator::new(lifecycle, ordered).unwrap();
        let command = command(1);
        coordinator.accept_local(command.clone()).unwrap();
        let batch = CommandBatch {
            commands: vec![AdmittedCommand {
                origin_sequence: 1,
                command: command.clone(),
            }],
        };
        let reference = reference(
            &batch,
            keys[0].public,
            RouteGeneration(1),
            CommandSpecVersion(1),
        );
        let receipts = stores
            .iter()
            .map(|store| store.store_batch(&reference, &batch).unwrap())
            .collect();
        coordinator
            .mark_available(
                &batch,
                AvailabilityCertificate {
                    reference: reference.clone(),
                    trust: AvailabilityTrust::Trusted,
                    receipts,
                },
            )
            .unwrap();
        let statement = OrderStatement {
            consensus_group_id: reference.consensus_group_id,
            blossom_epoch_hash: crate::HashType([8; 32]),
            position: Watermark { position: 1 },
            reference_hash: reference.hash().unwrap(),
            previous_order_certificate_hash: crate::HashType::default(),
            validator_generation: ValidatorGeneration(1),
        };
        let votes = stores
            .iter()
            .take(2)
            .map(|store| store.sign_order_statement(&statement).unwrap())
            .collect::<Vec<_>>();
        coordinator
            .finalize(OrderCertificate::from_votes(statement, votes).unwrap())
            .unwrap();
        assert!(
            coordinator
                .accepted_command_hash(command.identity)
                .is_some()
        );
        let outcome = coordinator
            .complete_globally_applied(
                &reference,
                &batch,
                Duration::from_secs(1),
                &mut NoopApplication,
            )
            .unwrap();
        assert!(matches!(outcome, WaitForOutcome::Reached(_)));
        assert!(
            coordinator
                .accepted_command_hash(command.identity)
                .is_none()
        );
        assert!(matches!(
            coordinator
                .complete_globally_applied(
                    &reference,
                    &batch,
                    Duration::from_secs(1),
                    &mut NoopApplication,
                )
                .unwrap(),
            WaitForOutcome::Reached(_)
        ));
    }

    #[test]
    fn constructor_rejects_an_in_memory_lifecycle() {
        let temporary = tempfile::tempdir().unwrap();
        let keys = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let (durable_lifecycle, ordered, stores) = open_engines(
            temporary.path(),
            &keys,
            RouteGeneration(1),
            CommandSpecVersion(1),
        );
        drop(durable_lifecycle);
        let runtime = HighAvailabilityRuntime::new(
            ConsensusGroupId::named("coordinator-nondurable-test"),
            keys[0].public,
            members(&keys),
            crate::HighAvailabilityParameters::default(),
        )
        .unwrap();
        let lifecycle =
            ActiveActiveHaEngine::new(runtime, RouteGeneration(1), CommandSpecVersion(1)).unwrap();

        assert!(ActiveActiveGlobalCoordinator::new(lifecycle, ordered).is_err());
        drop(stores);
    }

    #[test]
    fn constructor_finishes_cutover_after_ordered_store_commits_first() {
        let temporary = tempfile::tempdir().unwrap();
        let keys = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let (lifecycle, ordered, stores) = open_engines(
            temporary.path(),
            &keys,
            RouteGeneration(1),
            CommandSpecVersion(1),
        );
        let mut coordinator = ActiveActiveGlobalCoordinator::new(lifecycle, ordered).unwrap();
        let command = command(1);
        coordinator.accept_local(command.clone()).unwrap();
        coordinator
            .begin_application_cutover(RouteGeneration(2), CommandSpecVersion(1))
            .unwrap();
        coordinator.recertify_accepted(command.identity).unwrap();
        let manifest = coordinator.cutover_manifest().unwrap();
        coordinator
            .ordered
            .activate_application_contract(
                manifest.cutover.to,
                manifest.cutover.to_command_spec_version,
            )
            .unwrap();
        drop(coordinator);
        drop(stores);

        let (lifecycle, ordered, _stores) = open_engines(
            temporary.path(),
            &keys,
            RouteGeneration(2),
            CommandSpecVersion(1),
        );
        let recovered = ActiveActiveGlobalCoordinator::new(lifecycle, ordered).unwrap();
        let status = recovered.recovery_status().unwrap();
        assert_eq!(status.route_generation, RouteGeneration(2));
        assert_eq!(status.command_spec_version, CommandSpecVersion(1));
        assert!(status.cutover.is_none());
        assert_eq!(
            recovered.accepted_command_hash(command.identity),
            Some(command.hash().unwrap())
        );
    }
}
