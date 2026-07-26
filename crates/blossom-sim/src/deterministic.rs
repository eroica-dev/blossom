//! Protocol adapters for the generic deterministic event environment.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use blossom::high_availability::{
    AmendmentPayload, AmendmentRecord, ClientEpoch as HaClientEpoch, ClientId as HaClientId,
    CommandIdentity as HaCommandIdentity, Watermark as HaWatermark,
};
use blossom::{
    ActiveActiveCommand, ClientEpoch, ClientId, CommandIdentity, CommandOperation, CommandResult,
    ConsensusGroupId, HaDispatch, HaMessage, HaRecoverySnapshot, HaReplicationMode, HashType,
    HighAvailabilityParameters, HighAvailabilityRuntime, Keypair, NodeIdentity, Nonce, SecKey,
    SharedStateMachine, TelemetryEvent, TelemetryEventKind, TelemetryHandle, Transaction,
    TrustMode, high_availability_majority, supermajority_count,
};
#[cfg(feature = "parallel-networks")]
use blossom::{
    HaGroupRegistration, HaGroupStateReference, ParallelNetworkCoordinator, ParallelNetworkEvent,
    PubKey, TrustedCheckpointDag, TrustedDagIngestOutcome, TrustedDagRoundCompletion,
    TrustedDagVertex, TrustedDagVertexBody,
};
#[cfg(feature = "trusted-checkpoint-dag")]
use blossom::{QuorumSize, run_sequential_quorum_dag_experiment};
use deterministic_test_env::{
    ClientOutcome, ClusterView, DeterministicCluster, DeterministicNode, Effect, EventKey,
    ExecutionTrace, ExplorationBounds, GlobalObserver, LinkFault, NodeContext, NodeEvent,
    NodeFault, PropertyKind, PropertyRegistry, RegionFault, RunMode, Scenario, ScenarioAction,
    ScenarioActionKind, SimChannel, SimTime, StorageFault, SystematicExplorer, TraceReducer,
};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::{EpochChaosConfig, run_epoch_chaos};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeterministicCampaignProfile {
    Pr,
    Novelty,
    Nightly,
    Release,
}

impl DeterministicCampaignProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pr => "pr",
            Self::Novelty => "novelty",
            Self::Nightly => "nightly",
            Self::Release => "release",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HaFaultPlan {
    None,
    AsymmetricPartition,
    MinorityPartition,
    RegionalPartition,
    RegionalOutage,
    DelayAndDuplicate,
    Corruption,
    ProcessPauseAndThrottle,
    GracefulRedeploy,
    CrashAfterConfirmation,
    StorageDelay,
    StorageFull,
    StorageIo,
    StorageFailure,
    StorageTornWrite,
    StorageCorruption,
    StorageDiskReplacement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaDeterministicConfig {
    pub nodes: usize,
    pub epochs: usize,
    pub seed: u64,
    pub durable: bool,
    pub fault_plan: HaFaultPlan,
    pub fault_depth: u8,
    pub systematic_schedules: usize,
    pub max_events: usize,
}

impl Default for HaDeterministicConfig {
    fn default() -> Self {
        Self {
            nodes: 3,
            epochs: 25,
            seed: 0x6861_5f64_7374_0001,
            durable: false,
            fault_plan: HaFaultPlan::MinorityPartition,
            fault_depth: 2,
            systematic_schedules: 1,
            max_events: 50_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolCellReport {
    pub protocol: String,
    pub topology: String,
    pub epochs: usize,
    pub schedules: usize,
    pub unique_states: usize,
    pub events: usize,
    pub safety_passed: bool,
    pub replay_passed: bool,
    pub property_failures: Vec<String>,
    pub final_state_digest: String,
    pub scenario: Option<Scenario>,
    pub replay_manifest: Option<deterministic_test_env::ReplayManifest>,
    pub minimized: Option<deterministic_test_env::ReducedTrace>,
    pub trace: Option<ExecutionTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicCampaignReport {
    pub profile: DeterministicCampaignProfile,
    pub cells: Vec<ProtocolCellReport>,
    pub total_events: usize,
    pub total_schedules: usize,
    pub safety_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicCampaignArtifact {
    pub schema_version: u16,
    pub git_revision: String,
    pub report: DeterministicCampaignReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum HaCommand {
    Dispatch {
        expected_nonce: u64,
        command: ActiveActiveCommand,
        duplicate_retry: bool,
    },
    Acknowledge {
        expected_nonce: u64,
    },
    Confirm {
        expected_nonce: u64,
    },
    Amend {
        expected_nonce: u64,
        target_nonce: u64,
        sequence: u64,
        payload: Vec<u8>,
    },
    RequireSealed {
        required_nonce: u64,
    },
    RecoverFrom {
        source: usize,
    },
    Status,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum HaSimMessage {
    Protocol(Box<HaMessage>),
    RecoveryRequest,
    RecoverySnapshot(Box<HaRecoverySnapshot>),
}

struct HaDeterministicNode {
    runtime: Option<HighAvailabilityRuntime>,
    group_id: ConsensusGroupId,
    self_key: blossom::PubKey,
    identities: Vec<NodeIdentity>,
    parameters: HighAvailabilityParameters,
    durable_path: Option<PathBuf>,
    _temporary_guard: Option<Arc<TempDir>>,
    rejected_messages: u64,
    command_failures: u64,
    finalized: BTreeMap<u64, HashType>,
    sealed: BTreeMap<u64, HashType>,
    historical_conflict: bool,
    sealed_conflict: bool,
    amendment_attempts: u64,
    amendment_successes: u64,
    recovery_attempts: u64,
    recovery_successes: u64,
    sealed_check_attempts: u64,
    sealed_check_failures: u64,
    application_hash: HashType,
    application_results: BTreeMap<CommandIdentity, CommandResult>,
    application_apply_failures: u64,
    injected_fault_observations: u64,
}

impl HaDeterministicNode {
    fn runtime(&self) -> Option<&HighAvailabilityRuntime> {
        self.runtime.as_ref()
    }

    fn runtime_mut(&mut self) -> blossom::Result<&mut HighAvailabilityRuntime> {
        self.runtime.as_mut().ok_or_else(|| {
            blossom::BlossomError::InvalidConfiguration(
                "deterministic HA node is not running".to_string(),
            )
        })
    }

    fn peer_effects(
        &self,
        message: HaSimMessage,
        operation: u64,
        stage: &'static str,
        channel: SimChannel,
    ) -> Vec<Effect> {
        let payload = serde_json::to_vec(&message).expect("HA message serializes");
        self.identities
            .iter()
            .enumerate()
            .filter(|(_, identity)| identity.public_key() != self.self_key)
            .map(|(target, _)| Effect::Send {
                target,
                channel,
                payload: payload.clone(),
                delay_micros: 0,
                key: EventKey::new(
                    stage,
                    u32::try_from(target).unwrap_or(u32::MAX),
                    operation,
                    0,
                ),
            })
            .collect()
    }

    fn send_effect(
        &self,
        target: usize,
        message: HaSimMessage,
        operation: u64,
        stage: &'static str,
        channel: SimChannel,
    ) -> Effect {
        Effect::Send {
            target,
            channel,
            payload: serde_json::to_vec(&message).expect("HA simulation message serializes"),
            delay_micros: 0,
            key: EventKey::new(
                stage,
                u32::try_from(target).unwrap_or(u32::MAX),
                operation,
                0,
            ),
        }
    }

    fn current_nonce(&self) -> Option<u64> {
        self.runtime()
            .map(|runtime| runtime.current_round().round_id.nonce.value())
    }

    fn install_recovery_snapshot(&mut self, snapshot: HaRecoverySnapshot) -> blossom::Result<()> {
        let safe_prefix = self.runtime().is_some_and(|runtime| {
            runtime.epochs().len() <= snapshot.epochs.len()
                && runtime
                    .epochs()
                    .iter()
                    .zip(&snapshot.epochs)
                    .all(|(local, recovered)| {
                        local.nonce == recovered.nonce && local.hash == recovered.hash
                    })
        });
        if !safe_prefix {
            return Err(blossom::BlossomError::WireProtocol(
                "recovery snapshot does not extend the local immutable prefix".to_string(),
            ));
        }
        if self
            .runtime_mut()
            .and_then(|runtime| runtime.install_recovery_snapshot(snapshot.clone()))
            .is_ok()
        {
            return Ok(());
        }

        // Production services redeploy a node onto a fresh durable volume when
        // transient round state prevents an in-place snapshot install. The
        // deterministic adapter mirrors that service-facing recovery path, but
        // only after proving the local immutable history is a prefix.
        self.runtime.take();
        if let Some(path) = &self.durable_path {
            crate::deterministic_durable::replace_store(path)?;
        }
        let mut replacement = if let Some(path) = &self.durable_path {
            HighAvailabilityRuntime::open(
                path,
                self.group_id,
                self.self_key,
                self.identities.clone(),
                self.parameters,
            )
        } else {
            HighAvailabilityRuntime::new(
                self.group_id,
                self.self_key,
                self.identities.clone(),
                self.parameters,
            )
        }?;
        replacement.install_recovery_snapshot(snapshot)?;
        self.runtime = Some(replacement);
        Ok(())
    }

    fn record_finalized(&mut self) {
        let Some(runtime) = self.runtime() else {
            return;
        };
        let sealed_through = runtime.sealed_watermark().position;
        let entries = runtime
            .epochs()
            .iter()
            .map(|epoch| (epoch.nonce.value(), epoch.hash))
            .collect::<Vec<_>>();
        for (nonce, hash) in entries {
            if self
                .finalized
                .insert(nonce, hash)
                .is_some_and(|existing| existing != hash)
            {
                self.historical_conflict = true;
            }
            if nonce <= sealed_through
                && self
                    .sealed
                    .insert(nonce, hash)
                    .is_some_and(|existing| existing != hash)
            {
                self.sealed_conflict = true;
            }
        }
        self.refresh_application_state();
    }

    fn refresh_application_state(&mut self) {
        let Some(runtime) = self.runtime() else {
            return;
        };
        let commands = runtime
            .epochs()
            .iter()
            .flat_map(|epoch| epoch.ordered_blocks())
            .flat_map(|(_, block)| block.body.txs.iter())
            .filter_map(|transaction| transaction.payload_as_borsh::<ActiveActiveCommand>().ok())
            .collect::<Vec<_>>();
        let Ok(mut application) = SharedStateMachine::new(4_096) else {
            self.application_apply_failures = self.application_apply_failures.saturating_add(1);
            return;
        };
        let mut results = BTreeMap::new();
        for command in commands {
            match application.apply(&command) {
                Ok(result) => {
                    if results
                        .insert(command.identity, result.clone())
                        .is_some_and(|existing| existing != result)
                    {
                        self.application_apply_failures =
                            self.application_apply_failures.saturating_add(1);
                    }
                }
                Err(_) => {
                    self.application_apply_failures =
                        self.application_apply_failures.saturating_add(1);
                    return;
                }
            }
        }
        match application.canonical_hash() {
            Ok(hash) => {
                self.application_hash = hash;
                self.application_results = results;
            }
            Err(_) => {
                self.application_apply_failures = self.application_apply_failures.saturating_add(1);
            }
        }
    }

    fn handle_command(
        &mut self,
        command: HaCommand,
        context: &NodeContext,
        client_id: u64,
        operation_id: u64,
    ) -> Vec<Effect> {
        if context.storage_fault != StorageFault::Healthy {
            self.injected_fault_observations = self.injected_fault_observations.saturating_add(1);
        }
        let is_status = matches!(command, HaCommand::Status);
        let expected_nonce = match &command {
            HaCommand::Dispatch { expected_nonce, .. }
            | HaCommand::Acknowledge { expected_nonce }
            | HaCommand::Confirm { expected_nonce }
            | HaCommand::Amend { expected_nonce, .. } => Some(*expected_nonce),
            HaCommand::RequireSealed { .. } | HaCommand::RecoverFrom { .. } | HaCommand::Status => {
                None
            }
        };
        if let Some(expected) = expected_nonce {
            match self.current_nonce() {
                Some(current) if current > expected => {
                    return vec![response_ok(client_id, operation_id, b"already-advanced")];
                }
                Some(current) if current < expected => {
                    self.command_failures = self.command_failures.saturating_add(1);
                    return vec![Effect::Respond {
                        client_id,
                        operation_id,
                        outcome: ClientOutcome::Fail {
                            error: format!(
                                "HA round {expected} is not ready; current round is {current}"
                            ),
                        },
                        delay_micros: 0,
                        key: EventKey::new(
                            "ha-command-not-ready",
                            u32::try_from(context.node).unwrap_or(u32::MAX),
                            operation_id,
                            0,
                        ),
                    }];
                }
                Some(_) => {}
                None => {
                    self.command_failures = self.command_failures.saturating_add(1);
                    return vec![Effect::Respond {
                        client_id,
                        operation_id,
                        outcome: ClientOutcome::Fail {
                            error: "deterministic HA node is not running".to_string(),
                        },
                        delay_micros: 0,
                        key: EventKey::new(
                            "ha-command-not-running",
                            u32::try_from(context.node).unwrap_or(u32::MAX),
                            operation_id,
                            0,
                        ),
                    }];
                }
            }
        }
        let storage_blocked = matches!(
            context.storage_fault,
            StorageFault::Full
                | StorageFault::Io
                | StorageFault::Fsync
                | StorageFault::TornWrite { .. }
                | StorageFault::Corrupt { .. }
                | StorageFault::ReplaceDisk
        );
        let result: blossom::Result<Vec<Effect>> = match command {
            HaCommand::Dispatch {
                expected_nonce,
                command,
                duplicate_retry,
            } => {
                let transaction = Transaction::from_borsh(&command);
                let dispatch = self.runtime_mut().and_then(|runtime| {
                    let transaction = transaction?;
                    let mut transactions = vec![transaction.clone()];
                    if duplicate_retry {
                        transactions.push(transaction);
                    }
                    replay_or_build_dispatch(runtime, transactions, expected_nonce)
                });
                dispatch.map(|dispatch| {
                    self.peer_effects(
                        HaSimMessage::Protocol(Box::new(HaMessage::Dispatch(dispatch))),
                        expected_nonce,
                        "ha-dispatch",
                        SimChannel::Protocol,
                    )
                })
            }
            HaCommand::Acknowledge { expected_nonce } => {
                if storage_blocked {
                    Err(blossom::BlossomError::Io(
                        "deterministic injected acknowledgement persistence failure".to_string(),
                    ))
                } else {
                    self.runtime_mut()
                        .and_then(HighAvailabilityRuntime::acknowledge)
                        .map(|acknowledgement| {
                            self.peer_effects(
                                HaSimMessage::Protocol(Box::new(HaMessage::Acknowledge(
                                    acknowledgement,
                                ))),
                                expected_nonce,
                                "ha-acknowledge",
                                SimChannel::Protocol,
                            )
                        })
                }
            }
            HaCommand::Confirm { expected_nonce } => {
                if storage_blocked {
                    Err(blossom::BlossomError::Io(
                        "deterministic injected confirmation persistence failure".to_string(),
                    ))
                } else {
                    self.runtime_mut()
                        .and_then(HighAvailabilityRuntime::confirm)
                        .map(|(confirmation, _)| {
                            self.peer_effects(
                                HaSimMessage::Protocol(Box::new(HaMessage::Confirm(confirmation))),
                                expected_nonce,
                                "ha-confirm",
                                SimChannel::Protocol,
                            )
                        })
                }
            }
            HaCommand::Amend {
                expected_nonce,
                target_nonce,
                sequence,
                payload,
            } => {
                self.amendment_attempts = self.amendment_attempts.saturating_add(1);
                let client_id = HaClientId(
                    self.self_key.0[..16]
                        .try_into()
                        .expect("public key prefix has exactly sixteen bytes"),
                );
                let transaction = self.runtime_mut().and_then(|runtime| {
                    let target = runtime
                        .epochs()
                        .iter()
                        .find(|epoch| epoch.nonce.value() == target_nonce)
                        .ok_or_else(|| {
                            blossom::BlossomError::InvalidConfiguration(format!(
                                "deterministic amendment target nonce {target_nonce} is unavailable"
                            ))
                        })?;
                    let amendment = AmendmentRecord {
                        target_epoch_hash: target.hash,
                        target_epoch_nonce: target.nonce,
                        containing_epoch_nonce: Nonce::new(expected_nonce),
                        origin_slot: runtime.self_slot(),
                        command_identity: HaCommandIdentity {
                            client_id,
                            client_epoch: HaClientEpoch(1),
                            sequence,
                        },
                        supersedes: None,
                        payload: AmendmentPayload::Compensation {
                            command_bytes: payload,
                        },
                    };
                    runtime.amendment_transaction(&amendment)
                });
                transaction
                    .and_then(|transaction| {
                        self.runtime_mut().and_then(|runtime| {
                            runtime.build_dispatch_at(vec![transaction], u128::from(context.now.0))
                        })
                    })
                    .map(|dispatch| {
                        self.amendment_successes = self.amendment_successes.saturating_add(1);
                        self.peer_effects(
                            HaSimMessage::Protocol(Box::new(HaMessage::Dispatch(dispatch))),
                            expected_nonce,
                            "ha-amendment-dispatch",
                            SimChannel::Protocol,
                        )
                    })
            }
            HaCommand::RequireSealed { required_nonce } => {
                self.sealed_check_attempts = self.sealed_check_attempts.saturating_add(1);
                let result = self
                    .runtime()
                    .ok_or_else(|| {
                        blossom::BlossomError::InvalidConfiguration(
                            "deterministic HA node is not running".to_string(),
                        )
                    })
                    .and_then(|runtime| {
                        runtime.require_sealed(HaWatermark {
                            position: required_nonce,
                        })
                    })
                    .map(|()| Vec::new());
                if result.is_err() {
                    self.sealed_check_failures = self.sealed_check_failures.saturating_add(1);
                }
                result
            }
            HaCommand::RecoverFrom { source } => {
                self.recovery_attempts = self.recovery_attempts.saturating_add(1);
                if source >= self.identities.len() || source == context.node {
                    Err(blossom::BlossomError::InvalidConfiguration(
                        "deterministic recovery source must be a different HA member".to_string(),
                    ))
                } else {
                    Ok(vec![self.send_effect(
                        source,
                        HaSimMessage::RecoveryRequest,
                        operation_id,
                        "ha-recovery-request",
                        SimChannel::Repair,
                    )])
                }
            }
            HaCommand::Status => self
                .runtime()
                .ok_or_else(|| {
                    blossom::BlossomError::InvalidConfiguration(
                        "deterministic HA node is not running".to_string(),
                    )
                })
                .and_then(HighAvailabilityRuntime::operational_status)
                .and_then(|status| {
                    serde_json::to_vec(&status)
                        .map(|payload| {
                            vec![Effect::Respond {
                                client_id,
                                operation_id,
                                outcome: ClientOutcome::Ok { payload },
                                delay_micros: 0,
                                key: EventKey::new(
                                    "ha-status-response",
                                    u32::try_from(context.node).unwrap_or(u32::MAX),
                                    operation_id,
                                    0,
                                ),
                            }]
                        })
                        .map_err(|error| blossom::BlossomError::WireProtocol(error.to_string()))
                }),
        };
        match result {
            Ok(mut effects) => {
                if !is_status {
                    effects.push(response_ok(client_id, operation_id, b"accepted"));
                }
                self.record_finalized();
                effects
            }
            Err(error) => {
                self.command_failures = self.command_failures.saturating_add(1);
                vec![Effect::Respond {
                    client_id,
                    operation_id,
                    outcome: ClientOutcome::Fail {
                        error: error.to_string(),
                    },
                    delay_micros: 0,
                    key: EventKey::new(
                        "ha-command-failure",
                        u32::try_from(context.node).unwrap_or(u32::MAX),
                        operation_id,
                        0,
                    ),
                }]
            }
        }
    }
}

impl DeterministicNode for HaDeterministicNode {
    fn on_event(
        &mut self,
        event: NodeEvent,
        context: &mut NodeContext,
    ) -> deterministic_test_env::Result<Vec<Effect>> {
        match event {
            NodeEvent::Client {
                client_id,
                operation_id,
                payload,
            } => {
                let command = serde_json::from_slice(&payload)
                    .map_err(|error| deterministic_test_env::SimEnvError::App(error.to_string()))?;
                Ok(self.handle_command(command, context, client_id, operation_id))
            }
            NodeEvent::Message {
                source, payload, ..
            } => {
                let Ok(message) = serde_json::from_slice::<HaSimMessage>(&payload) else {
                    self.rejected_messages = self.rejected_messages.saturating_add(1);
                    return Ok(Vec::new());
                };
                let effects = match message {
                    HaSimMessage::Protocol(message) => {
                        if self
                            .runtime_mut()
                            .and_then(|runtime| runtime.receive_message(*message))
                            .is_err()
                        {
                            self.rejected_messages = self.rejected_messages.saturating_add(1);
                        }
                        Vec::new()
                    }
                    HaSimMessage::RecoveryRequest => {
                        let Some(runtime) = self.runtime() else {
                            return Ok(Vec::new());
                        };
                        vec![self.send_effect(
                            source,
                            HaSimMessage::RecoverySnapshot(Box::new(runtime.recovery_snapshot())),
                            context.now.0,
                            "ha-recovery-snapshot",
                            SimChannel::Repair,
                        )]
                    }
                    HaSimMessage::RecoverySnapshot(snapshot) => {
                        match self.install_recovery_snapshot(*snapshot) {
                            Ok(()) => {
                                self.recovery_successes = self.recovery_successes.saturating_add(1);
                            }
                            Err(_) => {
                                self.rejected_messages = self.rejected_messages.saturating_add(1);
                            }
                        }
                        Vec::new()
                    }
                };
                if self.runtime().is_some() {
                    self.record_finalized();
                }
                Ok(effects)
            }
            NodeEvent::Timer { .. } | NodeEvent::StorageComplete { .. } | NodeEvent::Quiesce => {
                Ok(Vec::new())
            }
        }
    }

    fn state_digest(&self) -> String {
        let Some(runtime) = self.runtime() else {
            return format!(
                "crashed:{}:{}:{:?}:{:?}:{}:{}:{}:{}",
                self.rejected_messages,
                self.command_failures,
                self.finalized,
                self.sealed,
                self.historical_conflict,
                self.sealed_conflict,
                self.application_hash,
                self.application_apply_failures,
            );
        };
        let revision = runtime
            .revision()
            .map(|revision| revision.revision_hash.to_string())
            .unwrap_or_else(|error| format!("error:{error}"));
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            runtime.head().nonce,
            runtime.head().hash,
            runtime.sealed_watermark().position,
            revision,
            runtime.members().active_mask(),
            self.historical_conflict,
            self.sealed_conflict,
            self.amendment_successes,
            self.recovery_successes,
            self.sealed_check_attempts,
            self.sealed_check_failures,
            self.application_hash,
            self.application_apply_failures,
            self.injected_fault_observations,
        )
    }

    fn crash(&mut self) -> deterministic_test_env::Result<()> {
        self.runtime.take();
        Ok(())
    }

    fn restart(&mut self) -> deterministic_test_env::Result<()> {
        // Treat restart as an idempotent process boundary. A graceful-stop
        // implementation from an older simulator may not have called
        // `crash()`, so defensively release the database handle before reopen.
        self.runtime.take();
        let runtime = if let Some(path) = &self.durable_path {
            HighAvailabilityRuntime::open(
                path,
                self.group_id,
                self.self_key,
                self.identities.clone(),
                self.parameters,
            )
        } else {
            HighAvailabilityRuntime::new(
                self.group_id,
                self.self_key,
                self.identities.clone(),
                self.parameters,
            )
        }
        .map_err(|error| deterministic_test_env::SimEnvError::App(error.to_string()))?;
        self.runtime = Some(runtime);
        self.record_finalized();
        Ok(())
    }
}

fn response_ok(client_id: u64, operation_id: u64, payload: &[u8]) -> Effect {
    Effect::Respond {
        client_id,
        operation_id,
        outcome: ClientOutcome::Ok {
            payload: payload.to_vec(),
        },
        delay_micros: 0,
        key: EventKey::new("ha-command-response", 0, operation_id, 0),
    }
}

fn replay_or_build_dispatch(
    runtime: &mut HighAvailabilityRuntime,
    transactions: Vec<Transaction>,
    expected_nonce: u64,
) -> blossom::Result<HaDispatch> {
    let slot = runtime.self_slot();
    let round_id = runtime.current_round().round_id;
    if round_id.nonce.value() != expected_nonce {
        return Err(blossom::BlossomError::InvalidEpochNonce);
    }
    if let Some(block) = runtime.current_round().blocks[slot.index()].clone() {
        let matches_existing = block.body.txs.len() == transactions.len()
            && block
                .body
                .txs
                .iter()
                .zip(&transactions)
                .all(|(existing, requested)| {
                    existing.hash == requested.hash
                        && existing.payload.as_ref() == requested.payload.as_ref()
                });
        if !matches_existing {
            return Err(blossom::BlossomError::WireProtocol(
                "idempotent dispatch retry conflicts with the durable local block".to_string(),
            ));
        }
        return Ok(HaDispatch {
            round_id,
            sender: slot,
            block_hash: block.hash,
            block,
        });
    }

    // The logical dispatch timestamp is part of the block hash. Derive it from
    // the round identity so a client retry after disk replacement recreates
    // the exact bytes peers may already possess.
    let created_micros = u128::from(expected_nonce)
        .saturating_mul(1_000)
        .saturating_add(10);
    runtime.build_dispatch_at(transactions, created_micros)
}

pub fn run_ha_deterministic(config: HaDeterministicConfig) -> Result<ProtocolCellReport, BoxError> {
    if !(2..=7).contains(&config.nodes) {
        return Err("HA deterministic node count must be 2..=7"
            .to_string()
            .into());
    }
    let identities = deterministic_identities(config.nodes, config.seed);
    let group_id = ConsensusGroupId::named(format!(
        "ha-dst-{}-{}-{}",
        config.nodes, config.seed, config.durable
    ));
    let parameters = HighAvailabilityParameters::default();
    let scenario = ha_scenario(&config)?;
    let report_scenario = scenario.clone();
    let quiescence_time = SimTime(ha_final_quiescence_time(&config));
    // Reachability is a campaign-level concern. Healthy cells deliberately
    // drive amendments, reordered sessions, and strict sealing to completion;
    // fault cells continue checking the corresponding safety invariants while
    // allowing the injected fault to cause safe non-progress.
    let expect_amendment = config.fault_plan == HaFaultPlan::None && config.epochs >= 7;
    let expect_reordered_sequences = config.fault_plan == HaFaultPlan::None && config.epochs >= 11;
    let make_nodes = || {
        build_ha_nodes(&identities, group_id, parameters, config.durable)
            .map_err(|error| deterministic_test_env::SimEnvError::App(error.to_string()))
    };
    let (trace, schedules, unique_states) = if config.systematic_schedules > 1 {
        let explorer = SystematicExplorer {
            bounds: ExplorationBounds {
                max_events: config.max_events,
                max_schedules: config.systematic_schedules,
                max_branch_width: 8,
                fault_depth: scenario.fault_depth,
            },
        };
        let report = explorer.explore_with_observer(&scenario, make_nodes, || HaObserver {
            quiescence_time,
            fault_plan: config.fault_plan,
            expect_amendment,
            expect_reordered_sequences,
        })?;
        let trace = report
            .failures
            .first()
            .or_else(|| report.traces.last())
            .cloned()
            .ok_or("systematic HA exploration produced no traces")?;
        let replay = DeterministicCluster::new(
            scenario.clone(),
            make_nodes()?,
            RunMode::Replay {
                choices: trace.choices.clone(),
            },
        )?
        .run_with_observer(&mut HaObserver {
            quiescence_time,
            fault_plan: config.fault_plan,
            expect_amendment,
            expect_reordered_sequences,
        })?;
        if trace.final_state_digest != replay.final_state_digest
            || trace.client_history != replay.client_history
            || trace.properties != replay.properties
        {
            return Err("systematic HA deterministic replay diverged".into());
        }
        if !trace.properties.passed() {
            let second_replay = DeterministicCluster::new(
                scenario.clone(),
                make_nodes()?,
                RunMode::Replay {
                    choices: trace.choices.clone(),
                },
            )?
            .run_with_observer(&mut HaObserver {
                quiescence_time,
                fault_plan: config.fault_plan,
                expect_amendment,
                expect_reordered_sequences,
            })?;
            if replay != second_replay {
                return Err("systematic HA failure did not reproduce twice".into());
            }
        }
        (trace, report.schedules, report.unique_states)
    } else {
        let mut cluster = DeterministicCluster::new(
            scenario.clone(),
            make_nodes()?,
            RunMode::Random { seed: config.seed },
        )?;
        define_ha_properties(
            cluster.properties_mut(),
            config.fault_plan,
            expect_amendment,
            expect_reordered_sequences,
        );
        let trace = cluster.run_with_observer(&mut HaObserver {
            quiescence_time,
            fault_plan: config.fault_plan,
            expect_amendment,
            expect_reordered_sequences,
        })?;
        let replay = DeterministicCluster::new(
            scenario.clone(),
            make_nodes()?,
            RunMode::Replay {
                choices: trace.choices.clone(),
            },
        )?
        .run_with_observer(&mut HaObserver {
            quiescence_time,
            fault_plan: config.fault_plan,
            expect_amendment,
            expect_reordered_sequences,
        })?;
        if trace.final_state_digest != replay.final_state_digest
            || trace.client_history != replay.client_history
            || trace.properties != replay.properties
        {
            return Err("HA deterministic replay diverged".into());
        }
        if !trace.properties.passed() {
            let second_replay = DeterministicCluster::new(
                scenario.clone(),
                make_nodes()?,
                RunMode::Replay {
                    choices: trace.choices.clone(),
                },
            )?
            .run_with_observer(&mut HaObserver {
                quiescence_time,
                fault_plan: config.fault_plan,
                expect_amendment,
                expect_reordered_sequences,
            })?;
            if replay != second_replay {
                return Err("HA deterministic failure did not reproduce twice".into());
            }
        }
        (trace, 1, 1)
    };
    let failures = trace
        .properties
        .statuses
        .iter()
        .filter(|(_, status)| **status != deterministic_test_env::PropertyStatus::Passing)
        .map(|(name, status)| format!("{name}: {status:?}"))
        .collect::<Vec<_>>();
    let failed_properties = trace
        .properties
        .statuses
        .iter()
        .filter(|(_, status)| **status != deterministic_test_env::PropertyStatus::Passing)
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    let replay_manifest = deterministic_test_env::ReplayManifest::from_trace(
        &report_scenario,
        &trace,
        "working-tree",
        format!(
            "cargo run --release -p blossom-sim --features high-availability --bin blossom-deterministic-campaign -- --profile pr --seed {}",
            config.seed
        ),
    )?;
    let minimized =
        if failures.is_empty() || std::env::var_os("BLOSSOM_SKIP_TRACE_REDUCTION").is_some() {
            None
        } else {
            Some(TraceReducer::default().reduce(
                &report_scenario,
                &trace,
                make_nodes,
                || HaObserver {
                    quiescence_time,
                    fault_plan: config.fault_plan,
                    expect_amendment,
                    expect_reordered_sequences,
                },
                |candidate| {
                    candidate.properties.statuses.iter().any(|(name, status)| {
                        failed_properties.contains(name)
                            && *status != deterministic_test_env::PropertyStatus::Passing
                    })
                },
            )?)
        };
    Ok(ProtocolCellReport {
        protocol: "blossom-ha-leaderless-active-active".to_string(),
        topology: format!(
            "{}-node-{}-{:?}",
            config.nodes,
            if config.durable { "durable" } else { "memory" },
            config.fault_plan
        ),
        epochs: config.epochs,
        schedules,
        unique_states,
        events: trace.events.len(),
        safety_passed: failures.is_empty(),
        replay_passed: true,
        property_failures: failures,
        final_state_digest: trace.final_state_digest.clone(),
        scenario: Some(report_scenario),
        replay_manifest: Some(replay_manifest),
        minimized,
        trace: Some(trace),
    })
}

fn deterministic_identities(count: usize, seed: u64) -> Vec<NodeIdentity> {
    (0..count)
        .map(|index| {
            let mut secret = [0u8; 32];
            for (offset, byte) in secret.iter_mut().enumerate() {
                *byte = seed
                    .wrapping_add(index as u64)
                    .wrapping_add(offset as u64)
                    .rotate_left((offset % 63) as u32) as u8;
            }
            let keypair = Keypair::from_secret(SecKey(secret));
            NodeIdentity::new(
                keypair.public,
                Some(keypair.secret),
                "dst",
                format!("node-{index}"),
                20_000 + index as u16,
                false,
            )
        })
        .collect()
}

fn build_ha_nodes(
    identities: &[NodeIdentity],
    group_id: ConsensusGroupId,
    parameters: HighAvailabilityParameters,
    durable: bool,
) -> Result<Vec<HaDeterministicNode>, BoxError> {
    let temporary_guard = durable.then(tempfile::tempdir).transpose()?.map(Arc::new);
    identities
        .iter()
        .enumerate()
        .map(|(index, identity)| {
            let durable_path = durable.then(|| {
                temporary_guard
                    .as_ref()
                    .expect("durable HA simulation owns a temporary directory")
                    .path()
                    .join(format!("node-{index}.redb"))
            });
            let runtime = match &durable_path {
                Some(path) => HighAvailabilityRuntime::open(
                    path,
                    group_id,
                    identity.public_key(),
                    identities.to_vec(),
                    parameters,
                ),
                None => HighAvailabilityRuntime::new(
                    group_id,
                    identity.public_key(),
                    identities.to_vec(),
                    parameters,
                ),
            }?;
            Ok(HaDeterministicNode {
                runtime: Some(runtime),
                group_id,
                self_key: identity.public_key(),
                identities: identities.to_vec(),
                parameters,
                durable_path,
                _temporary_guard: temporary_guard.clone(),
                rejected_messages: 0,
                command_failures: 0,
                finalized: BTreeMap::new(),
                sealed: BTreeMap::new(),
                historical_conflict: false,
                sealed_conflict: false,
                amendment_attempts: 0,
                amendment_successes: 0,
                recovery_attempts: 0,
                recovery_successes: 0,
                sealed_check_attempts: 0,
                sealed_check_failures: 0,
                application_hash: SharedStateMachine::new(4_096)?.canonical_hash()?,
                application_results: BTreeMap::new(),
                application_apply_failures: 0,
                injected_fault_observations: 0,
            })
        })
        .collect()
}

fn ha_scenario(config: &HaDeterministicConfig) -> Result<Scenario, BoxError> {
    let mut scenario = Scenario::new(
        format!(
            "ha-{}-{}-{:?}",
            config.nodes, config.epochs, config.fault_plan
        ),
        "blossom-ha",
        config.nodes,
    );
    scenario.seed = config.seed;
    scenario.max_events = config.max_events;
    scenario.max_virtual_time = SimTime(ha_final_quiescence_time(config).saturating_add(700));
    scenario.fault_depth = match config.fault_plan {
        HaFaultPlan::None => 0,
        _ => config.fault_depth,
    };
    let fault_epoch = ha_fault_epoch(config);
    let victim = config.nodes.saturating_sub(1);
    let mut operation = 0u64;
    for epoch in 1..=config.epochs {
        let base = u64::try_from(epoch)
            .unwrap_or(u64::MAX)
            .saturating_mul(1_000);
        if epoch == fault_epoch {
            schedule_ha_faults(&mut scenario, config, victim, base, &mut operation);
        }
        schedule_ha_epoch_commands(&mut scenario, config, epoch, base, &mut operation)?;
    }
    scenario.push(ScenarioAction {
        at: SimTime(
            u64::try_from(config.epochs)
                .unwrap_or(u64::MAX)
                .saturating_mul(1_000)
                .saturating_add(550),
        ),
        key: EventKey::new("ha-final-heal", 0, operation, 0),
        action: ScenarioActionKind::HealAll,
    });
    if config.fault_plan != HaFaultPlan::None {
        push_command(
            &mut scenario,
            u64::try_from(config.epochs)
                .unwrap_or(u64::MAX)
                .saturating_mul(1_000)
                .saturating_add(950),
            victim,
            &HaCommand::RecoverFrom { source: 0 },
            &mut operation,
        )?;
    }
    if config.fault_plan == HaFaultPlan::StorageDiskReplacement {
        let retry_start = u64::try_from(config.epochs)
            .unwrap_or(u64::MAX)
            .saturating_mul(1_000)
            .saturating_add(1_100);
        for (offset, epoch) in (fault_epoch..=config.epochs).enumerate() {
            let retry_base = retry_start.saturating_add(
                u64::try_from(offset)
                    .unwrap_or(u64::MAX)
                    .saturating_mul(1_000),
            );
            schedule_ha_epoch_commands(&mut scenario, config, epoch, retry_base, &mut operation)?;
        }
    }
    let final_phase_base = ha_final_phase_base(config);
    let final_sealed_nonce = config
        .epochs
        .saturating_sub(HighAvailabilityParameters::default().mutable_epoch_depth as usize);
    push_command(
        &mut scenario,
        final_phase_base.saturating_add(1_100),
        0,
        &HaCommand::RequireSealed {
            required_nonce: final_sealed_nonce as u64,
        },
        &mut operation,
    )?;
    scenario.push(ScenarioAction {
        at: SimTime(final_phase_base.saturating_add(1_300)),
        key: EventKey::new("ha-final-quiesce", 0, operation, 0),
        action: ScenarioActionKind::Quiesce,
    });
    Ok(scenario)
}

fn ha_fault_epoch(config: &HaDeterministicConfig) -> usize {
    config.epochs.max(2) / 2
}

fn ha_final_phase_base(config: &HaDeterministicConfig) -> u64 {
    let workload_end = u64::try_from(config.epochs)
        .unwrap_or(u64::MAX)
        .saturating_mul(1_000);
    if config.fault_plan != HaFaultPlan::StorageDiskReplacement {
        return workload_end;
    }
    let retry_count_after_first = config.epochs.saturating_sub(ha_fault_epoch(config));
    workload_end.saturating_add(1_100).saturating_add(
        u64::try_from(retry_count_after_first)
            .unwrap_or(u64::MAX)
            .saturating_mul(1_000),
    )
}

fn ha_final_quiescence_time(config: &HaDeterministicConfig) -> u64 {
    ha_final_phase_base(config).saturating_add(1_300)
}

fn schedule_ha_epoch_commands(
    scenario: &mut Scenario,
    config: &HaDeterministicConfig,
    epoch: usize,
    base: u64,
    operation: &mut u64,
) -> Result<(), BoxError> {
    for node in 0..config.nodes {
        push_command(
            scenario,
            base.saturating_add(10),
            node,
            &deterministic_dispatch_command(node, epoch, config.seed),
            operation,
        )?;
        push_command(
            scenario,
            base.saturating_add(150),
            node,
            &HaCommand::Acknowledge {
                expected_nonce: epoch as u64,
            },
            operation,
        )?;
        push_command(
            scenario,
            base.saturating_add(300),
            node,
            &HaCommand::Confirm {
                expected_nonce: epoch as u64,
            },
            operation,
        )?;
        push_command(
            scenario,
            base.saturating_add(700),
            node,
            &HaCommand::Acknowledge {
                expected_nonce: epoch as u64,
            },
            operation,
        )?;
        push_command(
            scenario,
            base.saturating_add(800),
            node,
            &HaCommand::Confirm {
                expected_nonce: epoch as u64,
            },
            operation,
        )?;
    }
    push_command(
        scenario,
        base.saturating_add(850),
        0,
        &HaCommand::Status,
        operation,
    )?;
    scenario.push(ScenarioAction {
        at: SimTime(base.saturating_add(900)),
        key: EventKey::new("ha-quiesce", 0, *operation, 0),
        action: ScenarioActionKind::Quiesce,
    });
    *operation = operation.saturating_add(1);
    Ok(())
}

fn deterministic_application_command(node: usize, epoch: usize, seed: u64) -> ActiveActiveCommand {
    let sequence = match (node, epoch) {
        (0, 10) => 11,
        (0, 11) => 10,
        _ => epoch as u64,
    };
    let operation = match epoch % 3 {
        0 => CommandOperation::Append {
            key: b"shared-append-log".to_vec(),
            value: format!("{seed}:{epoch}:{node};").into_bytes(),
        },
        1 => CommandOperation::BlindWrite {
            key: format!("writer-{node}").into_bytes(),
            value: format!("{seed}:{epoch}").into_bytes(),
        },
        _ => CommandOperation::CompareAndSwap {
            key: b"shared-cas".to_vec(),
            expected: None,
            value: format!("{seed}:{epoch}:{node}").into_bytes(),
        },
    };
    ActiveActiveCommand {
        identity: CommandIdentity {
            client_id: ClientId([u8::try_from(node).unwrap_or(u8::MAX); 16]),
            client_epoch: ClientEpoch(1),
            sequence,
        },
        operation,
    }
}

fn deterministic_dispatch_command(node: usize, epoch: usize, seed: u64) -> HaCommand {
    if node == 0 && epoch >= 7 && epoch.is_multiple_of(7) {
        HaCommand::Amend {
            expected_nonce: epoch as u64,
            target_nonce: epoch.saturating_sub(1) as u64,
            sequence: epoch as u64,
            payload: format!("amend-epoch-{}-from-{epoch}", epoch.saturating_sub(1)).into_bytes(),
        }
    } else {
        HaCommand::Dispatch {
            expected_nonce: epoch as u64,
            command: deterministic_application_command(node, epoch, seed),
            duplicate_retry: epoch.is_multiple_of(5),
        }
    }
}

fn schedule_ha_faults(
    scenario: &mut Scenario,
    config: &HaDeterministicConfig,
    victim: usize,
    base: u64,
    operation: &mut u64,
) {
    match config.fault_plan {
        HaFaultPlan::None => {}
        HaFaultPlan::AsymmetricPartition => {
            for source in 0..config.nodes.saturating_sub(1) {
                push_link_fault(scenario, base, source, victim, LinkFault::Jam, operation);
                push_link_fault(
                    scenario,
                    base.saturating_add(550),
                    source,
                    victim,
                    LinkFault::Heal,
                    operation,
                );
            }
        }
        HaFaultPlan::MinorityPartition => {
            for peer in 0..config.nodes.saturating_sub(1) {
                push_link_fault(scenario, base, victim, peer, LinkFault::Jam, operation);
                push_link_fault(scenario, base, peer, victim, LinkFault::Drop, operation);
                push_link_fault(
                    scenario,
                    base.saturating_add(550),
                    victim,
                    peer,
                    LinkFault::Heal,
                    operation,
                );
                push_link_fault(
                    scenario,
                    base.saturating_add(550),
                    peer,
                    victim,
                    LinkFault::Heal,
                    operation,
                );
            }
        }
        HaFaultPlan::RegionalPartition | HaFaultPlan::RegionalOutage => {
            let fault = if config.fault_plan == HaFaultPlan::RegionalPartition {
                RegionFault::Partition
            } else {
                RegionFault::Offline
            };
            scenario.push(ScenarioAction {
                at: SimTime(base),
                key: EventKey::new(
                    "ha-region-fault",
                    u32::try_from(victim).unwrap_or(u32::MAX),
                    *operation,
                    0,
                ),
                action: ScenarioActionKind::RegionFault {
                    region: "ha-minority-region".to_string(),
                    nodes: vec![victim],
                    fault,
                },
            });
            *operation = operation.saturating_add(1);
            scenario.push(ScenarioAction {
                at: SimTime(base.saturating_add(550)),
                key: EventKey::new(
                    "ha-region-heal",
                    u32::try_from(victim).unwrap_or(u32::MAX),
                    *operation,
                    0,
                ),
                action: ScenarioActionKind::RegionFault {
                    region: "ha-minority-region".to_string(),
                    nodes: vec![victim],
                    fault: RegionFault::Heal,
                },
            });
            *operation = operation.saturating_add(1);
        }
        HaFaultPlan::DelayAndDuplicate => {
            let peer = usize::from(config.nodes > 2);
            push_link_fault(
                scenario,
                base,
                peer,
                victim,
                LinkFault::Delay { micros: 240 },
                operation,
            );
            push_link_fault(
                scenario,
                base.saturating_add(250),
                peer,
                victim,
                LinkFault::Duplicate { copies: 2 },
                operation,
            );
            push_link_fault(
                scenario,
                base.saturating_add(550),
                peer,
                victim,
                LinkFault::Heal,
                operation,
            );
        }
        HaFaultPlan::Corruption => {
            let peer = usize::from(config.nodes > 2);
            push_link_fault(
                scenario,
                base,
                peer,
                victim,
                LinkFault::Corrupt { xor: 0x80 },
                operation,
            );
            push_link_fault(
                scenario,
                base.saturating_add(550),
                peer,
                victim,
                LinkFault::Heal,
                operation,
            );
        }
        HaFaultPlan::ProcessPauseAndThrottle => {
            scenario.push(ScenarioAction {
                at: SimTime(base.saturating_add(50)),
                key: EventKey::new(
                    "ha-throttle",
                    u32::try_from(victim).unwrap_or(u32::MAX),
                    *operation,
                    0,
                ),
                action: ScenarioActionKind::NodeFault {
                    node: victim,
                    fault: NodeFault::Throttle { delay_micros: 200 },
                },
            });
            *operation = operation.saturating_add(1);
            scenario.push(ScenarioAction {
                at: SimTime(base.saturating_add(100)),
                key: EventKey::new(
                    "ha-pause",
                    u32::try_from(victim).unwrap_or(u32::MAX),
                    *operation,
                    0,
                ),
                action: ScenarioActionKind::NodeFault {
                    node: victim,
                    fault: NodeFault::Pause { micros: 450 },
                },
            });
            *operation = operation.saturating_add(1);
        }
        HaFaultPlan::GracefulRedeploy => {
            push_node_fault(
                scenario,
                base.saturating_add(50),
                victim,
                NodeFault::GracefulStop,
                "ha-graceful-stop",
                operation,
            );
            push_node_fault(
                scenario,
                base.saturating_add(550),
                victim,
                NodeFault::Restart,
                "ha-redeploy",
                operation,
            );
        }
        HaFaultPlan::CrashAfterConfirmation => {
            push_node_fault(
                scenario,
                base.saturating_add(350),
                victim,
                NodeFault::Crash,
                "ha-crash",
                operation,
            );
            push_node_fault(
                scenario,
                base.saturating_add(550),
                victim,
                NodeFault::Restart,
                "ha-restart",
                operation,
            );
        }
        HaFaultPlan::StorageDelay => {
            push_storage_fault(
                scenario,
                base.saturating_add(100),
                victim,
                StorageFault::Delay { micros: 300 },
                "ha-storage-delay",
                operation,
            );
            push_node_fault(
                scenario,
                base.saturating_add(100),
                victim,
                NodeFault::Throttle { delay_micros: 300 },
                "ha-storage-delay-throttle",
                operation,
            );
            push_storage_fault(
                scenario,
                base.saturating_add(550),
                victim,
                StorageFault::Healthy,
                "ha-storage-delay-heal",
                operation,
            );
        }
        HaFaultPlan::StorageFull => {
            schedule_storage_fault_window(scenario, base, victim, StorageFault::Full, operation);
        }
        HaFaultPlan::StorageIo => {
            schedule_storage_fault_window(scenario, base, victim, StorageFault::Io, operation);
        }
        HaFaultPlan::StorageFailure => {
            schedule_storage_fault_window(scenario, base, victim, StorageFault::Fsync, operation);
        }
        HaFaultPlan::StorageTornWrite => {
            schedule_storage_fault_window(
                scenario,
                base,
                victim,
                StorageFault::TornWrite { keep_bytes: 8 },
                operation,
            );
        }
        HaFaultPlan::StorageCorruption => {
            schedule_storage_fault_window(
                scenario,
                base,
                victim,
                StorageFault::Corrupt { xor: 0x80 },
                operation,
            );
        }
        HaFaultPlan::StorageDiskReplacement => {
            push_node_fault(
                scenario,
                base.saturating_add(90),
                victim,
                NodeFault::Crash,
                "ha-replace-disk-stop",
                operation,
            );
            schedule_storage_fault_window(
                scenario,
                base,
                victim,
                StorageFault::ReplaceDisk,
                operation,
            );
            push_node_fault(
                scenario,
                base.saturating_add(150),
                victim,
                NodeFault::Restart,
                "ha-replace-disk-redeploy",
                operation,
            );
        }
    }
}

fn push_node_fault(
    scenario: &mut Scenario,
    at: u64,
    node: usize,
    fault: NodeFault,
    domain: &'static str,
    operation: &mut u64,
) {
    scenario.push(ScenarioAction {
        at: SimTime(at),
        key: EventKey::new(
            domain,
            u32::try_from(node).unwrap_or(u32::MAX),
            *operation,
            0,
        ),
        action: ScenarioActionKind::NodeFault { node, fault },
    });
    *operation = operation.saturating_add(1);
}

fn push_storage_fault(
    scenario: &mut Scenario,
    at: u64,
    node: usize,
    fault: StorageFault,
    domain: &'static str,
    operation: &mut u64,
) {
    scenario.push(ScenarioAction {
        at: SimTime(at),
        key: EventKey::new(
            domain,
            u32::try_from(node).unwrap_or(u32::MAX),
            *operation,
            0,
        ),
        action: ScenarioActionKind::StorageFault { node, fault },
    });
    *operation = operation.saturating_add(1);
}

fn schedule_storage_fault_window(
    scenario: &mut Scenario,
    base: u64,
    node: usize,
    fault: StorageFault,
    operation: &mut u64,
) {
    push_storage_fault(
        scenario,
        base.saturating_add(100),
        node,
        fault,
        "ha-storage-fault",
        operation,
    );
    push_storage_fault(
        scenario,
        base.saturating_add(550),
        node,
        StorageFault::Healthy,
        "ha-storage-heal",
        operation,
    );
}

fn push_command(
    scenario: &mut Scenario,
    at: u64,
    node: usize,
    command: &HaCommand,
    operation: &mut u64,
) -> Result<(), BoxError> {
    scenario.push(ScenarioAction {
        at: SimTime(at),
        key: EventKey::new(
            "ha-client-command",
            u32::try_from(node).unwrap_or(u32::MAX),
            *operation,
            0,
        ),
        action: ScenarioActionKind::Client {
            source: node,
            target: node,
            client_id: node as u64,
            operation_id: *operation,
            payload: serde_json::to_vec(command)?,
        },
    });
    *operation = operation.saturating_add(1);
    Ok(())
}

fn push_link_fault(
    scenario: &mut Scenario,
    at: u64,
    source: usize,
    target: usize,
    fault: LinkFault,
    operation: &mut u64,
) {
    scenario.push(ScenarioAction {
        at: SimTime(at),
        key: EventKey::new(
            "ha-link-fault",
            u32::try_from(source).unwrap_or(u32::MAX),
            *operation,
            u32::try_from(target).unwrap_or(u32::MAX),
        ),
        action: ScenarioActionKind::LinkFault {
            source,
            target,
            fault,
        },
    });
    *operation = operation.saturating_add(1);
}

fn define_ha_properties(
    properties: &mut PropertyRegistry,
    fault_plan: HaFaultPlan,
    expect_amendment: bool,
    expect_reordered_sequences: bool,
) {
    properties.define("ha_unique_finality", PropertyKind::Always);
    properties.define("ha_historical_finality_is_stable", PropertyKind::Always);
    properties.define("ha_local_chain_is_contiguous", PropertyKind::Always);
    properties.define("ha_confirmation_has_majority", PropertyKind::Always);
    properties.define("ha_sealed_prefix_is_immutable", PropertyKind::Always);
    properties.define("ha_consensus_parameters_agree", PropertyKind::Always);
    properties.define(
        "ha_revision_hashes_agree_at_equal_heads",
        PropertyKind::Always,
    );
    properties.define("ha_application_is_exact_once", PropertyKind::Always);
    properties.define(
        "ha_application_hashes_agree_at_equal_heads",
        PropertyKind::Always,
    );
    properties.define("ha_service_mode_is_leaderless", PropertyKind::Always);
    properties.define("ha_service_status_is_actionable", PropertyKind::Always);
    if fault_plan == HaFaultPlan::None {
        properties.define("ha_strict_seal_barrier_passed", PropertyKind::Reachable);
    }
    properties.define("ha_progress_observed", PropertyKind::Reachable);
    properties.define(
        "ha_unknown_client_outcomes_resolved",
        PropertyKind::EventuallyAfterQuiescence,
    );
    properties.define(
        "ha_converged_after_quiescence",
        PropertyKind::EventuallyAfterQuiescence,
    );
    if expect_amendment {
        properties.define("ha_mutable_amendment_applied", PropertyKind::Reachable);
    }
    if expect_reordered_sequences {
        properties.define(
            "ha_reordered_client_sequences_applied",
            PropertyKind::Reachable,
        );
    }
    if fault_plan != HaFaultPlan::None {
        properties.define("ha_fault_effect_observed", PropertyKind::Sometimes);
        properties.define("ha_recovery_path_exercised", PropertyKind::Reachable);
    }
}

fn define_ha_properties_if_missing(
    properties: &mut PropertyRegistry,
    fault_plan: HaFaultPlan,
    expect_amendment: bool,
    expect_reordered_sequences: bool,
) {
    if properties.report().statuses.is_empty() {
        define_ha_properties(
            properties,
            fault_plan,
            expect_amendment,
            expect_reordered_sequences,
        );
    }
}

struct HaObserver {
    quiescence_time: SimTime,
    fault_plan: HaFaultPlan,
    expect_amendment: bool,
    expect_reordered_sequences: bool,
}

impl GlobalObserver<HaDeterministicNode> for HaObserver {
    fn observe(
        &mut self,
        view: ClusterView<'_, HaDeterministicNode>,
        properties: &mut PropertyRegistry,
    ) {
        define_ha_properties_if_missing(
            properties,
            self.fault_plan,
            self.expect_amendment,
            self.expect_reordered_sequences,
        );
        observe_ha(view, properties, self.quiescence_time);
    }
}

fn observe_ha(
    view: ClusterView<'_, HaDeterministicNode>,
    properties: &mut PropertyRegistry,
    quiescence_time: SimTime,
) {
    let mut by_nonce = BTreeMap::<u64, BTreeSet<HashType>>::new();
    let mut local_chain_valid = true;
    let mut confirmation_valid = true;
    let mut leaderless = true;
    let mut heads = BTreeSet::new();
    let mut max_nonce = 0u64;
    let mut failure_effect = false;
    let mut service_status_valid = true;
    let mut historical_finality_valid = true;
    let mut sealed_prefix_valid = true;
    let mut parameter_hashes = BTreeSet::new();
    let mut revisions_by_head = BTreeMap::<(u64, HashType), BTreeSet<HashType>>::new();
    let mut application_hashes_by_head = BTreeMap::<(u64, HashType), BTreeSet<HashType>>::new();
    let mut application_valid = true;
    let mut reordered_sequences_applied = false;
    let mut amendment_successes = 0u64;
    let mut recovery_successes = 0u64;
    let mut strict_seal_barrier_passed = false;
    for node in view.nodes {
        failure_effect |= node.rejected_messages > 0
            || node.command_failures > 0
            || node.injected_fault_observations > 0;
        historical_finality_valid &= !node.historical_conflict;
        sealed_prefix_valid &= !node.sealed_conflict;
        amendment_successes = amendment_successes.saturating_add(node.amendment_successes);
        recovery_successes = recovery_successes.saturating_add(node.recovery_successes);
        strict_seal_barrier_passed |=
            node.sealed_check_attempts > 0 && node.sealed_check_failures == 0;
        application_valid &= node.application_apply_failures == 0;
        reordered_sequences_applied |=
            node.application_results
                .keys()
                .any(|identity| identity.client_id == ClientId([0; 16]) && identity.sequence == 10)
                && node.application_results.keys().any(|identity| {
                    identity.client_id == ClientId([0; 16]) && identity.sequence == 11
                });
        for (nonce, hash) in &node.finalized {
            by_nonce.entry(*nonce).or_default().insert(*hash);
        }
        let Some(runtime) = node.runtime() else {
            continue;
        };
        leaderless &= runtime.replication_mode() == HaReplicationMode::LeaderlessActiveActive;
        service_status_valid &= runtime.operational_status().is_ok_and(|status| {
            let threshold = high_availability_majority(usize::from(status.active_nodes)) as u8;
            let unavailable = matches!(
                status.health,
                blossom::HaServiceHealth::Unavailable | blossom::HaServiceHealth::Suspended
            );
            status.required_nodes == threshold
                && status.strict_reads_through == runtime.sealed_watermark()
                && (!unavailable || !status.accepts_writes)
                && (!unavailable
                    || status
                        .directives
                        .contains(&blossom::HaServiceDirective::DrainWrites))
        });
        heads.insert((runtime.head().nonce.value(), runtime.head().hash));
        max_nonce = max_nonce.max(runtime.head().nonce.value());
        parameter_hashes.insert(runtime.parameters_hash());
        if let Ok(revision) = runtime.revision() {
            revisions_by_head
                .entry((runtime.head().nonce.value(), runtime.head().hash))
                .or_default()
                .insert(revision.revision_hash);
        }
        application_hashes_by_head
            .entry((runtime.head().nonce.value(), runtime.head().hash))
            .or_default()
            .insert(node.application_hash);
        for epoch in runtime.epochs() {
            if epoch.nonce != Nonce::default() {
                confirmation_valid &= epoch.confirmation_mask.count_ones() as usize
                    >= high_availability_majority(epoch.active_mask.count_ones() as usize);
            }
        }
        local_chain_valid &= runtime.epochs().windows(2).all(|window| {
            window[1].previous_epoch_hash == window[0].hash
                && window[1].previous_epoch_nonce == Some(window[0].nonce)
                && window[1].nonce == window[0].nonce.new_next()
        });
    }
    properties.observe(
        "ha_unique_finality",
        view.now,
        by_nonce.values().all(|hashes| hashes.len() <= 1),
        "no two healthy nodes may finalize different hashes at one nonce",
    );
    properties.observe(
        "ha_historical_finality_is_stable",
        view.now,
        historical_finality_valid,
        "a finalized nonce must never change, including while its node is crashed",
    );
    properties.observe(
        "ha_local_chain_is_contiguous",
        view.now,
        local_chain_valid,
        "every local finalized chain binds the previous hash and nonce",
    );
    properties.observe(
        "ha_confirmation_has_majority",
        view.now,
        confirmation_valid,
        "every non-genesis HA epoch carries a strict-majority confirmation mask",
    );
    properties.observe(
        "ha_sealed_prefix_is_immutable",
        view.now,
        sealed_prefix_valid,
        "a sealed epoch hash must remain immutable across amendments and restart",
    );
    properties.observe(
        "ha_consensus_parameters_agree",
        view.now,
        parameter_hashes.len() <= 1,
        "all running members must use the same committed HA parameter hash",
    );
    properties.observe(
        "ha_revision_hashes_agree_at_equal_heads",
        view.now,
        revisions_by_head
            .values()
            .all(|revisions| revisions.len() <= 1),
        "nodes at the same immutable head must expose the same application revision",
    );
    properties.observe(
        "ha_application_is_exact_once",
        view.now,
        application_valid,
        "certified application commands, duplicate retries, and reordered sequences must apply exactly once",
    );
    properties.observe(
        "ha_application_hashes_agree_at_equal_heads",
        view.now,
        application_hashes_by_head
            .values()
            .all(|hashes| hashes.len() <= 1),
        "nodes at one certified head must rebuild the same application state hash",
    );
    properties.observe(
        "ha_service_mode_is_leaderless",
        view.now,
        leaderless,
        "HA runtime must remain leaderless active-active",
    );
    properties.observe(
        "ha_service_status_is_actionable",
        view.now,
        service_status_valid,
        "HA status must expose a correct threshold, sealed watermark, and safe service directives",
    );
    if properties
        .report()
        .statuses
        .contains_key("ha_strict_seal_barrier_passed")
    {
        properties.observe(
            "ha_strict_seal_barrier_passed",
            view.now,
            strict_seal_barrier_passed,
            "a strict operation must pass after its required watermark is sealed",
        );
    }
    properties.observe(
        "ha_progress_observed",
        view.now,
        max_nonce > 0,
        "at least one HA epoch finalized",
    );
    if properties
        .report()
        .statuses
        .contains_key("ha_mutable_amendment_applied")
    {
        properties.observe(
            "ha_mutable_amendment_applied",
            view.now,
            amendment_successes > 0,
            "a mutable logical epoch amendment must be accepted and incorporated",
        );
    }
    if properties
        .report()
        .statuses
        .contains_key("ha_reordered_client_sequences_applied")
    {
        properties.observe(
            "ha_reordered_client_sequences_applied",
            view.now,
            reordered_sequences_applied,
            "client sequence eleven followed by ten must both execute exactly once",
        );
    }
    if properties
        .report()
        .statuses
        .contains_key("ha_recovery_path_exercised")
    {
        properties.observe(
            "ha_recovery_path_exercised",
            view.now,
            recovery_successes > 0,
            "a faulted member must install a peer recovery snapshot",
        );
    }
    if view.now >= quiescence_time {
        let running = view
            .lifecycle
            .iter()
            .filter(|lifecycle| **lifecycle == deterministic_test_env::NodeLifecycle::Running)
            .count();
        properties.observe(
            "ha_converged_after_quiescence",
            view.now,
            running > 0 && heads.len() <= 1,
            "all running nodes converge after faults are removed",
        );
        properties.observe(
            "ha_unknown_client_outcomes_resolved",
            view.now,
            unknown_ha_outcomes_resolved(view.client_history, view.nodes),
            "unknown responses must be resolved from finalized/sealed state or an idempotent recovery action",
        );
    }
    if properties
        .report()
        .statuses
        .contains_key("ha_fault_effect_observed")
    {
        properties.observe(
            "ha_fault_effect_observed",
            view.now,
            failure_effect
                || view
                    .lifecycle
                    .iter()
                    .any(|lifecycle| *lifecycle != deterministic_test_env::NodeLifecycle::Running),
            "the injected fault must affect delivery, persistence, or lifecycle",
        );
    }
}

fn unknown_ha_outcomes_resolved(
    history: &[deterministic_test_env::ClientHistoryEvent],
    nodes: &[HaDeterministicNode],
) -> bool {
    let invocations = history
        .iter()
        .filter_map(|event| match event {
            deterministic_test_env::ClientHistoryEvent::Invoke {
                source,
                operation_id,
                payload,
                ..
            } => serde_json::from_slice::<HaCommand>(payload)
                .ok()
                .map(|command| (*operation_id, (*source, command))),
            deterministic_test_env::ClientHistoryEvent::Complete { .. } => None,
        })
        .collect::<BTreeMap<_, _>>();
    let minimum_head = nodes
        .iter()
        .filter_map(HaDeterministicNode::runtime)
        .map(|runtime| runtime.head().nonce.value())
        .min()
        .unwrap_or_default();
    let minimum_sealed = nodes
        .iter()
        .filter_map(HaDeterministicNode::runtime)
        .map(|runtime| runtime.sealed_watermark().position)
        .min()
        .unwrap_or_default();
    history.iter().all(|event| {
        let deterministic_test_env::ClientHistoryEvent::Complete {
            operation_id,
            outcome: ClientOutcome::Unknown,
            ..
        } = event
        else {
            return true;
        };
        let Some((source, command)) = invocations.get(operation_id) else {
            return false;
        };
        match command {
            HaCommand::Dispatch { expected_nonce, .. }
            | HaCommand::Acknowledge { expected_nonce }
            | HaCommand::Confirm { expected_nonce } => minimum_head >= *expected_nonce,
            HaCommand::Amend { expected_nonce, .. } => {
                minimum_head >= *expected_nonce
                    && nodes
                        .get(*source)
                        .is_some_and(|node| node.amendment_successes > 0)
            }
            HaCommand::RequireSealed { required_nonce } => minimum_sealed >= *required_nonce,
            HaCommand::RecoverFrom { .. } => nodes
                .get(*source)
                .is_some_and(|node| node.recovery_successes > 0),
            HaCommand::Status => true,
        }
    })
}

pub fn run_deterministic_campaign(
    profile: DeterministicCampaignProfile,
    seed: u64,
) -> Result<DeterministicCampaignReport, BoxError> {
    run_deterministic_campaign_with_observer(profile, seed, |_| {})
}

pub fn run_deterministic_campaign_with_telemetry(
    profile: DeterministicCampaignProfile,
    seed: u64,
    telemetry: &TelemetryHandle,
) -> Result<DeterministicCampaignReport, BoxError> {
    telemetry.record(
        TelemetryEvent::new(TelemetryEventKind::Event, "simulation", "campaign_started")
            .with_outcome("ok")
            .with_field("profile", profile.as_str())
            .with_field("seed", seed.to_string()),
    );
    let report = run_deterministic_campaign_with_observer(profile, seed, |cell| {
        telemetry.record(protocol_cell_telemetry(cell));
    })?;
    telemetry.record(
        TelemetryEvent::new(
            TelemetryEventKind::Event,
            "simulation",
            "campaign_completed",
        )
        .with_outcome(if report.safety_passed { "ok" } else { "failed" })
        .with_field("profile", profile.as_str())
        .with_field("seed", seed.to_string())
        .with_field("cells", report.cells.len().to_string())
        .with_field("events", report.total_events.to_string())
        .with_field("schedules", report.total_schedules.to_string()),
    );
    Ok(report)
}

pub fn run_deterministic_campaign_with_observer(
    profile: DeterministicCampaignProfile,
    seed: u64,
    mut observer: impl FnMut(&ProtocolCellReport),
) -> Result<DeterministicCampaignReport, BoxError> {
    let (epochs, schedules, include_durable, fault_depth, faults): (
        usize,
        usize,
        bool,
        u8,
        &[HaFaultPlan],
    ) = match profile {
        DeterministicCampaignProfile::Pr => (
            10,
            200,
            true,
            1,
            &[
                HaFaultPlan::None,
                HaFaultPlan::AsymmetricPartition,
                HaFaultPlan::RegionalPartition,
                HaFaultPlan::GracefulRedeploy,
                HaFaultPlan::StorageFull,
                HaFaultPlan::StorageFailure,
                HaFaultPlan::StorageDiskReplacement,
            ],
        ),
        DeterministicCampaignProfile::Novelty => (
            11,
            8,
            true,
            2,
            &[
                HaFaultPlan::None,
                HaFaultPlan::AsymmetricPartition,
                HaFaultPlan::MinorityPartition,
                HaFaultPlan::RegionalPartition,
                HaFaultPlan::RegionalOutage,
                HaFaultPlan::DelayAndDuplicate,
                HaFaultPlan::Corruption,
                HaFaultPlan::ProcessPauseAndThrottle,
                HaFaultPlan::GracefulRedeploy,
                HaFaultPlan::CrashAfterConfirmation,
                HaFaultPlan::StorageDelay,
                HaFaultPlan::StorageFull,
                HaFaultPlan::StorageIo,
                HaFaultPlan::StorageFailure,
                HaFaultPlan::StorageTornWrite,
                HaFaultPlan::StorageCorruption,
                HaFaultPlan::StorageDiskReplacement,
            ],
        ),
        DeterministicCampaignProfile::Nightly => (
            1_200,
            1,
            true,
            2,
            &[
                HaFaultPlan::None,
                HaFaultPlan::AsymmetricPartition,
                HaFaultPlan::MinorityPartition,
                HaFaultPlan::RegionalPartition,
                HaFaultPlan::RegionalOutage,
                HaFaultPlan::DelayAndDuplicate,
                HaFaultPlan::Corruption,
                HaFaultPlan::ProcessPauseAndThrottle,
                HaFaultPlan::GracefulRedeploy,
                HaFaultPlan::CrashAfterConfirmation,
                HaFaultPlan::StorageDelay,
                HaFaultPlan::StorageFull,
                HaFaultPlan::StorageIo,
                HaFaultPlan::StorageFailure,
                HaFaultPlan::StorageTornWrite,
                HaFaultPlan::StorageCorruption,
                HaFaultPlan::StorageDiskReplacement,
            ],
        ),
        DeterministicCampaignProfile::Release => (
            10_000,
            1,
            true,
            3,
            &[
                HaFaultPlan::None,
                HaFaultPlan::AsymmetricPartition,
                HaFaultPlan::MinorityPartition,
                HaFaultPlan::RegionalPartition,
                HaFaultPlan::RegionalOutage,
                HaFaultPlan::DelayAndDuplicate,
                HaFaultPlan::Corruption,
                HaFaultPlan::ProcessPauseAndThrottle,
                HaFaultPlan::GracefulRedeploy,
                HaFaultPlan::CrashAfterConfirmation,
                HaFaultPlan::StorageDelay,
                HaFaultPlan::StorageFull,
                HaFaultPlan::StorageIo,
                HaFaultPlan::StorageFailure,
                HaFaultPlan::StorageTornWrite,
                HaFaultPlan::StorageCorruption,
                HaFaultPlan::StorageDiskReplacement,
            ],
        ),
    };
    let mut cells = Vec::new();
    let node_counts: Vec<usize> = match profile {
        DeterministicCampaignProfile::Pr | DeterministicCampaignProfile::Novelty => {
            vec![2, 3, 5, 7]
        }
        DeterministicCampaignProfile::Nightly | DeterministicCampaignProfile::Release => {
            (2..=7).collect()
        }
    };
    for nodes in node_counts {
        for durable in [false, true] {
            if durable && !include_durable {
                continue;
            }
            for fault_plan in faults {
                if !durable
                    && (*fault_plan == HaFaultPlan::CrashAfterConfirmation
                        || is_storage_fault(*fault_plan))
                {
                    continue;
                }
                let cell = run_ha_deterministic(HaDeterministicConfig {
                    nodes,
                    epochs,
                    seed: seed ^ nodes as u64 ^ ((*fault_plan as u64) << 32),
                    durable,
                    fault_plan: *fault_plan,
                    fault_depth,
                    systematic_schedules: 1,
                    max_events: epochs.saturating_mul(nodes).saturating_mul(64).max(10_000),
                })?;
                observer(&cell);
                cells.push(cell);
                let systematic = match profile {
                    DeterministicCampaignProfile::Pr => {
                        !durable && *fault_plan == HaFaultPlan::AsymmetricPartition
                    }
                    DeterministicCampaignProfile::Novelty => *fault_plan != HaFaultPlan::None,
                    DeterministicCampaignProfile::Nightly
                    | DeterministicCampaignProfile::Release => *fault_plan != HaFaultPlan::None,
                };
                if systematic {
                    let companion_schedules = match (profile, durable) {
                        (DeterministicCampaignProfile::Pr, _) => schedules,
                        (DeterministicCampaignProfile::Novelty, false) => schedules,
                        (DeterministicCampaignProfile::Novelty, true) => 2,
                        (DeterministicCampaignProfile::Nightly, false) => 16,
                        (DeterministicCampaignProfile::Nightly, true) => 4,
                        (DeterministicCampaignProfile::Release, false) => 64,
                        (DeterministicCampaignProfile::Release, true) => 16,
                    };
                    let companion_epochs = match profile {
                        DeterministicCampaignProfile::Pr => 2,
                        DeterministicCampaignProfile::Novelty => 11,
                        DeterministicCampaignProfile::Nightly
                        | DeterministicCampaignProfile::Release => 11,
                    };
                    let companion = run_ha_deterministic(HaDeterministicConfig {
                        nodes,
                        epochs: companion_epochs,
                        seed: seed
                            ^ nodes as u64
                            ^ ((*fault_plan as u64) << 32)
                            ^ 0x7379_7374_656d_6174,
                        durable,
                        fault_plan: *fault_plan,
                        fault_depth,
                        systematic_schedules: companion_schedules,
                        max_events: 10_000,
                    })?;
                    observer(&companion);
                    cells.push(companion);
                }
            }
        }
    }

    let trusted_epochs = match profile {
        DeterministicCampaignProfile::Pr | DeterministicCampaignProfile::Novelty => 50,
        DeterministicCampaignProfile::Nightly => 1_200,
        DeterministicCampaignProfile::Release => 10_000,
    };
    for nodes in match profile {
        DeterministicCampaignProfile::Pr | DeterministicCampaignProfile::Novelty => vec![6, 9],
        DeterministicCampaignProfile::Nightly | DeterministicCampaignProfile::Release => {
            vec![6, 9, 12, 24, 72]
        }
    } {
        let config = EpochChaosConfig {
            nodes,
            epochs: trusted_epochs,
            seed: seed ^ nodes as u64 ^ 0x7472_7573_7465_6400,
            trust_mode: TrustMode::Trusted,
            drop_ppm: 5_000,
            jitter_ms: 10,
            repair_rounds: 4,
            repair_fanout: nodes,
            repair_quorum: supermajority_count(nodes),
            partition_start_epoch: (trusted_epochs > 100).then_some(trusted_epochs / 3),
            partition_end_epoch: (trusted_epochs > 100).then_some(trusted_epochs / 3 + 25),
            partition_left_nodes: if nodes >= 9 { nodes / 3 } else { 1 },
            ..EpochChaosConfig::default()
        };
        let report = run_epoch_chaos(config.clone())?;
        let replay = run_epoch_chaos(config)?;
        let replay_passed = report.final_correct_epoch_hash == replay.final_correct_epoch_hash
            && report.final_correct_epoch_nonce == replay.final_correct_epoch_nonce
            && report.final_unique_epoch_hashes == replay.final_unique_epoch_hashes
            && report.incorrectly_lost_local_blocks == replay.incorrectly_lost_local_blocks
            && report.total_messages == replay.total_messages;
        let safety_passed = report.final_unique_epoch_hashes == 1
            && report.final_incorrect_nodes == 0
            && report.incorrectly_lost_local_blocks == 0
            && replay_passed;
        let cell = ProtocolCellReport {
            protocol: "blossom-trusted-global".to_string(),
            topology: format!("{nodes}-node-q6-model"),
            epochs: trusted_epochs,
            schedules: 1,
            unique_states: 1,
            events: report.total_messages as usize,
            safety_passed,
            replay_passed,
            property_failures: if safety_passed {
                Vec::new()
            } else {
                vec![format!(
                    "trusted convergence/loss/replay failure: hashes={}, incorrect={}, lost={}, replay={replay_passed}",
                    report.final_unique_epoch_hashes,
                    report.final_incorrect_nodes,
                    report.incorrectly_lost_local_blocks
                )]
            },
            final_state_digest: report.final_correct_epoch_hash.to_string(),
            scenario: None,
            replay_manifest: None,
            minimized: None,
            trace: None,
        };
        observer(&cell);
        cells.push(cell);
    }
    #[cfg(feature = "trusted-checkpoint-dag")]
    {
        let dag_epochs = match profile {
            DeterministicCampaignProfile::Pr | DeterministicCampaignProfile::Novelty => 50,
            DeterministicCampaignProfile::Nightly => 1_200,
            DeterministicCampaignProfile::Release => 10_000,
        };
        let dag_cells: &[(usize, usize)] = match profile {
            DeterministicCampaignProfile::Pr | DeterministicCampaignProfile::Novelty => {
                &[(6, 3), (6, 6), (9, 3), (9, 6), (9, 9)]
            }
            DeterministicCampaignProfile::Nightly | DeterministicCampaignProfile::Release => &[
                (6, 3),
                (6, 6),
                (9, 3),
                (9, 6),
                (9, 9),
                (12, 6),
                (12, 9),
                (24, 6),
                (24, 9),
                (72, 6),
                (1_002, 6),
            ],
        };
        for (nodes, quorum) in dag_cells {
            let quorum_size = QuorumSize::new(*quorum)?;
            let first = run_sequential_quorum_dag_experiment(*nodes, quorum_size, 1_024, true)?;
            let replay = run_sequential_quorum_dag_experiment(*nodes, quorum_size, 1_024, true)?;
            let first_chain = run_trusted_checkpoint_chain(*nodes, quorum_size, dag_epochs, seed)?;
            let replay_chain = run_trusted_checkpoint_chain(*nodes, quorum_size, dag_epochs, seed)?;
            let replay_passed = first.final_order_root == replay.final_order_root
                && first.finalized_vertex_count == replay.finalized_vertex_count
                && first.all_nodes_converged == replay.all_nodes_converged
                && first_chain == replay_chain;
            let safety_passed = first.all_nodes_converged
                && first.finalized_vertex_count == *nodes
                && first_chain.checkpoints == dag_epochs
                && replay_passed;
            let cell = ProtocolCellReport {
                protocol: "blossom-trusted-checkpoint-dag".to_string(),
                topology: format!("{nodes}-node-q{quorum}-model-core"),
                epochs: dag_epochs,
                schedules: 2,
                unique_states: dag_epochs,
                events: first
                    .candidate_vertex_occurrences
                    .try_into()
                    .unwrap_or(usize::MAX)
                    .saturating_add(first_chain.events),
                safety_passed,
                replay_passed,
                property_failures: if safety_passed {
                    Vec::new()
                } else {
                    vec!["trusted checkpoint DAG failed convergence or replay".to_string()]
                },
                final_state_digest: first_chain.final_checkpoint_hash.to_string(),
                scenario: None,
                replay_manifest: None,
                minimized: None,
                trace: None,
            };
            observer(&cell);
            cells.push(cell);
        }
    }
    #[cfg(feature = "parallel-networks")]
    {
        let ha_sizes: Vec<usize> = match profile {
            DeterministicCampaignProfile::Pr | DeterministicCampaignProfile::Novelty => {
                vec![2, 3, 5, 7]
            }
            DeterministicCampaignProfile::Nightly | DeterministicCampaignProfile::Release => {
                (2..=7).collect()
            }
        };
        let global_sizes: &[usize] = match profile {
            DeterministicCampaignProfile::Pr | DeterministicCampaignProfile::Novelty => &[6],
            DeterministicCampaignProfile::Nightly | DeterministicCampaignProfile::Release => {
                &[6, 12]
            }
        };
        let parallel_epochs = match profile {
            DeterministicCampaignProfile::Pr | DeterministicCampaignProfile::Novelty => 10,
            DeterministicCampaignProfile::Nightly => 1_200,
            DeterministicCampaignProfile::Release => 10_000,
        };
        for ha_nodes in ha_sizes {
            for global_nodes in global_sizes {
                let first =
                    run_parallel_network_cell(ha_nodes, *global_nodes, parallel_epochs, seed)?;
                let replay =
                    run_parallel_network_cell(ha_nodes, *global_nodes, parallel_epochs, seed)?;
                let replay_passed = first == replay;
                let safety_passed = first.safety_passed && replay_passed;
                let cell = ProtocolCellReport {
                    protocol: "blossom-parallel-ha-global".to_string(),
                    topology: format!("ha-{ha_nodes}-global-{global_nodes}-q6"),
                    epochs: first.ha_epochs,
                    schedules: 2,
                    unique_states: 2,
                    events: first.events,
                    safety_passed,
                    replay_passed,
                    property_failures: if safety_passed {
                        Vec::new()
                    } else {
                        vec!["parallel HA/Global Blossom independence or replay failed".to_string()]
                    },
                    final_state_digest: first.state_digest.to_string(),
                    scenario: None,
                    replay_manifest: None,
                    minimized: None,
                    trace: None,
                };
                observer(&cell);
                cells.push(cell);
            }
        }
    }
    let total_events = cells.iter().map(|cell| cell.events).sum();
    let total_schedules = cells.iter().map(|cell| cell.schedules).sum();
    let safety_passed = cells
        .iter()
        .all(|cell| cell.safety_passed && cell.replay_passed);
    Ok(DeterministicCampaignReport {
        profile,
        cells,
        total_events,
        total_schedules,
        safety_passed,
    })
}

fn is_storage_fault(fault: HaFaultPlan) -> bool {
    matches!(
        fault,
        HaFaultPlan::StorageDelay
            | HaFaultPlan::StorageFull
            | HaFaultPlan::StorageIo
            | HaFaultPlan::StorageFailure
            | HaFaultPlan::StorageTornWrite
            | HaFaultPlan::StorageCorruption
            | HaFaultPlan::StorageDiskReplacement
    )
}

fn protocol_cell_telemetry(cell: &ProtocolCellReport) -> TelemetryEvent {
    let mut event = TelemetryEvent::new(
        TelemetryEventKind::Event,
        "simulation",
        "protocol_cell_completed",
    )
    .with_outcome(if cell.safety_passed && cell.replay_passed {
        "ok"
    } else {
        "failed"
    })
    .with_field("protocol", cell.protocol.clone())
    .with_field("topology", cell.topology.clone())
    .with_field("epochs", cell.epochs.to_string())
    .with_field("schedules", cell.schedules.to_string())
    .with_field("unique_states", cell.unique_states.to_string())
    .with_field("events", cell.events.to_string())
    .with_field("safety_passed", cell.safety_passed.to_string())
    .with_field("replay_passed", cell.replay_passed.to_string())
    .with_field("final_state_digest", cell.final_state_digest.clone());
    if !cell.property_failures.is_empty() {
        event = event.with_field("property_failures", cell.property_failures.join(" | "));
    }
    event
}

#[cfg(feature = "trusted-checkpoint-dag")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustedCheckpointChainResult {
    checkpoints: usize,
    events: usize,
    final_checkpoint_hash: HashType,
}

#[cfg(feature = "trusted-checkpoint-dag")]
fn run_trusted_checkpoint_chain(
    nodes: usize,
    quorum_size: QuorumSize,
    checkpoints: usize,
    seed: u64,
) -> Result<TrustedCheckpointChainResult, BoxError> {
    let members = (0..nodes)
        .map(|index| {
            let mut secret = [0u8; 32];
            secret[..8].copy_from_slice(&seed.to_le_bytes());
            secret[8..16].copy_from_slice(&(index as u64).to_le_bytes());
            secret[16..24].copy_from_slice(
                &seed
                    .rotate_left(u32::try_from(index % 63 + 1).unwrap_or(1))
                    .to_le_bytes(),
            );
            secret[24..]
                .copy_from_slice(&(seed ^ index as u64 ^ 0x6461_675f_6368_6169).to_le_bytes());
            Keypair::from_secret(SecKey(secret)).public
        })
        .collect::<Vec<_>>();
    let group_id = ConsensusGroupId::named(format!("deterministic-dag-chain-{nodes}-{seed}"));
    let mut dag = blossom::TrustedCheckpointDag::new(
        members[0],
        members.clone(),
        group_id,
        1,
        quorum_size,
        false,
    )?;
    let mut origin_sequences = vec![0u64; nodes];
    let mut origin_parents = vec![None; nodes];
    let mut events = 0usize;
    for checkpoint_index in 0..checkpoints {
        let origin_index = checkpoint_index % nodes;
        origin_sequences[origin_index] = origin_sequences[origin_index].saturating_add(1);
        let vertex = blossom::TrustedDagVertex::new(blossom::TrustedDagVertexBody {
            group_id,
            membership_generation: dag.head().body.membership_generation,
            origin: members[origin_index],
            origin_sequence: origin_sequences[origin_index],
            origin_parent: origin_parents[origin_index],
            anchor_checkpoint_hash: dag.head().hash,
            anchor_checkpoint_nonce: dag.head().body.nonce,
            payload_root: HashType::hash(
                format!("dag-chain-{seed}-{checkpoint_index}-{origin_index}").as_bytes(),
            ),
            command_count: 1,
            byte_length: 32,
        })?;
        if dag.ingest_vertex(vertex.clone())?
            != (blossom::TrustedDagIngestOutcome::Stored { activated: 1 })
        {
            return Err("trusted checkpoint-chain vertex was not activated".into());
        }
        let candidate = dag.build_candidate([vertex.hash])?;
        let mut round = 0u8;
        loop {
            let expected = dag.expected_round_members(round)?;
            let threshold = supermajority_count(expected.len());
            for member in expected.iter().take(threshold) {
                dag.record_acknowledgement(round, *member, candidate.clone())?;
            }
            let lock = dag
                .try_lock_round(round)?
                .ok_or("trusted checkpoint-chain round failed to lock")?;
            for member in expected.iter().take(threshold) {
                dag.record_confirmation(round, *member, lock.candidate.digest)?;
            }
            events = events.saturating_add(threshold.saturating_mul(2));
            match dag.try_complete_round(round)? {
                blossom::TrustedDagRoundCompletion::Advanced { next_round } => {
                    round = next_round;
                }
                blossom::TrustedDagRoundCompletion::Finalized {
                    checkpoint,
                    ordered_vertices,
                } if ordered_vertices == vec![vertex.hash]
                    && checkpoint.body.nonce
                        == Nonce::new(
                            u64::try_from(checkpoint_index)
                                .unwrap_or(u64::MAX)
                                .saturating_add(1),
                        ) =>
                {
                    origin_parents[origin_index] = Some(vertex.hash);
                    break;
                }
                completion => {
                    return Err(format!(
                        "trusted checkpoint-chain round failed or reordered its vertex: {completion:?}"
                    )
                    .into());
                }
            }
        }
        events = events.saturating_add(1);
    }
    Ok(TrustedCheckpointChainResult {
        checkpoints,
        events,
        final_checkpoint_hash: dag.head().hash,
    })
}

#[cfg(feature = "parallel-networks")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParallelNetworkCellResult {
    ha_epochs: usize,
    events: usize,
    state_digest: HashType,
    safety_passed: bool,
}

#[cfg(feature = "parallel-networks")]
fn run_parallel_network_cell(
    ha_nodes: usize,
    global_nodes: usize,
    ha_epoch_target: usize,
    seed: u64,
) -> Result<ParallelNetworkCellResult, BoxError> {
    let scope = ConsensusGroupId::named(format!(
        "deterministic-parallel-global-{global_nodes}-{seed}"
    ));
    let ha_group = ConsensusGroupId::named(format!("deterministic-parallel-ha-{ha_nodes}-{seed}"));
    let ha_identities = deterministic_identities(ha_nodes, seed ^ 0x6861_5f70_6172_0000);
    let mut ha_runtimes = ha_identities
        .iter()
        .map(|identity| {
            HighAvailabilityRuntime::new(
                ha_group,
                identity.public_key(),
                ha_identities.clone(),
                HighAvailabilityParameters::default(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let registration = HaGroupRegistration::from_runtime(scope, &ha_runtimes[0])?;

    let global_identities = deterministic_identities(global_nodes, seed ^ 0x676c_6f62_616c_0000);
    let global_members = global_identities
        .iter()
        .map(NodeIdentity::public_key)
        .collect::<Vec<_>>();
    if registration
        .members
        .iter()
        .any(|member| global_members.contains(member))
    {
        return Err("parallel HA and Global Blossom identities must remain disjoint".into());
    }
    let mut dag = TrustedCheckpointDag::new(
        global_members[0],
        global_members.clone(),
        scope,
        1,
        QuorumSize::new(6)?,
        false,
    )?;
    let mut coordinator = ParallelNetworkCoordinator::new(scope);
    let registration_event = ParallelNetworkEvent::RegisterHaGroup(registration.clone());
    let registration_vertex =
        parallel_event_vertex(&dag, global_members[0], 1, None, &registration_event)?;
    let registration_vertex_hash = registration_vertex.hash;
    let (registration_checkpoint, registration_order) =
        finalize_parallel_vertex(&mut dag, registration_vertex)?;
    coordinator.apply_global_checkpoint(
        &dag,
        &registration_checkpoint,
        &registration_order,
        &BTreeMap::from([(registration_vertex_hash, registration_event.clone())]),
    )?;

    let sealing_epochs = usize::try_from(
        HighAvailabilityParameters::default()
            .mutable_epoch_depth
            .saturating_add(1),
    )
    .unwrap_or(usize::MAX);
    let ha_epoch_target = ha_epoch_target.max(sealing_epochs.saturating_add(1));
    for epoch in 0..sealing_epochs {
        finalize_parallel_ha_epoch(&mut ha_runtimes, epoch)?;
    }
    let ha_head_before_global = ha_runtimes[0].head().clone();
    let reference = HaGroupStateReference::from_runtime(
        &registration,
        &ha_runtimes[0],
        HashType::hash(format!("parallel-state-{seed}").as_bytes()),
        None,
    )?;
    let state_event = ParallelNetworkEvent::PublishHaState(Box::new(reference.clone()));
    let state_vertex = parallel_event_vertex(
        &dag,
        global_members[0],
        2,
        Some(registration_vertex_hash),
        &state_event,
    )?;
    let state_vertex_hash = state_vertex.hash;
    let (state_checkpoint, state_order) = finalize_parallel_vertex(&mut dag, state_vertex)?;
    coordinator.apply_global_checkpoint(
        &dag,
        &state_checkpoint,
        &state_order,
        &BTreeMap::from([(state_vertex_hash, state_event)]),
    )?;
    let global_head_before_ha_only = dag.head().clone();

    // A Global Blossom outage must not stop an HA group that still has its
    // own majority. No Global event is scheduled while this epoch finalizes.
    for epoch in sealing_epochs..ha_epoch_target {
        finalize_parallel_ha_epoch(&mut ha_runtimes, epoch)?;
    }
    let ha_advanced_independently = ha_runtimes[0].head().nonce > ha_head_before_global.nonce
        && dag.head() == &global_head_before_ha_only;
    let ha_head_before_global_only = ha_runtimes[0].head().clone();

    // An HA-group outage must not stop Global Blossom. Reapplying its immutable
    // registration is an idempotent global coordination event.
    let repeat_registration = ParallelNetworkEvent::RegisterHaGroup(registration.clone());
    let repeat_vertex = parallel_event_vertex(
        &dag,
        global_members[0],
        3,
        Some(state_vertex_hash),
        &repeat_registration,
    )?;
    let repeat_vertex_hash = repeat_vertex.hash;
    let (repeat_checkpoint, repeat_order) = finalize_parallel_vertex(&mut dag, repeat_vertex)?;
    coordinator.apply_global_checkpoint(
        &dag,
        &repeat_checkpoint,
        &repeat_order,
        &BTreeMap::from([(repeat_vertex_hash, repeat_registration)]),
    )?;
    let global_advanced_independently = dag.head().body.nonce == Nonce::new(3)
        && ha_runtimes[0].head().nonce == ha_head_before_global_only.nonce
        && ha_runtimes[0].head().hash == ha_head_before_global_only.hash;

    let snapshot = coordinator.snapshot()?;
    let restored = ParallelNetworkCoordinator::from_snapshot(snapshot.clone())?;
    let state_digest = HashType::hash(&serde_json::to_vec(&(
        snapshot.hash,
        restored.status(),
        ha_runtimes[0].head().hash,
        dag.head().hash,
    ))?);
    let safety_passed = registration.members.len() == ha_nodes
        && global_members.len() == global_nodes
        && coordinator.status().registered_ha_groups == 1
        && coordinator.status().ha_groups_with_global_state == 1
        && coordinator.state_head(ha_group) == Some(&reference)
        && restored.status() == coordinator.status()
        && ha_advanced_independently
        && global_advanced_independently;
    Ok(ParallelNetworkCellResult {
        ha_epochs: ha_epoch_target,
        events: ha_epoch_target
            .saturating_mul(ha_nodes)
            .saturating_mul(ha_nodes)
            .saturating_mul(3)
            .saturating_add(3usize.saturating_mul(global_nodes)),
        state_digest,
        safety_passed,
    })
}

#[cfg(feature = "parallel-networks")]
fn finalize_parallel_ha_epoch(
    runtimes: &mut [HighAvailabilityRuntime],
    epoch: usize,
) -> Result<(), BoxError> {
    let dispatches = (0..runtimes.len())
        .map(|index| {
            runtimes[index].build_dispatch_at(
                vec![Transaction::new(format!("parallel-ha-{epoch}-{index}"))],
                epoch as u128,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    for (sender, dispatch) in dispatches.iter().enumerate() {
        for (receiver, runtime) in runtimes.iter_mut().enumerate() {
            if receiver != sender {
                runtime.receive_dispatch(dispatch.clone())?;
            }
        }
    }
    let acknowledgements = (0..runtimes.len())
        .map(|index| runtimes[index].acknowledge())
        .collect::<Result<Vec<_>, _>>()?;
    for (sender, acknowledgement) in acknowledgements.iter().enumerate() {
        for (receiver, runtime) in runtimes.iter_mut().enumerate() {
            if receiver != sender {
                runtime.receive_acknowledgement(acknowledgement.clone())?;
            }
        }
    }
    let confirmations = (0..runtimes.len())
        .map(|index| runtimes[index].confirm().map(|confirmation| confirmation.0))
        .collect::<Result<Vec<_>, _>>()?;
    for (sender, confirmation) in confirmations.iter().enumerate() {
        for (receiver, runtime) in runtimes.iter_mut().enumerate() {
            if receiver != sender {
                runtime.receive_confirmation(confirmation.clone())?;
            }
        }
    }
    let head = runtimes[0].head().hash;
    if runtimes.iter().any(|runtime| runtime.head().hash != head) {
        return Err("parallel HA group did not converge".into());
    }
    Ok(())
}

#[cfg(feature = "parallel-networks")]
fn parallel_event_vertex(
    dag: &TrustedCheckpointDag,
    origin: PubKey,
    sequence: u64,
    parent: Option<HashType>,
    event: &ParallelNetworkEvent,
) -> Result<TrustedDagVertex, BoxError> {
    Ok(TrustedDagVertex::new(TrustedDagVertexBody {
        group_id: dag.head().body.group_id,
        membership_generation: dag.head().body.membership_generation,
        origin,
        origin_sequence: sequence,
        origin_parent: parent,
        anchor_checkpoint_hash: dag.head().hash,
        anchor_checkpoint_nonce: dag.head().body.nonce,
        payload_root: event.hash()?,
        command_count: 1,
        byte_length: u64::try_from(serde_json::to_vec(event)?.len()).unwrap_or(u64::MAX),
    })?)
}

#[cfg(feature = "parallel-networks")]
fn finalize_parallel_vertex(
    dag: &mut TrustedCheckpointDag,
    vertex: TrustedDagVertex,
) -> Result<(blossom::TrustedDagCheckpoint, Vec<HashType>), BoxError> {
    if dag.ingest_vertex(vertex.clone())? != (TrustedDagIngestOutcome::Stored { activated: 1 }) {
        return Err("parallel Global Blossom vertex was not activated".into());
    }
    let candidate = dag.build_candidate([vertex.hash])?;
    let mut round = 0u8;
    loop {
        let expected = dag.expected_round_members(round)?;
        let threshold = supermajority_count(expected.len());
        for member in expected.iter().take(threshold) {
            dag.record_acknowledgement(round, *member, candidate.clone())?;
        }
        let lock = dag
            .try_lock_round(round)?
            .ok_or("parallel Global Blossom round failed to lock")?;
        for member in expected.iter().take(threshold) {
            dag.record_confirmation(round, *member, lock.candidate.digest)?;
        }
        match dag.try_complete_round(round)? {
            TrustedDagRoundCompletion::Advanced { next_round } => round = next_round,
            TrustedDagRoundCompletion::Finalized {
                checkpoint,
                ordered_vertices,
            } => return Ok((*checkpoint, ordered_vertices)),
            completion => {
                return Err(format!(
                    "parallel Global Blossom round did not finalize: {completion:?}"
                )
                .into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_identities_replay_exactly() {
        assert_eq!(
            deterministic_identities(7, 42),
            deterministic_identities(7, 42)
        );
        assert_ne!(
            deterministic_identities(7, 42),
            deterministic_identities(7, 43)
        );
    }

    #[test]
    fn two_node_healthy_trace_is_replayable_and_safe() {
        let report = run_ha_deterministic(HaDeterministicConfig {
            nodes: 2,
            epochs: 4,
            seed: 7,
            durable: false,
            fault_plan: HaFaultPlan::None,
            fault_depth: 0,
            systematic_schedules: 1,
            max_events: 10_000,
        })
        .unwrap();
        assert!(report.safety_passed, "{:?}", report.property_failures);
        assert!(report.replay_passed);
        assert_eq!(report.epochs, 4);
    }

    #[test]
    fn three_node_asymmetric_partition_recovers_and_converges() {
        let report = run_ha_deterministic(HaDeterministicConfig {
            nodes: 3,
            epochs: 8,
            seed: 11,
            durable: true,
            fault_plan: HaFaultPlan::AsymmetricPartition,
            fault_depth: 2,
            systematic_schedules: 1,
            max_events: 20_000,
        })
        .unwrap();
        assert!(report.safety_passed, "{:?}", report.property_failures);
    }

    #[test]
    fn every_deterministic_fault_class_recovers_without_safety_loss() {
        let faults = [
            HaFaultPlan::MinorityPartition,
            HaFaultPlan::RegionalPartition,
            HaFaultPlan::RegionalOutage,
            HaFaultPlan::DelayAndDuplicate,
            HaFaultPlan::Corruption,
            HaFaultPlan::ProcessPauseAndThrottle,
            HaFaultPlan::GracefulRedeploy,
            HaFaultPlan::CrashAfterConfirmation,
            HaFaultPlan::StorageDelay,
            HaFaultPlan::StorageFull,
            HaFaultPlan::StorageIo,
            HaFaultPlan::StorageFailure,
            HaFaultPlan::StorageTornWrite,
            HaFaultPlan::StorageCorruption,
            HaFaultPlan::StorageDiskReplacement,
        ];
        for fault_plan in faults {
            let report = run_ha_deterministic(HaDeterministicConfig {
                nodes: 3,
                epochs: 12,
                seed: 0x6661_756c_745f_0000 ^ ((fault_plan as u64) << 16),
                durable: fault_plan == HaFaultPlan::CrashAfterConfirmation
                    || is_storage_fault(fault_plan),
                fault_plan,
                fault_depth: 2,
                systematic_schedules: 1,
                max_events: 40_000,
            })
            .unwrap_or_else(|error| panic!("{fault_plan:?} failed to execute: {error}"));
            assert!(
                report.safety_passed,
                "{fault_plan:?}: {:?}",
                report.property_failures
            );
        }
    }

    #[test]
    fn deterministic_disk_replacement_model_redeploys_and_recovers() {
        let report = run_ha_deterministic(HaDeterministicConfig {
            nodes: 3,
            epochs: 12,
            seed: 0x6469_736b_5f72_6570,
            durable: true,
            fault_plan: HaFaultPlan::StorageDiskReplacement,
            fault_depth: 2,
            systematic_schedules: 1,
            max_events: 40_000,
        })
        .unwrap();
        assert!(report.safety_passed, "{:?}", report.property_failures);
    }

    #[test]
    fn two_node_disk_replacement_resolves_ambiguous_pending_round() {
        let report = run_ha_deterministic(HaDeterministicConfig {
            nodes: 2,
            epochs: 10,
            seed: 7_238_256_910_417_031_025,
            durable: true,
            fault_plan: HaFaultPlan::StorageDiskReplacement,
            fault_depth: 1,
            systematic_schedules: 1,
            max_events: 40_000,
        })
        .unwrap();
        assert!(report.safety_passed, "{:?}", report.property_failures);
        assert!(report.replay_passed);
    }

    #[test]
    fn active_passive_contract_remains_external_to_blossom_runtime() {
        let topology = blossom::HaServiceTopology::active_passive(5, 3).unwrap();
        let status = topology
            .assess(3, blossom::HaLeadershipStatus::Unavailable)
            .unwrap();
        assert!(!status.accepts_writes);
        assert!(
            status
                .directives
                .contains(&blossom::HaServiceDirective::AwaitLeader)
        );
    }
}
