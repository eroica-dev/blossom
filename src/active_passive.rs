//! Native leader-based active-passive replication backed by OpenRaft.
//!
//! Blossom owns the command envelope, service-facing lifecycle, and OpenRaft
//! node facade. Embedding applications provide OpenRaft's network factory and
//! state-machine implementation so application mutations and the applied-log
//! watermark can share one atomic durability boundary.

mod log_store;

use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use openraft::error::{CheckIsLeaderError, ClientWriteError, Fatal, InitializeError, RaftError};
use openraft::network::RaftNetworkFactory;
use openraft::raft::ClientWriteResponse;
use openraft::storage::{RaftLogStorage, RaftStateMachine};
use openraft::{BasicNode, Config, LogId, RaftMetrics, ServerState};
use serde::{Deserialize, Serialize};

use crate::active_active::{
    ApplicationCommandEnvelope, ApplicationResult, CommandIdentity, CommandSpecVersion,
    RouteGeneration,
};
use crate::error::{BlossomError, Result};
use crate::hash::HashType;
use crate::high_availability::{
    HaLeadershipStatus, HaModeOperationalStatus, HaReplicationMode, HaServiceTopology,
};

pub use log_store::{MemoryRaftLogStore, RaftLogStoreIdentity, ShardStreamRaftLogStore};
pub use openraft;

const ACTIVE_PASSIVE_COMMAND_HASH_DOMAIN: &[u8] = b"blossom/active-passive/openraft-command/v1";

pub type ActivePassiveNodeId = u64;
pub type ActivePassiveNode = BasicNode;

/// Opaque application command replicated by the native active-passive engine.
///
/// The route generation and command-spec version are part of the committed
/// OpenRaft log entry. Application state machines must reject a command whose
/// contract does not match the contract active at that log position.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActivePassiveCommand {
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
    pub command: ApplicationCommandEnvelope,
}

impl ActivePassiveCommand {
    pub fn validate(&self) -> Result<()> {
        self.route_generation.validate()?;
        self.command_spec_version.validate()?;
        self.command.validate()
    }

    pub fn identity(&self) -> CommandIdentity {
        self.command.identity
    }

    pub fn hash(&self) -> Result<HashType> {
        self.validate()?;
        let encoded = borsh::to_vec(self).map_err(|error| {
            BlossomError::WireProtocol(format!("encode active-passive command: {error}"))
        })?;
        let domain_length = (ACTIVE_PASSIVE_COMMAND_HASH_DOMAIN.len() as u64).to_le_bytes();
        let encoded_length = (encoded.len() as u64).to_le_bytes();
        Ok(HashType::hash_slices([
            domain_length.as_slice(),
            ACTIVE_PASSIVE_COMMAND_HASH_DOMAIN,
            encoded_length.as_slice(),
            encoded.as_slice(),
        ]))
    }
}

/// Contract transition committed in the same OpenRaft log as application
/// commands.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct ActivePassiveContractChange {
    pub previous_route_generation: RouteGeneration,
    pub route_generation: RouteGeneration,
    pub previous_command_spec_version: CommandSpecVersion,
    pub command_spec_version: CommandSpecVersion,
}

impl ActivePassiveContractChange {
    pub fn validate(self) -> Result<()> {
        self.previous_route_generation.validate()?;
        self.route_generation.validate()?;
        self.previous_command_spec_version.validate()?;
        self.command_spec_version.validate()?;
        if self.route_generation.0 < self.previous_route_generation.0
            || self.command_spec_version.0 < self.previous_command_spec_version.0
            || (self.route_generation == self.previous_route_generation
                && self.command_spec_version == self.previous_command_spec_version)
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-passive contract change must monotonically advance route or command-spec version"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Persisted application-contract fence used by active-passive state machines.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct ActivePassiveContract {
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
}

impl ActivePassiveContract {
    pub fn new(
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<Self> {
        route_generation.validate()?;
        command_spec_version.validate()?;
        Ok(Self {
            route_generation,
            command_spec_version,
        })
    }

    pub fn validate_command(self, command: &ActivePassiveCommand) -> Result<()> {
        command.validate()?;
        if command.route_generation != self.route_generation
            || command.command_spec_version != self.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-passive command does not match the contract active at this log position"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn activate(&mut self, change: ActivePassiveContractChange) -> Result<()> {
        change.validate()?;
        if change.previous_route_generation != self.route_generation
            || change.previous_command_spec_version != self.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-passive contract change does not extend the active contract".to_string(),
            ));
        }
        self.route_generation = change.route_generation;
        self.command_spec_version = change.command_spec_version;
        Ok(())
    }
}

/// Native active-passive OpenRaft log payload.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum ActivePassiveRequest {
    Command(ActivePassiveCommand),
    ActivateContract(ActivePassiveContractChange),
}

impl ActivePassiveRequest {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Command(command) => command.validate(),
            Self::ActivateContract(change) => change.validate(),
        }
    }
}

/// Application-defined result returned after an OpenRaft log entry is applied.
///
/// Blank and membership entries normally return `command_identity = None`.
/// Normal entries return either an opaque result or a deterministic
/// application error. The application state machine owns deduplication by
/// [`CommandIdentity`] as required for retry-safe Raft clients.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ActivePassiveResponse {
    pub command_identity: Option<CommandIdentity>,
    pub result: Option<ApplicationResult>,
    pub application_error: Option<String>,
    pub activated_contract: Option<ActivePassiveContract>,
}

openraft::declare_raft_types!(
    pub ActivePassiveRaftConfig:
        D = ActivePassiveRequest,
        R = ActivePassiveResponse,
);

pub type ActivePassiveRaft = openraft::Raft<ActivePassiveRaftConfig>;
pub type ActivePassiveClientWriteResponse = ClientWriteResponse<ActivePassiveRaftConfig>;
pub type ActivePassiveClientWriteRaftError =
    RaftError<ActivePassiveNodeId, ClientWriteError<ActivePassiveNodeId, ActivePassiveNode>>;
pub type ActivePassiveLinearizableReadError =
    RaftError<ActivePassiveNodeId, CheckIsLeaderError<ActivePassiveNodeId, ActivePassiveNode>>;
pub type ActivePassiveInitializeRaftError =
    RaftError<ActivePassiveNodeId, InitializeError<ActivePassiveNodeId, ActivePassiveNode>>;

#[derive(Debug, thiserror::Error)]
pub enum ActivePassiveStartError {
    #[error("invalid active-passive topology: {0}")]
    InvalidTopology(BlossomError),
    #[error("OpenRaft failed to start: {0}")]
    Raft(#[from] Fatal<ActivePassiveNodeId>),
}

#[derive(Debug, thiserror::Error)]
pub enum ActivePassiveInitializeError {
    #[error("invalid active-passive initial membership: {0}")]
    InvalidMembership(BlossomError),
    #[error("OpenRaft cluster initialization failed: {0}")]
    Raft(#[from] ActivePassiveInitializeRaftError),
}

#[derive(Debug, thiserror::Error)]
pub enum ActivePassiveWriteError {
    #[error("invalid active-passive command: {0}")]
    InvalidCommand(#[from] BlossomError),
    #[error("OpenRaft client write failed: {0}")]
    Raft(#[from] ActivePassiveClientWriteRaftError),
}

#[derive(Debug, thiserror::Error)]
pub enum ActivePassiveMembershipError {
    #[error("invalid active-passive membership change: {0}")]
    InvalidMembership(BlossomError),
    #[error("OpenRaft membership change failed: {0}")]
    Raft(#[from] ActivePassiveClientWriteRaftError),
}

/// Point-in-time native active-passive status.
#[derive(Debug, Clone)]
pub struct ActivePassiveOperationalStatus {
    pub node_id: ActivePassiveNodeId,
    pub current_term: u64,
    pub server_state: ServerState,
    pub current_leader: Option<ActivePassiveNodeId>,
    pub last_log_index: Option<u64>,
    pub last_applied: Option<LogId<ActivePassiveNodeId>>,
    pub snapshot: Option<LogId<ActivePassiveNodeId>>,
    pub service: HaModeOperationalStatus,
    /// Whether this node is the current write target.
    ///
    /// OpenRaft still performs the authoritative quorum check when the write
    /// is submitted; this field is an operational routing hint.
    pub accepts_local_writes: bool,
}

/// Native OpenRaft node facade for the active-passive HA profile.
///
/// `ActivePassiveRuntime` owns the OpenRaft task and exposes the operations
/// Blossom services need without hiding OpenRaft's application-owned network
/// and state-machine durability traits.
#[derive(Clone)]
pub struct ActivePassiveRuntime {
    node_id: ActivePassiveNodeId,
    topology: HaServiceTopology,
    raft: ActivePassiveRaft,
    membership_change: Arc<tokio::sync::Mutex<()>>,
}

impl ActivePassiveRuntime {
    pub async fn new<N, LS, SM>(
        node_id: ActivePassiveNodeId,
        topology: HaServiceTopology,
        config: Arc<Config>,
        network: N,
        log_store: LS,
        state_machine: SM,
    ) -> std::result::Result<Self, ActivePassiveStartError>
    where
        N: RaftNetworkFactory<ActivePassiveRaftConfig>,
        LS: RaftLogStorage<ActivePassiveRaftConfig>,
        SM: RaftStateMachine<ActivePassiveRaftConfig>,
    {
        let validated_topology = HaServiceTopology::active_passive(
            usize::from(topology.physical_nodes),
            usize::from(topology.voting_nodes),
        )
        .map_err(ActivePassiveStartError::InvalidTopology)?;
        if topology.mode != HaReplicationMode::MajorityLeaderActivePassive
            || topology != validated_topology
        {
            return Err(ActivePassiveStartError::InvalidTopology(
                BlossomError::InvalidConfiguration(
                    "ActivePassiveRuntime requires a validated majority-leader active-passive topology"
                        .to_string(),
                ),
            ));
        }
        let config = Arc::new(config.as_ref().clone().validate().map_err(|error| {
            ActivePassiveStartError::InvalidTopology(BlossomError::InvalidConfiguration(format!(
                "invalid active-passive OpenRaft configuration: {error}"
            )))
        })?);
        if config.cluster_name.trim().is_empty() {
            return Err(ActivePassiveStartError::InvalidTopology(
                BlossomError::InvalidConfiguration(
                    "active-passive OpenRaft cluster_name cannot be empty".to_string(),
                ),
            ));
        }
        let raft =
            ActivePassiveRaft::new(node_id, config, network, log_store, state_machine).await?;
        Ok(Self {
            node_id,
            topology,
            raft,
            membership_change: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn node_id(&self) -> ActivePassiveNodeId {
        self.node_id
    }

    pub fn topology(&self) -> HaServiceTopology {
        self.topology
    }

    pub fn raft(&self) -> &ActivePassiveRaft {
        &self.raft
    }

    pub fn metrics(
        &self,
    ) -> tokio::sync::watch::Receiver<RaftMetrics<ActivePassiveNodeId, ActivePassiveNode>> {
        self.raft.metrics()
    }

    pub async fn initialize(
        &self,
        members: BTreeMap<ActivePassiveNodeId, ActivePassiveNode>,
    ) -> std::result::Result<(), ActivePassiveInitializeError> {
        if members.len() != usize::from(self.topology.voting_nodes) {
            return Err(ActivePassiveInitializeError::InvalidMembership(
                BlossomError::InvalidConfiguration(format!(
                    "active-passive initialization requires exactly {} voting nodes, got {}",
                    self.topology.voting_nodes,
                    members.len()
                )),
            ));
        }
        if !members.contains_key(&self.node_id) {
            return Err(ActivePassiveInitializeError::InvalidMembership(
                BlossomError::InvalidConfiguration(
                    "the initializing active-passive node must be an initial voter".to_string(),
                ),
            ));
        }
        Ok(self.raft.initialize(members).await?)
    }

    pub async fn client_write(
        &self,
        command: ActivePassiveCommand,
    ) -> std::result::Result<ActivePassiveClientWriteResponse, ActivePassiveWriteError> {
        command.validate()?;
        Ok(self
            .raft
            .client_write(ActivePassiveRequest::Command(command))
            .await?)
    }

    pub async fn activate_application_contract(
        &self,
        change: ActivePassiveContractChange,
    ) -> std::result::Result<ActivePassiveClientWriteResponse, ActivePassiveWriteError> {
        change.validate()?;
        Ok(self
            .raft
            .client_write(ActivePassiveRequest::ActivateContract(change))
            .await?)
    }

    pub async fn ensure_linearizable(
        &self,
    ) -> std::result::Result<Option<LogId<ActivePassiveNodeId>>, ActivePassiveLinearizableReadError>
    {
        self.raft.ensure_linearizable().await
    }

    pub async fn add_learner(
        &self,
        node_id: ActivePassiveNodeId,
        node: ActivePassiveNode,
        blocking: bool,
    ) -> std::result::Result<ActivePassiveClientWriteResponse, ActivePassiveMembershipError> {
        let _membership_change = self.membership_change.lock().await;
        let metrics = self.raft.metrics().borrow().clone();
        let membership = metrics.membership_config.membership();
        let already_present = membership.get_node(&node_id).is_some();
        let node_count = membership.nodes().count();
        if !already_present && node_count >= usize::from(self.topology.physical_nodes) {
            return Err(ActivePassiveMembershipError::InvalidMembership(
                BlossomError::InvalidConfiguration(format!(
                    "active-passive topology allows at most {} physical nodes",
                    self.topology.physical_nodes
                )),
            ));
        }
        Ok(self.raft.add_learner(node_id, node, blocking).await?)
    }

    /// Replaces the voter set using OpenRaft joint consensus.
    ///
    /// New voters must first be caught-up learners. Blossom requires the
    /// replacement set to preserve the topology's declared voter count; use a
    /// new topology and cluster migration to intentionally resize a cluster.
    pub async fn replace_voters(
        &self,
        voter_ids: impl IntoIterator<Item = ActivePassiveNodeId>,
        retain_removed_as_learners: bool,
    ) -> std::result::Result<ActivePassiveClientWriteResponse, ActivePassiveMembershipError> {
        let _membership_change = self.membership_change.lock().await;
        let voter_ids = voter_ids
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        if voter_ids.len() != usize::from(self.topology.voting_nodes) {
            return Err(ActivePassiveMembershipError::InvalidMembership(
                BlossomError::InvalidConfiguration(format!(
                    "active-passive topology requires exactly {} voters, got {}",
                    self.topology.voting_nodes,
                    voter_ids.len()
                )),
            ));
        }
        Ok(self
            .raft
            .change_membership(voter_ids, retain_removed_as_learners)
            .await?)
    }

    pub fn operational_status(
        &self,
        responsive_voters: usize,
    ) -> Result<ActivePassiveOperationalStatus> {
        let metrics = self.raft.metrics().borrow().clone();
        let leadership = if metrics.current_leader.is_some() {
            HaLeadershipStatus::Elected
        } else {
            HaLeadershipStatus::Unavailable
        };
        let service = self.topology.assess(responsive_voters, leadership)?;
        let accepts_local_writes = service.accepts_writes
            && metrics.state == ServerState::Leader
            && metrics.current_leader == Some(self.node_id);
        Ok(ActivePassiveOperationalStatus {
            node_id: self.node_id,
            current_term: metrics.current_term,
            server_state: metrics.state,
            current_leader: metrics.current_leader,
            last_log_index: metrics.last_log_index,
            last_applied: metrics.last_applied,
            snapshot: metrics.snapshot,
            service,
            accepts_local_writes,
        })
    }

    pub async fn shutdown(&self) -> std::result::Result<(), tokio::task::JoinError> {
        self.raft.shutdown().await
    }
}
