//! Adapter that drives Blossom's native OpenRaft runtime in benchmarks.

#![allow(clippy::result_large_err)] // OpenRaft's storage API returns its concrete StorageError.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use blossom::active_passive::openraft;
use blossom::{
    ActiveActiveCommand, BlossomLogStore, BlossomLogStoreConfig, BlossomLogStoreIdentity,
};
use openraft::error::{InstallSnapshotError, RPCError, RaftError, RemoteError, Unreachable};
use openraft::network::{Backoff, RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{RaftStateMachine, Snapshot};
use openraft::{
    BasicNode, Config, Entry, EntryPayload, LogId, RaftSnapshotBuilder, RaftTypeConfig,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinSet;

use crate::{CommandResult, SharedStateMachine};

const RAFT_STATE_TABLE: &str = "benchmark_raft_state_machine_v1";

pub type NodeId = u64;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RaftAppliedResponse {
    pub result: Option<CommandResult>,
    pub application_error: Option<String>,
}

openraft::declare_raft_types!(
    pub BenchmarkRaftConfig:
        D = ActiveActiveCommand,
        R = RaftAppliedResponse,
);

pub type BenchmarkRaft = openraft::Raft<BenchmarkRaftConfig>;
pub type BenchmarkLogStore = blossom::MemoryRaftLogStore<BenchmarkRaftConfig>;
pub type BenchmarkShardStreamLogStore = blossom::ShardStreamRaftLogStore<BenchmarkRaftConfig>;
type InProcessRoutes = RwLock<BTreeMap<NodeId, BenchmarkRaft>>;
type SharedInProcessRoutes = Arc<InProcessRoutes>;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StateMachineData {
    last_applied_log: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    machine: SharedStateMachine,
}

impl StateMachineData {
    fn new(max_reorder: u64) -> Self {
        Self {
            last_applied_log: None,
            last_membership: StoredMembership::default(),
            machine: SharedStateMachine::new(max_reorder)
                .expect("benchmark reorder window is valid"),
        }
    }

    fn encode(&self) -> std::io::Result<Vec<u8>> {
        let wire = StateMachineDataWire {
            last_applied_log: self.last_applied_log,
            last_membership: self.last_membership.clone(),
            machine: borsh::to_vec(&self.machine).map_err(std::io::Error::other)?,
        };
        serde_json::to_vec(&wire).map_err(std::io::Error::other)
    }

    fn decode(bytes: &[u8]) -> std::io::Result<Self> {
        let wire: StateMachineDataWire =
            serde_json::from_slice(bytes).map_err(std::io::Error::other)?;
        Ok(Self {
            last_applied_log: wire.last_applied_log,
            last_membership: wire.last_membership,
            machine: borsh::from_slice(&wire.machine).map_err(std::io::Error::other)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct StateMachineDataWire {
    last_applied_log: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    machine: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StoredSnapshot {
    meta: SnapshotMeta<NodeId, BasicNode>,
    data: Vec<u8>,
}

#[derive(Debug)]
pub struct BenchmarkStateMachineStore {
    state_machine: RwLock<StateMachineData>,
    snapshot_idx: AtomicU64,
    current_snapshot: RwLock<Option<StoredSnapshot>>,
    durable_store: Option<BlossomLogStore>,
}

impl BenchmarkStateMachineStore {
    pub fn new(max_reorder: u64) -> Self {
        Self {
            state_machine: RwLock::new(StateMachineData::new(max_reorder)),
            snapshot_idx: AtomicU64::new(0),
            current_snapshot: RwLock::new(None),
            durable_store: None,
        }
    }

    pub fn open_durable(
        path: impl AsRef<Path>,
        max_reorder: u64,
        node_id: NodeId,
        cluster_name: &str,
    ) -> Result<Self, StorageError<NodeId>> {
        let public_scope = serde_json::to_vec(&(cluster_name, node_id))
            .map_err(|error| StorageIOError::write_state_machine(&error))?;
        let identity =
            BlossomLogStoreIdentity::new("benchmark-raft-state-machine", public_scope, 1)
                .map_err(|error| state_machine_write_error(error.to_string()))?;
        let store = BlossomLogStore::open(BlossomLogStoreConfig::new(path.as_ref()), identity)
            .map_err(|error| state_machine_write_error(error.to_string()))?;
        let state_machine = store
            .get(RAFT_STATE_TABLE, b"state")
            .map_err(|error| state_machine_read_error(error.to_string()))?
            .map(|bytes| {
                StateMachineData::decode(&bytes)
                    .map_err(|error| StorageIOError::read_state_machine(&error))
            })
            .transpose()?
            .unwrap_or_else(|| StateMachineData::new(max_reorder));
        let current_snapshot = store
            .get(RAFT_STATE_TABLE, b"snapshot")
            .map_err(|error| state_machine_read_error(error.to_string()))?
            .map(|bytes| {
                serde_json::from_slice::<StoredSnapshot>(&bytes)
                    .map_err(|error| StorageIOError::read_snapshot(None, &error))
            })
            .transpose()?;
        let snapshot_idx = store
            .get(RAFT_STATE_TABLE, b"snapshot_index")
            .map_err(|error| state_machine_read_error(error.to_string()))?
            .map(|bytes| {
                serde_json::from_slice::<u64>(&bytes)
                    .map_err(|error| StorageIOError::read_state_machine(&error))
            })
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            state_machine: RwLock::new(state_machine),
            snapshot_idx: AtomicU64::new(snapshot_idx),
            current_snapshot: RwLock::new(current_snapshot),
            durable_store: Some(store),
        })
    }

    pub async fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state_machine
            .read()
            .await
            .machine
            .get(key)
            .map(<[u8]>::to_vec)
    }

    pub async fn last_applied(&self) -> Option<LogId<NodeId>> {
        self.state_machine.read().await.last_applied_log
    }

    async fn persist(
        &self,
        state: &StateMachineData,
        snapshot: Option<&StoredSnapshot>,
        snapshot_idx: u64,
    ) -> Result<(), StorageError<NodeId>> {
        let Some(store) = self.durable_store.clone() else {
            return Ok(());
        };
        let state_bytes = state
            .encode()
            .map_err(|error| StorageIOError::write_state_machine(&error))?;
        let snapshot_bytes = snapshot
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|error| StorageIOError::write_snapshot(None, &error))?;
        let snapshot_index_bytes = serde_json::to_vec(&snapshot_idx)
            .map_err(|error| StorageIOError::write_state_machine(&error))?;
        tokio::task::spawn_blocking(move || {
            store
                .transaction(|transaction| {
                    transaction.insert(RAFT_STATE_TABLE, b"state".to_vec(), state_bytes)?;
                    transaction.insert(
                        RAFT_STATE_TABLE,
                        b"snapshot_index".to_vec(),
                        snapshot_index_bytes,
                    )?;
                    if let Some(snapshot_bytes) = snapshot_bytes {
                        transaction.insert(
                            RAFT_STATE_TABLE,
                            b"snapshot".to_vec(),
                            snapshot_bytes,
                        )?;
                    }
                    Ok(())
                })
                .map(|_| ())
        })
        .await
        .map_err(|error| {
            state_machine_write_error(format!("state-machine durability task failed: {error}"))
        })?
        .map_err(|error| state_machine_write_error(error.to_string()))
    }
}

fn state_machine_read_error(message: String) -> StorageError<NodeId> {
    let error = std::io::Error::other(message);
    StorageIOError::read_state_machine(&error).into()
}

fn state_machine_write_error(message: String) -> StorageError<NodeId> {
    let error = std::io::Error::other(message);
    StorageIOError::write_state_machine(&error).into()
}

pub struct BenchmarkDurableStores {
    pub log_store: BenchmarkShardStreamLogStore,
    pub state_machine: Arc<BenchmarkStateMachineStore>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaftStorageProfile {
    InMemory,
    DurableShardStream { root: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftDeterministicFault {
    None,
    FollowerPause,
    LeaderPause,
    AsymmetricFollowerPartition,
    QuorumLossPartition,
    NetworkDelay,
    ResponseLossAfterCommit,
    AppendRequestLoss,
    AppendResponseLoss,
    DuplicateAppendRequest,
    AppendRequestDelay,
    AppendResponseDelay,
    VoteRequestLoss,
    VoteResponseLoss,
    RepeatedLeaderChurn,
    DurableFollowerRestart,
    DurableLeaderRestart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftDeterministicReport {
    pub physical_nodes: usize,
    pub voters: usize,
    pub learners: usize,
    pub commands: u64,
    pub seed: u64,
    pub durable: bool,
    pub fault: RaftDeterministicFault,
    pub expected_stalls: u64,
    pub ambiguous_outcomes: u64,
    pub ambiguous_outcomes_resolved: bool,
    pub leader_changes: u64,
    pub final_value: Vec<u8>,
    pub all_nodes_converged: bool,
    pub linearizable_read_passed: bool,
    pub history_linearizable: bool,
    #[serde(default)]
    pub protocol_invariants_passed: bool,
    #[serde(default)]
    pub fault_coverage_passed: bool,
    #[serde(default)]
    pub network_fault_coverage: RaftNetworkFaultCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftNodeProtocolState {
    pub node_id: NodeId,
    pub running: bool,
    pub current_term: u64,
    pub current_leader: Option<NodeId>,
    pub last_log_index: Option<u64>,
    pub last_applied_index: Option<u64>,
    pub snapshot_index: Option<u64>,
    pub purged_index: Option<u64>,
    pub voter_ids: BTreeSet<NodeId>,
}

impl RaftNodeProtocolState {
    pub fn invariants_hold(&self) -> bool {
        // `last_log_index` describes the retained log, not the complete
        // replicated history. After a full snapshot purge it may be `None`
        // while `snapshot_index` and `last_applied_index` remain populated.
        let replicated_tail = match (self.last_log_index, self.snapshot_index) {
            (Some(log), Some(snapshot)) => Some(log.max(snapshot)),
            (Some(log), None) => Some(log),
            (None, Some(snapshot)) => Some(snapshot),
            (None, None) => None,
        };
        self.running
            && index_is_not_ahead(self.last_applied_index, replicated_tail)
            && index_is_not_ahead(self.snapshot_index, self.last_applied_index)
            && index_is_not_ahead(self.purged_index, self.snapshot_index)
    }
}

fn index_is_not_ahead(left: Option<u64>, right: Option<u64>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left <= right,
        (None, _) => true,
        (Some(_), None) => false,
    }
}

impl BenchmarkDurableStores {
    pub fn open(
        path: impl AsRef<Path>,
        max_reorder: u64,
        node_id: NodeId,
        cluster_name: &str,
    ) -> Result<Self, StorageError<NodeId>> {
        let log_store = BenchmarkShardStreamLogStore::open_bound(
            path.as_ref().join("raft-log"),
            blossom::RaftLogStoreIdentity::new(cluster_name, node_id),
        )?;
        let state_machine = Arc::new(BenchmarkStateMachineStore::open_durable(
            path.as_ref().join("state-machine"),
            max_reorder,
            node_id,
            cluster_name,
        )?);
        Ok(Self {
            log_store,
            state_machine,
        })
    }

    async fn reopen_after_shutdown(
        path: impl AsRef<Path>,
        max_reorder: u64,
        node_id: NodeId,
        cluster_name: &str,
        timeout: Duration,
    ) -> Result<Self, StorageError<NodeId>> {
        let path = path.as_ref().to_path_buf();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match Self::open(&path, max_reorder, node_id, cluster_name) {
                Ok(stores) => return Ok(stores),
                Err(error)
                    if error.to_string().contains("already open")
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl RaftSnapshotBuilder<BenchmarkRaftConfig> for Arc<BenchmarkStateMachineStore> {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<BenchmarkRaftConfig>, StorageError<NodeId>> {
        let state = self.state_machine.read().await.clone();
        let data = state
            .encode()
            .map_err(|error| StorageIOError::read_state_machine(&error))?;
        let last_log_id = state.last_applied_log;
        let last_membership = state.last_membership.clone();
        let snapshot_index = self.snapshot_idx.fetch_add(1, Ordering::Relaxed) + 1;
        let snapshot_id = last_log_id.map_or_else(
            || format!("empty-{snapshot_index}"),
            |log_id| format!("{}-{}-{snapshot_index}", log_id.leader_id, log_id.index),
        );
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id,
        };
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        self.persist(&state, Some(&stored), snapshot_index).await?;
        *self.current_snapshot.write().await = Some(stored);
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<BenchmarkRaftConfig> for Arc<BenchmarkStateMachineStore> {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let state = self.state_machine.read().await;
        Ok((state.last_applied_log, state.last_membership.clone()))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<RaftAppliedResponse>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<BenchmarkRaftConfig>> + Send,
    {
        let mut state = self.state_machine.read().await.clone();
        let mut responses = Vec::new();
        for entry in entries {
            state.last_applied_log = Some(entry.log_id);
            match entry.payload {
                EntryPayload::Blank => responses.push(RaftAppliedResponse {
                    result: None,
                    application_error: None,
                }),
                EntryPayload::Membership(membership) => {
                    state.last_membership = StoredMembership::new(Some(entry.log_id), membership);
                    responses.push(RaftAppliedResponse {
                        result: None,
                        application_error: None,
                    });
                }
                EntryPayload::Normal(command) => {
                    let response = match state.machine.apply(&command) {
                        Ok(result) => RaftAppliedResponse {
                            result: Some(result),
                            application_error: None,
                        },
                        Err(error) => RaftAppliedResponse {
                            result: None,
                            application_error: Some(error.to_string()),
                        },
                    };
                    responses.push(response);
                }
            }
        }
        let current_snapshot = self.current_snapshot.read().await.clone();
        self.persist(
            &state,
            current_snapshot.as_ref(),
            self.snapshot_idx.load(Ordering::Relaxed),
        )
        .await?;
        *self.state_machine.write().await = state;
        Ok(responses)
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<<BenchmarkRaftConfig as RaftTypeConfig>::SnapshotData>, StorageError<NodeId>>
    {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<<BenchmarkRaftConfig as RaftTypeConfig>::SnapshotData>,
    ) -> Result<(), StorageError<NodeId>> {
        let data = snapshot.into_inner();
        let state = StateMachineData::decode(&data)
            .map_err(|error| StorageIOError::read_snapshot(Some(meta.signature()), &error))?;
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data,
        };
        self.persist(
            &state,
            Some(&stored),
            self.snapshot_idx.load(Ordering::Relaxed),
        )
        .await?;
        *self.state_machine.write().await = state;
        *self.current_snapshot.write().await = Some(stored);
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<BenchmarkRaftConfig>>, StorageError<NodeId>> {
        Ok(self
            .current_snapshot
            .read()
            .await
            .as_ref()
            .map(|snapshot| Snapshot {
                meta: snapshot.meta.clone(),
                snapshot: Box::new(Cursor::new(snapshot.data.clone())),
            }))
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }
}

mod campaign;
mod cluster;
mod network;

pub use campaign::*;
pub use cluster::*;
pub use network::*;

#[cfg(test)]
use campaign::deterministic_raft_write;

#[cfg(test)]
mod tests;
