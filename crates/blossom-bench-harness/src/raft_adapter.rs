#![allow(clippy::result_large_err)] // OpenRaft's storage API returns its concrete StorageError.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use blossom::{ActiveActiveCommand, CommandResult, SharedStateMachine};
use openraft::error::{
    InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Unreachable,
};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{RaftStateMachine, Snapshot};
use openraft::{
    BasicNode, Config, Entry, EntryPayload, LogId, RaftSnapshotBuilder, RaftTypeConfig,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership,
};
use redb::{Database, Durability, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, watch};
use tokio::task::JoinSet;

use crate::raft_log_store::{MemoryLogStore, RedbLogStore};

const RAFT_STATE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("benchmark_raft_state_machine_v1");

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
pub type BenchmarkLogStore = MemoryLogStore<BenchmarkRaftConfig>;
pub type BenchmarkRedbLogStore = RedbLogStore<BenchmarkRaftConfig>;

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
    database: Option<Arc<Database>>,
}

impl BenchmarkStateMachineStore {
    pub fn new(max_reorder: u64) -> Self {
        Self {
            state_machine: RwLock::new(StateMachineData::new(max_reorder)),
            snapshot_idx: AtomicU64::new(0),
            current_snapshot: RwLock::new(None),
            database: None,
        }
    }

    pub fn from_redb(
        database: Arc<Database>,
        max_reorder: u64,
    ) -> Result<Self, StorageError<NodeId>> {
        let mut transaction = database
            .begin_write()
            .map_err(|error| StorageIOError::write_state_machine(&error))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StorageIOError::write_state_machine(&error))?;
        {
            transaction
                .open_table(RAFT_STATE_TABLE)
                .map_err(|error| StorageIOError::write_state_machine(&error))?;
        }
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_state_machine(&error))?;

        let transaction = database
            .begin_read()
            .map_err(|error| StorageIOError::read_state_machine(&error))?;
        let table = transaction
            .open_table(RAFT_STATE_TABLE)
            .map_err(|error| StorageIOError::read_state_machine(&error))?;
        let state_machine = table
            .get("state")
            .map_err(|error| StorageIOError::read_state_machine(&error))?
            .map(|bytes| {
                StateMachineData::decode(bytes.value())
                    .map_err(|error| StorageIOError::read_state_machine(&error))
            })
            .transpose()?
            .unwrap_or_else(|| StateMachineData::new(max_reorder));
        let current_snapshot = table
            .get("snapshot")
            .map_err(|error| StorageIOError::read_state_machine(&error))?
            .map(|bytes| {
                serde_json::from_slice::<StoredSnapshot>(bytes.value())
                    .map_err(|error| StorageIOError::read_snapshot(None, &error))
            })
            .transpose()?;
        let snapshot_idx = table
            .get("snapshot_index")
            .map_err(|error| StorageIOError::read_state_machine(&error))?
            .map(|bytes| {
                serde_json::from_slice::<u64>(bytes.value())
                    .map_err(|error| StorageIOError::read_state_machine(&error))
            })
            .transpose()?
            .unwrap_or(0);
        drop(table);
        drop(transaction);
        Ok(Self {
            state_machine: RwLock::new(state_machine),
            snapshot_idx: AtomicU64::new(snapshot_idx),
            current_snapshot: RwLock::new(current_snapshot),
            database: Some(database),
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

    fn database(&self) -> Option<Arc<Database>> {
        self.database.clone()
    }

    fn persist(
        &self,
        state: &StateMachineData,
        snapshot: Option<&StoredSnapshot>,
        snapshot_idx: u64,
    ) -> Result<(), StorageError<NodeId>> {
        let Some(database) = &self.database else {
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
        let mut transaction = database
            .begin_write()
            .map_err(|error| StorageIOError::write_state_machine(&error))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StorageIOError::write_state_machine(&error))?;
        {
            let mut table = transaction
                .open_table(RAFT_STATE_TABLE)
                .map_err(|error| StorageIOError::write_state_machine(&error))?;
            table
                .insert("state", state_bytes.as_slice())
                .map_err(|error| StorageIOError::write_state_machine(&error))?;
            table
                .insert("snapshot_index", snapshot_index_bytes.as_slice())
                .map_err(|error| StorageIOError::write_state_machine(&error))?;
            if let Some(snapshot_bytes) = snapshot_bytes.as_deref() {
                table
                    .insert("snapshot", snapshot_bytes)
                    .map_err(|error| StorageIOError::write_snapshot(None, &error))?;
            }
        }
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_state_machine(&error).into())
    }
}

pub struct BenchmarkDurableStores {
    pub log_store: BenchmarkRedbLogStore,
    pub state_machine: Arc<BenchmarkStateMachineStore>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaftStorageProfile {
    InMemory,
    DurableRedbImmediate { root: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftDeterministicFault {
    None,
    FollowerPause,
    LeaderPause,
    AsymmetricFollowerPartition,
    DurableFollowerRestart,
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
    pub leader_changes: u64,
    pub final_value: Vec<u8>,
    pub all_nodes_converged: bool,
    pub linearizable_read_passed: bool,
    pub history_linearizable: bool,
}

impl BenchmarkDurableStores {
    pub fn open(path: impl AsRef<Path>, max_reorder: u64) -> Result<Self, StorageError<NodeId>> {
        let log_store = BenchmarkRedbLogStore::open(path)?;
        let state_machine = Arc::new(BenchmarkStateMachineStore::from_redb(
            log_store.database(),
            max_reorder,
        )?);
        Ok(Self {
            log_store,
            state_machine,
        })
    }

    fn from_database(
        database: Arc<Database>,
        max_reorder: u64,
    ) -> Result<Self, StorageError<NodeId>> {
        let log_store = BenchmarkRedbLogStore::from_database(database.clone())?;
        let state_machine = Arc::new(BenchmarkStateMachineStore::from_redb(
            database,
            max_reorder,
        )?);
        Ok(Self {
            log_store,
            state_machine,
        })
    }
}

impl RaftSnapshotBuilder<BenchmarkRaftConfig> for Arc<BenchmarkStateMachineStore> {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<BenchmarkRaftConfig>, StorageError<NodeId>> {
        let state = self.state_machine.read().await;
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
        self.persist(&state, Some(&stored), snapshot_index)?;
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
        )?;
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
        )?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkState {
    Healthy,
    Blocked,
    Delayed(Duration),
}

#[derive(Debug, Clone, Default)]
pub struct InProcessNetworkControl {
    links: Arc<RwLock<BTreeMap<(NodeId, NodeId), LinkState>>>,
}

impl InProcessNetworkControl {
    pub async fn set_link(&self, source: NodeId, target: NodeId, state: LinkState) {
        self.links.write().await.insert((source, target), state);
    }

    pub async fn partition(&self, left: &BTreeSet<NodeId>, right: &BTreeSet<NodeId>) {
        let mut links = self.links.write().await;
        for source in left {
            for target in right {
                links.insert((*source, *target), LinkState::Blocked);
                links.insert((*target, *source), LinkState::Blocked);
            }
        }
    }

    pub async fn heal(&self) {
        self.links.write().await.clear();
    }

    async fn before_rpc(&self, source: NodeId, target: NodeId) -> Result<(), RPCTransportError> {
        match self.links.read().await.get(&(source, target)).cloned() {
            Some(LinkState::Blocked) => Err(RPCTransportError::Blocked),
            Some(LinkState::Delayed(delay)) => {
                tokio::time::sleep(delay).await;
                Ok(())
            }
            Some(LinkState::Healthy) | None => Ok(()),
        }
    }
}

#[derive(Debug)]
enum RPCTransportError {
    Blocked,
    MissingNode,
}

impl std::fmt::Display for RPCTransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked => write!(formatter, "benchmark network link is blocked"),
            Self::MissingNode => write!(formatter, "benchmark target node is unavailable"),
        }
    }
}

impl std::error::Error for RPCTransportError {}

#[derive(Clone, Default)]
struct InProcessNetworkFactory {
    source: NodeId,
    routes: Arc<RwLock<BTreeMap<NodeId, BenchmarkRaft>>>,
    control: InProcessNetworkControl,
}

impl RaftNetworkFactory<BenchmarkRaftConfig> for InProcessNetworkFactory {
    type Network = InProcessNetwork;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        InProcessNetwork {
            source: self.source,
            target,
            routes: self.routes.clone(),
            control: self.control.clone(),
        }
    }
}

struct InProcessNetwork {
    source: NodeId,
    target: NodeId,
    routes: Arc<RwLock<BTreeMap<NodeId, BenchmarkRaft>>>,
    control: InProcessNetworkControl,
}

impl InProcessNetwork {
    async fn target(
        &self,
    ) -> Result<BenchmarkRaft, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.control
            .before_rpc(self.source, self.target)
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))?;
        self.routes
            .read()
            .await
            .get(&self.target)
            .cloned()
            .ok_or_else(|| RPCError::Unreachable(Unreachable::new(&RPCTransportError::MissingNode)))
    }
}

impl RaftNetwork<BenchmarkRaftConfig> for InProcessNetwork {
    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<BenchmarkRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.target()
            .await?
            .append_entries(request)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<BenchmarkRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let target = self.target().await.map_err(|error| match error {
            RPCError::Timeout(error) => RPCError::Timeout(error),
            RPCError::Unreachable(error) => RPCError::Unreachable(error),
            RPCError::Network(error) => RPCError::Network(error),
            RPCError::PayloadTooLarge(error) => RPCError::PayloadTooLarge(error),
            RPCError::RemoteError(error) => RPCError::Network(NetworkError::new(&error)),
        })?;
        target
            .install_snapshot(request)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))
    }

    async fn vote(
        &mut self,
        request: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.target()
            .await?
            .vote(request)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))
    }
}

pub struct InProcessRaftCluster {
    pub nodes: BTreeMap<NodeId, BenchmarkRaft>,
    pub state_machines: BTreeMap<NodeId, Arc<BenchmarkStateMachineStore>>,
    pub voters: BTreeSet<NodeId>,
    pub learners: BTreeSet<NodeId>,
    pub network_control: InProcessNetworkControl,
    metrics: BTreeMap<NodeId, watch::Receiver<openraft::RaftMetrics<NodeId, BasicNode>>>,
    routes: Arc<RwLock<BTreeMap<NodeId, BenchmarkRaft>>>,
    paused_nodes: BTreeSet<NodeId>,
    config: Arc<Config>,
    storage_paths: BTreeMap<NodeId, PathBuf>,
}

impl InProcessRaftCluster {
    pub async fn start(
        voter_count: usize,
        learner_count: usize,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::start_with_storage(voter_count, learner_count, RaftStorageProfile::InMemory).await
    }

    pub async fn start_with_storage(
        voter_count: usize,
        learner_count: usize,
        storage: RaftStorageProfile,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if !matches!(voter_count, 2 | 3 | 5 | 7) {
            return Err("benchmark Raft voter count must be 2, 3, 5, or 7".into());
        }
        let total = voter_count
            .checked_add(learner_count)
            .ok_or("Raft cluster size overflow")?;
        let routes = Arc::new(RwLock::new(BTreeMap::new()));
        let network_control = InProcessNetworkControl::default();
        let config = Arc::new(
            Config {
                heartbeat_interval: 50,
                // Keep local scheduler pressure from hundreds of concurrent
                // benchmark clients from masquerading as a leader fault.
                election_timeout_min: 1_000,
                election_timeout_max: 2_000,
                snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(10_000),
                ..Default::default()
            }
            .validate()?,
        );
        let mut nodes = BTreeMap::new();
        let mut state_machines = BTreeMap::new();
        let mut metrics = BTreeMap::new();
        let mut storage_paths = BTreeMap::new();
        for node_id in 1..=total as u64 {
            let network = InProcessNetworkFactory {
                source: node_id,
                routes: routes.clone(),
                control: network_control.clone(),
            };
            let (raft, state_machine) = match &storage {
                RaftStorageProfile::InMemory => {
                    let state_machine = Arc::new(BenchmarkStateMachineStore::new(4096));
                    let raft = BenchmarkRaft::new(
                        node_id,
                        config.clone(),
                        network,
                        BenchmarkLogStore::default(),
                        state_machine.clone(),
                    )
                    .await?;
                    (raft, state_machine)
                }
                RaftStorageProfile::DurableRedbImmediate { root } => {
                    std::fs::create_dir_all(root)?;
                    let path = root.join(format!("node-{node_id}.redb"));
                    let stores = BenchmarkDurableStores::open(&path, 4096)?;
                    let state_machine = stores.state_machine;
                    let raft = BenchmarkRaft::new(
                        node_id,
                        config.clone(),
                        network,
                        stores.log_store,
                        state_machine.clone(),
                    )
                    .await?;
                    storage_paths.insert(node_id, path);
                    (raft, state_machine)
                }
            };
            metrics.insert(node_id, raft.metrics());
            nodes.insert(node_id, raft.clone());
            state_machines.insert(node_id, state_machine);
            routes.write().await.insert(node_id, raft);
        }
        let voters = (1..=voter_count as u64).collect::<BTreeSet<_>>();
        let learners = ((voter_count as u64 + 1)..=total as u64).collect::<BTreeSet<_>>();
        let initial_nodes = voters
            .iter()
            .map(|node_id| {
                (
                    *node_id,
                    BasicNode {
                        addr: format!("in-process://{node_id}"),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        nodes
            .get(&1)
            .expect("node one exists")
            .initialize(initial_nodes)
            .await?;

        let mut cluster = Self {
            nodes,
            state_machines,
            voters,
            learners,
            network_control,
            metrics,
            routes,
            paused_nodes: BTreeSet::new(),
            config,
            storage_paths,
        };
        let leader = cluster.wait_for_leader(Duration::from_secs(5)).await?;
        cluster
            .nodes
            .get(&leader)
            .expect("leader exists")
            .wait(Some(Duration::from_secs(5)))
            .applied_index_at_least(Some(0), "initial membership must commit before learners")
            .await?;
        for learner in cluster.learners.clone() {
            cluster
                .nodes
                .get(&leader)
                .expect("leader exists")
                .add_learner(
                    learner,
                    BasicNode {
                        addr: format!("in-process://{learner}"),
                    },
                    true,
                )
                .await?;
        }
        Ok(cluster)
    }

    pub async fn kill_and_restart_node(
        &mut self,
        node_id: NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.storage_paths
            .get(&node_id)
            .ok_or("kill/restart requires the durable redb storage profile")?;
        let database = self
            .state_machines
            .get(&node_id)
            .and_then(|state_machine| state_machine.database())
            .ok_or("durable node is missing its redb database")?;
        self.routes.write().await.remove(&node_id);
        let raft = self
            .nodes
            .remove(&node_id)
            .ok_or_else(|| format!("unknown OpenRaft node {node_id}"))?;
        raft.shutdown().await?;
        drop(raft);
        self.state_machines.remove(&node_id);
        self.metrics.remove(&node_id);

        let stores = BenchmarkDurableStores::from_database(database, 4096)?;
        let state_machine = stores.state_machine;
        let raft = BenchmarkRaft::new(
            node_id,
            self.config.clone(),
            InProcessNetworkFactory {
                source: node_id,
                routes: self.routes.clone(),
                control: self.network_control.clone(),
            },
            stores.log_store,
            state_machine.clone(),
        )
        .await?;
        self.metrics.insert(node_id, raft.metrics());
        self.state_machines.insert(node_id, state_machine);
        self.nodes.insert(node_id, raft.clone());
        self.routes.write().await.insert(node_id, raft);
        self.paused_nodes.remove(&node_id);
        for peer in self.nodes.keys().copied().filter(|peer| *peer != node_id) {
            self.network_control
                .set_link(node_id, peer, LinkState::Healthy)
                .await;
            self.network_control
                .set_link(peer, node_id, LinkState::Healthy)
                .await;
        }
        Ok(())
    }

    pub async fn wait_for_leader(
        &mut self,
        timeout: Duration,
    ) -> Result<NodeId, Box<dyn std::error::Error + Send + Sync>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            for receiver in self.metrics.values() {
                if let Some(leader) = receiver.borrow().current_leader
                    && !self.paused_nodes.contains(&leader)
                {
                    return Ok(leader);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("timed out waiting for OpenRaft leader".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn client_write(
        &mut self,
        command: ActiveActiveCommand,
    ) -> Result<
        openraft::raft::ClientWriteResponse<BenchmarkRaftConfig>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        command.validate()?;
        let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
        Ok(self
            .nodes
            .get(&leader)
            .expect("leader exists")
            .client_write(command)
            .await?)
    }

    /// Sends independent clients to the current leader concurrently and waits
    /// until every command is committed and applied.
    pub async fn client_write_concurrent(
        &mut self,
        commands: Vec<ActiveActiveCommand>,
    ) -> Result<Vec<RaftAppliedResponse>, Box<dyn std::error::Error + Send + Sync>> {
        if commands.is_empty() {
            return Err("concurrent OpenRaft write batch cannot be empty".into());
        }
        for command in &commands {
            command.validate()?;
        }
        let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
        let routes = self.routes.clone();
        let metrics = self.metrics.values().cloned().collect::<Vec<_>>();
        let command_count = commands.len();
        let mut writes = JoinSet::new();
        for (index, command) in commands.into_iter().enumerate() {
            let routes = routes.clone();
            let metrics = metrics.clone();
            writes.spawn(async move {
                let mut target = leader;
                let mut last_error = None;
                for _ in 0..500 {
                    let raft =
                        routes.read().await.get(&target).cloned().ok_or_else(|| {
                            format!("OpenRaft write target {target} is unavailable")
                        })?;
                    match raft.client_write(command.clone()).await {
                        Ok(response) => return Ok((index, response.data)),
                        Err(error) => {
                            let forwarded = error
                                .forward_to_leader::<BasicNode>()
                                .and_then(|forward| forward.leader_id);
                            last_error = Some(error.to_string());
                            if let Some(next) = forwarded {
                                target = next;
                            } else if let Some(next) = metrics
                                .iter()
                                .find_map(|metrics| metrics.borrow().current_leader)
                            {
                                target = next;
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
                Err(format!(
                    "OpenRaft concurrent write exhausted retries: {}",
                    last_error.unwrap_or_else(|| "no leader".to_string())
                ))
            });
        }
        let mut responses = vec![None; command_count];
        while let Some(response) = writes.join_next().await {
            let (index, response) = response??;
            responses[index] = Some(response);
        }
        responses
            .into_iter()
            .map(|response| response.ok_or_else(|| "OpenRaft concurrent write was lost".into()))
            .collect()
    }

    pub async fn ensure_linearizable(
        &mut self,
    ) -> Result<NodeId, Box<dyn std::error::Error + Send + Sync>> {
        let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
        self.nodes
            .get(&leader)
            .expect("leader exists")
            .ensure_linearizable()
            .await?;
        Ok(leader)
    }

    pub async fn read_linearizable(
        &mut self,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let leader = self.ensure_linearizable().await?;
        Ok(self
            .state_machines
            .get(&leader)
            .expect("leader state machine exists")
            .get(key)
            .await)
    }

    pub async fn current_leader(
        &mut self,
    ) -> Result<NodeId, Box<dyn std::error::Error + Send + Sync>> {
        self.wait_for_leader(Duration::from_secs(5)).await
    }

    pub async fn pause_node(
        &mut self,
        node_id: NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.nodes.contains_key(&node_id) {
            return Err(format!("unknown OpenRaft node {node_id}").into());
        }
        self.paused_nodes.insert(node_id);
        self.routes.write().await.remove(&node_id);
        for peer in self.nodes.keys().copied().filter(|peer| *peer != node_id) {
            self.network_control
                .set_link(node_id, peer, LinkState::Blocked)
                .await;
            self.network_control
                .set_link(peer, node_id, LinkState::Blocked)
                .await;
        }
        Ok(())
    }

    pub async fn resume_node(
        &mut self,
        node_id: NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let raft = self
            .nodes
            .get(&node_id)
            .cloned()
            .ok_or_else(|| format!("unknown OpenRaft node {node_id}"))?;
        self.routes.write().await.insert(node_id, raft);
        self.paused_nodes.remove(&node_id);
        for peer in self.nodes.keys().copied().filter(|peer| *peer != node_id) {
            self.network_control
                .set_link(node_id, peer, LinkState::Healthy)
                .await;
            self.network_control
                .set_link(peer, node_id, LinkState::Healthy)
                .await;
        }
        Ok(())
    }

    pub async fn trigger_snapshot(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
        self.nodes[&leader].trigger().snapshot().await?;
        Ok(())
    }

    pub async fn shutdown(self) {
        for raft in self.nodes.into_values() {
            let _ = raft.shutdown().await;
        }
    }
}

pub async fn run_raft_deterministic_campaign(
    physical_nodes: usize,
    commands: u64,
    seed: u64,
    durable: bool,
    fault: RaftDeterministicFault,
) -> Result<RaftDeterministicReport, Box<dyn std::error::Error + Send + Sync>> {
    if !(2..=7).contains(&physical_nodes) {
        return Err("deterministic OpenRaft physical node count must be 2..=7".into());
    }
    if commands == 0 {
        return Err("deterministic OpenRaft command count must be positive".into());
    }
    if !durable && fault == RaftDeterministicFault::DurableFollowerRestart {
        return Err("OpenRaft kill/restart requires durable storage".into());
    }
    let voters = match physical_nodes {
        2 => 2,
        3 | 4 => 3,
        5 | 6 => 5,
        7 => 7,
        _ => unreachable!("physical node count was validated"),
    };
    let learners = physical_nodes.saturating_sub(voters);
    let root = std::env::temp_dir().join(format!(
        "blossom-raft-dst-{}-{}-{}",
        std::process::id(),
        physical_nodes,
        seed
    ));
    let storage = if durable {
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        RaftStorageProfile::DurableRedbImmediate { root: root.clone() }
    } else {
        RaftStorageProfile::InMemory
    };
    let mut cluster = InProcessRaftCluster::start_with_storage(voters, learners, storage).await?;
    let initial_leader = cluster.current_leader().await?;
    let mut expected_stalls = 0u64;
    let mut leader_changes = 0u64;
    let fault_at = (commands / 2).max(1);
    let key = format!("raft-dst-key-{seed}").into_bytes();
    let mut history = Vec::with_capacity(usize::try_from(commands).unwrap_or(usize::MAX));

    for sequence in 1..=commands {
        let mut heal_after_write = false;
        if sequence == fault_at {
            let leader = cluster.current_leader().await?;
            let follower = cluster
                .voters
                .iter()
                .copied()
                .find(|node| *node != leader)
                .ok_or("deterministic OpenRaft campaign requires a follower")?;
            match fault {
                RaftDeterministicFault::None => {}
                RaftDeterministicFault::FollowerPause => {
                    cluster.pause_node(follower).await?;
                    if voters == 2 {
                        expected_stalls = expected_stalls.saturating_add(1);
                        assert_raft_write_stalls(
                            &mut cluster,
                            deterministic_raft_command(&key, sequence, seed),
                        )
                        .await?;
                    }
                    cluster.resume_node(follower).await?;
                }
                RaftDeterministicFault::LeaderPause => {
                    cluster.pause_node(leader).await?;
                    if voters == 2 {
                        expected_stalls = expected_stalls.saturating_add(1);
                        assert_raft_write_stalls(
                            &mut cluster,
                            deterministic_raft_command(&key, sequence, seed),
                        )
                        .await?;
                        cluster.resume_node(leader).await?;
                    } else {
                        let replacement = cluster.wait_for_leader(Duration::from_secs(10)).await?;
                        if replacement != leader {
                            leader_changes = leader_changes.saturating_add(1);
                        }
                        cluster.resume_node(leader).await?;
                    }
                }
                RaftDeterministicFault::AsymmetricFollowerPartition => {
                    cluster
                        .network_control
                        .set_link(leader, follower, LinkState::Blocked)
                        .await;
                    if voters == 2 {
                        expected_stalls = expected_stalls.saturating_add(1);
                        assert_raft_write_stalls(
                            &mut cluster,
                            deterministic_raft_command(&key, sequence, seed),
                        )
                        .await?;
                        cluster.network_control.heal().await;
                    } else {
                        heal_after_write = true;
                    }
                }
                RaftDeterministicFault::DurableFollowerRestart => {
                    cluster.kill_and_restart_node(follower).await?;
                }
            }
        }

        let command = deterministic_raft_command(&key, sequence, seed);
        let response = deterministic_raft_write(&mut cluster, command.clone()).await?;
        if response.application_error.is_some() || response.result != Some(CommandResult::Written) {
            return Err(format!(
                "OpenRaft deterministic write {sequence} did not apply: {:?}",
                response
            )
            .into());
        }
        history.push(crate::correctness::HistoryOperation {
            operation_id: sequence,
            invocation_nanos: u128::from(sequence).saturating_mul(2),
            response_nanos: u128::from(sequence).saturating_mul(2).saturating_add(1),
            command,
            result: CommandResult::Written,
        });
        if heal_after_write {
            cluster.network_control.heal().await;
        }
    }

    let final_value = deterministic_raft_value(commands, seed);
    let linearizable_read_passed =
        cluster.read_linearizable(&key).await? == Some(final_value.clone());
    let history_linearizable = history
        .chunks(63)
        .all(|segment| crate::correctness::check_linearizable_history(segment, 64).linearizable);
    cluster.trigger_snapshot().await?;
    let all_nodes_converged = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut converged = true;
            for machine in cluster.state_machines.values() {
                if machine.get(&key).await != Some(final_value.clone()) {
                    converged = false;
                    break;
                }
            }
            if converged {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or(false);
    let final_leader = cluster.current_leader().await?;
    if final_leader != initial_leader {
        leader_changes = leader_changes.saturating_add(1);
    }
    cluster.shutdown().await;
    if durable {
        std::fs::remove_dir_all(&root).ok();
    }
    Ok(RaftDeterministicReport {
        physical_nodes,
        voters,
        learners,
        commands,
        seed,
        durable,
        fault,
        expected_stalls,
        leader_changes,
        final_value,
        all_nodes_converged,
        linearizable_read_passed,
        history_linearizable,
    })
}

fn deterministic_raft_command(key: &[u8], sequence: u64, seed: u64) -> ActiveActiveCommand {
    use blossom::{ClientEpoch, ClientId, CommandIdentity, CommandOperation};

    let mut client = [0u8; 16];
    client[..8].copy_from_slice(&seed.to_le_bytes());
    client[8..].copy_from_slice(&(seed ^ sequence).rotate_left(17).to_le_bytes());
    ActiveActiveCommand {
        identity: CommandIdentity {
            client_id: ClientId(client),
            client_epoch: ClientEpoch(1),
            sequence: 1,
        },
        operation: CommandOperation::BlindWrite {
            key: key.to_vec(),
            value: deterministic_raft_value(sequence, seed),
        },
    }
}

fn deterministic_raft_value(sequence: u64, seed: u64) -> Vec<u8> {
    [sequence.to_le_bytes(), seed.to_le_bytes()].concat()
}

async fn deterministic_raft_write(
    cluster: &mut InProcessRaftCluster,
    command: ActiveActiveCommand,
) -> Result<RaftAppliedResponse, Box<dyn std::error::Error + Send + Sync>> {
    cluster
        .client_write_concurrent(vec![command])
        .await?
        .pop()
        .ok_or_else(|| "deterministic OpenRaft write returned no response".into())
}

async fn assert_raft_write_stalls(
    cluster: &mut InProcessRaftCluster,
    command: ActiveActiveCommand,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match tokio::time::timeout(Duration::from_millis(250), cluster.client_write(command)).await {
        Err(_) | Ok(Err(_)) => Ok(()),
        Ok(Ok(_)) => Err("two-voter OpenRaft write unexpectedly committed without quorum".into()),
    }
}

#[cfg(test)]
mod tests {
    use blossom::{ClientEpoch, ClientId, CommandIdentity, CommandOperation};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn openraft_client_write_waits_through_state_machine_application() {
        let mut cluster = InProcessRaftCluster::start(3, 2).await.unwrap();
        let command = ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([1; 16]),
                client_epoch: ClientEpoch(1),
                sequence: 1,
            },
            operation: CommandOperation::BlindWrite {
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            },
        };
        let response = cluster.client_write(command).await.unwrap();
        assert_eq!(response.data.application_error, None);
        assert_eq!(response.data.result, Some(CommandResult::Written));

        let leader = cluster.ensure_linearizable().await.unwrap();
        assert_eq!(
            cluster.state_machines[&leader].get(b"key").await,
            Some(b"value".to_vec())
        );
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn openraft_concurrent_clients_all_wait_through_application() {
        let mut cluster = InProcessRaftCluster::start(3, 0).await.unwrap();
        let commands = (0..6)
            .map(|writer| ActiveActiveCommand {
                identity: CommandIdentity {
                    client_id: ClientId([20 + writer as u8; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 1,
                },
                operation: CommandOperation::BlindWrite {
                    key: format!("parallel-key-{writer}").into_bytes(),
                    value: vec![writer as u8; 32],
                },
            })
            .collect();

        let responses = cluster.client_write_concurrent(commands).await.unwrap();

        assert_eq!(responses.len(), 6);
        assert!(
            responses
                .iter()
                .all(|response| response.application_error.is_none()
                    && response.result == Some(CommandResult::Written))
        );
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn openraft_re_elects_after_current_leader_is_paused() {
        let mut cluster = InProcessRaftCluster::start(3, 0).await.unwrap();
        let first = cluster.current_leader().await.unwrap();
        cluster.pause_node(first).await.unwrap();
        let second = cluster.current_leader().await.unwrap();
        assert_ne!(first, second);
        cluster.resume_node(first).await.unwrap();
        cluster.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redb_vote_log_state_machine_and_snapshot_survive_restart() {
        let path = std::env::temp_dir().join(format!(
            "blossom-openraft-durable-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config = Arc::new(
            Config {
                heartbeat_interval: 50,
                election_timeout_min: 150,
                election_timeout_max: 300,
                snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(1),
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );
        let routes = Arc::new(RwLock::new(BTreeMap::new()));
        let control = InProcessNetworkControl::default();
        let BenchmarkDurableStores {
            log_store,
            state_machine,
        } = BenchmarkDurableStores::open(&path, 64).unwrap();
        let raft = BenchmarkRaft::new(
            1,
            config.clone(),
            InProcessNetworkFactory {
                source: 1,
                routes: routes.clone(),
                control: control.clone(),
            },
            log_store,
            state_machine.clone(),
        )
        .await
        .unwrap();
        routes.write().await.insert(1, raft.clone());
        raft.initialize(BTreeMap::from([(
            1,
            BasicNode {
                addr: "in-process://1".to_string(),
            },
        )]))
        .await
        .unwrap();
        let mut metrics = raft.metrics();
        tokio::time::timeout(Duration::from_secs(5), async {
            while metrics.borrow().current_leader != Some(1) {
                metrics.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        raft.client_write(ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([7; 16]),
                client_epoch: ClientEpoch(1),
                sequence: 1,
            },
            operation: CommandOperation::BlindWrite {
                key: b"durable".to_vec(),
                value: b"value".to_vec(),
            },
        })
        .await
        .unwrap();
        raft.trigger().snapshot().await.unwrap();
        raft.shutdown().await.unwrap();
        routes.write().await.clear();
        drop(raft);
        drop(state_machine);

        let (log_store, state_machine) = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match BenchmarkDurableStores::open(&path, 64) {
                    Ok(stores) => break (stores.log_store, stores.state_machine),
                    Err(error) if error.to_string().contains("Database already open") => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("reopen durable OpenRaft store: {error}"),
                }
            }
        })
        .await
        .expect("OpenRaft released redb after shutdown");
        assert_eq!(state_machine.get(b"durable").await, Some(b"value".to_vec()));
        assert!(state_machine.last_applied().await.is_some());
        let restarted = BenchmarkRaft::new(
            1,
            config,
            InProcessNetworkFactory {
                source: 1,
                routes: routes.clone(),
                control,
            },
            log_store,
            state_machine.clone(),
        )
        .await
        .unwrap();
        routes.write().await.insert(1, restarted.clone());
        restarted.shutdown().await.unwrap();
        routes.write().await.clear();
        drop(restarted);
        drop(state_machine);
        std::fs::remove_file(path).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn durable_cluster_kill_restart_and_catch_up_is_a_real_restart() {
        let root = std::env::temp_dir().join(format!(
            "blossom-openraft-cluster-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut cluster = InProcessRaftCluster::start_with_storage(
            3,
            0,
            RaftStorageProfile::DurableRedbImmediate { root: root.clone() },
        )
        .await
        .unwrap();
        let leader = cluster.current_leader().await.unwrap();
        let follower = *cluster.voters.iter().find(|node| **node != leader).unwrap();
        cluster
            .client_write(ActiveActiveCommand {
                identity: CommandIdentity {
                    client_id: ClientId([8; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 1,
                },
                operation: CommandOperation::BlindWrite {
                    key: b"restart".to_vec(),
                    value: b"before".to_vec(),
                },
            })
            .await
            .unwrap();
        cluster.kill_and_restart_node(follower).await.unwrap();
        cluster
            .client_write(ActiveActiveCommand {
                identity: CommandIdentity {
                    client_id: ClientId([8; 16]),
                    client_epoch: ClientEpoch(1),
                    sequence: 2,
                },
                operation: CommandOperation::BlindWrite {
                    key: b"restart".to_vec(),
                    value: b"after".to_vec(),
                },
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if cluster.state_machines[&follower].get(b"restart").await
                    == Some(b"after".to_vec())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        cluster.shutdown().await;
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "production durability soak; run explicitly with BLOSSOM_RAFT_SOAK_COMMANDS"]
    async fn durable_openraft_survives_thousand_write_leader_and_follower_restart_soak() {
        let commands = std::env::var("BLOSSOM_RAFT_SOAK_COMMANDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1_001);
        assert!(
            commands >= 1_001,
            "production OpenRaft soak must run 1,001+ writes"
        );
        let root = std::env::temp_dir().join(format!(
            "blossom-openraft-soak-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut cluster = InProcessRaftCluster::start_with_storage(
            3,
            0,
            RaftStorageProfile::DurableRedbImmediate { root: root.clone() },
        )
        .await
        .unwrap();
        let key = b"raft-soak".to_vec();

        for sequence in 1..=commands {
            if sequence.is_multiple_of(211) {
                let leader = cluster.current_leader().await.unwrap();
                cluster.kill_and_restart_node(leader).await.unwrap();
                cluster
                    .wait_for_leader(Duration::from_secs(10))
                    .await
                    .unwrap();
            } else if sequence.is_multiple_of(97) {
                let leader = cluster.current_leader().await.unwrap();
                let follower = *cluster.voters.iter().find(|node| **node != leader).unwrap();
                cluster.kill_and_restart_node(follower).await.unwrap();
            }

            let value = sequence.to_le_bytes().to_vec();
            let response = cluster
                .client_write(ActiveActiveCommand {
                    identity: CommandIdentity {
                        client_id: ClientId([0x5A; 16]),
                        client_epoch: ClientEpoch(1),
                        sequence,
                    },
                    operation: CommandOperation::BlindWrite {
                        key: key.clone(),
                        value: value.clone(),
                    },
                })
                .await
                .unwrap();
            assert_eq!(response.data.application_error, None);
            assert_eq!(response.data.result, Some(CommandResult::Written));

            if sequence.is_multiple_of(101) {
                assert_eq!(cluster.read_linearizable(&key).await.unwrap(), Some(value));
            }
        }

        let expected = commands.to_le_bytes().to_vec();
        cluster.trigger_snapshot().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut converged = true;
                for machine in cluster.state_machines.values() {
                    if machine.get(&key).await != Some(expected.clone()) {
                        converged = false;
                        break;
                    }
                }
                if converged {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("OpenRaft followers did not converge after the restart soak");
        assert_eq!(
            cluster.read_linearizable(&key).await.unwrap(),
            Some(expected)
        );
        cluster.shutdown().await;
        std::fs::remove_dir_all(root).ok();
    }
}
