//! End-to-end OpenRaft election, write, membership, snapshot, and restart tests.

#![cfg(feature = "active-passive")]
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use blossom::active_passive::openraft;
use blossom::{
    ActivePassiveCommand, ActivePassiveContract, ActivePassiveContractChange, ActivePassiveNode,
    ActivePassiveRaft, ActivePassiveRaftConfig, ActivePassiveRequest, ActivePassiveResponse,
    ActivePassiveRuntime, ApplicationCommand, ApplicationCommandEnvelope, ApplicationResult,
    ClientEpoch, ClientId, CommandIdentity, CommandSpecVersion, HaServiceTopology, HashType,
    MemoryRaftLogStore, RaftLogStoreIdentity, RouteGeneration, ShardStreamRaftLogStore,
};
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
    Config, Entry, EntryPayload, LogId, RaftSnapshotBuilder, SnapshotMeta, StorageError,
    StorageIOError, StoredMembership,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

type NodeId = u64;

#[test]
fn durable_log_is_bound_to_cluster_and_node_identity() {
    let path = std::env::temp_dir().join(format!(
        "blossom-active-passive-identity-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    std::fs::remove_dir_all(&path).ok();
    let expected = RaftLogStoreIdentity::new("native-active-passive", 7);
    let store =
        ShardStreamRaftLogStore::<ActivePassiveRaftConfig>::open_bound(&path, expected.clone())
            .unwrap();
    assert_eq!(store.identity(), expected.clone());
    ShardStreamRaftLogStore::<ActivePassiveRaftConfig>::from_log_store(store.log_store(), expected)
        .unwrap();
    let wrong_node = ShardStreamRaftLogStore::<ActivePassiveRaftConfig>::from_log_store(
        store.log_store(),
        RaftLogStoreIdentity::new("native-active-passive", 8),
    );
    assert!(wrong_node.is_err());
    let wrong_cluster = ShardStreamRaftLogStore::<ActivePassiveRaftConfig>::from_log_store(
        store.log_store(),
        RaftLogStoreIdentity::new("another-cluster", 7),
    );
    assert!(wrong_cluster.is_err());
    drop(store);
    std::fs::remove_dir_all(path).ok();
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AppliedRecord {
    identity: CommandIdentity,
    command_hash: HashType,
    result: ApplicationResult,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TestState {
    last_applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, ActivePassiveNode>,
    contract: ActivePassiveContract,
    applied: Vec<AppliedRecord>,
}

impl TestState {
    fn new() -> Self {
        Self {
            last_applied: None,
            membership: StoredMembership::default(),
            contract: ActivePassiveContract::new(RouteGeneration(1), CommandSpecVersion(1))
                .unwrap(),
            applied: Vec::new(),
        }
    }

    fn apply_request(&mut self, request: ActivePassiveRequest) -> ActivePassiveResponse {
        match request {
            ActivePassiveRequest::Command(command) => {
                let identity = command.identity();
                if let Err(error) = self.contract.validate_command(&command) {
                    return ActivePassiveResponse {
                        command_identity: Some(identity),
                        application_error: Some(error.to_string()),
                        ..Default::default()
                    };
                }
                let command_hash = match command.hash() {
                    Ok(hash) => hash,
                    Err(error) => {
                        return ActivePassiveResponse {
                            command_identity: Some(identity),
                            application_error: Some(error.to_string()),
                            ..Default::default()
                        };
                    }
                };
                if let Some(existing) = self
                    .applied
                    .iter()
                    .find(|record| record.identity == identity)
                {
                    return if existing.command_hash == command_hash {
                        ActivePassiveResponse {
                            command_identity: Some(identity),
                            result: Some(existing.result.clone()),
                            ..Default::default()
                        }
                    } else {
                        ActivePassiveResponse {
                            command_identity: Some(identity),
                            application_error: Some(
                                "command identity was reused with different bytes".to_string(),
                            ),
                            ..Default::default()
                        }
                    };
                }
                let result =
                    match ApplicationResult::new(command.command.command.as_bytes().to_vec()) {
                        Ok(result) => result,
                        Err(error) => {
                            return ActivePassiveResponse {
                                command_identity: Some(identity),
                                application_error: Some(error.to_string()),
                                ..Default::default()
                            };
                        }
                    };
                self.applied.push(AppliedRecord {
                    identity,
                    command_hash,
                    result: result.clone(),
                });
                ActivePassiveResponse {
                    command_identity: Some(identity),
                    result: Some(result),
                    ..Default::default()
                }
            }
            ActivePassiveRequest::ActivateContract(change) => {
                if let Err(error) = self.contract.activate(change) {
                    return ActivePassiveResponse {
                        application_error: Some(error.to_string()),
                        ..Default::default()
                    };
                }
                ActivePassiveResponse {
                    activated_contract: Some(self.contract),
                    ..Default::default()
                }
            }
        }
    }
}

struct TestStateMachine {
    state: RwLock<TestState>,
    snapshot: RwLock<Option<TestSnapshotRecord>>,
    snapshot_index: AtomicU64,
}

type TestSnapshotRecord = (SnapshotMeta<NodeId, ActivePassiveNode>, Vec<u8>);

#[derive(Clone)]
struct TestStateMachineHandle(Arc<TestStateMachine>);

impl TestStateMachine {
    fn handle() -> TestStateMachineHandle {
        TestStateMachineHandle(Arc::new(Self {
            state: RwLock::new(TestState::new()),
            snapshot: RwLock::new(None),
            snapshot_index: AtomicU64::new(0),
        }))
    }
}

impl RaftSnapshotBuilder<ActivePassiveRaftConfig> for TestStateMachineHandle {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<ActivePassiveRaftConfig>, StorageError<NodeId>> {
        let state = self.0.state.read().await;
        let data = serde_json::to_vec(&*state)
            .map_err(|error| StorageIOError::read_state_machine(&error))?;
        let index = self.0.snapshot_index.fetch_add(1, Ordering::Relaxed) + 1;
        let meta = SnapshotMeta {
            last_log_id: state.last_applied,
            last_membership: state.membership.clone(),
            snapshot_id: format!("test-{index}"),
        };
        *self.0.snapshot.write().await = Some((meta.clone(), data.clone()));
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<ActivePassiveRaftConfig> for TestStateMachineHandle {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<NodeId>>,
            StoredMembership<NodeId, ActivePassiveNode>,
        ),
        StorageError<NodeId>,
    > {
        let state = self.0.state.read().await;
        Ok((state.last_applied, state.membership.clone()))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<ActivePassiveResponse>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<ActivePassiveRaftConfig>> + Send,
    {
        let mut state = self.0.state.write().await;
        let mut responses = Vec::new();
        for entry in entries {
            state.last_applied = Some(entry.log_id);
            let response = match entry.payload {
                EntryPayload::Blank => ActivePassiveResponse::default(),
                EntryPayload::Membership(membership) => {
                    state.membership = StoredMembership::new(Some(entry.log_id), membership);
                    ActivePassiveResponse::default()
                }
                EntryPayload::Normal(request) => state.apply_request(request),
            };
            responses.push(response);
        }
        Ok(responses)
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<
        Box<<ActivePassiveRaftConfig as openraft::RaftTypeConfig>::SnapshotData>,
        StorageError<NodeId>,
    > {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, ActivePassiveNode>,
        snapshot: Box<<ActivePassiveRaftConfig as openraft::RaftTypeConfig>::SnapshotData>,
    ) -> Result<(), StorageError<NodeId>> {
        let data = snapshot.into_inner();
        let state: TestState = serde_json::from_slice(&data)
            .map_err(|error| StorageIOError::read_snapshot(Some(meta.signature()), &error))?;
        *self.0.state.write().await = state;
        *self.0.snapshot.write().await = Some((meta.clone(), data));
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<ActivePassiveRaftConfig>>, StorageError<NodeId>> {
        Ok(self
            .0
            .snapshot
            .read()
            .await
            .as_ref()
            .map(|(meta, data)| Snapshot {
                meta: meta.clone(),
                snapshot: Box::new(Cursor::new(data.clone())),
            }))
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }
}

#[derive(Debug)]
struct TestNetworkError(&'static str);

impl std::fmt::Display for TestNetworkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TestNetworkError {}

#[derive(Clone, Default)]
struct TestNetworkFactory {
    source: NodeId,
    routes: Arc<RwLock<BTreeMap<NodeId, ActivePassiveRaft>>>,
    blocked: Arc<RwLock<BTreeSet<(NodeId, NodeId)>>>,
}

impl TestNetworkFactory {
    async fn isolate(&self, node_id: NodeId, nodes: impl Iterator<Item = NodeId>) {
        let mut blocked = self.blocked.write().await;
        for peer in nodes.filter(|peer| *peer != node_id) {
            blocked.insert((node_id, peer));
            blocked.insert((peer, node_id));
        }
    }
}

impl RaftNetworkFactory<ActivePassiveRaftConfig> for TestNetworkFactory {
    type Network = TestNetwork;

    async fn new_client(&mut self, target: NodeId, _node: &ActivePassiveNode) -> Self::Network {
        TestNetwork {
            source: self.source,
            target,
            routes: self.routes.clone(),
            blocked: self.blocked.clone(),
        }
    }
}

struct TestNetwork {
    source: NodeId,
    target: NodeId,
    routes: Arc<RwLock<BTreeMap<NodeId, ActivePassiveRaft>>>,
    blocked: Arc<RwLock<BTreeSet<(NodeId, NodeId)>>>,
}

impl TestNetwork {
    async fn target(
        &self,
    ) -> Result<ActivePassiveRaft, RPCError<NodeId, ActivePassiveNode, RaftError<NodeId>>> {
        if self
            .blocked
            .read()
            .await
            .contains(&(self.source, self.target))
        {
            return Err(RPCError::Unreachable(Unreachable::new(&TestNetworkError(
                "test link is blocked",
            ))));
        }
        self.routes
            .read()
            .await
            .get(&self.target)
            .cloned()
            .ok_or_else(|| {
                RPCError::Unreachable(Unreachable::new(&TestNetworkError(
                    "test target is unavailable",
                )))
            })
    }
}

impl RaftNetwork<ActivePassiveRaftConfig> for TestNetwork {
    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<ActivePassiveRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, ActivePassiveNode, RaftError<NodeId>>>
    {
        self.target()
            .await?
            .append_entries(request)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<ActivePassiveRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, ActivePassiveNode, RaftError<NodeId, InstallSnapshotError>>,
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
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, ActivePassiveNode, RaftError<NodeId>>> {
        self.target()
            .await?
            .vote(request)
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)))
    }
}

async fn wait_for_leader(
    runtimes: &BTreeMap<NodeId, ActivePassiveRuntime>,
    excluded: Option<NodeId>,
) -> NodeId {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        for (node_id, runtime) in runtimes {
            if Some(*node_id) == excluded {
                continue;
            }
            let metrics = runtime.metrics();
            let metrics = metrics.borrow();
            if metrics.state == openraft::ServerState::Leader
                && metrics.current_leader == Some(*node_id)
            {
                return *node_id;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for OpenRaft leader"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn command(sequence: u64, route: u64, spec: u64, bytes: &[u8]) -> ActivePassiveCommand {
    ActivePassiveCommand {
        route_generation: RouteGeneration(route),
        command_spec_version: CommandSpecVersion(spec),
        command: ApplicationCommandEnvelope {
            identity: CommandIdentity {
                client_id: ClientId([9; 16]),
                client_epoch: ClientEpoch(1),
                sequence,
            },
            command: ApplicationCommand::new(bytes.to_vec()).unwrap(),
        },
    }
}

#[tokio::test]
async fn native_runtime_rejects_wrong_topology_and_empty_cluster_name() {
    let network = TestNetworkFactory::default();
    let wrong_topology = ActivePassiveRuntime::new(
        1,
        HaServiceTopology::active_active(3).unwrap(),
        Arc::new(Config::default().validate().unwrap()),
        network.clone(),
        MemoryRaftLogStore::<ActivePassiveRaftConfig>::default(),
        TestStateMachine::handle(),
    )
    .await;
    assert!(wrong_topology.is_err());

    let empty_cluster = ActivePassiveRuntime::new(
        1,
        HaServiceTopology::active_passive(3, 3).unwrap(),
        Arc::new(
            Config {
                cluster_name: " ".to_string(),
                ..Default::default()
            }
            .validate()
            .unwrap(),
        ),
        network,
        MemoryRaftLogStore::<ActivePassiveRaftConfig>::default(),
        TestStateMachine::handle(),
    )
    .await;
    assert!(empty_cluster.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_active_passive_supports_failover_contracts_learners_and_reads() {
    let topology = HaServiceTopology::active_passive(4, 3).unwrap();
    let routes = Arc::new(RwLock::new(BTreeMap::new()));
    let blocked = Arc::new(RwLock::new(BTreeSet::new()));
    let config = Arc::new(
        Config {
            cluster_name: "blossom-native-active-passive-test".to_string(),
            heartbeat_interval: 25,
            election_timeout_min: 200,
            election_timeout_max: 400,
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(4),
            ..Default::default()
        }
        .validate()
        .unwrap(),
    );

    let mut runtimes = BTreeMap::new();
    for node_id in 1..=4 {
        let runtime = ActivePassiveRuntime::new(
            node_id,
            topology,
            config.clone(),
            TestNetworkFactory {
                source: node_id,
                routes: routes.clone(),
                blocked: blocked.clone(),
            },
            MemoryRaftLogStore::<ActivePassiveRaftConfig>::default(),
            TestStateMachine::handle(),
        )
        .await
        .unwrap();
        routes.write().await.insert(node_id, runtime.raft().clone());
        runtimes.insert(node_id, runtime);
    }

    let initial = (1..=3)
        .map(|node_id| {
            (
                node_id,
                ActivePassiveNode {
                    addr: format!("in-process://{node_id}"),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    runtimes.get(&1).unwrap().initialize(initial).await.unwrap();
    let leader = wait_for_leader(&runtimes, None).await;

    let first = runtimes
        .get(&leader)
        .unwrap()
        .client_write(command(1, 1, 1, b"first"))
        .await
        .unwrap();
    assert_eq!(first.data.result.unwrap().as_bytes(), b"first");
    runtimes
        .get(&leader)
        .unwrap()
        .ensure_linearizable()
        .await
        .unwrap();

    let activation = runtimes
        .get(&leader)
        .unwrap()
        .activate_application_contract(ActivePassiveContractChange {
            previous_route_generation: RouteGeneration(1),
            route_generation: RouteGeneration(2),
            previous_command_spec_version: CommandSpecVersion(1),
            command_spec_version: CommandSpecVersion(2),
        })
        .await
        .unwrap();
    assert_eq!(
        activation.data.activated_contract,
        Some(ActivePassiveContract::new(RouteGeneration(2), CommandSpecVersion(2)).unwrap())
    );

    let fenced = runtimes
        .get(&leader)
        .unwrap()
        .client_write(command(2, 1, 1, b"stale"))
        .await
        .unwrap();
    assert!(fenced.data.application_error.is_some());
    let upgraded = runtimes
        .get(&leader)
        .unwrap()
        .client_write(command(3, 2, 2, b"upgraded"))
        .await
        .unwrap();
    assert_eq!(upgraded.data.result.unwrap().as_bytes(), b"upgraded");

    runtimes
        .get(&leader)
        .unwrap()
        .add_learner(
            4,
            ActivePassiveNode {
                addr: "in-process://4".to_string(),
            },
            true,
        )
        .await
        .unwrap();
    let excess_learner = runtimes
        .get(&leader)
        .unwrap()
        .add_learner(
            5,
            ActivePassiveNode {
                addr: "in-process://5".to_string(),
            },
            true,
        )
        .await;
    assert!(excess_learner.is_err());
    let undersized_voters = runtimes
        .get(&leader)
        .unwrap()
        .replace_voters([1, 2], false)
        .await;
    assert!(undersized_voters.is_err());
    let voters = [1, 2, 4].into_iter().collect::<BTreeSet<_>>();
    runtimes
        .get(&leader)
        .unwrap()
        .replace_voters(voters, false)
        .await
        .unwrap();

    TestNetworkFactory {
        source: 0,
        routes: routes.clone(),
        blocked: blocked.clone(),
    }
    .isolate(leader, 1..=4)
    .await;
    let replacement = wait_for_leader(&runtimes, Some(leader)).await;
    let after_failover = runtimes
        .get(&replacement)
        .unwrap()
        .client_write(command(4, 2, 2, b"after-failover"))
        .await
        .unwrap();
    assert_eq!(
        after_failover.data.result.unwrap().as_bytes(),
        b"after-failover"
    );
    runtimes
        .get(&replacement)
        .unwrap()
        .ensure_linearizable()
        .await
        .unwrap();
    let status = runtimes
        .get(&replacement)
        .unwrap()
        .operational_status(3)
        .unwrap();
    assert_eq!(status.current_leader, Some(replacement));
    assert!(status.accepts_local_writes);

    for runtime in runtimes.values() {
        runtime.shutdown().await.unwrap();
    }
}
