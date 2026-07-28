//! In-process OpenRaft network, partitions, and scripted RPC faults.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkState {
    Healthy,
    Blocked,
    Delayed(Duration),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaftRpcKind {
    AppendEntries,
    InstallSnapshot,
    Vote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RaftRpcMatch {
    Any,
    DataBearing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum RaftRpcFaultAction {
    DropRequest,
    DropResponse,
    DuplicateRequest,
    DelayRequest { millis: u64 },
    DelayResponse { millis: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptedRaftRpcFault {
    pub id: String,
    pub source: Option<NodeId>,
    pub target: Option<NodeId>,
    pub rpc: RaftRpcKind,
    pub request_match: RaftRpcMatch,
    pub action: RaftRpcFaultAction,
}

impl ScriptedRaftRpcFault {
    pub fn between(
        id: impl Into<String>,
        source: NodeId,
        target: NodeId,
        rpc: RaftRpcKind,
        request_match: RaftRpcMatch,
        action: RaftRpcFaultAction,
    ) -> Self {
        Self {
            id: id.into(),
            source: Some(source),
            target: Some(target),
            rpc,
            request_match,
            action,
        }
    }

    pub fn any_route(
        id: impl Into<String>,
        rpc: RaftRpcKind,
        request_match: RaftRpcMatch,
        action: RaftRpcFaultAction,
    ) -> Self {
        Self {
            id: id.into(),
            source: None,
            target: None,
            rpc,
            request_match,
            action,
        }
    }

    fn matches(
        &self,
        source: NodeId,
        target: NodeId,
        rpc: RaftRpcKind,
        data_bearing: bool,
    ) -> bool {
        self.source.is_none_or(|expected| expected == source)
            && self.target.is_none_or(|expected| expected == target)
            && self.rpc == rpc
            && match self.request_match {
                RaftRpcMatch::Any => true,
                RaftRpcMatch::DataBearing => data_bearing,
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftRpcFaultEvent {
    pub id: String,
    pub source: NodeId,
    pub target: NodeId,
    pub rpc: RaftRpcKind,
    pub data_bearing: bool,
    pub action: RaftRpcFaultAction,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RaftNetworkFaultCoverage {
    pub total_rpcs: u64,
    pub append_entries_rpcs: u64,
    pub data_bearing_append_entries_rpcs: u64,
    pub install_snapshot_rpcs: u64,
    pub vote_rpcs: u64,
    pub blocked_by_link: u64,
    pub delayed_by_link: u64,
    pub request_drops: u64,
    pub response_drops: u64,
    pub duplicate_requests: u64,
    pub request_delays: u64,
    pub response_delays: u64,
    pub configured_fault_ids: BTreeSet<String>,
    pub executed_fault_ids: BTreeSet<String>,
    pub configured_faults: Vec<ScriptedRaftRpcFault>,
    pub executed_faults: Vec<RaftRpcFaultEvent>,
}

impl RaftNetworkFaultCoverage {
    pub fn unfired_fault_ids(&self) -> BTreeSet<String> {
        self.configured_fault_ids
            .difference(&self.executed_fault_ids)
            .cloned()
            .collect()
    }

    pub fn all_scripted_faults_fired(&self) -> bool {
        self.unfired_fault_ids().is_empty()
    }
}

#[derive(Debug, Default)]
struct InProcessNetworkState {
    links: BTreeMap<(NodeId, NodeId), LinkState>,
    scripted_faults: Vec<ScriptedRaftRpcFault>,
    coverage: RaftNetworkFaultCoverage,
}

#[derive(Debug, Clone, Default)]
pub struct InProcessNetworkControl {
    state: Arc<RwLock<InProcessNetworkState>>,
    routes: Arc<Mutex<Option<Weak<InProcessRoutes>>>>,
}

impl InProcessNetworkControl {
    pub(super) fn attach_routes(&self, routes: &SharedInProcessRoutes) {
        *self.routes.lock().expect("benchmark routes lock poisoned") = Some(Arc::downgrade(routes));
    }

    pub async fn set_link(&self, source: NodeId, target: NodeId, state: LinkState) {
        self.state
            .write()
            .await
            .links
            .insert((source, target), state);
    }

    pub async fn partition(&self, left: &BTreeSet<NodeId>, right: &BTreeSet<NodeId>) {
        let mut state = self.state.write().await;
        for source in left {
            for target in right {
                state.links.insert((*source, *target), LinkState::Blocked);
                state.links.insert((*target, *source), LinkState::Blocked);
            }
        }
    }

    pub async fn script_rpc_fault(
        &self,
        fault: ScriptedRaftRpcFault,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if fault.id.trim().is_empty() {
            return Err("scripted Raft RPC fault ID must not be empty".into());
        }
        let mut state = self.state.write().await;
        if state.coverage.configured_fault_ids.contains(&fault.id) {
            return Err(format!("duplicate scripted Raft RPC fault ID: {}", fault.id).into());
        }
        state.coverage.configured_fault_ids.insert(fault.id.clone());
        state.coverage.configured_faults.push(fault.clone());
        state.scripted_faults.push(fault);
        Ok(())
    }

    pub async fn clear_pending_scripted_faults(&self) {
        self.state.write().await.scripted_faults.clear();
    }

    pub async fn coverage(&self) -> RaftNetworkFaultCoverage {
        self.state.read().await.coverage.clone()
    }

    /// Heals every simulated link and drives replication until the live nodes
    /// have caught up with the leader's applied watermark.
    ///
    /// Clearing an out-of-band simulated partition is not itself an OpenRaft
    /// event. A single heartbeat is also insufficient when the first request
    /// discovers that an isolated voter advanced its term: that request makes
    /// the old leader step down, before the replacement leader exists to be
    /// woken. Keep waking leaders across the transition and wait for ordinary
    /// append replication to converge. The bounded wait keeps this fault
    /// control usable when the caller deliberately leaves another fault active.
    pub async fn heal(&self) {
        self.state.write().await.links.clear();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut converged_samples = 0u8;
        loop {
            let nodes = self.live_nodes().await;
            for raft in &nodes {
                if raft.metrics().borrow().state == openraft::ServerState::Leader {
                    let _ = raft.trigger().heartbeat().await;
                }
            }

            if replication_is_converged(&nodes) {
                converged_samples = converged_samples.saturating_add(1);
                if converged_samples >= 2 {
                    return;
                }
            } else {
                converged_samples = 0;
            }
            if tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    pub(super) async fn wake_replication(&self) {
        for raft in self.live_nodes().await {
            if raft.metrics().borrow().state == openraft::ServerState::Leader {
                let _ = raft.trigger().heartbeat().await;
            }
        }
    }

    async fn live_nodes(&self) -> Vec<BenchmarkRaft> {
        let routes = self
            .routes
            .lock()
            .expect("benchmark routes lock poisoned")
            .as_ref()
            .and_then(Weak::upgrade);
        let Some(routes) = routes else {
            return Vec::new();
        };
        routes.read().await.values().cloned().collect()
    }

    async fn begin_rpc(
        &self,
        source: NodeId,
        target: NodeId,
        rpc: RaftRpcKind,
        data_bearing: bool,
    ) -> Result<RpcDirective, RPCTransportError> {
        let (link_state, scripted_fault) = {
            let mut state = self.state.write().await;
            state.coverage.total_rpcs = state.coverage.total_rpcs.saturating_add(1);
            match rpc {
                RaftRpcKind::AppendEntries => {
                    state.coverage.append_entries_rpcs =
                        state.coverage.append_entries_rpcs.saturating_add(1);
                    if data_bearing {
                        state.coverage.data_bearing_append_entries_rpcs = state
                            .coverage
                            .data_bearing_append_entries_rpcs
                            .saturating_add(1);
                    }
                }
                RaftRpcKind::InstallSnapshot => {
                    state.coverage.install_snapshot_rpcs =
                        state.coverage.install_snapshot_rpcs.saturating_add(1);
                }
                RaftRpcKind::Vote => {
                    state.coverage.vote_rpcs = state.coverage.vote_rpcs.saturating_add(1);
                }
            }

            let link_state = state.links.get(&(source, target)).cloned();
            if matches!(link_state, Some(LinkState::Blocked)) {
                state.coverage.blocked_by_link = state.coverage.blocked_by_link.saturating_add(1);
                return Err(RPCTransportError::Blocked);
            }
            if matches!(link_state, Some(LinkState::Delayed(_))) {
                state.coverage.delayed_by_link = state.coverage.delayed_by_link.saturating_add(1);
            }

            let scripted_fault = state
                .scripted_faults
                .iter()
                .position(|fault| fault.matches(source, target, rpc, data_bearing))
                .map(|position| state.scripted_faults.remove(position));
            if let Some(fault) = &scripted_fault {
                state.coverage.executed_fault_ids.insert(fault.id.clone());
                state.coverage.executed_faults.push(RaftRpcFaultEvent {
                    id: fault.id.clone(),
                    source,
                    target,
                    rpc,
                    data_bearing,
                    action: fault.action,
                });
                match fault.action {
                    RaftRpcFaultAction::DropRequest => {
                        state.coverage.request_drops =
                            state.coverage.request_drops.saturating_add(1);
                    }
                    RaftRpcFaultAction::DropResponse => {
                        state.coverage.response_drops =
                            state.coverage.response_drops.saturating_add(1);
                    }
                    RaftRpcFaultAction::DuplicateRequest => {
                        state.coverage.duplicate_requests =
                            state.coverage.duplicate_requests.saturating_add(1);
                    }
                    RaftRpcFaultAction::DelayRequest { .. } => {
                        state.coverage.request_delays =
                            state.coverage.request_delays.saturating_add(1);
                    }
                    RaftRpcFaultAction::DelayResponse { .. } => {
                        state.coverage.response_delays =
                            state.coverage.response_delays.saturating_add(1);
                    }
                }
            }
            (link_state, scripted_fault)
        };

        if let Some(LinkState::Delayed(delay)) = link_state {
            tokio::time::sleep(delay).await;
        }
        if let Some(fault) = &scripted_fault {
            match fault.action {
                RaftRpcFaultAction::DropRequest => {
                    return Err(RPCTransportError::ScriptedRequestDrop(fault.id.clone()));
                }
                RaftRpcFaultAction::DelayRequest { millis } => {
                    tokio::time::sleep(Duration::from_millis(millis)).await;
                }
                RaftRpcFaultAction::DropResponse
                | RaftRpcFaultAction::DuplicateRequest
                | RaftRpcFaultAction::DelayResponse { .. } => {}
            }
        }
        Ok(RpcDirective { scripted_fault })
    }

    async fn finish_rpc(&self, directive: &RpcDirective) -> Result<(), RPCTransportError> {
        let Some(fault) = &directive.scripted_fault else {
            return Ok(());
        };
        match fault.action {
            RaftRpcFaultAction::DropResponse => {
                Err(RPCTransportError::ScriptedResponseDrop(fault.id.clone()))
            }
            RaftRpcFaultAction::DelayResponse { millis } => {
                tokio::time::sleep(Duration::from_millis(millis)).await;
                Ok(())
            }
            RaftRpcFaultAction::DropRequest
            | RaftRpcFaultAction::DuplicateRequest
            | RaftRpcFaultAction::DelayRequest { .. } => Ok(()),
        }
    }
}

#[derive(Debug)]
struct RpcDirective {
    scripted_fault: Option<ScriptedRaftRpcFault>,
}

impl RpcDirective {
    fn duplicate_request(&self) -> bool {
        self.scripted_fault
            .as_ref()
            .is_some_and(|fault| fault.action == RaftRpcFaultAction::DuplicateRequest)
    }
}

fn replication_is_converged(nodes: &[BenchmarkRaft]) -> bool {
    let snapshots = nodes
        .iter()
        .map(|raft| raft.metrics().borrow().clone())
        .collect::<Vec<_>>();
    let leaders = snapshots
        .iter()
        .filter(|metrics| metrics.state == openraft::ServerState::Leader)
        .collect::<Vec<_>>();
    if leaders.len() != 1 {
        return false;
    }
    let leader = leaders[0];
    let Some(leader_id) = leader.current_leader else {
        return false;
    };
    let target = leader.last_applied.map(|log_id| log_id.index);
    snapshots.iter().all(|metrics| {
        metrics.current_leader == Some(leader_id)
            && match (metrics.last_applied.map(|log_id| log_id.index), target) {
                (_, None) => true,
                (Some(applied), Some(target)) => applied >= target,
                (None, Some(_)) => false,
            }
    })
}

#[derive(Debug)]
enum RPCTransportError {
    Blocked,
    MissingNode,
    ScriptedRequestDrop(String),
    ScriptedResponseDrop(String),
}

impl std::fmt::Display for RPCTransportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocked => write!(formatter, "benchmark network link is blocked"),
            Self::MissingNode => write!(formatter, "benchmark target node is unavailable"),
            Self::ScriptedRequestDrop(id) => {
                write!(formatter, "scripted Raft RPC request drop: {id}")
            }
            Self::ScriptedResponseDrop(id) => {
                write!(formatter, "scripted Raft RPC response drop: {id}")
            }
        }
    }
}

impl std::error::Error for RPCTransportError {}

#[derive(Clone, Default)]
pub(super) struct InProcessNetworkFactory {
    pub(super) source: NodeId,
    pub(super) routes: SharedInProcessRoutes,
    pub(super) control: InProcessNetworkControl,
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

pub(super) struct InProcessNetwork {
    source: NodeId,
    target: NodeId,
    routes: SharedInProcessRoutes,
    control: InProcessNetworkControl,
}

impl InProcessNetwork {
    async fn target(
        &self,
        rpc: RaftRpcKind,
        data_bearing: bool,
    ) -> Result<(BenchmarkRaft, RpcDirective), RPCTransportError> {
        let target = self
            .routes
            .read()
            .await
            .get(&self.target)
            .cloned()
            .ok_or(RPCTransportError::MissingNode)?;
        let directive = self
            .control
            .begin_rpc(self.source, self.target, rpc, data_bearing)
            .await?;
        Ok((target, directive))
    }

    async fn finish_rpc(
        &self,
        directive: &RpcDirective,
    ) -> Result<(), RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.control
            .finish_rpc(directive)
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))
    }
}

impl RaftNetwork<BenchmarkRaftConfig> for InProcessNetwork {
    fn backoff(&self) -> Backoff {
        // Fault windows in the in-process adapter are short and explicitly
        // controlled. A production-scale 500 ms unreachable backoff can drain
        // every heal heartbeat and leave the simulated replica unaware that
        // connectivity returned. Retry promptly without busy-spinning.
        Backoff::new(std::iter::repeat(Duration::from_millis(10)))
    }

    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<BenchmarkRaftConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let data_bearing = !request.entries.is_empty();
        let (target, directive) = self
            .target(RaftRpcKind::AppendEntries, data_bearing)
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))?;
        let response = target
            .append_entries(request.clone())
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)));
        if directive.duplicate_request() {
            let _ = target.append_entries(request).await;
        }
        self.finish_rpc(&directive).await?;
        response
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<BenchmarkRaftConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let (target, directive) = self
            .target(RaftRpcKind::InstallSnapshot, !request.data.is_empty())
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))?;
        let response = target
            .install_snapshot(request.clone())
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)));
        if directive.duplicate_request() {
            let _ = target.install_snapshot(request).await;
        }
        self.control
            .finish_rpc(&directive)
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))?;
        response
    }

    async fn vote(
        &mut self,
        request: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let (target, directive) = self
            .target(RaftRpcKind::Vote, true)
            .await
            .map_err(|error| RPCError::Unreachable(Unreachable::new(&error)))?;
        let response = target
            .vote(request.clone())
            .await
            .map_err(|error| RPCError::RemoteError(RemoteError::new(self.target, error)));
        if directive.duplicate_request() {
            let _ = target.vote(request).await;
        }
        self.finish_rpc(&directive).await?;
        response
    }
}
