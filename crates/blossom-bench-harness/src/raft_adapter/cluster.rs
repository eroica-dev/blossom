//! Native OpenRaft cluster lifecycle, writes, reads, membership, and restart.

use super::*;

pub struct InProcessRaftCluster {
    pub nodes: BTreeMap<NodeId, BenchmarkRaft>,
    pub state_machines: BTreeMap<NodeId, Arc<BenchmarkStateMachineStore>>,
    pub voters: BTreeSet<NodeId>,
    pub learners: BTreeSet<NodeId>,
    pub network_control: InProcessNetworkControl,
    metrics: BTreeMap<NodeId, watch::Receiver<openraft::RaftMetrics<NodeId, BasicNode>>>,
    routes: SharedInProcessRoutes,
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
        let config = Config {
            heartbeat_interval: 50,
            // Keep local scheduler pressure from hundreds of concurrent
            // benchmark clients from masquerading as a leader fault.
            election_timeout_min: 1_000,
            election_timeout_max: 2_000,
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(10_000),
            ..Default::default()
        };
        Self::start_with_storage_and_config(voter_count, learner_count, storage, config).await
    }

    pub async fn start_with_storage_and_config(
        voter_count: usize,
        learner_count: usize,
        storage: RaftStorageProfile,
        config: Config,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::start_with_validated_config(
            voter_count,
            learner_count,
            storage,
            Arc::new(config.validate()?),
        )
        .await
    }

    async fn start_with_validated_config(
        voter_count: usize,
        learner_count: usize,
        storage: RaftStorageProfile,
        config: Arc<Config>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        if !matches!(voter_count, 2 | 3 | 5 | 7) {
            return Err("benchmark Raft voter count must be 2, 3, 5, or 7".into());
        }
        let total = voter_count
            .checked_add(learner_count)
            .ok_or("Raft cluster size overflow")?;
        let routes = Arc::new(RwLock::new(BTreeMap::new()));
        let network_control = InProcessNetworkControl::default();
        network_control.attach_routes(&routes);
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
                RaftStorageProfile::DurableShardStream { root } => {
                    std::fs::create_dir_all(root)?;
                    let path = root.join(format!("node-{node_id}"));
                    let stores =
                        BenchmarkDurableStores::open(&path, 4096, node_id, &config.cluster_name)?;
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

    pub fn protocol_state(&self) -> Vec<RaftNodeProtocolState> {
        self.metrics
            .iter()
            .map(|(node_id, receiver)| {
                let metrics = receiver.borrow();
                RaftNodeProtocolState {
                    node_id: *node_id,
                    running: metrics.running_state.is_ok(),
                    current_term: metrics.current_term,
                    current_leader: metrics.current_leader,
                    last_log_index: metrics.last_log_index,
                    last_applied_index: metrics.last_applied.map(|log_id| log_id.index),
                    snapshot_index: metrics.snapshot.map(|log_id| log_id.index),
                    purged_index: metrics.purged.map(|log_id| log_id.index),
                    voter_ids: metrics.membership_config.voter_ids().collect(),
                }
            })
            .collect()
    }

    pub fn protocol_invariants_hold(&self) -> bool {
        self.protocol_state()
            .iter()
            .all(RaftNodeProtocolState::invariants_hold)
    }

    pub async fn wait_for_protocol_invariants(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.protocol_invariants_hold() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn replace_voters(
        &mut self,
        voter_ids: BTreeSet<NodeId>,
        retain_removed_as_learners: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if voter_ids.is_empty() {
            return Err("OpenRaft voter replacement cannot be empty".into());
        }
        if !voter_ids
            .iter()
            .all(|node_id| self.nodes.contains_key(node_id))
        {
            return Err("OpenRaft voter replacement references an unknown node".into());
        }
        let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
        self.nodes[&leader]
            .change_membership(voter_ids.clone(), retain_removed_as_learners)
            .await?;
        self.voters = voter_ids;
        self.learners = self
            .nodes
            .keys()
            .copied()
            .filter(|node_id| !self.voters.contains(node_id))
            .collect();
        Ok(())
    }

    pub async fn wait_for_voters(
        &self,
        voter_ids: &BTreeSet<NodeId>,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let converged = self.metrics.values().all(|receiver| {
                receiver
                    .borrow()
                    .membership_config
                    .voter_ids()
                    .collect::<BTreeSet<_>>()
                    == *voter_ids
            });
            if converged {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for OpenRaft voter membership {voter_ids:?}"
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn kill_and_restart_node(
        &mut self,
        node_id: NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path = self
            .storage_paths
            .get(&node_id)
            .cloned()
            .ok_or("kill/restart requires the durable shard-stream storage profile")?;
        self.routes.write().await.remove(&node_id);
        let raft = self
            .nodes
            .remove(&node_id)
            .ok_or_else(|| format!("unknown OpenRaft node {node_id}"))?;
        raft.shutdown().await?;
        drop(raft);
        self.state_machines.remove(&node_id);
        self.metrics.remove(&node_id);

        let stores = BenchmarkDurableStores::reopen_after_shutdown(
            path,
            4096,
            node_id,
            &self.config.cluster_name,
            Duration::from_secs(5),
        )
        .await?;
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
        self.wake_replication().await?;
        Ok(())
    }

    pub async fn wait_for_leader(
        &mut self,
        timeout: Duration,
    ) -> Result<NodeId, Box<dyn std::error::Error + Send + Sync>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            for (node, receiver) in &self.metrics {
                let metrics = receiver.borrow();
                if metrics.state == openraft::ServerState::Leader
                    && metrics.current_leader == Some(*node)
                    && !self.paused_nodes.contains(node)
                {
                    return Ok(*node);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for an active OpenRaft node to report itself as leader; final metrics: {:?}",
                    self.raft_metrics()
                )
                .into());
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
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut last_error = "no leader has accepted the write".to_string();
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(format!(
                    "OpenRaft client write did not survive the leader transition: {last_error}; final metrics: {:?}",
                    self.raft_metrics()
                )
                .into());
            }
            let leader = match self
                .wait_for_leader((deadline - now).min(Duration::from_millis(500)))
                .await
            {
                Ok(leader) => leader,
                Err(error) => {
                    last_error = error.to_string();
                    self.network_control.wake_replication().await;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let raft = match self.routes.read().await.get(&leader).cloned() {
                Some(raft) => raft,
                None => {
                    last_error = format!("reported leader {leader} is unavailable");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            match raft.client_write(command.clone()).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    // ForwardToLeader(None) and stale leader hints are normal
                    // while a new term is settling. Rediscover the
                    // authoritative leader and retry the same idempotent
                    // application command.
                    last_error = error.to_string();
                    self.network_control.wake_replication().await;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Sends independent clients to the current leader concurrently and waits
    /// until every command is committed and applied.
    ///
    /// Commands are admitted to OpenRaft in input order before their response
    /// futures are awaited. This keeps the batch concurrent while making the
    /// application history independent of Tokio task polling order.
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
        let command_count = commands.len();
        let mut responses = vec![None; command_count];
        let mut pending = commands.into_iter().enumerate().collect::<Vec<_>>();
        let mut last_error = None;
        for _ in 0..500 {
            let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
            let raft = self
                .routes
                .read()
                .await
                .get(&leader)
                .cloned()
                .ok_or_else(|| format!("OpenRaft write target {leader} is unavailable"))?;
            let mut inflight = Vec::with_capacity(pending.len());
            let mut retry = Vec::new();
            for (index, command) in pending {
                match raft.client_write_ff(command.clone()).await {
                    Ok(receiver) => inflight.push((index, command, receiver)),
                    Err(error) => {
                        last_error = Some(error.to_string());
                        retry.push((index, command));
                    }
                }
            }
            for (index, command, receiver) in inflight {
                match receiver.await {
                    Ok(Ok(response)) => responses[index] = Some(response.data),
                    Ok(Err(error)) => {
                        last_error = Some(error.to_string());
                        retry.push((index, command));
                    }
                    Err(error) => {
                        last_error = Some(error.to_string());
                        retry.push((index, command));
                    }
                }
            }
            if retry.is_empty() {
                return responses
                    .into_iter()
                    .map(|response| {
                        response.ok_or_else(|| "OpenRaft concurrent write was lost".into())
                    })
                    .collect();
            }
            retry.sort_by_key(|(index, _)| *index);
            pending = retry;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(format!(
            "OpenRaft concurrent write exhausted retries: {}",
            last_error.unwrap_or_else(|| "no leader".to_string())
        )
        .into())
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
        self.wake_replication().await?;
        Ok(())
    }

    /// Returns a point-in-time metrics snapshot for every live Raft node.
    pub fn raft_metrics(&self) -> BTreeMap<NodeId, openraft::RaftMetrics<NodeId, BasicNode>> {
        self.metrics
            .iter()
            .map(|(node, metrics)| (*node, metrics.borrow().clone()))
            .collect()
    }

    /// Explicitly wakes replication on the current leader.
    pub async fn wake_replication(
        &mut self,
    ) -> Result<NodeId, Box<dyn std::error::Error + Send + Sync>> {
        let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
        self.nodes[&leader].trigger().heartbeat().await?;
        Ok(leader)
    }

    /// Builds a snapshot and waits until the leader publishes its watermark.
    ///
    /// OpenRaft's trigger API acknowledges queueing rather than completion.
    /// The benchmark adapter uses the stronger completion contract so fault
    /// campaigns can establish a real snapshot-before-heal boundary.
    pub async fn trigger_snapshot(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
        let target = self.metrics[&leader].borrow().last_applied;
        self.nodes[&leader].trigger().snapshot().await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let metrics = self.metrics[&leader].borrow().clone();
            if target.is_none_or(|target| {
                metrics
                    .snapshot
                    .is_some_and(|snapshot| snapshot.index >= target.index)
            }) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for OpenRaft leader {leader} snapshot through {:?}; final metrics: {metrics}",
                    target.map(|log_id| log_id.index)
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn trigger_snapshot_and_purge(
        &mut self,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        self.trigger_snapshot().await?;
        let leader = self.wait_for_leader(Duration::from_secs(5)).await?;
        let snapshot_index = self.metrics[&leader]
            .borrow()
            .snapshot
            .ok_or("OpenRaft snapshot completed without a watermark")?
            .index;
        self.nodes[&leader]
            .trigger()
            .purge_log(snapshot_index)
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if self.metrics[&leader]
                .borrow()
                .purged
                .is_some_and(|log_id| log_id.index >= snapshot_index)
            {
                return Ok(snapshot_index);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for OpenRaft leader {leader} to purge through {snapshot_index}"
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn wait_for_value_on_all_nodes(
        &self,
        key: &[u8],
        expected: &[u8],
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let mut converged = true;
            for machine in self.state_machines.values() {
                if machine.get(key).await.as_deref() != Some(expected) {
                    converged = false;
                    break;
                }
            }
            if converged {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for every OpenRaft state machine to converge; final metrics: {:?}",
                    self.raft_metrics()
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn shutdown_checked(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Stop every node as one cluster operation. Sequentially stopping the
        // current leader gives the survivors enough time to elect and start
        // replication while their peers and routes are being torn down.
        self.routes.write().await.clear();
        let mut shutdowns = JoinSet::new();
        for (node_id, raft) in self.nodes {
            shutdowns.spawn(async move {
                raft.shutdown()
                    .await
                    .map_err(|error| format!("OpenRaft node {node_id} shutdown failed: {error}"))
            });
        }
        while let Some(result) = shutdowns.join_next().await {
            result.map_err(|error| format!("OpenRaft shutdown task failed: {error}"))??;
        }
        Ok(())
    }

    pub async fn shutdown(self) {
        self.shutdown_checked()
            .await
            .expect("benchmark OpenRaft cluster must shut down cleanly");
    }
}
