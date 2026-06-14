use blossom::{
    BlossomError, Keypair, NodeIdentity, Result, RuntimeConfig, TcpNode, TrustMode, WireRequest,
    genesis_epoch,
};
pub use deterministic_test_env::{
    ClusterProfile, CpuProfile, HardwareFaultConfig, HardwareFaultKind, HermeticActionRecord,
    HermeticEventLog, HermeticEventRecord, HermeticOutcome, HermeticPerfReport, HermeticSimConfig,
    NodePerfReport, NodeProfile, PlannedAction,
};
use deterministic_test_env::{HermeticNodeFuture, SimEnvError};

#[derive(Debug, Clone)]
pub struct HermeticPlan {
    pub node_count: usize,
    pub trust_mode: TrustMode,
    pub config: HermeticSimConfig,
    actions: Vec<PlannedAction<WireRequest>>,
}

impl HermeticPlan {
    pub fn new(node_count: usize, trust_mode: TrustMode, config: HermeticSimConfig) -> Self {
        Self {
            node_count,
            trust_mode,
            config,
            actions: Vec::new(),
        }
    }

    pub fn request(
        &mut self,
        at_ms: u64,
        source: usize,
        target: usize,
        request: WireRequest,
    ) -> &mut Self {
        self.actions.push(PlannedAction::Request {
            at_ms,
            source,
            target,
            request: Box::new(request),
        });
        self
    }

    pub fn node_down(&mut self, at_ms: u64, node: usize) -> &mut Self {
        self.actions.push(PlannedAction::NodeDown { at_ms, node });
        self
    }

    pub fn node_up(&mut self, at_ms: u64, node: usize) -> &mut Self {
        self.actions.push(PlannedAction::NodeUp { at_ms, node });
        self
    }

    pub fn set_latency(
        &mut self,
        at_ms: u64,
        nodes: impl IntoIterator<Item = usize>,
        latency_ms: u64,
    ) -> &mut Self {
        self.actions.push(PlannedAction::SetLatency {
            at_ms,
            nodes: nodes.into_iter().collect(),
            latency_ms,
        });
        self
    }

    pub fn set_cpu(
        &mut self,
        at_ms: u64,
        nodes: impl IntoIterator<Item = usize>,
        profile: CpuProfile,
    ) -> &mut Self {
        self.actions.push(PlannedAction::SetCpu {
            at_ms,
            nodes: nodes.into_iter().collect(),
            profile,
        });
        self
    }

    pub fn set_hardware_faults(
        &mut self,
        at_ms: u64,
        nodes: impl IntoIterator<Item = usize>,
        faults: HardwareFaultConfig,
    ) -> &mut Self {
        self.actions.push(PlannedAction::SetHardwareFaults {
            at_ms,
            nodes: nodes.into_iter().collect(),
            faults,
        });
        self
    }

    pub fn actions(&self) -> &[PlannedAction<WireRequest>] {
        &self.actions
    }

    fn generic(&self) -> deterministic_test_env::HermeticPlan<WireRequest, TrustMode> {
        let mut plan = deterministic_test_env::HermeticPlan::new(
            self.node_count,
            self.trust_mode,
            self.config.clone(),
        );
        for action in &self.actions {
            match action.clone() {
                PlannedAction::Request {
                    at_ms,
                    source,
                    target,
                    request,
                } => {
                    plan.request(at_ms, source, target, *request);
                }
                PlannedAction::NodeDown { at_ms, node } => {
                    plan.node_down(at_ms, node);
                }
                PlannedAction::NodeUp { at_ms, node } => {
                    plan.node_up(at_ms, node);
                }
                PlannedAction::SetLatency {
                    at_ms,
                    nodes,
                    latency_ms,
                } => {
                    plan.set_latency(at_ms, nodes, latency_ms);
                }
                PlannedAction::SetCpu {
                    at_ms,
                    nodes,
                    profile,
                } => {
                    plan.set_cpu(at_ms, nodes, profile);
                }
                PlannedAction::SetHardwareFaults {
                    at_ms,
                    nodes,
                    faults,
                } => {
                    plan.set_hardware_faults(at_ms, nodes, faults);
                }
            }
        }
        plan
    }
}

pub struct HermeticCluster {
    inner: deterministic_test_env::HermeticCluster<HermeticBlossomNode, WireRequest>,
}

struct HermeticBlossomNode {
    #[allow(dead_code)]
    keypair: Keypair,
    node: TcpNode,
}

impl deterministic_test_env::HermeticNode<WireRequest> for HermeticBlossomNode {
    fn handle_request<'a>(&'a mut self, request: WireRequest) -> HermeticNodeFuture<'a> {
        Box::pin(async move {
            self.node
                .handle_request(request)
                .await
                .map(|response| response.kind())
                .map_err(|err| SimEnvError::App(err.to_string()))
        })
    }
}

impl HermeticCluster {
    pub fn new(
        node_count: usize,
        trust_mode: TrustMode,
        config: HermeticSimConfig,
    ) -> Result<Self> {
        let nodes = build_nodes(node_count, trust_mode)?;
        let inner = deterministic_test_env::HermeticCluster::new(nodes, config, request_kind)
            .map_err(to_blossom_error)?;
        Ok(Self { inner })
    }

    pub fn from_plan(plan: &HermeticPlan) -> Result<Self> {
        let nodes = build_nodes(plan.node_count, plan.trust_mode)?;
        let inner = deterministic_test_env::HermeticCluster::from_plan(
            &plan.generic(),
            nodes,
            request_kind,
        )
        .map_err(to_blossom_error)?;
        Ok(Self { inner })
    }

    pub fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }

    pub fn log(&self) -> &[HermeticEventRecord] {
        self.inner.log()
    }

    pub fn into_log(self) -> HermeticEventLog {
        self.inner.into_log()
    }

    pub fn perf_report(&self) -> HermeticPerfReport {
        self.inner.perf_report()
    }

    pub fn into_report(self) -> HermeticRunReport {
        let report = self.inner.into_report();
        HermeticRunReport {
            log: report.log,
            perf: report.perf,
        }
    }

    pub fn set_node_latency(&mut self, node: usize, latency_ms: u64) -> Result<()> {
        self.inner
            .set_node_latency(node, latency_ms)
            .map_err(to_blossom_error)
    }

    pub fn set_nodes_latency(
        &mut self,
        nodes: impl IntoIterator<Item = usize>,
        latency_ms: u64,
    ) -> Result<()> {
        self.inner
            .set_nodes_latency(nodes, latency_ms)
            .map_err(to_blossom_error)
    }

    pub fn set_node_up(&mut self, node: usize, up: bool) -> Result<()> {
        self.inner.set_node_up(node, up).map_err(to_blossom_error)
    }

    pub fn set_node_cpu(&mut self, node: usize, profile: CpuProfile) -> Result<()> {
        self.inner
            .set_node_cpu(node, profile)
            .map_err(to_blossom_error)
    }

    pub fn set_nodes_cpu(
        &mut self,
        nodes: impl IntoIterator<Item = usize>,
        profile: CpuProfile,
    ) -> Result<()> {
        self.inner
            .set_nodes_cpu(nodes, profile)
            .map_err(to_blossom_error)
    }

    pub fn set_node_hardware_faults(
        &mut self,
        node: usize,
        faults: HardwareFaultConfig,
    ) -> Result<()> {
        self.inner
            .set_node_hardware_faults(node, faults)
            .map_err(to_blossom_error)
    }

    pub fn set_nodes_hardware_faults(
        &mut self,
        nodes: impl IntoIterator<Item = usize>,
        faults: HardwareFaultConfig,
    ) -> Result<()> {
        self.inner
            .set_nodes_hardware_faults(nodes, faults)
            .map_err(to_blossom_error)
    }

    pub fn schedule_plan(&mut self, plan: &HermeticPlan) -> Result<()> {
        self.inner
            .schedule_plan(&plan.generic())
            .map_err(to_blossom_error)
    }

    pub fn schedule_request(
        &mut self,
        at_ms: u64,
        source: usize,
        target: usize,
        request: WireRequest,
    ) -> Result<()> {
        self.inner
            .schedule_request(at_ms, source, target, request)
            .map_err(to_blossom_error)
    }

    pub fn schedule_node_down(&mut self, at_ms: u64, node: usize) -> Result<()> {
        self.inner
            .schedule_node_down(at_ms, node)
            .map_err(to_blossom_error)
    }

    pub fn schedule_node_up(&mut self, at_ms: u64, node: usize) -> Result<()> {
        self.inner
            .schedule_node_up(at_ms, node)
            .map_err(to_blossom_error)
    }

    pub fn schedule_latency(
        &mut self,
        at_ms: u64,
        nodes: impl IntoIterator<Item = usize>,
        latency_ms: u64,
    ) -> Result<()> {
        self.inner
            .schedule_latency(at_ms, nodes, latency_ms)
            .map_err(to_blossom_error)
    }

    pub fn schedule_cpu(
        &mut self,
        at_ms: u64,
        nodes: impl IntoIterator<Item = usize>,
        profile: CpuProfile,
    ) -> Result<()> {
        self.inner
            .schedule_cpu(at_ms, nodes, profile)
            .map_err(to_blossom_error)
    }

    pub fn schedule_hardware_faults(
        &mut self,
        at_ms: u64,
        nodes: impl IntoIterator<Item = usize>,
        faults: HardwareFaultConfig,
    ) -> Result<()> {
        self.inner
            .schedule_hardware_faults(at_ms, nodes, faults)
            .map_err(to_blossom_error)
    }

    pub async fn run_until_idle(&mut self) -> Result<()> {
        self.inner.run_until_idle().await.map_err(to_blossom_error)
    }
}

pub async fn run_plan(plan: &HermeticPlan) -> Result<HermeticEventLog> {
    let mut cluster = HermeticCluster::from_plan(plan)?;
    cluster.run_until_idle().await?;
    Ok(cluster.into_log())
}

pub async fn run_plan_with_perf(plan: &HermeticPlan) -> Result<HermeticRunReport> {
    let mut cluster = HermeticCluster::from_plan(plan)?;
    cluster.run_until_idle().await?;
    Ok(cluster.into_report())
}

pub async fn replay_matches(plan: &HermeticPlan, expected: &HermeticEventLog) -> Result<bool> {
    let replayed = run_plan(plan).await?;
    Ok(&replayed == expected)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermeticRunReport {
    pub log: HermeticEventLog,
    pub perf: HermeticPerfReport,
}

fn build_nodes(node_count: usize, trust_mode: TrustMode) -> Result<Vec<HermeticBlossomNode>> {
    if node_count == 0 {
        return Err(BlossomError::WireProtocol(
            "hermetic cluster must contain at least one node".to_string(),
        ));
    }

    let mut identities = Vec::with_capacity(node_count);
    let mut keypairs = Vec::with_capacity(node_count);
    for index in 0..node_count {
        let keypair = Keypair::generate();
        let identity = NodeIdentity::new(
            keypair.public,
            Some(keypair.secret),
            "sim",
            "hermetic",
            index as u16,
            false,
        );
        identities.push(identity);
        keypairs.push(keypair);
    }

    let genesis = genesis_epoch(identities.iter().map(|identity| {
        NodeIdentity::new(
            identity.public_key(),
            None,
            identity.protocol.clone(),
            identity.host.clone(),
            identity.port,
            identity.shuffle,
        )
    }));

    let mut nodes = Vec::with_capacity(node_count);
    for (identity, keypair) in identities.into_iter().zip(keypairs) {
        let mut runtime_config = RuntimeConfig::new(identity);
        runtime_config.genesis = Some(genesis.clone());
        runtime_config.trust_mode = trust_mode;
        nodes.push(HermeticBlossomNode {
            keypair,
            node: TcpNode::new(blossom::NodeRuntime::new(runtime_config)),
        });
    }
    Ok(nodes)
}

fn to_blossom_error(err: SimEnvError) -> BlossomError {
    BlossomError::WireProtocol(err.to_string())
}

fn request_kind(request: &WireRequest) -> &'static str {
    match request {
        WireRequest::Health => "health",
        WireRequest::Ping(_) => "ping",
        #[cfg(feature = "availability-gossip")]
        WireRequest::AvailabilityGossip(_) => "availability_gossip",
        #[cfg(feature = "availability-gossip")]
        WireRequest::GetFilteredPayload(_) => "get_filtered_payload",
        #[cfg(feature = "availability-gossip")]
        WireRequest::GetFilteredPayloadBatch(_) => "get_filtered_payload_batch",
        #[cfg(feature = "availability-gossip")]
        WireRequest::StoreFilteredPayload(_) => "store_filtered_payload",
        #[cfg(feature = "availability-gossip")]
        WireRequest::StoreFilteredPayloadBatch(_) => "store_filtered_payload_batch",
        WireRequest::State => "state",
        WireRequest::AddressBook => "address_book",
        WireRequest::RegisterService(_) => "register_service",
        WireRequest::Group { .. } => "group",
        WireRequest::NextNonce => "next_nonce",
        WireRequest::SubmitBlock(_) => "submit_block",
        WireRequest::Dispatch { .. } => "dispatch",
        WireRequest::Message(_) => "message",
        WireRequest::SendNonce(_) => "send_nonce",
        WireRequest::BlockNonce(_) => "block_nonce",
        WireRequest::GetBlock(_) => "get_block",
        WireRequest::SendBlock(_) => "send_block",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blossom::{NodePing, TrustMode};
    use deterministic_test_env::CHAOS_RATE_DENOMINATOR;

    #[tokio::test]
    async fn hermetic_plan_replays_exactly() {
        let mut plan = HermeticPlan::new(
            4,
            TrustMode::Verified,
            HermeticSimConfig {
                seed: 42,
                default_latency_ms: 2,
                jitter_ms: 3,
                drop_ppm: 0,
            },
        );
        plan.set_latency(5, [2, 3], 25)
            .node_down(12, 2)
            .node_up(40, 2);
        for index in 0..20 {
            plan.request(
                index,
                0,
                (index as usize % 3) + 1,
                WireRequest::Ping(NodePing::new(index)),
            );
        }

        let first = run_plan(&plan).await.unwrap();
        let second = run_plan(&plan).await.unwrap();

        assert_eq!(first, second);
        assert!(replay_matches(&plan, &first).await.unwrap());
        assert!(first.response_count() > 0);
        assert!(first.unavailable_count() > 0);
    }

    #[tokio::test]
    async fn hermetic_latency_changes_delivery_time_for_node_collection() {
        let mut plan = HermeticPlan::new(
            3,
            TrustMode::Verified,
            HermeticSimConfig {
                seed: 7,
                default_latency_ms: 1,
                jitter_ms: 0,
                drop_ppm: 0,
            },
        );
        plan.set_latency(0, [1], 50)
            .request(1, 0, 1, WireRequest::Ping(NodePing::new(1)))
            .request(1, 0, 2, WireRequest::Ping(NodePing::new(2)));

        let log = run_plan(&plan).await.unwrap();
        let node_one = log
            .records
            .iter()
            .find(|record| {
                matches!(
                    record.action,
                    HermeticActionRecord::Request { target: 1, .. }
                )
            })
            .unwrap();
        let node_two = log
            .records
            .iter()
            .find(|record| {
                matches!(
                    record.action,
                    HermeticActionRecord::Request { target: 2, .. }
                )
            })
            .unwrap();

        assert_eq!(node_one.delivered_at_ms, 51);
        assert_eq!(node_two.delivered_at_ms, 2);
    }

    #[tokio::test]
    async fn hermetic_drop_rate_is_seeded_and_replayable() {
        let mut plan = HermeticPlan::new(
            2,
            TrustMode::Verified,
            HermeticSimConfig {
                seed: 99,
                default_latency_ms: 0,
                jitter_ms: 0,
                drop_ppm: CHAOS_RATE_DENOMINATOR,
            },
        );
        for index in 0..8 {
            plan.request(index, 0, 1, WireRequest::Ping(NodePing::new(index)));
        }

        let log = run_plan(&plan).await.unwrap();

        assert_eq!(log.dropped_count(), 8);
        assert_eq!(log.response_count(), 0);
        assert!(replay_matches(&plan, &log).await.unwrap());
    }
}
