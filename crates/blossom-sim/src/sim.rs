use std::collections::BTreeMap;

use blossom::{
    BlossomError, Keypair, NodeIdentity, Result, RuntimeConfig, TcpNode, TrustMode, WireRequest,
    genesis_epoch,
};

use crate::chaos::CHAOS_RATE_DENOMINATOR;
use crate::data::splitmix64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermeticSimConfig {
    pub seed: u64,
    pub default_latency_ms: u64,
    pub jitter_ms: u64,
    pub drop_ppm: u32,
}

impl Default for HermeticSimConfig {
    fn default() -> Self {
        Self {
            seed: 0x7369_6d5f_626c_6f31,
            default_latency_ms: 0,
            jitter_ms: 0,
            drop_ppm: 0,
        }
    }
}

impl HermeticSimConfig {
    pub fn validate(&self) -> Result<()> {
        if self.drop_ppm > CHAOS_RATE_DENOMINATOR {
            return Err(BlossomError::WireProtocol(format!(
                "drop_ppm must be <= {CHAOS_RATE_DENOMINATOR}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct HermeticPlan {
    pub node_count: usize,
    pub trust_mode: TrustMode,
    pub config: HermeticSimConfig,
    actions: Vec<PlannedAction>,
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

    pub fn actions(&self) -> &[PlannedAction] {
        &self.actions
    }
}

#[derive(Debug, Clone)]
pub enum PlannedAction {
    Request {
        at_ms: u64,
        source: usize,
        target: usize,
        request: Box<WireRequest>,
    },
    NodeDown {
        at_ms: u64,
        node: usize,
    },
    NodeUp {
        at_ms: u64,
        node: usize,
    },
    SetLatency {
        at_ms: u64,
        nodes: Vec<usize>,
        latency_ms: u64,
    },
}

impl PlannedAction {
    pub fn at_ms(&self) -> u64 {
        match self {
            Self::Request { at_ms, .. }
            | Self::NodeDown { at_ms, .. }
            | Self::NodeUp { at_ms, .. }
            | Self::SetLatency { at_ms, .. } => *at_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermeticEventLog {
    pub config: HermeticSimConfig,
    pub records: Vec<HermeticEventRecord>,
}

impl HermeticEventLog {
    pub fn response_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| matches!(record.outcome, HermeticOutcome::Response { .. }))
            .count()
    }

    pub fn dropped_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| matches!(record.outcome, HermeticOutcome::Dropped))
            .count()
    }

    pub fn unavailable_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| matches!(record.outcome, HermeticOutcome::NodeUnavailable))
            .count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermeticEventRecord {
    pub event_id: u64,
    pub planned_at_ms: u64,
    pub delivered_at_ms: u64,
    pub action: HermeticActionRecord,
    pub outcome: HermeticOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HermeticActionRecord {
    Request {
        source: usize,
        target: usize,
        request_kind: &'static str,
    },
    NodeDown {
        node: usize,
    },
    NodeUp {
        node: usize,
    },
    SetLatency {
        nodes: Vec<usize>,
        latency_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HermeticOutcome {
    Response { response_kind: &'static str },
    Error { message: String },
    Dropped,
    NodeUnavailable,
    Applied,
}

pub struct HermeticCluster {
    nodes: Vec<HermeticNode>,
    now_ms: u64,
    next_event_id: u64,
    queue: BTreeMap<(u64, u64), ScheduledEvent>,
    up: Vec<bool>,
    latency_ms: Vec<u64>,
    config: HermeticSimConfig,
    log: Vec<HermeticEventRecord>,
}

struct HermeticNode {
    #[allow(dead_code)]
    keypair: Keypair,
    node: TcpNode,
}

enum ScheduledEvent {
    Request {
        planned_at_ms: u64,
        source: usize,
        target: usize,
        request: Box<WireRequest>,
    },
    DeliverRequest {
        planned_at_ms: u64,
        source: usize,
        target: usize,
        request: Box<WireRequest>,
    },
    NodeDown {
        planned_at_ms: u64,
        node: usize,
    },
    NodeUp {
        planned_at_ms: u64,
        node: usize,
    },
    SetLatency {
        planned_at_ms: u64,
        nodes: Vec<usize>,
        latency_ms: u64,
    },
}

impl HermeticCluster {
    pub fn new(
        node_count: usize,
        trust_mode: TrustMode,
        config: HermeticSimConfig,
    ) -> Result<Self> {
        if node_count == 0 {
            return Err(BlossomError::WireProtocol(
                "hermetic cluster must contain at least one node".to_string(),
            ));
        }
        config.validate()?;

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
            nodes.push(HermeticNode {
                keypair,
                node: TcpNode::new(blossom::NodeRuntime::new(runtime_config)),
            });
        }

        Ok(Self {
            nodes,
            now_ms: 0,
            next_event_id: 0,
            queue: BTreeMap::new(),
            up: vec![true; node_count],
            latency_ms: vec![config.default_latency_ms; node_count],
            config,
            log: Vec::new(),
        })
    }

    pub fn from_plan(plan: &HermeticPlan) -> Result<Self> {
        let mut cluster = Self::new(plan.node_count, plan.trust_mode, plan.config.clone())?;
        cluster.schedule_plan(plan)?;
        Ok(cluster)
    }

    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    pub fn log(&self) -> &[HermeticEventRecord] {
        &self.log
    }

    pub fn into_log(self) -> HermeticEventLog {
        HermeticEventLog {
            config: self.config,
            records: self.log,
        }
    }

    pub fn set_node_latency(&mut self, node: usize, latency_ms: u64) -> Result<()> {
        self.ensure_node(node)?;
        self.latency_ms[node] = latency_ms;
        Ok(())
    }

    pub fn set_nodes_latency(
        &mut self,
        nodes: impl IntoIterator<Item = usize>,
        latency_ms: u64,
    ) -> Result<()> {
        for node in nodes {
            self.set_node_latency(node, latency_ms)?;
        }
        Ok(())
    }

    pub fn set_node_up(&mut self, node: usize, up: bool) -> Result<()> {
        self.ensure_node(node)?;
        self.up[node] = up;
        Ok(())
    }

    pub fn schedule_plan(&mut self, plan: &HermeticPlan) -> Result<()> {
        if plan.node_count != self.nodes.len() {
            return Err(BlossomError::WireProtocol(format!(
                "plan node count {} does not match cluster node count {}",
                plan.node_count,
                self.nodes.len()
            )));
        }
        for action in plan.actions() {
            match action.clone() {
                PlannedAction::Request {
                    at_ms,
                    source,
                    target,
                    request,
                } => self.schedule_request(at_ms, source, target, *request)?,
                PlannedAction::NodeDown { at_ms, node } => self.schedule_node_down(at_ms, node)?,
                PlannedAction::NodeUp { at_ms, node } => self.schedule_node_up(at_ms, node)?,
                PlannedAction::SetLatency {
                    at_ms,
                    nodes,
                    latency_ms,
                } => self.schedule_latency(at_ms, nodes, latency_ms)?,
            }
        }
        Ok(())
    }

    pub fn schedule_request(
        &mut self,
        at_ms: u64,
        source: usize,
        target: usize,
        request: WireRequest,
    ) -> Result<()> {
        self.ensure_node(source)?;
        self.ensure_node(target)?;
        self.push_event(
            at_ms,
            ScheduledEvent::Request {
                planned_at_ms: at_ms,
                source,
                target,
                request: Box::new(request),
            },
        );
        Ok(())
    }

    pub fn schedule_node_down(&mut self, at_ms: u64, node: usize) -> Result<()> {
        self.ensure_node(node)?;
        self.push_event(
            at_ms,
            ScheduledEvent::NodeDown {
                planned_at_ms: at_ms,
                node,
            },
        );
        Ok(())
    }

    pub fn schedule_node_up(&mut self, at_ms: u64, node: usize) -> Result<()> {
        self.ensure_node(node)?;
        self.push_event(
            at_ms,
            ScheduledEvent::NodeUp {
                planned_at_ms: at_ms,
                node,
            },
        );
        Ok(())
    }

    pub fn schedule_latency(
        &mut self,
        at_ms: u64,
        nodes: impl IntoIterator<Item = usize>,
        latency_ms: u64,
    ) -> Result<()> {
        let nodes = nodes.into_iter().collect::<Vec<_>>();
        for node in &nodes {
            self.ensure_node(*node)?;
        }
        self.push_event(
            at_ms,
            ScheduledEvent::SetLatency {
                planned_at_ms: at_ms,
                nodes,
                latency_ms,
            },
        );
        Ok(())
    }

    pub async fn run_until_idle(&mut self) -> Result<()> {
        while let Some(((delivered_at_ms, event_id), event)) = self.pop_next() {
            self.now_ms = delivered_at_ms;
            match self.handle_event(event_id, delivered_at_ms, event).await? {
                Some(record) => self.log.push(record),
                None => {}
            }
        }
        Ok(())
    }

    async fn handle_event(
        &mut self,
        event_id: u64,
        delivered_at_ms: u64,
        event: ScheduledEvent,
    ) -> Result<Option<HermeticEventRecord>> {
        match event {
            ScheduledEvent::Request {
                planned_at_ms,
                source,
                target,
                request,
            } => {
                let request_delay_ms = self.latency_ms[target]
                    .checked_add(self.jitter_ms(event_id, source, target))
                    .ok_or_else(|| {
                        BlossomError::WireProtocol("simulated time overflow".to_string())
                    })?;
                let request_delivered_at_ms = delivered_at_ms
                    .checked_add(request_delay_ms)
                    .ok_or_else(|| {
                        BlossomError::WireProtocol("simulated time overflow".to_string())
                    })?;
                self.push_event(
                    request_delivered_at_ms,
                    ScheduledEvent::DeliverRequest {
                        planned_at_ms,
                        source,
                        target,
                        request,
                    },
                );
                Ok(None)
            }
            ScheduledEvent::DeliverRequest {
                planned_at_ms,
                source,
                target,
                request,
            } => {
                let request_kind = request_kind(&request);
                let action = HermeticActionRecord::Request {
                    source,
                    target,
                    request_kind,
                };
                let outcome = if !self.up[target] {
                    HermeticOutcome::NodeUnavailable
                } else if self.should_drop(event_id, source, target) {
                    HermeticOutcome::Dropped
                } else {
                    match self.nodes[target].node.handle_request(*request).await {
                        Ok(response) => HermeticOutcome::Response {
                            response_kind: response.kind(),
                        },
                        Err(err) => HermeticOutcome::Error {
                            message: err.to_string(),
                        },
                    }
                };
                Ok(Some(HermeticEventRecord {
                    event_id,
                    planned_at_ms,
                    delivered_at_ms,
                    action,
                    outcome,
                }))
            }
            ScheduledEvent::NodeDown {
                planned_at_ms,
                node,
            } => {
                self.up[node] = false;
                Ok(Some(HermeticEventRecord {
                    event_id,
                    planned_at_ms,
                    delivered_at_ms,
                    action: HermeticActionRecord::NodeDown { node },
                    outcome: HermeticOutcome::Applied,
                }))
            }
            ScheduledEvent::NodeUp {
                planned_at_ms,
                node,
            } => {
                self.up[node] = true;
                Ok(Some(HermeticEventRecord {
                    event_id,
                    planned_at_ms,
                    delivered_at_ms,
                    action: HermeticActionRecord::NodeUp { node },
                    outcome: HermeticOutcome::Applied,
                }))
            }
            ScheduledEvent::SetLatency {
                planned_at_ms,
                nodes,
                latency_ms,
            } => {
                for node in &nodes {
                    self.latency_ms[*node] = latency_ms;
                }
                Ok(Some(HermeticEventRecord {
                    event_id,
                    planned_at_ms,
                    delivered_at_ms,
                    action: HermeticActionRecord::SetLatency { nodes, latency_ms },
                    outcome: HermeticOutcome::Applied,
                }))
            }
        }
    }

    fn push_event(&mut self, delivered_at_ms: u64, event: ScheduledEvent) {
        let event_id = self.next_event_id;
        self.next_event_id += 1;
        self.queue.insert((delivered_at_ms, event_id), event);
    }

    fn pop_next(&mut self) -> Option<((u64, u64), ScheduledEvent)> {
        let key = *self.queue.keys().next()?;
        self.queue.remove_entry(&key)
    }

    fn jitter_ms(&self, event_id: u64, source: usize, target: usize) -> u64 {
        if self.config.jitter_ms == 0 {
            return 0;
        }
        let seed = self.config.seed
            ^ event_id.rotate_left(13)
            ^ (source as u64).rotate_left(29)
            ^ (target as u64).rotate_left(47);
        splitmix64(seed) % (self.config.jitter_ms + 1)
    }

    fn should_drop(&self, event_id: u64, source: usize, target: usize) -> bool {
        self.config.drop_ppm > 0
            && (splitmix64(
                self.config.seed
                    ^ event_id.rotate_left(17)
                    ^ (source as u64).rotate_left(31)
                    ^ (target as u64).rotate_left(43),
            ) % CHAOS_RATE_DENOMINATOR as u64)
                < self.config.drop_ppm as u64
    }

    fn ensure_node(&self, node: usize) -> Result<()> {
        if node >= self.nodes.len() {
            return Err(BlossomError::WireProtocol(format!(
                "node index {node} out of range for {} nodes",
                self.nodes.len()
            )));
        }
        Ok(())
    }
}

pub async fn run_plan(plan: &HermeticPlan) -> Result<HermeticEventLog> {
    let mut cluster = HermeticCluster::from_plan(plan)?;
    cluster.run_until_idle().await?;
    Ok(cluster.into_log())
}

pub async fn replay_matches(plan: &HermeticPlan, expected: &HermeticEventLog) -> Result<bool> {
    let replayed = run_plan(plan).await?;
    Ok(&replayed == expected)
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
