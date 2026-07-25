//! Deterministic discrete-event execution for distributed protocol models.
//!
//! The engine deliberately controls only protocol-visible nondeterminism:
//! message delivery, virtual time, injected faults, process lifecycle, storage
//! completions, and client responses. Protocol adapters remain responsible for
//! converting their native messages and durable operations into [`Effect`]s.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Result, SimEnvError, splitmix64};

pub const DETERMINISTIC_SCENARIO_VERSION: u16 = 1;
pub const DETERMINISTIC_TRACE_VERSION: u16 = 1;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash,
)]
pub struct SimTime(pub u64);

impl SimTime {
    pub const ZERO: Self = Self(0);

    pub fn saturating_add(self, micros: u64) -> Self {
        Self(self.0.saturating_add(micros))
    }
}

impl fmt::Display for SimTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}us", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct ChoiceId {
    pub domain: String,
    pub actor: u32,
    pub operation: u64,
    pub occurrence: u32,
}

impl ChoiceId {
    pub fn new(domain: impl Into<String>, actor: u32, operation: u64, occurrence: u32) -> Self {
        Self {
            domain: domain.into(),
            actor,
            operation,
            occurrence,
        }
    }

    fn sample(&self, seed: u64) -> u64 {
        let mut digest = Sha256::new();
        digest.update(b"blossom/deterministic-choice/v1");
        digest.update(seed.to_le_bytes());
        digest.update(self.domain.as_bytes());
        digest.update(self.actor.to_le_bytes());
        digest.update(self.operation.to_le_bytes());
        digest.update(self.occurrence.to_le_bytes());
        let bytes: [u8; 32] = digest.finalize().into();
        splitmix64(u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .expect("SHA-256 prefix is eight bytes"),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct EventKey {
    pub domain: String,
    pub actor: u32,
    pub operation: u64,
    pub occurrence: u32,
}

impl EventKey {
    pub fn new(domain: impl Into<String>, actor: u32, operation: u64, occurrence: u32) -> Self {
        Self {
            domain: domain.into(),
            actor,
            operation,
            occurrence,
        }
    }
}

impl From<&EventKey> for ChoiceId {
    fn from(key: &EventKey) -> Self {
        Self {
            domain: key.domain.clone(),
            actor: key.actor,
            operation: key.operation,
            occurrence: key.occurrence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimChannel {
    ClientRequest,
    ClientResponse,
    Protocol,
    Repair,
    Membership,
    Timer,
    Storage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientOutcome {
    Ok { payload: Vec<u8> },
    Fail { error: String },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkFault {
    Heal,
    Drop,
    Delay { micros: u64 },
    Duplicate { copies: u8 },
    Jam,
    Corrupt { xor: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkState {
    Up,
    Drop,
    Delay { micros: u64 },
    Duplicate { copies: u8 },
    Jam,
    Corrupt { xor: u8 },
}

impl Default for LinkState {
    fn default() -> Self {
        Self::Up
    }
}

impl From<LinkFault> for LinkState {
    fn from(fault: LinkFault) -> Self {
        match fault {
            LinkFault::Heal => Self::Up,
            LinkFault::Drop => Self::Drop,
            LinkFault::Delay { micros } => Self::Delay { micros },
            LinkFault::Duplicate { copies } => Self::Duplicate { copies },
            LinkFault::Jam => Self::Jam,
            LinkFault::Corrupt { xor } => Self::Corrupt { xor },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeFault {
    Pause { micros: u64 },
    Throttle { delay_micros: u64 },
    GracefulStop,
    Crash,
    Restart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageFault {
    Healthy,
    Delay { micros: u64 },
    Full,
    Io,
    Fsync,
    TornWrite { keep_bytes: usize },
    Corrupt { xor: u8 },
}

impl Default for StorageFault {
    fn default() -> Self {
        Self::Healthy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeLifecycle {
    Running,
    PausedUntil(SimTime),
    GracefullyStopped,
    Crashed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeEvent {
    Client {
        client_id: u64,
        operation_id: u64,
        payload: Vec<u8>,
    },
    Message {
        source: usize,
        channel: SimChannel,
        payload: Vec<u8>,
    },
    Timer {
        timer_id: u64,
        payload: Vec<u8>,
    },
    StorageComplete {
        operation_id: u64,
        result: std::result::Result<Vec<u8>, String>,
        context: Vec<u8>,
    },
    Quiesce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Send {
        target: usize,
        channel: SimChannel,
        payload: Vec<u8>,
        delay_micros: u64,
        key: EventKey,
    },
    Respond {
        client_id: u64,
        operation_id: u64,
        outcome: ClientOutcome,
        delay_micros: u64,
        key: EventKey,
    },
    ScheduleTimer {
        timer_id: u64,
        payload: Vec<u8>,
        delay_micros: u64,
        key: EventKey,
    },
    Persist {
        operation_id: u64,
        key_bytes: Vec<u8>,
        value: Vec<u8>,
        context: Vec<u8>,
        key: EventKey,
    },
    Delete {
        operation_id: u64,
        key_bytes: Vec<u8>,
        context: Vec<u8>,
        key: EventKey,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimEventKind {
    Node {
        target: usize,
        event: NodeEvent,
    },
    LinkFault {
        source: usize,
        target: usize,
        fault: LinkFault,
    },
    NodeFault {
        node: usize,
        fault: NodeFault,
    },
    StorageFault {
        node: usize,
        fault: StorageFault,
    },
    ClientResponse {
        source: usize,
        client_id: u64,
        operation_id: u64,
        outcome: ClientOutcome,
    },
    HealAll,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimEvent {
    pub at: SimTime,
    pub key: EventKey,
    pub kind: SimEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioAction {
    pub at: SimTime,
    pub key: EventKey,
    pub action: ScenarioActionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioActionKind {
    Client {
        source: usize,
        target: usize,
        client_id: u64,
        operation_id: u64,
        payload: Vec<u8>,
    },
    LinkFault {
        source: usize,
        target: usize,
        fault: LinkFault,
    },
    NodeFault {
        node: usize,
        fault: NodeFault,
    },
    StorageFault {
        node: usize,
        fault: StorageFault,
    },
    HealAll,
    Quiesce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    pub schema_version: u16,
    pub name: String,
    pub protocol: String,
    pub node_count: usize,
    pub seed: u64,
    pub max_events: usize,
    pub max_virtual_time: SimTime,
    pub fault_depth: u8,
    pub actions: Vec<ScenarioAction>,
}

impl Scenario {
    pub fn new(name: impl Into<String>, protocol: impl Into<String>, node_count: usize) -> Self {
        Self {
            schema_version: DETERMINISTIC_SCENARIO_VERSION,
            name: name.into(),
            protocol: protocol.into(),
            node_count,
            seed: 0x6473_745f_626c_6f73,
            max_events: 10_000,
            max_virtual_time: SimTime(60_000_000),
            fault_depth: 1,
            actions: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != DETERMINISTIC_SCENARIO_VERSION {
            return Err(SimEnvError::App(format!(
                "unsupported deterministic scenario version {}",
                self.schema_version
            )));
        }
        if self.node_count == 0 {
            return Err(SimEnvError::InvalidNodeCount);
        }
        if self.max_events == 0 {
            return Err(SimEnvError::App(
                "deterministic scenario max_events must be positive".to_string(),
            ));
        }
        for action in &self.actions {
            match &action.action {
                ScenarioActionKind::Client { source, target, .. }
                | ScenarioActionKind::LinkFault { source, target, .. } => {
                    self.validate_node(*source)?;
                    self.validate_node(*target)?;
                }
                ScenarioActionKind::NodeFault { node, .. }
                | ScenarioActionKind::StorageFault { node, .. } => self.validate_node(*node)?,
                ScenarioActionKind::HealAll | ScenarioActionKind::Quiesce => {}
            }
        }
        Ok(())
    }

    fn validate_node(&self, node: usize) -> Result<()> {
        if node >= self.node_count {
            return Err(SimEnvError::InvalidNode {
                node,
                node_count: self.node_count,
            });
        }
        Ok(())
    }

    pub fn push(&mut self, action: ScenarioAction) -> &mut Self {
        self.actions.push(action);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorationBounds {
    pub max_events: usize,
    pub max_schedules: usize,
    pub max_branch_width: usize,
    pub fault_depth: u8,
}

impl Default for ExplorationBounds {
    fn default() -> Self {
        Self {
            max_events: 500,
            max_schedules: 200,
            max_branch_width: 8,
            fault_depth: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunMode {
    Random {
        seed: u64,
    },
    Replay {
        choices: Vec<ChoiceRecord>,
    },
    Systematic {
        schedule: Vec<usize>,
        bounds: ExplorationBounds,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChoiceRecord {
    pub choice_id: ChoiceId,
    pub enabled: Vec<EventKey>,
    pub selected: EventKey,
    pub selected_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventDisposition {
    Applied,
    Dropped,
    Jammed,
    Duplicated { copies: u8 },
    Delayed { micros: u64 },
    Corrupted,
    NodeUnavailable,
    StorageFailed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub sequence: u64,
    pub at: SimTime,
    pub event: SimEvent,
    pub disposition: EventDisposition,
    pub state_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientHistoryEvent {
    Invoke {
        at: SimTime,
        source: usize,
        target: usize,
        client_id: u64,
        operation_id: u64,
        payload: Vec<u8>,
    },
    Complete {
        at: SimTime,
        source: usize,
        client_id: u64,
        operation_id: u64,
        outcome: ClientOutcome,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultCoverage {
    pub link_faults: BTreeSet<String>,
    pub node_faults: BTreeSet<String>,
    pub storage_faults: BTreeSet<String>,
    pub combined_fault_depth: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub schema_version: u16,
    pub scenario_name: String,
    pub protocol: String,
    pub seed: u64,
    pub choices: Vec<ChoiceRecord>,
    pub events: Vec<TraceEvent>,
    pub client_history: Vec<ClientHistoryEvent>,
    pub properties: PropertyReport,
    pub fault_coverage: FaultCoverage,
    pub final_state_digest: String,
    pub stopped_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayManifest {
    pub schema_version: u16,
    pub scenario_hash: String,
    pub trace_hash: String,
    pub git_revision: String,
    pub configuration_hash: String,
    pub replay_command: String,
}

impl ReplayManifest {
    pub fn from_trace(
        scenario: &Scenario,
        trace: &ExecutionTrace,
        git_revision: impl Into<String>,
        replay_command: impl Into<String>,
    ) -> Result<Self> {
        let scenario_bytes =
            serde_json::to_vec(scenario).map_err(|error| SimEnvError::App(error.to_string()))?;
        let trace_bytes =
            serde_json::to_vec(trace).map_err(|error| SimEnvError::App(error.to_string()))?;
        Ok(Self {
            schema_version: DETERMINISTIC_TRACE_VERSION,
            scenario_hash: hex_digest(&scenario_bytes),
            trace_hash: hex_digest(&trace_bytes),
            git_revision: git_revision.into(),
            configuration_hash: hex_digest(
                format!(
                    "{}:{}:{}:{}",
                    scenario.protocol,
                    scenario.node_count,
                    scenario.max_events,
                    scenario.max_virtual_time.0
                )
                .as_bytes(),
            ),
            replay_command: replay_command.into(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyKind {
    Always,
    Reachable,
    Sometimes,
    EventuallyAfterQuiescence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyStatus {
    Passing,
    Failing,
    Unreached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyObservation {
    pub name: String,
    pub kind: PropertyKind,
    pub at: SimTime,
    pub holds: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyReport {
    pub observations: Vec<PropertyObservation>,
    pub statuses: BTreeMap<String, PropertyStatus>,
}

impl PropertyReport {
    pub fn passed(&self) -> bool {
        self.statuses
            .values()
            .all(|status| *status == PropertyStatus::Passing)
    }

    pub fn failures(&self) -> impl Iterator<Item = &PropertyObservation> {
        self.observations
            .iter()
            .filter(|observation| !observation.holds)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PropertyRegistry {
    report: PropertyReport,
    kinds: BTreeMap<String, PropertyKind>,
    reached: BTreeSet<String>,
}

impl PropertyRegistry {
    pub fn define(&mut self, name: impl Into<String>, kind: PropertyKind) {
        let name = name.into();
        self.kinds.insert(name.clone(), kind);
        self.report.statuses.entry(name).or_insert(match kind {
            PropertyKind::Always => PropertyStatus::Passing,
            PropertyKind::Reachable
            | PropertyKind::Sometimes
            | PropertyKind::EventuallyAfterQuiescence => PropertyStatus::Unreached,
        });
    }

    pub fn observe(
        &mut self,
        name: impl Into<String>,
        at: SimTime,
        holds: bool,
        detail: impl Into<String>,
    ) {
        let name = name.into();
        let kind = self
            .kinds
            .get(&name)
            .copied()
            .unwrap_or(PropertyKind::Always);
        self.report.observations.push(PropertyObservation {
            name: name.clone(),
            kind,
            at,
            holds,
            detail: detail.into(),
        });
        match kind {
            PropertyKind::Always => {
                if !holds {
                    self.report.statuses.insert(name, PropertyStatus::Failing);
                }
            }
            PropertyKind::Reachable
            | PropertyKind::Sometimes
            | PropertyKind::EventuallyAfterQuiescence => {
                if holds {
                    self.reached.insert(name.clone());
                    self.report.statuses.insert(name, PropertyStatus::Passing);
                }
            }
        }
    }

    pub fn report(&self) -> PropertyReport {
        self.report.clone()
    }
}

#[derive(Debug, Clone)]
pub struct NodeContext {
    pub now: SimTime,
    pub node: usize,
    pub storage_fault: StorageFault,
    seed: u64,
}

impl NodeContext {
    pub fn choose(&self, choice: &ChoiceId, upper_exclusive: usize) -> usize {
        if upper_exclusive == 0 {
            return 0;
        }
        choice.sample(self.seed) as usize % upper_exclusive
    }
}

pub trait DeterministicNode: Send {
    fn on_event(&mut self, event: NodeEvent, context: &mut NodeContext) -> Result<Vec<Effect>>;

    fn state_digest(&self) -> String;

    fn crash(&mut self) -> Result<()> {
        Ok(())
    }

    fn restart(&mut self) -> Result<()> {
        Ok(())
    }
}

pub struct ClusterView<'a, Node> {
    pub now: SimTime,
    pub nodes: &'a [Node],
    pub lifecycle: &'a [NodeLifecycle],
    pub durable: &'a [BTreeMap<Vec<u8>, Vec<u8>>],
    pub client_history: &'a [ClientHistoryEvent],
}

pub trait GlobalObserver<Node> {
    fn observe(&mut self, view: ClusterView<'_, Node>, properties: &mut PropertyRegistry);
}

impl<Node, Function> GlobalObserver<Node> for Function
where
    Function: FnMut(ClusterView<'_, Node>, &mut PropertyRegistry),
{
    fn observe(&mut self, view: ClusterView<'_, Node>, properties: &mut PropertyRegistry) {
        self(view, properties);
    }
}

struct QueuedEvent {
    event: SimEvent,
    sequence: u64,
}

pub struct DeterministicCluster<Node> {
    scenario: Scenario,
    nodes: Vec<Node>,
    now: SimTime,
    next_sequence: u64,
    queue: BTreeMap<SimTime, Vec<QueuedEvent>>,
    jammed: BTreeMap<(usize, usize), VecDeque<SimEvent>>,
    links: Vec<Vec<LinkState>>,
    lifecycle: Vec<NodeLifecycle>,
    throttle_micros: Vec<u64>,
    storage_faults: Vec<StorageFault>,
    durable: Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    trace: ExecutionTrace,
    mode: RunMode,
    replay_cursor: usize,
    systematic_cursor: usize,
    active_faults: u8,
    properties: PropertyRegistry,
}

impl<Node> DeterministicCluster<Node>
where
    Node: DeterministicNode,
{
    pub fn new(scenario: Scenario, nodes: Vec<Node>, mode: RunMode) -> Result<Self> {
        scenario.validate()?;
        if nodes.len() != scenario.node_count {
            return Err(SimEnvError::PlanNodeCountMismatch {
                plan_node_count: scenario.node_count,
                cluster_node_count: nodes.len(),
            });
        }
        let node_count = nodes.len();
        let mut cluster = Self {
            trace: ExecutionTrace {
                schema_version: DETERMINISTIC_TRACE_VERSION,
                scenario_name: scenario.name.clone(),
                protocol: scenario.protocol.clone(),
                seed: scenario.seed,
                choices: Vec::new(),
                events: Vec::new(),
                client_history: Vec::new(),
                properties: PropertyReport::default(),
                fault_coverage: FaultCoverage::default(),
                final_state_digest: String::new(),
                stopped_reason: String::new(),
            },
            scenario,
            nodes,
            now: SimTime::ZERO,
            next_sequence: 0,
            queue: BTreeMap::new(),
            jammed: BTreeMap::new(),
            links: vec![vec![LinkState::Up; node_count]; node_count],
            lifecycle: vec![NodeLifecycle::Running; node_count],
            throttle_micros: vec![0; node_count],
            storage_faults: vec![StorageFault::Healthy; node_count],
            durable: vec![BTreeMap::new(); node_count],
            mode,
            replay_cursor: 0,
            systematic_cursor: 0,
            active_faults: 0,
            properties: PropertyRegistry::default(),
        };
        let actions = cluster.scenario.actions.clone();
        for action in actions {
            cluster.schedule_action(action)?;
        }
        Ok(cluster)
    }

    pub fn properties_mut(&mut self) -> &mut PropertyRegistry {
        &mut self.properties
    }

    pub fn now(&self) -> SimTime {
        self.now
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn run(self) -> Result<ExecutionTrace> {
        self.run_with_observer(
            &mut |_view: ClusterView<'_, Node>, _properties: &mut PropertyRegistry| {},
        )
    }

    pub fn run_with_observer<Observer>(mut self, observer: &mut Observer) -> Result<ExecutionTrace>
    where
        Observer: GlobalObserver<Node>,
    {
        let mut processed = 0usize;
        while processed < self.scenario.max_events {
            let Some(events) = self.take_next_enabled()? else {
                self.trace.stopped_reason = "quiescent".to_string();
                break;
            };
            let selected = self.select_event(events)?;
            if selected.event.at > self.scenario.max_virtual_time {
                self.trace.stopped_reason = "max_virtual_time".to_string();
                break;
            }
            self.now = selected.event.at;
            let disposition = self.apply_event(selected.event.clone())?;
            let state_digest = self.state_digest();
            self.trace.events.push(TraceEvent {
                sequence: selected.sequence,
                at: self.now,
                event: selected.event,
                disposition,
                state_digest,
            });
            observer.observe(
                ClusterView {
                    now: self.now,
                    nodes: &self.nodes,
                    lifecycle: &self.lifecycle,
                    durable: &self.durable,
                    client_history: &self.trace.client_history,
                },
                &mut self.properties,
            );
            processed = processed.saturating_add(1);
        }
        if self.trace.stopped_reason.is_empty() {
            self.trace.stopped_reason = "max_events".to_string();
        }
        self.trace.final_state_digest = self.state_digest();
        self.trace.properties = self.properties.report();
        Ok(self.trace)
    }

    fn schedule_action(&mut self, action: ScenarioAction) -> Result<()> {
        let kind = match action.action {
            ScenarioActionKind::Client {
                source,
                target,
                client_id,
                operation_id,
                payload,
            } => {
                self.trace.client_history.push(ClientHistoryEvent::Invoke {
                    at: action.at,
                    source,
                    target,
                    client_id,
                    operation_id,
                    payload: payload.clone(),
                });
                SimEventKind::Node {
                    target,
                    event: NodeEvent::Client {
                        client_id,
                        operation_id,
                        payload,
                    },
                }
            }
            ScenarioActionKind::LinkFault {
                source,
                target,
                fault,
            } => SimEventKind::LinkFault {
                source,
                target,
                fault,
            },
            ScenarioActionKind::NodeFault { node, fault } => {
                SimEventKind::NodeFault { node, fault }
            }
            ScenarioActionKind::StorageFault { node, fault } => {
                SimEventKind::StorageFault { node, fault }
            }
            ScenarioActionKind::HealAll => SimEventKind::HealAll,
            ScenarioActionKind::Quiesce => {
                for target in 0..self.nodes.len() {
                    self.enqueue(SimEvent {
                        at: action.at,
                        key: EventKey::new(
                            "quiesce",
                            u32::try_from(target).unwrap_or(u32::MAX),
                            action.key.operation,
                            action.key.occurrence,
                        ),
                        kind: SimEventKind::Node {
                            target,
                            event: NodeEvent::Quiesce,
                        },
                    });
                }
                return Ok(());
            }
        };
        self.enqueue(SimEvent {
            at: action.at,
            key: action.key,
            kind,
        });
        Ok(())
    }

    fn enqueue(&mut self, event: SimEvent) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.queue
            .entry(event.at)
            .or_default()
            .push(QueuedEvent { event, sequence });
    }

    fn take_next_enabled(&mut self) -> Result<Option<Vec<QueuedEvent>>> {
        let Some(time) = self.queue.keys().next().copied() else {
            return Ok(None);
        };
        let mut events = self
            .queue
            .remove(&time)
            .expect("selected deterministic queue key exists");
        events.sort_by(|left, right| {
            left.event
                .key
                .cmp(&right.event.key)
                .then(left.sequence.cmp(&right.sequence))
        });
        Ok(Some(events))
    }

    fn select_event(&mut self, mut enabled: Vec<QueuedEvent>) -> Result<QueuedEvent> {
        let enabled_keys = enabled
            .iter()
            .map(|event| event.event.key.clone())
            .collect::<Vec<_>>();
        let index = match &self.mode {
            RunMode::Random { seed } => enabled
                .iter()
                .enumerate()
                .min_by_key(|(_, event)| ChoiceId::from(&event.event.key).sample(*seed))
                .map(|(index, _)| index)
                .unwrap_or_default(),
            RunMode::Replay { choices } => {
                let expected = choices.get(self.replay_cursor).ok_or_else(|| {
                    SimEnvError::App("replay trace exhausted before execution".to_string())
                })?;
                enabled
                    .iter()
                    .position(|event| event.event.key == expected.selected)
                    .ok_or_else(|| {
                        SimEnvError::App(format!(
                            "replay event {:?} is not enabled",
                            expected.selected
                        ))
                    })?
            }
            RunMode::Systematic { schedule, bounds } => {
                let configured = schedule
                    .get(self.systematic_cursor)
                    .copied()
                    .unwrap_or_default();
                configured % enabled.len().min(bounds.max_branch_width.max(1))
            }
        };
        let selected = enabled.remove(index);
        let choice_id = ChoiceId::from(&selected.event.key);
        for event in enabled {
            self.queue.entry(event.event.at).or_default().push(event);
        }
        self.trace.choices.push(ChoiceRecord {
            choice_id,
            enabled: enabled_keys,
            selected: selected.event.key.clone(),
            selected_index: index,
        });
        self.replay_cursor = self.replay_cursor.saturating_add(1);
        self.systematic_cursor = self.systematic_cursor.saturating_add(1);
        Ok(selected)
    }

    fn apply_event(&mut self, event: SimEvent) -> Result<EventDisposition> {
        match event.kind {
            SimEventKind::Node { target, event } => self.deliver_node_event(target, event),
            SimEventKind::LinkFault {
                source,
                target,
                fault,
            } => {
                self.validate_node(source)?;
                self.validate_node(target)?;
                let was_jammed = self.links[source][target] == LinkState::Jam;
                self.links[source][target] = fault.clone().into();
                self.active_faults = match fault {
                    LinkFault::Heal => self.active_faults.saturating_sub(1),
                    _ => self.active_faults.saturating_add(1),
                };
                self.trace.fault_coverage.combined_fault_depth = self
                    .trace
                    .fault_coverage
                    .combined_fault_depth
                    .max(self.active_faults);
                self.trace
                    .fault_coverage
                    .link_faults
                    .insert(format!("{fault:?}"));
                if was_jammed && self.links[source][target] != LinkState::Jam {
                    self.release_jam(source, target);
                }
                Ok(EventDisposition::Applied)
            }
            SimEventKind::NodeFault { node, fault } => {
                self.apply_node_fault(node, fault.clone())?;
                self.trace
                    .fault_coverage
                    .node_faults
                    .insert(format!("{fault:?}"));
                Ok(EventDisposition::Applied)
            }
            SimEventKind::StorageFault { node, fault } => {
                self.validate_node(node)?;
                self.storage_faults[node] = fault.clone();
                self.trace
                    .fault_coverage
                    .storage_faults
                    .insert(format!("{fault:?}"));
                Ok(EventDisposition::Applied)
            }
            SimEventKind::ClientResponse {
                source,
                client_id,
                operation_id,
                outcome,
            } => {
                self.trace
                    .client_history
                    .push(ClientHistoryEvent::Complete {
                        at: self.now,
                        source,
                        client_id,
                        operation_id,
                        outcome,
                    });
                Ok(EventDisposition::Applied)
            }
            SimEventKind::HealAll => {
                self.heal_all()?;
                Ok(EventDisposition::Applied)
            }
        }
    }

    fn deliver_node_event(&mut self, target: usize, event: NodeEvent) -> Result<EventDisposition> {
        self.validate_node(target)?;
        match self.lifecycle[target] {
            NodeLifecycle::Running => {}
            NodeLifecycle::PausedUntil(until) if until <= self.now => {
                self.lifecycle[target] = NodeLifecycle::Running;
            }
            NodeLifecycle::PausedUntil(until) => {
                self.enqueue(SimEvent {
                    at: until,
                    key: EventKey::new(
                        "paused-redelivery",
                        u32::try_from(target).unwrap_or(u32::MAX),
                        self.next_sequence,
                        0,
                    ),
                    kind: SimEventKind::Node { target, event },
                });
                return Ok(EventDisposition::Delayed {
                    micros: until.0.saturating_sub(self.now.0),
                });
            }
            NodeLifecycle::GracefullyStopped | NodeLifecycle::Crashed => {
                return Ok(EventDisposition::NodeUnavailable);
            }
        }
        let throttle = self.throttle_micros[target];
        if throttle > 0 {
            self.throttle_micros[target] = 0;
            self.enqueue(SimEvent {
                at: self.now.saturating_add(throttle),
                key: EventKey::new(
                    "throttled-redelivery",
                    u32::try_from(target).unwrap_or(u32::MAX),
                    self.next_sequence,
                    0,
                ),
                kind: SimEventKind::Node { target, event },
            });
            return Ok(EventDisposition::Delayed { micros: throttle });
        }
        let mut context = NodeContext {
            now: self.now,
            node: target,
            storage_fault: self.storage_faults[target].clone(),
            seed: self.scenario.seed,
        };
        let effects = self.nodes[target].on_event(event, &mut context)?;
        for effect in effects {
            self.apply_effect(target, effect)?;
        }
        Ok(EventDisposition::Applied)
    }

    fn apply_effect(&mut self, source: usize, effect: Effect) -> Result<()> {
        match effect {
            Effect::Send {
                target,
                channel,
                mut payload,
                delay_micros,
                key,
            } => {
                self.validate_node(target)?;
                let link = self.links[source][target].clone();
                match link {
                    LinkState::Up => {
                        self.enqueue_message(source, target, channel, payload, delay_micros, key)
                    }
                    LinkState::Drop => {}
                    LinkState::Delay { micros } => self.enqueue_message(
                        source,
                        target,
                        channel,
                        payload,
                        delay_micros.saturating_add(micros),
                        key,
                    ),
                    LinkState::Duplicate { copies } => {
                        for occurrence in 0..copies.max(1) {
                            let mut duplicate_key = key.clone();
                            duplicate_key.occurrence = duplicate_key
                                .occurrence
                                .saturating_add(u32::from(occurrence));
                            self.enqueue_message(
                                source,
                                target,
                                channel,
                                payload.clone(),
                                delay_micros,
                                duplicate_key,
                            );
                        }
                    }
                    LinkState::Jam => {
                        self.jammed
                            .entry((source, target))
                            .or_default()
                            .push_back(SimEvent {
                                at: self.now.saturating_add(delay_micros),
                                key,
                                kind: SimEventKind::Node {
                                    target,
                                    event: NodeEvent::Message {
                                        source,
                                        channel,
                                        payload,
                                    },
                                },
                            });
                    }
                    LinkState::Corrupt { xor } => {
                        if let Some(first) = payload.first_mut() {
                            *first ^= xor;
                        }
                        self.enqueue_message(source, target, channel, payload, delay_micros, key);
                    }
                }
            }
            Effect::Respond {
                client_id,
                operation_id,
                outcome,
                delay_micros,
                key,
            } => {
                let response_fault = ChoiceId::from(&key).sample(self.selection_seed()) % 1_000_000;
                let outcome = if response_fault < 10_000 && self.scenario.fault_depth > 0 {
                    ClientOutcome::Unknown
                } else {
                    outcome
                };
                self.enqueue(SimEvent {
                    at: self.now.saturating_add(delay_micros),
                    key,
                    kind: SimEventKind::ClientResponse {
                        source,
                        client_id,
                        operation_id,
                        outcome,
                    },
                });
            }
            Effect::ScheduleTimer {
                timer_id,
                payload,
                delay_micros,
                key,
            } => self.enqueue(SimEvent {
                at: self.now.saturating_add(delay_micros),
                key,
                kind: SimEventKind::Node {
                    target: source,
                    event: NodeEvent::Timer { timer_id, payload },
                },
            }),
            Effect::Persist {
                operation_id,
                key_bytes,
                value,
                context,
                key,
            } => self.apply_persist_effect(
                source,
                operation_id,
                key_bytes,
                Some(value),
                context,
                key,
            ),
            Effect::Delete {
                operation_id,
                key_bytes,
                context,
                key,
            } => self.apply_persist_effect(source, operation_id, key_bytes, None, context, key),
        }
        Ok(())
    }

    fn apply_persist_effect(
        &mut self,
        node: usize,
        operation_id: u64,
        key_bytes: Vec<u8>,
        value: Option<Vec<u8>>,
        context: Vec<u8>,
        key: EventKey,
    ) {
        let fault = self.storage_faults[node].clone();
        let mut delay = 0;
        let result = match fault {
            StorageFault::Healthy => match value {
                Some(value) => {
                    self.durable[node].insert(key_bytes, value.clone());
                    Ok(value)
                }
                None => {
                    self.durable[node].remove(&key_bytes);
                    Ok(Vec::new())
                }
            },
            StorageFault::Delay { micros } => {
                delay = micros;
                match value {
                    Some(value) => {
                        self.durable[node].insert(key_bytes, value.clone());
                        Ok(value)
                    }
                    None => {
                        self.durable[node].remove(&key_bytes);
                        Ok(Vec::new())
                    }
                }
            }
            StorageFault::Full => Err("storage full".to_string()),
            StorageFault::Io => Err("storage I/O failure".to_string()),
            StorageFault::Fsync => Err("storage fsync failure".to_string()),
            StorageFault::TornWrite { keep_bytes } => {
                if let Some(mut value) = value {
                    value.truncate(keep_bytes.min(value.len()));
                    self.durable[node].insert(key_bytes, value);
                }
                Err("torn write".to_string())
            }
            StorageFault::Corrupt { xor } => {
                if let Some(mut value) = value {
                    if let Some(first) = value.first_mut() {
                        *first ^= xor;
                    }
                    self.durable[node].insert(key_bytes, value);
                }
                Err("storage corruption".to_string())
            }
        };
        self.enqueue(SimEvent {
            at: self.now.saturating_add(delay),
            key,
            kind: SimEventKind::Node {
                target: node,
                event: NodeEvent::StorageComplete {
                    operation_id,
                    result,
                    context,
                },
            },
        });
    }

    fn enqueue_message(
        &mut self,
        source: usize,
        target: usize,
        channel: SimChannel,
        payload: Vec<u8>,
        delay_micros: u64,
        key: EventKey,
    ) {
        self.enqueue(SimEvent {
            at: self.now.saturating_add(delay_micros),
            key,
            kind: SimEventKind::Node {
                target,
                event: NodeEvent::Message {
                    source,
                    channel,
                    payload,
                },
            },
        });
    }

    fn apply_node_fault(&mut self, node: usize, fault: NodeFault) -> Result<()> {
        self.validate_node(node)?;
        match fault {
            NodeFault::Pause { micros } => {
                self.lifecycle[node] = NodeLifecycle::PausedUntil(self.now.saturating_add(micros));
            }
            NodeFault::Throttle { delay_micros } => {
                self.throttle_micros[node] = delay_micros;
            }
            NodeFault::GracefulStop => {
                self.lifecycle[node] = NodeLifecycle::GracefullyStopped;
            }
            NodeFault::Crash => {
                self.nodes[node].crash()?;
                self.lifecycle[node] = NodeLifecycle::Crashed;
            }
            NodeFault::Restart => {
                self.nodes[node].restart()?;
                self.lifecycle[node] = NodeLifecycle::Running;
            }
        }
        Ok(())
    }

    fn heal_all(&mut self) -> Result<()> {
        for source in 0..self.nodes.len() {
            for target in 0..self.nodes.len() {
                let was_jammed = self.links[source][target] == LinkState::Jam;
                self.links[source][target] = LinkState::Up;
                if was_jammed {
                    self.release_jam(source, target);
                }
            }
            self.storage_faults[source] = StorageFault::Healthy;
            self.throttle_micros[source] = 0;
            if self.lifecycle[source] != NodeLifecycle::Running {
                self.nodes[source].restart()?;
                self.lifecycle[source] = NodeLifecycle::Running;
            }
        }
        self.active_faults = 0;
        Ok(())
    }

    fn release_jam(&mut self, source: usize, target: usize) {
        if let Some(mut events) = self.jammed.remove(&(source, target)) {
            let mut release_offset = 0u64;
            while let Some(mut event) = events.pop_front() {
                event.at = event.at.max(self.now.saturating_add(release_offset));
                release_offset = release_offset.saturating_add(1);
                self.enqueue(event);
            }
        }
    }

    fn validate_node(&self, node: usize) -> Result<()> {
        if node >= self.nodes.len() {
            return Err(SimEnvError::InvalidNode {
                node,
                node_count: self.nodes.len(),
            });
        }
        Ok(())
    }

    fn selection_seed(&self) -> u64 {
        match &self.mode {
            RunMode::Random { seed } => *seed,
            RunMode::Replay { .. } | RunMode::Systematic { .. } => self.scenario.seed,
        }
    }

    fn state_digest(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"blossom/deterministic-cluster-state/v1");
        digest.update(self.now.0.to_le_bytes());
        for (index, node) in self.nodes.iter().enumerate() {
            digest.update(index.to_le_bytes());
            digest.update(node.state_digest().as_bytes());
            digest.update(format!("{:?}", self.lifecycle[index]).as_bytes());
            for (key, value) in &self.durable[index] {
                digest.update(key);
                digest.update(value);
            }
        }
        hex_bytes(&digest.finalize())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorationReport {
    pub schedules: usize,
    pub unique_states: usize,
    pub failures: Vec<ExecutionTrace>,
    pub traces: Vec<ExecutionTrace>,
}

pub struct SystematicExplorer {
    pub bounds: ExplorationBounds,
}

/// Conservative semantic dependency relation used for partial-order reduction.
///
/// Operations on the same actor, the same logical operation, or the same
/// protocol stage are considered dependent. Events for different actors and
/// unrelated stages may commute and do not need every permutation explored.
pub fn event_keys_dependent(left: &EventKey, right: &EventKey) -> bool {
    left.actor == right.actor
        || left.operation == right.operation
        || left
            .domain
            .split('-')
            .next()
            .zip(right.domain.split('-').next())
            .is_some_and(|(left, right)| left == right)
}

struct NoopObserver;

impl<Node> GlobalObserver<Node> for NoopObserver {
    fn observe(&mut self, _view: ClusterView<'_, Node>, _properties: &mut PropertyRegistry) {}
}

impl SystematicExplorer {
    pub fn explore<Node, Factory>(
        &self,
        scenario: &Scenario,
        factory: Factory,
    ) -> Result<ExplorationReport>
    where
        Node: DeterministicNode,
        Factory: FnMut() -> Result<Vec<Node>>,
    {
        self.explore_with_observer(scenario, factory, || NoopObserver)
    }

    pub fn explore_with_observer<Node, Factory, Observer, ObserverFactory>(
        &self,
        scenario: &Scenario,
        mut factory: Factory,
        mut observer_factory: ObserverFactory,
    ) -> Result<ExplorationReport>
    where
        Node: DeterministicNode,
        Factory: FnMut() -> Result<Vec<Node>>,
        Observer: GlobalObserver<Node>,
        ObserverFactory: FnMut() -> Observer,
    {
        let mut traces = Vec::new();
        let mut failures = Vec::new();
        let mut states = BTreeSet::new();
        let mut prefixes = VecDeque::from([Vec::<usize>::new()]);
        let mut seen_prefixes = BTreeSet::from([Vec::<usize>::new()]);
        while traces.len() < self.bounds.max_schedules {
            let Some(schedule) = prefixes.pop_front() else {
                break;
            };
            let mut bounded = scenario.clone();
            bounded.max_events = bounded.max_events.min(self.bounds.max_events);
            bounded.fault_depth = bounded.fault_depth.min(self.bounds.fault_depth);
            let trace = DeterministicCluster::new(
                bounded,
                factory()?,
                RunMode::Systematic {
                    schedule: schedule.clone(),
                    bounds: self.bounds.clone(),
                },
            )?
            .run_with_observer(&mut observer_factory())?;
            states.insert(trace.final_state_digest.clone());
            if !trace.properties.passed() {
                failures.push(trace.clone());
            }
            let branch_limit = trace
                .choices
                .len()
                .min(self.bounds.max_events)
                .min(schedule.len().saturating_add(1));
            for depth in 0..branch_limit {
                let width = trace.choices[depth]
                    .enabled
                    .len()
                    .min(self.bounds.max_branch_width);
                for branch in 0..width {
                    if branch == trace.choices[depth].selected_index
                        || !event_keys_dependent(
                            &trace.choices[depth].selected,
                            &trace.choices[depth].enabled[branch],
                        )
                    {
                        continue;
                    }
                    let mut next = schedule.clone();
                    next.resize(depth.saturating_add(1), 0);
                    next[depth] = branch;
                    while next.last() == Some(&0) {
                        next.pop();
                    }
                    if seen_prefixes.insert(next.clone()) {
                        prefixes.push_back(next);
                    }
                }
            }
            traces.push(trace);
        }
        Ok(ExplorationReport {
            schedules: traces.len(),
            unique_states: states.len(),
            failures,
            traces,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReducedTrace {
    pub scenario: Scenario,
    pub trace: ExecutionTrace,
    pub removed_actions: usize,
    pub attempts: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceReducer {
    pub max_attempts: usize,
}

impl Default for TraceReducer {
    fn default() -> Self {
        Self {
            max_attempts: 1_000,
        }
    }
}

impl TraceReducer {
    pub fn reduce<Node, Factory, Observer, ObserverFactory, Failure>(
        &self,
        scenario: &Scenario,
        original: &ExecutionTrace,
        mut factory: Factory,
        mut observer_factory: ObserverFactory,
        failure: Failure,
    ) -> Result<ReducedTrace>
    where
        Node: DeterministicNode,
        Factory: FnMut() -> Result<Vec<Node>>,
        Observer: GlobalObserver<Node>,
        ObserverFactory: FnMut() -> Observer,
        Failure: Fn(&ExecutionTrace) -> bool,
    {
        if !failure(original) {
            return Err(SimEnvError::App(
                "trace reducer requires an initially failing trace".to_string(),
            ));
        }
        let mut reduced = scenario.clone();
        let mut best = original.clone();
        let mut cursor = 0usize;
        let mut attempts = 0usize;
        while cursor < reduced.actions.len() && attempts < self.max_attempts {
            let mut candidate = reduced.clone();
            candidate.actions.remove(cursor);
            attempts = attempts.saturating_add(1);
            let trace = DeterministicCluster::new(
                candidate.clone(),
                factory()?,
                RunMode::Random {
                    seed: original.seed,
                },
            )?
            .run_with_observer(&mut observer_factory())?;
            if failure(&trace) {
                reduced = candidate;
                best = trace;
            } else {
                cursor = cursor.saturating_add(1);
            }
        }
        Ok(ReducedTrace {
            removed_actions: scenario.actions.len().saturating_sub(reduced.actions.len()),
            scenario: reduced,
            trace: best,
            attempts,
        })
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex_bytes(&digest.finalize())
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct CounterNode {
        value: u64,
        crashed_value: Option<u64>,
    }

    impl DeterministicNode for CounterNode {
        fn on_event(
            &mut self,
            event: NodeEvent,
            _context: &mut NodeContext,
        ) -> Result<Vec<Effect>> {
            match event {
                NodeEvent::Client {
                    client_id,
                    operation_id,
                    payload,
                } => {
                    self.value = self.value.saturating_add(1);
                    Ok(vec![Effect::Respond {
                        client_id,
                        operation_id,
                        outcome: ClientOutcome::Ok { payload },
                        delay_micros: 0,
                        key: EventKey::new("response", 0, operation_id, 0),
                    }])
                }
                NodeEvent::Message { .. } | NodeEvent::Timer { .. } | NodeEvent::Quiesce => {
                    self.value = self.value.saturating_add(1);
                    Ok(Vec::new())
                }
                NodeEvent::StorageComplete { .. } => Ok(Vec::new()),
            }
        }

        fn state_digest(&self) -> String {
            self.value.to_string()
        }

        fn crash(&mut self) -> Result<()> {
            self.crashed_value = Some(self.value);
            self.value = 0;
            Ok(())
        }

        fn restart(&mut self) -> Result<()> {
            self.value = self.crashed_value.unwrap_or_default();
            Ok(())
        }
    }

    fn scenario() -> Scenario {
        let mut scenario = Scenario::new("replay", "counter", 2);
        scenario.seed = 7;
        scenario.actions = vec![
            ScenarioAction {
                at: SimTime(1),
                key: EventKey::new("client", 0, 10, 0),
                action: ScenarioActionKind::Client {
                    source: 0,
                    target: 0,
                    client_id: 1,
                    operation_id: 10,
                    payload: b"a".to_vec(),
                },
            },
            ScenarioAction {
                at: SimTime(1),
                key: EventKey::new("client", 1, 11, 0),
                action: ScenarioActionKind::Client {
                    source: 1,
                    target: 1,
                    client_id: 2,
                    operation_id: 11,
                    payload: b"b".to_vec(),
                },
            },
        ];
        scenario
    }

    fn nodes() -> Vec<CounterNode> {
        vec![
            CounterNode {
                value: 0,
                crashed_value: None,
            },
            CounterNode {
                value: 0,
                crashed_value: None,
            },
        ]
    }

    #[test]
    fn exact_trace_replay_preserves_state_and_history() {
        let scenario = scenario();
        let first =
            DeterministicCluster::new(scenario.clone(), nodes(), RunMode::Random { seed: 42 })
                .unwrap()
                .run()
                .unwrap();
        let replay = DeterministicCluster::new(
            scenario,
            nodes(),
            RunMode::Replay {
                choices: first.choices.clone(),
            },
        )
        .unwrap()
        .run()
        .unwrap();
        assert_eq!(first.final_state_digest, replay.final_state_digest);
        assert_eq!(first.client_history, replay.client_history);
    }

    #[test]
    fn response_loss_is_an_explicit_unknown_outcome() {
        let mut scenario = scenario();
        scenario.fault_depth = 1;
        let mut observed_unknown = false;
        for seed in 0..10_000 {
            let trace =
                DeterministicCluster::new(scenario.clone(), nodes(), RunMode::Random { seed })
                    .unwrap()
                    .run()
                    .unwrap();
            observed_unknown |= trace.client_history.iter().any(|event| {
                matches!(
                    event,
                    ClientHistoryEvent::Complete {
                        outcome: ClientOutcome::Unknown,
                        ..
                    }
                )
            });
            if observed_unknown {
                break;
            }
        }
        assert!(observed_unknown);
    }

    #[test]
    fn directed_jam_releases_messages_on_heal() {
        struct Sender {
            sent: bool,
            received: u64,
        }

        impl DeterministicNode for Sender {
            fn on_event(
                &mut self,
                event: NodeEvent,
                _context: &mut NodeContext,
            ) -> Result<Vec<Effect>> {
                match event {
                    NodeEvent::Client { operation_id, .. } if !self.sent => {
                        self.sent = true;
                        Ok(vec![Effect::Send {
                            target: 1,
                            channel: SimChannel::Protocol,
                            payload: vec![1],
                            delay_micros: 0,
                            key: EventKey::new("message", 0, operation_id, 0),
                        }])
                    }
                    NodeEvent::Message { .. } => {
                        self.received = self.received.saturating_add(1);
                        Ok(Vec::new())
                    }
                    _ => Ok(Vec::new()),
                }
            }

            fn state_digest(&self) -> String {
                format!("{}:{}", self.sent, self.received)
            }
        }

        let mut scenario = Scenario::new("jam", "counter", 2);
        scenario.actions = vec![
            ScenarioAction {
                at: SimTime(0),
                key: EventKey::new("jam", 0, 0, 0),
                action: ScenarioActionKind::LinkFault {
                    source: 0,
                    target: 1,
                    fault: LinkFault::Jam,
                },
            },
            ScenarioAction {
                at: SimTime(1),
                key: EventKey::new("client", 0, 1, 0),
                action: ScenarioActionKind::Client {
                    source: 0,
                    target: 0,
                    client_id: 1,
                    operation_id: 1,
                    payload: Vec::new(),
                },
            },
            ScenarioAction {
                at: SimTime(2),
                key: EventKey::new("heal", 0, 2, 0),
                action: ScenarioActionKind::HealAll,
            },
        ];
        let trace = DeterministicCluster::new(
            scenario,
            vec![
                Sender {
                    sent: false,
                    received: 0,
                },
                Sender {
                    sent: false,
                    received: 0,
                },
            ],
            RunMode::Random { seed: 1 },
        )
        .unwrap()
        .run()
        .unwrap();
        assert!(trace.final_state_digest.len() == 64);
        assert_eq!(trace.stopped_reason, "quiescent");
    }

    #[test]
    fn property_registry_distinguishes_safety_and_reachability() {
        let mut properties = PropertyRegistry::default();
        properties.define("safe", PropertyKind::Always);
        properties.define("fault_seen", PropertyKind::Sometimes);
        properties.observe("safe", SimTime(1), true, "ok");
        properties.observe("fault_seen", SimTime(2), true, "observed");
        assert!(properties.report().passed());
        properties.observe("safe", SimTime(3), false, "violated");
        assert!(!properties.report().passed());
    }

    #[test]
    fn systematic_explorer_visits_multiple_schedules() {
        let explorer = SystematicExplorer {
            bounds: ExplorationBounds {
                max_events: 20,
                max_schedules: 4,
                max_branch_width: 2,
                fault_depth: 1,
            },
        };
        let report = explorer.explore(&scenario(), || Ok(nodes())).unwrap();
        assert!(report.schedules >= 2);
        assert!(!report.traces.is_empty());
    }
}
