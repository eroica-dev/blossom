//! In-process deterministic cluster fixtures for tests and examples.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::address_book::{
    Service, ServiceKind, ServiceRecordBody, SignedServiceRecord, unix_time_millis,
};
use crate::algorithm::{ConsensusParameters, QuorumSize};
use crate::block::{Block, Transaction};
use crate::crypto::{Keypair, SecKey};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::runtime::{
    EpochTarget, RuntimeConfig, TrustMode, genesis_epoch_for_group_with_parameters,
};
use crate::tcp::{
    ConsensusDriverConfig, TcpConnection, TcpNode, TcpNodeMetrics, TcpNodeMetricsSnapshot,
    send_wire_frame, send_wire_request, send_wire_request_raw_response,
};
use crate::wire::{
    EncodedFrame, WireRequest, WireResponse, read_wire_request, write_wire_response,
};

pub struct SimulatedCluster {
    nodes: Vec<SimulatedNode>,
}

pub struct SimulatedNode {
    pub identity: NodeIdentity,
    pub service: Service,
    pub keypair: Keypair,
    pub metrics: TcpNodeMetrics,
    pub runtime: crate::NodeRuntime,
    client: crate::TcpServiceClient,
    handle: JoinHandle<()>,
}

pub struct MockBlockService {
    pub service: Service,
    pub keypair: Keypair,
    state: Arc<Mutex<MockBlockServiceState>>,
    handle: JoinHandle<()>,
}

#[derive(Debug, Default)]
pub struct MockBlockServiceState {
    pub received_nonces: Vec<Nonce>,
    pub blocked_nonces: Vec<Nonce>,
    pub blocks: BTreeMap<Nonce, Block>,
    pub received_blocks: Vec<Block>,
}

impl SimulatedCluster {
    pub async fn spawn(count: usize) -> Result<Self> {
        Self::spawn_with_trust_mode(count, TrustMode::Verified).await
    }

    pub async fn spawn_trusted(count: usize) -> Result<Self> {
        Self::spawn_with_trust_mode(count, TrustMode::Trusted).await
    }

    pub async fn spawn_with_trust_mode(count: usize, trust_mode: TrustMode) -> Result<Self> {
        Self::spawn_with_options(count, trust_mode, None, QuorumSize::DEFAULT, false).await
    }

    /// Starts consensus-capable TCP nodes without autonomous consensus drivers.
    ///
    /// This is useful for deterministic protocol tests and benchmarks that
    /// need to establish an admission barrier before any node begins
    /// dispatching. Callers drive rounds explicitly with [`TcpNode`].
    pub async fn spawn_manual_with_trust_mode_and_quorum(
        count: usize,
        trust_mode: TrustMode,
        quorum_size: QuorumSize,
    ) -> Result<Self> {
        Self::spawn_with_options(count, trust_mode, None, quorum_size, true).await
    }

    pub async fn spawn_autonomous(count: usize) -> Result<Self> {
        Self::spawn_autonomous_with_config(count, ConsensusDriverConfig::default()).await
    }

    pub async fn spawn_autonomous_with_config(
        count: usize,
        driver: ConsensusDriverConfig,
    ) -> Result<Self> {
        Self::spawn_autonomous_with_config_and_quorum(count, driver, QuorumSize::DEFAULT).await
    }

    pub async fn spawn_autonomous_with_config_and_quorum(
        count: usize,
        driver: ConsensusDriverConfig,
        quorum_size: QuorumSize,
    ) -> Result<Self> {
        Self::spawn_autonomous_with_config_trust_mode_and_quorum(
            count,
            driver,
            TrustMode::Verified,
            quorum_size,
        )
        .await
    }

    pub async fn spawn_autonomous_with_config_trust_mode_and_quorum(
        count: usize,
        driver: ConsensusDriverConfig,
        trust_mode: TrustMode,
        quorum_size: QuorumSize,
    ) -> Result<Self> {
        Self::spawn_with_options(count, trust_mode, Some(driver), quorum_size, true).await
    }

    async fn spawn_with_options(
        count: usize,
        trust_mode: TrustMode,
        driver: Option<ConsensusDriverConfig>,
        quorum_size: QuorumSize,
        configure_consensus_peers: bool,
    ) -> Result<Self> {
        if count == 0 {
            return Err(BlossomError::WireProtocol(
                "simulated cluster must contain at least one node".to_string(),
            ));
        }

        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|err| BlossomError::Io(err.to_string()))?;
            let port = listener
                .local_addr()
                .map_err(|err| BlossomError::Io(err.to_string()))?
                .port();
            let keypair = Keypair::generate();
            let identity = NodeIdentity::new(
                keypair.public,
                Some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                port,
                false,
            );
            entries.push((index, listener, keypair, identity));
        }

        let genesis = genesis_epoch_for_group_with_parameters(
            ConsensusGroupId::root(),
            entries.iter().map(|(_, _, _, identity)| {
                NodeIdentity::new(
                    identity.public_key(),
                    None,
                    identity.protocol.clone(),
                    identity.host.clone(),
                    identity.port,
                    identity.shuffle,
                )
            }),
            ConsensusParameters::new(quorum_size),
        );
        let services = entries
            .iter()
            .map(|(_, _, _, identity)| {
                Service::new(
                    ServiceKind::Consensus,
                    identity.public_key(),
                    identity.protocol.clone(),
                    identity.host.clone(),
                    identity.port,
                )
            })
            .collect::<Vec<_>>();

        let mut nodes = Vec::with_capacity(count);
        for (index, listener, keypair, identity) in entries {
            let mut config = RuntimeConfig::new(identity.clone()).with_quorum_size(quorum_size);
            config.genesis = Some(genesis.clone());
            config.trust_mode = trust_mode;
            if configure_consensus_peers {
                for service in &services {
                    config.address_book.add(service.clone());
                }
            }
            let runtime = crate::NodeRuntime::new(config);
            let metrics = TcpNodeMetrics::default();
            let node = TcpNode::with_metrics(runtime, metrics.clone());
            let node_runtime = node.runtime.clone();
            let node_driver = driver.clone();
            let handle = tokio::spawn(async move {
                let result = match node_driver {
                    Some(driver) => node.serve_with_consensus_driver(listener, driver).await,
                    None => node.serve(listener).await,
                };
                if let Err(err) = result {
                    log::error!("simulated node {index} failed: {err}");
                }
            });
            let service = services[index].clone();
            nodes.push(SimulatedNode {
                identity,
                service,
                keypair,
                metrics,
                runtime: node_runtime,
                client: crate::TcpServiceClient::new(),
                handle,
            });
        }

        Ok(Self { nodes })
    }

    pub fn nodes(&self) -> &[SimulatedNode] {
        &self.nodes
    }

    pub fn node(&self, index: usize) -> &SimulatedNode {
        &self.nodes[index]
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn node_metrics(&self) -> Vec<TcpNodeMetricsSnapshot> {
        self.nodes
            .iter()
            .map(|node| node.metrics.snapshot())
            .collect()
    }

    pub async fn request(&self, index: usize, request: WireRequest) -> Result<WireResponse> {
        self.nodes[index]
            .client
            .request(&self.nodes[index].service, &request)
            .await
    }

    /// Returns an owned persistent client and service handle for concurrent
    /// fanout without opening a fresh TCP connection for every request.
    pub fn request_handle(&self, index: usize) -> (crate::TcpServiceClient, Service) {
        (
            self.nodes[index].client.clone(),
            self.nodes[index].service.clone(),
        )
    }

    pub async fn request_frame(&self, index: usize, frame: &EncodedFrame) -> Result<WireResponse> {
        self.nodes[index].request_frame(frame).await
    }

    pub async fn request_raw_response_frame(
        &self,
        index: usize,
        request: WireRequest,
    ) -> Result<EncodedFrame> {
        self.nodes[index].request_raw_response_frame(request).await
    }

    pub async fn connect(&self, index: usize) -> Result<TcpConnection> {
        self.nodes[index].connect().await
    }

    pub async fn next_target(&self, index: usize) -> Result<EpochTarget> {
        match self.request(index, WireRequest::NextNonce).await? {
            WireResponse::NextNonce(target) => Ok(target),
            response => Err(BlossomError::WireProtocol(format!(
                "expected next nonce, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn signed_block_for(
        &self,
        target_node: usize,
        signer: usize,
        txs: impl IntoIterator<Item = Transaction>,
    ) -> Result<Block> {
        let target = self.next_target(target_node).await?;
        Ok(signed_block(
            target,
            self.nodes[signer].keypair.secret.clone(),
            txs,
        ))
    }
}

impl Drop for SimulatedCluster {
    fn drop(&mut self) {
        for node in &self.nodes {
            node.handle.abort();
        }
    }
}

impl SimulatedNode {
    pub fn client(&self) -> crate::TcpServiceClient {
        self.client.clone()
    }

    pub fn addr(&self) -> String {
        self.service.socket_addr()
    }

    pub async fn request(&self, request: WireRequest) -> Result<WireResponse> {
        send_wire_request(self.addr(), request).await
    }

    pub async fn request_frame(&self, frame: &EncodedFrame) -> Result<WireResponse> {
        send_wire_frame(self.addr(), frame).await
    }

    pub async fn request_raw_response_frame(&self, request: WireRequest) -> Result<EncodedFrame> {
        send_wire_request_raw_response(self.addr(), request).await
    }

    pub async fn connect(&self) -> Result<TcpConnection> {
        TcpConnection::connect(self.addr()).await
    }
}

impl MockBlockService {
    pub async fn spawn() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        let port = listener
            .local_addr()
            .map_err(|err| BlossomError::Io(err.to_string()))?
            .port();
        let keypair = Keypair::generate();
        let service = Service::new(ServiceKind::Block, keypair.public, "tcp", "127.0.0.1", port);
        let state = Arc::new(Mutex::new(MockBlockServiceState::default()));
        let service_state = state.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let service_state = service_state.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_mock_block_connection(stream, service_state).await {
                        log::error!("mock block service connection failed: {err}");
                    }
                });
            }
        });

        Ok(Self {
            service,
            keypair,
            state,
            handle,
        })
    }

    pub fn insert_block(&self, block: Block) {
        self.state
            .lock()
            .expect("mock block service state poisoned")
            .blocks
            .insert(block.body.nonce, block);
    }

    pub fn received_nonces(&self) -> Vec<Nonce> {
        self.state
            .lock()
            .expect("mock block service state poisoned")
            .received_nonces
            .clone()
    }

    pub fn blocked_nonces(&self) -> Vec<Nonce> {
        self.state
            .lock()
            .expect("mock block service state poisoned")
            .blocked_nonces
            .clone()
    }

    pub fn received_blocks(&self) -> Vec<Block> {
        self.state
            .lock()
            .expect("mock block service state poisoned")
            .received_blocks
            .clone()
    }

    pub async fn request(&self, request: WireRequest) -> Result<WireResponse> {
        send_wire_request(self.service.socket_addr(), request).await
    }

    pub fn signed_block(
        &self,
        target: EpochTarget,
        txs: impl IntoIterator<Item = Transaction>,
    ) -> Block {
        signed_block(target, self.keypair.secret.clone(), txs)
    }

    /// Creates a signed endpoint record owned by an already committed member.
    pub fn signed_record(
        &self,
        group_id: ConsensusGroupId,
        owner: &Keypair,
        generation: u64,
    ) -> Result<SignedServiceRecord> {
        SignedServiceRecord::signed(
            ServiceRecordBody {
                group_id,
                owner: owner.public,
                service_kind: self.service.kind,
                protocol: self.service.protocol.clone(),
                host: self.service.host.clone(),
                port: self.service.port,
                generation,
                expires_at_unix_millis: unix_time_millis().saturating_add(60_000),
                tombstone: false,
            },
            &owner.signer(),
        )
    }
}

impl Drop for MockBlockService {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub fn signed_block(
    target: EpochTarget,
    secret_key: SecKey,
    txs: impl IntoIterator<Item = Transaction>,
) -> Block {
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.body.txs.extend(txs);
    block.sign(&secret_key);
    block
}

async fn handle_mock_block_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<MockBlockServiceState>>,
) -> Result<()> {
    let request = read_wire_request(&mut stream).await?;
    let response = handle_mock_block_request(request, state);
    write_wire_response(&mut stream, &response).await
}

fn handle_mock_block_request(
    request: WireRequest,
    state: Arc<Mutex<MockBlockServiceState>>,
) -> WireResponse {
    match request {
        WireRequest::SendNonce(nonce) => {
            state
                .lock()
                .expect("mock block service state poisoned")
                .received_nonces
                .push(nonce);
            WireResponse::Ok
        }
        WireRequest::BlockNonce(nonce) => {
            state
                .lock()
                .expect("mock block service state poisoned")
                .blocked_nonces
                .push(nonce);
            WireResponse::Ok
        }
        WireRequest::GetBlock(nonce) => state
            .lock()
            .expect("mock block service state poisoned")
            .blocks
            .get(&nonce)
            .cloned()
            .map(WireResponse::Block)
            .unwrap_or_else(|| WireResponse::Error(format!("missing block for nonce {nonce}"))),
        WireRequest::SendBlock(block) => {
            state
                .lock()
                .expect("mock block service state poisoned")
                .received_blocks
                .push(block);
            WireResponse::Ok
        }
        WireRequest::Health => {
            WireResponse::Health(crate::wire::NodeHealth::new("ok", crate::PubKey::default()))
        }
        WireRequest::Ping(ping) => WireResponse::Pong(crate::wire::NodePong::new(
            crate::ConsensusGroupId::root(),
            crate::PubKey::default(),
            ping.nonce,
            ping.payload,
        )),
        request => WireResponse::Error(format!(
            "unsupported mock block request {}",
            request_kind(&request)
        )),
    }
}

fn request_kind(request: &WireRequest) -> &'static str {
    match request {
        WireRequest::Health => "health",
        WireRequest::Ping(_) => "ping",
        WireRequest::Application(_) => "application",
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
        WireRequest::EpochChain => "epoch_chain",
        WireRequest::CertifiedEpochSuffix { .. } => "certified_epoch_suffix",
        WireRequest::AddressBook => "address_book",
        WireRequest::RegisterService(_) => "register_service",
        WireRequest::Group { .. } => "group",
        WireRequest::NextNonce => "next_nonce",
        WireRequest::SubmitBlock(_) => "submit_block",
        WireRequest::Dispatch { .. } => "dispatch",
        WireRequest::PrefillDispatch(_) => "prefill_dispatch",
        WireRequest::Message(_) => "message",
        WireRequest::SendNonce(_) => "send_nonce",
        WireRequest::BlockNonce(_) => "block_nonce",
        WireRequest::GetBlock(_) => "get_block",
        WireRequest::GetBlocksByHash { .. } => "get_blocks_by_hash",
        WireRequest::SendBlock(_) => "send_block",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_block_sets_target_and_verifies() {
        let keypair = Keypair::generate();
        let target = EpochTarget {
            group_id: crate::group::ConsensusGroupId::root(),
            last_epoch: crate::HashType([5; 32]),
            nonce: Nonce::new(3),
        };

        let block = signed_block(target.clone(), keypair.secret, [Transaction::new("tx")]);

        assert_eq!(block.body.validator, keypair.public);
        assert_eq!(block.body.last_epoch, target.last_epoch);
        assert_eq!(block.body.nonce, target.nonce);
        assert_eq!(block.len(), 1);
        assert!(block.verify_integrity().is_ok());
    }

    #[tokio::test]
    async fn simulated_cluster_spawns_requested_number_of_nodes() {
        let cluster = SimulatedCluster::spawn(2).await.unwrap();

        assert_eq!(cluster.len(), 2);
        assert!(!cluster.is_empty());
        assert_ne!(
            cluster.node(0).identity.public_key(),
            cluster.node(1).identity.public_key()
        );
    }

    #[tokio::test]
    async fn simulated_cluster_can_spawn_in_trusted_mode() {
        let cluster = SimulatedCluster::spawn_trusted(2).await.unwrap();

        assert_eq!(cluster.len(), 2);
    }

    #[tokio::test]
    async fn autonomous_cluster_commits_configurable_quorum_parameters() {
        let cluster = SimulatedCluster::spawn_autonomous_with_config_and_quorum(
            3,
            ConsensusDriverConfig::default(),
            QuorumSize::new(9).unwrap(),
        )
        .await
        .unwrap();
        let response = cluster
            .request(0, WireRequest::Ping(crate::NodePing::new(7)))
            .await
            .unwrap();
        let WireResponse::Pong(pong) = response else {
            panic!("expected pong");
        };
        assert_eq!(pong.quorum_size, 9);
    }

    #[tokio::test]
    async fn simulated_cluster_records_per_node_tcp_metrics() {
        let cluster = SimulatedCluster::spawn(2).await.unwrap();

        cluster
            .request(1, WireRequest::Ping(crate::NodePing::new(7)))
            .await
            .unwrap();
        cluster
            .request(1, WireRequest::Ping(crate::NodePing::new(8)))
            .await
            .unwrap();

        let metrics = cluster.node_metrics();
        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0].requests, 0);
        assert_eq!(metrics[1].connections, 1);
        assert_eq!(metrics[1].requests, 2);
        assert_eq!(metrics[1].responses, 2);
        assert_eq!(metrics[1].errors, 0);
        assert!(metrics[1].handler_nanos > 0);
    }

    #[tokio::test]
    async fn zero_node_cluster_is_rejected() {
        assert!(matches!(
            SimulatedCluster::spawn(0).await,
            Err(BlossomError::WireProtocol(_))
        ));
    }
}
