use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::address_book::{Service, ServiceKind};
use crate::block::{Block, Transaction};
use crate::crypto::{Keypair, SecKey};
use crate::error::{BlossomError, Result};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::runtime::{EpochTarget, RuntimeConfig, genesis_epoch};
use crate::tcp::{TcpNode, send_wire_request};
use crate::wire::{WireRequest, WireResponse, read_frame, write_frame};

pub struct SimulatedCluster {
    nodes: Vec<SimulatedNode>,
}

pub struct SimulatedNode {
    pub identity: NodeIdentity,
    pub service: Service,
    pub keypair: Keypair,
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
                Some(keypair.secret),
                "tcp",
                "127.0.0.1",
                port,
                false,
            );
            entries.push((index, listener, keypair, identity));
        }

        let genesis = genesis_epoch(entries.iter().map(|(_, _, _, identity)| {
            NodeIdentity::new(
                identity.public_key(),
                None,
                identity.protocol.clone(),
                identity.host.clone(),
                identity.port,
                identity.shuffle,
            )
        }));

        let mut nodes = Vec::with_capacity(count);
        for (index, listener, keypair, identity) in entries {
            let mut config = RuntimeConfig::new(identity.clone());
            config.genesis = Some(genesis.clone());
            let runtime = crate::NodeRuntime::new(config);
            let node = TcpNode::new(runtime);
            let handle = tokio::spawn(async move {
                if let Err(err) = node.serve(listener).await {
                    log::error!("simulated node {index} failed: {err}");
                }
            });
            let service = Service::new(
                ServiceKind::Consensus,
                identity.public_key(),
                identity.protocol.clone(),
                identity.host.clone(),
                identity.port,
            );
            nodes.push(SimulatedNode {
                identity,
                service,
                keypair,
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

    pub async fn request(&self, index: usize, request: WireRequest) -> Result<WireResponse> {
        self.nodes[index].request(request).await
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
        Ok(signed_block(target, self.nodes[signer].keypair.secret, txs))
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
    pub fn addr(&self) -> String {
        self.service.socket_addr()
    }

    pub async fn request(&self, request: WireRequest) -> Result<WireResponse> {
        send_wire_request(self.addr(), request).await
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
        signed_block(target, self.keypair.secret, txs)
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
    let request = read_frame(&mut stream).await?;
    let response = handle_mock_block_request(request, state);
    write_frame(&mut stream, &response).await
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
        WireRequest::Health => WireResponse::Health(crate::wire::NodeHealth {
            status: "ok".to_string(),
            public_key: crate::PubKey::default(),
        }),
        request => WireResponse::Error(format!(
            "unsupported mock block request {}",
            request_kind(&request)
        )),
    }
}

fn request_kind(request: &WireRequest) -> &'static str {
    match request {
        WireRequest::Health => "health",
        WireRequest::State => "state",
        WireRequest::AddressBook => "address_book",
        WireRequest::RegisterService(_) => "register_service",
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

    #[test]
    fn signed_block_sets_target_and_verifies() {
        let keypair = Keypair::generate();
        let target = EpochTarget {
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
    async fn zero_node_cluster_is_rejected() {
        assert!(matches!(
            SimulatedCluster::spawn(0).await,
            Err(BlossomError::WireProtocol(_))
        ));
    }
}
