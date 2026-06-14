use std::sync::Arc;
use std::time::Instant;

use fast_telemetry::Counter;
use tokio::net::{TcpListener, TcpStream};

use crate::address_book::ServiceKind;
#[cfg(feature = "availability-gossip")]
use crate::availability::FilteredPayloadMissing;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::HashType;
use crate::runtime::{MultiGroupRuntime, NodeRuntime};
use crate::service_client::TcpServiceClient;
use crate::wire::{
    AddressBookUpdate, EncodedFrame, NodeHealth, NodePong, WireRequest, WireRequestFrame,
    WireResponse, read_encoded_frame, read_wire_request_frame_optional, read_wire_response,
    write_encoded_frame, write_wire_request, write_wire_response,
};

#[derive(Clone)]
pub struct TcpNode {
    pub runtime: NodeRuntime,
    pub services: TcpServiceClient,
    metrics: Option<TcpNodeMetrics>,
}

impl TcpNode {
    pub fn new(runtime: NodeRuntime) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            metrics: None,
        }
    }

    pub fn with_services(runtime: NodeRuntime, services: TcpServiceClient) -> Self {
        Self {
            runtime,
            services,
            metrics: None,
        }
    }

    pub fn with_metrics(runtime: NodeRuntime, metrics: TcpNodeMetrics) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            metrics: Some(metrics),
        }
    }

    pub fn metrics(&self) -> Option<TcpNodeMetricsSnapshot> {
        self.metrics.as_ref().map(TcpNodeMetrics::snapshot)
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|err| BlossomError::Io(err.to_string()))?;
            let node = self.clone();
            if let Some(metrics) = &node.metrics {
                metrics.record_connection();
            }
            tokio::spawn(async move {
                if let Err(err) = node.handle_connection(stream).await {
                    log::error!("connection failed: {err}");
                }
            });
        }
    }

    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        configure_tcp_stream(&stream)?;
        while let Some(request) = read_wire_request_frame_optional(&mut stream).await? {
            let started = Instant::now();
            let result = self.handle_request_frame(request).await;
            if let Some(metrics) = &self.metrics {
                metrics.record_request(started.elapsed().as_nanos(), result.is_ok());
            }
            let response = match result {
                Ok(response) => response,
                Err(err) => WireResponse::Error(err.to_string()),
            };
            write_wire_response(&mut stream, &response).await?;
        }
        Ok(())
    }

    pub async fn handle_request_frame(&self, request: WireRequestFrame) -> Result<WireResponse> {
        match request {
            WireRequestFrame::Request(request) => self.handle_request(request).await,
            WireRequestFrame::HotDispatch(dispatch) => Ok(WireResponse::MessageReceipt(
                self.runtime.receive_hot_dispatch(dispatch)?,
            )),
        }
    }

    pub async fn handle_request(&self, request: WireRequest) -> Result<WireResponse> {
        match request {
            WireRequest::Group { group_id, request } => {
                if group_id != self.runtime.group_id() {
                    return Err(unknown_group(group_id));
                }
                handle_runtime_request(&self.runtime, &self.services, *request).await
            }
            request => handle_runtime_request(&self.runtime, &self.services, request).await,
        }
    }
}

#[derive(Clone, Default)]
pub struct TcpNodeMetrics {
    inner: Arc<TcpNodeMetricsInner>,
}

struct TcpNodeMetricsInner {
    connections: Counter,
    requests: Counter,
    responses: Counter,
    errors: Counter,
    handler_nanos: Counter,
}

impl Default for TcpNodeMetricsInner {
    fn default() -> Self {
        Self {
            connections: Counter::new(64),
            requests: Counter::new(64),
            responses: Counter::new(64),
            errors: Counter::new(64),
            handler_nanos: Counter::new(64),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpNodeMetricsSnapshot {
    pub connections: u64,
    pub requests: u64,
    pub responses: u64,
    pub errors: u64,
    pub handler_nanos: u64,
}

impl TcpNodeMetrics {
    pub fn snapshot(&self) -> TcpNodeMetricsSnapshot {
        TcpNodeMetricsSnapshot {
            connections: counter_sum_u64(&self.inner.connections),
            requests: counter_sum_u64(&self.inner.requests),
            responses: counter_sum_u64(&self.inner.responses),
            errors: counter_sum_u64(&self.inner.errors),
            handler_nanos: counter_sum_u64(&self.inner.handler_nanos),
        }
    }

    fn record_connection(&self) {
        self.inner.connections.inc();
    }

    fn record_request(&self, nanos: u128, success: bool) {
        self.inner.requests.inc();
        match success {
            true => self.inner.responses.inc(),
            false => self.inner.errors.inc(),
        };
        counter_add_u128(&self.inner.handler_nanos, nanos);
    }
}

fn counter_sum_u64(counter: &Counter) -> u64 {
    u64::try_from(counter.sum()).unwrap_or_default()
}

fn counter_add_u128(counter: &Counter, value: u128) {
    counter.add(isize::try_from(value).unwrap_or(isize::MAX));
}

#[derive(Clone)]
pub struct TcpMultiGroupNode {
    pub runtime: MultiGroupRuntime,
    pub services: TcpServiceClient,
}

impl TcpMultiGroupNode {
    pub fn new(runtime: MultiGroupRuntime) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
        }
    }

    pub fn with_services(runtime: MultiGroupRuntime, services: TcpServiceClient) -> Self {
        Self { runtime, services }
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|err| BlossomError::Io(err.to_string()))?;
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(err) = node.handle_connection(stream).await {
                    log::error!("connection failed: {err}");
                }
            });
        }
    }

    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        configure_tcp_stream(&stream)?;
        while let Some(request) = read_wire_request_frame_optional(&mut stream).await? {
            let response = match self.handle_request_frame(request).await {
                Ok(response) => response,
                Err(err) => WireResponse::Error(err.to_string()),
            };
            write_wire_response(&mut stream, &response).await?;
        }
        Ok(())
    }

    pub async fn handle_request_frame(&self, request: WireRequestFrame) -> Result<WireResponse> {
        match request {
            WireRequestFrame::Request(request) => self.handle_request(request).await,
            WireRequestFrame::HotDispatch(dispatch) => {
                let runtime = self
                    .runtime
                    .group_for_epoch(&dispatch.header.last_epoch)
                    .ok_or_else(|| unknown_epoch_group(dispatch.header.last_epoch))?;
                Ok(WireResponse::MessageReceipt(
                    runtime.receive_hot_dispatch(dispatch)?,
                ))
            }
        }
    }

    pub async fn handle_request(&self, request: WireRequest) -> Result<WireResponse> {
        match request {
            WireRequest::Group { group_id, request } => {
                let runtime = self
                    .runtime
                    .group(&group_id)
                    .ok_or_else(|| unknown_group(group_id))?;
                handle_runtime_request(&runtime, &self.services, *request).await
            }
            request => {
                let runtime = self.runtime.root_runtime();
                handle_runtime_request(&runtime, &self.services, request).await
            }
        }
    }
}

async fn handle_runtime_request(
    runtime: &NodeRuntime,
    services: &TcpServiceClient,
    request: WireRequest,
) -> Result<WireResponse> {
    match request {
        WireRequest::Health => Ok(WireResponse::Health(NodeHealth::new(
            "ok",
            runtime.self_node().public_key(),
        ))),
        WireRequest::Ping(ping) => Ok(WireResponse::Pong(NodePong::new(
            runtime.group_id(),
            runtime.self_node().public_key(),
            ping.nonce,
            ping.payload,
        ))),
        #[cfg(feature = "availability-gossip")]
        WireRequest::AvailabilityGossip(gossip) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_availability_gossip(gossip)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::GetFilteredPayload(fetch) => {
            let missing = FilteredPayloadMissing {
                scope: fetch.body.scope,
                holder: runtime.self_node().public_key(),
                slot_hash: fetch.body.slot_hash,
                payload_commitment: fetch.body.payload_commitment,
            };
            match runtime.serve_filtered_payload_fetch(fetch)? {
                Some(delivery) => Ok(WireResponse::FilteredPayload(delivery)),
                None => Ok(WireResponse::FilteredPayloadMissing(missing)),
            }
        }
        #[cfg(feature = "availability-gossip")]
        WireRequest::GetFilteredPayloadBatch(fetch) => Ok(WireResponse::FilteredPayloadBatch(
            runtime.serve_filtered_payload_batch_fetch(fetch)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::StoreFilteredPayload(delivery) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_filtered_payload(delivery)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::StoreFilteredPayloadBatch(delivery) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_filtered_payload_batch(delivery)?,
        )),
        WireRequest::State => Ok(WireResponse::State(runtime.status()?)),
        WireRequest::AddressBook => Ok(WireResponse::AddressBook(runtime.address_book())),
        WireRequest::RegisterService(registration) => {
            let (service, admission) = registration.into_parts();
            let previous = runtime.register_service(service.clone());
            let admitted_node = match admission {
                Some(admission) => runtime.stage_node_admission(admission)?,
                None => None,
            };
            let nonce_announced = if service.kind == ServiceKind::Block {
                let target = runtime.next_epoch_target()?;
                services.send_nonce(&service, target.nonce).await?;
                Some(target.nonce)
            } else {
                None
            };
            Ok(WireResponse::AddressBookUpdated(AddressBookUpdate {
                service,
                previous,
                nonce_announced,
                admitted_node,
            }))
        }
        WireRequest::NextNonce => Ok(WireResponse::NextNonce(runtime.next_epoch_target()?)),
        WireRequest::SubmitBlock(block) => {
            Ok(WireResponse::BlockAccepted(runtime.submit_block(block)?))
        }
        WireRequest::Dispatch { round } => {
            Ok(WireResponse::Dispatch(runtime.dispatch_local_block(round)?))
        }
        WireRequest::Message(message) => Ok(WireResponse::MessageReceipt(
            runtime.receive_message(message)?,
        )),
        WireRequest::SendNonce(_) | WireRequest::BlockNonce(_) => Ok(WireResponse::Ok),
        WireRequest::GetBlock(_) => Err(BlossomError::WireProtocol(
            "this node does not serve block-service block retrieval".to_string(),
        )),
        WireRequest::SendBlock(block) => {
            runtime.submit_block(block)?;
            Ok(WireResponse::Ok)
        }
        WireRequest::Group { group_id, .. } => Err(BlossomError::WireProtocol(format!(
            "nested grouped request for group {group_id} is not allowed"
        ))),
    }
}

fn unknown_group(group_id: ConsensusGroupId) -> BlossomError {
    BlossomError::WireProtocol(format!("unknown consensus group {group_id}"))
}

fn unknown_epoch_group(last_epoch: HashType) -> BlossomError {
    BlossomError::WireProtocol(format!("no consensus group is tracking epoch {last_epoch}"))
}

pub struct TcpConnection {
    stream: TcpStream,
}

impl TcpConnection {
    pub async fn connect(addr: impl AsRef<str>) -> Result<Self> {
        let stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        configure_tcp_stream(&stream)?;
        Ok(Self { stream })
    }

    pub async fn request(&mut self, request: &WireRequest) -> Result<WireResponse> {
        write_wire_request(&mut self.stream, request).await?;
        read_wire_response(&mut self.stream).await
    }

    pub async fn request_frame(&mut self, frame: &EncodedFrame) -> Result<WireResponse> {
        write_encoded_frame(&mut self.stream, frame).await?;
        read_wire_response(&mut self.stream).await
    }

    pub async fn request_raw_response(&mut self, request: &WireRequest) -> Result<EncodedFrame> {
        write_wire_request(&mut self.stream, request).await?;
        read_encoded_frame(&mut self.stream).await
    }
}

fn configure_tcp_stream(stream: &TcpStream) -> Result<()> {
    stream
        .set_nodelay(true)
        .map_err(|err| BlossomError::Io(err.to_string()))
}

pub async fn send_wire_request(
    addr: impl AsRef<str>,
    request: WireRequest,
) -> Result<WireResponse> {
    let mut connection = TcpConnection::connect(addr).await?;
    connection.request(&request).await
}

pub async fn send_wire_frame(addr: impl AsRef<str>, frame: &EncodedFrame) -> Result<WireResponse> {
    let mut connection = TcpConnection::connect(addr).await?;
    connection.request_frame(frame).await
}

pub async fn send_wire_request_raw_response(
    addr: impl AsRef<str>,
    request: WireRequest,
) -> Result<EncodedFrame> {
    let mut connection = TcpConnection::connect(addr).await?;
    connection.request_raw_response(&request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::group::ConsensusGroupId;
    use crate::node::NodeIdentity;
    use crate::runtime::{
        MultiGroupRuntime, RuntimeConfig, genesis_epoch, genesis_epoch_for_group,
    };

    fn tcp_node() -> (TcpNode, Keypair) {
        let keypair = Keypair::generate();
        let identity = NodeIdentity::new(
            keypair.public,
            Some(keypair.secret),
            "tcp",
            "127.0.0.1",
            8080,
            false,
        );
        (
            TcpNode::new(crate::NodeRuntime::new(RuntimeConfig::new(identity))),
            keypair,
        )
    }

    #[tokio::test]
    async fn handle_request_returns_health_and_errors() {
        let (node, keypair) = tcp_node();

        match node.handle_request(WireRequest::Health).await.unwrap() {
            WireResponse::Health(health) => {
                assert_eq!(health.public_key, keypair.public);
                assert!(health.protocol_hash_compatible());
            }
            response => panic!("expected health, got {}", response.kind()),
        }

        match node
            .handle_request(WireRequest::GetBlock(crate::Nonce::new(1)))
            .await
            .unwrap_err()
        {
            BlossomError::WireProtocol(message) => assert!(message.contains("does not serve")),
            error => panic!("unexpected error: {error}"),
        }
    }

    #[tokio::test]
    async fn handle_request_returns_direct_pong_without_consensus() {
        let (node, keypair) = tcp_node();
        let ping = crate::NodePing::with_payload(42, b"hello-peer");

        match node.handle_request(WireRequest::Ping(ping)).await.unwrap() {
            WireResponse::Pong(pong) => {
                assert_eq!(pong.group_id, ConsensusGroupId::root());
                assert_eq!(pong.public_key, keypair.public);
                assert!(pong.protocol_hash_compatible());
                assert_eq!(pong.nonce, 42);
                assert_eq!(pong.payload, b"hello-peer");
            }
            response => panic!("expected pong, got {}", response.kind()),
        }
    }

    #[tokio::test]
    async fn multi_group_node_routes_grouped_requests_to_subnets() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let identities = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                NodeIdentity::new(
                    keypair.public,
                    (index == 0).then_some(keypair.secret),
                    "tcp",
                    "127.0.0.1",
                    8000 + index as u16,
                    false,
                )
            })
            .collect::<Vec<_>>();

        let root_genesis = genesis_epoch(identities.clone());
        let subnet_id = ConsensusGroupId::named("cache-hotset-a");
        let subnet_genesis = genesis_epoch_for_group(subnet_id, identities[..3].to_vec());

        let mut root_config = RuntimeConfig::new(identities[0].clone());
        root_config.genesis = Some(root_genesis.clone());
        let root_runtime = NodeRuntime::new(root_config);

        let mut subnet_config = RuntimeConfig::new(identities[0].clone());
        subnet_config.group_id = subnet_id;
        subnet_config.genesis = Some(subnet_genesis.clone());
        let subnet_runtime = NodeRuntime::new(subnet_config);
        subnet_runtime
            .set_application_state(b"subnet-only")
            .unwrap();

        let root_target = root_runtime.next_epoch_target().unwrap();
        let subnet_target = subnet_runtime.next_epoch_target().unwrap();
        let node = TcpMultiGroupNode::new(MultiGroupRuntime::with_groups(
            root_runtime,
            [subnet_runtime],
        ));

        match node.handle_request(WireRequest::NextNonce).await.unwrap() {
            WireResponse::NextNonce(target) => {
                assert_eq!(target.last_epoch, root_target.last_epoch)
            }
            response => panic!("expected root next nonce, got {}", response.kind()),
        }

        let grouped_next = WireRequest::Group {
            group_id: subnet_id,
            request: Box::new(WireRequest::NextNonce),
        };
        match node.handle_request(grouped_next).await.unwrap() {
            WireResponse::NextNonce(target) => {
                assert_eq!(target.last_epoch, subnet_target.last_epoch);
                assert_eq!(target.nonce, subnet_target.nonce);
            }
            response => panic!("expected subnet next nonce, got {}", response.kind()),
        }

        let grouped_ping = WireRequest::Group {
            group_id: subnet_id,
            request: Box::new(WireRequest::Ping(crate::NodePing::new(7))),
        };
        match node.handle_request(grouped_ping).await.unwrap() {
            WireResponse::Pong(pong) => {
                assert_eq!(pong.group_id, subnet_id);
                assert_eq!(pong.public_key, keypairs[0].public);
                assert_eq!(pong.nonce, 7);
                assert!(pong.payload.is_empty());
            }
            response => panic!("expected subnet pong, got {}", response.kind()),
        }

        let grouped_dispatch = WireRequest::Group {
            group_id: subnet_id,
            request: Box::new(WireRequest::Dispatch { round: 0 }),
        };
        match node.handle_request(grouped_dispatch).await.unwrap() {
            WireResponse::Dispatch(dispatch) => {
                assert_eq!(dispatch.header.last_epoch, subnet_target.last_epoch);
                let block = dispatch.body.blocks.values().next().unwrap();
                assert_eq!(block.application_state(), b"subnet-only");
            }
            response => panic!("expected subnet dispatch, got {}", response.kind()),
        }

        let unknown_group = WireRequest::Group {
            group_id: ConsensusGroupId::named("not-hosted"),
            request: Box::new(WireRequest::NextNonce),
        };
        assert!(matches!(
            node.handle_request(unknown_group).await,
            Err(BlossomError::WireProtocol(message)) if message.contains("unknown consensus group")
        ));
    }
}
