//! Typed client operations over Blossom's bounded TCP wire surface.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::address_book::Service;
#[cfg(feature = "availability-gossip")]
use crate::availability::{
    AvailabilityGossip, AvailabilityReceipt, FilteredPayloadBatchDelivery,
    FilteredPayloadBatchFetch, FilteredPayloadDelivery, FilteredPayloadFetch,
};
use crate::block::Block;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::messages::Msg;
use crate::nonce::Nonce;
use crate::tcp::TcpConnection;
use crate::wire::{
    ApplicationRequest, ApplicationResponse, EncodedFrame, NodePing, NodePong, WireRequest,
    WireResponse, hot_wire_codec_enabled,
};

const CONNECT_ATTEMPTS: usize = 4;
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(10);
// Covers Blossom's default six-member committee without eviction while the
// tested 36-node in-process topology stays below a 1,024-descriptor limit.
const DEFAULT_MAX_POOLED_CONNECTIONS: usize = 6;

struct PooledTcpConnection {
    connection: Mutex<TcpConnection>,
    _slot: OwnedSemaphorePermit,
}

struct TcpServicePool {
    connections: Mutex<BTreeMap<String, Arc<PooledTcpConnection>>>,
    slots: Arc<Semaphore>,
    max_connections: usize,
}

#[derive(Clone)]
pub struct TcpServiceClient {
    pool: Arc<TcpServicePool>,
    group_id: Option<ConsensusGroupId>,
}

#[derive(Clone, Debug)]
pub struct TimedNodePong {
    pub pong: NodePong,
    pub rtt: Duration,
}

impl TcpServiceClient {
    /// Creates a client with Blossom's bounded default persistent pool.
    pub fn new() -> Self {
        Self::with_max_connections(
            NonZeroUsize::new(DEFAULT_MAX_POOLED_CONNECTIONS)
                .expect("the default TCP pool size is non-zero"),
        )
    }

    /// Creates a client with an explicit maximum number of live connections.
    ///
    /// Idle connections are evicted when the pool is full. If every pooled
    /// connection is active, new destinations wait for a slot instead of
    /// exhausting the process file-descriptor limit.
    pub fn with_max_connections(max_connections: NonZeroUsize) -> Self {
        let max_connections = max_connections.get();
        Self {
            pool: Arc::new(TcpServicePool {
                connections: Mutex::new(BTreeMap::new()),
                slots: Arc::new(Semaphore::new(max_connections)),
                max_connections,
            }),
            group_id: None,
        }
    }

    /// Routes ordinary requests through one group on a shared multi-group
    /// listener. Hot dispatch frames remain epoch-routed.
    pub fn for_group(mut self, group_id: ConsensusGroupId) -> Self {
        self.group_id = Some(group_id);
        self
    }

    /// Returns the maximum number of persistent connections owned by this pool.
    pub fn max_connections(&self) -> usize {
        self.pool.max_connections
    }

    pub async fn request(&self, service: &Service, request: &WireRequest) -> Result<WireResponse> {
        let frame = self.encode_request_frame(request)?;
        self.request_frame(service, &frame).await
    }

    /// Encodes a request with this client's shared-listener group routing.
    ///
    /// Hot dispatch remains unwrapped because the multi-group listener routes
    /// that specialized frame by its parent epoch. Every ordinary consensus
    /// message must retain the explicit group envelope, including frames that
    /// callers encode once before concurrent broadcast.
    pub(crate) fn encode_request_frame(&self, request: &WireRequest) -> Result<EncodedFrame> {
        if self.group_id.is_some()
            && hot_wire_codec_enabled()
            && matches!(request, WireRequest::Message(Msg::Dispatch(_)))
        {
            return EncodedFrame::encode_wire_request(request);
        }
        let Some(group_id) = self.group_id else {
            return EncodedFrame::encode_wire_request(request);
        };
        if matches!(request, WireRequest::Group { .. }) {
            return Err(BlossomError::WireProtocol(
                "a group-routed TCP client cannot wrap an already grouped request".to_string(),
            ));
        }
        EncodedFrame::encode_wire_request(&WireRequest::Group {
            group_id,
            request: Box::new(request.clone()),
        })
    }

    pub async fn request_frame(
        &self,
        service: &Service,
        frame: &EncodedFrame,
    ) -> Result<WireResponse> {
        let address = service.socket_addr();
        let connection = self.connection(&address).await?;
        let response = {
            let mut connection = connection.connection.lock().await;
            connection.request_frame(frame).await
        };
        match response {
            Ok(response) => Ok(response),
            Err(first_error) => {
                self.remove_connection(&address, &connection).await;
                drop(connection);
                let replacement = self.connection(&address).await?;
                let mut replacement = replacement.connection.lock().await;
                replacement.request_frame(frame).await.map_err(|second_error| {
                    BlossomError::ExternalService(format!(
                        "persistent request failed ({first_error}); reconnect failed ({second_error})"
                    ))
                })
            }
        }
    }

    async fn connection(&self, address: &str) -> Result<Arc<PooledTcpConnection>> {
        let mut last_error = None;
        for attempt in 0..CONNECT_ATTEMPTS {
            let permit = loop {
                let mut connections = self.pool.connections.lock().await;
                if let Some(connection) = connections.get(address).cloned() {
                    return Ok(connection);
                }
                match self.pool.slots.clone().try_acquire_owned() {
                    Ok(permit) => break permit,
                    Err(TryAcquireError::Closed) => {
                        return Err(BlossomError::Io(
                            "TCP service connection pool is closed".to_string(),
                        ));
                    }
                    Err(TryAcquireError::NoPermits) => {
                        let idle = connections.iter().find_map(|(address, connection)| {
                            (Arc::strong_count(connection) == 1).then(|| address.clone())
                        });
                        if let Some(idle) = idle {
                            connections.remove(&idle);
                            continue;
                        }
                    }
                }
                drop(connections);
                tokio::time::sleep(Duration::from_millis(1)).await;
            };
            match TcpConnection::connect(address).await {
                Ok(connection) => {
                    let connection = Arc::new(PooledTcpConnection {
                        connection: Mutex::new(connection),
                        _slot: permit,
                    });
                    let mut connections = self.pool.connections.lock().await;
                    return Ok(connections
                        .entry(address.to_string())
                        .or_insert_with(|| connection.clone())
                        .clone());
                }
                Err(error) => last_error = Some(error),
            }
            if attempt + 1 < CONNECT_ATTEMPTS {
                let multiplier = u32::try_from(attempt + 1).unwrap_or(u32::MAX);
                tokio::time::sleep(CONNECT_RETRY_DELAY.saturating_mul(multiplier)).await;
            }
        }
        Err(last_error.unwrap_or_else(|| {
            BlossomError::Io(format!(
                "failed to connect to {address} after {CONNECT_ATTEMPTS} attempts"
            ))
        }))
    }

    async fn remove_connection(&self, address: &str, failed: &Arc<PooledTcpConnection>) {
        let mut connections = self.pool.connections.lock().await;
        if connections
            .get(address)
            .is_some_and(|current| Arc::ptr_eq(current, failed))
        {
            connections.remove(address);
        }
    }

    pub async fn send_nonce(&self, service: &Service, nonce: Nonce) -> Result<()> {
        expect_ok(self.send(service, WireRequest::SendNonce(nonce)).await?)
    }

    pub async fn ping(&self, service: &Service, ping: NodePing) -> Result<NodePong> {
        match self.send(service, WireRequest::Ping(ping)).await? {
            WireResponse::Pong(pong) => Ok(pong),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected pong response, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn timed_ping(&self, service: &Service, ping: NodePing) -> Result<TimedNodePong> {
        let started = Instant::now();
        let pong = self.ping(service, ping).await?;
        Ok(TimedNodePong {
            pong,
            rtt: started.elapsed(),
        })
    }

    pub async fn application(
        &self,
        service: &Service,
        request: ApplicationRequest,
    ) -> Result<ApplicationResponse> {
        match self
            .send(service, WireRequest::Application(request))
            .await?
        {
            WireResponse::Application(response) => Ok(response),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected application response, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn address_book(&self, service: &Service) -> Result<Vec<Service>> {
        match self.send(service, WireRequest::AddressBook).await? {
            WireResponse::AddressBook(services) => Ok(services),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected address book response, got {}",
                response.kind()
            ))),
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub async fn send_availability_gossip(
        &self,
        service: &Service,
        gossip: AvailabilityGossip,
    ) -> Result<AvailabilityReceipt> {
        match self
            .send(service, WireRequest::AvailabilityGossip(gossip))
            .await?
        {
            WireResponse::AvailabilityReceipt(receipt) => Ok(receipt),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected availability receipt response, got {}",
                response.kind()
            ))),
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub async fn fetch_filtered_payload(
        &self,
        service: &Service,
        fetch: FilteredPayloadFetch,
    ) -> Result<Option<FilteredPayloadDelivery>> {
        match self
            .send(service, WireRequest::GetFilteredPayload(fetch))
            .await?
        {
            WireResponse::FilteredPayload(delivery) => Ok(Some(delivery)),
            WireResponse::FilteredPayloadMissing(_) => Ok(None),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected filtered payload response, got {}",
                response.kind()
            ))),
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub async fn fetch_filtered_payload_batch(
        &self,
        service: &Service,
        fetch: FilteredPayloadBatchFetch,
    ) -> Result<FilteredPayloadBatchDelivery> {
        match self
            .send(service, WireRequest::GetFilteredPayloadBatch(fetch))
            .await?
        {
            WireResponse::FilteredPayloadBatch(delivery) => Ok(delivery),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected filtered payload batch response, got {}",
                response.kind()
            ))),
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub async fn store_filtered_payload(
        &self,
        service: &Service,
        delivery: FilteredPayloadDelivery,
    ) -> Result<AvailabilityReceipt> {
        match self
            .send(service, WireRequest::StoreFilteredPayload(delivery))
            .await?
        {
            WireResponse::AvailabilityReceipt(receipt) => Ok(receipt),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected availability receipt response, got {}",
                response.kind()
            ))),
        }
    }

    #[cfg(feature = "availability-gossip")]
    pub async fn store_filtered_payload_batch(
        &self,
        service: &Service,
        delivery: FilteredPayloadBatchDelivery,
    ) -> Result<AvailabilityReceipt> {
        match self
            .send(service, WireRequest::StoreFilteredPayloadBatch(delivery))
            .await?
        {
            WireResponse::AvailabilityReceipt(receipt) => Ok(receipt),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected availability receipt response, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn block_nonce(&self, service: &Service, nonce: Nonce) -> Result<()> {
        expect_ok(self.send(service, WireRequest::BlockNonce(nonce)).await?)
    }

    pub async fn get_block(&self, service: &Service, nonce: Nonce) -> Result<Block> {
        match self.send(service, WireRequest::GetBlock(nonce)).await? {
            WireResponse::Block(block) => Ok(block),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected block response, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn send_block(&self, service: &Service, block: &Block) -> Result<()> {
        expect_ok(
            self.send(service, WireRequest::SendBlock(block.clone()))
                .await?,
        )
    }

    async fn send(&self, service: &Service, request: WireRequest) -> Result<WireResponse> {
        self.request(service, &request)
            .await
            .map_err(|err| BlossomError::ExternalService(err.to_string()))
    }
}

impl Default for TcpServiceClient {
    fn default() -> Self {
        Self::new()
    }
}

fn expect_ok(response: WireResponse) -> Result<()> {
    match response {
        WireResponse::Ok => Ok(()),
        WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
        response => Err(BlossomError::WireProtocol(format!(
            "expected ok response, got {}",
            response.kind()
        ))),
    }
}
