use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::address_book::Service;
#[cfg(feature = "availability-gossip")]
use crate::availability::{
    AvailabilityGossip, AvailabilityReceipt, FilteredPayloadBatchDelivery,
    FilteredPayloadBatchFetch, FilteredPayloadDelivery, FilteredPayloadFetch,
};
use crate::block::Block;
use crate::error::{BlossomError, Result};
use crate::nonce::Nonce;
use crate::tcp::TcpConnection;
use crate::wire::{
    ApplicationRequest, ApplicationResponse, EncodedFrame, NodePing, NodePong, WireRequest,
    WireResponse,
};

#[derive(Clone, Default)]
pub struct TcpServiceClient {
    connections: Arc<Mutex<BTreeMap<String, Arc<Mutex<TcpConnection>>>>>,
}

#[derive(Clone, Debug)]
pub struct TimedNodePong {
    pub pong: NodePong,
    pub rtt: Duration,
}

impl TcpServiceClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn request(&self, service: &Service, request: &WireRequest) -> Result<WireResponse> {
        let frame = EncodedFrame::encode_wire_request(request)?;
        self.request_frame(service, &frame).await
    }

    pub async fn request_frame(
        &self,
        service: &Service,
        frame: &EncodedFrame,
    ) -> Result<WireResponse> {
        let address = service.socket_addr();
        let connection = self.connection(&address).await?;
        let response = {
            let mut connection = connection.lock().await;
            connection.request_frame(frame).await
        };
        match response {
            Ok(response) => Ok(response),
            Err(first_error) => {
                self.remove_connection(&address, &connection).await;
                let replacement = self.connection(&address).await?;
                let mut replacement = replacement.lock().await;
                replacement.request_frame(frame).await.map_err(|second_error| {
                    BlossomError::ExternalService(format!(
                        "persistent request failed ({first_error}); reconnect failed ({second_error})"
                    ))
                })
            }
        }
    }

    async fn connection(&self, address: &str) -> Result<Arc<Mutex<TcpConnection>>> {
        if let Some(connection) = self.connections.lock().await.get(address).cloned() {
            return Ok(connection);
        }
        let connection = Arc::new(Mutex::new(TcpConnection::connect(address).await?));
        let mut connections = self.connections.lock().await;
        Ok(connections
            .entry(address.to_string())
            .or_insert_with(|| connection.clone())
            .clone())
    }

    async fn remove_connection(&self, address: &str, failed: &Arc<Mutex<TcpConnection>>) {
        let mut connections = self.connections.lock().await;
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
