use std::time::{Duration, Instant};

use crate::address_book::Service;
#[cfg(feature = "availability-gossip")]
use crate::availability::{
    AvailabilityGossip, AvailabilityReceipt, FilteredPayloadBatchDelivery,
    FilteredPayloadBatchFetch, FilteredPayloadDelivery, FilteredPayloadFetch,
};
use crate::block::Block;
use crate::error::{BlossomError, Result};
use crate::nonce::Nonce;
use crate::tcp::send_wire_request;
use crate::wire::{
    ApplicationRequest, ApplicationResponse, NodePing, NodePong, WireRequest, WireResponse,
};

#[derive(Clone, Debug, Default)]
pub struct TcpServiceClient;

#[derive(Clone, Debug)]
pub struct TimedNodePong {
    pub pong: NodePong,
    pub rtt: Duration,
}

impl TcpServiceClient {
    pub fn new() -> Self {
        Self
    }

    pub async fn send_nonce(&self, service: &Service, nonce: Nonce) -> Result<()> {
        expect_ok(send(service, WireRequest::SendNonce(nonce)).await?)
    }

    pub async fn ping(&self, service: &Service, ping: NodePing) -> Result<NodePong> {
        match send(service, WireRequest::Ping(ping)).await? {
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
        match send(service, WireRequest::Application(request)).await? {
            WireResponse::Application(response) => Ok(response),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected application response, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn address_book(&self, service: &Service) -> Result<Vec<Service>> {
        match send(service, WireRequest::AddressBook).await? {
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
        match send(service, WireRequest::AvailabilityGossip(gossip)).await? {
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
        match send(service, WireRequest::GetFilteredPayload(fetch)).await? {
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
        match send(service, WireRequest::GetFilteredPayloadBatch(fetch)).await? {
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
        match send(service, WireRequest::StoreFilteredPayload(delivery)).await? {
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
        match send(service, WireRequest::StoreFilteredPayloadBatch(delivery)).await? {
            WireResponse::AvailabilityReceipt(receipt) => Ok(receipt),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected availability receipt response, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn block_nonce(&self, service: &Service, nonce: Nonce) -> Result<()> {
        expect_ok(send(service, WireRequest::BlockNonce(nonce)).await?)
    }

    pub async fn get_block(&self, service: &Service, nonce: Nonce) -> Result<Block> {
        match send(service, WireRequest::GetBlock(nonce)).await? {
            WireResponse::Block(block) => Ok(block),
            WireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected block response, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn send_block(&self, service: &Service, block: &Block) -> Result<()> {
        expect_ok(send(service, WireRequest::SendBlock(block.clone())).await?)
    }
}

async fn send(service: &Service, request: WireRequest) -> Result<WireResponse> {
    send_wire_request(service.socket_addr(), request)
        .await
        .map_err(|err| BlossomError::ExternalService(err.to_string()))
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
