use tokio::net::TcpStream;

use crate::address_book::Service;
use crate::block::Block;
use crate::error::{BlossomError, Result};
use crate::nonce::Nonce;
use crate::wire::{WireRequest, WireResponse, read_frame, write_frame};

#[derive(Clone, Debug, Default)]
pub struct TcpServiceClient;

impl TcpServiceClient {
    pub fn new() -> Self {
        Self
    }

    pub async fn send_nonce(&self, service: &Service, nonce: Nonce) -> Result<()> {
        expect_ok(send(service, WireRequest::SendNonce(nonce)).await?)
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
    let mut stream = TcpStream::connect(service.socket_addr())
        .await
        .map_err(|err| BlossomError::ExternalService(err.to_string()))?;
    write_frame(&mut stream, &request).await?;
    read_frame(&mut stream).await
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
