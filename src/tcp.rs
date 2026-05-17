use tokio::net::{TcpListener, TcpStream};

use crate::address_book::ServiceKind;
use crate::error::{BlossomError, Result};
use crate::runtime::NodeRuntime;
use crate::service_client::TcpServiceClient;
use crate::wire::{
    AddressBookUpdate, NodeHealth, WireRequest, WireResponse, read_frame, write_frame,
};

#[derive(Clone)]
pub struct TcpNode {
    pub runtime: NodeRuntime,
    pub services: TcpServiceClient,
}

impl TcpNode {
    pub fn new(runtime: NodeRuntime) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
        }
    }

    pub fn with_services(runtime: NodeRuntime, services: TcpServiceClient) -> Self {
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
        let request = read_frame(&mut stream).await?;
        let response = match self.handle_request(request).await {
            Ok(response) => response,
            Err(err) => WireResponse::Error(err.to_string()),
        };
        write_frame(&mut stream, &response).await
    }

    pub async fn handle_request(&self, request: WireRequest) -> Result<WireResponse> {
        match request {
            WireRequest::Health => Ok(WireResponse::Health(NodeHealth {
                status: "ok".to_string(),
                public_key: self.runtime.self_node().public_key(),
            })),
            WireRequest::State => Ok(WireResponse::State(self.runtime.status()?)),
            WireRequest::AddressBook => Ok(WireResponse::AddressBook(self.runtime.address_book())),
            WireRequest::RegisterService(service) => {
                let previous = self.runtime.register_service(service.clone());
                let nonce_announced = if service.kind == ServiceKind::Block {
                    let target = self.runtime.next_epoch_target()?;
                    self.services.send_nonce(&service, target.nonce).await?;
                    Some(target.nonce)
                } else {
                    None
                };
                Ok(WireResponse::AddressBookUpdated(AddressBookUpdate {
                    service,
                    previous,
                    nonce_announced,
                }))
            }
            WireRequest::NextNonce => {
                Ok(WireResponse::NextNonce(self.runtime.next_epoch_target()?))
            }
            WireRequest::SubmitBlock(block) => Ok(WireResponse::BlockAccepted(
                self.runtime.submit_block(block)?,
            )),
            WireRequest::Dispatch { round } => Ok(WireResponse::Dispatch(
                self.runtime.dispatch_local_block(round)?,
            )),
            WireRequest::Message(message) => Ok(WireResponse::MessageReceipt(
                self.runtime.receive_message(message)?,
            )),
            WireRequest::SendNonce(_) | WireRequest::BlockNonce(_) => Ok(WireResponse::Ok),
            WireRequest::GetBlock(_) => Err(BlossomError::WireProtocol(
                "this node does not serve block-service block retrieval".to_string(),
            )),
            WireRequest::SendBlock(block) => {
                self.runtime.submit_block(block)?;
                Ok(WireResponse::Ok)
            }
        }
    }
}

pub async fn send_wire_request(
    addr: impl AsRef<str>,
    request: WireRequest,
) -> Result<WireResponse> {
    let mut stream = TcpStream::connect(addr.as_ref())
        .await
        .map_err(|err| BlossomError::Io(err.to_string()))?;
    write_frame(&mut stream, &request).await?;
    read_frame(&mut stream).await
}
