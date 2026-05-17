use tokio::net::{TcpListener, TcpStream};

use crate::address_book::ServiceKind;
use crate::error::{BlossomError, Result};
use crate::runtime::NodeRuntime;
use crate::service_client::TcpServiceClient;
use crate::wire::{
    AddressBookUpdate, EncodedFrame, NodeHealth, WireRequest, WireRequestFrame, WireResponse,
    read_encoded_frame, read_wire_request_frame_optional, read_wire_response, write_encoded_frame,
    write_wire_request, write_wire_response,
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
            WireRequestFrame::HotDispatch(dispatch) => Ok(WireResponse::MessageReceipt(
                self.runtime.receive_hot_dispatch(dispatch)?,
            )),
        }
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

pub struct TcpConnection {
    stream: TcpStream,
}

impl TcpConnection {
    pub async fn connect(addr: impl AsRef<str>) -> Result<Self> {
        let stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
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
    use crate::node::NodeIdentity;
    use crate::runtime::RuntimeConfig;

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
            WireResponse::Health(health) => assert_eq!(health.public_key, keypair.public),
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
}
