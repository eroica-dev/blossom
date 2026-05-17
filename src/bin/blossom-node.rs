use std::io;

use clap::Parser;
use tokio::net::{TcpListener, TcpStream};

use blossom::{
    AddressBookUpdate, BlossomError, NodeHealth, NodeIdentity, NodeRuntime, PubKey,
    Result as BlossomResult, RuntimeConfig, SecKey, Service, ServiceKind, TcpServiceClient,
    WireRequest, WireResponse, read_frame, write_frame,
};

type MainResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(name = "blossom-node", about = "Run a Blossom consensus node")]
struct Args {
    #[arg(long, env = "BLOSSOM_HOST", default_value = "127.0.0.1")]
    host: String,
    #[arg(long, env = "BLOSSOM_PORT", default_value_t = 8080)]
    port: u16,
    #[arg(long, env = "BLOSSOM_PROTOCOL", default_value = "tcp")]
    protocol: String,
    #[arg(long, env = "BLOSSOM_PUBLIC_KEY")]
    public_key: Option<String>,
    #[arg(long, env = "BLOSSOM_SECRET_KEY")]
    secret_key: Option<String>,
    #[arg(long, env = "BLOSSOM_BLOCK_CAP", default_value_t = 100)]
    block_cap: usize,
    #[arg(long, value_name = "KIND:PUBKEY@HOST:PORT")]
    service: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    runtime: NodeRuntime,
    services: TcpServiceClient,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let self_node = identity_from_args(&args)?;
    let mut config = RuntimeConfig::new(self_node);
    config.block_cap = args.block_cap;
    let runtime = NodeRuntime::new(config);

    for spec in &args.service {
        let service = parse_service_spec(spec, &args.protocol)
            .map_err(|err| invalid_input(err.to_string()))?;
        runtime.register_service(service);
    }

    let state = AppState {
        runtime,
        services: TcpServiceClient::new(),
    };
    let bind = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&bind).await?;

    println!("blossom node listening on tcp://{bind}");
    println!("public key: {}", state.runtime.self_node().public_key());

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state).await {
                log::error!("connection failed: {err}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream, state: AppState) -> BlossomResult<()> {
    let request = read_frame(&mut stream).await?;
    let response = match handle_request(state, request).await {
        Ok(response) => response,
        Err(err) => WireResponse::Error(err.to_string()),
    };
    write_frame(&mut stream, &response).await
}

async fn handle_request(state: AppState, request: WireRequest) -> BlossomResult<WireResponse> {
    match request {
        WireRequest::Health => Ok(WireResponse::Health(NodeHealth {
            status: "ok".to_string(),
            public_key: state.runtime.self_node().public_key(),
        })),
        WireRequest::State => Ok(WireResponse::State(state.runtime.status()?)),
        WireRequest::AddressBook => Ok(WireResponse::AddressBook(state.runtime.address_book())),
        WireRequest::RegisterService(service) => {
            let previous = state.runtime.register_service(service.clone());
            let nonce_announced = if service.kind == ServiceKind::Block {
                let target = state.runtime.next_epoch_target()?;
                state.services.send_nonce(&service, target.nonce).await?;
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
        WireRequest::NextNonce => Ok(WireResponse::NextNonce(state.runtime.next_epoch_target()?)),
        WireRequest::SubmitBlock(block) => Ok(WireResponse::BlockAccepted(
            state.runtime.submit_block(block)?,
        )),
        WireRequest::Dispatch { round } => Ok(WireResponse::Dispatch(
            state.runtime.dispatch_local_block(round)?,
        )),
        WireRequest::Message(message) => Ok(WireResponse::MessageReceipt(
            state.runtime.receive_message(message)?,
        )),
        WireRequest::SendNonce(_) | WireRequest::BlockNonce(_) => Ok(WireResponse::Ok),
        WireRequest::GetBlock(_) => Err(BlossomError::WireProtocol(
            "this node does not serve block-service block retrieval".to_string(),
        )),
        WireRequest::SendBlock(block) => {
            state.runtime.submit_block(block)?;
            Ok(WireResponse::Ok)
        }
    }
}

fn identity_from_args(args: &Args) -> MainResult<NodeIdentity> {
    match (&args.public_key, &args.secret_key) {
        (Some(public_key), Some(secret_key)) => Ok(NodeIdentity::new(
            PubKey::try_from(public_key.as_str())?,
            Some(SecKey::try_from(secret_key.as_str())?),
            args.protocol.clone(),
            args.host.clone(),
            args.port,
            true,
        )),
        (None, None) => Ok(NodeIdentity::generate(
            args.protocol.clone(),
            args.host.clone(),
            args.port,
        )),
        _ => Err(invalid_input(
            "provide both BLOSSOM_PUBLIC_KEY and BLOSSOM_SECRET_KEY, or neither",
        )
        .into()),
    }
}

fn parse_service_spec(spec: &str, default_protocol: &str) -> BlossomResult<Service> {
    let (kind, rest) = spec
        .split_once(':')
        .ok_or_else(|| BlossomError::UnknownService(spec.to_string()))?;
    let (public_key, endpoint) = rest
        .split_once('@')
        .ok_or_else(|| BlossomError::UnknownService(spec.to_string()))?;
    let (protocol, host_port) = endpoint
        .split_once("://")
        .map_or((default_protocol, endpoint), |(protocol, host_port)| {
            (protocol, host_port)
        });
    let (host, port) = host_port
        .rsplit_once(':')
        .ok_or_else(|| BlossomError::UnknownService(spec.to_string()))?;

    Ok(Service::new(
        kind.parse()?,
        PubKey::try_from(public_key)?,
        protocol,
        host,
        port.parse()
            .map_err(|_| BlossomError::UnknownService(spec.to_string()))?,
    ))
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
