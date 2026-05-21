use std::io;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;

use blossom::{
    BlossomError, NodeIdentity, NodeRuntime, PubKey, Result as BlossomResult, RuntimeConfig,
    SecKey, Service, TcpNode, TelemetryHandle, TrustMode,
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
    #[arg(long, env = "BLOSSOM_TRUSTED", default_value_t = false)]
    trusted: bool,
    #[arg(long, value_name = "KIND:PUBKEY@HOST:PORT")]
    service: Vec<String>,
    #[arg(long, env = "BLOSSOM_OBSERVER_ADDR")]
    observer_addr: Option<String>,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    let self_node = identity_from_args(&args)?;
    let mut config = RuntimeConfig::new(self_node);
    config.block_cap = args.block_cap;
    if args.trusted {
        config.trust_mode = TrustMode::Trusted;
    }
    match args.observer_addr.as_ref() {
        Some(addr) => {
            config.telemetry =
                TelemetryHandle::new(Arc::new(blossom::JsonlTcpTelemetrySink::connect(addr)?));
        }
        None => {}
    }
    let runtime = NodeRuntime::new(config);

    for spec in &args.service {
        let service = parse_service_spec(spec, &args.protocol)
            .map_err(|err| invalid_input(err.to_string()))?;
        runtime.register_service(service);
    }

    let node = TcpNode::new(runtime);
    let bind = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&bind).await?;

    println!("blossom node listening on tcp://{bind}");
    println!("public key: {}", node.runtime.self_node().public_key());
    node.serve(listener).await?;
    Ok(())
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
