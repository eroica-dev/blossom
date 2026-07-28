//! Standalone TCP node for local operation and integration testing.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;

use blossom::{
    AddressBook, BlossomError, ConsensusDriverConfig, NodeIdentity, NodeRuntime, PubKey,
    QuorumSize, Result as BlossomResult, RuntimeConfig, RuntimeSnapshotV1, SecKey, Service,
    TcpNode, TelemetryHandle, TrustMode,
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
    #[arg(long, env = "BLOSSOM_QUORUM_SIZE")]
    quorum_size: Option<QuorumSize>,
    #[arg(long, env = "BLOSSOM_TRUSTED", default_value_t = false)]
    trusted: bool,
    #[arg(long, value_name = "KIND:PUBKEY@HOST:PORT")]
    service: Vec<String>,
    #[arg(long, env = "BLOSSOM_BOOTSTRAP_SERVICES")]
    bootstrap_services: Option<PathBuf>,
    #[arg(long, env = "BLOSSOM_STATE_SNAPSHOT")]
    state_snapshot: Option<PathBuf>,
    #[arg(long, env = "BLOSSOM_BLOCK_STORE")]
    block_store: Option<PathBuf>,
    #[arg(long, env = "BLOSSOM_TRUSTED_EPOCH_LOG")]
    trusted_epoch_log: Option<PathBuf>,
    #[arg(
        long,
        env = "BLOSSOM_SYNC_BOOTSTRAP_ADDRESS_BOOKS",
        default_value_t = false
    )]
    sync_bootstrap_address_books: bool,
    #[arg(long, env = "BLOSSOM_OBSERVER_ADDR")]
    observer_addr: Option<String>,
    #[arg(long, env = "BLOSSOM_AUTO_CONSENSUS", default_value_t = false)]
    auto_consensus: bool,
    #[arg(
        long,
        env = "BLOSSOM_CONSENSUS_DRIVER_INTERVAL_MS",
        default_value_t = 25
    )]
    consensus_driver_interval_ms: u64,
    #[arg(long, env = "BLOSSOM_CONSENSUS_DRIVER_MAX_ROUND", default_value_t = 1)]
    consensus_driver_max_round: u8,
}

#[tokio::main]
async fn main() -> MainResult<()> {
    let args = Args::parse();
    #[cfg(feature = "eden-logger")]
    {
        eden_logger::init(eden_logger::WriterConfig::default());
        eden_logger::init_from_env();
    }
    let self_node = identity_from_args(&args)?;
    let loaded_snapshot = match args.state_snapshot.as_ref() {
        Some(path) if path.exists() => Some(RuntimeSnapshotV1::read_json(path)?),
        _ => None,
    };
    let restored_from_snapshot = loaded_snapshot.is_some();
    let mut config = match loaded_snapshot {
        Some(snapshot) => RuntimeConfig::from_snapshot_with_quorum_override(
            snapshot,
            self_node,
            args.quorum_size,
        )?,
        None => RuntimeConfig::new(self_node)
            .with_quorum_size(args.quorum_size.unwrap_or(QuorumSize::DEFAULT)),
    };
    config.snapshot_path = args.state_snapshot.clone();
    config.block_store_path = args.block_store.clone();
    config.trusted_epoch_log_path = args.trusted_epoch_log.clone();
    if !restored_from_snapshot {
        config.block_cap = args.block_cap;
    }
    if args.trusted && config.trust_mode != TrustMode::Trusted {
        config.trust_mode = TrustMode::Trusted;
    }
    if let Some(path) = args.bootstrap_services.as_ref() {
        let services = AddressBook::read_services_json(path)?;
        config.address_book.extend_services(services);
    }
    if args.sync_bootstrap_address_books {
        let bootstrap_services = config.address_book.clone().into_services();
        let client = blossom::TcpServiceClient::new();
        for service in bootstrap_services {
            match client.address_book(&service).await {
                Ok(services) => config.address_book.extend_services(services),
                Err(err) => eprintln!(
                    "bootstrap address-book sync failed for {}: {err}",
                    service.socket_addr()
                ),
            }
        }
    }
    let mut telemetry_sinks = Vec::<Arc<dyn blossom::TelemetrySink>>::new();
    #[cfg(feature = "telemetry")]
    let fast_telemetry_runtime =
        fast_telemetry::Runtime::new(fast_telemetry::RuntimeConfig::default());
    #[cfg(feature = "telemetry")]
    let fast_telemetry_registration =
        blossom::FastTelemetryRegistration::register(&fast_telemetry_runtime);
    #[cfg(feature = "telemetry")]
    telemetry_sinks.push(fast_telemetry_registration.sink());
    #[cfg(feature = "eden-logger")]
    telemetry_sinks.push(Arc::new(blossom::EdenLoggerTelemetrySink::new()));
    if let Some(addr) = args.observer_addr.as_ref() {
        telemetry_sinks.push(Arc::new(blossom::JsonlTcpTelemetrySink::connect(addr)?));
    }
    if !telemetry_sinks.is_empty() {
        config.telemetry =
            TelemetryHandle::new(Arc::new(blossom::FanoutTelemetrySink::new(telemetry_sinks)));
    }
    let runtime = NodeRuntime::try_new(config)?;
    runtime.emit_telemetry_event("service", "node_started", None);

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
    println!(
        "quorum branching factor: {}",
        node.runtime.consensus_parameters().quorum_size
    );
    if args.auto_consensus {
        let driver = ConsensusDriverConfig {
            interval: std::time::Duration::from_millis(args.consensus_driver_interval_ms),
            max_round: args.consensus_driver_max_round,
            ..ConsensusDriverConfig::default()
        };
        println!(
            "auto consensus driver enabled: interval={}ms max_round={}",
            args.consensus_driver_interval_ms, args.consensus_driver_max_round
        );
        node.serve_with_consensus_driver(listener, driver).await?;
    } else {
        node.serve(listener).await?;
    }
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
