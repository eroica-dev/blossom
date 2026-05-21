use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use blossom::{
    BlossomError, EncodedFrame, EpochTarget, Result, SimulatedCluster, SimulatedNode, TrustMode,
    WireRequest, WireResponse, read_encoded_frame, read_wire_response, signed_block,
    write_encoded_frame, write_wire_request,
};
use tokio::net::TcpStream;
use tokio::time::sleep;

pub const CHAOS_RATE_DENOMINATOR: u32 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkChaosConfig {
    pub seed: u64,
    pub latency_ms: u64,
    pub jitter_ms: u64,
    pub drop_ppm: u32,
    pub connect_crash_ppm: u32,
    pub response_crash_ppm: u32,
}

impl Default for NetworkChaosConfig {
    fn default() -> Self {
        Self {
            seed: 0x626c_6f73_736f_6d31,
            latency_ms: 0,
            jitter_ms: 0,
            drop_ppm: 0,
            connect_crash_ppm: 0,
            response_crash_ppm: 0,
        }
    }
}

impl NetworkChaosConfig {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn is_enabled(&self) -> bool {
        self.latency_ms > 0
            || self.jitter_ms > 0
            || self.drop_ppm > 0
            || self.connect_crash_ppm > 0
            || self.response_crash_ppm > 0
    }

    pub fn validate(&self) -> Result<()> {
        for (label, value) in [
            ("drop_ppm", self.drop_ppm),
            ("connect_crash_ppm", self.connect_crash_ppm),
            ("response_crash_ppm", self.response_crash_ppm),
        ] {
            if value > CHAOS_RATE_DENOMINATOR {
                return Err(BlossomError::WireProtocol(format!(
                    "{label} must be <= {CHAOS_RATE_DENOMINATOR}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkChaosReport {
    pub attempts: u64,
    pub successes: u64,
    pub dropped: u64,
    pub connect_crashes: u64,
    pub response_crashes: u64,
    pub injected_delay_ms: u64,
}

#[derive(Clone)]
pub struct NetworkChaos {
    inner: Arc<NetworkChaosInner>,
}

struct NetworkChaosInner {
    config: NetworkChaosConfig,
    sequence: AtomicU64,
    attempts: AtomicU64,
    successes: AtomicU64,
    dropped: AtomicU64,
    connect_crashes: AtomicU64,
    response_crashes: AtomicU64,
    injected_delay_ms: AtomicU64,
}

impl fmt::Debug for NetworkChaos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkChaos")
            .field("config", &self.inner.config)
            .field("report", &self.report())
            .finish()
    }
}

impl NetworkChaos {
    pub fn new(config: NetworkChaosConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(NetworkChaosInner {
                config,
                sequence: AtomicU64::new(0),
                attempts: AtomicU64::new(0),
                successes: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                connect_crashes: AtomicU64::new(0),
                response_crashes: AtomicU64::new(0),
                injected_delay_ms: AtomicU64::new(0),
            }),
        })
    }

    pub fn config(&self) -> &NetworkChaosConfig {
        &self.inner.config
    }

    pub fn report(&self) -> NetworkChaosReport {
        NetworkChaosReport {
            attempts: self.inner.attempts.load(Ordering::Relaxed),
            successes: self.inner.successes.load(Ordering::Relaxed),
            dropped: self.inner.dropped.load(Ordering::Relaxed),
            connect_crashes: self.inner.connect_crashes.load(Ordering::Relaxed),
            response_crashes: self.inner.response_crashes.load(Ordering::Relaxed),
            injected_delay_ms: self.inner.injected_delay_ms.load(Ordering::Relaxed),
        }
    }

    async fn request(
        &self,
        node_index: usize,
        addr: impl AsRef<str>,
        request: &WireRequest,
    ) -> Result<WireResponse> {
        let sample = self.sample(node_index as u64);
        self.before_connect(&sample).await?;
        let mut stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        self.after_connect(&sample).await?;
        write_wire_request(&mut stream, request).await?;
        self.before_response(&sample).await?;
        let response = read_wire_response(&mut stream).await?;
        self.inner.successes.fetch_add(1, Ordering::Relaxed);
        Ok(response)
    }

    async fn request_frame(
        &self,
        node_index: usize,
        addr: impl AsRef<str>,
        frame: &EncodedFrame,
    ) -> Result<WireResponse> {
        let sample = self.sample(node_index as u64);
        self.before_connect(&sample).await?;
        let mut stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        self.after_connect(&sample).await?;
        write_encoded_frame(&mut stream, frame).await?;
        self.before_response(&sample).await?;
        let response = read_wire_response(&mut stream).await?;
        self.inner.successes.fetch_add(1, Ordering::Relaxed);
        Ok(response)
    }

    async fn request_raw_response_frame(
        &self,
        node_index: usize,
        addr: impl AsRef<str>,
        request: &WireRequest,
    ) -> Result<EncodedFrame> {
        let sample = self.sample(node_index as u64);
        self.before_connect(&sample).await?;
        let mut stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        self.after_connect(&sample).await?;
        write_wire_request(&mut stream, request).await?;
        self.before_response(&sample).await?;
        let frame = read_encoded_frame(&mut stream).await?;
        self.inner.successes.fetch_add(1, Ordering::Relaxed);
        Ok(frame)
    }

    fn sample(&self, node_index: u64) -> ChaosSample {
        let sequence = self.inner.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        self.inner.attempts.fetch_add(1, Ordering::Relaxed);
        let seed = self.inner.config.seed ^ sequence.rotate_left(17) ^ node_index.rotate_left(37);
        ChaosSample {
            request_delay_ms: self.delay_ms(seed, 0x11),
            response_delay_ms: self.delay_ms(seed, 0x22),
            drop: self.sample_rate(seed, 0x33, self.inner.config.drop_ppm),
            connect_crash: self.sample_rate(seed, 0x44, self.inner.config.connect_crash_ppm),
            response_crash: self.sample_rate(seed, 0x55, self.inner.config.response_crash_ppm),
        }
    }

    fn delay_ms(&self, seed: u64, salt: u64) -> u64 {
        let jitter = if self.inner.config.jitter_ms == 0 {
            0
        } else {
            splitmix64(seed ^ salt) % (self.inner.config.jitter_ms + 1)
        };
        self.inner.config.latency_ms + jitter
    }

    fn sample_rate(&self, seed: u64, salt: u64, ppm: u32) -> bool {
        ppm > 0 && (splitmix64(seed ^ salt) % CHAOS_RATE_DENOMINATOR as u64) < ppm as u64
    }

    async fn before_connect(&self, sample: &ChaosSample) -> Result<()> {
        if sample.drop {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            return Err(BlossomError::Io(
                "simulated network drop before TCP connect".to_string(),
            ));
        }
        self.sleep_ms(sample.request_delay_ms).await;
        Ok(())
    }

    async fn after_connect(&self, sample: &ChaosSample) -> Result<()> {
        if sample.connect_crash {
            self.inner.connect_crashes.fetch_add(1, Ordering::Relaxed);
            return Err(BlossomError::Io(
                "simulated TCP connection crash before request write".to_string(),
            ));
        }
        Ok(())
    }

    async fn before_response(&self, sample: &ChaosSample) -> Result<()> {
        if sample.response_crash {
            self.inner.response_crashes.fetch_add(1, Ordering::Relaxed);
            return Err(BlossomError::Io(
                "simulated TCP connection crash before response read".to_string(),
            ));
        }
        self.sleep_ms(sample.response_delay_ms).await;
        Ok(())
    }

    async fn sleep_ms(&self, ms: u64) {
        if ms == 0 {
            return;
        }
        self.inner
            .injected_delay_ms
            .fetch_add(ms, Ordering::Relaxed);
        sleep(Duration::from_millis(ms)).await;
    }
}

struct ChaosSample {
    request_delay_ms: u64,
    response_delay_ms: u64,
    drop: bool,
    connect_crash: bool,
    response_crash: bool,
}

pub struct SimTcpCluster {
    cluster: SimulatedCluster,
    network: NetworkChaos,
}

impl SimTcpCluster {
    pub async fn spawn(count: usize, network: NetworkChaosConfig) -> Result<Self> {
        Self::spawn_with_trust_mode(count, blossom::TrustMode::Verified, network).await
    }

    pub async fn spawn_trusted(count: usize, network: NetworkChaosConfig) -> Result<Self> {
        Self::spawn_with_trust_mode(count, blossom::TrustMode::Trusted, network).await
    }

    pub async fn spawn_with_trust_mode(
        count: usize,
        trust_mode: TrustMode,
        network: NetworkChaosConfig,
    ) -> Result<Self> {
        Ok(Self {
            cluster: SimulatedCluster::spawn_with_trust_mode(count, trust_mode).await?,
            network: NetworkChaos::new(network)?,
        })
    }

    pub fn inner(&self) -> &SimulatedCluster {
        &self.cluster
    }

    pub fn nodes(&self) -> &[SimulatedNode] {
        self.cluster.nodes()
    }

    pub fn node(&self, index: usize) -> &SimulatedNode {
        self.cluster.node(index)
    }

    pub fn len(&self) -> usize {
        self.cluster.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cluster.is_empty()
    }

    pub fn network(&self) -> &NetworkChaos {
        &self.network
    }

    pub fn network_report(&self) -> NetworkChaosReport {
        self.network.report()
    }

    pub async fn request(&self, index: usize, request: WireRequest) -> Result<WireResponse> {
        self.network
            .request(index, self.cluster.node(index).addr(), &request)
            .await
    }

    pub async fn request_frame(&self, index: usize, frame: &EncodedFrame) -> Result<WireResponse> {
        self.network
            .request_frame(index, self.cluster.node(index).addr(), frame)
            .await
    }

    pub async fn request_raw_response_frame(
        &self,
        index: usize,
        request: WireRequest,
    ) -> Result<EncodedFrame> {
        self.network
            .request_raw_response_frame(index, self.cluster.node(index).addr(), &request)
            .await
    }

    pub async fn next_target(&self, index: usize) -> Result<EpochTarget> {
        match self.request(index, WireRequest::NextNonce).await? {
            WireResponse::NextNonce(target) => Ok(target),
            response => Err(BlossomError::WireProtocol(format!(
                "expected next nonce, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn signed_block_for(
        &self,
        target_node: usize,
        signer: usize,
        txs: impl IntoIterator<Item = blossom::Transaction>,
    ) -> Result<blossom::Block> {
        let target = self.next_target(target_node).await?;
        Ok(signed_block(
            target,
            self.cluster.node(signer).keypair.secret,
            txs,
        ))
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = value;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blossom::{NodePing, WireRequest, WireResponse};

    #[tokio::test]
    async fn sim_tcp_cluster_counts_successful_delayed_requests() {
        let cluster = SimTcpCluster::spawn(
            1,
            NetworkChaosConfig {
                latency_ms: 1,
                ..NetworkChaosConfig::default()
            },
        )
        .await
        .unwrap();

        let response = cluster.request(0, WireRequest::Health).await.unwrap();
        assert!(matches!(response, WireResponse::Health(_)));

        let report = cluster.network_report();
        assert_eq!(report.attempts, 1);
        assert_eq!(report.successes, 1);
        assert_eq!(report.dropped, 0);
        assert!(report.injected_delay_ms >= 2);
    }

    #[tokio::test]
    async fn sim_tcp_cluster_can_drop_before_connecting() {
        let cluster = SimTcpCluster::spawn(
            1,
            NetworkChaosConfig {
                drop_ppm: CHAOS_RATE_DENOMINATOR,
                ..NetworkChaosConfig::default()
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            cluster.request(0, WireRequest::Health).await,
            Err(BlossomError::Io(message)) if message.contains("simulated network drop")
        ));

        let report = cluster.network_report();
        assert_eq!(report.attempts, 1);
        assert_eq!(report.successes, 0);
        assert_eq!(report.dropped, 1);
    }

    #[tokio::test]
    async fn sim_tcp_cluster_can_crash_connections() {
        let cluster = SimTcpCluster::spawn(
            1,
            NetworkChaosConfig {
                connect_crash_ppm: CHAOS_RATE_DENOMINATOR,
                ..NetworkChaosConfig::default()
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            cluster.request(0, WireRequest::Ping(NodePing::new(7))).await,
            Err(BlossomError::Io(message)) if message.contains("connection crash")
        ));

        let report = cluster.network_report();
        assert_eq!(report.attempts, 1);
        assert_eq!(report.successes, 0);
        assert_eq!(report.connect_crashes, 1);
    }

    #[test]
    fn network_chaos_rejects_invalid_rates() {
        assert!(matches!(
            NetworkChaos::new(NetworkChaosConfig {
                drop_ppm: CHAOS_RATE_DENOMINATOR + 1,
                ..NetworkChaosConfig::default()
            }),
            Err(BlossomError::WireProtocol(_))
        ));
    }
}
