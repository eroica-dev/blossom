use std::fmt;

use blossom::{
    BlossomError, EncodedFrame, EpochTarget, Result, SimulatedCluster, SimulatedNode,
    TcpNodeMetricsSnapshot, TrustMode, WireRequest, WireResponse, read_encoded_frame,
    read_wire_response, signed_block, write_encoded_frame, write_wire_request,
};
pub use deterministic_test_env::{CHAOS_RATE_DENOMINATOR, NetworkChaosConfig, NetworkChaosReport};
use deterministic_test_env::{NetworkChaos as GenericNetworkChaos, SimEnvError};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct NetworkChaos {
    inner: GenericNetworkChaos,
}

impl fmt::Debug for NetworkChaos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkChaos")
            .field("config", self.inner.config())
            .field("report", &self.report())
            .finish()
    }
}

impl NetworkChaos {
    pub fn new(config: NetworkChaosConfig) -> Result<Self> {
        Ok(Self {
            inner: GenericNetworkChaos::new(config).map_err(to_blossom_error)?,
        })
    }

    pub fn config(&self) -> &NetworkChaosConfig {
        self.inner.config()
    }

    pub fn report(&self) -> NetworkChaosReport {
        self.inner.report()
    }

    pub async fn request_with_ordinal(
        &self,
        node_index: usize,
        ordinal: u64,
        addr: impl AsRef<str>,
        request: &WireRequest,
    ) -> Result<WireResponse> {
        let sample = self.inner.sample_with_ordinal(node_index as u64, ordinal);
        self.request_with_sample(addr, request, sample).await
    }

    async fn request(
        &self,
        node_index: usize,
        addr: impl AsRef<str>,
        request: &WireRequest,
    ) -> Result<WireResponse> {
        let sample = self.inner.sample(node_index as u64);
        self.request_with_sample(addr, request, sample).await
    }

    async fn request_with_sample(
        &self,
        addr: impl AsRef<str>,
        request: &WireRequest,
        sample: deterministic_test_env::ChaosSample,
    ) -> Result<WireResponse> {
        self.inner
            .before_connect(&sample)
            .await
            .map_err(to_blossom_io)?;
        let mut stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        self.inner
            .after_connect(&sample)
            .await
            .map_err(to_blossom_io)?;
        write_wire_request(&mut stream, request).await?;
        self.inner
            .before_response(&sample)
            .await
            .map_err(to_blossom_io)?;
        let response = read_wire_response(&mut stream).await?;
        self.inner.record_success();
        Ok(response)
    }

    async fn request_frame(
        &self,
        node_index: usize,
        addr: impl AsRef<str>,
        frame: &EncodedFrame,
    ) -> Result<WireResponse> {
        let sample = self.inner.sample(node_index as u64);
        self.inner
            .before_connect(&sample)
            .await
            .map_err(to_blossom_io)?;
        let mut stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        self.inner
            .after_connect(&sample)
            .await
            .map_err(to_blossom_io)?;
        write_encoded_frame(&mut stream, frame).await?;
        self.inner
            .before_response(&sample)
            .await
            .map_err(to_blossom_io)?;
        let response = read_wire_response(&mut stream).await?;
        self.inner.record_success();
        Ok(response)
    }

    async fn request_raw_response_frame(
        &self,
        node_index: usize,
        addr: impl AsRef<str>,
        request: &WireRequest,
    ) -> Result<EncodedFrame> {
        let sample = self.inner.sample(node_index as u64);
        self.inner
            .before_connect(&sample)
            .await
            .map_err(to_blossom_io)?;
        let mut stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        self.inner
            .after_connect(&sample)
            .await
            .map_err(to_blossom_io)?;
        write_wire_request(&mut stream, request).await?;
        self.inner
            .before_response(&sample)
            .await
            .map_err(to_blossom_io)?;
        let frame = read_encoded_frame(&mut stream).await?;
        self.inner.record_success();
        Ok(frame)
    }
}

fn to_blossom_error(err: SimEnvError) -> BlossomError {
    BlossomError::WireProtocol(err.to_string())
}

fn to_blossom_io(err: SimEnvError) -> BlossomError {
    BlossomError::Io(err.to_string())
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

    pub fn node_metrics(&self) -> Vec<TcpNodeMetricsSnapshot> {
        self.cluster.node_metrics()
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
