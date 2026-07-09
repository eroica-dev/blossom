use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use blossom::{
    BlossomError, EncodedFrame, NodePing, Result, WireRequest, WireResponse,
    configured_max_frame_size, read_wire_response,
};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::chaos::SimTcpCluster;
use crate::data::{DataPattern, DeterministicData, splitmix64};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzCaseKind {
    ValidPing,
    RandomPayload,
    ZeroLength,
    OversizedLength,
    TruncatedPayload,
    PartialPrefix,
}

impl FuzzCaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ValidPing => "valid_ping",
            Self::RandomPayload => "random_payload",
            Self::ZeroLength => "zero_length",
            Self::OversizedLength => "oversized_length",
            Self::TruncatedPayload => "truncated_payload",
            Self::PartialPrefix => "partial_prefix",
        }
    }

    fn deterministic(index: usize, include_valid: bool) -> Self {
        const MALFORMED: [FuzzCaseKind; 5] = [
            FuzzCaseKind::RandomPayload,
            FuzzCaseKind::ZeroLength,
            FuzzCaseKind::OversizedLength,
            FuzzCaseKind::TruncatedPayload,
            FuzzCaseKind::PartialPrefix,
        ];
        const ALL: [FuzzCaseKind; 6] = [
            FuzzCaseKind::ValidPing,
            FuzzCaseKind::RandomPayload,
            FuzzCaseKind::ZeroLength,
            FuzzCaseKind::OversizedLength,
            FuzzCaseKind::TruncatedPayload,
            FuzzCaseKind::PartialPrefix,
        ];
        if include_valid {
            ALL[index % ALL.len()]
        } else {
            MALFORMED[index % MALFORMED.len()]
        }
    }
}

impl fmt::Display for FuzzCaseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FuzzCaseKind {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "valid_ping" => Ok(Self::ValidPing),
            "random_payload" => Ok(Self::RandomPayload),
            "zero_length" => Ok(Self::ZeroLength),
            "oversized_length" => Ok(Self::OversizedLength),
            "truncated_payload" => Ok(Self::TruncatedPayload),
            "partial_prefix" => Ok(Self::PartialPrefix),
            _ => Err(format!(
                "unknown fuzz case {value}; expected valid_ping, random_payload, zero_length, oversized_length, truncated_payload, or partial_prefix"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzConfig {
    pub seed: u64,
    pub cases: usize,
    pub max_payload_bytes: usize,
    pub payload_pattern: DataPattern,
    pub include_valid: bool,
    pub read_timeout_ms: u64,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            seed: 0x6675_7a7a_5f62_6c31,
            cases: 256,
            max_payload_bytes: 4096,
            payload_pattern: DataPattern::SplitMix,
            include_valid: true,
            read_timeout_ms: 100,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FuzzReport {
    pub cases: usize,
    pub valid_cases: usize,
    pub malformed_cases: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub io_errors: usize,
    pub timeouts: usize,
    pub node_health_ok: bool,
    pub bytes_sent: usize,
}

pub async fn run_node_io_fuzz(cluster: &SimTcpCluster, config: &FuzzConfig) -> Result<FuzzReport> {
    let mut report = FuzzReport::default();
    let data = DeterministicData::new(config.seed, config.payload_pattern);

    for case_index in 0..config.cases {
        let node_index = case_index % cluster.len();
        let kind = FuzzCaseKind::deterministic(case_index, config.include_valid);
        let case = build_case(kind, case_index, config, &data)?;
        report.cases += 1;
        report.bytes_sent += case.bytes.len();
        if case.valid {
            report.valid_cases += 1;
        } else {
            report.malformed_cases += 1;
        }

        match send_case(
            cluster.node(node_index).addr(),
            &case,
            config.read_timeout_ms,
        )
        .await
        {
            FuzzOutcome::Accepted => report.accepted += 1,
            FuzzOutcome::Rejected => report.rejected += 1,
            FuzzOutcome::IoError => report.io_errors += 1,
            FuzzOutcome::Timeout => report.timeouts += 1,
        }
    }

    report.node_health_ok = matches!(
        cluster.request(0, WireRequest::Health).await,
        Ok(WireResponse::Health(_))
    );
    Ok(report)
}

#[derive(Debug, Clone)]
struct FuzzCase {
    bytes: Vec<u8>,
    valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FuzzOutcome {
    Accepted,
    Rejected,
    IoError,
    Timeout,
}

fn build_case(
    kind: FuzzCaseKind,
    case_index: usize,
    config: &FuzzConfig,
    data: &DeterministicData,
) -> Result<FuzzCase> {
    match kind {
        FuzzCaseKind::ValidPing => {
            let payload_len = deterministic_len(config.seed, case_index, config.max_payload_bytes);
            let payload = data.bytes(payload_len, 0, case_index as u64);
            let frame = EncodedFrame::encode_wire_request(&WireRequest::Ping(
                NodePing::with_payload(case_index as u64, payload),
            ))?;
            Ok(FuzzCase {
                bytes: frame.as_bytes().to_vec(),
                valid: true,
            })
        }
        FuzzCaseKind::RandomPayload => {
            let payload_len =
                deterministic_len(config.seed, case_index, config.max_payload_bytes).max(1);
            Ok(FuzzCase {
                bytes: framed(data.bytes(payload_len, 1, case_index as u64)),
                valid: false,
            })
        }
        FuzzCaseKind::ZeroLength => Ok(FuzzCase {
            bytes: 0u32.to_be_bytes().to_vec(),
            valid: false,
        }),
        FuzzCaseKind::OversizedLength => {
            let len = configured_max_frame_size().saturating_add(1);
            let len = u32::try_from(len).unwrap_or(u32::MAX);
            Ok(FuzzCase {
                bytes: len.to_be_bytes().to_vec(),
                valid: false,
            })
        }
        FuzzCaseKind::TruncatedPayload => {
            let payload_len =
                deterministic_len(config.seed, case_index, config.max_payload_bytes).max(2);
            let mut payload = data.bytes(payload_len, 2, case_index as u64);
            payload.truncate(payload_len / 2);
            let mut bytes = (payload_len as u32).to_be_bytes().to_vec();
            bytes.extend_from_slice(&payload);
            Ok(FuzzCase {
                bytes,
                valid: false,
            })
        }
        FuzzCaseKind::PartialPrefix => {
            let full = splitmix64(config.seed ^ case_index as u64).to_be_bytes();
            let take = (case_index % 3) + 1;
            Ok(FuzzCase {
                bytes: full[..take].to_vec(),
                valid: false,
            })
        }
    }
}

async fn send_case(addr: String, case: &FuzzCase, read_timeout_ms: u64) -> FuzzOutcome {
    let stream = match TcpStream::connect(addr).await {
        Ok(stream) => stream,
        Err(_) => return FuzzOutcome::IoError,
    };
    let mut stream = BufWriter::new(stream);
    if stream.write_all(&case.bytes).await.is_err() {
        return FuzzOutcome::IoError;
    }
    if stream.flush().await.is_err() {
        return FuzzOutcome::IoError;
    }
    if stream.shutdown().await.is_err() {
        return FuzzOutcome::IoError;
    }

    let mut stream = stream.into_inner();
    match timeout(
        Duration::from_millis(read_timeout_ms),
        read_wire_response(&mut stream),
    )
    .await
    {
        Ok(Ok(WireResponse::Pong(_))) if case.valid => FuzzOutcome::Accepted,
        Ok(Ok(WireResponse::Error(_))) => FuzzOutcome::Rejected,
        Ok(Ok(_)) => FuzzOutcome::Rejected,
        Ok(Err(BlossomError::Io(_))) => FuzzOutcome::IoError,
        Ok(Err(_)) => FuzzOutcome::Rejected,
        Err(_) => FuzzOutcome::Timeout,
    }
}

fn framed(payload: Vec<u8>) -> Vec<u8> {
    let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(&payload);
    bytes
}

fn deterministic_len(seed: u64, case_index: usize, max_payload_bytes: usize) -> usize {
    if max_payload_bytes == 0 {
        return 0;
    }
    (splitmix64(seed ^ case_index as u64) as usize % max_payload_bytes) + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaos::{NetworkChaosConfig, SimTcpCluster};

    #[tokio::test]
    async fn deterministic_fuzz_keeps_node_alive() {
        let cluster = SimTcpCluster::spawn(1, NetworkChaosConfig::default())
            .await
            .unwrap();
        let report = run_node_io_fuzz(
            &cluster,
            &FuzzConfig {
                seed: 11,
                cases: 24,
                max_payload_bytes: 128,
                payload_pattern: DataPattern::SplitMix,
                include_valid: true,
                read_timeout_ms: 100,
            },
        )
        .await
        .unwrap();

        assert_eq!(report.cases, 24);
        assert!(report.valid_cases > 0);
        assert!(report.malformed_cases > 0);
        assert!(report.accepted > 0);
        assert!(report.node_health_ok);
    }

    #[test]
    fn fuzz_case_sequence_is_reproducible() {
        let data = DeterministicData::new(5, DataPattern::Incrementing);
        let config = FuzzConfig {
            seed: 5,
            cases: 2,
            max_payload_bytes: 16,
            payload_pattern: DataPattern::Incrementing,
            include_valid: true,
            read_timeout_ms: 100,
        };

        let first = build_case(FuzzCaseKind::RandomPayload, 7, &config, &data)
            .unwrap()
            .bytes;
        let second = build_case(FuzzCaseKind::RandomPayload, 7, &config, &data)
            .unwrap()
            .bytes;

        assert_eq!(first, second);
    }
}
