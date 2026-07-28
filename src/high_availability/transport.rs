//! Authenticated HA TCP sessions, bounded requests, and broadcast assessment.

use super::*;

/// Time and concurrency bounds applied by the authenticated HA TCP transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HaNetworkLimits {
    /// Maximum time allowed to establish and authenticate a peer connection.
    pub connect_timeout: Duration,
    /// Maximum time allowed for an individual request or response operation.
    pub request_timeout: Duration,
    /// Maximum time an authenticated connection may wait for its next request.
    pub idle_timeout: Duration,
    /// Maximum number of inbound connections served concurrently.
    pub max_connections: usize,
}

impl Default for HaNetworkLimits {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_HA_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_HA_REQUEST_TIMEOUT,
            idle_timeout: DEFAULT_HA_IDLE_TIMEOUT,
            max_connections: DEFAULT_HA_MAX_CONNECTIONS,
        }
    }
}

impl HaNetworkLimits {
    /// Rejects zero-valued timeouts and connection limits.
    pub fn validate(self) -> Result<()> {
        if self.connect_timeout.is_zero()
            || self.request_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.max_connections == 0
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA network timeouts and connection limits must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

async fn ha_timeout<T>(
    duration: Duration,
    operation: &'static str,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    timeout(duration, future)
        .await
        .map_err(|_| BlossomError::ExternalService(format!("HA transport {operation} timed out")))?
}

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
/// Stable client identifier used to deduplicate HA application commands.
pub struct ClientId(pub [u8; 16]);

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
/// Client incarnation used to fence commands from an earlier process lifetime.
pub struct ClientEpoch(pub u64);

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
/// Globally unique identity of an HA application command.
pub struct CommandIdentity {
    /// Stable identity of the command producer.
    pub client_id: ClientId,
    /// Producer incarnation that issued the command.
    pub client_epoch: ClientEpoch,
    /// Monotonic sequence number within the client incarnation.
    pub sequence: u64,
}

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
)]
/// Application progress committed by an HA epoch.
pub struct Watermark {
    /// Highest application position covered by the watermark.
    pub position: u64,
}

/// Shared secret used to authenticate and integrity-protect the isolated HA
/// transport profile.
///
/// HA protocol messages remain unsigned. The transport key instead creates a
/// mutually authenticated session for fixed genesis members and authenticates
/// every request and response frame. Operators should still use TLS when
/// confidentiality is required.
#[derive(Clone, PartialEq, Eq)]
pub struct HaTransportKey([u8; HA_TRANSPORT_KEY_BYTES]);

impl HaTransportKey {
    /// Wraps exactly 32 bytes of transport signing material.
    pub fn new(bytes: [u8; HA_TRANSPORT_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Generates a transport key with the operating system random source.
    pub fn generate() -> Self {
        let mut bytes = [0u8; HA_TRANSPORT_KEY_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Decodes a transport key from its 64-character hexadecimal form.
    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).map_err(|_| BlossomError::InvalidHex)?;
        let actual = bytes.len();
        let bytes: [u8; HA_TRANSPORT_KEY_BYTES] =
            bytes.try_into().map_err(|_| BlossomError::InvalidLength {
                expected: HA_TRANSPORT_KEY_BYTES,
                actual,
            })?;
        Ok(Self(bytes))
    }

    /// Loads the transport key from [`BLOSSOM_HA_TRANSPORT_KEY_ENV`].
    pub fn from_environment() -> Result<Self> {
        let value = env::var(BLOSSOM_HA_TRANSPORT_KEY_ENV).map_err(|_| {
            BlossomError::InvalidConfiguration(format!(
                "{BLOSSOM_HA_TRANSPORT_KEY_ENV} must contain a 32-byte hex key"
            ))
        })?;
        Self::from_hex(&value)
    }

    /// Returns the hexadecimal representation for explicit secret provisioning.
    ///
    /// The returned string contains secret material and must not be logged or
    /// placed in durable Blossom state.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn as_bytes(&self) -> &[u8; HA_TRANSPORT_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for HaTransportKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HaTransportKey([REDACTED])")
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportHelloBody {
    version: u16,
    group_id: ConsensusGroupId,
    fixed_membership_hash: HashType,
    parameters_hash: HashType,
    client: PubKey,
    server: PubKey,
    client_nonce: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportHello {
    body: HaTransportHelloBody,
    pub(super) mac: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportChallengeBody {
    hello: HaTransportHelloBody,
    server_nonce: [u8; HA_TRANSPORT_KEY_BYTES],
    pub(super) session_id: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportChallenge {
    body: HaTransportChallengeBody,
    pub(super) mac: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportSessionSeed {
    hello: HaTransportHelloBody,
    server_nonce: [u8; HA_TRANSPORT_KEY_BYTES],
}

/// Request envelope for the isolated HA transport.
///
/// This deliberately does not reuse [`crate::wire::WireRequest`], so enabling
/// HA cannot change the discriminants or compatibility profile of Blossom's
/// existing verified and trusted wire protocol.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum HaWireRequest {
    /// Submits one HA protocol message.
    Message(Box<HaMessage>),
    /// Requests the peer's validated runtime status.
    Status,
    /// Reserved health request for transport-version compatibility.
    Health,
}

/// Response envelope for the isolated HA transport.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum HaWireResponse {
    /// Acknowledges an accepted HA protocol message.
    Receipt(HaWireReceipt),
    /// Returns the peer's current runtime status.
    Status(Box<HaNodeStatus>),
    /// Reports a request validation or processing failure.
    Error(String),
}

impl HaWireResponse {
    /// Returns the stable diagnostic name of this response variant.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Receipt(_) => "high_availability_receipt",
            Self::Status(_) => "high_availability_status",
            Self::Error(_) => "error",
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub(super) struct HaAuthenticatedRequestBody {
    pub(super) session_id: [u8; HA_TRANSPORT_KEY_BYTES],
    pub(super) sequence: u64,
    pub(super) request: HaWireRequest,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub(super) struct HaAuthenticatedRequest {
    pub(super) body: HaAuthenticatedRequestBody,
    pub(super) mac: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub(super) struct HaAuthenticatedResponseBody {
    pub(super) session_id: [u8; HA_TRANSPORT_KEY_BYTES],
    pub(super) sequence: u64,
    response: HaWireResponse,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub(super) struct HaAuthenticatedResponse {
    pub(super) body: HaAuthenticatedResponseBody,
    pub(super) mac: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(Clone)]
pub(super) struct HaTransportContext {
    local_key: PubKey,
    group_id: ConsensusGroupId,
    fixed_membership_hash: HashType,
    parameters_hash: HashType,
    members: BTreeSet<PubKey>,
}

impl HaTransportContext {
    pub(super) fn from_runtime(runtime: &HighAvailabilityRuntime) -> Self {
        let members = (0..runtime.members().member_count())
            .filter_map(|index| runtime.members().member(HaMemberSlot(index as u8)))
            .map(NodeIdentity::public_key)
            .collect();
        let local_key = runtime
            .members()
            .member(runtime.self_slot())
            .expect("validated HA self slot")
            .public_key();
        Self {
            local_key,
            group_id: runtime.state.group_id,
            fixed_membership_hash: runtime.members().fixed_identity_hash(),
            parameters_hash: runtime.parameters_hash(),
            members,
        }
    }

    fn validate_peer(&self, peer: PubKey) -> Result<()> {
        if !self.members.contains(&peer) || peer == self.local_key {
            return Err(BlossomError::UnknownSender);
        }
        Ok(())
    }
}

pub(super) fn ha_transport_mac<T: BorshSerialize>(
    key: &[u8],
    domain: &[u8],
    value: &T,
) -> Result<[u8; HA_TRANSPORT_KEY_BYTES]> {
    let encoded = borsh::to_vec(value).map_err(|error| {
        BlossomError::WireProtocol(format!("encode HA transport transcript: {error}"))
    })?;
    let mut mac = HaHmacSha256::new_from_slice(key)
        .map_err(|_| BlossomError::InvalidConfiguration("invalid HA transport key".to_string()))?;
    mac.update(domain);
    mac.update(&(encoded.len() as u64).to_le_bytes());
    mac.update(&encoded);
    Ok(mac.finalize().into_bytes().into())
}

pub(super) fn verify_ha_transport_mac<T: BorshSerialize>(
    key: &[u8],
    domain: &[u8],
    value: &T,
    expected: &[u8; HA_TRANSPORT_KEY_BYTES],
) -> Result<()> {
    let encoded = borsh::to_vec(value).map_err(|error| {
        BlossomError::WireProtocol(format!("encode HA transport transcript: {error}"))
    })?;
    let mut mac = HaHmacSha256::new_from_slice(key)
        .map_err(|_| BlossomError::InvalidConfiguration("invalid HA transport key".to_string()))?;
    mac.update(domain);
    mac.update(&(encoded.len() as u64).to_le_bytes());
    mac.update(&encoded);
    mac.verify_slice(expected)
        .map_err(|_| BlossomError::WireProtocol("HA transport authentication failed".to_string()))
}

fn derive_ha_session_key(
    key: &HaTransportKey,
    challenge: &HaTransportChallengeBody,
) -> Result<[u8; HA_TRANSPORT_KEY_BYTES]> {
    ha_transport_mac(key.as_bytes(), HA_TRANSPORT_SESSION_DOMAIN, challenge)
}

#[derive(Debug, Clone)]
/// Observable effect produced while processing an authenticated HA message.
pub enum HaRuntimeEvent {
    /// A peer handshake was accepted.
    HandshakeAccepted,
    /// A membership vote was accepted but did not yet form a certificate.
    MembershipVoteAccepted,
    /// A membership certificate changed the active member set.
    MembershipChanged(HaMembershipCertificate),
    /// A dispatch was admitted, deduplicated, or rejected as late.
    Dispatch(HaDispatchOutcome),
    /// An acknowledgement was accepted.
    Acknowledged,
    /// A confirmation was accepted without locally finalizing an epoch.
    Confirmed,
    /// The message completed and finalized the enclosed epoch.
    Finalized(Box<HaEpoch>),
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Compact transport acknowledgement for an accepted HA runtime event.
pub struct HaWireReceipt {
    /// Stable event name suitable for metrics and diagnostics.
    pub kind: String,
    /// Finalized epoch hash when the event completed an epoch.
    pub finalized_epoch_hash: Option<HashType>,
    /// Runtime nonce observed after processing the message.
    pub nonce: Nonce,
}

impl HaWireReceipt {
    fn from_event(event: &HaRuntimeEvent, nonce: Nonce) -> Self {
        match event {
            HaRuntimeEvent::HandshakeAccepted => Self {
                kind: "handshake_accepted".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::MembershipVoteAccepted => Self {
                kind: "membership_vote_accepted".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::MembershipChanged(_) => Self {
                kind: "membership_changed".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::Dispatch(outcome) => Self {
                kind: match outcome {
                    HaDispatchOutcome::Accepted => "dispatch_accepted",
                    HaDispatchOutcome::Duplicate => "dispatch_duplicate",
                    HaDispatchOutcome::Late { .. } => "dispatch_late",
                }
                .to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::Acknowledged => Self {
                kind: "acknowledged".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::Confirmed => Self {
                kind: "confirmed".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::Finalized(epoch) => Self {
                kind: "finalized".to_string(),
                finalized_epoch_hash: Some(epoch.hash),
                nonce: epoch.nonce,
            },
        }
    }
}

#[derive(Debug, Clone)]
/// Outcome of sending one HA message to one peer.
pub struct HaBroadcastReceipt {
    /// Public identity of the attempted peer.
    pub peer: PubKey,
    /// Peer receipt or the bounded transport failure.
    pub response: Result<HaWireReceipt>,
}

#[derive(Debug, Clone, Default)]
/// Per-peer outcomes from broadcasting one HA message.
pub struct HaBroadcastReport {
    /// Exactly one outcome for each configured peer attempt.
    pub receipts: Vec<HaBroadcastReceipt>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Quorum and lifecycle interpretation of an HA broadcast report.
pub struct HaBroadcastAssessment {
    /// Service health implied by immediate peer reachability.
    pub health: HaServiceHealth,
    /// Number of distinct remote peers contacted.
    pub attempted_peers: u8,
    /// Responsive node count, including the local node.
    pub responsive_nodes: u8,
    /// Majority required by the current active membership.
    pub required_nodes: u8,
    /// Whether the responsive nodes meet the majority threshold.
    pub quorum_reached: bool,
    /// Operational actions required to fail closed at the service boundary.
    pub directives: Vec<HaServiceDirective>,
}

impl HaBroadcastReport {
    /// Counts distinct peers that returned successful receipts.
    pub fn accepted(&self) -> usize {
        self.receipts
            .iter()
            .filter(|receipt| receipt.response.is_ok())
            .map(|receipt| receipt.peer)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Converts immediate transport outcomes into service lifecycle actions.
    ///
    /// The local active node counts as responsive. This lets a service detect
    /// loss of quorum before another epoch can finalize and update the
    /// epoch-based presence tracker.
    pub fn assess(&self, active_nodes: usize) -> Result<HaBroadcastAssessment> {
        if !(MIN_HA_NODES..=MAX_HA_NODES).contains(&active_nodes) {
            return Err(BlossomError::InvalidHighAvailabilityNodeCount(active_nodes));
        }
        let attempted_peers = u8::try_from(
            self.receipts
                .iter()
                .map(|receipt| receipt.peer)
                .collect::<BTreeSet<_>>()
                .len()
                .min(MAX_HA_NODES - 1),
        )
        .expect("HA peer count is at most six");
        let responsive_nodes =
            u8::try_from(1usize.saturating_add(self.accepted()).min(active_nodes))
                .expect("HA responsive count is at most seven");
        let required_nodes = u8::try_from(high_availability_majority(active_nodes))
            .expect("HA majority is at most seven");
        let quorum_reached = responsive_nodes >= required_nodes;
        let health = if !quorum_reached {
            HaServiceHealth::Unavailable
        } else if usize::from(responsive_nodes) < active_nodes {
            HaServiceHealth::Degraded
        } else {
            HaServiceHealth::Ready
        };
        let directives = match health {
            HaServiceHealth::Ready => vec![HaServiceDirective::Continue],
            HaServiceHealth::Degraded => vec![
                HaServiceDirective::Continue,
                HaServiceDirective::NotifyOperators,
            ],
            HaServiceHealth::Unavailable => vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::AwaitQuorum {
                    required: required_nodes,
                    responsive: responsive_nodes,
                },
            ],
            HaServiceHealth::Suspended => unreachable!("broadcast assessment is for active nodes"),
        };
        Ok(HaBroadcastAssessment {
            health,
            attempted_peers,
            responsive_nodes,
            required_nodes,
            quorum_reached,
            directives,
        })
    }
}

pub(super) struct HaAuthenticatedConnection {
    pub(super) stream: TcpStream,
    pub(super) session_id: [u8; HA_TRANSPORT_KEY_BYTES],
    pub(super) session_key: [u8; HA_TRANSPORT_KEY_BYTES],
    next_sequence: u64,
    limits: HaNetworkLimits,
}

impl HaAuthenticatedConnection {
    pub(super) async fn connect(
        service: &Service,
        context: &HaTransportContext,
        transport_key: &HaTransportKey,
        limits: HaNetworkLimits,
    ) -> Result<Self> {
        limits.validate()?;
        context.validate_peer(service.public_key)?;
        let mut stream = timeout(
            limits.connect_timeout,
            TcpStream::connect(service.socket_addr()),
        )
        .await
        .map_err(|_| BlossomError::ExternalService("HA connect timed out".to_string()))?
        .map_err(|error| BlossomError::Io(error.to_string()))?;
        let mut client_nonce = [0u8; HA_TRANSPORT_KEY_BYTES];
        OsRng.fill_bytes(&mut client_nonce);
        let hello_body = HaTransportHelloBody {
            version: HA_TRANSPORT_VERSION,
            group_id: context.group_id,
            fixed_membership_hash: context.fixed_membership_hash,
            parameters_hash: context.parameters_hash,
            client: context.local_key,
            server: service.public_key,
            client_nonce,
        };
        let hello = HaTransportHello {
            mac: ha_transport_mac(
                transport_key.as_bytes(),
                HA_TRANSPORT_HELLO_DOMAIN,
                &hello_body,
            )?,
            body: hello_body.clone(),
        };
        ha_timeout(
            limits.request_timeout,
            "hello write",
            write_frame(&mut stream, &hello),
        )
        .await?;

        let challenge: HaTransportChallenge = ha_timeout(
            limits.request_timeout,
            "challenge read",
            read_frame(&mut stream),
        )
        .await?;
        if challenge.body.hello != hello_body {
            return Err(BlossomError::WireProtocol(
                "HA transport challenge changed the authenticated hello".to_string(),
            ));
        }
        verify_ha_transport_mac(
            transport_key.as_bytes(),
            HA_TRANSPORT_CHALLENGE_DOMAIN,
            &challenge.body,
            &challenge.mac,
        )?;
        let seed = HaTransportSessionSeed {
            hello: hello_body,
            server_nonce: challenge.body.server_nonce,
        };
        let expected_session_id = ha_transport_mac(
            transport_key.as_bytes(),
            HA_TRANSPORT_SESSION_ID_DOMAIN,
            &seed,
        )?;
        if challenge.body.session_id != expected_session_id {
            return Err(BlossomError::WireProtocol(
                "HA transport session identifier mismatch".to_string(),
            ));
        }
        let session_key = derive_ha_session_key(transport_key, &challenge.body)?;
        Ok(Self {
            stream,
            session_id: expected_session_id,
            session_key,
            next_sequence: 1,
            limits,
        })
    }

    async fn request(&mut self, request: &HaWireRequest) -> Result<HaWireResponse> {
        let sequence = self.next_sequence;
        let body = HaAuthenticatedRequestBody {
            session_id: self.session_id,
            sequence,
            request: request.clone(),
        };
        let request = HaAuthenticatedRequest {
            mac: ha_transport_mac(&self.session_key, HA_TRANSPORT_REQUEST_DOMAIN, &body)?,
            body,
        };
        ha_timeout(
            self.limits.request_timeout,
            "request write",
            write_frame(&mut self.stream, &request),
        )
        .await?;

        let response: HaAuthenticatedResponse = ha_timeout(
            self.limits.request_timeout,
            "response read",
            read_frame(&mut self.stream),
        )
        .await?;
        if response.body.session_id != self.session_id || response.body.sequence != sequence {
            return Err(BlossomError::WireProtocol(
                "HA transport response session or sequence mismatch".to_string(),
            ));
        }
        verify_ha_transport_mac(
            &self.session_key,
            HA_TRANSPORT_RESPONSE_DOMAIN,
            &response.body,
            &response.mac,
        )?;
        self.next_sequence = sequence.checked_add(1).ok_or_else(|| {
            BlossomError::WireProtocol("HA transport sequence exhausted".to_string())
        })?;
        Ok(response.body.response)
    }
}

/// Persistent authenticated client for the isolated HA wire profile.
///
/// The client binds a connection to the fixed genesis membership and committed
/// HA parameters. Every frame is HMAC-authenticated with a monotonically
/// increasing per-session sequence number.
#[derive(Clone)]
pub struct HighAvailabilityTcpClient {
    context: HaTransportContext,
    transport_key: HaTransportKey,
    limits: HaNetworkLimits,
    connections: Arc<Mutex<BTreeMap<String, Arc<Mutex<HaAuthenticatedConnection>>>>>,
}

impl HighAvailabilityTcpClient {
    /// Builds a client using the runtime's consensus context and default limits.
    pub fn for_runtime(runtime: &HighAvailabilityRuntime, transport_key: HaTransportKey) -> Self {
        Self::for_runtime_with_limits(runtime, transport_key, HaNetworkLimits::default())
            .expect("default HA network limits are valid")
    }

    /// Builds a client using the runtime's consensus context and explicit limits.
    pub fn for_runtime_with_limits(
        runtime: &HighAvailabilityRuntime,
        transport_key: HaTransportKey,
        limits: HaNetworkLimits,
    ) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            context: HaTransportContext::from_runtime(runtime),
            transport_key,
            limits,
            connections: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Sends one request over a persistent authenticated session.
    ///
    /// A failed session is removed and the request is retried once on a fresh
    /// connection; both attempts remain bounded by [`HaNetworkLimits`].
    pub async fn request(
        &self,
        service: &Service,
        request: &HaWireRequest,
    ) -> Result<HaWireResponse> {
        let key = format!("{}#{}", service.socket_addr(), service.public_key);
        let connection = self.connection(&key, service).await?;
        let response = {
            let mut connection = connection.lock().await;
            connection.request(request).await
        };
        match response {
            Ok(response) => Ok(response),
            Err(first_error) => {
                self.remove_connection(&key, &connection).await;
                let replacement = self.connection(&key, service).await?;
                let mut replacement = replacement.lock().await;
                replacement.request(request).await.map_err(|second_error| {
                    BlossomError::ExternalService(format!(
                        "authenticated HA request failed ({first_error}); reconnect failed ({second_error})"
                    ))
                })
            }
        }
    }

    /// Fetches and decodes the peer's current HA runtime status.
    pub async fn status(&self, service: &Service) -> Result<HaNodeStatus> {
        match self.request(service, &HaWireRequest::Status).await? {
            HaWireResponse::Status(status) => Ok(*status),
            HaWireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected HA status, got {}",
                response.kind()
            ))),
        }
    }

    /// Sends one HA protocol message and returns its runtime receipt.
    pub async fn send_message(
        &self,
        service: &Service,
        message: HaMessage,
    ) -> Result<HaWireReceipt> {
        match self
            .request(service, &HaWireRequest::Message(Box::new(message)))
            .await?
        {
            HaWireResponse::Receipt(receipt) => Ok(receipt),
            HaWireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected HA receipt, got {}",
                response.kind()
            ))),
        }
    }

    async fn connection(
        &self,
        key: &str,
        service: &Service,
    ) -> Result<Arc<Mutex<HaAuthenticatedConnection>>> {
        if let Some(connection) = self.connections.lock().await.get(key).cloned() {
            return Ok(connection);
        }
        let connection = Arc::new(Mutex::new(
            HaAuthenticatedConnection::connect(
                service,
                &self.context,
                &self.transport_key,
                self.limits,
            )
            .await?,
        ));
        let mut connections = self.connections.lock().await;
        Ok(connections
            .entry(key.to_string())
            .or_insert_with(|| connection.clone())
            .clone())
    }

    async fn remove_connection(&self, key: &str, failed: &Arc<Mutex<HaAuthenticatedConnection>>) {
        let mut connections = self.connections.lock().await;
        if connections
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, failed))
        {
            connections.remove(key);
        }
    }
}

/// Authenticated TCP service for the small-cluster HA runtime.
///
/// Each stage is broadcast directly to every configured peer over persistent,
/// replay-protected sessions. With the seven-node cap that is at most six
/// outgoing requests per local stage.
#[derive(Clone)]
pub struct HighAvailabilityTcpNode {
    runtime: Arc<Mutex<HighAvailabilityRuntime>>,
    peers: Vec<Service>,
    services: HighAvailabilityTcpClient,
    transport_key: HaTransportKey,
    limits: HaNetworkLimits,
    connection_limit: Arc<Semaphore>,
}

impl HighAvailabilityTcpNode {
    /// Builds an authenticated HA service with default network limits.
    pub fn new(
        runtime: HighAvailabilityRuntime,
        peers: Vec<Service>,
        transport_key: HaTransportKey,
    ) -> Result<Self> {
        Self::new_with_limits(runtime, peers, transport_key, HaNetworkLimits::default())
    }

    /// Builds an authenticated HA service with explicit network limits.
    pub fn new_with_limits(
        runtime: HighAvailabilityRuntime,
        peers: Vec<Service>,
        transport_key: HaTransportKey,
        limits: HaNetworkLimits,
    ) -> Result<Self> {
        limits.validate()?;
        let context = HaTransportContext::from_runtime(&runtime);
        for peer in &peers {
            context.validate_peer(peer.public_key)?;
        }
        let services = HighAvailabilityTcpClient::for_runtime_with_limits(
            &runtime,
            transport_key.clone(),
            limits,
        )?;
        Ok(Self {
            runtime: Arc::new(Mutex::new(runtime)),
            peers,
            services,
            transport_key,
            limits,
            connection_limit: Arc::new(Semaphore::new(limits.max_connections)),
        })
    }

    /// Returns the shared runtime used by the transport service.
    pub fn runtime(&self) -> Arc<Mutex<HighAvailabilityRuntime>> {
        self.runtime.clone()
    }

    /// Interprets a broadcast against the runtime's active member count.
    pub async fn assess_broadcast(
        &self,
        report: &HaBroadcastReport,
    ) -> Result<HaBroadcastAssessment> {
        let active_nodes = self.runtime.lock().await.members().active_count();
        report.assess(active_nodes)
    }

    /// Serves authenticated HA connections until the listener fails or closes.
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|error| BlossomError::Io(error.to_string()))?;
            let Ok(permit) = self.connection_limit.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let node = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = node.handle_connection(stream).await {
                    node.runtime.lock().await.emit_telemetry_failure(
                        "transport",
                        "ha_connection_failed",
                        &error,
                    );
                    log::error!("HA connection failed: {error}");
                }
            });
        }
    }

    /// Authenticates and serves one inbound connection until it becomes idle or closes.
    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        let context = {
            let runtime = self.runtime.lock().await;
            HaTransportContext::from_runtime(&runtime)
        };
        let hello: HaTransportHello = ha_timeout(
            self.limits.request_timeout,
            "server hello read",
            read_frame(&mut stream),
        )
        .await?;
        if hello.body.version != HA_TRANSPORT_VERSION
            || hello.body.group_id != context.group_id
            || hello.body.fixed_membership_hash != context.fixed_membership_hash
            || hello.body.parameters_hash != context.parameters_hash
            || hello.body.server != context.local_key
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA transport hello does not match local consensus context".to_string(),
            ));
        }
        context.validate_peer(hello.body.client)?;
        verify_ha_transport_mac(
            self.transport_key.as_bytes(),
            HA_TRANSPORT_HELLO_DOMAIN,
            &hello.body,
            &hello.mac,
        )?;

        let mut server_nonce = [0u8; HA_TRANSPORT_KEY_BYTES];
        OsRng.fill_bytes(&mut server_nonce);
        let seed = HaTransportSessionSeed {
            hello: hello.body.clone(),
            server_nonce,
        };
        let session_id = ha_transport_mac(
            self.transport_key.as_bytes(),
            HA_TRANSPORT_SESSION_ID_DOMAIN,
            &seed,
        )?;
        let challenge_body = HaTransportChallengeBody {
            hello: hello.body,
            server_nonce,
            session_id,
        };
        let challenge = HaTransportChallenge {
            mac: ha_transport_mac(
                self.transport_key.as_bytes(),
                HA_TRANSPORT_CHALLENGE_DOMAIN,
                &challenge_body,
            )?,
            body: challenge_body,
        };
        ha_timeout(
            self.limits.request_timeout,
            "server challenge write",
            write_frame(&mut stream, &challenge),
        )
        .await?;
        let session_key = derive_ha_session_key(&self.transport_key, &challenge.body)?;

        let mut expected_sequence = 1u64;
        while let Some(request) = ha_timeout(
            self.limits.idle_timeout,
            "idle request read",
            read_frame_optional::<HaAuthenticatedRequest, _>(&mut stream),
        )
        .await?
        {
            if request.body.session_id != session_id || request.body.sequence != expected_sequence {
                return Err(BlossomError::WireProtocol(format!(
                    "HA transport expected sequence {expected_sequence}"
                )));
            }
            verify_ha_transport_mac(
                &session_key,
                HA_TRANSPORT_REQUEST_DOMAIN,
                &request.body,
                &request.mac,
            )?;
            let response = self
                .handle_authenticated_request(challenge.body.hello.client, request.body.request)
                .await
                .unwrap_or_else(|error| HaWireResponse::Error(error.to_string()));
            let response_body = HaAuthenticatedResponseBody {
                session_id,
                sequence: expected_sequence,
                response,
            };
            let response = HaAuthenticatedResponse {
                mac: ha_transport_mac(&session_key, HA_TRANSPORT_RESPONSE_DOMAIN, &response_body)?,
                body: response_body,
            };
            ha_timeout(
                self.limits.request_timeout,
                "server response write",
                write_frame(&mut stream, &response),
            )
            .await?;
            expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
                BlossomError::WireProtocol("HA transport sequence exhausted".to_string())
            })?;
        }
        Ok(())
    }

    async fn handle_authenticated_request(
        &self,
        authenticated_peer: PubKey,
        request: HaWireRequest,
    ) -> Result<HaWireResponse> {
        match request {
            HaWireRequest::Message(message) => {
                let mut runtime = self.runtime.lock().await;
                let claimed_peer = ha_message_sender(&message, runtime.members())?;
                if claimed_peer != authenticated_peer {
                    return Err(BlossomError::WireProtocol(
                        "HA message sender does not match authenticated transport peer".to_string(),
                    ));
                }
                let event = runtime.receive_message(*message)?;
                let nonce = runtime.head().nonce;
                Ok(HaWireResponse::Receipt(HaWireReceipt::from_event(
                    &event, nonce,
                )))
            }
            HaWireRequest::Status => Ok(HaWireResponse::Status(Box::new(
                self.runtime.lock().await.status()?,
            ))),
            _ => Err(BlossomError::WireProtocol(
                "HA service accepts only high-availability messages and status requests"
                    .to_string(),
            )),
        }
    }

    /// Builds a local dispatch and broadcasts it to every configured peer.
    pub async fn build_and_broadcast_dispatch(
        &self,
        transactions: Vec<crate::block::Transaction>,
    ) -> Result<(HaDispatch, HaBroadcastReport)> {
        let dispatch = self.runtime.lock().await.build_dispatch(transactions)?;
        let report = self
            .broadcast_message(HaMessage::Dispatch(dispatch.clone()))
            .await;
        Ok((dispatch, report))
    }

    /// Builds the local acknowledgement and broadcasts it to every peer.
    pub async fn build_and_broadcast_acknowledgement(
        &self,
    ) -> Result<(HaAcknowledge, HaBroadcastReport)> {
        let acknowledgement = self.runtime.lock().await.acknowledge()?;
        let report = self
            .broadcast_message(HaMessage::Acknowledge(acknowledgement.clone()))
            .await;
        Ok((acknowledgement, report))
    }

    /// Builds the local confirmation and broadcasts it to every peer.
    ///
    /// The returned epoch is present when the local confirmation completed
    /// finalization.
    pub async fn build_and_broadcast_confirmation(
        &self,
    ) -> Result<(HaConfirm, Option<HaEpoch>, HaBroadcastReport)> {
        let (confirmation, epoch) = self.runtime.lock().await.confirm()?;
        let report = self
            .broadcast_message(HaMessage::Confirm(confirmation.clone()))
            .await;
        Ok((confirmation, epoch, report))
    }

    /// Casts and broadcasts a vote to suspend one member slot.
    pub async fn vote_and_broadcast_suspension(
        &self,
        slot: HaMemberSlot,
    ) -> Result<(
        HaMembershipVote,
        Option<HaMembershipCertificate>,
        HaBroadcastReport,
    )> {
        let (vote, certificate) = self.runtime.lock().await.vote_to_suspend(slot)?;
        let report = self
            .broadcast_message(HaMessage::MembershipVote(vote))
            .await;
        Ok((vote, certificate, report))
    }

    /// Casts and broadcasts a vote to reactivate one caught-up member slot.
    pub async fn vote_and_broadcast_reactivation(
        &self,
        slot: HaMemberSlot,
        caught_up_through: Nonce,
    ) -> Result<(
        HaMembershipVote,
        Option<HaMembershipCertificate>,
        HaBroadcastReport,
    )> {
        let (vote, certificate) = self
            .runtime
            .lock()
            .await
            .vote_to_reactivate(slot, caught_up_through)?;
        let report = self
            .broadcast_message(HaMessage::MembershipVote(vote))
            .await;
        Ok((vote, certificate, report))
    }

    /// Broadcasts one message concurrently and retains every peer outcome.
    pub async fn broadcast_message(&self, message: HaMessage) -> HaBroadcastReport {
        let mut tasks = Vec::with_capacity(self.peers.len());
        for peer in self.peers.iter().cloned() {
            let services = self.services.clone();
            let message = message.clone();
            tasks.push((
                peer.public_key,
                tokio::spawn(async move { services.send_message(&peer, message).await }),
            ));
        }
        let mut receipts = Vec::with_capacity(tasks.len());
        for (peer, task) in tasks {
            let response = match task.await {
                Ok(response) => response,
                Err(error) => Err(BlossomError::Io(format!(
                    "HA broadcast task failed: {error}"
                ))),
            };
            receipts.push(HaBroadcastReceipt { peer, response });
        }
        HaBroadcastReport { receipts }
    }
}

fn ha_message_sender(message: &HaMessage, members: &HaMemberSlots) -> Result<PubKey> {
    let slot = match message {
        HaMessage::Handshake(handshake) => return Ok(handshake.sender),
        HaMessage::MembershipVote(vote) => vote.sender,
        HaMessage::Dispatch(dispatch) => dispatch.sender,
        HaMessage::Acknowledge(acknowledgement) => acknowledgement.sender,
        HaMessage::Confirm(confirmation) => confirmation.sender,
    };
    members
        .member(slot)
        .map(NodeIdentity::public_key)
        .ok_or(BlossomError::UnknownSender)
}
