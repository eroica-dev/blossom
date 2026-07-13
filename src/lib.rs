//! Blossom v2 consensus protocol.
//!
//! This crate contains the protocol messages, quorum selection, block
//! commitment, membership reducers, runtime service registry, TCP wire surface,
//! telemetry events, and block-intake primitives needed to build and test
//! Blossom nodes.
//!
//! Blossom is application-agnostic: transaction payload bytes and block-carried
//! application state are committed by the protocol but interpreted by the
//! application layer. Ledger, cache, database, and workflow integrations should
//! live above this crate.
//!
//! Start with [`NodeRuntime`] for consensus participation, [`OverlayRuntime`]
//! for topology-aware fan-out without epoch state, [`WireRequest`] for TCP
//! integration, and [`Transaction`] plus [`Block`] for application bytes.

pub mod address_book;
pub mod admission;
pub mod algorithm;
#[cfg(feature = "availability-gossip")]
pub mod availability;
pub mod block;
pub mod block_store;
pub mod blossom;
pub mod crypto;
pub mod encounter;
pub mod error;
pub mod group;
pub mod harness;
pub mod hash;
pub mod latency_topology;
pub mod local_block;
pub mod membership;
pub mod messages;
pub mod node;
pub mod nonce;
pub mod overlay;
pub mod register;
pub mod round_skip;
pub mod runtime;
pub mod service_client;
pub mod state;
#[cfg(feature = "availability-gossip")]
pub mod subset_gossip;
pub mod tcp;
pub mod telemetry;
pub mod wire;

#[cfg(any(
    feature = "propagation-adaptive",
    feature = "propagation-inventory",
    feature = "propagation-push"
))]
pub use blossom_propagation as propagation;

pub use address_book::{AddressBook, Service, ServiceKind};
pub use admission::{
    NODE_ADMISSION_DOMAIN, NodeAdmission, NodeAdmissionBody, RECONNECT_VOTE_DOMAIN, ReconnectVote,
    ReconnectVoteBody,
};
pub use algorithm::{
    QUORUM_SIZE, SUPERMAJORITY, byzantine_fault_bound, distinct_current_validator_count,
    has_distinct_supermajority, has_supermajority, max_liveness_omissions,
    min_supermajority_intersection, select_prefill_recipients, supermajority_count,
    supermajority_has_honest_overlap, supermajority_order_statistic,
};
#[cfg(feature = "availability-gossip")]
pub use availability::{
    AvailabilityEntry, AvailabilityGossip, AvailabilityGossipBody, AvailabilityReceipt,
    AvailabilityStore, FILTERED_PAYLOAD_MAX_BYTES, FilteredPayloadBatchDelivery,
    FilteredPayloadBatchDeliveryBody, FilteredPayloadBatchFetch, FilteredPayloadBatchFetchBody,
    FilteredPayloadDelivery, FilteredPayloadDeliveryBody, FilteredPayloadDeliveryItem,
    FilteredPayloadFetch, FilteredPayloadFetchBody, FilteredPayloadMissing, FilteredPayloadRequest,
    LocalFilteredPayload, ideal_push_gossip_delay_ms, ideal_push_gossip_rounds,
    validate_filtered_payload,
};
pub use block::{
    BLOCK_APPLICATION_STATE_MAX_BYTES, BLOCK_APPLICATION_STATE_SOFT_LIMIT_BYTES, Block,
    BlockApplicationState, BlockBody, Transaction, TransactionPayload,
};
#[cfg(feature = "filtered-transactions")]
pub use block::{FilteredDeliveryPolicy, FilteredPayloadView, FilteredTransactionSlot};
#[cfg(feature = "fair-block-ordering")]
pub use block::{
    fair_block_order_key, fair_block_order_seed, fair_order_transaction_count,
    fair_ordered_block_commitments, fair_ordered_blocks,
};
pub use block_store::{BlockHandle, BlockIndex, BlockRecord, DurableBlockStore};
pub use blossom::*;
pub use crypto::{Keypair, PubKey, SecKey, SecretSigner, Signature, verify_batch};
pub use encounter::{
    ENCOUNTER_RECORD_DOMAIN, ENCOUNTER_RECORD_ENCODED_LEN, EncounterOutcome, EncounterPhase,
    EncounterRecord, EncounterRecordBody,
};
pub use error::{BlossomError, Result};
pub use group::ConsensusGroupId;
pub use harness::{MockBlockService, SimulatedCluster, SimulatedNode, signed_block};
pub use hash::{
    DoHash, FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE, FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE,
    HashType, PROTOCOL_FEATURE_CODE_VERSION, PROTOCOL_FEATURE_CODES, PROTOCOL_FEATURE_REGISTRY,
    ProtocolConsensusSurface, ProtocolFeatureCode, ProtocolFeatureRegistryEntry,
    RESERVED_PROTOCOL_FEATURE_CODE, SHA256_PROTOCOL_HASH_ALGORITHM, XXH3_PROTOCOL_HASH_ALGORITHM,
    protocol_feature_code_bytes, protocol_feature_registry_entry, protocol_hash_algorithm,
    protocol_hash_algorithm_is_compatible, validate_protocol_feature_codes,
    validate_protocol_feature_registry,
};
pub use indextreemap::{IndexTreeMap, SharedIndexTreeMap};
pub use latency_topology::{
    ClosestPeer, LatencyEstimate, LatencyEstimateMethod, LatencyRelationship, LatencyTopology,
    LatencyTopologyConfig, LatencyTopologyMetadataV1, unix_time_millis,
};
pub use local_block::LocalBlock;
pub use membership::{
    ConsensusNodeAdmissionPlan, ConsensusNodeRemovalDecision, ConsensusNodeRemovalPlan,
    ConsensusNodeRemovalPolicy, apply_consensus_node_admission_plan,
    apply_consensus_node_removal_plan, apply_epoch_membership_transition,
    derive_consensus_node_admission_plan, derive_consensus_node_removal_plan,
};
pub use messages::{MSGKey, Msg};
pub use node::{NodeIdentity, NodeType};
pub use nonce::Nonce;
pub use overlay::{BroadcastReceipt, BroadcastReport, FanOutStrategy, OverlayRuntime};
pub use register::{MessageMatrix, QuorumQueue, Status};
pub use round_skip::{
    DataDisseminationManifest, DataDisseminationManifestValidation, FutureRoundAssistDecision,
    FutureRoundAssistInput, FutureRoundAssistKind, RoundSkipCertificate,
    RoundSkipCertificateValidation, RoundSkipVote, future_round_assist_decision,
    skipped_round_assist_decision,
};
pub use runtime::{
    AcceptedBlock, EpochTarget, MessageReceipt, MultiGroupRuntime, NodeRuntime, NodeStatus,
    ObservedEncounterRecord, PeerApplicationState, PrefillDispatchBroadcastReport,
    PrefillDispatchPlan, ReconnectAdmissionDecision, ReconnectAdmissionEvidence, RuntimeConfig,
    RuntimeMode, RuntimeSnapshotV1, TrustMode, genesis_epoch, genesis_epoch_for_group,
};
pub use service_client::{TcpServiceClient, TimedNodePong};
pub use state::{
    DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES, DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER,
    Epoch, EpochBody, EpochChain, EpochNonce, LocalState, MAX_PENDING_RAW_DISPATCH_BYTES_ENV,
    MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER_ENV, PendingDispatch, PrefillDispatchRecord,
    TempConsensus, TempQuorum, configured_max_pending_raw_dispatch_bytes,
    configured_max_pending_raw_dispatch_bytes_per_sender,
};
#[cfg(feature = "availability-gossip")]
pub use subset_gossip::{
    SubsetGossipConfig, SubsetGossipEpochRow, SubsetGossipProtocolVersion, SubsetGossipReport,
    SubsetLatencyDistribution, SubsetLatencyProfile, SubsetPrefillMode, run_subset_gossip,
    run_subset_gossip_v1, run_subset_gossip_v2,
};
pub use tcp::{
    ApplicationHandler, ApplicationHandlerFuture, ConsensusDriverConfig, ConsensusDriverTick,
    TcpConnection, TcpMultiGroupNode, TcpNode, TcpNodeMetrics, TcpNodeMetricsSnapshot,
    send_wire_frame, send_wire_request, send_wire_request_raw_response,
};
pub use telemetry::{
    InMemoryTelemetrySink, JsonlTcpTelemetrySink, JsonlTcpTelemetrySinkConfig, NoopTelemetrySink,
    TELEMETRY_SCHEMA_VERSION, TelemetryEvent, TelemetryEventKind, TelemetryHandle, TelemetrySink,
};
pub use wire::{
    AddressBookUpdate, ApplicationRequest, ApplicationResponse, EncodedFrame, FRAME_PREFIX_BYTES,
    FRAME_WRITE_CHUNK_BYTES_ENV, HOT_WIRE_CODEC_ENV, HotDispatch, NodeHealth, NodePing, NodePong,
    ServiceRegistration, WireRequest, WireRequestFrame, WireResponse,
    configured_frame_write_chunk_bytes, configured_max_frame_size, decode_wire_request_frame,
    decode_wire_request_payload, decode_wire_response_payload, encoded_len, framed_len,
    hot_dispatch_response_into_request_frame, hot_dispatch_response_to_request_frame,
    hot_wire_codec_enabled, hot_wire_request_framed_len, hot_wire_response_framed_len,
    read_encoded_frame, read_frame, read_wire_request, read_wire_request_frame,
    read_wire_request_frame_optional, read_wire_response, wire_request_framed_len,
    wire_response_framed_len, write_encoded_frame, write_frame, write_wire_request,
    write_wire_response,
};
