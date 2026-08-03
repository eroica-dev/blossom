//! Durable active-active admission and globally ordered application delivery.
//!
//! Blossom treats [`ApplicationCommand`] and [`ApplicationResult`] as opaque
//! bytes. [`DurableAdmissionStore`] admits and deduplicates commands,
//! availability certificates prove that referenced bytes are recoverable, and
//! [`GlobalOrderedEngine`] installs certified references in one hash-chained
//! order before invoking an application-owned [`OrderedApplication`].
//!
//! The application owns command semantics, result encoding, transport, and the
//! atomic state-machine transaction. It must deduplicate the
//! `(reference_hash, watermark)` replay key because ordered delivery is
//! intentionally at-least-once across a crash between the application commit
//! and Blossom's durable completion record.
//!
//! Implementation ownership is split into `model`, `certificates`, `store`,
//! `engine`, and `tracking`. Public items are re-exported here so the module's
//! external paths remain stable.

#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use borsh::{BorshDeserialize, BorshSerialize};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::algorithm::{has_supermajority, supermajority_count};
use crate::block::Transaction;
use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::HashType;
use crate::log_store::{
    BlossomLogStore, BlossomLogStoreConfig, BlossomLogStoreIdentity, BlossomLogTransaction,
};
use crate::runtime::TrustMode;
use crate::safety::SiteId;
use crate::state::Epoch;
use crate::telemetry::{TelemetryEvent, TelemetryEventKind, TelemetryHandle};

const COMMAND_HASH_DOMAIN: &[u8] = b"blossom/active-active/command/v2";
const COMMAND_BATCH_HASH_DOMAIN: &[u8] = b"blossom/active-active/command-batch/v1";
const REFERENCE_HASH_DOMAIN: &[u8] = b"blossom/active-active/batch-reference/v2";
const REFERENCE_TRANSACTION_DOMAIN: &[u8] = b"blossom/active-active/reference-transaction/v2";
const MERKLE_LEAF_DOMAIN: &[u8] = b"blossom/active-active/merkle-leaf/v1";
const MERKLE_NODE_DOMAIN: &[u8] = b"blossom/active-active/merkle-node/v1";
const ADMISSION_RECEIPT_DOMAIN: &[u8] = b"blossom/active-active/admission-receipt/v1";
const ADMISSION_BATCH_RECEIPT_DOMAIN: &[u8] = b"blossom/active-active/admission-batch-receipt/v1";
const AVAILABILITY_RECEIPT_DOMAIN: &[u8] = b"blossom/active-active/availability-receipt/v1";
const ORDER_STATEMENT_DOMAIN: &[u8] = b"blossom/active-active/order-statement/v1";
const ORDER_CERTIFICATE_DOMAIN: &[u8] = b"blossom/active-active/order-certificate/v1";
const ORDER_VOTE_HASH_DOMAIN: &[u8] = b"blossom/active-active/order-vote/v1";
const READ_BARRIER_STATEMENT_DOMAIN: &[u8] = b"blossom/active-active/read-barrier-statement/v1";
const READ_BARRIER_CERTIFICATE_DOMAIN: &[u8] = b"blossom/active-active/read-barrier-certificate/v1";
const READ_BARRIER_VOTE_HASH_DOMAIN: &[u8] = b"blossom/active-active/read-barrier-vote/v1";
const COMMITTEE_TRANSITION_STATEMENT_DOMAIN: &[u8] =
    b"blossom/active-active/committee-transition-statement/v1";
const COMMITTEE_TRANSITION_CERTIFICATE_DOMAIN: &[u8] =
    b"blossom/active-active/committee-transition-certificate/v1";
/// Maximum encoded bytes in one opaque application command.
pub const MAX_APPLICATION_COMMAND_BYTES: usize = 64 << 20;
/// Maximum encoded bytes in one opaque application result.
pub const MAX_APPLICATION_RESULT_BYTES: usize = 64 << 20;
/// Default upper bound on commands carried by one batch.
pub const DEFAULT_MAX_BATCH_COMMANDS: usize = 4_096;
/// Default upper bound on a batch's canonical encoded size.
pub const DEFAULT_MAX_BATCH_BYTES: usize = 64 << 20;
/// Maximum encoded bytes in an application shard identifier.
pub const MAX_ACTIVE_ACTIVE_SHARD_ID_BYTES: usize = 256;
/// Maximum number of finalized-but-unapplied availability windows.
pub const MAX_PIPELINED_AVAILABILITY_WINDOWS: usize = 8;
/// Largest timeout accepted by bounded milestone waits.
pub const MAX_WAIT_FOR_TIMEOUT: Duration = Duration::from_secs(300);
const WAIT_FOR_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// One trusted ordering window may contain one reference from every validator.
///
/// The runtime bounds pending availability by windows, not by individual
/// parallel writers, so universal-writer epochs do not exhaust the pipeline
/// merely because the validator population is large.
pub const MAX_REFERENCES_PER_ORDERING_WINDOW: usize = 65_536;

const COMMANDS_TABLE: &str = "active_active_commands_v1";
const COMMAND_IDENTITIES_TABLE: &str = "active_active_command_identities_v1";
const ADMISSION_BATCHES_TABLE: &str = "active_active_admission_batches_v3";
const BATCHES_TABLE: &str = "active_active_batches_v1";
const MILESTONES_TABLE: &str = "active_active_milestones_v1";
const REFERENCE_STATUS_TABLE: &str = "active_active_reference_status_v3";
const APPLIED_COMPLETIONS_TABLE: &str = "active_active_applied_completions_v3";
const META_TABLE: &str = "active_active_meta_v1";
const ORDER_VOTES_TABLE: &str = "active_active_order_votes_v1";
const READ_BARRIER_VOTES_TABLE: &str = "active_active_read_barrier_votes_v1";
const COMMITTEE_TRANSITION_VOTES_TABLE: &str = "active_active_committee_transition_votes_v1";
const STORE_IDENTITY_TABLE: &str = "active_active_store_identity_v3";
const AVAILABLE_REFERENCES_TABLE: &str = "active_active_available_references_v3";
const FINALIZED_POSITIONS_TABLE: &str = "active_active_finalized_positions_v3";
const POSITION_REFERENCES_TABLE: &str = "active_active_position_references_v3";
const ORIGIN_TAILS_TABLE: &str = "active_active_origin_tails_v3";
const ORDERED_METADATA_TABLE: &str = "active_active_ordered_metadata_v3";
const COMMITTEE_TRANSITIONS_TABLE: &str = "active_active_committee_transitions_v1";
const STORE_IDENTITY_KEY: &str = "identity";
const ORDERED_METADATA_KEY: &str = "metadata";
const ACTIVE_ACTIVE_STORE_SCHEMA_VERSION: u16 = 3;
const DURABLE_ORDERED_STATE_VERSION: u16 = 3;

mod certificates;
mod engine;
mod model;
mod store;
mod tracking;

pub use certificates::*;
pub use model::*;
pub use tracking::*;

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct DurableOrderedState {
    version: u16,
    holder_membership_epoch: ReplicaMembershipEpoch,
    validator_generation: ValidatorGeneration,
    route_generation: RouteGeneration,
    command_spec_version: CommandSpecVersion,
    available: BTreeMap<HashType, AvailabilityCertificate>,
    finalized: BTreeMap<u64, OrderCertificate>,
    final_reference_by_position: BTreeMap<u64, HashType>,
    last_origin_reference: BTreeMap<(PubKey, u64, u64), (HashType, u64)>,
    last_finalized_position: u64,
    last_order_certificate_hash: HashType,
    applied_watermark: Watermark,
    committee_transitions: BTreeMap<ValidatorGeneration, CommitteeTransitionCertificate>,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct DurableOrderedMetadata {
    version: u16,
    holder_membership_epoch: ReplicaMembershipEpoch,
    validator_generation: ValidatorGeneration,
    route_generation: RouteGeneration,
    command_spec_version: CommandSpecVersion,
    last_finalized_position: u64,
    last_order_certificate_hash: HashType,
    applied_watermark: Watermark,
}

impl From<&DurableOrderedState> for DurableOrderedMetadata {
    fn from(state: &DurableOrderedState) -> Self {
        Self {
            version: state.version,
            holder_membership_epoch: state.holder_membership_epoch,
            validator_generation: state.validator_generation,
            route_generation: state.route_generation,
            command_spec_version: state.command_spec_version,
            last_finalized_position: state.last_finalized_position,
            last_order_certificate_hash: state.last_order_certificate_hash,
            applied_watermark: state.applied_watermark,
        }
    }
}

type OrderedOrigin = (PubKey, u64, u64);
type OrderedOriginTail = (HashType, u64);

struct OrderedStateDelta {
    metadata: DurableOrderedMetadata,
    available_upserts: Vec<(HashType, AvailabilityCertificate)>,
    available_removals: Vec<HashType>,
    finalized_upserts: Vec<(u64, OrderCertificate)>,
    position_upserts: Vec<(u64, HashType)>,
    origin_tail_upserts: Vec<(OrderedOrigin, OrderedOriginTail)>,
}

impl OrderedStateDelta {
    fn new(metadata: DurableOrderedMetadata) -> Self {
        Self {
            metadata,
            available_upserts: Vec::new(),
            available_removals: Vec::new(),
            finalized_upserts: Vec::new(),
            position_upserts: Vec::new(),
            origin_tail_upserts: Vec::new(),
        }
    }
}

fn validate_shard_id(shard: &[u8]) -> Result<()> {
    if shard.is_empty() || shard.len() > MAX_ACTIVE_ACTIVE_SHARD_ID_BYTES {
        return Err(BlossomError::InvalidConfiguration(format!(
            "active-active shard id must contain 1..={MAX_ACTIVE_ACTIVE_SHARD_ID_BYTES} bytes"
        )));
    }
    Ok(())
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct DurableStoreIdentity {
    schema_version: u16,
    holder: PubKey,
    site: SiteId,
    store_generation: StoreGeneration,
    cluster_id: Option<HashType>,
    consensus_group_id: Option<ConsensusGroupId>,
}

impl DurableStoreIdentity {
    fn new(holder: PubKey, site: SiteId, store_generation: StoreGeneration) -> Self {
        Self {
            schema_version: ACTIVE_ACTIVE_STORE_SCHEMA_VERSION,
            holder,
            site,
            store_generation,
            cluster_id: None,
            consensus_group_id: None,
        }
    }

    fn validate_startup(
        &self,
        holder: PubKey,
        site: &SiteId,
        store_generation: StoreGeneration,
    ) -> Result<()> {
        if self.schema_version != ACTIVE_ACTIVE_STORE_SCHEMA_VERSION {
            return Err(BlossomError::InvalidConfiguration(format!(
                "unsupported active-active store schema {}; expected {}",
                self.schema_version, ACTIVE_ACTIVE_STORE_SCHEMA_VERSION
            )));
        }
        if self.holder != holder || &self.site != site || self.store_generation != store_generation
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active store identity does not match holder, site, or generation"
                    .to_string(),
            ));
        }
        if self.cluster_id.is_some() != self.consensus_group_id.is_some() {
            return Err(BlossomError::InvalidConfiguration(
                "active-active store has a partially bound protocol scope".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
/// Durable site-local command admission and ordered-state store.
///
/// The store identity binds the holder, site, generation, cluster, and
/// consensus group. Signing material stays in memory and is never serialized
/// into the embedded LogStore.
pub struct DurableAdmissionStore {
    store: BlossomLogStore,
    holder: PubKey,
    site: SiteId,
    store_generation: StoreGeneration,
    signer: SecretSigner,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Process-local durability counters for active-active operations.
pub struct ActiveActiveDurabilityMetrics {
    /// Number of committed LogStore transactions.
    pub commit_count: u64,
    /// Number of data-synchronization operations completed by the store.
    pub fsync_count: u64,
}

/// One immutable, globally ordered batch delivered to an embedding application.
///
/// `reference_hash` and `watermark` form the replay key. Implementations of
/// [`OrderedApplication`] must durably deduplicate that key because a process
/// failure after the callback commits but before Blossom commits its own state
/// can cause the callback to be invoked again after restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedBatch {
    /// Hash of the certified batch reference.
    pub reference_hash: HashType,
    /// Complete reference committed by the ordering certificate.
    pub reference: BatchReference,
    /// Verified command bytes addressed by the reference.
    pub batch: CommandBatch,
    /// Global position assigned to this batch.
    pub watermark: Watermark,
}

/// Application-owned state-machine hook for direct Blossom integrations.
///
/// `shard-kv`, `shard-stream`, and other consumers implement this trait in
/// their own crates. The callback is invoked in certified order and must be
/// idempotent for the supplied `(reference_hash, watermark)` replay key.
pub trait OrderedApplication {
    /// Applies one certified batch and returns one result per command.
    ///
    /// Implementations must atomically deduplicate the batch's
    /// `(reference_hash, watermark)` pair with their application mutation.
    fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Result of attempting to apply the next contiguous ordered positions.
pub enum ApplyProgress {
    /// One or more positions were applied through `watermark`.
    Applied {
        /// Highest position applied by this call.
        watermark: Watermark,
        /// Durable per-reference application completions.
        completions: Vec<AppliedCompletion>,
    },
    /// The next finalized reference is not locally available yet.
    HeadOfLineUnavailable {
        /// Highest contiguous position already applied.
        watermark: Watermark,
        /// Reference whose missing bytes block further application.
        blocked_reference: HashType,
    },
}

/// Durable engine for the `active-sync-global-ordered` consistency profile.
///
/// The engine validates availability and order evidence, enforces origin and
/// global hash-chain continuity, records terminal [`Milestone::Applied`]
/// completions, and issues quorum-certified read barriers. It never interprets
/// application command bytes.
pub struct GlobalOrderedEngine {
    store: DurableAdmissionStore,
    mode: ActiveActiveConsistencyMode,
    holder_membership: HolderMembership,
    validator_generation: ValidatorGeneration,
    validators: BTreeSet<PubKey>,
    genesis_holder_membership: HolderMembership,
    genesis_validator_generation: ValidatorGeneration,
    genesis_validators: BTreeSet<PubKey>,
    committee_transitions: BTreeMap<ValidatorGeneration, CommitteeTransitionCertificate>,
    order_trust_mode: TrustMode,
    available: BTreeMap<HashType, AvailabilityCertificate>,
    finalized: BTreeMap<u64, OrderCertificate>,
    final_reference_by_position: BTreeMap<u64, HashType>,
    finalized_reference_hashes: BTreeSet<HashType>,
    last_origin_reference: BTreeMap<(PubKey, u64, u64), (HashType, u64)>,
    last_finalized_position: u64,
    last_order_certificate_hash: HashType,
    applied_watermark: Watermark,
    route_generation: RouteGeneration,
    command_spec_version: CommandSpecVersion,
    telemetry: TelemetryHandle,
}

fn milestone_event(
    mode: ActiveActiveConsistencyMode,
    reference_hash: HashType,
    milestone: Milestone,
    watermark: Option<Watermark>,
) -> MilestoneEvent {
    MilestoneEvent {
        protocol: mode.as_str().to_string(),
        reference_hash,
        milestone,
        timestamp_micros: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros(),
        watermark,
    }
}

fn ranges_overlap(first_a: u64, last_a: u64, first_b: u64, last_b: u64) -> bool {
    first_a <= last_b && first_b <= last_a
}

fn hash_borsh<T: BorshSerialize>(domain: &[u8], value: &T) -> Result<HashType> {
    let bytes = borsh::to_vec(value)
        .map_err(|err| BlossomError::WireProtocol(format!("encode hash input: {err}")))?;
    Ok(sha256_hash(domain, &[&bytes]))
}

fn signed_body_bytes<T: BorshSerialize>(domain: &[u8], body: &T) -> Result<Vec<u8>> {
    let encoded = borsh::to_vec(body)
        .map_err(|err| BlossomError::WireProtocol(format!("encode signed body: {err}")))?;
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn sha256_hash(domain: &[u8], slices: &[&[u8]]) -> HashType {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for slice in slices {
        hasher.update((slice.len() as u64).to_le_bytes());
        hasher.update(slice);
    }
    HashType::from_byte_hash(hasher.finalize().into())
}

fn decode_u64(bytes: &[u8], field: &str) -> Result<u64> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
        BlossomError::WireProtocol(format!(
            "decode durable active-active {field}: expected 8 bytes"
        ))
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn encode_error(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::WireProtocol(format!("encode durable active-active record: {error}"))
}

#[cfg(test)]
mod tests;
