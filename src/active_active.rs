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
const REFERENCE_HASH_DOMAIN: &[u8] = b"blossom/active-active/batch-reference/v2";
const REFERENCE_TRANSACTION_DOMAIN: &[u8] = b"blossom/active-active/reference-transaction/v2";
const MERKLE_LEAF_DOMAIN: &[u8] = b"blossom/active-active/merkle-leaf/v1";
const MERKLE_NODE_DOMAIN: &[u8] = b"blossom/active-active/merkle-node/v1";
const ADMISSION_RECEIPT_DOMAIN: &[u8] = b"blossom/active-active/admission-receipt/v1";
const AVAILABILITY_RECEIPT_DOMAIN: &[u8] = b"blossom/active-active/availability-receipt/v1";
const ORDER_STATEMENT_DOMAIN: &[u8] = b"blossom/active-active/order-statement/v1";
const ORDER_CERTIFICATE_DOMAIN: &[u8] = b"blossom/active-active/order-certificate/v1";
const ORDER_VOTE_HASH_DOMAIN: &[u8] = b"blossom/active-active/order-vote/v1";
const READ_BARRIER_STATEMENT_DOMAIN: &[u8] = b"blossom/active-active/read-barrier-statement/v1";
const READ_BARRIER_CERTIFICATE_DOMAIN: &[u8] = b"blossom/active-active/read-barrier-certificate/v1";
const READ_BARRIER_VOTE_HASH_DOMAIN: &[u8] = b"blossom/active-active/read-barrier-vote/v1";
pub const MAX_APPLICATION_COMMAND_BYTES: usize = 64 << 20;
pub const MAX_APPLICATION_RESULT_BYTES: usize = 64 << 20;
pub const DEFAULT_MAX_BATCH_COMMANDS: usize = 4_096;
pub const DEFAULT_MAX_BATCH_BYTES: usize = 64 << 20;
pub const MAX_PIPELINED_AVAILABILITY_WINDOWS: usize = 8;
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
const BATCHES_TABLE: &str = "active_active_batches_v1";
const MILESTONES_TABLE: &str = "active_active_milestones_v1";
const REFERENCE_STATUS_TABLE: &str = "active_active_reference_status_v3";
const APPLIED_COMPLETIONS_TABLE: &str = "active_active_applied_completions_v3";
const META_TABLE: &str = "active_active_meta_v1";
const ORDER_VOTES_TABLE: &str = "active_active_order_votes_v1";
const READ_BARRIER_VOTES_TABLE: &str = "active_active_read_barrier_votes_v1";
const STORE_IDENTITY_TABLE: &str = "active_active_store_identity_v3";
const AVAILABLE_REFERENCES_TABLE: &str = "active_active_available_references_v3";
const FINALIZED_POSITIONS_TABLE: &str = "active_active_finalized_positions_v3";
const POSITION_REFERENCES_TABLE: &str = "active_active_position_references_v3";
const ORIGIN_TAILS_TABLE: &str = "active_active_origin_tails_v3";
const ORDERED_METADATA_TABLE: &str = "active_active_ordered_metadata_v3";
const STORE_IDENTITY_KEY: &str = "identity";
const ORDERED_METADATA_KEY: &str = "metadata";
const ACTIVE_ACTIVE_STORE_SCHEMA_VERSION: u16 = 3;
const DURABLE_ORDERED_STATE_VERSION: u16 = 3;

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
pub struct CommandIdentity {
    pub client_id: ClientId,
    pub client_epoch: ClientEpoch,
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
)]
pub struct RouteGeneration(pub u64);

impl RouteGeneration {
    pub fn validate(self) -> Result<()> {
        if self.0 == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "route generations start at one".to_string(),
            ));
        }
        Ok(())
    }
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
pub struct CommandSpecVersion(pub u64);

impl CommandSpecVersion {
    pub fn validate(self) -> Result<()> {
        if self.0 == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "application command-spec versions start at one".to_string(),
            ));
        }
        Ok(())
    }
}

/// Opaque application-owned command bytes.
///
/// Blossom commits, orders, and deduplicates the envelope identity. It never
/// interprets the bytes or maintains a shadow copy of application state.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ApplicationCommand {
    bytes: Vec<u8>,
}

impl ApplicationCommand {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let command = Self { bytes };
        command.validate()?;
        Ok(command)
    }

    pub fn validate(&self) -> Result<()> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_APPLICATION_COMMAND_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "application command must contain 1..={MAX_APPLICATION_COMMAND_BYTES} bytes"
            )));
        }
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Opaque application-owned result bytes returned after ordered execution.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ApplicationResult {
    bytes: Vec<u8>,
}

impl ApplicationResult {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let result = Self { bytes };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        if self.bytes.len() > MAX_APPLICATION_RESULT_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "application result exceeds {MAX_APPLICATION_RESULT_BYTES} bytes"
            )));
        }
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ApplicationCommandEnvelope {
    pub identity: CommandIdentity,
    pub command: ApplicationCommand,
}

impl ApplicationCommandEnvelope {
    pub fn validate(&self) -> Result<()> {
        if self.identity.sequence == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "client command sequences start at one".to_string(),
            ));
        }
        self.command.validate()
    }

    pub fn hash(&self) -> Result<HashType> {
        self.validate()?;
        hash_borsh(COMMAND_HASH_DOMAIN, self)
    }
}

/// Backwards-compatible profile-specific name for
/// [`ApplicationCommandEnvelope`].
pub type ActiveActiveCommand = ApplicationCommandEnvelope;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AdmittedCommand {
    pub origin_sequence: u64,
    pub command: ActiveActiveCommand,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommandBatch {
    pub commands: Vec<AdmittedCommand>,
}

impl CommandBatch {
    pub fn validate(&self) -> Result<()> {
        let Some(first) = self.commands.first() else {
            return Err(BlossomError::InvalidConfiguration(
                "command batch cannot be empty".to_string(),
            ));
        };
        if self.commands.len() > DEFAULT_MAX_BATCH_COMMANDS {
            return Err(BlossomError::InvalidConfiguration(format!(
                "batch command count {} exceeds maximum {}",
                self.commands.len(),
                DEFAULT_MAX_BATCH_COMMANDS
            )));
        }
        if first.origin_sequence == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "origin sequences start at one".to_string(),
            ));
        }
        let mut expected = first.origin_sequence;
        for admitted in &self.commands {
            admitted.command.validate()?;
            if admitted.origin_sequence != expected {
                return Err(BlossomError::InvalidConfiguration(
                    "batch origin sequences are not contiguous".to_string(),
                ));
            }
            expected = expected.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("origin sequence overflow".to_string())
            })?;
        }
        let encoded = borsh::to_vec(self).map_err(encode_error)?;
        if encoded.len() > DEFAULT_MAX_BATCH_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "batch encoded size {} exceeds maximum {}",
                encoded.len(),
                DEFAULT_MAX_BATCH_BYTES
            )));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        borsh::to_vec(self).map_err(|err| {
            BlossomError::WireProtocol(format!("encode active-active command batch: {err}"))
        })
    }

    pub fn merkle_root(&self) -> Result<HashType> {
        self.validate()?;
        let mut level = self
            .commands
            .iter()
            .map(|command| {
                let command_bytes = borsh::to_vec(command).map_err(|err| {
                    BlossomError::WireProtocol(format!("encode active-active Merkle leaf: {err}"))
                })?;
                Ok(sha256_hash(MERKLE_LEAF_DOMAIN, &[&command_bytes]))
            })
            .collect::<Result<Vec<_>>>()?;

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let left = pair[0];
                let right = pair.get(1).copied().unwrap_or(left);
                next.push(sha256_hash(
                    MERKLE_NODE_DOMAIN,
                    &[left.as_ref(), right.as_ref()],
                ));
            }
            level = next;
        }
        Ok(level[0])
    }
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
pub struct ReplicaMembershipEpoch(pub u64);

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
pub struct ValidatorGeneration(pub u64);

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
pub struct StoreGeneration(pub u64);

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
pub struct Watermark {
    pub position: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AppliedBy {
    pub membership_snapshot: ReplicaMembershipEpoch,
    pub required_nodes: BTreeSet<PubKey>,
    pub watermark: Watermark,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum Milestone {
    AcceptedLocal,
    Available,
    Finalized,
    Applied,
}

impl Milestone {
    fn rank(self) -> u8 {
        match self {
            Self::AcceptedLocal => 0,
            Self::Available => 1,
            Self::Finalized => 2,
            Self::Applied => 3,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied)
    }

    pub fn reaches(self, target: Self) -> bool {
        self.rank() >= target.rank()
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MilestoneEvent {
    pub protocol: String,
    pub reference_hash: HashType,
    pub milestone: Milestone,
    pub timestamp_micros: u128,
    pub watermark: Option<Watermark>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveActiveConsistencyMode {
    ActiveSyncCausalEventual,
    ActiveSyncConsensusOrderedEventual,
    ActiveSyncGlobalOrdered,
}

impl ActiveActiveConsistencyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActiveSyncCausalEventual => "active-sync-causal-eventual",
            Self::ActiveSyncConsensusOrderedEventual => "active-sync-consensus-ordered-eventual",
            Self::ActiveSyncGlobalOrdered => "active-sync-global-ordered",
        }
    }
}

impl FromStr for ActiveActiveConsistencyMode {
    type Err = BlossomError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "active-sync-causal-eventual" => Ok(Self::ActiveSyncCausalEventual),
            "active-sync-consensus-ordered-eventual" => {
                Ok(Self::ActiveSyncConsensusOrderedEventual)
            }
            "active-sync-global-ordered" => Ok(Self::ActiveSyncGlobalOrdered),
            _ => Err(BlossomError::InvalidConfiguration(format!(
                "unknown active-active consistency mode {value:?}"
            ))),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    LocalAsync,
    GlobalFinalized,
    GlobalApplied,
}

impl WriteMode {
    pub const fn required_milestone(self) -> Milestone {
        match self {
            Self::LocalAsync => Milestone::AcceptedLocal,
            Self::GlobalFinalized => Milestone::Finalized,
            Self::GlobalApplied => Milestone::Applied,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ReadConsistency {
    Local,
    AtLeast(Watermark),
    Linearizable,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct BatchReference {
    pub format_version: u16,
    pub codec_version: u16,
    pub cluster_id: HashType,
    pub consensus_group_id: ConsensusGroupId,
    pub shard: Vec<u8>,
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
    pub origin: PubKey,
    pub origin_incarnation: u64,
    pub origin_key_generation: u64,
    pub first_origin_sequence: u64,
    pub last_origin_sequence: u64,
    pub command_count: u32,
    pub byte_length: u64,
    pub merkle_root: HashType,
    pub data_holder_membership_epoch: ReplicaMembershipEpoch,
    pub validator_generation: ValidatorGeneration,
    pub previous_origin_reference_hash: HashType,
}

#[derive(Debug, Clone)]
pub struct BatchReferenceMetadata {
    pub cluster_id: HashType,
    pub consensus_group_id: ConsensusGroupId,
    pub shard: Vec<u8>,
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
    pub origin: PubKey,
    pub origin_incarnation: u64,
    pub origin_key_generation: u64,
    pub data_holder_membership_epoch: ReplicaMembershipEpoch,
    pub validator_generation: ValidatorGeneration,
    pub previous_origin_reference_hash: HashType,
}

impl BatchReference {
    pub const FORMAT_VERSION: u16 = 2;
    pub const CODEC_VERSION: u16 = 2;

    pub fn for_batch(batch: &CommandBatch, metadata: BatchReferenceMetadata) -> Result<Self> {
        batch.validate()?;
        let bytes = batch.canonical_bytes()?;
        let first = batch
            .commands
            .first()
            .expect("validated non-empty batch")
            .origin_sequence;
        let last = batch
            .commands
            .last()
            .expect("validated non-empty batch")
            .origin_sequence;
        let command_count = u32::try_from(batch.commands.len()).map_err(|_| {
            BlossomError::InvalidConfiguration("batch command count exceeds u32".to_string())
        })?;
        let byte_length = u64::try_from(bytes.len()).map_err(|_| {
            BlossomError::InvalidConfiguration("batch byte length exceeds u64".to_string())
        })?;
        Ok(Self {
            format_version: Self::FORMAT_VERSION,
            codec_version: Self::CODEC_VERSION,
            cluster_id: metadata.cluster_id,
            consensus_group_id: metadata.consensus_group_id,
            shard: metadata.shard,
            route_generation: metadata.route_generation,
            command_spec_version: metadata.command_spec_version,
            origin: metadata.origin,
            origin_incarnation: metadata.origin_incarnation,
            origin_key_generation: metadata.origin_key_generation,
            first_origin_sequence: first,
            last_origin_sequence: last,
            command_count,
            byte_length,
            merkle_root: batch.merkle_root()?,
            data_holder_membership_epoch: metadata.data_holder_membership_epoch,
            validator_generation: metadata.validator_generation,
            previous_origin_reference_hash: metadata.previous_origin_reference_hash,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != Self::FORMAT_VERSION || self.codec_version != Self::CODEC_VERSION
        {
            return Err(BlossomError::InvalidConfiguration(
                "unsupported active-active reference format or codec".to_string(),
            ));
        }
        self.route_generation.validate()?;
        self.command_spec_version.validate()?;
        if self.command_count == 0
            || self.first_origin_sequence == 0
            || self.last_origin_sequence < self.first_origin_sequence
        {
            return Err(BlossomError::InvalidConfiguration(
                "invalid command range in batch reference".to_string(),
            ));
        }
        let range_count = self
            .last_origin_sequence
            .checked_sub(self.first_origin_sequence)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration("batch sequence range overflow".to_string())
            })?;
        if range_count != u64::from(self.command_count) || self.byte_length == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "batch range, count, or byte length mismatch".to_string(),
            ));
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<HashType> {
        self.validate()?;
        hash_borsh(REFERENCE_HASH_DOMAIN, self)
    }

    pub fn verify_batch(&self, batch: &CommandBatch) -> Result<()> {
        batch.validate()?;
        let bytes = batch.canonical_bytes()?;
        let first = batch.commands.first().unwrap().origin_sequence;
        let last = batch.commands.last().unwrap().origin_sequence;
        if self.first_origin_sequence != first
            || self.last_origin_sequence != last
            || usize::try_from(self.command_count).ok() != Some(batch.commands.len())
            || usize::try_from(self.byte_length).ok() != Some(bytes.len())
            || self.merkle_root != batch.merkle_root()?
        {
            return Err(BlossomError::InvalidConfiguration(
                "batch bytes do not match finalized reference".to_string(),
            ));
        }
        Ok(())
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.origin == other.origin
            && self.origin_incarnation == other.origin_incarnation
            && self.origin_key_generation == other.origin_key_generation
            && ranges_overlap(
                self.first_origin_sequence,
                self.last_origin_sequence,
                other.first_origin_sequence,
                other.last_origin_sequence,
            )
            && self.hash().ok() != other.hash().ok()
    }

    /// Encodes this compact reference as an opaque Blossom transaction.
    pub fn to_transaction(&self) -> Result<Transaction> {
        self.validate()?;
        let encoded = borsh::to_vec(self).map_err(encode_error)?;
        let mut payload = Vec::with_capacity(REFERENCE_TRANSACTION_DOMAIN.len() + encoded.len());
        payload.extend_from_slice(REFERENCE_TRANSACTION_DOMAIN);
        payload.extend_from_slice(&encoded);
        Ok(Transaction::new(payload))
    }

    /// Decodes an active-active reference transaction. Unrelated application
    /// transactions return `Ok(None)`.
    pub fn from_transaction(transaction: &Transaction) -> Result<Option<Self>> {
        let payload = transaction.payload.as_slice();
        let Some(encoded) = payload.strip_prefix(REFERENCE_TRANSACTION_DOMAIN) else {
            return Ok(None);
        };
        let reference = borsh::from_slice::<Self>(encoded).map_err(|error| {
            BlossomError::WireProtocol(format!("decode batch reference transaction: {error}"))
        })?;
        reference.validate()?;
        Ok(Some(reference))
    }
}

/// Extracts compact active-active references in the immutable order certified
/// by one finalized Blossom epoch.
pub fn ordered_batch_references(epoch: &Epoch) -> Result<Vec<BatchReference>> {
    if epoch.hash != HashType::hash(&epoch.body.to_bytes()) {
        return Err(BlossomError::InvalidBlockHash);
    }
    epoch.epoch_approved()?;
    ordered_batch_references_from_blocks(epoch, true)
}

/// Extracts references from an epoch that the caller observed as finalized by
/// a trusted [`crate::NodeRuntime`].
///
/// Unlike [`ordered_batch_references`], this does not claim that the standalone
/// `Epoch` is a portable cryptographic finality certificate. The trusted
/// runtime's committed chain is the authority; trusted mode adds no signature
/// or consensus round above that deterministic epoch order.
pub fn ordered_batch_references_trusted(epoch: &Epoch) -> Result<Vec<BatchReference>> {
    if epoch.hash != HashType::hash(&epoch.body.to_bytes()) {
        return Err(BlossomError::InvalidBlockHash);
    }
    ordered_batch_references_from_blocks(epoch, false)
}

fn ordered_batch_references_from_blocks(
    epoch: &Epoch,
    verify_block_signatures: bool,
) -> Result<Vec<BatchReference>> {
    let mut references = Vec::new();
    for (_, block) in epoch.body.ordered_blocks() {
        if verify_block_signatures {
            block.verify_integrity()?;
        } else {
            block.verify_unsigned_integrity()?;
        }
        for transaction in &block.body.txs {
            if let Some(reference) = BatchReference::from_transaction(transaction)? {
                if reference.consensus_group_id != epoch.body.group_id {
                    return Err(BlossomError::InvalidConfiguration(
                        "batch reference group does not match its finalized Blossom epoch"
                            .to_string(),
                    ));
                }
                references.push(reference);
            }
        }
    }
    Ok(references)
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AdmissionReceiptBody {
    pub command_identity: CommandIdentity,
    pub command_hash: HashType,
    pub origin_sequence: u64,
    pub holder: PubKey,
    pub site: SiteId,
    pub membership_epoch: ReplicaMembershipEpoch,
    pub durable_store_generation: StoreGeneration,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AdmissionReceipt {
    pub body: AdmissionReceiptBody,
    pub signature: Signature,
}

impl AdmissionReceipt {
    pub fn signed(body: AdmissionReceiptBody, signer: &SecretSigner) -> Result<Self> {
        if signer.public_key() != body.holder {
            return Err(BlossomError::KeyMismatch);
        }
        let message = signed_body_bytes(ADMISSION_RECEIPT_DOMAIN, &body)?;
        Ok(Self {
            body,
            signature: signer.sign(&message),
        })
    }

    pub fn verify(&self) -> Result<()> {
        let message = signed_body_bytes(ADMISSION_RECEIPT_DOMAIN, &self.body)?;
        self.signature.verify(&message, &self.body.holder)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LocalAdmissionPolicy {
    pub site: SiteId,
    pub membership_epoch: ReplicaMembershipEpoch,
    pub members: BTreeSet<PubKey>,
    pub store_generations: BTreeMap<PubKey, StoreGeneration>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LocalAdmissionCertificate {
    pub policy: LocalAdmissionPolicy,
    pub command_identity: CommandIdentity,
    pub command_hash: HashType,
    pub origin_sequence: u64,
    pub receipts: Vec<AdmissionReceipt>,
}

impl LocalAdmissionCertificate {
    pub fn verify(&self) -> Result<()> {
        if self.policy.members.is_empty()
            || self
                .policy
                .store_generations
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
                != self.policy.members
        {
            return Err(BlossomError::InvalidConfiguration(
                "admission policy must bind one store generation per member".to_string(),
            ));
        }
        let mut holders = BTreeSet::new();
        for receipt in &self.receipts {
            receipt.verify()?;
            if receipt.body.command_identity != self.command_identity
                || receipt.body.command_hash != self.command_hash
                || receipt.body.origin_sequence != self.origin_sequence
                || receipt.body.site != self.policy.site
                || receipt.body.membership_epoch != self.policy.membership_epoch
                || !self.policy.members.contains(&receipt.body.holder)
                || self.policy.store_generations.get(&receipt.body.holder)
                    != Some(&receipt.body.durable_store_generation)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "admission receipt does not match its frozen policy".to_string(),
                ));
            }
            holders.insert(receipt.body.holder);
        }
        if holders.len() < supermajority_count(self.policy.members.len()) {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityReceiptBody {
    pub reference_hash: HashType,
    pub holder: PubKey,
    pub site: SiteId,
    pub membership_epoch: ReplicaMembershipEpoch,
    pub durable_store_generation: StoreGeneration,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedAvailabilityReceipt {
    pub body: AvailabilityReceiptBody,
    pub signature: Signature,
}

impl AuthenticatedAvailabilityReceipt {
    pub fn signed(body: AvailabilityReceiptBody, signer: &SecretSigner) -> Result<Self> {
        if signer.public_key() != body.holder {
            return Err(BlossomError::KeyMismatch);
        }
        let message = signed_body_bytes(AVAILABILITY_RECEIPT_DOMAIN, &body)?;
        Ok(Self {
            body,
            signature: signer.sign(&message),
        })
    }

    pub fn verify(&self) -> Result<()> {
        let message = signed_body_bytes(AVAILABILITY_RECEIPT_DOMAIN, &self.body)?;
        self.signature.verify(&message, &self.body.holder)
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum AvailabilityTrust {
    Trusted,
    VerifiedClaims,
}

impl AvailabilityTrust {
    pub fn result_label(self) -> &'static str {
        match self {
            Self::Trusted => "trusted durable availability",
            Self::VerifiedClaims => "Byzantine finality with authenticated availability claims",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HolderMembership {
    pub epoch: ReplicaMembershipEpoch,
    pub members_by_site: BTreeMap<SiteId, BTreeSet<PubKey>>,
    pub store_generations: BTreeMap<PubKey, StoreGeneration>,
    pub holder_fault_bound: usize,
}

impl HolderMembership {
    pub fn validate(&self) -> Result<()> {
        if self.members_by_site.len() != 3 || self.members_by_site.values().any(BTreeSet::is_empty)
        {
            return Err(BlossomError::InvalidConfiguration(
                "availability membership requires three non-empty sites".to_string(),
            ));
        }
        let mut all_members = BTreeSet::new();
        for members in self.members_by_site.values() {
            for member in members {
                if !all_members.insert(*member) {
                    return Err(BlossomError::InvalidConfiguration(
                        "one availability holder cannot belong to multiple sites".to_string(),
                    ));
                }
            }
        }
        if self
            .store_generations
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != all_members
        {
            return Err(BlossomError::InvalidConfiguration(
                "holder membership must bind one store generation per member".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AvailabilityCertificate {
    pub reference: BatchReference,
    pub trust: AvailabilityTrust,
    pub receipts: Vec<AuthenticatedAvailabilityReceipt>,
}

impl AvailabilityCertificate {
    pub fn verify(&self, membership: &HolderMembership) -> Result<()> {
        membership.validate()?;
        self.reference.validate()?;
        if membership.epoch != self.reference.data_holder_membership_epoch {
            return Err(BlossomError::InvalidConfiguration(
                "holder membership generation mismatch".to_string(),
            ));
        }
        let reference_hash = self.reference.hash()?;
        let mut holders_by_site = BTreeMap::<SiteId, BTreeSet<PubKey>>::new();
        let mut all_holders = BTreeSet::new();
        for receipt in &self.receipts {
            receipt.verify()?;
            if receipt.body.reference_hash != reference_hash
                || receipt.body.membership_epoch != membership.epoch
            {
                return Err(BlossomError::InvalidConfiguration(
                    "availability receipt does not bind the complete reference".to_string(),
                ));
            }
            let Some(site_members) = membership.members_by_site.get(&receipt.body.site) else {
                return Err(BlossomError::UnknownSender);
            };
            if !site_members.contains(&receipt.body.holder)
                || membership.store_generations.get(&receipt.body.holder)
                    != Some(&receipt.body.durable_store_generation)
                || !all_holders.insert(receipt.body.holder)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate or ineligible availability holder".to_string(),
                ));
            }
            holders_by_site
                .entry(receipt.body.site.clone())
                .or_default()
                .insert(receipt.body.holder);
        }

        let certified_sites = membership
            .members_by_site
            .iter()
            .filter(|(site, members)| {
                let count = holders_by_site.get(*site).map_or(0, BTreeSet::len);
                let required = match self.trust {
                    AvailabilityTrust::Trusted => supermajority_count(members.len()),
                    AvailabilityTrust::VerifiedClaims => membership
                        .holder_fault_bound
                        .checked_mul(2)
                        .and_then(|value| value.checked_add(1))
                        .unwrap_or(usize::MAX),
                };
                count >= required
            })
            .count();
        if certified_sites < 2 {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    pub fn holders(&self) -> BTreeSet<PubKey> {
        self.receipts
            .iter()
            .map(|receipt| receipt.body.holder)
            .collect()
    }

    pub fn repair_targets(&self, membership: &HolderMembership) -> Result<BTreeSet<PubKey>> {
        membership.validate()?;
        if membership.epoch != self.reference.data_holder_membership_epoch {
            return Err(BlossomError::InvalidConfiguration(
                "holder membership generation mismatch".to_string(),
            ));
        }
        let holders = self.holders();
        let mut repair_targets = BTreeSet::new();
        for members in membership.members_by_site.values() {
            let required = match self.trust {
                AvailabilityTrust::Trusted => supermajority_count(members.len()),
                AvailabilityTrust::VerifiedClaims => membership
                    .holder_fault_bound
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "holder repair threshold overflow".to_string(),
                        )
                    })?,
            };
            let present = members.intersection(&holders).count();
            repair_targets.extend(
                members
                    .difference(&holders)
                    .take(required.saturating_sub(present))
                    .copied(),
            );
        }
        Ok(repair_targets)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct OrderStatement {
    pub consensus_group_id: ConsensusGroupId,
    /// Hash of the Blossom epoch that fixed this reference's immutable order.
    pub blossom_epoch_hash: HashType,
    pub position: Watermark,
    pub reference_hash: HashType,
    pub previous_order_certificate_hash: HashType,
    pub validator_generation: ValidatorGeneration,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct OrderCertificate {
    pub statement: OrderStatement,
    pub signatures: BTreeMap<PubKey, Signature>,
}

impl OrderCertificate {
    pub fn signing_bytes(statement: &OrderStatement) -> Result<Vec<u8>> {
        signed_body_bytes(ORDER_STATEMENT_DOMAIN, statement)
    }

    pub fn verify(
        &self,
        validator_generation: ValidatorGeneration,
        validators: &BTreeSet<PubKey>,
    ) -> Result<()> {
        if self.statement.validator_generation != validator_generation
            || self.statement.position.position == 0
            || self.statement.blossom_epoch_hash == HashType::default()
            || self.signatures.len() > validators.len()
        {
            return Err(BlossomError::FailedConsensus);
        }
        let message = Self::signing_bytes(&self.statement)?;
        let mut valid = 0usize;
        for (validator, signature) in &self.signatures {
            if !validators.contains(validator) {
                return Err(BlossomError::UnknownSender);
            }
            signature.verify(&message, validator)?;
            valid += 1;
        }
        if !has_supermajority(validators.len(), valid) {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    fn trusted(statement: OrderStatement) -> Self {
        Self {
            statement,
            signatures: BTreeMap::new(),
        }
    }

    fn verify_trusted(&self, validator_generation: ValidatorGeneration) -> Result<()> {
        if self.statement.validator_generation != validator_generation
            || self.statement.position.position == 0
            || self.statement.blossom_epoch_hash == HashType::default()
            || !self.signatures.is_empty()
        {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    pub fn from_votes(
        statement: OrderStatement,
        votes: impl IntoIterator<Item = OrderVote>,
    ) -> Result<Self> {
        let mut signatures = BTreeMap::new();
        for vote in votes {
            if vote.statement != statement {
                return Err(BlossomError::InvalidConfiguration(
                    "order vote does not match the certificate statement".to_string(),
                ));
            }
            if signatures.insert(vote.validator, vote.signature).is_some() {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate validator order vote".to_string(),
                ));
            }
        }
        Ok(Self {
            statement,
            signatures,
        })
    }

    pub fn hash(&self) -> Result<HashType> {
        hash_borsh(ORDER_CERTIFICATE_DOMAIN, self)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct OrderVote {
    pub statement: OrderStatement,
    pub validator: PubKey,
    pub signature: Signature,
}

impl OrderVote {
    pub fn verify(&self) -> Result<()> {
        self.signature.verify(
            &OrderCertificate::signing_bytes(&self.statement)?,
            &self.validator,
        )
    }
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
pub struct ReadBarrierChallenge(pub [u8; 32]);

impl ReadBarrierChallenge {
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadBarrierRequest {
    pub challenge: ReadBarrierChallenge,
}

impl ReadBarrierRequest {
    pub fn fresh() -> Self {
        Self {
            challenge: ReadBarrierChallenge::random(),
        }
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReadBarrierStatement {
    pub cluster_id: HashType,
    pub consensus_group_id: ConsensusGroupId,
    pub validator_generation: ValidatorGeneration,
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
    pub challenge: ReadBarrierChallenge,
    pub position: Watermark,
    pub order_certificate_hash: HashType,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReadBarrierVote {
    pub statement: ReadBarrierStatement,
    pub validator: PubKey,
    pub signature: Signature,
}

impl ReadBarrierVote {
    pub fn verify(&self) -> Result<()> {
        self.signature.verify(
            &ReadBarrierCertificate::signing_bytes(&self.statement)?,
            &self.validator,
        )
    }
}

/// A fresh quorum observation of the global order head.
///
/// Freshness is relative to the caller-generated challenge. Reusing a
/// challenge intentionally permits replay, so callers must generate a new
/// challenge for every linearizable read attempt.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReadBarrierCertificate {
    pub statement: ReadBarrierStatement,
    pub signatures: BTreeMap<PubKey, Signature>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CertifiedReadBarrier {
    pub request: ReadBarrierRequest,
    pub certificate: ReadBarrierCertificate,
}

impl ReadBarrierCertificate {
    pub fn signing_bytes(statement: &ReadBarrierStatement) -> Result<Vec<u8>> {
        signed_body_bytes(READ_BARRIER_STATEMENT_DOMAIN, statement)
    }

    pub fn from_votes(
        statement: ReadBarrierStatement,
        votes: impl IntoIterator<Item = ReadBarrierVote>,
    ) -> Result<Self> {
        let mut signatures = BTreeMap::new();
        for vote in votes {
            if vote.statement != statement {
                return Err(BlossomError::InvalidConfiguration(
                    "read-barrier vote does not match the certificate statement".to_string(),
                ));
            }
            vote.verify()?;
            if signatures.insert(vote.validator, vote.signature).is_some() {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate validator read-barrier vote".to_string(),
                ));
            }
        }
        Ok(Self {
            statement,
            signatures,
        })
    }

    pub fn verify(
        &self,
        expected_challenge: ReadBarrierChallenge,
        validator_generation: ValidatorGeneration,
        validators: &BTreeSet<PubKey>,
    ) -> Result<()> {
        if self.statement.challenge != expected_challenge
            || self.statement.validator_generation != validator_generation
            || self.signatures.len() > validators.len()
        {
            return Err(BlossomError::FailedConsensus);
        }
        self.statement.route_generation.validate()?;
        self.statement.command_spec_version.validate()?;
        if (self.statement.position == Watermark::default())
            != (self.statement.order_certificate_hash == HashType::default())
        {
            return Err(BlossomError::FailedConsensus);
        }
        let message = Self::signing_bytes(&self.statement)?;
        let mut valid = 0usize;
        for (validator, signature) in &self.signatures {
            if !validators.contains(validator) {
                return Err(BlossomError::UnknownSender);
            }
            signature.verify(&message, validator)?;
            valid += 1;
        }
        if !has_supermajority(validators.len(), valid) {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<HashType> {
        hash_borsh(READ_BARRIER_CERTIFICATE_DOMAIN, self)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AppliedCompletion {
    pub reference_hash: HashType,
    pub watermark: Watermark,
    pub results: Vec<ApplicationResult>,
}

impl AppliedCompletion {
    fn validate(&self, expected_command_count: Option<usize>) -> Result<()> {
        if self.watermark.position == 0
            || expected_command_count.is_some_and(|count| count != self.results.len())
        {
            return Err(BlossomError::InvalidConfiguration(
                "applied completion watermark or result count is invalid".to_string(),
            ));
        }
        let mut total_bytes = 0usize;
        for result in &self.results {
            result.validate()?;
            total_bytes = total_bytes
                .checked_add(result.as_bytes().len())
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "application completion result size overflow".to_string(),
                    )
                })?;
        }
        if total_bytes > MAX_APPLICATION_RESULT_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "application completion results exceed {MAX_APPLICATION_RESULT_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ReferenceStatus {
    Unknown,
    Pending(MilestoneEvent),
    Applied(AppliedCompletion),
}

impl ReferenceStatus {
    pub fn reached(&self, target: Milestone) -> bool {
        match self {
            Self::Unknown => false,
            Self::Pending(event) => event.milestone.reaches(target),
            Self::Applied(_) => true,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Applied(_))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WaitForOutcome {
    Reached(ReferenceStatus),
    TimedOut(ReferenceStatus),
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationContractActivation {
    pub previous_route_generation: RouteGeneration,
    pub route_generation: RouteGeneration,
    pub previous_command_spec_version: CommandSpecVersion,
    pub command_spec_version: CommandSpecVersion,
    pub activated_at: Watermark,
}

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
pub struct DurableAdmissionStore {
    store: BlossomLogStore,
    holder: PubKey,
    site: SiteId,
    store_generation: StoreGeneration,
    signer: SecretSigner,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveActiveDurabilityMetrics {
    pub commit_count: u64,
    pub fsync_count: u64,
}

impl DurableAdmissionStore {
    pub fn open(
        path: impl AsRef<Path>,
        site: SiteId,
        store_generation: StoreGeneration,
        signer: SecretSigner,
    ) -> Result<Self> {
        let holder = signer.public_key();
        let public_scope =
            borsh::to_vec(&(holder, site.clone(), store_generation)).map_err(encode_error)?;
        let identity =
            BlossomLogStoreIdentity::new("active-active", public_scope, store_generation.0)?;
        let log_store = BlossomLogStore::open(BlossomLogStoreConfig::new(path.as_ref()), identity)?;
        let store = Self {
            store: log_store,
            holder,
            site,
            store_generation,
            signer,
        };
        store.initialize_identity()?;
        Ok(store)
    }

    pub fn log_store(&self) -> BlossomLogStore {
        self.store.clone()
    }

    fn initialize_identity(&self) -> Result<()> {
        self.transact(|transaction| {
            if let Some(encoded) =
                transaction.get(STORE_IDENTITY_TABLE, STORE_IDENTITY_KEY.as_bytes())?
            {
                let identity =
                    borsh::from_slice::<DurableStoreIdentity>(&encoded).map_err(|error| {
                        BlossomError::WireProtocol(format!(
                            "decode active-active store identity: {error}"
                        ))
                    })?;
                identity.validate_startup(self.holder, &self.site, self.store_generation)?;
            } else {
                let identity = DurableStoreIdentity::new(
                    self.holder,
                    self.site.clone(),
                    self.store_generation,
                );
                transaction.insert(
                    STORE_IDENTITY_TABLE,
                    STORE_IDENTITY_KEY.as_bytes().to_vec(),
                    borsh::to_vec(&identity).map_err(encode_error)?,
                )?;
            }
            Ok(())
        })
    }

    pub fn durability_metrics(&self) -> ActiveActiveDurabilityMetrics {
        let metrics = self.store.durability_metrics();
        ActiveActiveDurabilityMetrics {
            commit_count: metrics.committed_transactions,
            fsync_count: metrics.fsyncs,
        }
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut BlossomLogTransaction<'_>) -> Result<T>,
    ) -> Result<T> {
        self.store.transaction(operation).map(|(result, _)| result)
    }

    fn bind_protocol_scope(
        &self,
        cluster_id: HashType,
        consensus_group_id: ConsensusGroupId,
    ) -> Result<()> {
        self.transact(|transaction| {
            self.bind_protocol_scope_in_transaction(transaction, cluster_id, consensus_group_id)?;
            Ok(())
        })
    }

    fn protocol_scope(&self) -> Result<Option<(HashType, ConsensusGroupId)>> {
        let encoded = self
            .store
            .get(STORE_IDENTITY_TABLE, STORE_IDENTITY_KEY.as_bytes())?
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active store identity is missing".to_string(),
                )
            })?;
        let identity = borsh::from_slice::<DurableStoreIdentity>(&encoded).map_err(|error| {
            BlossomError::WireProtocol(format!("decode active-active store identity: {error}"))
        })?;
        identity.validate_startup(self.holder, &self.site, self.store_generation)?;
        match (identity.cluster_id, identity.consensus_group_id) {
            (Some(cluster_id), Some(consensus_group_id)) => {
                Ok(Some((cluster_id, consensus_group_id)))
            }
            (None, None) => Ok(None),
            _ => Err(BlossomError::InvalidConfiguration(
                "active-active store has a partially bound protocol scope".to_string(),
            )),
        }
    }

    fn bind_protocol_scope_in_transaction(
        &self,
        transaction: &mut BlossomLogTransaction<'_>,
        cluster_id: HashType,
        consensus_group_id: ConsensusGroupId,
    ) -> Result<bool> {
        let encoded = transaction
            .get(STORE_IDENTITY_TABLE, STORE_IDENTITY_KEY.as_bytes())?
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active store identity is missing".to_string(),
                )
            })?;
        let mut identity =
            borsh::from_slice::<DurableStoreIdentity>(&encoded).map_err(|error| {
                BlossomError::WireProtocol(format!("decode active-active store identity: {error}"))
            })?;
        identity.validate_startup(self.holder, &self.site, self.store_generation)?;
        match (identity.cluster_id, identity.consensus_group_id) {
            (None, None) => {
                identity.cluster_id = Some(cluster_id);
                identity.consensus_group_id = Some(consensus_group_id);
                transaction.insert(
                    STORE_IDENTITY_TABLE,
                    STORE_IDENTITY_KEY.as_bytes().to_vec(),
                    borsh::to_vec(&identity).map_err(encode_error)?,
                )?;
                Ok(true)
            }
            (Some(existing_cluster), Some(existing_group))
                if existing_cluster == cluster_id && existing_group == consensus_group_id =>
            {
                Ok(false)
            }
            _ => Err(BlossomError::InvalidConfiguration(
                "active-active store protocol scope does not match cluster or group".to_string(),
            )),
        }
    }

    pub fn admit(
        &self,
        command: &AdmittedCommand,
        membership_epoch: ReplicaMembershipEpoch,
    ) -> Result<AdmissionReceipt> {
        command.command.validate()?;
        if command.origin_sequence == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "origin sequences start at one".to_string(),
            ));
        }
        let command_hash = command.command.hash()?;
        let identity_key = borsh::to_vec(&command.command.identity).map_err(encode_error)?;
        let command_key = borsh::to_vec(&(command.origin_sequence, command.command.identity))
            .map_err(encode_error)?;
        let command_bytes = borsh::to_vec(command).map_err(encode_error)?;

        self.transact(|transaction| {
            if let Some(existing) =
                transaction.get(COMMAND_IDENTITIES_TABLE, identity_key.as_slice())?
            {
                if existing.as_slice() != command_hash.as_ref() {
                    return Err(BlossomError::InvalidConfiguration(
                        "conflicting bytes for one command identity".to_string(),
                    ));
                }
            } else {
                transaction.insert(
                    COMMAND_IDENTITIES_TABLE,
                    identity_key,
                    command_hash.as_ref().to_vec(),
                )?;
            }
            transaction.insert(COMMANDS_TABLE, command_key, command_bytes)?;
            Ok(())
        })?;

        AdmissionReceipt::signed(
            AdmissionReceiptBody {
                command_identity: command.command.identity,
                command_hash,
                origin_sequence: command.origin_sequence,
                holder: self.holder,
                site: self.site.clone(),
                membership_epoch,
                durable_store_generation: self.store_generation,
            },
            &self.signer,
        )
    }

    pub fn store_batch(
        &self,
        reference: &BatchReference,
        batch: &CommandBatch,
    ) -> Result<AuthenticatedAvailabilityReceipt> {
        reference.verify_batch(batch)?;
        let reference_hash = reference.hash()?;
        let bytes = batch.canonical_bytes()?;
        self.transact(|transaction| {
            self.bind_protocol_scope_in_transaction(
                transaction,
                reference.cluster_id,
                reference.consensus_group_id,
            )?;
            transaction.insert(BATCHES_TABLE, reference_hash.as_ref().to_vec(), bytes)?;
            Ok(())
        })?;

        AuthenticatedAvailabilityReceipt::signed(
            AvailabilityReceiptBody {
                reference_hash,
                holder: self.holder,
                site: self.site.clone(),
                membership_epoch: reference.data_holder_membership_epoch,
                durable_store_generation: self.store_generation,
            },
            &self.signer,
        )
    }

    pub fn load_batch(&self, reference: &BatchReference) -> Result<Option<CommandBatch>> {
        let hash = reference.hash()?;
        let Some(bytes) = self.store.get(BATCHES_TABLE, hash.as_ref())? else {
            return Ok(None);
        };
        let batch = borsh::from_slice::<CommandBatch>(&bytes).map_err(|err| {
            BlossomError::WireProtocol(format!("decode durable command batch: {err}"))
        })?;
        reference.verify_batch(&batch)?;
        Ok(Some(batch))
    }

    pub fn repair_batch_from(
        &self,
        source: &DurableAdmissionStore,
        reference: &BatchReference,
    ) -> Result<AuthenticatedAvailabilityReceipt> {
        let batch = source.load_batch(reference)?.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "repair source does not possess the referenced batch".to_string(),
            )
        })?;
        self.store_batch(reference, &batch)
    }

    pub fn collect_batch(
        &self,
        reference: &BatchReference,
        position: Watermark,
        evidence: &RetentionEvidence,
    ) -> Result<bool> {
        if !evidence.permits_collection(position) {
            return Err(BlossomError::InvalidConfiguration(
                "batch retention evidence does not cover the applied position".to_string(),
            ));
        }
        let hash = reference.hash()?;
        let removed = self.transact(|transaction| {
            let removed = transaction.get(BATCHES_TABLE, hash.as_ref())?.is_some();
            transaction.remove(BATCHES_TABLE, hash.as_ref().to_vec())?;
            Ok(removed)
        })?;
        Ok(removed)
    }

    pub fn record_milestone(&self, event: &MilestoneEvent) -> Result<u64> {
        if event.milestone == Milestone::Applied {
            return Err(BlossomError::InvalidConfiguration(
                "Applied must be recorded atomically with an applied completion".to_string(),
            ));
        }
        let bytes = borsh::to_vec(event).map_err(encode_error)?;
        self.transact(|transaction| {
            let sequence = transaction
                .get(META_TABLE, b"next_milestone_sequence")?
                .map(|value| decode_u64(&value, "next milestone sequence"))
                .transpose()?
                .unwrap_or(0);
            let next = sequence.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("milestone sequence overflow".to_string())
            })?;
            transaction.insert(
                META_TABLE,
                b"next_milestone_sequence".to_vec(),
                next.to_be_bytes().to_vec(),
            )?;
            transaction.insert(
                MILESTONES_TABLE,
                sequence.to_be_bytes().to_vec(),
                bytes.clone(),
            )?;
            if let Some(existing) =
                transaction.get(REFERENCE_STATUS_TABLE, event.reference_hash.as_ref())?
            {
                let existing =
                    borsh::from_slice::<MilestoneEvent>(&existing).map_err(encode_error)?;
                if existing.milestone.rank() > event.milestone.rank() {
                    return Err(BlossomError::InvalidConfiguration(
                        "reference milestone cannot regress".to_string(),
                    ));
                }
            }
            transaction.insert(
                REFERENCE_STATUS_TABLE,
                event.reference_hash.as_ref().to_vec(),
                bytes,
            )?;
            Ok(sequence)
        })
    }

    /// Durably records one validator vote before returning its signature.
    ///
    /// The `(consensus group, validator generation, position)` key may only be
    /// associated with one statement hash, including across process restarts.
    pub fn sign_order_statement(&self, statement: &OrderStatement) -> Result<OrderVote> {
        if statement.position.position == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "order positions start at one".to_string(),
            ));
        }
        let vote_key = borsh::to_vec(&(
            statement.consensus_group_id,
            statement.validator_generation,
            statement.position,
        ))
        .map_err(encode_error)?;
        let statement_hash = hash_borsh(ORDER_VOTE_HASH_DOMAIN, statement)?;
        self.transact(|transaction| {
            if let Some(existing) = transaction.get(ORDER_VOTES_TABLE, vote_key.as_slice())? {
                if existing.as_slice() != statement_hash.as_ref() {
                    return Err(BlossomError::InvalidConfiguration(
                        "validator refuses to equivocate at one order position".to_string(),
                    ));
                }
            } else {
                transaction.insert(
                    ORDER_VOTES_TABLE,
                    vote_key,
                    statement_hash.as_ref().to_vec(),
                )?;
            }
            Ok(())
        })?;
        let signature = self
            .signer
            .sign(&OrderCertificate::signing_bytes(statement)?);
        Ok(OrderVote {
            statement: statement.clone(),
            validator: self.holder,
            signature,
        })
    }

    /// Durably locks one response per caller challenge before returning a
    /// validator signature. This prevents a restarted validator from signing
    /// conflicting order heads for the same freshness challenge.
    pub fn sign_read_barrier_statement(
        &self,
        statement: &ReadBarrierStatement,
    ) -> Result<ReadBarrierVote> {
        let vote_key = borsh::to_vec(&(
            statement.consensus_group_id,
            statement.validator_generation,
            statement.challenge,
        ))
        .map_err(encode_error)?;
        let statement_hash = hash_borsh(READ_BARRIER_VOTE_HASH_DOMAIN, statement)?;
        self.transact(|transaction| {
            if let Some(existing) =
                transaction.get(READ_BARRIER_VOTES_TABLE, vote_key.as_slice())?
            {
                if existing.as_slice() != statement_hash.as_ref() {
                    return Err(BlossomError::InvalidConfiguration(
                        "validator refuses to equivocate for one read-barrier challenge"
                            .to_string(),
                    ));
                }
            } else {
                transaction.insert(
                    READ_BARRIER_VOTES_TABLE,
                    vote_key,
                    statement_hash.as_ref().to_vec(),
                )?;
            }
            Ok(())
        })?;
        Ok(ReadBarrierVote {
            statement: statement.clone(),
            validator: self.holder,
            signature: self
                .signer
                .sign(&ReadBarrierCertificate::signing_bytes(statement)?),
        })
    }

    pub fn milestones(&self) -> Result<Vec<MilestoneEvent>> {
        self.store
            .scan(MILESTONES_TABLE)?
            .into_iter()
            .map(|(_, value)| {
                borsh::from_slice(&value).map_err(|err| {
                    BlossomError::WireProtocol(format!("decode milestone event: {err}"))
                })
            })
            .collect()
    }

    pub fn reference_status(&self, reference_hash: HashType) -> Result<ReferenceStatus> {
        if let Some(bytes) = self
            .store
            .get(APPLIED_COMPLETIONS_TABLE, reference_hash.as_ref())?
        {
            let completion = borsh::from_slice::<AppliedCompletion>(&bytes).map_err(|error| {
                BlossomError::WireProtocol(format!("decode applied completion: {error}"))
            })?;
            completion.validate(None)?;
            if completion.reference_hash != reference_hash {
                return Err(BlossomError::InvalidConfiguration(
                    "applied-completion table key does not match its record".to_string(),
                ));
            }
            return Ok(ReferenceStatus::Applied(completion));
        }
        let Some(bytes) = self
            .store
            .get(REFERENCE_STATUS_TABLE, reference_hash.as_ref())?
        else {
            return Ok(ReferenceStatus::Unknown);
        };
        let event = borsh::from_slice::<MilestoneEvent>(&bytes).map_err(|error| {
            BlossomError::WireProtocol(format!("decode reference status: {error}"))
        })?;
        if event.reference_hash != reference_hash || event.milestone == Milestone::Applied {
            return Err(BlossomError::InvalidConfiguration(
                "reference-status table is inconsistent with its applied completion".to_string(),
            ));
        }
        Ok(ReferenceStatus::Pending(event))
    }

    pub fn wait_for(
        &self,
        reference_hash: HashType,
        target: Milestone,
        timeout: Duration,
    ) -> Result<WaitForOutcome> {
        if timeout > MAX_WAIT_FOR_TIMEOUT {
            return Err(BlossomError::InvalidConfiguration(format!(
                "wait timeout exceeds the {} second bound",
                MAX_WAIT_FOR_TIMEOUT.as_secs()
            )));
        }
        let started = Instant::now();
        loop {
            let status = self.reference_status(reference_hash)?;
            if status.reached(target) {
                return Ok(WaitForOutcome::Reached(status));
            }
            if status.is_terminal() || started.elapsed() >= timeout {
                return Ok(WaitForOutcome::TimedOut(status));
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(WaitForOutcome::TimedOut(status));
            }
            thread::sleep(WAIT_FOR_POLL_INTERVAL.min(remaining));
        }
    }

    fn persist_ordered_delta(
        &self,
        delta: &OrderedStateDelta,
        milestones: &[MilestoneEvent],
        completion: Option<&AppliedCompletion>,
    ) -> Result<()> {
        let completion_bytes = completion
            .map(borsh::to_vec)
            .transpose()
            .map_err(encode_error)?;
        let metadata_bytes = borsh::to_vec(&delta.metadata).map_err(encode_error)?;
        let milestone_bytes = milestones
            .iter()
            .map(borsh::to_vec)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(encode_error)?;
        self.transact(|transaction| {
            transaction.insert(
                ORDERED_METADATA_TABLE,
                ORDERED_METADATA_KEY.as_bytes().to_vec(),
                metadata_bytes,
            )?;
            for hash in &delta.available_removals {
                transaction.remove(AVAILABLE_REFERENCES_TABLE, hash.as_ref().to_vec())?;
            }
            for (hash, certificate) in &delta.available_upserts {
                transaction.insert(
                    AVAILABLE_REFERENCES_TABLE,
                    hash.as_ref().to_vec(),
                    borsh::to_vec(certificate).map_err(encode_error)?,
                )?;
            }
            for (position, certificate) in &delta.finalized_upserts {
                transaction.insert(
                    FINALIZED_POSITIONS_TABLE,
                    position.to_be_bytes().to_vec(),
                    borsh::to_vec(certificate).map_err(encode_error)?,
                )?;
            }
            for (position, reference_hash) in &delta.position_upserts {
                transaction.insert(
                    POSITION_REFERENCES_TABLE,
                    position.to_be_bytes().to_vec(),
                    borsh::to_vec(reference_hash).map_err(encode_error)?,
                )?;
            }
            for (origin, tail) in &delta.origin_tail_upserts {
                transaction.insert(
                    ORIGIN_TAILS_TABLE,
                    borsh::to_vec(origin).map_err(encode_error)?,
                    borsh::to_vec(tail).map_err(encode_error)?,
                )?;
            }
            if !milestone_bytes.is_empty() {
                let mut sequence = transaction
                    .get(META_TABLE, b"next_milestone_sequence")?
                    .map(|value| decode_u64(&value, "next milestone sequence"))
                    .transpose()?
                    .unwrap_or(0);
                for (event, event_bytes) in milestones.iter().zip(&milestone_bytes) {
                    transaction.insert(
                        MILESTONES_TABLE,
                        sequence.to_be_bytes().to_vec(),
                        event_bytes.clone(),
                    )?;
                    transaction.insert(
                        REFERENCE_STATUS_TABLE,
                        event.reference_hash.as_ref().to_vec(),
                        event_bytes.clone(),
                    )?;
                    sequence = sequence.checked_add(1).ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "milestone sequence overflow".to_string(),
                        )
                    })?;
                }
                transaction.insert(
                    META_TABLE,
                    b"next_milestone_sequence".to_vec(),
                    sequence.to_be_bytes().to_vec(),
                )?;
            }
            if let (Some(completion), Some(completion_bytes)) = (completion, completion_bytes) {
                transaction.insert(
                    APPLIED_COMPLETIONS_TABLE,
                    completion.reference_hash.as_ref().to_vec(),
                    completion_bytes,
                )?;
            }
            Ok(())
        })
    }

    fn load_ordered_state(&self) -> Result<Option<DurableOrderedState>> {
        let Some(metadata_bytes) = self
            .store
            .get(ORDERED_METADATA_TABLE, ORDERED_METADATA_KEY.as_bytes())?
        else {
            return Ok(None);
        };
        let metadata =
            borsh::from_slice::<DurableOrderedMetadata>(&metadata_bytes).map_err(|err| {
                BlossomError::WireProtocol(format!("decode ordered-engine metadata: {err}"))
            })?;

        let available = self
            .store
            .scan(AVAILABLE_REFERENCES_TABLE)?
            .into_iter()
            .map(|(key, value)| {
                let certificate =
                    borsh::from_slice::<AvailabilityCertificate>(&value).map_err(|error| {
                        BlossomError::WireProtocol(format!("decode available reference: {error}"))
                    })?;
                if certificate.reference.hash()?.as_ref() != key.as_slice() {
                    return Err(BlossomError::InvalidConfiguration(
                        "available-reference table key does not match certificate".to_string(),
                    ));
                }
                Ok((certificate.reference.hash()?, certificate))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let finalized = self
            .store
            .scan(FINALIZED_POSITIONS_TABLE)?
            .into_iter()
            .map(|(position, value)| {
                let position = decode_u64(&position, "finalized position")?;
                let certificate =
                    borsh::from_slice::<OrderCertificate>(&value).map_err(|error| {
                        BlossomError::WireProtocol(format!(
                            "decode finalized order certificate: {error}"
                        ))
                    })?;
                Ok((position, certificate))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let final_reference_by_position = self
            .store
            .scan(POSITION_REFERENCES_TABLE)?
            .into_iter()
            .map(|(position, value)| {
                let position = decode_u64(&position, "finalized reference position")?;
                let reference_hash = borsh::from_slice::<HashType>(&value).map_err(|error| {
                    BlossomError::WireProtocol(format!("decode finalized reference hash: {error}"))
                })?;
                Ok((position, reference_hash))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let last_origin_reference = self
            .store
            .scan(ORIGIN_TAILS_TABLE)?
            .into_iter()
            .map(|(key, value)| {
                let origin = borsh::from_slice::<(PubKey, u64, u64)>(&key).map_err(|error| {
                    BlossomError::WireProtocol(format!("decode origin-tail key: {error}"))
                })?;
                let tail = borsh::from_slice::<(HashType, u64)>(&value).map_err(|error| {
                    BlossomError::WireProtocol(format!("decode origin-tail value: {error}"))
                })?;
                Ok((origin, tail))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(Some(DurableOrderedState {
            version: metadata.version,
            holder_membership_epoch: metadata.holder_membership_epoch,
            validator_generation: metadata.validator_generation,
            route_generation: metadata.route_generation,
            command_spec_version: metadata.command_spec_version,
            available,
            finalized,
            final_reference_by_position,
            last_origin_reference,
            last_finalized_position: metadata.last_finalized_position,
            last_order_certificate_hash: metadata.last_order_certificate_hash,
            applied_watermark: metadata.applied_watermark,
        }))
    }
}

/// One immutable, globally ordered batch delivered to an embedding application.
///
/// `reference_hash` and `watermark` form the replay key. Implementations of
/// [`OrderedApplication`] must durably deduplicate that key because a process
/// failure after the callback commits but before Blossom commits its own state
/// can cause the callback to be invoked again after restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedBatch {
    pub reference_hash: HashType,
    pub reference: BatchReference,
    pub batch: CommandBatch,
    pub watermark: Watermark,
}

/// Application-owned state-machine hook for direct Blossom integrations.
///
/// `shard-kv`, `shard-stream`, and other consumers implement this trait in
/// their own crates. The callback is invoked in certified order and must be
/// idempotent for the supplied `(reference_hash, watermark)` replay key.
pub trait OrderedApplication {
    fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyProgress {
    Applied {
        watermark: Watermark,
        completions: Vec<AppliedCompletion>,
    },
    HeadOfLineUnavailable {
        watermark: Watermark,
        blocked_reference: HashType,
    },
}

pub struct GlobalOrderedEngine {
    store: DurableAdmissionStore,
    mode: ActiveActiveConsistencyMode,
    holder_membership: HolderMembership,
    validator_generation: ValidatorGeneration,
    validators: BTreeSet<PubKey>,
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

impl GlobalOrderedEngine {
    pub fn new(
        store: DurableAdmissionStore,
        mode: ActiveActiveConsistencyMode,
        holder_membership: HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: BTreeSet<PubKey>,
        _max_reorder: u64,
    ) -> Result<Self> {
        Self::new_with_application_contract(
            store,
            mode,
            holder_membership,
            validator_generation,
            validators,
            TrustMode::Verified,
            RouteGeneration(1),
            CommandSpecVersion(1),
        )
    }

    pub fn new_with_trust_mode(
        store: DurableAdmissionStore,
        mode: ActiveActiveConsistencyMode,
        holder_membership: HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: BTreeSet<PubKey>,
        order_trust_mode: TrustMode,
        _max_reorder: u64,
    ) -> Result<Self> {
        Self::new_with_application_contract(
            store,
            mode,
            holder_membership,
            validator_generation,
            validators,
            order_trust_mode,
            RouteGeneration(1),
            CommandSpecVersion(1),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_application_contract(
        store: DurableAdmissionStore,
        mode: ActiveActiveConsistencyMode,
        holder_membership: HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: BTreeSet<PubKey>,
        order_trust_mode: TrustMode,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<Self> {
        if mode != ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered {
            return Err(BlossomError::InvalidConfiguration(
                "GlobalOrderedEngine requires active-sync-global-ordered mode".to_string(),
            ));
        }
        holder_membership.validate()?;
        if holder_membership
            .members_by_site
            .get(&store.site)
            .is_none_or(|members| !members.contains(&store.holder))
            || holder_membership.store_generations.get(&store.holder)
                != Some(&store.store_generation)
        {
            return Err(BlossomError::InvalidConfiguration(
                "ordered-engine store identity is not a holder in the committed membership"
                    .to_string(),
            ));
        }
        if validators.is_empty() {
            return Err(BlossomError::InvalidConfiguration(
                "global ordering requires at least one validator".to_string(),
            ));
        }
        if validators.len() > MAX_REFERENCES_PER_ORDERING_WINDOW {
            return Err(BlossomError::InvalidConfiguration(format!(
                "validator count exceeds the per-window reference limit of \
                 {MAX_REFERENCES_PER_ORDERING_WINDOW}"
            )));
        }
        route_generation.validate()?;
        command_spec_version.validate()?;
        let loaded_ordered = store.load_ordered_state()?;
        let mut engine = Self {
            store,
            mode,
            holder_membership,
            validator_generation,
            validators,
            order_trust_mode,
            available: BTreeMap::new(),
            finalized: BTreeMap::new(),
            final_reference_by_position: BTreeMap::new(),
            finalized_reference_hashes: BTreeSet::new(),
            last_origin_reference: BTreeMap::new(),
            last_finalized_position: 0,
            last_order_certificate_hash: HashType::default(),
            applied_watermark: Watermark::default(),
            route_generation,
            command_spec_version,
            telemetry: TelemetryHandle::default(),
        };
        if let Some(state) = loaded_ordered {
            engine.validate_durable_state(&state)?;
            engine.install_durable_state(state);
        }
        Ok(engine)
    }

    pub fn with_telemetry(mut self, telemetry: TelemetryHandle) -> Self {
        self.telemetry = telemetry;
        self
    }

    pub fn set_telemetry(&mut self, telemetry: TelemetryHandle) {
        self.telemetry = telemetry;
    }

    pub fn telemetry(&self) -> &TelemetryHandle {
        &self.telemetry
    }

    /// Activates a new route and/or application command specification at a
    /// quiescent applied boundary. The next `BatchReference` must commit the
    /// new values.
    pub fn activate_application_contract(
        &mut self,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<ApplicationContractActivation> {
        route_generation.validate()?;
        command_spec_version.validate()?;
        if !self.available.is_empty()
            || self.applied_watermark.position != self.last_finalized_position
        {
            return Err(BlossomError::InvalidConfiguration(
                "application-contract activation requires no available or unapplied references"
                    .to_string(),
            ));
        }
        if route_generation.0 < self.route_generation.0
            || command_spec_version.0 < self.command_spec_version.0
            || (route_generation == self.route_generation
                && command_spec_version == self.command_spec_version)
        {
            return Err(BlossomError::InvalidConfiguration(
                "application-contract activation must monotonically advance route or command-spec version"
                    .to_string(),
            ));
        }
        let activation = ApplicationContractActivation {
            previous_route_generation: self.route_generation,
            route_generation,
            previous_command_spec_version: self.command_spec_version,
            command_spec_version,
            activated_at: self.applied_watermark,
        };
        let mut metadata = self.durable_metadata();
        metadata.route_generation = route_generation;
        metadata.command_spec_version = command_spec_version;
        self.store
            .persist_ordered_delta(&OrderedStateDelta::new(metadata), &[], None)?;
        self.route_generation = route_generation;
        self.command_spec_version = command_spec_version;
        Ok(activation)
    }

    pub fn accept_local(&self, certificate: &LocalAdmissionCertificate) -> Result<MilestoneEvent> {
        certificate.verify()?;
        let event = milestone_event(
            self.mode,
            certificate.command_hash,
            Milestone::AcceptedLocal,
            None,
        );
        self.store.record_milestone(&event)?;
        self.telemetry.record_milestone(&event);
        Ok(event)
    }

    pub fn mark_available(
        &mut self,
        certificate: AvailabilityCertificate,
    ) -> Result<MilestoneEvent> {
        certificate.verify(&self.holder_membership)?;
        if certificate.reference.route_generation != self.route_generation
            || certificate.reference.command_spec_version != self.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "available reference route generation or command-spec version does not match the active application contract"
                    .to_string(),
            ));
        }
        self.store.bind_protocol_scope(
            certificate.reference.cluster_id,
            certificate.reference.consensus_group_id,
        )?;
        if certificate.reference.validator_generation != self.validator_generation {
            return Err(BlossomError::InvalidConfiguration(
                "available reference validator generation mismatch".to_string(),
            ));
        }
        let reference_hash = certificate.reference.hash()?;
        if self.available.contains_key(&reference_hash) {
            let event = milestone_event(self.mode, reference_hash, Milestone::Available, None);
            self.telemetry.record_milestone(&event);
            return Ok(event);
        }
        if self
            .final_reference_by_position
            .values()
            .any(|existing| *existing == reference_hash)
        {
            let event = milestone_event(self.mode, reference_hash, Milestone::Available, None);
            self.telemetry.record_milestone(&event);
            return Ok(event);
        }
        let max_pending_references = MAX_PIPELINED_AVAILABILITY_WINDOWS
            .checked_mul(self.validators.len())
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "availability pipeline capacity overflow".to_string(),
                )
            })?;
        if self.available.len() >= max_pending_references {
            return Err(BlossomError::BlockQueueFull);
        }
        let origin_key = (
            certificate.reference.origin,
            certificate.reference.origin_incarnation,
            certificate.reference.origin_key_generation,
        );
        let (expected_previous_hash, expected_first_sequence) =
            self.last_origin_reference.get(&origin_key).map_or(
                (
                    HashType::default(),
                    certificate.reference.first_origin_sequence,
                ),
                |(hash, last_sequence)| (*hash, last_sequence.saturating_add(1)),
            );
        if certificate.reference.previous_origin_reference_hash != expected_previous_hash
            || certificate.reference.first_origin_sequence != expected_first_sequence
        {
            return Err(BlossomError::InvalidConfiguration(
                "origin reference does not extend its hash-chained contiguous range".to_string(),
            ));
        }
        for existing in self.available.values() {
            if certificate.reference.conflicts_with(&existing.reference) {
                return Err(BlossomError::InvalidConfiguration(
                    "overlapping or equivocated origin reference".to_string(),
                ));
            }
        }
        let origin_tail = (reference_hash, certificate.reference.last_origin_sequence);
        let mut delta = OrderedStateDelta::new(self.durable_metadata());
        delta.origin_tail_upserts.push((origin_key, origin_tail));
        delta
            .available_upserts
            .push((reference_hash, certificate.clone()));
        let event = milestone_event(self.mode, reference_hash, Milestone::Available, None);
        self.store
            .persist_ordered_delta(&delta, std::slice::from_ref(&event), None)?;
        self.last_origin_reference.insert(origin_key, origin_tail);
        self.available.insert(reference_hash, certificate);
        self.telemetry.record_milestone(&event);
        Ok(event)
    }

    /// Derives the next order statement from a finalized Blossom epoch.
    ///
    /// Global ordering intentionally commits one availability-certified
    /// reference transaction per Blossom epoch so every validator derives the
    /// same next hash-chain position without a leader-assigned sequence.
    pub fn order_statement_for_finalized_epoch(&self, epoch: &Epoch) -> Result<OrderStatement> {
        self.order_statement_for_epoch_references(ordered_batch_references(epoch)?, epoch)
    }

    /// Derives the next statement from an epoch committed by a trusted runtime.
    ///
    /// Trusted nodes do not add a second signature or consensus round. The
    /// locally committed epoch hash and deterministic BTree block order are the
    /// trusted order receipt.
    pub fn order_statement_for_trusted_finalized_epoch(
        &self,
        epoch: &Epoch,
    ) -> Result<OrderStatement> {
        self.order_statement_for_epoch_references(ordered_batch_references_trusted(epoch)?, epoch)
    }

    /// Finalizes every availability-certified reference in one trusted epoch.
    ///
    /// References are consumed in the epoch's canonical BTree block-hash
    /// order. The committed epoch is the order authority: this method creates
    /// no signatures, votes, proposals, or additional consensus certificate.
    pub fn finalize_trusted_epoch(&mut self, epoch: &Epoch) -> Result<Vec<MilestoneEvent>> {
        if !self.order_trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "unsigned trusted epoch finality requires a trusted ordered engine".to_string(),
            ));
        }
        let references = ordered_batch_references_trusted(epoch)?;
        self.validate_epoch_validator_set(epoch)?;

        // Validate the entire epoch before persisting any part of its order so
        // malformed later references cannot leave a partially installed epoch.
        let mut known_predecessors = self
            .final_reference_by_position
            .values()
            .copied()
            .collect::<BTreeSet<_>>();
        let finalized_positions = self
            .final_reference_by_position
            .iter()
            .map(|(position, hash)| (*hash, *position))
            .collect::<BTreeMap<_, _>>();
        let mut epoch_references = BTreeSet::new();
        let mut existing_positions = Vec::with_capacity(references.len());
        for reference in &references {
            self.validate_orderable_reference(reference)?;
            let reference_hash = reference.hash()?;
            if !epoch_references.insert(reference_hash) {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted epoch contains a duplicate batch reference".to_string(),
                ));
            }
            if reference.previous_origin_reference_hash != HashType::default()
                && !known_predecessors.contains(&reference.previous_origin_reference_hash)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "an origin reference cannot precede its hash-chain predecessor".to_string(),
                ));
            }
            known_predecessors.insert(reference_hash);
            existing_positions.push(finalized_positions.get(&reference_hash).copied());
        }

        let existing_count = existing_positions
            .iter()
            .filter(|position| position.is_some())
            .count();
        if existing_count != 0 {
            if existing_count != references.len() {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted epoch replay is only partially present in the finality log"
                        .to_string(),
                ));
            }
            let first_position = existing_positions
                .first()
                .and_then(|position| *position)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "trusted epoch replay has no first order position".to_string(),
                    )
                })?;
            let mut events = Vec::with_capacity(references.len());
            for (index, (reference, position)) in
                references.iter().zip(existing_positions).enumerate()
            {
                let position = position.expect("all replay positions checked above");
                if position
                    != first_position
                        .checked_add(u64::try_from(index).map_err(|_| {
                            BlossomError::InvalidConfiguration(
                                "trusted epoch reference index overflow".to_string(),
                            )
                        })?)
                        .ok_or_else(|| {
                            BlossomError::InvalidConfiguration(
                                "trusted epoch replay position overflow".to_string(),
                            )
                        })?
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted epoch replay is not a contiguous canonical order".to_string(),
                    ));
                }
                let certificate = self.finalized.get(&position).ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "trusted epoch replay is missing its order receipt".to_string(),
                    )
                })?;
                certificate.verify_trusted(self.validator_generation)?;
                if certificate.statement.blossom_epoch_hash != epoch.hash
                    || certificate.statement.reference_hash != reference.hash()?
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted epoch replay conflicts with its durable order receipt".to_string(),
                    ));
                }
                events.push(milestone_event(
                    self.mode,
                    certificate.statement.reference_hash,
                    Milestone::Finalized,
                    Some(certificate.statement.position),
                ));
            }
            for event in &events {
                self.telemetry.record_milestone(event);
            }
            return Ok(events);
        }

        let mut delta = OrderedStateDelta::new(self.durable_metadata());
        let mut events = Vec::with_capacity(references.len());
        let mut next_position = self.last_finalized_position;
        let mut previous_certificate_hash = self.last_order_certificate_hash;
        for reference in references {
            let reference_hash = reference.hash()?;
            next_position = next_position.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("order position overflow".to_string())
            })?;
            let statement = OrderStatement {
                consensus_group_id: reference.consensus_group_id,
                blossom_epoch_hash: epoch.hash,
                position: Watermark {
                    position: next_position,
                },
                reference_hash,
                previous_order_certificate_hash: previous_certificate_hash,
                validator_generation: self.validator_generation,
            };
            let receipt = OrderCertificate::trusted(statement);
            receipt.verify_trusted(self.validator_generation)?;
            previous_certificate_hash = receipt.hash()?;
            delta.finalized_upserts.push((next_position, receipt));
            delta.position_upserts.push((next_position, reference_hash));
            events.push(milestone_event(
                self.mode,
                reference_hash,
                Milestone::Finalized,
                Some(Watermark {
                    position: next_position,
                }),
            ));
        }
        delta.metadata.last_finalized_position = next_position;
        delta.metadata.last_order_certificate_hash = previous_certificate_hash;
        self.store.persist_ordered_delta(&delta, &events, None)?;
        for (position, certificate) in delta.finalized_upserts {
            self.finalized.insert(position, certificate);
        }
        for (position, reference_hash) in delta.position_upserts {
            self.final_reference_by_position
                .insert(position, reference_hash);
            self.finalized_reference_hashes.insert(reference_hash);
        }
        self.last_finalized_position = next_position;
        self.last_order_certificate_hash = previous_certificate_hash;
        for event in &events {
            self.telemetry.record_milestone(event);
        }
        Ok(events)
    }

    fn order_statement_for_epoch_references(
        &self,
        references: Vec<BatchReference>,
        epoch: &Epoch,
    ) -> Result<OrderStatement> {
        self.validate_epoch_validator_set(epoch)?;
        let [reference] = references.as_slice() else {
            return Err(BlossomError::InvalidConfiguration(
                "single-reference ordering API requires exactly one batch reference transaction"
                    .to_string(),
            ));
        };
        self.order_statement_for_reference(reference, epoch.hash)
    }

    fn validate_epoch_validator_set(&self, epoch: &Epoch) -> Result<()> {
        let epoch_validators = epoch
            .body
            .verifiers
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        if epoch_validators != self.validators {
            return Err(BlossomError::InvalidConfiguration(
                "finalized Blossom epoch validator set does not match the ordering generation"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_orderable_reference(&self, reference: &BatchReference) -> Result<HashType> {
        if reference.validator_generation != self.validator_generation
            || reference.route_generation != self.route_generation
            || reference.command_spec_version != self.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "batch reference generation or application contract mismatch".to_string(),
            ));
        }
        let reference_hash = reference.hash()?;
        if !self.available.contains_key(&reference_hash) {
            return Err(BlossomError::InvalidConfiguration(
                "availability must be certified before proposing an order statement".to_string(),
            ));
        }
        Ok(reference_hash)
    }

    fn order_statement_for_reference(
        &self,
        reference: &BatchReference,
        blossom_epoch_hash: HashType,
    ) -> Result<OrderStatement> {
        let reference_hash = self.validate_orderable_reference(reference)?;
        self.ensure_origin_predecessor_finalized(reference)?;
        Ok(OrderStatement {
            consensus_group_id: reference.consensus_group_id,
            blossom_epoch_hash,
            position: Watermark {
                position: self.last_finalized_position.checked_add(1).ok_or_else(|| {
                    BlossomError::InvalidConfiguration("order position overflow".to_string())
                })?,
            },
            reference_hash,
            previous_order_certificate_hash: self.last_order_certificate_hash,
            validator_generation: self.validator_generation,
        })
    }

    pub fn finalize(&mut self, certificate: OrderCertificate) -> Result<MilestoneEvent> {
        if self.order_trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted ordering must finalize directly from the committed Blossom epoch"
                    .to_string(),
            ));
        }
        certificate.verify(self.validator_generation, &self.validators)?;
        self.finalize_validated(certificate)
    }

    /// Finalizes a trusted order statement without signatures or another vote.
    pub fn finalize_trusted(&mut self, statement: OrderStatement) -> Result<MilestoneEvent> {
        if !self.order_trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "unsigned trusted finality requires a trusted ordered engine".to_string(),
            ));
        }
        let receipt = OrderCertificate::trusted(statement);
        receipt.verify_trusted(self.validator_generation)?;
        self.finalize_validated(receipt)
    }

    fn finalize_validated(&mut self, certificate: OrderCertificate) -> Result<MilestoneEvent> {
        let statement = &certificate.statement;
        if let Some(existing) = self.finalized.get(&statement.position.position) {
            if existing.statement == certificate.statement {
                let event = milestone_event(
                    self.mode,
                    statement.reference_hash,
                    Milestone::Finalized,
                    Some(statement.position),
                );
                self.telemetry.record_milestone(&event);
                return Ok(event);
            }
            return Err(BlossomError::InvalidConfiguration(
                "two certificates assign different contents to one order position".to_string(),
            ));
        }
        let expected_position = self.last_finalized_position.checked_add(1).ok_or_else(|| {
            BlossomError::InvalidConfiguration("order position overflow".to_string())
        })?;
        if statement.position.position != expected_position
            || statement.previous_order_certificate_hash != self.last_order_certificate_hash
        {
            return Err(BlossomError::InvalidConfiguration(
                "order certificate does not extend the stable finality chain".to_string(),
            ));
        }
        if !self.available.contains_key(&statement.reference_hash) {
            return Err(BlossomError::InvalidConfiguration(
                "availability must be certified before finality".to_string(),
            ));
        }
        let available_reference = &self
            .available
            .get(&statement.reference_hash)
            .expect("checked above")
            .reference;
        if statement.consensus_group_id != available_reference.consensus_group_id
            || statement.validator_generation != available_reference.validator_generation
        {
            return Err(BlossomError::InvalidConfiguration(
                "order certificate scope does not match the available reference".to_string(),
            ));
        }
        self.ensure_origin_predecessor_finalized(available_reference)?;
        if let Some(existing) = self
            .final_reference_by_position
            .get(&statement.position.position)
            && *existing != statement.reference_hash
        {
            return Err(BlossomError::InvalidConfiguration(
                "two certificates assign different references to one order position".to_string(),
            ));
        }
        let certificate_hash = certificate.hash()?;
        let mut delta = OrderedStateDelta::new(self.durable_metadata());
        delta
            .finalized_upserts
            .push((statement.position.position, certificate.clone()));
        delta
            .position_upserts
            .push((statement.position.position, statement.reference_hash));
        delta.metadata.last_finalized_position = statement.position.position;
        delta.metadata.last_order_certificate_hash = certificate_hash;
        let event = milestone_event(
            self.mode,
            statement.reference_hash,
            Milestone::Finalized,
            Some(statement.position),
        );
        self.store
            .persist_ordered_delta(&delta, std::slice::from_ref(&event), None)?;
        let finalized_position = statement.position.position;
        let finalized_reference = statement.reference_hash;
        self.finalized.insert(finalized_position, certificate);
        self.final_reference_by_position
            .insert(finalized_position, finalized_reference);
        self.finalized_reference_hashes.insert(finalized_reference);
        self.last_finalized_position = finalized_position;
        self.last_order_certificate_hash = certificate_hash;
        self.telemetry.record_milestone(&event);
        Ok(event)
    }

    pub fn apply_contiguous_to<A: OrderedApplication>(
        &mut self,
        application: &mut A,
    ) -> Result<ApplyProgress> {
        let next_position = self.applied_watermark.position.saturating_add(1);
        let Some(certificate) = self.finalized.get(&next_position) else {
            return Ok(ApplyProgress::Applied {
                watermark: self.applied_watermark,
                completions: Vec::new(),
            });
        };
        let reference_hash = certificate.statement.reference_hash;
        let availability = self
            .available
            .get(&reference_hash)
            .expect("finality requires availability certificate");
        let Some(batch) = self.store.load_batch(&availability.reference)? else {
            if self.telemetry.is_enabled() {
                self.telemetry.record(
                    TelemetryEvent::new(
                        TelemetryEventKind::Event,
                        "apply",
                        "head_of_line_unavailable",
                    )
                    .with_outcome("blocked")
                    .with_field("watermark", self.applied_watermark.position.to_string())
                    .with_field("blocked_reference", reference_hash.to_string()),
                );
            }
            return Ok(ApplyProgress::HeadOfLineUnavailable {
                watermark: self.applied_watermark,
                blocked_reference: reference_hash,
            });
        };
        let next_watermark = certificate.statement.position;
        let command_count = batch.commands.len();
        let results = application.apply_ordered(&OrderedBatch {
            reference_hash,
            reference: availability.reference.clone(),
            batch,
            watermark: next_watermark,
        })?;
        let completion = AppliedCompletion {
            reference_hash,
            watermark: next_watermark,
            results,
        };
        completion.validate(Some(command_count))?;
        let mut delta = OrderedStateDelta::new(self.durable_metadata());
        delta.metadata.applied_watermark = next_watermark;
        delta.available_removals.push(reference_hash);
        let event = milestone_event(
            self.mode,
            reference_hash,
            Milestone::Applied,
            Some(next_watermark),
        );
        self.store.persist_ordered_delta(
            &delta,
            std::slice::from_ref(&event),
            Some(&completion),
        )?;
        self.applied_watermark = next_watermark;
        self.available.remove(&reference_hash);
        self.telemetry.record_milestone(&event);
        Ok(ApplyProgress::Applied {
            watermark: self.applied_watermark,
            completions: vec![completion],
        })
    }

    pub fn apply_through_to<A: OrderedApplication>(
        &mut self,
        target: Watermark,
        application: &mut A,
    ) -> Result<ApplyProgress> {
        let mut all_completions = Vec::new();
        while self.applied_watermark < target {
            match self.apply_contiguous_to(application)? {
                ApplyProgress::Applied {
                    watermark,
                    completions,
                } => {
                    if completions.is_empty() && watermark < target {
                        return Err(BlossomError::FailedConsensus);
                    }
                    all_completions.extend(completions);
                }
                blocked @ ApplyProgress::HeadOfLineUnavailable { .. } => return Ok(blocked),
            }
        }
        Ok(ApplyProgress::Applied {
            watermark: self.applied_watermark,
            completions: all_completions,
        })
    }

    /// Advances an embedding application to the watermark required by a read.
    ///
    /// After this method succeeds the caller can issue the actual read against
    /// its own state machine. A linearizable read requires a freshly certified
    /// Blossom order/read barrier supplied by the caller's consensus driver.
    pub fn satisfy_read_consistency_to<A: OrderedApplication>(
        &mut self,
        consistency: ReadConsistency,
        linearizable_barrier: Option<&CertifiedReadBarrier>,
        application: &mut A,
    ) -> Result<Watermark> {
        let required = match consistency {
            ReadConsistency::Local => None,
            ReadConsistency::AtLeast(watermark) => Some(watermark),
            ReadConsistency::Linearizable => {
                let barrier = linearizable_barrier.ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "linearizable Blossom read requires a fresh certified read barrier"
                            .to_string(),
                    )
                })?;
                Some(self.acquire_read_barrier(barrier)?)
            }
        };
        if let Some(required) = required {
            match self.apply_through_to(required, application)? {
                ApplyProgress::Applied { watermark, .. } if watermark >= required => {}
                ApplyProgress::HeadOfLineUnavailable {
                    blocked_reference, ..
                } => {
                    return Err(BlossomError::InvalidConfiguration(format!(
                        "read blocked by unavailable reference {blocked_reference}"
                    )));
                }
                _ => return Err(BlossomError::FailedConsensus),
            }
        }
        Ok(self.applied_watermark)
    }

    pub fn applied_watermark(&self) -> Watermark {
        self.applied_watermark
    }

    pub fn route_generation(&self) -> RouteGeneration {
        self.route_generation
    }

    pub fn command_spec_version(&self) -> CommandSpecVersion {
        self.command_spec_version
    }

    pub fn status(&self, reference_hash: HashType) -> Result<ReferenceStatus> {
        self.store.reference_status(reference_hash)
    }

    pub fn wait_for(
        &self,
        reference_hash: HashType,
        target: Milestone,
        timeout: Duration,
    ) -> Result<WaitForOutcome> {
        self.store.wait_for(reference_hash, target, timeout)
    }

    /// Completes a write according to its requested acknowledgement mode.
    ///
    /// The embedding consensus driver remains responsible for admission,
    /// availability, and finality. For [`WriteMode::GlobalApplied`], this
    /// method additionally drives contiguous application once finality is
    /// visible and does not return `Reached` until an [`AppliedCompletion`] is
    /// durable. Every mode observes the same bounded timeout contract as
    /// [`Self::wait_for`].
    pub fn complete_write<A: OrderedApplication>(
        &mut self,
        reference_hash: HashType,
        mode: WriteMode,
        timeout: Duration,
        application: &mut A,
    ) -> Result<WaitForOutcome> {
        if mode != WriteMode::GlobalApplied {
            return self.wait_for(reference_hash, mode.required_milestone(), timeout);
        }
        if timeout > MAX_WAIT_FOR_TIMEOUT {
            return Err(BlossomError::InvalidConfiguration(format!(
                "wait timeout exceeds the {} second bound",
                MAX_WAIT_FOR_TIMEOUT.as_secs()
            )));
        }
        let started = Instant::now();
        loop {
            let status = self.status(reference_hash)?;
            if status.reached(Milestone::Applied) {
                return Ok(WaitForOutcome::Reached(status));
            }
            if let ReferenceStatus::Pending(event) = &status
                && event.milestone.reaches(Milestone::Finalized)
            {
                let target = event.watermark.ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "finalized reference is missing its order watermark".to_string(),
                    )
                })?;
                let _ = self.apply_through_to(target, application)?;
                let applied = self.status(reference_hash)?;
                if applied.reached(Milestone::Applied) {
                    return Ok(WaitForOutcome::Reached(applied));
                }
            }
            let status = self.status(reference_hash)?;
            if status.is_terminal() || started.elapsed() >= timeout {
                return Ok(WaitForOutcome::TimedOut(status));
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Ok(WaitForOutcome::TimedOut(status));
            }
            thread::sleep(WAIT_FOR_POLL_INTERVAL.min(remaining));
        }
    }

    /// Builds this validator's statement for a caller-issued freshness
    /// challenge. The statement is not a barrier until a quorum signs it.
    pub fn read_barrier_statement(
        &self,
        request: ReadBarrierRequest,
    ) -> Result<ReadBarrierStatement> {
        let (position, order_certificate_hash) = self.validated_local_order_tail()?;
        let (cluster_id, consensus_group_id) = self.store.protocol_scope()?.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "read barriers require a bound cluster and consensus-group scope".to_string(),
            )
        })?;
        Ok(ReadBarrierStatement {
            cluster_id,
            consensus_group_id,
            validator_generation: self.validator_generation,
            route_generation: self.route_generation,
            command_spec_version: self.command_spec_version,
            challenge: request.challenge,
            position,
            order_certificate_hash,
        })
    }

    pub fn vote_for_read_barrier(&self, request: ReadBarrierRequest) -> Result<ReadBarrierVote> {
        if !self.validators.contains(&self.store.holder) {
            return Err(BlossomError::UnknownSender);
        }
        let statement = self.read_barrier_statement(request)?;
        self.store.sign_read_barrier_statement(&statement)
    }

    /// Validates a caller-challenge-bound quorum certificate and checks that
    /// the local finalized chain has caught up to exactly the certified tail.
    pub fn acquire_read_barrier(&self, barrier: &CertifiedReadBarrier) -> Result<Watermark> {
        barrier.certificate.verify(
            barrier.request.challenge,
            self.validator_generation,
            &self.validators,
        )?;
        let statement = &barrier.certificate.statement;
        let scope = self.store.protocol_scope()?.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "read barriers require a bound cluster and consensus-group scope".to_string(),
            )
        })?;
        if scope != (statement.cluster_id, statement.consensus_group_id)
            || statement.route_generation != self.route_generation
            || statement.command_spec_version != self.command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "read-barrier scope or application contract does not match this engine".to_string(),
            ));
        }
        let local_tail = self.validated_local_order_tail()?;
        if local_tail != (statement.position, statement.order_certificate_hash) {
            return Err(BlossomError::InvalidConfiguration(
                "local finality chain has not caught up to the fresh consensus read barrier"
                    .to_string(),
            ));
        }
        Ok(statement.position)
    }

    fn validated_local_order_tail(&self) -> Result<(Watermark, HashType)> {
        if self.last_finalized_position == 0 {
            if self.last_order_certificate_hash != HashType::default() {
                return Err(BlossomError::InvalidConfiguration(
                    "empty finality chain has a non-empty tail hash".to_string(),
                ));
            }
            return Ok((Watermark::default(), HashType::default()));
        }
        let certificate = self
            .finalized
            .get(&self.last_finalized_position)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "current order head is missing its certificate".to_string(),
                )
            })?;
        if certificate.hash()? != self.last_order_certificate_hash {
            return Err(BlossomError::InvalidConfiguration(
                "current order head certificate does not match the durable tail".to_string(),
            ));
        }
        if self.order_trust_mode.is_trusted() {
            certificate.verify_trusted(self.validator_generation)?;
        } else {
            certificate.verify(self.validator_generation, &self.validators)?;
        }
        Ok((
            certificate.statement.position,
            self.last_order_certificate_hash,
        ))
    }

    fn ensure_origin_predecessor_finalized(&self, reference: &BatchReference) -> Result<()> {
        if reference.previous_origin_reference_hash != HashType::default()
            && !self
                .finalized_reference_hashes
                .contains(&reference.previous_origin_reference_hash)
        {
            return Err(BlossomError::InvalidConfiguration(
                "an origin reference cannot finalize before its hash-chain predecessor".to_string(),
            ));
        }
        Ok(())
    }

    fn durable_metadata(&self) -> DurableOrderedMetadata {
        DurableOrderedMetadata {
            version: DURABLE_ORDERED_STATE_VERSION,
            holder_membership_epoch: self.holder_membership.epoch,
            validator_generation: self.validator_generation,
            route_generation: self.route_generation,
            command_spec_version: self.command_spec_version,
            last_finalized_position: self.last_finalized_position,
            last_order_certificate_hash: self.last_order_certificate_hash,
            applied_watermark: self.applied_watermark,
        }
    }

    fn install_durable_state(&mut self, state: DurableOrderedState) {
        self.route_generation = state.route_generation;
        self.command_spec_version = state.command_spec_version;
        self.available = state.available;
        self.finalized = state.finalized;
        self.finalized_reference_hashes = state
            .final_reference_by_position
            .values()
            .copied()
            .collect();
        self.final_reference_by_position = state.final_reference_by_position;
        self.last_origin_reference = state.last_origin_reference;
        self.last_finalized_position = state.last_finalized_position;
        self.last_order_certificate_hash = state.last_order_certificate_hash;
        self.applied_watermark = state.applied_watermark;
    }

    fn validate_durable_state(&self, state: &DurableOrderedState) -> Result<()> {
        state.route_generation.validate()?;
        state.command_spec_version.validate()?;
        if state.version != DURABLE_ORDERED_STATE_VERSION
            || state.holder_membership_epoch != self.holder_membership.epoch
            || state.validator_generation != self.validator_generation
            || state.route_generation != self.route_generation
            || state.command_spec_version != self.command_spec_version
            || state.applied_watermark.position > state.last_finalized_position
        {
            return Err(BlossomError::InvalidConfiguration(
                "durable ordered-engine parameters do not match startup configuration".to_string(),
            ));
        }
        if state.finalized.len()
            != usize::try_from(state.last_finalized_position).unwrap_or(usize::MAX)
            || state.final_reference_by_position.len() != state.finalized.len()
        {
            return Err(BlossomError::InvalidConfiguration(
                "durable finality tables contain missing or out-of-range positions".to_string(),
            ));
        }
        for (reference_hash, availability) in &state.available {
            availability.verify(&self.holder_membership)?;
            if availability.reference.hash()? != *reference_hash
                || availability.reference.route_generation != state.route_generation
                || availability.reference.command_spec_version != state.command_spec_version
            {
                return Err(BlossomError::InvalidConfiguration(
                    "durable availability does not match its key or application contract"
                        .to_string(),
                ));
            }
            self.store.bind_protocol_scope(
                availability.reference.cluster_id,
                availability.reference.consensus_group_id,
            )?;
        }
        let mut previous_hash = HashType::default();
        for position in 1..=state.last_finalized_position {
            let certificate = state.finalized.get(&position).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "durable finality chain is not contiguous".to_string(),
                )
            })?;
            if self.order_trust_mode.is_trusted() {
                certificate.verify_trusted(self.validator_generation)?;
            } else {
                certificate.verify(self.validator_generation, &self.validators)?;
            }
            if certificate.statement.position.position != position
                || certificate.statement.previous_order_certificate_hash != previous_hash
                || state.final_reference_by_position.get(&position)
                    != Some(&certificate.statement.reference_hash)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "durable finality chain failed stable-prefix validation".to_string(),
                ));
            }
            previous_hash = certificate.hash()?;
            if position <= state.applied_watermark.position {
                let reference_hash = certificate.statement.reference_hash;
                match self.store.reference_status(reference_hash)? {
                    ReferenceStatus::Applied(completion)
                        if completion.reference_hash == reference_hash
                            && completion.watermark.position == position => {}
                    _ => {
                        return Err(BlossomError::InvalidConfiguration(
                            "durable applied watermark is missing an exact applied completion"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        if previous_hash != state.last_order_certificate_hash {
            return Err(BlossomError::InvalidConfiguration(
                "durable finality chain tail hash mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AppliedByTracker {
    membership_snapshot: ReplicaMembershipEpoch,
    required_nodes: BTreeSet<PubKey>,
    observed: BTreeMap<PubKey, Watermark>,
}

impl AppliedByTracker {
    pub fn new(
        membership_snapshot: ReplicaMembershipEpoch,
        required_nodes: BTreeSet<PubKey>,
    ) -> Result<Self> {
        if required_nodes.is_empty() {
            return Err(BlossomError::InvalidConfiguration(
                "AppliedBy requires a non-empty frozen replica set".to_string(),
            ));
        }
        Ok(Self {
            membership_snapshot,
            required_nodes,
            observed: BTreeMap::new(),
        })
    }

    pub fn observe(&mut self, node: PubKey, watermark: Watermark) -> Result<()> {
        if !self.required_nodes.contains(&node) {
            return Err(BlossomError::UnknownSender);
        }
        self.observed
            .entry(node)
            .and_modify(|current| *current = (*current).max(watermark))
            .or_insert(watermark);
        Ok(())
    }

    pub fn reached(&self, watermark: Watermark) -> Option<AppliedBy> {
        self.required_nodes
            .iter()
            .all(|node| {
                self.observed
                    .get(node)
                    .is_some_and(|seen| *seen >= watermark)
            })
            .then(|| AppliedBy {
                membership_snapshot: self.membership_snapshot,
                required_nodes: self.required_nodes.clone(),
                watermark,
            })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RetentionEvidence {
    pub durable_snapshot_watermark: Watermark,
    pub applied_by: AppliedBy,
}

impl RetentionEvidence {
    pub fn permits_collection(&self, position: Watermark) -> bool {
        self.durable_snapshot_watermark >= position && self.applied_by.watermark >= position
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipCutoverDisposition {
    FinalizeUnderOldMembership,
    RecertifyUnderNewMembership,
    ExplicitAbort,
}

pub fn required_cutover_disposition(
    accepted_local: bool,
    available_under_old_membership: bool,
    can_recertify: bool,
) -> MembershipCutoverDisposition {
    if accepted_local && available_under_old_membership {
        MembershipCutoverDisposition::FinalizeUnderOldMembership
    } else if accepted_local && can_recertify {
        MembershipCutoverDisposition::RecertifyUnderNewMembership
    } else {
        MembershipCutoverDisposition::ExplicitAbort
    }
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
mod tests {
    use super::*;
    use crate::algorithm::ConsensusParameters;
    use crate::block::Block;
    use crate::crypto::Keypair;
    use crate::node::NodeIdentity;
    use crate::nonce::Nonce;
    use crate::state::EpochBody;
    use indextreemap::IndexTreeMap;

    #[derive(BorshSerialize, BorshDeserialize)]
    struct TestCommand {
        key: Vec<u8>,
        value: Vec<u8>,
    }

    fn test_result() -> ApplicationResult {
        ApplicationResult::new(vec![1]).unwrap()
    }

    #[derive(Default)]
    struct RecordingApplication {
        applied: BTreeSet<(HashType, Watermark)>,
        values: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl OrderedApplication for RecordingApplication {
        fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>> {
            if !self
                .applied
                .insert((ordered.reference_hash, ordered.watermark))
            {
                return Ok(vec![test_result(); ordered.batch.commands.len()]);
            }
            for admitted in &ordered.batch.commands {
                let command = borsh::from_slice::<TestCommand>(admitted.command.command.as_bytes())
                    .map_err(encode_error)?;
                self.values.insert(command.key, command.value);
            }
            Ok(vec![test_result(); ordered.batch.commands.len()])
        }
    }

    struct FailingApplication;

    impl OrderedApplication for FailingApplication {
        fn apply_ordered(&mut self, _ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>> {
            Err(BlossomError::ExternalService(
                "application unavailable".to_string(),
            ))
        }
    }

    struct DivergentApplication;

    impl OrderedApplication for DivergentApplication {
        fn apply_ordered(&mut self, _ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>> {
            Ok(Vec::new())
        }
    }

    fn command(client: u8, sequence: u64, value: &[u8]) -> ActiveActiveCommand {
        let payload = borsh::to_vec(&TestCommand {
            key: b"key".to_vec(),
            value: value.to_vec(),
        })
        .unwrap();
        ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([client; 16]),
                client_epoch: ClientEpoch(1),
                sequence,
            },
            command: ApplicationCommand::new(payload).unwrap(),
        }
    }

    fn batch() -> CommandBatch {
        CommandBatch {
            commands: vec![
                AdmittedCommand {
                    origin_sequence: 10,
                    command: command(1, 10, b"ten"),
                },
                AdmittedCommand {
                    origin_sequence: 11,
                    command: command(1, 11, b"eleven"),
                },
            ],
        }
    }

    fn reference(batch: &CommandBatch, origin: PubKey) -> BatchReference {
        BatchReference::for_batch(
            batch,
            BatchReferenceMetadata {
                cluster_id: HashType([1; 32]),
                consensus_group_id: ConsensusGroupId::root(),
                shard: b"shard-0".to_vec(),
                route_generation: RouteGeneration(1),
                command_spec_version: CommandSpecVersion(1),
                origin,
                origin_incarnation: 1,
                origin_key_generation: 1,
                data_holder_membership_epoch: ReplicaMembershipEpoch(3),
                validator_generation: ValidatorGeneration(5),
                previous_origin_reference_hash: HashType::default(),
            },
        )
        .unwrap()
    }

    #[test]
    fn reference_commits_canonical_batch_with_sha256_merkle_root() {
        let keypair = Keypair::generate();
        let batch = batch();
        let reference = reference(&batch, keypair.public);

        reference.verify_batch(&batch).unwrap();
        let transaction = reference.to_transaction().unwrap();
        assert_eq!(
            BatchReference::from_transaction(&transaction).unwrap(),
            Some(reference.clone())
        );
        assert!(
            BatchReference::from_transaction(&Transaction::new(b"unrelated".to_vec()))
                .unwrap()
                .is_none()
        );
        let mut modified = batch;
        modified.commands[0].command = command(1, 10, b"different");
        assert!(reference.verify_batch(&modified).is_err());

        let mut rerouted = reference.clone();
        rerouted.route_generation = RouteGeneration(2);
        assert_ne!(reference.hash().unwrap(), rerouted.hash().unwrap());
        let mut upgraded_spec = reference.clone();
        upgraded_spec.command_spec_version = CommandSpecVersion(2);
        assert_ne!(reference.hash().unwrap(), upgraded_spec.hash().unwrap());
        let mut legacy = reference;
        legacy.format_version = 1;
        legacy.codec_version = 1;
        assert!(legacy.validate().is_err());
    }

    #[test]
    fn finalized_blossom_epoch_certifies_reference_transaction_order() {
        let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let batch = batch();
        let reference = reference(&batch, keypairs[0].public);
        let mut block = Block::default();
        block.body.txs.push(reference.to_transaction().unwrap());
        block.sign_with(&keypairs[0].signer());

        let mut verifiers = IndexTreeMap::new();
        for (index, keypair) in keypairs.iter().enumerate() {
            verifiers.insert(
                keypair.public,
                NodeIdentity::new(
                    keypair.public,
                    None,
                    "tcp",
                    "127.0.0.1",
                    8000 + index as u16,
                    false,
                ),
            );
        }
        let mut epoch = Epoch {
            hash: HashType::default(),
            signatures: BTreeMap::new(),
            body: EpochBody {
                group_id: ConsensusGroupId::root(),
                verifiers,
                blocks: BTreeMap::from([(block.hash, block)]),
                consensus_parameters: Some(ConsensusParameters::default()),
                ..EpochBody::default()
            },
        };
        epoch.set_hash();
        for index in 0..2 {
            let validator = *epoch.body.verifiers.get_key_from_index(index).unwrap();
            let keypair = keypairs
                .iter()
                .find(|keypair| keypair.public == validator)
                .unwrap();
            epoch
                .signatures
                .insert(index, keypair.signer().sign(epoch.hash.as_ref()));
        }

        assert_eq!(
            ordered_batch_references(&epoch).unwrap(),
            vec![reference.clone()]
        );
        epoch.signatures.clear();
        assert!(ordered_batch_references(&epoch).is_err());
        assert_eq!(
            ordered_batch_references_trusted(&epoch).unwrap(),
            vec![reference]
        );
    }

    #[test]
    fn command_envelopes_are_opaque_and_bounded() {
        let opaque = command(1, 1, b"value");
        assert!(opaque.validate().is_ok());
        assert_eq!(
            borsh::from_slice::<TestCommand>(opaque.command.as_bytes())
                .unwrap()
                .value,
            b"value"
        );
        assert!(ApplicationCommand::new(Vec::new()).is_err());
    }

    #[test]
    fn write_mode_is_independent_of_application_semantics() {
        assert_eq!(
            WriteMode::LocalAsync.required_milestone(),
            Milestone::AcceptedLocal
        );
        assert_eq!(
            WriteMode::GlobalFinalized.required_milestone(),
            Milestone::Finalized
        );
        assert_eq!(
            WriteMode::GlobalApplied.required_milestone(),
            Milestone::Applied
        );
        assert!(Milestone::Applied.is_terminal());
    }

    #[test]
    fn applied_by_uses_a_frozen_replica_set() {
        let nodes = [PubKey([1; 32]), PubKey([2; 32])]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut tracker = AppliedByTracker::new(ReplicaMembershipEpoch(7), nodes.clone()).unwrap();
        tracker
            .observe(PubKey([1; 32]), Watermark { position: 9 })
            .unwrap();
        assert!(tracker.reached(Watermark { position: 9 }).is_none());
        tracker
            .observe(PubKey([2; 32]), Watermark { position: 9 })
            .unwrap();
        assert_eq!(
            tracker.reached(Watermark { position: 9 }).unwrap(),
            AppliedBy {
                membership_snapshot: ReplicaMembershipEpoch(7),
                required_nodes: nodes,
                watermark: Watermark { position: 9 },
            }
        );
    }

    #[test]
    fn durable_store_rejects_identity_equivocation_and_recovers_state() {
        let keypair = Keypair::generate();
        let path = std::env::temp_dir().join(format!(
            "blossom-active-active-{}-{}",
            std::process::id(),
            keypair.public
        ));
        let store = DurableAdmissionStore::open(
            &path,
            SiteId("site-a".to_string()),
            StoreGeneration(1),
            keypair.signer(),
        )
        .unwrap();
        let first = AdmittedCommand {
            origin_sequence: 1,
            command: command(8, 1, b"first"),
        };
        store.admit(&first, ReplicaMembershipEpoch(1)).unwrap();
        let conflicting = AdmittedCommand {
            origin_sequence: 2,
            command: command(8, 1, b"conflict"),
        };
        assert!(
            store
                .admit(&conflicting, ReplicaMembershipEpoch(1))
                .is_err()
        );

        drop(store);

        let reopened = DurableAdmissionStore::open(
            &path,
            SiteId("site-a".to_string()),
            StoreGeneration(1),
            keypair.signer(),
        )
        .unwrap();
        assert!(
            reopened
                .admit(&conflicting, ReplicaMembershipEpoch(1))
                .is_err()
        );
        drop(reopened);
        std::fs::remove_dir_all(path).ok();
    }

    #[test]
    fn durable_store_reopen_fails_closed_on_identity_and_scope_mismatch() {
        let keypair = Keypair::generate();
        let other = Keypair::generate();
        let path = std::env::temp_dir().join(format!(
            "blossom-active-active-identity-{}-{}",
            std::process::id(),
            keypair.public
        ));
        let store = DurableAdmissionStore::open(
            &path,
            SiteId("site-a".to_string()),
            StoreGeneration(7),
            keypair.signer(),
        )
        .unwrap();
        let batch = batch();
        let reference = reference(&batch, keypair.public);
        let before_store = store.durability_metrics();
        store.store_batch(&reference, &batch).unwrap();
        let metrics = store.durability_metrics();
        assert_eq!(metrics.commit_count, before_store.commit_count + 1);
        assert!(metrics.fsync_count >= metrics.commit_count);
        drop(store);

        assert!(
            DurableAdmissionStore::open(
                &path,
                SiteId("site-b".to_string()),
                StoreGeneration(7),
                keypair.signer(),
            )
            .is_err()
        );
        assert!(
            DurableAdmissionStore::open(
                &path,
                SiteId("site-a".to_string()),
                StoreGeneration(8),
                keypair.signer(),
            )
            .is_err()
        );
        assert!(
            DurableAdmissionStore::open(
                &path,
                SiteId("site-a".to_string()),
                StoreGeneration(7),
                other.signer(),
            )
            .is_err()
        );

        let reopened = DurableAdmissionStore::open(
            &path,
            SiteId("site-a".to_string()),
            StoreGeneration(7),
            keypair.signer(),
        )
        .unwrap();
        let mut wrong_cluster = reference.clone();
        wrong_cluster.cluster_id = HashType([9; 32]);
        assert!(reopened.store_batch(&wrong_cluster, &batch).is_err());
        let mut wrong_group = reference;
        wrong_group.consensus_group_id = ConsensusGroupId::named("wrong-group");
        assert!(reopened.store_batch(&wrong_group, &batch).is_err());
        drop(reopened);
        std::fs::remove_dir_all(path).ok();
    }

    #[test]
    fn legacy_store_without_identity_requires_fresh_initialization() {
        let keypair = Keypair::generate();
        let path = std::env::temp_dir().join(format!(
            "blossom-active-active-legacy-{}-{}.legacy-db",
            std::process::id(),
            keypair.public
        ));
        std::fs::write(&path, b"legacy-database-state").unwrap();

        assert!(
            DurableAdmissionStore::open(
                &path,
                SiteId("site-a".to_string()),
                StoreGeneration(1),
                keypair.signer(),
            )
            .is_err()
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn command_batches_and_application_payloads_are_bounded() {
        let commands = (1..=DEFAULT_MAX_BATCH_COMMANDS + 1)
            .map(|sequence| AdmittedCommand {
                origin_sequence: sequence as u64,
                command: command(
                    u8::try_from(sequence % 251).unwrap(),
                    sequence as u64,
                    b"value",
                ),
            })
            .collect();
        assert!(CommandBatch { commands }.validate().is_err());
        assert!(ApplicationCommand::new(Vec::new()).is_err());
    }

    #[test]
    fn trusted_order_receipt_survives_restart_without_becoming_verified() {
        let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let sites = ["site-a", "site-b", "site-c"];
        let paths = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                std::env::temp_dir().join(format!(
                    "blossom-trusted-order-restart-{}-{index}-{}",
                    std::process::id(),
                    keypair.public
                ))
            })
            .collect::<Vec<_>>();
        let stores = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                DurableAdmissionStore::open(
                    &paths[index],
                    SiteId(sites[index].to_string()),
                    StoreGeneration(1),
                    keypair.signer(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let batch = CommandBatch {
            commands: vec![AdmittedCommand {
                origin_sequence: 1,
                command: command(12, 1, b"trusted"),
            }],
        };
        let reference = reference(&batch, keypairs[0].public);
        let receipts = stores
            .iter()
            .map(|store| store.store_batch(&reference, &batch).unwrap())
            .collect::<Vec<_>>();
        let holder_membership = HolderMembership {
            epoch: ReplicaMembershipEpoch(3),
            members_by_site: keypairs
                .iter()
                .enumerate()
                .map(|(index, keypair)| {
                    (
                        SiteId(sites[index].to_string()),
                        [keypair.public].into_iter().collect(),
                    )
                })
                .collect(),
            store_generations: keypairs
                .iter()
                .map(|keypair| (keypair.public, StoreGeneration(1)))
                .collect(),
            holder_fault_bound: 0,
        };
        let validators = keypairs
            .iter()
            .map(|keypair| keypair.public)
            .collect::<BTreeSet<_>>();
        let mut engine = GlobalOrderedEngine::new_with_trust_mode(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership.clone(),
            ValidatorGeneration(5),
            validators.clone(),
            TrustMode::Trusted,
            64,
        )
        .unwrap();
        engine
            .mark_available(AvailabilityCertificate {
                reference: reference.clone(),
                trust: AvailabilityTrust::Trusted,
                receipts,
            })
            .unwrap();
        let statement = OrderStatement {
            consensus_group_id: ConsensusGroupId::root(),
            blossom_epoch_hash: HashType([12; 32]),
            position: Watermark { position: 1 },
            reference_hash: reference.hash().unwrap(),
            previous_order_certificate_hash: HashType::default(),
            validator_generation: ValidatorGeneration(5),
        };
        engine.finalize_trusted(statement.clone()).unwrap();
        assert!(
            engine
                .finalized
                .get(&1)
                .is_some_and(|receipt| receipt.signatures.is_empty())
        );
        {
            assert_eq!(
                stores[0]
                    .store
                    .scan(AVAILABLE_REFERENCES_TABLE)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                stores[0]
                    .store
                    .scan(FINALIZED_POSITIONS_TABLE)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                stores[0]
                    .store
                    .scan(POSITION_REFERENCES_TABLE)
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                stores[0]
                    .store
                    .get(ORDERED_METADATA_TABLE, ORDERED_METADATA_KEY.as_bytes())
                    .unwrap()
                    .is_some()
            );
            assert!(
                stores[0]
                    .store
                    .scan(APPLIED_COMPLETIONS_TABLE)
                    .unwrap()
                    .is_empty()
            );
        }
        drop(engine);

        let restarted = GlobalOrderedEngine::new_with_trust_mode(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership.clone(),
            ValidatorGeneration(5),
            validators.clone(),
            TrustMode::Trusted,
            64,
        )
        .unwrap();
        assert_eq!(
            restarted
                .finalized
                .get(&1)
                .map(|receipt| &receipt.statement),
            Some(&statement)
        );
        let request = ReadBarrierRequest::fresh();
        let statement = restarted.read_barrier_statement(request).unwrap();
        let votes = stores
            .iter()
            .take(2)
            .map(|store| store.sign_read_barrier_statement(&statement).unwrap())
            .collect::<Vec<_>>();
        let barrier = CertifiedReadBarrier {
            request,
            certificate: ReadBarrierCertificate::from_votes(statement, votes).unwrap(),
        };
        assert_eq!(
            restarted.acquire_read_barrier(&barrier).unwrap(),
            Watermark { position: 1 }
        );
        drop(restarted);

        assert!(
            GlobalOrderedEngine::new(
                stores[0].clone(),
                ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
                holder_membership,
                ValidatorGeneration(5),
                validators,
                64,
            )
            .is_err()
        );
        {
            stores[0]
                .store
                .transaction(|transaction| {
                    transaction.remove(FINALIZED_POSITIONS_TABLE, 1u64.to_be_bytes().to_vec())?;
                    Ok(())
                })
                .unwrap();
        }
        assert!(
            GlobalOrderedEngine::new_with_trust_mode(
                stores[0].clone(),
                ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
                HolderMembership {
                    epoch: ReplicaMembershipEpoch(3),
                    members_by_site: keypairs
                        .iter()
                        .enumerate()
                        .map(|(index, keypair)| {
                            (
                                SiteId(sites[index].to_string()),
                                [keypair.public].into_iter().collect(),
                            )
                        })
                        .collect(),
                    store_generations: keypairs
                        .iter()
                        .map(|keypair| (keypair.public, StoreGeneration(1)))
                        .collect(),
                    holder_fault_bound: 0,
                },
                ValidatorGeneration(5),
                keypairs.iter().map(|keypair| keypair.public).collect(),
                TrustMode::Trusted,
                64,
            )
            .is_err()
        );
        drop(stores);
        for path in paths {
            std::fs::remove_dir_all(path).ok();
        }
    }

    #[test]
    fn trusted_epoch_finalizes_all_writer_references_in_btree_block_order() {
        let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let sites = ["site-a", "site-b", "site-c"];
        let paths = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                std::env::temp_dir().join(format!(
                    "blossom-trusted-parallel-writers-{}-{index}-{}",
                    std::process::id(),
                    keypair.public
                ))
            })
            .collect::<Vec<_>>();
        let stores = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                DurableAdmissionStore::open(
                    &paths[index],
                    SiteId(sites[index].to_string()),
                    StoreGeneration(1),
                    keypair.signer(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let holder_membership = HolderMembership {
            epoch: ReplicaMembershipEpoch(3),
            members_by_site: keypairs
                .iter()
                .enumerate()
                .map(|(index, keypair)| {
                    (
                        SiteId(sites[index].to_string()),
                        [keypair.public].into_iter().collect(),
                    )
                })
                .collect(),
            store_generations: keypairs
                .iter()
                .map(|keypair| (keypair.public, StoreGeneration(1)))
                .collect(),
            holder_fault_bound: 0,
        };
        let validators = keypairs
            .iter()
            .map(|keypair| keypair.public)
            .collect::<BTreeSet<_>>();
        let mut engine = GlobalOrderedEngine::new_with_trust_mode(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership.clone(),
            ValidatorGeneration(5),
            validators.clone(),
            TrustMode::Trusted,
            64,
        )
        .unwrap();

        let mut blocks = BTreeMap::new();
        for (index, keypair) in keypairs.iter().enumerate() {
            let batch = CommandBatch {
                commands: vec![AdmittedCommand {
                    origin_sequence: 1,
                    command: command(20 + index as u8, 1, &[index as u8]),
                }],
            };
            let reference = reference(&batch, keypair.public);
            let receipts = stores
                .iter()
                .map(|store| store.store_batch(&reference, &batch).unwrap())
                .collect();
            engine
                .mark_available(AvailabilityCertificate {
                    reference: reference.clone(),
                    trust: AvailabilityTrust::Trusted,
                    receipts,
                })
                .unwrap();
            let mut block = Block::default();
            block.body.txs.push(reference.to_transaction().unwrap());
            block.seal_unsigned(keypair.public);
            blocks.insert(block.hash, block);
        }
        let mut verifiers = IndexTreeMap::new();
        for (index, keypair) in keypairs.iter().enumerate() {
            verifiers.insert(
                keypair.public,
                NodeIdentity::new(
                    keypair.public,
                    None,
                    "tcp",
                    "127.0.0.1",
                    9000 + index as u16,
                    false,
                ),
            );
        }
        let mut epoch = Epoch {
            hash: HashType::default(),
            signatures: BTreeMap::new(),
            body: EpochBody {
                group_id: ConsensusGroupId::root(),
                nonce: Nonce::new(1),
                previous_nonce: Some(Nonce::new(0)),
                verifiers,
                blocks,
                consensus_parameters: Some(ConsensusParameters::default()),
                ..EpochBody::default()
            },
        };
        epoch.set_hash();
        let expected_hashes = ordered_batch_references_trusted(&epoch)
            .unwrap()
            .iter()
            .map(BatchReference::hash)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let generic_ordered_transactions = epoch.trusted_ordered_transactions().unwrap();
        assert_eq!(generic_ordered_transactions.len(), 3);
        assert_eq!(
            generic_ordered_transactions
                .iter()
                .map(|ordered| {
                    BatchReference::from_transaction(&ordered.transaction)
                        .unwrap()
                        .unwrap()
                        .hash()
                        .unwrap()
                })
                .collect::<Vec<_>>(),
            expected_hashes
        );

        let events = engine.finalize_trusted_epoch(&epoch).unwrap();

        assert_eq!(events.len(), 3);
        assert_eq!(
            events
                .iter()
                .map(|event| event.reference_hash)
                .collect::<Vec<_>>(),
            expected_hashes
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.watermark.unwrap().position)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(
            engine
                .finalized
                .values()
                .all(|receipt| receipt.signatures.is_empty())
        );
        let milestone_count = engine.store.milestones().unwrap().len();
        let replayed_events = engine.finalize_trusted_epoch(&epoch).unwrap();
        assert_eq!(
            replayed_events
                .iter()
                .map(|event| (event.reference_hash, event.milestone, event.watermark))
                .collect::<Vec<_>>(),
            events
                .iter()
                .map(|event| (event.reference_hash, event.milestone, event.watermark))
                .collect::<Vec<_>>()
        );
        assert_eq!(engine.last_finalized_position, 3);
        assert_eq!(engine.store.milestones().unwrap().len(), milestone_count);
        let mut application = RecordingApplication::default();
        assert!(matches!(
            engine
                .apply_through_to(Watermark { position: 3 }, &mut application)
                .unwrap(),
            ApplyProgress::Applied {
                watermark: Watermark { position: 3 },
                completions
            } if completions.len() == 3
        ));

        let activation = engine
            .activate_application_contract(RouteGeneration(2), CommandSpecVersion(3))
            .unwrap();
        assert_eq!(activation.activated_at, Watermark { position: 3 });
        drop(engine);
        assert!(
            GlobalOrderedEngine::new_with_trust_mode(
                stores[0].clone(),
                ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
                holder_membership.clone(),
                ValidatorGeneration(5),
                validators.clone(),
                TrustMode::Trusted,
                64,
            )
            .is_err()
        );
        let upgraded = GlobalOrderedEngine::new_with_application_contract(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership,
            ValidatorGeneration(5),
            validators,
            TrustMode::Trusted,
            RouteGeneration(2),
            CommandSpecVersion(3),
        )
        .unwrap();
        assert_eq!(upgraded.route_generation(), RouteGeneration(2));
        assert_eq!(upgraded.command_spec_version(), CommandSpecVersion(3));
        drop(upgraded);
        drop(stores);
        for path in paths {
            std::fs::remove_dir_all(path).ok();
        }
    }

    #[test]
    fn availability_must_precede_finality_and_application_uses_certified_order() {
        let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let sites = ["site-a", "site-b", "site-c"];
        let paths = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                std::env::temp_dir().join(format!(
                    "blossom-global-order-{}-{index}-{}",
                    std::process::id(),
                    keypair.public
                ))
            })
            .collect::<Vec<_>>();
        let stores = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                DurableAdmissionStore::open(
                    &paths[index],
                    SiteId(sites[index].to_string()),
                    StoreGeneration(1),
                    keypair.signer(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let batch = CommandBatch {
            commands: vec![AdmittedCommand {
                origin_sequence: 1,
                command: command(9, 1, b"globally-ordered"),
            }],
        };
        let reference = reference(&batch, keypairs[0].public);
        let receipts = stores
            .iter()
            .map(|store| store.store_batch(&reference, &batch).unwrap())
            .collect::<Vec<_>>();
        let members_by_site = keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                (
                    SiteId(sites[index].to_string()),
                    [keypair.public].into_iter().collect(),
                )
            })
            .collect();
        let holder_membership = HolderMembership {
            epoch: ReplicaMembershipEpoch(3),
            members_by_site,
            store_generations: keypairs
                .iter()
                .map(|keypair| (keypair.public, StoreGeneration(1)))
                .collect(),
            holder_fault_bound: 0,
        };
        let availability = AvailabilityCertificate {
            reference: reference.clone(),
            trust: AvailabilityTrust::Trusted,
            receipts,
        };
        availability.verify(&holder_membership).unwrap();

        let validators = keypairs
            .iter()
            .map(|keypair| keypair.public)
            .collect::<BTreeSet<_>>();
        let mut engine = GlobalOrderedEngine::new(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership.clone(),
            ValidatorGeneration(5),
            validators.clone(),
            64,
        )
        .unwrap();
        let statement = OrderStatement {
            consensus_group_id: ConsensusGroupId::root(),
            blossom_epoch_hash: HashType([7; 32]),
            position: Watermark { position: 1 },
            reference_hash: reference.hash().unwrap(),
            previous_order_certificate_hash: HashType::default(),
            validator_generation: ValidatorGeneration(5),
        };
        let votes = stores
            .iter()
            .take(2)
            .map(|store| store.sign_order_statement(&statement).unwrap())
            .collect::<Vec<_>>();
        let certificate = OrderCertificate::from_votes(statement.clone(), votes).unwrap();
        let mut conflicting_statement = statement;
        conflicting_statement.reference_hash = HashType([99; 32]);
        assert!(
            stores[0]
                .sign_order_statement(&conflicting_statement)
                .is_err()
        );

        assert!(engine.finalize(certificate.clone()).is_err());
        engine.mark_available(availability).unwrap();
        assert_eq!(
            engine.last_origin_reference.get(&(
                reference.origin,
                reference.origin_incarnation,
                reference.origin_key_generation,
            )),
            Some(&(reference.hash().unwrap(), reference.last_origin_sequence))
        );
        let successor_batch = CommandBatch {
            commands: vec![AdmittedCommand {
                origin_sequence: 2,
                command: command(9, 2, b"successor"),
            }],
        };
        let successor_reference = BatchReference::for_batch(
            &successor_batch,
            BatchReferenceMetadata {
                cluster_id: HashType([1; 32]),
                consensus_group_id: ConsensusGroupId::root(),
                shard: b"shard-0".to_vec(),
                route_generation: RouteGeneration(1),
                command_spec_version: CommandSpecVersion(1),
                origin: keypairs[0].public,
                origin_incarnation: 1,
                origin_key_generation: 1,
                data_holder_membership_epoch: ReplicaMembershipEpoch(3),
                validator_generation: ValidatorGeneration(5),
                previous_origin_reference_hash: reference.hash().unwrap(),
            },
        )
        .unwrap();
        assert_eq!(
            successor_reference.previous_origin_reference_hash,
            reference.hash().unwrap()
        );
        assert_eq!(
            successor_reference.first_origin_sequence,
            reference.last_origin_sequence + 1
        );
        let successor_receipts = stores
            .iter()
            .map(|store| {
                store
                    .store_batch(&successor_reference, &successor_batch)
                    .unwrap()
            })
            .collect();
        engine
            .mark_available(AvailabilityCertificate {
                reference: successor_reference.clone(),
                trust: AvailabilityTrust::Trusted,
                receipts: successor_receipts,
            })
            .unwrap();
        let successor_statement = OrderStatement {
            consensus_group_id: ConsensusGroupId::root(),
            blossom_epoch_hash: HashType([8; 32]),
            position: Watermark { position: 1 },
            reference_hash: successor_reference.hash().unwrap(),
            previous_order_certificate_hash: HashType::default(),
            validator_generation: ValidatorGeneration(5),
        };
        let successor_signing_bytes =
            OrderCertificate::signing_bytes(&successor_statement).unwrap();
        let successor_certificate = OrderCertificate {
            statement: successor_statement,
            signatures: keypairs
                .iter()
                .take(2)
                .map(|keypair| {
                    (
                        keypair.public,
                        keypair.signer().sign(&successor_signing_bytes),
                    )
                })
                .collect(),
        };
        assert!(
            engine.finalize(successor_certificate).is_err(),
            "an origin successor cannot finalize before its predecessor"
        );
        engine.finalize(certificate.clone()).unwrap();
        engine.finalize(certificate).unwrap();
        let retention = RetentionEvidence {
            durable_snapshot_watermark: Watermark { position: 1 },
            applied_by: AppliedBy {
                membership_snapshot: ReplicaMembershipEpoch(3),
                required_nodes: [stores[0].holder].into_iter().collect(),
                watermark: Watermark { position: 1 },
            },
        };
        assert!(
            stores[0]
                .collect_batch(&reference, Watermark { position: 1 }, &retention)
                .unwrap()
        );
        let mut application = RecordingApplication::default();
        assert!(matches!(
            engine.apply_contiguous_to(&mut application).unwrap(),
            ApplyProgress::HeadOfLineUnavailable {
                watermark: Watermark { position: 0 },
                blocked_reference,
            } if blocked_reference == reference.hash().unwrap()
        ));
        stores[0].repair_batch_from(&stores[1], &reference).unwrap();
        assert!(engine.apply_contiguous_to(&mut FailingApplication).is_err());
        assert!(
            engine
                .apply_contiguous_to(&mut DivergentApplication)
                .is_err()
        );
        assert_eq!(engine.applied_watermark(), Watermark::default());

        let reference_hash = reference.hash().unwrap();
        assert!(matches!(
            engine
                .complete_write(
                    reference_hash,
                    WriteMode::GlobalApplied,
                    Duration::from_millis(10),
                    &mut application,
                )
                .unwrap(),
            WaitForOutcome::Reached(ReferenceStatus::Applied(AppliedCompletion {
                watermark: Watermark { position: 1 },
                ..
            }))
        ));
        engine
            .satisfy_read_consistency_to(ReadConsistency::Local, None, &mut application)
            .unwrap();
        assert_eq!(
            application.values.get(b"key".as_slice()),
            Some(&b"globally-ordered".to_vec())
        );
        assert!(matches!(
            engine.status(reference_hash).unwrap(),
            ReferenceStatus::Applied(AppliedCompletion {
                watermark: Watermark { position: 1 },
                ..
            })
        ));
        assert!(matches!(
            engine
                .wait_for(reference_hash, Milestone::Applied, Duration::from_millis(1))
                .unwrap(),
            WaitForOutcome::Reached(ReferenceStatus::Applied(_))
        ));
        assert!(matches!(
            engine
                .wait_for(
                    HashType([0xEE; 32]),
                    Milestone::Applied,
                    Duration::from_millis(1)
                )
                .unwrap(),
            WaitForOutcome::TimedOut(ReferenceStatus::Unknown)
        ));

        drop(engine);
        let mut restarted = GlobalOrderedEngine::new(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership.clone(),
            ValidatorGeneration(5),
            validators.clone(),
            64,
        )
        .unwrap();
        assert_eq!(restarted.applied_watermark(), Watermark { position: 1 });
        assert!(matches!(
            restarted.apply_contiguous_to(&mut application).unwrap(),
            ApplyProgress::Applied {
                watermark: Watermark { position: 1 },
                completions
            } if completions.is_empty()
        ));
        let request = ReadBarrierRequest::fresh();
        let statement = restarted.read_barrier_statement(request).unwrap();
        let votes = stores
            .iter()
            .take(2)
            .map(|store| store.sign_read_barrier_statement(&statement).unwrap())
            .collect::<Vec<_>>();
        let barrier = CertifiedReadBarrier {
            request,
            certificate: ReadBarrierCertificate::from_votes(statement, votes).unwrap(),
        };
        assert_eq!(
            restarted
                .satisfy_read_consistency_to(
                    ReadConsistency::Linearizable,
                    Some(&barrier),
                    &mut application,
                )
                .unwrap(),
            Watermark { position: 1 }
        );
        let mut replayed_with_different_request = barrier;
        replayed_with_different_request.request = ReadBarrierRequest::fresh();
        assert!(
            restarted
                .satisfy_read_consistency_to(
                    ReadConsistency::Linearizable,
                    Some(&replayed_with_different_request),
                    &mut application,
                )
                .is_err()
        );
        drop(restarted);
        drop(stores);
        for path in paths {
            std::fs::remove_dir_all(path).ok();
        }
    }
}
