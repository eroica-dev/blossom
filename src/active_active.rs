use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use borsh::{BorshDeserialize, BorshSerialize};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::algorithm::{has_supermajority, supermajority_count};
use crate::block::Transaction;
use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::HashType;
use crate::runtime::TrustMode;
use crate::safety::SiteId;
use crate::state::Epoch;
use crate::telemetry::{TelemetryEvent, TelemetryEventKind, TelemetryHandle};

const COMMAND_HASH_DOMAIN: &[u8] = b"blossom/active-active/command/v1";
const REFERENCE_HASH_DOMAIN: &[u8] = b"blossom/active-active/batch-reference/v1";
const REFERENCE_TRANSACTION_DOMAIN: &[u8] = b"blossom/active-active/reference-transaction/v1";
const MERKLE_LEAF_DOMAIN: &[u8] = b"blossom/active-active/merkle-leaf/v1";
const MERKLE_NODE_DOMAIN: &[u8] = b"blossom/active-active/merkle-node/v1";
const ADMISSION_RECEIPT_DOMAIN: &[u8] = b"blossom/active-active/admission-receipt/v1";
const AVAILABILITY_RECEIPT_DOMAIN: &[u8] = b"blossom/active-active/availability-receipt/v1";
const ORDER_STATEMENT_DOMAIN: &[u8] = b"blossom/active-active/order-statement/v1";
const ORDER_CERTIFICATE_DOMAIN: &[u8] = b"blossom/active-active/order-certificate/v1";
const ORDER_VOTE_HASH_DOMAIN: &[u8] = b"blossom/active-active/order-vote/v1";
const MAX_COMMAND_KEY_BYTES: usize = 1 << 20;
const MAX_COMMAND_VALUE_BYTES: usize = 64 << 20;
pub const MAX_PIPELINED_AVAILABILITY_WINDOWS: usize = 8;
/// One trusted ordering window may contain one reference from every validator.
///
/// The runtime bounds pending availability by windows, not by individual
/// parallel writers, so universal-writer epochs do not exhaust the pipeline
/// merely because the validator population is large.
pub const MAX_REFERENCES_PER_ORDERING_WINDOW: usize = 65_536;

const COMMANDS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("active_active_commands_v1");
const COMMAND_IDENTITIES_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("active_active_command_identities_v1");
const BATCHES_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("active_active_batches_v1");
const MILESTONES_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("active_active_milestones_v1");
const ACTIVE_STATE_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("active_active_state_v1");
const META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("active_active_meta_v1");
const ORDER_VOTES_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("active_active_order_votes_v1");
const STATE_MACHINE_KEY: &str = "state_machine";
const ORDERED_ENGINE_KEY: &str = "ordered_engine";
const DURABLE_ORDERED_STATE_VERSION: u16 = 1;

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

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum CommandOperation {
    BlindWrite {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Append {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    CompareAndSwap {
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        value: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActiveActiveCommand {
    pub identity: CommandIdentity,
    pub operation: CommandOperation,
}

impl ActiveActiveCommand {
    pub fn validate(&self) -> Result<()> {
        if self.identity.sequence == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "client command sequences start at one".to_string(),
            ));
        }
        let (key, values) = match &self.operation {
            CommandOperation::BlindWrite { key, value }
            | CommandOperation::Append { key, value } => (key, vec![value]),
            CommandOperation::CompareAndSwap {
                key,
                expected,
                value,
            } => {
                let mut values = vec![value];
                if let Some(expected) = expected {
                    values.push(expected);
                }
                (key, values)
            }
        };
        if key.is_empty() || key.len() > MAX_COMMAND_KEY_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "command key must contain 1..={MAX_COMMAND_KEY_BYTES} bytes"
            )));
        }
        if values
            .into_iter()
            .any(|value| value.len() > MAX_COMMAND_VALUE_BYTES)
        {
            return Err(BlossomError::InvalidConfiguration(format!(
                "command value exceeds {MAX_COMMAND_VALUE_BYTES} bytes"
            )));
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<HashType> {
        self.validate()?;
        hash_borsh(COMMAND_HASH_DOMAIN, self)
    }

    pub fn is_compare_and_swap(&self) -> bool {
        matches!(self.operation, CommandOperation::CompareAndSwap { .. })
    }
}

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
    Sealed,
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
}

impl WriteMode {
    pub fn required_milestone(self, command: &ActiveActiveCommand) -> Milestone {
        if command.is_compare_and_swap() {
            Milestone::Applied
        } else {
            match self {
                Self::LocalAsync => Milestone::AcceptedLocal,
                Self::GlobalFinalized => Milestone::Finalized,
            }
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
    pub origin: PubKey,
    pub origin_incarnation: u64,
    pub origin_key_generation: u64,
    pub data_holder_membership_epoch: ReplicaMembershipEpoch,
    pub validator_generation: ValidatorGeneration,
    pub previous_origin_reference_hash: HashType,
}

impl BatchReference {
    pub const FORMAT_VERSION: u16 = 1;
    pub const CODEC_VERSION: u16 = 1;

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

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum CommandResult {
    Written,
    Appended {
        new_length: u64,
    },
    CompareAndSwap {
        swapped: bool,
        current: Option<Vec<u8>>,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct CachedResult {
    command_hash: HashType,
    result: CommandResult,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct SessionDedupState {
    contiguous_sequence: u64,
    sparse_executed: BTreeSet<u64>,
    recent_results: BTreeMap<u64, CachedResult>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct DeduplicationWindow {
    max_reorder: u64,
    sessions: BTreeMap<(ClientId, ClientEpoch), SessionDedupState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupDecision {
    Execute,
    Cached(CommandResult),
}

impl DeduplicationWindow {
    pub fn new(max_reorder: u64) -> Result<Self> {
        if max_reorder == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "deduplication reorder window must be positive".to_string(),
            ));
        }
        Ok(Self {
            max_reorder,
            sessions: BTreeMap::new(),
        })
    }

    pub fn check(
        &self,
        identity: CommandIdentity,
        command_hash: HashType,
    ) -> Result<DedupDecision> {
        let Some(session) = self
            .sessions
            .get(&(identity.client_id, identity.client_epoch))
        else {
            if identity.sequence > self.max_reorder {
                return Err(BlossomError::InvalidConfiguration(
                    "first client sequence is outside the reorder window".to_string(),
                ));
            }
            return Ok(DedupDecision::Execute);
        };
        if let Some(cached) = session.recent_results.get(&identity.sequence) {
            if cached.command_hash != command_hash {
                return Err(BlossomError::InvalidConfiguration(
                    "conflicting bytes for one command identity".to_string(),
                ));
            }
            return Ok(DedupDecision::Cached(cached.result.clone()));
        }
        if identity.sequence <= session.contiguous_sequence {
            return Err(BlossomError::InvalidConfiguration(
                "command identity is older than the retained result window".to_string(),
            ));
        }
        let maximum = session.contiguous_sequence.saturating_add(self.max_reorder);
        if identity.sequence > maximum {
            return Err(BlossomError::InvalidConfiguration(
                "client sequence exceeds the bounded reorder window".to_string(),
            ));
        }
        Ok(DedupDecision::Execute)
    }

    pub fn record(
        &mut self,
        identity: CommandIdentity,
        command_hash: HashType,
        result: CommandResult,
    ) -> Result<()> {
        let session = self
            .sessions
            .entry((identity.client_id, identity.client_epoch))
            .or_insert_with(|| SessionDedupState {
                contiguous_sequence: 0,
                sparse_executed: BTreeSet::new(),
                recent_results: BTreeMap::new(),
            });
        if let Some(existing) = session.recent_results.get(&identity.sequence) {
            if existing.command_hash != command_hash {
                return Err(BlossomError::InvalidConfiguration(
                    "conflicting bytes for one command identity".to_string(),
                ));
            }
            return Ok(());
        }
        session.sparse_executed.insert(identity.sequence);
        session.recent_results.insert(
            identity.sequence,
            CachedResult {
                command_hash,
                result,
            },
        );
        while session
            .contiguous_sequence
            .checked_add(1)
            .is_some_and(|next| session.sparse_executed.remove(&next))
        {
            session.contiguous_sequence += 1;
        }
        let retain_from = session
            .contiguous_sequence
            .saturating_sub(self.max_reorder.saturating_sub(1));
        session
            .recent_results
            .retain(|sequence, _| *sequence >= retain_from);
        Ok(())
    }

    pub fn contiguous_sequence(&self, client_id: ClientId, client_epoch: ClientEpoch) -> u64 {
        self.sessions
            .get(&(client_id, client_epoch))
            .map_or(0, |state| state.contiguous_sequence)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct SharedStateMachine {
    values: BTreeMap<Vec<u8>, Vec<u8>>,
    deduplication: DeduplicationWindow,
}

impl SharedStateMachine {
    pub fn new(max_reorder: u64) -> Result<Self> {
        Ok(Self {
            values: BTreeMap::new(),
            deduplication: DeduplicationWindow::new(max_reorder)?,
        })
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.values.get(key).map(Vec::as_slice)
    }

    pub fn apply(&mut self, command: &ActiveActiveCommand) -> Result<CommandResult> {
        command.validate()?;
        let command_hash = command.hash()?;
        match self.deduplication.check(command.identity, command_hash)? {
            DedupDecision::Cached(result) => return Ok(result),
            DedupDecision::Execute => {}
        }

        let result = match &command.operation {
            CommandOperation::BlindWrite { key, value } => {
                self.values.insert(key.clone(), value.clone());
                CommandResult::Written
            }
            CommandOperation::Append { key, value } => {
                let stored = self.values.entry(key.clone()).or_default();
                stored.extend_from_slice(value);
                CommandResult::Appended {
                    new_length: u64::try_from(stored.len()).unwrap_or(u64::MAX),
                }
            }
            CommandOperation::CompareAndSwap {
                key,
                expected,
                value,
            } => {
                let current = self.values.get(key).cloned();
                let swapped = &current == expected;
                if swapped {
                    self.values.insert(key.clone(), value.clone());
                }
                CommandResult::CompareAndSwap { swapped, current }
            }
        };
        self.deduplication
            .record(command.identity, command_hash, result.clone())?;
        Ok(result)
    }

    pub fn deduplication(&self) -> &DeduplicationWindow {
        &self.deduplication
    }

    pub fn values(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.values
    }

    pub fn canonical_hash(&self) -> Result<HashType> {
        hash_borsh(b"blossom/active-active/state-machine/v1", self)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct DurableOrderedState {
    version: u16,
    holder_membership_epoch: ReplicaMembershipEpoch,
    validator_generation: ValidatorGeneration,
    available: BTreeMap<HashType, AvailabilityCertificate>,
    finalized: BTreeMap<u64, OrderCertificate>,
    final_reference_by_position: BTreeMap<u64, HashType>,
    last_origin_reference: BTreeMap<(PubKey, u64, u64), (HashType, u64)>,
    last_finalized_position: u64,
    last_order_certificate_hash: HashType,
    applied_watermark: Watermark,
}

#[derive(Clone)]
pub struct DurableAdmissionStore {
    database: Arc<Database>,
    holder: PubKey,
    site: SiteId,
    store_generation: StoreGeneration,
    signer: SecretSigner,
}

impl DurableAdmissionStore {
    pub fn open(
        path: impl AsRef<Path>,
        site: SiteId,
        store_generation: StoreGeneration,
        signer: SecretSigner,
    ) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|err| BlossomError::Io(err.to_string()))?;
        }
        let database = Database::create(path).map_err(storage_error)?;
        let store = Self {
            database: Arc::new(database),
            holder: signer.public_key(),
            site,
            store_generation,
            signer,
        };
        store.initialize_tables()?;
        Ok(store)
    }

    fn initialize_tables(&self) -> Result<()> {
        let mut transaction = self.database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            transaction
                .open_table(COMMANDS_TABLE)
                .map_err(storage_error)?;
            transaction
                .open_table(COMMAND_IDENTITIES_TABLE)
                .map_err(storage_error)?;
            transaction
                .open_table(BATCHES_TABLE)
                .map_err(storage_error)?;
            transaction
                .open_table(MILESTONES_TABLE)
                .map_err(storage_error)?;
            transaction
                .open_table(ACTIVE_STATE_TABLE)
                .map_err(storage_error)?;
            transaction.open_table(META_TABLE).map_err(storage_error)?;
            transaction
                .open_table(ORDER_VOTES_TABLE)
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)
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

        let mut transaction = self.database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            let mut identities = transaction
                .open_table(COMMAND_IDENTITIES_TABLE)
                .map_err(storage_error)?;
            if let Some(existing) = identities
                .get(identity_key.as_slice())
                .map_err(storage_error)?
            {
                if existing.value() != command_hash.as_ref() {
                    return Err(BlossomError::InvalidConfiguration(
                        "conflicting bytes for one command identity".to_string(),
                    ));
                }
            } else {
                identities
                    .insert(identity_key.as_slice(), command_hash.as_ref())
                    .map_err(storage_error)?;
            }
            let mut commands = transaction
                .open_table(COMMANDS_TABLE)
                .map_err(storage_error)?;
            commands
                .insert(command_key.as_slice(), command_bytes.as_slice())
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;

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
        let mut transaction = self.database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            let mut table = transaction
                .open_table(BATCHES_TABLE)
                .map_err(storage_error)?;
            table
                .insert(reference_hash.as_ref(), bytes.as_slice())
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;

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
        let transaction = self.database.begin_read().map_err(storage_error)?;
        let table = transaction
            .open_table(BATCHES_TABLE)
            .map_err(storage_error)?;
        let Some(bytes) = table.get(hash.as_ref()).map_err(storage_error)? else {
            return Ok(None);
        };
        let batch = borsh::from_slice::<CommandBatch>(bytes.value()).map_err(|err| {
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
        let mut transaction = self.database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        let removed = {
            let mut table = transaction
                .open_table(BATCHES_TABLE)
                .map_err(storage_error)?;
            table
                .remove(hash.as_ref())
                .map_err(storage_error)?
                .is_some()
        };
        transaction.commit().map_err(storage_error)?;
        Ok(removed)
    }

    pub fn record_milestone(&self, event: &MilestoneEvent) -> Result<u64> {
        let bytes = borsh::to_vec(event).map_err(encode_error)?;
        let mut transaction = self.database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        let sequence;
        {
            let mut meta = transaction.open_table(META_TABLE).map_err(storage_error)?;
            sequence = meta
                .get("next_milestone_sequence")
                .map_err(storage_error)?
                .map_or(0, |value| value.value());
            let next = sequence.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("milestone sequence overflow".to_string())
            })?;
            meta.insert("next_milestone_sequence", next)
                .map_err(storage_error)?;
            let mut events = transaction
                .open_table(MILESTONES_TABLE)
                .map_err(storage_error)?;
            events
                .insert(sequence, bytes.as_slice())
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(sequence)
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
        let mut transaction = self.database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            let mut votes = transaction
                .open_table(ORDER_VOTES_TABLE)
                .map_err(storage_error)?;
            if let Some(existing) = votes.get(vote_key.as_slice()).map_err(storage_error)? {
                if existing.value() != statement_hash.as_ref() {
                    return Err(BlossomError::InvalidConfiguration(
                        "validator refuses to equivocate at one order position".to_string(),
                    ));
                }
            } else {
                votes
                    .insert(vote_key.as_slice(), statement_hash.as_ref())
                    .map_err(storage_error)?;
            }
        }
        transaction.commit().map_err(storage_error)?;
        let signature = self
            .signer
            .sign(&OrderCertificate::signing_bytes(statement)?);
        Ok(OrderVote {
            statement: statement.clone(),
            validator: self.holder,
            signature,
        })
    }

    pub fn milestones(&self) -> Result<Vec<MilestoneEvent>> {
        let transaction = self.database.begin_read().map_err(storage_error)?;
        let table = transaction
            .open_table(MILESTONES_TABLE)
            .map_err(storage_error)?;
        table
            .iter()
            .map_err(storage_error)?
            .map(|entry| {
                let (_, value) = entry.map_err(storage_error)?;
                borsh::from_slice(value.value()).map_err(|err| {
                    BlossomError::WireProtocol(format!("decode milestone event: {err}"))
                })
            })
            .collect()
    }

    pub fn persist_state_machine(
        &self,
        machine: &SharedStateMachine,
        watermark: Watermark,
    ) -> Result<()> {
        let bytes = borsh::to_vec(&(machine, watermark)).map_err(encode_error)?;
        let mut transaction = self.database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            let mut table = transaction
                .open_table(ACTIVE_STATE_TABLE)
                .map_err(storage_error)?;
            table
                .insert(STATE_MACHINE_KEY, bytes.as_slice())
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)
    }

    pub fn load_state_machine(&self) -> Result<Option<(SharedStateMachine, Watermark)>> {
        let transaction = self.database.begin_read().map_err(storage_error)?;
        let table = transaction
            .open_table(ACTIVE_STATE_TABLE)
            .map_err(storage_error)?;
        let Some(bytes) = table.get(STATE_MACHINE_KEY).map_err(storage_error)? else {
            return Ok(None);
        };
        borsh::from_slice(bytes.value())
            .map(Some)
            .map_err(|err| BlossomError::WireProtocol(format!("decode state machine: {err}")))
    }

    fn persist_ordered_state(
        &self,
        machine: &SharedStateMachine,
        state: &DurableOrderedState,
        milestone: Option<&MilestoneEvent>,
    ) -> Result<()> {
        self.persist_ordered_state_with_milestones(
            machine,
            state,
            milestone.map(std::slice::from_ref).unwrap_or_default(),
        )
    }

    fn persist_ordered_state_with_milestones(
        &self,
        machine: &SharedStateMachine,
        state: &DurableOrderedState,
        milestones: &[MilestoneEvent],
    ) -> Result<()> {
        let machine_bytes =
            borsh::to_vec(&(machine, state.applied_watermark)).map_err(encode_error)?;
        let ordered_bytes = borsh::to_vec(state).map_err(encode_error)?;
        let milestone_bytes = milestones
            .iter()
            .map(borsh::to_vec)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(encode_error)?;
        let mut transaction = self.database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            let mut table = transaction
                .open_table(ACTIVE_STATE_TABLE)
                .map_err(storage_error)?;
            table
                .insert(STATE_MACHINE_KEY, machine_bytes.as_slice())
                .map_err(storage_error)?;
            table
                .insert(ORDERED_ENGINE_KEY, ordered_bytes.as_slice())
                .map_err(storage_error)?;
            if !milestone_bytes.is_empty() {
                let mut sequence = transaction
                    .open_table(META_TABLE)
                    .map_err(storage_error)?
                    .get("next_milestone_sequence")
                    .map_err(storage_error)?
                    .map_or(0, |value| value.value());
                let mut events = transaction
                    .open_table(MILESTONES_TABLE)
                    .map_err(storage_error)?;
                for event_bytes in &milestone_bytes {
                    events
                        .insert(sequence, event_bytes.as_slice())
                        .map_err(storage_error)?;
                    sequence = sequence.checked_add(1).ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "milestone sequence overflow".to_string(),
                        )
                    })?;
                }
                drop(events);
                let mut meta = transaction.open_table(META_TABLE).map_err(storage_error)?;
                meta.insert("next_milestone_sequence", sequence)
                    .map_err(storage_error)?;
            }
        }
        transaction.commit().map_err(storage_error)
    }

    fn load_ordered_state(&self) -> Result<Option<DurableOrderedState>> {
        let transaction = self.database.begin_read().map_err(storage_error)?;
        let table = transaction
            .open_table(ACTIVE_STATE_TABLE)
            .map_err(storage_error)?;
        let Some(bytes) = table.get(ORDERED_ENGINE_KEY).map_err(storage_error)? else {
            return Ok(None);
        };
        borsh::from_slice(bytes.value())
            .map(Some)
            .map_err(|err| BlossomError::WireProtocol(format!("decode ordered engine: {err}")))
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
    pub canonical_results: Vec<CommandResult>,
}

/// Application-owned state-machine hook for direct Blossom integrations.
///
/// `shard-kv`, `shard-stream`, and other consumers implement this trait in
/// their own crates. The callback is invoked in certified order and must be
/// idempotent for the supplied `(reference_hash, watermark)` replay key.
pub trait OrderedApplication {
    fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<CommandResult>>;
}

#[derive(Debug, Default)]
struct CanonicalOnlyApplication;

impl OrderedApplication for CanonicalOnlyApplication {
    fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<CommandResult>> {
        Ok(ordered.canonical_results.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyProgress {
    Applied {
        watermark: Watermark,
        results: Vec<CommandResult>,
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
    last_origin_reference: BTreeMap<(PubKey, u64, u64), (HashType, u64)>,
    last_finalized_position: u64,
    last_order_certificate_hash: HashType,
    applied_watermark: Watermark,
    state_machine: SharedStateMachine,
    telemetry: TelemetryHandle,
}

impl GlobalOrderedEngine {
    pub fn new(
        store: DurableAdmissionStore,
        mode: ActiveActiveConsistencyMode,
        holder_membership: HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: BTreeSet<PubKey>,
        max_reorder: u64,
    ) -> Result<Self> {
        Self::new_with_trust_mode(
            store,
            mode,
            holder_membership,
            validator_generation,
            validators,
            TrustMode::Verified,
            max_reorder,
        )
    }

    pub fn new_with_trust_mode(
        store: DurableAdmissionStore,
        mode: ActiveActiveConsistencyMode,
        holder_membership: HolderMembership,
        validator_generation: ValidatorGeneration,
        validators: BTreeSet<PubKey>,
        order_trust_mode: TrustMode,
        max_reorder: u64,
    ) -> Result<Self> {
        if mode != ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered {
            return Err(BlossomError::InvalidConfiguration(
                "GlobalOrderedEngine requires active-sync-global-ordered mode".to_string(),
            ));
        }
        holder_membership.validate()?;
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
        let (state_machine, applied_watermark) = store
            .load_state_machine()?
            .unwrap_or((SharedStateMachine::new(max_reorder)?, Watermark::default()));
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
            last_origin_reference: BTreeMap::new(),
            last_finalized_position: 0,
            last_order_certificate_hash: HashType::default(),
            applied_watermark,
            state_machine,
            telemetry: TelemetryHandle::default(),
        };
        if let Some(state) = loaded_ordered {
            engine.validate_durable_state(&state)?;
            if state.applied_watermark != engine.applied_watermark {
                return Err(BlossomError::InvalidConfiguration(
                    "durable state machine and ordered-engine watermarks disagree".to_string(),
                ));
            }
            engine.install_durable_state(state);
        } else if engine.applied_watermark != Watermark::default() {
            return Err(BlossomError::InvalidConfiguration(
                "state machine has applied data but no durable ordered-engine chain".to_string(),
            ));
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
        let mut durable = self.durable_state();
        durable.last_origin_reference.insert(
            origin_key,
            (reference_hash, certificate.reference.last_origin_sequence),
        );
        durable.available.insert(reference_hash, certificate);
        let event = milestone_event(self.mode, reference_hash, Milestone::Available, None);
        self.store
            .persist_ordered_state(&self.state_machine, &durable, Some(&event))?;
        self.install_durable_state(durable);
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

        let mut durable = self.durable_state();
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
            durable.finalized.insert(next_position, receipt);
            durable
                .final_reference_by_position
                .insert(next_position, reference_hash);
            events.push(milestone_event(
                self.mode,
                reference_hash,
                Milestone::Finalized,
                Some(Watermark {
                    position: next_position,
                }),
            ));
        }
        durable.last_finalized_position = next_position;
        durable.last_order_certificate_hash = previous_certificate_hash;
        self.store
            .persist_ordered_state_with_milestones(&self.state_machine, &durable, &events)?;
        self.install_durable_state(durable);
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
        if reference.validator_generation != self.validator_generation {
            return Err(BlossomError::InvalidConfiguration(
                "batch reference validator generation mismatch".to_string(),
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
        let mut durable = self.durable_state();
        durable
            .finalized
            .insert(statement.position.position, certificate.clone());
        durable
            .final_reference_by_position
            .insert(statement.position.position, statement.reference_hash);
        durable.last_finalized_position = statement.position.position;
        durable.last_order_certificate_hash = certificate_hash;
        let event = milestone_event(
            self.mode,
            statement.reference_hash,
            Milestone::Finalized,
            Some(statement.position),
        );
        self.store
            .persist_ordered_state(&self.state_machine, &durable, Some(&event))?;
        self.install_durable_state(durable);
        self.telemetry.record_milestone(&event);
        Ok(event)
    }

    pub fn apply_contiguous(&mut self) -> Result<ApplyProgress> {
        self.apply_contiguous_to(&mut CanonicalOnlyApplication)
    }

    pub fn apply_contiguous_to<A: OrderedApplication>(
        &mut self,
        application: &mut A,
    ) -> Result<ApplyProgress> {
        let next_position = self.applied_watermark.position.saturating_add(1);
        let Some(certificate) = self.finalized.get(&next_position) else {
            return Ok(ApplyProgress::Applied {
                watermark: self.applied_watermark,
                results: Vec::new(),
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
        let mut staged_machine = self.state_machine.clone();
        let mut results = Vec::with_capacity(batch.commands.len());
        for command in &batch.commands {
            results.push(staged_machine.apply(&command.command)?);
        }
        let next_watermark = certificate.statement.position;
        let application_results = application.apply_ordered(&OrderedBatch {
            reference_hash,
            reference: availability.reference.clone(),
            batch,
            watermark: next_watermark,
            canonical_results: results.clone(),
        })?;
        if application_results != results {
            return Err(BlossomError::ExternalService(
                "application results diverged from the shared command specification".to_string(),
            ));
        }
        let mut durable = self.durable_state();
        durable.applied_watermark = next_watermark;
        durable.available.remove(&reference_hash);
        let event = milestone_event(
            self.mode,
            reference_hash,
            Milestone::Applied,
            Some(next_watermark),
        );
        self.store
            .persist_ordered_state(&staged_machine, &durable, Some(&event))?;
        self.state_machine = staged_machine;
        self.install_durable_state(durable);
        self.telemetry.record_milestone(&event);
        Ok(ApplyProgress::Applied {
            watermark: self.applied_watermark,
            results,
        })
    }

    pub fn apply_through(&mut self, target: Watermark) -> Result<ApplyProgress> {
        self.apply_through_to(target, &mut CanonicalOnlyApplication)
    }

    pub fn apply_through_to<A: OrderedApplication>(
        &mut self,
        target: Watermark,
        application: &mut A,
    ) -> Result<ApplyProgress> {
        let mut all_results = Vec::new();
        while self.applied_watermark < target {
            match self.apply_contiguous_to(application)? {
                ApplyProgress::Applied { watermark, results } => {
                    if results.is_empty() && watermark < target {
                        return Err(BlossomError::FailedConsensus);
                    }
                    all_results.extend(results);
                }
                blocked @ ApplyProgress::HeadOfLineUnavailable { .. } => return Ok(blocked),
            }
        }
        Ok(ApplyProgress::Applied {
            watermark: self.applied_watermark,
            results: all_results,
        })
    }

    pub fn read(
        &mut self,
        key: &[u8],
        consistency: ReadConsistency,
        linearizable_barrier: Option<Watermark>,
    ) -> Result<Option<Vec<u8>>> {
        self.satisfy_read_consistency_to(
            consistency,
            linearizable_barrier,
            &mut CanonicalOnlyApplication,
        )?;
        Ok(self.state_machine.get(key).map(<[u8]>::to_vec))
    }

    /// Advances an embedding application to the watermark required by a read.
    ///
    /// After this method succeeds the caller can issue the actual read against
    /// its own state machine. A linearizable read requires a freshly certified
    /// Blossom order/read barrier supplied by the caller's consensus driver.
    pub fn satisfy_read_consistency_to<A: OrderedApplication>(
        &mut self,
        consistency: ReadConsistency,
        linearizable_barrier: Option<Watermark>,
        application: &mut A,
    ) -> Result<Watermark> {
        let required = match consistency {
            ReadConsistency::Local => None,
            ReadConsistency::AtLeast(watermark) => Some(watermark),
            ReadConsistency::Linearizable => Some(linearizable_barrier.ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "linearizable Blossom read requires an order/read barrier".to_string(),
                )
            })?),
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

    fn ensure_origin_predecessor_finalized(&self, reference: &BatchReference) -> Result<()> {
        if reference.previous_origin_reference_hash != HashType::default()
            && !self
                .final_reference_by_position
                .values()
                .any(|hash| *hash == reference.previous_origin_reference_hash)
        {
            return Err(BlossomError::InvalidConfiguration(
                "an origin reference cannot finalize before its hash-chain predecessor".to_string(),
            ));
        }
        Ok(())
    }

    fn durable_state(&self) -> DurableOrderedState {
        DurableOrderedState {
            version: DURABLE_ORDERED_STATE_VERSION,
            holder_membership_epoch: self.holder_membership.epoch,
            validator_generation: self.validator_generation,
            available: self.available.clone(),
            finalized: self.finalized.clone(),
            final_reference_by_position: self.final_reference_by_position.clone(),
            last_origin_reference: self.last_origin_reference.clone(),
            last_finalized_position: self.last_finalized_position,
            last_order_certificate_hash: self.last_order_certificate_hash,
            applied_watermark: self.applied_watermark,
        }
    }

    fn install_durable_state(&mut self, state: DurableOrderedState) {
        self.available = state.available;
        self.finalized = state.finalized;
        self.final_reference_by_position = state.final_reference_by_position;
        self.last_origin_reference = state.last_origin_reference;
        self.last_finalized_position = state.last_finalized_position;
        self.last_order_certificate_hash = state.last_order_certificate_hash;
        self.applied_watermark = state.applied_watermark;
    }

    fn validate_durable_state(&self, state: &DurableOrderedState) -> Result<()> {
        if state.version != DURABLE_ORDERED_STATE_VERSION
            || state.holder_membership_epoch != self.holder_membership.epoch
            || state.validator_generation != self.validator_generation
            || state.applied_watermark.position > state.last_finalized_position
        {
            return Err(BlossomError::InvalidConfiguration(
                "durable ordered-engine parameters do not match startup configuration".to_string(),
            ));
        }
        for availability in state.available.values() {
            availability.verify(&self.holder_membership)?;
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

fn storage_error(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::Io(format!("redb: {error}"))
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

    #[derive(Default)]
    struct RecordingApplication {
        applied: BTreeSet<(HashType, Watermark)>,
        values: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl OrderedApplication for RecordingApplication {
        fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<CommandResult>> {
            if !self
                .applied
                .insert((ordered.reference_hash, ordered.watermark))
            {
                return Ok(ordered.canonical_results.clone());
            }
            for admitted in &ordered.batch.commands {
                match &admitted.command.operation {
                    CommandOperation::BlindWrite { key, value } => {
                        self.values.insert(key.clone(), value.clone());
                    }
                    CommandOperation::Append { key, value } => {
                        self.values
                            .entry(key.clone())
                            .or_default()
                            .extend_from_slice(value);
                    }
                    CommandOperation::CompareAndSwap {
                        key,
                        expected,
                        value,
                    } if self.values.get(key) == expected.as_ref() => {
                        self.values.insert(key.clone(), value.clone());
                    }
                    CommandOperation::CompareAndSwap { .. } => {}
                }
            }
            Ok(ordered.canonical_results.clone())
        }
    }

    struct FailingApplication;

    impl OrderedApplication for FailingApplication {
        fn apply_ordered(&mut self, _ordered: &OrderedBatch) -> Result<Vec<CommandResult>> {
            Err(BlossomError::ExternalService(
                "application unavailable".to_string(),
            ))
        }
    }

    struct DivergentApplication;

    impl OrderedApplication for DivergentApplication {
        fn apply_ordered(&mut self, _ordered: &OrderedBatch) -> Result<Vec<CommandResult>> {
            Ok(Vec::new())
        }
    }

    fn command(client: u8, sequence: u64, value: &[u8]) -> ActiveActiveCommand {
        ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([client; 16]),
                client_epoch: ClientEpoch(1),
                sequence,
            },
            operation: CommandOperation::BlindWrite {
                key: b"key".to_vec(),
                value: value.to_vec(),
            },
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
    fn reordered_client_sequences_execute_exactly_once() {
        let mut state = SharedStateMachine::new(64).unwrap();
        let sequence_11 = command(1, 11, b"eleven");
        let sequence_10 = command(1, 10, b"ten");

        state.apply(&sequence_11).unwrap();
        state.apply(&sequence_10).unwrap();
        assert_eq!(
            state
                .deduplication()
                .contiguous_sequence(ClientId([1; 16]), ClientEpoch(1)),
            0,
            "sequences 1 through 9 are still missing"
        );

        for sequence in 1..=9 {
            state
                .apply(&command(1, sequence, &[sequence as u8]))
                .unwrap();
        }
        assert_eq!(
            state
                .deduplication()
                .contiguous_sequence(ClientId([1; 16]), ClientEpoch(1)),
            11
        );
        let duplicate = state.apply(&sequence_11).unwrap();
        assert_eq!(duplicate, CommandResult::Written);
    }

    #[test]
    fn conflicting_bytes_for_one_identity_are_rejected() {
        let mut state = SharedStateMachine::new(64).unwrap();
        state.apply(&command(2, 1, b"first")).unwrap();
        assert!(state.apply(&command(2, 1, b"second")).is_err());
    }

    #[test]
    fn compare_and_swap_requires_applied_completion() {
        let cas = ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([4; 16]),
                client_epoch: ClientEpoch(1),
                sequence: 1,
            },
            operation: CommandOperation::CompareAndSwap {
                key: b"key".to_vec(),
                expected: None,
                value: b"value".to_vec(),
            },
        };
        assert_eq!(
            WriteMode::LocalAsync.required_milestone(&cas),
            Milestone::Applied
        );
        assert_eq!(
            WriteMode::GlobalFinalized.required_milestone(&cas),
            Milestone::Applied
        );
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
            "blossom-active-active-{}-{}.redb",
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

        let mut machine = SharedStateMachine::new(16).unwrap();
        machine.apply(&first.command).unwrap();
        store
            .persist_state_machine(&machine, Watermark { position: 1 })
            .unwrap();
        drop(store);

        let reopened = DurableAdmissionStore::open(
            &path,
            SiteId("site-a".to_string()),
            StoreGeneration(1),
            keypair.signer(),
        )
        .unwrap();
        let (machine, watermark) = reopened.load_state_machine().unwrap().unwrap();
        assert_eq!(watermark.position, 1);
        assert_eq!(machine.get(b"key"), Some(b"first".as_slice()));
        drop(reopened);
        std::fs::remove_file(path).ok();
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
                    "blossom-trusted-order-restart-{}-{index}-{}.redb",
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
        drop(stores);
        for path in paths {
            std::fs::remove_file(path).ok();
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
                    "blossom-trusted-parallel-writers-{}-{index}-{}.redb",
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
            holder_membership,
            ValidatorGeneration(5),
            validators,
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
        assert!(matches!(
            engine.apply_through(Watermark { position: 3 }).unwrap(),
            ApplyProgress::Applied {
                watermark: Watermark { position: 3 },
                results
            } if results.len() == 3
        ));

        drop(engine);
        drop(stores);
        for path in paths {
            std::fs::remove_file(path).ok();
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
                    "blossom-global-order-{}-{index}-{}.redb",
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
        assert!(matches!(
            engine.apply_contiguous().unwrap(),
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

        let mut application = RecordingApplication::default();
        let progress = engine.apply_contiguous_to(&mut application).unwrap();
        assert!(matches!(
            progress,
            ApplyProgress::Applied {
                watermark: Watermark { position: 1 },
                ..
            }
        ));
        assert_eq!(
            engine.read(b"key", ReadConsistency::Local, None).unwrap(),
            Some(b"globally-ordered".to_vec())
        );
        assert_eq!(
            application.values.get(b"key".as_slice()),
            Some(&b"globally-ordered".to_vec())
        );

        drop(engine);
        let mut restarted = GlobalOrderedEngine::new(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership,
            ValidatorGeneration(5),
            validators,
            64,
        )
        .unwrap();
        assert_eq!(restarted.applied_watermark(), Watermark { position: 1 });
        assert!(matches!(
            restarted.apply_contiguous().unwrap(),
            ApplyProgress::Applied {
                watermark: Watermark { position: 1 },
                results
            } if results.is_empty()
        ));
        assert_eq!(
            restarted
                .read(
                    b"key",
                    ReadConsistency::Linearizable,
                    Some(Watermark { position: 1 })
                )
                .unwrap(),
            Some(b"globally-ordered".to_vec())
        );
        drop(restarted);
        drop(stores);
        for path in paths {
            std::fs::remove_file(path).ok();
        }
    }
}
