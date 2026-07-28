//! Opaque commands, batches, references, generations, and milestone records.

use super::*;

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
/// Stable application client identifier used for write deduplication.
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
/// Client-selected incarnation that fences writes from older sessions.
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
/// Globally stable identity of one application command.
pub struct CommandIdentity {
    /// Logical application client.
    pub client_id: ClientId,
    /// Current client incarnation.
    pub client_epoch: ClientEpoch,
    /// One-based command sequence within the incarnation.
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
/// Monotonic application routing generation.
pub struct RouteGeneration(pub u64);

impl RouteGeneration {
    /// Rejects the reserved zero generation.
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
/// Monotonic version of the application's opaque command schema.
pub struct CommandSpecVersion(pub u64);

impl CommandSpecVersion {
    /// Rejects the reserved zero version.
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
    /// Wraps bounded non-empty application bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let command = Self { bytes };
        command.validate()?;
        Ok(command)
    }

    /// Validates the command byte bound.
    pub fn validate(&self) -> Result<()> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_APPLICATION_COMMAND_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "application command must contain 1..={MAX_APPLICATION_COMMAND_BYTES} bytes"
            )));
        }
        Ok(())
    }

    /// Borrows the opaque command bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the owned opaque command bytes.
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
    /// Wraps bounded application result bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let result = Self { bytes };
        result.validate()?;
        Ok(result)
    }

    /// Validates the result byte bound.
    pub fn validate(&self) -> Result<()> {
        if self.bytes.len() > MAX_APPLICATION_RESULT_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "application result exceeds {MAX_APPLICATION_RESULT_BYTES} bytes"
            )));
        }
        Ok(())
    }

    /// Borrows the opaque result bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the owned opaque result bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Opaque command paired with its replay-resistant identity.
pub struct ApplicationCommandEnvelope {
    /// Stable deduplication identity.
    pub identity: CommandIdentity,
    /// Application-owned command bytes.
    pub command: ApplicationCommand,
}

impl ApplicationCommandEnvelope {
    /// Validates identity and payload bounds.
    pub fn validate(&self) -> Result<()> {
        if self.identity.sequence == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "client command sequences start at one".to_string(),
            ));
        }
        self.command.validate()
    }

    /// Computes the domain-separated command hash.
    pub fn hash(&self) -> Result<HashType> {
        self.validate()?;
        hash_borsh(COMMAND_HASH_DOMAIN, self)
    }
}

/// Backwards-compatible profile-specific name for
/// [`ApplicationCommandEnvelope`].
pub type ActiveActiveCommand = ApplicationCommandEnvelope;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// One command assigned a contiguous sequence by its origin writer.
pub struct AdmittedCommand {
    /// One-based writer-local sequence committed by the batch.
    pub origin_sequence: u64,
    /// Admitted application command.
    pub command: ActiveActiveCommand,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Contiguous non-empty commands emitted by one origin.
pub struct CommandBatch {
    /// Commands in writer sequence order.
    pub commands: Vec<AdmittedCommand>,
}

impl CommandBatch {
    /// Validates count, byte, identity, and contiguous-sequence bounds.
    pub fn validate(&self) -> Result<()> {
        self.validate_commands()?;
        let encoded = borsh::to_vec(self).map_err(encode_error)?;
        Self::validate_encoded_len(encoded.len())
    }

    fn validate_commands(&self) -> Result<()> {
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
        Ok(())
    }

    fn validate_encoded_len(encoded_len: usize) -> Result<()> {
        if encoded_len > DEFAULT_MAX_BATCH_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "batch encoded size {} exceeds maximum {}",
                encoded_len, DEFAULT_MAX_BATCH_BYTES
            )));
        }
        Ok(())
    }

    /// Returns the canonical Borsh bytes committed by a reference.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_commands()?;
        let encoded = borsh::to_vec(self).map_err(|err| {
            BlossomError::WireProtocol(format!("encode active-active command batch: {err}"))
        })?;
        Self::validate_encoded_len(encoded.len())?;
        Ok(encoded)
    }

    /// Computes the domain-separated hash of the complete canonical batch.
    pub fn hash(&self) -> Result<HashType> {
        let encoded = self.canonical_bytes()?;
        Ok(sha256_hash(COMMAND_BATCH_HASH_DOMAIN, &[&encoded]))
    }

    /// Computes the canonical binary Merkle root of admitted commands.
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
/// Generation of the holder set that durably stores command bytes.
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
/// Generation of the validator set authorized to order references.
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
/// Incarnation of one holder's durable admission store.
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
/// One-based position in the certified global application order.
pub struct Watermark {
    /// Global position; zero denotes the pre-application origin.
    pub position: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Evidence that a frozen replica set applied through one watermark.
pub struct AppliedBy {
    /// Holder membership generation frozen for this proof.
    pub membership_snapshot: ReplicaMembershipEpoch,
    /// Exact replica keys required by the proof.
    pub required_nodes: BTreeSet<PubKey>,
    /// Watermark reached by every required replica.
    pub watermark: Watermark,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Durable lifecycle of one batch reference.
pub enum Milestone {
    /// The local holder durably admitted the command bytes.
    AcceptedLocal,
    /// The holder policy certifies that the bytes are recoverable.
    Available,
    /// Consensus assigned an immutable global position.
    Finalized,
    /// The application callback and opaque results are durable.
    Applied,
}

impl Milestone {
    pub(super) fn rank(self) -> u8 {
        match self {
            Self::AcceptedLocal => 0,
            Self::Available => 1,
            Self::Finalized => 2,
            Self::Applied => 3,
        }
    }

    /// Returns whether this milestone is terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied)
    }

    /// Returns whether this milestone is at or beyond `target`.
    pub fn reaches(self, target: Self) -> bool {
        self.rank() >= target.rank()
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Timestamped durable transition for one reference.
pub struct MilestoneEvent {
    /// Consistency profile that emitted the event.
    pub protocol: String,
    /// Hash of the reference whose state changed.
    pub reference_hash: HashType,
    /// New durable milestone.
    pub milestone: Milestone,
    /// Best-effort Unix timestamp in microseconds.
    pub timestamp_micros: u128,
    /// Global position once one has been assigned.
    pub watermark: Option<Watermark>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Named active-active consistency profiles.
pub enum ActiveActiveConsistencyMode {
    /// Causal delivery with eventual convergence.
    ActiveSyncCausalEventual,
    /// Consensus-ordered eventual delivery.
    ActiveSyncConsensusOrderedEventual,
    /// Globally ordered, durably applied delivery.
    ActiveSyncGlobalOrdered,
}

impl ActiveActiveConsistencyMode {
    /// Returns the stable configuration label.
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
/// Completion policy selected by an application write API.
pub enum WriteMode {
    /// Return after local durable admission.
    LocalAsync,
    /// Return after an immutable global position is certified.
    GlobalFinalized,
    /// Return after ordered application and result persistence.
    GlobalApplied,
}

impl WriteMode {
    /// Returns the milestone required by this policy.
    pub const fn required_milestone(self) -> Milestone {
        match self {
            Self::LocalAsync => Milestone::AcceptedLocal,
            Self::GlobalFinalized => Milestone::Finalized,
            Self::GlobalApplied => Milestone::Applied,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Read authority required before consulting application state.
pub enum ReadConsistency {
    /// Read immediately from local application state.
    Local,
    /// Wait until application reaches at least the supplied watermark.
    AtLeast(Watermark),
    /// Require a fresh quorum-certified read barrier.
    Linearizable,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Compact, hash-committed description of one command batch.
///
/// The reference commits routing and command-schema generations so a cutover
/// cannot silently reinterpret accepted bytes.
pub struct BatchReference {
    /// Reference envelope format version.
    pub format_version: u16,
    /// Canonical payload codec version.
    pub codec_version: u16,
    /// Application cluster identifier.
    pub cluster_id: HashType,
    /// Blossom consensus group ordering the reference.
    pub consensus_group_id: ConsensusGroupId,
    /// Application-defined shard/routing key.
    pub shard: Vec<u8>,
    /// Routing generation active at admission.
    pub route_generation: RouteGeneration,
    /// Command schema active at admission.
    pub command_spec_version: CommandSpecVersion,
    /// Writer public key.
    pub origin: PubKey,
    /// Writer process or logical incarnation.
    pub origin_incarnation: u64,
    /// Writer signing-key generation.
    pub origin_key_generation: u64,
    /// First writer-local sequence in the batch.
    pub first_origin_sequence: u64,
    /// Last writer-local sequence in the batch.
    pub last_origin_sequence: u64,
    /// Number of commands committed by the reference.
    pub command_count: u32,
    /// Canonical encoded batch length.
    pub byte_length: u64,
    /// Merkle root of the canonical admitted commands.
    pub merkle_root: HashType,
    /// Holder membership generation proving availability.
    pub data_holder_membership_epoch: ReplicaMembershipEpoch,
    /// Validator generation authorized to order the reference.
    pub validator_generation: ValidatorGeneration,
    /// Previous reference hash in this writer's origin chain.
    pub previous_origin_reference_hash: HashType,
}

#[derive(Debug, Clone)]
/// Inputs used to construct a [`BatchReference`] for verified batch bytes.
pub struct BatchReferenceMetadata {
    /// Application cluster identifier.
    pub cluster_id: HashType,
    /// Blossom consensus group that will order the reference.
    pub consensus_group_id: ConsensusGroupId,
    /// Application-defined shard/routing key.
    pub shard: Vec<u8>,
    /// Routing generation active at admission.
    pub route_generation: RouteGeneration,
    /// Command schema active at admission.
    pub command_spec_version: CommandSpecVersion,
    /// Writer public key.
    pub origin: PubKey,
    /// Writer process or logical incarnation.
    pub origin_incarnation: u64,
    /// Writer signing-key generation.
    pub origin_key_generation: u64,
    /// Holder membership generation proving availability.
    pub data_holder_membership_epoch: ReplicaMembershipEpoch,
    /// Validator generation authorized to order the reference.
    pub validator_generation: ValidatorGeneration,
    /// Previous reference hash in this writer's origin chain.
    pub previous_origin_reference_hash: HashType,
}

impl BatchReference {
    /// Current reference envelope format.
    pub const FORMAT_VERSION: u16 = 2;
    /// Current canonical payload codec.
    pub const CODEC_VERSION: u16 = 2;

    /// Constructs a reference that commits the verified batch and metadata.
    pub fn for_batch(batch: &CommandBatch, metadata: BatchReferenceMetadata) -> Result<Self> {
        batch.validate()?;
        validate_shard_id(&metadata.shard)?;
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

    /// Validates versions, generations, and sequence/count consistency.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != Self::FORMAT_VERSION || self.codec_version != Self::CODEC_VERSION
        {
            return Err(BlossomError::InvalidConfiguration(
                "unsupported active-active reference format or codec".to_string(),
            ));
        }
        self.route_generation.validate()?;
        self.command_spec_version.validate()?;
        validate_shard_id(&self.shard)?;
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

    /// Computes the signed and ordered domain-separated reference hash.
    pub fn hash(&self) -> Result<HashType> {
        self.validate()?;
        hash_borsh(REFERENCE_HASH_DOMAIN, self)
    }

    /// Verifies that complete batch bytes match this compact reference.
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

    /// Detects overlapping, non-identical ranges from the same origin chain.
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
