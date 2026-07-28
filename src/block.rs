//! Blocks, opaque transactions, commitments, filtering, and fair ordering.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
#[cfg(feature = "fair-block-ordering")]
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::admission::NodeAdmission;
use crate::crypto::{PubKey, SecKey, SecretSigner, Signature};
use crate::encounter::EncounterRecord;
use crate::error::{BlossomError, Result};
use crate::hash::{HashType, ProtocolHasher};
use crate::nonce::Nonce;

pub const BLOCK_APPLICATION_STATE_SOFT_LIMIT_BYTES: usize = 4 * 1024;
pub const BLOCK_APPLICATION_STATE_MAX_BYTES: usize = 8 * 1024;
#[cfg(feature = "fair-block-ordering")]
const FAIR_BLOCK_ORDER_SEED_DOMAIN: &[u8] = b"blossom.fair-block-order.seed.v1";
#[cfg(feature = "fair-block-ordering")]
const FAIR_BLOCK_ORDER_KEY_DOMAIN: &[u8] = b"blossom.fair-block-order.key.v1";

/// Opaque application-defined transaction data.
///
/// Blossom does not parse this payload. Applications can store any stable
/// encoding here, including versioned binary structs or key/value records.
/// The bytes are committed into the block hash through their enclosing
/// [`Transaction`].
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
#[serde(transparent)]
#[repr(transparent)]
pub struct TransactionPayload {
    pub(crate) bytes: Vec<u8>,
}

impl TransactionPayload {
    #[inline]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for TransactionPayload {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for TransactionPayload {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl From<&[u8]> for TransactionPayload {
    #[inline]
    fn from(value: &[u8]) -> Self {
        Self::new(value)
    }
}

impl From<&str> for TransactionPayload {
    #[inline]
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes())
    }
}

impl From<String> for TransactionPayload {
    #[inline]
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

impl From<TransactionPayload> for Vec<u8> {
    #[inline]
    fn from(value: TransactionPayload) -> Self {
        value.bytes
    }
}

#[cfg(feature = "filtered-transactions")]
const FILTERED_TRANSACTION_SLOT_DOMAIN: &[u8] = b"blossom-filtered-transaction-slot:v1";

/// Delivery hint for a filtered transaction payload.
///
/// The consensus block commits this policy as metadata only. Applications and
/// future availability-gossip machinery decide how payload bytes move.
#[cfg(feature = "filtered-transactions")]
#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum FilteredDeliveryPolicy {
    Direct = 1,
    #[default]
    Gossip = 2,
}

/// Local materialization state for a filtered transaction.
#[cfg(feature = "filtered-transactions")]
#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum FilteredPayloadView {
    #[default]
    Transparent = 0,
    Full = 1,
    Tombstone = 2,
}

/// Canonical metadata for a filtered transaction slot.
///
/// Every node commits the same slot into the block hash. Target nodes may also
/// carry the full payload locally, while non-target nodes carry a tombstone and
/// verify only the slot commitment.
#[cfg(feature = "filtered-transactions")]
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FilteredTransactionSlot {
    pub key_hash: HashType,
    pub kind: u16,
    pub targets: Vec<PubKey>,
    pub payload_commitment: HashType,
    pub payload_len: u64,
    pub delivery_policy: FilteredDeliveryPolicy,
}

#[cfg(feature = "filtered-transactions")]
impl FilteredTransactionSlot {
    pub fn new(
        key_hash: HashType,
        kind: u16,
        targets: impl Into<Vec<PubKey>>,
        payload_commitment: HashType,
        payload_len: u64,
        delivery_policy: FilteredDeliveryPolicy,
    ) -> Result<Self> {
        let mut slot = Self {
            key_hash,
            kind,
            targets: targets.into(),
            payload_commitment,
            payload_len,
            delivery_policy,
        };
        slot.normalize_targets();
        slot.validate()?;
        Ok(slot)
    }

    pub fn for_payload(
        key_hash: HashType,
        kind: u16,
        targets: impl Into<Vec<PubKey>>,
        payload: &[u8],
        delivery_policy: FilteredDeliveryPolicy,
    ) -> Result<Self> {
        Self::new(
            key_hash,
            kind,
            targets,
            HashType::hash(payload),
            payload.len() as u64,
            delivery_policy,
        )
    }

    pub fn hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        self.update_hash(&mut hasher);
        hasher.finalize()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.append_bytes_to(&mut bytes);
        bytes
    }

    pub fn encoded_len(&self) -> usize {
        FILTERED_TRANSACTION_SLOT_DOMAIN.len() + 32 + 2 + 4 + (self.targets.len() * 32) + 32 + 8 + 1
    }

    pub fn append_bytes_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(FILTERED_TRANSACTION_SLOT_DOMAIN);
        bytes.extend_from_slice(self.key_hash.as_ref());
        bytes.extend_from_slice(&self.kind.to_le_bytes());
        bytes.extend_from_slice(&(self.targets.len() as u32).to_le_bytes());
        for target in &self.targets {
            bytes.extend_from_slice(target.as_ref());
        }
        bytes.extend_from_slice(self.payload_commitment.as_ref());
        bytes.extend_from_slice(&self.payload_len.to_le_bytes());
        bytes.push(self.delivery_policy as u8);
    }

    pub fn update_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(FILTERED_TRANSACTION_SLOT_DOMAIN);
        hasher.update(self.key_hash.as_ref());
        hasher.update(self.kind.to_le_bytes());
        hasher.update((self.targets.len() as u32).to_le_bytes());
        for target in &self.targets {
            hasher.update(target.as_ref());
        }
        hasher.update(self.payload_commitment.as_ref());
        hasher.update(self.payload_len.to_le_bytes());
        hasher.update([self.delivery_policy as u8]);
    }

    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            return Err(BlossomError::WireProtocol(
                "filtered transaction target set cannot be empty".to_string(),
            ));
        }
        if !self.targets_are_sorted() {
            return Err(BlossomError::WireProtocol(
                "filtered transaction targets must be sorted".to_string(),
            ));
        }
        if !self.targets_are_unique() {
            return Err(BlossomError::WireProtocol(
                "filtered transaction targets must be unique".to_string(),
            ));
        }
        Ok(())
    }

    pub fn is_target(&self, public_key: &PubKey) -> bool {
        self.targets.binary_search(public_key).is_ok()
    }

    fn normalize_targets(&mut self) {
        self.targets.sort();
        self.targets.dedup();
    }

    fn targets_are_sorted(&self) -> bool {
        self.targets.windows(2).all(|window| window[0] <= window[1])
    }

    fn targets_are_unique(&self) -> bool {
        self.targets.windows(2).all(|window| window[0] != window[1])
    }
}

/// A hash-identified opaque application transaction.
///
/// The transaction hash is used by the block Merkle root. The payload bytes are
/// also included in the block body hash, so peers cannot alter application data
/// without invalidating block integrity.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct Transaction {
    pub hash: HashType,
    pub payload: TransactionPayload,
    #[cfg(feature = "filtered-transactions")]
    pub filtered_slot: Option<FilteredTransactionSlot>,
    #[cfg(feature = "filtered-transactions")]
    pub filtered_view: FilteredPayloadView,
}

impl Transaction {
    #[inline]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        let hash = HashType::hash(&bytes);
        Self {
            hash,
            payload: TransactionPayload { bytes },
            #[cfg(feature = "filtered-transactions")]
            filtered_slot: None,
            #[cfg(feature = "filtered-transactions")]
            filtered_view: FilteredPayloadView::Transparent,
        }
    }

    #[inline]
    pub fn from_payload(payload: impl Into<TransactionPayload>) -> Self {
        let payload = payload.into();
        let hash = HashType::hash(&payload.bytes);
        Self {
            hash,
            payload,
            #[cfg(feature = "filtered-transactions")]
            filtered_slot: None,
            #[cfg(feature = "filtered-transactions")]
            filtered_view: FilteredPayloadView::Transparent,
        }
    }

    #[inline]
    pub(crate) fn from_parts(hash: HashType, payload: impl Into<TransactionPayload>) -> Self {
        Self {
            hash,
            payload: payload.into(),
            #[cfg(feature = "filtered-transactions")]
            filtered_slot: None,
            #[cfg(feature = "filtered-transactions")]
            filtered_view: FilteredPayloadView::Transparent,
        }
    }

    /// Builds a filtered transaction for a target set that receives the full
    /// local payload.
    ///
    /// The transaction identifier is the canonical slot hash. Non-target peers
    /// can materialize the same slot with [`Transaction::filtered_tombstone`]
    /// and still verify the same block hash.
    #[cfg(feature = "filtered-transactions")]
    #[inline]
    pub fn filtered_full(
        key_hash: HashType,
        kind: u16,
        targets: impl Into<Vec<PubKey>>,
        payload: impl Into<TransactionPayload>,
        delivery_policy: FilteredDeliveryPolicy,
    ) -> Result<Self> {
        let payload = payload.into();
        let slot = FilteredTransactionSlot::for_payload(
            key_hash,
            kind,
            targets,
            payload.as_slice(),
            delivery_policy,
        )?;
        Ok(Self::from_filtered_parts(
            slot.hash(),
            slot,
            payload,
            FilteredPayloadView::Full,
        ))
    }

    /// Builds a filtered tombstone from canonical slot metadata.
    ///
    /// Tombstones carry no local payload, but their block hash contribution is
    /// identical to the matching full transaction.
    #[cfg(feature = "filtered-transactions")]
    #[inline]
    pub fn filtered_tombstone(slot: FilteredTransactionSlot) -> Result<Self> {
        let mut slot = slot;
        slot.normalize_targets();
        slot.validate()?;
        Ok(Self::from_filtered_parts(
            slot.hash(),
            slot,
            TransactionPayload::default(),
            FilteredPayloadView::Tombstone,
        ))
    }

    #[cfg(feature = "filtered-transactions")]
    #[inline]
    pub(crate) fn from_filtered_parts(
        hash: HashType,
        slot: FilteredTransactionSlot,
        payload: impl Into<TransactionPayload>,
        filtered_view: FilteredPayloadView,
    ) -> Self {
        Self {
            hash,
            payload: payload.into(),
            filtered_slot: Some(slot),
            filtered_view,
        }
    }

    #[inline]
    pub fn from_borsh<T>(value: &T) -> Result<Self>
    where
        T: BorshSerialize + ?Sized,
    {
        let bytes = borsh::to_vec(value).map_err(|err| {
            BlossomError::WireProtocol(format!("failed to encode transaction payload: {err}"))
        })?;
        Ok(Self::new(bytes))
    }

    #[inline]
    pub fn payload_as_borsh<T>(&self) -> Result<T>
    where
        T: BorshDeserialize,
    {
        borsh::from_slice(self.payload.as_slice()).map_err(|err| {
            BlossomError::WireProtocol(format!("failed to decode transaction payload: {err}"))
        })
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.payload.bytes.as_slice()
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut TransactionPayload {
        &mut self.payload
    }

    #[inline]
    pub fn payload_len(&self) -> usize {
        self.payload.bytes.len()
    }

    #[cfg(feature = "filtered-transactions")]
    #[inline]
    pub fn committed_payload_len(&self) -> u64 {
        self.filtered_slot
            .as_ref()
            .map(|slot| slot.payload_len)
            .unwrap_or(self.payload.bytes.len() as u64)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.payload.bytes.is_empty()
    }

    /// Returns a local view of this transaction for `viewer`.
    ///
    /// Transparent transactions are unchanged. Filtered full transactions are
    /// converted to tombstones when the viewer is not in the target set. The
    /// canonical transaction hash is preserved.
    #[cfg(feature = "filtered-transactions")]
    pub fn materialize_for(&self, viewer: &PubKey) -> Self {
        let Some(slot) = &self.filtered_slot else {
            return self.clone();
        };
        if self.filtered_view == FilteredPayloadView::Full && !slot.is_target(viewer) {
            return Self::from_filtered_parts(
                self.hash,
                slot.clone(),
                TransactionPayload::default(),
                FilteredPayloadView::Tombstone,
            );
        }
        self.clone()
    }

    #[cfg(feature = "filtered-transactions")]
    #[inline]
    pub fn is_filtered(&self) -> bool {
        self.filtered_slot.is_some()
    }

    #[cfg(feature = "filtered-transactions")]
    #[inline]
    pub fn is_filtered_tombstone(&self) -> bool {
        self.filtered_slot.is_some() && self.filtered_view == FilteredPayloadView::Tombstone
    }

    #[cfg(feature = "filtered-transactions")]
    #[inline]
    pub fn filtered_slot(&self) -> Option<&FilteredTransactionSlot> {
        self.filtered_slot.as_ref()
    }

    #[inline]
    pub fn into_payload(self) -> TransactionPayload {
        self.payload
    }

    /// Builds a transaction with an application-supplied identifier.
    ///
    /// This is intended for trusted/application-specific overlays where the
    /// caller already computed a stable key or content hash. The block hash
    /// still commits to both this identifier and the transaction bytes, but the
    /// transaction Merkle root represents these external identifiers rather than
    /// Blossom-computed payload hashes.
    #[cfg(feature = "external-transaction-hashes")]
    #[inline]
    pub fn from_external_hash(hash: HashType, payload: impl Into<TransactionPayload>) -> Self {
        Self::from_parts(hash, payload)
    }

    /// Builds a transaction from a 64-bit external key hash, such as
    /// fast-cache's XXH3 `hash_key` value.
    ///
    /// The little-endian `u64` is stored in the first eight bytes of Blossom's
    /// 32-byte transaction identifier and the remaining bytes are zero.
    #[cfg(feature = "external-transaction-hashes")]
    #[inline]
    pub fn from_external_hash_u64(hash: u64, payload: impl Into<TransactionPayload>) -> Self {
        let mut padded = [0; 32];
        padded[..8].copy_from_slice(&hash.to_le_bytes());
        Self::from_external_hash(HashType(padded), payload)
    }

    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.canonical_encoded_len());
        self.append_canonical_bytes_to(&mut bytes);
        bytes
    }

    #[inline]
    fn canonical_encoded_len(&self) -> usize {
        32 + self.canonical_payload_encoded_len()
    }

    #[inline]
    fn canonical_payload_encoded_len(&self) -> usize {
        #[cfg(feature = "filtered-transactions")]
        if let Some(slot) = &self.filtered_slot {
            return slot.encoded_len();
        }

        self.payload.bytes.len()
    }

    fn append_canonical_bytes_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.hash.as_ref());
        self.append_canonical_payload_to(bytes);
    }

    fn append_canonical_payload_to(&self, bytes: &mut Vec<u8>) {
        #[cfg(feature = "filtered-transactions")]
        if let Some(slot) = &self.filtered_slot {
            slot.append_bytes_to(bytes);
            return;
        }

        bytes.extend_from_slice(self.payload.bytes.as_slice());
    }

    #[cfg(feature = "fair-block-ordering")]
    fn update_canonical_payload_fair_order_seed(
        &self,
        hasher: &mut ProtocolHasher,
        modulo: u64,
        byte_index: &mut u64,
    ) {
        #[cfg(feature = "filtered-transactions")]
        if let Some(slot) = &self.filtered_slot {
            let mut bytes = Vec::with_capacity(slot.encoded_len());
            slot.append_bytes_to(&mut bytes);
            update_modulo_seed(hasher, &bytes, modulo, byte_index);
            return;
        }

        update_modulo_seed(hasher, self.payload.bytes.as_slice(), modulo, byte_index);
    }

    fn update_canonical_payload_hash(&self, hasher: &mut ProtocolHasher) {
        #[cfg(feature = "filtered-transactions")]
        if let Some(slot) = &self.filtered_slot {
            slot.update_hash(hasher);
            return;
        }

        hasher.update(self.payload.bytes.as_slice());
    }

    #[cfg(feature = "filtered-transactions")]
    fn validate_filtered_integrity(&self) -> Result<()> {
        match (&self.filtered_slot, self.filtered_view) {
            (None, FilteredPayloadView::Transparent) => Ok(()),
            (None, _) => Err(BlossomError::WireProtocol(
                "filtered transaction view set without a slot".to_string(),
            )),
            (Some(slot), FilteredPayloadView::Transparent) => {
                slot.validate()?;
                Err(BlossomError::WireProtocol(
                    "filtered transaction slot cannot use transparent view".to_string(),
                ))
            }
            (Some(slot), FilteredPayloadView::Tombstone) => {
                slot.validate()?;
                if self.hash != slot.hash() {
                    return Err(BlossomError::InvalidBlockHash);
                }
                if !self.payload.bytes.is_empty() {
                    return Err(BlossomError::WireProtocol(
                        "filtered tombstone cannot carry payload bytes".to_string(),
                    ));
                }
                Ok(())
            }
            (Some(slot), FilteredPayloadView::Full) => {
                slot.validate()?;
                if self.hash != slot.hash() {
                    return Err(BlossomError::InvalidBlockHash);
                }
                if self.payload.bytes.len() as u64 != slot.payload_len {
                    return Err(BlossomError::InvalidBlockHash);
                }
                if HashType::hash(self.payload.bytes.as_slice()) != slot.payload_commitment {
                    return Err(BlossomError::InvalidBlockHash);
                }
                Ok(())
            }
        }
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct Block {
    pub hash: HashType,
    pub signature: Signature,
    pub body: BlockBody,
}

impl Block {
    pub fn empty_with_nonce(nonce: Nonce) -> Self {
        let mut block = Self::default();
        block.body.nonce = nonce;
        block.set_hash();
        block
    }

    pub fn hash(&self) -> HashType {
        self.body.hash()
    }

    pub fn set_hash(&mut self) {
        self.hash = self.hash();
    }

    pub fn set_application_state(&mut self, bytes: impl Into<Vec<u8>>) -> Result<()> {
        self.body.set_application_state(bytes)
    }

    pub fn application_state(&self) -> &[u8] {
        self.body.application_state.as_slice()
    }

    pub fn application_state_len(&self) -> usize {
        self.body.application_state.len()
    }

    pub fn sign(&mut self, secret_key: &SecKey) {
        let signer = SecretSigner::new(secret_key);
        self.sign_with(&signer);
    }

    pub fn sign_with(&mut self, signer: &SecretSigner) {
        self.body.validator = signer.public_key();
        self.seal();
        self.signature = signer.sign(self.hash.as_ref());
    }

    pub fn seal_unsigned(&mut self, validator: PubKey) {
        self.body.validator = validator;
        self.seal();
        self.signature = Signature::default();
    }

    fn seal(&mut self) {
        self.body.merkle_root = self.body.compute_merkle_root();
        self.hash = self.body.hash();
    }

    pub fn verify_signature(&self) -> Result<()> {
        self.signature
            .verify(self.body.hash().as_ref(), &self.body.validator)
    }

    pub fn verify_integrity(&self) -> Result<()> {
        self.verify_integrity_with_hash(self.hash)
    }

    pub fn verify_integrity_with_hash(&self, expected_hash: HashType) -> Result<()> {
        self.verify_unsigned_integrity_with_hash(expected_hash)?;
        self.signature
            .verify(self.hash.as_ref(), &self.body.validator)
    }

    pub fn verify_unsigned_integrity(&self) -> Result<()> {
        self.verify_unsigned_integrity_with_hash(self.hash)
    }

    pub fn verify_unsigned_integrity_with_hash(&self, expected_hash: HashType) -> Result<()> {
        self.body.application_state.validate()?;
        self.body.validate_encounter_records()?;
        self.body.validate_node_admissions()?;
        self.body.validate_transactions()?;
        let (body_hash, merkle_root) = self.body.hash_and_merkle_root();
        if self.hash != expected_hash || body_hash != expected_hash {
            return Err(BlossomError::InvalidBlockHash);
        }
        if self.body.merkle_root != merkle_root {
            return Err(BlossomError::InvalidBlockHash);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.body.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.body.txs.is_empty()
    }

    #[cfg(feature = "fair-block-ordering")]
    pub fn append_fair_order_bytes_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.hash.as_ref());
        bytes.extend_from_slice(self.signature.as_ref());
        self.body.append_bytes_to(bytes);
    }

    #[cfg(feature = "fair-block-ordering")]
    fn update_fair_order_seed(
        &self,
        hasher: &mut ProtocolHasher,
        modulo: u64,
        byte_index: &mut u64,
    ) {
        update_modulo_seed(hasher, self.hash.as_ref(), modulo, byte_index);
        update_modulo_seed(hasher, self.signature.as_ref(), modulo, byte_index);
        self.body.update_fair_order_seed(hasher, modulo, byte_index);
    }

    #[cfg(feature = "fair-block-ordering")]
    pub fn fair_order_encoded_len(&self) -> usize {
        32 + self.signature.as_ref().len() + self.body.encoded_len()
    }

    /// Returns a local filtered view of this block for `viewer`.
    ///
    /// The block hash, Merkle root, and signature are not changed. Only
    /// non-target full filtered payloads are replaced by tombstones.
    #[cfg(feature = "filtered-transactions")]
    pub fn materialize_for(&self, viewer: &PubKey) -> Self {
        let mut block = self.clone();
        block.body.txs = block
            .body
            .txs
            .iter()
            .map(|tx| tx.materialize_for(viewer))
            .collect();
        block
    }
}

#[cfg(feature = "fair-block-ordering")]
pub fn fair_order_transaction_count(blocks: &BTreeMap<HashType, Block>) -> u64 {
    blocks
        .values()
        .map(|block| block.body.txs.len() as u64)
        .fold(0u64, u64::saturating_add)
}

#[cfg(feature = "fair-block-ordering")]
pub fn fair_block_order_seed(blocks: &BTreeMap<HashType, Block>) -> HashType {
    let transaction_count = fair_order_transaction_count(blocks);
    let modulo = transaction_count.max(1);
    let mut byte_index = 0u64;
    let mut hasher = ProtocolHasher::new();
    hasher.update(FAIR_BLOCK_ORDER_SEED_DOMAIN);
    hasher.update(transaction_count.to_le_bytes());
    hasher.update((blocks.len() as u64).to_le_bytes());
    for (block_hash, block) in blocks {
        update_modulo_seed(&mut hasher, block_hash.as_ref(), modulo, &mut byte_index);
        block.update_fair_order_seed(&mut hasher, modulo, &mut byte_index);
    }
    hasher.finalize()
}

#[cfg(feature = "fair-block-ordering")]
pub fn fair_block_order_key(
    seed: HashType,
    transaction_count: u64,
    block_hash: &HashType,
    block: &Block,
) -> HashType {
    let mut hasher = ProtocolHasher::new();
    hasher.update(FAIR_BLOCK_ORDER_KEY_DOMAIN);
    hasher.update(seed.as_ref());
    hasher.update(transaction_count.to_le_bytes());
    hasher.update(block_hash.as_ref());
    hasher.update(block.hash.as_ref());
    hasher.update(block.body.validator.as_ref());
    hasher.update((block.body.txs.len() as u64).to_le_bytes());
    hasher.finalize()
}

#[cfg(feature = "fair-block-ordering")]
pub fn fair_ordered_blocks(blocks: &BTreeMap<HashType, Block>) -> Vec<(&HashType, &Block)> {
    let seed = fair_block_order_seed(blocks);
    let transaction_count = fair_order_transaction_count(blocks);
    let mut ordered = blocks
        .iter()
        .map(|(block_hash, block)| {
            (
                fair_block_order_key(seed, transaction_count, block_hash, block),
                block_hash,
                block,
            )
        })
        .collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    ordered
        .into_iter()
        .map(|(_, block_hash, block)| (block_hash, block))
        .collect()
}

#[cfg(feature = "fair-block-ordering")]
pub fn fair_ordered_block_commitments(blocks: &BTreeMap<HashType, Block>) -> Vec<HashType> {
    let seed = fair_block_order_seed(blocks);
    let transaction_count = fair_order_transaction_count(blocks);
    let mut commitments = blocks
        .iter()
        .map(|(block_hash, block)| {
            (
                fair_block_order_key(seed, transaction_count, block_hash, block),
                *block_hash,
            )
        })
        .collect::<Vec<_>>();
    commitments.sort_unstable();
    commitments.into_iter().map(|(key, _)| key).collect()
}

#[cfg(feature = "fair-block-ordering")]
fn update_modulo_seed(
    hasher: &mut ProtocolHasher,
    bytes: &[u8],
    modulo: u64,
    byte_index: &mut u64,
) {
    const MODULO_ENTRY_BYTES: usize = 9;
    const MODULO_CHUNK_ENTRIES: usize = 128;
    const MODULO_CHUNK_BYTES: usize = MODULO_ENTRY_BYTES * MODULO_CHUNK_ENTRIES;

    let mut chunk = [0u8; MODULO_CHUNK_BYTES];
    let mut chunk_len = 0usize;

    for byte in bytes {
        chunk[chunk_len..chunk_len + 8].copy_from_slice(&(*byte_index % modulo).to_le_bytes());
        chunk[chunk_len + 8] = *byte;
        chunk_len += MODULO_ENTRY_BYTES;
        *byte_index = byte_index.wrapping_add(1);

        if chunk_len == MODULO_CHUNK_BYTES {
            hasher.update(chunk);
            chunk_len = 0;
        }
    }

    if chunk_len > 0 {
        hasher.update(&chunk[..chunk_len]);
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct BlockBody {
    pub validator: PubKey,
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub created: u128,
    pub dispatched: u128,
    pub merkle_root: HashType,
    pub application_state: BlockApplicationState,
    pub encounter_records: Vec<EncounterRecord>,
    pub node_admissions: Vec<NodeAdmission>,
    pub txs: Vec<Transaction>,
}

impl Default for BlockBody {
    fn default() -> Self {
        Self {
            validator: PubKey::default(),
            last_epoch: HashType::default(),
            nonce: Nonce::default(),
            created: now_micros(),
            dispatched: 0,
            merkle_root: HashType::default(),
            application_state: BlockApplicationState::default(),
            encounter_records: Vec::new(),
            node_admissions: Vec::new(),
            txs: Vec::new(),
        }
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct BlockApplicationState {
    bytes: Vec<u8>,
}

impl BlockApplicationState {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        validate_application_state_len(bytes.len())?;
        Ok(Self { bytes })
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn exceeds_soft_limit(&self) -> bool {
        self.len() > BLOCK_APPLICATION_STATE_SOFT_LIMIT_BYTES
    }

    pub fn validate(&self) -> Result<()> {
        validate_application_state_len(self.len())
    }
}

impl BlockBody {
    pub fn set_application_state(&mut self, bytes: impl Into<Vec<u8>>) -> Result<()> {
        self.application_state = BlockApplicationState::new(bytes)?;
        Ok(())
    }

    pub fn application_state(&self) -> &[u8] {
        self.application_state.as_slice()
    }

    pub fn application_state_len(&self) -> usize {
        self.application_state.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.append_bytes_to(&mut bytes);
        bytes
    }

    pub fn append_bytes_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.validator.as_ref());
        bytes.extend_from_slice(self.last_epoch.as_ref());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.extend_from_slice(&self.created.to_le_bytes());
        bytes.extend_from_slice(&self.dispatched.to_le_bytes());
        bytes.extend_from_slice(self.merkle_root.as_ref());
        bytes.extend_from_slice(&(self.application_state.len() as u64).to_le_bytes());
        bytes.extend_from_slice(self.application_state.as_slice());
        bytes.extend_from_slice(&(self.encounter_records.len() as u64).to_le_bytes());
        for record in &self.encounter_records {
            record.append_bytes_to(bytes);
        }
        bytes.extend_from_slice(&(self.node_admissions.len() as u64).to_le_bytes());
        for admission in &self.node_admissions {
            admission.body.append_bytes_to(bytes);
            bytes.extend_from_slice(admission.signature.as_ref());
        }
        for tx in &self.txs {
            bytes.extend_from_slice(tx.hash.as_ref());
            bytes.extend_from_slice(&(tx.canonical_payload_encoded_len() as u64).to_le_bytes());
            tx.append_canonical_payload_to(bytes);
        }
    }

    #[cfg(feature = "fair-block-ordering")]
    fn update_fair_order_seed(
        &self,
        hasher: &mut ProtocolHasher,
        modulo: u64,
        byte_index: &mut u64,
    ) {
        update_modulo_seed(hasher, self.validator.as_ref(), modulo, byte_index);
        update_modulo_seed(hasher, self.last_epoch.as_ref(), modulo, byte_index);
        update_modulo_seed(hasher, &self.nonce.to_le_bytes(), modulo, byte_index);
        update_modulo_seed(hasher, &self.created.to_le_bytes(), modulo, byte_index);
        update_modulo_seed(hasher, &self.dispatched.to_le_bytes(), modulo, byte_index);
        update_modulo_seed(hasher, self.merkle_root.as_ref(), modulo, byte_index);
        update_modulo_seed(
            hasher,
            &(self.application_state.len() as u64).to_le_bytes(),
            modulo,
            byte_index,
        );
        update_modulo_seed(
            hasher,
            self.application_state.as_slice(),
            modulo,
            byte_index,
        );
        update_modulo_seed(
            hasher,
            &(self.encounter_records.len() as u64).to_le_bytes(),
            modulo,
            byte_index,
        );
        for record in &self.encounter_records {
            let mut bytes = Vec::with_capacity(record.encoded_len());
            record.append_bytes_to(&mut bytes);
            update_modulo_seed(hasher, &bytes, modulo, byte_index);
        }
        update_modulo_seed(
            hasher,
            &(self.node_admissions.len() as u64).to_le_bytes(),
            modulo,
            byte_index,
        );
        for admission in &self.node_admissions {
            let mut bytes = Vec::with_capacity(
                admission.body.encoded_len() + admission.signature.as_ref().len(),
            );
            admission.body.append_bytes_to(&mut bytes);
            bytes.extend_from_slice(admission.signature.as_ref());
            update_modulo_seed(hasher, &bytes, modulo, byte_index);
        }
        for tx in &self.txs {
            update_modulo_seed(hasher, tx.hash.as_ref(), modulo, byte_index);
            update_modulo_seed(
                hasher,
                &(tx.canonical_payload_encoded_len() as u64).to_le_bytes(),
                modulo,
                byte_index,
            );
            tx.update_canonical_payload_fair_order_seed(hasher, modulo, byte_index);
        }
    }

    pub fn encoded_len(&self) -> usize {
        32 + 32
            + 8
            + 16
            + 16
            + 32
            + 8
            + self.application_state.len()
            + 8
            + self
                .encounter_records
                .iter()
                .map(EncounterRecord::encoded_len)
                .sum::<usize>()
            + 8
            + self
                .node_admissions
                .iter()
                .map(|admission| admission.body.encoded_len() + admission.signature.as_ref().len())
                .sum::<usize>()
            + self
                .txs
                .iter()
                .map(|tx| 32 + 8 + tx.canonical_payload_encoded_len())
                .sum::<usize>()
    }

    pub fn hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(self.validator.as_ref());
        hasher.update(self.last_epoch.as_ref());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.created.to_le_bytes());
        hasher.update(self.dispatched.to_le_bytes());
        hasher.update(self.merkle_root.as_ref());
        hasher.update((self.application_state.len() as u64).to_le_bytes());
        hasher.update(self.application_state.as_slice());
        hasher.update((self.encounter_records.len() as u64).to_le_bytes());
        for record in &self.encounter_records {
            record.update_hash(&mut hasher);
        }
        hasher.update((self.node_admissions.len() as u64).to_le_bytes());
        for admission in &self.node_admissions {
            admission.body.update_hash(&mut hasher);
            hasher.update(admission.signature.as_ref());
        }
        for tx in &self.txs {
            hasher.update(tx.hash.as_ref());
            hasher.update((tx.canonical_payload_encoded_len() as u64).to_le_bytes());
            tx.update_canonical_payload_hash(&mut hasher);
        }
        hasher.finalize()
    }

    pub fn hash_and_merkle_root(&self) -> (HashType, HashType) {
        let mut body_hasher = ProtocolHasher::new();
        let mut merkle_hasher = ProtocolHasher::new();
        body_hasher.update(self.validator.as_ref());
        body_hasher.update(self.last_epoch.as_ref());
        body_hasher.update(self.nonce.to_le_bytes());
        body_hasher.update(self.created.to_le_bytes());
        body_hasher.update(self.dispatched.to_le_bytes());
        body_hasher.update(self.merkle_root.as_ref());
        body_hasher.update((self.application_state.len() as u64).to_le_bytes());
        body_hasher.update(self.application_state.as_slice());
        body_hasher.update((self.encounter_records.len() as u64).to_le_bytes());
        for record in &self.encounter_records {
            record.update_hash(&mut body_hasher);
        }
        body_hasher.update((self.node_admissions.len() as u64).to_le_bytes());
        for admission in &self.node_admissions {
            admission.body.update_hash(&mut body_hasher);
            body_hasher.update(admission.signature.as_ref());
        }
        for tx in &self.txs {
            body_hasher.update(tx.hash.as_ref());
            body_hasher.update((tx.canonical_payload_encoded_len() as u64).to_le_bytes());
            tx.update_canonical_payload_hash(&mut body_hasher);
            merkle_hasher.update(tx.hash.as_ref());
        }
        (body_hasher.finalize(), merkle_hasher.finalize())
    }

    pub fn compute_merkle_root(&self) -> HashType {
        HashType::hash_slices(self.txs.iter().map(|tx| tx.hash.as_ref()))
    }

    fn validate_encounter_records(&self) -> Result<()> {
        for record in &self.encounter_records {
            if record.body.observer != self.validator {
                return Err(BlossomError::UnknownSender);
            }
            record.verify()?;
        }
        Ok(())
    }

    fn validate_node_admissions(&self) -> Result<()> {
        for admission in &self.node_admissions {
            admission.verify()?;
        }
        Ok(())
    }

    fn validate_transactions(&self) -> Result<()> {
        #[cfg(feature = "filtered-transactions")]
        {
            for tx in &self.txs {
                tx.validate_filtered_integrity()?;
            }
        }

        Ok(())
    }
}

fn validate_application_state_len(len: usize) -> Result<()> {
    if len > BLOCK_APPLICATION_STATE_MAX_BYTES {
        return Err(BlossomError::BlockApplicationStateTooLarge {
            max: BLOCK_APPLICATION_STATE_MAX_BYTES,
            actual: len,
        });
    }
    Ok(())
}

fn now_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

#[cfg(test)]
mod tests;
