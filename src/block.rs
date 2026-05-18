use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{PubKey, SecKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::hash::{HashType, ProtocolHasher};
use crate::nonce::Nonce;

pub const BLOCK_APPLICATION_STATE_SOFT_LIMIT_BYTES: usize = 4 * 1024;
pub const BLOCK_APPLICATION_STATE_MAX_BYTES: usize = 8 * 1024;

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

/// A hash-identified opaque application transaction.
///
/// The transaction hash is used by the block Merkle root. The payload bytes are
/// also included in the block body hash, so peers cannot alter application data
/// without invalidating block integrity.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct Transaction {
    pub hash: HashType,
    pub payload: TransactionPayload,
}

impl Transaction {
    #[inline]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        let hash = HashType::hash(&bytes);
        Self {
            hash,
            payload: TransactionPayload { bytes },
        }
    }

    #[inline]
    pub fn from_payload(payload: impl Into<TransactionPayload>) -> Self {
        let payload = payload.into();
        let hash = HashType::hash(&payload.bytes);
        Self { hash, payload }
    }

    #[inline]
    pub(crate) fn from_parts(hash: HashType, payload: impl Into<TransactionPayload>) -> Self {
        Self {
            hash,
            payload: payload.into(),
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

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.payload.bytes.is_empty()
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
        [self.hash.as_ref(), self.payload.bytes.as_slice()].concat()
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
        let signer = SecretSigner::new(*secret_key);
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
        for tx in &self.txs {
            let payload = tx.payload.bytes.as_slice();
            bytes.extend_from_slice(tx.hash.as_ref());
            bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            bytes.extend_from_slice(payload);
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
            + self
                .txs
                .iter()
                .map(|tx| 32 + 8 + tx.payload.bytes.len())
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
        for tx in &self.txs {
            let payload = tx.payload.bytes.as_slice();
            hasher.update(tx.hash.as_ref());
            hasher.update((payload.len() as u64).to_le_bytes());
            hasher.update(payload);
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
        for tx in &self.txs {
            let payload = tx.payload.bytes.as_slice();
            body_hasher.update(tx.hash.as_ref());
            body_hasher.update((payload.len() as u64).to_le_bytes());
            body_hasher.update(payload);
            merkle_hasher.update(tx.hash.as_ref());
        }
        (body_hasher.finalize(), merkle_hasher.finalize())
    }

    pub fn compute_merkle_root(&self) -> HashType {
        HashType::hash_slices(self.txs.iter().map(|tx| tx.hash.as_ref()))
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
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn block_signature_round_trip() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.txs.push(Transaction::new("tx-1"));
        block.sign(&keypair.secret);

        assert_eq!(block.body.validator, keypair.public);
        assert!(
            block
                .signature
                .verify(block.hash.as_ref(), &keypair.public)
                .is_ok()
        );
        assert!(block.verify_signature().is_ok());
    }

    #[test]
    fn block_can_sign_with_cached_signer() {
        let keypair = Keypair::generate();
        let signer = keypair.signer();
        let mut block = Block::default();
        block.body.txs.push(Transaction::new("tx-1"));
        block.sign_with(&signer);

        assert_eq!(block.body.validator, keypair.public);
        assert!(block.verify_signature().is_ok());
    }

    #[test]
    fn block_body_hash_matches_canonical_bytes() {
        let mut block = Block::default();
        block.set_application_state([1, 2, 3, 4]).unwrap();
        block.body.txs.push(Transaction::new("tx-1"));
        block.body.txs.push(Transaction::new("tx-2"));

        assert_eq!(block.body.hash(), HashType::hash(&block.body.to_bytes()));
        assert_eq!(
            block.body.hash_and_merkle_root().0,
            HashType::hash(&block.body.to_bytes())
        );
        assert_eq!(block.body.encoded_len(), block.body.to_bytes().len());
    }

    #[test]
    fn application_state_is_opaque_bounded_and_hash_committed() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block
            .set_application_state(b"v1:cache-pressure=low")
            .unwrap();
        let without_state_hash = Block::default().hash();
        block.sign(&keypair.secret);

        assert_eq!(block.application_state(), b"v1:cache-pressure=low");
        assert_eq!(block.application_state_len(), 21);
        assert_ne!(block.hash, without_state_hash);
        assert!(block.verify_integrity().is_ok());

        let mut tampered = block.clone();
        tampered
            .body
            .set_application_state(b"v1:cache-pressure=high")
            .unwrap();
        assert_eq!(
            tampered.verify_integrity(),
            Err(BlossomError::InvalidBlockHash)
        );
    }

    #[test]
    fn application_state_limits_are_enforced() {
        let soft =
            BlockApplicationState::new(vec![0; BLOCK_APPLICATION_STATE_SOFT_LIMIT_BYTES + 1])
                .unwrap();
        assert!(soft.exceeds_soft_limit());

        let too_large = vec![0; BLOCK_APPLICATION_STATE_MAX_BYTES + 1];
        assert_eq!(
            BlockApplicationState::new(too_large),
            Err(BlossomError::BlockApplicationStateTooLarge {
                max: BLOCK_APPLICATION_STATE_MAX_BYTES,
                actual: BLOCK_APPLICATION_STATE_MAX_BYTES + 1
            })
        );

        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.application_state = BlockApplicationState {
            bytes: vec![0; BLOCK_APPLICATION_STATE_MAX_BYTES + 1],
        };
        block.sign(&keypair.secret);

        assert_eq!(
            block.verify_integrity(),
            Err(BlossomError::BlockApplicationStateTooLarge {
                max: BLOCK_APPLICATION_STATE_MAX_BYTES,
                actual: BLOCK_APPLICATION_STATE_MAX_BYTES + 1
            })
        );
    }

    #[test]
    fn merkle_root_matches_concatenated_transaction_hashes() {
        let mut block = Block::default();
        block.body.txs.push(Transaction::new("tx-1"));
        block.body.txs.push(Transaction::new("tx-2"));
        let expected = HashType::hash(
            &[
                block.body.txs[0].hash.as_ref(),
                block.body.txs[1].hash.as_ref(),
            ]
            .concat(),
        );

        assert_eq!(block.body.compute_merkle_root(), expected);
        assert_eq!(block.body.hash_and_merkle_root().1, expected);
    }

    #[test]
    fn transaction_hash_and_payload_are_stable() {
        let tx = Transaction::new("tx-1");

        assert_eq!(tx.hash, HashType::hash(b"tx-1"));
        assert_eq!(tx.payload(), b"tx-1");
        assert_eq!(tx.payload_len(), 4);
        assert_eq!(tx.to_bytes(), [tx.hash.as_ref(), b"tx-1"].concat());
    }

    #[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
    struct CustomKvPayload {
        version: u16,
        key: Vec<u8>,
        value: Vec<u8>,
    }

    #[test]
    fn transaction_payload_accepts_application_defined_data() {
        let kv = CustomKvPayload {
            version: 1,
            key: b"cache:key".to_vec(),
            value: b"cache-value".to_vec(),
        };

        let tx = Transaction::from_borsh(&kv).unwrap();
        let decoded: CustomKvPayload = tx.payload_as_borsh().unwrap();

        assert_eq!(decoded, kv);
        assert_eq!(tx.hash, HashType::hash(tx.payload()));
        assert_eq!(tx.to_bytes(), [tx.hash.as_ref(), tx.payload()].concat());
    }

    #[cfg(feature = "external-transaction-hashes")]
    #[test]
    fn external_transaction_hashes_are_supported_and_block_committed() {
        let external_hash = 0x1122_3344_5566_7788;
        let tx = Transaction::from_external_hash_u64(external_hash, b"kv-payload".to_vec());

        assert_eq!(&tx.hash.as_ref()[..8], &external_hash.to_le_bytes());
        assert_eq!(&tx.hash.as_ref()[8..], &[0; 24]);
        assert_ne!(tx.hash, HashType::hash(tx.payload()));

        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.last_epoch = HashType([1; 32]);
        block.body.nonce = Nonce::new(1);
        block.body.txs.push(tx);
        block.sign(&keypair.secret);

        assert!(block.verify_integrity().is_ok());

        let mut tampered = block.clone();
        tampered.body.txs[0].payload_mut().as_mut_slice()[0] ^= 0xff;
        assert_eq!(
            tampered.verify_integrity(),
            Err(BlossomError::InvalidBlockHash)
        );

        let mut tampered = block;
        tampered.body.txs[0].hash = HashType([9; 32]);
        assert_eq!(
            tampered.verify_integrity(),
            Err(BlossomError::InvalidBlockHash)
        );
    }

    #[test]
    fn signed_block_integrity_rejects_hash_merkle_and_signature_tampering() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.txs.push(Transaction::new("tx-1"));
        block.sign(&keypair.secret);
        assert!(block.verify_integrity().is_ok());
        assert!(block.verify_integrity_with_hash(block.hash).is_ok());
        assert_eq!(
            block.verify_integrity_with_hash(HashType([6; 32])),
            Err(crate::error::BlossomError::InvalidBlockHash)
        );

        let mut tampered_hash = block.clone();
        tampered_hash.hash = HashType([9; 32]);
        assert_eq!(
            tampered_hash.verify_integrity(),
            Err(crate::error::BlossomError::InvalidBlockHash)
        );

        let mut tampered_merkle = block.clone();
        tampered_merkle.body.merkle_root = HashType([8; 32]);
        tampered_merkle.set_hash();
        assert_eq!(
            tampered_merkle.verify_integrity(),
            Err(crate::error::BlossomError::InvalidBlockHash)
        );

        let mut tampered_signature = block;
        tampered_signature.signature = Signature([7; 64]);
        assert_eq!(
            tampered_signature.verify_integrity(),
            Err(crate::error::BlossomError::SignatureError)
        );
    }

    #[test]
    fn unsigned_sealed_block_preserves_hash_and_merkle_integrity() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.txs.push(Transaction::new("tx-1"));
        block.seal_unsigned(keypair.public);

        assert_eq!(block.body.validator, keypair.public);
        assert_eq!(block.signature, Signature::default());
        assert!(block.verify_unsigned_integrity().is_ok());
        assert_eq!(
            block.verify_integrity(),
            Err(crate::error::BlossomError::SignatureError)
        );

        let mut tampered = block;
        tampered.body.txs.push(Transaction::new("tx-2"));
        assert_eq!(
            tampered.verify_unsigned_integrity(),
            Err(crate::error::BlossomError::InvalidBlockHash)
        );
    }

    #[test]
    fn empty_with_nonce_sets_nonce_and_hash() {
        let block = Block::empty_with_nonce(Nonce::new(9));

        assert_eq!(block.body.nonce, Nonce::new(9));
        assert_eq!(block.hash, block.hash());
        assert!(block.is_empty());
        assert_eq!(block.len(), 0);
    }
}
