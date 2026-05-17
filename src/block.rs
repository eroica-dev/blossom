use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{PubKey, SecKey, Signature};
use crate::error::Result;
use crate::hash::HashType;
use crate::nonce::Nonce;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct Transaction {
    pub hash: HashType,
    pub bytes: Vec<u8>,
}

impl Transaction {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        let hash = HashType::hash(&bytes);
        Self { hash, bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [self.hash.as_ref(), self.bytes.as_slice()].concat()
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

    pub fn sign(&mut self, secret_key: &SecKey) {
        self.body.validator = PubKey::from(secret_key_to_public(secret_key).as_array());
        self.body.merkle_root = self.body.compute_merkle_root();
        self.set_hash();
        self.signature = Signature::sign(&self.body.to_bytes(), secret_key);
    }

    pub fn verify_signature(&self) -> Result<()> {
        self.signature
            .verify(&self.body.to_bytes(), &self.body.validator)
    }

    pub fn verify_integrity(&self) -> Result<()> {
        if self.hash != self.hash() {
            return Err(crate::error::BlossomError::InvalidBlockHash);
        }
        if self.body.merkle_root != self.body.compute_merkle_root() {
            return Err(crate::error::BlossomError::InvalidBlockHash);
        }
        self.verify_signature()
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
            txs: Vec::new(),
        }
    }
}

impl BlockBody {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.validator.as_ref());
        bytes.extend_from_slice(self.last_epoch.as_ref());
        bytes.extend_from_slice(&self.nonce.to_bytes());
        bytes.extend_from_slice(&self.created.to_le_bytes());
        bytes.extend_from_slice(&self.dispatched.to_le_bytes());
        bytes.extend_from_slice(self.merkle_root.as_ref());
        for tx in &self.txs {
            bytes.extend_from_slice(tx.hash.as_ref());
            bytes.extend_from_slice(&(tx.bytes.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&tx.bytes);
        }
        bytes
    }

    pub fn hash(&self) -> HashType {
        HashType::hash(&self.to_bytes())
    }

    pub fn compute_merkle_root(&self) -> HashType {
        let mut bytes = Vec::with_capacity(self.txs.len() * 32);
        for tx in &self.txs {
            bytes.extend_from_slice(tx.hash.as_ref());
        }
        HashType::hash(&bytes)
    }
}

fn now_micros() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

fn secret_key_to_public(secret_key: &SecKey) -> PubKey {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key.as_array());
    let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
    PubKey(verifying_key.to_bytes())
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
        assert!(block.verify_signature().is_ok());
    }

    #[test]
    fn transaction_hash_and_bytes_are_stable() {
        let tx = Transaction::new("tx-1");

        assert_eq!(tx.hash, HashType::hash(b"tx-1"));
        assert_eq!(tx.to_bytes(), [tx.hash.as_ref(), b"tx-1"].concat());
    }

    #[test]
    fn signed_block_integrity_rejects_hash_merkle_and_signature_tampering() {
        let keypair = Keypair::generate();
        let mut block = Block::default();
        block.body.txs.push(Transaction::new("tx-1"));
        block.sign(&keypair.secret);
        assert!(block.verify_integrity().is_ok());

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
    fn empty_with_nonce_sets_nonce_and_hash() {
        let block = Block::empty_with_nonce(Nonce::new(9));

        assert_eq!(block.body.nonce, Nonce::new(9));
        assert_eq!(block.hash, block.hash());
        assert!(block.is_empty());
        assert_eq!(block.len(), 0);
    }
}
