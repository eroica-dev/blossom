use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::hash::{HashType, ProtocolHasher};
use crate::nonce::Nonce;

pub const ENCOUNTER_RECORD_DOMAIN: &[u8] = b"blossom-encounter-record:v1";
pub const ENCOUNTER_BODY_ENCODED_LEN: usize = ENCOUNTER_RECORD_DOMAIN.len()
    + PUBKEY_BYTES
    + PUBKEY_BYTES
    + HASH_BYTES
    + NONCE_BYTES
    + ROUND_BYTES
    + PHASE_BYTES
    + OUTCOME_BYTES
    + EVIDENCE_FLAG_BYTES
    + HASH_BYTES
    + TIMESTAMP_BYTES;
pub const ENCOUNTER_RECORD_ENCODED_LEN: usize = ENCOUNTER_BODY_ENCODED_LEN + SIGNATURE_BYTES;

const PUBKEY_BYTES: usize = 32;
const HASH_BYTES: usize = 32;
const NONCE_BYTES: usize = 8;
const ROUND_BYTES: usize = 1;
const PHASE_BYTES: usize = 1;
const OUTCOME_BYTES: usize = 1;
const EVIDENCE_FLAG_BYTES: usize = 1;
const TIMESTAMP_BYTES: usize = 16;
const SIGNATURE_BYTES: usize = 64;

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum EncounterPhase {
    Dispatch = 1,
    Verification = 2,
    Proposal = 3,
    Commit = 4,
    EpochStarted = 5,
    CatchUp = 6,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum EncounterOutcome {
    /// The observer expected a signature from the subject and did not see one.
    MissingSignature = 1,
    /// The subject sent a signature that did not verify.
    InvalidSignature = 2,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncounterRecordBody {
    pub observer: PubKey,
    pub subject: PubKey,
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub round: u8,
    pub phase: EncounterPhase,
    pub outcome: EncounterOutcome,
    pub evidence_hash: Option<HashType>,
    pub observed_at_micros: u128,
}

impl EncounterRecordBody {
    pub fn new(
        observer: PubKey,
        subject: PubKey,
        last_epoch: HashType,
        nonce: Nonce,
        round: u8,
        phase: EncounterPhase,
        outcome: EncounterOutcome,
    ) -> Self {
        Self {
            observer,
            subject,
            last_epoch,
            nonce,
            round,
            phase,
            outcome,
            evidence_hash: None,
            observed_at_micros: 0,
        }
    }

    pub fn with_evidence_hash(mut self, evidence_hash: HashType) -> Self {
        self.evidence_hash = Some(evidence_hash);
        self
    }

    pub fn observed_at_micros(mut self, observed_at_micros: u128) -> Self {
        self.observed_at_micros = observed_at_micros;
        self
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
        ENCOUNTER_BODY_ENCODED_LEN
    }

    pub fn append_bytes_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(ENCOUNTER_RECORD_DOMAIN);
        bytes.extend_from_slice(self.observer.as_ref());
        bytes.extend_from_slice(self.subject.as_ref());
        bytes.extend_from_slice(self.last_epoch.as_ref());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes.push(self.round);
        bytes.push(self.phase as u8);
        bytes.push(self.outcome as u8);
        match self.evidence_hash {
            Some(hash) => {
                bytes.push(1);
                bytes.extend_from_slice(hash.as_ref());
            }
            None => {
                bytes.push(0);
                bytes.extend_from_slice(HashType::default().as_ref());
            }
        }
        bytes.extend_from_slice(&self.observed_at_micros.to_le_bytes());
    }

    pub fn update_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(ENCOUNTER_RECORD_DOMAIN);
        hasher.update(self.observer.as_ref());
        hasher.update(self.subject.as_ref());
        hasher.update(self.last_epoch.as_ref());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update([self.round]);
        hasher.update([self.phase as u8]);
        hasher.update([self.outcome as u8]);
        match self.evidence_hash {
            Some(hash) => {
                hasher.update([1]);
                hasher.update(hash.as_ref());
            }
            None => {
                hasher.update([0]);
                hasher.update(HashType::default().as_ref());
            }
        }
        hasher.update(self.observed_at_micros.to_le_bytes());
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct EncounterRecord {
    pub body: EncounterRecordBody,
    pub signature: Signature,
}

impl EncounterRecord {
    pub fn signed(body: EncounterRecordBody, signer: &SecretSigner) -> Result<Self> {
        if body.observer != signer.public_key() {
            return Err(BlossomError::KeyMismatch);
        }
        let signature = signer.sign(body.hash().as_ref());
        Ok(Self { body, signature })
    }

    pub fn verify(&self) -> Result<()> {
        self.signature
            .verify(self.body.hash().as_ref(), &self.body.observer)
    }

    pub fn hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        self.update_hash(&mut hasher);
        hasher.finalize()
    }

    pub fn encoded_len(&self) -> usize {
        ENCOUNTER_RECORD_ENCODED_LEN
    }

    pub fn append_bytes_to(&self, bytes: &mut Vec<u8>) {
        self.body.append_bytes_to(bytes);
        bytes.extend_from_slice(&self.signature.0);
    }

    pub fn update_hash(&self, hasher: &mut ProtocolHasher) {
        self.body.update_hash(hasher);
        hasher.update(self.signature.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn signed_encounter_record_verifies_and_rejects_tampering() {
        let observer = Keypair::generate();
        let subject = Keypair::generate();
        let body = EncounterRecordBody::new(
            observer.public,
            subject.public,
            HashType([3; 32]),
            Nonce::new(7),
            1,
            EncounterPhase::Verification,
            EncounterOutcome::MissingSignature,
        )
        .with_evidence_hash(HashType::hash(b"timeout:peer did not answer"))
        .observed_at_micros(42);

        let record = EncounterRecord::signed(body, &observer.signer()).unwrap();
        assert!(record.verify().is_ok());

        let mut tampered = record.clone();
        tampered.body.outcome = EncounterOutcome::InvalidSignature;
        assert_eq!(tampered.verify(), Err(BlossomError::SignatureError));
    }

    #[test]
    fn signer_must_match_observer() {
        let observer = Keypair::generate();
        let signer = Keypair::generate();
        let body = EncounterRecordBody::new(
            observer.public,
            PubKey([4; 32]),
            HashType::default(),
            Nonce::new(1),
            0,
            EncounterPhase::Dispatch,
            EncounterOutcome::MissingSignature,
        );

        assert_eq!(
            EncounterRecord::signed(body, &signer.signer()),
            Err(BlossomError::KeyMismatch)
        );
    }
}
