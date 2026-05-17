use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::{Keypair, PubKey, SecKey, Signature};
use crate::error::{BlossomError, Result};

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Default,
)]
pub struct NodeIdentity {
    pub public_key: PubKey,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub secret_key: Option<SecKey>,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub shuffle: bool,
}

impl NodeIdentity {
    pub fn new(
        public_key: PubKey,
        secret_key: Option<SecKey>,
        protocol: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        shuffle: bool,
    ) -> Self {
        Self {
            public_key,
            secret_key,
            protocol: protocol.into(),
            host: host.into(),
            port,
            shuffle,
        }
    }

    pub fn generate(protocol: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        let keypair = Keypair::generate();
        Self::new(
            keypair.public,
            Some(keypair.secret),
            protocol,
            host,
            port,
            true,
        )
    }

    pub fn public_key(&self) -> PubKey {
        self.public_key
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let secret_key = self.secret_key.ok_or(BlossomError::MissingSecretKey)?;
        Ok(Signature::sign(message, &secret_key))
    }

    pub fn verify(signature: &Signature, message: &[u8], public_key: &PubKey) -> Result<()> {
        signature.verify(message, public_key)
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Default,
)]
pub enum NodeType {
    #[default]
    Validator,
    Observer,
    Consort,
}
