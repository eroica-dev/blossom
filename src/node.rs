use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::{Keypair, PubKey, SecKey, SecretSigner, Signature};
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

    pub fn signer(&self) -> Result<SecretSigner> {
        let secret_key = self.secret_key.ok_or(BlossomError::MissingSecretKey)?;
        let signer = SecretSigner::new(secret_key);
        if !signer.matches_public_key(&self.public_key) {
            return Err(BlossomError::KeyMismatch);
        }
        Ok(signer)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        Ok(self.signer()?.sign(message))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_node_can_sign_and_verify() {
        let node = NodeIdentity::generate("tcp", "127.0.0.1", 8080);
        let message = b"node-message";
        let signature = node.sign(message).unwrap();

        assert_eq!(node.protocol, "tcp");
        assert_eq!(node.host, "127.0.0.1");
        assert_eq!(node.port, 8080);
        assert!(NodeIdentity::verify(&signature, message, &node.public_key()).is_ok());
    }

    #[test]
    fn missing_secret_key_cannot_sign() {
        let node = NodeIdentity::new(PubKey([9; 32]), None, "tcp", "localhost", 1, false);

        assert_eq!(node.sign(b"message"), Err(BlossomError::MissingSecretKey));
    }

    #[test]
    fn mismatched_secret_key_cannot_sign() {
        let public = Keypair::generate().public;
        let secret = Keypair::generate().secret;
        let node = NodeIdentity::new(public, Some(secret), "tcp", "localhost", 1, false);

        assert_eq!(node.sign(b"message"), Err(BlossomError::KeyMismatch));
    }

    #[test]
    fn serialization_omits_secret_key() {
        let node = NodeIdentity::generate("tcp", "localhost", 9000);
        let json = serde_json::to_string(&node).unwrap();
        let decoded = serde_json::from_str::<NodeIdentity>(&json).unwrap();

        assert!(!json.contains("secret_key"));
        assert_eq!(decoded.secret_key, None);
        assert_eq!(decoded.public_key, node.public_key);
    }
}
