//! Public node identities, signer separation, and node roles.

use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::{Keypair, PubKey, SecKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
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
    #[borsh(skip)]
    secret_key: Option<SecKey>,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub shuffle: bool,
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("public_key", &self.public_key)
            .field(
                "signing_material",
                &self.secret_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("shuffle", &self.shuffle)
            .finish()
    }
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
            Some(keypair.secret.clone()),
            protocol,
            host,
            port,
            true,
        )
    }

    pub fn public_key(&self) -> PubKey {
        self.public_key
    }

    pub fn public_only(&self) -> Self {
        let mut identity = self.clone();
        identity.secret_key = None;
        identity
    }

    pub fn has_signing_material(&self) -> bool {
        self.secret_key.is_some()
    }

    pub fn signer(&self) -> Result<SecretSigner> {
        let secret_key = self
            .secret_key
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
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
        let borsh = borsh::to_vec(&node).unwrap();
        let decoded_borsh = borsh::from_slice::<NodeIdentity>(&borsh).unwrap();

        assert!(!json.contains("secret_key"));
        assert_eq!(decoded.secret_key, None);
        assert_eq!(decoded_borsh.secret_key, None);
        assert_eq!(decoded.public_key, node.public_key);
        assert!(
            !format!("{node:?}")
                .contains(&hex::encode(node.secret_key.as_ref().unwrap().as_array()))
        );
    }
}
