use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature as DalekSignature, Signer,
    SigningKey, Verifier, VerifyingKey,
    hazmat::{ExpandedSecretKey, raw_sign},
    verify_batch as dalek_verify_batch,
};
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha512;

use crate::error::{BlossomError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    pub public: PubKey,
    pub secret: SecKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = VerifyingKey::from(&signing_key);
        Self {
            public: PubKey(verifying_key.to_bytes()),
            secret: SecKey(signing_key.to_bytes()),
        }
    }

    pub fn signer(&self) -> SecretSigner {
        SecretSigner::new(self.secret)
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Default,
    Copy,
)]
pub struct PubKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl PubKey {
    pub fn try_from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).map_err(|_| BlossomError::InvalidHex)?;
        Self::try_from(bytes.as_slice())
    }

    pub fn as_array(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }
}

impl Deref for PubKey {
    type Target = [u8; PUBLIC_KEY_LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for PubKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&[u8]> for PubKey {
    type Error = BlossomError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let actual = value.len();
        let bytes = value.try_into().map_err(|_| BlossomError::InvalidLength {
            expected: PUBLIC_KEY_LENGTH,
            actual,
        })?;
        Ok(Self(bytes))
    }
}

impl TryFrom<&str> for PubKey {
    type Error = BlossomError;

    fn try_from(value: &str) -> Result<Self> {
        Self::try_from_hex(value)
    }
}

impl From<&[u8; PUBLIC_KEY_LENGTH]> for PubKey {
    fn from(value: &[u8; PUBLIC_KEY_LENGTH]) -> Self {
        Self(*value)
    }
}

impl Serialize for PubKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = <String as Deserialize>::deserialize(deserializer)?;
        Self::try_from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Default,
    Copy,
)]
pub struct SecKey(pub [u8; SECRET_KEY_LENGTH]);

impl SecKey {
    pub fn try_from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).map_err(|_| BlossomError::InvalidHex)?;
        Self::try_from(bytes.as_slice())
    }

    pub fn as_array(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.0
    }
}

impl Deref for SecKey {
    type Target = [u8; SECRET_KEY_LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for SecKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for SecKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&[u8]> for SecKey {
    type Error = BlossomError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let actual = value.len();
        let bytes = value.try_into().map_err(|_| BlossomError::InvalidLength {
            expected: SECRET_KEY_LENGTH,
            actual,
        })?;
        Ok(Self(bytes))
    }
}

impl TryFrom<&str> for SecKey {
    type Error = BlossomError;

    fn try_from(value: &str) -> Result<Self> {
        Self::try_from_hex(value)
    }
}

impl From<&[u8; SECRET_KEY_LENGTH]> for SecKey {
    fn from(value: &[u8; SECRET_KEY_LENGTH]) -> Self {
        Self(*value)
    }
}

impl Serialize for SecKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SecKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = <String as Deserialize>::deserialize(deserializer)?;
        Self::try_from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(
    BorshSerialize, BorshDeserialize, Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd, Copy,
)]
pub struct Signature(pub [u8; SIGNATURE_LENGTH]);

impl Signature {
    pub fn sign(message: &[u8], secret_key: &SecKey) -> Self {
        let signing_key = SigningKey::from_bytes(secret_key.as_array());
        Self(signing_key.sign(message).to_bytes())
    }

    pub fn verify(&self, message: &[u8], public_key: &PubKey) -> Result<()> {
        let verifying_key = VerifyingKey::from_bytes(public_key.as_array())
            .map_err(|_| BlossomError::InvalidPublicKey)?;
        let signature = DalekSignature::from_bytes(&self.0);
        verifying_key
            .verify(message, &signature)
            .map_err(|_| BlossomError::SignatureError)
    }

    pub fn try_from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).map_err(|_| BlossomError::InvalidHex)?;
        Self::try_from(bytes.as_slice())
    }
}

pub fn verify_batch(
    messages: &[&[u8]],
    signatures: &[Signature],
    public_keys: &[PubKey],
) -> Result<()> {
    if messages.len() != signatures.len() || signatures.len() != public_keys.len() {
        return Err(BlossomError::InvalidLength {
            expected: messages.len(),
            actual: signatures.len().max(public_keys.len()),
        });
    }

    let verifying_keys = public_keys
        .iter()
        .map(|public_key| {
            VerifyingKey::from_bytes(public_key.as_array())
                .map_err(|_| BlossomError::InvalidPublicKey)
        })
        .collect::<Result<Vec<_>>>()?;
    if verifying_keys.iter().any(VerifyingKey::is_weak) {
        return Err(BlossomError::InvalidPublicKey);
    }

    let signatures = signatures
        .iter()
        .map(|signature| DalekSignature::from_bytes(&signature.0))
        .collect::<Vec<_>>();
    dalek_verify_batch(messages, &signatures, &verifying_keys)
        .map_err(|_| BlossomError::SignatureError)
}

pub struct SecretSigner {
    public_key: PubKey,
    verifying_key: VerifyingKey,
    expanded_key: Arc<ExpandedSecretKey>,
}

impl SecretSigner {
    pub fn new(secret_key: SecKey) -> Self {
        let signing_key = SigningKey::from_bytes(secret_key.as_array());
        let verifying_key = signing_key.verifying_key();
        // Keep dalek's hazmat API private and derive this only from the normal seed.
        let expanded_key = ExpandedSecretKey::from(secret_key.as_array());
        let public_key = PubKey(verifying_key.to_bytes());
        Self {
            public_key,
            verifying_key,
            expanded_key: Arc::new(expanded_key),
        }
    }

    pub fn public_key(&self) -> PubKey {
        self.public_key
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(raw_sign::<Sha512>(&self.expanded_key, message, &self.verifying_key).to_bytes())
    }

    pub fn matches_public_key(&self, public_key: &PubKey) -> bool {
        self.public_key == *public_key
    }
}

impl Clone for SecretSigner {
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key,
            verifying_key: self.verifying_key,
            expanded_key: Arc::clone(&self.expanded_key),
        }
    }
}

impl fmt::Debug for SecretSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretSigner")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self([0; SIGNATURE_LENGTH])
    }
}

impl Deref for Signature {
    type Target = [u8; SIGNATURE_LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = BlossomError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let actual = value.len();
        let bytes = value.try_into().map_err(|_| BlossomError::InvalidLength {
            expected: SIGNATURE_LENGTH,
            actual,
        })?;
        Ok(Self(bytes))
    }
}

impl TryFrom<&str> for Signature {
    type Error = BlossomError;

    fn try_from(value: &str) -> Result<Self> {
        Self::try_from_hex(value)
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = <String as Deserialize>::deserialize(deserializer)?;
        Self::try_from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies() {
        let keypair = Keypair::generate();
        let message = b"blossom";
        let signature = Signature::sign(message, &keypair.secret);

        assert!(signature.verify(message, &keypair.public).is_ok());
        assert!(signature.verify(b"not blossom", &keypair.public).is_err());
    }

    #[test]
    fn secret_signer_reuses_key_material_without_changing_signatures() {
        let keypair = Keypair::generate();
        let signer = keypair.signer();
        let message = b"cached signer";
        let signature = signer.sign(message);
        let expected = Signature::sign(message, &keypair.secret);

        assert_eq!(signer.public_key(), keypair.public);
        assert!(signer.matches_public_key(&keypair.public));
        assert_eq!(signature, expected);
        assert!(signature.verify(message, &keypair.public).is_ok());
    }

    #[test]
    fn batch_verifies_multiple_signatures() {
        let keypairs = [
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
            Keypair::generate(),
        ];
        let messages = [
            b"one".as_slice(),
            b"two".as_slice(),
            b"three".as_slice(),
            b"four".as_slice(),
        ];
        let signatures = keypairs
            .iter()
            .zip(messages)
            .map(|(keypair, message)| Signature::sign(message, &keypair.secret))
            .collect::<Vec<_>>();
        let public_keys = keypairs
            .iter()
            .map(|keypair| keypair.public)
            .collect::<Vec<_>>();

        assert!(verify_batch(&messages, &signatures, &public_keys).is_ok());

        let mut bad = signatures.clone();
        bad[0] = signatures[1];
        assert!(verify_batch(&messages, &bad, &public_keys).is_err());
    }

    #[test]
    fn public_secret_and_signature_hex_round_trip() {
        let keypair = Keypair::generate();
        let signature = Signature::sign(b"message", &keypair.secret);

        assert_eq!(
            PubKey::try_from_hex(&keypair.public.to_string()),
            Ok(keypair.public)
        );
        assert_eq!(
            SecKey::try_from_hex(&keypair.secret.to_string()),
            Ok(keypair.secret)
        );
        assert_eq!(
            Signature::try_from_hex(&signature.to_string()),
            Ok(signature)
        );
    }

    #[test]
    fn malformed_key_material_is_rejected() {
        assert_eq!(PubKey::try_from_hex("xx"), Err(BlossomError::InvalidHex));
        assert_eq!(
            PubKey::try_from(&[1, 2][..]),
            Err(BlossomError::InvalidLength {
                expected: 32,
                actual: 2
            })
        );
        assert_eq!(
            SecKey::try_from(&[1, 2, 3][..]),
            Err(BlossomError::InvalidLength {
                expected: 32,
                actual: 3
            })
        );
        assert_eq!(
            Signature::try_from(&[1; 8][..]),
            Err(BlossomError::InvalidLength {
                expected: 64,
                actual: 8
            })
        );
    }

    #[test]
    fn serde_round_trip_uses_hex_strings() {
        let keypair = Keypair::generate();
        let signature = Signature::sign(b"message", &keypair.secret);

        let public_json = serde_json::to_string(&keypair.public).unwrap();
        let secret_json = serde_json::to_string(&keypair.secret).unwrap();
        let signature_json = serde_json::to_string(&signature).unwrap();

        assert!(public_json.contains(&keypair.public.to_string()));
        assert_eq!(
            serde_json::from_str::<PubKey>(&public_json).unwrap(),
            keypair.public
        );
        assert_eq!(
            serde_json::from_str::<SecKey>(&secret_json).unwrap(),
            keypair.secret
        );
        assert_eq!(
            serde_json::from_str::<Signature>(&signature_json).unwrap(),
            signature
        );
    }
}
