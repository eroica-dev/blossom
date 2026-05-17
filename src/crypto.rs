use std::fmt;
use std::ops::Deref;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature as DalekSignature, Signer,
    SigningKey, Verifier, VerifyingKey,
};
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
}
