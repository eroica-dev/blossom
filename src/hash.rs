use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::hash::Hash;
use std::ops::Deref;

use crate::error::{BlossomError, Result};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Default,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Copy,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct HashType(pub [u8; 32]);

impl HashType {
    pub fn hash(bytes: &[u8]) -> Self {
        let mut sha256 = Sha256::new();
        sha256.update(bytes);
        Self(sha256.finalize().into())
    }

    pub fn from_byte_hash(hash: [u8; 32]) -> Self {
        Self(hash)
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn try_from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).map_err(|_| BlossomError::InvalidHex)?;
        Self::try_from(bytes.as_slice())
    }
}

impl Deref for HashType {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for HashType {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&[u8]> for HashType {
    type Error = BlossomError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let actual = value.len();
        let bytes: [u8; 32] = value.try_into().map_err(|_| BlossomError::InvalidLength {
            expected: 32,
            actual,
        })?;
        Ok(Self(bytes))
    }
}

impl From<[u8; 32]> for HashType {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl Serialize for HashType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HashType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = <String as Deserialize>::deserialize(deserializer)?;
        Self::try_from_hex(&value).map_err(serde::de::Error::custom)
    }
}

pub trait DoHash {
    fn hash(&self) -> HashType;
}

impl<K, V> DoHash for BTreeMap<K, V>
where
    K: Ord + AsRef<[u8]>,
{
    fn hash(&self) -> HashType {
        let mut bytes = Vec::with_capacity(self.len() * 32);
        for key in self.keys() {
            bytes.extend_from_slice(key.as_ref());
        }
        HashType::hash(&bytes)
    }
}

impl<K, V> DoHash for IndexTreeMap<K, V>
where
    K: Sized + Default + Ord + Clone + Hash + AsRef<[u8]>,
    V: Sized + Default + Clone,
{
    fn hash(&self) -> HashType {
        let mut bytes = Vec::with_capacity(self.len() * 32);
        for key in self.keys() {
            bytes.extend_from_slice(key.as_ref());
        }
        HashType::hash(&bytes)
    }
}
