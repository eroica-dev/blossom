use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::{IndexTreeMap, SharedIndexTreeMap};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(not(feature = "insecure-fast-hash"))]
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
#[cfg(feature = "insecure-fast-hash")]
use xxhash_rust::xxh3::Xxh3;

use crate::error::{BlossomError, Result};

pub const SHA256_PROTOCOL_HASH_ALGORITHM: &str = "sha256";
pub const XXH3_PROTOCOL_HASH_ALGORITHM: &str = "xxh3-128x2";

pub fn protocol_hash_algorithm() -> &'static str {
    #[cfg(feature = "insecure-fast-hash")]
    {
        XXH3_PROTOCOL_HASH_ALGORITHM
    }

    #[cfg(not(feature = "insecure-fast-hash"))]
    {
        SHA256_PROTOCOL_HASH_ALGORITHM
    }
}

pub fn protocol_hash_algorithm_is_compatible(peer: &str) -> bool {
    peer == protocol_hash_algorithm()
}

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
        let mut hasher = ProtocolHasher::new();
        hasher.update(bytes);
        hasher.finalize()
    }

    pub fn hash_slices<'a, I>(slices: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut hasher = ProtocolHasher::new();
        for bytes in slices {
            hasher.update(bytes);
        }
        hasher.finalize()
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

#[cfg(not(feature = "insecure-fast-hash"))]
pub struct ProtocolHasher {
    inner: Sha256,
}

#[cfg(not(feature = "insecure-fast-hash"))]
impl ProtocolHasher {
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.inner.update(bytes.as_ref());
    }

    pub fn finalize(self) -> HashType {
        HashType::from_byte_hash(self.inner.finalize().into())
    }
}

#[cfg(feature = "insecure-fast-hash")]
pub struct ProtocolHasher {
    primary: Xxh3,
    secondary: Xxh3,
}

#[cfg(feature = "insecure-fast-hash")]
impl ProtocolHasher {
    pub fn new() -> Self {
        Self {
            primary: Xxh3::new(),
            secondary: Xxh3::with_seed(0xb105_50ff_0d15_ea5e),
        }
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        let bytes = bytes.as_ref();
        self.primary.update(bytes);
        self.secondary.update(bytes);
    }

    pub fn finalize(self) -> HashType {
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(&self.primary.digest128().to_le_bytes());
        bytes[16..].copy_from_slice(&self.secondary.digest128().to_le_bytes());
        HashType::from_byte_hash(bytes)
    }
}

impl Default for ProtocolHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> DoHash for BTreeMap<K, V>
where
    K: Ord + AsRef<[u8]>,
{
    fn hash(&self) -> HashType {
        HashType::hash_slices(self.keys().map(AsRef::as_ref))
    }
}

impl<K, V> DoHash for IndexTreeMap<K, V>
where
    K: Sized + Ord + AsRef<[u8]>,
{
    fn hash(&self) -> HashType {
        HashType::hash_slices(self.keys_ref().map(AsRef::as_ref))
    }
}

impl<K, V> DoHash for SharedIndexTreeMap<K, V>
where
    K: AsRef<[u8]>,
{
    fn hash(&self) -> HashType {
        HashType::hash_slices(self.keys_ref().map(AsRef::as_ref))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PubKey;

    #[test]
    fn hex_display_parse_and_json_round_trip() {
        let hash = HashType([7; 32]);
        let encoded = hash.to_string();

        assert_eq!(HashType::try_from_hex(&encoded), Ok(hash));
        assert_eq!(
            serde_json::to_string(&hash).unwrap(),
            format!("\"{encoded}\"")
        );
        assert_eq!(
            serde_json::from_str::<HashType>(&format!("\"{encoded}\"")).unwrap(),
            hash
        );
    }

    #[test]
    fn invalid_hex_and_length_are_rejected() {
        assert_eq!(
            HashType::try_from_hex("not-hex"),
            Err(BlossomError::InvalidHex)
        );
        assert_eq!(
            HashType::try_from(&[1, 2, 3][..]),
            Err(BlossomError::InvalidLength {
                expected: 32,
                actual: 3
            })
        );
    }

    #[test]
    fn map_hashes_are_key_ordered_and_value_independent() {
        let mut first = BTreeMap::new();
        first.insert(PubKey([2; 32]), "two");
        first.insert(PubKey([1; 32]), "one");

        let mut second = BTreeMap::new();
        second.insert(PubKey([1; 32]), "different");
        second.insert(PubKey([2; 32]), "values");

        assert_eq!(DoHash::hash(&first), DoHash::hash(&second));
    }

    #[test]
    fn index_tree_hash_uses_indexed_keys() {
        let mut tree = IndexTreeMap::new();
        tree.insert(PubKey([1; 32]), ());
        tree.insert(PubKey([2; 32]), ());

        let mut map = BTreeMap::new();
        map.insert(PubKey([1; 32]), ());
        map.insert(PubKey([2; 32]), ());

        assert_eq!(DoHash::hash(&tree), DoHash::hash(&map));
    }
}
