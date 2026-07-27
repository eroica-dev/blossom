use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::{IndexTreeMap, SharedIndexTreeMap};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(not(feature = "insecure-fast-hash"))]
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Deref;
use std::sync::OnceLock;
#[cfg(feature = "insecure-fast-hash")]
use xxhash_rust::xxh3::Xxh3;

use crate::error::{BlossomError, Result};

pub const SHA256_PROTOCOL_HASH_ALGORITHM: &str = "sha256";
pub const XXH3_PROTOCOL_HASH_ALGORITHM: &str = "xxh3-128x2";
pub const PROTOCOL_FEATURE_CODE_VERSION: u8 = 1;
pub const RESERVED_PROTOCOL_FEATURE_CODE: u16 = 0x0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolFeatureCode {
    pub id: u16,
    pub label: &'static str,
}

impl ProtocolFeatureCode {
    pub const fn new(id: u16, label: &'static str) -> Self {
        Self { id, label }
    }
}

pub const FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE: ProtocolFeatureCode =
    ProtocolFeatureCode::new(0x0001, "fair-block-ordering");
pub const HIGH_AVAILABILITY_PROTOCOL_FEATURE_CODE: ProtocolFeatureCode =
    ProtocolFeatureCode::new(0x0002, "high-availability");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolConsensusSurface {
    EpochBlockOrdering,
    HighAvailabilityFinality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolFeatureRegistryEntry {
    pub code: ProtocolFeatureCode,
    pub dependencies: &'static [u16],
    pub conflicts: &'static [u16],
    pub consensus_surface: ProtocolConsensusSurface,
}

pub const FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE: ProtocolFeatureRegistryEntry =
    ProtocolFeatureRegistryEntry {
        code: FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE,
        dependencies: &[],
        conflicts: &[],
        consensus_surface: ProtocolConsensusSurface::EpochBlockOrdering,
    };
pub const HIGH_AVAILABILITY_PROTOCOL_FEATURE: ProtocolFeatureRegistryEntry =
    ProtocolFeatureRegistryEntry {
        code: HIGH_AVAILABILITY_PROTOCOL_FEATURE_CODE,
        dependencies: &[],
        conflicts: &[],
        consensus_surface: ProtocolConsensusSurface::HighAvailabilityFinality,
    };

pub const PROTOCOL_FEATURE_REGISTRY: &[ProtocolFeatureRegistryEntry] = &[
    FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE,
    HIGH_AVAILABILITY_PROTOCOL_FEATURE,
];

#[cfg(all(feature = "fair-block-ordering", feature = "high-availability"))]
pub const PROTOCOL_FEATURE_CODES: &[ProtocolFeatureCode] = &[
    FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE,
    HIGH_AVAILABILITY_PROTOCOL_FEATURE_CODE,
];
#[cfg(all(feature = "fair-block-ordering", not(feature = "high-availability")))]
pub const PROTOCOL_FEATURE_CODES: &[ProtocolFeatureCode] =
    &[FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE];
#[cfg(all(not(feature = "fair-block-ordering"), feature = "high-availability"))]
pub const PROTOCOL_FEATURE_CODES: &[ProtocolFeatureCode] =
    &[HIGH_AVAILABILITY_PROTOCOL_FEATURE_CODE];
#[cfg(all(
    not(feature = "fair-block-ordering"),
    not(feature = "high-availability")
))]
pub const PROTOCOL_FEATURE_CODES: &[ProtocolFeatureCode] = &[];

pub fn protocol_hash_algorithm() -> &'static str {
    static PROTOCOL_HASH_ALGORITHM: OnceLock<String> = OnceLock::new();
    PROTOCOL_HASH_ALGORITHM
        .get_or_init(protocol_hash_algorithm_string)
        .as_str()
}

fn protocol_base_hash_algorithm() -> &'static str {
    #[cfg(feature = "insecure-fast-hash")]
    {
        XXH3_PROTOCOL_HASH_ALGORITHM
    }

    #[cfg(not(feature = "insecure-fast-hash"))]
    {
        SHA256_PROTOCOL_HASH_ALGORITHM
    }
}

fn protocol_hash_algorithm_string() -> String {
    let mut profile = protocol_base_hash_algorithm().to_string();
    for feature_code in PROTOCOL_FEATURE_CODES {
        profile.push('+');
        profile.push_str(feature_code.label);
    }
    profile
}

pub fn protocol_hash_algorithm_is_compatible(peer: &str) -> bool {
    peer == protocol_hash_algorithm()
}

pub fn protocol_feature_registry_entry(id: u16) -> Option<&'static ProtocolFeatureRegistryEntry> {
    PROTOCOL_FEATURE_REGISTRY
        .iter()
        .find(|entry| entry.code.id == id)
}

pub fn validate_protocol_feature_registry() -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut previous = None;
    for entry in PROTOCOL_FEATURE_REGISTRY {
        let code = entry.code;
        if code.id == RESERVED_PROTOCOL_FEATURE_CODE {
            return Err(BlossomError::WireProtocol(
                "protocol feature registry uses reserved feature id 0x0000".to_string(),
            ));
        }
        if code.label.is_empty() {
            return Err(BlossomError::WireProtocol(
                "protocol feature registry contains an empty feature label".to_string(),
            ));
        }
        if previous.is_some_and(|previous| previous >= code.id) {
            return Err(BlossomError::WireProtocol(
                "protocol feature registry must be sorted by ascending feature id".to_string(),
            ));
        }
        if !seen.insert(code.id) {
            return Err(BlossomError::WireProtocol(format!(
                "protocol feature registry duplicates feature id 0x{:04x}",
                code.id
            )));
        }
        previous = Some(code.id);
    }

    for entry in PROTOCOL_FEATURE_REGISTRY {
        for dependency in entry.dependencies {
            if *dependency == entry.code.id {
                return Err(BlossomError::WireProtocol(format!(
                    "protocol feature {} depends on itself",
                    entry.code.label
                )));
            }
            if !seen.contains(dependency) {
                return Err(BlossomError::WireProtocol(format!(
                    "protocol feature {} depends on unregistered feature id 0x{dependency:04x}",
                    entry.code.label
                )));
            }
        }
        for conflict in entry.conflicts {
            if *conflict == entry.code.id {
                return Err(BlossomError::WireProtocol(format!(
                    "protocol feature {} conflicts with itself",
                    entry.code.label
                )));
            }
            if !seen.contains(conflict) {
                return Err(BlossomError::WireProtocol(format!(
                    "protocol feature {} conflicts with unregistered feature id 0x{conflict:04x}",
                    entry.code.label
                )));
            }
            if entry.dependencies.contains(conflict) {
                return Err(BlossomError::WireProtocol(format!(
                    "protocol feature {} both depends on and conflicts with feature id 0x{conflict:04x}",
                    entry.code.label
                )));
            }
        }
    }

    Ok(())
}

pub fn validate_protocol_feature_codes(codes: &[ProtocolFeatureCode]) -> Result<()> {
    validate_protocol_feature_registry()?;

    if codes.len() > u16::MAX as usize {
        return Err(BlossomError::WireProtocol(
            "protocol feature profile has too many active features".to_string(),
        ));
    }

    let mut seen = BTreeSet::new();
    let mut previous = None;
    for code in codes {
        if code.id == RESERVED_PROTOCOL_FEATURE_CODE {
            return Err(BlossomError::WireProtocol(
                "protocol feature profile uses reserved feature id 0x0000".to_string(),
            ));
        }
        if code.label.is_empty() {
            return Err(BlossomError::WireProtocol(
                "protocol feature profile contains an empty feature label".to_string(),
            ));
        }
        if previous.is_some_and(|previous| previous >= code.id) {
            return Err(BlossomError::WireProtocol(
                "protocol feature profile must be sorted by ascending feature id".to_string(),
            ));
        }
        if !seen.insert(code.id) {
            return Err(BlossomError::WireProtocol(format!(
                "protocol feature profile duplicates feature id 0x{:04x}",
                code.id
            )));
        }
        let Some(entry) = protocol_feature_registry_entry(code.id) else {
            return Err(BlossomError::WireProtocol(format!(
                "protocol feature profile uses unregistered feature id 0x{:04x}",
                code.id
            )));
        };
        if entry.code.label != code.label {
            return Err(BlossomError::WireProtocol(format!(
                "protocol feature id 0x{:04x} label mismatch: expected {}, got {}",
                code.id, entry.code.label, code.label
            )));
        }
        previous = Some(code.id);
    }

    for code in codes {
        let entry = protocol_feature_registry_entry(code.id).expect("entry checked above");
        for dependency in entry.dependencies {
            if !seen.contains(dependency) {
                return Err(BlossomError::WireProtocol(format!(
                    "protocol feature {} requires missing feature id 0x{dependency:04x}",
                    entry.code.label
                )));
            }
        }
        for conflict in entry.conflicts {
            if seen.contains(conflict) {
                return Err(BlossomError::WireProtocol(format!(
                    "protocol feature {} conflicts with feature id 0x{conflict:04x}",
                    entry.code.label
                )));
            }
        }
    }

    Ok(())
}

pub fn protocol_feature_code_bytes() -> Vec<u8> {
    validate_protocol_feature_codes(PROTOCOL_FEATURE_CODES)
        .expect("compiled protocol feature profile must be valid");

    let mut bytes = Vec::with_capacity(3 + (PROTOCOL_FEATURE_CODES.len() * 2));
    bytes.push(PROTOCOL_FEATURE_CODE_VERSION);
    bytes.extend_from_slice(&(PROTOCOL_FEATURE_CODES.len() as u16).to_be_bytes());
    for feature_code in PROTOCOL_FEATURE_CODES {
        bytes.extend_from_slice(&feature_code.id.to_be_bytes());
    }
    bytes
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
    #[cfg(not(feature = "fair-block-ordering"))]
    fn protocol_hash_algorithm_reports_raw_ordering_profile() {
        #[cfg(feature = "insecure-fast-hash")]
        assert_eq!(protocol_hash_algorithm(), XXH3_PROTOCOL_HASH_ALGORITHM);

        #[cfg(not(feature = "insecure-fast-hash"))]
        assert_eq!(protocol_hash_algorithm(), SHA256_PROTOCOL_HASH_ALGORITHM);

        assert_eq!(PROTOCOL_FEATURE_CODES, &[]);
        assert_eq!(
            protocol_feature_code_bytes(),
            vec![PROTOCOL_FEATURE_CODE_VERSION, 0x00, 0x00]
        );
    }

    #[test]
    #[cfg(feature = "fair-block-ordering")]
    fn protocol_hash_algorithm_reports_fair_ordering_profile() {
        #[cfg(all(feature = "insecure-fast-hash", feature = "high-availability"))]
        assert_eq!(
            protocol_hash_algorithm(),
            "xxh3-128x2+fair-block-ordering+high-availability"
        );
        #[cfg(all(not(feature = "insecure-fast-hash"), feature = "high-availability"))]
        assert_eq!(
            protocol_hash_algorithm(),
            "sha256+fair-block-ordering+high-availability"
        );
        #[cfg(feature = "insecure-fast-hash")]
        #[cfg(not(feature = "high-availability"))]
        assert_eq!(protocol_hash_algorithm(), "xxh3-128x2+fair-block-ordering");

        #[cfg(not(feature = "insecure-fast-hash"))]
        #[cfg(not(feature = "high-availability"))]
        assert_eq!(protocol_hash_algorithm(), "sha256+fair-block-ordering");

        #[cfg(feature = "high-availability")]
        assert_eq!(
            PROTOCOL_FEATURE_CODES,
            &[
                FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE,
                HIGH_AVAILABILITY_PROTOCOL_FEATURE_CODE
            ]
        );
        #[cfg(not(feature = "high-availability"))]
        assert_eq!(
            PROTOCOL_FEATURE_CODES,
            &[FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE]
        );
        #[cfg(feature = "high-availability")]
        assert_eq!(
            protocol_feature_code_bytes(),
            vec![
                PROTOCOL_FEATURE_CODE_VERSION,
                0x00,
                0x02,
                0x00,
                0x01,
                0x00,
                0x02
            ]
        );
        #[cfg(not(feature = "high-availability"))]
        assert_eq!(
            protocol_feature_code_bytes(),
            vec![PROTOCOL_FEATURE_CODE_VERSION, 0x00, 0x01, 0x00, 0x01]
        );
        assert!(!protocol_hash_algorithm_is_compatible(
            protocol_base_hash_algorithm()
        ));
    }

    #[test]
    fn protocol_feature_code_namespace_has_extension_room() {
        assert!(u16::MAX as usize > 65_000);
        assert!(PROTOCOL_FEATURE_CODES.len() <= u16::MAX as usize);
        assert!(
            PROTOCOL_FEATURE_CODES
                .iter()
                .all(|feature_code| feature_code.id != RESERVED_PROTOCOL_FEATURE_CODE)
        );
        assert!(
            PROTOCOL_FEATURE_CODES
                .windows(2)
                .all(|window| window[0].id < window[1].id)
        );
    }

    #[test]
    fn protocol_feature_registry_validates_active_profile() {
        assert_eq!(
            protocol_feature_registry_entry(FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE.id),
            Some(&FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE)
        );
        assert_eq!(
            protocol_feature_registry_entry(HIGH_AVAILABILITY_PROTOCOL_FEATURE_CODE.id),
            Some(&HIGH_AVAILABILITY_PROTOCOL_FEATURE)
        );
        assert!(validate_protocol_feature_registry().is_ok());
        assert!(validate_protocol_feature_codes(PROTOCOL_FEATURE_CODES).is_ok());
        assert!(
            PROTOCOL_FEATURE_REGISTRY
                .windows(2)
                .all(|window| window[0].code.id < window[1].code.id)
        );
    }

    #[test]
    fn protocol_feature_registry_rejects_invalid_profiles() {
        assert!(
            validate_protocol_feature_codes(&[ProtocolFeatureCode::new(
                RESERVED_PROTOCOL_FEATURE_CODE,
                "reserved"
            )])
            .is_err()
        );
        assert!(
            validate_protocol_feature_codes(&[ProtocolFeatureCode::new(0x7fff, "not-registered")])
                .is_err()
        );
        assert!(
            validate_protocol_feature_codes(&[ProtocolFeatureCode::new(
                FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE.id,
                "wrong-label"
            )])
            .is_err()
        );
        assert!(
            validate_protocol_feature_codes(&[
                FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE,
                FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE
            ])
            .is_err()
        );
    }

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
