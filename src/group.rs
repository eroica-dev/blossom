//! Stable identifiers for independent consensus groups.

use std::fmt;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::hash::{HashType, ProtocolHasher};

const GROUP_ID_DOMAIN: &[u8] = b"blossom-consensus-group:v1:";

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[serde(transparent)]
pub struct ConsensusGroupId(pub HashType);

impl ConsensusGroupId {
    pub fn root() -> Self {
        Self(HashType::default())
    }

    pub fn named(name: impl AsRef<str>) -> Self {
        let mut hasher = ProtocolHasher::new();
        hasher.update(GROUP_ID_DOMAIN);
        hasher.update(name.as_ref().as_bytes());
        Self(hasher.finalize())
    }

    pub fn from_hash(hash: HashType) -> Self {
        Self(hash)
    }

    pub fn hash(self) -> HashType {
        self.0
    }
}

impl Default for ConsensusGroupId {
    fn default() -> Self {
        Self::root()
    }
}

impl AsRef<[u8]> for ConsensusGroupId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for ConsensusGroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_group_ids_are_stable_and_domain_separated_from_root() {
        let first = ConsensusGroupId::named("cache-hotset-a");
        let second = ConsensusGroupId::named("cache-hotset-a");
        let other = ConsensusGroupId::named("cache-hotset-b");

        assert_eq!(first, second);
        assert_ne!(first, other);
        assert_ne!(first, ConsensusGroupId::root());
    }
}
