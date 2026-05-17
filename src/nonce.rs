use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

#[derive(
    Serialize,
    Deserialize,
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
pub struct Nonce(pub u64);

impl Nonce {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    pub fn mut_next(&mut self) {
        self.0 += 1;
    }

    pub fn new_next(&self) -> Self {
        Self(self.0 + 1)
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    pub fn value(self) -> u64 {
        self.0
    }
}

impl Deref for Nonce {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
