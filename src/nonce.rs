//! Monotonic epoch nonce type and successor operations.

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

    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increments_without_mutating_original_next_value() {
        let mut nonce = Nonce::new(41);

        assert_eq!(nonce.new_next(), Nonce::new(42));
        assert_eq!(nonce, Nonce::new(41));

        nonce.mut_next();
        assert_eq!(nonce, Nonce::new(42));
    }

    #[test]
    fn bytes_and_display_are_little_endian_decimal() {
        let nonce = Nonce::new(258);

        assert_eq!(nonce.to_string(), "258");
        assert_eq!(nonce.to_bytes(), 258u64.to_le_bytes().to_vec());
        assert_eq!(nonce.value(), 258);
    }
}
