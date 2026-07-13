use std::fmt;
use std::str::FromStr;

pub use deterministic_test_env::splitmix64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPattern {
    Zero,
    Incrementing,
    Alternating,
    SplitMix,
}

impl DataPattern {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::Incrementing => "incrementing",
            Self::Alternating => "alternating",
            Self::SplitMix => "splitmix",
        }
    }
}

impl fmt::Display for DataPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DataPattern {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "zero" => Ok(Self::Zero),
            "incrementing" => Ok(Self::Incrementing),
            "alternating" => Ok(Self::Alternating),
            "splitmix" => Ok(Self::SplitMix),
            _ => Err(format!(
                "unknown data pattern {value}; expected zero, incrementing, alternating, or splitmix"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicData {
    seed: u64,
    pattern: DataPattern,
}

impl DeterministicData {
    pub fn new(seed: u64, pattern: DataPattern) -> Self {
        Self { seed, pattern }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn pattern(&self) -> DataPattern {
        self.pattern
    }

    pub fn bytes(&self, len: usize, stream: u64, index: u64) -> Vec<u8> {
        let mut bytes = vec![0; len];
        self.fill(&mut bytes, stream, index);
        bytes
    }

    pub fn fill(&self, bytes: &mut [u8], stream: u64, index: u64) {
        match self.pattern {
            DataPattern::Zero => {
                bytes.fill(0);
            }
            DataPattern::Incrementing => {
                let base = self.seed ^ stream.rotate_left(17) ^ index.rotate_left(41);
                for (offset, byte) in bytes.iter_mut().enumerate() {
                    *byte = base.wrapping_add(offset as u64) as u8;
                }
            }
            DataPattern::Alternating => {
                let first = (self.seed ^ stream ^ index) as u8;
                let second = !first;
                for (offset, byte) in bytes.iter_mut().enumerate() {
                    *byte = if offset % 2 == 0 { first } else { second };
                }
            }
            DataPattern::SplitMix => {
                let mut state = self.seed ^ stream.rotate_left(19) ^ index.rotate_left(43);
                for chunk in bytes.chunks_mut(8) {
                    state = splitmix64(state);
                    let state_bytes = state.to_le_bytes();
                    chunk.copy_from_slice(&state_bytes[..chunk.len()]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_data_is_reproducible() {
        let data = DeterministicData::new(7, DataPattern::SplitMix);

        assert_eq!(data.bytes(32, 1, 2), data.bytes(32, 1, 2));
        assert_ne!(data.bytes(32, 1, 2), data.bytes(32, 1, 3));
    }

    #[test]
    fn data_patterns_parse_from_strings() {
        assert_eq!("zero".parse::<DataPattern>(), Ok(DataPattern::Zero));
        assert_eq!(
            "incrementing".parse::<DataPattern>(),
            Ok(DataPattern::Incrementing)
        );
        assert!("bogus".parse::<DataPattern>().is_err());
    }
}
