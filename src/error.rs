use std::fmt;

pub type Result<T> = std::result::Result<T, BlossomError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlossomError {
    InvalidHex,
    InvalidLength { expected: usize, actual: usize },
    MissingSecretKey,
    SignatureError,
    InvalidPublicKey,
    InvalidSecretKey,
    UnknownSender,
    EmptyEpochChain,
    InvalidEpochNonce,
}

impl fmt::Display for BlossomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex => write!(f, "invalid hex"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected}, got {actual}")
            }
            Self::MissingSecretKey => write!(f, "missing secret key"),
            Self::SignatureError => write!(f, "signature verification failed"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSecretKey => write!(f, "invalid secret key"),
            Self::UnknownSender => write!(f, "unknown sender"),
            Self::EmptyEpochChain => write!(f, "empty epoch chain"),
            Self::InvalidEpochNonce => write!(f, "invalid epoch nonce"),
        }
    }
}

impl std::error::Error for BlossomError {}
