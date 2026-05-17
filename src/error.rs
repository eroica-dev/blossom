use std::fmt;

pub type Result<T> = std::result::Result<T, BlossomError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlossomError {
    InvalidHex,
    InvalidLength {
        expected: usize,
        actual: usize,
    },
    MissingSecretKey,
    SignatureError,
    InvalidPublicKey,
    InvalidSecretKey,
    UnknownSender,
    UnknownService(String),
    EmptyEpochChain,
    InvalidEpochNonce,
    InvalidBlockHash,
    InvalidBlockLastEpoch,
    InvalidBlockNonce {
        expected: crate::nonce::Nonce,
        actual: crate::nonce::Nonce,
    },
    DuplicateBlock,
    BlockQueueFull,
    ExternalService(String),
    Io(String),
    InvalidFrameSize(usize),
    WireProtocol(String),
    FailedConsensus,
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
            Self::UnknownService(kind) => write!(f, "unknown service {kind}"),
            Self::EmptyEpochChain => write!(f, "empty epoch chain"),
            Self::InvalidEpochNonce => write!(f, "invalid epoch nonce"),
            Self::InvalidBlockHash => write!(f, "invalid block hash"),
            Self::InvalidBlockLastEpoch => write!(f, "invalid block last epoch"),
            Self::InvalidBlockNonce { expected, actual } => {
                write!(f, "invalid block nonce: expected {expected}, got {actual}")
            }
            Self::DuplicateBlock => write!(f, "duplicate block for nonce"),
            Self::BlockQueueFull => write!(f, "block queue is full"),
            Self::ExternalService(message) => write!(f, "external service error: {message}"),
            Self::Io(message) => write!(f, "io error: {message}"),
            Self::InvalidFrameSize(size) => write!(f, "invalid frame size: {size} bytes"),
            Self::WireProtocol(message) => write!(f, "wire protocol error: {message}"),
            Self::FailedConsensus => write!(f, "failed consensus"),
        }
    }
}

impl std::error::Error for BlossomError {}
