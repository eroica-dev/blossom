//! Blossom consensus protocol.
//!
//! This crate is a focused extraction of the Blossom protocol logic from Eden.
//! It keeps the protocol messages, quorum selection, consensus state, and the
//! small cryptographic/data primitives needed to use them without the service,
//! API, database, or actor runtime layers.

pub mod algorithm;
pub mod block;
pub mod blossom;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod messages;
pub mod node;
pub mod nonce;
pub mod register;
pub mod state;

pub use algorithm::{QUORUM_SIZE, SUPERMAJORITY};
pub use block::{Block, BlockBody, Transaction};
pub use blossom::*;
pub use crypto::{Keypair, PubKey, SecKey, Signature};
pub use error::{BlossomError, Result};
pub use hash::{DoHash, HashType};
pub use messages::{MSGKey, Msg};
pub use node::{NodeIdentity, NodeType};
pub use nonce::Nonce;
pub use register::{MessageMatrix, QuorumQueue, Status};
pub use state::{Epoch, EpochBody, EpochChain, EpochNonce, LocalState, TempConsensus, TempQuorum};
