//! Blossom consensus protocol.
//!
//! This crate is a focused extraction of the Blossom protocol logic from Eden.
//! It keeps the protocol messages, quorum selection, consensus state, runtime
//! service registry, and block-intake primitives needed to stand up a node
//! without carrying the rest of Eden's database or actor stack.

pub mod address_book;
pub mod algorithm;
pub mod block;
pub mod block_store;
pub mod blossom;
pub mod crypto;
pub mod error;
pub mod harness;
pub mod hash;
pub mod local_block;
pub mod messages;
pub mod node;
pub mod nonce;
pub mod register;
pub mod runtime;
pub mod service_client;
pub mod state;
pub mod tcp;
pub mod wire;

pub use address_book::{AddressBook, Service, ServiceKind};
pub use algorithm::{QUORUM_SIZE, SUPERMAJORITY};
pub use block::{Block, BlockBody, Transaction};
pub use block_store::{BlockHandle, BlockIndex, BlockRecord};
pub use blossom::*;
pub use crypto::{Keypair, PubKey, SecKey, SecretSigner, Signature};
pub use error::{BlossomError, Result};
pub use harness::{MockBlockService, SimulatedCluster, SimulatedNode, signed_block};
pub use hash::{DoHash, HashType};
pub use indextreemap::IndexTreeMap;
pub use local_block::LocalBlock;
pub use messages::{MSGKey, Msg};
pub use node::{NodeIdentity, NodeType};
pub use nonce::Nonce;
pub use register::{MessageMatrix, QuorumQueue, Status};
pub use runtime::{
    AcceptedBlock, EpochTarget, MessageReceipt, NodeRuntime, NodeStatus, RuntimeConfig,
    genesis_epoch,
};
pub use service_client::TcpServiceClient;
pub use state::{Epoch, EpochBody, EpochChain, EpochNonce, LocalState, TempConsensus, TempQuorum};
pub use tcp::{TcpNode, send_wire_request};
pub use wire::{
    AddressBookUpdate, NodeHealth, WireRequest, WireResponse, configured_max_frame_size,
    encoded_len, framed_len, read_frame, write_frame,
};
