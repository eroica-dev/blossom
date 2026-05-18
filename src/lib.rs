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
pub mod overlay;
pub mod register;
pub mod runtime;
pub mod service_client;
pub mod state;
pub mod tcp;
pub mod wire;

pub use address_book::{AddressBook, Service, ServiceKind};
pub use algorithm::{QUORUM_SIZE, SUPERMAJORITY};
pub use block::{
    BLOCK_APPLICATION_STATE_MAX_BYTES, BLOCK_APPLICATION_STATE_SOFT_LIMIT_BYTES, Block,
    BlockApplicationState, BlockBody, Transaction,
};
pub use block_store::{BlockHandle, BlockIndex, BlockRecord};
pub use blossom::*;
pub use crypto::{Keypair, PubKey, SecKey, SecretSigner, Signature, verify_batch};
pub use error::{BlossomError, Result};
pub use harness::{MockBlockService, SimulatedCluster, SimulatedNode, signed_block};
pub use hash::{DoHash, HashType};
pub use indextreemap::{IndexTreeMap, SharedIndexTreeMap};
pub use local_block::LocalBlock;
pub use messages::{MSGKey, Msg};
pub use node::{NodeIdentity, NodeType};
pub use nonce::Nonce;
pub use overlay::{BroadcastReceipt, BroadcastReport, FanOutStrategy, OverlayRuntime};
pub use register::{MessageMatrix, QuorumQueue, Status};
pub use runtime::{
    AcceptedBlock, EpochTarget, MessageReceipt, NodeRuntime, NodeStatus, PeerApplicationState,
    RuntimeConfig, RuntimeMode, TrustMode, genesis_epoch,
};
pub use service_client::TcpServiceClient;
pub use state::{
    DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES, DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER,
    Epoch, EpochBody, EpochChain, EpochNonce, LocalState, MAX_PENDING_RAW_DISPATCH_BYTES_ENV,
    MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER_ENV, PendingDispatch, TempConsensus, TempQuorum,
    configured_max_pending_raw_dispatch_bytes,
    configured_max_pending_raw_dispatch_bytes_per_sender,
};
pub use tcp::{
    TcpConnection, TcpNode, send_wire_frame, send_wire_request, send_wire_request_raw_response,
};
pub use wire::{
    AddressBookUpdate, EncodedFrame, FRAME_PREFIX_BYTES, HOT_WIRE_CODEC_ENV, HotDispatch,
    NodeHealth, WireRequest, WireRequestFrame, WireResponse, configured_max_frame_size,
    decode_wire_request_frame, decode_wire_request_payload, decode_wire_response_payload,
    encoded_len, framed_len, hot_dispatch_response_to_request_frame, hot_wire_codec_enabled,
    hot_wire_request_framed_len, hot_wire_response_framed_len, read_encoded_frame, read_frame,
    read_wire_request, read_wire_request_frame, read_wire_request_frame_optional,
    read_wire_response, wire_request_framed_len, wire_response_framed_len, write_encoded_frame,
    write_frame, write_wire_request, write_wire_response,
};
