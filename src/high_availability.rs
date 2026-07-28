//! Trusted, fixed-membership high-availability consensus for 2–7 nodes.
//!
//! This module deliberately does not reuse Blossom's hierarchical verified
//! quorum implementation. HA membership is small and fixed, so round state is
//! represented by seven slots and `u8` masks. The threat model is authenticated
//! trusted peers with crash, delay, reordering, and partition faults.
//!
//! The parent module owns shared runtime and durable-state types. Focused child
//! modules own parameters, protocol records, round transitions, membership,
//! status/recovery views, transport, and durable encoding. Public records are
//! re-exported here to preserve the original API surface.

#![warn(missing_docs)]

use std::array;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use borsh::{BorshDeserialize, BorshSerialize};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

use crate::address_book::Service;
use crate::block::Block;
use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{HashType, ProtocolHasher};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::telemetry::{TelemetryEvent, TelemetryEventKind, TelemetryHandle};
use crate::wire::{read_frame, read_frame_optional, write_frame};
use crate::{
    BlossomLogStore, BlossomLogStoreConfig, BlossomLogStoreIdentity, BlossomLogTransaction,
};

const HA_METADATA_TABLE: &str = "ha_metadata_v1";
const HA_EPOCHS_TABLE: &str = "ha_epochs_v1";
const HA_MEMBERSHIP_CHANGES_TABLE: &str = "ha_membership_changes_v1";
const HA_AMENDMENTS_TABLE: &str = "ha_amendments_v1";
const HA_RUNTIME_STATE_KEY: &[u8] = b"state";
const HA_RUNTIME_STATE_FORMAT_VERSION: u16 = 1;

/// Minimum supported fixed HA membership.
pub const MIN_HA_NODES: usize = 2;
/// Maximum supported fixed HA membership.
pub const MAX_HA_NODES: usize = 7;
/// Default number of successors before a logical epoch becomes sealed.
pub const DEFAULT_MUTABLE_EPOCH_DEPTH: u32 = 6;
/// Default consecutive missed epochs before a member becomes unresponsive.
pub const DEFAULT_UNRESPONSIVE_EPOCH_DEPTH: u32 = 6;
/// Environment variable for the mutable-epoch depth.
pub const BLOSSOM_MUTABLE_EPOCH_DEPTH_ENV: &str = "BLOSSOM_MUTABLE_EPOCH_DEPTH";
/// Environment variable for the unresponsive-member depth.
pub const BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH_ENV: &str = "BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH";
/// Environment variable containing the hexadecimal HA transport key.
pub const BLOSSOM_HA_TRANSPORT_KEY_ENV: &str = "BLOSSOM_HA_TRANSPORT_KEY";
/// Size of the shared HA transport key in bytes.
pub const HA_TRANSPORT_KEY_BYTES: usize = 32;
/// Default deadline for establishing an HA TCP connection.
pub const DEFAULT_HA_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Default deadline for one authenticated HA request.
pub const DEFAULT_HA_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Default idle deadline for an authenticated HA connection.
pub const DEFAULT_HA_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default server-side authenticated connection limit.
pub const DEFAULT_HA_MAX_CONNECTIONS: usize = 128;

const HA_PARAMETERS_HASH_DOMAIN: &[u8] = b"blossom/high-availability/parameters/v1";
const HA_MEMBERSHIP_HASH_DOMAIN: &[u8] = b"blossom/high-availability/fixed-membership/v1";
const HA_CANDIDATE_HASH_DOMAIN: &[u8] = b"blossom/high-availability/candidate/v1";
const HA_EPOCH_HASH_DOMAIN: &[u8] = b"blossom/high-availability/epoch/v1";
const HA_AMENDMENT_HASH_DOMAIN: &[u8] = b"blossom/high-availability/amendment/v1";
const HA_REVISION_HASH_DOMAIN: &[u8] = b"blossom/high-availability/revision/v1";
const HA_HISTORY_ACCUMULATOR_DOMAIN: &[u8] = b"blossom/high-availability/history-accumulator/v1";
const HA_HISTORY_CHECKPOINT_DOMAIN: &[u8] = b"blossom/high-availability/history-checkpoint/v1";
const HA_MEMBERSHIP_PROPOSAL_HASH_DOMAIN: &[u8] =
    b"blossom/high-availability/membership-proposal/v1";
const HA_AMENDMENT_RECORD_PREFIX: &[u8; 16] = b"BLOSSOM-HA-AMND1";
const HA_TRANSPORT_VERSION: u16 = 1;
const HA_TRANSPORT_HELLO_DOMAIN: &[u8] = b"blossom/high-availability/transport/hello/v1";
const HA_TRANSPORT_CHALLENGE_DOMAIN: &[u8] = b"blossom/high-availability/transport/challenge/v1";
const HA_TRANSPORT_SESSION_DOMAIN: &[u8] = b"blossom/high-availability/transport/session/v1";
const HA_TRANSPORT_SESSION_ID_DOMAIN: &[u8] = b"blossom/high-availability/transport/session-id/v1";
const HA_TRANSPORT_REQUEST_DOMAIN: &[u8] = b"blossom/high-availability/transport/request/v1";
const HA_TRANSPORT_RESPONSE_DOMAIN: &[u8] = b"blossom/high-availability/transport/response/v1";

/// Current HA parameter codec version.
pub const HIGH_AVAILABILITY_PARAMETERS_VERSION: u16 = 1;
/// Current recovery-snapshot codec version.
pub const HIGH_AVAILABILITY_RECOVERY_SNAPSHOT_VERSION: u16 = 2;
/// Current certified history-checkpoint codec version.
pub const HIGH_AVAILABILITY_HISTORY_CHECKPOINT_VERSION: u16 = 1;

type HaHmacSha256 = Hmac<Sha256>;

mod durable;
mod engine;
mod membership;
mod parameters;
mod protocol;
mod rounds;
mod status;
mod transport;

pub use parameters::*;
pub use protocol::*;
pub use status::*;
pub use transport::*;

use parameters::low_bits;
#[cfg(test)]
use protocol::masked_hashes;
use protocol::{decode_amendment_transaction, encode_amendment_transaction};
use status::accumulate_history;
#[cfg(test)]
use transport::{
    HaAuthenticatedConnection, HaAuthenticatedRequest, HaAuthenticatedRequestBody,
    HaAuthenticatedResponse, HaTransportContext, ha_transport_mac, verify_ha_transport_mac,
};

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
struct HighAvailabilityRuntimeState {
    group_id: ConsensusGroupId,
    self_slot: HaMemberSlot,
    members: HaMemberSlots,
    membership_generation: u64,
    parameters: HighAvailabilityParameters,
    checkpoint: Option<HaHistoryCheckpoint>,
    epochs: Vec<HaEpoch>,
    round: HaRoundState,
    presence: HaPresenceTracker,
    membership_vote_lock: Option<HashType>,
    membership_votes: [Option<HashType>; MAX_HA_NODES],
    membership_changes: Vec<HaMembershipCertificate>,
    amendments: Vec<AmendmentRecord>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct HaDurableMetadata {
    format_version: u16,
    group_id: ConsensusGroupId,
    self_slot: HaMemberSlot,
    members: HaMemberSlots,
    membership_generation: u64,
    parameters: HighAvailabilityParameters,
    checkpoint: Option<HaHistoryCheckpoint>,
    round: HaRoundState,
    presence: HaPresenceTracker,
    membership_vote_lock: Option<HashType>,
    membership_votes: [Option<HashType>; MAX_HA_NODES],
}

impl From<&HighAvailabilityRuntimeState> for HaDurableMetadata {
    fn from(state: &HighAvailabilityRuntimeState) -> Self {
        Self {
            format_version: HA_RUNTIME_STATE_FORMAT_VERSION,
            group_id: state.group_id,
            self_slot: state.self_slot,
            members: state.members.clone(),
            membership_generation: state.membership_generation,
            parameters: state.parameters,
            checkpoint: state.checkpoint.clone(),
            round: state.round.clone(),
            presence: state.presence.clone(),
            membership_vote_lock: state.membership_vote_lock,
            membership_votes: state.membership_votes,
        }
    }
}

#[derive(Clone)]
struct HaDurableStore {
    store: BlossomLogStore,
    cached: Arc<StdMutex<Option<HaDurableCache>>>,
    #[cfg(test)]
    test_fault: Option<Arc<std::sync::atomic::AtomicU8>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct HaSequenceSummary {
    len: usize,
    first_hash: Option<HashType>,
    last_hash: Option<HashType>,
}

struct HaDurableCache {
    metadata: HaDurableMetadata,
    checkpoint_bytes: Vec<u8>,
    epochs: HaSequenceSummary,
    membership_changes: HaSequenceSummary,
    amendments: HaSequenceSummary,
}

/// Durable trusted HA runtime.
///
/// Every mutating method commits immediate-durability state before returning.
/// In particular, `confirm()` persists the one-candidate lock before the
/// returned message may be put on the network.
pub struct HighAvailabilityRuntime {
    store: Option<HaDurableStore>,
    state: HighAvailabilityRuntimeState,
    telemetry: TelemetryHandle,
}

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn ha_strict_majorities_intersect() {
        let member_count: u8 = kani::any();
        kani::assume(member_count >= MIN_HA_NODES as u8);
        kani::assume(member_count <= MAX_HA_NODES as u8);
        let active_mask = low_bits(member_count);
        let left: u8 = kani::any();
        let right: u8 = kani::any();
        kani::assume(left & !active_mask == 0);
        kani::assume(right & !active_mask == 0);
        let required = high_availability_majority(member_count as usize);
        kani::assume(left.count_ones() as usize >= required);
        kani::assume(right.count_ones() as usize >= required);

        assert_ne!(left & right, 0);
    }
}
