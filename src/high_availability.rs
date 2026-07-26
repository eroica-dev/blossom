//! Trusted, fixed-membership high-availability consensus for 2–7 nodes.
//!
//! This module deliberately does not reuse Blossom's hierarchical verified
//! quorum implementation. HA membership is small and fixed, so round state is
//! represented by seven slots and `u8` masks. The threat model is authenticated
//! trusted peers with crash, delay, reordering, and partition faults.

use std::array;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use redb::{Database, Durability, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

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

const HA_RUNTIME_STATE_TABLE: TableDefinition<u8, &[u8]> =
    TableDefinition::new("ha_runtime_state_v1");
const HA_RUNTIME_STATE_KEY: u8 = 1;

pub const MIN_HA_NODES: usize = 2;
pub const MAX_HA_NODES: usize = 7;
pub const DEFAULT_MUTABLE_EPOCH_DEPTH: u32 = 6;
pub const DEFAULT_UNRESPONSIVE_EPOCH_DEPTH: u32 = 6;
pub const BLOSSOM_MUTABLE_EPOCH_DEPTH_ENV: &str = "BLOSSOM_MUTABLE_EPOCH_DEPTH";
pub const BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH_ENV: &str = "BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH";
pub const BLOSSOM_HA_TRANSPORT_KEY_ENV: &str = "BLOSSOM_HA_TRANSPORT_KEY";
pub const HA_TRANSPORT_KEY_BYTES: usize = 32;

const HA_PARAMETERS_HASH_DOMAIN: &[u8] = b"blossom/high-availability/parameters/v1";
const HA_MEMBERSHIP_HASH_DOMAIN: &[u8] = b"blossom/high-availability/fixed-membership/v1";
const HA_CANDIDATE_HASH_DOMAIN: &[u8] = b"blossom/high-availability/candidate/v1";
const HA_EPOCH_HASH_DOMAIN: &[u8] = b"blossom/high-availability/epoch/v1";
const HA_AMENDMENT_HASH_DOMAIN: &[u8] = b"blossom/high-availability/amendment/v1";
const HA_REVISION_HASH_DOMAIN: &[u8] = b"blossom/high-availability/revision/v1";
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

pub const HIGH_AVAILABILITY_PARAMETERS_VERSION: u16 = 1;
pub const HIGH_AVAILABILITY_RECOVERY_SNAPSHOT_VERSION: u16 = 1;

type HaHmacSha256 = Hmac<Sha256>;

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
    PartialOrd,
    Ord,
    Hash,
)]
pub struct ClientId(pub [u8; 16]);

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
    PartialOrd,
    Ord,
    Hash,
)]
pub struct ClientEpoch(pub u64);

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
    PartialOrd,
    Ord,
    Hash,
)]
pub struct CommandIdentity {
    pub client_id: ClientId,
    pub client_epoch: ClientEpoch,
    pub sequence: u64,
}

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
    PartialOrd,
    Ord,
    Hash,
    Default,
)]
pub struct Watermark {
    pub position: u64,
}

/// Shared secret used to authenticate and integrity-protect the isolated HA
/// transport profile.
///
/// HA protocol messages remain unsigned. The transport key instead creates a
/// mutually authenticated session for fixed genesis members and authenticates
/// every request and response frame. Operators should still use TLS when
/// confidentiality is required.
#[derive(Clone, PartialEq, Eq)]
pub struct HaTransportKey([u8; HA_TRANSPORT_KEY_BYTES]);

impl HaTransportKey {
    pub fn new(bytes: [u8; HA_TRANSPORT_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let mut bytes = [0u8; HA_TRANSPORT_KEY_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).map_err(|_| BlossomError::InvalidHex)?;
        let actual = bytes.len();
        let bytes: [u8; HA_TRANSPORT_KEY_BYTES] =
            bytes.try_into().map_err(|_| BlossomError::InvalidLength {
                expected: HA_TRANSPORT_KEY_BYTES,
                actual,
            })?;
        Ok(Self(bytes))
    }

    pub fn from_environment() -> Result<Self> {
        let value = env::var(BLOSSOM_HA_TRANSPORT_KEY_ENV).map_err(|_| {
            BlossomError::InvalidConfiguration(format!(
                "{BLOSSOM_HA_TRANSPORT_KEY_ENV} must contain a 32-byte hex key"
            ))
        })?;
        Self::from_hex(&value)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn as_bytes(&self) -> &[u8; HA_TRANSPORT_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for HaTransportKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HaTransportKey([REDACTED])")
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportHelloBody {
    version: u16,
    group_id: ConsensusGroupId,
    fixed_membership_hash: HashType,
    parameters_hash: HashType,
    client: PubKey,
    server: PubKey,
    client_nonce: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportHello {
    body: HaTransportHelloBody,
    mac: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportChallengeBody {
    hello: HaTransportHelloBody,
    server_nonce: [u8; HA_TRANSPORT_KEY_BYTES],
    session_id: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportChallenge {
    body: HaTransportChallengeBody,
    mac: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct HaTransportSessionSeed {
    hello: HaTransportHelloBody,
    server_nonce: [u8; HA_TRANSPORT_KEY_BYTES],
}

/// Request envelope for the isolated HA transport.
///
/// This deliberately does not reuse [`crate::wire::WireRequest`], so enabling
/// HA cannot change the discriminants or compatibility profile of Blossom's
/// existing verified and trusted wire protocol.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum HaWireRequest {
    Message(Box<HaMessage>),
    Status,
    Health,
}

/// Response envelope for the isolated HA transport.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum HaWireResponse {
    Receipt(HaWireReceipt),
    Status(Box<HaNodeStatus>),
    Error(String),
}

impl HaWireResponse {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Receipt(_) => "high_availability_receipt",
            Self::Status(_) => "high_availability_status",
            Self::Error(_) => "error",
        }
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
struct HaAuthenticatedRequestBody {
    session_id: [u8; HA_TRANSPORT_KEY_BYTES],
    sequence: u64,
    request: HaWireRequest,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
struct HaAuthenticatedRequest {
    body: HaAuthenticatedRequestBody,
    mac: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
struct HaAuthenticatedResponseBody {
    session_id: [u8; HA_TRANSPORT_KEY_BYTES],
    sequence: u64,
    response: HaWireResponse,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
struct HaAuthenticatedResponse {
    body: HaAuthenticatedResponseBody,
    mac: [u8; HA_TRANSPORT_KEY_BYTES],
}

#[derive(Clone)]
struct HaTransportContext {
    local_key: PubKey,
    group_id: ConsensusGroupId,
    fixed_membership_hash: HashType,
    parameters_hash: HashType,
    members: BTreeSet<PubKey>,
}

impl HaTransportContext {
    fn from_runtime(runtime: &HighAvailabilityRuntime) -> Self {
        let members = (0..runtime.members().member_count())
            .filter_map(|index| runtime.members().member(HaMemberSlot(index as u8)))
            .map(NodeIdentity::public_key)
            .collect();
        let local_key = runtime
            .members()
            .member(runtime.self_slot())
            .expect("validated HA self slot")
            .public_key();
        Self {
            local_key,
            group_id: runtime.state.group_id,
            fixed_membership_hash: runtime.members().fixed_identity_hash(),
            parameters_hash: runtime.parameters_hash(),
            members,
        }
    }

    fn validate_peer(&self, peer: PubKey) -> Result<()> {
        if !self.members.contains(&peer) || peer == self.local_key {
            return Err(BlossomError::UnknownSender);
        }
        Ok(())
    }
}

fn ha_transport_mac<T: BorshSerialize>(
    key: &[u8],
    domain: &[u8],
    value: &T,
) -> Result<[u8; HA_TRANSPORT_KEY_BYTES]> {
    let encoded = borsh::to_vec(value).map_err(|error| {
        BlossomError::WireProtocol(format!("encode HA transport transcript: {error}"))
    })?;
    let mut mac = HaHmacSha256::new_from_slice(key)
        .map_err(|_| BlossomError::InvalidConfiguration("invalid HA transport key".to_string()))?;
    mac.update(domain);
    mac.update(&(encoded.len() as u64).to_le_bytes());
    mac.update(&encoded);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_ha_transport_mac<T: BorshSerialize>(
    key: &[u8],
    domain: &[u8],
    value: &T,
    expected: &[u8; HA_TRANSPORT_KEY_BYTES],
) -> Result<()> {
    let encoded = borsh::to_vec(value).map_err(|error| {
        BlossomError::WireProtocol(format!("encode HA transport transcript: {error}"))
    })?;
    let mut mac = HaHmacSha256::new_from_slice(key)
        .map_err(|_| BlossomError::InvalidConfiguration("invalid HA transport key".to_string()))?;
    mac.update(domain);
    mac.update(&(encoded.len() as u64).to_le_bytes());
    mac.update(&encoded);
    mac.verify_slice(expected)
        .map_err(|_| BlossomError::WireProtocol("HA transport authentication failed".to_string()))
}

fn derive_ha_session_key(
    key: &HaTransportKey,
    challenge: &HaTransportChallengeBody,
) -> Result<[u8; HA_TRANSPORT_KEY_BYTES]> {
    ha_transport_mac(key.as_bytes(), HA_TRANSPORT_SESSION_DOMAIN, challenge)
}

/// Returns the strict-majority threshold for an HA active membership.
pub const fn high_availability_majority(member_count: usize) -> usize {
    (member_count / 2) + 1
}

/// Number of crash/inactive members tolerated without reconfiguration.
pub const fn high_availability_fault_tolerance(member_count: usize) -> usize {
    member_count.saturating_sub(high_availability_majority(member_count))
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct HighAvailabilityParameters {
    pub version: u16,
    pub mutable_epoch_depth: u32,
    pub unresponsive_epoch_depth: u32,
}

impl HighAvailabilityParameters {
    pub const fn new(mutable_epoch_depth: u32, unresponsive_epoch_depth: u32) -> Self {
        Self {
            version: HIGH_AVAILABILITY_PARAMETERS_VERSION,
            mutable_epoch_depth,
            unresponsive_epoch_depth,
        }
    }

    pub fn validate(self) -> Result<()> {
        if self.version != HIGH_AVAILABILITY_PARAMETERS_VERSION {
            return Err(BlossomError::InvalidConfiguration(format!(
                "unsupported high-availability parameters version {}",
                self.version
            )));
        }
        if self.mutable_epoch_depth == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "mutable epoch depth must be positive".to_string(),
            ));
        }
        if self.unresponsive_epoch_depth == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "unresponsive epoch depth must be positive".to_string(),
            ));
        }
        Ok(())
    }

    pub fn resolve_startup(
        mutable_cli: Option<&str>,
        mutable_environment: Option<&str>,
        unresponsive_cli: Option<&str>,
        unresponsive_environment: Option<&str>,
    ) -> Result<Self> {
        let mutable_epoch_depth = parse_depth(
            BLOSSOM_MUTABLE_EPOCH_DEPTH_ENV,
            mutable_cli.or(mutable_environment),
            DEFAULT_MUTABLE_EPOCH_DEPTH,
        )?;
        let unresponsive_epoch_depth = parse_depth(
            BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH_ENV,
            unresponsive_cli.or(unresponsive_environment),
            DEFAULT_UNRESPONSIVE_EPOCH_DEPTH,
        )?;
        let parameters = Self::new(mutable_epoch_depth, unresponsive_epoch_depth);
        parameters.validate()?;
        Ok(parameters)
    }

    pub fn from_environment() -> Result<Self> {
        Self::resolve_startup(
            None,
            optional_environment(BLOSSOM_MUTABLE_EPOCH_DEPTH_ENV)?.as_deref(),
            None,
            optional_environment(BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH_ENV)?.as_deref(),
        )
    }

    pub fn hash(self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_PARAMETERS_HASH_DOMAIN);
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.mutable_epoch_depth.to_le_bytes());
        hasher.update(self.unresponsive_epoch_depth.to_le_bytes());
        hasher.finalize()
    }
}

impl Default for HighAvailabilityParameters {
    fn default() -> Self {
        Self::new(
            DEFAULT_MUTABLE_EPOCH_DEPTH,
            DEFAULT_UNRESPONSIVE_EPOCH_DEPTH,
        )
    }
}

fn optional_environment(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(BlossomError::InvalidConfiguration(format!(
            "read {name}: {error}"
        ))),
    }
}

fn parse_depth(name: &str, value: Option<&str>, default: u32) -> Result<u32> {
    let value = match value {
        Some(value) => value.parse::<u32>().map_err(|_| {
            BlossomError::InvalidConfiguration(format!(
                "{name} must be a positive u32, got {value:?}"
            ))
        })?,
        None => default,
    };
    if value == 0 {
        return Err(BlossomError::InvalidConfiguration(format!(
            "{name} must be positive"
        )));
    }
    Ok(value)
}

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
    PartialOrd,
    Ord,
    Hash,
)]
pub struct HaMemberSlot(pub u8);

impl HaMemberSlot {
    pub fn index(self) -> usize {
        usize::from(self.0)
    }

    fn bit(self) -> Result<u8> {
        if self.index() >= MAX_HA_NODES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "HA member slot {} exceeds maximum slot {}",
                self.0,
                MAX_HA_NODES - 1
            )));
        }
        Ok(1u8 << self.0)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaMemberSlots {
    member_count: u8,
    active_mask: u8,
    fixed_identity_hash: HashType,
    members: [Option<NodeIdentity>; MAX_HA_NODES],
}

impl HaMemberSlots {
    pub fn new(mut members: Vec<NodeIdentity>) -> Result<Self> {
        if !(MIN_HA_NODES..=MAX_HA_NODES).contains(&members.len()) {
            return Err(BlossomError::InvalidHighAvailabilityNodeCount(
                members.len(),
            ));
        }
        members.sort_by_key(NodeIdentity::public_key);
        if members
            .windows(2)
            .any(|pair| pair[0].public_key() == pair[1].public_key())
        {
            return Err(BlossomError::InvalidConfiguration(
                "high-availability membership contains duplicate public keys".to_string(),
            ));
        }
        let member_count = u8::try_from(members.len()).expect("HA membership is at most seven");
        let active_mask = low_bits(member_count);
        let mut slots = array::from_fn(|_| None);
        for (index, member) in members.into_iter().enumerate() {
            slots[index] = Some(member);
        }
        let result = Self {
            member_count,
            active_mask,
            fixed_identity_hash: Self::compute_fixed_identity_hash(member_count, &slots),
            members: slots,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        let member_count = usize::from(self.member_count);
        if !(MIN_HA_NODES..=MAX_HA_NODES).contains(&member_count) {
            return Err(BlossomError::InvalidHighAvailabilityNodeCount(member_count));
        }
        if self.active_mask & !low_bits(self.member_count) != 0 {
            return Err(BlossomError::InvalidConfiguration(
                "HA active mask references an unassigned slot".to_string(),
            ));
        }
        if self.fixed_identity_hash
            != Self::compute_fixed_identity_hash(self.member_count, &self.members)
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA fixed membership hash does not match its public-key slots".to_string(),
            ));
        }
        if self.active_count() < MIN_HA_NODES {
            return Err(BlossomError::InvalidConfiguration(
                "HA requires at least two active members".to_string(),
            ));
        }
        for index in 0..MAX_HA_NODES {
            let should_exist = index < member_count;
            if self.members[index].is_some() != should_exist {
                return Err(BlossomError::InvalidConfiguration(
                    "HA membership slots must be densely assigned".to_string(),
                ));
            }
            if index > 0
                && index < member_count
                && self.members[index - 1]
                    .as_ref()
                    .expect("validated dense member")
                    .public_key()
                    >= self.members[index]
                        .as_ref()
                        .expect("validated dense member")
                        .public_key()
            {
                return Err(BlossomError::InvalidConfiguration(
                    "HA membership slots must be ordered by public key".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn member_count(&self) -> usize {
        usize::from(self.member_count)
    }

    pub fn active_mask(&self) -> u8 {
        self.active_mask
    }

    pub fn active_count(&self) -> usize {
        (self.active_mask & low_bits(self.member_count)).count_ones() as usize
    }

    pub fn majority(&self) -> usize {
        high_availability_majority(self.active_count())
    }

    pub fn fixed_identity_hash(&self) -> HashType {
        self.fixed_identity_hash
    }

    fn compute_fixed_identity_hash(
        member_count: u8,
        members: &[Option<NodeIdentity>; MAX_HA_NODES],
    ) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_MEMBERSHIP_HASH_DOMAIN);
        hasher.update([member_count]);
        for member in members.iter().take(usize::from(member_count)) {
            hasher.update(
                member
                    .as_ref()
                    .expect("validated HA membership is densely assigned")
                    .public_key()
                    .as_ref(),
            );
        }
        hasher.finalize()
    }

    pub fn member(&self, slot: HaMemberSlot) -> Option<&NodeIdentity> {
        self.members.get(slot.index()).and_then(Option::as_ref)
    }

    pub fn slot_for(&self, public_key: &PubKey) -> Option<HaMemberSlot> {
        self.members
            .iter()
            .take(self.member_count())
            .position(|member| {
                member
                    .as_ref()
                    .is_some_and(|member| member.public_key() == *public_key)
            })
            .map(|index| HaMemberSlot(index as u8))
    }

    fn same_fixed_identities(&self, other: &Self) -> bool {
        self.member_count == other.member_count
            && (0..self.member_count()).all(|index| {
                self.members[index]
                    .as_ref()
                    .zip(other.members[index].as_ref())
                    .is_some_and(|(left, right)| left.public_key() == right.public_key())
            })
    }

    fn public_only(&self) -> Self {
        let mut result = self.clone();
        for member in result.members.iter_mut().flatten() {
            member.secret_key = None;
        }
        result
    }

    pub fn is_active(&self, slot: HaMemberSlot) -> bool {
        slot.bit()
            .is_ok_and(|bit| self.active_mask & bit != 0 && self.member(slot).is_some())
    }

    pub fn with_suspended(&self, slot: HaMemberSlot) -> Result<Self> {
        if !self.is_active(slot) {
            return Err(BlossomError::InvalidConfiguration(
                "cannot suspend an inactive HA member".to_string(),
            ));
        }
        let next_mask = self.active_mask & !slot.bit()?;
        if next_mask.count_ones() < MIN_HA_NODES as u32 {
            return Err(BlossomError::InvalidConfiguration(
                "cannot suspend enough HA members to leave fewer than two active".to_string(),
            ));
        }
        let mut next = self.clone();
        next.active_mask = next_mask;
        next.validate()?;
        Ok(next)
    }

    pub fn with_reactivated(&self, slot: HaMemberSlot) -> Result<Self> {
        if self.member(slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        let mut next = self.clone();
        next.active_mask |= slot.bit()?;
        next.validate()?;
        Ok(next)
    }
}

fn low_bits(count: u8) -> u8 {
    ((1u16 << count) - 1) as u8
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct HaRoundId {
    pub group_id: ConsensusGroupId,
    pub fixed_membership_hash: HashType,
    pub membership_generation: u64,
    pub active_mask: u8,
    pub parameters_hash: HashType,
    pub previous_epoch_hash: HashType,
    pub previous_epoch_nonce: Nonce,
    pub nonce: Nonce,
    pub round: u8,
}

impl HaRoundId {
    pub fn validate_for(&self, members: &HaMemberSlots) -> Result<()> {
        if self.fixed_membership_hash != members.fixed_identity_hash()
            || self.active_mask != members.active_mask()
        {
            return Err(BlossomError::WireProtocol(
                "HA message fixed membership or active membership mask mismatch".to_string(),
            ));
        }
        if self.nonce != self.previous_epoch_nonce.new_next() {
            return Err(BlossomError::InvalidEpochNonce);
        }
        Ok(())
    }

    fn update_hash(&self, hasher: &mut ProtocolHasher) {
        hasher.update(self.group_id.as_ref());
        hasher.update(self.fixed_membership_hash.as_ref());
        hasher.update(self.membership_generation.to_le_bytes());
        hasher.update([self.active_mask]);
        hasher.update(self.parameters_hash.as_ref());
        hasher.update(self.previous_epoch_hash.as_ref());
        hasher.update(self.previous_epoch_nonce.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update([self.round]);
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaCandidate {
    pub included_mask: u8,
    pub presence_mask: u8,
    pub block_hashes: [HashType; MAX_HA_NODES],
    pub digest: HashType,
}

impl HaCandidate {
    fn from_round(
        round_id: HaRoundId,
        included_mask: u8,
        presence_mask: u8,
        block_hashes: [HashType; MAX_HA_NODES],
    ) -> Self {
        let digest = candidate_digest(round_id, included_mask, presence_mask, &block_hashes);
        Self {
            included_mask,
            presence_mask,
            block_hashes,
            digest,
        }
    }

    pub fn validate(&self, round_id: HaRoundId) -> Result<()> {
        if self.included_mask == 0 || self.included_mask & !round_id.active_mask != 0 {
            return Err(BlossomError::WireProtocol(
                "HA candidate mask is empty or references an inactive slot".to_string(),
            ));
        }
        if self.presence_mask & !round_id.active_mask != 0
            || self.presence_mask & self.included_mask != self.included_mask
        {
            return Err(BlossomError::WireProtocol(
                "HA candidate presence must include every block origin and only active members"
                    .to_string(),
            ));
        }
        for index in 0..MAX_HA_NODES {
            let included = self.included_mask & (1u8 << index) != 0;
            if !included && self.block_hashes[index] != HashType::default() {
                return Err(BlossomError::WireProtocol(
                    "HA candidate contains a hash outside its included mask".to_string(),
                ));
            }
        }
        if self.digest
            != candidate_digest(
                round_id,
                self.included_mask,
                self.presence_mask,
                &self.block_hashes,
            )
        {
            return Err(BlossomError::WireProtocol(
                "HA candidate digest mismatch".to_string(),
            ));
        }
        Ok(())
    }

    pub fn ordered_slots(&self) -> HaOrderedSlots {
        let mut result = HaOrderedSlots::default();
        for index in 0..MAX_HA_NODES {
            if self.included_mask & (1u8 << index) == 0 {
                continue;
            }
            let slot = index as u8;
            let mut position = result.len as usize;
            while position > 0 {
                let previous_slot = result.slots[position - 1];
                let ordering =
                    self.block_hashes[index].cmp(&self.block_hashes[usize::from(previous_slot)]);
                if ordering == Ordering::Greater
                    || (ordering == Ordering::Equal && slot >= previous_slot)
                {
                    break;
                }
                result.slots[position] = previous_slot;
                position -= 1;
            }
            result.slots[position] = slot;
            result.len += 1;
        }
        result
    }
}

fn candidate_digest(
    round_id: HaRoundId,
    included_mask: u8,
    presence_mask: u8,
    block_hashes: &[HashType; MAX_HA_NODES],
) -> HashType {
    let mut hasher = ProtocolHasher::new();
    hasher.update(HA_CANDIDATE_HASH_DOMAIN);
    round_id.update_hash(&mut hasher);
    hasher.update([included_mask]);
    hasher.update([presence_mask]);
    for (index, block_hash) in block_hashes.iter().enumerate() {
        if included_mask & (1u8 << index) != 0 {
            hasher.update([index as u8]);
            hasher.update(block_hash.as_ref());
        }
    }
    hasher.finalize()
}

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
    Default,
)]
pub struct HaOrderedSlots {
    pub len: u8,
    pub slots: [u8; MAX_HA_NODES],
}

impl HaOrderedSlots {
    pub fn as_slice(&self) -> &[u8] {
        &self.slots[..usize::from(self.len)]
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HaDispatch {
    pub round_id: HaRoundId,
    pub sender: HaMemberSlot,
    pub block_hash: HashType,
    pub block: Block,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaAcknowledge {
    pub round_id: HaRoundId,
    pub sender: HaMemberSlot,
    pub received_mask: u8,
    pub block_hashes: [HashType; MAX_HA_NODES],
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaConfirm {
    pub round_id: HaRoundId,
    pub sender: HaMemberSlot,
    pub candidate: HaCandidate,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum HaMessage {
    Handshake(HaHandshake),
    MembershipVote(HaMembershipVote),
    Dispatch(HaDispatch),
    Acknowledge(HaAcknowledge),
    Confirm(HaConfirm),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaDispatchOutcome {
    Accepted,
    Duplicate,
    Late { target_epoch: Nonce },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaFinalizedRound {
    pub round_id: HaRoundId,
    pub candidate: HaCandidate,
    pub confirmation_mask: u8,
    pub presence_mask: u8,
    pub ordered_slots: HaOrderedSlots,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HaEpoch {
    pub hash: HashType,
    pub group_id: ConsensusGroupId,
    pub fixed_membership_hash: HashType,
    pub membership_generation: u64,
    pub active_mask: u8,
    pub previous_epoch_hash: HashType,
    pub previous_epoch_nonce: Option<Nonce>,
    pub nonce: Nonce,
    pub candidate: HaCandidate,
    pub confirmation_mask: u8,
    pub presence_mask: u8,
    pub ordered_slots: HaOrderedSlots,
    pub blocks: [Option<Block>; MAX_HA_NODES],
    pub parameters: HighAvailabilityParameters,
    pub parameters_hash: HashType,
}

impl HaEpoch {
    fn from_finalized(
        finalized: HaFinalizedRound,
        blocks: &[Option<Block>; MAX_HA_NODES],
        parameters: HighAvailabilityParameters,
    ) -> Self {
        let mut epoch = Self {
            hash: HashType::default(),
            group_id: finalized.round_id.group_id,
            fixed_membership_hash: finalized.round_id.fixed_membership_hash,
            membership_generation: finalized.round_id.membership_generation,
            active_mask: finalized.round_id.active_mask,
            previous_epoch_hash: finalized.round_id.previous_epoch_hash,
            previous_epoch_nonce: Some(finalized.round_id.previous_epoch_nonce),
            nonce: finalized.round_id.nonce,
            candidate: finalized.candidate,
            confirmation_mask: finalized.confirmation_mask,
            presence_mask: finalized.presence_mask,
            ordered_slots: finalized.ordered_slots,
            blocks: array::from_fn(|index| blocks[index].clone()),
            parameters,
            parameters_hash: parameters.hash(),
        };
        epoch.hash = epoch.compute_hash();
        epoch
    }

    fn genesis(
        group_id: ConsensusGroupId,
        members: &HaMemberSlots,
        parameters: HighAvailabilityParameters,
    ) -> Self {
        let round_id = HaRoundId {
            group_id,
            fixed_membership_hash: members.fixed_identity_hash(),
            membership_generation: 0,
            active_mask: members.active_mask(),
            parameters_hash: parameters.hash(),
            previous_epoch_hash: HashType::default(),
            previous_epoch_nonce: Nonce::default(),
            nonce: Nonce::default(),
            round: 0,
        };
        let candidate =
            HaCandidate::from_round(round_id, 1, 1, [HashType::default(); MAX_HA_NODES]);
        let mut epoch = Self {
            hash: HashType::default(),
            group_id,
            fixed_membership_hash: members.fixed_identity_hash(),
            membership_generation: 0,
            active_mask: members.active_mask(),
            previous_epoch_hash: HashType::default(),
            previous_epoch_nonce: None,
            nonce: Nonce::default(),
            candidate,
            confirmation_mask: members.active_mask(),
            presence_mask: members.active_mask(),
            ordered_slots: HaOrderedSlots::default(),
            blocks: array::from_fn(|_| None),
            parameters,
            parameters_hash: parameters.hash(),
        };
        epoch.hash = epoch.compute_hash();
        epoch
    }

    pub fn compute_hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_EPOCH_HASH_DOMAIN);
        hasher.update(self.group_id.as_ref());
        hasher.update(self.fixed_membership_hash.as_ref());
        hasher.update(self.membership_generation.to_le_bytes());
        hasher.update([self.active_mask]);
        hasher.update(self.previous_epoch_hash.as_ref());
        match self.previous_epoch_nonce {
            Some(nonce) => {
                hasher.update([1]);
                hasher.update(nonce.to_le_bytes());
            }
            None => hasher.update([0]),
        }
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(self.candidate.digest.as_ref());
        hasher.update([self.presence_mask]);
        hasher.update(self.parameters_hash.as_ref());
        hasher.finalize()
    }

    pub fn ordered_blocks(&self) -> impl Iterator<Item = (HaMemberSlot, &Block)> {
        self.ordered_slots.as_slice().iter().filter_map(|slot| {
            let slot = HaMemberSlot(*slot);
            self.blocks[slot.index()]
                .as_ref()
                .map(|block| (slot, block))
        })
    }

    pub fn validate(&self, members: &HaMemberSlots) -> Result<()> {
        self.parameters.validate()?;
        if self.parameters_hash != self.parameters.hash() {
            return Err(BlossomError::InvalidConfiguration(
                "HA epoch parameters hash mismatch".to_string(),
            ));
        }
        if self.fixed_membership_hash != members.fixed_identity_hash() {
            return Err(BlossomError::InvalidConfiguration(
                "HA epoch fixed membership hash mismatch".to_string(),
            ));
        }
        if self.active_mask & !low_bits(members.member_count) != 0 {
            return Err(BlossomError::WireProtocol(
                "HA epoch active mask references an unknown member".to_string(),
            ));
        }
        if self.previous_epoch_nonce.is_some()
            && self
                .previous_epoch_nonce
                .is_none_or(|previous| previous.new_next() != self.nonce)
        {
            return Err(BlossomError::InvalidEpochNonce);
        }
        if self.hash != self.compute_hash() {
            return Err(BlossomError::InvalidBlockHash);
        }
        self.candidate.validate(HaRoundId {
            group_id: self.group_id,
            fixed_membership_hash: self.fixed_membership_hash,
            membership_generation: self.membership_generation,
            active_mask: self.active_mask,
            parameters_hash: self.parameters_hash,
            previous_epoch_hash: self.previous_epoch_hash,
            previous_epoch_nonce: self.previous_epoch_nonce.unwrap_or_default(),
            nonce: self.nonce,
            round: 0,
        })?;
        if self.confirmation_mask & !self.active_mask != 0
            || (self.confirmation_mask.count_ones() as usize)
                < high_availability_majority(self.active_mask.count_ones() as usize)
        {
            return Err(BlossomError::WireProtocol(
                "HA epoch does not carry a strict-majority confirmation certificate".to_string(),
            ));
        }
        if self.presence_mask != self.candidate.presence_mask
            || self.ordered_slots != self.candidate.ordered_slots()
        {
            return Err(BlossomError::WireProtocol(
                "HA epoch presence or fixed ordering disagrees with its candidate".to_string(),
            ));
        }
        for index in 0..MAX_HA_NODES {
            let included = self.candidate.included_mask & (1u8 << index) != 0;
            if included {
                let block = self.blocks[index].as_ref().ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "HA epoch candidate references a missing block".to_string(),
                    )
                })?;
                block.verify_unsigned_integrity_with_hash(self.candidate.block_hashes[index])?;
            } else if self.blocks[index].is_some() {
                return Err(BlossomError::WireProtocol(
                    "HA epoch stores a block outside its finalized candidate".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl HaFinalizedRound {
    pub fn hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_EPOCH_HASH_DOMAIN);
        self.round_id.update_hash(&mut hasher);
        hasher.update(self.candidate.digest.as_ref());
        hasher.update([self.presence_mask]);
        hasher.finalize()
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HaRoundState {
    pub round_id: HaRoundId,
    pub blocks: [Option<Block>; MAX_HA_NODES],
    pub block_hashes: [HashType; MAX_HA_NODES],
    pub received_mask: u8,
    /// Row `i` is the latest monotonic block-receipt mask from member `i`.
    pub acknowledgements: [u8; MAX_HA_NODES],
    pub confirmations: [Option<HashType>; MAX_HA_NODES],
    pub confirmed_candidate: Option<HashType>,
    pub finalized: Option<HaFinalizedRound>,
}

impl HaRoundState {
    pub fn new(round_id: HaRoundId, members: &HaMemberSlots) -> Result<Self> {
        members.validate()?;
        round_id.validate_for(members)?;
        Ok(Self {
            round_id,
            blocks: array::from_fn(|_| None),
            block_hashes: [HashType::default(); MAX_HA_NODES],
            received_mask: 0,
            acknowledgements: [0; MAX_HA_NODES],
            confirmations: array::from_fn(|_| None),
            confirmed_candidate: None,
            finalized: None,
        })
    }

    pub fn receive_dispatch(
        &mut self,
        members: &HaMemberSlots,
        dispatch: HaDispatch,
    ) -> Result<HaDispatchOutcome> {
        self.validate_message_scope(members, dispatch.round_id, dispatch.sender)?;
        let slot = dispatch.sender.index();
        let expected_member = members
            .member(dispatch.sender)
            .ok_or(BlossomError::UnknownSender)?;
        if dispatch.block.body.validator != expected_member.public_key() {
            return Err(BlossomError::UnknownSender);
        }
        if dispatch.block.body.last_epoch != self.round_id.previous_epoch_hash {
            return Err(BlossomError::InvalidBlockLastEpoch);
        }
        if dispatch.block.body.nonce != self.round_id.nonce {
            return Err(BlossomError::InvalidBlockNonce {
                expected: self.round_id.nonce,
                actual: dispatch.block.body.nonce,
            });
        }
        dispatch
            .block
            .verify_unsigned_integrity_with_hash(dispatch.block_hash)?;

        if let Some(existing) = &self.blocks[slot] {
            if self.block_hashes[slot] == dispatch.block_hash
                && existing.hash == dispatch.block.hash
            {
                return Ok(HaDispatchOutcome::Duplicate);
            }
            return Err(BlossomError::WireProtocol(format!(
                "HA slot {} dispatched conflicting block bytes",
                dispatch.sender.0
            )));
        }
        if self.confirmed_candidate.is_some() || self.finalized.is_some() {
            return Ok(HaDispatchOutcome::Late {
                target_epoch: self.round_id.nonce,
            });
        }
        self.blocks[slot] = Some(dispatch.block);
        self.block_hashes[slot] = dispatch.block_hash;
        self.received_mask |= dispatch.sender.bit()?;
        Ok(HaDispatchOutcome::Accepted)
    }

    pub fn acknowledge(
        &mut self,
        members: &HaMemberSlots,
        sender: HaMemberSlot,
    ) -> Result<HaAcknowledge> {
        self.validate_sender(members, sender)?;
        let acknowledgement = HaAcknowledge {
            round_id: self.round_id,
            sender,
            received_mask: self.received_mask,
            block_hashes: masked_hashes(self.received_mask, &self.block_hashes),
        };
        self.receive_acknowledgement(members, acknowledgement.clone())?;
        Ok(acknowledgement)
    }

    pub fn receive_acknowledgement(
        &mut self,
        members: &HaMemberSlots,
        acknowledgement: HaAcknowledge,
    ) -> Result<()> {
        self.validate_message_scope(members, acknowledgement.round_id, acknowledgement.sender)?;
        if acknowledgement.received_mask & !self.round_id.active_mask != 0 {
            return Err(BlossomError::WireProtocol(
                "HA acknowledgement references an inactive slot".to_string(),
            ));
        }
        for index in 0..MAX_HA_NODES {
            let bit = 1u8 << index;
            if acknowledgement.received_mask & bit != 0 {
                if self.blocks[index].is_none()
                    || acknowledgement.block_hashes[index] != self.block_hashes[index]
                {
                    return Err(BlossomError::WireProtocol(
                        "HA acknowledgement references an unknown or conflicting block".to_string(),
                    ));
                }
            } else if acknowledgement.block_hashes[index] != HashType::default() {
                return Err(BlossomError::WireProtocol(
                    "HA acknowledgement contains a hash outside its receipt mask".to_string(),
                ));
            }
        }
        let row = &mut self.acknowledgements[acknowledgement.sender.index()];
        if *row & !acknowledgement.received_mask != 0 {
            return Err(BlossomError::WireProtocol(
                "HA acknowledgement attempted to retract a receipt".to_string(),
            ));
        }
        *row = acknowledgement.received_mask;
        Ok(())
    }

    pub fn available_mask(&self, members: &HaMemberSlots) -> u8 {
        let required = members.majority();
        let mut available = 0u8;
        for block_slot in 0..MAX_HA_NODES {
            let block_bit = 1u8 << block_slot;
            if self.received_mask & block_bit == 0 {
                continue;
            }
            let acknowledgers = (0..MAX_HA_NODES)
                .filter(|sender| self.round_id.active_mask & (1u8 << sender) != 0)
                .filter(|sender| self.acknowledgements[*sender] & block_bit != 0)
                .count();
            if acknowledgers >= required {
                available |= block_bit;
            }
        }
        available
    }

    pub fn confirm(&mut self, members: &HaMemberSlots, sender: HaMemberSlot) -> Result<HaConfirm> {
        self.validate_sender(members, sender)?;
        let sender_index = sender.index();
        if self.received_mask == 0
            || self.available_mask(members) & self.received_mask != self.received_mask
        {
            return Err(BlossomError::FailedConsensus);
        }
        let candidate = HaCandidate::from_round(
            self.round_id,
            self.received_mask,
            self.certified_presence_candidate_mask(members),
            masked_hashes(self.received_mask, &self.block_hashes),
        );
        if let Some(existing) = self.confirmations[sender_index] {
            if existing != candidate.digest || self.confirmed_candidate != Some(candidate.digest) {
                return Err(BlossomError::WireProtocol(
                    "HA durable confirmation lock does not match recoverable round state"
                        .to_string(),
                ));
            }
            return Ok(HaConfirm {
                round_id: self.round_id,
                sender,
                candidate,
            });
        }
        let confirmation = HaConfirm {
            round_id: self.round_id,
            sender,
            candidate,
        };
        self.receive_confirmation(members, confirmation.clone())?;
        self.confirmed_candidate = Some(confirmation.candidate.digest);
        Ok(confirmation)
    }

    pub fn receive_confirmation(
        &mut self,
        members: &HaMemberSlots,
        confirmation: HaConfirm,
    ) -> Result<Option<HaFinalizedRound>> {
        self.validate_message_scope(members, confirmation.round_id, confirmation.sender)?;
        confirmation.candidate.validate(self.round_id)?;
        if confirmation.candidate.included_mask != self.received_mask {
            return Err(BlossomError::WireProtocol(
                "HA confirmation does not contain every locally accepted pre-lock dispatch"
                    .to_string(),
            ));
        }
        if self.available_mask(members) & confirmation.candidate.included_mask
            != confirmation.candidate.included_mask
        {
            return Err(BlossomError::FailedConsensus);
        }
        for index in 0..MAX_HA_NODES {
            if confirmation.candidate.included_mask & (1u8 << index) != 0
                && confirmation.candidate.block_hashes[index] != self.block_hashes[index]
            {
                return Err(BlossomError::WireProtocol(
                    "HA confirmation block hash mismatch".to_string(),
                ));
            }
        }
        let sender_index = confirmation.sender.index();
        if let Some(existing) = self.confirmations[sender_index] {
            if existing == confirmation.candidate.digest {
                return Ok(self.finalized.clone());
            }
            return Err(BlossomError::WireProtocol(
                "HA member confirmed conflicting candidates".to_string(),
            ));
        }
        if let Some(locked) = self.confirmed_candidate
            && locked != confirmation.candidate.digest
        {
            return Err(BlossomError::WireProtocol(
                "HA local confirmation lock conflicts with received candidate".to_string(),
            ));
        }
        self.confirmations[sender_index] = Some(confirmation.candidate.digest);

        let mut confirmation_mask = 0u8;
        for index in 0..MAX_HA_NODES {
            if self.round_id.active_mask & (1u8 << index) != 0
                && self.confirmations[index] == Some(confirmation.candidate.digest)
            {
                confirmation_mask |= 1u8 << index;
            }
        }
        if confirmation_mask.count_ones() as usize >= members.majority() {
            self.confirmed_candidate = Some(confirmation.candidate.digest);
            let finalized = HaFinalizedRound {
                round_id: self.round_id,
                // Availability certifies the included dispatch origins. The
                // particular confirmation subset is arrival-order dependent
                // and is retained only as local audit evidence.
                presence_mask: confirmation.candidate.presence_mask,
                ordered_slots: confirmation.candidate.ordered_slots(),
                candidate: confirmation.candidate,
                confirmation_mask,
            };
            self.finalized = Some(finalized.clone());
            return Ok(Some(finalized));
        }
        Ok(None)
    }

    pub fn block(&self, slot: HaMemberSlot) -> Option<&Block> {
        self.blocks.get(slot.index()).and_then(Option::as_ref)
    }

    fn certified_presence_candidate_mask(&self, members: &HaMemberSlots) -> u8 {
        let mut presence = self.available_mask(members);
        for index in 0..MAX_HA_NODES {
            if self.round_id.active_mask & (1u8 << index) != 0 && self.acknowledgements[index] != 0
            {
                presence |= 1u8 << index;
            }
        }
        presence
    }

    fn validate_message_scope(
        &self,
        members: &HaMemberSlots,
        round_id: HaRoundId,
        sender: HaMemberSlot,
    ) -> Result<()> {
        if round_id != self.round_id {
            return Err(BlossomError::WireProtocol(
                "HA message targets another epoch or round".to_string(),
            ));
        }
        round_id.validate_for(members)?;
        self.validate_sender(members, sender)
    }

    fn validate_sender(&self, members: &HaMemberSlots, sender: HaMemberSlot) -> Result<()> {
        if !members.is_active(sender) {
            return Err(BlossomError::UnknownSender);
        }
        Ok(())
    }
}

fn masked_hashes(mask: u8, hashes: &[HashType; MAX_HA_NODES]) -> [HashType; MAX_HA_NODES] {
    array::from_fn(|index| {
        if mask & (1u8 << index) != 0 {
            hashes[index]
        } else {
            HashType::default()
        }
    })
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum AmendmentPayload {
    LateBlock {
        block_hash: HashType,
        block_bytes: Vec<u8>,
    },
    Compensation {
        command_bytes: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AmendmentRecord {
    pub target_epoch_hash: HashType,
    pub target_epoch_nonce: Nonce,
    pub containing_epoch_nonce: Nonce,
    pub origin_slot: HaMemberSlot,
    pub command_identity: CommandIdentity,
    pub supersedes: Option<CommandIdentity>,
    pub payload: AmendmentPayload,
}

impl AmendmentRecord {
    pub fn hash(&self) -> Result<HashType> {
        let bytes = borsh::to_vec(self)
            .map_err(|error| BlossomError::WireProtocol(format!("encode HA amendment: {error}")))?;
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_AMENDMENT_HASH_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize())
    }
}

fn encode_amendment_transaction(amendment: &AmendmentRecord) -> Result<crate::block::Transaction> {
    let encoded = borsh::to_vec(amendment).map_err(|error| {
        BlossomError::WireProtocol(format!("encode HA amendment transaction: {error}"))
    })?;
    let mut payload = Vec::with_capacity(HA_AMENDMENT_RECORD_PREFIX.len() + encoded.len());
    payload.extend_from_slice(HA_AMENDMENT_RECORD_PREFIX);
    payload.extend_from_slice(&encoded);
    Ok(crate::block::Transaction::new(payload))
}

fn decode_amendment_transaction(
    transaction: &crate::block::Transaction,
) -> Result<Option<AmendmentRecord>> {
    let payload = transaction.payload();
    let Some(encoded) = payload.strip_prefix(HA_AMENDMENT_RECORD_PREFIX) else {
        return Ok(None);
    };
    borsh::from_slice(encoded).map(Some).map_err(|error| {
        BlossomError::WireProtocol(format!("decode HA amendment transaction: {error}"))
    })
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum EpochLifecycle {
    Mutable { remaining_successors: u32 },
    Sealed,
}

pub fn epoch_lifecycle(epoch: Nonce, head: Nonce, mutable_epoch_depth: u32) -> EpochLifecycle {
    let distance = head.value().saturating_sub(epoch.value());
    if distance >= u64::from(mutable_epoch_depth) {
        EpochLifecycle::Sealed
    } else {
        EpochLifecycle::Mutable {
            remaining_successors: mutable_epoch_depth - distance as u32,
        }
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum NodeAvailabilityStatus {
    Active,
    Missing { consecutive_epochs: u32 },
    Unresponsive,
    Suspended { since: Nonce },
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct StateRevision {
    pub head: Watermark,
    pub sealed: Watermark,
    pub revision_hash: HashType,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct HaHandshake {
    pub group_id: ConsensusGroupId,
    pub sender: PubKey,
    pub fixed_membership_hash: HashType,
    pub membership_generation: u64,
    pub active_mask: u8,
    pub parameters_hash: HashType,
    pub head_nonce: Nonce,
    pub head_hash: HashType,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaNodeStatus {
    pub group_id: ConsensusGroupId,
    pub self_slot: HaMemberSlot,
    pub member_count: u8,
    pub fixed_membership_hash: HashType,
    pub active_mask: u8,
    pub membership_generation: u64,
    pub parameters: HighAvailabilityParameters,
    pub parameters_hash: HashType,
    pub head_nonce: Nonce,
    pub head_hash: HashType,
    pub sealed: Watermark,
    pub revision: StateRevision,
    pub availability: [NodeAvailabilityStatus; MAX_HA_NODES],
    pub committed_membership_changes: u64,
}

/// Service-facing readiness classification for HA integrations.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaServiceHealth {
    Ready,
    Degraded,
    Unavailable,
    Suspended,
}

/// Machine-readable actions that a service supervisor can map to alerts,
/// traffic draining, user notices, or a redeploy workflow.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum HaServiceDirective {
    Continue,
    NotifyOperators,
    NotifyUsers,
    DrainWrites,
    AwaitQuorum { required: u8, responsive: u8 },
    FetchRecoverySnapshot { minimum_head: Nonce },
    OfferRecoverySnapshot { through: Nonce },
    AwaitReactivation,
    RestartOrRedeploy,
    QuarantinePeer,
    AwaitLeader,
}

/// Service-level replication choice for a 2–7 node HA deployment.
///
/// `LeaderlessActiveActive` is implemented by [`HighAvailabilityRuntime`].
/// `MajorityLeaderActivePassive` is an integration contract for an external
/// leader-based engine such as Raft; Blossom core intentionally does not
/// depend on or implement that engine.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaReplicationMode {
    LeaderlessActiveActive,
    MajorityLeaderActivePassive,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaWriteRoute {
    AnyActiveMember,
    CurrentLeader,
}

/// Leadership observation supplied by the service's active-passive driver.
///
/// Leaderless Blossom HA callers must use `NotApplicable`. The service API
/// never attempts to infer leadership from Blossom HA state.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaLeadershipStatus {
    NotApplicable,
    Unavailable,
    Elected,
}

/// Validated physical and voting layout for one HA service deployment.
///
/// Active-active Blossom uses every physical member as a voter. Active-passive
/// deployments may use non-voting learners, but majority leadership and write
/// availability are always derived from `voting_nodes`.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct HaServiceTopology {
    pub mode: HaReplicationMode,
    pub physical_nodes: u8,
    pub voting_nodes: u8,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaModeOperationalStatus {
    pub topology: HaServiceTopology,
    pub write_route: HaWriteRoute,
    pub leadership: HaLeadershipStatus,
    pub responsive_voters: u8,
    pub required_voters: u8,
    pub tolerated_voter_failures: u8,
    pub health: HaServiceHealth,
    pub accepts_writes: bool,
    pub serves_local_reads: bool,
    pub directives: Vec<HaServiceDirective>,
}

impl HaServiceTopology {
    pub fn active_active(member_count: usize) -> Result<Self> {
        let member_count = validated_ha_node_count(member_count)?;
        Ok(Self {
            mode: HaReplicationMode::LeaderlessActiveActive,
            physical_nodes: member_count,
            voting_nodes: member_count,
        })
    }

    pub fn active_passive(physical_nodes: usize, voting_nodes: usize) -> Result<Self> {
        let physical_nodes = validated_ha_node_count(physical_nodes)?;
        let voting_nodes = validated_ha_node_count(voting_nodes)?;
        if voting_nodes > physical_nodes {
            return Err(BlossomError::InvalidConfiguration(
                "HA active-passive voting nodes cannot exceed physical nodes".to_string(),
            ));
        }
        Ok(Self {
            mode: HaReplicationMode::MajorityLeaderActivePassive,
            physical_nodes,
            voting_nodes,
        })
    }

    pub const fn write_route(self) -> HaWriteRoute {
        match self.mode {
            HaReplicationMode::LeaderlessActiveActive => HaWriteRoute::AnyActiveMember,
            HaReplicationMode::MajorityLeaderActivePassive => HaWriteRoute::CurrentLeader,
        }
    }

    pub fn required_voters(self) -> u8 {
        u8::try_from(high_availability_majority(usize::from(self.voting_nodes)))
            .expect("validated HA topology has at most seven voters")
    }

    pub fn tolerated_voter_failures(self) -> u8 {
        self.voting_nodes.saturating_sub(self.required_voters())
    }

    /// Converts protocol reachability and leadership observations into one
    /// service-facing write/readiness decision.
    ///
    /// A two-voter topology requires both voters. With only one responsive
    /// voter, both replication modes remain locally readable but reject new
    /// consensus writes.
    pub fn assess(
        self,
        responsive_voters: usize,
        leadership: HaLeadershipStatus,
    ) -> Result<HaModeOperationalStatus> {
        if responsive_voters > usize::from(self.voting_nodes) {
            return Err(BlossomError::InvalidConfiguration(
                "responsive HA voters cannot exceed configured voting nodes".to_string(),
            ));
        }
        match (self.mode, leadership) {
            (HaReplicationMode::LeaderlessActiveActive, HaLeadershipStatus::NotApplicable)
            | (
                HaReplicationMode::MajorityLeaderActivePassive,
                HaLeadershipStatus::Unavailable | HaLeadershipStatus::Elected,
            ) => {}
            (HaReplicationMode::LeaderlessActiveActive, _) => {
                return Err(BlossomError::InvalidConfiguration(
                    "leaderless active-active HA does not accept a leadership state".to_string(),
                ));
            }
            (HaReplicationMode::MajorityLeaderActivePassive, HaLeadershipStatus::NotApplicable) => {
                return Err(BlossomError::InvalidConfiguration(
                    "active-passive HA requires an observation from its majority-leader driver"
                        .to_string(),
                ));
            }
        }

        let responsive_voters = u8::try_from(responsive_voters)
            .expect("validated HA topology has at most seven voters");
        let required_voters = self.required_voters();
        let has_quorum = responsive_voters >= required_voters;
        let has_write_authority = match self.mode {
            HaReplicationMode::LeaderlessActiveActive => true,
            HaReplicationMode::MajorityLeaderActivePassive => {
                leadership == HaLeadershipStatus::Elected
            }
        };
        let accepts_writes = has_quorum && has_write_authority;
        let health = if !accepts_writes {
            HaServiceHealth::Unavailable
        } else if responsive_voters < self.voting_nodes {
            HaServiceHealth::Degraded
        } else {
            HaServiceHealth::Ready
        };
        let directives = if !has_quorum {
            vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::AwaitQuorum {
                    required: required_voters,
                    responsive: responsive_voters,
                },
            ]
        } else if !has_write_authority {
            vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::AwaitLeader,
            ]
        } else if responsive_voters < self.voting_nodes {
            vec![
                HaServiceDirective::Continue,
                HaServiceDirective::NotifyOperators,
            ]
        } else {
            vec![HaServiceDirective::Continue]
        };

        Ok(HaModeOperationalStatus {
            topology: self,
            write_route: self.write_route(),
            leadership,
            responsive_voters,
            required_voters,
            tolerated_voter_failures: self.tolerated_voter_failures(),
            health,
            accepts_writes,
            serves_local_reads: true,
            directives,
        })
    }
}

fn validated_ha_node_count(node_count: usize) -> Result<u8> {
    if !(MIN_HA_NODES..=MAX_HA_NODES).contains(&node_count) {
        return Err(BlossomError::InvalidHighAvailabilityNodeCount(node_count));
    }
    Ok(u8::try_from(node_count).expect("validated HA node count is at most seven"))
}

/// Machine-readable classification for mapping HA failures into service
/// supervisors, alerts, traffic draining, and redeploy automation.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaFailureClass {
    DurabilityUnavailable,
    QuorumUnavailable,
    TransportUnavailable,
    PeerAuthentication,
    Configuration,
    ProtocolViolation,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaFailureAssessment {
    pub class: HaFailureClass,
    pub health: HaServiceHealth,
    /// Whether retrying in the same process can be useful. Durable-store I/O
    /// failures are not retried because redb requires close and reopen after an
    /// I/O error.
    pub retry_in_process: bool,
    pub directives: Vec<HaServiceDirective>,
}

pub fn assess_high_availability_failure(error: &BlossomError) -> HaFailureAssessment {
    let message = error.to_string();
    if matches!(error, BlossomError::Io(_)) && message.contains("HA durable store") {
        return HaFailureAssessment {
            class: HaFailureClass::DurabilityUnavailable,
            health: HaServiceHealth::Unavailable,
            retry_in_process: false,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::RestartOrRedeploy,
            ],
        };
    }
    if matches!(error, BlossomError::FailedConsensus) {
        return HaFailureAssessment {
            class: HaFailureClass::QuorumUnavailable,
            health: HaServiceHealth::Unavailable,
            retry_in_process: true,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::DrainWrites,
            ],
        };
    }
    if matches!(
        error,
        BlossomError::Io(_) | BlossomError::ExternalService(_)
    ) {
        return HaFailureAssessment {
            class: HaFailureClass::TransportUnavailable,
            health: HaServiceHealth::Degraded,
            retry_in_process: true,
            directives: vec![HaServiceDirective::NotifyOperators],
        };
    }
    if matches!(
        error,
        BlossomError::UnknownSender | BlossomError::WireProtocol(_)
    ) && (message.contains("authentication")
        || message.contains("authenticated transport peer")
        || matches!(error, BlossomError::UnknownSender))
    {
        return HaFailureAssessment {
            class: HaFailureClass::PeerAuthentication,
            health: HaServiceHealth::Degraded,
            retry_in_process: false,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::QuarantinePeer,
            ],
        };
    }
    if matches!(
        error,
        BlossomError::InvalidConfiguration(_) | BlossomError::InvalidHighAvailabilityNodeCount(_)
    ) {
        return HaFailureAssessment {
            class: HaFailureClass::Configuration,
            health: HaServiceHealth::Unavailable,
            retry_in_process: false,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::DrainWrites,
            ],
        };
    }
    HaFailureAssessment {
        class: HaFailureClass::ProtocolViolation,
        health: HaServiceHealth::Unavailable,
        retry_in_process: false,
        directives: vec![
            HaServiceDirective::NotifyOperators,
            HaServiceDirective::DrainWrites,
            HaServiceDirective::QuarantinePeer,
        ],
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaOperationalStatus {
    pub health: HaServiceHealth,
    pub self_status: NodeAvailabilityStatus,
    pub active_nodes: u8,
    pub responsive_nodes: u8,
    pub required_nodes: u8,
    pub accepts_writes: bool,
    pub serves_local_reads: bool,
    pub strict_reads_through: Watermark,
    pub directives: Vec<HaServiceDirective>,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaPeerCompatibility {
    Compatible,
    LocalBehind,
    PeerBehind,
    Diverged,
    Incompatible,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaPeerAssessment {
    pub compatibility: HaPeerCompatibility,
    pub local_head: Nonce,
    pub peer_head: Nonce,
    pub directives: Vec<HaServiceDirective>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum HaOperationalEventKind {
    HealthChanged {
        from: HaServiceHealth,
        to: HaServiceHealth,
    },
    HeadAdvanced {
        from: Nonce,
        to: Nonce,
    },
    SealedWatermarkAdvanced {
        from: Watermark,
        to: Watermark,
    },
    MemberAvailabilityChanged {
        slot: HaMemberSlot,
        from: NodeAvailabilityStatus,
        to: NodeAvailabilityStatus,
    },
    MembershipGenerationChanged {
        from: u64,
        to: u64,
        active_mask: u8,
    },
    StateRevisionChanged {
        from: HashType,
        to: HashType,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaOperationalEvent {
    pub observed_at: Nonce,
    pub kind: HaOperationalEventKind,
    pub directives: Vec<HaServiceDirective>,
}

/// Immutable consensus state used to catch a stopped or suspended HA member up
/// to a healthy peer. Transient Dispatch/Acknowledge/Confirm state is
/// deliberately excluded: recovery resumes at the next epoch boundary.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HaRecoverySnapshot {
    pub format_version: u16,
    pub group_id: ConsensusGroupId,
    pub members: HaMemberSlots,
    pub fixed_membership_hash: HashType,
    pub membership_generation: u64,
    pub parameters: HighAvailabilityParameters,
    pub parameters_hash: HashType,
    pub epochs: Vec<HaEpoch>,
    pub presence: HaPresenceTracker,
    pub membership_changes: Vec<HaMembershipCertificate>,
    pub amendments: Vec<AmendmentRecord>,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaMembershipAction {
    Suspend,
    Reactivate { caught_up_through: Nonce },
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct HaMembershipProposal {
    pub group_id: ConsensusGroupId,
    pub membership_generation: u64,
    pub active_mask: u8,
    pub parameters_hash: HashType,
    pub effective_nonce: Nonce,
    pub slot: HaMemberSlot,
    pub action: HaMembershipAction,
    pub digest: HashType,
}

impl HaMembershipProposal {
    fn new(
        group_id: ConsensusGroupId,
        membership_generation: u64,
        active_mask: u8,
        parameters_hash: HashType,
        effective_nonce: Nonce,
        slot: HaMemberSlot,
        action: HaMembershipAction,
    ) -> Self {
        let mut proposal = Self {
            group_id,
            membership_generation,
            active_mask,
            parameters_hash,
            effective_nonce,
            slot,
            action,
            digest: HashType::default(),
        };
        proposal.digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_MEMBERSHIP_PROPOSAL_HASH_DOMAIN);
        hasher.update(self.group_id.as_ref());
        hasher.update(self.membership_generation.to_le_bytes());
        hasher.update([self.active_mask]);
        hasher.update(self.parameters_hash.as_ref());
        hasher.update(self.effective_nonce.to_le_bytes());
        hasher.update([self.slot.0]);
        match self.action {
            HaMembershipAction::Suspend => hasher.update([0]),
            HaMembershipAction::Reactivate { caught_up_through } => {
                hasher.update([1]);
                hasher.update(caught_up_through.to_le_bytes());
            }
        }
        hasher.finalize()
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct HaMembershipVote {
    pub proposal: HaMembershipProposal,
    pub sender: HaMemberSlot,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct HaMembershipCertificate {
    pub proposal: HaMembershipProposal,
    pub approval_mask: u8,
}

impl HaNodeStatus {
    pub fn operational_status(&self) -> HaOperationalStatus {
        let active_nodes = self.active_mask.count_ones() as u8;
        let required_nodes = u8::try_from(high_availability_majority(usize::from(active_nodes)))
            .expect("HA majority is at most seven");
        let mut responsive_mask = 0u8;
        for index in 0..usize::from(self.member_count) {
            let bit = 1u8 << index;
            if self.active_mask & bit == 0 {
                continue;
            }
            if index == self.self_slot.index()
                || self.availability[index] == NodeAvailabilityStatus::Active
            {
                responsive_mask |= bit;
            }
        }
        let responsive_nodes = responsive_mask.count_ones() as u8;
        let self_status = self.availability[self.self_slot.index()];
        let self_active = self.active_mask & (1u8 << self.self_slot.0) != 0;
        let health =
            if !self_active || matches!(self_status, NodeAvailabilityStatus::Suspended { .. }) {
                HaServiceHealth::Suspended
            } else if responsive_nodes < required_nodes {
                HaServiceHealth::Unavailable
            } else if responsive_nodes < active_nodes
                || self
                    .availability
                    .iter()
                    .take(usize::from(self.member_count))
                    .any(|status| *status != NodeAvailabilityStatus::Active)
            {
                HaServiceHealth::Degraded
            } else {
                HaServiceHealth::Ready
            };
        let directives = match health {
            HaServiceHealth::Ready => vec![HaServiceDirective::Continue],
            HaServiceHealth::Degraded => vec![
                HaServiceDirective::Continue,
                HaServiceDirective::NotifyOperators,
            ],
            HaServiceHealth::Unavailable => vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::AwaitQuorum {
                    required: required_nodes,
                    responsive: responsive_nodes,
                },
            ],
            HaServiceHealth::Suspended => vec![
                HaServiceDirective::DrainWrites,
                HaServiceDirective::FetchRecoverySnapshot {
                    minimum_head: self.head_nonce,
                },
                HaServiceDirective::AwaitReactivation,
            ],
        };
        HaOperationalStatus {
            health,
            self_status,
            active_nodes,
            responsive_nodes,
            required_nodes,
            accepts_writes: self_active
                && matches!(health, HaServiceHealth::Ready | HaServiceHealth::Degraded),
            serves_local_reads: true,
            strict_reads_through: self.sealed,
            directives,
        }
    }

    pub fn assess_peer(&self, peer: &Self) -> HaPeerAssessment {
        let incompatible = self.group_id != peer.group_id
            || self.fixed_membership_hash != peer.fixed_membership_hash
            || self.parameters_hash != peer.parameters_hash;
        let (compatibility, directives) = if incompatible {
            (
                HaPeerCompatibility::Incompatible,
                vec![
                    HaServiceDirective::QuarantinePeer,
                    HaServiceDirective::NotifyOperators,
                ],
            )
        } else if self.membership_generation < peer.membership_generation {
            (
                HaPeerCompatibility::LocalBehind,
                vec![
                    HaServiceDirective::DrainWrites,
                    HaServiceDirective::FetchRecoverySnapshot {
                        minimum_head: peer.head_nonce,
                    },
                    HaServiceDirective::RestartOrRedeploy,
                ],
            )
        } else if self.membership_generation > peer.membership_generation {
            (
                HaPeerCompatibility::PeerBehind,
                vec![HaServiceDirective::OfferRecoverySnapshot {
                    through: self.head_nonce,
                }],
            )
        } else if self.active_mask != peer.active_mask
            || (self.head_nonce == peer.head_nonce
                && (self.head_hash != peer.head_hash
                    || self.revision.revision_hash != peer.revision.revision_hash))
        {
            (
                HaPeerCompatibility::Diverged,
                vec![
                    HaServiceDirective::QuarantinePeer,
                    HaServiceDirective::NotifyOperators,
                    HaServiceDirective::DrainWrites,
                ],
            )
        } else if self.head_nonce < peer.head_nonce {
            (
                HaPeerCompatibility::LocalBehind,
                vec![
                    HaServiceDirective::DrainWrites,
                    HaServiceDirective::FetchRecoverySnapshot {
                        minimum_head: peer.head_nonce,
                    },
                    HaServiceDirective::RestartOrRedeploy,
                ],
            )
        } else if self.head_nonce > peer.head_nonce {
            (
                HaPeerCompatibility::PeerBehind,
                vec![HaServiceDirective::OfferRecoverySnapshot {
                    through: self.head_nonce,
                }],
            )
        } else {
            (
                HaPeerCompatibility::Compatible,
                vec![HaServiceDirective::Continue],
            )
        };
        HaPeerAssessment {
            compatibility,
            local_head: self.head_nonce,
            peer_head: peer.head_nonce,
            directives,
        }
    }

    pub fn operational_events_since(&self, previous: &Self) -> Vec<HaOperationalEvent> {
        let current_status = self.operational_status();
        let directives = current_status.directives;
        let mut events = Vec::new();
        let previous_health = previous.operational_status().health;
        let current_health = current_status.health;
        if previous_health != current_health {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::HealthChanged {
                    from: previous_health,
                    to: current_health,
                },
                directives: directives.clone(),
            });
        }
        if previous.head_nonce != self.head_nonce {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::HeadAdvanced {
                    from: previous.head_nonce,
                    to: self.head_nonce,
                },
                directives: directives.clone(),
            });
        }
        if previous.sealed != self.sealed {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::SealedWatermarkAdvanced {
                    from: previous.sealed,
                    to: self.sealed,
                },
                directives: directives.clone(),
            });
        }
        for index in 0..usize::from(self.member_count) {
            if previous.availability[index] != self.availability[index] {
                events.push(HaOperationalEvent {
                    observed_at: self.head_nonce,
                    kind: HaOperationalEventKind::MemberAvailabilityChanged {
                        slot: HaMemberSlot(index as u8),
                        from: previous.availability[index],
                        to: self.availability[index],
                    },
                    directives: directives.clone(),
                });
            }
        }
        if previous.membership_generation != self.membership_generation
            || previous.active_mask != self.active_mask
        {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::MembershipGenerationChanged {
                    from: previous.membership_generation,
                    to: self.membership_generation,
                    active_mask: self.active_mask,
                },
                directives: directives.clone(),
            });
        }
        if previous.revision.revision_hash != self.revision.revision_hash {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::StateRevisionChanged {
                    from: previous.revision.revision_hash,
                    to: self.revision.revision_hash,
                },
                directives,
            });
        }
        events
    }
}

impl StateRevision {
    pub fn from_epoch_hashes(
        head: Watermark,
        sealed: Watermark,
        hashes: impl IntoIterator<Item = HashType>,
    ) -> Self {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_REVISION_HASH_DOMAIN);
        hasher.update(head.position.to_le_bytes());
        hasher.update(sealed.position.to_le_bytes());
        for hash in hashes {
            hasher.update(hash.as_ref());
        }
        Self {
            head,
            sealed,
            revision_hash: hasher.finalize(),
        }
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaPresenceTracker {
    missed: [u32; MAX_HA_NODES],
    statuses: [NodeAvailabilityStatus; MAX_HA_NODES],
}

impl Default for HaPresenceTracker {
    fn default() -> Self {
        Self {
            missed: [0; MAX_HA_NODES],
            statuses: [NodeAvailabilityStatus::Active; MAX_HA_NODES],
        }
    }
}

impl HaPresenceTracker {
    pub fn observe_epoch(
        &mut self,
        members: &HaMemberSlots,
        presence_mask: u8,
        nonce: Nonce,
        parameters: HighAvailabilityParameters,
    ) {
        for index in 0..members.member_count() {
            let slot = HaMemberSlot(index as u8);
            if !members.is_active(slot) {
                continue;
            }
            if presence_mask & (1u8 << index) != 0 {
                self.missed[index] = 0;
                self.statuses[index] = NodeAvailabilityStatus::Active;
                continue;
            }
            self.missed[index] = self.missed[index].saturating_add(1);
            self.statuses[index] = if self.missed[index] >= parameters.unresponsive_epoch_depth {
                NodeAvailabilityStatus::Unresponsive
            } else {
                NodeAvailabilityStatus::Missing {
                    consecutive_epochs: self.missed[index],
                }
            };
        }
        let _ = nonce;
    }

    pub fn status(&self, slot: HaMemberSlot) -> NodeAvailabilityStatus {
        self.statuses
            .get(slot.index())
            .copied()
            .unwrap_or(NodeAvailabilityStatus::Unresponsive)
    }

    pub fn missed_epochs(&self, slot: HaMemberSlot) -> u32 {
        self.missed.get(slot.index()).copied().unwrap_or(u32::MAX)
    }

    pub fn mark_suspended(&mut self, slot: HaMemberSlot, since: Nonce) {
        if let Some(status) = self.statuses.get_mut(slot.index()) {
            *status = NodeAvailabilityStatus::Suspended { since };
        }
    }

    pub fn mark_reactivated(&mut self, slot: HaMemberSlot) {
        if let Some(missed) = self.missed.get_mut(slot.index()) {
            *missed = 0;
        }
        if let Some(status) = self.statuses.get_mut(slot.index()) {
            *status = NodeAvailabilityStatus::Active;
        }
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
struct HighAvailabilityRuntimeState {
    group_id: ConsensusGroupId,
    self_slot: HaMemberSlot,
    members: HaMemberSlots,
    membership_generation: u64,
    parameters: HighAvailabilityParameters,
    epochs: Vec<HaEpoch>,
    round: HaRoundState,
    presence: HaPresenceTracker,
    membership_vote_lock: Option<HashType>,
    membership_votes: [Option<HashType>; MAX_HA_NODES],
    membership_changes: Vec<HaMembershipCertificate>,
    amendments: Vec<AmendmentRecord>,
}

impl HighAvailabilityRuntimeState {
    fn validate(&self) -> Result<()> {
        self.parameters.validate()?;
        self.members.validate()?;
        if self.members.member(self.self_slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        if self.epochs.is_empty() {
            return Err(BlossomError::EmptyEpochChain);
        }
        let mut genesis_members = self.members.clone();
        genesis_members.active_mask = low_bits(genesis_members.member_count);
        let expected_genesis = HaEpoch::genesis(self.group_id, &genesis_members, self.parameters);
        let stored_genesis = borsh::to_vec(&self.epochs[0]).map_err(|error| {
            BlossomError::WireProtocol(format!("encode stored HA genesis: {error}"))
        })?;
        let canonical_genesis = borsh::to_vec(&expected_genesis).map_err(|error| {
            BlossomError::WireProtocol(format!("encode canonical HA genesis: {error}"))
        })?;
        if stored_genesis != canonical_genesis {
            return Err(BlossomError::WireProtocol(
                "HA genesis does not match the committed fixed membership".to_string(),
            ));
        }
        for (index, epoch) in self.epochs.iter().enumerate() {
            if epoch.group_id != self.group_id
                || epoch.fixed_membership_hash != self.members.fixed_identity_hash()
                || epoch.parameters != self.parameters
                || epoch.parameters_hash != self.parameters.hash()
            {
                return Err(BlossomError::InvalidConfiguration(
                    "HA epoch parameters or group mismatch".to_string(),
                ));
            }
            if epoch.hash != epoch.compute_hash() {
                return Err(BlossomError::WireProtocol(
                    "HA epoch hash mismatch".to_string(),
                ));
            }
            if index > 0 {
                let previous = &self.epochs[index - 1];
                if epoch.previous_epoch_hash != previous.hash
                    || epoch.previous_epoch_nonce != Some(previous.nonce)
                    || epoch.nonce != previous.nonce.new_next()
                {
                    return Err(BlossomError::WireProtocol(
                        "HA epoch chain linkage mismatch".to_string(),
                    ));
                }
                epoch.validate(&self.members)?;
            }
        }
        let tip = self.epochs.last().expect("non-empty checked above");
        if self.round.round_id.group_id != self.group_id
            || self.round.round_id.fixed_membership_hash != self.members.fixed_identity_hash()
            || self.round.round_id.membership_generation != self.membership_generation
            || self.round.round_id.active_mask != self.members.active_mask()
            || self.round.round_id.parameters_hash != self.parameters.hash()
            || self.round.round_id.previous_epoch_hash != tip.hash
            || self.round.round_id.previous_epoch_nonce != tip.nonce
            || self.round.round_id.nonce != tip.nonce.new_next()
        {
            return Err(BlossomError::WireProtocol(
                "HA current round does not extend the epoch tip".to_string(),
            ));
        }
        for index in self.members.member_count()..MAX_HA_NODES {
            if self.membership_votes[index].is_some() {
                return Err(BlossomError::WireProtocol(
                    "HA membership vote references an unassigned slot".to_string(),
                ));
            }
        }
        if let Some(locked) = self.membership_vote_lock
            && self.membership_votes[self.self_slot.index()] != Some(locked)
        {
            return Err(BlossomError::WireProtocol(
                "HA durable membership vote lock is missing its local vote".to_string(),
            ));
        }
        let mut expected_generation = 0u64;
        let mut expected_active_mask = low_bits(self.members.member_count);
        for certificate in &self.membership_changes {
            let proposal = certificate.proposal;
            if proposal.digest != proposal.compute_digest()
                || proposal.group_id != self.group_id
                || proposal.membership_generation != expected_generation
                || proposal.active_mask != expected_active_mask
                || proposal.parameters_hash != self.parameters.hash()
                || certificate.approval_mask & !expected_active_mask != 0
                || (certificate.approval_mask.count_ones() as usize)
                    < high_availability_majority(expected_active_mask.count_ones() as usize)
            {
                return Err(BlossomError::WireProtocol(
                    "invalid durable HA membership certificate chain".to_string(),
                ));
            }
            let bit = proposal.slot.bit()?;
            match proposal.action {
                HaMembershipAction::Suspend => {
                    if expected_active_mask & bit == 0
                        || (expected_active_mask & !bit).count_ones() < MIN_HA_NODES as u32
                    {
                        return Err(BlossomError::WireProtocol(
                            "invalid durable HA suspension certificate".to_string(),
                        ));
                    }
                    expected_active_mask &= !bit;
                }
                HaMembershipAction::Reactivate { .. } => {
                    if expected_active_mask & bit != 0 {
                        return Err(BlossomError::WireProtocol(
                            "invalid durable HA reactivation certificate".to_string(),
                        ));
                    }
                    expected_active_mask |= bit;
                }
            }
            expected_generation = expected_generation.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("HA membership generation overflow".to_string())
            })?;
        }
        if expected_generation != self.membership_generation
            || expected_active_mask != self.members.active_mask()
        {
            return Err(BlossomError::WireProtocol(
                "HA membership certificates do not reconstruct current membership".to_string(),
            ));
        }

        let mut replay_members = genesis_members;
        let mut replay_generation = 0u64;
        let mut replay_presence = HaPresenceTracker::default();
        let mut change_index = 0usize;
        for epoch in self.epochs.iter().skip(1) {
            while self
                .membership_changes
                .get(change_index)
                .is_some_and(|certificate| certificate.proposal.effective_nonce == epoch.nonce)
            {
                let certificate = self.membership_changes[change_index];
                Self::replay_membership_change(
                    &mut replay_members,
                    &mut replay_presence,
                    certificate,
                )?;
                replay_generation = replay_generation.checked_add(1).ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "HA membership generation overflow".to_string(),
                    )
                })?;
                change_index += 1;
            }
            if self
                .membership_changes
                .get(change_index)
                .is_some_and(|certificate| certificate.proposal.effective_nonce < epoch.nonce)
                || epoch.membership_generation != replay_generation
                || epoch.active_mask != replay_members.active_mask()
            {
                return Err(BlossomError::WireProtocol(
                    "HA epoch membership generation does not match its certificate chain"
                        .to_string(),
                ));
            }
            replay_presence.observe_epoch(
                &replay_members,
                epoch.presence_mask,
                epoch.nonce,
                self.parameters,
            );
        }
        let pending_nonce = tip.nonce.new_next();
        while let Some(certificate) = self.membership_changes.get(change_index).copied() {
            if certificate.proposal.effective_nonce != pending_nonce {
                return Err(BlossomError::WireProtocol(
                    "HA membership certificate is not effective at an epoch boundary".to_string(),
                ));
            }
            Self::replay_membership_change(&mut replay_members, &mut replay_presence, certificate)?;
            replay_generation = replay_generation.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("HA membership generation overflow".to_string())
            })?;
            change_index += 1;
        }
        if replay_generation != self.membership_generation
            || replay_members.active_mask() != self.members.active_mask()
            || replay_presence != self.presence
        {
            return Err(BlossomError::WireProtocol(
                "HA recovered presence or membership state is not deterministic".to_string(),
            ));
        }
        for amendment in &self.amendments {
            self.validate_amendment_structure(amendment)?;
        }
        Ok(())
    }

    fn replay_membership_change(
        members: &mut HaMemberSlots,
        presence: &mut HaPresenceTracker,
        certificate: HaMembershipCertificate,
    ) -> Result<()> {
        let proposal = certificate.proposal;
        *members = match proposal.action {
            HaMembershipAction::Suspend => {
                presence.mark_suspended(proposal.slot, proposal.effective_nonce);
                members.with_suspended(proposal.slot)?
            }
            HaMembershipAction::Reactivate { .. } => {
                presence.mark_reactivated(proposal.slot);
                members.with_reactivated(proposal.slot)?
            }
        };
        Ok(())
    }

    fn head(&self) -> &HaEpoch {
        self.epochs.last().expect("HA runtime always has genesis")
    }

    fn sealed_nonce(&self) -> Nonce {
        Nonce::new(
            self.head()
                .nonce
                .value()
                .saturating_sub(u64::from(self.parameters.mutable_epoch_depth)),
        )
    }

    fn validate_amendment_structure(&self, amendment: &AmendmentRecord) -> Result<()> {
        if self.members.member(amendment.origin_slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        let target = self
            .epochs
            .iter()
            .find(|epoch| epoch.nonce == amendment.target_epoch_nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "HA amendment target epoch is not in the local chain".to_string(),
                )
            })?;
        if target.hash != amendment.target_epoch_hash {
            return Err(BlossomError::WireProtocol(
                "HA amendment target hash mismatch".to_string(),
            ));
        }
        let containing_exists = self
            .epochs
            .iter()
            .any(|epoch| epoch.nonce == amendment.containing_epoch_nonce);
        if !containing_exists || amendment.containing_epoch_nonce <= amendment.target_epoch_nonce {
            return Err(BlossomError::InvalidConfiguration(
                "HA amendment must be carried by a later committed epoch".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_new_amendment(&self, amendment: &AmendmentRecord) -> Result<()> {
        self.validate_amendment_structure(amendment)?;
        if matches!(
            epoch_lifecycle(
                amendment.target_epoch_nonce,
                self.head().nonce,
                self.parameters.mutable_epoch_depth,
            ),
            EpochLifecycle::Sealed
        ) {
            return Err(BlossomError::EpochSealed {
                target: amendment.target_epoch_nonce,
                sealed: self.sealed_nonce(),
                writable: self.round.round_id.nonce,
            });
        }
        Ok(())
    }
}

#[derive(Clone)]
struct HaDurableStore {
    database: Arc<Database>,
}

impl HaDurableStore {
    fn open(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(|error| BlossomError::Io(error.to_string()))?;
        }
        let database = Database::create(path).map_err(ha_storage_error)?;
        Self::from_database(database)
    }

    fn from_database(database: Database) -> Result<Self> {
        let store = Self {
            database: Arc::new(database),
        };
        let mut transaction = store.database.begin_write().map_err(ha_storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(ha_storage_error)?;
        {
            transaction
                .open_table(HA_RUNTIME_STATE_TABLE)
                .map_err(ha_storage_error)?;
        }
        transaction.commit().map_err(ha_storage_error)?;
        Ok(store)
    }

    fn load(&self) -> Result<Option<HighAvailabilityRuntimeState>> {
        let transaction = self.database.begin_read().map_err(ha_storage_error)?;
        let table = transaction
            .open_table(HA_RUNTIME_STATE_TABLE)
            .map_err(ha_storage_error)?;
        let Some(value) = table.get(HA_RUNTIME_STATE_KEY).map_err(ha_storage_error)? else {
            return Ok(None);
        };
        let state =
            borsh::from_slice::<HighAvailabilityRuntimeState>(value.value()).map_err(|error| {
                BlossomError::WireProtocol(format!("decode durable HA runtime state: {error}"))
            })?;
        state.validate()?;
        Ok(Some(state))
    }

    fn persist(&self, state: &HighAvailabilityRuntimeState) -> Result<()> {
        let bytes = borsh::to_vec(state).map_err(|error| {
            BlossomError::WireProtocol(format!("encode durable HA runtime state: {error}"))
        })?;
        let mut transaction = self.database.begin_write().map_err(ha_storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(ha_storage_error)?;
        {
            let mut table = transaction
                .open_table(HA_RUNTIME_STATE_TABLE)
                .map_err(ha_storage_error)?;
            table
                .insert(HA_RUNTIME_STATE_KEY, bytes.as_slice())
                .map_err(ha_storage_error)?;
        }
        transaction.commit().map_err(ha_storage_error)
    }
}

fn ha_storage_error(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::Io(format!("HA durable store: {error}"))
}

#[derive(Debug, Clone)]
pub enum HaRuntimeEvent {
    HandshakeAccepted,
    MembershipVoteAccepted,
    MembershipChanged(HaMembershipCertificate),
    Dispatch(HaDispatchOutcome),
    Acknowledged,
    Confirmed,
    Finalized(Box<HaEpoch>),
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaWireReceipt {
    pub kind: String,
    pub finalized_epoch_hash: Option<HashType>,
    pub nonce: Nonce,
}

impl HaWireReceipt {
    fn from_event(event: &HaRuntimeEvent, nonce: Nonce) -> Self {
        match event {
            HaRuntimeEvent::HandshakeAccepted => Self {
                kind: "handshake_accepted".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::MembershipVoteAccepted => Self {
                kind: "membership_vote_accepted".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::MembershipChanged(_) => Self {
                kind: "membership_changed".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::Dispatch(outcome) => Self {
                kind: match outcome {
                    HaDispatchOutcome::Accepted => "dispatch_accepted",
                    HaDispatchOutcome::Duplicate => "dispatch_duplicate",
                    HaDispatchOutcome::Late { .. } => "dispatch_late",
                }
                .to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::Acknowledged => Self {
                kind: "acknowledged".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::Confirmed => Self {
                kind: "confirmed".to_string(),
                finalized_epoch_hash: None,
                nonce,
            },
            HaRuntimeEvent::Finalized(epoch) => Self {
                kind: "finalized".to_string(),
                finalized_epoch_hash: Some(epoch.hash),
                nonce: epoch.nonce,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct HaBroadcastReceipt {
    pub peer: PubKey,
    pub response: Result<HaWireReceipt>,
}

#[derive(Debug, Clone, Default)]
pub struct HaBroadcastReport {
    pub receipts: Vec<HaBroadcastReceipt>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaBroadcastAssessment {
    pub health: HaServiceHealth,
    pub attempted_peers: u8,
    pub responsive_nodes: u8,
    pub required_nodes: u8,
    pub quorum_reached: bool,
    pub directives: Vec<HaServiceDirective>,
}

impl HaBroadcastReport {
    pub fn accepted(&self) -> usize {
        self.receipts
            .iter()
            .filter(|receipt| receipt.response.is_ok())
            .map(|receipt| receipt.peer)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Converts immediate transport outcomes into service lifecycle actions.
    ///
    /// The local active node counts as responsive. This lets a service detect
    /// loss of quorum before another epoch can finalize and update the
    /// epoch-based presence tracker.
    pub fn assess(&self, active_nodes: usize) -> Result<HaBroadcastAssessment> {
        if !(MIN_HA_NODES..=MAX_HA_NODES).contains(&active_nodes) {
            return Err(BlossomError::InvalidHighAvailabilityNodeCount(active_nodes));
        }
        let attempted_peers = u8::try_from(
            self.receipts
                .iter()
                .map(|receipt| receipt.peer)
                .collect::<BTreeSet<_>>()
                .len()
                .min(MAX_HA_NODES - 1),
        )
        .expect("HA peer count is at most six");
        let responsive_nodes =
            u8::try_from(1usize.saturating_add(self.accepted()).min(active_nodes))
                .expect("HA responsive count is at most seven");
        let required_nodes = u8::try_from(high_availability_majority(active_nodes))
            .expect("HA majority is at most seven");
        let quorum_reached = responsive_nodes >= required_nodes;
        let health = if !quorum_reached {
            HaServiceHealth::Unavailable
        } else if usize::from(responsive_nodes) < active_nodes {
            HaServiceHealth::Degraded
        } else {
            HaServiceHealth::Ready
        };
        let directives = match health {
            HaServiceHealth::Ready => vec![HaServiceDirective::Continue],
            HaServiceHealth::Degraded => vec![
                HaServiceDirective::Continue,
                HaServiceDirective::NotifyOperators,
            ],
            HaServiceHealth::Unavailable => vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::AwaitQuorum {
                    required: required_nodes,
                    responsive: responsive_nodes,
                },
            ],
            HaServiceHealth::Suspended => unreachable!("broadcast assessment is for active nodes"),
        };
        Ok(HaBroadcastAssessment {
            health,
            attempted_peers,
            responsive_nodes,
            required_nodes,
            quorum_reached,
            directives,
        })
    }
}

struct HaAuthenticatedConnection {
    stream: TcpStream,
    session_id: [u8; HA_TRANSPORT_KEY_BYTES],
    session_key: [u8; HA_TRANSPORT_KEY_BYTES],
    next_sequence: u64,
}

impl HaAuthenticatedConnection {
    async fn connect(
        service: &Service,
        context: &HaTransportContext,
        transport_key: &HaTransportKey,
    ) -> Result<Self> {
        context.validate_peer(service.public_key)?;
        let mut stream = TcpStream::connect(service.socket_addr())
            .await
            .map_err(|error| BlossomError::Io(error.to_string()))?;
        let mut client_nonce = [0u8; HA_TRANSPORT_KEY_BYTES];
        OsRng.fill_bytes(&mut client_nonce);
        let hello_body = HaTransportHelloBody {
            version: HA_TRANSPORT_VERSION,
            group_id: context.group_id,
            fixed_membership_hash: context.fixed_membership_hash,
            parameters_hash: context.parameters_hash,
            client: context.local_key,
            server: service.public_key,
            client_nonce,
        };
        let hello = HaTransportHello {
            mac: ha_transport_mac(
                transport_key.as_bytes(),
                HA_TRANSPORT_HELLO_DOMAIN,
                &hello_body,
            )?,
            body: hello_body.clone(),
        };
        write_frame(&mut stream, &hello).await?;

        let challenge: HaTransportChallenge = read_frame(&mut stream).await?;
        if challenge.body.hello != hello_body {
            return Err(BlossomError::WireProtocol(
                "HA transport challenge changed the authenticated hello".to_string(),
            ));
        }
        verify_ha_transport_mac(
            transport_key.as_bytes(),
            HA_TRANSPORT_CHALLENGE_DOMAIN,
            &challenge.body,
            &challenge.mac,
        )?;
        let seed = HaTransportSessionSeed {
            hello: hello_body,
            server_nonce: challenge.body.server_nonce,
        };
        let expected_session_id = ha_transport_mac(
            transport_key.as_bytes(),
            HA_TRANSPORT_SESSION_ID_DOMAIN,
            &seed,
        )?;
        if challenge.body.session_id != expected_session_id {
            return Err(BlossomError::WireProtocol(
                "HA transport session identifier mismatch".to_string(),
            ));
        }
        let session_key = derive_ha_session_key(transport_key, &challenge.body)?;
        Ok(Self {
            stream,
            session_id: expected_session_id,
            session_key,
            next_sequence: 1,
        })
    }

    async fn request(&mut self, request: &HaWireRequest) -> Result<HaWireResponse> {
        let sequence = self.next_sequence;
        let body = HaAuthenticatedRequestBody {
            session_id: self.session_id,
            sequence,
            request: request.clone(),
        };
        let request = HaAuthenticatedRequest {
            mac: ha_transport_mac(&self.session_key, HA_TRANSPORT_REQUEST_DOMAIN, &body)?,
            body,
        };
        write_frame(&mut self.stream, &request).await?;

        let response: HaAuthenticatedResponse = read_frame(&mut self.stream).await?;
        if response.body.session_id != self.session_id || response.body.sequence != sequence {
            return Err(BlossomError::WireProtocol(
                "HA transport response session or sequence mismatch".to_string(),
            ));
        }
        verify_ha_transport_mac(
            &self.session_key,
            HA_TRANSPORT_RESPONSE_DOMAIN,
            &response.body,
            &response.mac,
        )?;
        self.next_sequence = sequence.checked_add(1).ok_or_else(|| {
            BlossomError::WireProtocol("HA transport sequence exhausted".to_string())
        })?;
        Ok(response.body.response)
    }
}

/// Persistent authenticated client for the isolated HA wire profile.
///
/// The client binds a connection to the fixed genesis membership and committed
/// HA parameters. Every frame is HMAC-authenticated with a monotonically
/// increasing per-session sequence number.
#[derive(Clone)]
pub struct HighAvailabilityTcpClient {
    context: HaTransportContext,
    transport_key: HaTransportKey,
    connections: Arc<Mutex<BTreeMap<String, Arc<Mutex<HaAuthenticatedConnection>>>>>,
}

impl HighAvailabilityTcpClient {
    pub fn for_runtime(runtime: &HighAvailabilityRuntime, transport_key: HaTransportKey) -> Self {
        Self {
            context: HaTransportContext::from_runtime(runtime),
            transport_key,
            connections: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn request(
        &self,
        service: &Service,
        request: &HaWireRequest,
    ) -> Result<HaWireResponse> {
        let key = format!("{}#{}", service.socket_addr(), service.public_key);
        let connection = self.connection(&key, service).await?;
        let response = {
            let mut connection = connection.lock().await;
            connection.request(request).await
        };
        match response {
            Ok(response) => Ok(response),
            Err(first_error) => {
                self.remove_connection(&key, &connection).await;
                let replacement = self.connection(&key, service).await?;
                let mut replacement = replacement.lock().await;
                replacement.request(request).await.map_err(|second_error| {
                    BlossomError::ExternalService(format!(
                        "authenticated HA request failed ({first_error}); reconnect failed ({second_error})"
                    ))
                })
            }
        }
    }

    pub async fn status(&self, service: &Service) -> Result<HaNodeStatus> {
        match self.request(service, &HaWireRequest::Status).await? {
            HaWireResponse::Status(status) => Ok(*status),
            HaWireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected HA status, got {}",
                response.kind()
            ))),
        }
    }

    pub async fn send_message(
        &self,
        service: &Service,
        message: HaMessage,
    ) -> Result<HaWireReceipt> {
        match self
            .request(service, &HaWireRequest::Message(Box::new(message)))
            .await?
        {
            HaWireResponse::Receipt(receipt) => Ok(receipt),
            HaWireResponse::Error(message) => Err(BlossomError::ExternalService(message)),
            response => Err(BlossomError::WireProtocol(format!(
                "expected HA receipt, got {}",
                response.kind()
            ))),
        }
    }

    async fn connection(
        &self,
        key: &str,
        service: &Service,
    ) -> Result<Arc<Mutex<HaAuthenticatedConnection>>> {
        if let Some(connection) = self.connections.lock().await.get(key).cloned() {
            return Ok(connection);
        }
        let connection = Arc::new(Mutex::new(
            HaAuthenticatedConnection::connect(service, &self.context, &self.transport_key).await?,
        ));
        let mut connections = self.connections.lock().await;
        Ok(connections
            .entry(key.to_string())
            .or_insert_with(|| connection.clone())
            .clone())
    }

    async fn remove_connection(&self, key: &str, failed: &Arc<Mutex<HaAuthenticatedConnection>>) {
        let mut connections = self.connections.lock().await;
        if connections
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, failed))
        {
            connections.remove(key);
        }
    }
}

/// Authenticated TCP service for the small-cluster HA runtime.
///
/// Each stage is broadcast directly to every configured peer over persistent,
/// replay-protected sessions. With the seven-node cap that is at most six
/// outgoing requests per local stage.
#[derive(Clone)]
pub struct HighAvailabilityTcpNode {
    runtime: Arc<Mutex<HighAvailabilityRuntime>>,
    peers: Vec<Service>,
    services: HighAvailabilityTcpClient,
    transport_key: HaTransportKey,
}

impl HighAvailabilityTcpNode {
    pub fn new(
        runtime: HighAvailabilityRuntime,
        peers: Vec<Service>,
        transport_key: HaTransportKey,
    ) -> Result<Self> {
        let context = HaTransportContext::from_runtime(&runtime);
        for peer in &peers {
            context.validate_peer(peer.public_key)?;
        }
        let services = HighAvailabilityTcpClient::for_runtime(&runtime, transport_key.clone());
        Ok(Self {
            runtime: Arc::new(Mutex::new(runtime)),
            peers,
            services,
            transport_key,
        })
    }

    pub fn runtime(&self) -> Arc<Mutex<HighAvailabilityRuntime>> {
        self.runtime.clone()
    }

    pub async fn assess_broadcast(
        &self,
        report: &HaBroadcastReport,
    ) -> Result<HaBroadcastAssessment> {
        let active_nodes = self.runtime.lock().await.members().active_count();
        report.assess(active_nodes)
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|error| BlossomError::Io(error.to_string()))?;
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(error) = node.handle_connection(stream).await {
                    node.runtime.lock().await.emit_telemetry_failure(
                        "transport",
                        "ha_connection_failed",
                        &error,
                    );
                    log::error!("HA connection failed: {error}");
                }
            });
        }
    }

    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        let context = {
            let runtime = self.runtime.lock().await;
            HaTransportContext::from_runtime(&runtime)
        };
        let hello: HaTransportHello = read_frame(&mut stream).await?;
        if hello.body.version != HA_TRANSPORT_VERSION
            || hello.body.group_id != context.group_id
            || hello.body.fixed_membership_hash != context.fixed_membership_hash
            || hello.body.parameters_hash != context.parameters_hash
            || hello.body.server != context.local_key
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA transport hello does not match local consensus context".to_string(),
            ));
        }
        context.validate_peer(hello.body.client)?;
        verify_ha_transport_mac(
            self.transport_key.as_bytes(),
            HA_TRANSPORT_HELLO_DOMAIN,
            &hello.body,
            &hello.mac,
        )?;

        let mut server_nonce = [0u8; HA_TRANSPORT_KEY_BYTES];
        OsRng.fill_bytes(&mut server_nonce);
        let seed = HaTransportSessionSeed {
            hello: hello.body.clone(),
            server_nonce,
        };
        let session_id = ha_transport_mac(
            self.transport_key.as_bytes(),
            HA_TRANSPORT_SESSION_ID_DOMAIN,
            &seed,
        )?;
        let challenge_body = HaTransportChallengeBody {
            hello: hello.body,
            server_nonce,
            session_id,
        };
        let challenge = HaTransportChallenge {
            mac: ha_transport_mac(
                self.transport_key.as_bytes(),
                HA_TRANSPORT_CHALLENGE_DOMAIN,
                &challenge_body,
            )?,
            body: challenge_body,
        };
        write_frame(&mut stream, &challenge).await?;
        let session_key = derive_ha_session_key(&self.transport_key, &challenge.body)?;

        let mut expected_sequence = 1u64;
        while let Some(request) =
            read_frame_optional::<HaAuthenticatedRequest, _>(&mut stream).await?
        {
            if request.body.session_id != session_id || request.body.sequence != expected_sequence {
                return Err(BlossomError::WireProtocol(format!(
                    "HA transport expected sequence {expected_sequence}"
                )));
            }
            verify_ha_transport_mac(
                &session_key,
                HA_TRANSPORT_REQUEST_DOMAIN,
                &request.body,
                &request.mac,
            )?;
            let response = self
                .handle_authenticated_request(challenge.body.hello.client, request.body.request)
                .await
                .unwrap_or_else(|error| HaWireResponse::Error(error.to_string()));
            let response_body = HaAuthenticatedResponseBody {
                session_id,
                sequence: expected_sequence,
                response,
            };
            let response = HaAuthenticatedResponse {
                mac: ha_transport_mac(&session_key, HA_TRANSPORT_RESPONSE_DOMAIN, &response_body)?,
                body: response_body,
            };
            write_frame(&mut stream, &response).await?;
            expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
                BlossomError::WireProtocol("HA transport sequence exhausted".to_string())
            })?;
        }
        Ok(())
    }

    async fn handle_authenticated_request(
        &self,
        authenticated_peer: PubKey,
        request: HaWireRequest,
    ) -> Result<HaWireResponse> {
        match request {
            HaWireRequest::Message(message) => {
                let mut runtime = self.runtime.lock().await;
                let claimed_peer = ha_message_sender(&message, runtime.members())?;
                if claimed_peer != authenticated_peer {
                    return Err(BlossomError::WireProtocol(
                        "HA message sender does not match authenticated transport peer".to_string(),
                    ));
                }
                let event = runtime.receive_message(*message)?;
                let nonce = runtime.head().nonce;
                Ok(HaWireResponse::Receipt(HaWireReceipt::from_event(
                    &event, nonce,
                )))
            }
            HaWireRequest::Status => Ok(HaWireResponse::Status(Box::new(
                self.runtime.lock().await.status()?,
            ))),
            _ => Err(BlossomError::WireProtocol(
                "HA service accepts only high-availability messages and status requests"
                    .to_string(),
            )),
        }
    }

    pub async fn build_and_broadcast_dispatch(
        &self,
        transactions: Vec<crate::block::Transaction>,
    ) -> Result<(HaDispatch, HaBroadcastReport)> {
        let dispatch = self.runtime.lock().await.build_dispatch(transactions)?;
        let report = self
            .broadcast_message(HaMessage::Dispatch(dispatch.clone()))
            .await;
        Ok((dispatch, report))
    }

    pub async fn build_and_broadcast_acknowledgement(
        &self,
    ) -> Result<(HaAcknowledge, HaBroadcastReport)> {
        let acknowledgement = self.runtime.lock().await.acknowledge()?;
        let report = self
            .broadcast_message(HaMessage::Acknowledge(acknowledgement.clone()))
            .await;
        Ok((acknowledgement, report))
    }

    pub async fn build_and_broadcast_confirmation(
        &self,
    ) -> Result<(HaConfirm, Option<HaEpoch>, HaBroadcastReport)> {
        let (confirmation, epoch) = self.runtime.lock().await.confirm()?;
        let report = self
            .broadcast_message(HaMessage::Confirm(confirmation.clone()))
            .await;
        Ok((confirmation, epoch, report))
    }

    pub async fn vote_and_broadcast_suspension(
        &self,
        slot: HaMemberSlot,
    ) -> Result<(
        HaMembershipVote,
        Option<HaMembershipCertificate>,
        HaBroadcastReport,
    )> {
        let (vote, certificate) = self.runtime.lock().await.vote_to_suspend(slot)?;
        let report = self
            .broadcast_message(HaMessage::MembershipVote(vote))
            .await;
        Ok((vote, certificate, report))
    }

    pub async fn vote_and_broadcast_reactivation(
        &self,
        slot: HaMemberSlot,
        caught_up_through: Nonce,
    ) -> Result<(
        HaMembershipVote,
        Option<HaMembershipCertificate>,
        HaBroadcastReport,
    )> {
        let (vote, certificate) = self
            .runtime
            .lock()
            .await
            .vote_to_reactivate(slot, caught_up_through)?;
        let report = self
            .broadcast_message(HaMessage::MembershipVote(vote))
            .await;
        Ok((vote, certificate, report))
    }

    pub async fn broadcast_message(&self, message: HaMessage) -> HaBroadcastReport {
        let mut tasks = Vec::with_capacity(self.peers.len());
        for peer in self.peers.iter().cloned() {
            let services = self.services.clone();
            let message = message.clone();
            tasks.push((
                peer.public_key,
                tokio::spawn(async move { services.send_message(&peer, message).await }),
            ));
        }
        let mut receipts = Vec::with_capacity(tasks.len());
        for (peer, task) in tasks {
            let response = match task.await {
                Ok(response) => response,
                Err(error) => Err(BlossomError::Io(format!(
                    "HA broadcast task failed: {error}"
                ))),
            };
            receipts.push(HaBroadcastReceipt { peer, response });
        }
        HaBroadcastReport { receipts }
    }
}

fn ha_message_sender(message: &HaMessage, members: &HaMemberSlots) -> Result<PubKey> {
    let slot = match message {
        HaMessage::Handshake(handshake) => return Ok(handshake.sender),
        HaMessage::MembershipVote(vote) => vote.sender,
        HaMessage::Dispatch(dispatch) => dispatch.sender,
        HaMessage::Acknowledge(acknowledgement) => acknowledgement.sender,
        HaMessage::Confirm(confirmation) => confirmation.sender,
    };
    members
        .member(slot)
        .map(NodeIdentity::public_key)
        .ok_or(BlossomError::UnknownSender)
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

impl HighAvailabilityRuntime {
    pub fn new(
        group_id: ConsensusGroupId,
        self_key: PubKey,
        members: Vec<NodeIdentity>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        Self::create(None, group_id, self_key, members, parameters)
    }

    pub fn open(
        path: impl AsRef<Path>,
        group_id: ConsensusGroupId,
        self_key: PubKey,
        members: Vec<NodeIdentity>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        let store = HaDurableStore::open(path)?;
        Self::open_store(store, group_id, self_key, members, parameters)
    }

    fn open_store(
        store: HaDurableStore,
        group_id: ConsensusGroupId,
        self_key: PubKey,
        members: Vec<NodeIdentity>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        if let Some(state) = store.load()? {
            if state.group_id != group_id
                || state.parameters != parameters
                || !state
                    .members
                    .same_fixed_identities(&HaMemberSlots::new(members)?)
                || state
                    .members
                    .member(state.self_slot)
                    .is_none_or(|member| member.public_key() != self_key)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "durable HA runtime configuration mismatch".to_string(),
                ));
            }
            return Ok(Self {
                store: Some(store),
                state,
                telemetry: TelemetryHandle::default(),
            });
        }
        Self::create(Some(store), group_id, self_key, members, parameters)
    }

    fn create(
        store: Option<HaDurableStore>,
        group_id: ConsensusGroupId,
        self_key: PubKey,
        members: Vec<NodeIdentity>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        parameters.validate()?;
        let members = HaMemberSlots::new(members)?;
        let self_slot = members
            .slot_for(&self_key)
            .ok_or(BlossomError::UnknownSender)?;
        let genesis = HaEpoch::genesis(group_id, &members, parameters);
        let round_id = HaRoundId {
            group_id,
            fixed_membership_hash: members.fixed_identity_hash(),
            membership_generation: 0,
            active_mask: members.active_mask(),
            parameters_hash: parameters.hash(),
            previous_epoch_hash: genesis.hash,
            previous_epoch_nonce: genesis.nonce,
            nonce: genesis.nonce.new_next(),
            round: 0,
        };
        let state = HighAvailabilityRuntimeState {
            group_id,
            self_slot,
            members: members.clone(),
            membership_generation: 0,
            parameters,
            epochs: vec![genesis],
            round: HaRoundState::new(round_id, &members)?,
            presence: HaPresenceTracker::default(),
            membership_vote_lock: None,
            membership_votes: array::from_fn(|_| None),
            membership_changes: Vec::new(),
            amendments: Vec::new(),
        };
        state.validate()?;
        let runtime = Self {
            store,
            state,
            telemetry: TelemetryHandle::default(),
        };
        runtime.persist()?;
        Ok(runtime)
    }

    pub fn with_telemetry(mut self, telemetry: TelemetryHandle) -> Self {
        self.telemetry = telemetry;
        self.record_operational_status();
        self
    }

    pub fn set_telemetry(&mut self, telemetry: TelemetryHandle) {
        self.telemetry = telemetry;
        self.record_operational_status();
    }

    pub fn telemetry(&self) -> &TelemetryHandle {
        &self.telemetry
    }

    /// Emits an HA-scoped structured failure without applying a recovery
    /// policy. Services may use this for transport and dependency failures.
    pub fn emit_telemetry_failure(
        &self,
        stage: impl Into<String>,
        event: impl Into<String>,
        error: &BlossomError,
    ) {
        self.telemetry.record(
            self.telemetry_event(stage, event)
                .with_outcome("error")
                .with_error(error.to_string()),
        );
    }

    fn self_public_key(&self) -> PubKey {
        self.state
            .members
            .member(self.state.self_slot)
            .expect("validated HA self slot")
            .public_key()
    }

    fn telemetry_event(
        &self,
        stage: impl Into<String>,
        event: impl Into<String>,
    ) -> TelemetryEvent {
        TelemetryEvent::new(TelemetryEventKind::Event, stage, event)
            .with_node(self.self_public_key())
            .with_group_id(self.state.group_id)
            .with_target(self.head().hash, self.head().nonce)
            .with_round(self.state.round.round_id.round)
            .with_field("self_slot", self.state.self_slot.0.to_string())
            .with_field(
                "membership_generation",
                self.state.membership_generation.to_string(),
            )
            .with_field("active_mask", self.state.members.active_mask().to_string())
            .with_field("parameters_hash", self.state.parameters.hash().to_string())
    }

    fn record_operational_status(&self) {
        let Ok(status) = self.status() else {
            return;
        };
        self.telemetry.record_ha_operational_status(
            self.self_public_key(),
            self.state.group_id,
            status.head_hash,
            status.head_nonce,
            &status.operational_status(),
        );
    }

    pub fn assess_failure(&self, error: &BlossomError) -> HaFailureAssessment {
        let assessment = assess_high_availability_failure(error);
        self.telemetry.record(
            self.telemetry_event("service", "ha_failure")
                .with_outcome("error")
                .with_error(error.to_string())
                .with_field("class", format!("{:?}", assessment.class))
                .with_field("retry_in_process", assessment.retry_in_process.to_string())
                .with_field("directives", format!("{:?}", assessment.directives)),
        );
        assessment
    }

    pub fn parameters(&self) -> HighAvailabilityParameters {
        self.state.parameters
    }

    pub fn parameters_hash(&self) -> HashType {
        self.state.parameters.hash()
    }

    pub fn members(&self) -> &HaMemberSlots {
        &self.state.members
    }

    pub fn self_slot(&self) -> HaMemberSlot {
        self.state.self_slot
    }

    pub fn current_round(&self) -> &HaRoundState {
        &self.state.round
    }

    pub fn epochs(&self) -> &[HaEpoch] {
        &self.state.epochs
    }

    pub fn head(&self) -> &HaEpoch {
        self.state.head()
    }

    pub fn sealed_watermark(&self) -> Watermark {
        Watermark {
            position: self.state.sealed_nonce().value(),
        }
    }

    pub fn lifecycle(&self, nonce: Nonce) -> EpochLifecycle {
        epoch_lifecycle(
            nonce,
            self.head().nonce,
            self.state.parameters.mutable_epoch_depth,
        )
    }

    /// Gates CAS results and strict/linearizable application reads on the
    /// immutable application watermark.
    pub fn require_sealed(&self, required: Watermark) -> Result<()> {
        let sealed = self.sealed_watermark();
        if sealed.position < required.position {
            return Err(BlossomError::WatermarkNotSealed {
                required: required.position,
                sealed: sealed.position,
            });
        }
        Ok(())
    }

    pub fn handshake(&self) -> HaHandshake {
        let sender = self
            .state
            .members
            .member(self.state.self_slot)
            .expect("validated HA self slot")
            .public_key();
        HaHandshake {
            group_id: self.state.group_id,
            sender,
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            membership_generation: self.state.membership_generation,
            active_mask: self.state.members.active_mask(),
            parameters_hash: self.parameters_hash(),
            head_nonce: self.head().nonce,
            head_hash: self.head().hash,
        }
    }

    pub fn validate_handshake(&self, handshake: &HaHandshake) -> Result<()> {
        if handshake.group_id != self.state.group_id
            || handshake.fixed_membership_hash != self.state.members.fixed_identity_hash()
            || handshake.membership_generation != self.state.membership_generation
            || handshake.active_mask != self.state.members.active_mask()
            || handshake.parameters_hash != self.parameters_hash()
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA handshake consensus parameters or membership mismatch".to_string(),
            ));
        }
        let sender_slot = self
            .state
            .members
            .slot_for(&handshake.sender)
            .ok_or(BlossomError::UnknownSender)?;
        if !self.state.members.is_active(sender_slot) {
            return Err(BlossomError::UnknownSender);
        }
        if handshake.head_nonce == self.head().nonce && handshake.head_hash != self.head().hash {
            return Err(BlossomError::WireProtocol(
                "HA handshake reports a conflicting hash at the local head nonce".to_string(),
            ));
        }
        Ok(())
    }

    pub fn status(&self) -> Result<HaNodeStatus> {
        Ok(HaNodeStatus {
            group_id: self.state.group_id,
            self_slot: self.state.self_slot,
            member_count: u8::try_from(self.state.members.member_count())
                .expect("HA membership is at most seven"),
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            active_mask: self.state.members.active_mask(),
            membership_generation: self.state.membership_generation,
            parameters: self.state.parameters,
            parameters_hash: self.parameters_hash(),
            head_nonce: self.head().nonce,
            head_hash: self.head().hash,
            sealed: self.sealed_watermark(),
            revision: self.revision()?,
            availability: array::from_fn(|index| {
                self.state.presence.status(HaMemberSlot(index as u8))
            }),
            committed_membership_changes: u64::try_from(self.state.membership_changes.len())
                .unwrap_or(u64::MAX),
        })
    }

    pub fn operational_status(&self) -> Result<HaOperationalStatus> {
        let status = self.status()?.operational_status();
        self.telemetry.record_ha_operational_status(
            self.self_public_key(),
            self.state.group_id,
            self.head().hash,
            self.head().nonce,
            &status,
        );
        Ok(status)
    }

    pub const fn replication_mode(&self) -> HaReplicationMode {
        HaReplicationMode::LeaderlessActiveActive
    }

    pub fn service_topology(&self) -> HaServiceTopology {
        HaServiceTopology::active_active(self.state.members.member_count())
            .expect("validated HA runtime membership is between two and seven")
    }

    pub fn assess_peer_status(&self, peer: &HaNodeStatus) -> Result<HaPeerAssessment> {
        Ok(self.status()?.assess_peer(peer))
    }

    /// Exports finalized HA history and committed membership metadata for
    /// direct application-managed catch-up.
    pub fn recovery_snapshot(&self) -> HaRecoverySnapshot {
        HaRecoverySnapshot {
            format_version: HIGH_AVAILABILITY_RECOVERY_SNAPSHOT_VERSION,
            group_id: self.state.group_id,
            members: self.state.members.public_only(),
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            membership_generation: self.state.membership_generation,
            parameters: self.state.parameters,
            parameters_hash: self.parameters_hash(),
            epochs: self.state.epochs.clone(),
            presence: self.state.presence.clone(),
            membership_changes: self.state.membership_changes.clone(),
            amendments: self.state.amendments.clone(),
        }
    }

    /// Installs a trusted peer's finalized recovery snapshot. Local transient
    /// round work must be empty so accepted writes and durable vote locks are
    /// never discarded implicitly.
    pub fn install_recovery_snapshot(
        &mut self,
        snapshot: HaRecoverySnapshot,
    ) -> Result<StateRevision> {
        snapshot.members.validate()?;
        if snapshot.format_version != HIGH_AVAILABILITY_RECOVERY_SNAPSHOT_VERSION
            || snapshot.group_id != self.state.group_id
            || snapshot.parameters != self.state.parameters
            || snapshot.parameters_hash != snapshot.parameters.hash()
            || snapshot.fixed_membership_hash != snapshot.members.fixed_identity_hash()
            || !snapshot.members.same_fixed_identities(&self.state.members)
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA recovery snapshot configuration mismatch".to_string(),
            ));
        }
        let snapshot_head = snapshot
            .epochs
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if snapshot_head.nonce < self.head().nonce
            || snapshot.epochs.len() < self.state.epochs.len()
            || self
                .state
                .epochs
                .iter()
                .zip(&snapshot.epochs)
                .any(|(local, recovered)| {
                    local.nonce != recovered.nonce || local.hash != recovered.hash
                })
        {
            return Err(BlossomError::WireProtocol(
                "HA recovery snapshot would roll back or replace finalized history".to_string(),
            ));
        }
        let round = &self.state.round;
        if round.received_mask != 0
            || round.acknowledgements.iter().any(|mask| *mask != 0)
            || round.confirmations.iter().any(Option::is_some)
            || round.confirmed_candidate.is_some()
            || round.finalized.is_some()
            || self.state.membership_vote_lock.is_some()
            || self.state.membership_votes.iter().any(Option::is_some)
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA recovery requires an empty local round with no durable vote lock".to_string(),
            ));
        }

        // Keep this process's local endpoint and secret material. Only the
        // fixed public-key identities and committed active mask cross the
        // recovery boundary.
        let mut recovered_members = self.state.members.clone();
        recovered_members.active_mask = snapshot.members.active_mask();
        recovered_members.validate()?;
        let next_round = HaRoundId {
            group_id: self.state.group_id,
            fixed_membership_hash: recovered_members.fixed_identity_hash(),
            membership_generation: snapshot.membership_generation,
            active_mask: recovered_members.active_mask(),
            parameters_hash: self.parameters_hash(),
            previous_epoch_hash: snapshot_head.hash,
            previous_epoch_nonce: snapshot_head.nonce,
            nonce: snapshot_head.nonce.new_next(),
            round: 0,
        };
        let replacement = HighAvailabilityRuntimeState {
            group_id: self.state.group_id,
            self_slot: self.state.self_slot,
            members: recovered_members.clone(),
            membership_generation: snapshot.membership_generation,
            parameters: self.state.parameters,
            epochs: snapshot.epochs,
            round: HaRoundState::new(next_round, &recovered_members)?,
            presence: snapshot.presence,
            membership_vote_lock: None,
            membership_votes: array::from_fn(|_| None),
            membership_changes: snapshot.membership_changes,
            amendments: snapshot.amendments,
        };
        replacement.validate()?;
        if let Some(store) = &self.store {
            store.persist(&replacement)?;
        }
        self.state = replacement;
        let revision = self.revision()?;
        self.telemetry.record(
            self.telemetry_event("recovery", "snapshot_installed")
                .with_outcome("ok")
                .with_field("revision_hash", revision.revision_hash.to_string())
                .with_field("sealed_watermark", revision.sealed.position.to_string()),
        );
        self.record_operational_status();
        Ok(revision)
    }

    pub fn build_dispatch(
        &mut self,
        transactions: Vec<crate::block::Transaction>,
    ) -> Result<HaDispatch> {
        self.build_dispatch_with_created(transactions, None)
    }

    /// Builds this node's dispatch with an explicit block creation timestamp.
    ///
    /// Deterministic simulations and replay verification can use this method
    /// to remove wall-clock time from the protocol input. Production callers
    /// should normally use [`Self::build_dispatch`].
    pub fn build_dispatch_at(
        &mut self,
        transactions: Vec<crate::block::Transaction>,
        created_micros: u128,
    ) -> Result<HaDispatch> {
        self.build_dispatch_with_created(transactions, Some(created_micros))
    }

    fn build_dispatch_with_created(
        &mut self,
        transactions: Vec<crate::block::Transaction>,
        created_micros: Option<u128>,
    ) -> Result<HaDispatch> {
        self.validate_amendment_transactions(&transactions, self.state.round.round_id.nonce)?;
        let member = self
            .state
            .members
            .member(self.state.self_slot)
            .ok_or(BlossomError::UnknownSender)?;
        let mut block = Block::default();
        if let Some(created_micros) = created_micros {
            block.body.created = created_micros;
        }
        block.body.last_epoch = self.state.round.round_id.previous_epoch_hash;
        block.body.nonce = self.state.round.round_id.nonce;
        block.body.txs = transactions;
        block.seal_unsigned(member.public_key());
        let dispatch = HaDispatch {
            round_id: self.state.round.round_id,
            sender: self.state.self_slot,
            block_hash: block.hash,
            block,
        };
        self.state
            .round
            .receive_dispatch(&self.state.members, dispatch.clone())?;
        self.telemetry.record(
            self.telemetry_event("dispatch", "dispatch_built")
                .with_outcome("ok")
                .with_field("slot", dispatch.sender.0.to_string())
                .with_field("block_hash", dispatch.block_hash.to_string())
                .with_field("transactions", dispatch.block.body.txs.len().to_string())
                .with_field(
                    "bytes",
                    borsh::object_length(&dispatch.block)
                        .unwrap_or_default()
                        .to_string(),
                ),
        );
        // The local block becomes externally durable evidence when
        // `acknowledge()` persists the complete receipt state. A crash before
        // that point emitted no acknowledgement and may safely replay.
        Ok(dispatch)
    }

    pub fn receive_dispatch(&mut self, dispatch: HaDispatch) -> Result<HaRuntimeEvent> {
        if dispatch.round_id != self.state.round.round_id {
            if dispatch.round_id.nonce < self.state.round.round_id.nonce {
                return Ok(HaRuntimeEvent::Dispatch(HaDispatchOutcome::Late {
                    target_epoch: dispatch.round_id.nonce,
                }));
            }
            return Err(BlossomError::WireProtocol(
                "future HA dispatch cannot be applied before catch-up".to_string(),
            ));
        }
        self.validate_amendment_transactions(
            &dispatch.block.body.txs,
            self.state.round.round_id.nonce,
        )?;
        let outcome = self
            .state
            .round
            .receive_dispatch(&self.state.members, dispatch)?;
        // Do not fsync each arrival. The receiver persists all accepted block
        // bytes before broadcasting its monotonic acknowledgement.
        self.telemetry.record(
            self.telemetry_event("dispatch", "dispatch_received")
                .with_outcome("ok")
                .with_field("outcome", format!("{outcome:?}")),
        );
        Ok(HaRuntimeEvent::Dispatch(outcome))
    }

    pub fn acknowledge(&mut self) -> Result<HaAcknowledge> {
        let sender_index = self.state.self_slot.index();
        let previous_acknowledgement = self.state.round.acknowledgements[sender_index];
        let acknowledgement = self
            .state
            .round
            .acknowledge(&self.state.members, self.state.self_slot)?;
        if let Err(error) = self.persist() {
            self.state.round.acknowledgements[sender_index] = previous_acknowledgement;
            return Err(error);
        }
        self.telemetry.record(
            self.telemetry_event("acknowledge", "acknowledgement_persisted")
                .with_outcome("ok")
                .with_field("sender_slot", acknowledgement.sender.0.to_string())
                .with_field("received_mask", acknowledgement.received_mask.to_string()),
        );
        Ok(acknowledgement)
    }

    pub fn receive_acknowledgement(
        &mut self,
        acknowledgement: HaAcknowledge,
    ) -> Result<HaRuntimeEvent> {
        if acknowledgement.round_id.nonce < self.state.round.round_id.nonce {
            if self
                .state
                .epochs
                .iter()
                .any(|epoch| epoch.nonce == acknowledgement.round_id.nonce)
            {
                return Ok(HaRuntimeEvent::Acknowledged);
            }
            return Err(BlossomError::WireProtocol(
                "HA acknowledgement targets an unknown stale epoch".to_string(),
            ));
        }
        let sender = acknowledgement.sender;
        let received_mask = acknowledgement.received_mask;
        self.state
            .round
            .receive_acknowledgement(&self.state.members, acknowledgement)?;
        self.telemetry.record(
            self.telemetry_event("acknowledge", "acknowledgement_received")
                .with_outcome("ok")
                .with_field("sender_slot", sender.0.to_string())
                .with_field("received_mask", received_mask.to_string()),
        );
        // Acknowledgement observations are replayable until this node creates
        // its own durable confirmation lock.
        Ok(HaRuntimeEvent::Acknowledged)
    }

    /// Durably confirms the current candidate.
    ///
    /// If this process restarts after persisting its lock but before sending
    /// the message, calling `confirm` again reconstructs and returns the exact
    /// same confirmation. It never creates a second candidate.
    pub fn confirm(&mut self) -> Result<(HaConfirm, Option<HaEpoch>)> {
        let previous_confirmations = self.state.round.confirmations;
        let previous_confirmed_candidate = self.state.round.confirmed_candidate;
        let previous_finalized = self.state.round.finalized.clone();
        let confirmation = self
            .state
            .round
            .confirm(&self.state.members, self.state.self_slot)?;
        // The confirmation lock is durable before the caller can broadcast.
        if let Err(error) = self.persist() {
            self.state.round.confirmations = previous_confirmations;
            self.state.round.confirmed_candidate = previous_confirmed_candidate;
            self.state.round.finalized = previous_finalized;
            return Err(error);
        }
        let epoch = self.commit_finalized_round()?;
        self.telemetry.record(
            self.telemetry_event("confirm", "confirmation_persisted")
                .with_outcome("ok")
                .with_field("sender_slot", confirmation.sender.0.to_string())
                .with_field(
                    "candidate_digest",
                    confirmation.candidate.digest.to_string(),
                ),
        );
        Ok((confirmation, epoch))
    }

    pub fn receive_confirmation(&mut self, confirmation: HaConfirm) -> Result<HaRuntimeEvent> {
        if confirmation.round_id.nonce < self.state.round.round_id.nonce {
            let Some(epoch) = self
                .state
                .epochs
                .iter()
                .find(|epoch| epoch.nonce == confirmation.round_id.nonce)
            else {
                return Err(BlossomError::WireProtocol(
                    "HA confirmation targets an unknown stale epoch".to_string(),
                ));
            };
            if epoch.candidate.digest != confirmation.candidate.digest {
                return Err(BlossomError::WireProtocol(
                    "stale HA confirmation conflicts with finalized candidate".to_string(),
                ));
            }
            return Ok(HaRuntimeEvent::Confirmed);
        }
        let sender = confirmation.sender;
        let candidate_digest = confirmation.candidate.digest;
        self.state
            .round
            .receive_confirmation(&self.state.members, confirmation)?;
        self.telemetry.record(
            self.telemetry_event("confirm", "confirmation_received")
                .with_outcome("ok")
                .with_field("sender_slot", sender.0.to_string())
                .with_field("candidate_digest", candidate_digest.to_string()),
        );
        match self.commit_finalized_round()? {
            Some(epoch) => Ok(HaRuntimeEvent::Finalized(Box::new(epoch))),
            // Peer confirmations can be retransmitted. Persisting each partial
            // count would add O(N²) fsyncs without strengthening safety.
            None => Ok(HaRuntimeEvent::Confirmed),
        }
    }

    pub fn receive_message(&mut self, message: HaMessage) -> Result<HaRuntimeEvent> {
        match message {
            HaMessage::Handshake(message) => {
                self.validate_handshake(&message)?;
                Ok(HaRuntimeEvent::HandshakeAccepted)
            }
            HaMessage::MembershipVote(message) => self.receive_membership_vote(message),
            HaMessage::Dispatch(message) => self.receive_dispatch(message),
            HaMessage::Acknowledge(message) => self.receive_acknowledgement(message),
            HaMessage::Confirm(message) => self.receive_confirmation(message),
        }
    }

    fn commit_finalized_round(&mut self) -> Result<Option<HaEpoch>> {
        let Some(finalized) = self.state.round.finalized.clone() else {
            return Ok(None);
        };
        let mut committed_amendments = Vec::new();
        for slot in finalized.ordered_slots.as_slice() {
            let block = self.state.round.blocks[usize::from(*slot)]
                .as_ref()
                .ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "finalized HA amendment scan is missing a candidate block".to_string(),
                    )
                })?;
            for transaction in &block.body.txs {
                if let Some(amendment) = decode_amendment_transaction(transaction)? {
                    self.validate_proposed_amendment(&amendment, finalized.round_id.nonce)?;
                    let amendment_hash = amendment.hash()?;
                    if let Some(existing) =
                        committed_amendments
                            .iter()
                            .find(|existing: &&AmendmentRecord| {
                                existing.command_identity == amendment.command_identity
                            })
                    {
                        if existing.hash()? != amendment_hash {
                            return Err(BlossomError::InvalidConfiguration(
                                "conflicting HA amendments for one command identity".to_string(),
                            ));
                        }
                    } else {
                        committed_amendments.push(amendment);
                    }
                }
            }
        }
        let epoch =
            HaEpoch::from_finalized(finalized, &self.state.round.blocks, self.state.parameters);
        let next_id = HaRoundId {
            group_id: self.state.group_id,
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            membership_generation: self.state.membership_generation,
            active_mask: self.state.members.active_mask(),
            parameters_hash: self.state.parameters.hash(),
            previous_epoch_hash: epoch.hash,
            previous_epoch_nonce: epoch.nonce,
            nonce: epoch.nonce.new_next(),
            round: 0,
        };
        let next_round = HaRoundState::new(next_id, &self.state.members)?;
        let previous_presence = self.state.presence.clone();
        let previous_epoch_count = self.state.epochs.len();
        let previous_amendment_count = self.state.amendments.len();
        self.state.presence.observe_epoch(
            &self.state.members,
            epoch.presence_mask,
            epoch.nonce,
            self.state.parameters,
        );
        self.state.epochs.push(epoch.clone());
        for amendment in committed_amendments {
            if !self
                .state
                .amendments
                .iter()
                .any(|existing| existing.command_identity == amendment.command_identity)
            {
                self.state.amendments.push(amendment);
            }
        }
        let previous_round = std::mem::replace(&mut self.state.round, next_round);
        if let Err(error) = self.persist() {
            self.state.round = previous_round;
            self.state.presence = previous_presence;
            self.state.epochs.truncate(previous_epoch_count);
            self.state.amendments.truncate(previous_amendment_count);
            return Err(error);
        }
        self.telemetry.record(
            self.telemetry_event("finality", "epoch_finalized")
                .with_outcome("ok")
                .with_target(epoch.hash, epoch.nonce)
                .with_field("candidate_digest", epoch.candidate.digest.to_string())
                .with_field("included_slots", epoch.candidate.included_mask.to_string())
                .with_field("presence_mask", epoch.presence_mask.to_string())
                .with_field("confirmation_mask", epoch.confirmation_mask.to_string()),
        );
        let sealed = self.sealed_watermark();
        if sealed.position > 0 {
            self.telemetry.record(
                self.telemetry_event("seal", "sealed_watermark_observed")
                    .with_outcome("ok")
                    .with_field("watermark", sealed.position.to_string()),
            );
        }
        self.record_operational_status();
        Ok(Some(epoch))
    }

    pub fn append_amendment(&mut self, amendment: AmendmentRecord) -> Result<StateRevision> {
        self.state.validate_new_amendment(&amendment)?;
        let incoming_hash = amendment.hash()?;
        let target_epoch_nonce = amendment.target_epoch_nonce;
        let containing_epoch = self
            .state
            .epochs
            .iter()
            .find(|epoch| epoch.nonce == amendment.containing_epoch_nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "HA amendment containing epoch is not committed".to_string(),
                )
            })?;
        let mut committed = false;
        for (_, block) in containing_epoch.ordered_blocks() {
            for transaction in &block.body.txs {
                if decode_amendment_transaction(transaction)?
                    .as_ref()
                    .is_some_and(|candidate| candidate.hash().ok() == Some(incoming_hash))
                {
                    committed = true;
                }
            }
        }
        if !committed {
            return Err(BlossomError::InvalidConfiguration(
                "HA amendment bytes are not committed by the containing epoch".to_string(),
            ));
        }
        for existing in &self.state.amendments {
            if existing.command_identity == amendment.command_identity {
                if existing.hash()? == incoming_hash {
                    return self.revision();
                }
                return Err(BlossomError::InvalidConfiguration(
                    "conflicting HA amendment bytes for one command identity".to_string(),
                ));
            }
        }
        self.state.amendments.push(amendment);
        if let Err(error) = self.persist() {
            self.state.amendments.pop();
            return Err(error);
        }
        let revision = self.revision()?;
        self.telemetry.record(
            self.telemetry_event("apply", "amendment_applied")
                .with_outcome("ok")
                .with_field("target_nonce", target_epoch_nonce.to_string())
                .with_field("amendment_hash", incoming_hash.to_string())
                .with_field("revision_hash", revision.revision_hash.to_string()),
        );
        Ok(revision)
    }

    pub fn amendment_transaction(
        &self,
        amendment: &AmendmentRecord,
    ) -> Result<crate::block::Transaction> {
        self.validate_proposed_amendment(amendment, self.state.round.round_id.nonce)?;
        encode_amendment_transaction(amendment)
    }

    pub fn amendments_for_epoch(&self, nonce: Nonce) -> Vec<&AmendmentRecord> {
        let mut amendments = self
            .state
            .amendments
            .iter()
            .filter(|amendment| amendment.target_epoch_nonce == nonce)
            .collect::<Vec<_>>();
        amendments.sort_by_key(|amendment| amendment.hash().unwrap_or_default());
        amendments
    }

    pub fn logical_epoch_record_hashes(&self, nonce: Nonce) -> Result<Vec<HashType>> {
        let epoch = self
            .state
            .epochs
            .iter()
            .find(|epoch| epoch.nonce == nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration("unknown HA epoch nonce".to_string())
            })?;
        let mut hashes = epoch
            .ordered_slots
            .as_slice()
            .iter()
            .map(|slot| epoch.candidate.block_hashes[usize::from(*slot)])
            .collect::<Vec<_>>();
        for amendment in self.amendments_for_epoch(nonce) {
            hashes.push(amendment.hash()?);
        }
        hashes.sort_unstable();
        Ok(hashes)
    }

    pub fn revision(&self) -> Result<StateRevision> {
        let mut hashes = Vec::new();
        for epoch in &self.state.epochs {
            hashes.extend(self.logical_epoch_record_hashes(epoch.nonce)?);
        }
        Ok(StateRevision::from_epoch_hashes(
            Watermark {
                position: self.head().nonce.value(),
            },
            self.sealed_watermark(),
            hashes,
        ))
    }

    pub fn node_status(&self, slot: HaMemberSlot) -> NodeAvailabilityStatus {
        self.state.presence.status(slot)
    }

    fn validate_amendment_transactions(
        &self,
        transactions: &[crate::block::Transaction],
        containing_nonce: Nonce,
    ) -> Result<()> {
        let mut proposed: Vec<AmendmentRecord> = Vec::new();
        for transaction in transactions {
            let Some(amendment) = decode_amendment_transaction(transaction)? else {
                continue;
            };
            self.validate_proposed_amendment(&amendment, containing_nonce)?;
            let incoming_hash = amendment.hash()?;
            if let Some(existing) = proposed
                .iter()
                .find(|existing| existing.command_identity == amendment.command_identity)
            {
                if existing.hash()? != incoming_hash {
                    return Err(BlossomError::InvalidConfiguration(
                        "conflicting HA amendments for one command identity".to_string(),
                    ));
                }
            } else {
                proposed.push(amendment);
            }
        }
        Ok(())
    }

    fn validate_proposed_amendment(
        &self,
        amendment: &AmendmentRecord,
        containing_nonce: Nonce,
    ) -> Result<()> {
        if amendment.containing_epoch_nonce != containing_nonce
            || amendment.containing_epoch_nonce <= amendment.target_epoch_nonce
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA amendment must name the later epoch that carries its bytes".to_string(),
            ));
        }
        if self.state.members.member(amendment.origin_slot).is_none() {
            return Err(BlossomError::UnknownSender);
        }
        let target = self
            .state
            .epochs
            .iter()
            .find(|epoch| epoch.nonce == amendment.target_epoch_nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "HA amendment target epoch is not in the local chain".to_string(),
                )
            })?;
        if target.hash != amendment.target_epoch_hash {
            return Err(BlossomError::WireProtocol(
                "HA amendment target hash mismatch".to_string(),
            ));
        }
        if matches!(
            epoch_lifecycle(
                amendment.target_epoch_nonce,
                self.head().nonce,
                self.state.parameters.mutable_epoch_depth,
            ),
            EpochLifecycle::Sealed
        ) {
            return Err(BlossomError::EpochSealed {
                target: amendment.target_epoch_nonce,
                sealed: self.state.sealed_nonce(),
                writable: containing_nonce,
            });
        }
        for existing in &self.state.amendments {
            if existing.command_identity == amendment.command_identity
                && existing.hash()? != amendment.hash()?
            {
                return Err(BlossomError::InvalidConfiguration(
                    "conflicting HA amendment bytes for one command identity".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn vote_to_suspend(
        &mut self,
        slot: HaMemberSlot,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.require_epoch_boundary_for_membership_change()?;
        let proposal = HaMembershipProposal::new(
            self.state.group_id,
            self.state.membership_generation,
            self.state.members.active_mask(),
            self.parameters_hash(),
            self.state.round.round_id.nonce,
            slot,
            HaMembershipAction::Suspend,
        );
        self.cast_membership_vote(proposal)
    }

    pub fn vote_to_reactivate(
        &mut self,
        slot: HaMemberSlot,
        caught_up_through: Nonce,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.require_epoch_boundary_for_membership_change()?;
        let proposal = HaMembershipProposal::new(
            self.state.group_id,
            self.state.membership_generation,
            self.state.members.active_mask(),
            self.parameters_hash(),
            self.state.round.round_id.nonce,
            slot,
            HaMembershipAction::Reactivate { caught_up_through },
        );
        self.cast_membership_vote(proposal)
    }

    fn cast_membership_vote(
        &mut self,
        proposal: HaMembershipProposal,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.validate_membership_proposal(&proposal)?;
        if let Some(locked) = self.state.membership_vote_lock
            && locked != proposal.digest
        {
            return Err(BlossomError::WireProtocol(
                "HA member already voted for a conflicting membership change".to_string(),
            ));
        }
        let previous_vote_lock = self.state.membership_vote_lock;
        let previous_votes = self.state.membership_votes;
        let sender = self.state.self_slot;
        self.state.membership_vote_lock = Some(proposal.digest);
        self.state.membership_votes[sender.index()] = Some(proposal.digest);
        let vote = HaMembershipVote { proposal, sender };
        let certificate = match self.try_commit_membership_proposal(proposal) {
            Ok(certificate) => certificate,
            Err(error) => {
                self.state.membership_vote_lock = previous_vote_lock;
                self.state.membership_votes = previous_votes;
                return Err(error);
            }
        };
        if certificate.is_none() {
            // The one-proposal vote lock is durable before the vote may be
            // broadcast on the trusted transport.
            if let Err(error) = self.persist() {
                self.state.membership_vote_lock = previous_vote_lock;
                self.state.membership_votes = previous_votes;
                return Err(error);
            }
        }
        Ok((vote, certificate))
    }

    pub fn receive_membership_vote(&mut self, vote: HaMembershipVote) -> Result<HaRuntimeEvent> {
        if vote.proposal.membership_generation < self.state.membership_generation {
            let certificate = self
                .state
                .membership_changes
                .iter()
                .find(|certificate| certificate.proposal.digest == vote.proposal.digest)
                .copied()
                .ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "stale HA membership vote has no committed certificate".to_string(),
                    )
                })?;
            return Ok(HaRuntimeEvent::MembershipChanged(certificate));
        }
        self.require_epoch_boundary_for_membership_change()?;
        self.validate_membership_proposal(&vote.proposal)?;
        if vote.proposal.active_mask & vote.sender.bit()? == 0 {
            return Err(BlossomError::UnknownSender);
        }
        let sender_index = vote.sender.index();
        if let Some(existing) = self.state.membership_votes[sender_index] {
            if existing == vote.proposal.digest {
                return Ok(HaRuntimeEvent::MembershipVoteAccepted);
            }
            return Err(BlossomError::WireProtocol(
                "HA member sent conflicting membership votes".to_string(),
            ));
        }
        let previous_vote_lock = self.state.membership_vote_lock;
        let previous_votes = self.state.membership_votes;
        self.state.membership_votes[sender_index] = Some(vote.proposal.digest);
        let certificate = match self.try_commit_membership_proposal(vote.proposal) {
            Ok(certificate) => certificate,
            Err(error) => {
                self.state.membership_vote_lock = previous_vote_lock;
                self.state.membership_votes = previous_votes;
                return Err(error);
            }
        };
        match certificate {
            Some(certificate) => Ok(HaRuntimeEvent::MembershipChanged(certificate)),
            None => Ok(HaRuntimeEvent::MembershipVoteAccepted),
        }
    }

    fn validate_membership_proposal(&self, proposal: &HaMembershipProposal) -> Result<()> {
        if proposal.digest != proposal.compute_digest()
            || proposal.group_id != self.state.group_id
            || proposal.membership_generation != self.state.membership_generation
            || proposal.active_mask != self.state.members.active_mask()
            || proposal.parameters_hash != self.parameters_hash()
            || proposal.effective_nonce != self.state.round.round_id.nonce
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA membership proposal does not match the current epoch boundary".to_string(),
            ));
        }
        match proposal.action {
            HaMembershipAction::Suspend => {
                if self.node_status(proposal.slot) != NodeAvailabilityStatus::Unresponsive {
                    return Err(BlossomError::InvalidConfiguration(
                        "HA member is not yet unresponsive".to_string(),
                    ));
                }
                self.state.members.with_suspended(proposal.slot)?;
            }
            HaMembershipAction::Reactivate { caught_up_through } => {
                if self.state.members.is_active(proposal.slot) {
                    return Err(BlossomError::InvalidConfiguration(
                        "HA member is already active".to_string(),
                    ));
                }
                if caught_up_through < self.head().nonce {
                    return Err(BlossomError::InvalidConfiguration(
                        "HA member must catch up through the current head before reactivation"
                            .to_string(),
                    ));
                }
                self.state.members.with_reactivated(proposal.slot)?;
            }
        }
        Ok(())
    }

    fn try_commit_membership_proposal(
        &mut self,
        proposal: HaMembershipProposal,
    ) -> Result<Option<HaMembershipCertificate>> {
        let mut approval_mask = 0u8;
        for index in 0..MAX_HA_NODES {
            if proposal.active_mask & (1u8 << index) != 0
                && self.state.membership_votes[index] == Some(proposal.digest)
            {
                approval_mask |= 1u8 << index;
            }
        }
        if (approval_mask.count_ones() as usize) < self.state.members.majority() {
            return Ok(None);
        }
        let certificate = HaMembershipCertificate {
            proposal,
            approval_mask,
        };
        self.apply_membership_certificate(certificate)?;
        Ok(Some(certificate))
    }

    fn apply_membership_certificate(&mut self, certificate: HaMembershipCertificate) -> Result<()> {
        self.validate_membership_proposal(&certificate.proposal)?;
        let previous_members = self.state.members.clone();
        let previous_generation = self.state.membership_generation;
        let previous_change_count = self.state.membership_changes.len();
        let previous_vote_lock = self.state.membership_vote_lock;
        let previous_votes = self.state.membership_votes;
        let previous_presence = self.state.presence.clone();
        let previous_round = self.state.round.clone();
        let proposal = certificate.proposal;
        let transition = (|| {
            self.state.members = match proposal.action {
                HaMembershipAction::Suspend => {
                    self.state
                        .presence
                        .mark_suspended(proposal.slot, proposal.effective_nonce);
                    self.state.members.with_suspended(proposal.slot)?
                }
                HaMembershipAction::Reactivate { .. } => {
                    self.state.presence.mark_reactivated(proposal.slot);
                    self.state.members.with_reactivated(proposal.slot)?
                }
            };
            self.state.membership_generation = self
                .state
                .membership_generation
                .checked_add(1)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "HA membership generation overflow".to_string(),
                    )
                })?;
            self.state.membership_changes.push(certificate);
            self.state.membership_vote_lock = None;
            self.state.membership_votes = array::from_fn(|_| None);
            self.retarget_current_round()?;
            self.persist()
        })();
        if let Err(error) = transition {
            self.state.members = previous_members;
            self.state.membership_generation = previous_generation;
            self.state
                .membership_changes
                .truncate(previous_change_count);
            self.state.membership_vote_lock = previous_vote_lock;
            self.state.membership_votes = previous_votes;
            self.state.presence = previous_presence;
            self.state.round = previous_round;
            return Err(error);
        }
        self.telemetry.record(
            self.telemetry_event("membership", "membership_changed")
                .with_outcome("ok")
                .with_field("slot", proposal.slot.0.to_string())
                .with_field("action", format!("{:?}", proposal.action))
                .with_field(
                    "membership_generation",
                    self.state.membership_generation.to_string(),
                )
                .with_field("active_mask", self.state.members.active_mask().to_string()),
        );
        self.record_operational_status();
        Ok(())
    }

    fn require_epoch_boundary_for_membership_change(&self) -> Result<()> {
        let round = &self.state.round;
        if round.received_mask != 0
            || round.acknowledgements.iter().any(|mask| *mask != 0)
            || round.confirmations.iter().any(Option::is_some)
            || round.confirmed_candidate.is_some()
            || round.finalized.is_some()
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA membership changes take effect only at an empty epoch boundary".to_string(),
            ));
        }
        Ok(())
    }

    fn retarget_current_round(&mut self) -> Result<()> {
        let head = self.state.head();
        let round_id = HaRoundId {
            group_id: self.state.group_id,
            fixed_membership_hash: self.state.members.fixed_identity_hash(),
            membership_generation: self.state.membership_generation,
            active_mask: self.state.members.active_mask(),
            parameters_hash: self.state.parameters.hash(),
            previous_epoch_hash: head.hash,
            previous_epoch_nonce: head.nonce,
            nonce: head.nonce.new_next(),
            round: 0,
        };
        self.state.round = HaRoundState::new(round_id, &self.state.members)?;
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        match &self.store {
            Some(store) => store.persist(&self.state),
            // Mutating protocol methods validate their inputs and transitions
            // incrementally. A full history scan here would turn every
            // in-memory Dispatch/Ack/Confirm into work proportional to the
            // retained epoch chain. Durable reload still performs the complete
            // validation before exposing recovered state.
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_book::ServiceKind;
    use crate::block::Transaction;
    use redb::StorageBackend;
    use std::io;
    use std::process::{Child, Command, Stdio};
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    const STORAGE_FAULT_NONE: u8 = 0;
    const STORAGE_FAULT_FULL: u8 = 1;
    const STORAGE_FAULT_SYNC: u8 = 2;

    #[derive(Debug, Clone)]
    struct HaFaultStorage {
        live_bytes: Arc<RwLock<Vec<u8>>>,
        durable_bytes: Arc<RwLock<Vec<u8>>>,
        fault: Arc<AtomicU8>,
    }

    impl HaFaultStorage {
        fn new() -> Self {
            Self {
                live_bytes: Arc::new(RwLock::new(Vec::new())),
                durable_bytes: Arc::new(RwLock::new(Vec::new())),
                fault: Arc::new(AtomicU8::new(STORAGE_FAULT_NONE)),
            }
        }

        fn set_fault(&self, fault: u8) {
            self.fault.store(fault, AtomicOrdering::SeqCst);
        }

        fn backend(&self) -> HaFaultBackend {
            let recovered = self.durable_bytes.read().unwrap().clone();
            *self.live_bytes.write().unwrap() = recovered;
            HaFaultBackend {
                live_bytes: self.live_bytes.clone(),
                durable_bytes: self.durable_bytes.clone(),
                fault: self.fault.clone(),
            }
        }
    }

    #[derive(Debug)]
    struct HaFaultBackend {
        live_bytes: Arc<RwLock<Vec<u8>>>,
        durable_bytes: Arc<RwLock<Vec<u8>>>,
        fault: Arc<AtomicU8>,
    }

    impl HaFaultBackend {
        fn fail_if(&self, expected: u8, message: &'static str) -> io::Result<()> {
            if self.fault.load(AtomicOrdering::SeqCst) == expected {
                let kind = if expected == STORAGE_FAULT_FULL {
                    io::ErrorKind::StorageFull
                } else {
                    io::ErrorKind::Other
                };
                return Err(io::Error::new(kind, message));
            }
            Ok(())
        }
    }

    impl StorageBackend for HaFaultBackend {
        fn len(&self) -> io::Result<u64> {
            Ok(self
                .live_bytes
                .read()
                .map_err(|_| io::Error::other("poisoned HA test storage"))?
                .len() as u64)
        }

        fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            let offset = usize::try_from(offset)
                .map_err(|_| io::Error::other("HA test storage offset overflow"))?;
            let bytes = self
                .live_bytes
                .read()
                .map_err(|_| io::Error::other("poisoned HA test storage"))?;
            let source = bytes
                .get(offset..offset.saturating_add(out.len()))
                .ok_or_else(|| io::Error::other("HA test storage read out of bounds"))?;
            out.copy_from_slice(source);
            Ok(())
        }

        fn set_len(&self, len: u64) -> io::Result<()> {
            self.fail_if(STORAGE_FAULT_FULL, "injected HA ENOSPC")?;
            let len = usize::try_from(len)
                .map_err(|_| io::Error::other("HA test storage length overflow"))?;
            self.live_bytes
                .write()
                .map_err(|_| io::Error::other("poisoned HA test storage"))?
                .resize(len, 0);
            Ok(())
        }

        fn sync_data(&self) -> io::Result<()> {
            self.fail_if(STORAGE_FAULT_SYNC, "injected HA fsync failure")?;
            let live = self
                .live_bytes
                .read()
                .map_err(|_| io::Error::other("poisoned HA test storage"))?
                .clone();
            *self
                .durable_bytes
                .write()
                .map_err(|_| io::Error::other("poisoned HA test storage"))? = live;
            Ok(())
        }

        fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            self.fail_if(STORAGE_FAULT_FULL, "injected HA ENOSPC")?;
            let offset = usize::try_from(offset)
                .map_err(|_| io::Error::other("HA test storage offset overflow"))?;
            let mut bytes = self
                .live_bytes
                .write()
                .map_err(|_| io::Error::other("poisoned HA test storage"))?;
            let destination = bytes
                .get_mut(offset..offset.saturating_add(data.len()))
                .ok_or_else(|| io::Error::other("HA test storage write out of bounds"))?;
            destination.copy_from_slice(data);
            Ok(())
        }
    }

    fn fault_injected_runtime(storage: &HaFaultStorage) -> HighAvailabilityRuntime {
        let database = Database::builder()
            .create_with_backend(storage.backend())
            .unwrap();
        let store = HaDurableStore::from_database(database).unwrap();
        let identities = (0..3u8).map(member).collect::<Vec<_>>();
        HighAvailabilityRuntime::open_store(
            store,
            ConsensusGroupId::named("ha-runtime-test"),
            identities[0].public_key(),
            identities,
            HighAvailabilityParameters::default(),
        )
        .unwrap()
    }

    fn spawn_authenticated_ha_worker(path: &Path, port: u16, key: &HaTransportKey) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "high_availability::tests::authenticated_ha_process_worker",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BLOSSOM_HA_PROCESS_WORKER", "1")
            .env("BLOSSOM_HA_PROCESS_PATH", path)
            .env("BLOSSOM_HA_PROCESS_PORT", port.to_string())
            .env("BLOSSOM_HA_PROCESS_KEY", key.to_hex())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    async fn await_authenticated_worker(
        client: &HighAvailabilityTcpClient,
        service: &Service,
        child: &mut Child,
    ) -> HaNodeStatus {
        let mut last_error = None;
        for _ in 0..200 {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("HA qualification worker exited before readiness: {status}");
            }
            match client.status(service).await {
                Ok(status) => return status,
                Err(error) => last_error = Some(error),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "HA qualification worker did not become ready: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no connection attempt".to_string())
        );
    }

    fn member(index: u8) -> NodeIdentity {
        NodeIdentity::new(
            PubKey([index; 32]),
            None,
            "tcp",
            "127.0.0.1",
            9000 + u16::from(index),
            false,
        )
    }

    fn members(count: usize) -> HaMemberSlots {
        HaMemberSlots::new((0..count as u8).map(member).collect()).unwrap()
    }

    fn round_id(active_mask: u8) -> HaRoundId {
        let member_count = (u8::BITS - active_mask.leading_zeros()) as usize;
        HaRoundId {
            group_id: ConsensusGroupId::named("ha-test"),
            fixed_membership_hash: members(member_count).fixed_identity_hash(),
            membership_generation: 1,
            active_mask,
            parameters_hash: HighAvailabilityParameters::default().hash(),
            previous_epoch_hash: HashType([9; 32]),
            previous_epoch_nonce: Nonce::new(4),
            nonce: Nonce::new(5),
            round: 0,
        }
    }

    fn dispatch(member: &NodeIdentity, slot: u8, target: HaRoundId, label: &str) -> HaDispatch {
        let mut block = Block::default();
        block.body.last_epoch = target.previous_epoch_hash;
        block.body.nonce = target.nonce;
        block.body.txs.push(Transaction::new(label));
        block.seal_unsigned(member.public_key());
        HaDispatch {
            round_id: target,
            sender: HaMemberSlot(slot),
            block_hash: block.hash,
            block,
        }
    }

    fn install_dispatches(states: &mut [HaRoundState], members: &HaMemberSlots, slots: &[u8]) {
        for slot in slots {
            let message = dispatch(
                members.member(HaMemberSlot(*slot)).unwrap(),
                *slot,
                states[0].round_id,
                &format!("block-{slot}"),
            );
            for state in states.iter_mut() {
                assert_eq!(
                    state.receive_dispatch(members, message.clone()).unwrap(),
                    HaDispatchOutcome::Accepted
                );
            }
        }
    }

    fn runtimes(count: usize) -> Vec<HighAvailabilityRuntime> {
        let identities = (0..count as u8).map(member).collect::<Vec<_>>();
        identities
            .iter()
            .map(|identity| {
                HighAvailabilityRuntime::new(
                    ConsensusGroupId::named("ha-runtime-test"),
                    identity.public_key(),
                    identities.clone(),
                    HighAvailabilityParameters::default(),
                )
                .unwrap()
            })
            .collect()
    }

    fn finalize_runtime_epoch(
        runtimes: &mut [HighAvailabilityRuntime],
        participants: &[usize],
        label: &str,
    ) {
        let transaction_sets = participants
            .iter()
            .map(|index| vec![Transaction::new(format!("{label}-{index}"))])
            .collect::<Vec<_>>();
        finalize_runtime_transactions(runtimes, participants, transaction_sets);
    }

    fn finalize_runtime_transactions(
        runtimes: &mut [HighAvailabilityRuntime],
        participants: &[usize],
        transaction_sets: Vec<Vec<Transaction>>,
    ) {
        assert_eq!(participants.len(), transaction_sets.len());
        let mut dispatches = Vec::new();
        for (index, transactions) in participants.iter().zip(transaction_sets) {
            dispatches.push((
                *index,
                runtimes[*index].build_dispatch(transactions).unwrap(),
            ));
        }
        for (sender, dispatch) in &dispatches {
            for receiver in participants {
                if receiver != sender {
                    runtimes[*receiver]
                        .receive_dispatch(dispatch.clone())
                        .unwrap();
                }
            }
        }
        let acknowledgements = participants
            .iter()
            .map(|index| (*index, runtimes[*index].acknowledge().unwrap()))
            .collect::<Vec<_>>();
        for (sender, acknowledgement) in &acknowledgements {
            for receiver in participants {
                if receiver != sender {
                    runtimes[*receiver]
                        .receive_acknowledgement(acknowledgement.clone())
                        .unwrap();
                }
            }
        }
        let confirmations = participants
            .iter()
            .map(|index| (*index, runtimes[*index].confirm().unwrap().0))
            .collect::<Vec<_>>();
        for (sender, confirmation) in &confirmations {
            for receiver in participants.iter().copied() {
                if receiver != *sender {
                    runtimes[receiver]
                        .receive_confirmation(confirmation.clone())
                        .unwrap();
                }
            }
        }
        let head_hash = runtimes[participants[0]].head().hash;
        assert!(
            participants
                .iter()
                .all(|index| runtimes[*index].head().hash == head_hash)
        );
    }

    #[test]
    fn runtime_emits_protocol_and_service_telemetry() {
        let sink = Arc::new(crate::telemetry::InMemoryTelemetrySink::default());
        let telemetry =
            TelemetryHandle::new(sink.clone() as Arc<dyn crate::telemetry::TelemetrySink>);
        let mut nodes = runtimes(3);
        nodes[0].set_telemetry(telemetry);

        finalize_runtime_epoch(&mut nodes, &[0, 1], "telemetry");
        nodes[0].operational_status().unwrap();
        nodes[0].emit_telemetry_failure(
            "transport",
            "ha_connection_failed",
            &BlossomError::Io("injected".to_string()),
        );

        let events = sink.events();
        assert!(events.iter().any(|event| event.event == "dispatch_built"));
        assert!(
            events
                .iter()
                .any(|event| event.event == "acknowledgement_persisted")
        );
        assert!(
            events
                .iter()
                .any(|event| event.event == "confirmation_persisted")
        );
        assert!(events.iter().any(|event| event.event == "epoch_finalized"));
        assert!(events.iter().any(|event| event.event == "ha_status"));
        assert!(events.iter().any(|event| {
            event.event == "ha_connection_failed"
                && event.outcome.as_deref() == Some("error")
                && event.error.as_deref() == Some("io error: injected")
        }));
    }

    fn exchange_acknowledgements(states: &mut [HaRoundState], members: &HaMemberSlots) {
        let mut messages = Vec::new();
        for (index, state) in states.iter_mut().enumerate() {
            messages.push(
                state
                    .acknowledge(members, HaMemberSlot(index as u8))
                    .unwrap(),
            );
        }
        for message in messages {
            for state in states.iter_mut() {
                state
                    .receive_acknowledgement(members, message.clone())
                    .unwrap();
            }
        }
    }

    #[test]
    fn majority_and_fault_tolerance_are_explicit_for_two_through_seven() {
        let expected = [
            (2, 2, 0),
            (3, 2, 1),
            (4, 3, 1),
            (5, 3, 2),
            (6, 4, 2),
            (7, 4, 3),
        ];
        for (nodes, majority, faults) in expected {
            assert_eq!(high_availability_majority(nodes), majority);
            assert_eq!(high_availability_fault_tolerance(nodes), faults);
            assert_eq!(members(nodes).majority(), majority);
        }
    }

    #[test]
    fn membership_is_sorted_into_stable_slots_and_rejects_other_sizes() {
        let slots = HaMemberSlots::new(vec![member(3), member(1), member(2)]).unwrap();
        assert_eq!(
            slots.member(HaMemberSlot(0)).unwrap().public_key(),
            PubKey([1; 32])
        );
        assert_eq!(
            slots.member(HaMemberSlot(2)).unwrap().public_key(),
            PubKey([3; 32])
        );
        assert!(HaMemberSlots::new(vec![member(1)]).is_err());
        assert!(HaMemberSlots::new((0..8).map(member).collect()).is_err());
    }

    #[test]
    fn acknowledgement_masks_are_monotonic() {
        let members = members(3);
        let mut state = HaRoundState::new(round_id(members.active_mask()), &members).unwrap();
        state
            .receive_dispatch(
                &members,
                dispatch(
                    members.member(HaMemberSlot(0)).unwrap(),
                    0,
                    state.round_id,
                    "a",
                ),
            )
            .unwrap();
        let first = state.acknowledge(&members, HaMemberSlot(0)).unwrap();
        let mut retraction = first.clone();
        retraction.received_mask = 0;
        retraction.block_hashes = [HashType::default(); MAX_HA_NODES];
        assert!(state.receive_acknowledgement(&members, retraction).is_err());
    }

    #[test]
    fn three_nodes_finalize_with_two_while_third_is_inactive() {
        let members = members(3);
        let target = round_id(members.active_mask());
        let mut states = vec![
            HaRoundState::new(target, &members).unwrap(),
            HaRoundState::new(target, &members).unwrap(),
        ];
        install_dispatches(&mut states, &members, &[0, 1]);
        exchange_acknowledgements(&mut states, &members);
        let confirmations = vec![
            states[0].confirm(&members, HaMemberSlot(0)).unwrap(),
            states[1].confirm(&members, HaMemberSlot(1)).unwrap(),
        ];
        let mut finalized = None;
        for confirmation in confirmations {
            for state in states.iter_mut() {
                finalized = state
                    .receive_confirmation(&members, confirmation.clone())
                    .unwrap()
                    .or(finalized);
            }
        }
        let finalized = finalized.unwrap();
        assert_eq!(finalized.confirmation_mask.count_ones(), 2);
        assert_eq!(finalized.candidate.included_mask, 0b011);
        assert_eq!(finalized.ordered_slots.len, 2);
    }

    #[test]
    fn majority_confirmed_acknowledgement_certifies_presence_without_a_block() {
        let members = members(3);
        let target = round_id(members.active_mask());
        let mut states = vec![
            HaRoundState::new(target, &members).unwrap(),
            HaRoundState::new(target, &members).unwrap(),
            HaRoundState::new(target, &members).unwrap(),
        ];
        install_dispatches(&mut states, &members, &[0, 1]);
        exchange_acknowledgements(&mut states, &members);
        let confirmations = vec![
            states[0].confirm(&members, HaMemberSlot(0)).unwrap(),
            states[1].confirm(&members, HaMemberSlot(1)).unwrap(),
        ];
        let mut finalized = None;
        for confirmation in confirmations {
            for state in &mut states {
                finalized = state
                    .receive_confirmation(&members, confirmation.clone())
                    .unwrap()
                    .or(finalized);
            }
        }
        let finalized = finalized.unwrap();
        assert_eq!(finalized.candidate.included_mask, 0b011);
        assert_eq!(finalized.presence_mask, 0b111);
    }

    #[test]
    fn dispatch_accepted_after_confirmation_lock_is_late() {
        let members = members(3);
        let target = round_id(members.active_mask());
        let mut states = vec![
            HaRoundState::new(target, &members).unwrap(),
            HaRoundState::new(target, &members).unwrap(),
        ];
        install_dispatches(&mut states, &members, &[0, 1]);
        exchange_acknowledgements(&mut states, &members);
        states[0].confirm(&members, HaMemberSlot(0)).unwrap();
        let late = dispatch(
            members.member(HaMemberSlot(2)).unwrap(),
            2,
            target,
            "late-c",
        );
        assert_eq!(
            states[0].receive_dispatch(&members, late).unwrap(),
            HaDispatchOutcome::Late {
                target_epoch: target.nonce
            }
        );
    }

    #[test]
    fn c_before_confirmation_prevents_ab_candidate() {
        let members = members(3);
        let target = round_id(members.active_mask());
        let mut a = HaRoundState::new(target, &members).unwrap();
        for slot in 0..3 {
            a.receive_dispatch(
                &members,
                dispatch(
                    members.member(HaMemberSlot(slot)).unwrap(),
                    slot,
                    target,
                    &format!("block-{slot}"),
                ),
            )
            .unwrap();
        }
        let candidate_ab =
            HaCandidate::from_round(target, 0b011, 0b011, masked_hashes(0b011, &a.block_hashes));
        let confirm_ab = HaConfirm {
            round_id: target,
            sender: HaMemberSlot(1),
            candidate: candidate_ab,
        };
        assert!(a.receive_confirmation(&members, confirm_ab).is_err());
    }

    #[test]
    fn fixed_array_order_is_hash_sorted_and_deterministic() {
        let target = round_id(0b111);
        let hashes = [
            HashType([3; 32]),
            HashType([1; 32]),
            HashType([2; 32]),
            HashType::default(),
            HashType::default(),
            HashType::default(),
            HashType::default(),
        ];
        let candidate = HaCandidate::from_round(target, 0b111, 0b111, hashes);
        assert_eq!(candidate.ordered_slots().as_slice(), &[1, 2, 0]);
    }

    #[test]
    fn mutable_depth_seals_at_six_successors() {
        assert_eq!(
            epoch_lifecycle(Nonce::new(10), Nonce::new(15), 6),
            EpochLifecycle::Mutable {
                remaining_successors: 1
            }
        );
        assert_eq!(
            epoch_lifecycle(Nonce::new(10), Nonce::new(16), 6),
            EpochLifecycle::Sealed
        );
    }

    #[test]
    fn strict_operation_barrier_waits_for_the_sealed_watermark() {
        let mut nodes = runtimes(3);
        finalize_runtime_epoch(&mut nodes, &[0, 1], "target");
        let required = Watermark { position: 1 };
        assert!(matches!(
            nodes[0].require_sealed(required),
            Err(BlossomError::WatermarkNotSealed {
                required: 1,
                sealed: 0
            })
        ));
        for epoch in 1..=DEFAULT_MUTABLE_EPOCH_DEPTH {
            finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("successor-{epoch}"));
        }
        nodes[0].require_sealed(required).unwrap();
    }

    #[test]
    fn presence_marks_unresponsive_at_configured_depth() {
        let members = members(3);
        let mut tracker = HaPresenceTracker::default();
        for nonce in 1..=6 {
            tracker.observe_epoch(
                &members,
                0b011,
                Nonce::new(nonce),
                HighAvailabilityParameters::default(),
            );
        }
        assert_eq!(
            tracker.status(HaMemberSlot(2)),
            NodeAvailabilityStatus::Unresponsive
        );
        tracker.observe_epoch(
            &members,
            0b111,
            Nonce::new(7),
            HighAvailabilityParameters::default(),
        );
        assert_eq!(
            tracker.status(HaMemberSlot(2)),
            NodeAvailabilityStatus::Active
        );
    }

    #[test]
    fn cannot_suspend_a_two_node_cluster_to_one() {
        let members = members(2);
        assert!(members.with_suspended(HaMemberSlot(1)).is_err());
    }

    #[test]
    fn every_strict_majority_subset_finalizes_for_every_supported_size() {
        for count in MIN_HA_NODES..=MAX_HA_NODES {
            let required = high_availability_majority(count);
            for mask in 1u8..=low_bits(count as u8) {
                if mask.count_ones() as usize != required {
                    continue;
                }
                let participants = (0..count)
                    .filter(|index| mask & (1u8 << index) != 0)
                    .collect::<Vec<_>>();
                let mut nodes = runtimes(count);
                finalize_runtime_epoch(
                    &mut nodes,
                    &participants,
                    &format!("n-{count}-mask-{mask}"),
                );
                let first = participants[0];
                assert_eq!(nodes[first].head().nonce, Nonce::new(1));
                assert_eq!(
                    nodes[first].head().confirmation_mask.count_ones() as usize,
                    required
                );
            }
        }
    }

    #[test]
    fn every_submajority_subset_stops_before_confirmation() {
        for count in MIN_HA_NODES..=MAX_HA_NODES {
            let required = high_availability_majority(count);
            for mask in 1u8..=low_bits(count as u8) {
                if mask.count_ones() as usize >= required {
                    continue;
                }
                let participants = (0..count)
                    .filter(|index| mask & (1u8 << index) != 0)
                    .collect::<Vec<_>>();
                let mut nodes = runtimes(count);
                let dispatches = participants
                    .iter()
                    .map(|index| {
                        (
                            *index,
                            nodes[*index]
                                .build_dispatch(vec![Transaction::new(format!(
                                    "minority-{count}-{mask}-{index}"
                                ))])
                                .unwrap(),
                        )
                    })
                    .collect::<Vec<_>>();
                for (sender, dispatch) in &dispatches {
                    for receiver in &participants {
                        if receiver != sender {
                            nodes[*receiver].receive_dispatch(dispatch.clone()).unwrap();
                        }
                    }
                }
                let acknowledgements = participants
                    .iter()
                    .map(|index| (*index, nodes[*index].acknowledge().unwrap()))
                    .collect::<Vec<_>>();
                for (sender, acknowledgement) in &acknowledgements {
                    for receiver in &participants {
                        if receiver != sender {
                            nodes[*receiver]
                                .receive_acknowledgement(acknowledgement.clone())
                                .unwrap();
                        }
                    }
                }
                for participant in participants {
                    assert!(matches!(
                        nodes[participant].confirm(),
                        Err(BlossomError::FailedConsensus)
                    ));
                    assert_eq!(nodes[participant].head().nonce, Nonce::default());
                }
            }
        }
    }

    #[test]
    fn handshake_and_status_bind_committed_ha_parameters() {
        let nodes = runtimes(3);
        let handshake = nodes[0].handshake();
        nodes[1].validate_handshake(&handshake).unwrap();

        let mut conflicting = handshake;
        conflicting.parameters_hash = HashType::hash(b"different-parameters");
        assert!(matches!(
            nodes[1].validate_handshake(&conflicting),
            Err(BlossomError::InvalidConfiguration(_))
        ));

        let status = nodes[0].status().unwrap();
        assert_eq!(status.parameters, HighAvailabilityParameters::default());
        assert_eq!(status.parameters_hash, status.parameters.hash());
        assert_eq!(status.head_hash, nodes[0].head().hash);
        assert_eq!(
            nodes[0].head().parameters_hash,
            HighAvailabilityParameters::default().hash()
        );
    }

    #[test]
    fn operational_status_is_machine_actionable_across_failure_states() {
        let nodes = runtimes(3);
        let ready = nodes[0].status().unwrap();
        let ready_operational = ready.operational_status();
        assert_eq!(ready_operational.health, HaServiceHealth::Ready);
        assert!(ready_operational.accepts_writes);
        assert_eq!(
            ready_operational.directives,
            vec![HaServiceDirective::Continue]
        );

        let mut degraded = ready.clone();
        degraded.availability[2] = NodeAvailabilityStatus::Missing {
            consecutive_epochs: 1,
        };
        let degraded_operational = degraded.operational_status();
        assert_eq!(degraded_operational.health, HaServiceHealth::Degraded);
        assert!(degraded_operational.accepts_writes);
        assert!(
            degraded_operational
                .directives
                .contains(&HaServiceDirective::NotifyOperators)
        );

        let mut unavailable = degraded.clone();
        unavailable.availability[1] = NodeAvailabilityStatus::Unresponsive;
        let unavailable_operational = unavailable.operational_status();
        assert_eq!(unavailable_operational.health, HaServiceHealth::Unavailable);
        assert!(!unavailable_operational.accepts_writes);
        assert!(
            unavailable_operational
                .directives
                .contains(&HaServiceDirective::NotifyUsers)
        );
        assert!(
            unavailable_operational
                .directives
                .contains(&HaServiceDirective::DrainWrites)
        );
        assert!(
            unavailable_operational
                .directives
                .contains(&HaServiceDirective::AwaitQuorum {
                    required: 2,
                    responsive: 1,
                })
        );

        let mut suspended = ready;
        suspended.active_mask &= !(1u8 << suspended.self_slot.0);
        suspended.availability[suspended.self_slot.index()] = NodeAvailabilityStatus::Suspended {
            since: Nonce::new(9),
        };
        let suspended_operational = suspended.operational_status();
        assert_eq!(suspended_operational.health, HaServiceHealth::Suspended);
        assert!(!suspended_operational.accepts_writes);
        assert!(
            suspended_operational
                .directives
                .contains(&HaServiceDirective::AwaitReactivation)
        );
    }

    #[test]
    fn service_topologies_expose_distinct_write_paths_and_majorities() {
        for nodes in MIN_HA_NODES..=MAX_HA_NODES {
            let active_active = HaServiceTopology::active_active(nodes).unwrap();
            assert_eq!(
                active_active.mode,
                HaReplicationMode::LeaderlessActiveActive
            );
            assert_eq!(active_active.write_route(), HaWriteRoute::AnyActiveMember);
            assert_eq!(usize::from(active_active.physical_nodes), nodes);
            assert_eq!(usize::from(active_active.voting_nodes), nodes);
            assert_eq!(
                usize::from(active_active.required_voters()),
                high_availability_majority(nodes)
            );

            let active_passive = HaServiceTopology::active_passive(nodes, nodes).unwrap();
            assert_eq!(
                active_passive.mode,
                HaReplicationMode::MajorityLeaderActivePassive
            );
            assert_eq!(active_passive.write_route(), HaWriteRoute::CurrentLeader);
            assert_eq!(
                usize::from(active_passive.required_voters()),
                high_availability_majority(nodes)
            );
        }

        assert!(HaServiceTopology::active_active(1).is_err());
        assert!(HaServiceTopology::active_active(8).is_err());
        assert!(HaServiceTopology::active_passive(4, 5).is_err());
        assert!(HaServiceTopology::active_passive(7, 1).is_err());
    }

    #[test]
    fn two_node_loss_is_readable_but_never_write_available() {
        let active_active = HaServiceTopology::active_active(2)
            .unwrap()
            .assess(1, HaLeadershipStatus::NotApplicable)
            .unwrap();
        assert_eq!(active_active.required_voters, 2);
        assert_eq!(active_active.health, HaServiceHealth::Unavailable);
        assert!(!active_active.accepts_writes);
        assert!(active_active.serves_local_reads);
        assert!(
            active_active
                .directives
                .contains(&HaServiceDirective::AwaitQuorum {
                    required: 2,
                    responsive: 1,
                })
        );

        let active_passive = HaServiceTopology::active_passive(2, 2)
            .unwrap()
            .assess(1, HaLeadershipStatus::Elected)
            .unwrap();
        assert_eq!(active_passive.required_voters, 2);
        assert_eq!(active_passive.health, HaServiceHealth::Unavailable);
        assert!(!active_passive.accepts_writes);
        assert!(active_passive.serves_local_reads);
    }

    #[test]
    fn majority_leader_mode_requires_both_quorum_and_an_elected_leader() {
        let topology = HaServiceTopology::active_passive(6, 5).unwrap();
        let electing = topology.assess(5, HaLeadershipStatus::Unavailable).unwrap();
        assert_eq!(electing.required_voters, 3);
        assert!(!electing.accepts_writes);
        assert!(
            electing
                .directives
                .contains(&HaServiceDirective::AwaitLeader)
        );

        let elected = topology.assess(3, HaLeadershipStatus::Elected).unwrap();
        assert_eq!(elected.health, HaServiceHealth::Degraded);
        assert!(elected.accepts_writes);
        assert_eq!(elected.write_route, HaWriteRoute::CurrentLeader);

        assert!(
            topology
                .assess(5, HaLeadershipStatus::NotApplicable)
                .is_err()
        );
        assert!(
            HaServiceTopology::active_active(3)
                .unwrap()
                .assess(3, HaLeadershipStatus::Elected)
                .is_err()
        );
    }

    #[test]
    fn runtime_reports_the_leaderless_active_active_service_contract() {
        let nodes = runtimes(3);
        assert_eq!(
            nodes[0].replication_mode(),
            HaReplicationMode::LeaderlessActiveActive
        );
        assert_eq!(
            nodes[0].service_topology(),
            HaServiceTopology::active_active(3).unwrap()
        );
    }

    #[test]
    fn peer_assessment_drives_catch_up_redeploy_and_quarantine_workflows() {
        let mut nodes = runtimes(3);
        let before = nodes[2].status().unwrap();
        finalize_runtime_epoch(&mut nodes, &[0, 1], "epoch-1");
        let healthy = nodes[0].status().unwrap();

        let behind = before.assess_peer(&healthy);
        assert_eq!(behind.compatibility, HaPeerCompatibility::LocalBehind);
        assert!(
            behind
                .directives
                .contains(&HaServiceDirective::FetchRecoverySnapshot {
                    minimum_head: Nonce::new(1),
                })
        );
        assert!(
            behind
                .directives
                .contains(&HaServiceDirective::RestartOrRedeploy)
        );

        let recovery_snapshot = nodes[0].recovery_snapshot();
        nodes[2]
            .install_recovery_snapshot(recovery_snapshot)
            .unwrap();
        let recovered = nodes[2].status().unwrap();
        assert_eq!(
            recovered.assess_peer(&healthy).compatibility,
            HaPeerCompatibility::Compatible
        );

        let mut divergent = recovered.clone();
        divergent.head_hash = HashType([0xD1; 32]);
        let assessment = healthy.assess_peer(&divergent);
        assert_eq!(assessment.compatibility, HaPeerCompatibility::Diverged);
        assert!(
            assessment
                .directives
                .contains(&HaServiceDirective::QuarantinePeer)
        );
        assert!(
            assessment
                .directives
                .contains(&HaServiceDirective::DrainWrites)
        );
    }

    #[test]
    fn operational_events_report_health_head_and_revision_transitions() {
        let mut nodes = runtimes(3);
        let before = nodes[0].status().unwrap();
        finalize_runtime_epoch(&mut nodes, &[0, 1], "epoch-1");
        let after = nodes[0].status().unwrap();
        let events = after.operational_events_since(&before);

        assert!(events.iter().any(|event| matches!(
            event.kind,
            HaOperationalEventKind::HealthChanged {
                from: HaServiceHealth::Ready,
                to: HaServiceHealth::Degraded,
            }
        )));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            HaOperationalEventKind::HeadAdvanced {
                from,
                to,
            } if from == Nonce::new(0) && to == Nonce::new(1)
        )));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            HaOperationalEventKind::StateRevisionChanged { .. }
        )));
        assert!(events.iter().all(|event| {
            event
                .directives
                .contains(&HaServiceDirective::NotifyOperators)
        }));
    }

    #[test]
    fn broadcast_assessment_detects_quorum_loss_without_waiting_for_an_epoch() {
        let ok = |peer| HaBroadcastReceipt {
            peer: PubKey([peer; 32]),
            response: Ok(HaWireReceipt {
                kind: "acknowledged".to_string(),
                finalized_epoch_hash: None,
                nonce: Nonce::new(4),
            }),
        };
        let failed = |peer| HaBroadcastReceipt {
            peer: PubKey([peer; 32]),
            response: Err(BlossomError::Io("peer unavailable".to_string())),
        };

        let degraded = HaBroadcastReport {
            receipts: vec![ok(1), failed(2)],
        }
        .assess(3)
        .unwrap();
        assert_eq!(degraded.health, HaServiceHealth::Degraded);
        assert_eq!(degraded.responsive_nodes, 2);
        assert!(degraded.quorum_reached);
        assert!(
            degraded
                .directives
                .contains(&HaServiceDirective::NotifyOperators)
        );

        let duplicate_peer = HaBroadcastReport {
            receipts: vec![ok(1), ok(1), failed(2)],
        }
        .assess(3)
        .unwrap();
        assert_eq!(duplicate_peer.attempted_peers, 2);
        assert_eq!(duplicate_peer.responsive_nodes, 2);
        assert_eq!(duplicate_peer.health, HaServiceHealth::Degraded);

        let unavailable = HaBroadcastReport {
            receipts: vec![failed(1), failed(2)],
        }
        .assess(3)
        .unwrap();
        assert_eq!(unavailable.health, HaServiceHealth::Unavailable);
        assert_eq!(unavailable.responsive_nodes, 1);
        assert!(!unavailable.quorum_reached);
        assert!(
            unavailable
                .directives
                .contains(&HaServiceDirective::NotifyUsers)
        );
        assert!(
            unavailable
                .directives
                .contains(&HaServiceDirective::DrainWrites)
        );
    }

    #[tokio::test]
    async fn isolated_tcp_profile_serves_handshake_and_parameter_bound_status() {
        let mut nodes = runtimes(2);
        let peer_handshake = nodes[1].handshake();
        let server_runtime = nodes.remove(0);
        let server_key = server_runtime
            .members()
            .member(server_runtime.self_slot())
            .unwrap()
            .public_key();
        let expected_parameters_hash = server_runtime.parameters_hash();
        let transport_key = HaTransportKey::new([7; HA_TRANSPORT_KEY_BYTES]);
        let client = HighAvailabilityTcpClient::for_runtime(&nodes[0], transport_key.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server =
            HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key).unwrap();
        let task = tokio::spawn(server.serve(listener));
        let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);

        let status = client.status(&service).await.unwrap();
        assert_eq!(status.parameters_hash, expected_parameters_hash);

        let receipt = client
            .send_message(&service, HaMessage::Handshake(peer_handshake))
            .await
            .unwrap();
        assert_eq!(receipt.kind, "handshake_accepted");
        task.abort();
    }

    #[tokio::test]
    async fn ha_transport_rejects_raw_clients_and_wrong_keys() {
        let mut nodes = runtimes(2);
        let server_runtime = nodes.remove(0);
        let server_key = server_runtime
            .members()
            .member(server_runtime.self_slot())
            .unwrap()
            .public_key();
        let transport_key = HaTransportKey::new([11; HA_TRANSPORT_KEY_BYTES]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server =
            HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key).unwrap();
        let task = tokio::spawn(server.serve(listener));
        let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);

        let mut raw_stream = TcpStream::connect(service.socket_addr()).await.unwrap();
        write_frame(&mut raw_stream, &HaWireRequest::Status)
            .await
            .unwrap();
        assert!(
            read_frame::<HaWireResponse, _>(&mut raw_stream)
                .await
                .is_err()
        );

        let wrong_key_client = HighAvailabilityTcpClient::for_runtime(
            &nodes[0],
            HaTransportKey::new([12; HA_TRANSPORT_KEY_BYTES]),
        );
        assert!(wrong_key_client.status(&service).await.is_err());
        task.abort();
    }

    #[tokio::test]
    async fn ha_transport_binds_protocol_sender_to_authenticated_peer() {
        let mut nodes = runtimes(3);
        let spoofed_handshake = nodes[2].handshake();
        let server_runtime = nodes.remove(0);
        let server_key = server_runtime
            .members()
            .member(server_runtime.self_slot())
            .unwrap()
            .public_key();
        let transport_key = HaTransportKey::new([21; HA_TRANSPORT_KEY_BYTES]);
        let client = HighAvailabilityTcpClient::for_runtime(&nodes[0], transport_key.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server =
            HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key).unwrap();
        let task = tokio::spawn(server.serve(listener));
        let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);

        let error = client
            .send_message(&service, HaMessage::Handshake(spoofed_handshake))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("sender does not match authenticated transport peer")
        );
        task.abort();
    }

    #[tokio::test]
    async fn ha_transport_rejects_replayed_session_sequence() {
        let mut nodes = runtimes(2);
        let server_runtime = nodes.remove(0);
        let server_key = server_runtime
            .members()
            .member(server_runtime.self_slot())
            .unwrap()
            .public_key();
        let transport_key = HaTransportKey::new([31; HA_TRANSPORT_KEY_BYTES]);
        let context = HaTransportContext::from_runtime(&nodes[0]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server =
            HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key.clone())
                .unwrap();
        let task = tokio::spawn(server.serve(listener));
        let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);
        let mut connection = HaAuthenticatedConnection::connect(&service, &context, &transport_key)
            .await
            .unwrap();
        let body = HaAuthenticatedRequestBody {
            session_id: connection.session_id,
            sequence: 1,
            request: HaWireRequest::Status,
        };
        let request = HaAuthenticatedRequest {
            mac: ha_transport_mac(&connection.session_key, HA_TRANSPORT_REQUEST_DOMAIN, &body)
                .unwrap(),
            body,
        };

        write_frame(&mut connection.stream, &request).await.unwrap();
        let first: HaAuthenticatedResponse = read_frame(&mut connection.stream).await.unwrap();
        assert_eq!(first.body.sequence, 1);
        verify_ha_transport_mac(
            &connection.session_key,
            HA_TRANSPORT_RESPONSE_DOMAIN,
            &first.body,
            &first.mac,
        )
        .unwrap();

        write_frame(&mut connection.stream, &request).await.unwrap();
        assert!(
            read_frame::<HaAuthenticatedResponse, _>(&mut connection.stream)
                .await
                .is_err()
        );
        task.abort();
    }

    #[tokio::test]
    async fn ha_transport_rejects_frame_modified_after_authentication() {
        let mut nodes = runtimes(2);
        let server_runtime = nodes.remove(0);
        let server_key = server_runtime
            .members()
            .member(server_runtime.self_slot())
            .unwrap()
            .public_key();
        let transport_key = HaTransportKey::new([32; HA_TRANSPORT_KEY_BYTES]);
        let context = HaTransportContext::from_runtime(&nodes[0]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server =
            HighAvailabilityTcpNode::new(server_runtime, Vec::new(), transport_key.clone())
                .unwrap();
        let task = tokio::spawn(server.serve(listener));
        let service = Service::new(ServiceKind::Consensus, server_key, "tcp", "127.0.0.1", port);
        let mut connection = HaAuthenticatedConnection::connect(&service, &context, &transport_key)
            .await
            .unwrap();
        let authenticated_body = HaAuthenticatedRequestBody {
            session_id: connection.session_id,
            sequence: 1,
            request: HaWireRequest::Status,
        };
        let mut request = HaAuthenticatedRequest {
            mac: ha_transport_mac(
                &connection.session_key,
                HA_TRANSPORT_REQUEST_DOMAIN,
                &authenticated_body,
            )
            .unwrap(),
            body: authenticated_body,
        };
        request.body.request = HaWireRequest::Health;

        write_frame(&mut connection.stream, &request).await.unwrap();
        assert!(
            read_frame::<HaAuthenticatedResponse, _>(&mut connection.stream)
                .await
                .is_err()
        );
        task.abort();
    }

    #[test]
    fn authenticated_ha_process_worker() {
        if std::env::var("BLOSSOM_HA_PROCESS_WORKER").as_deref() != Ok("1") {
            return;
        }
        let path = std::env::var_os("BLOSSOM_HA_PROCESS_PATH")
            .map(std::path::PathBuf::from)
            .expect("worker durable path");
        let port = std::env::var("BLOSSOM_HA_PROCESS_PORT")
            .expect("worker port")
            .parse::<u16>()
            .expect("numeric worker port");
        let transport_key = HaTransportKey::from_hex(
            &std::env::var("BLOSSOM_HA_PROCESS_KEY").expect("worker transport key"),
        )
        .unwrap();
        let identities = (0..2u8).map(member).collect::<Vec<_>>();
        let mut runtime = HighAvailabilityRuntime::open(
            &path,
            ConsensusGroupId::named("ha-authenticated-process-qualification"),
            identities[0].public_key(),
            identities,
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        if runtime.current_round().received_mask == 0 {
            runtime
                .build_dispatch_at(vec![Transaction::new("worker-mid-epoch")], 1)
                .unwrap();
            runtime.acknowledge().unwrap();
        }
        let executor = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        executor.block_on(async move {
            let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            let node = HighAvailabilityTcpNode::new(runtime, Vec::new(), transport_key).unwrap();
            node.serve(listener).await.unwrap();
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_transport_and_durable_state_survive_forced_process_restart() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blossom-ha-process-{}-{unique}.redb",
            std::process::id()
        ));
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);

        let identities = (0..2u8).map(member).collect::<Vec<_>>();
        let client_runtime = HighAvailabilityRuntime::new(
            ConsensusGroupId::named("ha-authenticated-process-qualification"),
            identities[1].public_key(),
            identities.clone(),
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        let client_handshake = client_runtime.handshake();
        let transport_key = HaTransportKey::new([41; HA_TRANSPORT_KEY_BYTES]);
        let client = HighAvailabilityTcpClient::for_runtime(&client_runtime, transport_key.clone());
        let service = Service::new(
            ServiceKind::Consensus,
            identities[0].public_key(),
            "tcp",
            "127.0.0.1",
            port,
        );

        let mut first = spawn_authenticated_ha_worker(&path, port, &transport_key);
        let first_status = await_authenticated_worker(&client, &service, &mut first).await;
        assert_eq!(first_status.head_nonce, Nonce::default());
        client
            .send_message(&service, HaMessage::Handshake(client_handshake))
            .await
            .unwrap();
        first.kill().unwrap();
        let first_exit = first.wait().unwrap();
        assert!(!first_exit.success(), "forced worker kill should be abrupt");

        let mut restarted = spawn_authenticated_ha_worker(&path, port, &transport_key);
        let restarted_status = await_authenticated_worker(&client, &service, &mut restarted).await;
        assert_eq!(restarted_status.head_hash, first_status.head_hash);
        assert_eq!(restarted_status.head_nonce, first_status.head_nonce);
        assert_eq!(
            restarted_status.parameters_hash,
            first_status.parameters_hash
        );
        client
            .send_message(&service, HaMessage::Handshake(client_handshake))
            .await
            .unwrap();
        restarted.kill().unwrap();
        restarted.wait().unwrap();
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn ha_transport_key_parsing_and_debug_do_not_expose_secret() {
        let encoded = "ab".repeat(HA_TRANSPORT_KEY_BYTES);
        let key = HaTransportKey::from_hex(&encoded).unwrap();
        assert_eq!(key.to_hex(), encoded);
        assert_eq!(format!("{key:?}"), "HaTransportKey([REDACTED])");
        assert_eq!(
            HaTransportKey::from_hex("abcd").unwrap_err(),
            BlossomError::InvalidLength {
                expected: HA_TRANSPORT_KEY_BYTES,
                actual: 2,
            }
        );
    }

    #[test]
    fn durable_acknowledgement_rolls_back_on_disk_full_and_can_retry() {
        let storage = HaFaultStorage::new();
        let mut runtime = fault_injected_runtime(&storage);
        runtime
            .build_dispatch(vec![Transaction::new("disk-full")])
            .unwrap();
        let self_index = runtime.self_slot().index();
        assert_eq!(runtime.current_round().acknowledgements[self_index], 0);

        storage.set_fault(STORAGE_FAULT_FULL);
        let error = runtime.acknowledge().unwrap_err();
        assert!(error.to_string().contains("injected HA ENOSPC"));
        assert_eq!(runtime.current_round().acknowledgements[self_index], 0);
        assert_eq!(
            assess_high_availability_failure(&error),
            HaFailureAssessment {
                class: HaFailureClass::DurabilityUnavailable,
                health: HaServiceHealth::Unavailable,
                retry_in_process: false,
                directives: vec![
                    HaServiceDirective::NotifyOperators,
                    HaServiceDirective::NotifyUsers,
                    HaServiceDirective::DrainWrites,
                    HaServiceDirective::RestartOrRedeploy,
                ],
            }
        );

        drop(runtime);
        storage.set_fault(STORAGE_FAULT_NONE);
        let mut runtime = fault_injected_runtime(&storage);
        assert_eq!(runtime.current_round().acknowledgements[self_index], 0);
        runtime
            .build_dispatch(vec![Transaction::new("disk-full-retry")])
            .unwrap();
        let acknowledgement = runtime.acknowledge().unwrap();
        assert_ne!(acknowledgement.received_mask, 0);
        assert_eq!(
            runtime.current_round().acknowledgements[self_index],
            acknowledgement.received_mask
        );
    }

    #[test]
    fn durable_acknowledgement_rolls_back_on_fsync_failure_and_can_retry() {
        let storage = HaFaultStorage::new();
        let mut runtime = fault_injected_runtime(&storage);
        runtime
            .build_dispatch(vec![Transaction::new("fsync-failure")])
            .unwrap();
        let self_index = runtime.self_slot().index();

        storage.set_fault(STORAGE_FAULT_SYNC);
        let error = runtime.acknowledge().unwrap_err();
        assert!(error.to_string().contains("injected HA fsync failure"));
        assert_eq!(runtime.current_round().acknowledgements[self_index], 0);

        drop(runtime);
        storage.set_fault(STORAGE_FAULT_NONE);
        let mut runtime = fault_injected_runtime(&storage);
        runtime
            .build_dispatch(vec![Transaction::new("fsync-retry")])
            .unwrap();
        runtime.acknowledge().unwrap();
        assert_ne!(runtime.current_round().acknowledgements[self_index], 0);
    }

    #[test]
    fn finalized_epoch_is_not_applied_until_durable_commit_succeeds() {
        let storage = HaFaultStorage::new();
        let mut durable = fault_injected_runtime(&storage);
        let mut peers = runtimes(3);

        let dispatches = vec![
            durable
                .build_dispatch(vec![Transaction::new("durable")])
                .unwrap(),
            peers[1]
                .build_dispatch(vec![Transaction::new("peer-1")])
                .unwrap(),
            peers[2]
                .build_dispatch(vec![Transaction::new("peer-2")])
                .unwrap(),
        ];
        for dispatch in &dispatches {
            durable.receive_dispatch(dispatch.clone()).unwrap();
            peers[1].receive_dispatch(dispatch.clone()).unwrap();
        }
        let local_acknowledgement = durable.acknowledge().unwrap();
        peers[1]
            .receive_acknowledgement(local_acknowledgement)
            .unwrap();
        let peer_acknowledgement = peers[1].acknowledge().unwrap();
        durable
            .receive_acknowledgement(peer_acknowledgement)
            .unwrap();
        let (local_confirmation, finalized) = durable.confirm().unwrap();
        assert!(finalized.is_none());
        let peer_confirmation = HaConfirm {
            sender: HaMemberSlot(1),
            ..local_confirmation
        };

        storage.set_fault(STORAGE_FAULT_SYNC);
        let error = durable
            .receive_confirmation(peer_confirmation.clone())
            .unwrap_err();
        assert!(error.to_string().contains("injected HA fsync failure"));
        assert_eq!(durable.head().nonce, Nonce::default());
        assert_eq!(durable.current_round().round_id.nonce, Nonce::new(1));

        drop(durable);
        storage.set_fault(STORAGE_FAULT_NONE);
        let mut durable = fault_injected_runtime(&storage);
        assert_eq!(durable.head().nonce, Nonce::default());
        let event = durable.receive_confirmation(peer_confirmation).unwrap();
        assert!(matches!(event, HaRuntimeEvent::Finalized(_)));
        assert_eq!(durable.head().nonce, Nonce::new(1));
    }

    #[test]
    fn durable_confirmation_lock_survives_restart() {
        let identities = vec![member(0), member(1), member(2)];
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blossom-ha-lock-{}-{unique}.redb",
            std::process::id()
        ));
        let group = ConsensusGroupId::named("ha-durable-lock");
        let mut runtime = HighAvailabilityRuntime::open(
            &path,
            group,
            identities[0].public_key(),
            identities.clone(),
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        let local = runtime.build_dispatch(vec![Transaction::new("a")]).unwrap();
        let mut peer_block = Block::default();
        peer_block.body.last_epoch = local.round_id.previous_epoch_hash;
        peer_block.body.nonce = local.round_id.nonce;
        peer_block.body.txs.push(Transaction::new("b"));
        peer_block.seal_unsigned(identities[1].public_key());
        runtime
            .receive_dispatch(HaDispatch {
                round_id: local.round_id,
                sender: HaMemberSlot(1),
                block_hash: peer_block.hash,
                block: peer_block,
            })
            .unwrap();
        let local_ack = runtime.acknowledge().unwrap();
        let peer_ack = HaAcknowledge {
            round_id: local_ack.round_id,
            sender: HaMemberSlot(1),
            received_mask: local_ack.received_mask,
            block_hashes: local_ack.block_hashes,
        };
        runtime.receive_acknowledgement(peer_ack).unwrap();
        let first = runtime.confirm().unwrap().0;
        drop(runtime);

        let mut restored = HighAvailabilityRuntime::open(
            &path,
            group,
            identities[0].public_key(),
            identities,
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        assert_eq!(
            restored.current_round().confirmed_candidate,
            Some(first.candidate.digest)
        );
        let retransmitted = restored.confirm().unwrap().0;
        assert_eq!(retransmitted, first);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn durable_suspension_survives_restart_with_fixed_genesis_identities() {
        let identities = vec![member(0), member(1), member(2)];
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blossom-ha-suspension-{}-{unique}.redb",
            std::process::id()
        ));
        let group = ConsensusGroupId::named("ha-durable-suspension");
        let durable = HighAvailabilityRuntime::open(
            &path,
            group,
            identities[0].public_key(),
            identities.clone(),
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        let mut nodes = vec![
            durable,
            HighAvailabilityRuntime::new(
                group,
                identities[1].public_key(),
                identities.clone(),
                HighAvailabilityParameters::default(),
            )
            .unwrap(),
            HighAvailabilityRuntime::new(
                group,
                identities[2].public_key(),
                identities.clone(),
                HighAvailabilityParameters::default(),
            )
            .unwrap(),
        ];
        for epoch in 1..=DEFAULT_UNRESPONSIVE_EPOCH_DEPTH {
            finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
        }
        let peer_vote = nodes[1].vote_to_suspend(HaMemberSlot(2)).unwrap().0;
        nodes[0].vote_to_suspend(HaMemberSlot(2)).unwrap();
        assert!(matches!(
            nodes[0].receive_membership_vote(peer_vote).unwrap(),
            HaRuntimeEvent::MembershipChanged(_)
        ));
        assert_eq!(nodes[0].members().active_mask(), 0b011);
        drop(nodes);

        let restored = HighAvailabilityRuntime::open(
            &path,
            group,
            identities[0].public_key(),
            identities,
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        assert_eq!(restored.members().active_mask(), 0b011);
        assert_eq!(restored.status().unwrap().membership_generation, 1);
        assert_eq!(
            restored.node_status(HaMemberSlot(2)),
            NodeAvailabilityStatus::Suspended {
                since: Nonce::new(7)
            }
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    #[ignore = "production durability soak; run explicitly with BLOSSOM_HA_SOAK_EPOCHS"]
    fn durable_runtime_survives_thousand_epoch_restart_and_recovery_soak() {
        let epochs = std::env::var("BLOSSOM_HA_SOAK_EPOCHS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1_001);
        assert!(epochs >= 1_001, "production HA soak must run 1,001+ epochs");
        let identities = vec![member(0), member(1), member(2)];
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let paths = (0..3)
            .map(|slot| {
                std::env::temp_dir().join(format!(
                    "blossom-ha-soak-{}-{unique}-{slot}.redb",
                    std::process::id()
                ))
            })
            .collect::<Vec<_>>();
        let group = ConsensusGroupId::named(format!("ha-durable-soak-{unique}"));
        let parameters = HighAvailabilityParameters::default();
        let open_all = || {
            paths
                .iter()
                .enumerate()
                .map(|(slot, path)| {
                    HighAvailabilityRuntime::open(
                        path,
                        group,
                        identities[slot].public_key(),
                        identities.clone(),
                        parameters,
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let mut nodes = open_all();

        for epoch in 1..=epochs {
            if epoch.is_multiple_of(97) {
                let missing = (epoch / 97) % nodes.len();
                let participants = (0..nodes.len())
                    .filter(|slot| *slot != missing)
                    .collect::<Vec<_>>();
                finalize_runtime_epoch(
                    &mut nodes,
                    &participants,
                    &format!("durable-recovery-{epoch}"),
                );
                let snapshot = nodes[participants[0]].recovery_snapshot();
                nodes[missing].install_recovery_snapshot(snapshot).unwrap();
            } else {
                finalize_runtime_epoch(&mut nodes, &[0, 1, 2], &format!("durable-{epoch}"));
            }

            if epoch.is_multiple_of(41) || epoch == epochs {
                let expected_head = nodes[0].head().hash;
                let expected_revision = nodes[0].revision().unwrap();
                drop(nodes);
                nodes = open_all();
                for node in &nodes {
                    assert_eq!(node.head().nonce, Nonce::new(epoch as u64));
                    assert_eq!(node.head().hash, expected_head);
                    assert_eq!(node.revision().unwrap(), expected_revision);
                    node.head().validate(node.members()).unwrap();
                }
            }
        }

        drop(nodes);
        for path in paths {
            std::fs::remove_file(path).ok();
        }
    }

    #[test]
    fn recovery_snapshot_catches_up_only_on_the_existing_finalized_prefix() {
        let mut nodes = runtimes(3);
        for epoch in 1..=3 {
            finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
        }
        let snapshot = nodes[0].recovery_snapshot();
        let expected_revision = nodes[0].revision().unwrap();
        let recovered_revision = nodes[2]
            .install_recovery_snapshot(snapshot.clone())
            .unwrap();
        assert_eq!(nodes[2].head().hash, nodes[0].head().hash);
        assert_eq!(recovered_revision, expected_revision);

        let mut corrupt = snapshot;
        corrupt.epochs.last_mut().unwrap().hash = HashType([0xA5; 32]);
        let identities = (0..3u8).map(member).collect::<Vec<_>>();
        let mut fresh = HighAvailabilityRuntime::new(
            ConsensusGroupId::named("ha-runtime-test"),
            identities[2].public_key(),
            identities,
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        assert!(matches!(
            fresh.install_recovery_snapshot(corrupt),
            Err(BlossomError::WireProtocol(_))
        ));
    }

    #[test]
    fn recovery_snapshot_never_exports_member_secret_keys() {
        let identities = vec![
            NodeIdentity::generate("tcp", "127.0.0.1", 9200),
            NodeIdentity::generate("tcp", "127.0.0.1", 9201),
        ];
        let runtime = HighAvailabilityRuntime::new(
            ConsensusGroupId::named("ha-redacted-recovery"),
            identities[0].public_key(),
            identities.clone(),
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        assert!(
            identities
                .iter()
                .all(|identity| identity.secret_key.is_some())
        );
        let snapshot = runtime.recovery_snapshot();
        assert!((0..snapshot.members.member_count()).all(|index| {
            snapshot
                .members
                .member(HaMemberSlot(index as u8))
                .is_some_and(|member| member.secret_key.is_none())
        }));
    }

    #[test]
    fn amendments_change_provisional_revision_and_are_rejected_after_seal() {
        let mut nodes = runtimes(3);
        finalize_runtime_epoch(&mut nodes, &[0, 1], "epoch-1");
        let target = nodes[0].head().clone();
        let amendment = AmendmentRecord {
            target_epoch_hash: target.hash,
            target_epoch_nonce: target.nonce,
            containing_epoch_nonce: nodes[0].current_round().round_id.nonce,
            origin_slot: HaMemberSlot(2),
            command_identity: CommandIdentity {
                client_id: ClientId([7; 16]),
                client_epoch: ClientEpoch(1),
                sequence: 1,
            },
            supersedes: None,
            payload: AmendmentPayload::Compensation {
                command_bytes: b"late-c".to_vec(),
            },
        };
        let before = nodes[0].revision().unwrap();
        let amendment_transaction = nodes[0].amendment_transaction(&amendment).unwrap();
        finalize_runtime_transactions(
            &mut nodes,
            &[0, 1],
            vec![
                vec![amendment_transaction],
                vec![Transaction::new("epoch-2-node-1")],
            ],
        );
        let after = nodes[0].revision().unwrap();
        assert_ne!(before.revision_hash, after.revision_hash);
        assert_eq!(nodes[0].amendments_for_epoch(target.nonce).len(), 1);
        assert_eq!(nodes[1].amendments_for_epoch(target.nonce).len(), 1);
        for epoch in 3..=7 {
            finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
        }
        assert!(matches!(
            nodes[0].amendment_transaction(&AmendmentRecord {
                containing_epoch_nonce: nodes[0].current_round().round_id.nonce,
                command_identity: CommandIdentity {
                    sequence: 2,
                    ..amendment.command_identity
                },
                ..amendment
            }),
            Err(BlossomError::EpochSealed { .. })
        ));
    }

    #[test]
    fn six_misses_allow_majority_suspension_and_caught_up_reactivation() {
        let mut nodes = runtimes(3);
        for epoch in 1..=6 {
            finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
        }
        assert_eq!(
            nodes[0].node_status(HaMemberSlot(2)),
            NodeAvailabilityStatus::Unresponsive
        );
        let suspend_zero = nodes[0].vote_to_suspend(HaMemberSlot(2)).unwrap().0;
        let suspend_one = nodes[1].vote_to_suspend(HaMemberSlot(2)).unwrap().0;
        assert!(matches!(
            nodes[0].receive_membership_vote(suspend_one).unwrap(),
            HaRuntimeEvent::MembershipChanged(_)
        ));
        assert!(matches!(
            nodes[1].receive_membership_vote(suspend_zero).unwrap(),
            HaRuntimeEvent::MembershipChanged(_)
        ));
        assert_eq!(nodes[0].members().active_mask(), 0b011);
        let head = nodes[0].head().nonce;
        let reactivate_zero = nodes[0]
            .vote_to_reactivate(HaMemberSlot(2), head)
            .unwrap()
            .0;
        let reactivate_one = nodes[1]
            .vote_to_reactivate(HaMemberSlot(2), head)
            .unwrap()
            .0;
        nodes[0].receive_membership_vote(reactivate_one).unwrap();
        nodes[1].receive_membership_vote(reactivate_zero).unwrap();
        assert_eq!(nodes[0].members().active_mask(), 0b111);
        assert_eq!(
            nodes[0].node_status(HaMemberSlot(2)),
            NodeAvailabilityStatus::Active
        );
    }

    #[test]
    fn membership_change_cannot_discard_an_in_progress_round() {
        let mut nodes = runtimes(3);
        for epoch in 1..=6 {
            finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
        }
        nodes[0].build_dispatch(Vec::new()).unwrap();
        assert!(matches!(
            nodes[0].vote_to_suspend(HaMemberSlot(2)),
            Err(BlossomError::InvalidConfiguration(message))
                if message.contains("empty epoch boundary")
        ));
    }
}

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
