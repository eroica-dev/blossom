//! Committed member capabilities, lifecycle operations, and freshness leases.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::address_book::Service;
use crate::address_book::unix_time_millis;
use crate::algorithm::supermajority_count;
use crate::block::{Block, Transaction};
use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::encounter::EncounterOutcome;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{HashType, ProtocolHasher};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;

const MEMBER_OPERATION_PREFIX: &[u8; 16] = b"BLOSSOM-MEMBER-1";
const MEMBER_SET_HASH_DOMAIN: &[u8] = b"blossom/member-set/v1";
const MEMBERSHIP_LEASE_DOMAIN: &[u8] = b"blossom/membership-lease/v1";
pub const MAX_MEMBERSHIP_LEASE_MILLIS: u64 = 30_000;

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
pub enum MemberCapability {
    Client,
    Relay,
    Validator,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum MemberStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MemberRecord {
    pub identity: NodeIdentity,
    pub capabilities: BTreeSet<MemberCapability>,
    pub generation: u64,
    pub status: MemberStatus,
}

impl MemberRecord {
    pub fn new(
        identity: NodeIdentity,
        capabilities: impl IntoIterator<Item = MemberCapability>,
        generation: u64,
    ) -> Result<Self> {
        if generation == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "member generations start at one".to_string(),
            ));
        }
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty() {
            return Err(BlossomError::InvalidConfiguration(
                "member capabilities cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            identity: identity.public_only(),
            capabilities,
            generation,
            status: MemberStatus::Active,
        })
    }

    pub fn public_key(&self) -> PubKey {
        self.identity.public_key()
    }

    pub fn is_active_with(&self, capability: MemberCapability) -> bool {
        self.status == MemberStatus::Active && self.capabilities.contains(&capability)
    }

    pub fn is_active(&self) -> bool {
        self.status == MemberStatus::Active
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct MemberSet {
    records: BTreeMap<PubKey, MemberRecord>,
}

pub type RelaySet = BTreeMap<PubKey, Service>;

#[derive(Debug, Clone)]
pub struct VerifiedMembershipView {
    pub group_id: ConsensusGroupId,
    pub epoch_hash: HashType,
    pub epoch_nonce: u64,
    /// Signed wall-clock expiry of the installed quorum lease.
    pub lease_expires_at_unix_millis: u64,
    /// Effective monotonic expiry, clamped by any published relay expiry.
    pub valid_until: Instant,
    pub members: Arc<MemberSet>,
    pub relays: Arc<RelaySet>,
}

impl VerifiedMembershipView {
    pub fn is_fresh(&self) -> bool {
        Instant::now() < self.valid_until
    }

    pub fn require_fresh(&self) -> Result<()> {
        if self.is_fresh() {
            Ok(())
        } else {
            Err(BlossomError::ExternalService(
                "verified membership lease expired; forwarding must fail closed".to_string(),
            ))
        }
    }
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
pub struct MembershipLeaseChallenge(pub [u8; 32]);

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipLeaseRequest {
    pub challenge: MembershipLeaseChallenge,
    /// Wall-clock issuance time committed by every validator signature.
    pub issued_at_unix_millis: u64,
    pub valid_for_millis: u64,
}

impl MembershipLeaseRequest {
    pub fn fresh(valid_for_millis: u64) -> Result<Self> {
        if valid_for_millis == 0 || valid_for_millis > MAX_MEMBERSHIP_LEASE_MILLIS {
            return Err(BlossomError::InvalidConfiguration(format!(
                "membership lease duration must be 1..={MAX_MEMBERSHIP_LEASE_MILLIS} milliseconds"
            )));
        }
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        Ok(Self {
            challenge: MembershipLeaseChallenge(challenge),
            issued_at_unix_millis: unix_time_millis(),
            valid_for_millis,
        })
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MembershipLeaseStatement {
    pub group_id: ConsensusGroupId,
    pub epoch_hash: HashType,
    pub epoch_nonce: Nonce,
    pub member_set_hash: HashType,
    pub challenge: MembershipLeaseChallenge,
    pub issued_at_unix_millis: u64,
    pub valid_for_millis: u64,
}

impl MembershipLeaseStatement {
    pub fn expires_at_unix_millis(&self) -> Result<u64> {
        if self.issued_at_unix_millis == 0
            || self.valid_for_millis == 0
            || self.valid_for_millis > MAX_MEMBERSHIP_LEASE_MILLIS
        {
            return Err(BlossomError::FailedConsensus);
        }
        self.issued_at_unix_millis
            .checked_add(self.valid_for_millis)
            .ok_or(BlossomError::FailedConsensus)
    }

    pub fn remaining_validity_at(&self, now_unix_millis: u64) -> Result<u64> {
        let expires_at = self.expires_at_unix_millis()?;
        if expires_at <= now_unix_millis
            || expires_at > now_unix_millis.saturating_add(MAX_MEMBERSHIP_LEASE_MILLIS)
        {
            return Err(BlossomError::FailedConsensus);
        }
        Ok(expires_at - now_unix_millis)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let encoded = borsh::to_vec(self).map_err(|error| {
            BlossomError::WireProtocol(format!("encode membership lease: {error}"))
        })?;
        let mut bytes = Vec::with_capacity(MEMBERSHIP_LEASE_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(MEMBERSHIP_LEASE_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MembershipLeaseVote {
    pub statement: MembershipLeaseStatement,
    pub validator: PubKey,
    pub signature: Signature,
}

impl MembershipLeaseVote {
    pub fn signed(statement: MembershipLeaseStatement, signer: &SecretSigner) -> Result<Self> {
        Ok(Self {
            signature: signer.sign(&statement.signing_bytes()?),
            validator: signer.public_key(),
            statement,
        })
    }

    pub fn verify(&self) -> Result<()> {
        self.signature
            .verify(&self.statement.signing_bytes()?, &self.validator)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct MembershipLeaseCertificate {
    pub statement: MembershipLeaseStatement,
    pub signatures: BTreeMap<PubKey, Signature>,
}

impl MembershipLeaseCertificate {
    pub fn from_votes(
        statement: MembershipLeaseStatement,
        votes: impl IntoIterator<Item = MembershipLeaseVote>,
    ) -> Result<Self> {
        let mut signatures = BTreeMap::new();
        for vote in votes {
            if vote.statement != statement {
                return Err(BlossomError::InvalidConfiguration(
                    "membership lease votes disagree on the statement".to_string(),
                ));
            }
            vote.verify()?;
            if signatures.insert(vote.validator, vote.signature).is_some() {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate membership lease validator".to_string(),
                ));
            }
        }
        Ok(Self {
            statement,
            signatures,
        })
    }

    pub fn verify(&self, validators: &IndexTreeMap<PubKey, NodeIdentity>) -> Result<()> {
        self.statement.remaining_validity_at(unix_time_millis())?;
        if self.signatures.len() < supermajority_count(validators.len()) {
            return Err(BlossomError::FailedConsensus);
        }
        let message = self.statement.signing_bytes()?;
        for (validator, signature) in &self.signatures {
            if !validators.contains_key(validator) {
                return Err(BlossomError::UnknownSender);
            }
            signature.verify(&message, validator)?;
        }
        Ok(())
    }
}

impl MemberSet {
    pub fn from_verifiers(verifiers: &IndexTreeMap<PubKey, NodeIdentity>) -> Self {
        let records = verifiers
            .values()
            .map(|identity| {
                let record = MemberRecord::new(
                    identity.clone(),
                    [MemberCapability::Relay, MemberCapability::Validator],
                    1,
                )
                .expect("validator bootstrap member is valid");
                (record.public_key(), record)
            })
            .collect();
        Self { records }
    }

    pub fn get(&self, public_key: &PubKey) -> Option<&MemberRecord> {
        self.records.get(public_key)
    }

    pub fn values(&self) -> impl Iterator<Item = &MemberRecord> {
        self.records.values()
    }

    pub fn active_with(&self, capability: MemberCapability) -> impl Iterator<Item = &MemberRecord> {
        self.records
            .values()
            .filter(move |record| record.is_active_with(capability))
    }

    pub fn hash(&self) -> Result<HashType> {
        let bytes = borsh::to_vec(self).map_err(|error| {
            BlossomError::WireProtocol(format!("encode committed member set: {error}"))
        })?;
        let mut hasher = ProtocolHasher::new();
        hasher.update(MEMBER_SET_HASH_DOMAIN);
        hasher.update(bytes);
        Ok(hasher.finalize())
    }

    pub fn active_validators(&self) -> IndexTreeMap<PubKey, NodeIdentity> {
        let mut verifiers = IndexTreeMap::new();
        for record in self.active_with(MemberCapability::Validator) {
            verifiers.insert(record.public_key(), record.identity.clone());
        }
        verifiers
    }

    pub fn sync_legacy_validators(&mut self, verifiers: &IndexTreeMap<PubKey, NodeIdentity>) {
        for record in self.records.values_mut() {
            if record.capabilities.contains(&MemberCapability::Validator)
                && !verifiers.contains_key(&record.public_key())
            {
                record.status = MemberStatus::Suspended;
            }
        }
        for identity in verifiers.values() {
            self.records
                .entry(identity.public_key())
                .and_modify(|record| {
                    record.identity = identity.public_only();
                    record.capabilities.insert(MemberCapability::Validator);
                    if record.status != MemberStatus::Revoked {
                        record.status = MemberStatus::Active;
                    }
                })
                .or_insert_with(|| {
                    MemberRecord::new(
                        identity.clone(),
                        [MemberCapability::Relay, MemberCapability::Validator],
                        1,
                    )
                    .expect("legacy validator member is valid")
                });
        }
    }

    /// Validates one operation against this committed registry without
    /// mutating it.
    pub fn validate_operation(&self, operation: &MemberOperation) -> Result<()> {
        let mut candidate = self.clone();
        candidate.apply(operation)
    }

    fn apply(&mut self, operation: &MemberOperation) -> Result<()> {
        match operation {
            MemberOperation::Add(record) => {
                if self.records.contains_key(&record.public_key())
                    || record.status != MemberStatus::Active
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "member add must introduce a new active key".to_string(),
                    ));
                }
                reject_validator_capability_grant(record)?;
                let validated = MemberRecord::new(
                    record.identity.clone(),
                    record.capabilities.iter().copied(),
                    record.generation,
                )?;
                self.records.insert(validated.public_key(), validated);
            }
            MemberOperation::Revoke {
                public_key,
                generation,
            } => {
                let record = self
                    .records
                    .get_mut(public_key)
                    .ok_or(BlossomError::UnknownSender)?;
                require_next_member_generation(record, *generation)?;
                record.generation = *generation;
                record.status = MemberStatus::Revoked;
            }
            MemberOperation::Suspend {
                public_key,
                generation,
            } => {
                let record = self
                    .records
                    .get_mut(public_key)
                    .ok_or(BlossomError::UnknownSender)?;
                require_next_member_generation(record, *generation)?;
                if record.status == MemberStatus::Revoked {
                    return Err(BlossomError::InvalidConfiguration(
                        "revoked member cannot be suspended".to_string(),
                    ));
                }
                record.generation = *generation;
                record.status = MemberStatus::Suspended;
            }
            MemberOperation::RotateKey {
                old_public_key,
                new_record,
            } => {
                if self.records.contains_key(&new_record.public_key()) {
                    return Err(BlossomError::InvalidConfiguration(
                        "member key rotation target already exists".to_string(),
                    ));
                }
                reject_validator_capability_grant(new_record)?;
                let old = self
                    .records
                    .get_mut(old_public_key)
                    .ok_or(BlossomError::UnknownSender)?;
                require_next_member_generation(old, new_record.generation)?;
                let validated = MemberRecord::new(
                    new_record.identity.clone(),
                    new_record.capabilities.iter().copied(),
                    new_record.generation,
                )?;
                old.generation = new_record.generation;
                old.status = MemberStatus::Revoked;
                self.records.insert(validated.public_key(), validated);
            }
        }
        Ok(())
    }
}

fn reject_validator_capability_grant(record: &MemberRecord) -> Result<()> {
    if record.capabilities.contains(&MemberCapability::Validator) {
        return Err(BlossomError::InvalidConfiguration(
            "validator capability can only be granted by certified node-admission evidence"
                .to_string(),
        ));
    }
    Ok(())
}

fn require_next_member_generation(record: &MemberRecord, generation: u64) -> Result<()> {
    if generation != record.generation.saturating_add(1) {
        return Err(BlossomError::InvalidConfiguration(
            "member operation generation is not the next monotonic value".to_string(),
        ));
    }
    Ok(())
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum MemberOperation {
    Add(MemberRecord),
    Revoke {
        public_key: PubKey,
        generation: u64,
    },
    Suspend {
        public_key: PubKey,
        generation: u64,
    },
    RotateKey {
        old_public_key: PubKey,
        new_record: MemberRecord,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommittedMemberOperation {
    pub group_id: ConsensusGroupId,
    pub parent_epoch_hash: HashType,
    pub operation: MemberOperation,
}

impl CommittedMemberOperation {
    pub fn to_transaction(&self) -> Result<Transaction> {
        let encoded = borsh::to_vec(self).map_err(|error| {
            BlossomError::WireProtocol(format!("encode member operation: {error}"))
        })?;
        let mut payload = Vec::with_capacity(MEMBER_OPERATION_PREFIX.len() + encoded.len());
        payload.extend_from_slice(MEMBER_OPERATION_PREFIX);
        payload.extend_from_slice(&encoded);
        Ok(Transaction::new(payload))
    }

    pub fn from_transaction(transaction: &Transaction) -> Result<Option<Self>> {
        let Some(encoded) = transaction
            .payload
            .as_slice()
            .strip_prefix(MEMBER_OPERATION_PREFIX)
        else {
            return Ok(None);
        };
        borsh::from_slice(encoded).map(Some).map_err(|error| {
            BlossomError::WireProtocol(format!("decode member operation: {error}"))
        })
    }
}

pub fn apply_committed_member_operations(
    previous: &MemberSet,
    blocks: &BTreeMap<HashType, Block>,
    group_id: ConsensusGroupId,
    parent_epoch_hash: HashType,
) -> MemberSet {
    let mut next = previous.clone();
    for block in blocks.values() {
        for transaction in &block.body.txs {
            let Ok(Some(operation)) = CommittedMemberOperation::from_transaction(transaction)
            else {
                continue;
            };
            if operation.group_id != group_id || operation.parent_epoch_hash != parent_epoch_hash {
                continue;
            }
            let _ = next.apply(&operation.operation);
        }
    }
    next
}

pub fn apply_epoch_member_registry_transition(
    previous: &MemberSet,
    legacy_verifiers: &IndexTreeMap<PubKey, NodeIdentity>,
    blocks: &BTreeMap<HashType, Block>,
    group_id: ConsensusGroupId,
    parent_epoch_hash: HashType,
) -> (MemberSet, IndexTreeMap<PubKey, NodeIdentity>) {
    let mut baseline = if previous.records.is_empty() {
        MemberSet::from_verifiers(legacy_verifiers)
    } else {
        previous.clone()
    };
    baseline.sync_legacy_validators(legacy_verifiers);
    let next = apply_committed_member_operations(&baseline, blocks, group_id, parent_epoch_hash);
    let validators = next.active_validators();
    if validators.is_empty() {
        (baseline.clone(), baseline.active_validators())
    } else {
        (next, validators)
    }
}

/// Controls deterministic verifier pruning from committed encounter evidence.
///
/// The default is disabled. `required_observers` can make removal stricter,
/// but it is clamped to at least the current verifier-set supermajority.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusNodeRemovalPolicy {
    pub enabled: bool,
    pub min_remaining_verifiers: usize,
    pub max_removals_per_epoch: usize,
    pub required_observers: Option<usize>,
}

impl ConsensusNodeRemovalPolicy {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn supermajority() -> Self {
        Self {
            enabled: true,
            min_remaining_verifiers: 1,
            max_removals_per_epoch: 1,
            required_observers: None,
        }
    }

    pub fn with_min_remaining_verifiers(mut self, min_remaining_verifiers: usize) -> Self {
        self.min_remaining_verifiers = min_remaining_verifiers;
        self
    }

    pub fn with_max_removals_per_epoch(mut self, max_removals_per_epoch: usize) -> Self {
        self.max_removals_per_epoch = max_removals_per_epoch;
        self
    }

    pub fn with_required_observers(mut self, required_observers: usize) -> Self {
        self.required_observers = Some(required_observers);
        self
    }

    pub fn required_observers_for(self, verifier_count: usize) -> usize {
        let supermajority = supermajority_count(verifier_count);
        self.required_observers
            .unwrap_or(supermajority)
            .max(supermajority)
    }
}

impl Default for ConsensusNodeRemovalPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            min_remaining_verifiers: 1,
            max_removals_per_epoch: 1,
            required_observers: None,
        }
    }
}

/// A deterministic decision to remove one verifier at the next epoch boundary.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsensusNodeRemovalDecision {
    pub subject: PubKey,
    pub observer_count: usize,
    pub required_observers: usize,
    pub missing_signature_count: usize,
    pub invalid_signature_count: usize,
}

/// The result of reducing committed encounter records into membership changes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ConsensusNodeRemovalPlan {
    pub decisions: Vec<ConsensusNodeRemovalDecision>,
    pub retained_verifier_count: usize,
}

impl ConsensusNodeRemovalPlan {
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    pub fn removed_subjects(&self) -> impl Iterator<Item = PubKey> + '_ {
        self.decisions.iter().map(|decision| decision.subject)
    }
}

/// The result of reducing committed node-admission records into membership
/// additions.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ConsensusNodeAdmissionPlan {
    pub admitted: Vec<NodeIdentity>,
    pub decisions: Vec<ConsensusNodeAdmissionDecision>,
    pub required_observers: usize,
}

impl ConsensusNodeAdmissionPlan {
    pub fn is_empty(&self) -> bool {
        self.admitted.is_empty()
    }
}

/// A deterministic decision to add one verifier at the next epoch boundary.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsensusNodeAdmissionDecision {
    pub node: NodeIdentity,
    pub admission_hash: HashType,
    pub observer_count: usize,
    pub required_observers: usize,
}

/// Reduces committed epoch blocks into a deterministic node-removal plan.
///
/// Only current verifiers can accuse current verifiers, the encounter record
/// must match the epoch/nonce being finalized, and one observer contributes at
/// most one vote per subject.
pub fn derive_consensus_node_removal_plan(
    verifiers: &IndexTreeMap<PubKey, NodeIdentity>,
    committed_blocks: &BTreeMap<HashType, Block>,
    last_epoch: HashType,
    nonce: Nonce,
    policy: ConsensusNodeRemovalPolicy,
) -> ConsensusNodeRemovalPlan {
    let verifier_count = verifiers.len();
    if !policy.enabled || verifier_count == 0 || policy.max_removals_per_epoch == 0 {
        return ConsensusNodeRemovalPlan {
            decisions: Vec::new(),
            retained_verifier_count: verifier_count,
        };
    }

    let required_observers = policy.required_observers_for(verifier_count);
    if required_observers == 0 {
        return ConsensusNodeRemovalPlan {
            decisions: Vec::new(),
            retained_verifier_count: verifier_count,
        };
    }

    let mut evidence_by_subject: BTreeMap<PubKey, BTreeMap<PubKey, EncounterOutcome>> =
        BTreeMap::new();
    for block in committed_blocks.values() {
        if !verifiers.contains_key(&block.body.validator) {
            continue;
        }

        for record in &block.body.encounter_records {
            let body = &record.body;
            if body.last_epoch != last_epoch
                || body.nonce != nonce
                || body.observer != block.body.validator
                || body.observer == body.subject
                || !verifiers.contains_key(&body.observer)
                || !verifiers.contains_key(&body.subject)
                || record.verify().is_err()
            {
                continue;
            }

            let subject_evidence = evidence_by_subject.entry(body.subject).or_default();
            let observer_evidence = subject_evidence
                .entry(body.observer)
                .or_insert(body.outcome);
            if *observer_evidence == EncounterOutcome::MissingSignature
                && body.outcome == EncounterOutcome::InvalidSignature
            {
                *observer_evidence = EncounterOutcome::InvalidSignature;
            }
        }
    }

    let mut candidates = evidence_by_subject
        .into_iter()
        .filter_map(|(subject, observer_outcomes)| {
            let observer_count = observer_outcomes.len();
            if observer_count < required_observers {
                return None;
            }

            let mut missing_signature_count = 0usize;
            let mut invalid_signature_count = 0usize;
            for outcome in observer_outcomes.values() {
                match outcome {
                    EncounterOutcome::MissingSignature => missing_signature_count += 1,
                    EncounterOutcome::InvalidSignature => invalid_signature_count += 1,
                }
            }

            Some(ConsensusNodeRemovalDecision {
                subject,
                observer_count,
                required_observers,
                missing_signature_count,
                invalid_signature_count,
            })
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        right
            .observer_count
            .cmp(&left.observer_count)
            .then_with(|| {
                right
                    .invalid_signature_count
                    .cmp(&left.invalid_signature_count)
            })
            .then_with(|| left.subject.cmp(&right.subject))
    });

    let removal_budget = verifier_count
        .saturating_sub(policy.min_remaining_verifiers)
        .min(policy.max_removals_per_epoch);
    candidates.truncate(removal_budget);

    ConsensusNodeRemovalPlan {
        retained_verifier_count: verifier_count.saturating_sub(candidates.len()),
        decisions: candidates,
    }
}

/// Reduces committed epoch blocks into a deterministic public-node admission
/// plan.
///
/// Only blocks from current verifiers can sponsor admissions, and the same
/// signed admission body must be carried by a distinct-validator supermajority.
/// The joining node must sign an admission body for the exact parent epoch and
/// nonce, and already active verifiers are ignored so a same-epoch drop cannot
/// be undone by a join proof carried in that same block set.
pub fn derive_consensus_node_admission_plan(
    verifiers: &IndexTreeMap<PubKey, NodeIdentity>,
    committed_blocks: &BTreeMap<HashType, Block>,
    last_epoch: HashType,
    nonce: Nonce,
) -> ConsensusNodeAdmissionPlan {
    let required_observers = supermajority_count(verifiers.len());
    if verifiers.is_empty() {
        return ConsensusNodeAdmissionPlan {
            admitted: Vec::new(),
            decisions: Vec::new(),
            required_observers,
        };
    }

    let mut evidence_by_admission = BTreeMap::<HashType, PendingNodeAdmission>::new();
    for block in committed_blocks.values() {
        let observer = block.body.validator;
        if !verifiers.contains_key(&observer) {
            continue;
        }

        let mut observed_in_block = BTreeSet::new();
        for admission in &block.body.node_admissions {
            if admission.body.last_epoch != last_epoch
                || admission.body.nonce != nonce
                || admission.verify().is_err()
            {
                continue;
            }
            let admission_hash = admission.body.hash();
            if !observed_in_block.insert(admission_hash) {
                continue;
            }
            let node = admission.body.node.clone();
            let public_key = node.public_key();
            if verifiers.contains_key(&public_key) {
                continue;
            }
            evidence_by_admission
                .entry(admission_hash)
                .or_insert_with(|| PendingNodeAdmission {
                    node,
                    admission_hash,
                    observers: BTreeSet::new(),
                })
                .observers
                .insert(observer);
        }
    }

    let mut decisions_by_key = BTreeMap::<PubKey, ConsensusNodeAdmissionDecision>::new();
    for pending in evidence_by_admission.into_values() {
        let observer_count = pending.observers.len();
        if observer_count < required_observers {
            continue;
        }

        let decision = ConsensusNodeAdmissionDecision {
            node: pending.node,
            admission_hash: pending.admission_hash,
            observer_count,
            required_observers,
        };
        decisions_by_key
            .entry(decision.node.public_key())
            .and_modify(|existing| {
                if admission_decision_precedes(&decision, existing) {
                    *existing = decision.clone();
                }
            })
            .or_insert(decision);
    }

    let decisions = decisions_by_key.into_values().collect::<Vec<_>>();
    ConsensusNodeAdmissionPlan {
        admitted: decisions
            .iter()
            .map(|decision| decision.node.clone())
            .collect(),
        decisions,
        required_observers,
    }
}

#[derive(Debug, Clone)]
struct PendingNodeAdmission {
    node: NodeIdentity,
    admission_hash: HashType,
    observers: BTreeSet<PubKey>,
}

fn admission_decision_precedes(
    left: &ConsensusNodeAdmissionDecision,
    right: &ConsensusNodeAdmissionDecision,
) -> bool {
    left.observer_count
        .cmp(&right.observer_count)
        .then_with(|| right.admission_hash.cmp(&left.admission_hash))
        .is_gt()
}

/// Applies a previously computed removal plan to a verifier set.
pub fn apply_consensus_node_removal_plan(
    verifiers: &mut IndexTreeMap<PubKey, NodeIdentity>,
    plan: &ConsensusNodeRemovalPlan,
) {
    let mut removed = BTreeSet::new();
    for subject in plan.removed_subjects() {
        if removed.insert(subject) {
            let _ = verifiers.remove(&subject);
        }
    }
}

/// Applies a previously computed admission plan to a verifier set.
pub fn apply_consensus_node_admission_plan(
    verifiers: &mut IndexTreeMap<PubKey, NodeIdentity>,
    plan: &ConsensusNodeAdmissionPlan,
) {
    for node in &plan.admitted {
        verifiers.insert(node.public_key(), node.clone());
    }
}

/// Applies the consensus membership transition for a finalized epoch.
///
/// The caller must pass only the block set that was accepted into the epoch
/// through consensus. This function derives the removal plan from those
/// committed blocks and returns the verifier set for the next epoch.
pub fn apply_epoch_membership_transition(
    verifiers: &IndexTreeMap<PubKey, NodeIdentity>,
    committed_blocks: &BTreeMap<HashType, Block>,
    last_epoch: HashType,
    nonce: Nonce,
    policy: ConsensusNodeRemovalPolicy,
) -> (IndexTreeMap<PubKey, NodeIdentity>, ConsensusNodeRemovalPlan) {
    let plan =
        derive_consensus_node_removal_plan(verifiers, committed_blocks, last_epoch, nonce, policy);
    let mut next_verifiers = verifiers.clone();
    apply_consensus_node_removal_plan(&mut next_verifiers, &plan);
    let admission_plan =
        derive_consensus_node_admission_plan(verifiers, committed_blocks, last_epoch, nonce);
    apply_consensus_node_admission_plan(&mut next_verifiers, &admission_plan);
    (next_verifiers, plan)
}

#[cfg(test)]
mod tests;
