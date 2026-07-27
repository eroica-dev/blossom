//! Application-level coordination between independent HA and Global Blossom
//! networks.
//!
//! HA and Global Blossom remain separate consensus domains:
//!
//! - HA finalizes and seals state inside one 2–7 node service group.
//! - Global Blossom orders coordination records across six or more independent
//!   Global Blossom members.
//! - This module converts sealed HA state into immutable references and applies
//!   those references only after Global Blossom finalizes their vertices.
//!
//! HA replicas never become Global Blossom votes through this API. Global
//! Blossom finality never changes HA membership or advances an HA watermark.

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{HashType, ProtocolHasher};
use crate::high_availability::{
    EpochLifecycle, HaEpoch, HaMemberSlot, HaMemberSlots, HighAvailabilityParameters,
    HighAvailabilityRuntime, MIN_HA_NODES, StateRevision, Watermark, high_availability_majority,
};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::trusted_dag::{TrustedCheckpointDag, TrustedDagCheckpoint};

const HA_GROUP_REGISTRATION_DOMAIN: &[u8] = b"blossom/parallel-networks/ha-group-registration/v1";
const HA_GROUP_STATE_REFERENCE_DOMAIN: &[u8] =
    b"blossom/parallel-networks/ha-group-state-reference/v1";
const PARALLEL_NETWORK_EVENT_DOMAIN: &[u8] = b"blossom/parallel-networks/global-event/v1";
const PARALLEL_NETWORK_SNAPSHOT_DOMAIN: &[u8] = b"blossom/parallel-networks/snapshot/v1";

pub const HA_GROUP_STATE_REFERENCE_VERSION: u16 = 1;
pub const PARALLEL_NETWORK_SNAPSHOT_VERSION: u16 = 1;

/// Fixed HA identity and durability parameters registered in Global Blossom.
///
/// Registration does not add these HA replicas to Global Blossom membership.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaGroupRegistration {
    pub coordination_scope: ConsensusGroupId,
    pub ha_group_id: ConsensusGroupId,
    pub members: Vec<PubKey>,
    pub fixed_membership_hash: HashType,
    pub parameters: HighAvailabilityParameters,
    pub parameters_hash: HashType,
    pub hash: HashType,
}

impl HaGroupRegistration {
    pub fn new(
        coordination_scope: ConsensusGroupId,
        ha_group_id: ConsensusGroupId,
        mut members: Vec<PubKey>,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self> {
        parameters.validate()?;
        members.sort_unstable();
        members.dedup();
        let slots = member_slots(&members)?;
        let mut registration = Self {
            coordination_scope,
            ha_group_id,
            members,
            fixed_membership_hash: slots.fixed_identity_hash(),
            parameters,
            parameters_hash: parameters.hash(),
            hash: HashType::default(),
        };
        registration.hash = registration.compute_hash()?;
        registration.validate()?;
        Ok(registration)
    }

    pub fn from_runtime(
        coordination_scope: ConsensusGroupId,
        runtime: &HighAvailabilityRuntime,
    ) -> Result<Self> {
        let members = (0..runtime.members().member_count())
            .map(|index| {
                runtime
                    .members()
                    .member(HaMemberSlot(index as u8))
                    .map(NodeIdentity::public_key)
                    .ok_or(BlossomError::UnknownSender)
            })
            .collect::<Result<Vec<_>>>()?;
        Self::new(
            coordination_scope,
            runtime.head().group_id,
            members,
            runtime.parameters(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.parameters.validate()?;
        if self.members.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(BlossomError::InvalidConfiguration(
                "parallel HA registration members must be unique and public-key sorted".to_string(),
            ));
        }
        let slots = member_slots(&self.members)?;
        if self.fixed_membership_hash != slots.fixed_identity_hash()
            || self.parameters_hash != self.parameters.hash()
            || self.hash != self.compute_hash()?
        {
            return Err(BlossomError::InvalidConfiguration(
                "parallel HA registration commitment mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn member_slots(&self) -> Result<HaMemberSlots> {
        self.validate()?;
        member_slots(&self.members)
    }

    fn validate_epoch(&self, epoch: &HaEpoch) -> Result<()> {
        epoch.validate(&self.member_slots()?)?;
        if epoch.group_id != self.ha_group_id
            || epoch.fixed_membership_hash != self.fixed_membership_hash
            || epoch.parameters != self.parameters
            || epoch.parameters_hash != self.parameters_hash
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA epoch does not belong to its parallel-network registration".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<HashType> {
        protocol_commitment(
            HA_GROUP_REGISTRATION_DOMAIN,
            &(
                self.coordination_scope,
                self.ha_group_id,
                &self.members,
                self.fixed_membership_hash,
                self.parameters,
                self.parameters_hash,
            ),
        )
    }
}

/// Sealed HA state exported for independent ordering by Global Blossom.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaGroupStateReferenceBody {
    pub version: u16,
    pub coordination_scope: ConsensusGroupId,
    pub registration_hash: HashType,
    pub ha_group_id: ConsensusGroupId,
    pub export_sequence: u64,
    pub previous_reference_hash: Option<HashType>,
    pub fixed_membership_hash: HashType,
    pub membership_generation: u64,
    pub active_mask: u8,
    pub parameters_hash: HashType,
    pub sealed_epoch_nonce: Nonce,
    pub sealed_epoch_hash: HashType,
    pub sealing_head_nonce: Nonce,
    pub sealing_head_hash: HashType,
    pub candidate_digest: HashType,
    pub confirmation_mask: u8,
    pub sealed_revision_hash: HashType,
    pub application_state_root: HashType,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct HaGroupStateReference {
    pub hash: HashType,
    pub body: HaGroupStateReferenceBody,
}

impl HaGroupStateReference {
    pub fn from_runtime(
        registration: &HaGroupRegistration,
        runtime: &HighAvailabilityRuntime,
        application_state_root: HashType,
        previous: Option<&Self>,
    ) -> Result<Self> {
        registration.validate()?;
        if HaGroupRegistration::from_runtime(registration.coordination_scope, runtime)?
            != *registration
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA runtime does not match its parallel-network registration".to_string(),
            ));
        }

        let sealed_epoch_nonce = Nonce::new(runtime.sealed_watermark().position);
        if sealed_epoch_nonce == Nonce::default()
            || runtime.lifecycle(sealed_epoch_nonce) != EpochLifecycle::Sealed
        {
            return Err(BlossomError::WatermarkNotSealed {
                required: 1,
                sealed: runtime.sealed_watermark().position,
            });
        }
        let sealed_epoch = runtime
            .epochs()
            .iter()
            .find(|epoch| epoch.nonce == sealed_epoch_nonce)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "HA sealed watermark does not name a retained epoch".to_string(),
                )
            })?;
        registration.validate_epoch(sealed_epoch)?;

        let mut sealed_record_hashes = Vec::new();
        for epoch in runtime
            .epochs()
            .iter()
            .filter(|epoch| epoch.nonce <= sealed_epoch_nonce)
        {
            sealed_record_hashes.extend(runtime.logical_epoch_record_hashes(epoch.nonce)?);
        }
        let sealed_watermark = Watermark {
            position: sealed_epoch_nonce.value(),
        };
        let sealed_revision_hash = StateRevision::from_epoch_hashes(
            sealed_watermark,
            sealed_watermark,
            sealed_record_hashes,
        )
        .revision_hash;
        let (export_sequence, previous_reference_hash) = match previous {
            Some(previous) => {
                previous.validate(registration)?;
                if sealed_epoch_nonce <= previous.body.sealed_epoch_nonce {
                    return Err(BlossomError::InvalidConfiguration(
                        "parallel HA state references must advance the sealed watermark"
                            .to_string(),
                    ));
                }
                (
                    previous
                        .body
                        .export_sequence
                        .checked_add(1)
                        .ok_or_else(|| {
                            BlossomError::InvalidConfiguration(
                                "parallel HA state reference sequence overflow".to_string(),
                            )
                        })?,
                    Some(previous.hash),
                )
            }
            None => (1, None),
        };
        let body = HaGroupStateReferenceBody {
            version: HA_GROUP_STATE_REFERENCE_VERSION,
            coordination_scope: registration.coordination_scope,
            registration_hash: registration.hash,
            ha_group_id: registration.ha_group_id,
            export_sequence,
            previous_reference_hash,
            fixed_membership_hash: sealed_epoch.fixed_membership_hash,
            membership_generation: sealed_epoch.membership_generation,
            active_mask: sealed_epoch.active_mask,
            parameters_hash: sealed_epoch.parameters_hash,
            sealed_epoch_nonce,
            sealed_epoch_hash: sealed_epoch.hash,
            sealing_head_nonce: runtime.head().nonce,
            sealing_head_hash: runtime.head().hash,
            candidate_digest: sealed_epoch.candidate.digest,
            confirmation_mask: sealed_epoch.confirmation_mask,
            sealed_revision_hash,
            application_state_root,
        };
        let reference = Self {
            hash: protocol_commitment(HA_GROUP_STATE_REFERENCE_DOMAIN, &body)?,
            body,
        };
        reference.validate(registration)?;
        Ok(reference)
    }

    pub fn validate(&self, registration: &HaGroupRegistration) -> Result<()> {
        registration.validate()?;
        if self.hash != protocol_commitment(HA_GROUP_STATE_REFERENCE_DOMAIN, &self.body)?
            || self.body.version != HA_GROUP_STATE_REFERENCE_VERSION
            || self.body.coordination_scope != registration.coordination_scope
            || self.body.registration_hash != registration.hash
            || self.body.ha_group_id != registration.ha_group_id
            || self.body.fixed_membership_hash != registration.fixed_membership_hash
            || self.body.parameters_hash != registration.parameters_hash
            || self.body.export_sequence == 0
        {
            return Err(BlossomError::InvalidConfiguration(
                "parallel HA state reference scope or commitment mismatch".to_string(),
            ));
        }
        if (self.body.export_sequence == 1) != self.body.previous_reference_hash.is_none() {
            return Err(BlossomError::InvalidConfiguration(
                "parallel HA state reference linkage does not match its sequence".to_string(),
            ));
        }
        let known_mask = ((1u16 << registration.members.len()) - 1) as u8;
        let active_count = (self.body.active_mask & known_mask).count_ones() as usize;
        if self.body.active_mask & !known_mask != 0
            || active_count < MIN_HA_NODES
            || self.body.confirmation_mask & !self.body.active_mask != 0
            || (self.body.confirmation_mask.count_ones() as usize)
                < high_availability_majority(active_count)
        {
            return Err(BlossomError::InvalidConfiguration(
                "parallel HA state reference lacks a valid HA majority".to_string(),
            ));
        }
        let minimum_sealing_head = self
            .body
            .sealed_epoch_nonce
            .value()
            .checked_add(u64::from(registration.parameters.mutable_epoch_depth))
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "parallel HA state reference sealing depth overflow".to_string(),
                )
            })?;
        if self.body.sealing_head_nonce.value() < minimum_sealing_head {
            return Err(BlossomError::InvalidConfiguration(
                "parallel HA state reference targets a mutable epoch".to_string(),
            ));
        }
        Ok(())
    }
}

/// Application records that Global Blossom may order.
///
/// These records describe HA networks; they do not participate in either
/// network's quorum calculation.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum ParallelNetworkEvent {
    RegisterHaGroup(HaGroupRegistration),
    PublishHaState(Box<HaGroupStateReference>),
}

impl ParallelNetworkEvent {
    pub fn hash(&self) -> Result<HashType> {
        protocol_commitment(PARALLEL_NETWORK_EVENT_DOMAIN, self)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ParallelNetworkStatus {
    pub coordination_scope: ConsensusGroupId,
    pub global_checkpoint_nonce: Option<Nonce>,
    pub global_checkpoint_hash: Option<HashType>,
    pub registered_ha_groups: usize,
    pub ha_groups_with_global_state: usize,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ParallelNetworkSnapshot {
    pub version: u16,
    pub coordination_scope: ConsensusGroupId,
    pub registrations: Vec<HaGroupRegistration>,
    pub state_heads: Vec<HaGroupStateReference>,
    pub global_checkpoint_nonce: Option<Nonce>,
    pub global_checkpoint_hash: Option<HashType>,
    pub hash: HashType,
}

impl ParallelNetworkSnapshot {
    pub fn validate(&self) -> Result<()> {
        if self.version != PARALLEL_NETWORK_SNAPSHOT_VERSION
            || self.global_checkpoint_nonce.is_some() != self.global_checkpoint_hash.is_some()
            || self.hash != self.compute_hash()?
        {
            return Err(BlossomError::InvalidConfiguration(
                "parallel-network snapshot version, checkpoint, or hash mismatch".to_string(),
            ));
        }
        let mut previous_group = None;
        let mut registrations = BTreeMap::new();
        for registration in &self.registrations {
            registration.validate()?;
            if registration.coordination_scope != self.coordination_scope
                || previous_group.is_some_and(|group| group >= registration.ha_group_id)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "parallel-network snapshot registrations are not canonical".to_string(),
                ));
            }
            previous_group = Some(registration.ha_group_id);
            registrations.insert(registration.ha_group_id, registration);
        }
        previous_group = None;
        for reference in &self.state_heads {
            if previous_group.is_some_and(|group| group >= reference.body.ha_group_id) {
                return Err(BlossomError::InvalidConfiguration(
                    "parallel-network snapshot state heads are not canonical".to_string(),
                ));
            }
            let registration = registrations
                .get(&reference.body.ha_group_id)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "parallel-network snapshot state has no registration".to_string(),
                    )
                })?;
            reference.validate(registration)?;
            previous_group = Some(reference.body.ha_group_id);
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<HashType> {
        protocol_commitment(
            PARALLEL_NETWORK_SNAPSHOT_DOMAIN,
            &(
                self.version,
                self.coordination_scope,
                &self.registrations,
                &self.state_heads,
                self.global_checkpoint_nonce,
                self.global_checkpoint_hash,
            ),
        )
    }
}

/// Reducer for HA metadata and state references finalized by an independent
/// Global Blossom network.
#[derive(Debug, Clone)]
pub struct ParallelNetworkCoordinator {
    coordination_scope: ConsensusGroupId,
    registrations: BTreeMap<ConsensusGroupId, HaGroupRegistration>,
    state_heads: BTreeMap<ConsensusGroupId, HaGroupStateReference>,
    global_checkpoint: Option<(Nonce, HashType)>,
}

impl ParallelNetworkCoordinator {
    pub fn new(coordination_scope: ConsensusGroupId) -> Self {
        Self {
            coordination_scope,
            registrations: BTreeMap::new(),
            state_heads: BTreeMap::new(),
            global_checkpoint: None,
        }
    }

    pub fn registration(&self, group_id: ConsensusGroupId) -> Option<&HaGroupRegistration> {
        self.registrations.get(&group_id)
    }

    pub fn state_head(&self, group_id: ConsensusGroupId) -> Option<&HaGroupStateReference> {
        self.state_heads.get(&group_id)
    }

    pub fn status(&self) -> ParallelNetworkStatus {
        ParallelNetworkStatus {
            coordination_scope: self.coordination_scope,
            global_checkpoint_nonce: self.global_checkpoint.map(|(nonce, _)| nonce),
            global_checkpoint_hash: self.global_checkpoint.map(|(_, hash)| hash),
            registered_ha_groups: self.registrations.len(),
            ha_groups_with_global_state: self.state_heads.len(),
        }
    }

    pub fn snapshot(&self) -> Result<ParallelNetworkSnapshot> {
        let mut snapshot = ParallelNetworkSnapshot {
            version: PARALLEL_NETWORK_SNAPSHOT_VERSION,
            coordination_scope: self.coordination_scope,
            registrations: self.registrations.values().cloned().collect(),
            state_heads: self.state_heads.values().cloned().collect(),
            global_checkpoint_nonce: self.global_checkpoint.map(|(nonce, _)| nonce),
            global_checkpoint_hash: self.global_checkpoint.map(|(_, hash)| hash),
            hash: HashType::default(),
        };
        snapshot.hash = snapshot.compute_hash()?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn from_snapshot(snapshot: ParallelNetworkSnapshot) -> Result<Self> {
        snapshot.validate()?;
        let global_checkpoint = snapshot
            .global_checkpoint_nonce
            .zip(snapshot.global_checkpoint_hash);
        Ok(Self {
            coordination_scope: snapshot.coordination_scope,
            registrations: snapshot
                .registrations
                .into_iter()
                .map(|registration| (registration.ha_group_id, registration))
                .collect(),
            state_heads: snapshot
                .state_heads
                .into_iter()
                .map(|reference| (reference.body.ha_group_id, reference))
                .collect(),
            global_checkpoint,
        })
    }

    /// Applies coordination records in the exact order committed by one Global
    /// Blossom checkpoint. The update is transactional: any invalid reference
    /// leaves the previous coordinator state unchanged.
    pub fn apply_global_checkpoint(
        &mut self,
        dag: &TrustedCheckpointDag,
        checkpoint: &TrustedDagCheckpoint,
        ordered_vertices: &[HashType],
        events_by_vertex: &BTreeMap<HashType, ParallelNetworkEvent>,
    ) -> Result<Vec<ParallelNetworkEvent>> {
        checkpoint.validate_hash()?;
        checkpoint.validate_ordered_delta(ordered_vertices)?;
        if checkpoint.body.group_id != self.coordination_scope
            || !dag
                .checkpoints()
                .iter()
                .any(|known| known.hash == checkpoint.hash && known.body == checkpoint.body)
        {
            return Err(BlossomError::InvalidConfiguration(
                "parallel-network event batch is not finalized by the configured Global Blossom network"
                    .to_string(),
            ));
        }
        match self.global_checkpoint {
            Some((previous_nonce, previous_hash))
                if checkpoint.body.previous_checkpoint_nonce != Some(previous_nonce)
                    || checkpoint.body.previous_checkpoint_hash != previous_hash =>
            {
                return Err(BlossomError::InvalidConfiguration(
                    "parallel-network coordinator requires contiguous Global Blossom checkpoints"
                        .to_string(),
                ));
            }
            None if checkpoint.body.nonce != Nonce::new(1)
                || checkpoint.body.previous_checkpoint_nonce != Some(Nonce::default()) =>
            {
                return Err(BlossomError::InvalidConfiguration(
                    "fresh parallel-network coordinator must replay Global Blossom from checkpoint one or restore a snapshot"
                        .to_string(),
                ));
            }
            _ => {}
        }
        let ordered_set = ordered_vertices.iter().copied().collect::<BTreeSet<_>>();
        if events_by_vertex
            .keys()
            .any(|vertex_hash| !ordered_set.contains(vertex_hash))
        {
            return Err(BlossomError::InvalidConfiguration(
                "parallel-network event map contains an unfinalized vertex".to_string(),
            ));
        }

        let mut next = self.clone();
        let mut applied = Vec::new();
        for vertex_hash in ordered_vertices {
            let Some(event) = events_by_vertex.get(vertex_hash) else {
                continue;
            };
            let vertex = dag.vertex(vertex_hash).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "parallel-network event references a missing Global Blossom vertex".to_string(),
                )
            })?;
            if vertex.body.payload_root != event.hash()? {
                return Err(BlossomError::InvalidConfiguration(
                    "parallel-network event does not match its finalized vertex commitment"
                        .to_string(),
                ));
            }
            next.apply_event(event)?;
            applied.push(event.clone());
        }
        next.global_checkpoint = Some((checkpoint.body.nonce, checkpoint.hash));
        *self = next;
        Ok(applied)
    }

    fn apply_event(&mut self, event: &ParallelNetworkEvent) -> Result<()> {
        match event {
            ParallelNetworkEvent::RegisterHaGroup(registration) => {
                registration.validate()?;
                if registration.coordination_scope != self.coordination_scope {
                    return Err(BlossomError::InvalidConfiguration(
                        "HA registration belongs to another Global Blossom coordination scope"
                            .to_string(),
                    ));
                }
                if let Some(existing) = self.registrations.get(&registration.ha_group_id) {
                    if existing != registration {
                        return Err(BlossomError::InvalidConfiguration(
                            "HA group registration cannot replace fixed identities in v1"
                                .to_string(),
                        ));
                    }
                } else {
                    self.registrations
                        .insert(registration.ha_group_id, registration.clone());
                }
            }
            ParallelNetworkEvent::PublishHaState(reference) => {
                let reference = reference.as_ref();
                let registration = self
                    .registrations
                    .get(&reference.body.ha_group_id)
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "HA state was globally ordered before its group registration"
                                .to_string(),
                        )
                    })?;
                reference.validate(registration)?;
                match self.state_heads.get(&reference.body.ha_group_id) {
                    Some(previous) if previous == reference => {}
                    Some(previous)
                        if reference.body.export_sequence
                            == previous.body.export_sequence.saturating_add(1)
                            && reference.body.previous_reference_hash == Some(previous.hash)
                            && reference.body.sealed_epoch_nonce
                                > previous.body.sealed_epoch_nonce =>
                    {
                        self.state_heads
                            .insert(reference.body.ha_group_id, reference.clone());
                    }
                    None if reference.body.export_sequence == 1
                        && reference.body.previous_reference_hash.is_none() =>
                    {
                        self.state_heads
                            .insert(reference.body.ha_group_id, reference.clone());
                    }
                    _ => {
                        return Err(BlossomError::InvalidConfiguration(
                            "HA state references must be globally applied as one contiguous sealed chain"
                                .to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn member_slots(members: &[PubKey]) -> Result<HaMemberSlots> {
    let identities = members
        .iter()
        .copied()
        .map(|public_key| NodeIdentity::new(public_key, None, "trusted", "", 0, false))
        .collect();
    HaMemberSlots::new(identities)
}

fn protocol_commitment<T: BorshSerialize>(domain: &[u8], value: &T) -> Result<HashType> {
    let bytes = borsh::to_vec(value).map_err(|error| {
        BlossomError::InvalidConfiguration(format!(
            "parallel-network commitment encoding failed: {error}"
        ))
    })?;
    let mut hasher = ProtocolHasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Ok(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::{QuorumSize, supermajority_count};
    use crate::block::Transaction;
    use crate::trusted_dag::{
        TrustedDagIngestOutcome, TrustedDagRoundCompletion, TrustedDagVertex, TrustedDagVertexBody,
    };

    fn public_key(value: u16) -> PubKey {
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&value.to_be_bytes());
        PubKey(bytes)
    }

    fn identities(base: u16, count: usize) -> Vec<NodeIdentity> {
        (0..count)
            .map(|offset| {
                NodeIdentity::new(
                    public_key(base + offset as u16),
                    None,
                    "tcp",
                    "127.0.0.1",
                    10_000 + base + offset as u16,
                    false,
                )
            })
            .collect()
    }

    fn ha_runtimes() -> Vec<HighAvailabilityRuntime> {
        let members = identities(100, 3);
        let group_id = ConsensusGroupId::named("parallel-ha");
        members
            .iter()
            .map(|member| {
                HighAvailabilityRuntime::new(
                    group_id,
                    member.public_key(),
                    members.clone(),
                    HighAvailabilityParameters::default(),
                )
                .unwrap()
            })
            .collect()
    }

    fn finalize_ha_epoch(runtimes: &mut [HighAvailabilityRuntime], label: &str) {
        let participants = 0..runtimes.len();
        let dispatches = participants
            .clone()
            .map(|index| {
                (
                    index,
                    runtimes[index]
                        .build_dispatch(vec![Transaction::new(format!("{label}-{index}"))])
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        for (sender, dispatch) in &dispatches {
            for receiver in participants.clone() {
                if receiver != *sender {
                    runtimes[receiver]
                        .receive_dispatch(dispatch.clone())
                        .unwrap();
                }
            }
        }
        let acknowledgements = participants
            .clone()
            .map(|index| (index, runtimes[index].acknowledge().unwrap()))
            .collect::<Vec<_>>();
        for (sender, acknowledgement) in &acknowledgements {
            for receiver in participants.clone() {
                if receiver != *sender {
                    runtimes[receiver]
                        .receive_acknowledgement(acknowledgement.clone())
                        .unwrap();
                }
            }
        }
        let confirmations = participants
            .clone()
            .map(|index| (index, runtimes[index].confirm().unwrap().0))
            .collect::<Vec<_>>();
        for (sender, confirmation) in confirmations {
            for receiver in participants.clone() {
                if receiver != sender {
                    runtimes[receiver]
                        .receive_confirmation(confirmation.clone())
                        .unwrap();
                }
            }
        }
        let head = runtimes[0].head().hash;
        assert!(runtimes.iter().all(|runtime| runtime.head().hash == head));
    }

    fn global_dag(scope: ConsensusGroupId) -> (TrustedCheckpointDag, Vec<PubKey>) {
        let members = (0..6)
            .map(|index| public_key(1_000 + index))
            .collect::<Vec<_>>();
        (
            TrustedCheckpointDag::new(
                members[0],
                members.clone(),
                scope,
                1,
                QuorumSize::new(6).unwrap(),
                false,
            )
            .unwrap(),
            members,
        )
    }

    fn event_vertex(
        dag: &TrustedCheckpointDag,
        origin: PubKey,
        sequence: u64,
        parent: Option<HashType>,
        event: &ParallelNetworkEvent,
    ) -> TrustedDagVertex {
        TrustedDagVertex::new(TrustedDagVertexBody {
            group_id: dag.head().body.group_id,
            membership_generation: dag.head().body.membership_generation,
            origin,
            origin_sequence: sequence,
            origin_parent: parent,
            anchor_checkpoint_hash: dag.head().hash,
            anchor_checkpoint_nonce: dag.head().body.nonce,
            payload_root: event.hash().unwrap(),
            command_count: 1,
            byte_length: borsh::to_vec(event).unwrap().len() as u64,
        })
        .unwrap()
    }

    fn finalize_global_vertex(
        dag: &mut TrustedCheckpointDag,
        vertex: TrustedDagVertex,
    ) -> (TrustedDagCheckpoint, Vec<HashType>) {
        assert!(matches!(
            dag.ingest_vertex(vertex.clone()).unwrap(),
            TrustedDagIngestOutcome::Stored { activated: 1 }
        ));
        let candidate = dag.build_candidate([vertex.hash]).unwrap();
        let expected = dag.expected_round_members(0).unwrap();
        let threshold = supermajority_count(expected.len());
        for member in expected.iter().take(threshold) {
            dag.record_acknowledgement(0, *member, candidate.clone())
                .unwrap();
        }
        let lock = dag.try_lock_round(0).unwrap().unwrap();
        for member in expected.iter().take(threshold) {
            dag.record_confirmation(0, *member, lock.candidate.digest)
                .unwrap();
        }
        match dag.try_complete_round(0).unwrap() {
            TrustedDagRoundCompletion::Finalized {
                checkpoint,
                ordered_vertices,
            } => (*checkpoint, ordered_vertices),
            completion => panic!("single-round global network did not finalize: {completion:?}"),
        }
    }

    #[test]
    fn ha_and_global_memberships_remain_independent() {
        let scope = ConsensusGroupId::named("parallel-global");
        let (mut dag, global_members) = global_dag(scope);
        let runtimes = ha_runtimes();
        let registration = HaGroupRegistration::from_runtime(scope, &runtimes[0]).unwrap();

        let selected = dag.expected_round_members(0).unwrap();
        assert!(
            selected
                .iter()
                .all(|member| global_members.contains(member))
        );
        assert!(
            registration
                .members
                .iter()
                .all(|member| !selected.contains(member))
        );

        let event = ParallelNetworkEvent::RegisterHaGroup(registration.clone());
        let vertex = event_vertex(&dag, global_members[0], 1, None, &event);
        let vertex_hash = vertex.hash;
        let (checkpoint, order) = finalize_global_vertex(&mut dag, vertex);
        let mut events = BTreeMap::new();
        events.insert(vertex_hash, event);
        let mut coordinator = ParallelNetworkCoordinator::new(scope);
        coordinator
            .apply_global_checkpoint(&dag, &checkpoint, &order, &events)
            .unwrap();

        assert_eq!(coordinator.status().registered_ha_groups, 1);
        assert_eq!(coordinator.status().ha_groups_with_global_state, 0);
        assert_eq!(runtimes[0].head().nonce, Nonce::default());
    }

    #[test]
    fn sealed_ha_state_is_ordered_globally_without_cross_advancing_either_network() {
        let scope = ConsensusGroupId::named("parallel-state");
        let (mut dag, global_members) = global_dag(scope);
        let mut runtimes = ha_runtimes();
        let registration = HaGroupRegistration::from_runtime(scope, &runtimes[0]).unwrap();
        let registration_event = ParallelNetworkEvent::RegisterHaGroup(registration.clone());
        let registration_vertex =
            event_vertex(&dag, global_members[0], 1, None, &registration_event);
        let registration_vertex_hash = registration_vertex.hash;
        let (registration_checkpoint, registration_order) =
            finalize_global_vertex(&mut dag, registration_vertex);
        let mut registration_events = BTreeMap::new();
        registration_events.insert(registration_vertex_hash, registration_event);
        let mut coordinator = ParallelNetworkCoordinator::new(scope);
        coordinator
            .apply_global_checkpoint(
                &dag,
                &registration_checkpoint,
                &registration_order,
                &registration_events,
            )
            .unwrap();

        assert!(
            HaGroupStateReference::from_runtime(
                &registration,
                &runtimes[0],
                HashType::hash(b"unsealed"),
                None,
            )
            .is_err()
        );
        for epoch in 0..7 {
            finalize_ha_epoch(&mut runtimes, &format!("ha-{epoch}"));
        }
        let ha_head_before_global = runtimes[0].head().hash;
        let state_reference = HaGroupStateReference::from_runtime(
            &registration,
            &runtimes[0],
            HashType::hash(b"sealed-state"),
            None,
        )
        .unwrap();
        let state_event = ParallelNetworkEvent::PublishHaState(Box::new(state_reference.clone()));
        let state_vertex = event_vertex(
            &dag,
            global_members[0],
            2,
            Some(registration_vertex_hash),
            &state_event,
        );
        let state_vertex_hash = state_vertex.hash;
        let (state_checkpoint, state_order) = finalize_global_vertex(&mut dag, state_vertex);
        let mut state_events = BTreeMap::new();
        state_events.insert(state_vertex_hash, state_event);
        coordinator
            .apply_global_checkpoint(&dag, &state_checkpoint, &state_order, &state_events)
            .unwrap();

        assert_eq!(
            coordinator.state_head(registration.ha_group_id).unwrap(),
            &state_reference
        );
        assert_eq!(coordinator.status().ha_groups_with_global_state, 1);
        assert_eq!(runtimes[0].head().hash, ha_head_before_global);
        assert_eq!(dag.head().body.nonce, Nonce::new(2));

        let encoded = borsh::to_vec(&coordinator.snapshot().unwrap()).unwrap();
        let snapshot = borsh::from_slice::<ParallelNetworkSnapshot>(&encoded).unwrap();
        let restored = ParallelNetworkCoordinator::from_snapshot(snapshot.clone()).unwrap();
        assert_eq!(restored.status(), coordinator.status());
        assert_eq!(
            restored.state_head(registration.ha_group_id),
            coordinator.state_head(registration.ha_group_id)
        );

        let mut corrupted = snapshot;
        corrupted.hash = HashType::hash(b"corrupt");
        assert!(ParallelNetworkCoordinator::from_snapshot(corrupted).is_err());
    }

    #[test]
    fn globally_ordered_state_without_registration_is_rejected_transactionally() {
        let scope = ConsensusGroupId::named("parallel-invalid");
        let (mut dag, global_members) = global_dag(scope);
        let mut runtimes = ha_runtimes();
        let registration = HaGroupRegistration::from_runtime(scope, &runtimes[0]).unwrap();
        for epoch in 0..7 {
            finalize_ha_epoch(&mut runtimes, &format!("ha-{epoch}"));
        }
        let reference = HaGroupStateReference::from_runtime(
            &registration,
            &runtimes[0],
            HashType::hash(b"state"),
            None,
        )
        .unwrap();
        let event = ParallelNetworkEvent::PublishHaState(Box::new(reference));
        let vertex = event_vertex(&dag, global_members[0], 1, None, &event);
        let vertex_hash = vertex.hash;
        let (checkpoint, order) = finalize_global_vertex(&mut dag, vertex);
        let mut events = BTreeMap::new();
        events.insert(vertex_hash, event);
        let mut coordinator = ParallelNetworkCoordinator::new(scope);

        assert!(
            coordinator
                .apply_global_checkpoint(&dag, &checkpoint, &order, &events)
                .is_err()
        );
        assert_eq!(coordinator.status().registered_ha_groups, 0);
        assert_eq!(coordinator.status().global_checkpoint_nonce, None);
    }

    #[test]
    fn thousand_reference_fault_soak_preserves_parallel_prefixes() {
        let scope = ConsensusGroupId::named("parallel-1001-soak");
        let (mut dag, global_members) = global_dag(scope);
        let mut runtimes = ha_runtimes();
        let registration = HaGroupRegistration::from_runtime(scope, &runtimes[0]).unwrap();
        let registration_event = ParallelNetworkEvent::RegisterHaGroup(registration.clone());
        let registration_vertex =
            event_vertex(&dag, global_members[0], 1, None, &registration_event);
        let mut global_parent = registration_vertex.hash;
        let (registration_checkpoint, registration_order) =
            finalize_global_vertex(&mut dag, registration_vertex);
        let mut registration_events = BTreeMap::new();
        registration_events.insert(global_parent, registration_event.clone());
        let mut coordinator = ParallelNetworkCoordinator::new(scope);
        coordinator
            .apply_global_checkpoint(
                &dag,
                &registration_checkpoint,
                &registration_order,
                &registration_events,
            )
            .unwrap();

        for epoch in 0..7 {
            finalize_ha_epoch(&mut runtimes, &format!("warmup-{epoch}"));
        }
        let mut previous_reference = None;
        for sequence in 1..=1_001u64 {
            let reference = HaGroupStateReference::from_runtime(
                &registration,
                &runtimes[0],
                HashType::hash(&sequence.to_le_bytes()),
                previous_reference.as_ref(),
            )
            .unwrap();
            let event = ParallelNetworkEvent::PublishHaState(Box::new(reference.clone()));
            let vertex = event_vertex(
                &dag,
                global_members[0],
                sequence + 1,
                Some(global_parent),
                &event,
            );
            let vertex_hash = vertex.hash;
            let (checkpoint, order) = finalize_global_vertex(&mut dag, vertex);
            let status_before = coordinator.status();

            if sequence % 97 == 0 {
                let mut wrong_events = BTreeMap::new();
                wrong_events.insert(vertex_hash, registration_event.clone());
                assert!(
                    coordinator
                        .apply_global_checkpoint(&dag, &checkpoint, &order, &wrong_events)
                        .is_err()
                );
                assert_eq!(coordinator.status(), status_before);
            }

            let mut events = BTreeMap::new();
            events.insert(vertex_hash, event);
            coordinator
                .apply_global_checkpoint(&dag, &checkpoint, &order, &events)
                .unwrap();
            assert_eq!(
                coordinator
                    .state_head(registration.ha_group_id)
                    .unwrap()
                    .body
                    .export_sequence,
                sequence
            );

            if sequence % 113 == 0 {
                let committed = coordinator.status();
                assert!(
                    coordinator
                        .apply_global_checkpoint(&dag, &checkpoint, &order, &events)
                        .is_err()
                );
                assert_eq!(coordinator.status(), committed);
            }

            previous_reference = Some(reference);
            global_parent = vertex_hash;
            if sequence < 1_001 {
                finalize_ha_epoch(&mut runtimes, &format!("advance-{sequence}"));
            }
        }

        assert_eq!(runtimes[0].sealed_watermark().position, 1_001);
        assert_eq!(dag.head().body.nonce, Nonce::new(1_002));
        assert_eq!(
            coordinator.status().global_checkpoint_nonce,
            Some(Nonce::new(1_002))
        );
    }
}
