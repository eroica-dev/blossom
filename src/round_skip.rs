//! Certified round skipping, dissemination manifests, and assistance policy.

use std::collections::{BTreeMap, BTreeSet};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::algorithm::{distinct_current_validator_count, has_supermajority, supermajority_count};
use crate::crypto::{PubKey, SecKey, SecretSigner, Signature};
use crate::error::{BlossomError, Result};
use crate::hash::{HashType, ProtocolHasher};
use crate::nonce::Nonce;

const ROUND_SKIP_MANIFEST_HASH_DOMAIN: &[u8] = b"blossom.round-skip.manifest.v1";
const ROUND_SKIP_VOTE_SIGNATURE_DOMAIN: &[u8] = b"blossom.round-skip.vote.v1";

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum FutureRoundAssistKind {
    RoundChangeSkip,
    DataBearing,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct FutureRoundAssistInput {
    pub kind: FutureRoundAssistKind,
    pub last_certified_round: Option<usize>,
    pub target_round: usize,
    pub skip_certificates: usize,
    pub first_fanout_completed: bool,
    pub local_block_in_candidate: bool,
    pub local_block_replicated: bool,
    pub parent_data_replicated: bool,
    pub parent_data_repairable: bool,
    pub holds_unreplicated_parent_data: bool,
    pub future_body_validated: bool,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum FutureRoundAssistDecision {
    Assist,
    AssistDroppingLocalBlock,
    BufferForCertificates,
    BufferForRepair,
    ServeDataBeforeAssist,
    RejectDataVoteUntilValidated,
}

pub fn future_round_assist_decision(input: FutureRoundAssistInput) -> FutureRoundAssistDecision {
    let next_uncertified_round = input
        .last_certified_round
        .map_or(0, |round| round.saturating_add(1));
    let skipped_rounds = input.target_round.saturating_sub(next_uncertified_round);
    if input.skip_certificates < skipped_rounds {
        return FutureRoundAssistDecision::BufferForCertificates;
    }

    if input.local_block_in_candidate && !input.first_fanout_completed {
        return FutureRoundAssistDecision::AssistDroppingLocalBlock;
    }

    if input.local_block_in_candidate && !input.local_block_replicated {
        return FutureRoundAssistDecision::ServeDataBeforeAssist;
    }

    match (
        input.parent_data_replicated,
        input.parent_data_repairable,
        input.holds_unreplicated_parent_data,
    ) {
        (false, false, _) => return FutureRoundAssistDecision::BufferForRepair,
        (false, true, true) => return FutureRoundAssistDecision::ServeDataBeforeAssist,
        _ => {}
    }

    if let (FutureRoundAssistKind::DataBearing, false) = (input.kind, input.future_body_validated) {
        return FutureRoundAssistDecision::RejectDataVoteUntilValidated;
    }

    FutureRoundAssistDecision::Assist
}

pub fn skipped_round_assist_decision(round: usize) -> FutureRoundAssistDecision {
    future_round_assist_decision(FutureRoundAssistInput {
        kind: FutureRoundAssistKind::RoundChangeSkip,
        last_certified_round: round.checked_sub(1),
        target_round: round.saturating_add(1),
        skip_certificates: 1,
        first_fanout_completed: round > 0,
        local_block_in_candidate: round == 0,
        local_block_replicated: round > 0,
        parent_data_replicated: true,
        parent_data_repairable: true,
        holds_unreplicated_parent_data: false,
        future_body_validated: false,
    })
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Default,
)]
pub struct DataDisseminationManifest {
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub first_fanout_round: u8,
    pub last_certified_round: Option<u8>,
    pub certified_blocks_hash: HashType,
    pub carried_blocks: BTreeSet<HashType>,
    pub dropped_local_blocks: BTreeSet<HashType>,
    pub source_nodes: BTreeSet<PubKey>,
    pub replica_holders: BTreeMap<HashType, BTreeSet<PubKey>>,
}

impl DataDisseminationManifest {
    pub fn first_fanout_completed(&self) -> bool {
        self.last_certified_round
            .is_some_and(|round| round >= self.first_fanout_round)
    }

    pub fn local_block_decision(&self, local_block: &HashType) -> FutureRoundAssistDecision {
        if self.dropped_local_blocks.contains(local_block) {
            return FutureRoundAssistDecision::AssistDroppingLocalBlock;
        }
        if !self.carried_blocks.contains(local_block) {
            return FutureRoundAssistDecision::Assist;
        }
        if !self.first_fanout_completed() {
            return FutureRoundAssistDecision::AssistDroppingLocalBlock;
        }
        if self.carried_block_replica_count(local_block) == 0 {
            return FutureRoundAssistDecision::ServeDataBeforeAssist;
        }
        FutureRoundAssistDecision::Assist
    }

    pub fn carried_block_replica_count(&self, block: &HashType) -> usize {
        self.replica_holders
            .get(block)
            .map(BTreeSet::len)
            .unwrap_or_default()
    }

    pub fn every_carried_block_has_replica(&self) -> bool {
        self.every_carried_block_has_replica_threshold(1)
    }

    pub fn byzantine_safe_replica_threshold(byzantine_fault_bound: usize) -> usize {
        byzantine_fault_bound.saturating_add(1)
    }

    pub fn every_carried_block_has_byzantine_safe_replica(
        &self,
        byzantine_fault_bound: usize,
    ) -> bool {
        self.every_carried_block_has_replica_threshold(Self::byzantine_safe_replica_threshold(
            byzantine_fault_bound,
        ))
    }

    pub fn every_carried_block_has_replica_threshold(&self, min_replicas: usize) -> bool {
        let min_replicas = min_replicas.max(1);
        self.carried_blocks
            .iter()
            .all(|block| self.carried_block_replica_count(block) >= min_replicas)
    }

    pub fn can_reconstruct_from(&self, sources: &BTreeSet<PubKey>) -> bool {
        self.can_reconstruct_from_threshold(sources, 1)
    }

    pub fn can_reconstruct_from_byzantine_safe_sources(
        &self,
        sources: &BTreeSet<PubKey>,
        byzantine_fault_bound: usize,
    ) -> bool {
        self.can_reconstruct_from_threshold(
            sources,
            Self::byzantine_safe_replica_threshold(byzantine_fault_bound),
        )
    }

    pub fn can_reconstruct_from_threshold(
        &self,
        sources: &BTreeSet<PubKey>,
        min_sources_per_block: usize,
    ) -> bool {
        let min_sources_per_block = min_sources_per_block.max(1);
        self.carried_blocks.is_empty()
            || self.carried_blocks.iter().all(|block| {
                self.replica_holders.get(block).is_some_and(|holders| {
                    holders
                        .iter()
                        .filter(|holder| sources.contains(holder))
                        .count()
                        >= min_sources_per_block
                })
            })
    }

    pub fn validate_availability(
        &self,
        current_validators: &[PubKey],
        min_replicas_per_block: usize,
    ) -> Result<DataDisseminationManifestValidation> {
        let min_replicas_per_block = min_replicas_per_block.max(1);
        let current_validators = current_validators.iter().copied().collect::<BTreeSet<_>>();

        for source in &self.source_nodes {
            if !current_validators.contains(source) {
                return Err(BlossomError::WireProtocol(
                    "data-dissemination manifest source is not a current validator".to_string(),
                ));
            }
        }

        if !self.carried_blocks.is_disjoint(&self.dropped_local_blocks) {
            return Err(BlossomError::WireProtocol(
                "data-dissemination manifest cannot both carry and drop the same block".to_string(),
            ));
        }

        for block in self.replica_holders.keys() {
            if !self.carried_blocks.contains(block) {
                return Err(BlossomError::WireProtocol(
                    "data-dissemination manifest has replica evidence for an uncarried block"
                        .to_string(),
                ));
            }
        }

        for holders in self.replica_holders.values() {
            for holder in holders {
                if !self.source_nodes.contains(holder) || !current_validators.contains(holder) {
                    return Err(BlossomError::WireProtocol(
                        "data-dissemination manifest replica holder is not an eligible validator"
                            .to_string(),
                    ));
                }
            }
        }

        if !self.every_carried_block_has_replica_threshold(min_replicas_per_block) {
            return Err(BlossomError::WireProtocol(format!(
                "data-dissemination manifest carried block has fewer than {min_replicas_per_block} replica holders"
            )));
        }

        Ok(DataDisseminationManifestValidation {
            carried_blocks: self.carried_blocks.len(),
            dropped_local_blocks: self.dropped_local_blocks.len(),
            min_replicas_per_block,
        })
    }

    pub fn full_data_holders(&self) -> BTreeSet<PubKey> {
        if self.carried_blocks.is_empty() {
            return self.source_nodes.clone();
        }
        self.source_nodes
            .iter()
            .filter(|source| {
                self.carried_blocks.iter().all(|block| {
                    self.replica_holders
                        .get(block)
                        .is_some_and(|holders| holders.contains(source))
                })
            })
            .copied()
            .collect()
    }

    pub fn hash(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(ROUND_SKIP_MANIFEST_HASH_DOMAIN);
        hasher.update(self.last_epoch.as_ref());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update([self.first_fanout_round]);
        match self.last_certified_round {
            Some(round) => {
                hasher.update([1]);
                hasher.update([round]);
            }
            None => hasher.update([0]),
        }
        hasher.update(self.certified_blocks_hash.as_ref());
        update_hash_set(&mut hasher, &self.carried_blocks);
        update_hash_set(&mut hasher, &self.dropped_local_blocks);
        update_pubkey_set(&mut hasher, &self.source_nodes);
        update_replica_map(&mut hasher, &self.replica_holders);
        hasher.finalize()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDisseminationManifestValidation {
    pub carried_blocks: usize,
    pub dropped_local_blocks: usize,
    pub min_replicas_per_block: usize,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Default,
)]
pub struct RoundSkipVote {
    pub voter: PubKey,
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub from_round: u8,
    pub to_round: u8,
    pub manifest_hash: HashType,
    pub signature: Signature,
}

impl RoundSkipVote {
    pub fn sign(
        voter: PubKey,
        secret_key: &SecKey,
        last_epoch: HashType,
        nonce: Nonce,
        from_round: u8,
        to_round: u8,
        manifest_hash: HashType,
    ) -> Self {
        Self::sign_with(
            voter,
            &SecretSigner::new(secret_key),
            last_epoch,
            nonce,
            from_round,
            to_round,
            manifest_hash,
        )
    }

    pub fn sign_with(
        voter: PubKey,
        signer: &SecretSigner,
        last_epoch: HashType,
        nonce: Nonce,
        from_round: u8,
        to_round: u8,
        manifest_hash: HashType,
    ) -> Self {
        let signing_hash = Self::signing_hash_for(
            &voter,
            &last_epoch,
            nonce,
            from_round,
            to_round,
            &manifest_hash,
        );
        Self {
            voter,
            last_epoch,
            nonce,
            from_round,
            to_round,
            manifest_hash,
            signature: signer.sign(signing_hash.as_ref()),
        }
    }

    pub fn signing_hash(&self) -> HashType {
        Self::signing_hash_for(
            &self.voter,
            &self.last_epoch,
            self.nonce,
            self.from_round,
            self.to_round,
            &self.manifest_hash,
        )
    }

    pub fn verify_signature(&self) -> Result<()> {
        self.signature
            .verify(self.signing_hash().as_ref(), &self.voter)
    }

    fn matches_certificate(&self, certificate: &RoundSkipCertificate) -> bool {
        self.last_epoch == certificate.last_epoch
            && self.nonce == certificate.nonce
            && self.from_round == certificate.from_round
            && self.to_round == certificate.to_round
            && self.manifest_hash == certificate.manifest_hash
    }

    fn signing_hash_for(
        voter: &PubKey,
        last_epoch: &HashType,
        nonce: Nonce,
        from_round: u8,
        to_round: u8,
        manifest_hash: &HashType,
    ) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(ROUND_SKIP_VOTE_SIGNATURE_DOMAIN);
        hasher.update(voter.as_ref());
        hasher.update(last_epoch.as_ref());
        hasher.update(nonce.to_le_bytes());
        hasher.update([from_round]);
        hasher.update([to_round]);
        hasher.update(manifest_hash.as_ref());
        hasher.finalize()
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq, Default,
)]
pub struct RoundSkipCertificate {
    pub last_epoch: HashType,
    pub nonce: Nonce,
    pub from_round: u8,
    pub to_round: u8,
    pub manifest_hash: HashType,
    pub votes: Vec<RoundSkipVote>,
}

impl RoundSkipCertificate {
    pub fn new(
        last_epoch: HashType,
        nonce: Nonce,
        from_round: u8,
        to_round: u8,
        manifest_hash: HashType,
        votes: Vec<RoundSkipVote>,
    ) -> Self {
        Self {
            last_epoch,
            nonce,
            from_round,
            to_round,
            manifest_hash,
            votes,
        }
    }

    pub fn valid_voters(&self, current_validators: &[PubKey]) -> BTreeSet<PubKey> {
        let current = current_validators.iter().copied().collect::<BTreeSet<_>>();
        self.votes
            .iter()
            .filter(|vote| vote.matches_certificate(self))
            .filter(|vote| current.contains(&vote.voter))
            .filter(|vote| vote.verify_signature().is_ok())
            .map(|vote| vote.voter)
            .collect()
    }

    pub fn valid_vote_count(&self, current_validators: &[PubKey]) -> usize {
        distinct_current_validator_count(
            self.valid_voters(current_validators),
            current_validators.iter().copied(),
        )
    }

    pub fn required_votes(&self, current_validators: &[PubKey]) -> usize {
        supermajority_count(current_validators.len())
    }

    pub fn reaches_supermajority(&self, current_validators: &[PubKey]) -> bool {
        has_supermajority(
            current_validators.len(),
            self.valid_vote_count(current_validators),
        )
    }

    pub fn validate_against_epoch(
        &self,
        current_validators: &[PubKey],
        expected_last_epoch: HashType,
        expected_nonce: Nonce,
    ) -> Result<RoundSkipCertificateValidation> {
        if self.to_round <= self.from_round {
            return Err(BlossomError::WireProtocol(
                "round-skip certificate must advance to a future round".to_string(),
            ));
        }
        if self.last_epoch != expected_last_epoch || self.nonce != expected_nonce {
            return Err(BlossomError::WireProtocol(
                "round-skip certificate is stale for this epoch".to_string(),
            ));
        }

        let valid_distinct_votes = self.valid_vote_count(current_validators);
        let required_votes = self.required_votes(current_validators);
        if !has_supermajority(current_validators.len(), valid_distinct_votes) {
            return Err(BlossomError::WireProtocol(format!(
                "round-skip certificate has {valid_distinct_votes} valid votes, needs {required_votes}"
            )));
        }

        Ok(RoundSkipCertificateValidation {
            valid_distinct_votes,
            required_votes,
        })
    }

    pub fn validate_against_epoch_and_manifest(
        &self,
        current_validators: &[PubKey],
        expected_last_epoch: HashType,
        expected_nonce: Nonce,
        manifest: &DataDisseminationManifest,
        min_replicas_per_block: usize,
    ) -> Result<RoundSkipCertificateValidation> {
        if self.manifest_hash != manifest.hash() {
            return Err(BlossomError::WireProtocol(
                "round-skip certificate manifest hash does not match manifest".to_string(),
            ));
        }

        manifest.validate_availability(current_validators, min_replicas_per_block)?;
        self.validate_against_epoch(current_validators, expected_last_epoch, expected_nonce)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundSkipCertificateValidation {
    pub valid_distinct_votes: usize,
    pub required_votes: usize,
}

fn update_hash_set(hasher: &mut ProtocolHasher, hashes: &BTreeSet<HashType>) {
    hasher.update((hashes.len() as u64).to_le_bytes());
    for hash in hashes {
        hasher.update(hash.as_ref());
    }
}

fn update_pubkey_set(hasher: &mut ProtocolHasher, keys: &BTreeSet<PubKey>) {
    hasher.update((keys.len() as u64).to_le_bytes());
    for key in keys {
        hasher.update(key.as_ref());
    }
}

fn update_replica_map(
    hasher: &mut ProtocolHasher,
    replica_holders: &BTreeMap<HashType, BTreeSet<PubKey>>,
) {
    hasher.update((replica_holders.len() as u64).to_le_bytes());
    for (block, holders) in replica_holders {
        hasher.update(block.as_ref());
        update_pubkey_set(hasher, holders);
    }
}

#[cfg(test)]
mod tests;
