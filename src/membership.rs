use std::collections::{BTreeMap, BTreeSet};

use indextreemap::IndexTreeMap;
use serde::{Deserialize, Serialize};

use crate::algorithm::supermajority_count;
use crate::block::Block;
use crate::crypto::PubKey;
use crate::encounter::EncounterOutcome;
use crate::hash::HashType;
use crate::node::NodeIdentity;
use crate::nonce::Nonce;

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
mod tests {
    use super::*;
    use crate::address_book::{Service, ServiceKind};
    use crate::admission::NodeAdmission;
    use crate::algorithm::select_quorums_from_index_tree;
    use crate::crypto::Keypair;
    use crate::encounter::{EncounterPhase, EncounterRecord, EncounterRecordBody};

    fn verifier_set(keypairs: &[Keypair]) -> IndexTreeMap<PubKey, NodeIdentity> {
        let mut verifiers = IndexTreeMap::new();
        for (index, keypair) in keypairs.iter().enumerate() {
            verifiers.insert(
                keypair.public,
                NodeIdentity::new(
                    keypair.public,
                    None,
                    "tcp",
                    "127.0.0.1",
                    9000 + index as u16,
                    false,
                ),
            );
        }
        verifiers
    }

    fn evidence_block(
        observer: &Keypair,
        subject: PubKey,
        last_epoch: HashType,
        nonce: Nonce,
        outcome: EncounterOutcome,
    ) -> Block {
        let record = EncounterRecord::signed(
            EncounterRecordBody::new(
                observer.public,
                subject,
                last_epoch,
                nonce,
                0,
                EncounterPhase::Verification,
                outcome,
            ),
            &observer.signer(),
        )
        .unwrap();

        let mut block = Block::default();
        block.body.last_epoch = last_epoch;
        block.body.nonce = nonce;
        block.body.encounter_records.push(record);
        block.sign(&observer.secret);
        block
    }

    fn admission_block(
        observer: &Keypair,
        admission: crate::admission::NodeAdmission,
        last_epoch: HashType,
        nonce: Nonce,
    ) -> Block {
        admission_block_with_created(observer, admission, last_epoch, nonce, 0)
    }

    fn admission_block_with_created(
        observer: &Keypair,
        admission: crate::admission::NodeAdmission,
        last_epoch: HashType,
        nonce: Nonce,
        created: u128,
    ) -> Block {
        let mut block = Block::default();
        block.body.last_epoch = last_epoch;
        block.body.nonce = nonce;
        block.body.created = created;
        block.body.node_admissions.push(admission);
        block.sign(&observer.secret);
        block
    }

    fn signed_admission(keypair: &Keypair, last_epoch: HashType, nonce: Nonce) -> NodeAdmission {
        let service = Service::new(
            ServiceKind::Consensus,
            keypair.public,
            "tcp",
            "127.0.0.1",
            9100,
        );
        NodeAdmission::signed_for_consensus_service(service, last_epoch, nonce, &keypair.signer())
            .unwrap()
    }

    #[test]
    fn supermajority_evidence_plans_node_removal() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let verifiers = verifier_set(&keypairs);
        let subject = keypairs[5].public;
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let blocks = keypairs[..4]
            .iter()
            .map(|observer| {
                let block = evidence_block(
                    observer,
                    subject,
                    last_epoch,
                    nonce,
                    EncounterOutcome::MissingSignature,
                );
                (block.hash, block)
            })
            .collect::<BTreeMap<_, _>>();

        let plan = derive_consensus_node_removal_plan(
            &verifiers,
            &blocks,
            last_epoch,
            nonce,
            ConsensusNodeRemovalPolicy::supermajority(),
        );

        assert_eq!(plan.retained_verifier_count, 5);
        assert_eq!(plan.decisions.len(), 1);
        assert_eq!(plan.decisions[0].subject, subject);
        assert_eq!(plan.decisions[0].observer_count, 4);
        assert_eq!(plan.decisions[0].required_observers, 4);
    }

    #[test]
    fn disabled_policy_never_removes_nodes() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let verifiers = verifier_set(&keypairs);
        let subject = keypairs[5].public;
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let blocks = keypairs[..4]
            .iter()
            .map(|observer| {
                let block = evidence_block(
                    observer,
                    subject,
                    last_epoch,
                    nonce,
                    EncounterOutcome::MissingSignature,
                );
                (block.hash, block)
            })
            .collect::<BTreeMap<_, _>>();

        let plan = derive_consensus_node_removal_plan(
            &verifiers,
            &blocks,
            last_epoch,
            nonce,
            ConsensusNodeRemovalPolicy::disabled(),
        );

        assert!(plan.is_empty());
        assert_eq!(plan.retained_verifier_count, 6);
    }

    #[test]
    fn required_observer_override_cannot_lower_supermajority_threshold() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let verifiers = verifier_set(&keypairs);
        let subject = keypairs[5].public;
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let blocks = keypairs[..3]
            .iter()
            .map(|observer| {
                let block = evidence_block(
                    observer,
                    subject,
                    last_epoch,
                    nonce,
                    EncounterOutcome::MissingSignature,
                );
                (block.hash, block)
            })
            .collect::<BTreeMap<_, _>>();
        let policy = ConsensusNodeRemovalPolicy::supermajority().with_required_observers(2);

        let plan =
            derive_consensus_node_removal_plan(&verifiers, &blocks, last_epoch, nonce, policy);

        assert_eq!(policy.required_observers_for(verifiers.len()), 4);
        assert!(plan.is_empty());
    }

    #[test]
    fn stale_duplicate_or_unknown_evidence_does_not_count() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let unknown = Keypair::generate();
        let verifiers = verifier_set(&keypairs);
        let subject = keypairs[5].public;
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let mut blocks = BTreeMap::new();

        let first = evidence_block(
            &keypairs[0],
            subject,
            last_epoch,
            nonce,
            EncounterOutcome::MissingSignature,
        );
        let duplicate = evidence_block(
            &keypairs[0],
            subject,
            last_epoch,
            nonce,
            EncounterOutcome::InvalidSignature,
        );
        let stale = evidence_block(
            &keypairs[1],
            subject,
            last_epoch,
            Nonce::new(1),
            EncounterOutcome::MissingSignature,
        );
        let outsider = evidence_block(
            &unknown,
            subject,
            last_epoch,
            nonce,
            EncounterOutcome::MissingSignature,
        );

        blocks.insert(first.hash, first);
        blocks.insert(duplicate.hash, duplicate);
        blocks.insert(stale.hash, stale);
        blocks.insert(outsider.hash, outsider);

        let plan = derive_consensus_node_removal_plan(
            &verifiers,
            &blocks,
            last_epoch,
            nonce,
            ConsensusNodeRemovalPolicy::supermajority(),
        );

        assert!(plan.is_empty());
        assert_eq!(plan.retained_verifier_count, 6);
    }

    #[test]
    fn policy_caps_removals_and_preserves_minimum_verifiers() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let verifiers = verifier_set(&keypairs);
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let mut blocks = BTreeMap::new();

        for subject in [keypairs[4].public, keypairs[5].public] {
            for observer in &keypairs[..4] {
                let block = evidence_block(
                    observer,
                    subject,
                    last_epoch,
                    nonce,
                    EncounterOutcome::MissingSignature,
                );
                blocks.insert(block.hash, block);
            }
        }

        let policy = ConsensusNodeRemovalPolicy {
            enabled: true,
            min_remaining_verifiers: 5,
            max_removals_per_epoch: 2,
            required_observers: None,
        };
        let plan =
            derive_consensus_node_removal_plan(&verifiers, &blocks, last_epoch, nonce, policy);

        assert_eq!(plan.decisions.len(), 1);
        assert_eq!(plan.retained_verifier_count, 5);
    }

    #[test]
    fn pruned_verifier_set_produces_compatible_round_schedules() {
        let keypairs = (0..13).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let verifiers = verifier_set(&keypairs);
        let last_epoch = HashType([7; 32]);
        let nonce = Nonce::new(3);
        let removed_subjects = [keypairs[11].public, keypairs[12].public];
        let mut blocks = BTreeMap::new();

        for subject in removed_subjects {
            for observer in &keypairs[..9] {
                let block = evidence_block(
                    observer,
                    subject,
                    last_epoch,
                    nonce,
                    EncounterOutcome::MissingSignature,
                );
                blocks.insert(block.hash, block);
            }
        }

        let (next_verifiers, plan) = apply_epoch_membership_transition(
            &verifiers,
            &blocks,
            last_epoch,
            nonce,
            ConsensusNodeRemovalPolicy::supermajority()
                .with_min_remaining_verifiers(6)
                .with_max_removals_per_epoch(2),
        );

        assert_eq!(plan.decisions.len(), 2);
        assert_eq!(next_verifiers.len(), 11);
        for subject in removed_subjects {
            assert!(!next_verifiers.contains_key(&subject));
        }

        let seed = HashType::hash(b"post-prune-round-schedule");
        for self_key in next_verifiers.keys().copied().collect::<Vec<_>>() {
            let self_quorums =
                select_quorums_from_index_tree(&next_verifiers, &self_key, seed, true);
            assert!(!self_quorums.is_empty());
            for (round, quorum) in self_quorums.iter().enumerate() {
                assert!(quorum.contains(&self_key));
                for peer in quorum {
                    let peer_quorums =
                        select_quorums_from_index_tree(&next_verifiers, peer, seed, true);
                    assert_eq!(
                        peer_quorums.get(round),
                        Some(quorum),
                        "round {round} self {self_key} peer {peer}"
                    );
                }
            }
        }
    }

    #[test]
    fn deterministic_order_prefers_invalid_signature_evidence() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let verifiers = verifier_set(&keypairs);
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let invalid_subject = keypairs[4].public;
        let missing_subject = keypairs[5].public;
        let mut blocks = BTreeMap::new();

        for observer in &keypairs[..4] {
            let invalid_block = evidence_block(
                observer,
                invalid_subject,
                last_epoch,
                nonce,
                EncounterOutcome::InvalidSignature,
            );
            blocks.insert(invalid_block.hash, invalid_block);

            let missing_block = evidence_block(
                observer,
                missing_subject,
                last_epoch,
                nonce,
                EncounterOutcome::MissingSignature,
            );
            blocks.insert(missing_block.hash, missing_block);
        }

        let plan = derive_consensus_node_removal_plan(
            &verifiers,
            &blocks,
            last_epoch,
            nonce,
            ConsensusNodeRemovalPolicy::supermajority(),
        );

        assert_eq!(plan.decisions.len(), 1);
        assert_eq!(plan.decisions[0].subject, invalid_subject);
        assert_eq!(plan.decisions[0].invalid_signature_count, 4);
    }

    #[test]
    fn single_validator_signed_node_admission_adds_new_verifier() {
        let keypairs = [Keypair::generate()];
        let joiner = Keypair::generate();
        let verifiers = verifier_set(&keypairs);
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let admission = signed_admission(&joiner, last_epoch, nonce);
        let block = admission_block(&keypairs[0], admission, last_epoch, nonce);
        let blocks = [(block.hash, block)]
            .into_iter()
            .collect::<BTreeMap<_, _>>();

        let (next_verifiers, removal_plan) = apply_epoch_membership_transition(
            &verifiers,
            &blocks,
            last_epoch,
            nonce,
            ConsensusNodeRemovalPolicy::disabled(),
        );

        assert!(removal_plan.is_empty());
        assert!(next_verifiers.contains_key(&joiner.public));
        assert_eq!(next_verifiers.len(), verifiers.len() + 1);
    }

    #[test]
    fn signed_node_admission_requires_supermajority_of_current_verifiers() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let joiner = Keypair::generate();
        let verifiers = verifier_set(&keypairs);
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let admission = signed_admission(&joiner, last_epoch, nonce);
        let blocks = keypairs[..3]
            .iter()
            .map(|observer| {
                let block = admission_block(observer, admission.clone(), last_epoch, nonce);
                (block.hash, block)
            })
            .collect::<BTreeMap<_, _>>();

        let plan = derive_consensus_node_admission_plan(&verifiers, &blocks, last_epoch, nonce);

        assert_eq!(plan.required_observers, 4);
        assert!(plan.is_empty());
    }

    #[test]
    fn duplicate_admission_votes_from_one_validator_do_not_satisfy_quorum() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let joiner = Keypair::generate();
        let verifiers = verifier_set(&keypairs);
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let admission = signed_admission(&joiner, last_epoch, nonce);
        let blocks = (0..4)
            .map(|index| {
                let block = admission_block_with_created(
                    &keypairs[0],
                    admission.clone(),
                    last_epoch,
                    nonce,
                    index,
                );
                (block.hash, block)
            })
            .collect::<BTreeMap<_, _>>();

        let plan = derive_consensus_node_admission_plan(&verifiers, &blocks, last_epoch, nonce);

        assert_eq!(plan.required_observers, 4);
        assert!(plan.is_empty());
    }

    #[test]
    fn supermajority_signed_node_admission_adds_new_verifier() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let joiner = Keypair::generate();
        let verifiers = verifier_set(&keypairs);
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let admission = signed_admission(&joiner, last_epoch, nonce);
        let blocks = keypairs[..4]
            .iter()
            .map(|observer| {
                let block = admission_block(observer, admission.clone(), last_epoch, nonce);
                (block.hash, block)
            })
            .collect::<BTreeMap<_, _>>();

        let (next_verifiers, removal_plan) = apply_epoch_membership_transition(
            &verifiers,
            &blocks,
            last_epoch,
            nonce,
            ConsensusNodeRemovalPolicy::disabled(),
        );

        assert!(removal_plan.is_empty());
        assert!(next_verifiers.contains_key(&joiner.public));
        assert_eq!(next_verifiers.len(), verifiers.len() + 1);
        let plan = derive_consensus_node_admission_plan(&verifiers, &blocks, last_epoch, nonce);
        assert_eq!(plan.decisions.len(), 1);
        assert_eq!(plan.decisions[0].observer_count, 4);
        assert_eq!(plan.decisions[0].required_observers, 4);
    }

    #[test]
    fn stale_or_unsigned_node_admissions_do_not_add_verifiers() {
        let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let joiner = Keypair::generate();
        let verifiers = verifier_set(&keypairs);
        let last_epoch = HashType([1; 32]);
        let nonce = Nonce::new(2);
        let stale = signed_admission(&joiner, last_epoch, Nonce::new(1));
        let block = admission_block(&keypairs[0], stale, last_epoch, nonce);
        let blocks = [(block.hash, block)]
            .into_iter()
            .collect::<BTreeMap<_, _>>();

        let plan = derive_consensus_node_admission_plan(&verifiers, &blocks, last_epoch, nonce);

        assert!(plan.is_empty());
    }
}
