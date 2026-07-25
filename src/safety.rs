use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::algorithm::{
    ConsensusParameters, QuorumSize, byzantine_fault_bound, max_liveness_omissions,
    min_supermajority_intersection, supermajority_count,
};
use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::hash::{HashType, ProtocolHasher};

const COMMITTEE_RANK_DOMAIN: &[u8] = b"blossom/site-balanced-committee/v1";

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct SiteId(pub String);

impl SiteId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(BlossomError::InvalidConfiguration(
                "site id cannot be empty".to_string(),
            ));
        }
        Ok(Self(value))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitteeParticipant {
    pub node: PubKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<SiteId>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CommitteeLayout {
    pub members: Vec<CommitteeParticipant>,
    pub members_by_site: BTreeMap<SiteId, Vec<PubKey>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SafetyManifest {
    pub version: u16,
    pub consensus_parameters_hash: HashType,
    pub configured_quorum_size: usize,
    pub effective_quorum_size: usize,
    pub validator_count: usize,
    pub committee_layout: CommitteeLayout,
    pub local_finality_threshold: usize,
    pub global_finality_threshold: usize,
    pub local_minimum_intersection: usize,
    pub global_minimum_intersection: usize,
    pub validator_byzantine_fault_bound: usize,
    pub holder_fault_bound: usize,
    pub max_validator_liveness_omissions: usize,
    pub site_loss_tolerance: bool,
    pub liveness_stop_conditions: Vec<String>,
}

impl SafetyManifest {
    pub const VERSION: u16 = 1;

    pub fn write_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|err| BlossomError::WireProtocol(format!("encode safety manifest: {err}")))?;
        fs::write(path, bytes).map_err(|err| BlossomError::Io(err.to_string()))
    }
}

/// Selects one deterministic committee. If complete three-site metadata is
/// supplied, every committee whose effective size is divisible by three is
/// balanced evenly across those sites.
pub fn select_site_balanced_committee(
    participants: impl IntoIterator<Item = CommitteeParticipant>,
    quorum_size: QuorumSize,
    seed: HashType,
    claim_site_loss_tolerance: bool,
) -> Result<CommitteeLayout> {
    let mut participants = participants.into_iter().collect::<Vec<_>>();
    participants.sort_by_key(|participant| participant.node);
    if participants
        .windows(2)
        .any(|pair| pair[0].node == pair[1].node)
    {
        return Err(BlossomError::InvalidConfiguration(
            "committee participant list contains duplicate nodes".to_string(),
        ));
    }

    let effective_size = quorum_size.effective(participants.len());
    let all_have_sites = participants
        .iter()
        .all(|participant| participant.site.is_some());
    let site_count = participants
        .iter()
        .filter_map(|participant| participant.site.as_ref())
        .collect::<BTreeSet<_>>()
        .len();

    if claim_site_loss_tolerance
        && (!all_have_sites || site_count != 3 || !effective_size.is_multiple_of(3))
    {
        return Err(BlossomError::InvalidConfiguration(
            "claimed site-loss tolerance requires complete metadata for exactly three sites and an effective committee divisible by three"
                .to_string(),
        ));
    }

    let mut selected = if all_have_sites && site_count == 3 && effective_size.is_multiple_of(3) {
        let per_site = effective_size / 3;
        let mut by_site = BTreeMap::<SiteId, Vec<CommitteeParticipant>>::new();
        for participant in participants {
            by_site
                .entry(participant.site.clone().expect("checked above"))
                .or_default()
                .push(participant);
        }

        if by_site.values().any(|members| members.len() < per_site) {
            if claim_site_loss_tolerance || effective_size == quorum_size.get() {
                return Err(BlossomError::InvalidConfiguration(format!(
                    "cannot place {per_site} committee members in each of three sites"
                )));
            }
            by_site.into_values().flatten().collect::<Vec<_>>()
        } else {
            let mut selected = Vec::with_capacity(effective_size);
            for (site, mut members) in by_site {
                members
                    .sort_by_key(|participant| committee_rank(seed, Some(&site), participant.node));
                selected.extend(members.into_iter().take(per_site));
            }
            selected
        }
    } else {
        participants
    };

    selected.sort_by_key(|participant| {
        committee_rank(seed, participant.site.as_ref(), participant.node)
    });
    selected.truncate(effective_size);
    selected.sort_by_key(|participant| participant.node);

    let mut members_by_site = BTreeMap::<SiteId, Vec<PubKey>>::new();
    for participant in &selected {
        if let Some(site) = &participant.site {
            members_by_site
                .entry(site.clone())
                .or_default()
                .push(participant.node);
        }
    }

    Ok(CommitteeLayout {
        members: selected,
        members_by_site,
    })
}

pub fn generate_safety_manifest(
    consensus_parameters: ConsensusParameters,
    participants: impl IntoIterator<Item = CommitteeParticipant>,
    seed: HashType,
    holder_fault_bound: usize,
    claim_site_loss_tolerance: bool,
) -> Result<SafetyManifest> {
    consensus_parameters.validate()?;
    let participants = participants.into_iter().collect::<Vec<_>>();
    let validator_count = participants.len();
    let committee_layout = select_site_balanced_committee(
        participants.clone(),
        consensus_parameters.quorum_size,
        seed,
        claim_site_loss_tolerance,
    )?;
    let effective_quorum_size = committee_layout.members.len();
    let site_loss_tolerance =
        site_loss_is_satisfied(&committee_layout, participants.as_slice(), validator_count);

    if claim_site_loss_tolerance && !site_loss_tolerance {
        return Err(BlossomError::InvalidConfiguration(
            "selected committee does not satisfy the claimed one-site-loss tolerance".to_string(),
        ));
    }

    Ok(SafetyManifest {
        version: SafetyManifest::VERSION,
        consensus_parameters_hash: consensus_parameters.hash(),
        configured_quorum_size: consensus_parameters.quorum_size.get(),
        effective_quorum_size,
        validator_count,
        local_finality_threshold: supermajority_count(effective_quorum_size),
        global_finality_threshold: supermajority_count(validator_count),
        local_minimum_intersection: min_supermajority_intersection(effective_quorum_size),
        global_minimum_intersection: min_supermajority_intersection(validator_count),
        validator_byzantine_fault_bound: byzantine_fault_bound(validator_count),
        holder_fault_bound,
        max_validator_liveness_omissions: max_liveness_omissions(validator_count),
        site_loss_tolerance,
        liveness_stop_conditions: vec![
            format!(
                "fewer than {} validators can participate",
                supermajority_count(validator_count)
            ),
            format!(
                "fewer than {} selected committee members can participate",
                supermajority_count(effective_quorum_size)
            ),
            "a finalized reference at the stable-prefix head is unavailable".to_string(),
        ],
        committee_layout,
    })
}

fn committee_rank(seed: HashType, site: Option<&SiteId>, node: PubKey) -> HashType {
    let mut hasher = ProtocolHasher::new();
    hasher.update(COMMITTEE_RANK_DOMAIN);
    hasher.update(seed.as_ref());
    if let Some(site) = site {
        hasher.update((site.0.len() as u64).to_le_bytes());
        hasher.update(site.0.as_bytes());
    } else {
        hasher.update(0u64.to_le_bytes());
    }
    hasher.update(node.as_ref());
    hasher.finalize()
}

fn site_loss_is_satisfied(
    layout: &CommitteeLayout,
    participants: &[CommitteeParticipant],
    validator_count: usize,
) -> bool {
    if layout.members_by_site.len() != 3
        || validator_count == 0
        || participants
            .iter()
            .any(|participant| participant.site.is_none())
    {
        return false;
    }
    let validators_by_site = participants.iter().fold(
        BTreeMap::<&SiteId, usize>::new(),
        |mut counts, participant| {
            *counts
                .entry(participant.site.as_ref().expect("checked above"))
                .or_default() += 1;
            counts
        },
    );
    if validators_by_site.len() != 3 {
        return false;
    }
    let local_threshold = supermajority_count(layout.members.len());
    let global_threshold = supermajority_count(validator_count);
    layout.members_by_site.iter().all(|(site, lost_committee)| {
        let lost_validators = validators_by_site.get(site).copied().unwrap_or_default();
        layout.members.len().saturating_sub(lost_committee.len()) >= local_threshold
            && validator_count.saturating_sub(lost_validators) >= global_threshold
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant(index: u8, site: &str) -> CommitteeParticipant {
        CommitteeParticipant {
            node: PubKey([index; 32]),
            site: Some(SiteId(site.to_string())),
        }
    }

    #[test]
    fn full_committee_is_evenly_distributed_across_three_sites() {
        let participants = (0..18)
            .map(|index| participant(index, ["a", "b", "c"][index as usize % 3]))
            .collect::<Vec<_>>();
        let layout = select_site_balanced_committee(
            participants,
            QuorumSize::new(9).unwrap(),
            HashType::hash(b"seed"),
            true,
        )
        .unwrap();

        assert_eq!(layout.members.len(), 9);
        assert!(
            layout
                .members_by_site
                .values()
                .all(|members| members.len() == 3)
        );
    }

    #[test]
    fn impossible_site_loss_claim_is_rejected() {
        let participants = (0..9)
            .map(|index| participant(index, if index < 8 { "a" } else { "b" }))
            .collect::<Vec<_>>();

        assert!(
            select_site_balanced_committee(
                participants,
                QuorumSize::new(9).unwrap(),
                HashType::default(),
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn global_validator_distribution_must_also_survive_one_site_loss() {
        let participants = (0..12)
            .map(|index| {
                participant(
                    index,
                    match index {
                        0..=7 => "a",
                        8..=9 => "b",
                        _ => "c",
                    },
                )
            })
            .collect::<Vec<_>>();

        assert!(
            generate_safety_manifest(
                ConsensusParameters::new(QuorumSize::new(6).unwrap()),
                participants,
                HashType::default(),
                0,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn manifest_separates_local_and_global_thresholds() {
        let participants = (0..18)
            .map(|index| participant(index, ["a", "b", "c"][index as usize % 3]))
            .collect::<Vec<_>>();
        let manifest = generate_safety_manifest(
            ConsensusParameters::new(QuorumSize::new(6).unwrap()),
            participants,
            HashType::default(),
            1,
            true,
        )
        .unwrap();

        assert_eq!(manifest.configured_quorum_size, 6);
        assert_eq!(manifest.effective_quorum_size, 6);
        assert_eq!(manifest.local_finality_threshold, 4);
        assert_eq!(manifest.global_finality_threshold, 12);
        assert_eq!(manifest.validator_byzantine_fault_bound, 5);
        assert!(manifest.site_loss_tolerance);
    }
}
