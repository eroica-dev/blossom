//! Frozen-replica application tracking and retention/cutover decisions.

use super::*;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Monotonic application progress observed from a frozen replica set.
pub struct AppliedByTracker {
    membership_snapshot: ReplicaMembershipEpoch,
    required_nodes: BTreeSet<PubKey>,
    observed: BTreeMap<PubKey, Watermark>,
}

impl AppliedByTracker {
    /// Creates a tracker for a non-empty membership snapshot.
    pub fn new(
        membership_snapshot: ReplicaMembershipEpoch,
        required_nodes: BTreeSet<PubKey>,
    ) -> Result<Self> {
        if required_nodes.is_empty() {
            return Err(BlossomError::InvalidConfiguration(
                "AppliedBy requires a non-empty frozen replica set".to_string(),
            ));
        }
        Ok(Self {
            membership_snapshot,
            required_nodes,
            observed: BTreeMap::new(),
        })
    }

    /// Records a monotonic watermark from one required replica.
    pub fn observe(&mut self, node: PubKey, watermark: Watermark) -> Result<()> {
        if !self.required_nodes.contains(&node) {
            return Err(BlossomError::UnknownSender);
        }
        self.observed
            .entry(node)
            .and_modify(|current| *current = (*current).max(watermark))
            .or_insert(watermark);
        Ok(())
    }

    /// Returns evidence once every required replica reaches `watermark`.
    pub fn reached(&self, watermark: Watermark) -> Option<AppliedBy> {
        self.required_nodes
            .iter()
            .all(|node| {
                self.observed
                    .get(node)
                    .is_some_and(|seen| *seen >= watermark)
            })
            .then(|| AppliedBy {
                membership_snapshot: self.membership_snapshot,
                required_nodes: self.required_nodes.clone(),
                watermark,
            })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Evidence required before finalized history may be collected.
pub struct RetentionEvidence {
    /// Watermark covered by an application-owned durable snapshot.
    pub durable_snapshot_watermark: Watermark,
    /// Proof that the frozen replica set applied through a watermark.
    pub applied_by: AppliedBy,
}

impl RetentionEvidence {
    /// Returns whether both retention conditions cover `position`.
    pub fn permits_collection(&self, position: Watermark) -> bool {
        self.durable_snapshot_watermark >= position && self.applied_by.watermark >= position
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Required treatment of an accepted write during membership cutover.
pub enum MembershipCutoverDisposition {
    /// Preserve the old certificate and finish under old membership.
    FinalizeUnderOldMembership,
    /// Issue new availability evidence under the new membership.
    RecertifyUnderNewMembership,
    /// Persist an explicit abort instead of silently losing the write.
    ExplicitAbort,
}

/// Selects the safe cutover disposition for one accepted write.
pub fn required_cutover_disposition(
    accepted_local: bool,
    available_under_old_membership: bool,
    can_recertify: bool,
) -> MembershipCutoverDisposition {
    if accepted_local && available_under_old_membership {
        MembershipCutoverDisposition::FinalizeUnderOldMembership
    } else if accepted_local && can_recertify {
        MembershipCutoverDisposition::RecertifyUnderNewMembership
    } else {
        MembershipCutoverDisposition::ExplicitAbort
    }
}
