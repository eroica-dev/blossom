//! Feature-gated data-plane propagation policies for Blossom.
//!
//! This crate deliberately keeps bandwidth and latency optimizations separate
//! from consensus logic. The policy layer can choose how payload bytes move,
//! but it must not weaken the trustless safety requirements around authenticated
//! evidence, duplicate suppression, and Byzantine withholding tolerance.

use std::fmt;

#[cfg(feature = "propagation-adaptive")]
pub mod adaptive;
#[cfg(feature = "propagation-inventory")]
pub mod bandwidth_inventory;
#[cfg(feature = "propagation-push")]
pub mod latency_push;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationStrategy {
    PushFullBlocks,
    InventoryThenMissing,
}

impl PropagationStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PushFullBlocks => "push-full-blocks",
            Self::InventoryThenMissing => "inventory-then-missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustBoundary {
    Trusted,
    Trustless {
        quorum_size: usize,
        tolerated_byzantine: usize,
    },
}

impl TrustBoundary {
    pub fn trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }

    pub fn tolerated_byzantine(self) -> usize {
        match self {
            Self::Trusted => 0,
            Self::Trustless {
                tolerated_byzantine,
                ..
            } => tolerated_byzantine,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestAuthentication {
    None,
    HashOnly,
    HolderSigned,
    QuorumCertified { distinct_signers: usize },
}

impl ManifestAuthentication {
    pub fn is_authenticated_for_trustless(self, quorum_size: usize) -> bool {
        match self {
            Self::HolderSigned => true,
            Self::QuorumCertified { distinct_signers } => {
                distinct_signers >= supermajority_count(quorum_size)
            }
            Self::None | Self::HashOnly => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedundancyPlan {
    pub holders_per_branch: usize,
    pub byzantine_withholders_per_branch: usize,
}

impl RedundancyPlan {
    pub const fn new(holders_per_branch: usize, byzantine_withholders_per_branch: usize) -> Self {
        Self {
            holders_per_branch,
            byzantine_withholders_per_branch,
        }
    }

    pub fn has_live_holder_after_withholding(self) -> bool {
        self.holders_per_branch > self.byzantine_withholders_per_branch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropagationPlan {
    pub strategy: PropagationStrategy,
    pub trust_boundary: TrustBoundary,
    pub manifest_authentication: ManifestAuthentication,
    pub redundancy: RedundancyPlan,
    pub during_consensus: bool,
}

impl PropagationPlan {
    pub fn validate(self) -> Result<ValidatedPropagationPlan, PropagationPolicyError> {
        if self.redundancy.holders_per_branch == 0 {
            return Err(PropagationPolicyError::NoDataHolders);
        }

        match self.strategy {
            PropagationStrategy::PushFullBlocks => {}
            PropagationStrategy::InventoryThenMissing => {
                validate_inventory_plan(self)?;
            }
        }

        Ok(ValidatedPropagationPlan(self))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedPropagationPlan(PropagationPlan);

impl ValidatedPropagationPlan {
    pub fn plan(self) -> PropagationPlan {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropagationPolicyError {
    NoDataHolders,
    UnauthenticatedTrustlessInventory,
    InsufficientByzantineRedundancy {
        holders_per_branch: usize,
        byzantine_withholders_per_branch: usize,
    },
    ByzantineWithholdingExceedsQuorumTolerance {
        byzantine_withholders_per_branch: usize,
        tolerated_byzantine: usize,
    },
    UnsafeTrustlessPullDuringConsensus,
    InvalidTrustlessQuorum {
        quorum_size: usize,
        tolerated_byzantine: usize,
    },
}

impl fmt::Display for PropagationPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDataHolders => write!(f, "propagation needs at least one data holder"),
            Self::UnauthenticatedTrustlessInventory => {
                write!(f, "trustless inventory requires authenticated manifests")
            }
            Self::InsufficientByzantineRedundancy {
                holders_per_branch,
                byzantine_withholders_per_branch,
            } => write!(
                f,
                "holders per branch ({holders_per_branch}) must exceed Byzantine withholders ({byzantine_withholders_per_branch})"
            ),
            Self::ByzantineWithholdingExceedsQuorumTolerance {
                byzantine_withholders_per_branch,
                tolerated_byzantine,
            } => write!(
                f,
                "Byzantine withholders per branch ({byzantine_withholders_per_branch}) exceeds quorum tolerance ({tolerated_byzantine})"
            ),
            Self::UnsafeTrustlessPullDuringConsensus => write!(
                f,
                "trustless consensus rounds cannot rely on unauthenticated or single-holder pull"
            ),
            Self::InvalidTrustlessQuorum {
                quorum_size,
                tolerated_byzantine,
            } => write!(
                f,
                "trustless quorum size {quorum_size} cannot tolerate {tolerated_byzantine} Byzantine nodes"
            ),
        }
    }
}

impl std::error::Error for PropagationPolicyError {}

pub fn supermajority_count(quorum_size: usize) -> usize {
    quorum_size.saturating_mul(2) / 3 + 1
}

fn validate_inventory_plan(plan: PropagationPlan) -> Result<(), PropagationPolicyError> {
    match plan.trust_boundary {
        TrustBoundary::Trusted => Ok(()),
        TrustBoundary::Trustless {
            quorum_size,
            tolerated_byzantine,
        } => {
            if quorum_size == 0 || tolerated_byzantine.saturating_mul(3) >= quorum_size {
                return Err(PropagationPolicyError::InvalidTrustlessQuorum {
                    quorum_size,
                    tolerated_byzantine,
                });
            }
            if !plan
                .manifest_authentication
                .is_authenticated_for_trustless(quorum_size)
            {
                return Err(PropagationPolicyError::UnauthenticatedTrustlessInventory);
            }
            if !plan.redundancy.has_live_holder_after_withholding() {
                return Err(PropagationPolicyError::InsufficientByzantineRedundancy {
                    holders_per_branch: plan.redundancy.holders_per_branch,
                    byzantine_withholders_per_branch: plan
                        .redundancy
                        .byzantine_withholders_per_branch,
                });
            }
            if plan.redundancy.byzantine_withholders_per_branch > tolerated_byzantine {
                return Err(
                    PropagationPolicyError::ByzantineWithholdingExceedsQuorumTolerance {
                        byzantine_withholders_per_branch: plan
                            .redundancy
                            .byzantine_withholders_per_branch,
                        tolerated_byzantine,
                    },
                );
            }
            if plan.during_consensus && plan.redundancy.holders_per_branch == 1 {
                return Err(PropagationPolicyError::UnsafeTrustlessPullDuringConsensus);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trustless_inventory_rejects_hash_only_manifests() {
        let err = PropagationPlan {
            strategy: PropagationStrategy::InventoryThenMissing,
            trust_boundary: TrustBoundary::Trustless {
                quorum_size: 6,
                tolerated_byzantine: 1,
            },
            manifest_authentication: ManifestAuthentication::HashOnly,
            redundancy: RedundancyPlan::new(2, 1),
            during_consensus: true,
        }
        .validate()
        .unwrap_err();

        assert_eq!(
            err,
            PropagationPolicyError::UnauthenticatedTrustlessInventory
        );
    }

    #[test]
    fn trustless_inventory_requires_live_holder_after_withholding() {
        let err = PropagationPlan {
            strategy: PropagationStrategy::InventoryThenMissing,
            trust_boundary: TrustBoundary::Trustless {
                quorum_size: 6,
                tolerated_byzantine: 1,
            },
            manifest_authentication: ManifestAuthentication::HolderSigned,
            redundancy: RedundancyPlan::new(1, 1),
            during_consensus: true,
        }
        .validate()
        .unwrap_err();

        assert_eq!(
            err,
            PropagationPolicyError::InsufficientByzantineRedundancy {
                holders_per_branch: 1,
                byzantine_withholders_per_branch: 1
            }
        );
    }

    #[test]
    fn trustless_inventory_accepts_signed_redundant_holder_set() {
        let validated = PropagationPlan {
            strategy: PropagationStrategy::InventoryThenMissing,
            trust_boundary: TrustBoundary::Trustless {
                quorum_size: 6,
                tolerated_byzantine: 1,
            },
            manifest_authentication: ManifestAuthentication::HolderSigned,
            redundancy: RedundancyPlan::new(2, 1),
            during_consensus: true,
        }
        .validate()
        .unwrap();

        assert_eq!(
            validated.plan().strategy,
            PropagationStrategy::InventoryThenMissing
        );
    }

    #[test]
    fn trustless_inventory_rejects_withholding_above_quorum_tolerance() {
        let err = PropagationPlan {
            strategy: PropagationStrategy::InventoryThenMissing,
            trust_boundary: TrustBoundary::Trustless {
                quorum_size: 6,
                tolerated_byzantine: 1,
            },
            manifest_authentication: ManifestAuthentication::HolderSigned,
            redundancy: RedundancyPlan::new(3, 2),
            during_consensus: true,
        }
        .validate()
        .unwrap_err();

        assert_eq!(
            err,
            PropagationPolicyError::ByzantineWithholdingExceedsQuorumTolerance {
                byzantine_withholders_per_branch: 2,
                tolerated_byzantine: 1,
            }
        );
    }

    #[test]
    fn trusted_inventory_can_use_local_hash_only_manifests() {
        PropagationPlan {
            strategy: PropagationStrategy::InventoryThenMissing,
            trust_boundary: TrustBoundary::Trusted,
            manifest_authentication: ManifestAuthentication::HashOnly,
            redundancy: RedundancyPlan::new(1, 0),
            during_consensus: true,
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn push_plan_does_not_require_inventory_manifest() {
        PropagationPlan {
            strategy: PropagationStrategy::PushFullBlocks,
            trust_boundary: TrustBoundary::Trustless {
                quorum_size: 6,
                tolerated_byzantine: 1,
            },
            manifest_authentication: ManifestAuthentication::None,
            redundancy: RedundancyPlan::new(1, 0),
            during_consensus: true,
        }
        .validate()
        .unwrap();
    }
}
