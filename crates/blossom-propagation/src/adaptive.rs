//! Adaptive propagation policy selection from latency and bandwidth signals.

use crate::{
    ManifestAuthentication, PropagationPlan, PropagationPolicyError, PropagationStrategy,
    RedundancyPlan, TrustBoundary, bandwidth_inventory, latency_push,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrategyEstimate {
    pub payload_bytes: usize,
    pub control_bytes: usize,
    pub latency_steps: usize,
}

impl StrategyEstimate {
    pub fn total_bytes(self) -> usize {
        self.payload_bytes.saturating_add(self.control_bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveInputs {
    pub trust_boundary: TrustBoundary,
    pub manifest_authentication: ManifestAuthentication,
    pub redundancy: RedundancyPlan,
    pub duplicate_bytes_expected: usize,
    pub inventory_bytes: usize,
    pub extra_rtt_ms: u64,
    pub link_bytes_per_second: u64,
    pub during_consensus: bool,
}

impl AdaptiveInputs {
    pub fn choose(self) -> Result<PropagationPlan, PropagationPolicyError> {
        let push = StrategyEstimate {
            payload_bytes: self.duplicate_bytes_expected,
            control_bytes: 0,
            latency_steps: 1,
        };
        let inventory = StrategyEstimate {
            payload_bytes: 0,
            control_bytes: self.inventory_bytes,
            latency_steps: 2,
        };
        self.choose_between(push, inventory)
    }

    pub fn choose_between(
        self,
        push: StrategyEstimate,
        inventory: StrategyEstimate,
    ) -> Result<PropagationPlan, PropagationPolicyError> {
        if inventory_beats_push(
            push,
            inventory,
            self.link_bytes_per_second,
            self.extra_rtt_ms,
        ) {
            let inventory_plan = bandwidth_inventory::plan(
                self.trust_boundary,
                self.manifest_authentication,
                self.redundancy,
                self.during_consensus,
            );
            inventory_plan.validate()?;
            return Ok(inventory_plan);
        }

        let push_plan = latency_push::plan(self.trust_boundary);
        push_plan.validate()?;
        Ok(push_plan)
    }
}

pub fn inventory_beats_push(
    push: StrategyEstimate,
    inventory: StrategyEstimate,
    link_bytes_per_second: u64,
    extra_rtt_ms: u64,
) -> bool {
    if push.total_bytes() <= inventory.total_bytes() {
        return false;
    }
    if link_bytes_per_second == 0 {
        return false;
    }

    let saved_bytes = push.total_bytes() - inventory.total_bytes();
    let saved_ms = transfer_time_ms(saved_bytes, link_bytes_per_second);
    saved_ms > extra_rtt_ms as u128
}

pub fn transfer_time_ms(bytes: usize, link_bytes_per_second: u64) -> u128 {
    if link_bytes_per_second == 0 {
        return u128::MAX;
    }
    (bytes as u128 * 1_000) / link_bytes_per_second as u128
}

pub fn strategy_name(plan: PropagationPlan) -> &'static str {
    match plan.strategy {
        PropagationStrategy::PushFullBlocks => "push-full-blocks",
        PropagationStrategy::InventoryThenMissing => "inventory-then-missing",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_uses_inventory_when_saved_transfer_time_beats_rtt() {
        let plan = AdaptiveInputs {
            trust_boundary: TrustBoundary::Trustless {
                quorum_size: 6,
                tolerated_byzantine: 1,
            },
            manifest_authentication: ManifestAuthentication::HolderSigned,
            redundancy: RedundancyPlan::new(2, 1),
            duplicate_bytes_expected: 10_000_000,
            inventory_bytes: 10_000,
            extra_rtt_ms: 5,
            link_bytes_per_second: 100_000_000,
            during_consensus: true,
        }
        .choose()
        .unwrap();

        assert_eq!(plan.strategy, PropagationStrategy::InventoryThenMissing);
    }

    #[test]
    fn adaptive_rejects_inventory_when_faster_but_not_safe() {
        let err = AdaptiveInputs {
            trust_boundary: TrustBoundary::Trustless {
                quorum_size: 6,
                tolerated_byzantine: 1,
            },
            manifest_authentication: ManifestAuthentication::HashOnly,
            redundancy: RedundancyPlan::new(2, 1),
            duplicate_bytes_expected: 10_000_000,
            inventory_bytes: 10_000,
            extra_rtt_ms: 5,
            link_bytes_per_second: 100_000_000,
            during_consensus: true,
        }
        .choose()
        .unwrap_err();

        assert_eq!(
            err,
            PropagationPolicyError::UnauthenticatedTrustlessInventory
        );
    }

    #[test]
    fn adaptive_uses_push_when_latency_cost_is_too_high() {
        let plan = AdaptiveInputs {
            trust_boundary: TrustBoundary::Trustless {
                quorum_size: 6,
                tolerated_byzantine: 1,
            },
            manifest_authentication: ManifestAuthentication::HolderSigned,
            redundancy: RedundancyPlan::new(2, 1),
            duplicate_bytes_expected: 10_000,
            inventory_bytes: 1_000,
            extra_rtt_ms: 50,
            link_bytes_per_second: 100_000_000,
            during_consensus: true,
        }
        .choose()
        .unwrap();

        assert_eq!(plan.strategy, PropagationStrategy::PushFullBlocks);
    }

    #[test]
    fn adaptive_uses_explicit_strategy_estimates() {
        let plan = AdaptiveInputs {
            trust_boundary: TrustBoundary::Trusted,
            manifest_authentication: ManifestAuthentication::HashOnly,
            redundancy: RedundancyPlan::new(1, 0),
            duplicate_bytes_expected: 0,
            inventory_bytes: 0,
            extra_rtt_ms: 1,
            link_bytes_per_second: 1_000_000,
            during_consensus: true,
        }
        .choose_between(
            StrategyEstimate {
                payload_bytes: 100_000,
                control_bytes: 0,
                latency_steps: 1,
            },
            StrategyEstimate {
                payload_bytes: 1_000,
                control_bytes: 100,
                latency_steps: 2,
            },
        )
        .unwrap();

        assert_eq!(plan.strategy, PropagationStrategy::InventoryThenMissing);
    }

    #[test]
    fn transfer_time_handles_zero_bandwidth() {
        assert_eq!(transfer_time_ms(10, 0), u128::MAX);
    }
}
