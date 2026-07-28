//! Inventory-first propagation for bandwidth-sensitive deployments.

use crate::{
    ManifestAuthentication, PropagationPlan, PropagationStrategy, RedundancyPlan, TrustBoundary,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingBlock {
    pub recipient: usize,
    pub block: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryRoute {
    pub sender: usize,
    pub recipient: usize,
    pub block: usize,
    pub payload_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryRoutePlan {
    pub routes: Vec<InventoryRoute>,
    pub sender_payload_bytes: Vec<usize>,
    pub payload_bytes: usize,
    pub control_bytes: usize,
    pub latency_steps: usize,
}

pub fn plan(
    trust_boundary: TrustBoundary,
    manifest_authentication: ManifestAuthentication,
    redundancy: RedundancyPlan,
    during_consensus: bool,
) -> PropagationPlan {
    PropagationPlan {
        strategy: PropagationStrategy::InventoryThenMissing,
        trust_boundary,
        manifest_authentication,
        redundancy,
        during_consensus,
    }
}

pub fn trusted_hash_only() -> PropagationPlan {
    plan(
        TrustBoundary::Trusted,
        ManifestAuthentication::HashOnly,
        RedundancyPlan::new(1, 0),
        true,
    )
}

pub fn trustless_signed_redundant(
    quorum_size: usize,
    tolerated_byzantine: usize,
    holders_per_branch: usize,
) -> PropagationPlan {
    plan(
        TrustBoundary::Trustless {
            quorum_size,
            tolerated_byzantine,
        },
        ManifestAuthentication::HolderSigned,
        RedundancyPlan::new(holders_per_branch, tolerated_byzantine),
        true,
    )
}

pub fn route_missing_blocks_balanced(
    holders_by_block: &[Vec<usize>],
    missing: &[MissingBlock],
    block_payload_bytes: &[usize],
    node_count: usize,
    inventory_manifest_bytes: usize,
    request_bytes_per_block: usize,
    response_overhead_bytes: usize,
) -> InventoryRoutePlan {
    let mut sender_payload_bytes = vec![0usize; node_count];
    let mut routes = Vec::with_capacity(missing.len());
    let mut payload_bytes = 0usize;

    for item in missing {
        let Some(holders) = holders_by_block.get(item.block) else {
            continue;
        };
        let Some(payload) = block_payload_bytes.get(item.block).copied() else {
            continue;
        };
        let Some(sender) = holders
            .iter()
            .copied()
            .filter(|holder| *holder != item.recipient && *holder < node_count)
            .min_by_key(|holder| (sender_payload_bytes[*holder], *holder))
        else {
            continue;
        };

        let routed_payload = payload.saturating_add(response_overhead_bytes);
        sender_payload_bytes[sender] = sender_payload_bytes[sender].saturating_add(routed_payload);
        payload_bytes = payload_bytes.saturating_add(routed_payload);
        routes.push(InventoryRoute {
            sender,
            recipient: item.recipient,
            block: item.block,
            payload_bytes: routed_payload,
        });
    }

    let active_holders = holders_by_block
        .iter()
        .flatten()
        .copied()
        .filter(|holder| *holder < node_count)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let control_bytes = active_holders
        .saturating_mul(inventory_manifest_bytes)
        .saturating_add(routes.len().saturating_mul(request_bytes_per_block));

    InventoryRoutePlan {
        routes,
        sender_payload_bytes,
        payload_bytes,
        control_bytes,
        latency_steps: usize::from(!missing.is_empty()) * 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_builds_valid_trusted_inventory_plan() {
        trusted_hash_only().validate().unwrap();
    }

    #[test]
    fn helper_builds_valid_trustless_inventory_plan() {
        trustless_signed_redundant(6, 1, 2).validate().unwrap();
    }

    #[test]
    fn balanced_routes_pick_least_loaded_holder() {
        let routes = route_missing_blocks_balanced(
            &[
                vec![0, 1],
                vec![0, 1],
                vec![1, 2],
                vec![1, 2],
                vec![2, 3],
                vec![2, 3],
            ],
            &[
                MissingBlock {
                    recipient: 4,
                    block: 0,
                },
                MissingBlock {
                    recipient: 4,
                    block: 1,
                },
                MissingBlock {
                    recipient: 4,
                    block: 2,
                },
                MissingBlock {
                    recipient: 4,
                    block: 3,
                },
                MissingBlock {
                    recipient: 4,
                    block: 4,
                },
                MissingBlock {
                    recipient: 4,
                    block: 5,
                },
            ],
            &[100, 100, 100, 100, 100, 100],
            5,
            32,
            16,
            8,
        );

        assert_eq!(routes.routes.len(), 6);
        assert_eq!(routes.sender_payload_bytes[0], 108);
        assert_eq!(routes.sender_payload_bytes[1], 216);
        assert_eq!(routes.sender_payload_bytes[2], 216);
        assert_eq!(routes.sender_payload_bytes[3], 108);
        assert_eq!(routes.payload_bytes, 648);
        assert_eq!(routes.control_bytes, 224);
        assert_eq!(routes.latency_steps, 2);
    }

    #[test]
    fn routes_ignore_missing_blocks_without_live_holder() {
        let routes = route_missing_blocks_balanced(
            &[vec![1]],
            &[MissingBlock {
                recipient: 1,
                block: 0,
            }],
            &[100],
            2,
            32,
            16,
            8,
        );

        assert!(routes.routes.is_empty());
        assert_eq!(routes.payload_bytes, 0);
    }
}
