//! Creusot proofs for Blossom quorum-threshold arithmetic.

use creusot_std::prelude::*;

#[requires(total@ <= 1_000_000)]
#[ensures(result@ == total@ - total@ / 3)]
pub fn supermajority_count(total: u64) -> u64 {
    total - (total / 3)
}

#[requires(total@ > 0)]
#[requires(total@ <= 1_000_000)]
#[ensures(result@ == (total@ - 1) / 3)]
pub fn byzantine_fault_bound(total: u64) -> u64 {
    (total - 1) / 3
}

#[requires(total@ > 0)]
#[requires(total@ <= 1_000_000)]
#[ensures(result@ == total@ - (total@ - total@ / 3))]
pub fn max_liveness_omissions(total: u64) -> u64 {
    total - supermajority_count(total)
}

#[requires(total@ > 0)]
#[requires(total@ <= 1_000_000)]
#[ensures(result@ == 2 * (total@ - total@ / 3) - total@)]
pub fn min_supermajority_intersection(total: u64) -> u64 {
    let quorum = supermajority_count(total);
    (2 * quorum) - total
}

#[requires(total@ > 0)]
#[requires(total@ <= 1_000_000)]
#[ensures(result == (2 * (total@ - total@ / 3) - total@ > (total@ - 1) / 3))]
pub fn supermajority_has_honest_overlap(total: u64) -> bool {
    min_supermajority_intersection(total) > byzantine_fault_bound(total)
}

#[requires(total@ == 6)]
#[ensures(total@ - total@ / 3 == 4)]
#[ensures(total@ - (total@ - total@ / 3) == 2)]
#[ensures((total@ - 1) / 3 == 1)]
#[ensures(2 * (total@ - total@ / 3) - total@ == 2)]
pub fn six_node_thresholds(total: u64) {}
