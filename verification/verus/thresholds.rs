//! Verus proofs for Blossom quorum-threshold arithmetic.

use vstd::prelude::*;

verus! {
    spec fn supermajority_count(n: nat) -> nat {
        n - n / 3
    }

    spec fn byzantine_fault_bound(n: nat) -> nat {
        (n - 1) / 3
    }

    spec fn max_liveness_omissions(n: nat) -> nat {
        n - supermajority_count(n)
    }

    spec fn min_supermajority_intersection(n: nat) -> nat {
        2 * supermajority_count(n) - n
    }

    proof fn six_node_thresholds()
        ensures
            supermajority_count(6) == 4,
            max_liveness_omissions(6) == 2,
            byzantine_fault_bound(6) == 1,
            min_supermajority_intersection(6) == 2,
    {
    }

    proof fn honest_overlap_boundary(n: nat)
        requires
            1 <= n,
            n <= 256,
        ensures
            min_supermajority_intersection(n) > byzantine_fault_bound(n),
    {
        assert(min_supermajority_intersection(n) > byzantine_fault_bound(n)) by(nonlinear_arith);
    }
}

fn main() {}
