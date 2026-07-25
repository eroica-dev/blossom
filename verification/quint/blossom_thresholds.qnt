module blossom_thresholds {
  pure val MAX_N = 64

  pure def supermajority_count(n: int): int = n - n / 3
  pure def byzantine_fault_bound(n: int): int = (n - 1) / 3
  pure def max_liveness_omissions(n: int): int = n - supermajority_count(n)
  pure def min_supermajority_intersection(n: int): int =
    2 * supermajority_count(n) - n
  pure def valid_branching_factor(q: int): bool = q >= 3 and q % 3 == 0
  pure def effective_branching_factor(q: int, n: int): int =
    if (q < n) q else n
  pure def ha_majority(n: int): int = n / 2 + 1
  pure def ha_tolerated_inactive(n: int): int = n - ha_majority(n)
  pure def ha_minimum_intersection(n: int): int = 2 * ha_majority(n) - n

  var tick: int

  action init = tick' = 0
  action step = tick' = tick

  val honest_overlap_boundary =
    1.to(MAX_N).forall(n =>
      min_supermajority_intersection(n) > byzantine_fault_bound(n)
    )

  val unsafe_boundary =
    1.to(MAX_N).forall(n =>
      2 * (supermajority_count(n) - 1) - n <= byzantine_fault_bound(n)
    )

  val six_node_thresholds =
    supermajority_count(6) == 4 and
    max_liveness_omissions(6) == 2 and
    byzantine_fault_bound(6) == 1 and
    min_supermajority_intersection(6) == 2

  val configurable_branching_factors =
    1.to(MAX_N).forall(n =>
      1.to(21).forall(k =>
        valid_branching_factor(3 * k) and
        effective_branching_factor(3 * k, n) <= 3 * k and
        effective_branching_factor(3 * k, n) <= n
      )
    )

  val ha_two_through_seven_thresholds =
    ha_majority(2) == 2 and ha_tolerated_inactive(2) == 0 and
    ha_majority(3) == 2 and ha_tolerated_inactive(3) == 1 and
    ha_majority(4) == 3 and ha_tolerated_inactive(4) == 1 and
    ha_majority(5) == 3 and ha_tolerated_inactive(5) == 2 and
    ha_majority(6) == 4 and ha_tolerated_inactive(6) == 2 and
    ha_majority(7) == 4 and ha_tolerated_inactive(7) == 3

  val ha_strict_majorities_intersect =
    2.to(7).forall(n => ha_minimum_intersection(n) >= 1)
}
