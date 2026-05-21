module blossom_thresholds {
  pure val MAX_N = 64

  pure def supermajority_count(n: int): int = n - n / 3
  pure def byzantine_fault_bound(n: int): int = (n - 1) / 3
  pure def max_liveness_omissions(n: int): int = n - supermajority_count(n)
  pure def min_supermajority_intersection(n: int): int =
    2 * supermajority_count(n) - n

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
}
