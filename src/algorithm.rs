use std::collections::BTreeSet;

use crate::crypto::PubKey;
use crate::hash::HashType;
use indextreemap::IndexTreeMap;

pub const QUORUM_SIZE: usize = 6;
pub const SUPERMAJORITY: f64 = 2.0 / 3.0;

pub fn select_quorums(
    nodes: impl IntoIterator<Item = PubKey>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
) -> Vec<Vec<PubKey>> {
    let mut node_map = IndexTreeMap::new();
    for node in nodes {
        node_map.insert(node, ());
    }

    select_quorums_from_index_tree(&node_map, self_key, seed, shuffle)
}

pub fn select_quorums_from_index_tree<N>(
    node_map: &IndexTreeMap<PubKey, N>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
) -> Vec<Vec<PubKey>>
where
    N: Default + Clone,
{
    if node_map.is_empty() {
        return Vec::new();
    }

    let self_index = match node_map.get_index_from_key(self_key) {
        Some(index) => index,
        None => return Vec::new(),
    };

    let (optimal_network_size, rounds) = find_round_number(node_map.len());
    if optimal_network_size == 0 || rounds == 0 {
        return Vec::new();
    }

    let mut ordered_indices: Vec<usize> = (0..node_map.len()).collect();
    let self_index = if shuffle {
        deterministic_shuffle(&mut ordered_indices, seed);
        ordered_indices
            .iter()
            .position(|index| *index == self_index)
            .unwrap_or(self_index)
    } else {
        self_index
    };

    algorithm(
        node_map,
        &ordered_indices,
        self_index,
        optimal_network_size,
        rounds,
    )
}

pub fn algorithm<N>(
    node_map: &IndexTreeMap<PubKey, N>,
    ordered_indices: &[usize],
    mut self_index: usize,
    optimal_network_size: usize,
    rounds: usize,
) -> Vec<Vec<PubKey>>
where
    N: Default + Clone,
{
    let mut quorum_members_matrix = Vec::new();
    if node_map.is_empty() || optimal_network_size == 0 {
        return quorum_members_matrix;
    }

    self_index = if self_index >= optimal_network_size {
        self_index % optimal_network_size
    } else {
        self_index
    };

    for mut round in 0..rounds {
        let mut ceiling_network_size = QUORUM_SIZE.pow(round as u32 + 1);
        let mut max_network_size = ceiling_network_size;
        let mut size_multiple = 1;

        if ceiling_network_size > optimal_network_size {
            ceiling_network_size = QUORUM_SIZE.pow(round as u32);
            round = round.saturating_sub(1);
            max_network_size = optimal_network_size;
            size_multiple = (optimal_network_size / ceiling_network_size).max(1);
        }

        let offset = QUORUM_SIZE.pow(round as u32);
        let first_quorum_member = (self_index - (self_index % max_network_size))
            + (self_index % (size_multiple * offset));

        let mut quorum = Vec::new();
        push_quorum_members(
            &mut quorum,
            node_map,
            ordered_indices,
            first_quorum_member,
            size_multiple,
            offset,
        );

        if ordered_indices.len() >= optimal_network_size {
            push_quorum_members(
                &mut quorum,
                node_map,
                ordered_indices,
                optimal_network_size + first_quorum_member,
                size_multiple,
                offset,
            );
        }

        quorum.sort_unstable();
        quorum.dedup();
        quorum_members_matrix.push(quorum);
    }

    quorum_members_matrix
}

fn push_quorum_members<N>(
    quorum: &mut Vec<PubKey>,
    node_map: &IndexTreeMap<PubKey, N>,
    ordered_indices: &[usize],
    first_quorum_member: usize,
    size_multiple: usize,
    offset: usize,
) where
    N: Default + Clone,
{
    for quorum_member in 0..QUORUM_SIZE {
        let index = first_quorum_member + (quorum_member * size_multiple * offset);
        match member_at(node_map, ordered_indices, index) {
            Some(member) => quorum.push(member),
            None => break,
        }
    }
}

fn member_at<N>(
    node_map: &IndexTreeMap<PubKey, N>,
    ordered_indices: &[usize],
    index: usize,
) -> Option<PubKey>
where
    N: Default + Clone,
{
    let map_index = ordered_indices.get(index).copied()?;
    node_map.get_key_from_index(map_index).copied()
}

pub fn deterministic_shuffle(indices: &mut [usize], seed: HashType) {
    let mut state = u64::from_le_bytes(seed.0[0..8].try_into().unwrap_or([1; 8]));
    if state == 0 {
        state = 0x9e37_79b9_7f4a_7c15;
    }

    for i in (1..indices.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let j = (state as usize) % (i + 1);
        indices.swap(i, j);
    }
}

pub fn find_round_number(network_size: usize) -> (usize, usize) {
    if network_size == 0 {
        return (0, 0);
    }
    if network_size <= QUORUM_SIZE {
        return (network_size, 1);
    }

    let network_size_logarithm = float_tolerance((network_size as f64).log(QUORUM_SIZE as f64));
    let logarithm_floor = network_size_logarithm.floor();
    let base_network_size = f64::powf(QUORUM_SIZE as f64, logarithm_floor);
    let optimal_network_size =
        base_network_size * (network_size as f64 / base_network_size).floor();
    let rounds = float_tolerance(optimal_network_size.log(QUORUM_SIZE as f64)).ceil();

    (optimal_network_size as usize, rounds as usize)
}

pub fn supermajority_count(total: usize) -> usize {
    total - (total / 3)
}

/// Returns true when a distinct-voter count reaches the Blossom supermajority.
///
/// Counts larger than `total` are rejected so duplicated or Sybil evidence
/// cannot satisfy a proof by over-counting.
pub fn has_supermajority(total: usize, count: usize) -> bool {
    total > 0 && count <= total && count >= supermajority_count(total)
}

/// Counts distinct voters that belong to the current validator set.
pub fn distinct_current_validator_count<T>(
    voters: impl IntoIterator<Item = T>,
    current_validators: impl IntoIterator<Item = T>,
) -> usize
where
    T: Ord + Copy,
{
    let current_validators = current_validators.into_iter().collect::<BTreeSet<_>>();
    voters
        .into_iter()
        .filter(|voter| current_validators.contains(voter))
        .collect::<BTreeSet<_>>()
        .len()
}

/// Returns true when distinct current-validator evidence reaches supermajority.
pub fn has_distinct_supermajority<T>(
    voters: impl IntoIterator<Item = T>,
    current_validators: impl IntoIterator<Item = T>,
) -> bool
where
    T: Ord + Copy,
{
    let current_validators = current_validators.into_iter().collect::<BTreeSet<_>>();
    let count = voters
        .into_iter()
        .filter(|voter| current_validators.contains(voter))
        .collect::<BTreeSet<_>>()
        .len();
    has_supermajority(current_validators.len(), count)
}

/// Maximum Byzantine population tolerated by the honest-overlap proof.
pub fn byzantine_fault_bound(total: usize) -> usize {
    total.saturating_sub(1) / 3
}

/// Number of slow or absent validators that can be ignored for liveness.
///
/// This is intentionally separate from `byzantine_fault_bound`: a validator can
/// be slow without being Byzantine.
pub fn max_liveness_omissions(total: usize) -> usize {
    total.saturating_sub(supermajority_count(total))
}

/// Minimum overlap between any two accepted supermajority vote sets.
pub fn min_supermajority_intersection(total: usize) -> usize {
    let quorum = supermajority_count(total);
    quorum.saturating_mul(2).saturating_sub(total)
}

/// Returns true when two supermajorities must share at least one honest voter.
pub fn supermajority_has_honest_overlap(total: usize) -> bool {
    total > 0 && min_supermajority_intersection(total) > byzantine_fault_bound(total)
}

/// Returns the slowest sample inside the fastest safe supermajority.
///
/// The caller must pass one sample per distinct current validator that has
/// supplied valid evidence. Fewer than a supermajority, or more samples than
/// eligible validators, means no valid supermajority proof exists.
pub fn supermajority_order_statistic<T, I>(samples: I, total: usize) -> Option<T>
where
    T: Ord + Copy,
    I: IntoIterator<Item = T>,
{
    let quorum = supermajority_count(total);
    if quorum == 0 {
        return None;
    }

    let mut samples = samples.into_iter().collect::<Vec<_>>();
    if samples.len() < quorum || samples.len() > total {
        return None;
    }

    samples.sort_unstable();
    samples.get(quorum - 1).copied()
}

fn float_tolerance(float: f64) -> f64 {
    let tolerance = 1_000_000_000.0;
    (float * tolerance).round() / tolerance
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: u8) -> PubKey {
        PubKey([index; 32])
    }

    #[test]
    fn round_number_matches_quorum_growth() {
        assert_eq!(find_round_number(0), (0, 0));
        assert_eq!(find_round_number(6), (6, 1));
        assert_eq!(find_round_number(36), (36, 2));
        assert_eq!(find_round_number(216), (216, 3));
    }

    #[test]
    fn selects_quorums_containing_self() {
        let nodes = (0..36).map(key).collect::<Vec<_>>();
        let quorums = select_quorums(nodes, &key(7), HashType::default(), false);

        assert_eq!(quorums.len(), 2);
        assert!(quorums.iter().all(|quorum| quorum.contains(&key(7))));
    }

    #[test]
    fn shuffled_quorums_still_contain_self() {
        let nodes = (0..36).map(key).collect::<Vec<_>>();
        let seed = HashType::hash(b"shuffle seed");
        let quorums = select_quorums(nodes, &key(7), seed, true);

        assert_eq!(quorums.len(), 2);
        assert!(quorums.iter().all(|quorum| quorum.contains(&key(7))));
    }

    #[test]
    fn empty_or_missing_self_produces_no_quorums() {
        assert!(
            select_quorums(Vec::<PubKey>::new(), &key(0), HashType::default(), false).is_empty()
        );
        assert!(select_quorums([key(1), key(2)], &key(0), HashType::default(), false).is_empty());
    }

    #[test]
    fn deterministic_shuffle_is_reproducible_and_seed_sensitive() {
        let seed = HashType::hash(b"seed");
        let mut first = (0..12).collect::<Vec<_>>();
        let mut second = (0..12).collect::<Vec<_>>();
        let mut different = (0..12).collect::<Vec<_>>();

        deterministic_shuffle(&mut first, seed);
        deterministic_shuffle(&mut second, seed);
        deterministic_shuffle(&mut different, HashType::hash(b"different"));

        assert_eq!(first, second);
        assert_ne!(first, different);
    }

    #[test]
    fn supermajority_matches_two_thirds_plus_one_boundary() {
        assert_eq!(supermajority_count(0), 0);
        assert_eq!(supermajority_count(1), 1);
        assert_eq!(supermajority_count(3), 2);
        assert_eq!(supermajority_count(6), 4);
        assert_eq!(supermajority_count(7), 5);
    }

    #[test]
    fn supermajority_count_rejects_under_threshold_and_overfull_votes() {
        assert!(!has_supermajority(0, 0));
        assert!(!has_supermajority(6, 3));
        assert!(has_supermajority(6, 4));
        assert!(has_supermajority(6, 6));
        assert!(!has_supermajority(6, 7));
    }

    #[test]
    fn distinct_current_validator_supermajority_ignores_duplicates_and_outsiders() {
        let current_validators = [key(0), key(1), key(2), key(3), key(4), key(5)];
        let voters = [key(0), key(0), key(1), key(2), key(3), key(99)];

        assert_eq!(
            distinct_current_validator_count(voters, current_validators),
            4
        );
        assert!(has_distinct_supermajority(voters, current_validators));
    }

    #[test]
    fn distinct_current_validator_supermajority_rejects_duplicate_shortfall() {
        let current_validators = [key(0), key(1), key(2), key(3), key(4), key(5)];
        let voters = [key(0), key(0), key(1), key(2), key(99)];

        assert_eq!(
            distinct_current_validator_count(voters, current_validators),
            3
        );
        assert!(!has_distinct_supermajority(voters, current_validators));
    }

    #[test]
    fn six_node_quorum_distinguishes_liveness_from_byzantine_safety() {
        assert_eq!(supermajority_count(6), 4);
        assert_eq!(max_liveness_omissions(6), 2);
        assert_eq!(byzantine_fault_bound(6), 1);
        assert_eq!(min_supermajority_intersection(6), 2);
        assert!(supermajority_has_honest_overlap(6));
    }

    #[test]
    fn supermajority_intersection_exceeds_bft_fault_bound() {
        for total in 1..=256 {
            assert!(
                supermajority_has_honest_overlap(total),
                "total={total} quorum={} min_intersection={} max_byzantine={}",
                supermajority_count(total),
                min_supermajority_intersection(total),
                byzantine_fault_bound(total)
            );
        }
    }

    #[test]
    fn one_below_supermajority_loses_honest_overlap_guarantee() {
        for total in 1..=256 {
            let unsafe_quorum = supermajority_count(total).saturating_sub(1);
            let max_byzantine = byzantine_fault_bound(total);
            let min_intersection = unsafe_quorum.saturating_mul(2).saturating_sub(total);

            assert!(
                min_intersection <= max_byzantine,
                "total={total} unsafe_quorum={unsafe_quorum} min_intersection={min_intersection} max_byzantine={max_byzantine}"
            );
        }
    }

    #[test]
    fn supermajority_order_statistic_uses_slowest_safe_supermajority() {
        let samples = [0, 10, 20, 100, 200, 300];

        assert_eq!(supermajority_order_statistic(samples, 6), Some(100));
    }

    #[test]
    fn supermajority_order_statistic_requires_distinct_current_validator_samples() {
        assert_eq!(supermajority_order_statistic([0, 10, 20], 6), None);
        assert_eq!(
            supermajority_order_statistic([0, 10, 20, 100, 200, 300, 1], 6),
            None
        );
    }

    #[test]
    fn quorum_selection_is_deterministic_and_self_consistent_across_sizes() {
        for size in 1..80 {
            let nodes = (0..size).map(|index| key(index as u8)).collect::<Vec<_>>();
            let seed = HashType::hash(&[size as u8]);

            for self_key in &nodes {
                let first = select_quorums(nodes.iter().copied(), self_key, seed, true);
                let second = select_quorums(nodes.iter().copied(), self_key, seed, true);
                assert_eq!(first, second, "size {size} self {self_key}");
                assert!(!first.is_empty(), "size {size} self {self_key}");

                for quorum in &first {
                    assert!(quorum.contains(self_key), "size {size} self {self_key}");
                    let mut sorted = quorum.clone();
                    sorted.sort_unstable();
                    sorted.dedup();
                    assert_eq!(&sorted, quorum, "size {size} self {self_key}");
                    assert!(
                        quorum.len() <= QUORUM_SIZE * 2,
                        "size {size} self {self_key} quorum len {}",
                        quorum.len()
                    );
                }
            }
        }
    }

    #[test]
    fn quorum_members_agree_on_their_round_group() {
        for size in [6usize, 7, 12, 35, 36, 37, 72, 80] {
            let nodes = (0..size).map(|index| key(index as u8)).collect::<Vec<_>>();
            let seed = HashType::hash(&[size as u8, 42]);

            for self_key in &nodes {
                let self_quorums = select_quorums(nodes.iter().copied(), self_key, seed, true);
                for (round, quorum) in self_quorums.iter().enumerate() {
                    for peer in quorum {
                        let peer_quorums = select_quorums(nodes.iter().copied(), peer, seed, true);
                        assert_eq!(
                            peer_quorums.get(round),
                            Some(quorum),
                            "size {size} round {round} self {self_key} peer {peer}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const MAX_VALIDATORS: usize = 64;

    #[kani::proof]
    fn supermajority_has_honest_overlap_for_small_validator_sets() {
        let total: usize = kani::any();
        kani::assume(total > 0);
        kani::assume(total <= MAX_VALIDATORS);

        assert!(supermajority_has_honest_overlap(total));
    }

    #[kani::proof]
    fn one_below_supermajority_loses_honest_overlap_for_small_validator_sets() {
        let total: usize = kani::any();
        kani::assume(total > 0);
        kani::assume(total <= MAX_VALIDATORS);

        let unsafe_quorum = supermajority_count(total).saturating_sub(1);
        let max_byzantine = byzantine_fault_bound(total);
        let min_intersection = unsafe_quorum.saturating_mul(2).saturating_sub(total);

        assert!(min_intersection <= max_byzantine);
    }

    #[kani::proof]
    fn supermajority_count_matches_expected_boundary_for_small_validator_sets() {
        let total: usize = kani::any();
        kani::assume(total > 0);
        kani::assume(total <= MAX_VALIDATORS);

        let quorum = supermajority_count(total);

        assert!(has_supermajority(total, quorum));
        assert!(!has_supermajority(total, quorum.saturating_sub(1)));
        assert!(!has_supermajority(total, total + 1));
    }
}
