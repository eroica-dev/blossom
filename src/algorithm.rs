use crate::crypto::PubKey;
use crate::hash::HashType;

pub const QUORUM_SIZE: usize = 6;
pub const SUPERMAJORITY: f64 = 2.0 / 3.0;

pub fn select_quorums(
    nodes: impl IntoIterator<Item = PubKey>,
    self_key: &PubKey,
    seed: HashType,
    shuffle: bool,
) -> Vec<Vec<PubKey>> {
    let mut ordered_nodes: Vec<PubKey> = nodes.into_iter().collect();
    ordered_nodes.sort_unstable();

    if ordered_nodes.is_empty() {
        return Vec::new();
    }

    let self_index = match ordered_nodes.iter().position(|node| node == self_key) {
        Some(index) => index,
        None => return Vec::new(),
    };

    let (optimal_network_size, rounds) = find_round_number(ordered_nodes.len());
    if optimal_network_size == 0 || rounds == 0 {
        return Vec::new();
    }

    let mut ordered_indices: Vec<usize> = (0..ordered_nodes.len()).collect();
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
        &ordered_nodes,
        &ordered_indices,
        self_index,
        optimal_network_size,
        rounds,
    )
}

pub fn algorithm(
    ordered_nodes: &[PubKey],
    ordered_indices: &[usize],
    mut self_index: usize,
    optimal_network_size: usize,
    rounds: usize,
) -> Vec<Vec<PubKey>> {
    let mut quorum_members_matrix = Vec::new();
    if ordered_nodes.is_empty() || optimal_network_size == 0 {
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
        for quorum_member in 0..QUORUM_SIZE {
            let index = first_quorum_member + (quorum_member * size_multiple * offset);
            if index >= ordered_nodes.len() {
                break;
            }
            quorum.push(ordered_nodes[index]);
        }

        if ordered_indices.len() >= optimal_network_size {
            for quorum_member in 0..QUORUM_SIZE {
                let index = optimal_network_size
                    + first_quorum_member
                    + (quorum_member * size_multiple * offset);
                if index >= ordered_nodes.len() {
                    break;
                }
                quorum.push(ordered_nodes[index]);
            }
        }

        quorum.sort_unstable();
        quorum.dedup();
        quorum_members_matrix.push(quorum);
    }

    quorum_members_matrix
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
}
