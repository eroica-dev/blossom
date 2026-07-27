use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};

const PARTS_PER_MILLION: u64 = 1_000_000;
const MAX_ANCHOR_SEED_ATTEMPTS: usize = 3;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyTopologyConfig {
    pub ewma_weight_ppm: u32,
    pub max_observation_age_millis: u64,
    pub max_metadata_relationships: usize,
}

impl Default for LatencyTopologyConfig {
    fn default() -> Self {
        Self {
            ewma_weight_ppm: 250_000,
            max_observation_age_millis: 30_000,
            max_metadata_relationships: 256,
        }
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct LatencyRelationship {
    pub source: PubKey,
    pub peer: PubKey,
    pub rtt_ewma_micros: u64,
    pub sample_count: u64,
    pub observed_at_millis: u64,
}

/// Bounded, reporter-owned observations suitable for application metadata.
///
/// This state is advisory. The receiver must authenticate `reporter` before
/// merging it; topology metadata never contributes to a consensus threshold.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct LatencyTopologyMetadataV1 {
    pub version: u16,
    pub reporter: PubKey,
    pub generated_at_millis: u64,
    pub relationships: Vec<LatencyRelationship>,
}

impl LatencyTopologyMetadataV1 {
    pub const VERSION: u16 = 1;
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LatencyEstimateMethod {
    Direct,
    Trilaterated,
    TriangleBounds,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LatencyEstimate {
    pub source: PubKey,
    pub peer: PubKey,
    pub rtt_micros: u64,
    pub lower_bound_micros: u64,
    pub upper_bound_micros: u64,
    pub method: LatencyEstimateMethod,
    pub anchors: Vec<PubKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClosestPeer {
    pub peer: PubKey,
    pub estimate: LatencyEstimate,
}

#[derive(Debug, Clone)]
pub struct LatencyTopology {
    config: LatencyTopologyConfig,
    relationships: BTreeMap<(PubKey, PubKey), LatencyRelationship>,
    neighbors: BTreeMap<PubKey, BTreeSet<PubKey>>,
}

impl Default for LatencyTopology {
    fn default() -> Self {
        Self::new(LatencyTopologyConfig::default())
    }
}

impl LatencyTopology {
    pub fn new(config: LatencyTopologyConfig) -> Self {
        assert!(config.ewma_weight_ppm <= PARTS_PER_MILLION as u32);
        assert!(config.max_observation_age_millis > 0);
        assert!(config.max_metadata_relationships > 0);
        Self {
            config,
            relationships: BTreeMap::new(),
            neighbors: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.relationships.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relationships.is_empty()
    }

    pub fn relationship(&self, source: PubKey, peer: PubKey) -> Option<&LatencyRelationship> {
        self.relationships.get(&(source, peer))
    }

    pub fn observe(
        &mut self,
        source: PubKey,
        peer: PubKey,
        rtt_micros: u64,
        observed_at_millis: u64,
    ) -> bool {
        if source == peer {
            return false;
        }
        let key = (source, peer);
        let (next, is_new) = match self.relationships.get(&key) {
            None => (
                LatencyRelationship {
                    source,
                    peer,
                    rtt_ewma_micros: rtt_micros,
                    sample_count: 1,
                    observed_at_millis,
                },
                true,
            ),
            Some(previous) => (
                LatencyRelationship {
                    source,
                    peer,
                    rtt_ewma_micros: ewma(
                        previous.rtt_ewma_micros,
                        rtt_micros,
                        u64::from(self.config.ewma_weight_ppm),
                    ),
                    sample_count: previous.sample_count.saturating_add(1),
                    observed_at_millis,
                },
                false,
            ),
        };
        self.relationships.insert(key, next);
        if is_new {
            self.index_pair(source, peer);
        }
        true
    }

    pub fn metadata(
        &self,
        reporter: PubKey,
        generated_at_millis: u64,
    ) -> LatencyTopologyMetadataV1 {
        let mut relationships = self
            .relationships
            .values()
            .filter(|relationship| relationship.source == reporter)
            .copied()
            .collect::<Vec<_>>();
        relationships.sort_by_key(|relationship| {
            (
                std::cmp::Reverse(relationship.observed_at_millis),
                std::cmp::Reverse(relationship.sample_count),
                relationship.peer,
            )
        });
        relationships.truncate(self.config.max_metadata_relationships);
        LatencyTopologyMetadataV1 {
            version: LatencyTopologyMetadataV1::VERSION,
            reporter,
            generated_at_millis,
            relationships,
        }
    }

    pub fn merge_metadata(
        &mut self,
        authenticated_reporter: PubKey,
        metadata: &LatencyTopologyMetadataV1,
        now_millis: u64,
    ) -> Result<usize> {
        self.validate_metadata(authenticated_reporter, metadata, now_millis)?;
        let mut merged = 0;
        for incoming in &metadata.relationships {
            let key = (incoming.source, incoming.peer);
            let current = self.relationships.get(&key);
            let replace = current.is_none_or(|current| {
                incoming.observed_at_millis > current.observed_at_millis
                    || (incoming.observed_at_millis == current.observed_at_millis
                        && incoming.sample_count > current.sample_count)
            });
            let is_new = current.is_none();
            if replace {
                self.relationships.insert(key, *incoming);
                if is_new {
                    self.index_pair(incoming.source, incoming.peer);
                }
                merged += 1;
            }
        }
        Ok(merged)
    }

    pub fn prune_stale(&mut self, now_millis: u64) -> usize {
        let before = self.relationships.len();
        let max_age = self.config.max_observation_age_millis;
        self.relationships.retain(|_, relationship| {
            now_millis.saturating_sub(relationship.observed_at_millis) <= max_age
        });
        let removed = before - self.relationships.len();
        if removed > 0 {
            self.rebuild_neighbors();
        }
        removed
    }

    /// Estimates an unmeasured RTT by placing both nodes against three common
    /// anchors with the law of cosines. Every estimate retains the exact
    /// triangle-inequality interval implied by all common anchors.
    pub fn estimate(
        &self,
        source: PubKey,
        peer: PubKey,
        now_millis: u64,
    ) -> Option<LatencyEstimate> {
        if source == peer {
            return Some(direct_estimate(source, peer, 0));
        }
        if let Some(distance) = self.fresh_direct_distance(source, peer, now_millis) {
            return Some(direct_estimate(source, peer, distance));
        }
        self.estimate_indirect(source, peer, now_millis)
    }

    /// Returns a fresh measured relationship without constructing a geometric
    /// view or inferring an unmeasured path.
    pub fn direct_rtt_micros(&self, source: PubKey, peer: PubKey, now_millis: u64) -> Option<u64> {
        if source == peer {
            return Some(0);
        }
        self.fresh_direct_distance(source, peer, now_millis)
    }

    pub fn closest_peer(
        &self,
        source: PubKey,
        peers: impl IntoIterator<Item = PubKey>,
        now_millis: u64,
    ) -> Option<ClosestPeer> {
        peers
            .into_iter()
            .filter_map(|peer| {
                self.estimate(source, peer, now_millis)
                    .map(|estimate| ClosestPeer { peer, estimate })
            })
            .min_by_key(|choice| (choice.estimate.rtt_micros, choice.peer))
    }

    fn estimate_indirect(
        &self,
        source: PubKey,
        peer: PubKey,
        now_millis: u64,
    ) -> Option<LatencyEstimate> {
        let common = self.common_anchors(source, peer, now_millis);
        if common.is_empty() {
            return None;
        }
        let (lower, upper) = self.triangle_bounds(source, peer, &common, now_millis)?;
        let trilaterated = self
            .select_trilateration_anchors(&common, now_millis)
            .and_then(|anchors| {
                self.trilaterated_distance(source, peer, anchors, now_millis)
                    .map(|estimate| (estimate, anchors))
            });

        let (rtt_micros, method, anchors) = match trilaterated {
            Some((estimate, anchors)) => {
                let mut reported_anchors = anchors.to_vec();
                reported_anchors.sort_unstable();
                (
                    f64_to_u64(estimate).clamp(lower, upper),
                    LatencyEstimateMethod::Trilaterated,
                    reported_anchors,
                )
            }
            None => (upper, LatencyEstimateMethod::TriangleBounds, common),
        };
        Some(LatencyEstimate {
            source,
            peer,
            rtt_micros,
            lower_bound_micros: lower,
            upper_bound_micros: upper,
            method,
            anchors,
        })
    }

    fn common_anchors(&self, source: PubKey, peer: PubKey, now_millis: u64) -> Vec<PubKey> {
        let Some(source_neighbors) = self.neighbors.get(&source) else {
            return Vec::new();
        };
        let Some(peer_neighbors) = self.neighbors.get(&peer) else {
            return Vec::new();
        };
        source_neighbors
            .intersection(peer_neighbors)
            .copied()
            .filter(|anchor| *anchor != source && *anchor != peer)
            .filter(|anchor| {
                self.fresh_direct_distance(source, *anchor, now_millis)
                    .is_some()
                    && self
                        .fresh_direct_distance(peer, *anchor, now_millis)
                        .is_some()
            })
            .collect()
    }

    fn triangle_bounds(
        &self,
        source: PubKey,
        peer: PubKey,
        anchors: &[PubKey],
        now_millis: u64,
    ) -> Option<(u64, u64)> {
        let mut lower = 0;
        let mut upper = u64::MAX;
        for anchor in anchors {
            let source_distance = self.fresh_direct_distance(source, *anchor, now_millis)?;
            let peer_distance = self.fresh_direct_distance(peer, *anchor, now_millis)?;
            lower = lower.max(source_distance.abs_diff(peer_distance));
            upper = upper.min(source_distance.saturating_add(peer_distance));
        }
        (lower <= upper).then_some((lower, upper))
    }

    fn select_trilateration_anchors(
        &self,
        common: &[PubKey],
        now_millis: u64,
    ) -> Option<[PubKey; 3]> {
        for first in common.iter().take(MAX_ANCHOR_SEED_ATTEMPTS).copied() {
            let Some((baseline_distance, second)) = common
                .iter()
                .copied()
                .filter(|candidate| *candidate != first)
                .filter_map(|candidate| {
                    self.fresh_direct_distance(first, candidate, now_millis)
                        .map(|distance| (distance, candidate))
                })
                .max()
            else {
                continue;
            };
            if baseline_distance == 0 {
                continue;
            }

            let Some((_, third)) = common
                .iter()
                .copied()
                .filter(|candidate| *candidate != first && *candidate != second)
                .filter_map(|candidate| {
                    let first_distance =
                        self.fresh_direct_distance(first, candidate, now_millis)? as f64;
                    let second_distance =
                        self.fresh_direct_distance(second, candidate, now_millis)? as f64;
                    let point = point_from_two_distances(
                        first_distance,
                        second_distance,
                        baseline_distance as f64,
                    )?;
                    (point.1 > f64::EPSILON).then_some((point.1, candidate))
                })
                .max_by(|left, right| {
                    left.0
                        .total_cmp(&right.0)
                        .then_with(|| left.1.cmp(&right.1))
                })
            else {
                continue;
            };
            return Some([first, second, third]);
        }
        None
    }

    fn trilaterated_distance(
        &self,
        source: PubKey,
        peer: PubKey,
        anchors: [PubKey; 3],
        now_millis: u64,
    ) -> Option<f64> {
        let ab = self.fresh_direct_distance(anchors[0], anchors[1], now_millis)? as f64;
        let ac = self.fresh_direct_distance(anchors[0], anchors[2], now_millis)? as f64;
        let bc = self.fresh_direct_distance(anchors[1], anchors[2], now_millis)? as f64;
        let anchor_c = point_from_two_distances(ac, bc, ab)?;
        if anchor_c.1 <= f64::EPSILON {
            return None;
        }

        let source_point =
            self.locate_against_anchors(source, anchors, ab, anchor_c, now_millis)?;
        let peer_point = self.locate_against_anchors(peer, anchors, ab, anchor_c, now_millis)?;
        Some(euclidean(source_point, peer_point))
    }

    fn locate_against_anchors(
        &self,
        node: PubKey,
        anchors: [PubKey; 3],
        ab: f64,
        anchor_c: (f64, f64),
        now_millis: u64,
    ) -> Option<(f64, f64)> {
        let distance_a = self.fresh_direct_distance(node, anchors[0], now_millis)? as f64;
        let distance_b = self.fresh_direct_distance(node, anchors[1], now_millis)? as f64;
        let distance_c = self.fresh_direct_distance(node, anchors[2], now_millis)? as f64;
        let point = point_from_two_distances(distance_a, distance_b, ab)?;
        let positive_error = (euclidean(point, anchor_c) - distance_c).abs();
        let negative = (point.0, -point.1);
        let negative_error = (euclidean(negative, anchor_c) - distance_c).abs();
        if negative_error < positive_error {
            Some(negative)
        } else {
            Some(point)
        }
    }

    fn index_pair(&mut self, first: PubKey, second: PubKey) {
        self.neighbors.entry(first).or_default().insert(second);
        self.neighbors.entry(second).or_default().insert(first);
    }

    fn rebuild_neighbors(&mut self) {
        let mut neighbors = BTreeMap::<PubKey, BTreeSet<PubKey>>::new();
        for &(first, second) in self.relationships.keys() {
            neighbors.entry(first).or_default().insert(second);
            neighbors.entry(second).or_default().insert(first);
        }
        self.neighbors = neighbors;
    }

    fn fresh_direct_distance(&self, first: PubKey, second: PubKey, now_millis: u64) -> Option<u64> {
        let fresh = |relationship: &&LatencyRelationship| {
            now_millis.saturating_sub(relationship.observed_at_millis)
                <= self.config.max_observation_age_millis
        };
        let forward = self.relationships.get(&(first, second)).filter(fresh);
        let reverse = self.relationships.get(&(second, first)).filter(fresh);
        match (forward, reverse) {
            (Some(forward), Some(reverse)) => Some(
                ((u128::from(forward.rtt_ewma_micros) + u128::from(reverse.rtt_ewma_micros)) / 2)
                    as u64,
            ),
            (Some(relationship), None) | (None, Some(relationship)) => {
                Some(relationship.rtt_ewma_micros)
            }
            (None, None) => None,
        }
    }

    fn validate_metadata(
        &self,
        authenticated_reporter: PubKey,
        metadata: &LatencyTopologyMetadataV1,
        now_millis: u64,
    ) -> Result<()> {
        if metadata.version != LatencyTopologyMetadataV1::VERSION {
            return Err(BlossomError::WireProtocol(format!(
                "unsupported latency topology metadata version {}",
                metadata.version
            )));
        }
        if metadata.reporter != authenticated_reporter {
            return Err(BlossomError::KeyMismatch);
        }
        if metadata.relationships.len() > self.config.max_metadata_relationships {
            return Err(BlossomError::WireProtocol(
                "latency topology metadata exceeds its relationship bound".to_string(),
            ));
        }
        if metadata.generated_at_millis > now_millis.saturating_add(60_000) {
            return Err(BlossomError::WireProtocol(
                "latency topology metadata timestamp is too far in the future".to_string(),
            ));
        }
        for relationship in &metadata.relationships {
            if relationship.source != metadata.reporter
                || relationship.source == relationship.peer
                || relationship.sample_count == 0
                || relationship.observed_at_millis > metadata.generated_at_millis
            {
                return Err(BlossomError::WireProtocol(
                    "latency topology metadata contains an invalid relationship".to_string(),
                ));
            }
        }
        Ok(())
    }
}

fn direct_estimate(source: PubKey, peer: PubKey, distance: u64) -> LatencyEstimate {
    LatencyEstimate {
        source,
        peer,
        rtt_micros: distance,
        lower_bound_micros: distance,
        upper_bound_micros: distance,
        method: LatencyEstimateMethod::Direct,
        anchors: Vec::new(),
    }
}

pub fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn point_from_two_distances(
    distance_a: f64,
    distance_b: f64,
    anchor_distance: f64,
) -> Option<(f64, f64)> {
    if anchor_distance <= f64::EPSILON {
        return None;
    }
    let x = (distance_a.mul_add(distance_a, -distance_b * distance_b)
        + anchor_distance * anchor_distance)
        / (2.0 * anchor_distance);
    let y_squared = distance_a.mul_add(distance_a, -x * x);
    let tolerance = distance_a.mul_add(distance_a, 1.0) * 1e-9;
    if y_squared < -tolerance {
        return None;
    }
    Some((x, y_squared.max(0.0).sqrt()))
}

fn euclidean(first: (f64, f64), second: (f64, f64)) -> f64 {
    (first.0 - second.0).hypot(first.1 - second.1)
}

fn f64_to_u64(value: f64) -> u64 {
    if !value.is_finite() || value <= 0.0 {
        0
    } else if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value.round() as u64
    }
}

fn ewma(previous: u64, sample: u64, alpha_ppm: u64) -> u64 {
    let inverse = PARTS_PER_MILLION.saturating_sub(alpha_ppm);
    let numerator = u128::from(previous)
        .saturating_mul(u128::from(inverse))
        .saturating_add(u128::from(sample).saturating_mul(u128::from(alpha_ppm)))
        .saturating_add(u128::from(PARTS_PER_MILLION / 2));
    (numerator / u128::from(PARTS_PER_MILLION)).min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: u8) -> PubKey {
        PubKey([value; 32])
    }

    fn observe_distance(topology: &mut LatencyTopology, first: u8, second: u8, distance: f64) {
        topology.observe(key(first), key(second), f64_to_u64(distance), 10_000);
    }

    #[test]
    fn trilaterates_nodes_that_have_not_communicated_directly() {
        let mut topology = LatencyTopology::default();
        let points = BTreeMap::from([
            (1, (0.0, 0.0)),
            (2, (10_000.0, 0.0)),
            (3, (0.0, 10_000.0)),
            (4, (2_000.0, 3_000.0)),
            (5, (8_000.0, 7_000.0)),
        ]);
        for first in [1, 2, 3] {
            for second in [1, 2, 3, 4, 5] {
                if first < second || second > 3 {
                    observe_distance(
                        &mut topology,
                        first,
                        second,
                        euclidean(points[&first], points[&second]),
                    );
                }
            }
        }

        let estimate = topology.estimate(key(4), key(5), 10_000).unwrap();
        assert_eq!(estimate.method, LatencyEstimateMethod::Trilaterated);
        assert_eq!(estimate.anchors, vec![key(1), key(2), key(3)]);
        assert!(estimate.rtt_micros.abs_diff(7_211) <= 2);
        assert!(estimate.lower_bound_micros <= estimate.rtt_micros);
        assert!(estimate.rtt_micros <= estimate.upper_bound_micros);
    }

    #[test]
    fn third_anchor_resolves_reflection_and_closest_peer_uses_the_result() {
        let mut topology = LatencyTopology::default();
        let points = BTreeMap::from([
            (1, (0.0, 0.0)),
            (2, (10_000.0, 0.0)),
            (3, (0.0, 10_000.0)),
            (4, (2_000.0, 3_000.0)),
            (5, (8_000.0, -7_000.0)),
            (6, (4_000.0, 4_000.0)),
        ]);
        for node in [4, 5, 6] {
            for anchor in [1, 2, 3] {
                observe_distance(
                    &mut topology,
                    anchor,
                    node,
                    euclidean(points[&anchor], points[&node]),
                );
            }
        }
        for (first, second) in [(1, 2), (1, 3), (2, 3)] {
            observe_distance(
                &mut topology,
                first,
                second,
                euclidean(points[&first], points[&second]),
            );
        }

        let reflected = topology.estimate(key(4), key(5), 10_000).unwrap();
        assert!(reflected.rtt_micros.abs_diff(11_662) <= 2);
        let closest = topology
            .closest_peer(key(4), [key(5), key(6)], 10_000)
            .unwrap();
        assert_eq!(closest.peer, key(6));
    }

    #[test]
    fn falls_back_to_honest_triangle_bounds() {
        let mut topology = LatencyTopology::default();
        observe_distance(&mut topology, 1, 3, 4_000.0);
        observe_distance(&mut topology, 2, 3, 6_000.0);
        let estimate = topology.estimate(key(1), key(2), 10_000).unwrap();
        assert_eq!(estimate.method, LatencyEstimateMethod::TriangleBounds);
        assert_eq!(estimate.lower_bound_micros, 2_000);
        assert_eq!(estimate.upper_bound_micros, 10_000);
        assert_eq!(estimate.rtt_micros, 10_000);
    }

    #[test]
    fn stale_relationships_do_not_inform_estimates() {
        let mut topology = LatencyTopology::default();
        topology.observe(key(1), key(2), 1_000, 1_000);
        assert_eq!(
            topology.direct_rtt_micros(key(1), key(2), 31_000),
            Some(1_000)
        );
        assert!(topology.estimate(key(1), key(2), 31_000).is_some());
        assert_eq!(topology.direct_rtt_micros(key(1), key(2), 31_001), None);
        assert!(topology.estimate(key(1), key(2), 31_001).is_none());
        assert_eq!(topology.prune_stale(31_001), 1);
    }

    #[test]
    fn metadata_is_bounded_owned_and_idempotent() {
        let config = LatencyTopologyConfig {
            max_metadata_relationships: 2,
            ..LatencyTopologyConfig::default()
        };
        let mut source = LatencyTopology::new(config);
        source.observe(key(1), key(2), 1_000, 10);
        source.observe(key(1), key(3), 2_000, 20);
        source.observe(key(1), key(4), 3_000, 30);
        source.observe(key(2), key(5), 4_000, 40);
        let metadata = source.metadata(key(1), 50);
        assert_eq!(metadata.relationships.len(), 2);
        assert!(
            metadata
                .relationships
                .iter()
                .all(|relationship| relationship.source == key(1))
        );

        let encoded = borsh::to_vec(&metadata).unwrap();
        assert!(encoded.len() < 1024);
        let mut target = LatencyTopology::new(config);
        assert_eq!(target.merge_metadata(key(1), &metadata, 50).unwrap(), 2);
        assert_eq!(target.merge_metadata(key(1), &metadata, 50).unwrap(), 0);
        assert!(target.merge_metadata(key(2), &metadata, 50).is_err());
    }

    #[test]
    fn bounded_anchor_selection_skips_an_unusable_seed() {
        let mut topology = LatencyTopology::default();
        let source = key(200);
        let peer = key(201);
        let points = BTreeMap::from([
            (key(1), (-10_000.0, -10_000.0)),
            (key(2), (0.0, 0.0)),
            (key(3), (10_000.0, 0.0)),
            (key(4), (0.0, 10_000.0)),
            (source, (2_000.0, 3_000.0)),
            (peer, (8_000.0, 7_000.0)),
        ]);
        for anchor in [key(1), key(2), key(3), key(4)] {
            topology.observe(
                source,
                anchor,
                f64_to_u64(euclidean(points[&source], points[&anchor])),
                10_000,
            );
            topology.observe(
                peer,
                anchor,
                f64_to_u64(euclidean(points[&peer], points[&anchor])),
                10_000,
            );
        }
        for (first, second) in [(key(2), key(3)), (key(2), key(4)), (key(3), key(4))] {
            topology.observe(
                first,
                second,
                f64_to_u64(euclidean(points[&first], points[&second])),
                10_000,
            );
        }

        let estimate = topology.estimate(source, peer, 10_000).unwrap();
        assert_eq!(estimate.method, LatencyEstimateMethod::Trilaterated);
        assert_eq!(estimate.anchors, vec![key(2), key(3), key(4)]);
        assert!(estimate.rtt_micros.abs_diff(7_211) <= 2);
    }

    #[test]
    fn bounds_trilateration_work_with_many_common_anchors() {
        let mut topology = LatencyTopology::default();
        let source = PubKey([200; 32]);
        let peer = PubKey([201; 32]);
        let source_point = (2_000.0, 3_000.0);
        let peer_point = (8_000.0, 7_000.0);
        let anchors = (0..24)
            .map(|index| {
                let angle = std::f64::consts::TAU * f64::from(index) / 24.0;
                (
                    key(index + 1),
                    (20_000.0 * angle.cos(), 20_000.0 * angle.sin()),
                )
            })
            .collect::<Vec<_>>();

        for (anchor, point) in &anchors {
            topology.observe(
                source,
                *anchor,
                f64_to_u64(euclidean(source_point, *point)),
                10_000,
            );
            topology.observe(
                peer,
                *anchor,
                f64_to_u64(euclidean(peer_point, *point)),
                10_000,
            );
        }
        for first in 0..anchors.len() {
            for second in (first + 1)..anchors.len() {
                topology.observe(
                    anchors[first].0,
                    anchors[second].0,
                    f64_to_u64(euclidean(anchors[first].1, anchors[second].1)),
                    10_000,
                );
            }
        }

        let common = topology.common_anchors(source, peer, 10_000);
        assert_eq!(common.len(), 24);
        assert_eq!(
            topology
                .select_trilateration_anchors(&common, 10_000)
                .unwrap()
                .len(),
            3
        );

        let estimate = topology.estimate(source, peer, 10_000).unwrap();
        assert_eq!(estimate.method, LatencyEstimateMethod::Trilaterated);
        assert_eq!(estimate.anchors.len(), 3);
        assert!(estimate.rtt_micros.abs_diff(7_211) <= 2);
    }
}
