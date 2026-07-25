use std::collections::BTreeMap;

use blossom::{
    AmendmentPayload, AmendmentRecord, BlossomError, ClientEpoch, ClientId, CommandIdentity,
    ConsensusGroupId, HaAcknowledge, HaConfirm, HaDispatch, HaMemberSlot, HaPeerCompatibility,
    HaRuntimeEvent, HaServiceDirective, HashType, HighAvailabilityParameters,
    HighAvailabilityRuntime, NodeAvailabilityStatus, NodeIdentity, Nonce, PubKey, Result,
    Transaction, high_availability_fault_tolerance, high_availability_majority,
};
use serde::{Deserialize, Serialize};

const RATE_DENOMINATOR: u64 = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaChaosConfig {
    pub nodes: usize,
    pub epochs: usize,
    pub seed: u64,
    pub drop_ppm: u32,
    pub duplicate_ppm: u32,
    pub boundary_crash_interval: usize,
    pub redeploy_interval: usize,
    pub isolation_interval: usize,
    pub corruption_probe_interval: usize,
    pub amendment_interval: usize,
    pub max_delivery_attempts: usize,
}

impl Default for HaChaosConfig {
    fn default() -> Self {
        Self {
            nodes: 7,
            epochs: 1_200,
            seed: 0x6861_5f63_6861_6f73,
            drop_ppm: 200_000,
            duplicate_ppm: 100_000,
            boundary_crash_interval: 11,
            redeploy_interval: 113,
            isolation_interval: 313,
            corruption_probe_interval: 173,
            amendment_interval: 37,
            max_delivery_attempts: 64,
        }
    }
}

impl HaChaosConfig {
    pub fn validate(&self) -> Result<()> {
        if !(2..=7).contains(&self.nodes) {
            return Err(BlossomError::InvalidHighAvailabilityNodeCount(self.nodes));
        }
        if self.epochs == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "HA chaos epochs must be positive".to_string(),
            ));
        }
        if self.drop_ppm >= RATE_DENOMINATOR as u32 || self.duplicate_ppm >= RATE_DENOMINATOR as u32
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA chaos rates must be below 1,000,000 ppm".to_string(),
            ));
        }
        if self.max_delivery_attempts == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "HA chaos delivery attempts must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HaChaosFault {
    BoundaryCrash { offline_slots: Vec<u8> },
    AsymmetricPacketLoss { dropped_attempts: u64 },
    ReorderedDelivery { deliveries: u64 },
    DuplicateDelivery { duplicates: u64 },
    MinorityIsolation { slot: u8, remaining_epochs: u32 },
    ExpectedQuorumLoss { available: u8, required: u8 },
    MemberSuspended { slot: u8 },
    MemberReactivated { slot: u8 },
    ServiceRedeployed { slot: u8 },
    CorruptSnapshotRejected { slot: u8 },
    MutableAmendment { target: Nonce },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaChaosEpochTrace {
    pub epoch: usize,
    pub nonce_before: Nonce,
    pub nonce_after: Nonce,
    pub active_mask: u8,
    pub participant_mask: u8,
    pub required: u8,
    pub finalized_hash: HashType,
    pub sealed: u64,
    pub faults: Vec<HaChaosFault>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaChaosReport {
    pub config: HaChaosConfig,
    pub finalized_epochs: usize,
    pub expected_quorum_stalls: u64,
    pub unexpected_stalls: u64,
    pub dropped_attempts: u64,
    pub duplicate_deliveries: u64,
    pub reordered_deliveries: u64,
    pub boundary_crashes: u64,
    pub recoveries: u64,
    pub redeployments: u64,
    pub suspensions: u64,
    pub reactivations: u64,
    pub corrupt_snapshots_rejected: u64,
    pub amendments: u64,
    pub final_nonce: Nonce,
    pub final_hash: HashType,
    pub final_revision: HashType,
    pub safety_violations: Vec<String>,
    pub traces: Vec<HaChaosEpochTrace>,
}

#[derive(Default)]
struct DeliveryStats {
    dropped_attempts: u64,
    duplicate_deliveries: u64,
    reordered_deliveries: u64,
}

impl DeliveryStats {
    fn merge(&mut self, other: Self) {
        self.dropped_attempts = self.dropped_attempts.saturating_add(other.dropped_attempts);
        self.duplicate_deliveries = self
            .duplicate_deliveries
            .saturating_add(other.duplicate_deliveries);
        self.reordered_deliveries = self
            .reordered_deliveries
            .saturating_add(other.reordered_deliveries);
    }
}

struct FinalizedExchange {
    hash: HashType,
    stats: DeliveryStats,
}

pub fn run_ha_chaos_campaign(config: HaChaosConfig) -> Result<HaChaosReport> {
    config.validate()?;
    let parameters = HighAvailabilityParameters::default();
    let identities = identities(config.nodes);
    let group = ConsensusGroupId::named(format!("ha-chaos-{}-{}", config.nodes, config.seed));
    let mut runtimes = build_runtimes(group, &identities, parameters)?;
    let mut canonical_hashes = BTreeMap::new();
    canonical_hashes.insert(Nonce::default(), runtimes[0].head().hash);
    let mut report = HaChaosReport {
        config: config.clone(),
        finalized_epochs: 0,
        expected_quorum_stalls: 0,
        unexpected_stalls: 0,
        dropped_attempts: 0,
        duplicate_deliveries: 0,
        reordered_deliveries: 0,
        boundary_crashes: 0,
        recoveries: 0,
        redeployments: 0,
        suspensions: 0,
        reactivations: 0,
        corrupt_snapshots_rejected: 0,
        amendments: 0,
        final_nonce: Nonce::default(),
        final_hash: runtimes[0].head().hash,
        final_revision: runtimes[0].revision()?.revision_hash,
        safety_violations: Vec::new(),
        traces: Vec::with_capacity(config.epochs),
    };
    let mut isolated: Option<(usize, u32)> = None;
    let unresponsive_depth = parameters.unresponsive_epoch_depth;

    for epoch in 1..=config.epochs {
        let mut faults = Vec::new();
        if isolated.is_none()
            && config.nodes >= 3
            && config.isolation_interval > 0
            && epoch.is_multiple_of(config.isolation_interval)
            && epoch + usize::try_from(unresponsive_depth).unwrap_or(usize::MAX) <= config.epochs
        {
            isolated = Some((
                select_slot(config.seed, epoch, config.nodes),
                unresponsive_depth,
            ));
        }

        let mut offline = Vec::new();
        if let Some((slot, remaining)) = isolated {
            offline.push(slot);
            faults.push(HaChaosFault::MinorityIsolation {
                slot: slot as u8,
                remaining_epochs: remaining,
            });
        } else if config.boundary_crash_interval > 0
            && epoch.is_multiple_of(config.boundary_crash_interval)
        {
            let tolerated = high_availability_fault_tolerance(config.nodes);
            if tolerated > 0 {
                let crash_count = 1 + ((epoch / config.boundary_crash_interval - 1) % tolerated);
                offline = select_slots(config.seed, epoch, config.nodes, crash_count);
                report.boundary_crashes = report
                    .boundary_crashes
                    .saturating_add(u64::try_from(offline.len()).unwrap_or(u64::MAX));
                faults.push(HaChaosFault::BoundaryCrash {
                    offline_slots: offline.iter().map(|slot| *slot as u8).collect(),
                });
            }
        }
        let participants = (0..config.nodes)
            .filter(|slot| !offline.contains(slot))
            .collect::<Vec<_>>();
        let nonce_before = runtimes[participants[0]].head().nonce;
        let required =
            high_availability_majority(runtimes[participants[0]].members().active_count());
        if participants.len() < required {
            report.unexpected_stalls = report.unexpected_stalls.saturating_add(1);
            return Err(BlossomError::FailedConsensus);
        }

        let transaction_sets = epoch_transactions(
            &runtimes,
            &participants,
            epoch,
            config.amendment_interval,
            &mut faults,
            &mut report,
        )?;
        let exchange = finalize_epoch(
            &mut runtimes,
            &participants,
            transaction_sets,
            &config,
            epoch,
        )?;
        let nonce_after = runtimes[participants[0]].head().nonce;
        if nonce_after != nonce_before.new_next() {
            report.unexpected_stalls = report.unexpected_stalls.saturating_add(1);
            return Err(BlossomError::InvalidEpochNonce);
        }
        if let Some(existing) = canonical_hashes.insert(nonce_after, exchange.hash)
            && existing != exchange.hash
        {
            report.safety_violations.push(format!(
                "nonce {nonce_after} finalized as both {existing} and {}",
                exchange.hash
            ));
            return Err(BlossomError::FailedConsensus);
        }
        if exchange.stats.dropped_attempts > 0 {
            faults.push(HaChaosFault::AsymmetricPacketLoss {
                dropped_attempts: exchange.stats.dropped_attempts,
            });
        }
        if exchange.stats.reordered_deliveries > 0 {
            faults.push(HaChaosFault::ReorderedDelivery {
                deliveries: exchange.stats.reordered_deliveries,
            });
        }
        if exchange.stats.duplicate_deliveries > 0 {
            faults.push(HaChaosFault::DuplicateDelivery {
                duplicates: exchange.stats.duplicate_deliveries,
            });
        }
        report.dropped_attempts = report
            .dropped_attempts
            .saturating_add(exchange.stats.dropped_attempts);
        report.duplicate_deliveries = report
            .duplicate_deliveries
            .saturating_add(exchange.stats.duplicate_deliveries);
        report.reordered_deliveries = report
            .reordered_deliveries
            .saturating_add(exchange.stats.reordered_deliveries);

        if let Some((isolated_slot, remaining)) = isolated {
            if remaining == 1 {
                complete_suspension_recovery_cycle(
                    &mut runtimes,
                    &identities,
                    group,
                    parameters,
                    isolated_slot,
                )?;
                report.suspensions = report.suspensions.saturating_add(1);
                report.reactivations = report.reactivations.saturating_add(1);
                report.recoveries = report.recoveries.saturating_add(1);
                faults.push(HaChaosFault::MemberSuspended {
                    slot: isolated_slot as u8,
                });
                faults.push(HaChaosFault::MemberReactivated {
                    slot: isolated_slot as u8,
                });
                isolated = None;
            } else {
                isolated = Some((isolated_slot, remaining - 1));
            }
        } else {
            for slot in offline {
                recover_runtime_from_peer(
                    &mut runtimes,
                    &identities,
                    group,
                    parameters,
                    slot,
                    participants[0],
                )?;
                report.recoveries = report.recoveries.saturating_add(1);
            }
        }

        if config.redeploy_interval > 0 && epoch.is_multiple_of(config.redeploy_interval) {
            let slot = select_slot(config.seed ^ 0x7265_6465_706c_6f79, epoch, config.nodes);
            let peer = (slot + 1) % config.nodes;
            redeploy_runtime_from_peer(&mut runtimes, &identities, group, parameters, slot, peer)?;
            report.redeployments = report.redeployments.saturating_add(1);
            faults.push(HaChaosFault::ServiceRedeployed { slot: slot as u8 });
        }
        if config.corruption_probe_interval > 0
            && epoch.is_multiple_of(config.corruption_probe_interval)
        {
            let slot = select_slot(config.seed ^ 0x636f_7272_7570_7400, epoch, config.nodes);
            reject_corrupt_snapshot_probe(&runtimes, &identities, group, parameters, slot)?;
            report.corrupt_snapshots_rejected = report.corrupt_snapshots_rejected.saturating_add(1);
            faults.push(HaChaosFault::CorruptSnapshotRejected { slot: slot as u8 });
        }
        if isolated.is_none() {
            assert_converged(&runtimes, epoch.is_multiple_of(50) || !faults.is_empty())?;
        }

        report.finalized_epochs += 1;
        report.traces.push(HaChaosEpochTrace {
            epoch,
            nonce_before,
            nonce_after,
            active_mask: runtimes[0].members().active_mask(),
            participant_mask: slots_mask(&participants),
            required: u8::try_from(required).expect("HA threshold is at most seven"),
            finalized_hash: exchange.hash,
            sealed: runtimes[0].sealed_watermark().position,
            faults,
        });
    }

    let (available, required) = assert_subquorum_stalls(&identities, group, parameters)?;
    report.expected_quorum_stalls = 1;
    report.traces.push(HaChaosEpochTrace {
        epoch: config.epochs.saturating_add(1),
        nonce_before: runtimes[0].head().nonce,
        nonce_after: runtimes[0].head().nonce,
        active_mask: runtimes[0].members().active_mask(),
        participant_mask: low_bits(available),
        required,
        finalized_hash: runtimes[0].head().hash,
        sealed: runtimes[0].sealed_watermark().position,
        faults: vec![HaChaosFault::ExpectedQuorumLoss {
            available,
            required,
        }],
    });

    assert_converged(&runtimes, true)?;
    report.final_nonce = runtimes[0].head().nonce;
    report.final_hash = runtimes[0].head().hash;
    report.final_revision = runtimes[0].revision()?.revision_hash;
    Ok(report)
}

fn identities(count: usize) -> Vec<NodeIdentity> {
    (0..count)
        .map(|index| {
            NodeIdentity::new(
                PubKey([(index + 1) as u8; 32]),
                None,
                "sim",
                format!("node-{index}"),
                10_000 + index as u16,
                false,
            )
        })
        .collect()
}

fn build_runtimes(
    group: ConsensusGroupId,
    identities: &[NodeIdentity],
    parameters: HighAvailabilityParameters,
) -> Result<Vec<HighAvailabilityRuntime>> {
    identities
        .iter()
        .map(|identity| {
            HighAvailabilityRuntime::new(
                group,
                identity.public_key(),
                identities.to_vec(),
                parameters,
            )
        })
        .collect()
}

fn epoch_transactions(
    runtimes: &[HighAvailabilityRuntime],
    participants: &[usize],
    epoch: usize,
    amendment_interval: usize,
    faults: &mut Vec<HaChaosFault>,
    report: &mut HaChaosReport,
) -> Result<Vec<Vec<Transaction>>> {
    let mut transaction_sets = participants
        .iter()
        .map(|slot| vec![Transaction::new(format!("epoch-{epoch}-slot-{slot}"))])
        .collect::<Vec<_>>();
    if amendment_interval > 0 && epoch > 1 && epoch.is_multiple_of(amendment_interval) {
        let origin = participants[0];
        let target = runtimes[origin].head();
        let mut client_id = [0u8; 16];
        client_id[..8].copy_from_slice(&(epoch as u64).to_le_bytes());
        client_id[8..].copy_from_slice(&(origin as u64).to_le_bytes());
        let amendment = AmendmentRecord {
            target_epoch_hash: target.hash,
            target_epoch_nonce: target.nonce,
            containing_epoch_nonce: runtimes[origin].current_round().round_id.nonce,
            origin_slot: HaMemberSlot(origin as u8),
            command_identity: CommandIdentity {
                client_id: ClientId(client_id),
                client_epoch: ClientEpoch(1),
                sequence: epoch as u64,
            },
            supersedes: None,
            payload: AmendmentPayload::Compensation {
                command_bytes: format!("correction-{epoch}").into_bytes(),
            },
        };
        transaction_sets[0].push(runtimes[origin].amendment_transaction(&amendment)?);
        faults.push(HaChaosFault::MutableAmendment {
            target: target.nonce,
        });
        report.amendments = report.amendments.saturating_add(1);
    }
    Ok(transaction_sets)
}

fn finalize_epoch(
    runtimes: &mut [HighAvailabilityRuntime],
    participants: &[usize],
    transaction_sets: Vec<Vec<Transaction>>,
    config: &HaChaosConfig,
    epoch: usize,
) -> Result<FinalizedExchange> {
    let dispatches = participants
        .iter()
        .zip(transaction_sets)
        .map(|(slot, transactions)| {
            runtimes[*slot]
                .build_dispatch_at(transactions, ((epoch as u128) << 8) | (*slot as u128))
                .map(|dispatch| (*slot, dispatch))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut stats = deliver_dispatches(runtimes, participants, &dispatches, config, epoch)?;
    let acknowledgements = participants
        .iter()
        .map(|slot| {
            runtimes[*slot]
                .acknowledge()
                .map(|message| (*slot, message))
        })
        .collect::<Result<Vec<_>>>()?;
    stats.merge(deliver_acknowledgements(
        runtimes,
        participants,
        &acknowledgements,
        config,
        epoch,
    )?);
    let confirmations = participants
        .iter()
        .map(|slot| {
            runtimes[*slot]
                .confirm()
                .map(|(message, _)| (*slot, message))
        })
        .collect::<Result<Vec<_>>>()?;
    stats.merge(deliver_confirmations(
        runtimes,
        participants,
        &confirmations,
        config,
        epoch,
    )?);
    let head = runtimes[participants[0]].head();
    for slot in participants {
        if runtimes[*slot].head().nonce != head.nonce || runtimes[*slot].head().hash != head.hash {
            return Err(BlossomError::WireProtocol(format!(
                "HA chaos divergence after epoch {epoch}"
            )));
        }
        runtimes[*slot].head().validate(runtimes[*slot].members())?;
    }
    Ok(FinalizedExchange {
        hash: head.hash,
        stats,
    })
}

fn deliver_dispatches(
    runtimes: &mut [HighAvailabilityRuntime],
    participants: &[usize],
    messages: &[(usize, HaDispatch)],
    config: &HaChaosConfig,
    epoch: usize,
) -> Result<DeliveryStats> {
    let mut deliveries = Vec::new();
    for (sender, message) in messages {
        for receiver in participants {
            if receiver != sender {
                deliveries.push((*sender, *receiver, message.clone()));
            }
        }
    }
    let reordered = reorder(&mut deliveries, config.seed, epoch, 1);
    let mut stats = DeliveryStats {
        reordered_deliveries: if reordered {
            u64::try_from(deliveries.len()).unwrap_or(u64::MAX)
        } else {
            0
        },
        ..DeliveryStats::default()
    };
    for (sender, receiver, message) in deliveries {
        deliver_with_retry(config, epoch, 1, sender, receiver, &mut stats, || {
            runtimes[receiver]
                .receive_dispatch(message.clone())
                .map(|_| ())
        })?;
    }
    Ok(stats)
}

fn deliver_acknowledgements(
    runtimes: &mut [HighAvailabilityRuntime],
    participants: &[usize],
    messages: &[(usize, HaAcknowledge)],
    config: &HaChaosConfig,
    epoch: usize,
) -> Result<DeliveryStats> {
    let mut deliveries = Vec::new();
    for (sender, message) in messages {
        for receiver in participants {
            if receiver != sender {
                deliveries.push((*sender, *receiver, message.clone()));
            }
        }
    }
    let reordered = reorder(&mut deliveries, config.seed, epoch, 2);
    let mut stats = DeliveryStats {
        reordered_deliveries: if reordered {
            u64::try_from(deliveries.len()).unwrap_or(u64::MAX)
        } else {
            0
        },
        ..DeliveryStats::default()
    };
    for (sender, receiver, message) in deliveries {
        deliver_with_retry(config, epoch, 2, sender, receiver, &mut stats, || {
            runtimes[receiver]
                .receive_acknowledgement(message.clone())
                .map(|_| ())
        })?;
    }
    Ok(stats)
}

fn deliver_confirmations(
    runtimes: &mut [HighAvailabilityRuntime],
    participants: &[usize],
    messages: &[(usize, HaConfirm)],
    config: &HaChaosConfig,
    epoch: usize,
) -> Result<DeliveryStats> {
    let mut deliveries = Vec::new();
    for (sender, message) in messages {
        for receiver in participants {
            if receiver != sender {
                deliveries.push((*sender, *receiver, message.clone()));
            }
        }
    }
    let reordered = reorder(&mut deliveries, config.seed, epoch, 3);
    let mut stats = DeliveryStats {
        reordered_deliveries: if reordered {
            u64::try_from(deliveries.len()).unwrap_or(u64::MAX)
        } else {
            0
        },
        ..DeliveryStats::default()
    };
    for (sender, receiver, message) in deliveries {
        deliver_with_retry(config, epoch, 3, sender, receiver, &mut stats, || {
            runtimes[receiver]
                .receive_confirmation(message.clone())
                .map(|_| ())
        })?;
    }
    Ok(stats)
}

fn deliver_with_retry(
    config: &HaChaosConfig,
    epoch: usize,
    stage: u64,
    sender: usize,
    receiver: usize,
    stats: &mut DeliveryStats,
    mut deliver: impl FnMut() -> Result<()>,
) -> Result<()> {
    for attempt in 0..config.max_delivery_attempts {
        let sample = deterministic_sample(
            config.seed,
            epoch as u64,
            stage,
            sender as u64,
            receiver as u64,
            attempt as u64,
        );
        if sample % RATE_DENOMINATOR < u64::from(config.drop_ppm) {
            stats.dropped_attempts = stats.dropped_attempts.saturating_add(1);
            continue;
        }
        deliver()?;
        if sample.rotate_left(23) % RATE_DENOMINATOR < u64::from(config.duplicate_ppm) {
            deliver()?;
            stats.duplicate_deliveries = stats.duplicate_deliveries.saturating_add(1);
        }
        return Ok(());
    }
    Err(BlossomError::Io(format!(
        "HA chaos exhausted {} delivery attempts at epoch {epoch}, stage {stage}, {sender}->{receiver}",
        config.max_delivery_attempts
    )))
}

fn reorder<T>(deliveries: &mut [T], seed: u64, epoch: usize, stage: u64) -> bool {
    if deliveries.len() <= 1 {
        return false;
    }
    let len = deliveries.len();
    let offset = deterministic_sample(seed, epoch as u64, stage, 0, 0, 1) as usize % len;
    let reverse = deterministic_sample(seed, epoch as u64, stage, 0, 0, 2) & 1 == 1;
    let changed = (0..len).any(|position| {
        let original = if reverse {
            (len - 1 - position + offset) % len
        } else {
            (position + offset) % len
        };
        original != position
    });
    deliveries.rotate_left(offset);
    if reverse {
        deliveries.reverse();
    }
    changed
}

fn recover_runtime_from_peer(
    runtimes: &mut [HighAvailabilityRuntime],
    identities: &[NodeIdentity],
    group: ConsensusGroupId,
    parameters: HighAvailabilityParameters,
    slot: usize,
    peer: usize,
) -> Result<()> {
    let peer_status = runtimes[peer].status()?;
    let local_status = runtimes[slot].status()?;
    let assessment = local_status.assess_peer(&peer_status);
    if assessment.compatibility != HaPeerCompatibility::LocalBehind
        || !assessment
            .directives
            .iter()
            .any(|directive| matches!(directive, HaServiceDirective::FetchRecoverySnapshot { .. }))
    {
        return Err(BlossomError::InvalidConfiguration(
            "HA chaos expected a lagging-node recovery directive".to_string(),
        ));
    }
    let snapshot = runtimes[peer].recovery_snapshot();
    runtimes[slot].install_recovery_snapshot(snapshot)?;
    let _ = (identities, group, parameters);
    Ok(())
}

fn redeploy_runtime_from_peer(
    runtimes: &mut [HighAvailabilityRuntime],
    identities: &[NodeIdentity],
    group: ConsensusGroupId,
    parameters: HighAvailabilityParameters,
    slot: usize,
    peer: usize,
) -> Result<()> {
    let snapshot = runtimes[peer].recovery_snapshot();
    let mut replacement = HighAvailabilityRuntime::new(
        group,
        identities[slot].public_key(),
        identities.to_vec(),
        parameters,
    )?;
    let assessment = replacement.assess_peer_status(&runtimes[peer].status()?)?;
    if assessment.compatibility != HaPeerCompatibility::LocalBehind
        || !assessment
            .directives
            .contains(&HaServiceDirective::RestartOrRedeploy)
    {
        return Err(BlossomError::InvalidConfiguration(
            "HA chaos redeploy did not request recovery".to_string(),
        ));
    }
    replacement.install_recovery_snapshot(snapshot)?;
    if replacement
        .assess_peer_status(&runtimes[peer].status()?)?
        .compatibility
        != HaPeerCompatibility::Compatible
    {
        return Err(BlossomError::InvalidConfiguration(
            "HA chaos redeploy did not become compatible".to_string(),
        ));
    }
    runtimes[slot] = replacement;
    Ok(())
}

fn complete_suspension_recovery_cycle(
    runtimes: &mut [HighAvailabilityRuntime],
    identities: &[NodeIdentity],
    group: ConsensusGroupId,
    parameters: HighAvailabilityParameters,
    isolated_slot: usize,
) -> Result<()> {
    let healthy = (0..runtimes.len())
        .filter(|slot| *slot != isolated_slot)
        .collect::<Vec<_>>();
    for slot in &healthy {
        if runtimes[*slot].node_status(HaMemberSlot(isolated_slot as u8))
            != NodeAvailabilityStatus::Unresponsive
        {
            return Err(BlossomError::InvalidConfiguration(
                "HA chaos isolation did not reach the unresponsive depth".to_string(),
            ));
        }
    }
    let votes = healthy
        .iter()
        .map(|slot| {
            runtimes[*slot]
                .vote_to_suspend(HaMemberSlot(isolated_slot as u8))
                .map(|(vote, _)| vote)
        })
        .collect::<Result<Vec<_>>>()?;
    deliver_membership_votes(runtimes, &healthy, &votes)?;
    let snapshot = runtimes[healthy[0]].recovery_snapshot();
    runtimes[isolated_slot].install_recovery_snapshot(snapshot)?;
    let caught_up = runtimes[healthy[0]].head().nonce;
    let reactivation_votes = healthy
        .iter()
        .map(|slot| {
            runtimes[*slot]
                .vote_to_reactivate(HaMemberSlot(isolated_slot as u8), caught_up)
                .map(|(vote, _)| vote)
        })
        .collect::<Result<Vec<_>>>()?;
    let all = (0..runtimes.len()).collect::<Vec<_>>();
    deliver_membership_votes(runtimes, &all, &reactivation_votes)?;
    if runtimes
        .iter()
        .any(|runtime| runtime.members().active_count() != runtimes.len())
    {
        return Err(BlossomError::InvalidConfiguration(
            "HA chaos reactivation did not restore full membership".to_string(),
        ));
    }
    let _ = (identities, group, parameters);
    Ok(())
}

fn deliver_membership_votes(
    runtimes: &mut [HighAvailabilityRuntime],
    receivers: &[usize],
    votes: &[blossom::HaMembershipVote],
) -> Result<()> {
    for vote in votes {
        for receiver in receivers {
            if *receiver == vote.sender.index() {
                continue;
            }
            match runtimes[*receiver].receive_membership_vote(*vote)? {
                HaRuntimeEvent::MembershipVoteAccepted | HaRuntimeEvent::MembershipChanged(_) => {}
                event => {
                    return Err(BlossomError::WireProtocol(format!(
                        "unexpected HA membership event: {event:?}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn reject_corrupt_snapshot_probe(
    runtimes: &[HighAvailabilityRuntime],
    identities: &[NodeIdentity],
    group: ConsensusGroupId,
    parameters: HighAvailabilityParameters,
    slot: usize,
) -> Result<()> {
    let mut snapshot = runtimes[0].recovery_snapshot();
    snapshot.epochs.last_mut().expect("genesis exists").hash = HashType([0xD3; 32]);
    let mut probe = HighAvailabilityRuntime::new(
        group,
        identities[slot].public_key(),
        identities.to_vec(),
        parameters,
    )?;
    if probe.install_recovery_snapshot(snapshot).is_ok() {
        return Err(BlossomError::WireProtocol(
            "HA chaos accepted a corrupt recovery snapshot".to_string(),
        ));
    }
    Ok(())
}

fn assert_subquorum_stalls(
    identities: &[NodeIdentity],
    group: ConsensusGroupId,
    parameters: HighAvailabilityParameters,
) -> Result<(u8, u8)> {
    let mut runtimes = build_runtimes(group, identities, parameters)?;
    let required = high_availability_majority(identities.len());
    let participants = (0..required.saturating_sub(1)).collect::<Vec<_>>();
    let dispatches = participants
        .iter()
        .map(|slot| {
            runtimes[*slot]
                .build_dispatch_at(
                    vec![Transaction::new(format!("subquorum-{slot}"))],
                    *slot as u128,
                )
                .map(|dispatch| (*slot, dispatch))
        })
        .collect::<Result<Vec<_>>>()?;
    for (sender, dispatch) in &dispatches {
        for receiver in &participants {
            if sender != receiver {
                runtimes[*receiver].receive_dispatch(dispatch.clone())?;
            }
        }
    }
    let acknowledgements = participants
        .iter()
        .map(|slot| {
            runtimes[*slot]
                .acknowledge()
                .map(|message| (*slot, message))
        })
        .collect::<Result<Vec<_>>>()?;
    for (sender, acknowledgement) in &acknowledgements {
        for receiver in &participants {
            if sender != receiver {
                runtimes[*receiver].receive_acknowledgement(acknowledgement.clone())?;
            }
        }
    }
    for participant in &participants {
        if !matches!(
            runtimes[*participant].confirm(),
            Err(BlossomError::FailedConsensus)
        ) {
            return Err(BlossomError::InvalidConfiguration(format!(
                "{}-node HA unexpectedly progressed with {} participants below its quorum of {required}",
                identities.len(),
                participants.len(),
            )));
        }
        if runtimes[*participant].head().nonce != Nonce::default() {
            return Err(BlossomError::InvalidConfiguration(
                "subquorum HA partition advanced its finalized head".to_string(),
            ));
        }
    }
    if identities.len() == 2
        && runtimes[0]
            .members()
            .with_suspended(HaMemberSlot(1))
            .is_ok()
    {
        return Err(BlossomError::InvalidConfiguration(
            "two-node HA unexpectedly allowed suspension to one".to_string(),
        ));
    }
    Ok((
        u8::try_from(participants.len()).expect("HA participant count is at most seven"),
        u8::try_from(required).expect("HA quorum is at most seven"),
    ))
}

fn assert_converged(runtimes: &[HighAvailabilityRuntime], check_revision: bool) -> Result<()> {
    let head = runtimes[0].head();
    let expected_nonce = head.nonce;
    let expected_hash = head.hash;
    let expected_generation = runtimes[0].status()?.membership_generation;
    let expected_mask = runtimes[0].members().active_mask();
    let expected_revision = check_revision
        .then(|| runtimes[0].revision())
        .transpose()?
        .map(|revision| revision.revision_hash);
    for (index, runtime) in runtimes.iter().enumerate().skip(1) {
        let actual_generation = runtime.status()?.membership_generation;
        let actual_revision = check_revision
            .then(|| runtime.revision())
            .transpose()?
            .map(|revision| revision.revision_hash);
        if runtime.head().nonce != expected_nonce
            || runtime.head().hash != expected_hash
            || runtime.members().active_mask() != expected_mask
            || actual_generation != expected_generation
            || (check_revision && actual_revision != expected_revision)
        {
            return Err(BlossomError::WireProtocol(format!(
                "HA chaos node {index} failed convergence: head={}/{}, expected={}/{}, mask={:#09b}/{:#09b}, generation={}/{}, revision={actual_revision:?}/{expected_revision:?}",
                runtime.head().nonce,
                runtime.head().hash,
                expected_nonce,
                expected_hash,
                runtime.members().active_mask(),
                expected_mask,
                actual_generation,
                expected_generation,
            )));
        }
    }
    Ok(())
}

fn select_slot(seed: u64, epoch: usize, nodes: usize) -> usize {
    deterministic_sample(seed, epoch as u64, 0, 0, 0, 0) as usize % nodes
}

fn select_slots(seed: u64, epoch: usize, nodes: usize, count: usize) -> Vec<usize> {
    let start = select_slot(seed, epoch, nodes);
    (0..count).map(|offset| (start + offset) % nodes).collect()
}

fn slots_mask(slots: &[usize]) -> u8 {
    slots.iter().fold(0u8, |mask, slot| mask | (1u8 << slot))
}

fn low_bits(count: u8) -> u8 {
    if count == u8::BITS as u8 {
        u8::MAX
    } else {
        (1u8 << count) - 1
    }
}

fn deterministic_sample(
    seed: u64,
    epoch: u64,
    stage: u64,
    sender: u64,
    receiver: u64,
    attempt: u64,
) -> u64 {
    let mut value = seed
        ^ epoch.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ stage.wrapping_mul(0xBF58_476D_1CE4_E5B9)
        ^ sender.wrapping_mul(0x94D0_49BB_1331_11EB)
        ^ receiver.rotate_left(17)
        ^ attempt.rotate_left(31);
    value ^= value >> 30;
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_fault_campaign_replays_exactly() {
        let config = HaChaosConfig {
            nodes: 3,
            epochs: 120,
            isolation_interval: 61,
            ..HaChaosConfig::default()
        };
        let first = run_ha_chaos_campaign(config.clone()).unwrap();
        let second = run_ha_chaos_campaign(config).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.finalized_epochs, 120);
        assert!(first.dropped_attempts > 0);
        assert!(first.duplicate_deliveries > 0);
        assert!(first.recoveries > 0);
        assert!(first.suspensions > 0);
        assert!(first.reactivations > 0);
        assert!(first.safety_violations.is_empty());
    }

    #[test]
    fn two_node_campaign_stalls_exactly_when_one_node_is_missing() {
        let report = run_ha_chaos_campaign(HaChaosConfig {
            nodes: 2,
            epochs: 20,
            isolation_interval: 0,
            ..HaChaosConfig::default()
        })
        .unwrap();
        assert_eq!(report.expected_quorum_stalls, 1);
        assert_eq!(report.unexpected_stalls, 0);
        assert_eq!(report.final_nonce, Nonce::new(20));
    }
}
