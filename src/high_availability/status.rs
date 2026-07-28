//! Lifecycle, health, recovery, topology, and membership status records.

use super::*;

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Whether a finalized epoch may still receive corrective amendments.
pub enum EpochLifecycle {
    /// Amendments remain allowed until the configured successor depth passes.
    Mutable {
        /// Additional successor epochs required before sealing.
        remaining_successors: u32,
    },
    /// The epoch is immutable and eligible for certified history compaction.
    Sealed,
}

/// Computes an epoch's amendment lifecycle relative to the current head.
pub fn epoch_lifecycle(epoch: Nonce, head: Nonce, mutable_epoch_depth: u32) -> EpochLifecycle {
    let distance = head.value().saturating_sub(epoch.value());
    if distance >= u64::from(mutable_epoch_depth) {
        EpochLifecycle::Sealed
    } else {
        EpochLifecycle::Mutable {
            remaining_successors: mutable_epoch_depth - distance as u32,
        }
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Liveness state inferred for one fixed HA member slot.
pub enum NodeAvailabilityStatus {
    /// The member was present in the latest relevant epoch.
    Active,
    /// The member has missed fewer than the unresponsive threshold.
    Missing {
        /// Number of consecutive epochs in which the member was absent.
        consecutive_epochs: u32,
    },
    /// The member exceeded the configured absence threshold.
    Unresponsive,
    /// Consensus removed the member from the active voting mask.
    Suspended {
        /// Epoch at which the suspension took effect.
        since: Nonce,
    },
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Hash-committed application progress through HA history.
pub struct StateRevision {
    /// Highest finalized application watermark.
    pub head: Watermark,
    /// Highest immutable application watermark.
    pub sealed: Watermark,
    /// Commitment to the watermarks and accumulated epoch history.
    pub revision_hash: HashType,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Peer context announcement used before exchanging HA round messages.
pub struct HaHandshake {
    /// Consensus group announced by the peer.
    pub group_id: ConsensusGroupId,
    /// Public identity of the sending member.
    pub sender: PubKey,
    /// Hash of the immutable member-slot assignment.
    pub fixed_membership_hash: HashType,
    /// Active-membership generation at the peer.
    pub membership_generation: u64,
    /// Active member slots at the peer.
    pub active_mask: u8,
    /// Hash of the peer's committed HA parameters.
    pub parameters_hash: HashType,
    /// Peer head nonce.
    pub head_nonce: Nonce,
    /// Peer head hash.
    pub head_hash: HashType,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Validated protocol and application state reported by one HA node.
pub struct HaNodeStatus {
    /// Consensus group served by the node.
    pub group_id: ConsensusGroupId,
    /// Node's immutable member slot.
    pub self_slot: HaMemberSlot,
    /// Number of fixed member slots.
    pub member_count: u8,
    /// Hash of the fixed slot-to-key assignment.
    pub fixed_membership_hash: HashType,
    /// Slots currently allowed to participate.
    pub active_mask: u8,
    /// Generation of the active member set.
    pub membership_generation: u64,
    /// Committed HA parameters.
    pub parameters: HighAvailabilityParameters,
    /// Hash commitment to [`Self::parameters`].
    pub parameters_hash: HashType,
    /// Latest finalized epoch nonce.
    pub head_nonce: Nonce,
    /// Latest finalized epoch hash.
    pub head_hash: HashType,
    /// Highest immutable application watermark.
    pub sealed: Watermark,
    /// Hash-committed application and history revision.
    pub revision: StateRevision,
    /// Per-slot availability observations.
    pub availability: [NodeAvailabilityStatus; MAX_HA_NODES],
    /// Number of certified membership changes retained by the node.
    pub committed_membership_changes: u64,
}

/// Service-facing readiness classification for HA integrations.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaServiceHealth {
    /// The service has full expected availability.
    Ready,
    /// The service can proceed but has lost redundancy.
    Degraded,
    /// The service cannot safely accept consensus writes.
    Unavailable,
    /// This node is not in the active member set.
    Suspended,
}

/// Machine-readable actions that a service supervisor can map to alerts,
/// traffic draining, user notices, or a redeploy workflow.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum HaServiceDirective {
    /// Continue normal service operation.
    Continue,
    /// Alert the deployment's operators.
    NotifyOperators,
    /// Surface degraded availability to service users.
    NotifyUsers,
    /// Stop admitting new writes.
    DrainWrites,
    /// Wait until enough voters are responsive.
    AwaitQuorum {
        /// Voter count required for progress.
        required: u8,
        /// Voters currently known to be responsive.
        responsive: u8,
    },
    /// Fetch certified recovery state from a healthy peer.
    FetchRecoverySnapshot {
        /// Minimum acceptable recovered head.
        minimum_head: Nonce,
    },
    /// Offer local certified recovery state to a lagging peer.
    OfferRecoverySnapshot {
        /// Latest epoch included in the offered state.
        through: Nonce,
    },
    /// Remain fail closed until a membership certificate reactivates the node.
    AwaitReactivation,
    /// Restart or replace the runtime before retrying.
    RestartOrRedeploy,
    /// Isolate a peer that failed authentication or consistency checks.
    QuarantinePeer,
    /// Wait for the active-passive consensus engine to elect a leader.
    AwaitLeader,
}

/// Service-level replication choice for a 2–7 node HA deployment.
///
/// `LeaderlessActiveActive` is implemented by [`HighAvailabilityRuntime`].
/// With the `active-passive` feature, `MajorityLeaderActivePassive` is
/// implemented by `crate::active_passive::ActivePassiveRuntime` using
/// OpenRaft.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaReplicationMode {
    /// Native Blossom protocol in which every active member accepts writes.
    LeaderlessActiveActive,
    /// OpenRaft protocol in which writes route through the elected leader.
    MajorityLeaderActivePassive,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Required routing policy for new writes.
pub enum HaWriteRoute {
    /// A write may enter through any active member.
    AnyActiveMember,
    /// A write must enter through the elected leader.
    CurrentLeader,
}

/// Leadership observation supplied by the selected active-passive engine.
///
/// Leaderless Blossom HA callers must use `NotApplicable`. The service API
/// never attempts to infer leadership from Blossom HA state.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaLeadershipStatus {
    /// Leadership is not part of the selected replication mode.
    NotApplicable,
    /// No writable leader is currently known.
    Unavailable,
    /// The active-passive engine reports an elected leader.
    Elected,
}

/// Validated physical and voting layout for one HA service deployment.
///
/// Active-active Blossom uses every physical member as a voter. Active-passive
/// deployments may use non-voting learners, but majority leadership and write
/// availability are always derived from `voting_nodes`.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct HaServiceTopology {
    /// Replication protocol selected by the application.
    pub mode: HaReplicationMode,
    /// Total service processes, including learners.
    pub physical_nodes: u8,
    /// Processes that participate in majority decisions.
    pub voting_nodes: u8,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Unified service readiness derived from topology, reachability, and leadership.
pub struct HaModeOperationalStatus {
    /// Validated physical and voting layout.
    pub topology: HaServiceTopology,
    /// Route required for new writes.
    pub write_route: HaWriteRoute,
    /// Leadership observation used by the assessment.
    pub leadership: HaLeadershipStatus,
    /// Voting nodes currently responsive.
    pub responsive_voters: u8,
    /// Voting nodes required for a majority.
    pub required_voters: u8,
    /// Simultaneous voter failures the configured topology can tolerate.
    pub tolerated_voter_failures: u8,
    /// Service-facing readiness classification.
    pub health: HaServiceHealth,
    /// Whether the service may admit new consensus writes.
    pub accepts_writes: bool,
    /// Whether locally available state may still serve reads.
    pub serves_local_reads: bool,
    /// Recommended machine-readable operational actions.
    pub directives: Vec<HaServiceDirective>,
}

impl HaServiceTopology {
    /// Validates and constructs a leaderless topology in which every node votes.
    pub fn active_active(member_count: usize) -> Result<Self> {
        let member_count = validated_ha_node_count(member_count)?;
        Ok(Self {
            mode: HaReplicationMode::LeaderlessActiveActive,
            physical_nodes: member_count,
            voting_nodes: member_count,
        })
    }

    /// Validates and constructs a leader-based topology with optional learners.
    pub fn active_passive(physical_nodes: usize, voting_nodes: usize) -> Result<Self> {
        let physical_nodes = validated_ha_node_count(physical_nodes)?;
        let voting_nodes = validated_ha_node_count(voting_nodes)?;
        if voting_nodes > physical_nodes {
            return Err(BlossomError::InvalidConfiguration(
                "HA active-passive voting nodes cannot exceed physical nodes".to_string(),
            ));
        }
        Ok(Self {
            mode: HaReplicationMode::MajorityLeaderActivePassive,
            physical_nodes,
            voting_nodes,
        })
    }

    /// Returns the write-routing policy implied by this topology.
    pub const fn write_route(self) -> HaWriteRoute {
        match self.mode {
            HaReplicationMode::LeaderlessActiveActive => HaWriteRoute::AnyActiveMember,
            HaReplicationMode::MajorityLeaderActivePassive => HaWriteRoute::CurrentLeader,
        }
    }

    /// Returns the strict-majority voter threshold.
    pub fn required_voters(self) -> u8 {
        u8::try_from(high_availability_majority(usize::from(self.voting_nodes)))
            .expect("validated HA topology has at most seven voters")
    }

    /// Returns the number of voting failures tolerated without losing quorum.
    pub fn tolerated_voter_failures(self) -> u8 {
        self.voting_nodes.saturating_sub(self.required_voters())
    }

    /// Converts protocol reachability and leadership observations into one
    /// service-facing write/readiness decision.
    ///
    /// A two-voter topology requires both voters. With only one responsive
    /// voter, both replication modes remain locally readable but reject new
    /// consensus writes.
    pub fn assess(
        self,
        responsive_voters: usize,
        leadership: HaLeadershipStatus,
    ) -> Result<HaModeOperationalStatus> {
        if responsive_voters > usize::from(self.voting_nodes) {
            return Err(BlossomError::InvalidConfiguration(
                "responsive HA voters cannot exceed configured voting nodes".to_string(),
            ));
        }
        match (self.mode, leadership) {
            (HaReplicationMode::LeaderlessActiveActive, HaLeadershipStatus::NotApplicable)
            | (
                HaReplicationMode::MajorityLeaderActivePassive,
                HaLeadershipStatus::Unavailable | HaLeadershipStatus::Elected,
            ) => {}
            (HaReplicationMode::LeaderlessActiveActive, _) => {
                return Err(BlossomError::InvalidConfiguration(
                    "leaderless active-active HA does not accept a leadership state".to_string(),
                ));
            }
            (HaReplicationMode::MajorityLeaderActivePassive, HaLeadershipStatus::NotApplicable) => {
                return Err(BlossomError::InvalidConfiguration(
                    "active-passive HA requires an observation from its majority-leader engine"
                        .to_string(),
                ));
            }
        }

        let responsive_voters = u8::try_from(responsive_voters)
            .expect("validated HA topology has at most seven voters");
        let required_voters = self.required_voters();
        let has_quorum = responsive_voters >= required_voters;
        let has_write_authority = match self.mode {
            HaReplicationMode::LeaderlessActiveActive => true,
            HaReplicationMode::MajorityLeaderActivePassive => {
                leadership == HaLeadershipStatus::Elected
            }
        };
        let accepts_writes = has_quorum && has_write_authority;
        let health = if !accepts_writes {
            HaServiceHealth::Unavailable
        } else if responsive_voters < self.voting_nodes {
            HaServiceHealth::Degraded
        } else {
            HaServiceHealth::Ready
        };
        let directives = if !has_quorum {
            vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::AwaitQuorum {
                    required: required_voters,
                    responsive: responsive_voters,
                },
            ]
        } else if !has_write_authority {
            vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::AwaitLeader,
            ]
        } else if responsive_voters < self.voting_nodes {
            vec![
                HaServiceDirective::Continue,
                HaServiceDirective::NotifyOperators,
            ]
        } else {
            vec![HaServiceDirective::Continue]
        };

        Ok(HaModeOperationalStatus {
            topology: self,
            write_route: self.write_route(),
            leadership,
            responsive_voters,
            required_voters,
            tolerated_voter_failures: self.tolerated_voter_failures(),
            health,
            accepts_writes,
            serves_local_reads: true,
            directives,
        })
    }
}

fn validated_ha_node_count(node_count: usize) -> Result<u8> {
    if !(MIN_HA_NODES..=MAX_HA_NODES).contains(&node_count) {
        return Err(BlossomError::InvalidHighAvailabilityNodeCount(node_count));
    }
    Ok(u8::try_from(node_count).expect("validated HA node count is at most seven"))
}

/// Machine-readable classification for mapping HA failures into service
/// supervisors, alerts, traffic draining, and redeploy automation.
#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum HaFailureClass {
    /// The durable store is poisoned or unavailable.
    DurabilityUnavailable,
    /// Too few voters are available for consensus progress.
    QuorumUnavailable,
    /// A bounded network operation failed.
    TransportUnavailable,
    /// A peer could not be authenticated as its claimed identity.
    PeerAuthentication,
    /// Local deployment or protocol parameters are invalid.
    Configuration,
    /// An authenticated message violated protocol invariants.
    ProtocolViolation,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Service-facing classification and response for an HA runtime failure.
pub struct HaFailureAssessment {
    /// Stable failure category.
    pub class: HaFailureClass,
    /// Resulting service readiness.
    pub health: HaServiceHealth,
    /// Whether retrying in the same process can be useful. Durable-store I/O
    /// failures are not retried because the poisoned LogStore must be closed
    /// and reopened after an ambiguous I/O error.
    pub retry_in_process: bool,
    /// Recommended machine-readable operational actions.
    pub directives: Vec<HaServiceDirective>,
}

/// Classifies an HA error into a fail-closed service response.
pub fn assess_high_availability_failure(error: &BlossomError) -> HaFailureAssessment {
    let message = error.to_string();
    if matches!(error, BlossomError::Io(_)) && message.contains("HA durable store") {
        return HaFailureAssessment {
            class: HaFailureClass::DurabilityUnavailable,
            health: HaServiceHealth::Unavailable,
            retry_in_process: false,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::RestartOrRedeploy,
            ],
        };
    }
    if matches!(error, BlossomError::FailedConsensus) {
        return HaFailureAssessment {
            class: HaFailureClass::QuorumUnavailable,
            health: HaServiceHealth::Unavailable,
            retry_in_process: true,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::DrainWrites,
            ],
        };
    }
    if matches!(
        error,
        BlossomError::Io(_) | BlossomError::ExternalService(_)
    ) {
        return HaFailureAssessment {
            class: HaFailureClass::TransportUnavailable,
            health: HaServiceHealth::Degraded,
            retry_in_process: true,
            directives: vec![HaServiceDirective::NotifyOperators],
        };
    }
    if matches!(
        error,
        BlossomError::UnknownSender | BlossomError::WireProtocol(_)
    ) && (message.contains("authentication")
        || message.contains("authenticated transport peer")
        || matches!(error, BlossomError::UnknownSender))
    {
        return HaFailureAssessment {
            class: HaFailureClass::PeerAuthentication,
            health: HaServiceHealth::Degraded,
            retry_in_process: false,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::QuarantinePeer,
            ],
        };
    }
    if matches!(
        error,
        BlossomError::InvalidConfiguration(_) | BlossomError::InvalidHighAvailabilityNodeCount(_)
    ) {
        return HaFailureAssessment {
            class: HaFailureClass::Configuration,
            health: HaServiceHealth::Unavailable,
            retry_in_process: false,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::DrainWrites,
            ],
        };
    }
    HaFailureAssessment {
        class: HaFailureClass::ProtocolViolation,
        health: HaServiceHealth::Unavailable,
        retry_in_process: false,
        directives: vec![
            HaServiceDirective::NotifyOperators,
            HaServiceDirective::DrainWrites,
            HaServiceDirective::QuarantinePeer,
        ],
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Service readiness derived from one node's native active-active status.
pub struct HaOperationalStatus {
    /// Overall service readiness.
    pub health: HaServiceHealth,
    /// Availability state of the reporting node.
    pub self_status: NodeAvailabilityStatus,
    /// Number of slots in the active membership mask.
    pub active_nodes: u8,
    /// Active nodes currently observed as responsive.
    pub responsive_nodes: u8,
    /// Responsive nodes required for a majority.
    pub required_nodes: u8,
    /// Whether this node may accept new consensus writes.
    pub accepts_writes: bool,
    /// Whether locally available state may serve reads.
    pub serves_local_reads: bool,
    /// Highest watermark safe for strict immutable reads.
    pub strict_reads_through: Watermark,
    /// Recommended machine-readable operational actions.
    pub directives: Vec<HaServiceDirective>,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Relationship between two reported HA runtime states.
pub enum HaPeerCompatibility {
    /// Consensus context and head state agree.
    Compatible,
    /// The local node needs recovery state from the peer.
    LocalBehind,
    /// The peer needs recovery state from the local node.
    PeerBehind,
    /// Equal-generation state conflicts at the same logical position.
    Diverged,
    /// The peers belong to different consensus contexts.
    Incompatible,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Compatibility decision and recovery actions for a peer status comparison.
pub struct HaPeerAssessment {
    /// Relationship between the local and peer states.
    pub compatibility: HaPeerCompatibility,
    /// Local finalized head nonce.
    pub local_head: Nonce,
    /// Peer finalized head nonce.
    pub peer_head: Nonce,
    /// Recommended machine-readable operational actions.
    pub directives: Vec<HaServiceDirective>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// State change observable by an HA service supervisor.
pub enum HaOperationalEventKind {
    /// Service readiness changed.
    HealthChanged {
        /// Previous readiness.
        from: HaServiceHealth,
        /// Current readiness.
        to: HaServiceHealth,
    },
    /// The finalized epoch head advanced.
    HeadAdvanced {
        /// Previous head nonce.
        from: Nonce,
        /// Current head nonce.
        to: Nonce,
    },
    /// The immutable application watermark advanced.
    SealedWatermarkAdvanced {
        /// Previous sealed watermark.
        from: Watermark,
        /// Current sealed watermark.
        to: Watermark,
    },
    /// One fixed member's availability changed.
    MemberAvailabilityChanged {
        /// Affected fixed member slot.
        slot: HaMemberSlot,
        /// Previous availability.
        from: NodeAvailabilityStatus,
        /// Current availability.
        to: NodeAvailabilityStatus,
    },
    /// A certified suspension or reactivation changed active membership.
    MembershipGenerationChanged {
        /// Previous membership generation.
        from: u64,
        /// Current membership generation.
        to: u64,
        /// Current active membership bitset.
        active_mask: u8,
    },
    /// The hash-committed application/history revision changed.
    StateRevisionChanged {
        /// Previous revision hash.
        from: HashType,
        /// Current revision hash.
        to: HashType,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Timestamped operational change with recommended service actions.
pub struct HaOperationalEvent {
    /// Head nonce at which the change was observed.
    pub observed_at: Nonce,
    /// Exact state transition.
    pub kind: HaOperationalEventKind,
    /// Recommended machine-readable operational actions.
    pub directives: Vec<HaServiceDirective>,
}

/// Immutable consensus state used to catch a stopped or suspended HA member up
/// to a healthy peer. Transient Dispatch/Acknowledge/Confirm state is
/// deliberately excluded: recovery resumes at the next epoch boundary.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HaRecoverySnapshot {
    /// Recovery snapshot codec version.
    pub format_version: u16,
    /// Consensus group captured by the snapshot.
    pub group_id: ConsensusGroupId,
    /// Immutable fixed member-slot assignment.
    pub members: HaMemberSlots,
    /// Hash of [`Self::members`]' public identities.
    pub fixed_membership_hash: HashType,
    /// Active-membership generation at the snapshot head.
    pub membership_generation: u64,
    /// Committed HA parameters.
    pub parameters: HighAvailabilityParameters,
    /// Hash commitment to [`Self::parameters`].
    pub parameters_hash: HashType,
    /// Certified compacted history anchor, when history was pruned.
    pub checkpoint: Option<HaHistoryCheckpoint>,
    /// Finalized suffix after the checkpoint or complete genesis history.
    pub epochs: Vec<HaEpoch>,
    /// Per-member presence state at the snapshot head.
    pub presence: HaPresenceTracker,
    /// Certified membership changes retained with the snapshot.
    pub membership_changes: Vec<HaMembershipCertificate>,
    /// Committed corrective amendments retained with the snapshot.
    pub amendments: Vec<AmendmentRecord>,
}

/// A majority-certified sealed HA history anchor.
///
/// HA runs under the documented authenticated crash-fault threat model, so
/// `approval_mask` is the exact strict-majority confirmation certificate from
/// `through_epoch`, rather than a Byzantine signature aggregate.
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct HaHistoryCheckpoint {
    /// Checkpoint codec version.
    pub format_version: u16,
    /// Consensus group committed by the checkpoint.
    pub group_id: ConsensusGroupId,
    /// Hash of the fixed member-slot assignment.
    pub fixed_membership_hash: HashType,
    /// Hash of the committed HA parameters.
    pub parameters_hash: HashType,
    /// Last sealed epoch summarized by the checkpoint.
    pub through_epoch: HaEpoch,
    /// Active-membership generation at the anchor.
    pub membership_generation: u64,
    /// Active member slots at the anchor.
    pub active_mask: u8,
    /// Per-member presence state at the anchor.
    pub presence: HaPresenceTracker,
    /// Rolling commitment to every epoch through the anchor.
    pub history_accumulator: HashType,
    /// Strict-majority confirmation mask copied from the anchor epoch.
    pub approval_mask: u8,
    /// Hash commitment to the complete checkpoint record.
    pub checkpoint_hash: HashType,
}

impl HaHistoryCheckpoint {
    pub(super) fn compute_hash(&self) -> Result<HashType> {
        let mut unsigned = self.clone();
        unsigned.checkpoint_hash = HashType::default();
        let encoded = borsh::to_vec(&unsigned).map_err(|error| {
            BlossomError::WireProtocol(format!("encode HA history checkpoint: {error}"))
        })?;
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_HISTORY_CHECKPOINT_DOMAIN);
        hasher.update(encoded);
        Ok(hasher.finalize())
    }

    pub(super) fn validate(
        &self,
        members: &HaMemberSlots,
        parameters: HighAvailabilityParameters,
    ) -> Result<()> {
        if self.format_version != HIGH_AVAILABILITY_HISTORY_CHECKPOINT_VERSION
            || self.group_id != self.through_epoch.group_id
            || self.fixed_membership_hash != members.fixed_identity_hash()
            || self.fixed_membership_hash != self.through_epoch.fixed_membership_hash
            || self.parameters_hash != parameters.hash()
            || self.parameters_hash != self.through_epoch.parameters_hash
            || self.membership_generation != self.through_epoch.membership_generation
            || self.active_mask != self.through_epoch.active_mask
            || self.approval_mask != self.through_epoch.confirmation_mask
            || self.approval_mask & !self.active_mask != 0
            || (self.approval_mask.count_ones() as usize)
                < high_availability_majority(self.active_mask.count_ones() as usize)
            || self.checkpoint_hash != self.compute_hash()?
        {
            return Err(BlossomError::WireProtocol(
                "invalid certified HA history checkpoint".to_string(),
            ));
        }
        self.through_epoch.validate(members)
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Membership transition authorized by a strict majority of active slots.
pub enum HaMembershipAction {
    /// Removes a fixed member slot from the active voting mask.
    Suspend,
    /// Restores a slot after proving possession of certified recovery state.
    Reactivate {
        /// Finalized nonce through which the member caught up.
        caught_up_through: Nonce,
        /// Certified checkpoint hash possessed by the member.
        checkpoint_hash: HashType,
        /// Application/history revision possessed by the member.
        state_revision: HashType,
    },
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Hash-committed proposal for one active-membership transition.
pub struct HaMembershipProposal {
    /// Consensus group in which the transition applies.
    pub group_id: ConsensusGroupId,
    /// Current generation that the transition advances.
    pub membership_generation: u64,
    /// Current active member bitset.
    pub active_mask: u8,
    /// Hash of the committed HA parameters.
    pub parameters_hash: HashType,
    /// First epoch nonce at which the transition applies.
    pub effective_nonce: Nonce,
    /// Fixed member slot affected by the transition.
    pub slot: HaMemberSlot,
    /// Suspension or checkpoint-bound reactivation.
    pub action: HaMembershipAction,
    /// Domain-separated commitment to all proposal fields.
    pub digest: HashType,
}

impl HaMembershipProposal {
    pub(super) fn new(
        group_id: ConsensusGroupId,
        membership_generation: u64,
        active_mask: u8,
        parameters_hash: HashType,
        effective_nonce: Nonce,
        slot: HaMemberSlot,
        action: HaMembershipAction,
    ) -> Self {
        let mut proposal = Self {
            group_id,
            membership_generation,
            active_mask,
            parameters_hash,
            effective_nonce,
            slot,
            action,
            digest: HashType::default(),
        };
        proposal.digest = proposal.compute_digest();
        proposal
    }

    pub(super) fn compute_digest(&self) -> HashType {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_MEMBERSHIP_PROPOSAL_HASH_DOMAIN);
        hasher.update(self.group_id.as_ref());
        hasher.update(self.membership_generation.to_le_bytes());
        hasher.update([self.active_mask]);
        hasher.update(self.parameters_hash.as_ref());
        hasher.update(self.effective_nonce.to_le_bytes());
        hasher.update([self.slot.0]);
        match self.action {
            HaMembershipAction::Suspend => hasher.update([0]),
            HaMembershipAction::Reactivate {
                caught_up_through,
                checkpoint_hash,
                state_revision,
            } => {
                hasher.update([1]);
                hasher.update(caught_up_through.to_le_bytes());
                hasher.update(checkpoint_hash.as_ref());
                hasher.update(state_revision.as_ref());
            }
        }
        hasher.finalize()
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// One active member's vote for an exact membership proposal.
pub struct HaMembershipVote {
    /// Proposal being approved.
    pub proposal: HaMembershipProposal,
    /// Fixed member slot casting the vote.
    pub sender: HaMemberSlot,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Strict-majority certificate for one membership transition.
pub struct HaMembershipCertificate {
    /// Exact certified proposal.
    pub proposal: HaMembershipProposal,
    /// Bitset of active slots that approved the proposal.
    pub approval_mask: u8,
}

impl HaNodeStatus {
    /// Derives native active-active service readiness from this node status.
    pub fn operational_status(&self) -> HaOperationalStatus {
        let active_nodes = self.active_mask.count_ones() as u8;
        let required_nodes = u8::try_from(high_availability_majority(usize::from(active_nodes)))
            .expect("HA majority is at most seven");
        let mut responsive_mask = 0u8;
        for index in 0..usize::from(self.member_count) {
            let bit = 1u8 << index;
            if self.active_mask & bit == 0 {
                continue;
            }
            if index == self.self_slot.index()
                || self.availability[index] == NodeAvailabilityStatus::Active
            {
                responsive_mask |= bit;
            }
        }
        let responsive_nodes = responsive_mask.count_ones() as u8;
        let self_status = self.availability[self.self_slot.index()];
        let self_active = self.active_mask & (1u8 << self.self_slot.0) != 0;
        let health =
            if !self_active || matches!(self_status, NodeAvailabilityStatus::Suspended { .. }) {
                HaServiceHealth::Suspended
            } else if responsive_nodes < required_nodes {
                HaServiceHealth::Unavailable
            } else if responsive_nodes < active_nodes
                || self
                    .availability
                    .iter()
                    .take(usize::from(self.member_count))
                    .any(|status| *status != NodeAvailabilityStatus::Active)
            {
                HaServiceHealth::Degraded
            } else {
                HaServiceHealth::Ready
            };
        let directives = match health {
            HaServiceHealth::Ready => vec![HaServiceDirective::Continue],
            HaServiceHealth::Degraded => vec![
                HaServiceDirective::Continue,
                HaServiceDirective::NotifyOperators,
            ],
            HaServiceHealth::Unavailable => vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::AwaitQuorum {
                    required: required_nodes,
                    responsive: responsive_nodes,
                },
            ],
            HaServiceHealth::Suspended => vec![
                HaServiceDirective::DrainWrites,
                HaServiceDirective::FetchRecoverySnapshot {
                    minimum_head: self.head_nonce,
                },
                HaServiceDirective::AwaitReactivation,
            ],
        };
        HaOperationalStatus {
            health,
            self_status,
            active_nodes,
            responsive_nodes,
            required_nodes,
            accepts_writes: self_active
                && matches!(health, HaServiceHealth::Ready | HaServiceHealth::Degraded),
            serves_local_reads: true,
            strict_reads_through: self.sealed,
            directives,
        }
    }

    /// Compares a peer status and recommends recovery or quarantine actions.
    pub fn assess_peer(&self, peer: &Self) -> HaPeerAssessment {
        let incompatible = self.group_id != peer.group_id
            || self.fixed_membership_hash != peer.fixed_membership_hash
            || self.parameters_hash != peer.parameters_hash;
        let (compatibility, directives) = if incompatible {
            (
                HaPeerCompatibility::Incompatible,
                vec![
                    HaServiceDirective::QuarantinePeer,
                    HaServiceDirective::NotifyOperators,
                ],
            )
        } else if self.membership_generation < peer.membership_generation {
            (
                HaPeerCompatibility::LocalBehind,
                vec![
                    HaServiceDirective::DrainWrites,
                    HaServiceDirective::FetchRecoverySnapshot {
                        minimum_head: peer.head_nonce,
                    },
                    HaServiceDirective::RestartOrRedeploy,
                ],
            )
        } else if self.membership_generation > peer.membership_generation {
            (
                HaPeerCompatibility::PeerBehind,
                vec![HaServiceDirective::OfferRecoverySnapshot {
                    through: self.head_nonce,
                }],
            )
        } else if self.active_mask != peer.active_mask
            || (self.head_nonce == peer.head_nonce
                && (self.head_hash != peer.head_hash
                    || self.revision.revision_hash != peer.revision.revision_hash))
        {
            (
                HaPeerCompatibility::Diverged,
                vec![
                    HaServiceDirective::QuarantinePeer,
                    HaServiceDirective::NotifyOperators,
                    HaServiceDirective::DrainWrites,
                ],
            )
        } else if self.head_nonce < peer.head_nonce {
            (
                HaPeerCompatibility::LocalBehind,
                vec![
                    HaServiceDirective::DrainWrites,
                    HaServiceDirective::FetchRecoverySnapshot {
                        minimum_head: peer.head_nonce,
                    },
                    HaServiceDirective::RestartOrRedeploy,
                ],
            )
        } else if self.head_nonce > peer.head_nonce {
            (
                HaPeerCompatibility::PeerBehind,
                vec![HaServiceDirective::OfferRecoverySnapshot {
                    through: self.head_nonce,
                }],
            )
        } else {
            (
                HaPeerCompatibility::Compatible,
                vec![HaServiceDirective::Continue],
            )
        };
        HaPeerAssessment {
            compatibility,
            local_head: self.head_nonce,
            peer_head: peer.head_nonce,
            directives,
        }
    }

    /// Produces externally observable state changes since `previous`.
    pub fn operational_events_since(&self, previous: &Self) -> Vec<HaOperationalEvent> {
        let current_status = self.operational_status();
        let directives = current_status.directives;
        let mut events = Vec::new();
        let previous_health = previous.operational_status().health;
        let current_health = current_status.health;
        if previous_health != current_health {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::HealthChanged {
                    from: previous_health,
                    to: current_health,
                },
                directives: directives.clone(),
            });
        }
        if previous.head_nonce != self.head_nonce {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::HeadAdvanced {
                    from: previous.head_nonce,
                    to: self.head_nonce,
                },
                directives: directives.clone(),
            });
        }
        if previous.sealed != self.sealed {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::SealedWatermarkAdvanced {
                    from: previous.sealed,
                    to: self.sealed,
                },
                directives: directives.clone(),
            });
        }
        for index in 0..usize::from(self.member_count) {
            if previous.availability[index] != self.availability[index] {
                events.push(HaOperationalEvent {
                    observed_at: self.head_nonce,
                    kind: HaOperationalEventKind::MemberAvailabilityChanged {
                        slot: HaMemberSlot(index as u8),
                        from: previous.availability[index],
                        to: self.availability[index],
                    },
                    directives: directives.clone(),
                });
            }
        }
        if previous.membership_generation != self.membership_generation
            || previous.active_mask != self.active_mask
        {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::MembershipGenerationChanged {
                    from: previous.membership_generation,
                    to: self.membership_generation,
                    active_mask: self.active_mask,
                },
                directives: directives.clone(),
            });
        }
        if previous.revision.revision_hash != self.revision.revision_hash {
            events.push(HaOperationalEvent {
                observed_at: self.head_nonce,
                kind: HaOperationalEventKind::StateRevisionChanged {
                    from: previous.revision.revision_hash,
                    to: self.revision.revision_hash,
                },
                directives,
            });
        }
        events
    }
}

impl StateRevision {
    /// Constructs a revision by accumulating a complete iterator of epoch hashes.
    pub fn from_epoch_hashes(
        head: Watermark,
        sealed: Watermark,
        hashes: impl IntoIterator<Item = HashType>,
    ) -> Self {
        Self::from_history_accumulator(
            head,
            sealed,
            accumulate_history(HashType::default(), hashes),
        )
    }

    /// Constructs a revision from an already accumulated history commitment.
    pub fn from_history_accumulator(
        head: Watermark,
        sealed: Watermark,
        history_accumulator: HashType,
    ) -> Self {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_REVISION_HASH_DOMAIN);
        hasher.update(head.position.to_le_bytes());
        hasher.update(sealed.position.to_le_bytes());
        hasher.update(history_accumulator.as_ref());
        Self {
            head,
            sealed,
            revision_hash: hasher.finalize(),
        }
    }
}

pub(super) fn accumulate_history(
    mut accumulator: HashType,
    hashes: impl IntoIterator<Item = HashType>,
) -> HashType {
    for hash in hashes {
        let mut hasher = ProtocolHasher::new();
        hasher.update(HA_HISTORY_ACCUMULATOR_DOMAIN);
        hasher.update(accumulator.as_ref());
        hasher.update(hash.as_ref());
        accumulator = hasher.finalize();
    }
    accumulator
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Tracks consecutive absence and lifecycle status for fixed HA member slots.
pub struct HaPresenceTracker {
    missed: [u32; MAX_HA_NODES],
    statuses: [NodeAvailabilityStatus; MAX_HA_NODES],
}

impl Default for HaPresenceTracker {
    fn default() -> Self {
        Self {
            missed: [0; MAX_HA_NODES],
            statuses: [NodeAvailabilityStatus::Active; MAX_HA_NODES],
        }
    }
}

impl HaPresenceTracker {
    /// Applies one finalized epoch's presence bitset to every active member.
    pub fn observe_epoch(
        &mut self,
        members: &HaMemberSlots,
        presence_mask: u8,
        nonce: Nonce,
        parameters: HighAvailabilityParameters,
    ) {
        for index in 0..members.member_count() {
            let slot = HaMemberSlot(index as u8);
            if !members.is_active(slot) {
                continue;
            }
            if presence_mask & (1u8 << index) != 0 {
                self.missed[index] = 0;
                self.statuses[index] = NodeAvailabilityStatus::Active;
                continue;
            }
            self.missed[index] = self.missed[index].saturating_add(1);
            self.statuses[index] = if self.missed[index] >= parameters.unresponsive_epoch_depth {
                NodeAvailabilityStatus::Unresponsive
            } else {
                NodeAvailabilityStatus::Missing {
                    consecutive_epochs: self.missed[index],
                }
            };
        }
        let _ = nonce;
    }

    /// Returns the inferred availability of `slot`.
    pub fn status(&self, slot: HaMemberSlot) -> NodeAvailabilityStatus {
        self.statuses
            .get(slot.index())
            .copied()
            .unwrap_or(NodeAvailabilityStatus::Unresponsive)
    }

    /// Returns the consecutive missed-epoch count for `slot`.
    pub fn missed_epochs(&self, slot: HaMemberSlot) -> u32 {
        self.missed.get(slot.index()).copied().unwrap_or(u32::MAX)
    }

    /// Marks `slot` as suspended at the supplied epoch.
    pub fn mark_suspended(&mut self, slot: HaMemberSlot, since: Nonce) {
        if let Some(status) = self.statuses.get_mut(slot.index()) {
            *status = NodeAvailabilityStatus::Suspended { since };
        }
    }

    /// Clears absence state and marks `slot` active.
    pub fn mark_reactivated(&mut self, slot: HaMemberSlot) {
        if let Some(missed) = self.missed.get_mut(slot.index()) {
            *missed = 0;
        }
        if let Some(status) = self.statuses.get_mut(slot.index()) {
            *status = NodeAvailabilityStatus::Active;
        }
    }
}
