//! HA health, topology, peer-assessment, and recovery-view tests.

use super::*;

#[test]
fn handshake_and_status_bind_committed_ha_parameters() {
    let nodes = runtimes(3);
    let handshake = nodes[0].handshake();
    nodes[1].validate_handshake(&handshake).unwrap();

    let mut conflicting = handshake;
    conflicting.parameters_hash = HashType::hash(b"different-parameters");
    assert!(matches!(
        nodes[1].validate_handshake(&conflicting),
        Err(BlossomError::InvalidConfiguration(_))
    ));

    let status = nodes[0].status().unwrap();
    assert_eq!(status.parameters, HighAvailabilityParameters::default());
    assert_eq!(status.parameters_hash, status.parameters.hash());
    assert_eq!(status.head_hash, nodes[0].head().hash);
    assert_eq!(
        nodes[0].head().parameters_hash,
        HighAvailabilityParameters::default().hash()
    );
}

#[test]
fn operational_status_is_machine_actionable_across_failure_states() {
    let nodes = runtimes(3);
    let ready = nodes[0].status().unwrap();
    let ready_operational = ready.operational_status();
    assert_eq!(ready_operational.health, HaServiceHealth::Ready);
    assert!(ready_operational.accepts_writes);
    assert_eq!(
        ready_operational.directives,
        vec![HaServiceDirective::Continue]
    );

    let mut degraded = ready.clone();
    degraded.availability[2] = NodeAvailabilityStatus::Missing {
        consecutive_epochs: 1,
    };
    let degraded_operational = degraded.operational_status();
    assert_eq!(degraded_operational.health, HaServiceHealth::Degraded);
    assert!(degraded_operational.accepts_writes);
    assert!(
        degraded_operational
            .directives
            .contains(&HaServiceDirective::NotifyOperators)
    );

    let mut unavailable = degraded.clone();
    unavailable.availability[1] = NodeAvailabilityStatus::Unresponsive;
    let unavailable_operational = unavailable.operational_status();
    assert_eq!(unavailable_operational.health, HaServiceHealth::Unavailable);
    assert!(!unavailable_operational.accepts_writes);
    assert!(
        unavailable_operational
            .directives
            .contains(&HaServiceDirective::NotifyUsers)
    );
    assert!(
        unavailable_operational
            .directives
            .contains(&HaServiceDirective::DrainWrites)
    );
    assert!(
        unavailable_operational
            .directives
            .contains(&HaServiceDirective::AwaitQuorum {
                required: 2,
                responsive: 1,
            })
    );

    let mut suspended = ready;
    suspended.active_mask &= !(1u8 << suspended.self_slot.0);
    suspended.availability[suspended.self_slot.index()] = NodeAvailabilityStatus::Suspended {
        since: Nonce::new(9),
    };
    let suspended_operational = suspended.operational_status();
    assert_eq!(suspended_operational.health, HaServiceHealth::Suspended);
    assert!(!suspended_operational.accepts_writes);
    assert!(
        suspended_operational
            .directives
            .contains(&HaServiceDirective::AwaitReactivation)
    );
}

#[test]
fn service_topologies_expose_distinct_write_paths_and_majorities() {
    for nodes in MIN_HA_NODES..=MAX_HA_NODES {
        let active_active = HaServiceTopology::active_active(nodes).unwrap();
        assert_eq!(
            active_active.mode,
            HaReplicationMode::LeaderlessActiveActive
        );
        assert_eq!(active_active.write_route(), HaWriteRoute::AnyActiveMember);
        assert_eq!(usize::from(active_active.physical_nodes), nodes);
        assert_eq!(usize::from(active_active.voting_nodes), nodes);
        assert_eq!(
            usize::from(active_active.required_voters()),
            high_availability_majority(nodes)
        );

        let active_passive = HaServiceTopology::active_passive(nodes, nodes).unwrap();
        assert_eq!(
            active_passive.mode,
            HaReplicationMode::MajorityLeaderActivePassive
        );
        assert_eq!(active_passive.write_route(), HaWriteRoute::CurrentLeader);
        assert_eq!(
            usize::from(active_passive.required_voters()),
            high_availability_majority(nodes)
        );
    }

    assert!(HaServiceTopology::active_active(1).is_err());
    assert!(HaServiceTopology::active_active(8).is_err());
    assert!(HaServiceTopology::active_passive(4, 5).is_err());
    assert!(HaServiceTopology::active_passive(7, 1).is_err());
}

#[test]
fn two_node_loss_is_readable_but_never_write_available() {
    let active_active = HaServiceTopology::active_active(2)
        .unwrap()
        .assess(1, HaLeadershipStatus::NotApplicable)
        .unwrap();
    assert_eq!(active_active.required_voters, 2);
    assert_eq!(active_active.health, HaServiceHealth::Unavailable);
    assert!(!active_active.accepts_writes);
    assert!(active_active.serves_local_reads);
    assert!(
        active_active
            .directives
            .contains(&HaServiceDirective::AwaitQuorum {
                required: 2,
                responsive: 1,
            })
    );

    let active_passive = HaServiceTopology::active_passive(2, 2)
        .unwrap()
        .assess(1, HaLeadershipStatus::Elected)
        .unwrap();
    assert_eq!(active_passive.required_voters, 2);
    assert_eq!(active_passive.health, HaServiceHealth::Unavailable);
    assert!(!active_passive.accepts_writes);
    assert!(active_passive.serves_local_reads);
}

#[test]
fn majority_leader_mode_requires_both_quorum_and_an_elected_leader() {
    let topology = HaServiceTopology::active_passive(6, 5).unwrap();
    let electing = topology.assess(5, HaLeadershipStatus::Unavailable).unwrap();
    assert_eq!(electing.required_voters, 3);
    assert!(!electing.accepts_writes);
    assert!(
        electing
            .directives
            .contains(&HaServiceDirective::AwaitLeader)
    );

    let elected = topology.assess(3, HaLeadershipStatus::Elected).unwrap();
    assert_eq!(elected.health, HaServiceHealth::Degraded);
    assert!(elected.accepts_writes);
    assert_eq!(elected.write_route, HaWriteRoute::CurrentLeader);

    assert!(
        topology
            .assess(5, HaLeadershipStatus::NotApplicable)
            .is_err()
    );
    assert!(
        HaServiceTopology::active_active(3)
            .unwrap()
            .assess(3, HaLeadershipStatus::Elected)
            .is_err()
    );
}

#[test]
fn runtime_reports_the_leaderless_active_active_service_contract() {
    let nodes = runtimes(3);
    assert_eq!(
        nodes[0].replication_mode(),
        HaReplicationMode::LeaderlessActiveActive
    );
    assert_eq!(
        nodes[0].service_topology(),
        HaServiceTopology::active_active(3).unwrap()
    );
}

#[test]
fn peer_assessment_drives_catch_up_redeploy_and_quarantine_workflows() {
    let mut nodes = runtimes(3);
    let before = nodes[2].status().unwrap();
    finalize_runtime_epoch(&mut nodes, &[0, 1], "epoch-1");
    let healthy = nodes[0].status().unwrap();

    let behind = before.assess_peer(&healthy);
    assert_eq!(behind.compatibility, HaPeerCompatibility::LocalBehind);
    assert!(
        behind
            .directives
            .contains(&HaServiceDirective::FetchRecoverySnapshot {
                minimum_head: Nonce::new(1),
            })
    );
    assert!(
        behind
            .directives
            .contains(&HaServiceDirective::RestartOrRedeploy)
    );

    let recovery_snapshot = nodes[0].recovery_snapshot();
    nodes[2]
        .install_recovery_snapshot(recovery_snapshot)
        .unwrap();
    let recovered = nodes[2].status().unwrap();
    assert_eq!(
        recovered.assess_peer(&healthy).compatibility,
        HaPeerCompatibility::Compatible
    );

    let mut divergent = recovered.clone();
    divergent.head_hash = HashType([0xD1; 32]);
    let assessment = healthy.assess_peer(&divergent);
    assert_eq!(assessment.compatibility, HaPeerCompatibility::Diverged);
    assert!(
        assessment
            .directives
            .contains(&HaServiceDirective::QuarantinePeer)
    );
    assert!(
        assessment
            .directives
            .contains(&HaServiceDirective::DrainWrites)
    );
}

#[test]
fn operational_events_report_health_head_and_revision_transitions() {
    let mut nodes = runtimes(3);
    let before = nodes[0].status().unwrap();
    finalize_runtime_epoch(&mut nodes, &[0, 1], "epoch-1");
    let after = nodes[0].status().unwrap();
    let events = after.operational_events_since(&before);

    assert!(events.iter().any(|event| matches!(
        event.kind,
        HaOperationalEventKind::HealthChanged {
            from: HaServiceHealth::Ready,
            to: HaServiceHealth::Degraded,
        }
    )));
    assert!(events.iter().any(|event| matches!(
        event.kind,
        HaOperationalEventKind::HeadAdvanced {
            from,
            to,
        } if from == Nonce::new(0) && to == Nonce::new(1)
    )));
    assert!(events.iter().any(|event| matches!(
        event.kind,
        HaOperationalEventKind::StateRevisionChanged { .. }
    )));
    assert!(events.iter().all(|event| {
        event
            .directives
            .contains(&HaServiceDirective::NotifyOperators)
    }));
}

#[test]
fn broadcast_assessment_detects_quorum_loss_without_waiting_for_an_epoch() {
    let ok = |peer| HaBroadcastReceipt {
        peer: PubKey([peer; 32]),
        response: Ok(HaWireReceipt {
            kind: "acknowledged".to_string(),
            finalized_epoch_hash: None,
            nonce: Nonce::new(4),
        }),
    };
    let failed = |peer| HaBroadcastReceipt {
        peer: PubKey([peer; 32]),
        response: Err(BlossomError::Io("peer unavailable".to_string())),
    };

    let degraded = HaBroadcastReport {
        receipts: vec![ok(1), failed(2)],
    }
    .assess(3)
    .unwrap();
    assert_eq!(degraded.health, HaServiceHealth::Degraded);
    assert_eq!(degraded.responsive_nodes, 2);
    assert!(degraded.quorum_reached);
    assert!(
        degraded
            .directives
            .contains(&HaServiceDirective::NotifyOperators)
    );

    let duplicate_peer = HaBroadcastReport {
        receipts: vec![ok(1), ok(1), failed(2)],
    }
    .assess(3)
    .unwrap();
    assert_eq!(duplicate_peer.attempted_peers, 2);
    assert_eq!(duplicate_peer.responsive_nodes, 2);
    assert_eq!(duplicate_peer.health, HaServiceHealth::Degraded);

    let unavailable = HaBroadcastReport {
        receipts: vec![failed(1), failed(2)],
    }
    .assess(3)
    .unwrap();
    assert_eq!(unavailable.health, HaServiceHealth::Unavailable);
    assert_eq!(unavailable.responsive_nodes, 1);
    assert!(!unavailable.quorum_reached);
    assert!(
        unavailable
            .directives
            .contains(&HaServiceDirective::NotifyUsers)
    );
    assert!(
        unavailable
            .directives
            .contains(&HaServiceDirective::DrainWrites)
    );
}
