//! HA round, candidate, epoch, and protocol-validation tests.

use super::*;

#[test]
fn majority_and_fault_tolerance_are_explicit_for_two_through_seven() {
    let expected = [
        (2, 2, 0),
        (3, 2, 1),
        (4, 3, 1),
        (5, 3, 2),
        (6, 4, 2),
        (7, 4, 3),
    ];
    for (nodes, majority, faults) in expected {
        assert_eq!(high_availability_majority(nodes), majority);
        assert_eq!(high_availability_fault_tolerance(nodes), faults);
        assert_eq!(members(nodes).majority(), majority);
    }
}

#[test]
fn membership_is_sorted_into_stable_slots_and_rejects_other_sizes() {
    let slots = HaMemberSlots::new(vec![member(3), member(1), member(2)]).unwrap();
    assert_eq!(
        slots.member(HaMemberSlot(0)).unwrap().public_key(),
        PubKey([1; 32])
    );
    assert_eq!(
        slots.member(HaMemberSlot(2)).unwrap().public_key(),
        PubKey([3; 32])
    );
    assert!(HaMemberSlots::new(vec![member(1)]).is_err());
    assert!(HaMemberSlots::new((0..8).map(member).collect()).is_err());
}

#[test]
fn acknowledgement_masks_are_monotonic() {
    let members = members(3);
    let mut state = HaRoundState::new(round_id(members.active_mask()), &members).unwrap();
    state
        .receive_dispatch(
            &members,
            dispatch(
                members.member(HaMemberSlot(0)).unwrap(),
                0,
                state.round_id,
                "a",
            ),
        )
        .unwrap();
    let first = state.acknowledge(&members, HaMemberSlot(0)).unwrap();
    let mut retraction = first.clone();
    retraction.received_mask = 0;
    retraction.block_hashes = [HashType::default(); MAX_HA_NODES];
    assert!(state.receive_acknowledgement(&members, retraction).is_err());
}

#[test]
fn three_nodes_finalize_with_two_while_third_is_inactive() {
    let members = members(3);
    let target = round_id(members.active_mask());
    let mut states = vec![
        HaRoundState::new(target, &members).unwrap(),
        HaRoundState::new(target, &members).unwrap(),
    ];
    install_dispatches(&mut states, &members, &[0, 1]);
    exchange_acknowledgements(&mut states, &members);
    let confirmations = vec![
        states[0].confirm(&members, HaMemberSlot(0)).unwrap(),
        states[1].confirm(&members, HaMemberSlot(1)).unwrap(),
    ];
    let mut finalized = None;
    for confirmation in confirmations {
        for state in states.iter_mut() {
            finalized = state
                .receive_confirmation(&members, confirmation.clone())
                .unwrap()
                .or(finalized);
        }
    }
    let finalized = finalized.unwrap();
    assert_eq!(finalized.confirmation_mask.count_ones(), 2);
    assert_eq!(finalized.candidate.included_mask, 0b011);
    assert_eq!(finalized.ordered_slots.len, 2);
}

#[test]
fn majority_confirmed_acknowledgement_certifies_presence_without_a_block() {
    let members = members(3);
    let target = round_id(members.active_mask());
    let mut states = vec![
        HaRoundState::new(target, &members).unwrap(),
        HaRoundState::new(target, &members).unwrap(),
        HaRoundState::new(target, &members).unwrap(),
    ];
    install_dispatches(&mut states, &members, &[0, 1]);
    exchange_acknowledgements(&mut states, &members);
    let confirmations = vec![
        states[0].confirm(&members, HaMemberSlot(0)).unwrap(),
        states[1].confirm(&members, HaMemberSlot(1)).unwrap(),
    ];
    let mut finalized = None;
    for confirmation in confirmations {
        for state in &mut states {
            finalized = state
                .receive_confirmation(&members, confirmation.clone())
                .unwrap()
                .or(finalized);
        }
    }
    let finalized = finalized.unwrap();
    assert_eq!(finalized.candidate.included_mask, 0b011);
    assert_eq!(finalized.presence_mask, 0b111);
}

#[test]
fn dispatch_accepted_after_confirmation_lock_is_late() {
    let members = members(3);
    let target = round_id(members.active_mask());
    let mut states = vec![
        HaRoundState::new(target, &members).unwrap(),
        HaRoundState::new(target, &members).unwrap(),
    ];
    install_dispatches(&mut states, &members, &[0, 1]);
    exchange_acknowledgements(&mut states, &members);
    states[0].confirm(&members, HaMemberSlot(0)).unwrap();
    let late = dispatch(
        members.member(HaMemberSlot(2)).unwrap(),
        2,
        target,
        "late-c",
    );
    assert_eq!(
        states[0].receive_dispatch(&members, late).unwrap(),
        HaDispatchOutcome::Late {
            target_epoch: target.nonce
        }
    );
}

#[test]
fn c_before_confirmation_prevents_ab_candidate() {
    let members = members(3);
    let target = round_id(members.active_mask());
    let mut a = HaRoundState::new(target, &members).unwrap();
    for slot in 0..3 {
        a.receive_dispatch(
            &members,
            dispatch(
                members.member(HaMemberSlot(slot)).unwrap(),
                slot,
                target,
                &format!("block-{slot}"),
            ),
        )
        .unwrap();
    }
    let candidate_ab =
        HaCandidate::from_round(target, 0b011, 0b011, masked_hashes(0b011, &a.block_hashes));
    let confirm_ab = HaConfirm {
        round_id: target,
        sender: HaMemberSlot(1),
        candidate: candidate_ab,
    };
    assert!(a.receive_confirmation(&members, confirm_ab).is_err());
}

#[test]
fn fixed_array_order_is_hash_sorted_and_deterministic() {
    let target = round_id(0b111);
    let hashes = [
        HashType([3; 32]),
        HashType([1; 32]),
        HashType([2; 32]),
        HashType::default(),
        HashType::default(),
        HashType::default(),
        HashType::default(),
    ];
    let candidate = HaCandidate::from_round(target, 0b111, 0b111, hashes);
    assert_eq!(candidate.ordered_slots().as_slice(), &[1, 2, 0]);
}

#[test]
fn mutable_depth_seals_at_six_successors() {
    assert_eq!(
        epoch_lifecycle(Nonce::new(10), Nonce::new(15), 6),
        EpochLifecycle::Mutable {
            remaining_successors: 1
        }
    );
    assert_eq!(
        epoch_lifecycle(Nonce::new(10), Nonce::new(16), 6),
        EpochLifecycle::Sealed
    );
}

#[test]
fn strict_operation_barrier_waits_for_the_sealed_watermark() {
    let mut nodes = runtimes(3);
    finalize_runtime_epoch(&mut nodes, &[0, 1], "target");
    let required = Watermark { position: 1 };
    assert!(matches!(
        nodes[0].require_sealed(required),
        Err(BlossomError::WatermarkNotSealed {
            required: 1,
            sealed: 0
        })
    ));
    for epoch in 1..=DEFAULT_MUTABLE_EPOCH_DEPTH {
        finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("successor-{epoch}"));
    }
    nodes[0].require_sealed(required).unwrap();
}

#[test]
fn presence_marks_unresponsive_at_configured_depth() {
    let members = members(3);
    let mut tracker = HaPresenceTracker::default();
    for nonce in 1..=6 {
        tracker.observe_epoch(
            &members,
            0b011,
            Nonce::new(nonce),
            HighAvailabilityParameters::default(),
        );
    }
    assert_eq!(
        tracker.status(HaMemberSlot(2)),
        NodeAvailabilityStatus::Unresponsive
    );
    tracker.observe_epoch(
        &members,
        0b111,
        Nonce::new(7),
        HighAvailabilityParameters::default(),
    );
    assert_eq!(
        tracker.status(HaMemberSlot(2)),
        NodeAvailabilityStatus::Active
    );
}

#[test]
fn cannot_suspend_a_two_node_cluster_to_one() {
    let members = members(2);
    assert!(members.with_suspended(HaMemberSlot(1)).is_err());
}

#[test]
fn every_strict_majority_subset_finalizes_for_every_supported_size() {
    for count in MIN_HA_NODES..=MAX_HA_NODES {
        let required = high_availability_majority(count);
        for mask in 1u8..=low_bits(count as u8) {
            if mask.count_ones() as usize != required {
                continue;
            }
            let participants = (0..count)
                .filter(|index| mask & (1u8 << index) != 0)
                .collect::<Vec<_>>();
            let mut nodes = runtimes(count);
            finalize_runtime_epoch(&mut nodes, &participants, &format!("n-{count}-mask-{mask}"));
            let first = participants[0];
            assert_eq!(nodes[first].head().nonce, Nonce::new(1));
            assert_eq!(
                nodes[first].head().confirmation_mask.count_ones() as usize,
                required
            );
        }
    }
}

#[test]
fn every_submajority_subset_stops_before_confirmation() {
    for count in MIN_HA_NODES..=MAX_HA_NODES {
        let required = high_availability_majority(count);
        for mask in 1u8..=low_bits(count as u8) {
            if mask.count_ones() as usize >= required {
                continue;
            }
            let participants = (0..count)
                .filter(|index| mask & (1u8 << index) != 0)
                .collect::<Vec<_>>();
            let mut nodes = runtimes(count);
            let dispatches = participants
                .iter()
                .map(|index| {
                    (
                        *index,
                        nodes[*index]
                            .build_dispatch(vec![Transaction::new(format!(
                                "minority-{count}-{mask}-{index}"
                            ))])
                            .unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            for (sender, dispatch) in &dispatches {
                for receiver in &participants {
                    if receiver != sender {
                        nodes[*receiver].receive_dispatch(dispatch.clone()).unwrap();
                    }
                }
            }
            let acknowledgements = participants
                .iter()
                .map(|index| (*index, nodes[*index].acknowledge().unwrap()))
                .collect::<Vec<_>>();
            for (sender, acknowledgement) in &acknowledgements {
                for receiver in &participants {
                    if receiver != sender {
                        nodes[*receiver]
                            .receive_acknowledgement(acknowledgement.clone())
                            .unwrap();
                    }
                }
            }
            for participant in participants {
                assert!(matches!(
                    nodes[participant].confirm(),
                    Err(BlossomError::FailedConsensus)
                ));
                assert_eq!(nodes[participant].head().nonce, Nonce::default());
            }
        }
    }
}
