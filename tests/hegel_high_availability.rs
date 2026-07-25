#![cfg(feature = "high-availability")]

use blossom::{
    ConsensusGroupId, DEFAULT_MUTABLE_EPOCH_DEPTH, DEFAULT_UNRESPONSIVE_EPOCH_DEPTH,
    EpochLifecycle, HaCandidate, HaMemberSlots, HaServiceDirective, HaServiceHealth, HashType,
    HighAvailabilityParameters, HighAvailabilityRuntime, MAX_HA_NODES, NodeAvailabilityStatus,
    NodeIdentity, PubKey, epoch_lifecycle, high_availability_fault_tolerance,
    high_availability_majority,
};
use hegel::TestCase;
use hegel::generators as gs;

fn member(index: u8) -> NodeIdentity {
    NodeIdentity::new(
        PubKey([index; 32]),
        None,
        "tcp",
        "127.0.0.1",
        10_000 + u16::from(index),
        false,
    )
}

#[hegel::test(test_cases = 200)]
fn every_supported_ha_size_has_intersecting_majorities(tc: TestCase) {
    let count = tc.draw(gs::integers::<u8>().min_value(2).max_value(7)) as usize;
    let majority = high_availability_majority(count);
    let all = (1u16 << count) - 1;
    for left in 0..=all {
        if left.count_ones() as usize != majority {
            continue;
        }
        for right in 0..=all {
            if right.count_ones() as usize == majority {
                assert_ne!(left & right, 0);
            }
        }
    }
    assert_eq!(high_availability_fault_tolerance(count), count - majority);
}

#[hegel::test(test_cases = 160)]
fn membership_slot_assignment_is_input_order_independent(tc: TestCase) {
    let count = tc.draw(gs::integers::<u8>().min_value(2).max_value(7));
    let reverse = tc.draw(gs::booleans());
    let mut input = (0..count).map(member).collect::<Vec<_>>();
    if reverse {
        input.reverse();
    } else {
        input.rotate_left(usize::from(count / 2));
    }
    let slots = HaMemberSlots::new(input).unwrap();
    let canonical = HaMemberSlots::new((0..count).map(member).collect::<Vec<_>>()).unwrap();
    assert_eq!(slots.fixed_identity_hash(), canonical.fixed_identity_hash());
    for index in 0..count {
        assert_eq!(
            slots
                .member(blossom::HaMemberSlot(index))
                .unwrap()
                .public_key(),
            PubKey([index; 32])
        );
    }
    let mut different = (0..count).map(member).collect::<Vec<_>>();
    different[usize::from(count - 1)] = member(count.saturating_add(16));
    assert_ne!(
        slots.fixed_identity_hash(),
        HaMemberSlots::new(different).unwrap().fixed_identity_hash()
    );
}

#[hegel::test(test_cases = 200)]
fn fixed_candidate_order_is_deterministic_for_every_mask(tc: TestCase) {
    let count = tc.draw(gs::integers::<u8>().min_value(2).max_value(7));
    let mut mask = tc.draw(gs::integers::<u8>()) & ((1u8 << count) - 1);
    if mask == 0 {
        mask = 1;
    }
    let salt = tc.draw(gs::integers::<u8>());
    let hashes = std::array::from_fn(|index| {
        if mask & (1u8 << index) != 0 {
            HashType::hash(&[salt, index as u8])
        } else {
            HashType::default()
        }
    });
    let candidate = HaCandidate {
        included_mask: mask,
        presence_mask: mask,
        block_hashes: hashes,
        digest: HashType::default(),
    };
    let first = candidate.ordered_slots();
    let second = candidate.ordered_slots();
    assert_eq!(first, second);
    assert_eq!(first.len as u32, mask.count_ones());
    for pair in first.as_slice().windows(2) {
        let left = usize::from(pair[0]);
        let right = usize::from(pair[1]);
        assert!(
            hashes[left] < hashes[right] || (hashes[left] == hashes[right] && pair[0] < pair[1])
        );
    }
}

#[hegel::test(test_cases = 160)]
fn epoch_depth_boundary_has_no_off_by_one(tc: TestCase) {
    let depth = tc.draw(gs::integers::<u8>().min_value(1).max_value(32)) as u32;
    let epoch = tc.draw(gs::integers::<u16>().max_value(20_000)) as u64;
    assert!(matches!(
        epoch_lifecycle(
            blossom::Nonce::new(epoch),
            blossom::Nonce::new(epoch + u64::from(depth) - 1),
            depth,
        ),
        EpochLifecycle::Mutable {
            remaining_successors: 1
        }
    ));
    assert_eq!(
        epoch_lifecycle(
            blossom::Nonce::new(epoch),
            blossom::Nonce::new(epoch + u64::from(depth)),
            depth,
        ),
        EpochLifecycle::Sealed
    );
}

#[hegel::test(test_cases = 120)]
fn depth_configuration_obeys_precedence_and_rejects_zero(tc: TestCase) {
    let mutable = tc.draw(gs::integers::<u8>().min_value(1).max_value(64));
    let unresponsive = tc.draw(gs::integers::<u8>().min_value(1).max_value(64));
    let mutable_env = mutable.saturating_add(1).max(1).to_string();
    let unresponsive_env = unresponsive.saturating_add(1).max(1).to_string();
    let mutable_cli = mutable.to_string();
    let unresponsive_cli = unresponsive.to_string();
    let resolved = HighAvailabilityParameters::resolve_startup(
        Some(&mutable_cli),
        Some(&mutable_env),
        Some(&unresponsive_cli),
        Some(&unresponsive_env),
    )
    .unwrap();
    assert_eq!(resolved.mutable_epoch_depth, u32::from(mutable));
    assert_eq!(resolved.unresponsive_epoch_depth, u32::from(unresponsive));
    assert!(HighAvailabilityParameters::resolve_startup(Some("0"), None, None, None).is_err());
    assert_eq!(
        HighAvailabilityParameters::resolve_startup(None, None, None, None).unwrap(),
        HighAvailabilityParameters::new(
            DEFAULT_MUTABLE_EPOCH_DEPTH,
            DEFAULT_UNRESPONSIVE_EPOCH_DEPTH,
        )
    );
    assert_eq!(MAX_HA_NODES, 7);
}

#[hegel::test(test_cases = 240)]
fn operational_health_matches_every_supported_quorum_boundary(tc: TestCase) {
    let count = tc.draw(gs::integers::<u8>().min_value(2).max_value(7));
    let responsive = tc.draw(gs::integers::<u8>().min_value(1).max_value(count));
    let identities = (0..count).map(member).collect::<Vec<_>>();
    let runtime = HighAvailabilityRuntime::new(
        ConsensusGroupId::named("hegel-ha-operational-health"),
        identities[0].public_key(),
        identities,
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    let mut status = runtime.status().unwrap();
    for index in usize::from(responsive)..usize::from(count) {
        status.availability[index] = NodeAvailabilityStatus::Missing {
            consecutive_epochs: 1,
        };
    }

    let operational = status.operational_status();
    let required = high_availability_majority(usize::from(count)) as u8;
    let expected = if responsive == count {
        HaServiceHealth::Ready
    } else if responsive >= required {
        HaServiceHealth::Degraded
    } else {
        HaServiceHealth::Unavailable
    };
    assert_eq!(operational.health, expected);
    assert_eq!(operational.responsive_nodes, responsive);
    assert_eq!(operational.required_nodes, required);
    assert_eq!(
        operational.accepts_writes,
        matches!(expected, HaServiceHealth::Ready | HaServiceHealth::Degraded)
    );
    if expected == HaServiceHealth::Unavailable {
        assert!(
            operational
                .directives
                .contains(&HaServiceDirective::NotifyUsers)
        );
        assert!(
            operational
                .directives
                .contains(&HaServiceDirective::DrainWrites)
        );
    }
}
