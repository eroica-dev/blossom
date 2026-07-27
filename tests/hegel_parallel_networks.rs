#![cfg(feature = "parallel-networks")]

use blossom::{ConsensusGroupId, HaGroupRegistration, HighAvailabilityParameters, PubKey};
use hegel::TestCase;
use hegel::generators as gs;

fn public_key(value: u64) -> PubKey {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    PubKey(bytes)
}

#[hegel::test(test_cases = 200)]
fn ha_registration_is_canonical_across_input_permutations(tc: TestCase) {
    let count = tc.draw(gs::integers::<u8>().min_value(2).max_value(7)) as usize;
    let offset = tc.draw(gs::integers::<u16>()) as u64;
    let reverse = tc.draw(gs::booleans());
    let rotation = tc.draw(gs::integers::<u8>().min_value(0).max_value(6)) as usize % count;
    let members = (0..count)
        .map(|index| public_key(offset + index as u64))
        .collect::<Vec<_>>();
    let mut permuted = members.clone();
    permuted.rotate_left(rotation);
    if reverse {
        permuted.reverse();
    }
    let scope = ConsensusGroupId::named("hegel-parallel-scope");
    let group = ConsensusGroupId::named("hegel-ha-group");
    let canonical =
        HaGroupRegistration::new(scope, group, members, HighAvailabilityParameters::default())
            .unwrap();
    let reordered = HaGroupRegistration::new(
        scope,
        group,
        permuted,
        HighAvailabilityParameters::default(),
    )
    .unwrap();

    assert_eq!(canonical, reordered);
}

#[hegel::test(test_cases = 100)]
fn registration_hash_binds_both_independent_network_scopes(tc: TestCase) {
    let salt = tc.draw(gs::integers::<u32>());
    let members = (0..3)
        .map(|index| public_key(u64::from(salt) * 10 + index))
        .collect::<Vec<_>>();
    let first = HaGroupRegistration::new(
        ConsensusGroupId::named("global-a"),
        ConsensusGroupId::named("ha-a"),
        members.clone(),
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    let other_global = HaGroupRegistration::new(
        ConsensusGroupId::named("global-b"),
        ConsensusGroupId::named("ha-a"),
        members.clone(),
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    let other_ha = HaGroupRegistration::new(
        ConsensusGroupId::named("global-a"),
        ConsensusGroupId::named("ha-b"),
        members,
        HighAvailabilityParameters::default(),
    )
    .unwrap();

    assert_ne!(first.hash, other_global.hash);
    assert_ne!(first.hash, other_ha.hash);
}
