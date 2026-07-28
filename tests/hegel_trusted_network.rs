//! Property checks for trusted-network durability and failover behavior.

use std::collections::BTreeMap;

use blossom::blossom::{Header, TrustedAcknowledgement, Verification, VerificationBody};
use blossom::state::{init_quorum, init_trusted_acknowledgements, init_trusted_confirmations};
use blossom::{DoHash, HashType, PubKey, Signature, supermajority_count};
use hegel::TestCase;
use hegel::generators as gs;

fn members(count: usize) -> Vec<PubKey> {
    (0..count)
        .map(|index| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
            PubKey(bytes)
        })
        .collect()
}

fn confirmation(sender: PubKey, candidate: HashType) -> Verification {
    Verification {
        header: Header {
            sender,
            signature: Signature::default(),
            ..Header::default()
        },
        body: VerificationBody {
            blocks_hash: candidate,
            blocks: BTreeMap::new(),
        },
    }
}

fn acknowledgement(sender: PubKey, mask: u16, member_count: usize) -> TrustedAcknowledgement {
    let blocks = (0..member_count)
        .filter(|index| mask & (1 << index) != 0)
        .map(|index| {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&(index as u64).to_le_bytes());
            (HashType(hash), ())
        })
        .collect::<BTreeMap<_, _>>();
    TrustedAcknowledgement {
        header: Header {
            sender,
            signature: Signature::default(),
            ..Header::default()
        },
        body: VerificationBody {
            blocks_hash: blocks.hash(),
            blocks,
        },
    }
}

#[hegel::test(test_cases = 300)]
fn trusted_acknowledgement_opens_exactly_at_two_thirds_dispatches(tc: TestCase) {
    let multiplier = tc.draw(gs::integers::<u8>().min_value(1).max_value(24)) as usize;
    let count = multiplier * 3;
    let observed = tc.draw(gs::integers::<u8>().max_value(count as u8)) as usize;
    let keys = members(count);
    let mut quorum = init_quorum(count as u32, &keys, &keys[0]);
    quorum.dispatch_status = Some(observed > 0);
    quorum.received_dispatches = keys
        .iter()
        .copied()
        .skip(1)
        .take(observed.saturating_sub(1))
        .collect();

    assert_eq!(
        quorum.has_trusted_dispatch_quorum(),
        observed >= supermajority_count(count)
    );
}

#[hegel::test(test_cases = 300)]
fn trusted_confirmation_quorum_never_finalizes_two_candidates(tc: TestCase) {
    let multiplier = tc.draw(gs::integers::<u8>().min_value(1).max_value(24)) as usize;
    let count = multiplier * 3;
    let first_count = tc.draw(gs::integers::<u8>().max_value(count as u8)) as usize;
    let keys = members(count);
    let first = HashType([0x11; 32]);
    let second = HashType([0x22; 32]);
    let mut confirmations = init_trusted_confirmations(count as u32);
    for (index, sender) in keys.iter().copied().enumerate() {
        confirmations
            .record(confirmation(
                sender,
                if index < first_count { first } else { second },
            ))
            .unwrap();
    }

    let threshold = supermajority_count(count);
    let first_final = first_count >= threshold;
    let second_final = count - first_count >= threshold;
    assert!(!(first_final && second_final));
    assert_eq!(
        confirmations.consensus_hash(),
        first_final
            .then_some(first)
            .or_else(|| second_final.then_some(second))
    );
}

#[hegel::test(test_cases = 500)]
fn trusted_acknowledgements_accept_exactly_monotonic_mask_growth(tc: TestCase) {
    let member_count = tc.draw(gs::integers::<u8>().min_value(1).max_value(12)) as usize;
    let max_mask = (1u16 << member_count) - 1;
    let previous_mask = tc.draw(gs::integers::<u16>().max_value(max_mask));
    let next_mask = tc.draw(gs::integers::<u16>().max_value(max_mask));
    let sender = members(1)[0];
    let mut acknowledgements = init_trusted_acknowledgements(member_count as u32);
    acknowledgements
        .record(acknowledgement(sender, previous_mask, member_count))
        .unwrap();

    let result = acknowledgements.record(acknowledgement(sender, next_mask, member_count));
    let is_monotonic = previous_mask & !next_mask == 0;
    assert_eq!(result.is_ok(), is_monotonic);
    assert_eq!(acknowledgements.acknowledgements.len(), 1);
    assert_eq!(acknowledgements.count.values().copied().sum::<u32>(), 1);
}

#[test]
fn every_dispatch_mask_through_twelve_members_matches_the_threshold() {
    for count in [3usize, 6, 9, 12] {
        let keys = members(count);
        for mask in 0u16..(1u16 << count) {
            let mut quorum = init_quorum(count as u32, &keys, &keys[0]);
            quorum.dispatch_status = Some(mask & 1 != 0);
            quorum.received_dispatches = keys
                .iter()
                .copied()
                .enumerate()
                .skip(1)
                .filter_map(|(index, key)| (mask & (1 << index) != 0).then_some(key))
                .collect();
            assert_eq!(
                quorum.has_trusted_dispatch_quorum(),
                mask & 1 != 0 && mask.count_ones() as usize >= supermajority_count(count)
            );
        }
    }
}
