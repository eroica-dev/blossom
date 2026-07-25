use std::str::FromStr;

use blossom::{
    CommitteeParticipant, ConsensusParameters, HashType, PubKey, QuorumSize, SiteId,
    find_round_number_with_size, generate_safety_manifest, select_quorums_with_size,
};
use hegel::TestCase;
use hegel::generators as gs;

#[hegel::test(test_cases = 250)]
fn quorum_environment_values_accept_exactly_q_equals_three_k(tc: TestCase) {
    let value = tc.draw(gs::integers::<u16>().max_value(4096)) as usize;
    let parsed = QuorumSize::from_str(&value.to_string());
    assert_eq!(parsed.is_ok(), value >= 3 && value.is_multiple_of(3));
}

#[hegel::test(test_cases = 200)]
fn startup_resolution_obeys_cli_environment_default_precedence(tc: TestCase) {
    let environment = tc.draw(gs::integers::<u8>().min_value(1).max_value(40)) as usize * 3;
    let cli = tc.draw(gs::integers::<u8>().min_value(1).max_value(40)) as usize * 3;
    let include_cli = tc.draw(gs::booleans());
    let environment_text = environment.to_string();
    let cli_text = cli.to_string();

    let resolved = QuorumSize::resolve_startup(
        include_cli.then_some(cli_text.as_str()),
        Some(environment_text.as_str()),
    )
    .unwrap();
    assert_eq!(resolved.get(), if include_cli { cli } else { environment });
    assert_eq!(QuorumSize::resolve_startup(None, None).unwrap().get(), 6);
}

#[hegel::test(test_cases = 200)]
fn arbitrary_q_three_k_topologies_are_deterministic_and_checked(tc: TestCase) {
    let multiplier = tc.draw(gs::integers::<u8>().min_value(1).max_value(20)) as usize;
    let node_count = tc.draw(gs::integers::<u8>().min_value(1).max_value(200)) as usize;
    let self_index = tc
        .draw(gs::integers::<u8>().max_value(u8::try_from(node_count - 1).unwrap_or(u8::MAX)))
        as usize;
    let q = QuorumSize::new(multiplier * 3).unwrap();
    let nodes = (0..node_count)
        .map(|index| PubKey([index as u8; 32]))
        .collect::<Vec<_>>();
    let self_key = nodes[self_index];
    let seed = HashType::hash(&[multiplier as u8, node_count as u8]);

    let first = select_quorums_with_size(nodes.iter().copied(), &self_key, seed, true, q);
    let second = select_quorums_with_size(nodes.iter().copied(), &self_key, seed, true, q);
    assert_eq!(first, second);
    assert!(first.iter().all(|round| round.contains(&self_key)));
    assert!(
        first
            .iter()
            .all(|round| round.len() <= q.get().saturating_mul(2))
    );

    let (optimal, rounds) = find_round_number_with_size(node_count, q);
    assert!(optimal <= node_count);
    assert!(rounds >= 1);
}

#[hegel::test(test_cases = 100)]
fn complete_three_site_metadata_yields_balanced_safety_manifests(tc: TestCase) {
    let multiplier = tc.draw(gs::integers::<u8>().min_value(1).max_value(12)) as usize;
    let q = QuorumSize::new(multiplier * 3).unwrap();
    let participants = (0..q.get() * 2)
        .map(|index| CommitteeParticipant {
            node: PubKey([index as u8; 32]),
            site: Some(SiteId(format!("site-{}", index % 3))),
        })
        .collect::<Vec<_>>();

    let manifest = generate_safety_manifest(
        ConsensusParameters::new(q),
        participants,
        HashType::hash(&[multiplier as u8]),
        multiplier.saturating_sub(1),
        true,
    )
    .unwrap();
    assert_eq!(manifest.configured_quorum_size, q.get());
    assert_eq!(manifest.effective_quorum_size, q.get());
    assert!(manifest.site_loss_tolerance);
    assert!(
        manifest
            .committee_layout
            .members_by_site
            .values()
            .all(|members| members.len() == multiplier)
    );
}
