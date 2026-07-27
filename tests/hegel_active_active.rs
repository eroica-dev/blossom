use blossom::{
    ActiveActiveCommand, AdmittedCommand, ApplicationCommand, ClientEpoch, ClientId,
    CommandIdentity, ConsensusGroupId, DurableAdmissionStore, HashType, Keypair,
    MembershipCutoverDisposition, OrderStatement, ReplicaMembershipEpoch, SiteId, StoreGeneration,
    ValidatorGeneration, Watermark, required_cutover_disposition,
};
use hegel::TestCase;
use hegel::generators as gs;

fn command(client: u8, sequence: u64, value: u8) -> ActiveActiveCommand {
    ActiveActiveCommand {
        identity: CommandIdentity {
            client_id: ClientId([client; 16]),
            client_epoch: ClientEpoch(1),
            sequence,
        },
        command: ApplicationCommand::new([sequence.to_le_bytes().as_slice(), &[value]].concat())
            .unwrap(),
    }
}

#[hegel::test(test_cases = 200)]
fn reordered_sequences_and_replays_have_stable_opaque_hashes(tc: TestCase) {
    let last = tc.draw(gs::integers::<u8>().min_value(2).max_value(48)) as u64;
    let reverse = tc.draw(gs::booleans());
    let mut order = (1..=last).collect::<Vec<_>>();
    if reverse {
        order.reverse();
    } else {
        order.sort_by_key(|sequence| (sequence % 2, *sequence));
    }
    for sequence in &order {
        assert_eq!(
            command(1, *sequence, *sequence as u8).hash().unwrap(),
            command(1, *sequence, *sequence as u8).hash().unwrap()
        );
    }
    assert_eq!(order.len(), last as usize);
}

#[hegel::test(test_cases = 150)]
fn command_identity_equivocation_changes_the_committed_hash(tc: TestCase) {
    let sequence = tc.draw(gs::integers::<u8>().min_value(1).max_value(32)) as u64;
    let first = tc.draw(gs::integers::<u8>());
    let mut second = tc.draw(gs::integers::<u8>());
    if second == first {
        second = second.wrapping_add(1);
    }
    assert_ne!(
        command(2, sequence, first).hash().unwrap(),
        command(2, sequence, second).hash().unwrap()
    );
}

#[hegel::test(test_cases = 40)]
fn durable_order_votes_never_sign_two_references_at_one_position(tc: TestCase) {
    let position = tc.draw(gs::integers::<u16>().min_value(1)) as u64;
    let first = tc.draw(gs::integers::<u8>());
    let mut second = tc.draw(gs::integers::<u8>());
    if second == first {
        second = second.wrapping_add(1);
    }
    let keypair = Keypair::generate();
    let path = std::env::temp_dir().join(format!(
        "blossom-hegel-order-vote-{}-{position}-{}",
        std::process::id(),
        keypair.public
    ));
    let store = DurableAdmissionStore::open(
        &path,
        SiteId("site-a".to_string()),
        StoreGeneration(1),
        keypair.signer(),
    )
    .unwrap();
    let statement = |reference_byte| OrderStatement {
        consensus_group_id: ConsensusGroupId::root(),
        blossom_epoch_hash: HashType([0x44; 32]),
        position: Watermark { position },
        reference_hash: HashType([reference_byte; 32]),
        previous_order_certificate_hash: HashType::default(),
        validator_generation: ValidatorGeneration(1),
    };

    let first_statement = statement(first);
    assert_eq!(
        store
            .sign_order_statement(&first_statement)
            .unwrap()
            .statement,
        first_statement
    );
    store.sign_order_statement(&first_statement).unwrap();
    assert!(store.sign_order_statement(&statement(second)).is_err());
    drop(store);
    std::fs::remove_dir_all(path).ok();
}

#[hegel::test(test_cases = 80)]
fn membership_cutover_always_resolves_accepted_work(tc: TestCase) {
    let accepted = tc.draw(gs::booleans());
    let available = tc.draw(gs::booleans());
    let can_recertify = tc.draw(gs::booleans());
    let disposition = required_cutover_disposition(accepted, available, can_recertify);
    if accepted && available {
        assert_eq!(
            disposition,
            MembershipCutoverDisposition::FinalizeUnderOldMembership
        );
    } else if accepted && can_recertify {
        assert_eq!(
            disposition,
            MembershipCutoverDisposition::RecertifyUnderNewMembership
        );
    } else {
        assert_eq!(disposition, MembershipCutoverDisposition::ExplicitAbort);
    }
}

#[hegel::test(test_cases = 40)]
fn durable_store_identity_is_stable_across_restart(tc: TestCase) {
    let site_number = tc.draw(gs::integers::<u8>().min_value(1).max_value(32));
    let generation = tc.draw(gs::integers::<u8>().min_value(1).max_value(32)) as u64;
    let keypair = Keypair::generate();
    let path = std::env::temp_dir().join(format!(
        "blossom-hegel-store-identity-{}-{site_number}-{}",
        std::process::id(),
        keypair.public
    ));
    let site = SiteId(format!("site-{site_number}"));
    let store = DurableAdmissionStore::open(
        &path,
        site.clone(),
        StoreGeneration(generation),
        keypair.signer(),
    )
    .unwrap();
    store
        .admit(
            &AdmittedCommand {
                origin_sequence: 1,
                command: command(site_number, 1, site_number),
            },
            ReplicaMembershipEpoch(1),
        )
        .unwrap();
    drop(store);

    assert!(
        DurableAdmissionStore::open(
            &path,
            SiteId(format!("other-{site_number}")),
            StoreGeneration(generation),
            keypair.signer(),
        )
        .is_err()
    );
    assert!(
        DurableAdmissionStore::open(
            &path,
            site.clone(),
            StoreGeneration(generation + 1),
            keypair.signer(),
        )
        .is_err()
    );
    let reopened =
        DurableAdmissionStore::open(&path, site, StoreGeneration(generation), keypair.signer())
            .unwrap();
    drop(reopened);
    std::fs::remove_dir_all(path).ok();
}
