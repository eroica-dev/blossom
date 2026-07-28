//! HA suspension, reactivation, and amendment tests.

use super::*;

#[test]
fn amendments_change_provisional_revision_and_are_rejected_after_seal() {
    let mut nodes = runtimes(3);
    finalize_runtime_epoch(&mut nodes, &[0, 1], "epoch-1");
    let target = nodes[0].head().clone();
    let amendment = AmendmentRecord {
        target_epoch_hash: target.hash,
        target_epoch_nonce: target.nonce,
        containing_epoch_nonce: nodes[0].current_round().round_id.nonce,
        origin_slot: HaMemberSlot(2),
        command_identity: CommandIdentity {
            client_id: ClientId([7; 16]),
            client_epoch: ClientEpoch(1),
            sequence: 1,
        },
        supersedes: None,
        payload: AmendmentPayload::Compensation {
            command_bytes: b"late-c".to_vec(),
        },
    };
    let before = nodes[0].revision().unwrap();
    let amendment_transaction = nodes[0].amendment_transaction(&amendment).unwrap();
    finalize_runtime_transactions(
        &mut nodes,
        &[0, 1],
        vec![
            vec![amendment_transaction],
            vec![Transaction::new("epoch-2-node-1")],
        ],
    );
    let after = nodes[0].revision().unwrap();
    assert_ne!(before.revision_hash, after.revision_hash);
    assert_eq!(nodes[0].amendments_for_epoch(target.nonce).len(), 1);
    assert_eq!(nodes[1].amendments_for_epoch(target.nonce).len(), 1);
    for epoch in 3..=7 {
        finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
    }
    assert!(matches!(
        nodes[0].amendment_transaction(&AmendmentRecord {
            containing_epoch_nonce: nodes[0].current_round().round_id.nonce,
            command_identity: CommandIdentity {
                sequence: 2,
                ..amendment.command_identity
            },
            ..amendment
        }),
        Err(BlossomError::EpochSealed { .. })
    ));
}

#[test]
fn six_misses_allow_majority_suspension_and_caught_up_reactivation() {
    let mut nodes = runtimes(3);
    for epoch in 1..=6 {
        finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
    }
    assert_eq!(
        nodes[0].node_status(HaMemberSlot(2)),
        NodeAvailabilityStatus::Unresponsive
    );
    let suspend_zero = nodes[0].vote_to_suspend(HaMemberSlot(2)).unwrap().0;
    let suspend_one = nodes[1].vote_to_suspend(HaMemberSlot(2)).unwrap().0;
    assert!(matches!(
        nodes[0].receive_membership_vote(suspend_one).unwrap(),
        HaRuntimeEvent::MembershipChanged(_)
    ));
    assert!(matches!(
        nodes[1].receive_membership_vote(suspend_zero).unwrap(),
        HaRuntimeEvent::MembershipChanged(_)
    ));
    assert_eq!(nodes[0].members().active_mask(), 0b011);
    let head = nodes[0].head().nonce;
    let reactivate_zero = nodes[0]
        .vote_to_reactivate(HaMemberSlot(2), head)
        .unwrap()
        .0;
    let reactivate_one = nodes[1]
        .vote_to_reactivate(HaMemberSlot(2), head)
        .unwrap()
        .0;
    nodes[0].receive_membership_vote(reactivate_one).unwrap();
    nodes[1].receive_membership_vote(reactivate_zero).unwrap();
    assert_eq!(nodes[0].members().active_mask(), 0b111);
    assert_eq!(
        nodes[0].node_status(HaMemberSlot(2)),
        NodeAvailabilityStatus::Active
    );
}

#[test]
fn membership_change_cannot_discard_an_in_progress_round() {
    let mut nodes = runtimes(3);
    for epoch in 1..=6 {
        finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
    }
    nodes[0].build_dispatch(Vec::new()).unwrap();
    assert!(matches!(
        nodes[0].vote_to_suspend(HaMemberSlot(2)),
        Err(BlossomError::InvalidConfiguration(message))
            if message.contains("empty epoch boundary")
    ));
}
