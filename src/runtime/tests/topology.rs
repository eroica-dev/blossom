//! Multi-group routing, latency topology, and fan-out tests.

use super::*;

#[test]
fn fanout_targets_use_registered_consensus_services() {
    let (runtime, keypairs, _) = runtime_with_peers();
    for (index, keypair) in keypairs.iter().enumerate().skip(1) {
        runtime.register_service(Service::new(
            ServiceKind::Consensus,
            keypair.public,
            "tcp",
            "127.0.0.1",
            8000 + index as u16,
        ));
    }

    let targets = runtime.fanout_targets(&FanOutStrategy::unshuffled_topology(HashType::default()));

    assert_eq!(targets.len(), 5);
    assert!(
        targets
            .iter()
            .all(|service| service.public_key != keypairs[0].public)
    );
}

#[test]
fn prefill_dispatch_plan_uses_future_coordinate_line_contacts() {
    let keypairs = (0..36).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8100 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(nodes.clone());
    let mut config = RuntimeConfig::new(nodes[0].clone());
    config.genesis = Some(genesis.clone());
    let runtime = NodeRuntime::new(config);

    for (index, keypair) in keypairs.iter().enumerate().skip(1) {
        runtime.register_service(Service::new(
            ServiceKind::Consensus,
            keypair.public,
            "tcp",
            "127.0.0.1",
            8100 + index as u16,
        ));
    }

    let plan = runtime.prefill_dispatch_plan().unwrap();

    assert_eq!(plan.target.last_epoch, genesis.hash);
    assert_eq!(plan.source, keypairs[0].public);
    assert_eq!(plan.recipient_count(), 10);
    assert_eq!(plan.reachable_count(), 10);
    assert!(plan.is_fully_reachable());
    assert!(!plan.recipients.contains(&keypairs[0].public));
}

#[test]
fn prefill_dispatch_plan_reports_missing_consensus_services() {
    let keypairs = (0..36).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8200 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(nodes.clone());
    let mut config = RuntimeConfig::new(nodes[0].clone());
    config.genesis = Some(genesis);
    let runtime = NodeRuntime::new(config);

    let plan = runtime.prefill_dispatch_plan().unwrap();

    assert_eq!(plan.recipient_count(), 10);
    assert_eq!(plan.reachable_count(), 0);
    assert_eq!(plan.missing_services.len(), 10);
    assert!(!plan.is_fully_reachable());
}

fn runtime_for_node(
    nodes: &[NodeIdentity],
    genesis: &Epoch,
    index: usize,
    trust_mode: TrustMode,
) -> NodeRuntime {
    let mut config = RuntimeConfig::new(nodes[index].clone());
    config.genesis = Some(genesis.clone());
    config.trust_mode = trust_mode;
    NodeRuntime::new(config)
}

fn thirty_six_node_test_cluster() -> (Vec<Keypair>, Vec<NodeIdentity>, Epoch, EpochTarget) {
    let keypairs = (0..36).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                Some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8300 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(nodes.clone());
    let target = EpochTarget {
        group_id: genesis.body.group_id,
        last_epoch: genesis.hash,
        nonce: genesis.body.nonce.new_next(),
    };
    (keypairs, nodes, genesis, target)
}

fn keypair_index(keypairs: &[Keypair], public_key: PubKey) -> usize {
    keypairs
        .iter()
        .position(|keypair| keypair.public == public_key)
        .expect("test keypair should exist")
}

fn prefill_future_contact_and_off_route_indices(
    keypairs: &[Keypair],
    target: &EpochTarget,
) -> (usize, usize) {
    let keys = keypairs
        .iter()
        .map(|keypair| keypair.public)
        .collect::<Vec<_>>();
    let quorums = crate::algorithm::select_quorums(
        keys.clone(),
        &keypairs[0].public,
        target.last_epoch,
        false,
    );
    let recipients = crate::algorithm::select_prefill_recipients(
        keys.clone(),
        &keypairs[0].public,
        target.last_epoch,
        false,
    );
    let first_quorum = quorums
        .first()
        .expect("36-node cluster should have a first quorum");
    let future_contact = recipients
        .iter()
        .copied()
        .find(|recipient| !first_quorum.contains(recipient))
        .expect("36-node cluster should have a future prefill contact");
    let off_route = keys
        .into_iter()
        .find(|key| *key != keypairs[0].public && !recipients.contains(key))
        .expect("36-node cluster should have an off-route node");

    (
        keypair_index(keypairs, future_contact),
        keypair_index(keypairs, off_route),
    )
}

#[test]
fn prefill_dispatch_accepts_future_contact_without_quorum_vote() {
    let (keypairs, nodes, genesis, target) = thirty_six_node_test_cluster();
    let (future_contact, _) = prefill_future_contact_and_off_route_indices(&keypairs, &target);
    let future_contact_runtime =
        runtime_for_node(&nodes, &genesis, future_contact, TrustMode::Verified);
    let normal_dispatch_runtime =
        runtime_for_node(&nodes, &genesis, future_contact, TrustMode::Verified);
    let block = signed_block_for_target(&keypairs[0], &target, b"prefill-block");
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let dispatch = signed_dispatch_for_blocks(&keypairs[0], &target, blocks);

    assert!(matches!(
        normal_dispatch_runtime.receive_message(Msg::Dispatch(dispatch.clone())),
        Err(BlossomError::UnknownSender)
    ));

    let receipt = future_contact_runtime
        .receive_prefill_dispatch(dispatch.clone())
        .unwrap();
    assert_eq!(receipt.kind, "prefill_dispatch");
    let state = future_contact_runtime
        .inner
        .state
        .read()
        .expect("state lock poisoned");
    let prefill = state
        .prefill_dispatches(&target.last_epoch, target.nonce)
        .expect("prefill dispatch should be stored");
    assert!(prefill.contains_key(&keypairs[0].public));
    assert!(
        state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .is_none()
    );
}

#[test]
fn prefill_dispatch_rejects_off_route_recipient() {
    let (keypairs, nodes, genesis, target) = thirty_six_node_test_cluster();
    let (_, off_route) = prefill_future_contact_and_off_route_indices(&keypairs, &target);
    let off_route_runtime = runtime_for_node(&nodes, &genesis, off_route, TrustMode::Verified);
    let block = signed_block_for_target(&keypairs[0], &target, b"prefill-block");
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let dispatch = signed_dispatch_for_blocks(&keypairs[0], &target, blocks);

    assert!(matches!(
        off_route_runtime.receive_prefill_dispatch(dispatch),
        Err(BlossomError::UnknownSender)
    ));
}

#[test]
fn prefill_dispatch_rejects_equivocation_from_same_sender() {
    let (keypairs, nodes, genesis, target) = thirty_six_node_test_cluster();
    let (future_contact, _) = prefill_future_contact_and_off_route_indices(&keypairs, &target);
    let runtime = runtime_for_node(&nodes, &genesis, future_contact, TrustMode::Verified);
    let first_block = signed_block_for_target(&keypairs[0], &target, b"prefill-a");
    let second_block = signed_block_for_target(&keypairs[0], &target, b"prefill-b");
    let mut first_blocks = BTreeMap::new();
    first_blocks.insert(first_block.hash, first_block);
    let mut second_blocks = BTreeMap::new();
    second_blocks.insert(second_block.hash, second_block);
    let first_dispatch = signed_dispatch_for_blocks(&keypairs[0], &target, first_blocks);
    let second_dispatch = signed_dispatch_for_blocks(&keypairs[0], &target, second_blocks);

    runtime.receive_prefill_dispatch(first_dispatch).unwrap();
    assert!(matches!(
        runtime.receive_prefill_dispatch(second_dispatch),
        Err(BlossomError::WireProtocol(_))
    ));
}

#[test]
fn prefill_dispatches_seed_later_round_verification() {
    let (keypairs, nodes, genesis, target) = thirty_six_node_test_cluster();
    let (future_contact, _) = prefill_future_contact_and_off_route_indices(&keypairs, &target);
    let runtime = runtime_for_node(&nodes, &genesis, future_contact, TrustMode::Verified);
    let block = signed_block_for_target(&keypairs[0], &target, b"seed-round-one");
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let dispatch = signed_dispatch_for_blocks(&keypairs[0], &target, blocks);
    runtime.receive_prefill_dispatch(dispatch.clone()).unwrap();

    let verifier = round_signer(&runtime, &keypairs, &target, 1);
    let mut verification_blocks = BTreeMap::new();
    let block_hash = *dispatch.body.blocks.keys().next().unwrap();
    verification_blocks.insert(block_hash, ());
    let verification_body = VerificationBody {
        blocks_hash: verification_blocks.hash(),
        blocks: verification_blocks,
    };
    let verification = Verification {
        header: signed_test_header_for_round(
            verifier,
            &target,
            1,
            MSGKey::Verification,
            &verification_body,
        ),
        body: verification_body,
    };

    let receipt = runtime
        .receive_message(Msg::Verification(verification))
        .unwrap();
    assert_eq!(receipt.kind, "verification");
    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 1)
        .expect("verification should initialize round 1");
    assert!(quorum.verified_blocks.contains_key(&block_hash));
    assert_eq!(quorum.verifications.verifications.len(), 1);
}

#[test]
fn prefill_seed_skips_round_zero() {
    let (keypairs, nodes, genesis, target) = thirty_six_node_test_cluster();
    let (future_contact, _) = prefill_future_contact_and_off_route_indices(&keypairs, &target);
    let runtime = runtime_for_node(&nodes, &genesis, future_contact, TrustMode::Verified);
    let block = signed_block_for_target(&keypairs[0], &target, b"round-zero-not-seeded");
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let dispatch = signed_dispatch_for_blocks(&keypairs[0], &target, blocks);
    let block_hash = *dispatch.body.blocks.keys().next().unwrap();
    runtime.receive_prefill_dispatch(dispatch).unwrap();

    assert_eq!(runtime.seed_prefill_dispatches_for_round(0).unwrap(), 0);
    let seeded = runtime.seed_prefill_dispatches_for_round(1).unwrap();

    assert_eq!(seeded, 1);
    let state = runtime.inner.state.read().expect("state lock poisoned");
    assert!(
        state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .is_none()
    );
    let round_one = state
        .get_quorum(&target.last_epoch, target.nonce, 1)
        .expect("round 1 should be seeded");
    assert!(round_one.verified_blocks.contains_key(&block_hash));
}

#[tokio::test]
async fn broadcast_prefill_dispatch_stores_local_availability() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let block = signed_block_for_target(&keypairs[0], &target, b"local-prefill");
    let block_hash = block.hash;
    runtime.submit_block(block).unwrap();

    let report = runtime.broadcast_prefill_dispatch().await.unwrap();

    assert_eq!(report.dispatch.header.sender, keypairs[0].public);
    assert_eq!(report.plan.recipient_count(), 5);
    assert_eq!(report.broadcast.attempted(), 0);
    let state = runtime.inner.state.read().expect("state lock poisoned");
    let prefill = state
        .prefill_dispatches(&target.last_epoch, target.nonce)
        .expect("local prefill dispatch should be stored");
    assert!(prefill.contains_key(&keypairs[0].public));
    assert!(
        prefill
            .get(&keypairs[0].public)
            .unwrap()
            .blocks
            .contains_key(&block_hash)
    );
}

#[tokio::test]
async fn try_broadcast_prefill_dispatch_retries_unacknowledged_recipients() {
    let (keypairs, nodes, genesis, target) = thirty_six_node_test_cluster();
    let runtime = runtime_for_node(&nodes, &genesis, 0, TrustMode::Verified);
    let block = signed_block_for_target(&keypairs[0], &target, b"driver-prefill");
    let block_hash = block.hash;
    runtime.submit_block(block).unwrap();

    assert_eq!(runtime.quorum_round_count().unwrap(), 2);
    assert!(!runtime.has_local_prefill_dispatch().unwrap());

    let first = runtime
        .try_broadcast_prefill_dispatch()
        .await
        .unwrap()
        .expect("first prefill should be produced");
    assert!(runtime.has_local_prefill_dispatch().unwrap());

    let second = runtime
        .try_broadcast_prefill_dispatch()
        .await
        .unwrap()
        .expect("unacknowledged prefill recipients should remain retryable");
    assert_eq!(
        borsh::to_vec(&first.dispatch).unwrap(),
        borsh::to_vec(&second.dispatch).unwrap()
    );

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let prefill = state
        .prefill_dispatches(&target.last_epoch, target.nonce)
        .expect("local prefill dispatch should be stored");
    assert!(
        prefill
            .get(&keypairs[0].public)
            .unwrap()
            .blocks
            .contains_key(&block_hash)
    );
}
