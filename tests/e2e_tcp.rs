//! End-to-end TCP runtime, wire request, and catch-up tests.

use std::collections::{BTreeMap, BTreeSet};

use blossom::algorithm::select_quorums;
#[cfg(feature = "availability-gossip")]
use blossom::{
    AvailabilityEntry, AvailabilityGossip, AvailabilityGossipBody, FilteredDeliveryPolicy,
    FilteredPayloadFetch, FilteredPayloadFetchBody,
};
use blossom::{
    Block, BlossomBody, Commit, CommitBody, ConsensusDriverConfig, ConsensusGroupId, Dispatch,
    DispatchBody, EchoReDispatch, EchoRequest, EchoResponse, EchoResponseBody, EpochStarted,
    EpochStartedBody, EpochTarget, FanOutStrategy, HashType, Header, Keypair, MSGKey,
    MockBlockService, Msg, NodeAdmission, NodePing, Nonce, OverlayRuntime, Proposal, ProposalBody,
    QuorumSize, Service, ServiceKind, Signature, SimulatedCluster, TcpNode, TcpServiceClient,
    Transaction, TrustMode, Verification, VerificationBody, WireRequest, WireResponse,
    select_prefill_recipients, supermajority_count,
};
use blossom::{DoHash, EncodedFrame, NodeIdentity};
use tokio::sync::mpsc;

static LARGE_TCP_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct ConsensusDriverTasks {
    tasks: Vec<(usize, tokio::task::JoinHandle<()>)>,
    failures: mpsc::UnboundedReceiver<(usize, String)>,
}

impl Drop for ConsensusDriverTasks {
    fn drop(&mut self) {
        for (_, task) in &self.tasks {
            task.abort();
        }
    }
}

impl ConsensusDriverTasks {
    async fn check(&mut self) -> blossom::Result<()> {
        if let Ok((node, error)) = self.failures.try_recv() {
            return Err(blossom::BlossomError::WireProtocol(format!(
                "consensus driver for node {node} stopped: {error}"
            )));
        }
        if let Some(position) = self.tasks.iter().position(|(_, task)| task.is_finished()) {
            let (node, task) = self.tasks.swap_remove(position);
            return match task.await {
                Ok(()) => Err(blossom::BlossomError::WireProtocol(format!(
                    "consensus driver for node {node} stopped unexpectedly"
                ))),
                Err(error) => Err(blossom::BlossomError::WireProtocol(format!(
                    "consensus driver task for node {node} failed: {error}"
                ))),
            };
        }
        Ok(())
    }
}

fn start_consensus_drivers(
    cluster: &SimulatedCluster,
    config: ConsensusDriverConfig,
) -> ConsensusDriverTasks {
    let (failure_tx, failures) = mpsc::unbounded_channel();
    let tasks = cluster
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let driver = TcpNode::with_metrics(node.runtime.clone(), node.metrics.clone());
            let config = config.clone();
            let failure_tx = failure_tx.clone();
            (
                index,
                tokio::spawn(async move {
                    if let Err(error) = driver.run_consensus_driver(config).await {
                        let _ = failure_tx.send((index, error.to_string()));
                    }
                }),
            )
        })
        .collect();
    drop(failure_tx);
    ConsensusDriverTasks { tasks, failures }
}

#[tokio::test]
async fn cluster_exposes_health_state_address_book_and_nonce() {
    let cluster = SimulatedCluster::spawn(3).await.unwrap();

    for index in 0..cluster.len() {
        let node = cluster.node(index);
        match node.request(WireRequest::Health).await.unwrap() {
            WireResponse::Health(health) => {
                assert_eq!(health.status, "ok");
                assert_eq!(health.public_key, node.identity.public_key());
                assert!(health.protocol_hash_compatible());
            }
            response => panic!("expected health, got {}", response.kind()),
        }

        match node
            .request(WireRequest::Ping(NodePing::with_payload(
                index as u64,
                b"direct-ping",
            )))
            .await
            .unwrap()
        {
            WireResponse::Pong(pong) => {
                assert_eq!(pong.group_id, ConsensusGroupId::root());
                assert_eq!(pong.public_key, node.identity.public_key());
                assert!(pong.protocol_hash_compatible());
                assert_eq!(pong.nonce, index as u64);
                assert_eq!(pong.payload, b"direct-ping");
            }
            response => panic!("expected pong, got {}", response.kind()),
        }

        match node.request(WireRequest::State).await.unwrap() {
            WireResponse::State(state) => {
                assert_eq!(state.node.public_key(), node.identity.public_key());
                assert!(!state.node.has_signing_material());
                assert_eq!(state.last_epoch_nonce, Nonce::new(0));
                assert_eq!(state.next_nonce, Nonce::new(1));
                assert_eq!(state.pending_blocks, 0);
            }
            response => panic!("expected state, got {}", response.kind()),
        }

        match node.request(WireRequest::EpochChain).await.unwrap() {
            WireResponse::EpochChain(chain) => {
                assert_eq!(chain.epochchain.len(), 1);
                assert_eq!(chain.epochchain[0].body.nonce, Nonce::new(0));
            }
            response => panic!("expected epoch chain, got {}", response.kind()),
        }

        match node
            .request(WireRequest::CertifiedEpochSuffix {
                anchor_hash: cluster.node(0).runtime.epochchain().epochchain[0].hash,
                anchor_nonce: Nonce::new(0),
                max_epochs: 1,
            })
            .await
            .unwrap()
        {
            WireResponse::CertifiedEpochSuffix(suffix) => {
                assert!(suffix.epochs.is_empty());
                assert_eq!(suffix.anchor_nonce, Nonce::new(0));
            }
            response => panic!("expected certified epoch suffix, got {}", response.kind()),
        }

        match node.request(WireRequest::AddressBook).await.unwrap() {
            WireResponse::AddressBook(services) => {
                assert_eq!(services.len(), 1);
                assert_eq!(services[0].kind, ServiceKind::Consensus);
                assert_eq!(services[0].public_key, node.identity.public_key());
            }
            response => panic!("expected address book, got {}", response.kind()),
        }

        assert_eq!(
            cluster.next_target(index).await.unwrap().nonce,
            Nonce::new(1)
        );

        let services = TcpServiceClient::new()
            .address_book(&node.service)
            .await
            .unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].public_key, node.identity.public_key());
    }

    let mut connection = cluster.connect(0).await.unwrap();
    match connection.request(&WireRequest::Health).await.unwrap() {
        WireResponse::Health(health) => {
            assert_eq!(health.status, "ok");
            assert_eq!(health.public_key, cluster.node(0).identity.public_key());
            assert!(health.protocol_hash_compatible());
        }
        response => panic!(
            "expected health over persistent connection, got {}",
            response.kind()
        ),
    }
    match connection.request(&WireRequest::NextNonce).await.unwrap() {
        WireResponse::NextNonce(target) => assert_eq!(target.nonce, Nonce::new(1)),
        response => panic!(
            "expected next nonce over persistent connection, got {}",
            response.kind()
        ),
    }
}

#[tokio::test]
async fn overlay_runtime_broadcasts_over_topology() {
    let cluster = SimulatedCluster::spawn(6).await.unwrap();
    let overlay = OverlayRuntime::new(cluster.node(0).identity.clone());
    for node in cluster.nodes() {
        overlay.register_service(node.service.clone());
    }

    let report = overlay
        .broadcast(
            Msg::Ok,
            FanOutStrategy::unshuffled_topology(HashType::default()),
        )
        .await
        .unwrap();

    assert_eq!(report.attempted(), 5);
    assert_eq!(report.accepted(), 5);
    assert_eq!(report.failed(), 0);
}

#[tokio::test]
async fn address_book_registration_announces_nonce_to_block_service() {
    let cluster = SimulatedCluster::spawn(1).await.unwrap();
    let block_service = MockBlockService::spawn().await.unwrap();

    match cluster
        .request(
            0,
            WireRequest::RegisterService(
                block_service
                    .signed_record(
                        cluster.node(0).runtime.group_id(),
                        &cluster.node(0).keypair,
                        1,
                    )
                    .unwrap()
                    .into(),
            ),
        )
        .await
        .unwrap()
    {
        WireResponse::AddressBookUpdated(update) => {
            assert_eq!(update.service.kind, ServiceKind::Block);
            assert_eq!(update.previous, None);
            assert_eq!(update.nonce_announced, Some(Nonce::new(1)));
        }
        response => panic!("expected address book update, got {}", response.kind()),
    }

    assert_eq!(block_service.received_nonces(), vec![Nonce::new(1)]);

    match cluster.request(0, WireRequest::AddressBook).await.unwrap() {
        WireResponse::AddressBook(services) => {
            assert!(services.iter().any(|service| {
                service.kind == ServiceKind::Block
                    && service.public_key == cluster.node(0).keypair.public
            }));
        }
        response => panic!("expected address book, got {}", response.kind()),
    }
}

#[tokio::test]
async fn consensus_service_registration_stages_public_node_admission() {
    let cluster = SimulatedCluster::spawn(1).await.unwrap();
    let joiner = Keypair::generate();
    let target = cluster.next_target(0).await.unwrap();
    let service = Service::new(
        ServiceKind::Consensus,
        joiner.public,
        "tcp",
        "127.0.0.1",
        9191,
    );
    let admission = NodeAdmission::signed_for_consensus_service(
        service.clone(),
        target.last_epoch,
        target.nonce,
        &joiner.signer(),
    )
    .unwrap();

    match cluster
        .request(0, WireRequest::RegisterService(admission.into()))
        .await
        .unwrap()
    {
        WireResponse::AddressBookUpdated(update) => {
            assert_eq!(update.service, service);
            assert_eq!(
                update.admitted_node.map(|node| node.public_key()),
                Some(joiner.public)
            );
            assert_eq!(update.nonce_announced, None);
        }
        response => panic!("expected address book update, got {}", response.kind()),
    }

    match cluster.request(0, WireRequest::AddressBook).await.unwrap() {
        WireResponse::AddressBook(services) => {
            assert!(services.iter().any(|registered| registered == &service));
        }
        response => panic!("expected address book, got {}", response.kind()),
    }
}

#[tokio::test]
async fn block_submission_duplicate_rejection_dispatch_and_late_admission_are_end_to_end() {
    let cluster = SimulatedCluster::spawn(1).await.unwrap();
    let block = cluster
        .signed_block_for(0, 0, [Transaction::new("tx-1")])
        .await
        .unwrap();

    match cluster
        .request(0, WireRequest::SubmitBlock(block.clone()))
        .await
        .unwrap()
    {
        WireResponse::BlockAccepted(accepted) => {
            assert_eq!(accepted.hash, block.hash);
            assert_eq!(accepted.nonce, Nonce::new(1));
            assert_eq!(accepted.application_state_bytes, 0);
        }
        response => panic!("expected accepted block, got {}", response.kind()),
    }

    match cluster
        .request(0, WireRequest::SubmitBlock(block.clone()))
        .await
        .unwrap()
    {
        WireResponse::Error(message) => assert!(message.contains("duplicate")),
        response => panic!("expected duplicate block error, got {}", response.kind()),
    }

    let target = cluster.next_target(0).await.unwrap();
    let wrong_nonce = blossom::signed_block(
        EpochTarget {
            group_id: target.group_id,
            last_epoch: target.last_epoch,
            nonce: target.nonce.new_next(),
        },
        cluster.node(0).keypair.secret.clone(),
        [Transaction::new("wrong-nonce")],
    );
    match cluster
        .request(0, WireRequest::SubmitBlock(wrong_nonce))
        .await
        .unwrap()
    {
        WireResponse::Error(message) => assert!(message.contains("invalid block nonce")),
        response => panic!("expected invalid nonce error, got {}", response.kind()),
    }

    let dispatch = expect_dispatch(cluster.request(0, WireRequest::Dispatch { round: 0 }).await);
    assert_eq!(dispatch.body.blocks.len(), 1);
    assert_eq!(dispatch.header.nonce, Nonce::new(1));
    let dispatched_tx = &dispatch.body.blocks.values().next().unwrap().body.txs[0];
    assert_eq!(dispatched_tx.payload(), b"tx-1");

    let second = cluster
        .signed_block_for(0, 0, [Transaction::new("tx-2")])
        .await
        .unwrap();
    match cluster
        .request(0, WireRequest::SendBlock(second))
        .await
        .unwrap()
    {
        WireResponse::Error(message) => assert!(message.contains("duplicate")),
        response => panic!(
            "expected late send block rejection, got {}",
            response.kind()
        ),
    }
}

#[tokio::test]
async fn prefill_dispatch_is_accepted_over_tcp_by_future_contact() {
    let _large_tcp_test_guard = LARGE_TCP_TEST_LOCK.lock().await;
    let cluster = SimulatedCluster::spawn(36).await.unwrap();
    let keys = cluster
        .nodes()
        .iter()
        .map(|node| node.identity.public_key())
        .collect::<Vec<_>>();
    let target = cluster.next_target(0).await.unwrap();
    let quorums = select_quorums(keys.clone(), &keys[0], target.last_epoch, false);
    let recipients = select_prefill_recipients(keys.clone(), &keys[0], target.last_epoch, false);
    let first_quorum = quorums.first().expect("36-node cluster has round 0");
    let future_contact = recipients
        .iter()
        .copied()
        .find(|recipient| !first_quorum.contains(recipient))
        .expect("36-node cluster has a future prefill contact");
    let future_contact_index = keys
        .iter()
        .position(|key| *key == future_contact)
        .expect("recipient should be in cluster");

    let block = cluster
        .signed_block_for(0, 0, [Transaction::new("prefill-tx")])
        .await
        .unwrap();
    match cluster
        .request(0, WireRequest::SubmitBlock(block))
        .await
        .unwrap()
    {
        WireResponse::BlockAccepted(_) => {}
        response => panic!("expected block accepted, got {}", response.kind()),
    }
    let dispatch = expect_dispatch(cluster.request(0, WireRequest::Dispatch { round: 0 }).await);

    match cluster
        .request(future_contact_index, WireRequest::PrefillDispatch(dispatch))
        .await
        .unwrap()
    {
        WireResponse::MessageReceipt(receipt) => {
            assert_eq!(receipt.kind, "prefill_dispatch");
            assert!(receipt.accepted);
        }
        response => panic!("expected prefill dispatch receipt, got {}", response.kind()),
    }
}

#[tokio::test]
async fn all_validators_form_blocks_for_the_same_epoch_target() {
    let cluster = SimulatedCluster::spawn(6).await.unwrap();
    let first_target = cluster.next_target(0).await.unwrap();
    let mut validators = BTreeSet::new();
    let mut block_hashes = BTreeSet::new();

    for index in 0..cluster.len() {
        let target = cluster.next_target(index).await.unwrap();
        assert_eq!(target.last_epoch, first_target.last_epoch);
        assert_eq!(target.nonce, first_target.nonce);

        let block = cluster
            .signed_block_for(
                index,
                index,
                [Transaction::new(format!("validator-{index}"))],
            )
            .await
            .unwrap();
        match cluster
            .request(index, WireRequest::SubmitBlock(block.clone()))
            .await
            .unwrap()
        {
            WireResponse::BlockAccepted(accepted) => {
                assert_eq!(accepted.hash, block.hash);
                assert_eq!(accepted.nonce, first_target.nonce);
            }
            response => panic!("expected accepted block, got {}", response.kind()),
        }

        let dispatch = expect_dispatch(
            cluster
                .request(index, WireRequest::Dispatch { round: 0 })
                .await,
        );
        assert_eq!(dispatch.header.last_epoch, first_target.last_epoch);
        assert_eq!(dispatch.header.nonce, first_target.nonce);
        assert_eq!(dispatch.body.blocks.len(), 1);
        let dispatched_block = dispatch.body.blocks.values().next().unwrap();
        assert_eq!(dispatched_block.body.last_epoch, first_target.last_epoch);
        assert_eq!(dispatched_block.body.nonce, first_target.nonce);
        assert_eq!(
            dispatched_block.body.validator,
            cluster.node(index).keypair.public
        );
        validators.insert(dispatched_block.body.validator);
        block_hashes.insert(dispatched_block.hash);
    }

    assert_eq!(validators.len(), cluster.len());
    assert_eq!(block_hashes.len(), cluster.len());
}

#[tokio::test]
async fn autonomous_tcp_driver_advances_all_nodes_through_epoch() {
    // Avoid starving this bounded liveness check while the 24- and 36-node
    // native TCP campaigns saturate the same test process.
    let _large_tcp_test_guard = LARGE_TCP_TEST_LOCK.lock().await;
    let cluster = SimulatedCluster::spawn_manual_with_trust_mode_and_quorum(
        6,
        TrustMode::Verified,
        QuorumSize::DEFAULT,
    )
    .await
    .unwrap();
    let first_target = cluster.next_target(0).await.unwrap();

    for index in 0..cluster.len() {
        let block = cluster
            .signed_block_for(
                index,
                index,
                [Transaction::new(format!("autonomous-{index}"))],
            )
            .await
            .unwrap();
        match cluster
            .request(index, WireRequest::SubmitBlock(block))
            .await
            .unwrap()
        {
            WireResponse::BlockAccepted(accepted) => {
                assert_eq!(accepted.nonce, first_target.nonce);
            }
            response => panic!("expected block accepted, got {}", response.kind()),
        }
    }

    let mut drivers = start_consensus_drivers(
        &cluster,
        ConsensusDriverConfig {
            interval: std::time::Duration::from_millis(100),
            ..ConsensusDriverConfig::default()
        },
    );
    let timeout_secs = if cfg!(debug_assertions) { 30 } else { 8 };
    let (final_hash, block_count) =
        wait_for_same_finalized_epoch(&cluster, first_target.nonce, timeout_secs, &mut drivers)
            .await
            .unwrap();
    assert_ne!(final_hash, first_target.last_epoch);
    assert_eq!(block_count, 6);
}

#[tokio::test]
async fn autonomous_tcp_driver_finalizes_small_committees() {
    let _large_tcp_test_guard = LARGE_TCP_TEST_LOCK.lock().await;

    for committee_size in [3, 5] {
        let cluster = SimulatedCluster::spawn_manual_with_trust_mode_and_quorum(
            committee_size,
            TrustMode::Verified,
            QuorumSize::DEFAULT,
        )
        .await
        .unwrap();
        let first_target = cluster.next_target(0).await.unwrap();

        for index in 0..cluster.len() {
            let block = cluster
                .signed_block_for(
                    index,
                    index,
                    [Transaction::new(format!(
                        "small-committee-{committee_size}-{index}"
                    ))],
                )
                .await
                .unwrap();
            match cluster
                .request(index, WireRequest::SubmitBlock(block))
                .await
                .unwrap()
            {
                WireResponse::BlockAccepted(accepted) => {
                    assert_eq!(accepted.nonce, first_target.nonce);
                }
                response => panic!("expected block accepted, got {}", response.kind()),
            }
        }

        let mut drivers = start_consensus_drivers(
            &cluster,
            ConsensusDriverConfig {
                interval: std::time::Duration::from_millis(25),
                ..ConsensusDriverConfig::default()
            },
        );
        let timeout_secs = if cfg!(debug_assertions) { 30 } else { 8 };
        let (final_hash, block_count) =
            wait_for_same_finalized_epoch(&cluster, first_target.nonce, timeout_secs, &mut drivers)
                .await
                .unwrap();
        assert_ne!(final_hash, first_target.last_epoch);
        assert_eq!(block_count, committee_size);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn autonomous_tcp_driver_finalizes_36_node_v2_two_round_epoch() {
    let _large_tcp_test_guard = LARGE_TCP_TEST_LOCK.lock().await;
    let cluster = SimulatedCluster::spawn_manual_with_trust_mode_and_quorum(
        36,
        TrustMode::Verified,
        QuorumSize::DEFAULT,
    )
    .await
    .unwrap();
    let first_target = cluster.next_target(0).await.unwrap();

    for index in 0..cluster.len() {
        let block = cluster
            .signed_block_for(
                index,
                index,
                [Transaction::new(format!("v2-two-round-{index}"))],
            )
            .await
            .unwrap();
        match cluster
            .request(index, WireRequest::SubmitBlock(block))
            .await
            .unwrap()
        {
            WireResponse::BlockAccepted(accepted) => {
                assert_eq!(accepted.nonce, first_target.nonce);
            }
            response => panic!("expected block accepted, got {}", response.kind()),
        }
    }

    let mut drivers = start_consensus_drivers(
        &cluster,
        ConsensusDriverConfig {
            interval: std::time::Duration::from_millis(50),
            event_driven: false,
            max_round: 1,
            drive_prefill: true,
            drive_dispatch: true,
            require_local_pending_block: false,
            continue_after_error: true,
        },
    );
    let timeout_secs = if cfg!(debug_assertions) { 240 } else { 8 };
    let (_final_hash, block_count) =
        wait_for_same_finalized_epoch(&cluster, first_target.nonce, timeout_secs, &mut drivers)
            .await
            .unwrap();
    assert_eq!(block_count, 36);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn autonomous_tcp_driver_finalizes_24_node_non_power_topology_epoch() {
    let _large_tcp_test_guard = LARGE_TCP_TEST_LOCK.lock().await;
    let cluster = SimulatedCluster::spawn_manual_with_trust_mode_and_quorum(
        24,
        TrustMode::Verified,
        QuorumSize::DEFAULT,
    )
    .await
    .unwrap();
    let first_target = cluster.next_target(0).await.unwrap();

    for index in 0..cluster.len() {
        let block = cluster
            .signed_block_for(
                index,
                index,
                [Transaction::new(format!("non-power-topology-{index}"))],
            )
            .await
            .unwrap();
        match cluster
            .request(index, WireRequest::SubmitBlock(block))
            .await
            .unwrap()
        {
            WireResponse::BlockAccepted(accepted) => {
                assert_eq!(accepted.nonce, first_target.nonce);
            }
            response => panic!("expected block accepted, got {}", response.kind()),
        }
    }

    let mut drivers = start_consensus_drivers(
        &cluster,
        ConsensusDriverConfig {
            interval: std::time::Duration::from_millis(20),
            event_driven: false,
            max_round: 1,
            drive_prefill: false,
            drive_dispatch: true,
            require_local_pending_block: false,
            continue_after_error: true,
        },
    );
    let timeout_secs = if cfg!(debug_assertions) { 120 } else { 8 };
    let (_final_hash, block_count) =
        wait_for_same_finalized_epoch(&cluster, first_target.nonce, timeout_secs, &mut drivers)
            .await
            .unwrap();
    assert_eq!(block_count, 24);
}

#[tokio::test]
async fn trusted_cluster_accepts_unsigned_block_and_dispatch() {
    let cluster = SimulatedCluster::spawn_with_trust_mode(6, TrustMode::Trusted)
        .await
        .unwrap();
    let target = cluster.next_target(0).await.unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block
        .set_application_state(b"v1:cache-pressure=72")
        .unwrap();
    block.body.txs.push(Transaction::new("trusted-tx"));
    block.seal_unsigned(cluster.node(0).keypair.public);

    match cluster
        .request(0, WireRequest::SubmitBlock(block.clone()))
        .await
        .unwrap()
    {
        WireResponse::BlockAccepted(accepted) => {
            assert_eq!(accepted.hash, block.hash);
            assert_eq!(accepted.nonce, target.nonce);
            assert_eq!(
                accepted.application_state_bytes,
                b"v1:cache-pressure=72".len()
            );
        }
        response => panic!("expected accepted block, got {}", response.kind()),
    }

    let dispatch = expect_dispatch(cluster.request(0, WireRequest::Dispatch { round: 0 }).await);
    assert_eq!(dispatch.header.signature, Signature::default());
    let dispatched_block = dispatch.body.blocks.values().next().unwrap();
    assert_eq!(dispatched_block.signature, Signature::default());
    assert_eq!(
        dispatched_block.application_state(),
        b"v1:cache-pressure=72"
    );
    assert!(dispatched_block.verify_unsigned_integrity().is_ok());
    assert!(dispatched_block.verify_integrity().is_err());

    let hot_dispatch_frame = EncodedFrame::encode_hot_wire_request(&WireRequest::Message(
        Msg::Dispatch(dispatch.clone()),
    ))
    .unwrap()
    .unwrap();
    expect_receipt(
        cluster.request_frame(1, &hot_dispatch_frame).await,
        "dispatch",
    );
    expect_receipt(
        cluster
            .request(2, WireRequest::Message(Msg::Dispatch(dispatch)))
            .await,
        "dispatch",
    );
}

#[tokio::test]
async fn service_client_exercises_mock_block_service_wire_requests() {
    let block_service = MockBlockService::spawn().await.unwrap();
    let client = TcpServiceClient::new();
    let target = EpochTarget {
        group_id: ConsensusGroupId::root(),
        last_epoch: HashType::default(),
        nonce: Nonce::new(7),
    };
    let block = block_service.signed_block(target, [Transaction::new("mock-service-tx")]);
    block_service.insert_block(block.clone());

    client
        .send_nonce(&block_service.service, Nonce::new(7))
        .await
        .unwrap();
    client
        .block_nonce(&block_service.service, Nonce::new(7))
        .await
        .unwrap();
    let pong = client
        .ping(
            &block_service.service,
            NodePing::with_payload(77, b"block-service"),
        )
        .await
        .unwrap();
    assert_eq!(pong.group_id, ConsensusGroupId::root());
    assert_eq!(pong.nonce, 77);
    assert_eq!(pong.payload, b"block-service");
    assert_eq!(
        client
            .get_block(&block_service.service, Nonce::new(7))
            .await
            .unwrap()
            .hash,
        block.hash
    );
    client
        .send_block(&block_service.service, &block)
        .await
        .unwrap();

    assert_eq!(block_service.received_nonces(), vec![Nonce::new(7)]);
    assert_eq!(block_service.blocked_nonces(), vec![Nonce::new(7)]);
    assert_eq!(block_service.received_blocks()[0].hash, block.hash);
}

#[cfg(feature = "availability-gossip")]
#[tokio::test]
async fn filtered_payload_availability_gossip_and_fetch_are_end_to_end() {
    let cluster = SimulatedCluster::spawn(3).await.unwrap();
    let holder = cluster.node(0);
    let target = cluster.node(1);
    let outsider = cluster.node(2);
    let payload = b"stable-kvcache-value".to_vec();
    let tx = Transaction::filtered_full(
        HashType::hash(b"stable-cache-key"),
        1,
        vec![target.identity.public_key()],
        payload.clone(),
        FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    let slot = tx.filtered_slot().unwrap().clone();
    let entry = AvailabilityEntry::new(slot.clone()).unwrap();
    let block = cluster.signed_block_for(0, 0, [tx]).await.unwrap();

    match cluster
        .request(0, WireRequest::SubmitBlock(block))
        .await
        .unwrap()
    {
        WireResponse::BlockAccepted(accepted) => {
            assert_eq!(accepted.group_id, ConsensusGroupId::root());
        }
        response => panic!("expected block accepted, got {}", response.kind()),
    }

    let gossip = AvailabilityGossip::signed(
        AvailabilityGossipBody {
            scope: ConsensusGroupId::root(),
            holder: holder.identity.public_key(),
            entries: vec![entry.clone()],
        },
        &holder.keypair.signer(),
    )
    .unwrap();
    match cluster
        .request(1, WireRequest::AvailabilityGossip(gossip))
        .await
        .unwrap()
    {
        WireResponse::AvailabilityReceipt(receipt) => {
            assert_eq!(receipt.entries_accepted, 1);
            assert_eq!(receipt.holder, holder.identity.public_key());
        }
        response => panic!("expected availability receipt, got {}", response.kind()),
    }

    let fetch = FilteredPayloadFetch::signed(
        FilteredPayloadFetchBody {
            scope: ConsensusGroupId::root(),
            requester: target.identity.public_key(),
            slot_hash: entry.slot_hash,
            payload_commitment: slot.payload_commitment,
        },
        &target.keypair.signer(),
    );
    let delivery = match cluster
        .request(0, WireRequest::GetFilteredPayload(fetch))
        .await
        .unwrap()
    {
        WireResponse::FilteredPayload(delivery) => {
            assert_eq!(delivery.body.payload, payload);
            delivery
        }
        response => panic!("expected filtered payload, got {}", response.kind()),
    };

    match cluster
        .request(1, WireRequest::StoreFilteredPayload(delivery))
        .await
        .unwrap()
    {
        WireResponse::AvailabilityReceipt(receipt) => {
            assert_eq!(receipt.entries_accepted, 1);
            assert_eq!(receipt.holder, holder.identity.public_key());
        }
        response => panic!("expected availability receipt, got {}", response.kind()),
    }

    let outsider_fetch = FilteredPayloadFetch::signed(
        FilteredPayloadFetchBody {
            scope: ConsensusGroupId::root(),
            requester: outsider.identity.public_key(),
            slot_hash: entry.slot_hash,
            payload_commitment: slot.payload_commitment,
        },
        &outsider.keypair.signer(),
    );
    match cluster
        .request(0, WireRequest::GetFilteredPayload(outsider_fetch))
        .await
        .unwrap()
    {
        WireResponse::Error(message) => assert!(message.contains("not authorized")),
        response => panic!("expected authorization error, got {}", response.kind()),
    }
}

#[tokio::test]
async fn protocol_message_variants_are_accepted_over_tcp() {
    let cluster = SimulatedCluster::spawn(6).await.unwrap();
    let block = cluster
        .signed_block_for(0, 0, [Transaction::new("dispatch-tx")])
        .await
        .unwrap();
    assert!(matches!(
        cluster
            .request(0, WireRequest::SubmitBlock(block))
            .await
            .unwrap(),
        WireResponse::BlockAccepted(_)
    ));

    let dispatch = expect_dispatch(cluster.request(0, WireRequest::Dispatch { round: 0 }).await);
    expect_receipt(
        cluster
            .request(1, WireRequest::Message(Msg::Dispatch(dispatch.clone())))
            .await,
        "dispatch",
    );
    let hot_dispatch_frame = EncodedFrame::encode_hot_wire_request(&WireRequest::Message(
        Msg::Dispatch(dispatch.clone()),
    ))
    .unwrap()
    .unwrap();
    expect_receipt(
        cluster.request_frame(2, &hot_dispatch_frame).await,
        "dispatch",
    );
    expect_receipt(
        cluster.request_frame(2, &hot_dispatch_frame).await,
        "dispatch_replay",
    );

    let sender = &cluster.node(0).identity;
    let blocks = dispatch
        .body
        .blocks
        .keys()
        .map(|hash| (*hash, ()))
        .collect::<BTreeMap<_, _>>();
    let blocks_hash = blocks.hash();

    let echo_body = EchoResponseBody {
        sender: sender.public_key(),
        blocks_hash: dispatch.body.blocks_hash,
        signature_tree_hash: dispatch.body.signature_tree_hash,
    };
    let echo = EchoResponse {
        header: signed_header(sender, &dispatch, MSGKey::EchoResponse, &echo_body),
        body: echo_body,
    };
    expect_receipt(
        cluster
            .request(1, WireRequest::Message(Msg::EchoResponse(echo)))
            .await,
        "echo_response",
    );

    let verification_body = VerificationBody {
        blocks_hash,
        blocks: blocks.clone(),
    };
    let verification = Verification {
        header: signed_header(sender, &dispatch, MSGKey::Verification, &verification_body),
        body: verification_body.clone(),
    };
    expect_receipt(
        cluster
            .request(
                1,
                WireRequest::Message(Msg::Verification(verification.clone())),
            )
            .await,
        "verification",
    );

    let proposal_body = ProposalBody {
        consensus: true,
        approved_blocks: Some(blocks.clone()),
        approved_hash: Some(blocks_hash),
        verif: Some(verification_proof_for_indices(
            &cluster,
            &dispatch,
            &blocks,
            &[0, 1, 2, 3],
        )),
        signature_tree: Some(blocks.clone()),
        signature_tree_hash: Some(blocks.hash()),
    };
    for index in [0usize, 2, 3, 4] {
        let proposal_sender = &cluster.node(index).identity;
        let proposal = Proposal {
            header: signed_header(proposal_sender, &dispatch, MSGKey::Proposal, &proposal_body),
            body: proposal_body.clone(),
        };
        expect_receipt(
            cluster
                .request(1, WireRequest::Message(Msg::Proposal(proposal)))
                .await,
            "proposal",
        );
    }

    let started_body = EpochStartedBody {};
    let started = EpochStarted {
        header: signed_header(sender, &dispatch, MSGKey::EpochStarted, &started_body),
        body: started_body,
    };
    expect_receipt(
        cluster
            .request(1, WireRequest::Message(Msg::EpochStarted(started)))
            .await,
        "epoch_started",
    );

    let echo_request = EchoRequest {
        header: signed_header(sender, &dispatch, MSGKey::EchoRequest, &blocks),
        requested_blocks: blocks.clone(),
    };
    match cluster
        .request(1, WireRequest::Message(Msg::EchoRequest(echo_request)))
        .await
        .unwrap()
    {
        WireResponse::EchoReDispatch(Some(redispatch)) => {
            assert_eq!(
                redispatch.header.sender,
                cluster.node(1).identity.public_key()
            );
            assert_eq!(redispatch.redispatched_blocks.len(), blocks.len());
        }
        response => panic!("expected echo redispatch response, got {}", response.kind()),
    }

    let echo_redispatch = EchoReDispatch {
        header: signed_header(
            sender,
            &dispatch,
            MSGKey::EchoReDispatch,
            &dispatch.body.blocks,
        ),
        redispatched_blocks: dispatch.body.blocks.clone(),
    };
    expect_receipt(
        cluster
            .request(
                1,
                WireRequest::Message(Msg::EchoReDispatch(echo_redispatch)),
            )
            .await,
        "echo_redispatch",
    );

    let prepared = cluster
        .node(1)
        .runtime
        .try_produce_commit(0)
        .unwrap()
        .unwrap();
    let epoch_hash = prepared.body.epoch_hash.unwrap();
    let commit_body = CommitBody {
        consensus: true,
        signature_tree_insert: None,
        epoch_hash: Some(epoch_hash),
        epoch_signature: Some(cluster.node(0).keypair.signer().sign(epoch_hash.as_ref())),
    };
    let commit = Commit {
        header: signed_header(sender, &dispatch, MSGKey::Commit, &commit_body),
        body: commit_body,
    };
    expect_receipt(
        cluster
            .request(1, WireRequest::Message(Msg::Commit(commit)))
            .await,
        "commit",
    );

    expect_receipt(
        cluster.request(1, WireRequest::Message(Msg::Ok)).await,
        "ok",
    );
    expect_receipt(
        cluster.request(1, WireRequest::Message(Msg::Fail)).await,
        "fail",
    );
}

#[tokio::test]
async fn tcp_consensus_messages_reject_wrong_round_members() {
    let cluster = SimulatedCluster::spawn(6).await.unwrap();
    let dispatch = local_dispatch(&cluster).await;
    let sender = &cluster.node(0).identity;

    for (label, message) in consensus_messages_for_round(sender, &dispatch, 1) {
        expect_error_contains(
            cluster.request(1, WireRequest::Message(message)).await,
            "unknown sender",
            label,
        );
    }
}

#[tokio::test]
async fn tcp_consensus_messages_reject_non_members() {
    let cluster = SimulatedCluster::spawn(6).await.unwrap();
    let dispatch = local_dispatch(&cluster).await;
    let unknown_keypair = Keypair::generate();
    let unknown = NodeIdentity::new(
        unknown_keypair.public,
        Some(unknown_keypair.secret),
        "tcp",
        "127.0.0.1",
        6553,
        false,
    );

    for (label, message) in consensus_messages_for_round(&unknown, &dispatch, 0) {
        expect_error_contains(
            cluster.request(1, WireRequest::Message(message)).await,
            "unknown sender",
            label,
        );
    }
}

async fn local_dispatch(cluster: &SimulatedCluster) -> Dispatch {
    let block = cluster
        .signed_block_for(0, 0, [Transaction::new("admission-gate")])
        .await
        .unwrap();
    assert!(matches!(
        cluster
            .request(0, WireRequest::SubmitBlock(block))
            .await
            .unwrap(),
        WireResponse::BlockAccepted(_)
    ));
    expect_dispatch(cluster.request(0, WireRequest::Dispatch { round: 0 }).await)
}

fn expect_dispatch(response: blossom::Result<WireResponse>) -> Dispatch {
    match response.unwrap() {
        WireResponse::Dispatch(dispatch) => dispatch,
        response => panic!("expected dispatch, got {}", response.kind()),
    }
}

fn expect_receipt(response: blossom::Result<WireResponse>, kind: &str) {
    match response.unwrap() {
        WireResponse::MessageReceipt(receipt) => {
            assert_eq!(receipt.kind, kind);
            assert!(receipt.accepted);
        }
        response => panic!("expected {kind} receipt, got {}", response.kind()),
    }
}

fn expect_error_contains(response: blossom::Result<WireResponse>, expected: &str, label: &str) {
    match response.unwrap() {
        WireResponse::Error(message) => assert!(
            message.contains(expected),
            "{label} error did not contain {expected:?}: {message}"
        ),
        response => panic!(
            "expected {label} error containing {expected:?}, got {}",
            response.kind()
        ),
    }
}

fn consensus_messages_for_round(
    sender: &NodeIdentity,
    dispatch: &Dispatch,
    round: u8,
) -> Vec<(&'static str, Msg)> {
    let dispatch_body = DispatchBody::default();
    let echo_body = EchoResponseBody::default();
    let verification_body = VerificationBody::default();
    let proposal_body = ProposalBody::default();
    let commit_body = CommitBody::default();
    let started_body = EpochStartedBody {};
    let requested_blocks = BTreeMap::new();
    let redispatched_blocks = BTreeMap::new();

    vec![
        (
            "dispatch",
            Msg::Dispatch(Dispatch {
                header: signed_header_for_round(
                    sender,
                    dispatch,
                    round,
                    MSGKey::Dispatch,
                    &dispatch_body,
                ),
                body: dispatch_body,
            }),
        ),
        (
            "echo_response",
            Msg::EchoResponse(EchoResponse {
                header: signed_header_for_round(
                    sender,
                    dispatch,
                    round,
                    MSGKey::EchoResponse,
                    &echo_body,
                ),
                body: echo_body,
            }),
        ),
        (
            "verification",
            Msg::Verification(Verification {
                header: signed_header_for_round(
                    sender,
                    dispatch,
                    round,
                    MSGKey::Verification,
                    &verification_body,
                ),
                body: verification_body,
            }),
        ),
        (
            "proposal",
            Msg::Proposal(Proposal {
                header: signed_header_for_round(
                    sender,
                    dispatch,
                    round,
                    MSGKey::Proposal,
                    &proposal_body,
                ),
                body: proposal_body,
            }),
        ),
        (
            "commit",
            Msg::Commit(Commit {
                header: signed_header_for_round(
                    sender,
                    dispatch,
                    round,
                    MSGKey::Commit,
                    &commit_body,
                ),
                body: commit_body,
            }),
        ),
        (
            "epoch_started",
            Msg::EpochStarted(EpochStarted {
                header: signed_header_for_round(
                    sender,
                    dispatch,
                    round,
                    MSGKey::EpochStarted,
                    &started_body,
                ),
                body: started_body,
            }),
        ),
        (
            "echo_request",
            Msg::EchoRequest(EchoRequest {
                header: signed_header_for_round(
                    sender,
                    dispatch,
                    round,
                    MSGKey::EchoRequest,
                    &requested_blocks,
                ),
                requested_blocks,
            }),
        ),
        (
            "echo_redispatch",
            Msg::EchoReDispatch(EchoReDispatch {
                header: signed_header_for_round(
                    sender,
                    dispatch,
                    round,
                    MSGKey::EchoReDispatch,
                    &redispatched_blocks,
                ),
                redispatched_blocks,
            }),
        ),
    ]
}

async fn wait_for_same_finalized_epoch(
    cluster: &SimulatedCluster,
    nonce: Nonce,
    timeout_secs: u64,
    drivers: &mut ConsensusDriverTasks,
) -> blossom::Result<(HashType, usize)> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        drivers.check().await?;
        let mut final_hashes = BTreeSet::new();
        let mut block_counts = BTreeSet::new();
        let mut finalized_nodes = 0usize;
        for index in 0..cluster.len() {
            match cluster.request(index, WireRequest::EpochChain).await? {
                WireResponse::EpochChain(chain) => {
                    if let Some(position) = chain
                        .epochchain
                        .iter()
                        .position(|epoch| epoch.body.nonce == nonce)
                    {
                        let epoch = &chain.epochchain[position];
                        let previous = position
                            .checked_sub(1)
                            .and_then(|position| chain.epochchain.get(position))
                            .ok_or_else(|| {
                                blossom::BlossomError::WireProtocol(
                                    "finalized epoch is missing its predecessor".to_string(),
                                )
                            })?;
                        epoch.verify_certificate(previous)?;
                        finalized_nodes += 1;
                        final_hashes.insert(epoch.hash);
                        block_counts.insert(epoch.body.blocks.len());
                    }
                }
                response => {
                    return Err(blossom::BlossomError::WireProtocol(format!(
                        "expected epoch chain, got {}",
                        response.kind()
                    )));
                }
            }
        }
        if finalized_nodes >= supermajority_count(cluster.len())
            && final_hashes.len() == 1
            && block_counts.len() == 1
        {
            drivers.check().await?;
            return Ok((
                *final_hashes.iter().next().unwrap(),
                *block_counts.iter().next().unwrap(),
            ));
        }
        if std::time::Instant::now() >= deadline {
            let catch_up_hints = cluster
                .nodes()
                .iter()
                .enumerate()
                .map(|(index, node)| {
                    (
                        index,
                        node.runtime
                            .epoch_started_catch_up_services()
                            .map(|services| services.len()),
                    )
                })
                .collect::<Vec<_>>();
            return Err(blossom::BlossomError::WireProtocol(format!(
                "cluster did not finalize the same epoch before deadline: finalized_nodes={}, unique_hashes={}, block_counts={:?}, catch_up_hints={catch_up_hints:?}",
                finalized_nodes,
                final_hashes.len(),
                block_counts
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

fn verification_proof_for_indices(
    cluster: &SimulatedCluster,
    dispatch: &Dispatch,
    blocks: &BTreeMap<HashType, ()>,
    signers: &[usize],
) -> Vec<(blossom::PubKey, Signature)> {
    let body = VerificationBody {
        blocks_hash: blocks.hash(),
        blocks: blocks.clone(),
    };
    signers
        .iter()
        .map(|index| {
            let node = &cluster.node(*index).identity;
            (
                node.public_key(),
                signed_header(node, dispatch, MSGKey::Verification, &body).signature,
            )
        })
        .collect()
}

fn signed_header<T: BlossomBody>(
    sender: &NodeIdentity,
    dispatch: &Dispatch,
    kind: MSGKey,
    body: &T,
) -> Header {
    signed_header_for_round(sender, dispatch, dispatch.header.round, kind, body)
}

fn signed_header_for_round<T: BlossomBody>(
    sender: &NodeIdentity,
    dispatch: &Dispatch,
    round: u8,
    kind: MSGKey,
    body: &T,
) -> Header {
    let message_hash = Header::signature_hash_for_body(
        &sender.public_key(),
        &dispatch.header.last_epoch,
        dispatch.header.nonce,
        round,
        kind,
        body,
    );
    Header {
        sender: sender.public_key(),
        last_epoch: dispatch.header.last_epoch,
        nonce: dispatch.header.nonce,
        round,
        signature: sender
            .sign(message_hash.as_ref())
            .unwrap_or_else(|_| Signature::default()),
    }
}
