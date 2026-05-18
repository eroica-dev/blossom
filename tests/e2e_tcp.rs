use std::collections::BTreeMap;

use blossom::{
    Block, BlossomBody, Commit, CommitBody, Dispatch, EchoReDispatch, EchoRequest, EchoResponse,
    EchoResponseBody, EpochStarted, EpochStartedBody, EpochTarget, FanOutStrategy, HashType,
    Header, MSGKey, MockBlockService, Msg, Nonce, OverlayRuntime, Proposal, ProposalBody,
    ServiceKind, Signature, SimulatedCluster, TcpServiceClient, Transaction, TrustMode,
    Verification, VerificationBody, WireRequest, WireResponse,
};
use blossom::{DoHash, EncodedFrame, NodeIdentity};

#[tokio::test]
async fn cluster_exposes_health_state_address_book_and_nonce() {
    let cluster = SimulatedCluster::spawn(3).await.unwrap();

    for index in 0..cluster.len() {
        let node = cluster.node(index);
        match node.request(WireRequest::Health).await.unwrap() {
            WireResponse::Health(health) => {
                assert_eq!(health.status, "ok");
                assert_eq!(health.public_key, node.identity.public_key());
            }
            response => panic!("expected health, got {}", response.kind()),
        }

        match node.request(WireRequest::State).await.unwrap() {
            WireResponse::State(state) => {
                assert_eq!(state.node.public_key(), node.identity.public_key());
                assert_eq!(state.node.secret_key, None);
                assert_eq!(state.last_epoch_nonce, Nonce::new(0));
                assert_eq!(state.next_nonce, Nonce::new(1));
                assert_eq!(state.pending_blocks, 0);
            }
            response => panic!("expected state, got {}", response.kind()),
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
    }

    let mut connection = cluster.connect(0).await.unwrap();
    match connection.request(&WireRequest::Health).await.unwrap() {
        WireResponse::Health(health) => {
            assert_eq!(health.status, "ok");
            assert_eq!(health.public_key, cluster.node(0).identity.public_key());
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
            WireRequest::RegisterService(block_service.service.clone()),
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
                    && service.public_key == block_service.service.public_key
            }));
        }
        response => panic!("expected address book, got {}", response.kind()),
    }
}

#[tokio::test]
async fn block_submission_duplicate_rejection_send_block_and_dispatch_are_end_to_end() {
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
            last_epoch: target.last_epoch,
            nonce: target.nonce.new_next(),
        },
        cluster.node(0).keypair.secret,
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
        WireResponse::Ok => {}
        response => panic!("expected send block ok, got {}", response.kind()),
    }
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
    match cluster.request_frame(2, &hot_dispatch_frame).await.unwrap() {
        WireResponse::Error(message) => assert!(message.contains("duplicate dispatch")),
        response => panic!(
            "expected duplicate hot dispatch error, got {}",
            response.kind()
        ),
    }

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
        verif: Some(vec![(sender.public_key(), verification.header.signature)]),
        signature_tree: Some(blocks.clone()),
        signature_tree_hash: Some(blocks.hash()),
    };
    let proposal = Proposal {
        header: signed_header(sender, &dispatch, MSGKey::Proposal, &proposal_body),
        body: proposal_body,
    };
    expect_receipt(
        cluster
            .request(1, WireRequest::Message(Msg::Proposal(proposal)))
            .await,
        "proposal",
    );

    let commit_body = CommitBody {
        consensus: true,
        signature_tree_insert: None,
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
        header: dispatch.header.clone(),
        requested_blocks: blocks.clone(),
    };
    expect_receipt(
        cluster
            .request(1, WireRequest::Message(Msg::EchoRequest(echo_request)))
            .await,
        "echo_request",
    );

    let echo_redispatch = EchoReDispatch {
        header: dispatch.header.clone(),
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

    expect_receipt(
        cluster.request(1, WireRequest::Message(Msg::Ok)).await,
        "ok",
    );
    expect_receipt(
        cluster.request(1, WireRequest::Message(Msg::Fail)).await,
        "fail",
    );
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

fn signed_header<T: BlossomBody>(
    sender: &NodeIdentity,
    dispatch: &Dispatch,
    kind: MSGKey,
    body: &T,
) -> Header {
    let message_hash = Header::signature_hash_for_body(
        &sender.public_key(),
        &dispatch.header.last_epoch,
        dispatch.header.nonce,
        dispatch.header.round,
        kind,
        body,
    );
    Header {
        sender: sender.public_key(),
        last_epoch: dispatch.header.last_epoch,
        nonce: dispatch.header.nonce,
        round: dispatch.header.round,
        signature: sender
            .sign(message_hash.as_ref())
            .unwrap_or_else(|_| Signature::default()),
    }
}
