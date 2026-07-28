//! Verified-mode consensus, message validation, and recovery tests.

use super::*;

#[test]
fn authenticated_newer_epoch_started_is_recorded_as_a_catch_up_hint() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let announced = EpochTarget {
        group_id: target.group_id,
        last_epoch: HashType::hash(b"certified-newer-epoch"),
        nonce: target.nonce.new_next(),
    };
    let body = EpochStartedBody::default();
    let message = EpochStarted {
        header: signed_test_header(&keypairs[1], &announced, MSGKey::EpochStarted, &body),
        body,
    };

    let receipt = runtime.receive_message(Msg::EpochStarted(message)).unwrap();

    assert_eq!(receipt.kind, "epoch_started_catch_up");
    assert_eq!(
        runtime
            .inner
            .epoch_started_hints
            .read()
            .expect("epoch-start hint lock poisoned")
            .get(&keypairs[1].public),
        Some(&announced)
    );
    assert_eq!(runtime.next_epoch_target().unwrap(), target);
}

#[test]
fn newer_epoch_started_rejects_a_non_validator_signer() {
    let (runtime, _, target) = runtime_with_peers();
    let outsider = Keypair::generate();
    let announced = EpochTarget {
        group_id: target.group_id,
        last_epoch: HashType::hash(b"untrusted-newer-epoch"),
        nonce: target.nonce.new_next(),
    };
    let body = EpochStartedBody::default();
    let message = EpochStarted {
        header: signed_test_header(&outsider, &announced, MSGKey::EpochStarted, &body),
        body,
    };

    assert_eq!(
        runtime.receive_message(Msg::EpochStarted(message)),
        Err(BlossomError::UnknownSender)
    );
    assert!(
        runtime
            .inner
            .epoch_started_hints
            .read()
            .expect("epoch-start hint lock poisoned")
            .is_empty()
    );
}

#[test]
fn idle_driver_recovery_assessment_materializes_the_round_and_waits() {
    let (runtime, _, _) = runtime_with_peers();

    let assessment = runtime.recovery_wait_assessment(0).unwrap();

    assert_eq!(assessment.status, RecoveryEvidenceStatus::DelayedOrMissing);
    assert_eq!(assessment.passed_nodes, 0);
    assert_eq!(assessment.pending_nodes, 0);
    assert!(assessment.required_nodes > 0);
    assert!(runtime.try_produce_false_proposal(0).unwrap().is_none());
}

#[test]
fn submits_block_for_next_nonce() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.sign(&keypair.secret);

    let accepted = runtime.submit_block(block).unwrap();
    assert_eq!(accepted.nonce, target.nonce);
    assert_eq!(accepted.application_state_bytes, 0);
    assert_eq!(runtime.status().unwrap().pending_blocks, 1);
}

#[test]
fn rejects_wrong_nonce() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce.new_next();
    block.sign(&keypair.secret);

    assert_eq!(
        runtime.submit_block(block),
        Err(BlossomError::InvalidBlockNonce {
            expected: target.nonce,
            actual: target.nonce.new_next()
        })
    );
}

#[test]
fn submit_block_rejects_wrong_last_epoch() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = HashType([9; 32]);
    block.body.nonce = target.nonce;
    block.sign(&keypair.secret);

    assert_eq!(
        runtime.submit_block(block),
        Err(BlossomError::InvalidBlockLastEpoch)
    );
    assert_eq!(runtime.status().unwrap().pending_blocks, 0);
}

#[test]
fn submit_block_rejects_invalid_hash_and_signature_before_queueing() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let mut tampered = signed_block_for_target(&keypair, &target, b"tx".to_vec());
    tampered
        .body
        .txs
        .push(crate::block::Transaction::new("tampered-after-sign"));

    assert_eq!(
        runtime.submit_block(tampered),
        Err(BlossomError::InvalidBlockHash)
    );
    assert_eq!(runtime.status().unwrap().pending_blocks, 0);

    let mut bad_signature = signed_block_for_target(&keypair, &target, b"tx".to_vec());
    bad_signature.signature = crate::Signature([1; 64]);

    assert_eq!(
        runtime.submit_block(bad_signature),
        Err(BlossomError::SignatureError)
    );
    assert_eq!(runtime.status().unwrap().pending_blocks, 0);
}

#[test]
fn builds_dispatch_from_local_block() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.sign(&keypair.secret);
    runtime.submit_block(block).unwrap();

    let dispatch = runtime.dispatch_local_block(0).unwrap();
    assert_eq!(dispatch.header.nonce, target.nonce);
    assert_eq!(dispatch.body.blocks.len(), 1);
    assert_eq!(runtime.status().unwrap().pending_blocks, 0);
}

#[test]
fn dispatch_local_block_commits_targeted_signed_block() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let block = signed_block_for_target(&keypair, &target, b"dispatch-tx".to_vec());
    runtime.submit_block(block).unwrap();

    let dispatch = runtime.dispatch_local_block(0).unwrap();

    assert!(dispatch.body.validate().is_ok());
    assert!(
        dispatch
            .header
            .verify_signature(MSGKey::Dispatch, &dispatch.body)
            .is_ok()
    );
    let (block_hash, block) = dispatch.body.blocks.iter().next().unwrap();
    assert_eq!(dispatch.body.blocks_hash, dispatch.body.blocks.hash());
    assert_eq!(block.body.last_epoch, target.last_epoch);
    assert_eq!(block.body.nonce, target.nonce);
    assert!(block.verify_integrity_with_hash(*block_hash).is_ok());
}

#[test]
fn dispatch_local_block_records_local_verified_blocks() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let block = signed_block_for_target(&keypair, &target, b"local-verified-dispatch");
    let block_hash = block.hash;
    runtime.submit_block(block).unwrap();

    let dispatch = runtime.dispatch_local_block(0).unwrap();

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
        .expect("local dispatch should initialize quorum state");
    assert!(quorum.verified_blocks.contains_key(&block_hash));
    assert_eq!(
        quorum.verified_blocks_hash,
        Some(quorum.verified_blocks_hash())
    );
}

#[test]
fn concurrent_dispatch_production_consumes_the_local_block_exactly_once() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let block = signed_block_for_target(&keypair, &target, b"concurrent-dispatch");
    let block_hash = block.hash;
    runtime.submit_block(block).unwrap();

    let workers = 16;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers));
    let results = std::thread::scope(|scope| {
        let handles = (0..workers)
            .map(|_| {
                let runtime = runtime.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    runtime.try_produce_dispatch(0).unwrap()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });

    let produced = results.into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(produced.len(), 1);
    assert!(produced[0].body.blocks.contains_key(&block_hash));
    assert_eq!(produced[0].body.blocks.len(), 1);
}

#[test]
fn target_bound_dispatch_refuses_to_cross_an_epoch_transition() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let block = signed_block_for_target(&keypair, &target, b"target-bound-dispatch");
    runtime.submit_block(block).unwrap();
    let stale_driver_target = EpochTarget {
        nonce: target.nonce.new_next(),
        ..target
    };

    assert!(
        runtime
            .try_produce_dispatch_for_target(0, Some(&stale_driver_target))
            .unwrap()
            .is_none()
    );
    assert_eq!(runtime.status().unwrap().pending_blocks, 1);

    let dispatch = runtime
        .try_produce_dispatch_for_target(0, Some(&target))
        .unwrap()
        .unwrap();
    assert_eq!(dispatch.body.blocks.len(), 1);
}

#[test]
fn submit_block_rejects_admission_after_the_local_dispatch_is_sealed() {
    let (runtime, keypair) = runtime();
    let target = runtime.next_epoch_target().unwrap();
    let empty_dispatch = runtime.dispatch_local_block(0).unwrap();
    assert!(
        empty_dispatch
            .body
            .blocks
            .values()
            .all(|block| block.body.txs.is_empty())
    );
    let late = signed_block_for_target(&keypair, &target, b"late-admission");

    assert_eq!(
        runtime.submit_block(late),
        Err(BlossomError::DuplicateBlock)
    );
    assert_eq!(runtime.status().unwrap().pending_blocks, 0);
    assert_eq!(
        borsh::to_vec(&runtime.dispatch_local_block(0).unwrap()).unwrap(),
        borsh::to_vec(&empty_dispatch).unwrap()
    );
}

#[test]
fn exact_dispatch_replay_is_idempotent_but_conflicting_replay_is_rejected() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let first_block = signed_block_for_target(signer, &target, b"first-dispatch");
    let first_dispatch = signed_dispatch_for_blocks(
        signer,
        &target,
        BTreeMap::from([(first_block.hash, first_block)]),
    );

    assert_eq!(
        runtime
            .receive_message(Msg::Dispatch(first_dispatch.clone()))
            .unwrap()
            .kind,
        "dispatch"
    );
    assert_eq!(
        runtime
            .receive_message(Msg::Dispatch(first_dispatch))
            .unwrap()
            .kind,
        "dispatch"
    );

    let conflicting_block = signed_block_for_target(signer, &target, b"conflicting-dispatch");
    let conflicting_dispatch = signed_dispatch_for_blocks(
        signer,
        &target,
        BTreeMap::from([(conflicting_block.hash, conflicting_block)]),
    );
    assert!(matches!(
        runtime.receive_message(Msg::Dispatch(conflicting_dispatch)),
        Err(BlossomError::WireProtocol(message))
            if message.contains("conflicting dispatch")
    ));
}

#[test]
fn runtime_emits_stage_telemetry_spans() {
    let sink = std::sync::Arc::new(InMemoryTelemetrySink::default());
    let (runtime, keypairs, target) = runtime_with_peers_mode_and_telemetry(
        TrustMode::Verified,
        Some(TelemetryHandle::new(sink.clone())),
    );

    let local_block = signed_block_for_target(&keypairs[0], &target, b"telemetry-local");
    runtime.submit_block(local_block).unwrap();
    runtime.dispatch_local_block(0).unwrap();

    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let remote_block = signed_block_for_target(signer, &target, b"telemetry-remote");
    let mut blocks = BTreeMap::new();
    blocks.insert(remote_block.hash, remote_block);
    let dispatch = signed_dispatch_for_blocks(signer, &target, blocks);
    runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();

    let events = sink.events();
    assert!(events.iter().any(|event| {
        event.kind == crate::telemetry::TelemetryEventKind::SpanStart
            && event.stage == "block_formation"
            && event.event == "block_submitted"
    }));
    assert!(events.iter().any(|event| {
        event.kind == crate::telemetry::TelemetryEventKind::SpanEnd
            && event.stage == "dispatch"
            && event.event == "dispatch_local_block"
            && event.outcome.as_deref() == Some("ok")
    }));
    assert!(events.iter().any(|event| {
        event.kind == crate::telemetry::TelemetryEventKind::SpanEnd
            && event.stage == "dispatch"
            && event.event == "dispatch_received"
            && event.message_kind.as_deref() == Some("Dispatch")
            && event.peer == Some(signer.public)
            && event.outcome.as_deref() == Some("ok")
    }));
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == crate::telemetry::TelemetryEventKind::SpanStart)
            .count(),
        events
            .iter()
            .filter(|event| event.kind == crate::telemetry::TelemetryEventKind::SpanEnd)
            .count()
    );
}

#[test]
fn receive_dispatch_updates_pending_state_and_message_matrix() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let remote_block = signed_block_for_target(signer, &target, b"matrix-dispatch");
    let mut blocks = BTreeMap::new();
    blocks.insert(remote_block.hash, remote_block);
    let dispatch = signed_dispatch_for_blocks(signer, &target, blocks);

    let receipt = runtime
        .receive_message(Msg::Dispatch(dispatch.clone()))
        .unwrap();
    assert_eq!(receipt.kind, "dispatch");

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("dispatch should initialize quorum state");
    assert_eq!(quorum.pending_dispatches.len(), 1);
    match &quorum.pending_dispatches[0] {
        PendingDispatch::Decoded(recorded) => {
            assert_eq!(recorded.header.sender, signer.public);
            assert_eq!(recorded.header.signature, dispatch.header.signature);
        }
        other => panic!("expected decoded pending dispatch, got {other:?}"),
    }
    assert!(quorum.received_dispatches.contains(&signer.public));

    let sender_index = quorum
        .msg_matrix
        .find_key_index(&signer.public)
        .expect("sender should be in matrix");
    let receiver_index = quorum
        .msg_matrix
        .find_key_index(&keypairs[0].public)
        .expect("runtime self should be in matrix");
    assert_eq!(
        quorum.msg_matrix.matrix[receiver_index][sender_index],
        crate::register::Status::DispatchReceived
    );
    match &quorum.msg_matrix.message_matrix[sender_index][receiver_index] {
        Some(Msg::Dispatch(recorded)) => {
            assert_eq!(recorded.header.sender, signer.public);
            assert_eq!(recorded.header.signature, dispatch.header.signature);
        }
        other => panic!("expected dispatch matrix message, got {other:?}"),
    }
}

#[test]
fn receive_dispatch_excludes_equivocated_validator_blocks() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let first_block = signed_block_for_target(signer, &target, b"prefill-equivocation-a");
    let second_block = signed_block_for_target(signer, &target, b"prefill-equivocation-b");
    let mut blocks = BTreeMap::new();
    blocks.insert(first_block.hash, first_block);
    blocks.insert(second_block.hash, second_block);
    let dispatch = signed_dispatch_for_blocks(signer, &target, blocks);

    runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("dispatch should initialize quorum state");
    assert!(quorum.verified_blocks().is_empty());
    assert!(quorum.canonical_verified_blocks().is_empty());
    assert!(quorum.equivocating_validators.contains(&signer.public));
    assert_eq!(
        quorum.verified_blocks_hash,
        Some(BTreeMap::<HashType, Block>::new().hash())
    );
}

#[test]
fn receive_echo_response_updates_message_matrix() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let dispatch_subject = keypairs
        .iter()
        .find(|keypair| keypair.public == round_peers[0])
        .unwrap();
    let echoer = keypairs
        .iter()
        .find(|keypair| keypair.public == round_peers[1])
        .unwrap();
    let body = EchoResponseBody {
        sender: dispatch_subject.public,
        blocks_hash: HashType([3; 32]),
        signature_tree_hash: HashType([4; 32]),
    };
    let echo = EchoResponse {
        header: signed_test_header(echoer, &target, MSGKey::EchoResponse, &body),
        body,
    };

    let receipt = runtime
        .receive_message(Msg::EchoResponse(echo.clone()))
        .unwrap();
    assert_eq!(receipt.kind, "echo_response");

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("echo response should initialize quorum state");
    let sender_index = quorum
        .msg_matrix
        .find_key_index(&dispatch_subject.public)
        .expect("dispatch subject should be in matrix");
    let receiver_index = quorum
        .msg_matrix
        .find_key_index(&echoer.public)
        .expect("echoer should be in matrix");
    assert_eq!(
        quorum.msg_matrix.matrix[receiver_index][sender_index],
        crate::register::Status::EchoReceived
    );
    match &quorum.msg_matrix.message_matrix[sender_index][receiver_index] {
        Some(Msg::EchoResponse(recorded)) => {
            assert_eq!(recorded.header.sender, echoer.public);
            assert_eq!(recorded.body.sender, dispatch_subject.public);
        }
        other => panic!("expected echo response matrix message, got {other:?}"),
    }
}

#[test]
fn receive_echo_response_rejects_unknown_subject_without_matrix_update() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let echoer = round_signer(&runtime, &keypairs, &target, 0);
    let unknown = Keypair::generate();
    let body = EchoResponseBody {
        sender: unknown.public,
        blocks_hash: HashType([3; 32]),
        signature_tree_hash: HashType([4; 32]),
    };
    let echo = EchoResponse {
        header: signed_test_header(echoer, &target, MSGKey::EchoResponse, &body),
        body,
    };

    assert_eq!(
        runtime.receive_message(Msg::EchoResponse(echo)),
        Err(BlossomError::UnknownSender)
    );

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("header validation should initialize quorum state");
    assert!(
        quorum
            .msg_matrix
            .message_matrix
            .iter()
            .all(|row| { row.iter().all(Option::is_none) })
    );
    assert!(quorum.msg_matrix.matrix.iter().all(|row| {
        row.iter()
            .all(|status| *status != crate::register::Status::EchoReceived)
    }));
}

#[test]
fn receive_verification_requires_locally_verified_block_set() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let block = signed_block_for_target(signer, &target, b"verified-before-vote");
    let mut verification_blocks = BTreeMap::new();
    verification_blocks.insert(block.hash, ());
    let verification_body = VerificationBody {
        blocks_hash: verification_blocks.hash(),
        blocks: verification_blocks.clone(),
    };
    let unverified_vote = Verification {
        header: signed_test_header(signer, &target, MSGKey::Verification, &verification_body),
        body: verification_body.clone(),
    };

    assert!(matches!(
        runtime.receive_message(Msg::Verification(unverified_vote)),
        Err(BlossomError::WireProtocol(message))
            if message.contains("not been locally verified")
    ));
    {
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("verification header should initialize quorum state");
        assert!(quorum.verifications.verifications.is_empty());
    }

    let mut dispatch_blocks = BTreeMap::new();
    dispatch_blocks.insert(block.hash, block);
    let dispatch = signed_dispatch_for_blocks(signer, &target, dispatch_blocks);
    runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();
    let verified_vote = Verification {
        header: signed_test_header(signer, &target, MSGKey::Verification, &verification_body),
        body: verification_body,
    };

    let receipt = runtime
        .receive_message(Msg::Verification(verified_vote))
        .unwrap();
    assert_eq!(receipt.kind, "verification");
    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("verified vote should keep quorum state");
    assert_eq!(quorum.verifications.verifications.len(), 1);
    assert_eq!(
        quorum.verifications.count.get(&verification_blocks.hash()),
        Some(&1)
    );
}

#[test]
fn runtime_verification_replaces_equivocating_sender_vote() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let first_block = signed_block_for_target(signer, &target, b"first-verified-set");
    let mut first_dispatch_blocks = BTreeMap::new();
    first_dispatch_blocks.insert(first_block.hash, first_block.clone());
    runtime
        .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
            signer,
            &target,
            first_dispatch_blocks,
        )))
        .unwrap();

    let mut first_vote_blocks = BTreeMap::new();
    first_vote_blocks.insert(first_block.hash, ());
    let first_body = VerificationBody {
        blocks_hash: first_vote_blocks.hash(),
        blocks: first_vote_blocks,
    };
    runtime
        .receive_message(Msg::Verification(Verification {
            header: signed_test_header(signer, &target, MSGKey::Verification, &first_body),
            body: first_body.clone(),
        }))
        .unwrap();

    let second_block_signer = keypairs
        .iter()
        .find(|keypair| keypair.public != signer.public)
        .expect("test cluster should have a second validator");
    let second_block =
        signed_block_for_target(second_block_signer, &target, b"second-verified-set");
    let mut second_dispatch_blocks = BTreeMap::new();
    second_dispatch_blocks.insert(second_block.hash, second_block.clone());
    let second_dispatch = signed_dispatch_for_blocks(
        round_signer(&runtime, &keypairs, &target, 0),
        &target,
        second_dispatch_blocks,
    );
    {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, 0);
        record_verified_dispatch_blocks(quorum, second_dispatch.body.blocks.clone());
    }

    let mut second_vote_blocks = BTreeMap::new();
    second_vote_blocks.insert(first_block.hash, ());
    second_vote_blocks.insert(second_block.hash, ());
    let second_body = VerificationBody {
        blocks_hash: second_vote_blocks.hash(),
        blocks: second_vote_blocks,
    };
    runtime
        .receive_message(Msg::Verification(Verification {
            header: signed_test_header(signer, &target, MSGKey::Verification, &second_body),
            body: second_body.clone(),
        }))
        .unwrap();

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("verification should keep quorum state");
    assert_eq!(quorum.verifications.verifications.len(), 1);
    assert_eq!(
        quorum.verifications.count.get(&first_body.blocks_hash),
        None
    );
    assert_eq!(
        quorum.verifications.count.get(&second_body.blocks_hash),
        Some(&1)
    );
}

#[test]
fn runtime_verification_supermajority_requires_distinct_valid_senders() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let body = VerificationBody::default();
    let repeated_sender = keypairs
        .iter()
        .find(|keypair| keypair.public == round_peers[0])
        .unwrap();

    for _ in 0..4 {
        runtime
            .receive_message(Msg::Verification(Verification {
                header: signed_test_header(repeated_sender, &target, MSGKey::Verification, &body),
                body: body.clone(),
            }))
            .unwrap();
    }
    {
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("verification should initialize quorum state");
        assert_eq!(quorum.verifications.verifications.len(), 1);
        assert_eq!(quorum.verifications.consensus_hash(), None);
    }

    for peer in round_peers.iter().take(4).skip(1) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        runtime
            .receive_message(Msg::Verification(Verification {
                header: signed_test_header(signer, &target, MSGKey::Verification, &body),
                body: body.clone(),
            }))
            .unwrap();
    }

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("verification should keep quorum state");
    assert_eq!(quorum.verifications.verifications.len(), 4);
    assert_eq!(
        quorum.verifications.consensus_hash(),
        Some(body.blocks_hash)
    );
}

#[test]
fn receive_proposal_rejects_missing_verification_proof() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let (dispatch, approved_blocks) =
        receive_valid_dispatch(&runtime, &keypairs, &target, b"proposal-missing-proof");
    let proposal_signer = round_signer(&runtime, &keypairs, &target, dispatch.header.round);
    let body = consensus_proposal_body(&approved_blocks, None);
    let proposal = Proposal {
        header: signed_test_header_for_round(
            proposal_signer,
            &target,
            dispatch.header.round,
            MSGKey::Proposal,
            &body,
        ),
        body,
    };

    assert!(matches!(
        runtime.receive_message(Msg::Proposal(proposal)),
        Err(BlossomError::WireProtocol(message))
            if message.contains("verification proof")
    ));

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
        .expect("dispatch should initialize quorum state");
    assert!(quorum.proposals.proposals.is_empty());
}

#[test]
fn receive_proposal_requires_distinct_verification_supermajority() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let (dispatch, approved_blocks) =
        receive_valid_dispatch(&runtime, &keypairs, &target, b"proposal-duplicate-proof");
    let proposal_signer = round_signer(&runtime, &keypairs, &target, dispatch.header.round);
    let repeated_proof = verification_proof_for(
        &keypairs,
        &target,
        dispatch.header.round,
        &approved_blocks,
        &[
            proposal_signer.public,
            proposal_signer.public,
            proposal_signer.public,
            proposal_signer.public,
        ],
    );
    let body = consensus_proposal_body(&approved_blocks, Some(repeated_proof));
    let proposal = Proposal {
        header: signed_test_header_for_round(
            proposal_signer,
            &target,
            dispatch.header.round,
            MSGKey::Proposal,
            &body,
        ),
        body,
    };

    assert!(matches!(
        runtime.receive_message(Msg::Proposal(proposal)),
        Err(BlossomError::WireProtocol(message))
            if message.contains("distinct verifier signatures")
    ));

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
        .expect("dispatch should initialize quorum state");
    assert!(quorum.proposals.proposals.is_empty());
}

#[test]
fn receive_proposal_rejects_non_quorum_verification_proof_signer() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let (dispatch, approved_blocks) =
        receive_valid_dispatch(&runtime, &keypairs, &target, b"proposal-outsider-proof");
    let proposal_signer = round_signer(&runtime, &keypairs, &target, dispatch.header.round);
    let unknown = Keypair::generate();
    let verification_body = VerificationBody {
        blocks_hash: approved_blocks.hash(),
        blocks: approved_blocks.clone(),
    };
    let unknown_header = signed_test_header_for_round(
        &unknown,
        &target,
        dispatch.header.round,
        MSGKey::Verification,
        &verification_body,
    );
    let mut proof = verification_proof_for(
        &keypairs,
        &target,
        dispatch.header.round,
        &approved_blocks,
        &[proposal_signer.public],
    );
    proof.push((unknown.public, unknown_header.signature));
    let body = consensus_proposal_body(&approved_blocks, Some(proof));
    let proposal = Proposal {
        header: signed_test_header_for_round(
            proposal_signer,
            &target,
            dispatch.header.round,
            MSGKey::Proposal,
            &body,
        ),
        body,
    };

    assert_eq!(
        runtime.receive_message(Msg::Proposal(proposal)),
        Err(BlossomError::UnknownSender)
    );

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
        .expect("dispatch should initialize quorum state");
    assert!(quorum.proposals.proposals.is_empty());
}

#[test]
fn receive_proposal_accepts_verified_supermajority_proof() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let (dispatch, approved_blocks) =
        receive_valid_dispatch(&runtime, &keypairs, &target, b"proposal-valid-proof");
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(dispatch.header.round)
    };
    let proposal_signer = keypairs
        .iter()
        .find(|keypair| keypair.public == round_peers[0])
        .unwrap();
    let proof = verification_proof_for(
        &keypairs,
        &target,
        dispatch.header.round,
        &approved_blocks,
        &round_peers[..4],
    );
    let body = consensus_proposal_body(&approved_blocks, Some(proof));
    let proposal = Proposal {
        header: signed_test_header_for_round(
            proposal_signer,
            &target,
            dispatch.header.round,
            MSGKey::Proposal,
            &body,
        ),
        body: body.clone(),
    };

    let receipt = runtime.receive_message(Msg::Proposal(proposal)).unwrap();
    assert_eq!(receipt.kind, "proposal");

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, dispatch.header.round)
        .expect("proposal should keep quorum state");
    assert_eq!(quorum.proposals.proposals.len(), 1);
    assert_eq!(
        quorum.proposals.count.get(&body.approved_hash.unwrap()),
        Some(&1)
    );
}

#[test]
fn receive_proposal_buffers_valid_proof_until_blocks_are_locally_verified() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let round = 0;
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(round)
    };
    let block_signer = keypairs
        .iter()
        .find(|keypair| keypair.public == round_peers[0])
        .unwrap();
    let block = signed_block_for_target(block_signer, &target, b"proposal-arrives-early");
    let mut dispatched_blocks = BTreeMap::new();
    dispatched_blocks.insert(block.hash, block);
    let dispatch = signed_dispatch_for_blocks(block_signer, &target, dispatched_blocks);
    let approved_blocks = dispatch
        .body
        .blocks
        .keys()
        .map(|hash| (*hash, ()))
        .collect::<BTreeMap<_, _>>();
    let proof = verification_proof_for(
        &keypairs,
        &target,
        round,
        &approved_blocks,
        &round_peers[..4],
    );
    let body = consensus_proposal_body(&approved_blocks, Some(proof));
    let proposal = Proposal {
        header: signed_test_header_for_round(block_signer, &target, round, MSGKey::Proposal, &body),
        body,
    };

    let receipt = runtime.receive_message(Msg::Proposal(proposal)).unwrap();
    assert_eq!(receipt.kind, "proposal_pending");
    {
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, round)
            .unwrap();
        assert_eq!(quorum.pending_proposals.len(), 1);
        assert!(quorum.proposals.proposals.is_empty());
    }

    runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();
    let verification_body = VerificationBody {
        blocks_hash: approved_blocks.hash(),
        blocks: approved_blocks,
    };
    runtime
        .receive_message(Msg::Verification(Verification {
            header: signed_test_header_for_round(
                block_signer,
                &target,
                round,
                MSGKey::Verification,
                &verification_body,
            ),
            body: verification_body,
        }))
        .unwrap();

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, round)
        .unwrap();
    assert!(quorum.pending_proposals.is_empty());
    assert_eq!(quorum.proposals.proposals.len(), 1);
}

#[test]
fn receive_commit_requires_distinct_true_supermajority() {
    let (runtime, keypairs, target) = runtime_with_peers();
    receive_proposal_supermajority(&runtime, &keypairs, &target, b"commit-threshold-proposals");
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let repeated_signer = keypairs
        .iter()
        .find(|keypair| keypair.public == round_peers[0])
        .unwrap();
    let commit_body = certified_commit_body(&runtime, repeated_signer, &target, 0);

    for _ in 0..4 {
        runtime
            .receive_message(Msg::Commit(Commit {
                header: signed_test_header(repeated_signer, &target, MSGKey::Commit, &commit_body),
                body: commit_body.clone(),
            }))
            .unwrap();
    }
    {
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("commit should initialize quorum state");
        assert_eq!(quorum.commit_senders.len(), 1);
        assert!(!quorum.commit_sent);
    }

    for peer in round_peers.iter().take(4).skip(1) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let commit_body = certified_commit_body(&runtime, signer, &target, 0);
        runtime
            .receive_message(Msg::Commit(Commit {
                header: signed_test_header(signer, &target, MSGKey::Commit, &commit_body),
                body: commit_body.clone(),
            }))
            .unwrap();
    }

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("commit should keep quorum state");
    assert_eq!(quorum.commit_senders.len(), 4);
    assert!(quorum.commit_sent);
}

#[test]
fn receive_commit_replaces_equivocating_sender_vote() {
    let (runtime, keypairs, target) = runtime_with_peers();
    receive_proposal_supermajority(
        &runtime,
        &keypairs,
        &target,
        b"commit-equivocation-proposals",
    );
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let false_body = CommitBody {
        consensus: false,
        signature_tree_insert: None,
        epoch_hash: None,
        epoch_signature: None,
    };
    let equivocator = keypairs
        .iter()
        .find(|keypair| keypair.public == round_peers[0])
        .unwrap();
    let true_body = certified_commit_body(&runtime, equivocator, &target, 0);

    runtime
        .receive_message(Msg::Commit(Commit {
            header: signed_test_header(equivocator, &target, MSGKey::Commit, &true_body),
            body: true_body.clone(),
        }))
        .unwrap();
    runtime
        .receive_message(Msg::Commit(Commit {
            header: signed_test_header(equivocator, &target, MSGKey::Commit, &false_body),
            body: false_body,
        }))
        .unwrap();

    for peer in round_peers.iter().take(4).skip(1) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let true_body = certified_commit_body(&runtime, signer, &target, 0);
        runtime
            .receive_message(Msg::Commit(Commit {
                header: signed_test_header(signer, &target, MSGKey::Commit, &true_body),
                body: true_body.clone(),
            }))
            .unwrap();
    }
    {
        let state = runtime.inner.state.read().expect("state lock poisoned");
        let quorum = state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .expect("commit should keep quorum state");
        assert_eq!(quorum.commit_senders.len(), 4);
        assert!(!quorum.commit_sent);
    }

    runtime
        .receive_message(Msg::Commit(Commit {
            header: signed_test_header(equivocator, &target, MSGKey::Commit, &true_body),
            body: true_body,
        }))
        .unwrap();

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("commit should keep quorum state");
    assert!(quorum.commit_sent);
}

#[test]
fn receive_commit_rejects_true_vote_before_local_proposal_supermajority() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let body = CommitBody {
        consensus: true,
        ..Default::default()
    };
    let commit = Commit {
        header: signed_test_header(signer, &target, MSGKey::Commit, &body),
        body,
    };

    assert!(matches!(
        runtime.receive_message(Msg::Commit(commit)),
        Err(BlossomError::FailedConsensus)
    ));

    {
        let state = runtime.inner.state.read().expect("state lock poisoned");
        assert!(
            state
                .get_quorum(&target.last_epoch, target.nonce, 0)
                .is_none()
        );
    }

    receive_proposal_supermajority(&runtime, &keypairs, &target, b"buffered-commit-proposals");
}

#[test]
fn receive_commit_supermajority_advances_epoch() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let (_, approved_blocks) =
        receive_proposal_supermajority(&runtime, &keypairs, &target, b"commit-finalizes-epoch");
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    for peer in round_peers.iter().take(4) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let body = certified_commit_body(&runtime, signer, &target, 0);
        runtime
            .receive_message(Msg::Commit(Commit {
                header: signed_test_header(signer, &target, MSGKey::Commit, &body),
                body: body.clone(),
            }))
            .unwrap();
    }

    let state = runtime.inner.state.read().expect("state lock poisoned");
    assert_eq!(state.epochchain.epochchain.len(), 2);
    let latest = state.epochchain.epochchain.last().unwrap();
    assert_eq!(latest.body.last_epoch, target.last_epoch);
    assert_eq!(latest.body.nonce, target.nonce);
    for block_hash in approved_blocks.keys() {
        assert!(latest.body.blocks.contains_key(block_hash));
    }
}

#[test]
fn produced_stage_messages_drive_verification_proposal_and_commit() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let local_block = signed_block_for_target(&keypairs[0], &target, b"stage-driver-local");
    runtime.submit_block(local_block).unwrap();
    let local_dispatch = runtime
        .try_produce_dispatch(0)
        .unwrap()
        .expect("queued local block should produce a dispatch");
    runtime
        .schedule_dispatch_retry(0, local_dispatch.body.blocks_hash)
        .unwrap();
    let retried_dispatch = runtime
        .try_produce_dispatch(0)
        .unwrap()
        .expect("an incomplete verified broadcast should retry");
    assert_eq!(
        borsh::to_vec(&retried_dispatch).unwrap(),
        borsh::to_vec(&local_dispatch).unwrap()
    );
    assert!(runtime.try_produce_dispatch(0).unwrap().is_none());
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let mut approved_blocks = local_dispatch
        .body
        .blocks
        .keys()
        .map(|hash| (*hash, ()))
        .collect::<BTreeMap<_, _>>();

    for (index, peer) in round_peers.iter().enumerate() {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let block = signed_block_for_target(signer, &target, format!("stage-driver-peer-{index}"));
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let dispatch = signed_dispatch_for_blocks(signer, &target, blocks);
        approved_blocks.extend(dispatch.body.blocks.keys().map(|hash| (*hash, ())));
        runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();
    }

    let local_verification = runtime
        .try_produce_verification(0)
        .unwrap()
        .expect("verified dispatch should produce a local verification");
    assert_eq!(local_verification.body.blocks, approved_blocks);
    local_verification
        .header
        .verify_signature(MSGKey::Verification, &local_verification.body)
        .unwrap();
    assert!(runtime.try_produce_verification(0).unwrap().is_none());
    runtime
        .schedule_verification_retry(0, local_verification.body.blocks_hash)
        .unwrap();
    let retried_verification = runtime
        .try_produce_verification(0)
        .unwrap()
        .expect("an incomplete verification broadcast should retry");
    assert_eq!(
        borsh::to_vec(&retried_verification).unwrap(),
        borsh::to_vec(&local_verification).unwrap()
    );
    assert!(runtime.try_produce_verification(0).unwrap().is_none());

    for peer in round_peers.iter().take(3) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        runtime
            .receive_message(Msg::Verification(Verification {
                header: signed_test_header(
                    signer,
                    &target,
                    MSGKey::Verification,
                    &local_verification.body,
                ),
                body: local_verification.body.clone(),
            }))
            .unwrap();
    }

    let local_proposal = runtime
        .try_produce_proposal(0)
        .unwrap()
        .expect("verification supermajority should produce a proposal");
    assert!(local_proposal.body.consensus);
    assert_eq!(local_proposal.body.verif.as_ref().map(Vec::len), Some(4));
    local_proposal
        .header
        .verify_signature(MSGKey::Proposal, &local_proposal.body)
        .unwrap();
    assert!(runtime.try_produce_proposal(0).unwrap().is_none());
    runtime
        .schedule_proposal_retry(0, local_proposal.header.signature)
        .unwrap();
    let retried_proposal = runtime
        .try_produce_proposal(0)
        .unwrap()
        .expect("an incomplete proposal broadcast should retry");
    assert_eq!(
        borsh::to_vec(&retried_proposal).unwrap(),
        borsh::to_vec(&local_proposal).unwrap()
    );
    assert!(runtime.try_produce_proposal(0).unwrap().is_none());

    for peer in round_peers.iter().take(3) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        runtime
            .receive_message(Msg::Proposal(Proposal {
                header: signed_test_header(signer, &target, MSGKey::Proposal, &local_proposal.body),
                body: local_proposal.body.clone(),
            }))
            .unwrap();
    }

    let local_commit = runtime
        .try_produce_commit(0)
        .unwrap()
        .expect("proposal supermajority should produce a commit");
    assert!(local_commit.body.consensus);
    local_commit
        .header
        .verify_signature(MSGKey::Commit, &local_commit.body)
        .unwrap();
    assert!(runtime.try_produce_commit(0).unwrap().is_none());
    let retry = runtime
        .retry_final_commit(0)
        .unwrap()
        .expect("final certificate share should remain retryable");
    assert_eq!(retry.header.sender, local_commit.header.sender);
    assert_eq!(retry.header.signature, local_commit.header.signature);
    assert_eq!(retry.body.epoch_hash, local_commit.body.epoch_hash);
    assert_eq!(
        retry.body.epoch_signature,
        local_commit.body.epoch_signature
    );

    for peer in round_peers.iter().take(3) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let body = certified_commit_body(&runtime, signer, &target, 0);
        runtime
            .receive_message(Msg::Commit(Commit {
                header: signed_test_header(signer, &target, MSGKey::Commit, &body),
                body,
            }))
            .unwrap();
    }

    let state = runtime.inner.state.read().expect("state lock poisoned");
    assert_eq!(state.epochchain.epochchain.len(), 2);
    assert_eq!(
        state.epochchain.epochchain.last().unwrap().body.nonce,
        target.nonce
    );
    drop(state);

    let epoch_started = runtime
        .try_produce_epoch_started()
        .unwrap()
        .expect("finalized epoch should produce an announcement");
    let epoch_started_retry = runtime
        .try_produce_epoch_started()
        .unwrap()
        .expect("unacknowledged epoch announcement should remain retryable");
    assert_eq!(
        epoch_started_retry.header.signature,
        epoch_started.header.signature
    );
    let first_acknowledgement = keypairs[1].public;
    runtime.complete_epoch_started_broadcast(&epoch_started, [first_acknowledgement]);
    assert!(
        runtime.try_produce_epoch_started().unwrap().is_some(),
        "an announcement must remain retryable for validators that have not acknowledged it"
    );
    runtime.complete_epoch_started_broadcast(
        &epoch_started,
        keypairs
            .iter()
            .map(|keypair| keypair.public)
            .filter(|validator| *validator != runtime.self_node().public_key()),
    );
    assert!(runtime.try_produce_epoch_started().unwrap().is_none());
}
