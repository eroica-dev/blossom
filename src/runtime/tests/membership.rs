//! Membership admission, capability, lease, and reconnect tests.

use super::*;

#[test]
fn staged_node_admission_is_committed_at_epoch_boundary() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let joiner = Keypair::generate();
    let service = Service::new(
        ServiceKind::Consensus,
        joiner.public,
        "tcp",
        "127.0.0.1",
        9100,
    );
    let admission = NodeAdmission::signed_for_consensus_service(
        service,
        target.last_epoch,
        target.nonce,
        &joiner.signer(),
    )
    .unwrap();

    let staged = runtime.stage_node_admission(admission).unwrap();
    assert_eq!(staged.map(|node| node.public_key()), Some(joiner.public));

    let dispatch = runtime.dispatch_local_block(0).unwrap();
    let local_admission = dispatch
        .body
        .blocks
        .values()
        .flat_map(|block| block.body.node_admissions.iter())
        .next()
        .cloned()
        .expect("local dispatch should carry staged admission");
    assert!(
        dispatch
            .body
            .blocks
            .values()
            .any(|block| block.body.node_admissions.len() == 1)
    );

    {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        {
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, 0);
            for signer in &keypairs[1..4] {
                let mut block = Block::default();
                block.body.last_epoch = target.last_epoch;
                block.body.nonce = target.nonce;
                block.body.node_admissions.push(local_admission.clone());
                block.sign(&signer.secret);
                quorum.verified_blocks.insert(block.hash, block);
            }
        }
        let epoch_hash = state
            .prepare_verified_epoch(&target.last_epoch, target.nonce, 0)
            .unwrap()
            .unwrap()
            .hash;
        for signer in &keypairs[..4] {
            state
                .get_mut_quorum(&target.last_epoch, target.nonce, 0)
                .epoch_signatures
                .insert(signer.public, signer.signer().sign(epoch_hash.as_ref()));
        }
        assert!(state.advance_epoch(&target.last_epoch, target.nonce, 0, true));
    }

    assert!(
        runtime
            .current_verifiers()
            .iter()
            .any(|node| node.public_key() == joiner.public)
    );
}

#[test]
fn stage_node_admission_rejects_stale_target() {
    let (runtime, _keypairs, target) = runtime_with_peers();
    let joiner = Keypair::generate();
    let service = Service::new(
        ServiceKind::Consensus,
        joiner.public,
        "tcp",
        "127.0.0.1",
        9100,
    );
    let admission = NodeAdmission::signed_for_consensus_service(
        service,
        target.last_epoch,
        target.nonce.new_next(),
        &joiner.signer(),
    )
    .unwrap();

    assert_eq!(
        runtime.stage_node_admission(admission),
        Err(BlossomError::InvalidEpochNonce)
    );
}

#[test]
fn status_omits_secret_key_and_registers_consensus_service() {
    let (runtime, keypair) = runtime();
    let status = runtime.status().unwrap();

    assert_eq!(status.node.public_key(), keypair.public);
    assert!(!status.node.has_signing_material());
    assert!(
        status
            .services
            .iter()
            .any(|service| service.kind == ServiceKind::Consensus
                && service.public_key == keypair.public)
    );
}

#[test]
fn overlay_mode_rejects_consensus_entrypoints() {
    let keypair = Keypair::generate();
    let node = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );
    let runtime = NodeRuntime::new(RuntimeConfig::overlay(node));

    assert_eq!(runtime.mode(), RuntimeMode::Overlay);
    assert!(matches!(
        runtime.next_epoch_target(),
        Err(BlossomError::WireProtocol(error)) if error.contains("consensus runtime mode")
    ));
    assert!(matches!(
        runtime.set_application_state(b"v1:state"),
        Err(BlossomError::WireProtocol(error)) if error.contains("consensus runtime mode")
    ));
    assert!(matches!(
        runtime.receive_message(Msg::Ok),
        Err(BlossomError::WireProtocol(error)) if error.contains("consensus runtime mode")
    ));
}

#[test]
fn submit_block_enforces_registered_block_service_key() {
    let (runtime, keypair) = runtime();
    let block_keypair = Keypair::generate();
    runtime.register_service(Service::new(
        ServiceKind::Block,
        block_keypair.public,
        "tcp",
        "127.0.0.1",
        9000,
    ));
    let target = runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.sign(&keypair.secret);

    assert_eq!(
        runtime.submit_block(block),
        Err(BlossomError::UnknownSender)
    );
}

#[test]
fn dispatch_without_queued_block_sends_signed_empty_block() {
    let (runtime, _) = runtime();
    runtime
        .set_application_state(b"v1:bandwidth=1048576")
        .unwrap();
    let target = runtime.next_epoch_target().unwrap();

    let dispatch = runtime.dispatch_local_block(0).unwrap();

    assert_eq!(dispatch.header.nonce, target.nonce);
    assert_eq!(dispatch.body.blocks.len(), 1);
    let block = dispatch.body.blocks.values().next().unwrap();
    assert!(block.is_empty());
    assert_eq!(block.application_state(), b"v1:bandwidth=1048576");
    assert!(block.verify_integrity().is_ok());
}

#[test]
fn missing_signature_encounter_is_added_to_next_empty_block() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let subject = keypairs[1].public;

    let record_hash = runtime
        .record_missing_signature(subject, 0, EncounterPhase::Verification, 123)
        .unwrap();

    assert_ne!(record_hash, HashType::default());
    assert_eq!(runtime.pending_encounter_records().len(), 1);

    let dispatch = runtime.dispatch_local_block(0).unwrap();
    let block = dispatch.body.blocks.values().next().unwrap();
    assert_eq!(block.body.last_epoch, target.last_epoch);
    assert_eq!(block.body.nonce, target.nonce);
    assert_eq!(block.body.encounter_records.len(), 1);
    assert_eq!(
        block.body.encounter_records[0].body.observer,
        keypairs[0].public
    );
    assert_eq!(block.body.encounter_records[0].body.subject, subject);
    assert_eq!(
        block.body.encounter_records[0].body.phase,
        EncounterPhase::Verification
    );
    assert_eq!(
        block.body.encounter_records[0].body.outcome,
        EncounterOutcome::MissingSignature
    );
    assert_eq!(block.body.encounter_records[0].body.evidence_hash, None);
    assert!(block.body.encounter_records[0].verify().is_ok());
    assert!(block.verify_integrity().is_ok());
    assert!(runtime.pending_encounter_records().is_empty());
}

#[test]
fn missing_signature_subjects_compare_expected_quorum_to_seen_signatures() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        let sender = state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
            .into_iter()
            .next()
            .expect("round should include a peer");
        keypairs
            .iter()
            .find(|keypair| keypair.public == sender)
            .unwrap()
            .clone()
    };
    let blocks = BTreeMap::new();
    let body = VerificationBody {
        blocks_hash: blocks.hash(),
        blocks,
    };
    let signature_hash = Header::signature_hash_for_body(
        &signer.public,
        &target.last_epoch,
        target.nonce,
        0,
        MSGKey::Verification,
        &body,
    );
    let verification = Verification {
        header: Header {
            sender: signer.public,
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round: 0,
            signature: signer.signer().sign(signature_hash.as_ref()),
        },
        body,
    };

    runtime
        .receive_message(Msg::Verification(verification))
        .unwrap();

    let missing = runtime
        .missing_signature_subjects(0, EncounterPhase::Verification)
        .unwrap();
    assert!(!missing.contains(&signer.public));
    assert_eq!(missing.len(), 4);
}

#[test]
fn record_missing_signatures_queues_evidence_for_absent_signers() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let expected_missing = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };

    let hashes = runtime
        .record_missing_signatures(0, EncounterPhase::Dispatch, 456)
        .unwrap();

    assert_eq!(hashes.len(), expected_missing.len());
    let records = runtime.pending_encounter_records();
    assert_eq!(records.len(), expected_missing.len());
    for record in records {
        assert_eq!(record.body.observer, keypairs[0].public);
        assert!(expected_missing.contains(&record.body.subject));
        assert_eq!(record.body.outcome, EncounterOutcome::MissingSignature);
        assert_eq!(record.body.phase, EncounterPhase::Dispatch);
        assert!(record.verify().is_ok());
    }
}

#[test]
fn receive_message_rejects_unknown_sender_and_bad_signature() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let unknown = Keypair::generate();
    let body = DispatchBody::default();
    let unknown_signature_hash = Header::signature_hash_for_body(
        &unknown.public,
        &target.last_epoch,
        target.nonce,
        0,
        MSGKey::Dispatch,
        &body,
    );
    let unknown_dispatch = Dispatch {
        header: Header {
            sender: unknown.public,
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round: 0,
            signature: unknown.signer().sign(unknown_signature_hash.as_ref()),
        },
        body: body.clone(),
    };
    assert_eq!(
        runtime.receive_message(Msg::Dispatch(unknown_dispatch)),
        Err(BlossomError::UnknownSender)
    );

    let bad_signature_dispatch = Dispatch {
        header: Header {
            sender: keypairs[1].public,
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round: 0,
            signature: crate::Signature([1; 64]),
        },
        body,
    };
    assert_eq!(
        runtime.receive_message(Msg::Dispatch(bad_signature_dispatch)),
        Err(BlossomError::SignatureError)
    );
}

#[test]
fn consensus_messages_reject_known_members_in_wrong_round_without_accounting() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let wrong_round = 1;

    for (label, message) in consensus_messages_for_target(signer, &target, wrong_round) {
        assert_eq!(
            runtime.receive_message(message),
            Err(BlossomError::UnknownSender),
            "{label} should reject a known member outside the addressed round"
        );
        assert!(
            runtime
                .inner
                .state
                .read()
                .expect("state lock poisoned")
                .get_quorum(&target.last_epoch, target.nonce, wrong_round)
                .is_none(),
            "{label} must not create wrong-round quorum accounting"
        );
    }

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let consensus = state
        .get_consensus(&target.last_epoch, target.nonce)
        .expect("header checks should initialize consensus");
    assert!(
        !consensus.quorum.contains_key(&wrong_round),
        "wrong-round traffic must not create quorum accounting; rounds: {:?}",
        consensus.quorum.keys().collect::<Vec<_>>()
    );
    let round_zero = consensus.quorum.get(&0);
    assert!(
        round_zero.is_none_or(|quorum| {
            quorum.received_dispatches.is_empty()
                && quorum.verifications.verifications.is_empty()
                && quorum.proposals.proposals.is_empty()
                && quorum.commit_senders.is_empty()
                && quorum.epoch_started_senders.is_empty()
        }),
        "wrong-round traffic must not be recorded in the valid round"
    );
}

#[test]
fn consensus_messages_reject_non_members_without_accounting() {
    let (runtime, _, target) = runtime_with_peers();
    let unknown = Keypair::generate();

    for (label, message) in consensus_messages_for_target(&unknown, &target, 0) {
        assert_eq!(
            runtime.receive_message(message),
            Err(BlossomError::UnknownSender),
            "{label} should reject non-member senders"
        );
    }

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let consensus = state
        .get_consensus(&target.last_epoch, target.nonce)
        .expect("header checks should initialize consensus");
    assert!(
        consensus.quorum.is_empty(),
        "non-member traffic must not create quorum accounting"
    );
}

#[test]
fn trusted_runtime_accepts_unsigned_known_member_work() {
    let (runtime, keypairs, target) = runtime_with_peers_mode(TrustMode::Trusted);
    let known_sender = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
            .into_iter()
            .next()
            .expect("round should include a peer")
    };
    let body = DispatchBody::default();
    let dispatch = Dispatch {
        header: Header {
            sender: known_sender,
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round: 0,
            signature: crate::Signature::default(),
        },
        body,
    };

    let receipt = runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();
    assert_eq!(receipt.kind, "dispatch");

    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.seal_unsigned(keypairs[0].public);

    let accepted = runtime.submit_block(block).unwrap();
    assert_eq!(accepted.nonce, target.nonce);
    assert_eq!(accepted.application_state_bytes, 0);
    assert_eq!(runtime.status().unwrap().pending_blocks, 1);
}

#[test]
fn trusted_runtime_still_rejects_unsigned_unknown_sender() {
    let (runtime, _, target) = runtime_with_peers_mode(TrustMode::Trusted);
    let unknown = Keypair::generate();
    let dispatch = Dispatch {
        header: Header {
            sender: unknown.public,
            last_epoch: target.last_epoch,
            nonce: target.nonce,
            round: 0,
            signature: crate::Signature::default(),
        },
        body: DispatchBody::default(),
    };

    assert_eq!(
        runtime.receive_message(Msg::Dispatch(dispatch)),
        Err(BlossomError::UnknownSender)
    );
}

#[test]
fn peer_application_states_reports_verified_peer_blocks() {
    let (runtime, _, target) = runtime_with_peers_mode(TrustMode::Trusted);
    let known_sender = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
            .into_iter()
            .next()
            .expect("round should include a peer")
    };
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block
        .set_application_state(b"v1:cache-pressure=low")
        .unwrap();
    block.seal_unsigned(known_sender);

    {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_quorum(&target.last_epoch, target.nonce, 0)
            .verified_blocks
            .insert(block.hash, block.clone());
    }

    let states = runtime.peer_application_states();
    let state = states.get(&known_sender).expect("peer state should exist");
    assert_eq!(state.peer, known_sender);
    assert_eq!(state.block_hash, block.hash);
    assert_eq!(state.last_epoch, target.last_epoch);
    assert_eq!(state.nonce, target.nonce);
    assert_eq!(state.application_state.as_slice(), b"v1:cache-pressure=low");
}

#[test]
fn observed_encounter_records_reports_verified_peer_blocks() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let observer = &keypairs[1];
    let subject = keypairs[2].public;
    let record = EncounterRecord::signed(
        EncounterRecordBody::new(
            observer.public,
            subject,
            target.last_epoch,
            target.nonce,
            0,
            EncounterPhase::Verification,
            EncounterOutcome::MissingSignature,
        ),
        &observer.signer(),
    )
    .unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.body.encounter_records.push(record.clone());
    block.sign(&observer.secret);
    assert!(block.verify_integrity().is_ok());

    {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_quorum(&target.last_epoch, target.nonce, 0)
            .verified_blocks
            .insert(block.hash, block.clone());
    }

    let records = runtime.observed_encounter_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].group_id, target.group_id);
    assert_eq!(records[0].block_hash, block.hash);
    assert_eq!(records[0].block_validator, observer.public);
    assert_eq!(records[0].record, record);
}

#[test]
fn echo_recovery_messages_reject_unknown_senders() {
    let (runtime, _, target) = runtime_with_peers();
    let unknown = Keypair::generate();
    let requested_blocks = BTreeMap::new();
    let request_header =
        signed_test_header(&unknown, &target, MSGKey::EchoRequest, &requested_blocks);
    let redispatched_blocks = BTreeMap::new();
    let redispatch_header = signed_test_header(
        &unknown,
        &target,
        MSGKey::EchoReDispatch,
        &redispatched_blocks,
    );

    assert_eq!(
        runtime.receive_message(Msg::EchoRequest(EchoRequest {
            header: request_header,
            requested_blocks,
        })),
        Err(BlossomError::UnknownSender)
    );
    assert_eq!(
        runtime.receive_message(Msg::EchoReDispatch(EchoReDispatch {
            header: redispatch_header,
            redispatched_blocks,
        })),
        Err(BlossomError::UnknownSender)
    );
}

#[test]
fn echo_recovery_messages_reject_bad_signatures() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = &keypairs[1];
    let mut requested_blocks = BTreeMap::new();
    requested_blocks.insert(HashType([1; 32]), ());
    let header = signed_test_header(signer, &target, MSGKey::EchoRequest, &requested_blocks);
    requested_blocks.insert(HashType([2; 32]), ());

    assert_eq!(
        runtime.receive_message(Msg::EchoRequest(EchoRequest {
            header,
            requested_blocks,
        })),
        Err(BlossomError::SignatureError)
    );
}

#[test]
fn round_skip_assist_emits_one_local_vote() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let manifest = DataDisseminationManifest {
        last_epoch: target.last_epoch,
        nonce: target.nonce,
        first_fanout_round: 0,
        last_certified_round: Some(0),
        certified_blocks_hash: HashType::default(),
        carried_blocks: BTreeSet::new(),
        dropped_local_blocks: BTreeSet::new(),
        source_nodes: keypairs.iter().map(|keypair| keypair.public).collect(),
        replica_holders: BTreeMap::new(),
    };

    let first = runtime
        .try_round_skip_assist(0, 1, manifest.clone())
        .unwrap();
    assert_eq!(first.decision, FutureRoundAssistDecision::Assist);
    let message = first.message.expect("first assist should emit a vote");
    assert_eq!(message.body.vote.voter, keypairs[0].public);
    assert_eq!(message.body.vote.last_epoch, target.last_epoch);
    assert_eq!(message.body.vote.nonce, target.nonce);
    assert_eq!(message.body.vote.from_round, 0);
    assert_eq!(message.body.vote.to_round, 1);
    assert_eq!(message.body.vote.manifest_hash, manifest.hash());
    message.body.vote.verify_signature().unwrap();

    let second = runtime.try_round_skip_assist(0, 1, manifest).unwrap();
    assert!(second.message.is_none());
}

#[test]
fn echo_request_responds_with_only_verified_or_durable_blocks() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let block = signed_block_for_target(&keypairs[0], &target, b"echo-redispatch");
    runtime.submit_block(block).unwrap();
    let dispatch = runtime.dispatch_local_block(0).unwrap();
    let block_hash = *dispatch.body.blocks.keys().next().unwrap();
    let mut requested_blocks = BTreeMap::new();
    requested_blocks.insert(block_hash, ());
    requested_blocks.insert(HashType([9; 32]), ());
    let requester = round_signer(&runtime, &keypairs, &target, 0);
    let request = EchoRequest {
        header: signed_test_header(requester, &target, MSGKey::EchoRequest, &requested_blocks),
        requested_blocks,
    };

    let redispatch = runtime
        .respond_to_echo_request(&request)
        .unwrap()
        .expect("verified block should be redispatched");
    assert_eq!(redispatch.redispatched_blocks.len(), 1);
    assert!(redispatch.redispatched_blocks.contains_key(&block_hash));
    assert_eq!(redispatch.header.sender, keypairs[0].public);
    redispatch
        .header
        .verify_signature(MSGKey::EchoReDispatch, &redispatch.redispatched_blocks)
        .unwrap();
}

#[test]
fn manifest_repair_rejects_off_manifest_and_inserts_valid_blocks() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let block = signed_block_for_target(&keypairs[1], &target, b"manifest-repair");
    let manifest = DataDisseminationManifest {
        last_epoch: target.last_epoch,
        nonce: target.nonce,
        first_fanout_round: 0,
        last_certified_round: Some(0),
        certified_blocks_hash: HashType::default(),
        carried_blocks: [block.hash].into_iter().collect(),
        dropped_local_blocks: BTreeSet::new(),
        source_nodes: keypairs.iter().map(|keypair| keypair.public).collect(),
        replica_holders: [(
            block.hash,
            [keypairs[1].public, keypairs[2].public]
                .into_iter()
                .collect(),
        )]
        .into_iter()
        .collect(),
    };

    let mut wrong = BTreeMap::new();
    wrong.insert(HashType([7; 32]), block.clone());
    assert!(runtime.repair_manifest_blocks(&manifest, wrong).is_err());

    let mut valid = BTreeMap::new();
    valid.insert(block.hash, block.clone());
    let receipt = runtime.repair_manifest_blocks(&manifest, valid).unwrap();
    assert_eq!(receipt.inserted_blocks, 1);
    assert!(receipt.missing_blocks.is_empty());
    assert_eq!(
        runtime
            .verified_or_durable_block_by_hash(block.hash)
            .unwrap()
            .unwrap()
            .hash,
        block.hash
    );
}

#[test]
fn reconcile_commit_advances_rebuilt_verified_epoch() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let block = signed_block_for_target(&keypairs[1], &target, b"reconcile-commit");
    let block_keys = [(block.hash, ())].into_iter().collect::<BTreeMap<_, _>>();
    let response_body = ReconcileResponseBody {
        blocks_hash: block_keys.hash(),
        blocks: [(block.hash, block.clone())].into_iter().collect(),
    };
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    runtime
        .receive_message(Msg::ReconcileResponse(ReconcileResponse {
            header: signed_test_header(signer, &target, MSGKey::ReconcileResponse, &response_body),
            body: response_body,
        }))
        .unwrap();
    let verified_hash = {
        let state = runtime.inner.state.read().expect("state lock poisoned");
        state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .unwrap()
            .verified_blocks_hash()
    };
    let epoch_hash = runtime
        .inner
        .state
        .read()
        .expect("state lock poisoned")
        .prepare_verified_epoch(&target.last_epoch, target.nonce, 0)
        .unwrap()
        .unwrap()
        .hash;
    let signatures = keypairs
        .iter()
        .take(4)
        .map(|keypair| (keypair.public, keypair.signer().sign(epoch_hash.as_ref())))
        .collect();
    let commit_body = ReconcileCommitBody {
        blocks_hash: verified_hash,
        epoch_hash,
        signatures,
    };
    let receipt = runtime
        .try_reconcile_commit(ReconcileCommit {
            header: signed_test_header(signer, &target, MSGKey::ReconcileCommit, &commit_body),
            body: commit_body,
        })
        .unwrap();
    assert_eq!(receipt.kind, "reconcile_commit");
    let chain = runtime.epochchain();
    assert_eq!(chain.epochchain.len(), 2);
    assert!(
        chain
            .epochchain
            .last()
            .unwrap()
            .body
            .blocks
            .contains_key(&block.hash)
    );
}
