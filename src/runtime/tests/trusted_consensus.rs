//! Trusted-mode consensus, persistence, and recovery tests.

use super::*;

#[test]
fn trusted_dispatch_quorum_advances_after_matching_confirmation_supermajority() {
    let (runtime, keypairs, target) = runtime_with_peers_mode(TrustMode::Trusted);
    let local_block = signed_block_for_target(&keypairs[0], &target, b"trusted-stage-driver-local");
    runtime.submit_block(local_block).unwrap();
    let local_dispatch = runtime
        .try_produce_dispatch(0)
        .unwrap()
        .expect("queued local block should produce a trusted dispatch");
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let mut expected_blocks = local_dispatch.body.blocks.clone();

    for (index, peer) in round_peers.iter().enumerate() {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let block = signed_block_for_target(
            signer,
            &target,
            format!("trusted-stage-driver-peer-{index}"),
        );
        let mut blocks = BTreeMap::new();
        blocks.insert(block.hash, block);
        let dispatch = signed_dispatch_for_blocks(signer, &target, blocks);
        expected_blocks.extend(dispatch.body.blocks.clone());
        runtime.receive_message(Msg::Dispatch(dispatch)).unwrap();
    }

    assert_eq!(runtime.status().unwrap().last_epoch_nonce, Nonce::new(0));
    assert!(
        !runtime
            .complete_trusted_verification(0, expected_blocks.hash())
            .unwrap()
    );

    establish_trusted_acknowledgement_quorum(&runtime, &target, 0, &round_peers);
    let confirmation = runtime
        .try_produce_verification(0)
        .unwrap()
        .expect("matching trusted acknowledgements should produce one confirmation");
    assert_eq!(confirmation.header.signature, Signature::default());
    assert_eq!(confirmation.body.blocks_hash, expected_blocks.hash());
    assert_eq!(
        confirmation.body.blocks,
        expected_blocks
            .keys()
            .map(|hash| (*hash, ()))
            .collect::<BTreeMap<_, _>>()
    );

    assert!(
        !runtime
            .complete_trusted_verification(0, confirmation.body.blocks_hash)
            .unwrap()
    );
    for peer in round_peers.iter().take(3) {
        runtime
            .receive_message(Msg::Verification(Verification {
                header: Header {
                    sender: *peer,
                    last_epoch: target.last_epoch,
                    nonce: target.nonce,
                    round: 0,
                    signature: Signature::default(),
                },
                body: confirmation.body.clone(),
            }))
            .unwrap();
    }

    let state = runtime.inner.state.read().expect("state lock poisoned");
    assert_eq!(state.epochchain.epochchain.len(), 2);
    let latest = state.epochchain.epochchain.last().unwrap();
    assert_eq!(latest.body.previous_nonce, Some(Nonce::new(0)));
    assert_eq!(latest.body.nonce, target.nonce);
    assert_eq!(
        latest.body.blocks.keys().copied().collect::<Vec<_>>(),
        expected_blocks.keys().copied().collect::<Vec<_>>()
    );
    let old_quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .expect("trusted round remains available for diagnostics");
    assert!(old_quorum.proposals.proposals.is_empty());
    assert!(old_quorum.commit_senders.is_empty());
}

#[test]
fn trusted_confirmation_quorum_tolerates_two_of_six_inactive_members() {
    let (runtime, keypairs, target) = runtime_with_peers_mode(TrustMode::Trusted);
    let local_block = signed_block_for_target(&keypairs[0], &target, b"trusted-local");
    runtime.submit_block(local_block).unwrap();
    runtime.try_produce_dispatch(0).unwrap().unwrap();
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };

    for (index, peer) in round_peers.iter().take(3).enumerate() {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let block = signed_block_for_target(signer, &target, format!("trusted-active-{index}"));
        runtime
            .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
                signer,
                &target,
                BTreeMap::from([(block.hash, block)]),
            )))
            .unwrap();
    }
    establish_trusted_acknowledgement_quorum(&runtime, &target, 0, &round_peers);
    let local_confirmation = runtime
        .try_produce_verification(0)
        .unwrap()
        .expect("four of six dispatchers satisfy the trusted threshold");

    for peer in round_peers.iter().take(2) {
        runtime
            .receive_message(Msg::Verification(Verification {
                header: Header {
                    sender: *peer,
                    last_epoch: target.last_epoch,
                    nonce: target.nonce,
                    round: 0,
                    signature: Signature::default(),
                },
                body: local_confirmation.body.clone(),
            }))
            .unwrap();
    }
    assert_eq!(runtime.status().unwrap().last_epoch_nonce, Nonce::new(0));

    let third = round_peers[2];
    runtime
        .receive_message(Msg::Verification(Verification {
            header: Header {
                sender: third,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: Signature::default(),
            },
            body: local_confirmation.body,
        }))
        .unwrap();
    let committed = runtime.epochchain().epochchain.pop().unwrap();
    assert_eq!(committed.body.nonce, target.nonce);
    assert_eq!(committed.body.blocks.len(), 4);

    let (blocked, blocked_keys, blocked_target) = runtime_with_peers_mode(TrustMode::Trusted);
    blocked
        .submit_block(signed_block_for_target(
            &blocked_keys[0],
            &blocked_target,
            b"blocked-local",
        ))
        .unwrap();
    blocked.try_produce_dispatch(0).unwrap().unwrap();
    let blocked_peers = {
        let mut state = blocked.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&blocked_target.last_epoch, blocked_target.nonce)
            .peers(0)
    };
    for peer in blocked_peers.iter().take(2) {
        let signer = blocked_keys
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let block = signed_block_for_target(signer, &blocked_target, b"blocked-peer");
        blocked
            .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
                signer,
                &blocked_target,
                BTreeMap::from([(block.hash, block)]),
            )))
            .unwrap();
    }
    assert!(blocked.try_produce_verification(0).unwrap().is_none());
}

#[test]
fn verified_runtime_rejects_trusted_acknowledgements_without_state_change() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let peer = round_signer(&runtime, &keypairs, &target, 0);
    let body = VerificationBody {
        blocks_hash: BTreeMap::<HashType, ()>::new().hash(),
        blocks: BTreeMap::new(),
    };
    let message = TrustedAcknowledgement {
        header: signed_test_header(peer, &target, MSGKey::TrustedAcknowledgement, &body),
        body,
    };
    let consensus_count_before = runtime
        .inner
        .state
        .read()
        .expect("state lock poisoned")
        .consensus
        .len();

    assert!(matches!(
        runtime.receive_message(Msg::TrustedAcknowledgement(message)),
        Err(BlossomError::InvalidConfiguration(message))
            if message.contains("verified mode")
    ));
    let state = runtime.inner.state.read().expect("state lock poisoned");
    assert_eq!(state.consensus.len(), consensus_count_before);
}

#[test]
fn trusted_confirmation_before_late_dispatch_commits_original_candidate() {
    let (runtime, keypairs, target) =
        runtime_with_node_count_mode_and_quorum(3, TrustMode::Trusted, QuorumSize::new(3).unwrap());
    let local = signed_block_for_target(&keypairs[0], &target, b"trusted-a");
    let local_hash = local.hash;
    runtime.submit_block(local).unwrap();
    runtime.try_produce_dispatch(0).unwrap().unwrap();
    let peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let b = keypairs
        .iter()
        .find(|keypair| keypair.public == peers[0])
        .unwrap();
    let c = keypairs
        .iter()
        .find(|keypair| keypair.public == peers[1])
        .unwrap();
    let block_b = signed_block_for_target(b, &target, b"trusted-b");
    let block_b_hash = block_b.hash;
    runtime
        .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
            b,
            &target,
            BTreeMap::from([(block_b.hash, block_b)]),
        )))
        .unwrap();
    let acknowledgement = runtime
        .try_produce_trusted_acknowledgement(0)
        .unwrap()
        .unwrap();
    runtime
        .receive_message(Msg::TrustedAcknowledgement(TrustedAcknowledgement {
            header: Header {
                sender: b.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: Signature::default(),
            },
            body: acknowledgement.body.clone(),
        }))
        .unwrap();
    let confirmation = runtime.try_produce_verification(0).unwrap().unwrap();

    let block_c = signed_block_for_target(c, &target, b"trusted-c-late");
    let block_c_hash = block_c.hash;
    runtime
        .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
            c,
            &target,
            BTreeMap::from([(block_c.hash, block_c)]),
        )))
        .unwrap();
    let expanded = runtime
        .try_produce_trusted_acknowledgement(0)
        .unwrap()
        .expect("late dispatch should expand the mutable acknowledgement");
    assert!(expanded.body.blocks.contains_key(&block_c_hash));
    assert!(runtime.try_produce_verification(0).unwrap().is_none());

    runtime
        .receive_message(Msg::Verification(Verification {
            header: Header {
                sender: b.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: Signature::default(),
            },
            body: confirmation.body,
        }))
        .unwrap();
    let epoch = runtime.epochchain().epochchain.pop().unwrap();
    assert_eq!(epoch.body.nonce, target.nonce);
    assert!(epoch.body.blocks.contains_key(&local_hash));
    assert!(epoch.body.blocks.contains_key(&block_b_hash));
    assert!(!epoch.body.blocks.contains_key(&block_c_hash));
}

#[test]
fn trusted_failed_stage_broadcasts_retry_the_exact_messages() {
    let (runtime, keypairs, target) =
        runtime_with_node_count_mode_and_quorum(3, TrustMode::Trusted, QuorumSize::new(3).unwrap());
    runtime
        .submit_block(signed_block_for_target(
            &keypairs[0],
            &target,
            b"trusted-retry-a",
        ))
        .unwrap();
    let dispatch = runtime.try_produce_dispatch(0).unwrap().unwrap();
    runtime
        .schedule_dispatch_retry(0, dispatch.body.blocks_hash)
        .unwrap();
    let retried_dispatch = runtime.try_produce_dispatch(0).unwrap().unwrap();
    assert_eq!(
        borsh::to_vec(&retried_dispatch).unwrap(),
        borsh::to_vec(&dispatch).unwrap()
    );

    let peer = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        let peer = state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)[0];
        keypairs
            .iter()
            .find(|keypair| keypair.public == peer)
            .unwrap()
            .clone()
    };
    let peer_block = signed_block_for_target(&peer, &target, b"trusted-retry-b");
    runtime
        .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
            &peer,
            &target,
            BTreeMap::from([(peer_block.hash, peer_block)]),
        )))
        .unwrap();

    let acknowledgement = runtime
        .try_produce_trusted_acknowledgement(0)
        .unwrap()
        .unwrap();
    runtime
        .schedule_trusted_acknowledgement_retry(0, acknowledgement.body.blocks_hash)
        .unwrap();
    let retried_acknowledgement = runtime
        .try_produce_trusted_acknowledgement(0)
        .unwrap()
        .unwrap();
    assert_eq!(
        borsh::to_vec(&retried_acknowledgement).unwrap(),
        borsh::to_vec(&acknowledgement).unwrap()
    );

    runtime
        .receive_message(Msg::TrustedAcknowledgement(TrustedAcknowledgement {
            header: Header {
                sender: peer.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: Signature::default(),
            },
            body: acknowledgement.body,
        }))
        .unwrap();
    let confirmation = runtime.try_produce_verification(0).unwrap().unwrap();
    runtime
        .schedule_trusted_confirmation_retry(0, confirmation.body.blocks_hash)
        .unwrap();
    let retried_confirmation = runtime.try_produce_verification(0).unwrap().unwrap();
    assert_eq!(
        borsh::to_vec(&retried_confirmation).unwrap(),
        borsh::to_vec(&confirmation).unwrap()
    );
}

#[test]
fn trusted_late_dispatch_before_confirmation_expands_candidate() {
    let (runtime, keypairs, target) =
        runtime_with_node_count_mode_and_quorum(3, TrustMode::Trusted, QuorumSize::new(3).unwrap());
    let local = signed_block_for_target(&keypairs[0], &target, b"trusted-a");
    runtime.submit_block(local).unwrap();
    runtime.try_produce_dispatch(0).unwrap().unwrap();
    let peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let b = keypairs
        .iter()
        .find(|keypair| keypair.public == peers[0])
        .unwrap();
    let c = keypairs
        .iter()
        .find(|keypair| keypair.public == peers[1])
        .unwrap();
    let block_b = signed_block_for_target(b, &target, b"trusted-b");
    runtime
        .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
            b,
            &target,
            BTreeMap::from([(block_b.hash, block_b)]),
        )))
        .unwrap();
    let first_acknowledgement = runtime
        .try_produce_trusted_acknowledgement(0)
        .unwrap()
        .unwrap();

    let block_c = signed_block_for_target(c, &target, b"trusted-c-before-confirm");
    let block_c_hash = block_c.hash;
    runtime
        .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
            c,
            &target,
            BTreeMap::from([(block_c.hash, block_c)]),
        )))
        .unwrap();
    let expanded = runtime
        .try_produce_trusted_acknowledgement(0)
        .unwrap()
        .unwrap();
    assert_ne!(
        expanded.body.blocks_hash,
        first_acknowledgement.body.blocks_hash
    );
    assert!(expanded.body.blocks.contains_key(&block_c_hash));
    assert!(runtime.try_produce_verification(0).unwrap().is_none());

    runtime
        .receive_message(Msg::TrustedAcknowledgement(TrustedAcknowledgement {
            header: Header {
                sender: b.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: Signature::default(),
            },
            body: expanded.body.clone(),
        }))
        .unwrap();
    let confirmation = runtime.try_produce_verification(0).unwrap().unwrap();
    runtime
        .receive_message(Msg::Verification(Verification {
            header: Header {
                sender: b.public,
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: Signature::default(),
            },
            body: confirmation.body,
        }))
        .unwrap();

    let epoch = runtime.epochchain().epochchain.pop().unwrap();
    assert_eq!(epoch.body.blocks.len(), 3);
    assert!(epoch.body.blocks.contains_key(&block_c_hash));
}

#[test]
fn durable_trusted_confirmation_lock_retransmits_identically_after_restart() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                9_000 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(nodes.clone());
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "blossom-trusted-runtime-lock-{}-{unique}",
        std::process::id()
    ));
    let open = || {
        let mut config = RuntimeConfig::new(nodes[0].clone());
        config.genesis = Some(genesis.clone());
        config.trust_mode = TrustMode::Trusted;
        config.trusted_epoch_log_path = Some(path.clone());
        NodeRuntime::try_new(config).unwrap()
    };
    let runtime = open();
    let target = runtime.next_epoch_target().unwrap();
    runtime
        .submit_block(signed_block_for_target(
            &keypairs[0],
            &target,
            b"durable-local",
        ))
        .unwrap();
    runtime.try_produce_dispatch(0).unwrap().unwrap();
    let peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    for peer in peers.iter().take(3) {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let block = signed_block_for_target(signer, &target, b"durable-peer");
        runtime
            .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
                signer,
                &target,
                BTreeMap::from([(block.hash, block)]),
            )))
            .unwrap();
    }
    establish_trusted_acknowledgement_quorum(&runtime, &target, 0, &peers);
    let first = runtime.try_produce_verification(0).unwrap().unwrap();
    let status = runtime.trusted_operational_status().unwrap();
    assert!(status.durable);
    assert!(status.pending_round_lock);
    assert_eq!(status.health, TrustedServiceHealth::Degraded);
    drop(runtime);

    let restarted = open();
    assert_eq!(restarted.status().unwrap().last_epoch_nonce, Nonce::new(0));
    let retransmitted = restarted.try_produce_verification(0).unwrap().unwrap();
    assert_eq!(retransmitted.header.last_epoch, first.header.last_epoch);
    assert_eq!(retransmitted.header.nonce, first.header.nonce);
    assert_eq!(retransmitted.body.blocks_hash, first.body.blocks_hash);
    assert_eq!(retransmitted.body.blocks, first.body.blocks);
    drop(restarted);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn durable_trusted_hierarchical_round_restarts_from_highest_lock() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                9_050 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let quorum_size = QuorumSize::new(3).unwrap();
    let genesis = genesis_epoch_for_group_with_parameters(
        ConsensusGroupId::root(),
        nodes.clone(),
        ConsensusParameters::new(quorum_size),
    );
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "blossom-trusted-hierarchical-restart-{}-{unique}",
        std::process::id()
    ));
    let open = || {
        let mut config = RuntimeConfig::new(nodes[0].clone()).with_quorum_size(quorum_size);
        config.genesis = Some(genesis.clone());
        config.trust_mode = TrustMode::Trusted;
        config.trusted_epoch_log_path = Some(path.clone());
        NodeRuntime::try_new(config).unwrap()
    };
    let runtime = open();
    let target = runtime.next_epoch_target().unwrap();
    runtime
        .submit_block(signed_block_for_target(
            &keypairs[0],
            &target,
            b"hierarchical-local",
        ))
        .unwrap();
    runtime.try_produce_dispatch(0).unwrap().unwrap();
    let round_zero_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    for peer in &round_zero_peers {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let block = signed_block_for_target(signer, &target, b"hierarchical-round-zero");
        runtime
            .receive_message(Msg::Dispatch(signed_dispatch_for_blocks(
                signer,
                &target,
                BTreeMap::from([(block.hash, block)]),
            )))
            .unwrap();
    }
    establish_trusted_acknowledgement_quorum(&runtime, &target, 0, &round_zero_peers);
    let round_zero_confirmation = runtime.try_produce_verification(0).unwrap().unwrap();
    runtime
        .receive_message(Msg::Verification(Verification {
            header: Header {
                sender: round_zero_peers[0],
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round: 0,
                signature: Signature::default(),
            },
            body: round_zero_confirmation.body,
        }))
        .unwrap();
    assert_eq!(runtime.current_consensus_round().unwrap(), 1);

    runtime.try_produce_dispatch(1).unwrap().unwrap();
    let round_one_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(1)
    };
    let carried_blocks = runtime
        .inner
        .state
        .read()
        .expect("state lock poisoned")
        .get_quorum(&target.last_epoch, target.nonce, 1)
        .unwrap()
        .canonical_verified_blocks();
    for peer in &round_one_peers {
        let signer = keypairs
            .iter()
            .find(|keypair| keypair.public == *peer)
            .unwrap();
        let block = signed_block_for_target(signer, &target, b"hierarchical-round-one");
        let mut blocks = carried_blocks.clone();
        if !blocks
            .values()
            .any(|carried| carried.body.validator == block.body.validator)
        {
            blocks.insert(block.hash, block);
        }
        runtime
            .receive_message(Msg::Dispatch(signed_dispatch_for_blocks_round(
                signer, &target, 1, blocks,
            )))
            .unwrap();
    }
    establish_trusted_acknowledgement_quorum(&runtime, &target, 1, &round_one_peers);
    let round_one_confirmation = runtime.try_produce_verification(1).unwrap().unwrap();
    assert_eq!(
        runtime
            .inner
            .trusted_epoch_log
            .as_ref()
            .unwrap()
            .round_locks()
            .unwrap()
            .len(),
        2
    );
    drop(runtime);

    let restarted = open();
    assert_eq!(restarted.current_consensus_round().unwrap(), 1);
    let retransmitted = restarted.try_produce_verification(1).unwrap().unwrap();
    assert_eq!(
        retransmitted.body.blocks_hash,
        round_one_confirmation.body.blocks_hash
    );
    assert_eq!(
        retransmitted.body.blocks,
        round_one_confirmation.body.blocks
    );
    drop(restarted);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn durable_trusted_local_submission_survives_restart_before_dispatch() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                9_100 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(nodes.clone());
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "blossom-trusted-local-submit-{}-{unique}",
        std::process::id()
    ));
    let open = || {
        let mut config = RuntimeConfig::new(nodes[0].clone());
        config.genesis = Some(genesis.clone());
        config.trust_mode = TrustMode::Trusted;
        config.trusted_epoch_log_path = Some(path.clone());
        NodeRuntime::try_new(config).unwrap()
    };
    let runtime = open();
    let target = runtime.next_epoch_target().unwrap();
    let block = signed_block_for_target(&keypairs[0], &target, b"survive-before-dispatch");
    let expected_hash = block.hash;
    runtime.submit_block(block).unwrap();
    drop(runtime);

    let restarted = open();
    assert_eq!(restarted.status().unwrap().pending_blocks, 1);
    let dispatch = restarted.try_produce_dispatch(0).unwrap().unwrap();
    assert!(dispatch.body.blocks.contains_key(&expected_hash));
    drop(restarted);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn durable_trusted_catch_up_retargets_omitted_local_work_without_restart() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                9_150 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(nodes.clone());
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "blossom-trusted-live-retarget-{}-{unique}",
        std::process::id()
    ));
    let mut config = RuntimeConfig::new(nodes[0].clone());
    config.genesis = Some(genesis.clone());
    config.trust_mode = TrustMode::Trusted;
    config.trusted_epoch_log_path = Some(path.clone());
    let runtime = NodeRuntime::try_new(config).unwrap();
    let target = runtime.next_epoch_target().unwrap();
    let block = signed_block_for_target(&keypairs[0], &target, b"retarget-without-restart");
    let transaction_hashes = block
        .body
        .txs
        .iter()
        .map(|transaction| transaction.hash)
        .collect::<Vec<_>>();
    runtime.submit_block(block).unwrap();

    let mut remote_epoch = Epoch {
        hash: HashType::default(),
        signatures: BTreeMap::new(),
        body: EpochBody {
            group_id: genesis.body.group_id,
            verifiers: genesis.body.verifiers.clone(),
            members: genesis.body.members.clone(),
            last_epoch: genesis.hash,
            previous_nonce: Some(genesis.body.nonce),
            nonce: genesis.body.nonce.new_next(),
            merkle_root: HashType::default(),
            blocks: BTreeMap::new(),
            consensus_parameters: Some(genesis.body.effective_consensus_parameters()),
        },
    };
    remote_epoch.set_hash();
    assert!(
        runtime
            .catch_up_from_epoch_started(EpochChain {
                epochchain: vec![remote_epoch.clone()],
            })
            .unwrap()
    );

    assert_eq!(
        runtime.status().unwrap().last_epoch_nonce,
        remote_epoch.body.nonce
    );
    assert_eq!(runtime.status().unwrap().pending_blocks, 1);
    let dispatch = runtime.try_produce_dispatch(0).unwrap().unwrap();
    let retried = dispatch.body.blocks.values().next().unwrap();
    assert_eq!(retried.body.last_epoch, remote_epoch.hash);
    assert_eq!(retried.body.nonce, remote_epoch.body.nonce.new_next());
    assert_eq!(
        retried
            .body
            .txs
            .iter()
            .map(|transaction| transaction.hash)
            .collect::<Vec<_>>(),
        transaction_hashes
    );
    drop(runtime);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn receive_message_rejects_stale_epoch_target_after_finality() {
    let (runtime, keypairs, target) = runtime_with_peers();
    receive_proposal_supermajority(
        &runtime,
        &keypairs,
        &target,
        b"stale-message-finalized-epoch",
    );
    let round_peers = {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .peers(0)
    };
    let stale_signer = keypairs
        .iter()
        .find(|keypair| keypair.public == round_peers[4])
        .unwrap();
    let stale_body = certified_commit_body(&runtime, stale_signer, &target, 0);
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

    let stale_commit = Commit {
        header: signed_test_header(stale_signer, &target, MSGKey::Commit, &stale_body),
        body: stale_body,
    };

    assert!(matches!(
        runtime.receive_message(Msg::Commit(stale_commit)),
        Err(BlossomError::WireProtocol(message))
            if message.contains("stale consensus target")
    ));
}

#[test]
fn receive_dispatch_rejects_bad_body_hash_before_sender_accounting() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let block = signed_block_for_target(signer, &target, b"dispatch-tx".to_vec());
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let valid_dispatch = signed_dispatch_for_blocks(signer, &target, blocks);
    let mut bad_dispatch = valid_dispatch.clone();
    bad_dispatch.body.blocks_hash = HashType([9; 32]);
    bad_dispatch.header = signed_test_header(signer, &target, MSGKey::Dispatch, &bad_dispatch.body);

    assert!(matches!(
        runtime.receive_message(Msg::Dispatch(bad_dispatch)),
        Err(BlossomError::WireProtocol(message))
            if message.contains("dispatch blocks hash")
    ));

    let receipt = runtime
        .receive_message(Msg::Dispatch(valid_dispatch))
        .unwrap();
    assert_eq!(receipt.kind, "dispatch");
    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .unwrap();
    assert_eq!(quorum.pending_dispatches.len(), 1);
    assert!(quorum.received_dispatches.contains(&signer.public));
}

#[test]
fn receive_dispatch_rejects_invalid_block_before_sender_accounting() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let valid_block = signed_block_for_target(signer, &target, b"valid-tx".to_vec());
    let mut valid_blocks = BTreeMap::new();
    valid_blocks.insert(valid_block.hash, valid_block);
    let valid_dispatch = signed_dispatch_for_blocks(signer, &target, valid_blocks);

    let mut invalid_block = signed_block_for_target(signer, &target, b"bad-tx".to_vec());
    let invalid_block_hash = invalid_block.hash;
    invalid_block
        .body
        .txs
        .push(crate::block::Transaction::new("tampered-after-sign"));
    let mut invalid_blocks = BTreeMap::new();
    invalid_blocks.insert(invalid_block_hash, invalid_block);
    let invalid_dispatch = signed_dispatch_for_blocks(signer, &target, invalid_blocks);

    assert_eq!(
        runtime.receive_message(Msg::Dispatch(invalid_dispatch)),
        Err(BlossomError::InvalidBlockHash)
    );

    let receipt = runtime
        .receive_message(Msg::Dispatch(valid_dispatch))
        .unwrap();
    assert_eq!(receipt.kind, "dispatch");
    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .unwrap();
    assert_eq!(quorum.pending_dispatches.len(), 1);
}

#[test]
fn receive_dispatch_rejects_wrong_block_target_before_sender_accounting() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let valid_block = signed_block_for_target(signer, &target, b"valid-tx".to_vec());
    let mut valid_blocks = BTreeMap::new();
    valid_blocks.insert(valid_block.hash, valid_block);
    let valid_dispatch = signed_dispatch_for_blocks(signer, &target, valid_blocks);

    let mut wrong_nonce = signed_block_for_target(signer, &target, b"wrong-nonce".to_vec());
    wrong_nonce.body.nonce = target.nonce.new_next();
    wrong_nonce.sign(&signer.secret);
    let mut wrong_blocks = BTreeMap::new();
    wrong_blocks.insert(wrong_nonce.hash, wrong_nonce.clone());
    let wrong_dispatch = signed_dispatch_for_blocks(signer, &target, wrong_blocks);

    assert_eq!(
        runtime.receive_message(Msg::Dispatch(wrong_dispatch)),
        Err(BlossomError::InvalidBlockNonce {
            expected: target.nonce,
            actual: wrong_nonce.body.nonce,
        })
    );

    let receipt = runtime
        .receive_message(Msg::Dispatch(valid_dispatch))
        .unwrap();
    assert_eq!(receipt.kind, "dispatch");
    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .unwrap();
    assert_eq!(quorum.pending_dispatches.len(), 1);
}
