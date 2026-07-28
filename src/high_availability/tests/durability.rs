//! HA durable-state, checkpoint, compaction, and recovery tests.

use super::*;

#[test]
fn durable_acknowledgement_rolls_back_on_disk_full_and_can_retry() {
    let storage = HaFaultStorage::new();
    let mut runtime = fault_injected_runtime(&storage);
    runtime
        .build_dispatch(vec![Transaction::new("disk-full")])
        .unwrap();
    let self_index = runtime.self_slot().index();
    assert_eq!(runtime.current_round().acknowledgements[self_index], 0);

    storage.set_fault(STORAGE_FAULT_FULL);
    let error = runtime.acknowledge().unwrap_err();
    assert!(error.to_string().contains("injected HA ENOSPC"));
    assert_eq!(runtime.current_round().acknowledgements[self_index], 0);
    assert_eq!(
        assess_high_availability_failure(&error),
        HaFailureAssessment {
            class: HaFailureClass::DurabilityUnavailable,
            health: HaServiceHealth::Unavailable,
            retry_in_process: false,
            directives: vec![
                HaServiceDirective::NotifyOperators,
                HaServiceDirective::NotifyUsers,
                HaServiceDirective::DrainWrites,
                HaServiceDirective::RestartOrRedeploy,
            ],
        }
    );

    drop(runtime);
    storage.set_fault(STORAGE_FAULT_NONE);
    let mut runtime = fault_injected_runtime(&storage);
    assert_eq!(runtime.current_round().acknowledgements[self_index], 0);
    runtime
        .build_dispatch(vec![Transaction::new("disk-full-retry")])
        .unwrap();
    let acknowledgement = runtime.acknowledge().unwrap();
    assert_ne!(acknowledgement.received_mask, 0);
    assert_eq!(
        runtime.current_round().acknowledgements[self_index],
        acknowledgement.received_mask
    );
}

#[test]
fn durable_acknowledgement_rolls_back_on_fsync_failure_and_can_retry() {
    let storage = HaFaultStorage::new();
    let mut runtime = fault_injected_runtime(&storage);
    runtime
        .build_dispatch(vec![Transaction::new("fsync-failure")])
        .unwrap();
    let self_index = runtime.self_slot().index();

    storage.set_fault(STORAGE_FAULT_SYNC);
    let error = runtime.acknowledge().unwrap_err();
    assert!(error.to_string().contains("injected HA fsync failure"));
    assert_eq!(runtime.current_round().acknowledgements[self_index], 0);

    drop(runtime);
    storage.set_fault(STORAGE_FAULT_NONE);
    let mut runtime = fault_injected_runtime(&storage);
    runtime
        .build_dispatch(vec![Transaction::new("fsync-retry")])
        .unwrap();
    runtime.acknowledge().unwrap();
    assert_ne!(runtime.current_round().acknowledgements[self_index], 0);
}

#[test]
fn finalized_epoch_is_not_applied_until_durable_commit_succeeds() {
    let storage = HaFaultStorage::new();
    let mut durable = fault_injected_runtime(&storage);
    let mut peers = runtimes(3);

    let dispatches = vec![
        durable
            .build_dispatch(vec![Transaction::new("durable")])
            .unwrap(),
        peers[1]
            .build_dispatch(vec![Transaction::new("peer-1")])
            .unwrap(),
        peers[2]
            .build_dispatch(vec![Transaction::new("peer-2")])
            .unwrap(),
    ];
    for dispatch in &dispatches {
        durable.receive_dispatch(dispatch.clone()).unwrap();
        peers[1].receive_dispatch(dispatch.clone()).unwrap();
    }
    let local_acknowledgement = durable.acknowledge().unwrap();
    peers[1]
        .receive_acknowledgement(local_acknowledgement)
        .unwrap();
    let peer_acknowledgement = peers[1].acknowledge().unwrap();
    durable
        .receive_acknowledgement(peer_acknowledgement)
        .unwrap();
    let (local_confirmation, finalized) = durable.confirm().unwrap();
    assert!(finalized.is_none());
    let peer_confirmation = HaConfirm {
        sender: HaMemberSlot(1),
        ..local_confirmation
    };

    storage.set_fault(STORAGE_FAULT_SYNC);
    let error = durable
        .receive_confirmation(peer_confirmation.clone())
        .unwrap_err();
    assert!(error.to_string().contains("injected HA fsync failure"));
    assert_eq!(durable.head().nonce, Nonce::default());
    assert_eq!(durable.current_round().round_id.nonce, Nonce::new(1));

    drop(durable);
    storage.set_fault(STORAGE_FAULT_NONE);
    let mut durable = fault_injected_runtime(&storage);
    assert_eq!(durable.head().nonce, Nonce::default());
    let event = durable.receive_confirmation(peer_confirmation).unwrap();
    assert!(matches!(event, HaRuntimeEvent::Finalized(_)));
    assert_eq!(durable.head().nonce, Nonce::new(1));
}

#[test]
fn durable_confirmation_lock_survives_restart() {
    let identities = vec![member(0), member(1), member(2)];
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("blossom-ha-lock-{}-{unique}", std::process::id()));
    let group = ConsensusGroupId::named("ha-durable-lock");
    let mut runtime = HighAvailabilityRuntime::open(
        &path,
        group,
        identities[0].public_key(),
        identities.clone(),
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    let local = runtime.build_dispatch(vec![Transaction::new("a")]).unwrap();
    let mut peer_block = Block::default();
    peer_block.body.last_epoch = local.round_id.previous_epoch_hash;
    peer_block.body.nonce = local.round_id.nonce;
    peer_block.body.txs.push(Transaction::new("b"));
    peer_block.seal_unsigned(identities[1].public_key());
    runtime
        .receive_dispatch(HaDispatch {
            round_id: local.round_id,
            sender: HaMemberSlot(1),
            block_hash: peer_block.hash,
            block: peer_block,
        })
        .unwrap();
    let local_ack = runtime.acknowledge().unwrap();
    let peer_ack = HaAcknowledge {
        round_id: local_ack.round_id,
        sender: HaMemberSlot(1),
        received_mask: local_ack.received_mask,
        block_hashes: local_ack.block_hashes,
    };
    runtime.receive_acknowledgement(peer_ack).unwrap();
    let first = runtime.confirm().unwrap().0;
    drop(runtime);

    let mut restored = HighAvailabilityRuntime::open(
        &path,
        group,
        identities[0].public_key(),
        identities,
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    assert_eq!(
        restored.current_round().confirmed_candidate,
        Some(first.candidate.digest)
    );
    let retransmitted = restored.confirm().unwrap().0;
    assert_eq!(retransmitted, first);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn durable_suspension_survives_restart_with_fixed_genesis_identities() {
    let identities = vec![member(0), member(1), member(2)];
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "blossom-ha-suspension-{}-{unique}",
        std::process::id()
    ));
    let group = ConsensusGroupId::named("ha-durable-suspension");
    let durable = HighAvailabilityRuntime::open(
        &path,
        group,
        identities[0].public_key(),
        identities.clone(),
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    let mut nodes = vec![
        durable,
        HighAvailabilityRuntime::new(
            group,
            identities[1].public_key(),
            identities.clone(),
            HighAvailabilityParameters::default(),
        )
        .unwrap(),
        HighAvailabilityRuntime::new(
            group,
            identities[2].public_key(),
            identities.clone(),
            HighAvailabilityParameters::default(),
        )
        .unwrap(),
    ];
    for epoch in 1..=DEFAULT_UNRESPONSIVE_EPOCH_DEPTH {
        finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
    }
    let peer_vote = nodes[1].vote_to_suspend(HaMemberSlot(2)).unwrap().0;
    nodes[0].vote_to_suspend(HaMemberSlot(2)).unwrap();
    assert!(matches!(
        nodes[0].receive_membership_vote(peer_vote).unwrap(),
        HaRuntimeEvent::MembershipChanged(_)
    ));
    assert_eq!(nodes[0].members().active_mask(), 0b011);
    drop(nodes);

    let restored = HighAvailabilityRuntime::open(
        &path,
        group,
        identities[0].public_key(),
        identities,
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    assert_eq!(restored.members().active_mask(), 0b011);
    assert_eq!(restored.status().unwrap().membership_generation, 1);
    assert_eq!(
        restored.node_status(HaMemberSlot(2)),
        NodeAvailabilityStatus::Suspended {
            since: Nonce::new(7)
        }
    );
    std::fs::remove_dir_all(path).ok();
}

#[test]
#[ignore = "production durability soak; run explicitly with BLOSSOM_HA_SOAK_EPOCHS"]
fn durable_runtime_survives_thousand_epoch_restart_and_recovery_soak() {
    let epochs = std::env::var("BLOSSOM_HA_SOAK_EPOCHS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_001);
    assert!(epochs >= 1_001, "production HA soak must run 1,001+ epochs");
    let identities = vec![member(0), member(1), member(2)];
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let paths = (0..3)
        .map(|slot| {
            std::env::temp_dir().join(format!(
                "blossom-ha-soak-{}-{unique}-{slot}",
                std::process::id()
            ))
        })
        .collect::<Vec<_>>();
    let group = ConsensusGroupId::named(format!("ha-durable-soak-{unique}"));
    let parameters = HighAvailabilityParameters::default();
    let open_all = || {
        paths
            .iter()
            .enumerate()
            .map(|(slot, path)| {
                HighAvailabilityRuntime::open(
                    path,
                    group,
                    identities[slot].public_key(),
                    identities.clone(),
                    parameters,
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let mut nodes = open_all();

    for epoch in 1..=epochs {
        if epoch.is_multiple_of(97) {
            let missing = (epoch / 97) % nodes.len();
            let participants = (0..nodes.len())
                .filter(|slot| *slot != missing)
                .collect::<Vec<_>>();
            finalize_runtime_epoch(
                &mut nodes,
                &participants,
                &format!("durable-recovery-{epoch}"),
            );
            let snapshot = nodes[participants[0]].recovery_snapshot();
            nodes[missing].install_recovery_snapshot(snapshot).unwrap();
        } else {
            finalize_runtime_epoch(&mut nodes, &[0, 1, 2], &format!("durable-{epoch}"));
        }

        if epoch.is_multiple_of(41) || epoch == epochs {
            let expected_head = nodes[0].head().hash;
            let expected_revision = nodes[0].revision().unwrap();
            drop(nodes);
            nodes = open_all();
            for node in &nodes {
                assert_eq!(node.head().nonce, Nonce::new(epoch as u64));
                assert_eq!(node.head().hash, expected_head);
                assert_eq!(node.revision().unwrap(), expected_revision);
                node.head().validate(node.members()).unwrap();
            }
        }
    }

    drop(nodes);
    for path in paths {
        std::fs::remove_dir_all(path).ok();
    }
}

#[test]
fn recovery_snapshot_catches_up_only_on_the_existing_finalized_prefix() {
    let mut nodes = runtimes(3);
    for epoch in 1..=3 {
        finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("epoch-{epoch}"));
    }
    let snapshot = nodes[0].recovery_snapshot();
    let expected_revision = nodes[0].revision().unwrap();
    let recovered_revision = nodes[2]
        .install_recovery_snapshot(snapshot.clone())
        .unwrap();
    assert_eq!(nodes[2].head().hash, nodes[0].head().hash);
    assert_eq!(recovered_revision, expected_revision);

    let mut corrupt = snapshot;
    corrupt.epochs.last_mut().unwrap().hash = HashType([0xA5; 32]);
    let identities = (0..3u8).map(member).collect::<Vec<_>>();
    let mut fresh = HighAvailabilityRuntime::new(
        ConsensusGroupId::named("ha-runtime-test"),
        identities[2].public_key(),
        identities,
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    assert!(matches!(
        fresh.install_recovery_snapshot(corrupt),
        Err(BlossomError::WireProtocol(_))
    ));
}

#[test]
fn certified_checkpoint_compacts_history_without_changing_revision() {
    let mut nodes = runtimes(3);
    for epoch in 0..10 {
        finalize_runtime_epoch(&mut nodes, &[0, 1], &format!("checkpoint-{epoch}"));
    }
    let revision_before = nodes[0].revision().unwrap();
    let retained_before = nodes[0].retained_epoch_count();
    let checkpoint = nodes[0].compact_history_through(Nonce::new(3)).unwrap();
    assert_eq!(checkpoint.through_epoch.nonce, Nonce::new(3));
    assert_eq!(
        nodes[0].history_checkpoint().unwrap().checkpoint_hash,
        checkpoint.checkpoint_hash
    );
    assert!(nodes[0].retained_epoch_count() < retained_before);
    assert_eq!(nodes[0].revision().unwrap(), revision_before);
    assert_eq!(nodes[0].epochs()[0].nonce, Nonce::new(3));

    let snapshot = nodes[0].recovery_snapshot();
    let mut learner = runtimes(3).remove(2);
    let recovered_revision = learner.install_recovery_snapshot(snapshot).unwrap();
    assert_eq!(recovered_revision, revision_before);
    assert_eq!(learner.head().hash, nodes[0].head().hash);
    assert_eq!(
        learner.history_checkpoint().unwrap().checkpoint_hash,
        checkpoint.checkpoint_hash
    );
}

#[test]
fn pre_envelope_durable_state_requires_deliberate_reset() {
    let runtime = runtimes(3).remove(0);
    let bytes = borsh::to_vec(&runtime.state).unwrap();
    let (store, path) = durable_store_with_bytes("pre-envelope", &bytes);

    assert!(
        store
            .load()
            .unwrap_err()
            .to_string()
            .contains("predates the v1 LogStore format")
    );

    drop(store);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn durable_v1_rejects_unknown_format_version() {
    let runtime = runtimes(3).remove(0);
    let mut metadata = HaDurableMetadata::from(&runtime.state);
    metadata.format_version = HA_RUNTIME_STATE_FORMAT_VERSION + 1;
    let bytes = borsh::to_vec(&metadata).unwrap();
    let (store, path) = durable_store_with_bytes("future-v1", &bytes);

    assert!(
        store
            .load()
            .unwrap_err()
            .to_string()
            .contains("unsupported durable HA runtime state format version")
    );

    drop(store);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn durable_state_and_recovery_snapshot_never_contain_member_secret_keys() {
    let keypairs = [Keypair::generate(), Keypair::generate()];
    let identities = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                Some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                9200 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let secret_bytes = keypairs
        .iter()
        .map(|keypair| keypair.secret.as_array().to_vec())
        .collect::<Vec<_>>();
    let path = std::env::temp_dir().join(format!(
        "blossom-ha-secret-regression-{}-{}",
        std::process::id(),
        identities[0].public_key()
    ));
    let runtime = HighAvailabilityRuntime::open(
        &path,
        ConsensusGroupId::named("ha-redacted-recovery"),
        identities[0].public_key(),
        identities.clone(),
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    assert!(identities.iter().all(NodeIdentity::has_signing_material));
    assert!((0..runtime.members().member_count()).all(|index| {
        runtime
            .members()
            .member(HaMemberSlot(index as u8))
            .is_some_and(|member| !member.has_signing_material())
    }));
    let snapshot = runtime.recovery_snapshot();
    assert!((0..snapshot.members.member_count()).all(|index| {
        snapshot
            .members
            .member(HaMemberSlot(index as u8))
            .is_some_and(|member| !member.has_signing_material())
    }));
    drop(runtime);
    let durable_bytes = durable_directory_bytes(&path);
    for secret in secret_bytes {
        assert!(
            !durable_bytes
                .windows(secret.len())
                .any(|window| window == secret.as_slice())
        );
    }
    std::fs::remove_dir_all(path).ok();
}
