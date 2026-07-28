//! Durable admission-store transaction and recovery tests.

use super::*;

#[test]
fn durable_store_rejects_identity_equivocation_and_recovers_state() {
    let keypair = Keypair::generate();
    let path = std::env::temp_dir().join(format!(
        "blossom-active-active-{}-{}",
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
    let first = AdmittedCommand {
        origin_sequence: 1,
        command: command(8, 1, b"first"),
    };
    store.admit(&first, ReplicaMembershipEpoch(1)).unwrap();
    let conflicting = AdmittedCommand {
        origin_sequence: 2,
        command: command(8, 1, b"conflict"),
    };
    assert!(
        store
            .admit(&conflicting, ReplicaMembershipEpoch(1))
            .is_err()
    );

    drop(store);

    let reopened = DurableAdmissionStore::open(
        &path,
        SiteId("site-a".to_string()),
        StoreGeneration(1),
        keypair.signer(),
    )
    .unwrap();
    assert!(
        reopened
            .admit(&conflicting, ReplicaMembershipEpoch(1))
            .is_err()
    );
    drop(reopened);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn sharded_batch_admission_is_one_commit_and_binds_complete_membership() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let paths = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            std::env::temp_dir().join(format!(
                "blossom-active-active-batch-{index}-{}-{}",
                std::process::id(),
                keypair.public
            ))
        })
        .collect::<Vec<_>>();
    let stores = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            DurableAdmissionStore::open(
                &paths[index],
                SiteId("site-a".to_string()),
                StoreGeneration(1),
                keypair.signer(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let batch = CommandBatch {
        commands: vec![
            AdmittedCommand {
                origin_sequence: 7,
                command: command(31, 1, b"first"),
            },
            AdmittedCommand {
                origin_sequence: 8,
                command: command(31, 2, b"second"),
            },
        ],
    };
    let mut receipts = Vec::new();
    for store in &stores {
        let before = store.durability_metrics();
        receipts.push(
            store
                .admit_command_batch(b"cache-shard-7".to_vec(), &batch, ReplicaMembershipEpoch(4))
                .unwrap(),
        );
        let after = store.durability_metrics();
        assert_eq!(after.commit_count, before.commit_count + 1);
        assert_eq!(after.fsync_count, before.fsync_count + 1);
    }
    let certificate = LocalAdmissionBatchCertificate {
        policy: LocalAdmissionPolicy {
            site: SiteId("site-a".to_string()),
            membership_epoch: ReplicaMembershipEpoch(4),
            members: keypairs.iter().map(|keypair| keypair.public).collect(),
            store_generations: keypairs
                .iter()
                .map(|keypair| (keypair.public, StoreGeneration(1)))
                .collect(),
        },
        shard: b"cache-shard-7".to_vec(),
        command_batch_hash: batch.hash().unwrap(),
        first_origin_sequence: 7,
        last_origin_sequence: 8,
        command_count: 2,
        receipts,
    };
    certificate.verify_batch(&batch).unwrap();

    let mut wrong_shard = certificate.clone();
    wrong_shard.shard = b"cache-shard-8".to_vec();
    assert!(wrong_shard.verify_batch(&batch).is_err());
    let conflicting = CommandBatch {
        commands: vec![
            batch.commands[0].clone(),
            AdmittedCommand {
                origin_sequence: 8,
                command: command(31, 2, b"conflicting"),
            },
        ],
    };
    assert!(certificate.verify_batch(&conflicting).is_err());

    drop(stores);
    for path in paths {
        std::fs::remove_dir_all(path).ok();
    }
}

#[test]
fn durable_store_reopen_fails_closed_on_identity_and_scope_mismatch() {
    let keypair = Keypair::generate();
    let other = Keypair::generate();
    let path = std::env::temp_dir().join(format!(
        "blossom-active-active-identity-{}-{}",
        std::process::id(),
        keypair.public
    ));
    let store = DurableAdmissionStore::open(
        &path,
        SiteId("site-a".to_string()),
        StoreGeneration(7),
        keypair.signer(),
    )
    .unwrap();
    let batch = batch();
    let reference = reference(&batch, keypair.public);
    let before_store = store.durability_metrics();
    store.store_batch(&reference, &batch).unwrap();
    let metrics = store.durability_metrics();
    assert_eq!(metrics.commit_count, before_store.commit_count + 1);
    assert!(metrics.fsync_count >= metrics.commit_count);
    drop(store);

    assert!(
        DurableAdmissionStore::open(
            &path,
            SiteId("site-b".to_string()),
            StoreGeneration(7),
            keypair.signer(),
        )
        .is_err()
    );
    assert!(
        DurableAdmissionStore::open(
            &path,
            SiteId("site-a".to_string()),
            StoreGeneration(8),
            keypair.signer(),
        )
        .is_err()
    );
    assert!(
        DurableAdmissionStore::open(
            &path,
            SiteId("site-a".to_string()),
            StoreGeneration(7),
            other.signer(),
        )
        .is_err()
    );

    let reopened = DurableAdmissionStore::open(
        &path,
        SiteId("site-a".to_string()),
        StoreGeneration(7),
        keypair.signer(),
    )
    .unwrap();
    let mut wrong_cluster = reference.clone();
    wrong_cluster.cluster_id = HashType([9; 32]);
    assert!(reopened.store_batch(&wrong_cluster, &batch).is_err());
    let mut wrong_group = reference;
    wrong_group.consensus_group_id = ConsensusGroupId::named("wrong-group");
    assert!(reopened.store_batch(&wrong_group, &batch).is_err());
    drop(reopened);
    std::fs::remove_dir_all(path).ok();
}

#[test]
fn legacy_store_without_identity_requires_fresh_initialization() {
    let keypair = Keypair::generate();
    let path = std::env::temp_dir().join(format!(
        "blossom-active-active-legacy-{}-{}.legacy-db",
        std::process::id(),
        keypair.public
    ));
    std::fs::write(&path, b"legacy-database-state").unwrap();

    assert!(
        DurableAdmissionStore::open(
            &path,
            SiteId("site-a".to_string()),
            StoreGeneration(1),
            keypair.signer(),
        )
        .is_err()
    );
    std::fs::remove_file(path).ok();
}

#[test]
fn command_batches_and_application_payloads_are_bounded() {
    let commands = (1..=DEFAULT_MAX_BATCH_COMMANDS + 1)
        .map(|sequence| AdmittedCommand {
            origin_sequence: sequence as u64,
            command: command(
                u8::try_from(sequence % 251).unwrap(),
                sequence as u64,
                b"value",
            ),
        })
        .collect();
    assert!(CommandBatch { commands }.validate().is_err());
    assert!(ApplicationCommand::new(Vec::new()).is_err());
}

#[test]
fn trusted_order_receipt_survives_restart_without_becoming_verified() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let sites = ["site-a", "site-b", "site-c"];
    let paths = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            std::env::temp_dir().join(format!(
                "blossom-trusted-order-restart-{}-{index}-{}",
                std::process::id(),
                keypair.public
            ))
        })
        .collect::<Vec<_>>();
    let stores = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            DurableAdmissionStore::open(
                &paths[index],
                SiteId(sites[index].to_string()),
                StoreGeneration(1),
                keypair.signer(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let batch = CommandBatch {
        commands: vec![AdmittedCommand {
            origin_sequence: 1,
            command: command(12, 1, b"trusted"),
        }],
    };
    let reference = reference(&batch, keypairs[0].public);
    let receipts = stores
        .iter()
        .map(|store| store.store_batch(&reference, &batch).unwrap())
        .collect::<Vec<_>>();
    let holder_membership = HolderMembership {
        epoch: ReplicaMembershipEpoch(3),
        members_by_site: keypairs
            .iter()
            .enumerate()
            .map(|(index, keypair)| {
                (
                    SiteId(sites[index].to_string()),
                    [keypair.public].into_iter().collect(),
                )
            })
            .collect(),
        store_generations: keypairs
            .iter()
            .map(|keypair| (keypair.public, StoreGeneration(1)))
            .collect(),
        holder_fault_bound: 0,
    };
    let validators = keypairs
        .iter()
        .map(|keypair| keypair.public)
        .collect::<BTreeSet<_>>();
    let mut engine = GlobalOrderedEngine::new_with_trust_mode(
        stores[0].clone(),
        ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
        holder_membership.clone(),
        ValidatorGeneration(5),
        validators.clone(),
        TrustMode::Trusted,
        64,
    )
    .unwrap();
    engine
        .mark_available(AvailabilityCertificate {
            reference: reference.clone(),
            trust: AvailabilityTrust::Trusted,
            receipts,
        })
        .unwrap();
    let statement = OrderStatement {
        consensus_group_id: ConsensusGroupId::root(),
        blossom_epoch_hash: HashType([12; 32]),
        position: Watermark { position: 1 },
        reference_hash: reference.hash().unwrap(),
        previous_order_certificate_hash: HashType::default(),
        validator_generation: ValidatorGeneration(5),
    };
    engine.finalize_trusted(statement.clone()).unwrap();
    assert!(
        engine
            .finalized
            .get(&1)
            .is_some_and(|receipt| receipt.signatures.is_empty())
    );
    {
        assert_eq!(
            stores[0]
                .store
                .scan(AVAILABLE_REFERENCES_TABLE)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            stores[0]
                .store
                .scan(FINALIZED_POSITIONS_TABLE)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            stores[0]
                .store
                .scan(POSITION_REFERENCES_TABLE)
                .unwrap()
                .len(),
            1
        );
        assert!(
            stores[0]
                .store
                .get(ORDERED_METADATA_TABLE, ORDERED_METADATA_KEY.as_bytes())
                .unwrap()
                .is_some()
        );
        assert!(
            stores[0]
                .store
                .scan(APPLIED_COMPLETIONS_TABLE)
                .unwrap()
                .is_empty()
        );
    }
    drop(engine);

    let restarted = GlobalOrderedEngine::new_with_trust_mode(
        stores[0].clone(),
        ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
        holder_membership.clone(),
        ValidatorGeneration(5),
        validators.clone(),
        TrustMode::Trusted,
        64,
    )
    .unwrap();
    assert_eq!(
        restarted
            .finalized
            .get(&1)
            .map(|receipt| &receipt.statement),
        Some(&statement)
    );
    let request = ReadBarrierRequest::fresh();
    let statement = restarted.read_barrier_statement(request).unwrap();
    let votes = stores
        .iter()
        .take(2)
        .map(|store| store.sign_read_barrier_statement(&statement).unwrap())
        .collect::<Vec<_>>();
    let barrier = CertifiedReadBarrier {
        request,
        certificate: ReadBarrierCertificate::from_votes(statement, votes).unwrap(),
    };
    assert_eq!(
        restarted.acquire_read_barrier(&barrier).unwrap(),
        Watermark { position: 1 }
    );
    drop(restarted);

    assert!(
        GlobalOrderedEngine::new(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership,
            ValidatorGeneration(5),
            validators,
            64,
        )
        .is_err()
    );
    {
        stores[0]
            .store
            .transaction(|transaction| {
                transaction.remove(FINALIZED_POSITIONS_TABLE, 1u64.to_be_bytes().to_vec())?;
                Ok(())
            })
            .unwrap();
    }
    assert!(
        GlobalOrderedEngine::new_with_trust_mode(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            HolderMembership {
                epoch: ReplicaMembershipEpoch(3),
                members_by_site: keypairs
                    .iter()
                    .enumerate()
                    .map(|(index, keypair)| {
                        (
                            SiteId(sites[index].to_string()),
                            [keypair.public].into_iter().collect(),
                        )
                    })
                    .collect(),
                store_generations: keypairs
                    .iter()
                    .map(|keypair| (keypair.public, StoreGeneration(1)))
                    .collect(),
                holder_fault_bound: 0,
            },
            ValidatorGeneration(5),
            keypairs.iter().map(|keypair| keypair.public).collect(),
            TrustMode::Trusted,
            64,
        )
        .is_err()
    );
    drop(stores);
    for path in paths {
        std::fs::remove_dir_all(path).ok();
    }
}
