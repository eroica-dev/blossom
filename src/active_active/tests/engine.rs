//! Global ordering, application, completion, and read-barrier tests.

use super::*;

#[test]
fn availability_must_precede_finality_and_application_uses_certified_order() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let sites = ["site-a", "site-b", "site-c"];
    let paths = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            std::env::temp_dir().join(format!(
                "blossom-global-order-{}-{index}-{}",
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
            command: command(9, 1, b"globally-ordered"),
        }],
    };
    let reference = reference(&batch, keypairs[0].public);
    let receipts = stores
        .iter()
        .map(|store| store.store_batch(&reference, &batch).unwrap())
        .collect::<Vec<_>>();
    let members_by_site = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            (
                SiteId(sites[index].to_string()),
                [keypair.public].into_iter().collect(),
            )
        })
        .collect();
    let holder_membership = HolderMembership {
        epoch: ReplicaMembershipEpoch(3),
        members_by_site,
        store_generations: keypairs
            .iter()
            .map(|keypair| (keypair.public, StoreGeneration(1)))
            .collect(),
        holder_fault_bound: 0,
    };
    let availability = AvailabilityCertificate {
        reference: reference.clone(),
        trust: AvailabilityTrust::Trusted,
        receipts,
    };
    availability.verify(&holder_membership).unwrap();

    let validators = keypairs
        .iter()
        .map(|keypair| keypair.public)
        .collect::<BTreeSet<_>>();
    let mut engine = GlobalOrderedEngine::new(
        stores[0].clone(),
        ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
        holder_membership.clone(),
        ValidatorGeneration(5),
        validators.clone(),
        64,
    )
    .unwrap();
    let statement = OrderStatement {
        consensus_group_id: ConsensusGroupId::root(),
        blossom_epoch_hash: HashType([7; 32]),
        position: Watermark { position: 1 },
        reference_hash: reference.hash().unwrap(),
        previous_order_certificate_hash: HashType::default(),
        validator_generation: ValidatorGeneration(5),
    };
    let votes = stores
        .iter()
        .take(2)
        .map(|store| store.sign_order_statement(&statement).unwrap())
        .collect::<Vec<_>>();
    let certificate = OrderCertificate::from_votes(statement.clone(), votes).unwrap();
    let mut conflicting_statement = statement;
    conflicting_statement.reference_hash = HashType([99; 32]);
    assert!(
        stores[0]
            .sign_order_statement(&conflicting_statement)
            .is_err()
    );

    assert!(engine.finalize(certificate.clone()).is_err());
    engine.mark_available(availability).unwrap();
    assert_eq!(
        engine.last_origin_reference.get(&(
            reference.origin,
            reference.origin_incarnation,
            reference.origin_key_generation,
        )),
        Some(&(reference.hash().unwrap(), reference.last_origin_sequence))
    );
    let successor_batch = CommandBatch {
        commands: vec![AdmittedCommand {
            origin_sequence: 2,
            command: command(9, 2, b"successor"),
        }],
    };
    let successor_reference = BatchReference::for_batch(
        &successor_batch,
        BatchReferenceMetadata {
            cluster_id: HashType([1; 32]),
            consensus_group_id: ConsensusGroupId::root(),
            shard: b"shard-0".to_vec(),
            route_generation: RouteGeneration(1),
            command_spec_version: CommandSpecVersion(1),
            origin: keypairs[0].public,
            origin_incarnation: 1,
            origin_key_generation: 1,
            data_holder_membership_epoch: ReplicaMembershipEpoch(3),
            validator_generation: ValidatorGeneration(5),
            previous_origin_reference_hash: reference.hash().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(
        successor_reference.previous_origin_reference_hash,
        reference.hash().unwrap()
    );
    assert_eq!(
        successor_reference.first_origin_sequence,
        reference.last_origin_sequence + 1
    );
    let successor_receipts = stores
        .iter()
        .map(|store| {
            store
                .store_batch(&successor_reference, &successor_batch)
                .unwrap()
        })
        .collect();
    engine
        .mark_available(AvailabilityCertificate {
            reference: successor_reference.clone(),
            trust: AvailabilityTrust::Trusted,
            receipts: successor_receipts,
        })
        .unwrap();
    let successor_statement = OrderStatement {
        consensus_group_id: ConsensusGroupId::root(),
        blossom_epoch_hash: HashType([8; 32]),
        position: Watermark { position: 1 },
        reference_hash: successor_reference.hash().unwrap(),
        previous_order_certificate_hash: HashType::default(),
        validator_generation: ValidatorGeneration(5),
    };
    let successor_signing_bytes = OrderCertificate::signing_bytes(&successor_statement).unwrap();
    let successor_certificate = OrderCertificate {
        statement: successor_statement,
        signatures: keypairs
            .iter()
            .take(2)
            .map(|keypair| {
                (
                    keypair.public,
                    keypair.signer().sign(&successor_signing_bytes),
                )
            })
            .collect(),
    };
    assert!(
        engine.finalize(successor_certificate).is_err(),
        "an origin successor cannot finalize before its predecessor"
    );
    engine.finalize(certificate.clone()).unwrap();
    engine.finalize(certificate).unwrap();
    let retention = RetentionEvidence {
        durable_snapshot_watermark: Watermark { position: 1 },
        applied_by: AppliedBy {
            membership_snapshot: ReplicaMembershipEpoch(3),
            required_nodes: [stores[0].holder].into_iter().collect(),
            watermark: Watermark { position: 1 },
        },
    };
    assert!(
        stores[0]
            .collect_batch(&reference, Watermark { position: 1 }, &retention)
            .unwrap()
    );
    let mut application = RecordingApplication::default();
    assert!(matches!(
        engine.apply_contiguous_to(&mut application).unwrap(),
        ApplyProgress::HeadOfLineUnavailable {
            watermark: Watermark { position: 0 },
            blocked_reference,
        } if blocked_reference == reference.hash().unwrap()
    ));
    stores[0].repair_batch_from(&stores[1], &reference).unwrap();
    assert!(engine.apply_contiguous_to(&mut FailingApplication).is_err());
    assert!(
        engine
            .apply_contiguous_to(&mut DivergentApplication)
            .is_err()
    );
    assert_eq!(engine.applied_watermark(), Watermark::default());

    let reference_hash = reference.hash().unwrap();
    assert!(matches!(
        engine
            .complete_write(
                reference_hash,
                WriteMode::GlobalApplied,
                Duration::from_millis(10),
                &mut application,
            )
            .unwrap(),
        WaitForOutcome::Reached(ReferenceStatus::Applied(AppliedCompletion {
            watermark: Watermark { position: 1 },
            ..
        }))
    ));
    engine
        .satisfy_read_consistency_to(ReadConsistency::Local, None, &mut application)
        .unwrap();
    assert_eq!(
        application.values.get(b"key".as_slice()),
        Some(&b"globally-ordered".to_vec())
    );
    assert!(matches!(
        engine.status(reference_hash).unwrap(),
        ReferenceStatus::Applied(AppliedCompletion {
            watermark: Watermark { position: 1 },
            ..
        })
    ));
    assert!(matches!(
        engine
            .wait_for(reference_hash, Milestone::Applied, Duration::from_millis(1))
            .unwrap(),
        WaitForOutcome::Reached(ReferenceStatus::Applied(_))
    ));
    assert!(matches!(
        engine
            .wait_for(
                HashType([0xEE; 32]),
                Milestone::Applied,
                Duration::from_millis(1)
            )
            .unwrap(),
        WaitForOutcome::TimedOut(ReferenceStatus::Unknown)
    ));

    drop(engine);
    let mut restarted = GlobalOrderedEngine::new(
        stores[0].clone(),
        ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
        holder_membership.clone(),
        ValidatorGeneration(5),
        validators.clone(),
        64,
    )
    .unwrap();
    assert_eq!(restarted.applied_watermark(), Watermark { position: 1 });
    assert!(matches!(
        restarted.apply_contiguous_to(&mut application).unwrap(),
        ApplyProgress::Applied {
            watermark: Watermark { position: 1 },
            completions
        } if completions.is_empty()
    ));
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
        restarted
            .satisfy_read_consistency_to(
                ReadConsistency::Linearizable,
                Some(&barrier),
                &mut application,
            )
            .unwrap(),
        Watermark { position: 1 }
    );
    let mut replayed_with_different_request = barrier;
    replayed_with_different_request.request = ReadBarrierRequest::fresh();
    assert!(
        restarted
            .satisfy_read_consistency_to(
                ReadConsistency::Linearizable,
                Some(&replayed_with_different_request),
                &mut application,
            )
            .is_err()
    );
    drop(restarted);
    drop(stores);
    for path in paths {
        std::fs::remove_dir_all(path).ok();
    }
}
