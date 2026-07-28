//! Trusted-direct ordering and application-contract tests.

use super::*;

#[test]
fn trusted_epoch_finalizes_all_writer_references_in_btree_block_order() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let sites = ["site-a", "site-b", "site-c"];
    let paths = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            std::env::temp_dir().join(format!(
                "blossom-trusted-parallel-writers-{}-{index}-{}",
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

    let mut blocks = BTreeMap::new();
    for (index, keypair) in keypairs.iter().enumerate() {
        let batch = CommandBatch {
            commands: vec![AdmittedCommand {
                origin_sequence: 1,
                command: command(20 + index as u8, 1, &[index as u8]),
            }],
        };
        let reference = reference(&batch, keypair.public);
        let receipts = stores
            .iter()
            .map(|store| store.store_batch(&reference, &batch).unwrap())
            .collect();
        engine
            .mark_available(AvailabilityCertificate {
                reference: reference.clone(),
                trust: AvailabilityTrust::Trusted,
                receipts,
            })
            .unwrap();
        let mut block = Block::default();
        block.body.txs.push(reference.to_transaction().unwrap());
        block.seal_unsigned(keypair.public);
        blocks.insert(block.hash, block);
    }
    let mut verifiers = IndexTreeMap::new();
    for (index, keypair) in keypairs.iter().enumerate() {
        verifiers.insert(
            keypair.public,
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                "127.0.0.1",
                9000 + index as u16,
                false,
            ),
        );
    }
    let mut epoch = Epoch {
        hash: HashType::default(),
        signatures: BTreeMap::new(),
        body: EpochBody {
            group_id: ConsensusGroupId::root(),
            nonce: Nonce::new(1),
            previous_nonce: Some(Nonce::new(0)),
            verifiers,
            blocks,
            consensus_parameters: Some(ConsensusParameters::default()),
            ..EpochBody::default()
        },
    };
    epoch.set_hash();
    let expected_hashes = ordered_batch_references_trusted(&epoch)
        .unwrap()
        .iter()
        .map(BatchReference::hash)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let generic_ordered_transactions = epoch.trusted_ordered_transactions().unwrap();
    assert_eq!(generic_ordered_transactions.len(), 3);
    assert_eq!(
        generic_ordered_transactions
            .iter()
            .map(|ordered| {
                BatchReference::from_transaction(&ordered.transaction)
                    .unwrap()
                    .unwrap()
                    .hash()
                    .unwrap()
            })
            .collect::<Vec<_>>(),
        expected_hashes
    );

    let events = engine.finalize_trusted_epoch(&epoch).unwrap();

    assert_eq!(events.len(), 3);
    assert_eq!(
        events
            .iter()
            .map(|event| event.reference_hash)
            .collect::<Vec<_>>(),
        expected_hashes
    );
    assert_eq!(
        events
            .iter()
            .map(|event| event.watermark.unwrap().position)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(
        engine
            .finalized
            .values()
            .all(|receipt| receipt.signatures.is_empty())
    );
    let milestone_count = engine.store.milestones().unwrap().len();
    let replayed_events = engine.finalize_trusted_epoch(&epoch).unwrap();
    assert_eq!(
        replayed_events
            .iter()
            .map(|event| (event.reference_hash, event.milestone, event.watermark))
            .collect::<Vec<_>>(),
        events
            .iter()
            .map(|event| (event.reference_hash, event.milestone, event.watermark))
            .collect::<Vec<_>>()
    );
    assert_eq!(engine.last_finalized_position, 3);
    assert_eq!(engine.store.milestones().unwrap().len(), milestone_count);
    let mut application = RecordingApplication::default();
    assert!(matches!(
        engine
            .apply_through_to(Watermark { position: 3 }, &mut application)
            .unwrap(),
        ApplyProgress::Applied {
            watermark: Watermark { position: 3 },
            completions
        } if completions.len() == 3
    ));

    let activation = engine
        .activate_application_contract(RouteGeneration(2), CommandSpecVersion(3))
        .unwrap();
    assert_eq!(activation.activated_at, Watermark { position: 3 });
    drop(engine);
    assert!(
        GlobalOrderedEngine::new_with_trust_mode(
            stores[0].clone(),
            ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
            holder_membership.clone(),
            ValidatorGeneration(5),
            validators.clone(),
            TrustMode::Trusted,
            64,
        )
        .is_err()
    );
    let upgraded = GlobalOrderedEngine::new_with_application_contract(
        stores[0].clone(),
        ActiveActiveConsistencyMode::ActiveSyncGlobalOrdered,
        holder_membership,
        ValidatorGeneration(5),
        validators,
        TrustMode::Trusted,
        RouteGeneration(2),
        CommandSpecVersion(3),
    )
    .unwrap();
    assert_eq!(upgraded.route_generation(), RouteGeneration(2));
    assert_eq!(upgraded.command_spec_version(), CommandSpecVersion(3));
    drop(upgraded);
    drop(stores);
    for path in paths {
        std::fs::remove_dir_all(path).ok();
    }
}
