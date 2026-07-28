//! Command, reference, certificate, and generation model tests.

use super::*;

#[test]
fn reference_commits_canonical_batch_with_sha256_merkle_root() {
    let keypair = Keypair::generate();
    let batch = batch();
    let reference = reference(&batch, keypair.public);

    reference.verify_batch(&batch).unwrap();
    let transaction = reference.to_transaction().unwrap();
    assert_eq!(
        BatchReference::from_transaction(&transaction).unwrap(),
        Some(reference.clone())
    );
    assert!(
        BatchReference::from_transaction(&Transaction::new(b"unrelated".to_vec()))
            .unwrap()
            .is_none()
    );
    let mut modified = batch;
    modified.commands[0].command = command(1, 10, b"different");
    assert!(reference.verify_batch(&modified).is_err());

    let mut rerouted = reference.clone();
    rerouted.route_generation = RouteGeneration(2);
    assert_ne!(reference.hash().unwrap(), rerouted.hash().unwrap());
    let mut upgraded_spec = reference.clone();
    upgraded_spec.command_spec_version = CommandSpecVersion(2);
    assert_ne!(reference.hash().unwrap(), upgraded_spec.hash().unwrap());
    let mut legacy = reference;
    legacy.format_version = 1;
    legacy.codec_version = 1;
    assert!(legacy.validate().is_err());
}

#[test]
fn finalized_blossom_epoch_certifies_reference_transaction_order() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let batch = batch();
    let reference = reference(&batch, keypairs[0].public);
    let mut block = Block::default();
    block.body.txs.push(reference.to_transaction().unwrap());
    block.sign_with(&keypairs[0].signer());

    let mut verifiers = IndexTreeMap::new();
    for (index, keypair) in keypairs.iter().enumerate() {
        verifiers.insert(
            keypair.public,
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                "127.0.0.1",
                8000 + index as u16,
                false,
            ),
        );
    }
    let mut epoch = Epoch {
        hash: HashType::default(),
        signatures: BTreeMap::new(),
        body: EpochBody {
            group_id: ConsensusGroupId::root(),
            verifiers,
            blocks: BTreeMap::from([(block.hash, block)]),
            consensus_parameters: Some(ConsensusParameters::default()),
            ..EpochBody::default()
        },
    };
    epoch.set_hash();
    for index in 0..2 {
        let validator = *epoch.body.verifiers.get_key_from_index(index).unwrap();
        let keypair = keypairs
            .iter()
            .find(|keypair| keypair.public == validator)
            .unwrap();
        epoch
            .signatures
            .insert(index, keypair.signer().sign(epoch.hash.as_ref()));
    }

    assert_eq!(
        ordered_batch_references(&epoch).unwrap(),
        vec![reference.clone()]
    );
    epoch.signatures.clear();
    assert!(ordered_batch_references(&epoch).is_err());
    assert_eq!(
        ordered_batch_references_trusted(&epoch).unwrap(),
        vec![reference]
    );
}

#[test]
fn command_envelopes_are_opaque_and_bounded() {
    let opaque = command(1, 1, b"value");
    assert!(opaque.validate().is_ok());
    assert_eq!(
        borsh::from_slice::<TestCommand>(opaque.command.as_bytes())
            .unwrap()
            .value,
        b"value"
    );
    assert!(ApplicationCommand::new(Vec::new()).is_err());
}

#[test]
fn write_mode_is_independent_of_application_semantics() {
    assert_eq!(
        WriteMode::LocalAsync.required_milestone(),
        Milestone::AcceptedLocal
    );
    assert_eq!(
        WriteMode::GlobalFinalized.required_milestone(),
        Milestone::Finalized
    );
    assert_eq!(
        WriteMode::GlobalApplied.required_milestone(),
        Milestone::Applied
    );
    assert!(Milestone::Applied.is_terminal());
}

#[test]
fn applied_by_uses_a_frozen_replica_set() {
    let nodes = [PubKey([1; 32]), PubKey([2; 32])]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut tracker = AppliedByTracker::new(ReplicaMembershipEpoch(7), nodes.clone()).unwrap();
    tracker
        .observe(PubKey([1; 32]), Watermark { position: 9 })
        .unwrap();
    assert!(tracker.reached(Watermark { position: 9 }).is_none());
    tracker
        .observe(PubKey([2; 32]), Watermark { position: 9 })
        .unwrap();
    assert_eq!(
        tracker.reached(Watermark { position: 9 }).unwrap(),
        AppliedBy {
            membership_snapshot: ReplicaMembershipEpoch(7),
            required_nodes: nodes,
            watermark: Watermark { position: 9 },
        }
    );
}
