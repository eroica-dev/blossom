//! Filtered-payload availability and gossip integration tests.

use super::*;

#[test]
fn genesis_epoch_group_id_is_hash_committed() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                "127.0.0.1",
                8000 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let root = genesis_epoch(nodes.clone());
    let subnet = genesis_epoch_for_group(ConsensusGroupId::named("cache-hotset-a"), nodes);

    assert_eq!(root.body.group_id, ConsensusGroupId::root());
    assert_eq!(
        subnet.body.group_id,
        ConsensusGroupId::named("cache-hotset-a")
    );
    assert_ne!(root.hash, subnet.hash);
}

#[test]
fn parallel_groups_keep_targets_and_application_state_separate() {
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
                8000 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();

    let root_genesis = genesis_epoch(nodes.clone());
    let subnet_id = ConsensusGroupId::named("cache-hotset-a");
    let subnet_genesis = genesis_epoch_for_group(subnet_id, nodes[..3].to_vec());
    assert_ne!(root_genesis.hash, subnet_genesis.hash);

    let mut root_config = RuntimeConfig::new(nodes[0].clone());
    root_config.genesis = Some(root_genesis.clone());
    let root_runtime = NodeRuntime::new(root_config);

    let mut subnet_config = RuntimeConfig::new(nodes[0].clone());
    subnet_config.group_id = subnet_id;
    subnet_config.genesis = Some(subnet_genesis.clone());
    let subnet_runtime = NodeRuntime::new(subnet_config);

    root_runtime.set_application_state(b"root-visible").unwrap();
    subnet_runtime
        .set_application_state(b"subnet-visible")
        .unwrap();

    let root_target = root_runtime.next_epoch_target().unwrap();
    let subnet_target = subnet_runtime.next_epoch_target().unwrap();
    assert_ne!(root_target.last_epoch, subnet_target.last_epoch);

    let root_dispatch = root_runtime.dispatch_local_block(0).unwrap();
    let subnet_dispatch = subnet_runtime.dispatch_local_block(0).unwrap();
    let root_block = root_dispatch.body.blocks.values().next().unwrap();
    let subnet_block = subnet_dispatch.body.blocks.values().next().unwrap();

    assert_eq!(root_block.application_state(), b"root-visible");
    assert_eq!(subnet_block.application_state(), b"subnet-visible");
    assert_eq!(root_dispatch.header.last_epoch, root_target.last_epoch);
    assert_eq!(subnet_dispatch.header.last_epoch, subnet_target.last_epoch);
    assert!(matches!(
        subnet_runtime.receive_message(Msg::Dispatch(root_dispatch.clone())),
        Err(BlossomError::WireProtocol(message))
            if message.contains("unknown consensus epoch")
    ));

    let multi = MultiGroupRuntime::with_groups(root_runtime.clone(), [subnet_runtime.clone()]);
    assert_eq!(multi.root_group(), ConsensusGroupId::root());
    assert_eq!(multi.len(), 2);
    assert_eq!(multi.group(&subnet_id).unwrap().group_id(), subnet_id);
    assert_eq!(
        multi
            .group_for_epoch(&subnet_target.last_epoch)
            .unwrap()
            .group_id(),
        subnet_id
    );
}

#[cfg(feature = "availability-gossip")]
#[test]
fn availability_gossip_fetches_filtered_payload_for_targets() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let genesis_nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                "127.0.0.1",
                8000 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(genesis_nodes);

    let runtime_for = |index: usize| {
        let node = NodeIdentity::new(
            keypairs[index].public,
            Some(keypairs[index].secret.clone()),
            "tcp",
            "127.0.0.1",
            8000 + index as u16,
            false,
        );
        let mut config = RuntimeConfig::new(node);
        config.genesis = Some(genesis.clone());
        NodeRuntime::new(config)
    };
    let holder = runtime_for(0);
    let target = runtime_for(1);
    let outsider = runtime_for(2);

    let payload = b"stable-kvcache-value".to_vec();
    let tx = crate::Transaction::filtered_full(
        HashType::hash(b"stable-cache-key"),
        1,
        vec![target.self_node().public_key()],
        payload.clone(),
        crate::FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    let slot = tx.filtered_slot().unwrap().clone();
    let entry = holder
        .store_filtered_payload_from_transaction(&tx)
        .unwrap()
        .unwrap();

    let gossip = holder.availability_gossip().unwrap();
    let receipt = target.receive_availability_gossip(gossip).unwrap();
    assert_eq!(receipt.entries_accepted, 1);
    assert_eq!(target.peer_availability_entries().len(), 1);

    let fetch = target
        .filtered_payload_fetch(entry.slot_hash, slot.payload_commitment)
        .unwrap();
    let delivery = holder
        .serve_filtered_payload_fetch(fetch)
        .unwrap()
        .expect("holder should return filtered payload");
    assert_eq!(delivery.body.payload, payload);
    target.receive_filtered_payload(delivery).unwrap();
    assert_eq!(target.local_availability_entries().len(), 1);

    let outsider_fetch = outsider
        .filtered_payload_fetch(entry.slot_hash, slot.payload_commitment)
        .unwrap();
    assert!(matches!(
        holder.serve_filtered_payload_fetch(outsider_fetch),
        Err(BlossomError::WireProtocol(message)) if message.contains("not authorized")
    ));
}

#[cfg(feature = "availability-gossip")]
#[test]
fn trusted_batch_gossip_still_rejects_unknown_fetch_requesters() {
    let (holder, _, _) = runtime_with_peers_mode(TrustMode::Trusted);
    let unknown = Keypair::generate();

    let payload = b"private-cache-value".to_vec();
    let tx = crate::Transaction::filtered_full(
        HashType::hash(b"private-cache-key"),
        1,
        vec![holder.self_node().public_key()],
        payload,
        crate::FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    let slot = tx.filtered_slot().unwrap().clone();
    let entry = holder
        .store_filtered_payload_from_transaction(&tx)
        .unwrap()
        .unwrap();
    let fetch = FilteredPayloadBatchFetch::trusted(FilteredPayloadBatchFetchBody {
        scope: holder.group_id(),
        requester: unknown.public,
        requests: vec![FilteredPayloadRequest::new(
            entry.slot_hash,
            slot.payload_commitment,
        )],
    })
    .unwrap();

    assert!(matches!(
        holder.serve_filtered_payload_batch_fetch(fetch),
        Err(BlossomError::UnknownSender)
    ));
}

#[cfg(feature = "availability-gossip")]
#[test]
fn trusted_batch_delivery_still_rejects_unauthorized_targets_and_tampering() {
    let (target, keypairs, _) = runtime_with_peers_mode(TrustMode::Trusted);
    let authorized_peer = keypairs[1].public;
    let holder_peer = keypairs[2].public;

    let payload = b"authorized-only-value".to_vec();
    let tx = crate::Transaction::filtered_full(
        HashType::hash(b"authorized-only-key"),
        1,
        vec![authorized_peer],
        payload.clone(),
        crate::FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    let slot = tx.filtered_slot().unwrap().clone();
    let delivery = FilteredPayloadBatchDelivery::trusted(FilteredPayloadBatchDeliveryBody {
        scope: target.group_id(),
        holder: holder_peer,
        items: vec![FilteredPayloadDeliveryItem {
            slot_hash: slot.hash(),
            slot: slot.clone(),
            payload: payload.clone(),
        }],
    })
    .unwrap();

    assert!(matches!(
        target.receive_filtered_payload_batch(delivery),
        Err(BlossomError::WireProtocol(message)) if message.contains("not a target")
    ));

    let tx = crate::Transaction::filtered_full(
        HashType::hash(b"tamper-key"),
        1,
        vec![target.self_node().public_key()],
        b"original-value".to_vec(),
        crate::FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    let slot = tx.filtered_slot().unwrap().clone();
    let mut delivery = FilteredPayloadBatchDelivery::trusted(FilteredPayloadBatchDeliveryBody {
        scope: target.group_id(),
        holder: holder_peer,
        items: vec![FilteredPayloadDeliveryItem {
            slot_hash: slot.hash(),
            slot,
            payload: b"original-value".to_vec(),
        }],
    })
    .unwrap();
    delivery.body.items[0].payload = b"tampered-value".to_vec();

    assert!(matches!(
        target.receive_filtered_payload_batch(delivery),
        Err(BlossomError::InvalidBlockHash)
    ));
}

#[cfg(feature = "availability-gossip")]
#[test]
fn duplicate_gossip_is_idempotent_for_peer_availability() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let genesis_nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                "127.0.0.1",
                8100 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(genesis_nodes);
    let runtime_for = |index: usize| {
        let node = NodeIdentity::new(
            keypairs[index].public,
            Some(keypairs[index].secret.clone()),
            "tcp",
            "127.0.0.1",
            8100 + index as u16,
            false,
        );
        let mut config = RuntimeConfig::new(node);
        config.genesis = Some(genesis.clone());
        NodeRuntime::new(config)
    };
    let holder = runtime_for(0);
    let target = runtime_for(1);

    let tx = crate::Transaction::filtered_full(
        HashType::hash(b"duplicate-gossip-key"),
        1,
        vec![target.self_node().public_key()],
        b"duplicate-gossip-value".to_vec(),
        crate::FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    holder
        .store_filtered_payload_from_transaction(&tx)
        .unwrap()
        .unwrap();
    let gossip = holder.availability_gossip().unwrap();

    assert_eq!(
        target
            .receive_availability_gossip(gossip.clone())
            .unwrap()
            .entries_accepted,
        1
    );
    assert_eq!(
        target
            .receive_availability_gossip(gossip)
            .unwrap()
            .entries_accepted,
        1
    );
    assert_eq!(target.peer_availability_entries().len(), 1);
}

#[cfg(feature = "availability-gossip")]
#[test]
fn stale_availability_metadata_returns_empty_batch_delivery() {
    let keypairs = (0..3).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let genesis_nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                None,
                "tcp",
                "127.0.0.1",
                8200 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(genesis_nodes);
    let runtime_for = |index: usize| {
        let node = NodeIdentity::new(
            keypairs[index].public,
            Some(keypairs[index].secret.clone()),
            "tcp",
            "127.0.0.1",
            8200 + index as u16,
            false,
        );
        let mut config = RuntimeConfig::new(node);
        config.genesis = Some(genesis.clone());
        NodeRuntime::new(config)
    };
    let holder = runtime_for(0);
    let target = runtime_for(1);

    let tx = crate::Transaction::filtered_full(
        HashType::hash(b"stale-gossip-key"),
        1,
        vec![target.self_node().public_key()],
        b"stale-gossip-value".to_vec(),
        crate::FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    let slot = tx.filtered_slot().unwrap().clone();
    let entry = AvailabilityEntry::new(slot.clone()).unwrap();
    let gossip = AvailabilityGossip::signed(
        AvailabilityGossipBody {
            scope: holder.group_id(),
            holder: holder.self_node().public_key(),
            entries: vec![entry.clone()],
        },
        &keypairs[0].signer(),
    )
    .unwrap();

    target.receive_availability_gossip(gossip).unwrap();
    let fetch = target
        .filtered_payload_batch_fetch(vec![FilteredPayloadRequest::new(
            entry.slot_hash,
            slot.payload_commitment,
        )])
        .unwrap();
    let delivery = holder.serve_filtered_payload_batch_fetch(fetch).unwrap();

    assert!(delivery.body.items.is_empty());
}
