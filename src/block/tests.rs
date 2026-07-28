//! Block, transaction, commitment, filtering, and ordering tests.

use super::*;
use crate::crypto::Keypair;
use crate::encounter::{EncounterOutcome, EncounterPhase, EncounterRecord, EncounterRecordBody};

#[cfg(feature = "fair-block-ordering")]
fn sealed_test_block(label: &str, txs: &[&str]) -> Block {
    let mut block = Block::default();
    block.body.created = 42;
    block.body.nonce = Nonce::new(1);
    for tx in txs {
        block
            .body
            .txs
            .push(Transaction::new(format!("{label}:{tx}")));
    }
    block.seal_unsigned(PubKey(HashType::hash(label.as_bytes()).0));
    block
}

#[cfg(feature = "fair-block-ordering")]
fn fair_order_test_blocks(count: usize) -> BTreeMap<HashType, Block> {
    (0..count)
        .map(|index| {
            let txs = (0..=(index % 5))
                .map(|tx_index| format!("tx-{tx_index}"))
                .collect::<Vec<_>>();
            let tx_refs = txs.iter().map(String::as_str).collect::<Vec<_>>();
            let block = sealed_test_block(&format!("block-{index}"), &tx_refs);
            (block.hash, block)
        })
        .collect()
}

#[cfg(feature = "fair-block-ordering")]
fn materialized_fair_block_order_seed(blocks: &BTreeMap<HashType, Block>) -> HashType {
    let transaction_count = fair_order_transaction_count(blocks);
    let modulo = transaction_count.max(1);
    let mut byte_index = 0u64;
    let mut hasher = ProtocolHasher::new();
    hasher.update(FAIR_BLOCK_ORDER_SEED_DOMAIN);
    hasher.update(transaction_count.to_le_bytes());
    hasher.update((blocks.len() as u64).to_le_bytes());
    for (block_hash, block) in blocks {
        let mut block_bytes = Vec::with_capacity(block.fair_order_encoded_len());
        block.append_fair_order_bytes_to(&mut block_bytes);
        update_modulo_seed(&mut hasher, block_hash.as_ref(), modulo, &mut byte_index);
        update_modulo_seed(&mut hasher, &block_bytes, modulo, &mut byte_index);
    }
    hasher.finalize()
}

#[test]
fn block_signature_round_trip() {
    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.txs.push(Transaction::new("tx-1"));
    block.sign(&keypair.secret);

    assert_eq!(block.body.validator, keypair.public);
    assert!(
        block
            .signature
            .verify(block.hash.as_ref(), &keypair.public)
            .is_ok()
    );
    assert!(block.verify_signature().is_ok());
}

#[test]
fn block_can_sign_with_cached_signer() {
    let keypair = Keypair::generate();
    let signer = keypair.signer();
    let mut block = Block::default();
    block.body.txs.push(Transaction::new("tx-1"));
    block.sign_with(&signer);

    assert_eq!(block.body.validator, keypair.public);
    assert!(block.verify_signature().is_ok());
}

#[test]
fn block_body_hash_matches_canonical_bytes() {
    let mut block = Block::default();
    block.set_application_state([1, 2, 3, 4]).unwrap();
    block.body.txs.push(Transaction::new("tx-1"));
    block.body.txs.push(Transaction::new("tx-2"));

    assert_eq!(block.body.hash(), HashType::hash(&block.body.to_bytes()));
    assert_eq!(
        block.body.hash_and_merkle_root().0,
        HashType::hash(&block.body.to_bytes())
    );
    assert_eq!(block.body.encoded_len(), block.body.to_bytes().len());
}

#[test]
fn application_state_is_opaque_bounded_and_hash_committed() {
    let keypair = Keypair::generate();
    let mut block = Block::default();
    block
        .set_application_state(b"v1:cache-pressure=low")
        .unwrap();
    let without_state_hash = Block::default().hash();
    block.sign(&keypair.secret);

    assert_eq!(block.application_state(), b"v1:cache-pressure=low");
    assert_eq!(block.application_state_len(), 21);
    assert_ne!(block.hash, without_state_hash);
    assert!(block.verify_integrity().is_ok());

    let mut tampered = block.clone();
    tampered
        .body
        .set_application_state(b"v1:cache-pressure=high")
        .unwrap();
    assert_eq!(
        tampered.verify_integrity(),
        Err(BlossomError::InvalidBlockHash)
    );
}

#[test]
fn encounter_records_are_signed_and_hash_committed() {
    let observer = Keypair::generate();
    let subject = Keypair::generate();
    let record = EncounterRecord::signed(
        EncounterRecordBody::new(
            observer.public,
            subject.public,
            HashType([4; 32]),
            Nonce::new(2),
            1,
            EncounterPhase::Verification,
            EncounterOutcome::MissingSignature,
        )
        .with_evidence_hash(HashType::hash(b"dispatch timeout")),
        &observer.signer(),
    )
    .unwrap();

    let mut block = Block::default();
    block.body.encounter_records.push(record.clone());
    block.sign(&observer.secret);

    assert!(block.verify_integrity().is_ok());
    assert!(
        block
            .body
            .to_bytes()
            .windows(record.signature.0.len())
            .any(|window| window == record.signature.0.as_slice())
    );

    let without_record_hash = {
        let mut empty = block.clone();
        empty.body.encounter_records.clear();
        empty.seal();
        empty.hash
    };
    assert_ne!(block.hash, without_record_hash);

    let mut tampered = block.clone();
    tampered.body.encounter_records[0].body.outcome = EncounterOutcome::InvalidSignature;
    tampered.set_hash();
    assert_eq!(
        tampered.verify_unsigned_integrity(),
        Err(BlossomError::SignatureError)
    );
}

#[test]
fn encounter_records_must_be_observed_by_block_validator() {
    let observer = Keypair::generate();
    let validator = Keypair::generate();
    let record = EncounterRecord::signed(
        EncounterRecordBody::new(
            observer.public,
            PubKey([8; 32]),
            HashType::default(),
            Nonce::new(1),
            0,
            EncounterPhase::Verification,
            EncounterOutcome::MissingSignature,
        ),
        &observer.signer(),
    )
    .unwrap();

    let mut block = Block::default();
    block.body.encounter_records.push(record);
    block.sign(&validator.secret);

    assert_eq!(block.verify_integrity(), Err(BlossomError::UnknownSender));
}

#[test]
fn application_state_limits_are_enforced() {
    let soft =
        BlockApplicationState::new(vec![0; BLOCK_APPLICATION_STATE_SOFT_LIMIT_BYTES + 1]).unwrap();
    assert!(soft.exceeds_soft_limit());

    let too_large = vec![0; BLOCK_APPLICATION_STATE_MAX_BYTES + 1];
    assert_eq!(
        BlockApplicationState::new(too_large),
        Err(BlossomError::BlockApplicationStateTooLarge {
            max: BLOCK_APPLICATION_STATE_MAX_BYTES,
            actual: BLOCK_APPLICATION_STATE_MAX_BYTES + 1
        })
    );

    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.application_state = BlockApplicationState {
        bytes: vec![0; BLOCK_APPLICATION_STATE_MAX_BYTES + 1],
    };
    block.sign(&keypair.secret);

    assert_eq!(
        block.verify_integrity(),
        Err(BlossomError::BlockApplicationStateTooLarge {
            max: BLOCK_APPLICATION_STATE_MAX_BYTES,
            actual: BLOCK_APPLICATION_STATE_MAX_BYTES + 1
        })
    );
}

#[test]
fn merkle_root_matches_concatenated_transaction_hashes() {
    let mut block = Block::default();
    block.body.txs.push(Transaction::new("tx-1"));
    block.body.txs.push(Transaction::new("tx-2"));
    let expected = HashType::hash(
        &[
            block.body.txs[0].hash.as_ref(),
            block.body.txs[1].hash.as_ref(),
        ]
        .concat(),
    );

    assert_eq!(block.body.compute_merkle_root(), expected);
    assert_eq!(block.body.hash_and_merkle_root().1, expected);
}

#[test]
fn transaction_hash_and_payload_are_stable() {
    let tx = Transaction::new("tx-1");

    assert_eq!(tx.hash, HashType::hash(b"tx-1"));
    assert_eq!(tx.payload(), b"tx-1");
    assert_eq!(tx.payload_len(), 4);
    assert_eq!(tx.to_bytes(), [tx.hash.as_ref(), b"tx-1"].concat());
}

#[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
struct CustomKvPayload {
    version: u16,
    key: Vec<u8>,
    value: Vec<u8>,
}

#[test]
fn transaction_payload_accepts_application_defined_data() {
    let kv = CustomKvPayload {
        version: 1,
        key: b"cache:key".to_vec(),
        value: b"cache-value".to_vec(),
    };

    let tx = Transaction::from_borsh(&kv).unwrap();
    let decoded: CustomKvPayload = tx.payload_as_borsh().unwrap();

    assert_eq!(decoded, kv);
    assert_eq!(tx.hash, HashType::hash(tx.payload()));
    assert_eq!(tx.to_bytes(), [tx.hash.as_ref(), tx.payload()].concat());
}

#[test]
#[cfg(feature = "fair-block-ordering")]
fn fair_order_seed_uses_modulo_transaction_count_and_all_block_bytes() {
    let block_a = sealed_test_block("a", &["tx-1"]);
    let block_b = sealed_test_block("b", &["tx-1"]);
    let block_c = sealed_test_block("c", &["tx-1", "tx-2"]);
    let mut one_block = BTreeMap::new();
    one_block.insert(block_a.hash, block_a.clone());
    let mut two_blocks_same_count = one_block.clone();
    two_blocks_same_count.insert(block_b.hash, block_b);
    let mut two_blocks_more_txs = one_block.clone();
    two_blocks_more_txs.insert(block_c.hash, block_c);

    let one_seed = fair_block_order_seed(&one_block);
    let same_count_seed = fair_block_order_seed(&two_blocks_same_count);
    let more_txs_seed = fair_block_order_seed(&two_blocks_more_txs);
    assert_ne!(one_seed, same_count_seed);
    assert_ne!(same_count_seed, more_txs_seed);

    let one_key = fair_block_order_key(
        one_seed,
        fair_order_transaction_count(&one_block),
        &block_a.hash,
        &block_a,
    );
    let more_txs_key = fair_block_order_key(
        more_txs_seed,
        fair_order_transaction_count(&two_blocks_more_txs),
        &block_a.hash,
        &block_a,
    );
    assert_ne!(one_key, more_txs_key);
}

#[test]
#[cfg(feature = "fair-block-ordering")]
fn fair_order_seed_streaming_matches_materialized_transcript() {
    let blocks = fair_order_test_blocks(24);

    assert_eq!(
        fair_block_order_seed(&blocks),
        materialized_fair_block_order_seed(&blocks)
    );
}

#[test]
#[cfg(feature = "fair-block-ordering")]
fn fair_ordering_is_stable_under_parallel_repeated_reads() {
    use std::sync::Arc;
    use std::thread;

    let blocks = Arc::new(fair_order_test_blocks(48));
    let expected_seed = fair_block_order_seed(&blocks);
    let expected_commitments = fair_ordered_block_commitments(&blocks);
    let handles = (0..8)
        .map(|_| {
            let blocks = Arc::clone(&blocks);
            let expected_commitments = expected_commitments.clone();
            thread::spawn(move || {
                for _ in 0..128 {
                    assert_eq!(fair_block_order_seed(&blocks), expected_seed);
                    assert_eq!(
                        fair_ordered_block_commitments(&blocks),
                        expected_commitments
                    );
                }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
#[cfg(feature = "fair-block-ordering")]
fn fair_ordering_can_reverse_raw_hash_order() {
    let mut found_reversal = false;
    for left_index in 0..64u16 {
        for right_index in (left_index + 1)..128u16 {
            let left = sealed_test_block(&format!("left-{left_index}"), &["tx"]);
            let right = sealed_test_block(&format!("right-{right_index}"), &["tx"]);
            let mut blocks = BTreeMap::new();
            blocks.insert(left.hash, left);
            blocks.insert(right.hash, right);
            let raw_order = blocks.keys().copied().collect::<Vec<_>>();
            let fair_order = fair_ordered_blocks(&blocks)
                .into_iter()
                .map(|(hash, _)| *hash)
                .collect::<Vec<_>>();
            if raw_order != fair_order {
                found_reversal = true;
                break;
            }
        }
        if found_reversal {
            break;
        }
    }

    assert!(found_reversal);
}

#[cfg(feature = "filtered-transactions")]
#[test]
fn filtered_transactions_share_canonical_hash_across_full_and_tombstone_views() {
    let signer = Keypair::generate();
    let target_a = Keypair::generate();
    let target_b = Keypair::generate();
    let non_target = Keypair::generate();
    let payload = b"cached-value-for-targets".to_vec();
    let full = Transaction::filtered_full(
        HashType::hash(b"cache-key"),
        7,
        vec![target_b.public, target_a.public],
        payload.clone(),
        FilteredDeliveryPolicy::Gossip,
    )
    .unwrap();
    let slot = full.filtered_slot().unwrap().clone();
    let tombstone = Transaction::filtered_tombstone(slot.clone()).unwrap();

    let mut expected_targets = vec![target_a.public, target_b.public];
    expected_targets.sort();
    assert_eq!(slot.targets, expected_targets);
    assert!(slot.is_target(&target_a.public));
    assert!(full.is_filtered());
    assert!(!full.is_filtered_tombstone());
    assert!(tombstone.is_filtered_tombstone());
    assert_eq!(full.hash, tombstone.hash);
    assert_eq!(full.to_bytes(), tombstone.to_bytes());
    assert_eq!(full.committed_payload_len(), payload.len() as u64);
    assert_eq!(tombstone.committed_payload_len(), payload.len() as u64);

    let mut full_block = Block::default();
    full_block.body.last_epoch = HashType([1; 32]);
    full_block.body.nonce = Nonce::new(1);
    full_block.body.created = 42;
    full_block.body.txs.push(full);
    full_block.sign(&signer.secret);

    let mut tombstone_block = Block::default();
    tombstone_block.body.last_epoch = HashType([1; 32]);
    tombstone_block.body.nonce = Nonce::new(1);
    tombstone_block.body.created = 42;
    tombstone_block.body.txs.push(tombstone);
    tombstone_block.sign(&signer.secret);

    assert_eq!(full_block.hash, tombstone_block.hash);
    assert_eq!(
        full_block.body.merkle_root,
        tombstone_block.body.merkle_root
    );
    assert!(full_block.verify_integrity().is_ok());
    assert!(tombstone_block.verify_integrity().is_ok());

    let target_view = full_block.materialize_for(&target_a.public);
    assert!(!target_view.body.txs[0].is_filtered_tombstone());
    let non_target_view = full_block.materialize_for(&non_target.public);
    assert!(non_target_view.body.txs[0].is_filtered_tombstone());
    assert_eq!(non_target_view.hash, full_block.hash);
    assert!(non_target_view.verify_integrity().is_ok());

    let mut tampered = full_block;
    tampered.body.txs[0].payload_mut().as_mut_slice()[0] ^= 0xff;
    assert_eq!(
        tampered.verify_integrity(),
        Err(BlossomError::InvalidBlockHash)
    );

    let mut invalid_tombstone = tombstone_block;
    invalid_tombstone.body.txs[0].payload_mut().bytes = b"not-a-tombstone".to_vec();
    assert_eq!(
        invalid_tombstone.verify_integrity(),
        Err(BlossomError::WireProtocol(
            "filtered tombstone cannot carry payload bytes".to_string()
        ))
    );
}

#[cfg(feature = "external-transaction-hashes")]
#[test]
fn external_transaction_hashes_are_supported_and_block_committed() {
    let external_hash = 0x1122_3344_5566_7788;
    let tx = Transaction::from_external_hash_u64(external_hash, b"kv-payload".to_vec());

    assert_eq!(&tx.hash.as_ref()[..8], &external_hash.to_le_bytes());
    assert_eq!(&tx.hash.as_ref()[8..], &[0; 24]);
    assert_ne!(tx.hash, HashType::hash(tx.payload()));

    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.last_epoch = HashType([1; 32]);
    block.body.nonce = Nonce::new(1);
    block.body.txs.push(tx);
    block.sign(&keypair.secret);

    assert!(block.verify_integrity().is_ok());

    let mut tampered = block.clone();
    tampered.body.txs[0].payload_mut().as_mut_slice()[0] ^= 0xff;
    assert_eq!(
        tampered.verify_integrity(),
        Err(BlossomError::InvalidBlockHash)
    );

    let mut tampered = block;
    tampered.body.txs[0].hash = HashType([9; 32]);
    assert_eq!(
        tampered.verify_integrity(),
        Err(BlossomError::InvalidBlockHash)
    );
}

#[test]
fn signed_block_integrity_rejects_hash_merkle_and_signature_tampering() {
    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.txs.push(Transaction::new("tx-1"));
    block.sign(&keypair.secret);
    assert!(block.verify_integrity().is_ok());
    assert!(block.verify_integrity_with_hash(block.hash).is_ok());
    assert_eq!(
        block.verify_integrity_with_hash(HashType([6; 32])),
        Err(crate::error::BlossomError::InvalidBlockHash)
    );

    let mut tampered_hash = block.clone();
    tampered_hash.hash = HashType([9; 32]);
    assert_eq!(
        tampered_hash.verify_integrity(),
        Err(crate::error::BlossomError::InvalidBlockHash)
    );

    let mut tampered_merkle = block.clone();
    tampered_merkle.body.merkle_root = HashType([8; 32]);
    tampered_merkle.set_hash();
    assert_eq!(
        tampered_merkle.verify_integrity(),
        Err(crate::error::BlossomError::InvalidBlockHash)
    );

    let mut tampered_signature = block;
    tampered_signature.signature = Signature([7; 64]);
    assert_eq!(
        tampered_signature.verify_integrity(),
        Err(crate::error::BlossomError::SignatureError)
    );
}

#[test]
fn unsigned_sealed_block_preserves_hash_and_merkle_integrity() {
    let keypair = Keypair::generate();
    let mut block = Block::default();
    block.body.txs.push(Transaction::new("tx-1"));
    block.seal_unsigned(keypair.public);

    assert_eq!(block.body.validator, keypair.public);
    assert_eq!(block.signature, Signature::default());
    assert!(block.verify_unsigned_integrity().is_ok());
    assert_eq!(
        block.verify_integrity(),
        Err(crate::error::BlossomError::SignatureError)
    );

    let mut tampered = block;
    tampered.body.txs.push(Transaction::new("tx-2"));
    assert_eq!(
        tampered.verify_unsigned_integrity(),
        Err(crate::error::BlossomError::InvalidBlockHash)
    );
}

#[test]
fn empty_with_nonce_sets_nonce_and_hash() {
    let block = Block::empty_with_nonce(Nonce::new(9));

    assert_eq!(block.body.nonce, Nonce::new(9));
    assert_eq!(block.hash, block.hash());
    assert!(block.is_empty());
    assert_eq!(block.len(), 0);
}
