//! Trusted epoch-log durability, locking, and recovery tests.

use super::*;
use crate::blossom::{Header, VerificationBody};
use crate::crypto::{Keypair, Signature};
use crate::node::NodeIdentity;
use crate::state::EpochBody;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

const NO_FAULT: u8 = 0;
const STORAGE_FULL: u8 = 1;
const SYNC_FAILURE: u8 = 2;
static NEXT_TEST_STORAGE_ID: AtomicU64 = AtomicU64::new(0);

fn unique_test_path(prefix: &str) -> std::path::PathBuf {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let sequence = NEXT_TEST_STORAGE_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{timestamp}-{sequence}",
        std::process::id()
    ))
}

fn nodes(count: usize) -> Vec<NodeIdentity> {
    (0..count)
        .map(|index| {
            let keypair = Keypair::generate();
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8_000 + index as u16,
                false,
            )
        })
        .collect()
}

fn next_epoch(previous: &Epoch) -> Epoch {
    next_epoch_with_blocks(previous, BTreeMap::new())
}

fn next_epoch_with_blocks(previous: &Epoch, blocks: BTreeMap<HashType, Block>) -> Epoch {
    let (verifiers, _) = apply_epoch_membership_transition(
        &previous.body.verifiers,
        &blocks,
        previous.hash,
        previous.body.nonce.new_next(),
        ConsensusNodeRemovalPolicy::disabled(),
    );
    let mut epoch = Epoch {
        hash: HashType::default(),
        signatures: BTreeMap::new(),
        body: EpochBody {
            group_id: previous.body.group_id,
            verifiers,
            members: previous.body.members.clone(),
            last_epoch: previous.hash,
            previous_nonce: Some(previous.body.nonce),
            nonce: previous.body.nonce.new_next(),
            merkle_root: block_merkle_root(&blocks),
            blocks,
            consensus_parameters: Some(previous.body.effective_consensus_parameters()),
        },
    };
    epoch.set_hash();
    epoch
}

fn seed_chain() -> (EpochChain, Vec<NodeIdentity>) {
    let identities = nodes(6);
    (
        EpochChain {
            epochchain: vec![crate::runtime::genesis_epoch(identities.clone())],
        },
        identities,
    )
}

fn trusted_block(previous: &Epoch, writer: PubKey, payload: &str) -> Block {
    let mut block = Block::default();
    block.body.last_epoch = previous.hash;
    block.body.nonce = previous.body.nonce.new_next();
    block.body.txs.push(crate::block::Transaction::new(payload));
    block.seal_unsigned(writer);
    block
}

fn round_lock(chain: &EpochChain, self_public_key: PubKey) -> TrustedRoundLock {
    round_lock_with_blocks(chain, self_public_key, 0, BTreeMap::new())
}

fn round_lock_with_blocks(
    chain: &EpochChain,
    self_public_key: PubKey,
    round: u8,
    blocks: BTreeMap<HashType, Block>,
) -> TrustedRoundLock {
    let head = chain.epochchain.last().unwrap();
    let round_id = TrustedRoundId {
        group_id: head.body.group_id,
        previous_epoch_hash: head.hash,
        previous_epoch_nonce: head.body.nonce,
        nonce: head.body.nonce.new_next(),
        round,
    };
    let block_hashes = blocks
        .keys()
        .map(|hash| (*hash, ()))
        .collect::<BTreeMap<_, _>>();
    TrustedRoundLock {
        round_id,
        verification: Verification {
            header: Header {
                sender: self_public_key,
                last_epoch: round_id.previous_epoch_hash,
                nonce: round_id.nonce,
                round,
                signature: Signature::default(),
            },
            body: VerificationBody {
                blocks_hash: block_hashes.hash(),
                blocks: block_hashes,
            },
        },
        blocks,
    }
}

#[derive(Debug, Clone)]
struct FaultStorage {
    path: Arc<std::path::PathBuf>,
    fault: Arc<AtomicU8>,
}

impl FaultStorage {
    fn new() -> Self {
        Self {
            path: Arc::new(unique_test_path("blossom-trusted-log-test")),
            fault: Arc::new(AtomicU8::new(NO_FAULT)),
        }
    }

    fn set_fault(&self, fault: u8) {
        self.fault.store(fault, Ordering::SeqCst);
    }
}

impl Drop for FaultStorage {
    fn drop(&mut self) {
        if Arc::strong_count(&self.path) == 1 {
            let _ = std::fs::remove_dir_all(self.path.as_ref());
        }
    }
}

fn fault_store(
    storage: &FaultStorage,
    seed: &EpochChain,
    self_public_key: PubKey,
) -> Result<(TrustedEpochLog, EpochChain)> {
    let (mut store, chain) = TrustedEpochLog::open(
        storage.path.as_ref(),
        self_public_key,
        seed,
        ConsensusNodeRemovalPolicy::disabled(),
    )?;
    store.test_fault = Some(storage.fault.clone());
    Ok((store, chain))
}

#[test]
fn confirmation_lock_survives_restart_and_rejects_conflicting_candidate() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let locked = round_lock(&seed, identities[0].public_key());
    store.lock_round(&locked).unwrap();
    drop(store);

    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    assert_eq!(
        store
            .round_lock(&locked.round_id)
            .unwrap()
            .unwrap()
            .candidate_hash(),
        locked.candidate_hash()
    );
    let mut conflicting = locked.clone();
    conflicting.verification.body.blocks_hash = HashType([0x55; 32]);
    assert!(store.lock_round(&conflicting).is_err());
}

#[test]
fn hierarchical_round_locks_survive_together_and_clear_with_final_epoch() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let first = round_lock(&seed, identities[0].public_key());
    let mut second = first.clone();
    second.round_id.round = 1;
    second.verification.header.round = 1;
    store.lock_round(&first).unwrap();
    store.lock_round(&second).unwrap();

    assert_eq!(store.round_locks().unwrap().len(), 2);
    drop(store);
    let (store, recovered) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    assert_eq!(
        store
            .round_locks()
            .unwrap()
            .iter()
            .map(|lock| lock.round_id.round)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );

    let epoch = next_epoch(recovered.epochchain.last().unwrap());
    store.append_epoch(&epoch, Some(second.round_id)).unwrap();
    assert!(store.round_locks().unwrap().is_empty());
}

#[test]
fn confirmation_locks_are_contiguous_and_cannot_target_an_old_head() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let first = round_lock(&seed, identities[0].public_key());
    let mut second = first.clone();
    second.round_id.round = 1;
    second.verification.header.round = 1;
    assert!(store.lock_round(&second).is_err());

    let epoch = next_epoch(seed.epochchain.last().unwrap());
    store.append_epoch(&epoch, None).unwrap();
    assert!(store.lock_round(&first).is_err());
    assert!(store.round_locks().unwrap().is_empty());
}

#[test]
fn epoch_append_cannot_discard_or_diverge_from_durable_confirmations() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let head = seed.epochchain.last().unwrap();
    let block = trusted_block(head, identities[0].public_key(), "confirmed");
    let block_hash = block.hash;
    let blocks = BTreeMap::from([(block_hash, block)]);
    let lock = round_lock_with_blocks(&seed, identities[0].public_key(), 0, blocks.clone());
    store.lock_round(&lock).unwrap();

    let conflicting = next_epoch(head);
    assert!(
        store
            .append_suffix(std::slice::from_ref(&conflicting))
            .is_err()
    );
    assert_eq!(store.head().unwrap().nonce, head.body.nonce);
    assert!(store.round_lock(&lock.round_id).unwrap().is_some());

    let matching = next_epoch_with_blocks(head, blocks);
    store.append_epoch(&matching, Some(lock.round_id)).unwrap();
    assert_eq!(store.head().unwrap().hash, matching.hash);
    assert!(store.round_locks().unwrap().is_empty());
}

#[test]
fn stale_local_submission_is_rejected_after_head_advances() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let head = seed.epochchain.last().unwrap();
    let stale = trusted_block(head, identities[0].public_key(), "stale");
    let epoch = next_epoch(head);
    store.append_epoch(&epoch, None).unwrap();

    assert!(store.persist_local_block(&stale).is_err());
    assert!(store.pending_local_block().unwrap().is_none());
}

#[test]
fn semantically_invalid_epoch_is_rejected_even_with_a_valid_hash() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let head = seed.epochchain.last().unwrap();
    let block = trusted_block(head, identities[0].public_key(), "semantic-corruption");
    let mut epoch = next_epoch_with_blocks(head, BTreeMap::from([(block.hash, block)]));
    epoch.body.merkle_root = HashType([0x77; 32]);
    epoch.set_hash();

    assert!(store.append_epoch(&epoch, None).is_err());
    assert_eq!(store.head().unwrap().hash, head.hash);
}

#[test]
fn failed_fsync_exposes_neither_confirmation_lock_nor_epoch() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let lock = round_lock(&seed, identities[0].public_key());

    storage.set_fault(SYNC_FAILURE);
    assert!(store.lock_round(&lock).is_err());
    drop(store);
    storage.set_fault(NO_FAULT);
    let (store, recovered) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    assert!(store.round_lock(&lock.round_id).unwrap().is_none());
    assert_eq!(recovered.epochchain.len(), 1);

    store.lock_round(&lock).unwrap();
    let epoch = next_epoch(recovered.epochchain.last().unwrap());
    storage.set_fault(SYNC_FAILURE);
    assert!(store.append_epoch(&epoch, Some(lock.round_id)).is_err());
    drop(store);
    storage.set_fault(NO_FAULT);
    let (store, recovered) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    assert_eq!(recovered.epochchain.len(), 1);
    assert!(store.round_lock(&lock.round_id).unwrap().is_some());
}

#[test]
fn storage_full_fails_closed_without_advancing_the_head() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let epoch = next_epoch(seed.epochchain.last().unwrap());
    storage.set_fault(STORAGE_FULL);
    assert!(store.append_epoch(&epoch, None).is_err());
    drop(store);
    storage.set_fault(NO_FAULT);
    let (_, recovered) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    assert_eq!(recovered.epochchain.len(), 1);
}

#[test]
fn omitted_local_writer_block_is_atomically_retargeted_and_recovered() {
    let (seed, identities) = seed_chain();
    let storage = FaultStorage::new();
    let (store, _) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    let head = seed.epochchain.last().unwrap();
    let mut local = Block::default();
    local.body.last_epoch = head.hash;
    local.body.nonce = head.body.nonce.new_next();
    local
        .body
        .txs
        .push(crate::block::Transaction::new("retry-me"));
    local.seal_unsigned(identities[0].public_key());
    let original_hash = local.hash;
    store.persist_local_block(&local).unwrap();

    let epoch = next_epoch(head);
    store.append_suffix(std::slice::from_ref(&epoch)).unwrap();
    let retry = store.pending_local_block().unwrap().unwrap();
    assert_ne!(retry.hash, original_hash);
    assert_eq!(retry.body.last_epoch, epoch.hash);
    assert_eq!(retry.body.nonce, epoch.body.nonce.new_next());
    assert_eq!(
        retry.body.txs.iter().map(|tx| tx.hash).collect::<Vec<_>>(),
        local.body.txs.iter().map(|tx| tx.hash).collect::<Vec<_>>()
    );
    drop(store);

    let (store, recovered) = fault_store(&storage, &seed, identities[0].public_key()).unwrap();
    assert_eq!(recovered.epochchain.last().unwrap().hash, epoch.hash);
    assert_eq!(
        store
            .pending_local_block()
            .unwrap()
            .unwrap()
            .body
            .txs
            .iter()
            .map(|tx| tx.hash)
            .collect::<Vec<_>>(),
        local.body.txs.iter().map(|tx| tx.hash).collect::<Vec<_>>()
    );
}

#[test]
fn append_only_log_recovers_more_than_one_thousand_epochs() {
    let (seed, identities) = seed_chain();
    let path = unique_test_path("blossom-trusted-log-soak");
    let (store, mut recovered) = TrustedEpochLog::open(
        &path,
        identities[0].public_key(),
        &seed,
        ConsensusNodeRemovalPolicy::disabled(),
    )
    .unwrap();
    for _ in 0..1_001 {
        let epoch = next_epoch(recovered.epochchain.last().unwrap());
        store.append_epoch(&epoch, None).unwrap();
        recovered.epochchain.push(epoch);
    }
    let expected_head = recovered.epochchain.last().unwrap().hash;
    drop(store);

    let (store, restored) = TrustedEpochLog::open(
        &path,
        identities[0].public_key(),
        &seed,
        ConsensusNodeRemovalPolicy::disabled(),
    )
    .unwrap();
    assert_eq!(restored.epochchain.len(), 1_002);
    assert_eq!(restored.epochchain.last().unwrap().hash, expected_head);
    assert_eq!(store.head().unwrap().epoch_count, 1_002);
    drop(store);
    std::fs::remove_dir_all(path).ok();
}
