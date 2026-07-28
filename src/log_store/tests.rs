//! Transactional LogStore recovery, checkpoint, and failure-injection tests.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blossom-log-store-{name}-{}-{unique}",
            std::process::id()
        ));
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open(path: &Path) -> BlossomLogStore {
    BlossomLogStore::open(
        BlossomLogStoreConfig::new(path),
        BlossomLogStoreIdentity::new("test", b"public-test-scope".to_vec(), 1).unwrap(),
    )
    .unwrap()
}

fn identity() -> BlossomLogStoreIdentity {
    BlossomLogStoreIdentity::new("test", b"public-test-scope".to_vec(), 1).unwrap()
}

#[test]
fn transaction_is_atomic_and_recovers_after_checkpoint() {
    let temp = TempDir::new("recover");
    let store = open(&temp.0);
    store
        .transaction(|transaction| {
            transaction.insert("values", b"a".to_vec(), b"one".to_vec())?;
            transaction.insert("values", b"b".to_vec(), b"two".to_vec())?;
            Ok(())
        })
        .unwrap();
    assert_eq!(store.get("values", b"a").unwrap().unwrap().as_ref(), b"one");
    store.checkpoint().unwrap();
    drop(store);

    let reopened = open(&temp.0);
    assert_eq!(
        reopened.get("values", b"b").unwrap().unwrap().as_ref(),
        b"two"
    );
    assert_eq!(reopened.snapshot().revision(), 1);
}

#[test]
fn aborted_transaction_and_range_removal_do_not_leak() {
    let temp = TempDir::new("abort");
    let store = open(&temp.0);
    let error = store
        .transaction::<()>(|transaction| {
            transaction.insert("values", b"a".to_vec(), b"one".to_vec())?;
            Err(BlossomError::InvalidConfiguration("abort".to_string()))
        })
        .unwrap_err();
    assert!(matches!(error, BlossomError::InvalidConfiguration(_)));
    assert!(store.get("values", b"a").unwrap().is_none());

    store
        .transaction(|transaction| {
            for key in [b"a", b"b", b"c"] {
                transaction.insert("values", key.to_vec(), key.to_vec())?;
            }
            Ok(())
        })
        .unwrap();
    store
        .transaction(|transaction| {
            transaction.remove_range("values", b"a".to_vec(), Some(b"c".to_vec()))?;
            assert_eq!(
                transaction.scan("values")?,
                vec![(b"c".to_vec(), b"c".to_vec())]
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn identity_mismatch_and_legacy_file_fail_closed() {
    let temp = TempDir::new("identity");
    drop(open(&temp.0));
    let mismatch = BlossomLogStore::open(
        BlossomLogStoreConfig::new(&temp.0),
        BlossomLogStoreIdentity::new("test", b"another-public-scope".to_vec(), 1).unwrap(),
    );
    assert!(matches!(
        mismatch,
        Err(BlossomError::InvalidConfiguration(_))
    ));

    let file = temp.0.with_extension("legacy-db");
    fs::write(&file, b"legacy").unwrap();
    assert!(matches!(
        BlossomLogStore::open(
            BlossomLogStoreConfig::new(file),
            BlossomLogStoreIdentity::new("test", b"public-test-scope".to_vec(), 1).unwrap(),
        ),
        Err(BlossomError::InvalidConfiguration(_))
    ));
}

#[test]
fn clean_shutdown_is_idempotent_and_rejects_new_writes() {
    let temp = TempDir::new("shutdown");
    let store = open(&temp.0);
    store
        .transaction(|transaction| transaction.insert("values", b"key".to_vec(), b"value".to_vec()))
        .unwrap();
    store.shutdown().unwrap();
    store.shutdown().unwrap();
    assert!(
        store
            .transaction(|transaction| {
                transaction.insert("values", b"other".to_vec(), b"value".to_vec())
            })
            .is_err()
    );
    assert_eq!(
        store.get("values", b"key").unwrap().unwrap().as_ref(),
        b"value"
    );
    drop(store);
    let reopened = open(&temp.0);
    assert_eq!(
        reopened.get("values", b"key").unwrap().unwrap().as_ref(),
        b"value"
    );
}

#[test]
fn chunked_transactions_and_checkpoint_replacement_replay() {
    let source = TempDir::new("chunked-source");
    let mut config = BlossomLogStoreConfig::new(&source.0);
    config.max_chunk_bytes = 64;
    config.max_value_bytes = 8 * 1024;
    config.max_transaction_bytes = 16 * 1024;
    let store = BlossomLogStore::open(config.clone(), identity()).unwrap();
    let value = vec![0x5a; 4 * 1024];
    let (_, receipt) = store
        .transaction(|transaction| {
            transaction.insert("values", b"large".to_vec(), value.clone())?;
            assert_eq!(transaction.get("values", b"large")?, Some(value.clone()));
            Ok(())
        })
        .unwrap();
    let receipt = receipt.unwrap();
    assert!(receipt.last_sequence > receipt.first_sequence);
    let snapshot = store.snapshot();
    drop(store);

    let reopened = BlossomLogStore::open(config, identity()).unwrap();
    assert_eq!(
        reopened.get("values", b"large").unwrap().unwrap().as_ref(),
        value.as_slice()
    );

    let destination = TempDir::new("chunked-destination");
    let destination_store = open(&destination.0);
    destination_store
        .transaction(|transaction| transaction.insert("stale", b"key".to_vec(), b"value".to_vec()))
        .unwrap();
    destination_store.replace_from_checkpoint(snapshot).unwrap();
    assert!(destination_store.get("stale", b"key").unwrap().is_none());
    assert_eq!(
        destination_store
            .get("values", b"large")
            .unwrap()
            .unwrap()
            .as_ref(),
        value.as_slice()
    );
    drop(destination_store);
    let destination_store = open(&destination.0);
    assert_eq!(
        destination_store
            .get("values", b"large")
            .unwrap()
            .unwrap()
            .as_ref(),
        value.as_slice()
    );
}

#[test]
fn concurrent_writers_are_serializable() {
    let temp = TempDir::new("serializable");
    let store = Arc::new(open(&temp.0));
    store
        .transaction(|transaction| {
            transaction.insert("counter", b"value".to_vec(), 0u64.to_be_bytes().to_vec())
        })
        .unwrap();
    let barrier = Arc::new(Barrier::new(5));
    let workers = (0..4)
        .map(|_| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..10 {
                    store
                        .transaction(|transaction| {
                            let bytes = transaction
                                .get("counter", b"value")?
                                .expect("counter exists");
                            let value = u64::from_be_bytes(bytes.try_into().expect("u64 counter"));
                            transaction.insert(
                                "counter",
                                b"value".to_vec(),
                                value.checked_add(1).expect("counter bound").to_be_bytes(),
                            )
                        })
                        .unwrap();
                }
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    let value = store.get("counter", b"value").unwrap().unwrap();
    assert_eq!(u64::from_be_bytes(value.as_ref().try_into().unwrap()), 40);
}

#[test]
fn model_replay_matches_ordered_table_operations() {
    let temp = TempDir::new("model");
    let mut store = open(&temp.0);
    let mut model = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    let mut seed = 0x1234_5678_9abc_def0u64;
    for step in 0..100u64 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let key = vec![b'a' + ((seed >> 32) % 12) as u8];
        match seed % 3 {
            0 => {
                let value = step.to_be_bytes().to_vec();
                store
                    .transaction(|transaction| {
                        transaction.insert("model", key.clone(), value.clone())
                    })
                    .unwrap();
                model.insert(key, value);
            }
            1 => {
                store
                    .transaction(|transaction| transaction.remove("model", key.clone()))
                    .unwrap();
                model.remove(&key);
            }
            _ => {
                let end = vec![key[0].saturating_add(2)];
                store
                    .transaction(|transaction| {
                        transaction.remove_range("model", key.clone(), Some(end.clone()))
                    })
                    .unwrap();
                model.retain(|candidate, _| {
                    candidate.as_slice() < key.as_slice() || candidate.as_slice() >= end.as_slice()
                });
            }
        }
        let actual = store
            .scan("model")
            .unwrap()
            .into_iter()
            .map(|(key, value)| (key, value.to_vec()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual, model);
        if step % 25 == 24 {
            store.checkpoint().unwrap();
            drop(store);
            store = open(&temp.0);
        }
    }
}

#[test]
fn complete_chunk_tail_is_durably_aborted_before_new_writes() {
    let temp = TempDir::new("tail-abort");
    let store = open(&temp.0);
    let body = TransactionBody {
        base_revision: 0,
        revision: 1,
        operations: vec![LogOperation::Insert {
            table: "values".to_string(),
            key: b"lost".to_vec(),
            value: b"unacknowledged".to_vec(),
        }],
    };
    let bytes = borsh::to_vec(&body).unwrap();
    let body_hash = hash_bytes(&bytes);
    {
        let mut writer = store.inner.writer.lock().unwrap();
        let sequence = writer.next_sequence;
        let payload = borsh::to_vec(&PersistedRecord::Chunk {
            format_version: BLOSSOM_LOG_STORE_FORMAT_VERSION,
            kind: GroupKind::Transaction,
            group_id: 1,
            index: 0,
            count: 1,
            body_hash,
            bytes,
        })
        .unwrap();
        writer
            .store
            .append_group(sequence, &[Bytes::from(payload)], true)
            .unwrap();
    }
    drop(store);

    let reopened = open(&temp.0);
    assert!(reopened.get("values", b"lost").unwrap().is_none());
    reopened
        .transaction(|transaction| {
            transaction.insert("values", b"kept".to_vec(), b"committed".to_vec())
        })
        .unwrap();
    drop(reopened);

    let reopened = open(&temp.0);
    assert!(reopened.get("values", b"lost").unwrap().is_none());
    assert_eq!(
        reopened.get("values", b"kept").unwrap().unwrap().as_ref(),
        b"committed"
    );
}

#[test]
fn complete_ambiguous_transaction_replays_once_and_retry_is_idempotent() {
    let temp = TempDir::new("ambiguous-complete");
    let store = open(&temp.0);
    let body = TransactionBody {
        base_revision: 0,
        revision: 1,
        operations: vec![LogOperation::Insert {
            table: "values".to_string(),
            key: b"idempotency-key".to_vec(),
            value: b"committed".to_vec(),
        }],
    };
    let bytes = borsh::to_vec(&body).unwrap();
    let body_hash = hash_bytes(&bytes);
    {
        let mut writer = store.inner.writer.lock().unwrap();
        let first_sequence = writer.next_sequence;
        let chunk = borsh::to_vec(&PersistedRecord::Chunk {
            format_version: BLOSSOM_LOG_STORE_FORMAT_VERSION,
            kind: GroupKind::Transaction,
            group_id: 1,
            index: 0,
            count: 1,
            body_hash,
            bytes,
        })
        .unwrap();
        let commit = borsh::to_vec(&PersistedRecord::Commit {
            format_version: BLOSSOM_LOG_STORE_FORMAT_VERSION,
            kind: GroupKind::Transaction,
            group_id: 1,
            count: 1,
            body_hash,
        })
        .unwrap();
        writer
            .store
            .append_group(
                first_sequence,
                &[Bytes::from(chunk), Bytes::from(commit)],
                true,
            )
            .unwrap();
    }
    drop(store);

    let reopened = open(&temp.0);
    assert_eq!(
        reopened
            .get("values", b"idempotency-key")
            .unwrap()
            .unwrap()
            .as_ref(),
        b"committed"
    );
    let (_, receipt) = reopened
        .transaction(|transaction| {
            if transaction.get("values", b"idempotency-key")?.is_none() {
                transaction.insert("values", b"idempotency-key".to_vec(), b"committed".to_vec())?;
            }
            Ok(())
        })
        .unwrap();
    assert!(receipt.is_none());
    assert_eq!(reopened.snapshot().revision(), 1);
}

#[test]
fn automatic_checkpoints_bound_local_pack_count() {
    let temp = TempDir::new("automatic-checkpoint");
    let mut config = BlossomLogStoreConfig::new(&temp.0);
    config.target_pack_bytes = 512;
    config.checkpoint_after_transactions = 2;
    config.checkpoint_after_bytes = usize::MAX as u64;
    let store = BlossomLogStore::open(config.clone(), identity()).unwrap();
    for value in 0..20u64 {
        store
            .transaction(|transaction| {
                transaction.insert("values", b"latest".to_vec(), value.to_be_bytes().to_vec())
            })
            .unwrap();
    }
    let metrics = store.durability_metrics();
    assert_eq!(metrics.committed_transactions, 20);
    assert!(metrics.checkpoints >= 11);
    drop(store);

    let pack_count = fs::read_dir(&temp.0)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".sse"))
        })
        .count();
    assert!(
        pack_count <= 3,
        "unexpected retained pack count {pack_count}"
    );
    let reopened = BlossomLogStore::open(config, identity()).unwrap();
    assert_eq!(
        u64::from_be_bytes(
            reopened
                .get("values", b"latest")
                .unwrap()
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap()
        ),
        19
    );
}
