//! Transactional, ShardLog-backed durable storage for Blossom.
//!
//! The store materializes ordered byte tables in memory and persists every
//! write transaction as a hash-committed ShardLog extent group. A
//! transaction becomes visible only after the underlying pack is synced.

#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shardlog::{ShardLog, ShardLogConfig};

use crate::{BlossomError, Result};

/// Durable record and identity format used by [`BlossomLogStore`].
pub const BLOSSOM_LOG_STORE_FORMAT_VERSION: u16 = 1;
const DEFAULT_TARGET_PACK_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_VALUE_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_TRANSACTION_BYTES: usize = 256 * 1024 * 1024;
const DEFAULT_MAX_CHECKPOINT_BYTES: usize = 1024 * 1024 * 1024;
const DEFAULT_CHECKPOINT_AFTER_TRANSACTIONS: u64 = 10_000;
const DEFAULT_CHECKPOINT_AFTER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TABLE_NAME_BYTES: usize = 128;
const MAX_KEY_BYTES: usize = 4 * 1024;
const MAX_GROUP_CHUNKS: u32 = 65_536;

type Table = BTreeMap<Vec<u8>, Arc<[u8]>>;
type Tables = BTreeMap<String, Table>;
/// One ordered table entry returned by a materialized read.
pub type BlossomLogEntry = (Vec<u8>, Arc<[u8]>);

/// Public, non-secret identity permanently bound to a store directory.
///
/// Signing material is intentionally not accepted by this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlossomLogStoreIdentity {
    /// Durable identity format version.
    pub format_version: u16,
    /// Application-defined subsystem kind, such as `ha-runtime`.
    pub store_kind: String,
    /// Application-defined public bytes distinguishing independent stores.
    pub public_scope: Vec<u8>,
    /// Application-defined storage generation.
    pub generation: u64,
}

impl BlossomLogStoreIdentity {
    /// Constructs and validates a version-1 public identity.
    pub fn new(
        store_kind: impl Into<String>,
        public_scope: impl Into<Vec<u8>>,
        generation: u64,
    ) -> Result<Self> {
        let identity = Self {
            format_version: BLOSSOM_LOG_STORE_FORMAT_VERSION,
            store_kind: store_kind.into(),
            public_scope: public_scope.into(),
            generation,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Checks the format version and all identity size bounds.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != BLOSSOM_LOG_STORE_FORMAT_VERSION
            || self.store_kind.is_empty()
            || self.store_kind.len() > MAX_TABLE_NAME_BYTES
            || self.public_scope.is_empty()
            || self.public_scope.len() > DEFAULT_MAX_VALUE_BYTES
        {
            return Err(BlossomError::InvalidConfiguration(
                "invalid Blossom LogStore identity".to_string(),
            ));
        }
        Ok(())
    }
}

/// Size, checkpoint, and directory settings for a [`BlossomLogStore`].
#[derive(Debug, Clone)]
pub struct BlossomLogStoreConfig {
    /// Exclusively owned directory containing ShardLog extent packs.
    pub data_dir: PathBuf,
    /// Approximate byte threshold for sealing the active extent pack.
    pub target_pack_bytes: u64,
    /// Maximum encoded bytes in one transaction or checkpoint chunk.
    pub max_chunk_bytes: usize,
    /// Maximum bytes in one table value.
    pub max_value_bytes: usize,
    /// Maximum encoded bytes in one complete transaction.
    pub max_transaction_bytes: usize,
    /// Maximum encoded bytes in one complete checkpoint.
    pub max_checkpoint_bytes: usize,
    /// Committed transactions between automatic checkpoints.
    pub checkpoint_after_transactions: u64,
    /// Appended transaction bytes between automatic checkpoints.
    pub checkpoint_after_bytes: u64,
}

impl BlossomLogStoreConfig {
    /// Creates production-oriented defaults for `data_dir`.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            target_pack_bytes: DEFAULT_TARGET_PACK_BYTES,
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
            max_transaction_bytes: DEFAULT_MAX_TRANSACTION_BYTES,
            max_checkpoint_bytes: DEFAULT_MAX_CHECKPOINT_BYTES,
            checkpoint_after_transactions: DEFAULT_CHECKPOINT_AFTER_TRANSACTIONS,
            checkpoint_after_bytes: DEFAULT_CHECKPOINT_AFTER_BYTES,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.target_pack_bytes == 0
            || self.max_chunk_bytes == 0
            || self.max_value_bytes == 0
            || self.max_transaction_bytes < self.max_value_bytes
            || self.max_checkpoint_bytes < self.max_value_bytes
            || self.checkpoint_after_transactions == 0
            || self.checkpoint_after_bytes == 0
        {
            return Err(BlossomError::InvalidConfiguration(
                "invalid Blossom LogStore configuration".to_string(),
            ));
        }
        Ok(())
    }
}

/// Durable location and size of one committed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlossomLogCommitReceipt {
    /// Materialized table revision after the transaction.
    pub revision: u64,
    /// First underlying ShardLog record sequence.
    pub first_sequence: u64,
    /// Last underlying ShardLog record sequence.
    pub last_sequence: u64,
    /// Total encoded payload bytes appended by the transaction.
    pub payload_bytes: u64,
}

/// Durable location and hash of one committed full-state checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlossomLogCheckpointReceipt {
    /// Materialized table revision captured by the checkpoint.
    pub revision: u64,
    /// First underlying ShardLog record sequence.
    pub first_sequence: u64,
    /// Last underlying ShardLog record sequence.
    pub last_sequence: u64,
    /// SHA-256 hash of the canonical encoded checkpoint body.
    pub state_hash: [u8; 32],
}

/// Process-local counters describing durability work completed by a handle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlossomLogDurabilityMetrics {
    /// Transactions committed through this handle.
    pub committed_transactions: u64,
    /// Synchronous transaction durability operations completed.
    pub fsyncs: u64,
    /// Encoded transaction bytes appended through this handle.
    pub appended_bytes: u64,
    /// Automatic and explicit checkpoints completed.
    pub checkpoints: u64,
    /// Transactions replayed while opening the handle.
    pub replayed_transactions: u64,
}

/// Immutable complete materialized state suitable for checkpoint replacement.
#[derive(Debug, Clone)]
pub struct BlossomLogSnapshot {
    identity: BlossomLogStoreIdentity,
    revision: u64,
    tables: Tables,
}

impl BlossomLogSnapshot {
    /// Builds a validated snapshot from owned ordered byte tables.
    pub fn from_tables(
        identity: BlossomLogStoreIdentity,
        revision: u64,
        tables: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
    ) -> Result<Self> {
        identity.validate()?;
        validate_checkpoint_tables(&tables, DEFAULT_MAX_VALUE_BYTES)?;
        Ok(Self {
            identity,
            revision,
            tables: tables
                .into_iter()
                .map(|(name, entries)| {
                    (
                        name,
                        entries
                            .into_iter()
                            .map(|(key, value)| (key, Arc::<[u8]>::from(value)))
                            .collect(),
                    )
                })
                .collect(),
        })
    }

    /// Returns the materialized revision captured by the snapshot.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the public store identity captured by the snapshot.
    pub fn identity(&self) -> &BlossomLogStoreIdentity {
        &self.identity
    }

    /// Returns an immutable value from the captured state.
    pub fn get(&self, table: &str, key: &[u8]) -> Option<Arc<[u8]>> {
        self.tables.get(table)?.get(key).cloned()
    }

    /// Returns every captured entry in key order.
    pub fn scan(&self, table: &str) -> Vec<BlossomLogEntry> {
        self.tables
            .get(table)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(key, value)| (key.clone(), Arc::clone(value)))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns captured entries in the half-open key range `[start, end)`.
    ///
    /// Passing `None` for `end` scans through the final key.
    pub fn scan_range(
        &self,
        table: &str,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<BlossomLogEntry>> {
        validate_range(table, start, end)?;
        Ok(self
            .tables
            .get(table)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(key, _)| in_range(key, start, end))
                    .map(|(key, value)| (key.clone(), Arc::clone(value)))
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
enum LogOperation {
    Insert {
        table: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Remove {
        table: String,
        key: Vec<u8>,
    },
    RemoveRange {
        table: String,
        start: Vec<u8>,
        end: Option<Vec<u8>>,
    },
    Clear {
        table: String,
    },
}

/// Serializable transaction view with read-your-staged-writes behavior.
///
/// Values remain private to the transaction until its closure returns
/// successfully and the complete durable record group is synchronized.
pub struct BlossomLogTransaction<'a> {
    base: &'a MaterializedState,
    operations: Vec<LogOperation>,
    max_value_bytes: usize,
}

impl BlossomLogTransaction<'_> {
    /// Reads one key after applying staged operations in program order.
    pub fn get(&self, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_table_name(table)?;
        validate_key(key)?;
        for operation in self.operations.iter().rev() {
            match operation {
                LogOperation::Insert {
                    table: operation_table,
                    key: operation_key,
                    value,
                } if operation_table == table && operation_key.as_slice() == key => {
                    return Ok(Some(value.clone()));
                }
                LogOperation::Remove {
                    table: operation_table,
                    key: operation_key,
                } if operation_table == table && operation_key.as_slice() == key => {
                    return Ok(None);
                }
                LogOperation::RemoveRange {
                    table: operation_table,
                    start,
                    end,
                } if operation_table == table && in_range(key, start, end.as_deref()) => {
                    return Ok(None);
                }
                LogOperation::Clear {
                    table: operation_table,
                } if operation_table == table => return Ok(None),
                _ => {}
            }
        }
        Ok(self
            .base
            .tables
            .get(table)
            .and_then(|entries| entries.get(key))
            .map(|value| value.to_vec()))
    }

    /// Returns every entry after applying staged operations in key order.
    pub fn scan(&self, table: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        validate_table_name(table)?;
        let mut materialized = self
            .base
            .tables
            .get(table)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_vec()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        for operation in &self.operations {
            apply_operation_to_table(&mut materialized, table, operation);
        }
        Ok(materialized.into_iter().collect())
    }

    /// Returns staged entries in the half-open key range `[start, end)`.
    pub fn scan_range(
        &self,
        table: &str,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        validate_range(table, start, end)?;
        Ok(self
            .scan(table)?
            .into_iter()
            .filter(|(key, _)| in_range(key, start, end))
            .collect())
    }

    /// Stages insertion or replacement of one value.
    pub fn insert(
        &mut self,
        table: impl Into<String>,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Result<()> {
        let table = table.into();
        let key = key.into();
        let value = value.into();
        validate_table_name(&table)?;
        validate_key(&key)?;
        if value.len() > self.max_value_bytes {
            return Err(BlossomError::InvalidConfiguration(format!(
                "Blossom LogStore value exceeds {} bytes",
                self.max_value_bytes
            )));
        }
        self.operations
            .push(LogOperation::Insert { table, key, value });
        Ok(())
    }

    /// Stages removal of one key.
    pub fn remove(&mut self, table: impl Into<String>, key: impl Into<Vec<u8>>) -> Result<()> {
        let table = table.into();
        let key = key.into();
        validate_table_name(&table)?;
        validate_key(&key)?;
        self.operations.push(LogOperation::Remove { table, key });
        Ok(())
    }

    /// Stages removal of the half-open key range `[start, end)`.
    ///
    /// Passing `None` for `end` removes through the final key.
    pub fn remove_range(
        &mut self,
        table: impl Into<String>,
        start: impl Into<Vec<u8>>,
        end: Option<Vec<u8>>,
    ) -> Result<()> {
        let table = table.into();
        let start = start.into();
        validate_table_name(&table)?;
        validate_key(&start)?;
        if let Some(end) = end.as_deref() {
            validate_key(end)?;
            if end <= start.as_slice() {
                return Err(BlossomError::InvalidConfiguration(
                    "Blossom LogStore range end must follow its start".to_string(),
                ));
            }
        }
        self.operations
            .push(LogOperation::RemoveRange { table, start, end });
        Ok(())
    }

    /// Stages removal of every entry in a table.
    pub fn clear(&mut self, table: impl Into<String>) -> Result<()> {
        let table = table.into();
        validate_table_name(&table)?;
        self.operations.push(LogOperation::Clear { table });
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MaterializedState {
    revision: u64,
    tables: Tables,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct TransactionBody {
    base_revision: u64,
    revision: u64,
    operations: Vec<LogOperation>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct CheckpointBody {
    identity: BlossomLogStoreIdentity,
    revision: u64,
    tables: BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
enum GroupKind {
    Transaction,
    Checkpoint,
}

#[derive(BorshSerialize, BorshDeserialize)]
enum PersistedRecord {
    Chunk {
        format_version: u16,
        kind: GroupKind,
        group_id: u64,
        index: u32,
        count: u32,
        body_hash: [u8; 32],
        bytes: Vec<u8>,
    },
    Commit {
        format_version: u16,
        kind: GroupKind,
        group_id: u64,
        count: u32,
        body_hash: [u8; 32],
    },
    Abort {
        format_version: u16,
        kind: GroupKind,
        group_id: u64,
        count: u32,
        body_hash: [u8; 32],
    },
}

struct PendingGroup {
    kind: GroupKind,
    group_id: u64,
    count: u32,
    body_hash: [u8; 32],
    chunks: Vec<Option<Vec<u8>>>,
}

struct StoreWriter {
    store: ShardLog,
    next_sequence: u64,
    transactions_since_checkpoint: u64,
    bytes_since_checkpoint: u64,
}

struct LogStoreInner {
    config: BlossomLogStoreConfig,
    identity: BlossomLogStoreIdentity,
    state: RwLock<MaterializedState>,
    writer: Mutex<StoreWriter>,
    closed: AtomicBool,
    poisoned: AtomicBool,
    committed_transactions: AtomicU64,
    fsyncs: AtomicU64,
    appended_bytes: AtomicU64,
    checkpoints: AtomicU64,
    replayed_transactions: AtomicU64,
}

/// Transactional ordered byte tables persisted in an embedded [`ShardLog`].
///
/// Reads use immutable in-memory materialized tables. Writers are serialized,
/// and a mutating transaction returns success only after its hash-committed
/// record group reaches durable storage.
///
/// [`ShardLog`]: shardlog::ShardLog
#[derive(Clone)]
pub struct BlossomLogStore {
    inner: Arc<LogStoreInner>,
}

impl std::fmt::Debug for BlossomLogStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlossomLogStore")
            .field("data_dir", &self.inner.config.data_dir)
            .field("identity", &self.inner.identity)
            .finish_non_exhaustive()
    }
}

impl BlossomLogStore {
    /// Opens or creates a store and validates its identity and committed log.
    ///
    /// Recovery loads the newest complete checkpoint and replays later
    /// transactions. An incomplete transaction tail is durably aborted before
    /// the handle accepts another write.
    pub fn open(config: BlossomLogStoreConfig, identity: BlossomLogStoreIdentity) -> Result<Self> {
        config.validate()?;
        identity.validate()?;
        if config.data_dir.is_file() {
            return Err(BlossomError::InvalidConfiguration(
                "legacy durable-state file cannot be opened as a Blossom LogStore; recover into a fresh directory"
                    .to_string(),
            ));
        }
        let mut store = ShardLog::open(ShardLogConfig {
            directory: config.data_dir.clone(),
            target_pack_bytes: config.target_pack_bytes,
            max_record_bytes: config
                .max_chunk_bytes
                .checked_add(1024 * 1024)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "Blossom LogStore frame limit overflow".to_string(),
                    )
                })?,
        })
        .map_err(storage_error)?;
        let (state, mut next_sequence, replayed_transactions, initialized, pending) =
            recover(&mut store, &identity, &config)?;
        if let Some(pending) = pending {
            next_sequence = abort_pending_group(&mut store, next_sequence, &pending)?;
        }
        let log_store = Self {
            inner: Arc::new(LogStoreInner {
                config,
                identity,
                state: RwLock::new(state),
                writer: Mutex::new(StoreWriter {
                    store,
                    next_sequence,
                    transactions_since_checkpoint: 0,
                    bytes_since_checkpoint: 0,
                }),
                closed: AtomicBool::new(false),
                poisoned: AtomicBool::new(false),
                committed_transactions: AtomicU64::new(0),
                fsyncs: AtomicU64::new(0),
                appended_bytes: AtomicU64::new(0),
                checkpoints: AtomicU64::new(0),
                replayed_transactions: AtomicU64::new(replayed_transactions),
            }),
        };
        if !initialized {
            log_store.checkpoint()?;
        }
        Ok(log_store)
    }

    /// Returns an immutable point-in-time copy of all materialized tables.
    pub fn snapshot(&self) -> BlossomLogSnapshot {
        let state = self
            .inner
            .state
            .read()
            .unwrap_or_else(|error| error.into_inner());
        BlossomLogSnapshot {
            identity: self.inner.identity.clone(),
            revision: state.revision,
            tables: state.tables.clone(),
        }
    }

    /// Returns the public identity permanently bound to this handle.
    pub fn identity(&self) -> &BlossomLogStoreIdentity {
        &self.inner.identity
    }

    /// Reads one value from the current materialized state.
    pub fn get(&self, table: &str, key: &[u8]) -> Result<Option<Arc<[u8]>>> {
        validate_table_name(table)?;
        validate_key(key)?;
        Ok(self
            .inner
            .state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .tables
            .get(table)
            .and_then(|entries| entries.get(key))
            .cloned())
    }

    /// Returns every current entry in a table in key order.
    pub fn scan(&self, table: &str) -> Result<Vec<BlossomLogEntry>> {
        validate_table_name(table)?;
        Ok(self
            .inner
            .state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .tables
            .get(table)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(key, value)| (key.clone(), Arc::clone(value)))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Returns current entries in the half-open key range `[start, end)`.
    pub fn scan_range(
        &self,
        table: &str,
        start: &[u8],
        end: Option<&[u8]>,
    ) -> Result<Vec<BlossomLogEntry>> {
        validate_range(table, start, end)?;
        Ok(self
            .inner
            .state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .tables
            .get(table)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(key, _)| in_range(key, start, end))
                    .map(|(key, value)| (key.clone(), Arc::clone(value)))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Executes one serializable read/write transaction.
    ///
    /// Returning an error from `operation` aborts without durable or visible
    /// mutation. A read-only transaction returns `None` as its receipt.
    pub fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut BlossomLogTransaction<'_>) -> Result<T>,
    ) -> Result<(T, Option<BlossomLogCommitReceipt>)> {
        self.ensure_writable()?;
        let mut writer = self.inner.writer.lock().map_err(lock_error)?;
        self.ensure_writable()?;
        let state = self.inner.state.read().map_err(lock_error)?;
        let mut transaction = BlossomLogTransaction {
            base: &state,
            operations: Vec::new(),
            max_value_bytes: self.inner.config.max_value_bytes,
        };
        let result = operation(&mut transaction)?;
        if transaction.operations.is_empty() {
            return Ok((result, None));
        }
        let base_revision = state.revision;
        let revision = base_revision.checked_add(1).ok_or_else(|| {
            BlossomError::InvalidConfiguration("Blossom LogStore revision overflow".to_string())
        })?;
        let body = TransactionBody {
            base_revision,
            revision,
            operations: transaction.operations,
        };
        let encoded = borsh::to_vec(&body).map_err(encode_error)?;
        if encoded.len() > self.inner.config.max_transaction_bytes {
            return Err(BlossomError::InvalidConfiguration(format!(
                "Blossom LogStore transaction exceeds {} bytes",
                self.inner.config.max_transaction_bytes
            )));
        }
        drop(state);
        let persisted =
            self.persist_group_locked(&mut writer, GroupKind::Transaction, revision, &encoded)?;
        {
            let mut state = self.inner.state.write().map_err(lock_error)?;
            if state.revision != base_revision {
                self.inner.poisoned.store(true, Ordering::Release);
                return Err(BlossomError::Io(
                    "Blossom LogStore materialized revision changed during a serialized commit"
                        .to_string(),
                ));
            }
            apply_operations(&mut state.tables, &body.operations);
            state.revision = revision;
        }
        writer.transactions_since_checkpoint =
            writer.transactions_since_checkpoint.saturating_add(1);
        writer.bytes_since_checkpoint = writer
            .bytes_since_checkpoint
            .saturating_add(persisted.payload_bytes);
        self.inner
            .committed_transactions
            .fetch_add(1, Ordering::Relaxed);
        self.maybe_checkpoint_locked(&mut writer);
        Ok((result, Some(persisted)))
    }

    /// Writes and locally compacts a full-state checkpoint.
    pub fn checkpoint(&self) -> Result<BlossomLogCheckpointReceipt> {
        self.ensure_writable()?;
        let mut writer = self.inner.writer.lock().map_err(lock_error)?;
        self.ensure_writable()?;
        self.checkpoint_locked(&mut writer)
    }

    /// Atomically installs a full-state snapshot with the same public identity.
    pub fn replace_from_checkpoint(
        &self,
        snapshot: BlossomLogSnapshot,
    ) -> Result<BlossomLogCheckpointReceipt> {
        self.ensure_writable()?;
        if snapshot.identity != self.inner.identity {
            return Err(BlossomError::InvalidConfiguration(
                "Blossom LogStore checkpoint identity does not match its destination".to_string(),
            ));
        }
        validate_materialized_checkpoint(
            &snapshot.tables,
            self.inner.config.max_value_bytes,
            self.inner.config.max_checkpoint_bytes,
        )?;
        let mut writer = self.inner.writer.lock().map_err(lock_error)?;
        self.ensure_writable()?;
        let revision = snapshot.revision;
        let receipt = self.write_checkpoint_locked(&mut writer, revision, &snapshot.tables)?;
        *self.inner.state.write().map_err(lock_error)? = MaterializedState {
            revision,
            tables: snapshot.tables,
        };
        Ok(receipt)
    }

    /// Returns process-local durability counters for this open handle.
    pub fn durability_metrics(&self) -> BlossomLogDurabilityMetrics {
        BlossomLogDurabilityMetrics {
            committed_transactions: self.inner.committed_transactions.load(Ordering::Relaxed),
            fsyncs: self.inner.fsyncs.load(Ordering::Relaxed),
            appended_bytes: self.inner.appended_bytes.load(Ordering::Relaxed),
            checkpoints: self.inner.checkpoints.load(Ordering::Relaxed),
            replayed_transactions: self.inner.replayed_transactions.load(Ordering::Relaxed),
        }
    }

    /// Synchronizes outstanding storage state and permanently closes the handle.
    ///
    /// Repeated calls are idempotent. Writes after shutdown fail.
    pub fn shutdown(&self) -> Result<()> {
        let mut writer = self.inner.writer.lock().map_err(lock_error)?;
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let result = writer.store.sync().map_err(storage_error);
        if result.is_err() {
            self.inner.poisoned.store(true, Ordering::Release);
        }
        result
    }

    fn ensure_writable(&self) -> Result<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(BlossomError::Io("Blossom LogStore is closed".to_string()));
        }
        if self.inner.poisoned.load(Ordering::Acquire) {
            return Err(BlossomError::Io(
                "Blossom LogStore is poisoned after a persistence failure; reopen it before writing"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn persist_group_locked(
        &self,
        writer: &mut StoreWriter,
        kind: GroupKind,
        group_id: u64,
        body: &[u8],
    ) -> Result<BlossomLogCommitReceipt> {
        let body_hash = hash_bytes(body);
        let chunks = body
            .chunks(self.inner.config.max_chunk_bytes)
            .collect::<Vec<_>>();
        let count = u32::try_from(chunks.len()).map_err(|_| {
            BlossomError::InvalidConfiguration("Blossom LogStore chunk count overflow".to_string())
        })?;
        if count == 0 || count > MAX_GROUP_CHUNKS {
            return Err(BlossomError::InvalidConfiguration(
                "Blossom LogStore transaction has an invalid chunk count".to_string(),
            ));
        }
        let mut records = Vec::with_capacity(chunks.len() + 1);
        for (index, chunk) in chunks.into_iter().enumerate() {
            records.push(PersistedRecord::Chunk {
                format_version: BLOSSOM_LOG_STORE_FORMAT_VERSION,
                kind,
                group_id,
                index: u32::try_from(index).expect("bounded chunk index"),
                count,
                body_hash,
                bytes: chunk.to_vec(),
            });
        }
        records.push(PersistedRecord::Commit {
            format_version: BLOSSOM_LOG_STORE_FORMAT_VERSION,
            kind,
            group_id,
            count,
            body_hash,
        });
        let first_sequence = writer.next_sequence;
        let mut payloads = Vec::with_capacity(records.len());
        let mut payload_bytes = 0u64;
        for record in records {
            let payload = borsh::to_vec(&record).map_err(encode_error)?;
            payload_bytes = payload_bytes.saturating_add(payload.len() as u64);
            payloads.push(Bytes::from(payload));
        }
        let receipt = match writer.store.append_group(first_sequence, &payloads, true) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.inner.poisoned.store(true, Ordering::Release);
                return Err(storage_error(error));
            }
        };
        writer.next_sequence = receipt.last_sequence.checked_add(1).ok_or_else(|| {
            BlossomError::InvalidConfiguration("Blossom LogStore sequence overflow".to_string())
        })?;
        self.inner.fsyncs.fetch_add(1, Ordering::Relaxed);
        self.inner
            .appended_bytes
            .fetch_add(payload_bytes, Ordering::Relaxed);
        Ok(BlossomLogCommitReceipt {
            revision: group_id,
            first_sequence,
            last_sequence: writer.next_sequence - 1,
            payload_bytes,
        })
    }

    fn maybe_checkpoint_locked(&self, writer: &mut StoreWriter) {
        if (writer.transactions_since_checkpoint >= self.inner.config.checkpoint_after_transactions
            || writer.bytes_since_checkpoint >= self.inner.config.checkpoint_after_bytes)
            && self.checkpoint_locked(writer).is_err()
        {
            // The transaction which triggered maintenance is already durable.
            // Keep its success unambiguous and force the next write to reopen.
            self.inner.poisoned.store(true, Ordering::Release);
        }
    }

    fn checkpoint_locked(&self, writer: &mut StoreWriter) -> Result<BlossomLogCheckpointReceipt> {
        let state = self.inner.state.read().map_err(lock_error)?;
        self.write_checkpoint_locked(writer, state.revision, &state.tables)
    }

    fn write_checkpoint_locked(
        &self,
        writer: &mut StoreWriter,
        revision: u64,
        tables: &Tables,
    ) -> Result<BlossomLogCheckpointReceipt> {
        validate_materialized_checkpoint(
            tables,
            self.inner.config.max_value_bytes,
            self.inner.config.max_checkpoint_bytes,
        )?;
        let checkpoint = CheckpointBody {
            identity: self.inner.identity.clone(),
            revision,
            tables: tables
                .iter()
                .map(|(name, entries)| {
                    (
                        name.clone(),
                        entries
                            .iter()
                            .map(|(key, value)| (key.clone(), value.to_vec()))
                            .collect(),
                    )
                })
                .collect(),
        };
        let encoded = borsh::to_vec(&checkpoint).map_err(encode_error)?;
        if encoded.len() > self.inner.config.max_checkpoint_bytes {
            return Err(BlossomError::InvalidConfiguration(format!(
                "Blossom LogStore checkpoint exceeds {} bytes",
                self.inner.config.max_checkpoint_bytes
            )));
        }
        let result = (|| {
            writer.store.seal().map_err(storage_error)?;
            let persisted =
                self.persist_group_locked(writer, GroupKind::Checkpoint, revision, &encoded)?;
            writer
                .store
                .compact_before(persisted.first_sequence)
                .map_err(storage_error)?;
            writer.transactions_since_checkpoint = 0;
            writer.bytes_since_checkpoint = 0;
            self.inner.checkpoints.fetch_add(1, Ordering::Relaxed);
            Ok(BlossomLogCheckpointReceipt {
                revision,
                first_sequence: persisted.first_sequence,
                last_sequence: persisted.last_sequence,
                state_hash: hash_bytes(&encoded),
            })
        })();
        if result.is_err() {
            self.inner.poisoned.store(true, Ordering::Release);
        }
        result
    }
}

fn recover(
    store: &mut ShardLog,
    expected_identity: &BlossomLogStoreIdentity,
    config: &BlossomLogStoreConfig,
) -> Result<(MaterializedState, u64, u64, bool, Option<PendingGroup>)> {
    let Some((first, next_sequence)) = store.bounds().map_err(storage_error)? else {
        return Ok((MaterializedState::default(), 0, 0, false, None));
    };
    let mut expected_sequence = first;
    let mut pending: Option<PendingGroup> = None;
    let mut state = MaterializedState::default();
    let mut initialized = false;
    let mut replayed_transactions = 0u64;
    while expected_sequence < next_sequence {
        let records = store
            .read_from(expected_sequence, 64 * 1024 * 1024, 1024)
            .map_err(storage_error)?;
        if records.is_empty() {
            return Err(BlossomError::InvalidConfiguration(
                "Blossom LogStore retained stream contains a sequence gap".to_string(),
            ));
        }
        for retained in records {
            if retained.sequence != expected_sequence {
                return Err(BlossomError::InvalidConfiguration(
                    "Blossom LogStore retained stream is not contiguous".to_string(),
                ));
            }
            expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration("Blossom LogStore sequence overflow".to_string())
            })?;
            let record =
                borsh::from_slice::<PersistedRecord>(&retained.payload).map_err(|error| {
                    BlossomError::WireProtocol(format!("decode LogStore record: {error}"))
                })?;
            match record {
                PersistedRecord::Chunk {
                    format_version,
                    kind,
                    group_id,
                    index,
                    count,
                    body_hash,
                    bytes,
                } => {
                    validate_record_version(format_version)?;
                    if count == 0
                        || count > MAX_GROUP_CHUNKS
                        || index >= count
                        || bytes.len() > config.max_chunk_bytes
                    {
                        return Err(BlossomError::InvalidConfiguration(
                            "Blossom LogStore chunk metadata is invalid".to_string(),
                        ));
                    }
                    match &mut pending {
                        Some(group)
                            if group.kind == kind
                                && group.group_id == group_id
                                && group.count == count
                                && group.body_hash == body_hash =>
                        {
                            if group.chunks[index as usize].replace(bytes).is_some() {
                                return Err(BlossomError::InvalidConfiguration(
                                    "Blossom LogStore group contains a duplicate chunk".to_string(),
                                ));
                            }
                        }
                        None => {
                            let mut chunks = vec![None; count as usize];
                            chunks[index as usize] = Some(bytes);
                            pending = Some(PendingGroup {
                                kind,
                                group_id,
                                count,
                                body_hash,
                                chunks,
                            });
                        }
                        Some(_) => {
                            return Err(BlossomError::InvalidConfiguration(
                                "Blossom LogStore contains interleaved transaction groups"
                                    .to_string(),
                            ));
                        }
                    }
                }
                PersistedRecord::Commit {
                    format_version,
                    kind,
                    group_id,
                    count,
                    body_hash,
                } => {
                    validate_record_version(format_version)?;
                    let group = pending.take().ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "Blossom LogStore commit has no transaction chunks".to_string(),
                        )
                    })?;
                    if group.kind != kind
                        || group.group_id != group_id
                        || group.count != count
                        || group.body_hash != body_hash
                        || group.chunks.iter().any(Option::is_none)
                    {
                        return Err(BlossomError::InvalidConfiguration(
                            "Blossom LogStore commit does not match its chunks".to_string(),
                        ));
                    }
                    let maximum_body_bytes = match kind {
                        GroupKind::Transaction => config.max_transaction_bytes,
                        GroupKind::Checkpoint => config.max_checkpoint_bytes,
                    };
                    let body_bytes = group
                        .chunks
                        .iter()
                        .try_fold(0usize, |total, chunk| {
                            total.checked_add(chunk.as_ref().map_or(0, Vec::len))
                        })
                        .ok_or_else(|| {
                            BlossomError::InvalidConfiguration(
                                "Blossom LogStore group size overflow".to_string(),
                            )
                        })?;
                    if body_bytes > maximum_body_bytes {
                        return Err(BlossomError::InvalidConfiguration(
                            "Blossom LogStore group exceeds its configured recovery bound"
                                .to_string(),
                        ));
                    }
                    let mut body = Vec::with_capacity(body_bytes);
                    for chunk in group.chunks.into_iter().flatten() {
                        body.extend_from_slice(&chunk);
                    }
                    if hash_bytes(&body) != body_hash {
                        return Err(BlossomError::InvalidConfiguration(
                            "Blossom LogStore transaction hash mismatch".to_string(),
                        ));
                    }
                    match kind {
                        GroupKind::Transaction => {
                            if !initialized {
                                return Err(BlossomError::InvalidConfiguration(
                                    "Blossom LogStore transaction precedes its identity checkpoint"
                                        .to_string(),
                                ));
                            }
                            let transaction = borsh::from_slice::<TransactionBody>(&body)
                                .map_err(encode_error)?;
                            if transaction.base_revision != state.revision
                                || transaction.revision
                                    != state.revision.checked_add(1).ok_or_else(|| {
                                        BlossomError::InvalidConfiguration(
                                            "Blossom LogStore revision overflow".to_string(),
                                        )
                                    })?
                            {
                                return Err(BlossomError::InvalidConfiguration(
                                    "Blossom LogStore transaction revision is not consecutive"
                                        .to_string(),
                                ));
                            }
                            validate_operations(&transaction.operations, config.max_value_bytes)?;
                            if body.len() > config.max_transaction_bytes {
                                return Err(BlossomError::InvalidConfiguration(
                                    "Blossom LogStore transaction exceeds the configured recovery bound"
                                        .to_string(),
                                ));
                            }
                            apply_operations(&mut state.tables, &transaction.operations);
                            state.revision = transaction.revision;
                            replayed_transactions = replayed_transactions.saturating_add(1);
                        }
                        GroupKind::Checkpoint => {
                            let checkpoint =
                                borsh::from_slice::<CheckpointBody>(&body).map_err(encode_error)?;
                            checkpoint.identity.validate()?;
                            if checkpoint.identity != *expected_identity {
                                return Err(BlossomError::InvalidConfiguration(
                                    "Blossom LogStore identity does not match its directory"
                                        .to_string(),
                                ));
                            }
                            validate_checkpoint_tables(&checkpoint.tables, config.max_value_bytes)?;
                            if body.len() > config.max_checkpoint_bytes {
                                return Err(BlossomError::InvalidConfiguration(
                                    "Blossom LogStore checkpoint exceeds the configured recovery bound"
                                        .to_string(),
                                ));
                            }
                            state = MaterializedState {
                                revision: checkpoint.revision,
                                tables: checkpoint
                                    .tables
                                    .into_iter()
                                    .map(|(name, entries)| {
                                        (
                                            name,
                                            entries
                                                .into_iter()
                                                .map(|(key, value)| (key, Arc::<[u8]>::from(value)))
                                                .collect(),
                                        )
                                    })
                                    .collect(),
                            };
                            initialized = true;
                        }
                    }
                }
                PersistedRecord::Abort {
                    format_version,
                    kind,
                    group_id,
                    count,
                    body_hash,
                } => {
                    validate_record_version(format_version)?;
                    let group = pending.take().ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "Blossom LogStore abort has no pending transaction chunks".to_string(),
                        )
                    })?;
                    if group.kind != kind
                        || group.group_id != group_id
                        || group.count != count
                        || group.body_hash != body_hash
                    {
                        return Err(BlossomError::InvalidConfiguration(
                            "Blossom LogStore abort does not match its pending chunks".to_string(),
                        ));
                    }
                }
            }
        }
    }
    // A chunk-only group can only be an unacknowledged active tail. ShardLog
    // has already repaired truncated frames; ignoring the complete chunk prefix
    // preserves transaction atomicity.
    Ok((
        state,
        next_sequence,
        replayed_transactions,
        initialized,
        pending,
    ))
}

fn abort_pending_group(store: &mut ShardLog, sequence: u64, pending: &PendingGroup) -> Result<u64> {
    let payload = borsh::to_vec(&PersistedRecord::Abort {
        format_version: BLOSSOM_LOG_STORE_FORMAT_VERSION,
        kind: pending.kind,
        group_id: pending.group_id,
        count: pending.count,
        body_hash: pending.body_hash,
    })
    .map_err(encode_error)?;
    store
        .append_group(sequence, &[Bytes::from(payload)], true)
        .map_err(storage_error)?;
    sequence.checked_add(1).ok_or_else(|| {
        BlossomError::InvalidConfiguration("Blossom LogStore sequence overflow".to_string())
    })
}

fn validate_materialized_checkpoint(
    tables: &Tables,
    max_value_bytes: usize,
    max_checkpoint_bytes: usize,
) -> Result<()> {
    let mut estimated = 128usize;
    for (name, entries) in tables {
        validate_table_name(name)?;
        estimated = estimated
            .checked_add(name.len())
            .and_then(|size| size.checked_add(16))
            .ok_or_else(checkpoint_size_overflow)?;
        for (key, value) in entries {
            validate_key(key)?;
            if value.len() > max_value_bytes {
                return Err(BlossomError::InvalidConfiguration(
                    "Blossom LogStore checkpoint value exceeds the supported bound".to_string(),
                ));
            }
            estimated = estimated
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .and_then(|size| size.checked_add(16))
                .ok_or_else(checkpoint_size_overflow)?;
            if estimated > max_checkpoint_bytes {
                return Err(BlossomError::InvalidConfiguration(format!(
                    "Blossom LogStore checkpoint exceeds {} bytes",
                    max_checkpoint_bytes
                )));
            }
        }
    }
    Ok(())
}

fn checkpoint_size_overflow() -> BlossomError {
    BlossomError::InvalidConfiguration("Blossom LogStore checkpoint size overflow".to_string())
}

fn validate_checkpoint_tables(
    tables: &BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>,
    max_value_bytes: usize,
) -> Result<()> {
    for (name, entries) in tables {
        validate_table_name(name)?;
        for (key, value) in entries {
            validate_key(key)?;
            if value.len() > max_value_bytes {
                return Err(BlossomError::InvalidConfiguration(
                    "Blossom LogStore checkpoint value exceeds the supported bound".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_operations(operations: &[LogOperation], max_value_bytes: usize) -> Result<()> {
    for operation in operations {
        match operation {
            LogOperation::Insert { table, key, value } => {
                validate_table_name(table)?;
                validate_key(key)?;
                if value.len() > max_value_bytes {
                    return Err(BlossomError::InvalidConfiguration(
                        "Blossom LogStore value exceeds the supported bound".to_string(),
                    ));
                }
            }
            LogOperation::Remove { table, key } => {
                validate_table_name(table)?;
                validate_key(key)?;
            }
            LogOperation::RemoveRange { table, start, end } => {
                validate_table_name(table)?;
                validate_key(start)?;
                if let Some(end) = end {
                    validate_key(end)?;
                }
            }
            LogOperation::Clear { table } => validate_table_name(table)?,
        }
    }
    Ok(())
}

fn apply_operations(tables: &mut Tables, operations: &[LogOperation]) {
    for operation in operations {
        match operation {
            LogOperation::Insert { table, key, value } => {
                tables
                    .entry(table.clone())
                    .or_default()
                    .insert(key.clone(), Arc::<[u8]>::from(value.clone()));
            }
            LogOperation::Remove { table, key } => {
                if let Some(entries) = tables.get_mut(table) {
                    entries.remove(key);
                }
            }
            LogOperation::RemoveRange { table, start, end } => {
                if let Some(entries) = tables.get_mut(table) {
                    let keys = entries
                        .range::<[u8], _>((
                            std::ops::Bound::Included(start.as_slice()),
                            match end {
                                Some(end) => std::ops::Bound::Excluded(end.as_slice()),
                                None => std::ops::Bound::Unbounded,
                            },
                        ))
                        .map(|(key, _)| key.clone())
                        .collect::<Vec<_>>();
                    for key in keys {
                        entries.remove(&key);
                    }
                }
            }
            LogOperation::Clear { table } => {
                tables.remove(table);
            }
        }
    }
}

fn apply_operation_to_table(
    table: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    name: &str,
    operation: &LogOperation,
) {
    match operation {
        LogOperation::Insert {
            table: operation_table,
            key,
            value,
        } if operation_table == name => {
            table.insert(key.clone(), value.clone());
        }
        LogOperation::Remove {
            table: operation_table,
            key,
        } if operation_table == name => {
            table.remove(key);
        }
        LogOperation::RemoveRange {
            table: operation_table,
            start,
            end,
        } if operation_table == name => {
            let keys = table
                .keys()
                .filter(|key| in_range(key, start, end.as_deref()))
                .cloned()
                .collect::<Vec<_>>();
            for key in keys {
                table.remove(&key);
            }
        }
        LogOperation::Clear {
            table: operation_table,
        } if operation_table == name => table.clear(),
        _ => {}
    }
}

fn in_range(key: &[u8], start: &[u8], end: Option<&[u8]>) -> bool {
    key >= start && end.is_none_or(|end| key < end)
}

fn validate_table_name(table: &str) -> Result<()> {
    if table.is_empty()
        || table.len() > MAX_TABLE_NAME_BYTES
        || !table
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(BlossomError::InvalidConfiguration(
            "invalid Blossom LogStore table name".to_string(),
        ));
    }
    Ok(())
}

fn validate_key(key: &[u8]) -> Result<()> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(BlossomError::InvalidConfiguration(
            "invalid Blossom LogStore key length".to_string(),
        ));
    }
    Ok(())
}

fn validate_range(table: &str, start: &[u8], end: Option<&[u8]>) -> Result<()> {
    validate_table_name(table)?;
    validate_key(start)?;
    if let Some(end) = end {
        validate_key(end)?;
        if end <= start {
            return Err(BlossomError::InvalidConfiguration(
                "Blossom LogStore range end must follow its start".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_record_version(version: u16) -> Result<()> {
    if version != BLOSSOM_LOG_STORE_FORMAT_VERSION {
        return Err(BlossomError::InvalidConfiguration(format!(
            "unsupported Blossom LogStore record version {version}"
        )));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode_error(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::WireProtocol(format!("Blossom LogStore encoding: {error}"))
}

fn storage_error(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::Io(format!("Blossom LogStore storage: {error}"))
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> BlossomError {
    BlossomError::Io(format!("Blossom LogStore lock poisoned: {error}"))
}

#[cfg(test)]
mod tests {
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
            .transaction(|transaction| {
                transaction.insert("values", b"key".to_vec(), b"value".to_vec())
            })
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
            .transaction(|transaction| {
                transaction.insert("stale", b"key".to_vec(), b"value".to_vec())
            })
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
                                let value =
                                    u64::from_be_bytes(bytes.try_into().expect("u64 counter"));
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
                        candidate.as_slice() < key.as_slice()
                            || candidate.as_slice() >= end.as_slice()
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
                    transaction.insert(
                        "values",
                        b"idempotency-key".to_vec(),
                        b"committed".to_vec(),
                    )?;
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
}
