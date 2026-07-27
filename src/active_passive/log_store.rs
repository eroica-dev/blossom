#![allow(clippy::result_large_err)] // OpenRaft exposes its concrete StorageError.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::{Bound, RangeBounds};
use std::path::Path;
use std::sync::Arc;

use openraft::storage::{LogFlushed, RaftLogStorage};
use openraft::{
    LogId, LogState, RaftLogId, RaftLogReader, RaftTypeConfig, StorageError, StorageIOError, Vote,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{BlossomLogStore, BlossomLogStoreConfig, BlossomLogStoreIdentity};

const RAFT_LOG_TABLE: &str = "active_passive_raft_log_v1";
const RAFT_META_TABLE: &str = "active_passive_raft_meta_v1";
const RAFT_LOG_STORE_FORMAT_VERSION: u16 = 1;

/// Durable public identity bound to an active-passive Raft log.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RaftLogStoreIdentity<NID> {
    /// Durable identity format version.
    pub format_version: u16,
    /// Public application-defined Raft cluster name.
    pub cluster_name: String,
    /// Public OpenRaft node identifier.
    pub node_id: NID,
}

impl<NID> RaftLogStoreIdentity<NID> {
    /// Creates a version-1 public identity for one cluster node.
    pub fn new(cluster_name: impl Into<String>, node_id: NID) -> Self {
        Self {
            format_version: RAFT_LOG_STORE_FORMAT_VERSION,
            cluster_name: cluster_name.into(),
            node_id,
        }
    }
}

/// In-memory OpenRaft log store for isolated tests and ephemeral deployments.
#[derive(Clone, Debug, Default)]
pub struct MemoryRaftLogStore<C: RaftTypeConfig> {
    inner: Arc<Mutex<MemoryRaftLogStoreInner<C>>>,
}

#[derive(Debug)]
struct MemoryRaftLogStoreInner<C: RaftTypeConfig> {
    last_purged_log_id: Option<LogId<C::NodeId>>,
    log: BTreeMap<u64, C::Entry>,
    committed: Option<LogId<C::NodeId>>,
    vote: Option<Vote<C::NodeId>>,
}

impl<C: RaftTypeConfig> Default for MemoryRaftLogStoreInner<C> {
    fn default() -> Self {
        Self {
            last_purged_log_id: None,
            log: BTreeMap::new(),
            committed: None,
            vote: None,
        }
    }
}

impl<C> RaftLogReader<C> for MemoryRaftLogStore<C>
where
    C: RaftTypeConfig,
    C::Entry: Clone,
{
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> std::result::Result<Vec<C::Entry>, StorageError<C::NodeId>>
    where
        RB: RangeBounds<u64> + Clone + Debug + Send,
    {
        let inner = self.inner.lock().await;
        Ok(inner
            .log
            .range(range)
            .map(|(_, entry)| entry.clone())
            .collect())
    }
}

impl<C> RaftLogStorage<C> for MemoryRaftLogStore<C>
where
    C: RaftTypeConfig,
    C::Entry: Clone,
{
    type LogReader = Self;

    async fn get_log_state(&mut self) -> std::result::Result<LogState<C>, StorageError<C::NodeId>> {
        let inner = self.inner.lock().await;
        let last_log_id = inner
            .log
            .iter()
            .next_back()
            .map(|(_, entry)| entry.get_log_id().clone())
            .or_else(|| inner.last_purged_log_id.clone());
        Ok(LogState {
            last_purged_log_id: inner.last_purged_log_id.clone(),
            last_log_id,
        })
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<C::NodeId>>,
    ) -> std::result::Result<(), StorageError<C::NodeId>> {
        self.inner.lock().await.committed = committed;
        Ok(())
    }

    async fn read_committed(
        &mut self,
    ) -> std::result::Result<Option<LogId<C::NodeId>>, StorageError<C::NodeId>> {
        Ok(self.inner.lock().await.committed.clone())
    }

    async fn save_vote(
        &mut self,
        vote: &Vote<C::NodeId>,
    ) -> std::result::Result<(), StorageError<C::NodeId>> {
        self.inner.lock().await.vote = Some(vote.clone());
        Ok(())
    }

    async fn read_vote(
        &mut self,
    ) -> std::result::Result<Option<Vote<C::NodeId>>, StorageError<C::NodeId>> {
        Ok(self.inner.lock().await.vote.clone())
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<C>,
    ) -> std::result::Result<(), StorageError<C::NodeId>>
    where
        I: IntoIterator<Item = C::Entry> + Send,
    {
        let mut inner = self.inner.lock().await;
        for entry in entries {
            inner.log.insert(entry.get_log_id().index, entry);
        }
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(
        &mut self,
        log_id: LogId<C::NodeId>,
    ) -> std::result::Result<(), StorageError<C::NodeId>> {
        let mut inner = self.inner.lock().await;
        let keys = inner
            .log
            .range(log_id.index..)
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        for index in keys {
            inner.log.remove(&index);
        }
        Ok(())
    }

    async fn purge(
        &mut self,
        log_id: LogId<C::NodeId>,
    ) -> std::result::Result<(), StorageError<C::NodeId>> {
        let mut inner = self.inner.lock().await;
        if inner.last_purged_log_id.as_ref() > Some(&log_id) {
            return Ok(());
        }
        inner.last_purged_log_id = Some(log_id.clone());
        let keys = inner
            .log
            .range(..=log_id.index)
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        for index in keys {
            inner.log.remove(&index);
        }
        Ok(())
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }
}

/// OpenRaft's v2 log-store adapter over [`BlossomLogStore`].
///
/// All reads come from immutable in-memory materialized tables. Durable
/// mutations run on Tokio's blocking pool and return only after ShardLog has
/// synchronized the complete transaction.
#[derive(Clone)]
pub struct ShardStreamRaftLogStore<C: RaftTypeConfig> {
    store: BlossomLogStore,
    identity: RaftLogStoreIdentity<C::NodeId>,
    marker: std::marker::PhantomData<fn() -> C>,
}

impl<C: RaftTypeConfig> Debug for ShardStreamRaftLogStore<C>
where
    C::NodeId: Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ShardStreamRaftLogStore")
            .field("identity", &self.identity)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl<C> ShardStreamRaftLogStore<C>
where
    C: RaftTypeConfig,
    C::NodeId: Clone + PartialEq + Serialize + DeserializeOwned,
{
    /// Opens a durable Raft log directory and binds it to a public cluster and
    /// node identity. Legacy database files fail closed and are never overwritten.
    pub fn open_bound(
        path: impl AsRef<Path>,
        identity: RaftLogStoreIdentity<C::NodeId>,
    ) -> std::result::Result<Self, StorageError<C::NodeId>> {
        validate_identity(&identity)?;
        let public_scope =
            serde_json::to_vec(&identity).map_err(|error| write_error(error.to_string()))?;
        let store_identity =
            BlossomLogStoreIdentity::new("active-passive-openraft", public_scope, 1)
                .map_err(|error| write_error(error.to_string()))?;
        let store =
            BlossomLogStore::open(BlossomLogStoreConfig::new(path.as_ref()), store_identity)
                .map_err(|error| write_error(error.to_string()))?;
        Ok(Self {
            store,
            identity,
            marker: std::marker::PhantomData,
        })
    }

    /// Wraps an existing LogStore whose public identity matches `identity`.
    pub fn from_log_store(
        store: BlossomLogStore,
        identity: RaftLogStoreIdentity<C::NodeId>,
    ) -> std::result::Result<Self, StorageError<C::NodeId>> {
        validate_identity(&identity)?;
        let public_scope =
            serde_json::to_vec(&identity).map_err(|error| write_error(error.to_string()))?;
        if store.identity().store_kind != "active-passive-openraft"
            || store.identity().public_scope != public_scope
            || store.identity().generation != 1
        {
            return Err(write_error(
                "active-passive Raft LogStore identity mismatch".to_string(),
            ));
        }
        Ok(Self {
            store,
            identity,
            marker: std::marker::PhantomData,
        })
    }

    /// Returns a clone of the shared transactional storage handle.
    pub fn log_store(&self) -> BlossomLogStore {
        self.store.clone()
    }

    /// Returns the public cluster and node identity bound to the log.
    pub fn identity(&self) -> RaftLogStoreIdentity<C::NodeId> {
        self.identity.clone()
    }

    fn read_meta<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> std::result::Result<Option<T>, StorageError<C::NodeId>> {
        self.store
            .get(RAFT_META_TABLE, key.as_bytes())
            .map_err(|error| read_error(error.to_string()))?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|error| read_error(error.to_string()))
            })
            .transpose()
    }

    async fn write_meta<T>(
        &self,
        key: &'static str,
        value: &T,
        vote: bool,
    ) -> std::result::Result<(), StorageError<C::NodeId>>
    where
        T: Serialize,
        C::NodeId: Send + 'static,
    {
        let bytes = serde_json::to_vec(value).map_err(|error| {
            if vote {
                vote_write_error(error.to_string())
            } else {
                write_error(error.to_string())
            }
        })?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            store
                .transaction(|transaction| {
                    transaction.insert(RAFT_META_TABLE, key.as_bytes().to_vec(), bytes)?;
                    Ok(())
                })
                .map(|_| ())
        })
        .await
        .map_err(|error| write_error(format!("Raft LogStore blocking task failed: {error}")))?
        .map_err(|error| {
            if vote {
                vote_write_error(error.to_string())
            } else {
                write_error(error.to_string())
            }
        })
    }
}

impl<C> RaftLogReader<C> for ShardStreamRaftLogStore<C>
where
    C: RaftTypeConfig,
    C::Entry: Clone + Serialize + DeserializeOwned,
    C::NodeId: Clone + PartialEq + Serialize + DeserializeOwned,
{
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> std::result::Result<Vec<C::Entry>, StorageError<C::NodeId>>
    where
        RB: RangeBounds<u64> + Clone + Debug + Send,
    {
        let Some((start, end)) = index_range(&range) else {
            return Ok(Vec::new());
        };
        let end_key = end.map(index_key);
        self.store
            .scan_range(
                RAFT_LOG_TABLE,
                &index_key(start),
                end_key.as_ref().map(<[u8; 8]>::as_slice),
            )
            .map_err(|error| read_error(error.to_string()))?
            .into_iter()
            .map(|(_, value)| {
                serde_json::from_slice(&value).map_err(|error| read_error(error.to_string()))
            })
            .collect()
    }
}

impl<C> RaftLogStorage<C> for ShardStreamRaftLogStore<C>
where
    C: RaftTypeConfig + 'static,
    C::Entry: Clone + Serialize + DeserializeOwned + Send + 'static,
    C::NodeId: Clone + PartialEq + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type LogReader = Self;

    async fn get_log_state(&mut self) -> std::result::Result<LogState<C>, StorageError<C::NodeId>> {
        let last_log_id = self
            .store
            .scan(RAFT_LOG_TABLE)
            .map_err(|error| read_error(error.to_string()))?
            .last()
            .map(|(_, value)| {
                serde_json::from_slice::<C::Entry>(value)
                    .map(|entry| entry.get_log_id().clone())
                    .map_err(|error| read_error(error.to_string()))
            })
            .transpose()?;
        let last_purged_log_id = self.read_meta("last_purged_log_id")?;
        Ok(LogState {
            last_log_id: last_log_id.or_else(|| last_purged_log_id.clone()),
            last_purged_log_id,
        })
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<C::NodeId>>,
    ) -> std::result::Result<(), StorageError<C::NodeId>> {
        self.write_meta("committed", &committed, false).await
    }

    async fn read_committed(
        &mut self,
    ) -> std::result::Result<Option<LogId<C::NodeId>>, StorageError<C::NodeId>> {
        Ok(self.read_meta("committed")?.flatten())
    }

    async fn save_vote(
        &mut self,
        vote: &Vote<C::NodeId>,
    ) -> std::result::Result<(), StorageError<C::NodeId>> {
        self.write_meta("vote", vote, true).await
    }

    async fn read_vote(
        &mut self,
    ) -> std::result::Result<Option<Vote<C::NodeId>>, StorageError<C::NodeId>> {
        self.read_meta("vote").map_err(|error| match error {
            StorageError::IO { source } => StorageError::IO {
                source: StorageIOError::read_vote(&source),
            },
            error => error,
        })
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<C>,
    ) -> std::result::Result<(), StorageError<C::NodeId>>
    where
        I: IntoIterator<Item = C::Entry> + Send,
    {
        let entries = match entries
            .into_iter()
            .map(|entry| {
                let index = entry.get_log_id().index;
                serde_json::to_vec(&entry)
                    .map(|bytes| (index, bytes))
                    .map_err(|error| {
                        StorageIOError::write_log_entry(entry.get_log_id().clone(), &error).into()
                    })
            })
            .collect::<std::result::Result<Vec<_>, StorageError<C::NodeId>>>()
        {
            Ok(entries) => entries,
            Err(error) => {
                callback.log_io_completed(Err(std::io::Error::other(error.to_string())));
                return Err(error);
            }
        };
        let store = self.store.clone();
        let durable = tokio::task::spawn_blocking(move || {
            store
                .transaction(|transaction| {
                    for (index, bytes) in entries {
                        transaction.insert(RAFT_LOG_TABLE, index_key(index).to_vec(), bytes)?;
                    }
                    Ok(())
                })
                .map(|_| ())
        })
        .await
        .map_err(|error| format!("Raft LogStore blocking task failed: {error}"))
        .and_then(|result| result.map_err(|error| error.to_string()));
        match durable {
            Ok(()) => {
                callback.log_io_completed(Ok(()));
                Ok(())
            }
            Err(message) => {
                callback.log_io_completed(Err(std::io::Error::other(message.clone())));
                Err(write_error(message))
            }
        }
    }

    async fn truncate(
        &mut self,
        log_id: LogId<C::NodeId>,
    ) -> std::result::Result<(), StorageError<C::NodeId>> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            store
                .transaction(|transaction| {
                    transaction.remove_range(
                        RAFT_LOG_TABLE,
                        index_key(log_id.index).to_vec(),
                        None,
                    )?;
                    Ok(())
                })
                .map(|_| ())
        })
        .await
        .map_err(|error| write_error(format!("Raft LogStore blocking task failed: {error}")))?
        .map_err(|error| write_error(error.to_string()))
    }

    async fn purge(
        &mut self,
        log_id: LogId<C::NodeId>,
    ) -> std::result::Result<(), StorageError<C::NodeId>> {
        let encoded =
            serde_json::to_vec(&log_id).map_err(|error| write_error(error.to_string()))?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            store
                .transaction(|transaction| {
                    let existing = transaction
                        .get(RAFT_META_TABLE, b"last_purged_log_id")?
                        .map(|bytes| {
                            serde_json::from_slice::<LogId<C::NodeId>>(&bytes).map_err(|error| {
                                crate::BlossomError::WireProtocol(format!(
                                    "decode Raft purge watermark: {error}"
                                ))
                            })
                        })
                        .transpose()?;
                    if existing.as_ref() > Some(&log_id) {
                        return Ok(());
                    }
                    transaction.insert(RAFT_META_TABLE, b"last_purged_log_id".to_vec(), encoded)?;
                    let end = log_id.index.checked_add(1).map(index_key);
                    transaction.remove_range(
                        RAFT_LOG_TABLE,
                        index_key(0).to_vec(),
                        end.map(|key| key.to_vec()),
                    )?;
                    Ok(())
                })
                .map(|_| ())
        })
        .await
        .map_err(|error| write_error(format!("Raft LogStore blocking task failed: {error}")))?
        .map_err(|error| write_error(error.to_string()))
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }
}

fn validate_identity<NID: openraft::NodeId>(
    identity: &RaftLogStoreIdentity<NID>,
) -> std::result::Result<(), StorageError<NID>> {
    if identity.format_version != RAFT_LOG_STORE_FORMAT_VERSION
        || identity.cluster_name.trim().is_empty()
    {
        return Err(write_error(
            "active-passive Raft identity requires format v1 and a non-empty cluster name"
                .to_string(),
        ));
    }
    Ok(())
}

fn index_key(index: u64) -> [u8; 8] {
    index.to_be_bytes()
}

fn index_range(range: &impl RangeBounds<u64>) -> Option<(u64, Option<u64>)> {
    let start = match range.start_bound() {
        Bound::Included(index) => *index,
        Bound::Excluded(index) => index.checked_add(1)?,
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(index) => index.checked_add(1),
        Bound::Excluded(index) => Some(*index),
        Bound::Unbounded => None,
    };
    if end.is_some_and(|end| end <= start) {
        None
    } else {
        Some((start, end))
    }
}

fn read_error<NID: openraft::NodeId>(message: String) -> StorageError<NID> {
    let error = std::io::Error::other(message);
    StorageIOError::read_logs(&error).into()
}

fn write_error<NID: openraft::NodeId>(message: String) -> StorageError<NID> {
    let error = std::io::Error::other(message);
    StorageIOError::write_logs(&error).into()
}

fn vote_write_error<NID: openraft::NodeId>(message: String) -> StorageError<NID> {
    let error = std::io::Error::other(message);
    StorageIOError::write_vote(&error).into()
}
