#![allow(clippy::result_large_err)] // OpenRaft's storage API returns its concrete StorageError.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

use openraft::storage::{LogFlushed, RaftLogStorage};
use openraft::{
    LogId, LogState, RaftLogId, RaftLogReader, RaftTypeConfig, StorageError, StorageIOError, Vote,
};
use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

const RAFT_LOG_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("benchmark_raft_log_v1");
const RAFT_META_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("benchmark_raft_meta_v1");

#[derive(Clone, Debug, Default)]
pub struct MemoryLogStore<C: RaftTypeConfig> {
    inner: Arc<Mutex<MemoryLogStoreInner<C>>>,
}

#[derive(Debug)]
struct MemoryLogStoreInner<C: RaftTypeConfig> {
    last_purged_log_id: Option<LogId<C::NodeId>>,
    log: BTreeMap<u64, C::Entry>,
    committed: Option<LogId<C::NodeId>>,
    vote: Option<Vote<C::NodeId>>,
}

impl<C: RaftTypeConfig> Default for MemoryLogStoreInner<C> {
    fn default() -> Self {
        Self {
            last_purged_log_id: None,
            log: BTreeMap::new(),
            committed: None,
            vote: None,
        }
    }
}

impl<C> RaftLogReader<C> for MemoryLogStore<C>
where
    C: RaftTypeConfig,
    C::Entry: Clone,
{
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<C::Entry>, StorageError<C::NodeId>>
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

impl<C> RaftLogStorage<C> for MemoryLogStore<C>
where
    C: RaftTypeConfig,
    C::Entry: Clone,
{
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<C>, StorageError<C::NodeId>> {
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
    ) -> Result<(), StorageError<C::NodeId>> {
        self.inner.lock().await.committed = committed;
        Ok(())
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<C::NodeId>>, StorageError<C::NodeId>> {
        Ok(self.inner.lock().await.committed.clone())
    }

    async fn save_vote(&mut self, vote: &Vote<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
        self.inner.lock().await.vote = Some(vote.clone());
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<C::NodeId>>, StorageError<C::NodeId>> {
        Ok(self.inner.lock().await.vote.clone())
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<C>,
    ) -> Result<(), StorageError<C::NodeId>>
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

    async fn truncate(&mut self, log_id: LogId<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
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

    async fn purge(&mut self, log_id: LogId<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
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

/// Immediate-durability redb implementation of OpenRaft's v2 log store.
///
/// This is used only by durable benchmark profiles; the protocol-core profile
/// deliberately uses [`MemoryLogStore`].
#[derive(Clone)]
pub struct RedbLogStore<C: RaftTypeConfig> {
    database: Arc<Database>,
    marker: std::marker::PhantomData<C>,
}

impl<C: RaftTypeConfig> std::fmt::Debug for RedbLogStore<C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedbLogStore")
            .finish_non_exhaustive()
    }
}

impl<C: RaftTypeConfig> RedbLogStore<C> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError<C::NodeId>> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent).map_err(|error| StorageIOError::write_logs(&error))?;
        }
        let database =
            Database::create(path).map_err(|error| StorageIOError::write_logs(&error))?;
        let store = Self {
            database: Arc::new(database),
            marker: std::marker::PhantomData,
        };
        store.initialize()?;
        Ok(store)
    }

    pub fn from_database(database: Arc<Database>) -> Result<Self, StorageError<C::NodeId>> {
        let store = Self {
            database,
            marker: std::marker::PhantomData,
        };
        store.initialize()?;
        Ok(store)
    }

    pub fn database(&self) -> Arc<Database> {
        self.database.clone()
    }

    fn initialize(&self) -> Result<(), StorageError<C::NodeId>> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StorageIOError::write_logs(&error))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StorageIOError::write_logs(&error))?;
        {
            transaction
                .open_table(RAFT_LOG_TABLE)
                .map_err(|error| StorageIOError::write_logs(&error))?;
            transaction
                .open_table(RAFT_META_TABLE)
                .map_err(|error| StorageIOError::write_logs(&error))?;
        }
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_logs(&error).into())
    }

    fn read_meta<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, StorageError<C::NodeId>> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StorageIOError::read_logs(&error))?;
        let table = transaction
            .open_table(RAFT_META_TABLE)
            .map_err(|error| StorageIOError::read_logs(&error))?;
        let Some(value) = table
            .get(key)
            .map_err(|error| StorageIOError::read_logs(&error))?
        else {
            return Ok(None);
        };
        serde_json::from_slice(value.value())
            .map(Some)
            .map_err(|error| StorageIOError::read_logs(&error).into())
    }

    fn write_meta<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        vote: bool,
    ) -> Result<(), StorageError<C::NodeId>> {
        let bytes = serde_json::to_vec(value).map_err(|error| {
            if vote {
                StorageIOError::write_vote(&error)
            } else {
                StorageIOError::write_logs(&error)
            }
        })?;
        let mut transaction = self.database.begin_write().map_err(|error| {
            if vote {
                StorageIOError::write_vote(&error)
            } else {
                StorageIOError::write_logs(&error)
            }
        })?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| {
                if vote {
                    StorageIOError::write_vote(&error)
                } else {
                    StorageIOError::write_logs(&error)
                }
            })?;
        {
            let mut table = transaction.open_table(RAFT_META_TABLE).map_err(|error| {
                if vote {
                    StorageIOError::write_vote(&error)
                } else {
                    StorageIOError::write_logs(&error)
                }
            })?;
            table.insert(key, bytes.as_slice()).map_err(|error| {
                if vote {
                    StorageIOError::write_vote(&error)
                } else {
                    StorageIOError::write_logs(&error)
                }
            })?;
        }
        transaction.commit().map_err(|error| {
            if vote {
                StorageIOError::write_vote(&error).into()
            } else {
                StorageIOError::write_logs(&error).into()
            }
        })
    }
}

impl<C> RaftLogReader<C> for RedbLogStore<C>
where
    C: RaftTypeConfig,
    C::Entry: Clone + Serialize + DeserializeOwned,
{
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<C::Entry>, StorageError<C::NodeId>>
    where
        RB: RangeBounds<u64> + Clone + Debug + Send,
    {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StorageIOError::read_logs(&error))?;
        let table = transaction
            .open_table(RAFT_LOG_TABLE)
            .map_err(|error| StorageIOError::read_logs(&error))?;
        table
            .range(range)
            .map_err(|error| StorageIOError::read_logs(&error))?
            .map(|entry| {
                let (_, value) = entry.map_err(|error| StorageIOError::read_logs(&error))?;
                serde_json::from_slice(value.value())
                    .map_err(|error| StorageIOError::read_logs(&error).into())
            })
            .collect()
    }
}

impl<C> RaftLogStorage<C> for RedbLogStore<C>
where
    C: RaftTypeConfig,
    C::Entry: Clone + Serialize + DeserializeOwned,
    C::NodeId: Serialize + DeserializeOwned,
{
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<C>, StorageError<C::NodeId>> {
        let transaction = self
            .database
            .begin_read()
            .map_err(|error| StorageIOError::read_logs(&error))?;
        let table = transaction
            .open_table(RAFT_LOG_TABLE)
            .map_err(|error| StorageIOError::read_logs(&error))?;
        let last_log_id = table
            .last()
            .map_err(|error| StorageIOError::read_logs(&error))?
            .map(|(_, value)| {
                serde_json::from_slice::<C::Entry>(value.value())
                    .map(|entry| entry.get_log_id().clone())
                    .map_err(|error| StorageIOError::read_logs(&error))
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
    ) -> Result<(), StorageError<C::NodeId>> {
        self.write_meta("committed", &committed, false)
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<C::NodeId>>, StorageError<C::NodeId>> {
        Ok(self.read_meta("committed")?.flatten())
    }

    async fn save_vote(&mut self, vote: &Vote<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
        self.write_meta("vote", vote, true)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<C::NodeId>>, StorageError<C::NodeId>> {
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
    ) -> Result<(), StorageError<C::NodeId>>
    where
        I: IntoIterator<Item = C::Entry> + Send,
    {
        let entries = entries
            .into_iter()
            .map(|entry| {
                let index = entry.get_log_id().index;
                let bytes = serde_json::to_vec(&entry).map_err(|error| {
                    StorageIOError::write_log_entry(entry.get_log_id().clone(), &error)
                })?;
                Ok((index, bytes))
            })
            .collect::<Result<Vec<_>, StorageIOError<C::NodeId>>>()?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StorageIOError::write_logs(&error))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StorageIOError::write_logs(&error))?;
        {
            let mut table = transaction
                .open_table(RAFT_LOG_TABLE)
                .map_err(|error| StorageIOError::write_logs(&error))?;
            for (index, bytes) in entries {
                table
                    .insert(index, bytes.as_slice())
                    .map_err(|error| StorageIOError::write_logs(&error))?;
            }
        }
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_logs(&error))?;
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StorageIOError::write_logs(&error))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StorageIOError::write_logs(&error))?;
        {
            let mut table = transaction
                .open_table(RAFT_LOG_TABLE)
                .map_err(|error| StorageIOError::write_logs(&error))?;
            let keys = table
                .range(log_id.index..)
                .map_err(|error| StorageIOError::write_logs(&error))?
                .map(|entry| {
                    entry
                        .map(|(key, _)| key.value())
                        .map_err(|error| StorageIOError::write_logs(&error))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for key in keys {
                table
                    .remove(key)
                    .map_err(|error| StorageIOError::write_logs(&error))?;
            }
        }
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_logs(&error).into())
    }

    async fn purge(&mut self, log_id: LogId<C::NodeId>) -> Result<(), StorageError<C::NodeId>> {
        let last_purged =
            serde_json::to_vec(&log_id).map_err(|error| StorageIOError::write_logs(&error))?;
        let mut transaction = self
            .database
            .begin_write()
            .map_err(|error| StorageIOError::write_logs(&error))?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(|error| StorageIOError::write_logs(&error))?;
        {
            let mut meta = transaction
                .open_table(RAFT_META_TABLE)
                .map_err(|error| StorageIOError::write_logs(&error))?;
            meta.insert("last_purged_log_id", last_purged.as_slice())
                .map_err(|error| StorageIOError::write_logs(&error))?;
            let mut table = transaction
                .open_table(RAFT_LOG_TABLE)
                .map_err(|error| StorageIOError::write_logs(&error))?;
            let keys = table
                .range(..=log_id.index)
                .map_err(|error| StorageIOError::write_logs(&error))?
                .map(|entry| {
                    entry
                        .map(|(key, _)| key.value())
                        .map_err(|error| StorageIOError::write_logs(&error))
                })
                .collect::<Result<Vec<_>, _>>()?;
            for key in keys {
                table
                    .remove(key)
                    .map_err(|error| StorageIOError::write_logs(&error))?;
            }
        }
        transaction
            .commit()
            .map_err(|error| StorageIOError::write_logs(&error).into())
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }
}
