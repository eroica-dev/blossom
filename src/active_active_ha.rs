//! Service-level active-active orchestration over the fixed-slot HA runtime.
//!
//! The HA runtime owns consensus and membership safety. This layer keeps the
//! application routing contract and locally accepted-write disposition
//! explicit across catch-up and membership cutovers.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::active_active::{
    ActiveActiveCommand, CommandIdentity, CommandSpecVersion, RouteGeneration,
};
use crate::block::Transaction;
use crate::error::{BlossomError, Result};
use crate::hash::HashType;
use crate::high_availability::{
    HaMemberSlot, HaMembershipCertificate, HaMembershipVote, HaOperationalStatus,
    HaRecoverySnapshot, HaRuntimeEvent, HighAvailabilityRuntime, NodeAvailabilityStatus,
    StateRevision,
};
use crate::nonce::Nonce;
use crate::{
    BlossomLogStore, BlossomLogStoreConfig, BlossomLogStoreIdentity, BlossomLogTransaction,
};

const ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_DOMAIN: &[u8] =
    b"blossom/active-active/ha-recovery-manifest/v2";
const ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_DOMAIN: &[u8] =
    b"blossom/active-active/ha-cutover-manifest/v2";
const ACTIVE_ACTIVE_HA_DURABLE_METADATA_DOMAIN: &[u8] =
    b"blossom/active-active/ha-durable-metadata/v2";
const ACTIVE_ACTIVE_HA_DURABLE_RECORD_DOMAIN: &[u8] = b"blossom/active-active/ha-durable-record/v2";
const ACTIVE_ACTIVE_HA_DURABLE_DELTA_DOMAIN: &[u8] = b"blossom/active-active/ha-durable-delta/v2";
const ACTIVE_ACTIVE_HA_METADATA_TABLE: &str = "active_active_ha_metadata_v2";
const ACTIVE_ACTIVE_HA_ACCEPTED_WRITES_TABLE: &str = "active_active_ha_accepted_writes_v2";
const ACTIVE_ACTIVE_HA_JOURNAL_TABLE: &str = "active_active_ha_journal_v2";
const ACTIVE_ACTIVE_HA_METADATA_KEY: &[u8] = b"metadata";
const ACTIVE_ACTIVE_HA_STORE_SCOPE: &[u8] = b"blossom/active-active/ha-lifecycle/v2";
const ACTIVE_ACTIVE_HA_STATE_FORMAT_VERSION: u16 = 2;
#[cfg(not(test))]
const ACTIVE_ACTIVE_HA_JOURNAL_CHECKPOINT_ENTRIES: u64 = 1_024;
#[cfg(test)]
const ACTIVE_ACTIVE_HA_JOURNAL_CHECKPOINT_ENTRIES: u64 = 8;
const ACTIVE_ACTIVE_HA_JOURNAL_CHECKPOINT_BYTES: u64 = 32 << 20;
pub const ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_VERSION: u16 = 2;
pub const ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_VERSION: u16 = 2;
pub const MAX_ACCEPTED_WRITE_ABORT_REASON_BYTES: usize = 1 << 10;
/// Maximum outstanding lifecycle records and maximum records in one grouped
/// durability mutation. This covers sixteen 4,096-command application-shard
/// batches while remaining bounded by the 64 MiB command-byte cap.
pub const MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES: usize = 65_536;
pub const MAX_ACTIVE_ACTIVE_HA_SHARD_LANES: usize = 256;
pub const MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES: usize = 64 << 20;
const MAX_ACTIVE_ACTIVE_HA_DURABLE_STATE_BYTES: usize = 128 << 20;

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum AcceptedWriteDisposition {
    Pending,
    Recertified {
        from: RouteGeneration,
        to: RouteGeneration,
        from_command_spec_version: CommandSpecVersion,
        to_command_spec_version: CommandSpecVersion,
        command: ActiveActiveCommand,
        command_hash: HashType,
    },
    Aborted {
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
        reason: String,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AcceptedWriteRecord {
    pub command: ActiveActiveCommand,
    pub command_hash: HashType,
    pub command_spec_version: CommandSpecVersion,
    pub accepted_route_generation: RouteGeneration,
    pub disposition: AcceptedWriteDisposition,
}

impl AcceptedWriteRecord {
    fn validate(&self) -> Result<()> {
        self.command.validate()?;
        self.command_spec_version.validate()?;
        self.accepted_route_generation.validate()?;
        if self.command.hash()? != self.command_hash {
            return Err(BlossomError::InvalidConfiguration(
                "accepted-write record hash does not match its command".to_string(),
            ));
        }
        match &self.disposition {
            AcceptedWriteDisposition::Pending => {}
            AcceptedWriteDisposition::Recertified {
                from,
                to,
                from_command_spec_version,
                to_command_spec_version,
                command,
                command_hash,
            } => {
                from.validate()?;
                to.validate()?;
                from_command_spec_version.validate()?;
                to_command_spec_version.validate()?;
                command.validate()?;
                if *from != self.accepted_route_generation
                    || *from_command_spec_version != self.command_spec_version
                    || to.0 <= from.0
                    || to_command_spec_version.0 < from_command_spec_version.0
                    || command.identity != self.command.identity
                    || command.hash()? != *command_hash
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "accepted-write recertification has an invalid target application contract"
                            .to_string(),
                    ));
                }
            }
            AcceptedWriteDisposition::Aborted {
                route_generation,
                command_spec_version,
                reason,
            } => {
                route_generation.validate()?;
                command_spec_version.validate()?;
                if *route_generation != self.accepted_route_generation
                    || *command_spec_version != self.command_spec_version
                    || reason.is_empty()
                    || reason.len() > MAX_ACCEPTED_WRITE_ABORT_REASON_BYTES
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "accepted-write abort record is invalid".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct ActiveActiveCutover {
    pub from: RouteGeneration,
    pub to: RouteGeneration,
    pub from_command_spec_version: CommandSpecVersion,
    pub to_command_spec_version: CommandSpecVersion,
    pub membership_generation: u64,
    pub active_mask: u8,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
struct ActiveActiveHaDurableMetadata {
    format_version: u16,
    route_generation: RouteGeneration,
    command_spec_version: CommandSpecVersion,
    accepted_write_count: u32,
    accepted_command_bytes: u64,
    accepted_writes_commitment: HashType,
    cutover: Option<ActiveActiveCutover>,
    next_journal_sequence: u64,
    journal_entries_since_checkpoint: u32,
    metadata_hash: HashType,
}

impl ActiveActiveHaDurableMetadata {
    fn new(
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
        accepted_write_count: usize,
        accepted_command_bytes: usize,
        accepted_writes_commitment: HashType,
        cutover: Option<ActiveActiveCutover>,
    ) -> Result<Self> {
        let accepted_write_count = u32::try_from(accepted_write_count).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "active-active HA accepted-write count exceeds u32".to_string(),
            )
        })?;
        let accepted_command_bytes = u64::try_from(accepted_command_bytes).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "active-active HA accepted command bytes exceed u64".to_string(),
            )
        })?;
        let mut metadata = Self {
            format_version: ACTIVE_ACTIVE_HA_STATE_FORMAT_VERSION,
            route_generation,
            command_spec_version,
            accepted_write_count,
            accepted_command_bytes,
            accepted_writes_commitment,
            cutover,
            next_journal_sequence: 0,
            journal_entries_since_checkpoint: 0,
            metadata_hash: HashType::default(),
        };
        metadata.metadata_hash = metadata.compute_hash()?;
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<()> {
        if self.format_version != ACTIVE_ACTIVE_HA_STATE_FORMAT_VERSION {
            return Err(BlossomError::InvalidConfiguration(
                "unsupported active-active HA durable-state version".to_string(),
            ));
        }
        self.route_generation.validate()?;
        self.command_spec_version.validate()?;
        if usize::try_from(self.accepted_write_count).unwrap_or(usize::MAX)
            > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES
            || usize::try_from(self.accepted_command_bytes).unwrap_or(usize::MAX)
                > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA durable metadata exceeds accepted-write bounds".to_string(),
            ));
        }
        validate_cutover_contract(
            self.route_generation,
            self.command_spec_version,
            self.cutover,
        )?;
        if self.compute_hash()? != self.metadata_hash {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA durable metadata hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn set_journal_position(
        &mut self,
        next_journal_sequence: u64,
        journal_entries_since_checkpoint: u32,
    ) -> Result<()> {
        self.next_journal_sequence = next_journal_sequence;
        self.journal_entries_since_checkpoint = journal_entries_since_checkpoint;
        self.metadata_hash = HashType::default();
        self.metadata_hash = self.compute_hash()?;
        self.validate()
    }

    fn compute_hash(&self) -> Result<HashType> {
        let mut unhashed = self.clone();
        unhashed.metadata_hash = HashType::default();
        manifest_hash(ACTIVE_ACTIVE_HA_DURABLE_METADATA_DOMAIN, &unhashed)
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
struct ActiveActiveHaDurableDelta {
    format_version: u16,
    upserts: Vec<AcceptedWriteRecord>,
    removals: Vec<CommandIdentity>,
    delta_hash: HashType,
}

impl ActiveActiveHaDurableDelta {
    fn new(upserts: Vec<AcceptedWriteRecord>, removals: Vec<CommandIdentity>) -> Result<Self> {
        let mut delta = Self {
            format_version: ACTIVE_ACTIVE_HA_STATE_FORMAT_VERSION,
            upserts,
            removals,
            delta_hash: HashType::default(),
        };
        delta.validate_canonical_shape()?;
        delta.delta_hash = delta.compute_hash()?;
        Ok(delta)
    }

    fn validate(&self) -> Result<()> {
        self.validate_canonical_shape()?;
        for record in &self.upserts {
            record.validate()?;
        }
        if self.compute_hash()? != self.delta_hash {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA durable delta hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_canonical_shape(&self) -> Result<()> {
        if self.format_version != ACTIVE_ACTIVE_HA_STATE_FORMAT_VERSION
            || self.upserts.len() > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES
            || self.removals.len() > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA durable delta has an unsupported version or size".to_string(),
            ));
        }
        let mut previous_upsert = None;
        for record in &self.upserts {
            if previous_upsert.is_some_and(|identity| identity >= record.command.identity) {
                return Err(BlossomError::InvalidConfiguration(
                    "active-active HA durable delta upserts are not canonical".to_string(),
                ));
            }
            previous_upsert = Some(record.command.identity);
        }
        let mut previous_removal = None;
        for identity in &self.removals {
            if previous_removal.is_some_and(|previous| previous >= *identity) {
                return Err(BlossomError::InvalidConfiguration(
                    "active-active HA durable delta removals are not canonical".to_string(),
                ));
            }
            previous_removal = Some(*identity);
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<HashType> {
        // Pending record command hashes already commit canonical command
        // identity and bytes. Hash compact fixed-width commitments here so a
        // hot-path journal append does not serialize every command twice.
        let upsert_count = u32::try_from(self.upserts.len()).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "active-active HA durable delta upsert count exceeds u32".to_string(),
            )
        })?;
        let removal_count = u32::try_from(self.removals.len()).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "active-active HA durable delta removal count exceeds u32".to_string(),
            )
        })?;
        let mut canonical =
            Vec::with_capacity(2 + 4 + (self.upserts.len() * 32) + 4 + (self.removals.len() * 32));
        canonical.extend_from_slice(&self.format_version.to_le_bytes());
        canonical.extend_from_slice(&upsert_count.to_le_bytes());
        for record in &self.upserts {
            canonical.extend_from_slice(accepted_write_record_commitment(record)?.as_ref());
        }
        canonical.extend_from_slice(&removal_count.to_le_bytes());
        for identity in &self.removals {
            canonical.extend_from_slice(&identity.client_id.0);
            canonical.extend_from_slice(&identity.client_epoch.0.to_le_bytes());
            canonical.extend_from_slice(&identity.sequence.to_le_bytes());
        }
        Ok(HashType::hash_slices([
            ACTIVE_ACTIVE_HA_DURABLE_DELTA_DOMAIN,
            canonical.as_slice(),
        ]))
    }

    fn apply_to(&self, accepted_writes: &mut BTreeMap<CommandIdentity, AcceptedWriteRecord>) {
        for identity in &self.removals {
            accepted_writes.remove(identity);
        }
        for record in &self.upserts {
            accepted_writes.insert(record.command.identity, record.clone());
        }
    }
}

struct ActiveActiveHaLoadedState {
    metadata: ActiveActiveHaDurableMetadata,
    accepted_writes: BTreeMap<CommandIdentity, AcceptedWriteRecord>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveActiveHaLifecycleDurabilityMetrics {
    pub commit_count: u64,
    pub fsync_count: u64,
}

/// Commands and canonical hashes prepared independently by one application
/// shard before the shared HA group commit.
#[derive(Debug, Clone)]
pub struct PreparedActiveActiveHaShardBatch {
    commands: Vec<(ActiveActiveCommand, HashType)>,
}

impl PreparedActiveActiveHaShardBatch {
    pub fn prepare(commands: Vec<ActiveActiveCommand>) -> Result<Self> {
        if commands.len() > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA shard batch exceeds {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES}"
            )));
        }
        let commands = commands
            .into_iter()
            .map(|command| {
                let command_hash = command.hash()?;
                Ok((command, command_hash))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { commands })
    }

    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    pub fn command_hashes(&self) -> Vec<HashType> {
        self.commands
            .iter()
            .map(|(_, command_hash)| *command_hash)
            .collect()
    }

    pub fn identities_and_hashes(
        &self,
    ) -> impl ExactSizeIterator<Item = (CommandIdentity, HashType)> + '_ {
        self.commands
            .iter()
            .map(|(command, command_hash)| (command.identity, *command_hash))
    }
}

#[derive(Clone)]
struct ActiveActiveHaDurableStore {
    store: BlossomLogStore,
    journal_entries: Arc<AtomicU64>,
    journal_bytes: Arc<AtomicU64>,
}

impl ActiveActiveHaDurableStore {
    fn open(path: impl AsRef<Path>) -> Result<Self> {
        let identity = BlossomLogStoreIdentity::new(
            "active-active-ha",
            ACTIVE_ACTIVE_HA_STORE_SCOPE,
            u64::from(ACTIVE_ACTIVE_HA_STATE_FORMAT_VERSION),
        )?;
        let mut config = BlossomLogStoreConfig::new(path.as_ref());
        config.max_value_bytes = MAX_ACTIVE_ACTIVE_HA_DURABLE_STATE_BYTES;
        let store = Self {
            store: BlossomLogStore::open(config, identity)?,
            journal_entries: Arc::new(AtomicU64::new(0)),
            journal_bytes: Arc::new(AtomicU64::new(0)),
        };
        Ok(store)
    }

    fn durability_metrics(&self) -> ActiveActiveHaLifecycleDurabilityMetrics {
        let metrics = self.store.durability_metrics();
        ActiveActiveHaLifecycleDurabilityMetrics {
            commit_count: metrics.committed_transactions,
            fsync_count: metrics.fsyncs,
        }
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut BlossomLogTransaction<'_>) -> Result<T>,
    ) -> Result<T> {
        self.store.transaction(operation).map(|(result, _)| result)
    }

    fn load(&self) -> Result<Option<ActiveActiveHaLoadedState>> {
        let Some(bytes) = self.store.get(
            ACTIVE_ACTIVE_HA_METADATA_TABLE,
            ACTIVE_ACTIVE_HA_METADATA_KEY,
        )?
        else {
            return Ok(None);
        };
        if bytes.len() > MAX_ACTIVE_ACTIVE_HA_DURABLE_STATE_BYTES {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA durable metadata exceeds its byte bound".to_string(),
            ));
        }
        let metadata =
            borsh::from_slice::<ActiveActiveHaDurableMetadata>(bytes.as_ref()).map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "active-active HA durable metadata is corrupt or predates format v2"
                        .to_string(),
                )
            })?;
        metadata.validate()?;

        let mut accepted_writes = BTreeMap::new();
        let mut encoded_bytes = 0usize;
        for (key, value) in self.store.scan(ACTIVE_ACTIVE_HA_ACCEPTED_WRITES_TABLE)? {
            encoded_bytes = encoded_bytes
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "active-active HA durable record bytes overflow".to_string(),
                    )
                })?;
            if encoded_bytes > MAX_ACTIVE_ACTIVE_HA_DURABLE_STATE_BYTES {
                return Err(BlossomError::InvalidConfiguration(
                    "active-active HA durable records exceed their byte bound".to_string(),
                ));
            }
            let record =
                borsh::from_slice::<AcceptedWriteRecord>(value.as_ref()).map_err(|_| {
                    BlossomError::InvalidConfiguration(
                        "active-active HA durable accepted-write record is corrupt".to_string(),
                    )
                })?;
            record.validate()?;
            let expected_key =
                borsh::to_vec(&record.command.identity).map_err(active_active_ha_encode_error)?;
            if expected_key != key {
                return Err(BlossomError::InvalidConfiguration(
                    "active-active HA durable accepted-write key mismatch".to_string(),
                ));
            }
            if accepted_writes
                .insert(record.command.identity, record)
                .is_some()
            {
                return Err(BlossomError::InvalidConfiguration(
                    "duplicate active-active HA durable accepted-write identity".to_string(),
                ));
            }
        }
        let mut expected_sequence = 0u64;
        let mut journal_bytes = 0u64;
        for (key, value) in self.store.scan(ACTIVE_ACTIVE_HA_JOURNAL_TABLE)? {
            let sequence = decode_journal_sequence(&key)?;
            if sequence != expected_sequence {
                return Err(BlossomError::InvalidConfiguration(
                    "active-active HA durable journal sequence is not contiguous".to_string(),
                ));
            }
            encoded_bytes = encoded_bytes.checked_add(value.len()).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active HA durable journal bytes overflow".to_string(),
                )
            })?;
            journal_bytes = journal_bytes
                .checked_add(u64::try_from(value.len()).map_err(|_| {
                    BlossomError::InvalidConfiguration(
                        "active-active HA durable journal entry length exceeds u64".to_string(),
                    )
                })?)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "active-active HA durable journal byte count overflow".to_string(),
                    )
                })?;
            if encoded_bytes > MAX_ACTIVE_ACTIVE_HA_DURABLE_STATE_BYTES {
                return Err(BlossomError::InvalidConfiguration(
                    "active-active HA durable journal exceeds its byte bound".to_string(),
                ));
            }
            let delta =
                borsh::from_slice::<ActiveActiveHaDurableDelta>(value.as_ref()).map_err(|_| {
                    BlossomError::InvalidConfiguration(
                        "active-active HA durable journal delta is corrupt".to_string(),
                    )
                })?;
            delta.validate()?;
            delta.apply_to(&mut accepted_writes);
            expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active HA durable journal sequence overflow".to_string(),
                )
            })?;
        }
        if expected_sequence != metadata.next_journal_sequence
            || u64::from(metadata.journal_entries_since_checkpoint) != expected_sequence
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA durable journal metadata mismatch".to_string(),
            ));
        }
        self.journal_entries
            .store(expected_sequence, Ordering::Relaxed);
        self.journal_bytes.store(journal_bytes, Ordering::Relaxed);
        validate_accepted_writes(
            metadata.route_generation,
            metadata.command_spec_version,
            metadata.cutover,
            &canonical_accepted_writes(&accepted_writes),
        )?;
        let accepted_command_bytes = accepted_writes_command_bytes(&accepted_writes)?;
        let accepted_writes_commitment = accepted_writes_commitment(&accepted_writes)?;
        if accepted_writes.len()
            != usize::try_from(metadata.accepted_write_count).unwrap_or(usize::MAX)
            || accepted_command_bytes
                != usize::try_from(metadata.accepted_command_bytes).unwrap_or(usize::MAX)
            || accepted_writes_commitment != metadata.accepted_writes_commitment
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA durable metadata does not match accepted-write records"
                    .to_string(),
            ));
        }
        Ok(Some(ActiveActiveHaLoadedState {
            metadata,
            accepted_writes,
        }))
    }

    fn persist_delta(
        &self,
        metadata: &ActiveActiveHaDurableMetadata,
        delta_bytes: Vec<u8>,
    ) -> Result<()> {
        metadata.validate()?;
        if delta_bytes.len() > MAX_ACTIVE_ACTIVE_HA_DURABLE_STATE_BYTES {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA durable delta exceeds its byte bound".to_string(),
            ));
        }
        let sequence = self.journal_entries.load(Ordering::Relaxed);
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "active-active HA durable journal sequence overflow".to_string(),
            )
        })?;
        let next_journal_bytes = self
            .journal_bytes
            .load(Ordering::Relaxed)
            .checked_add(u64::try_from(delta_bytes.len()).map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "active-active HA durable delta length exceeds u64".to_string(),
                )
            })?)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active HA durable journal byte count overflow".to_string(),
                )
            })?;
        let journal_entries = u32::try_from(next_sequence).map_err(|_| {
            BlossomError::InvalidConfiguration(
                "active-active HA durable journal entry count exceeds u32".to_string(),
            )
        })?;
        let mut metadata = metadata.clone();
        metadata.set_journal_position(next_sequence, journal_entries)?;
        let metadata_bytes = borsh::to_vec(&metadata).map_err(active_active_ha_encode_error)?;
        self.transact(|transaction| {
            transaction.insert(
                ACTIVE_ACTIVE_HA_JOURNAL_TABLE,
                sequence.to_be_bytes().to_vec(),
                delta_bytes,
            )?;
            transaction.insert(
                ACTIVE_ACTIVE_HA_METADATA_TABLE,
                ACTIVE_ACTIVE_HA_METADATA_KEY.to_vec(),
                metadata_bytes,
            )
        })?;
        self.journal_entries.store(next_sequence, Ordering::Relaxed);
        self.journal_bytes
            .store(next_journal_bytes, Ordering::Relaxed);
        Ok(())
    }

    fn needs_checkpoint(&self, next_delta_bytes: usize) -> bool {
        let next_delta_bytes = u64::try_from(next_delta_bytes).unwrap_or(u64::MAX);
        self.journal_entries.load(Ordering::Relaxed) >= ACTIVE_ACTIVE_HA_JOURNAL_CHECKPOINT_ENTRIES
            || self
                .journal_bytes
                .load(Ordering::Relaxed)
                .saturating_add(next_delta_bytes)
                > ACTIVE_ACTIVE_HA_JOURNAL_CHECKPOINT_BYTES
    }

    fn persist_checkpoint(
        &self,
        metadata: &ActiveActiveHaDurableMetadata,
        accepted_writes: &BTreeMap<CommandIdentity, AcceptedWriteRecord>,
    ) -> Result<()> {
        let canonical = canonical_accepted_writes(accepted_writes);
        validate_accepted_writes(
            metadata.route_generation,
            metadata.command_spec_version,
            metadata.cutover,
            &canonical,
        )?;
        if accepted_writes.len()
            != usize::try_from(metadata.accepted_write_count).unwrap_or(usize::MAX)
            || accepted_writes_command_bytes(accepted_writes)?
                != usize::try_from(metadata.accepted_command_bytes).unwrap_or(usize::MAX)
            || accepted_writes_commitment(accepted_writes)? != metadata.accepted_writes_commitment
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA checkpoint metadata does not match accepted writes".to_string(),
            ));
        }
        let encoded = canonical
            .iter()
            .map(|record| {
                let key = borsh::to_vec(&record.command.identity)
                    .map_err(active_active_ha_encode_error)?;
                let value = borsh::to_vec(record).map_err(active_active_ha_encode_error)?;
                Ok((key, value))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut metadata = metadata.clone();
        metadata.set_journal_position(0, 0)?;
        let metadata_bytes = borsh::to_vec(&metadata).map_err(active_active_ha_encode_error)?;
        self.transact(|transaction| {
            transaction.clear(ACTIVE_ACTIVE_HA_ACCEPTED_WRITES_TABLE)?;
            for (key, value) in &encoded {
                transaction.insert(
                    ACTIVE_ACTIVE_HA_ACCEPTED_WRITES_TABLE,
                    key.clone(),
                    value.clone(),
                )?;
            }
            transaction.clear(ACTIVE_ACTIVE_HA_JOURNAL_TABLE)?;
            transaction.insert(
                ACTIVE_ACTIVE_HA_METADATA_TABLE,
                ACTIVE_ACTIVE_HA_METADATA_KEY.to_vec(),
                metadata_bytes,
            )
        })?;
        self.store.checkpoint()?;
        self.journal_entries.store(0, Ordering::Relaxed);
        self.journal_bytes.store(0, Ordering::Relaxed);
        Ok(())
    }
}

fn decode_journal_sequence(key: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = key.try_into().map_err(|_| {
        BlossomError::InvalidConfiguration(
            "active-active HA durable journal key is invalid".to_string(),
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn active_active_ha_encode_error(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::WireProtocol(format!("encode active-active HA durable state: {error}"))
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ActiveActiveHaRecoveryManifest {
    pub format_version: u16,
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
    pub runtime: HaRecoverySnapshot,
    pub accepted_writes: Vec<AcceptedWriteRecord>,
    pub cutover: Option<ActiveActiveCutover>,
    pub manifest_hash: HashType,
}

impl ActiveActiveHaRecoveryManifest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_VERSION {
            return Err(BlossomError::InvalidConfiguration(
                "unsupported active-active HA recovery manifest version".to_string(),
            ));
        }
        self.route_generation.validate()?;
        self.command_spec_version.validate()?;
        validate_accepted_writes(
            self.route_generation,
            self.command_spec_version,
            self.cutover,
            &self.accepted_writes,
        )?;
        if self.compute_hash()? != self.manifest_hash {
            return Err(BlossomError::InvalidConfiguration(
                "HA recovery manifest hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<HashType> {
        let mut unhashed = self.clone();
        unhashed.manifest_hash = HashType::default();
        manifest_hash(ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_DOMAIN, &unhashed)
    }
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct AcceptedWriteResolution {
    pub command_identity: CommandIdentity,
    pub command_hash: HashType,
    pub disposition: AcceptedWriteDisposition,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActiveActiveHaCutoverManifest {
    pub format_version: u16,
    pub cutover: ActiveActiveCutover,
    pub command_spec_version: CommandSpecVersion,
    pub accepted_write_resolutions: Vec<AcceptedWriteResolution>,
    pub manifest_hash: HashType,
}

impl ActiveActiveHaCutoverManifest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_VERSION {
            return Err(BlossomError::InvalidConfiguration(
                "unsupported active-active HA cutover manifest version".to_string(),
            ));
        }
        self.cutover.from.validate()?;
        self.cutover.to.validate()?;
        self.command_spec_version.validate()?;
        self.cutover.from_command_spec_version.validate()?;
        self.cutover.to_command_spec_version.validate()?;
        if self.command_spec_version != self.cutover.from_command_spec_version
            || self.cutover.to.0 <= self.cutover.from.0
            || self.cutover.to_command_spec_version.0 < self.cutover.from_command_spec_version.0
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active cutover must advance a valid application contract".to_string(),
            ));
        }
        if self.accepted_write_resolutions.len() > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA cutover resolutions exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES}"
            )));
        }
        let mut previous = None;
        let mut translated_command_bytes = 0usize;
        for resolution in &self.accepted_write_resolutions {
            if matches!(resolution.disposition, AcceptedWriteDisposition::Pending)
                || previous.is_some_and(|identity| identity >= resolution.command_identity)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "cutover manifest has pending or non-canonical accepted-write resolutions"
                        .to_string(),
                ));
            }
            if let AcceptedWriteDisposition::Recertified { command, .. } = &resolution.disposition {
                translated_command_bytes = translated_command_bytes
                    .checked_add(command.command.as_bytes().len())
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "active-active HA cutover command bytes overflow".to_string(),
                        )
                    })?;
            }
            validate_cutover_disposition(self.cutover, &resolution.disposition)?;
            previous = Some(resolution.command_identity);
        }
        if translated_command_bytes > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA cutover command bytes exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES}"
            )));
        }
        if self.compute_hash()? != self.manifest_hash {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA cutover manifest hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<HashType> {
        let mut unhashed = self.clone();
        unhashed.manifest_hash = HashType::default();
        manifest_hash(ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_DOMAIN, &unhashed)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActiveActiveHaRecoveryStatus {
    pub operational: HaOperationalStatus,
    pub route_generation: RouteGeneration,
    pub command_spec_version: CommandSpecVersion,
    pub accepted_writes: usize,
    pub unresolved_accepted_writes: usize,
    pub cutover: Option<ActiveActiveCutover>,
    pub runtime_durable: bool,
    pub lifecycle_durable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LearnerCatchUp {
    pub installed_revision: StateRevision,
    pub caught_up_through: Nonce,
    pub eligible_for_activation: bool,
}

/// Active-active service facade for HA catch-up and route cutover operations.
pub struct ActiveActiveHaEngine {
    runtime: HighAvailabilityRuntime,
    route_generation: RouteGeneration,
    command_spec_version: CommandSpecVersion,
    accepted_writes: BTreeMap<CommandIdentity, AcceptedWriteRecord>,
    accepted_command_bytes: usize,
    accepted_writes_commitment: HashType,
    cutover: Option<ActiveActiveCutover>,
    store: Option<ActiveActiveHaDurableStore>,
}

impl ActiveActiveHaEngine {
    pub fn new(
        runtime: HighAvailabilityRuntime,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<Self> {
        Self::create(runtime, route_generation, command_spec_version, None)
    }

    /// Opens immediate-durability active-active lifecycle state.
    ///
    /// The HA runtime should also use [`HighAvailabilityRuntime::open`] for a
    /// production deployment. Existing lifecycle state is restored before the
    /// engine is returned. During crash recovery, the requested contract may
    /// match the target of a persisted in-progress cutover.
    pub fn open(
        path: impl AsRef<Path>,
        runtime: HighAvailabilityRuntime,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> Result<Self> {
        if !runtime.is_durable() {
            return Err(BlossomError::InvalidConfiguration(
                "durable active-active HA lifecycle requires a durable HA runtime".to_string(),
            ));
        }
        let store = ActiveActiveHaDurableStore::open(path)?;
        if let Some(state) = store.load()? {
            let requested_is_active = state.metadata.route_generation == route_generation
                && state.metadata.command_spec_version == command_spec_version;
            let requested_is_cutover_target = state.metadata.cutover.is_some_and(|cutover| {
                cutover.to == route_generation
                    && cutover.to_command_spec_version == command_spec_version
            });
            if !requested_is_active && !requested_is_cutover_target {
                return Err(BlossomError::InvalidConfiguration(
                    "durable active-active HA application contract mismatch".to_string(),
                ));
            }
            return Ok(Self {
                runtime,
                route_generation: state.metadata.route_generation,
                command_spec_version: state.metadata.command_spec_version,
                accepted_writes: state.accepted_writes,
                accepted_command_bytes: usize::try_from(state.metadata.accepted_command_bytes)
                    .expect("validated durable metadata fits usize"),
                accepted_writes_commitment: state.metadata.accepted_writes_commitment,
                cutover: state.metadata.cutover,
                store: Some(store),
            });
        }
        Self::create(runtime, route_generation, command_spec_version, Some(store))
    }

    fn create(
        runtime: HighAvailabilityRuntime,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
        store: Option<ActiveActiveHaDurableStore>,
    ) -> Result<Self> {
        route_generation.validate()?;
        command_spec_version.validate()?;
        let engine = Self {
            runtime,
            route_generation,
            command_spec_version,
            accepted_writes: BTreeMap::new(),
            accepted_command_bytes: 0,
            accepted_writes_commitment: HashType::default(),
            cutover: None,
            store,
        };
        engine.persist_lifecycle_delta(
            route_generation,
            command_spec_version,
            0,
            0,
            HashType::default(),
            None,
            Vec::new(),
            Vec::new(),
        )?;
        Ok(engine)
    }

    pub fn lifecycle_is_durable(&self) -> bool {
        self.store.is_some()
    }

    pub fn is_production_durable(&self) -> bool {
        self.lifecycle_is_durable() && self.runtime.is_durable()
    }

    pub fn lifecycle_durability_metrics(&self) -> Option<ActiveActiveHaLifecycleDurabilityMetrics> {
        self.store
            .as_ref()
            .map(ActiveActiveHaDurableStore::durability_metrics)
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_lifecycle_delta(
        &self,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
        accepted_write_count: usize,
        accepted_command_bytes: usize,
        accepted_writes_commitment: HashType,
        cutover: Option<ActiveActiveCutover>,
        upserts: Vec<AcceptedWriteRecord>,
        removals: Vec<CommandIdentity>,
    ) -> Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let metadata = ActiveActiveHaDurableMetadata::new(
            route_generation,
            command_spec_version,
            accepted_write_count,
            accepted_command_bytes,
            accepted_writes_commitment,
            cutover,
        )?;
        let delta = ActiveActiveHaDurableDelta::new(upserts, removals)?;
        let delta_bytes = borsh::to_vec(&delta).map_err(active_active_ha_encode_error)?;
        if store.needs_checkpoint(delta_bytes.len()) {
            let mut accepted_writes = self.accepted_writes.clone();
            delta.apply_to(&mut accepted_writes);
            store.persist_checkpoint(&metadata, &accepted_writes)
        } else {
            store.persist_delta(&metadata, delta_bytes)
        }
    }

    fn persist_next_lifecycle_state(
        &self,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
        accepted_writes: &BTreeMap<CommandIdentity, AcceptedWriteRecord>,
        cutover: Option<ActiveActiveCutover>,
    ) -> Result<()> {
        let accepted_command_bytes = accepted_writes_command_bytes(accepted_writes)?;
        let accepted_writes_commitment = accepted_writes_commitment(accepted_writes)?;
        let upserts = accepted_writes
            .iter()
            .filter_map(|(identity, record)| {
                (self.accepted_writes.get(identity) != Some(record)).then_some(record.clone())
            })
            .collect::<Vec<_>>();
        let removals = self
            .accepted_writes
            .keys()
            .filter(|identity| !accepted_writes.contains_key(identity))
            .copied()
            .collect::<Vec<_>>();
        self.persist_lifecycle_delta(
            route_generation,
            command_spec_version,
            accepted_writes.len(),
            accepted_command_bytes,
            accepted_writes_commitment,
            cutover,
            upserts,
            removals,
        )
    }

    pub fn runtime(&self) -> &HighAvailabilityRuntime {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut HighAvailabilityRuntime {
        &mut self.runtime
    }

    pub fn accept_local(&mut self, command: ActiveActiveCommand) -> Result<HashType> {
        self.accept_local_batch(vec![command])?
            .pop()
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "single active-active HA admission returned no command hash".to_string(),
                )
            })
    }

    /// Durably accepts a bounded group of commands with one lifecycle commit.
    ///
    /// The returned hashes preserve input order. Repeated identical command
    /// identities are idempotent and consume no additional durable records.
    pub fn accept_local_batch(
        &mut self,
        commands: Vec<ActiveActiveCommand>,
    ) -> Result<Vec<HashType>> {
        let mut hashes =
            self.accept_prepared_shard_batches(vec![PreparedActiveActiveHaShardBatch::prepare(
                commands,
            )?])?;
        hashes.pop().ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "active-active HA admission returned no shard result".to_string(),
            )
        })
    }

    /// Commits independently prepared shard batches in one durable lifecycle
    /// transaction. Shard workers can hash and validate in parallel before
    /// handing batches to this shared group-commit boundary.
    pub fn accept_prepared_shard_batches(
        &mut self,
        shard_batches: Vec<PreparedActiveActiveHaShardBatch>,
    ) -> Result<Vec<Vec<HashType>>> {
        if shard_batches.len() > MAX_ACTIVE_ACTIVE_HA_SHARD_LANES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA admission exceeds {MAX_ACTIVE_ACTIVE_HA_SHARD_LANES} shard lanes"
            )));
        }
        let command_count = shard_batches.iter().try_fold(0usize, |total, batch| {
            total.checked_add(batch.len()).ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active HA shard admission count overflow".to_string(),
                )
            })
        })?;
        if command_count > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA admission batch exceeds {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES}"
            )));
        }
        let hashes = shard_batches
            .iter()
            .map(PreparedActiveActiveHaShardBatch::command_hashes)
            .collect::<Vec<_>>();
        if command_count == 0 {
            return Ok(hashes);
        }
        let mut additions = BTreeMap::<CommandIdentity, AcceptedWriteRecord>::new();
        let mut next_command_bytes = self.accepted_command_bytes;
        let mut next_commitment = self.accepted_writes_commitment;
        for (command, command_hash) in shard_batches.into_iter().flat_map(|batch| batch.commands) {
            if let Some(existing) = self.accepted_writes.get(&command.identity) {
                if existing.command_hash != command_hash {
                    return Err(BlossomError::InvalidConfiguration(
                        "conflicting bytes for one accepted command identity".to_string(),
                    ));
                }
                continue;
            }
            if let Some(existing) = additions.get(&command.identity) {
                if existing.command_hash != command_hash {
                    return Err(BlossomError::InvalidConfiguration(
                        "conflicting bytes for one batched command identity".to_string(),
                    ));
                }
                continue;
            }
            if self.cutover.is_some() {
                return Err(BlossomError::InvalidConfiguration(
                    "new writes are fenced while an application cutover is active".to_string(),
                ));
            }
            next_command_bytes = next_command_bytes
                .checked_add(command.command.as_bytes().len())
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "active-active HA accepted command bytes overflow".to_string(),
                    )
                })?;
            let identity = command.identity;
            let record = AcceptedWriteRecord {
                command,
                command_hash,
                command_spec_version: self.command_spec_version,
                accepted_route_generation: self.route_generation,
                disposition: AcceptedWriteDisposition::Pending,
            };
            next_commitment =
                xor_hashes(next_commitment, accepted_write_record_commitment(&record)?);
            additions.insert(identity, record);
        }
        let next_count = self
            .accepted_writes
            .len()
            .checked_add(additions.len())
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active HA accepted-write count overflow".to_string(),
                )
            })?;
        if next_count > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA accepted writes exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES}"
            )));
        }
        if next_command_bytes > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA accepted command bytes exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES}"
            )));
        }
        let upserts = additions.values().cloned().collect::<Vec<_>>();
        self.persist_lifecycle_delta(
            self.route_generation,
            self.command_spec_version,
            next_count,
            next_command_bytes,
            next_commitment,
            self.cutover,
            upserts,
            Vec::new(),
        )?;
        if self.accepted_writes.is_empty() {
            self.accepted_writes = additions;
        } else {
            self.accepted_writes.extend(additions);
        }
        self.accepted_command_bytes = next_command_bytes;
        self.accepted_writes_commitment = next_commitment;
        Ok(hashes)
    }

    pub fn accepted_transaction(&self, identity: CommandIdentity) -> Result<Transaction> {
        let accepted = self.accepted_writes.get(&identity).ok_or_else(|| {
            BlossomError::InvalidConfiguration("unknown accepted write".to_string())
        })?;
        Transaction::from_borsh(&accepted.command)
    }

    pub fn accepted_command_hash(&self, identity: CommandIdentity) -> Option<HashType> {
        self.accepted_writes
            .get(&identity)
            .map(|accepted| accepted.command_hash)
    }

    pub fn begin_cutover(&mut self, next_route_generation: RouteGeneration) -> Result<()> {
        self.begin_application_cutover(next_route_generation, self.command_spec_version)
    }

    /// Begins one atomic route and command-spec cutover.
    ///
    /// A command-spec upgrade must also advance the route generation. Every
    /// accepted source-spec command must then be translated and rehashed with
    /// [`Self::recertify_accepted_as`] or explicitly aborted.
    pub fn begin_application_cutover(
        &mut self,
        next_route_generation: RouteGeneration,
        next_command_spec_version: CommandSpecVersion,
    ) -> Result<()> {
        next_route_generation.validate()?;
        next_command_spec_version.validate()?;
        if self.cutover.is_some()
            || next_route_generation.0 <= self.route_generation.0
            || next_command_spec_version.0 < self.command_spec_version.0
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active application cutover is already active, regresses the command spec, or does not advance the route"
                    .to_string(),
            ));
        }
        let status = self.runtime.status()?;
        let cutover = ActiveActiveCutover {
            from: self.route_generation,
            to: next_route_generation,
            from_command_spec_version: self.command_spec_version,
            to_command_spec_version: next_command_spec_version,
            membership_generation: status.membership_generation,
            active_mask: status.active_mask,
        };
        self.persist_next_lifecycle_state(
            self.route_generation,
            self.command_spec_version,
            &self.accepted_writes,
            Some(cutover),
        )?;
        self.cutover = Some(cutover);
        Ok(())
    }

    pub fn recertify_accepted(&mut self, identity: CommandIdentity) -> Result<()> {
        let command = self
            .accepted_writes
            .get(&identity)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration("unknown accepted write".to_string())
            })?
            .command
            .clone();
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "accepted-write recertification requires an active cutover".to_string(),
            )
        })?;
        if cutover.to_command_spec_version != cutover.from_command_spec_version {
            return Err(BlossomError::InvalidConfiguration(
                "command-spec upgrades require recertify_accepted_as with translated command bytes, or an explicit abort"
                    .to_string(),
            ));
        }
        self.recertify_accepted_as(identity, command)
    }

    pub fn recertify_accepted_as(
        &mut self,
        identity: CommandIdentity,
        translated_command: ActiveActiveCommand,
    ) -> Result<()> {
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "accepted-write recertification requires an active cutover".to_string(),
            )
        })?;
        translated_command.validate()?;
        if translated_command.identity != identity {
            return Err(BlossomError::InvalidConfiguration(
                "translated accepted write must preserve its command identity".to_string(),
            ));
        }
        let translated_command_hash = translated_command.hash()?;
        let translated_command_bytes = translated_command.command.as_bytes().len();
        let accepted = self.accepted_writes.get_mut(&identity).ok_or_else(|| {
            BlossomError::InvalidConfiguration("unknown accepted write".to_string())
        })?;
        if accepted.accepted_route_generation != cutover.from
            || accepted.command_spec_version != cutover.from_command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "accepted write does not belong to the cutover source application contract"
                    .to_string(),
            ));
        }
        let disposition = AcceptedWriteDisposition::Recertified {
            from: cutover.from,
            to: cutover.to,
            from_command_spec_version: cutover.from_command_spec_version,
            to_command_spec_version: cutover.to_command_spec_version,
            command: translated_command,
            command_hash: translated_command_hash,
        };
        if accepted.disposition == disposition {
            return Ok(());
        }
        if !matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
            return Err(BlossomError::InvalidConfiguration(
                "accepted write already has a different cutover resolution".to_string(),
            ));
        }
        let next_command_bytes = self
            .accepted_command_bytes
            .checked_add(translated_command_bytes)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active HA accepted command bytes overflow".to_string(),
                )
            })?;
        if next_command_bytes > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA accepted command bytes exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES}"
            )));
        }
        let previous = accepted.clone();
        accepted.disposition = disposition;
        let next = accepted.clone();
        let next_commitment = xor_hashes(
            xor_hashes(
                self.accepted_writes_commitment,
                accepted_write_record_commitment(&previous)?,
            ),
            accepted_write_record_commitment(&next)?,
        );
        if let Err(error) = self.persist_lifecycle_delta(
            self.route_generation,
            self.command_spec_version,
            self.accepted_writes.len(),
            next_command_bytes,
            next_commitment,
            self.cutover,
            vec![next],
            Vec::new(),
        ) {
            self.accepted_writes.insert(identity, previous);
            return Err(error);
        }
        self.accepted_command_bytes = next_command_bytes;
        self.accepted_writes_commitment = next_commitment;
        Ok(())
    }

    pub fn abort_accepted(
        &mut self,
        identity: CommandIdentity,
        reason: impl Into<String>,
    ) -> Result<()> {
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "accepted-write abort requires an active cutover".to_string(),
            )
        })?;
        let reason = reason.into();
        if reason.is_empty() || reason.len() > MAX_ACCEPTED_WRITE_ABORT_REASON_BYTES {
            return Err(BlossomError::InvalidConfiguration(
                "accepted-write abort reason is empty or too large".to_string(),
            ));
        }
        let accepted = self.accepted_writes.get_mut(&identity).ok_or_else(|| {
            BlossomError::InvalidConfiguration("unknown accepted write".to_string())
        })?;
        if accepted.accepted_route_generation != cutover.from
            || accepted.command_spec_version != cutover.from_command_spec_version
        {
            return Err(BlossomError::InvalidConfiguration(
                "accepted write does not belong to the cutover source application contract"
                    .to_string(),
            ));
        }
        let disposition = AcceptedWriteDisposition::Aborted {
            route_generation: accepted.accepted_route_generation,
            command_spec_version: accepted.command_spec_version,
            reason,
        };
        if accepted.disposition == disposition {
            return Ok(());
        }
        if !matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
            return Err(BlossomError::InvalidConfiguration(
                "accepted write already has a different cutover resolution".to_string(),
            ));
        }
        let previous = accepted.clone();
        accepted.disposition = disposition;
        let next = accepted.clone();
        let next_commitment = xor_hashes(
            xor_hashes(
                self.accepted_writes_commitment,
                accepted_write_record_commitment(&previous)?,
            ),
            accepted_write_record_commitment(&next)?,
        );
        if let Err(error) = self.persist_lifecycle_delta(
            self.route_generation,
            self.command_spec_version,
            self.accepted_writes.len(),
            self.accepted_command_bytes,
            next_commitment,
            self.cutover,
            vec![next],
            Vec::new(),
        ) {
            self.accepted_writes.insert(identity, previous);
            return Err(error);
        }
        self.accepted_writes_commitment = next_commitment;
        Ok(())
    }

    /// Cancels an unactivated cutover and returns every source-contract write
    /// to `Pending`. This is required when HA membership changes invalidate
    /// the prepared manifest.
    pub fn cancel_application_cutover(&mut self) -> Result<()> {
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "no active application cutover to cancel".to_string(),
            )
        })?;
        let mut accepted_writes = self.accepted_writes.clone();
        for accepted in accepted_writes.values_mut().filter(|accepted| {
            accepted.accepted_route_generation == cutover.from
                && accepted.command_spec_version == cutover.from_command_spec_version
        }) {
            accepted.disposition = AcceptedWriteDisposition::Pending;
        }
        let accepted_command_bytes = accepted_writes_command_bytes(&accepted_writes)?;
        self.persist_next_lifecycle_state(
            self.route_generation,
            self.command_spec_version,
            &accepted_writes,
            None,
        )?;
        self.accepted_command_bytes = accepted_command_bytes;
        self.accepted_writes_commitment = accepted_writes_commitment(&accepted_writes)?;
        self.accepted_writes = accepted_writes;
        self.cutover = None;
        Ok(())
    }

    pub fn cutover_manifest(&self) -> Result<ActiveActiveHaCutoverManifest> {
        let cutover = self.cutover.ok_or_else(|| {
            BlossomError::InvalidConfiguration("no active route cutover".to_string())
        })?;
        let mut accepted_write_resolutions = self
            .accepted_writes
            .values()
            .filter(|accepted| accepted.accepted_route_generation == cutover.from)
            .map(|accepted| {
                if matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
                    return Err(BlossomError::InvalidConfiguration(
                        "every accepted write must be recertified or explicitly aborted before cutover"
                            .to_string(),
                    ));
                }
                Ok(AcceptedWriteResolution {
                    command_identity: accepted.command.identity,
                    command_hash: accepted.command_hash,
                    disposition: accepted.disposition.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        accepted_write_resolutions.sort_unstable_by_key(|resolution| resolution.command_identity);
        let mut manifest = ActiveActiveHaCutoverManifest {
            format_version: ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_VERSION,
            cutover,
            command_spec_version: self.command_spec_version,
            accepted_write_resolutions,
            manifest_hash: HashType::default(),
        };
        manifest.manifest_hash = manifest.compute_hash()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn activate_cutover(&mut self, manifest: &ActiveActiveHaCutoverManifest) -> Result<()> {
        manifest.validate()?;
        let current = self.runtime.status()?;
        if self.cutover != Some(manifest.cutover)
            || self.route_generation != manifest.cutover.from
            || self.command_spec_version != manifest.cutover.from_command_spec_version
            || self.command_spec_version != manifest.command_spec_version
            || current.membership_generation != manifest.cutover.membership_generation
            || current.active_mask != manifest.cutover.active_mask
        {
            return Err(BlossomError::InvalidConfiguration(
                "cutover manifest does not match current routing or HA membership".to_string(),
            ));
        }
        let expected_resolutions = self
            .accepted_writes
            .values()
            .filter(|accepted| accepted.accepted_route_generation == manifest.cutover.from)
            .count();
        if manifest.accepted_write_resolutions.len() != expected_resolutions {
            return Err(BlossomError::InvalidConfiguration(
                "cutover manifest does not resolve every accepted source-generation write"
                    .to_string(),
            ));
        }
        for resolution in &manifest.accepted_write_resolutions {
            let accepted = self
                .accepted_writes
                .get(&resolution.command_identity)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "cutover manifest references an unknown accepted write".to_string(),
                    )
                })?;
            if accepted.command_hash != resolution.command_hash
                || accepted.disposition != resolution.disposition
            {
                return Err(BlossomError::InvalidConfiguration(
                    "cutover accepted-write resolution mismatch".to_string(),
                ));
            }
        }
        let mut accepted_writes = self.accepted_writes.clone();
        for resolution in &manifest.accepted_write_resolutions {
            match &resolution.disposition {
                AcceptedWriteDisposition::Recertified {
                    to,
                    to_command_spec_version,
                    command,
                    command_hash,
                    ..
                } => {
                    let accepted = accepted_writes
                        .get_mut(&resolution.command_identity)
                        .expect("validated above");
                    accepted.command = command.clone();
                    accepted.command_hash = *command_hash;
                    accepted.command_spec_version = *to_command_spec_version;
                    accepted.accepted_route_generation = *to;
                    accepted.disposition = AcceptedWriteDisposition::Pending;
                }
                AcceptedWriteDisposition::Aborted { .. } => {
                    accepted_writes.remove(&resolution.command_identity);
                }
                AcceptedWriteDisposition::Pending => unreachable!("manifest validation rejects"),
            }
        }
        let accepted_command_bytes = accepted_writes_command_bytes(&accepted_writes)?;
        self.persist_next_lifecycle_state(
            manifest.cutover.to,
            manifest.cutover.to_command_spec_version,
            &accepted_writes,
            None,
        )?;
        self.accepted_command_bytes = accepted_command_bytes;
        self.accepted_writes_commitment = accepted_writes_commitment(&accepted_writes)?;
        self.accepted_writes = accepted_writes;
        self.route_generation = manifest.cutover.to;
        self.command_spec_version = manifest.cutover.to_command_spec_version;
        self.cutover = None;
        Ok(())
    }

    pub fn complete_accepted(
        &mut self,
        identity: CommandIdentity,
        command_hash: HashType,
    ) -> Result<()> {
        self.complete_accepted_batch(&[(identity, command_hash)])
    }

    /// Durably completes a bounded group of accepted commands in one commit.
    pub fn complete_accepted_batch(
        &mut self,
        completions: &[(CommandIdentity, HashType)],
    ) -> Result<()> {
        if completions.len() > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA completion batch exceeds {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES}"
            )));
        }
        if completions.is_empty() {
            return Ok(());
        }
        let mut canonical = completions.to_vec();
        if canonical.windows(2).any(|pair| pair[0].0 > pair[1].0) {
            canonical.sort_unstable_by_key(|(identity, _)| *identity);
        }
        let mut removals = Vec::with_capacity(canonical.len());
        let mut removed_command_bytes = 0usize;
        let mut next_commitment = self.accepted_writes_commitment;
        for (identity, command_hash) in canonical {
            if let Some((previous_identity, previous_hash)) = removals.last()
                && *previous_identity == identity
            {
                if *previous_hash != command_hash {
                    return Err(BlossomError::InvalidConfiguration(
                        "conflicting hashes for one batched accepted-write completion".to_string(),
                    ));
                }
                continue;
            }
            let accepted = self.accepted_writes.get(&identity).ok_or_else(|| {
                BlossomError::InvalidConfiguration("unknown accepted write".to_string())
            })?;
            if accepted.command_hash != command_hash {
                return Err(BlossomError::InvalidConfiguration(
                    "accepted-write completion hash mismatch".to_string(),
                ));
            }
            if !matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
                return Err(BlossomError::InvalidConfiguration(
                    "resolved cutover write must remain in its manifest until activation"
                        .to_string(),
                ));
            }
            removed_command_bytes = removed_command_bytes
                .checked_add(accepted_write_command_bytes(accepted)?)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "accepted-write completion byte count overflow".to_string(),
                    )
                })?;
            next_commitment =
                xor_hashes(next_commitment, accepted_write_record_commitment(accepted)?);
            removals.push((identity, command_hash));
        }
        let next_command_bytes = self
            .accepted_command_bytes
            .checked_sub(removed_command_bytes)
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "accepted-write completion byte count underflow".to_string(),
                )
            })?;
        let removal_identities = removals
            .iter()
            .map(|(identity, _)| *identity)
            .collect::<Vec<_>>();
        self.persist_lifecycle_delta(
            self.route_generation,
            self.command_spec_version,
            self.accepted_writes.len() - removals.len(),
            next_command_bytes,
            next_commitment,
            self.cutover,
            Vec::new(),
            removal_identities,
        )?;
        if removals.len() == self.accepted_writes.len() {
            self.accepted_writes.clear();
        } else {
            for (identity, _) in &removals {
                self.accepted_writes.remove(identity);
            }
        }
        self.accepted_command_bytes = next_command_bytes;
        self.accepted_writes_commitment = next_commitment;
        Ok(())
    }

    pub fn recovery_status(&self) -> Result<ActiveActiveHaRecoveryStatus> {
        Ok(ActiveActiveHaRecoveryStatus {
            operational: self.runtime.operational_status()?,
            route_generation: self.route_generation,
            command_spec_version: self.command_spec_version,
            accepted_writes: self.accepted_writes.len(),
            unresolved_accepted_writes: self
                .accepted_writes
                .values()
                .filter(|accepted| {
                    matches!(accepted.disposition, AcceptedWriteDisposition::Pending)
                })
                .count(),
            cutover: self.cutover,
            runtime_durable: self.runtime.is_durable(),
            lifecycle_durable: self.lifecycle_is_durable(),
        })
    }

    pub fn recovery_manifest(&self) -> Result<ActiveActiveHaRecoveryManifest> {
        let mut manifest = ActiveActiveHaRecoveryManifest {
            format_version: ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_VERSION,
            route_generation: self.route_generation,
            command_spec_version: self.command_spec_version,
            runtime: self.runtime.recovery_snapshot(),
            accepted_writes: canonical_accepted_writes(&self.accepted_writes),
            cutover: self.cutover,
            manifest_hash: HashType::default(),
        };
        manifest.manifest_hash = manifest.compute_hash()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn install_recovery_manifest(
        &mut self,
        manifest: ActiveActiveHaRecoveryManifest,
    ) -> Result<LearnerCatchUp> {
        manifest.validate()?;
        if manifest.route_generation != self.route_generation
            || manifest.command_spec_version != self.command_spec_version
            || self
                .cutover
                .is_some_and(|cutover| Some(cutover) != manifest.cutover)
        {
            return Err(BlossomError::InvalidConfiguration(
                "recovery manifest application contract mismatch".to_string(),
            ));
        }
        for incoming in &manifest.accepted_writes {
            if let Some(existing) = self.accepted_writes.get(&incoming.command.identity)
                && existing != incoming
            {
                return Err(BlossomError::InvalidConfiguration(
                    "recovery manifest conflicts with a local accepted write".to_string(),
                ));
            }
        }
        let mut accepted_writes = self.accepted_writes.clone();
        for incoming in &manifest.accepted_writes {
            accepted_writes
                .entry(incoming.command.identity)
                .or_insert_with(|| incoming.clone());
        }
        if accepted_writes.len() > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA accepted writes exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES}"
            )));
        }
        let accepted_command_bytes = accepted_writes_command_bytes(&accepted_writes)?;
        if accepted_command_bytes > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES {
            return Err(BlossomError::InvalidConfiguration(format!(
                "active-active HA accepted command bytes exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES}"
            )));
        }
        let next_cutover = manifest.cutover;
        let caught_up_through = manifest
            .runtime
            .epochs
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?
            .nonce;
        let revision = self.runtime.install_recovery_snapshot(manifest.runtime)?;
        self.persist_next_lifecycle_state(
            self.route_generation,
            self.command_spec_version,
            &accepted_writes,
            next_cutover,
        )?;
        self.accepted_command_bytes = accepted_command_bytes;
        self.accepted_writes_commitment = accepted_writes_commitment(&accepted_writes)?;
        self.accepted_writes = accepted_writes;
        self.cutover = next_cutover;
        let eligible_for_activation = matches!(
            self.runtime.node_status(self.runtime.self_slot()),
            NodeAvailabilityStatus::Suspended { .. }
        ) && self.runtime.head().nonce >= caught_up_through;
        Ok(LearnerCatchUp {
            installed_revision: revision,
            caught_up_through,
            eligible_for_activation,
        })
    }

    pub fn activate_learner(
        &mut self,
        slot: HaMemberSlot,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.runtime
            .vote_to_reactivate(slot, self.runtime.head().nonce)
    }

    pub fn suspend_member(
        &mut self,
        slot: HaMemberSlot,
    ) -> Result<(HaMembershipVote, Option<HaMembershipCertificate>)> {
        self.runtime.vote_to_suspend(slot)
    }

    pub fn receive_activation_vote(&mut self, vote: HaMembershipVote) -> Result<HaRuntimeEvent> {
        self.runtime.receive_membership_vote(vote)
    }
}

fn accepted_write_command_bytes(accepted: &AcceptedWriteRecord) -> Result<usize> {
    let mut bytes = accepted.command.command.as_bytes().len();
    if let AcceptedWriteDisposition::Recertified { command, .. } = &accepted.disposition {
        bytes = bytes
            .checked_add(command.command.as_bytes().len())
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active HA accepted command bytes overflow".to_string(),
                )
            })?;
    }
    Ok(bytes)
}

fn accepted_writes_command_bytes(
    accepted_writes: &BTreeMap<CommandIdentity, AcceptedWriteRecord>,
) -> Result<usize> {
    accepted_writes
        .values()
        .try_fold(0usize, |total, accepted| {
            total
                .checked_add(accepted_write_command_bytes(accepted)?)
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "active-active HA accepted command bytes overflow".to_string(),
                    )
                })
        })
}

fn canonical_accepted_writes(
    accepted_writes: &BTreeMap<CommandIdentity, AcceptedWriteRecord>,
) -> Vec<AcceptedWriteRecord> {
    accepted_writes.values().cloned().collect()
}

fn accepted_write_record_commitment(record: &AcceptedWriteRecord) -> Result<HashType> {
    if matches!(record.disposition, AcceptedWriteDisposition::Pending) {
        // The command hash already commits the identity and canonical command
        // bytes. Pending records share the engine's route/spec metadata, so
        // hashing the complete record again would add one digest per hot-path
        // acceptance and completion without strengthening the commitment.
        Ok(record.command_hash)
    } else {
        manifest_hash(ACTIVE_ACTIVE_HA_DURABLE_RECORD_DOMAIN, record)
    }
}

fn accepted_writes_commitment(
    accepted_writes: &BTreeMap<CommandIdentity, AcceptedWriteRecord>,
) -> Result<HashType> {
    accepted_writes
        .values()
        .try_fold(HashType::default(), |commitment, record| {
            Ok(xor_hashes(
                commitment,
                accepted_write_record_commitment(record)?,
            ))
        })
}

fn xor_hashes(left: HashType, right: HashType) -> HashType {
    let mut bytes = left.0;
    for (byte, right) in bytes.iter_mut().zip(right.0) {
        *byte ^= right;
    }
    HashType(bytes)
}

fn validate_cutover_contract(
    route_generation: RouteGeneration,
    command_spec_version: CommandSpecVersion,
    cutover: Option<ActiveActiveCutover>,
) -> Result<()> {
    if let Some(cutover) = cutover {
        cutover.from.validate()?;
        cutover.to.validate()?;
        cutover.from_command_spec_version.validate()?;
        cutover.to_command_spec_version.validate()?;
        if cutover.from != route_generation
            || cutover.from_command_spec_version != command_spec_version
            || cutover.to.0 <= cutover.from.0
            || cutover.to_command_spec_version.0 < cutover.from_command_spec_version.0
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA cutover is inconsistent with its source contract".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_accepted_writes(
    route_generation: RouteGeneration,
    command_spec_version: CommandSpecVersion,
    cutover: Option<ActiveActiveCutover>,
    accepted_writes: &[AcceptedWriteRecord],
) -> Result<()> {
    if accepted_writes.len() > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES {
        return Err(BlossomError::InvalidConfiguration(format!(
            "active-active HA accepted writes exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES}"
        )));
    }
    validate_cutover_contract(route_generation, command_spec_version, cutover)?;
    let mut previous = None;
    let mut total_command_bytes = 0usize;
    for accepted in accepted_writes {
        accepted.validate()?;
        if accepted.command_spec_version != command_spec_version
            || accepted.accepted_route_generation != route_generation
            || previous.is_some_and(|identity| identity >= accepted.command.identity)
        {
            return Err(BlossomError::InvalidConfiguration(
                "active-active HA accepted writes are not canonical".to_string(),
            ));
        }
        total_command_bytes = total_command_bytes
            .checked_add(accepted.command.command.as_bytes().len())
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "active-active HA accepted command bytes overflow".to_string(),
                )
            })?;
        if let AcceptedWriteDisposition::Recertified { command, .. } = &accepted.disposition {
            total_command_bytes = total_command_bytes
                .checked_add(command.command.as_bytes().len())
                .ok_or_else(|| {
                    BlossomError::InvalidConfiguration(
                        "active-active HA accepted command bytes overflow".to_string(),
                    )
                })?;
        }
        if let Some(cutover) = cutover {
            validate_cutover_disposition(cutover, &accepted.disposition)?;
        } else if !matches!(accepted.disposition, AcceptedWriteDisposition::Pending) {
            return Err(BlossomError::InvalidConfiguration(
                "resolved accepted writes require an active cutover".to_string(),
            ));
        }
        previous = Some(accepted.command.identity);
    }
    if total_command_bytes > MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES {
        return Err(BlossomError::InvalidConfiguration(format!(
            "active-active HA accepted command bytes exceed {MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES}"
        )));
    }
    Ok(())
}

fn validate_cutover_disposition(
    cutover: ActiveActiveCutover,
    disposition: &AcceptedWriteDisposition,
) -> Result<()> {
    let matches_cutover = match disposition {
        AcceptedWriteDisposition::Pending => true,
        AcceptedWriteDisposition::Recertified {
            from,
            to,
            from_command_spec_version,
            to_command_spec_version,
            ..
        } => {
            *from == cutover.from
                && *to == cutover.to
                && *from_command_spec_version == cutover.from_command_spec_version
                && *to_command_spec_version == cutover.to_command_spec_version
        }
        AcceptedWriteDisposition::Aborted {
            route_generation,
            command_spec_version,
            ..
        } => {
            *route_generation == cutover.from
                && *command_spec_version == cutover.from_command_spec_version
        }
    };
    if !matches_cutover {
        return Err(BlossomError::InvalidConfiguration(
            "accepted-write disposition does not match the active cutover".to_string(),
        ));
    }
    Ok(())
}

fn manifest_hash<T: BorshSerialize>(domain: &[u8], value: &T) -> Result<HashType> {
    let encoded = borsh::to_vec(value).map_err(|error| {
        BlossomError::WireProtocol(format!("encode active-active HA manifest: {error}"))
    })?;
    Ok(HashType::hash_slices([domain, encoded.as_slice()]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::active_active::{ApplicationCommand, ClientEpoch, ClientId, CommandIdentity};
    use crate::crypto::PubKey;
    use crate::group::ConsensusGroupId;
    use crate::high_availability::HighAvailabilityParameters;
    use crate::node::NodeIdentity;

    fn members() -> Vec<NodeIdentity> {
        (0..3)
            .map(|index| {
                NodeIdentity::new(
                    PubKey([index; 32]),
                    None,
                    "tcp",
                    "127.0.0.1",
                    19_000 + u16::from(index),
                    false,
                )
            })
            .collect()
    }

    fn command(sequence: u64) -> ActiveActiveCommand {
        ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([7; 16]),
                client_epoch: ClientEpoch(1),
                sequence,
            },
            command: ApplicationCommand::new(sequence.to_le_bytes().to_vec()).unwrap(),
        }
    }

    fn engine() -> ActiveActiveHaEngine {
        let members = members();
        let runtime = HighAvailabilityRuntime::new(
            ConsensusGroupId::named("active-active-ha-facade"),
            members[0].public_key(),
            members,
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        ActiveActiveHaEngine::new(runtime, RouteGeneration(1), CommandSpecVersion(1)).unwrap()
    }

    fn durable_engine(
        root: &Path,
        route_generation: RouteGeneration,
        command_spec_version: CommandSpecVersion,
    ) -> ActiveActiveHaEngine {
        let members = members();
        let runtime = HighAvailabilityRuntime::open(
            root.join("runtime.redb"),
            ConsensusGroupId::named("active-active-ha-facade"),
            members[0].public_key(),
            members,
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        ActiveActiveHaEngine::open(
            root.join("lifecycle.redb"),
            runtime,
            route_generation,
            command_spec_version,
        )
        .unwrap()
    }

    #[test]
    fn cutover_requires_every_accepted_write_to_be_resolved() {
        let mut engine = engine();
        let recertified = command(1);
        let aborted = command(2);
        engine.accept_local(recertified.clone()).unwrap();
        engine.accept_local(aborted.clone()).unwrap();
        engine.begin_cutover(RouteGeneration(2)).unwrap();
        assert!(engine.cutover_manifest().is_err());

        engine.recertify_accepted(recertified.identity).unwrap();
        engine
            .abort_accepted(aborted.identity, "operator-confirmed abort")
            .unwrap();
        let manifest = engine.cutover_manifest().unwrap();
        engine.activate_cutover(&manifest).unwrap();

        let status = engine.recovery_status().unwrap();
        assert_eq!(status.route_generation, RouteGeneration(2));
        assert_eq!(status.command_spec_version, CommandSpecVersion(1));
        assert_eq!(status.accepted_writes, 1);
        assert_eq!(status.unresolved_accepted_writes, 1);
    }

    #[test]
    fn command_spec_cutover_requires_translation_or_abort() {
        let mut engine = engine();
        let original = command(1);
        engine.accept_local(original.clone()).unwrap();
        engine
            .begin_application_cutover(RouteGeneration(2), CommandSpecVersion(2))
            .unwrap();
        assert!(engine.recertify_accepted(original.identity).is_err());

        let translated = ActiveActiveCommand {
            identity: original.identity,
            command: ApplicationCommand::new(b"translated-command-spec-v2".to_vec()).unwrap(),
        };
        let translated_hash = translated.hash().unwrap();
        engine
            .recertify_accepted_as(original.identity, translated.clone())
            .unwrap();
        let manifest = engine.cutover_manifest().unwrap();
        assert_eq!(
            manifest.cutover.from_command_spec_version,
            CommandSpecVersion(1)
        );
        assert_eq!(
            manifest.cutover.to_command_spec_version,
            CommandSpecVersion(2)
        );
        engine.activate_cutover(&manifest).unwrap();

        let status = engine.recovery_status().unwrap();
        assert_eq!(status.route_generation, RouteGeneration(2));
        assert_eq!(status.command_spec_version, CommandSpecVersion(2));
        assert_eq!(
            engine
                .accepted_transaction(original.identity)
                .unwrap()
                .payload_as_borsh::<ActiveActiveCommand>()
                .unwrap(),
            translated
        );
        assert!(
            engine
                .complete_accepted(original.identity, original.hash().unwrap())
                .is_err()
        );
        engine
            .complete_accepted(original.identity, translated_hash)
            .unwrap();
    }

    #[test]
    fn recovery_manifest_carries_runtime_and_accepted_write_state() {
        let mut source = engine();
        let command = command(1);
        source.accept_local(command.clone()).unwrap();
        let manifest = source.recovery_manifest().unwrap();

        let mut learner = engine();
        let catch_up = learner.install_recovery_manifest(manifest).unwrap();
        assert_eq!(catch_up.caught_up_through, learner.runtime().head().nonce);
        assert_eq!(learner.recovery_status().unwrap().accepted_writes, 1);
        assert_eq!(
            learner
                .accepted_transaction(command.identity)
                .unwrap()
                .payload_as_borsh::<ActiveActiveCommand>()
                .unwrap(),
            command
        );
    }

    #[test]
    fn durable_lifecycle_restores_translated_cutover_across_restarts() {
        let temporary = tempfile::tempdir().unwrap();
        let original = command(1);
        let identity = original.identity;
        let translated = ActiveActiveCommand {
            identity,
            command: ApplicationCommand::new(b"translated-after-restart".to_vec()).unwrap(),
        };
        let translated_hash = translated.hash().unwrap();

        {
            let mut engine =
                durable_engine(temporary.path(), RouteGeneration(1), CommandSpecVersion(1));
            assert!(engine.is_production_durable());
            engine.accept_local(original).unwrap();
            engine
                .begin_application_cutover(RouteGeneration(2), CommandSpecVersion(2))
                .unwrap();
            engine
                .recertify_accepted_as(identity, translated.clone())
                .unwrap();
        }

        {
            let mut recovered =
                durable_engine(temporary.path(), RouteGeneration(2), CommandSpecVersion(2));
            let status = recovered.recovery_status().unwrap();
            assert_eq!(status.route_generation, RouteGeneration(1));
            assert_eq!(status.command_spec_version, CommandSpecVersion(1));
            assert!(status.runtime_durable);
            assert!(status.lifecycle_durable);
            let manifest = recovered.cutover_manifest().unwrap();
            recovered.activate_cutover(&manifest).unwrap();
        }

        let mut activated =
            durable_engine(temporary.path(), RouteGeneration(2), CommandSpecVersion(2));
        assert_eq!(
            activated
                .accepted_transaction(identity)
                .unwrap()
                .payload_as_borsh::<ActiveActiveCommand>()
                .unwrap(),
            translated
        );
        activated
            .complete_accepted(identity, translated_hash)
            .unwrap();
        drop(activated);
        assert_eq!(
            durable_engine(temporary.path(), RouteGeneration(2), CommandSpecVersion(2),)
                .recovery_status()
                .unwrap()
                .accepted_writes,
            0
        );
    }

    #[test]
    fn cancelled_cutover_returns_resolutions_to_pending_and_can_restart() {
        let mut engine = engine();
        let original = command(1);
        engine.accept_local(original.clone()).unwrap();
        engine
            .begin_application_cutover(RouteGeneration(2), CommandSpecVersion(2))
            .unwrap();
        assert!(engine.accept_local(command(2)).is_err());
        let translated = ActiveActiveCommand {
            identity: original.identity,
            command: ApplicationCommand::new(b"translated-v2".to_vec()).unwrap(),
        };
        engine
            .recertify_accepted_as(original.identity, translated)
            .unwrap();
        assert!(engine.cutover_manifest().is_ok());

        engine.cancel_application_cutover().unwrap();
        assert!(engine.cutover_manifest().is_err());
        assert_eq!(
            engine.recovery_status().unwrap().unresolved_accepted_writes,
            1
        );

        engine
            .begin_application_cutover(RouteGeneration(3), CommandSpecVersion(3))
            .unwrap();
        assert!(engine.recertify_accepted(original.identity).is_err());
        engine
            .abort_accepted(original.identity, "cancelled after membership drift")
            .unwrap();
        let manifest = engine.cutover_manifest().unwrap();
        engine.activate_cutover(&manifest).unwrap();
        assert_eq!(
            engine.recovery_status().unwrap().route_generation,
            RouteGeneration(3)
        );
    }

    #[test]
    fn legacy_manifest_versions_are_rejected() {
        let mut engine = engine();
        engine.begin_cutover(RouteGeneration(2)).unwrap();
        let mut cutover = engine.cutover_manifest().unwrap();
        cutover.format_version = 1;
        assert!(cutover.validate().is_err());

        let mut recovery = engine.recovery_manifest().unwrap();
        recovery.format_version = 1;
        assert!(recovery.validate().is_err());
    }

    #[test]
    fn accepted_write_count_is_bounded() {
        let mut engine = engine();
        for sequence in 1..=MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES as u64 {
            engine.accept_local(command(sequence)).unwrap();
        }
        assert!(
            engine
                .accept_local(command(MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES as u64 + 1))
                .is_err()
        );
    }

    #[test]
    fn durable_batches_use_one_commit_and_restore_normalized_records() {
        let temporary = tempfile::tempdir().unwrap();
        let mut engine =
            durable_engine(temporary.path(), RouteGeneration(1), CommandSpecVersion(1));
        let before = engine.lifecycle_durability_metrics().unwrap();
        let commands = (1..=256).map(command).collect::<Vec<_>>();
        let identities = commands
            .iter()
            .map(|command| command.identity)
            .collect::<Vec<_>>();
        let hashes = engine.accept_local_batch(commands).unwrap();
        let after_accept = engine.lifecycle_durability_metrics().unwrap();
        assert_eq!(after_accept.commit_count, before.commit_count + 1);
        assert_eq!(after_accept.fsync_count, before.fsync_count + 1);
        assert_eq!(engine.recovery_status().unwrap().accepted_writes, 256);
        drop(engine);

        let mut recovered =
            durable_engine(temporary.path(), RouteGeneration(1), CommandSpecVersion(1));
        assert_eq!(recovered.recovery_status().unwrap().accepted_writes, 256);
        for identity in &identities {
            recovered.accepted_transaction(*identity).unwrap();
        }
        let completions = identities.into_iter().zip(hashes).collect::<Vec<_>>();
        let before_complete = recovered.lifecycle_durability_metrics().unwrap();
        recovered.complete_accepted_batch(&completions).unwrap();
        let after_complete = recovered.lifecycle_durability_metrics().unwrap();
        assert_eq!(
            after_complete.commit_count,
            before_complete.commit_count + 1
        );
        assert_eq!(after_complete.fsync_count, before_complete.fsync_count + 1);
        drop(recovered);

        assert_eq!(
            durable_engine(temporary.path(), RouteGeneration(1), CommandSpecVersion(1))
                .recovery_status()
                .unwrap()
                .accepted_writes,
            0
        );
    }

    #[test]
    fn durable_journal_checkpoints_and_recovers() {
        let temporary = tempfile::tempdir().unwrap();
        let mut engine =
            durable_engine(temporary.path(), RouteGeneration(1), CommandSpecVersion(1));
        for sequence in 1..=5 {
            let command = command(sequence);
            let identity = command.identity;
            let command_hash = engine.accept_local(command).unwrap();
            engine.complete_accepted(identity, command_hash).unwrap();
        }
        assert!(
            engine
                .store
                .as_ref()
                .unwrap()
                .journal_entries
                .load(Ordering::Relaxed)
                < ACTIVE_ACTIVE_HA_JOURNAL_CHECKPOINT_ENTRIES
        );
        drop(engine);
        assert_eq!(
            durable_engine(temporary.path(), RouteGeneration(1), CommandSpecVersion(1))
                .recovery_status()
                .unwrap()
                .accepted_writes,
            0
        );
    }

    #[test]
    fn batched_admission_is_idempotent_and_rejects_conflicting_duplicates() {
        let mut engine = engine();
        let accepted = command(1);
        let hashes = engine
            .accept_local_batch(vec![accepted.clone(), accepted.clone()])
            .unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(engine.recovery_status().unwrap().accepted_writes, 1);

        let mut conflicting = accepted;
        conflicting.command = ApplicationCommand::new(b"conflict".to_vec()).unwrap();
        assert!(engine.accept_local_batch(vec![conflicting]).is_err());
        assert_eq!(engine.recovery_status().unwrap().accepted_writes, 1);
    }

    #[cfg(unix)]
    #[test]
    fn durable_lifecycle_rejects_group_readable_command_state() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("lifecycle.redb");
        fs::write(&path, []).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let members = members();
        let runtime = HighAvailabilityRuntime::open(
            temporary.path().join("runtime.redb"),
            ConsensusGroupId::named("active-active-ha-facade"),
            members[0].public_key(),
            members,
            HighAvailabilityParameters::default(),
        )
        .unwrap();
        assert!(
            ActiveActiveHaEngine::open(path, runtime, RouteGeneration(1), CommandSpecVersion(1),)
                .is_err()
        );
    }
}
