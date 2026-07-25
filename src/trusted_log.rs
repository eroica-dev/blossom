use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use serde::{Deserialize, Serialize};

use crate::algorithm::ConsensusParameters;
use crate::block::Block;
use crate::blossom::Verification;
use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{DoHash, HashType};
use crate::membership::{ConsensusNodeRemovalPolicy, apply_epoch_membership_transition};
use crate::nonce::Nonce;
use crate::state::{Epoch, EpochChain, block_merkle_root};

const TRUSTED_LOG_FORMAT_VERSION: u16 = 1;
const TRUSTED_LOG_MANIFEST_KEY: &str = "manifest";
const TRUSTED_LOG_HEAD_NONCE_KEY: &str = "head_nonce";
const TRUSTED_LOG_HEAD_HASH_KEY: &str = "head_hash";

const TRUSTED_LOG_MANIFEST_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("trusted_log_manifest_v1");
const TRUSTED_LOG_META_U64_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("trusted_log_meta_u64_v1");
const TRUSTED_LOG_META_BYTES_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("trusted_log_meta_bytes_v1");
const TRUSTED_LOG_EPOCHS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("trusted_log_epochs_v1");
const TRUSTED_LOG_ROUND_LOCKS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("trusted_log_round_locks_v1");
const TRUSTED_LOG_LOCAL_BLOCKS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("trusted_log_local_blocks_v1");

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct TrustedLogManifest {
    format_version: u16,
    group_id: ConsensusGroupId,
    self_public_key: PubKey,
    genesis_hash: HashType,
    consensus_parameters: ConsensusParameters,
    consensus_node_removal_policy: TrustedRemovalPolicyManifest,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct TrustedRemovalPolicyManifest {
    enabled: bool,
    min_remaining_verifiers: u64,
    max_removals_per_epoch: u64,
    required_observers: Option<u64>,
}

impl TrustedRemovalPolicyManifest {
    fn from_policy(policy: ConsensusNodeRemovalPolicy) -> Result<Self> {
        Ok(Self {
            enabled: policy.enabled,
            min_remaining_verifiers: u64::try_from(policy.min_remaining_verifiers).map_err(
                |_| {
                    BlossomError::InvalidConfiguration(
                        "trusted removal-policy minimum does not fit the durable format"
                            .to_string(),
                    )
                },
            )?,
            max_removals_per_epoch: u64::try_from(policy.max_removals_per_epoch).map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "trusted removal-policy maximum does not fit the durable format".to_string(),
                )
            })?,
            required_observers: policy
                .required_observers
                .map(u64::try_from)
                .transpose()
                .map_err(|_| {
                    BlossomError::InvalidConfiguration(
                        "trusted removal-policy observer threshold does not fit the durable format"
                            .to_string(),
                    )
                })?,
        })
    }
}

#[derive(
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct TrustedRoundId {
    pub group_id: ConsensusGroupId,
    pub previous_epoch_hash: HashType,
    pub previous_epoch_nonce: Nonce,
    pub nonce: Nonce,
    pub round: u8,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct TrustedRoundLock {
    pub round_id: TrustedRoundId,
    pub verification: Verification,
    pub blocks: BTreeMap<HashType, Block>,
}

impl TrustedRoundLock {
    pub fn candidate_hash(&self) -> HashType {
        self.verification.body.blocks_hash
    }

    pub fn validate(&self, self_public_key: PubKey) -> Result<()> {
        if self.verification.header.sender != self_public_key
            || self.verification.header.signature != crate::crypto::Signature::default()
            || self.verification.header.last_epoch != self.round_id.previous_epoch_hash
            || self.verification.header.nonce != self.round_id.nonce
            || self.verification.header.round != self.round_id.round
            || self.round_id.nonce != self.round_id.previous_epoch_nonce.new_next()
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted confirmation lock does not match its round identity".to_string(),
            ));
        }
        let expected_blocks = self
            .blocks
            .keys()
            .map(|hash| (*hash, ()))
            .collect::<BTreeMap<_, _>>();
        if self.verification.body.blocks != expected_blocks
            || self.verification.body.blocks_hash != expected_blocks.hash()
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted confirmation lock does not bind its exact candidate block set".to_string(),
            ));
        }
        let mut writers = BTreeSet::new();
        for (hash, block) in &self.blocks {
            if block.body.last_epoch != self.round_id.previous_epoch_hash
                || block.body.nonce != self.round_id.nonce
                || !writers.insert(block.body.validator)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted confirmation lock contains a stale or duplicate writer block"
                        .to_string(),
                ));
            }
            block.verify_unsigned_integrity_with_hash(*hash)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedLogHead {
    pub nonce: Nonce,
    pub hash: HashType,
    pub epoch_count: u64,
    pub pending_round_lock: bool,
}

#[derive(Clone)]
pub(crate) struct TrustedEpochLog {
    database: Arc<Database>,
    manifest: TrustedLogManifest,
    consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
}

impl TrustedEpochLog {
    pub(crate) fn open(
        path: impl AsRef<Path>,
        self_public_key: PubKey,
        seed: &EpochChain,
        consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    ) -> Result<(Self, EpochChain)> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent).map_err(trusted_log_io)?;
        }
        let database = Database::create(path).map_err(trusted_log_storage)?;
        Self::from_database(
            database,
            self_public_key,
            seed,
            consensus_node_removal_policy,
        )
    }

    pub(crate) fn from_database(
        database: Database,
        self_public_key: PubKey,
        seed: &EpochChain,
        consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    ) -> Result<(Self, EpochChain)> {
        validate_trusted_chain(seed, consensus_node_removal_policy)?;
        let genesis = seed
            .epochchain
            .first()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let manifest = TrustedLogManifest {
            format_version: TRUSTED_LOG_FORMAT_VERSION,
            group_id: genesis.body.group_id,
            self_public_key,
            genesis_hash: genesis.hash,
            consensus_parameters: genesis.body.effective_consensus_parameters(),
            consensus_node_removal_policy: TrustedRemovalPolicyManifest::from_policy(
                consensus_node_removal_policy,
            )?,
        };
        let store = Self {
            database: Arc::new(database),
            manifest,
            consensus_node_removal_policy,
        };
        store.initialize_tables()?;
        let recovered = match store.read_manifest()? {
            Some(committed) => {
                if committed != store.manifest {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted epoch log manifest conflicts with startup configuration"
                            .to_string(),
                    ));
                }
                store.load_chain()?
            }
            None => {
                store.seed(seed)?;
                seed.clone()
            }
        };
        validate_trusted_chain(&recovered, consensus_node_removal_policy)?;
        if recovered.epochchain.first().map(|epoch| epoch.hash) != Some(genesis.hash) {
            return Err(BlossomError::InvalidConfiguration(
                "trusted epoch log genesis conflicts with startup genesis".to_string(),
            ));
        }
        Ok((store, recovered))
    }

    fn initialize_tables(&self) -> Result<()> {
        let mut transaction = self.database.begin_write().map_err(trusted_log_storage)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(trusted_log_storage)?;
        {
            transaction
                .open_table(TRUSTED_LOG_MANIFEST_TABLE)
                .map_err(trusted_log_storage)?;
            transaction
                .open_table(TRUSTED_LOG_META_U64_TABLE)
                .map_err(trusted_log_storage)?;
            transaction
                .open_table(TRUSTED_LOG_META_BYTES_TABLE)
                .map_err(trusted_log_storage)?;
            transaction
                .open_table(TRUSTED_LOG_EPOCHS_TABLE)
                .map_err(trusted_log_storage)?;
            transaction
                .open_table(TRUSTED_LOG_ROUND_LOCKS_TABLE)
                .map_err(trusted_log_storage)?;
            transaction
                .open_table(TRUSTED_LOG_LOCAL_BLOCKS_TABLE)
                .map_err(trusted_log_storage)?;
        }
        transaction.commit().map_err(trusted_log_storage)
    }

    fn read_manifest(&self) -> Result<Option<TrustedLogManifest>> {
        let transaction = self.database.begin_read().map_err(trusted_log_storage)?;
        let table = transaction
            .open_table(TRUSTED_LOG_MANIFEST_TABLE)
            .map_err(trusted_log_storage)?;
        let Some(bytes) = table
            .get(TRUSTED_LOG_MANIFEST_KEY)
            .map_err(trusted_log_storage)?
        else {
            return Ok(None);
        };
        borsh::from_slice(bytes.value())
            .map(Some)
            .map_err(trusted_log_decode)
    }

    fn seed(&self, chain: &EpochChain) -> Result<()> {
        let manifest_bytes = borsh::to_vec(&self.manifest).map_err(trusted_log_encode)?;
        let encoded_epochs = chain
            .epochchain
            .iter()
            .map(|epoch| {
                borsh::to_vec(epoch)
                    .map(|bytes| (epoch.body.nonce.value(), bytes))
                    .map_err(trusted_log_encode)
            })
            .collect::<Result<Vec<_>>>()?;
        let head = chain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let mut transaction = self.database.begin_write().map_err(trusted_log_storage)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(trusted_log_storage)?;
        {
            let mut manifests = transaction
                .open_table(TRUSTED_LOG_MANIFEST_TABLE)
                .map_err(trusted_log_storage)?;
            manifests
                .insert(TRUSTED_LOG_MANIFEST_KEY, manifest_bytes.as_slice())
                .map_err(trusted_log_storage)?;
            let mut epochs = transaction
                .open_table(TRUSTED_LOG_EPOCHS_TABLE)
                .map_err(trusted_log_storage)?;
            for (nonce, bytes) in &encoded_epochs {
                epochs
                    .insert(*nonce, bytes.as_slice())
                    .map_err(trusted_log_storage)?;
            }
            write_head(&transaction, head)?;
        }
        transaction.commit().map_err(trusted_log_storage)
    }

    pub(crate) fn load_chain(&self) -> Result<EpochChain> {
        let transaction = self.database.begin_read().map_err(trusted_log_storage)?;
        let table = transaction
            .open_table(TRUSTED_LOG_EPOCHS_TABLE)
            .map_err(trusted_log_storage)?;
        let epochs = table
            .iter()
            .map_err(trusted_log_storage)?
            .map(|entry| {
                let (_, bytes) = entry.map_err(trusted_log_storage)?;
                borsh::from_slice::<Epoch>(bytes.value()).map_err(trusted_log_decode)
            })
            .collect::<Result<Vec<_>>>()?;
        let chain = EpochChain { epochchain: epochs };
        validate_trusted_chain(&chain, self.consensus_node_removal_policy)?;
        let expected = chain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let head = read_head(&transaction)?;
        if head != (expected.body.nonce, expected.hash) {
            return Err(BlossomError::InvalidConfiguration(
                "trusted epoch log head does not match its final record".to_string(),
            ));
        }
        Ok(chain)
    }

    pub(crate) fn lock_round(&self, round_lock: &TrustedRoundLock) -> Result<()> {
        round_lock.validate(self.manifest.self_public_key)?;
        let key = borsh::to_vec(&round_lock.round_id).map_err(trusted_log_encode)?;
        let bytes = borsh::to_vec(round_lock).map_err(trusted_log_encode)?;
        let mut transaction = self.database.begin_write().map_err(trusted_log_storage)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(trusted_log_storage)?;
        let head = read_write_head_epoch(&transaction)?;
        let head_nonce = head.body.nonce;
        let head_hash = head.hash;
        if round_lock.round_id.group_id != self.manifest.group_id
            || round_lock.round_id.previous_epoch_nonce != head_nonce
            || round_lock.round_id.previous_epoch_hash != head_hash
            || round_lock.round_id.nonce != head_nonce.new_next()
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted confirmation lock does not target the durable log head".to_string(),
            ));
        }
        if round_lock
            .blocks
            .values()
            .any(|block| !head.body.verifiers.contains_key(&block.body.validator))
        {
            return Err(BlossomError::UnknownSender);
        }
        {
            let mut locks = transaction
                .open_table(TRUSTED_LOG_ROUND_LOCKS_TABLE)
                .map_err(trusted_log_storage)?;
            let existing_locks = locks
                .iter()
                .map_err(trusted_log_storage)?
                .map(|entry| {
                    let (_, bytes) = entry.map_err(trusted_log_storage)?;
                    borsh::from_slice::<TrustedRoundLock>(bytes.value()).map_err(trusted_log_decode)
                })
                .collect::<Result<Vec<_>>>()?;
            for existing in &existing_locks {
                existing.validate(self.manifest.self_public_key)?;
                if existing.round_id.group_id != round_lock.round_id.group_id
                    || existing.round_id.previous_epoch_hash
                        != round_lock.round_id.previous_epoch_hash
                    || existing.round_id.previous_epoch_nonce
                        != round_lock.round_id.previous_epoch_nonce
                    || existing.round_id.nonce != round_lock.round_id.nonce
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted epoch log contains confirmation locks for different targets"
                            .to_string(),
                    ));
                }
            }
            if round_lock.round_id.round > 0
                && !existing_locks.iter().any(|existing| {
                    existing.round_id.round.checked_add(1) == Some(round_lock.round_id.round)
                        && existing
                            .verification
                            .body
                            .blocks
                            .keys()
                            .all(|hash| round_lock.verification.body.blocks.contains_key(hash))
                })
            {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted confirmation locks must be contiguous and preserve the prior candidate"
                        .to_string(),
                ));
            }
            if existing_locks
                .iter()
                .any(|existing| existing.round_id.round > round_lock.round_id.round)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted confirmation lock cannot be inserted below a persisted later round"
                        .to_string(),
                ));
            }
            if let Some(existing) = locks.get(key.as_slice()).map_err(trusted_log_storage)? {
                let existing = borsh::from_slice::<TrustedRoundLock>(existing.value())
                    .map_err(trusted_log_decode)?;
                if existing.candidate_hash() != round_lock.candidate_hash()
                    || existing.verification.body.blocks != round_lock.verification.body.blocks
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted node refuses to confirm two candidates for one round".to_string(),
                    ));
                }
                return Ok(());
            }
            locks
                .insert(key.as_slice(), bytes.as_slice())
                .map_err(trusted_log_storage)?;
        }
        transaction.commit().map_err(trusted_log_storage)
    }

    pub(crate) fn persist_local_block(&self, block: &Block) -> Result<()> {
        if block.body.validator != self.manifest.self_public_key {
            return Err(BlossomError::UnknownSender);
        }
        block.verify_unsigned_integrity()?;
        let bytes = borsh::to_vec(block).map_err(trusted_log_encode)?;
        let mut transaction = self.database.begin_write().map_err(trusted_log_storage)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(trusted_log_storage)?;
        let head = read_write_head_epoch(&transaction)?;
        let head_nonce = head.body.nonce;
        let head_hash = head.hash;
        if !head
            .body
            .verifiers
            .contains_key(&self.manifest.self_public_key)
        {
            return Err(BlossomError::UnknownSender);
        }
        if block.body.last_epoch != head_hash || block.body.nonce != head_nonce.new_next() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted local block does not target the durable log head".to_string(),
            ));
        }
        {
            let mut blocks = transaction
                .open_table(TRUSTED_LOG_LOCAL_BLOCKS_TABLE)
                .map_err(trusted_log_storage)?;
            if let Some(existing) = blocks
                .get(block.body.nonce.value())
                .map_err(trusted_log_storage)?
            {
                let existing =
                    borsh::from_slice::<Block>(existing.value()).map_err(trusted_log_decode)?;
                if existing.hash != block.hash {
                    return Err(BlossomError::DuplicateBlock);
                }
                return Ok(());
            }
            blocks
                .insert(block.body.nonce.value(), bytes.as_slice())
                .map_err(trusted_log_storage)?;
        }
        transaction.commit().map_err(trusted_log_storage)
    }

    pub(crate) fn pending_local_block(&self) -> Result<Option<Block>> {
        let head = self.load_head_epoch()?;
        let expected_nonce = head.body.nonce.new_next();
        let transaction = self.database.begin_read().map_err(trusted_log_storage)?;
        let blocks = transaction
            .open_table(TRUSTED_LOG_LOCAL_BLOCKS_TABLE)
            .map_err(trusted_log_storage)?;
        let Some(bytes) = blocks
            .get(expected_nonce.value())
            .map_err(trusted_log_storage)?
        else {
            return Ok(None);
        };
        let block = borsh::from_slice::<Block>(bytes.value()).map_err(trusted_log_decode)?;
        if block.body.validator != self.manifest.self_public_key
            || block.body.last_epoch != head.hash
            || block.body.nonce != expected_nonce
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted pending local block does not target the log head".to_string(),
            ));
        }
        block.verify_unsigned_integrity()?;
        Ok(Some(block))
    }

    pub(crate) fn round_lock(&self, round_id: &TrustedRoundId) -> Result<Option<TrustedRoundLock>> {
        let key = borsh::to_vec(round_id).map_err(trusted_log_encode)?;
        let transaction = self.database.begin_read().map_err(trusted_log_storage)?;
        let table = transaction
            .open_table(TRUSTED_LOG_ROUND_LOCKS_TABLE)
            .map_err(trusted_log_storage)?;
        let Some(bytes) = table.get(key.as_slice()).map_err(trusted_log_storage)? else {
            return Ok(None);
        };
        let round_lock =
            borsh::from_slice::<TrustedRoundLock>(bytes.value()).map_err(trusted_log_decode)?;
        round_lock.validate(self.manifest.self_public_key)?;
        if round_lock.round_id != *round_id {
            return Err(BlossomError::InvalidConfiguration(
                "trusted epoch log round-lock key conflicts with its record".to_string(),
            ));
        }
        Ok(Some(round_lock))
    }

    pub(crate) fn round_locks(&self) -> Result<Vec<TrustedRoundLock>> {
        let transaction = self.database.begin_read().map_err(trusted_log_storage)?;
        let table = transaction
            .open_table(TRUSTED_LOG_ROUND_LOCKS_TABLE)
            .map_err(trusted_log_storage)?;
        let mut locks = table
            .iter()
            .map_err(trusted_log_storage)?
            .map(|entry| {
                let (_, bytes) = entry.map_err(trusted_log_storage)?;
                let round_lock = borsh::from_slice::<TrustedRoundLock>(bytes.value())
                    .map_err(trusted_log_decode)?;
                round_lock.validate(self.manifest.self_public_key)?;
                Ok(round_lock)
            })
            .collect::<Result<Vec<_>>>()?;
        locks.sort_by_key(|round_lock| round_lock.round_id.round);
        Ok(locks)
    }

    pub(crate) fn append_epoch(
        &self,
        epoch: &Epoch,
        round_id: Option<TrustedRoundId>,
    ) -> Result<()> {
        let previous = self.load_head_epoch()?;
        validate_trusted_extension(&previous, epoch, self.consensus_node_removal_policy)?;
        self.append_validated_epochs(std::slice::from_ref(epoch), round_id)
    }

    pub(crate) fn append_suffix(&self, epochs: &[Epoch]) -> Result<()> {
        if epochs.is_empty() {
            return Ok(());
        }
        let head = self.load_head_epoch()?;
        let mut previous = &head;
        for epoch in epochs {
            validate_trusted_extension(previous, epoch, self.consensus_node_removal_policy)?;
            previous = epoch;
        }
        self.append_validated_epochs(epochs, None)
    }

    fn load_head_epoch(&self) -> Result<Epoch> {
        let transaction = self.database.begin_read().map_err(trusted_log_storage)?;
        let (nonce, expected_hash) = read_head(&transaction)?;
        let epochs = transaction
            .open_table(TRUSTED_LOG_EPOCHS_TABLE)
            .map_err(trusted_log_storage)?;
        let bytes = epochs
            .get(nonce.value())
            .map_err(trusted_log_storage)?
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted epoch log head record is missing".to_string(),
                )
            })?;
        let epoch = borsh::from_slice::<Epoch>(bytes.value()).map_err(trusted_log_decode)?;
        if epoch.hash != expected_hash || epoch.body.nonce != nonce {
            return Err(BlossomError::InvalidConfiguration(
                "trusted epoch log head metadata conflicts with its record".to_string(),
            ));
        }
        Ok(epoch)
    }

    fn append_validated_epochs(
        &self,
        epochs_to_append: &[Epoch],
        round_id: Option<TrustedRoundId>,
    ) -> Result<()> {
        let encoded = epochs_to_append
            .iter()
            .map(|epoch| {
                borsh::to_vec(epoch)
                    .map(|bytes| (epoch.body.nonce.value(), bytes))
                    .map_err(trusted_log_encode)
            })
            .collect::<Result<Vec<_>>>()?;
        let head = epochs_to_append.last().ok_or_else(|| {
            BlossomError::InvalidConfiguration("empty trusted log append".to_string())
        })?;
        let round_key = round_id
            .map(|id| borsh::to_vec(&id).map_err(trusted_log_encode))
            .transpose()?;

        let mut transaction = self.database.begin_write().map_err(trusted_log_storage)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(trusted_log_storage)?;
        {
            let current_nonce = {
                let meta = transaction
                    .open_table(TRUSTED_LOG_META_U64_TABLE)
                    .map_err(trusted_log_storage)?;
                meta.get(TRUSTED_LOG_HEAD_NONCE_KEY)
                    .map_err(trusted_log_storage)?
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "trusted epoch log is missing its head nonce".to_string(),
                        )
                    })?
                    .value()
            };
            let current_hash = {
                let meta = transaction
                    .open_table(TRUSTED_LOG_META_BYTES_TABLE)
                    .map_err(trusted_log_storage)?;
                let bytes = meta
                    .get(TRUSTED_LOG_HEAD_HASH_KEY)
                    .map_err(trusted_log_storage)?
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "trusted epoch log is missing its head hash".to_string(),
                        )
                    })?
                    .value()
                    .to_vec();
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                    BlossomError::InvalidConfiguration(
                        "trusted epoch log head hash has invalid length".to_string(),
                    )
                })?;
                HashType(bytes)
            };
            if current_nonce == head.body.nonce.value() && current_hash == head.hash {
                return Ok(());
            }
            let first = epochs_to_append
                .first()
                .expect("non-empty trusted epoch append");
            if first.body.last_epoch != current_hash
                || first.body.previous_nonce != Some(Nonce::new(current_nonce))
            {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted epoch append raced with a different stable-prefix extension"
                        .to_string(),
                ));
            }
            let mut table = transaction
                .open_table(TRUSTED_LOG_EPOCHS_TABLE)
                .map_err(trusted_log_storage)?;
            for ((nonce, bytes), epoch) in encoded.iter().zip(epochs_to_append) {
                if let Some(existing) = table.get(*nonce).map_err(trusted_log_storage)? {
                    let existing =
                        borsh::from_slice::<Epoch>(existing.value()).map_err(trusted_log_decode)?;
                    if existing.hash != epoch.hash {
                        return Err(BlossomError::InvalidConfiguration(
                            "trusted epoch log contains conflicting epochs at one nonce"
                                .to_string(),
                        ));
                    }
                } else {
                    table
                        .insert(*nonce, bytes.as_slice())
                        .map_err(trusted_log_storage)?;
                }
            }
            let retry_block = {
                let mut local_blocks = transaction
                    .open_table(TRUSTED_LOG_LOCAL_BLOCKS_TABLE)
                    .map_err(trusted_log_storage)?;
                let stale_keys = local_blocks
                    .iter()
                    .map_err(trusted_log_storage)?
                    .filter_map(|entry| match entry {
                        Ok((nonce, bytes)) if nonce.value() <= head.body.nonce.value() => {
                            Some(Ok((nonce.value(), bytes.value().to_vec())))
                        }
                        Ok(_) => None,
                        Err(error) => Some(Err(trusted_log_storage(error))),
                    })
                    .collect::<Result<Vec<_>>>()?;
                if stale_keys.len() > 1 {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted epoch log contains multiple stale local writer blocks".to_string(),
                    ));
                }
                let mut retry = None;
                for (nonce, bytes) in stale_keys {
                    let mut block =
                        borsh::from_slice::<Block>(&bytes).map_err(trusted_log_decode)?;
                    let committed = epochs_to_append.iter().any(|epoch| {
                        epoch.body.nonce.value() == nonce
                            && epoch.body.blocks.contains_key(&block.hash)
                    });
                    local_blocks.remove(nonce).map_err(trusted_log_storage)?;
                    if !committed {
                        block.body.last_epoch = head.hash;
                        block.body.nonce = head.body.nonce.new_next();
                        block.body.dispatched = 0;
                        block.seal_unsigned(self.manifest.self_public_key);
                        retry = Some(block);
                    }
                }
                retry
            };
            if let Some(retry_block) = retry_block {
                let retry_bytes = borsh::to_vec(&retry_block).map_err(trusted_log_encode)?;
                let mut local_blocks = transaction
                    .open_table(TRUSTED_LOG_LOCAL_BLOCKS_TABLE)
                    .map_err(trusted_log_storage)?;
                if let Some(existing) = local_blocks
                    .get(retry_block.body.nonce.value())
                    .map_err(trusted_log_storage)?
                {
                    let existing =
                        borsh::from_slice::<Block>(existing.value()).map_err(trusted_log_decode)?;
                    if existing.hash != retry_block.hash {
                        return Err(BlossomError::DuplicateBlock);
                    }
                } else {
                    local_blocks
                        .insert(retry_block.body.nonce.value(), retry_bytes.as_slice())
                        .map_err(trusted_log_storage)?;
                }
            }
            let mut locks = transaction
                .open_table(TRUSTED_LOG_ROUND_LOCKS_TABLE)
                .map_err(trusted_log_storage)?;
            let persisted_locks = locks
                .iter()
                .map_err(trusted_log_storage)?
                .map(|entry| {
                    let (key, bytes) = entry.map_err(trusted_log_storage)?;
                    let lock = borsh::from_slice::<TrustedRoundLock>(bytes.value())
                        .map_err(trusted_log_decode)?;
                    lock.validate(self.manifest.self_public_key)?;
                    Ok((key.value().to_vec(), lock))
                })
                .collect::<Result<Vec<_>>>()?;
            let first_epoch = epochs_to_append
                .first()
                .expect("non-empty trusted epoch append");
            for (_, lock) in &persisted_locks {
                if lock.round_id.group_id != self.manifest.group_id
                    || lock.round_id.previous_epoch_hash != current_hash
                    || lock.round_id.previous_epoch_nonce != Nonce::new(current_nonce)
                    || lock.round_id.nonce != first_epoch.body.nonce
                    || !lock
                        .verification
                        .body
                        .blocks
                        .keys()
                        .all(|hash| first_epoch.body.blocks.contains_key(hash))
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted epoch extension conflicts with a durable confirmation lock"
                            .to_string(),
                    ));
                }
            }
            if let Some(round_key) = round_key.as_deref() {
                let final_lock = persisted_locks
                    .iter()
                    .find(|(key, _)| key.as_slice() == round_key)
                    .map(|(_, lock)| lock)
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "trusted epoch append is missing its durable final-round lock"
                                .to_string(),
                        )
                    })?;
                let epoch_blocks = first_epoch
                    .body
                    .blocks
                    .keys()
                    .map(|hash| (*hash, ()))
                    .collect::<BTreeMap<_, _>>();
                if final_lock.verification.body.blocks != epoch_blocks {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted final epoch does not match its durable final-round confirmation"
                            .to_string(),
                    ));
                }
            }
            for (key, _) in persisted_locks {
                locks.remove(key.as_slice()).map_err(trusted_log_storage)?;
            }
            write_head(&transaction, head)?;
        }
        transaction.commit().map_err(trusted_log_storage)
    }

    pub(crate) fn head(&self) -> Result<TrustedLogHead> {
        let transaction = self.database.begin_read().map_err(trusted_log_storage)?;
        let (nonce, hash) = read_head(&transaction)?;
        let epochs = transaction
            .open_table(TRUSTED_LOG_EPOCHS_TABLE)
            .map_err(trusted_log_storage)?;
        let epoch_count = epochs.len().map_err(trusted_log_storage)?;
        let locks = transaction
            .open_table(TRUSTED_LOG_ROUND_LOCKS_TABLE)
            .map_err(trusted_log_storage)?;
        let pending_round_lock = locks.len().map_err(trusted_log_storage)? != 0;
        Ok(TrustedLogHead {
            nonce,
            hash,
            epoch_count,
            pending_round_lock,
        })
    }
}

fn write_head(transaction: &redb::WriteTransaction, epoch: &Epoch) -> Result<()> {
    let mut meta = transaction
        .open_table(TRUSTED_LOG_META_U64_TABLE)
        .map_err(trusted_log_storage)?;
    meta.insert(TRUSTED_LOG_HEAD_NONCE_KEY, epoch.body.nonce.value())
        .map_err(trusted_log_storage)?;
    let mut bytes = transaction
        .open_table(TRUSTED_LOG_META_BYTES_TABLE)
        .map_err(trusted_log_storage)?;
    bytes
        .insert(TRUSTED_LOG_HEAD_HASH_KEY, epoch.hash.as_ref())
        .map_err(trusted_log_storage)?;
    Ok(())
}

fn read_head(transaction: &redb::ReadTransaction) -> Result<(Nonce, HashType)> {
    let meta = transaction
        .open_table(TRUSTED_LOG_META_U64_TABLE)
        .map_err(trusted_log_storage)?;
    let nonce = meta
        .get(TRUSTED_LOG_HEAD_NONCE_KEY)
        .map_err(trusted_log_storage)?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted epoch log is missing its head nonce".to_string(),
            )
        })?
        .value();
    let bytes = transaction
        .open_table(TRUSTED_LOG_META_BYTES_TABLE)
        .map_err(trusted_log_storage)?;
    let hash = bytes
        .get(TRUSTED_LOG_HEAD_HASH_KEY)
        .map_err(trusted_log_storage)?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted epoch log is missing its head hash".to_string(),
            )
        })?;
    let hash_bytes: [u8; 32] = hash.value().try_into().map_err(|_| {
        BlossomError::InvalidConfiguration(
            "trusted epoch log head hash has invalid length".to_string(),
        )
    })?;
    Ok((Nonce::new(nonce), HashType(hash_bytes)))
}

fn read_write_head(transaction: &redb::WriteTransaction) -> Result<(Nonce, HashType)> {
    let nonce = {
        let meta = transaction
            .open_table(TRUSTED_LOG_META_U64_TABLE)
            .map_err(trusted_log_storage)?;
        meta.get(TRUSTED_LOG_HEAD_NONCE_KEY)
            .map_err(trusted_log_storage)?
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted epoch log is missing its head nonce".to_string(),
                )
            })?
            .value()
    };
    let hash_bytes = {
        let meta = transaction
            .open_table(TRUSTED_LOG_META_BYTES_TABLE)
            .map_err(trusted_log_storage)?;
        meta.get(TRUSTED_LOG_HEAD_HASH_KEY)
            .map_err(trusted_log_storage)?
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted epoch log is missing its head hash".to_string(),
                )
            })?
            .value()
            .to_vec()
    };
    let hash_bytes: [u8; 32] = hash_bytes.try_into().map_err(|_| {
        BlossomError::InvalidConfiguration(
            "trusted epoch log head hash has invalid length".to_string(),
        )
    })?;
    Ok((Nonce::new(nonce), HashType(hash_bytes)))
}

fn read_write_head_epoch(transaction: &redb::WriteTransaction) -> Result<Epoch> {
    let (nonce, expected_hash) = read_write_head(transaction)?;
    let epochs = transaction
        .open_table(TRUSTED_LOG_EPOCHS_TABLE)
        .map_err(trusted_log_storage)?;
    let bytes = epochs
        .get(nonce.value())
        .map_err(trusted_log_storage)?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted epoch log head record is missing".to_string(),
            )
        })?;
    let epoch = borsh::from_slice::<Epoch>(bytes.value()).map_err(trusted_log_decode)?;
    if epoch.body.nonce != nonce || epoch.hash != expected_hash {
        return Err(BlossomError::InvalidConfiguration(
            "trusted epoch log head metadata conflicts with its record".to_string(),
        ));
    }
    Ok(epoch)
}

pub(crate) fn validate_trusted_chain(
    chain: &EpochChain,
    consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
) -> Result<()> {
    let Some(genesis) = chain.epochchain.first() else {
        return Err(BlossomError::EmptyEpochChain);
    };
    if genesis.body.previous_nonce.is_some()
        || genesis.hash != HashType::hash(&genesis.body.to_bytes())
    {
        return Err(BlossomError::InvalidConfiguration(
            "trusted epoch log has an invalid genesis".to_string(),
        ));
    }
    genesis.body.effective_consensus_parameters().validate()?;
    for pair in chain.epochchain.windows(2) {
        validate_trusted_extension(&pair[0], &pair[1], consensus_node_removal_policy)?;
    }
    Ok(())
}

pub(crate) fn validate_trusted_extension(
    previous: &Epoch,
    epoch: &Epoch,
    consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
) -> Result<()> {
    if epoch.body.group_id != previous.body.group_id
        || epoch.body.last_epoch != previous.hash
        || epoch.body.previous_nonce != Some(previous.body.nonce)
        || epoch.body.nonce != previous.body.nonce.new_next()
        || epoch.body.effective_consensus_parameters()
            != previous.body.effective_consensus_parameters()
        || epoch.hash != HashType::hash(&epoch.body.to_bytes())
    {
        return Err(BlossomError::InvalidConfiguration(
            "trusted epoch does not extend the durable stable prefix".to_string(),
        ));
    }
    let mut writers = BTreeSet::new();
    for (hash, block) in &epoch.body.blocks {
        if block.body.last_epoch != previous.hash
            || block.body.nonce != epoch.body.nonce
            || !previous.body.verifiers.contains_key(&block.body.validator)
            || !writers.insert(block.body.validator)
        {
            return Err(BlossomError::InvalidConfiguration(
                "trusted epoch contains a stale, unknown, or duplicate writer block".to_string(),
            ));
        }
        block.verify_unsigned_integrity_with_hash(*hash)?;
    }
    if epoch.body.merkle_root != block_merkle_root(&epoch.body.blocks) {
        return Err(BlossomError::InvalidConfiguration(
            "trusted epoch Merkle root does not match its committed block set".to_string(),
        ));
    }
    let (expected_verifiers, _) = apply_epoch_membership_transition(
        &previous.body.verifiers,
        &epoch.body.blocks,
        previous.hash,
        epoch.body.nonce,
        consensus_node_removal_policy,
    );
    if expected_verifiers.keys().ne(epoch.body.verifiers.keys())
        || expected_verifiers
            .values()
            .ne(epoch.body.verifiers.values())
    {
        return Err(BlossomError::InvalidConfiguration(
            "trusted epoch verifier transition does not match its committed block set".to_string(),
        ));
    }
    Ok(())
}

pub fn assess_trusted_durability_failure(error: &BlossomError) -> TrustedFailureAssessment {
    if matches!(error, BlossomError::Io(message) if message.contains("trusted epoch log")) {
        return TrustedFailureAssessment {
            class: TrustedFailureClass::DurabilityUnavailable,
            retry_in_process: false,
            directives: vec![
                TrustedServiceDirective::NotifyOperators,
                TrustedServiceDirective::NotifyUsers,
                TrustedServiceDirective::DrainWrites,
                TrustedServiceDirective::RestartOrRedeploy,
            ],
        };
    }
    if matches!(error, BlossomError::FailedConsensus) {
        return TrustedFailureAssessment {
            class: TrustedFailureClass::QuorumUnavailable,
            retry_in_process: true,
            directives: vec![
                TrustedServiceDirective::NotifyOperators,
                TrustedServiceDirective::DrainWrites,
                TrustedServiceDirective::AwaitConfirmationQuorum,
            ],
        };
    }
    if matches!(
        error,
        BlossomError::InvalidConfiguration(_) | BlossomError::ConsensusParametersMismatch { .. }
    ) {
        return TrustedFailureAssessment {
            class: TrustedFailureClass::Configuration,
            retry_in_process: false,
            directives: vec![
                TrustedServiceDirective::NotifyOperators,
                TrustedServiceDirective::DrainWrites,
            ],
        };
    }
    TrustedFailureAssessment {
        class: TrustedFailureClass::ProtocolViolation,
        retry_in_process: false,
        directives: vec![
            TrustedServiceDirective::NotifyOperators,
            TrustedServiceDirective::DrainWrites,
            TrustedServiceDirective::QuarantinePeer,
        ],
    }
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub enum TrustedFailureClass {
    DurabilityUnavailable,
    QuorumUnavailable,
    Configuration,
    ProtocolViolation,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum TrustedServiceDirective {
    Continue,
    NotifyOperators,
    NotifyUsers,
    DrainWrites,
    AwaitConfirmationQuorum,
    FetchEpochRange { from: Nonce },
    RestartOrRedeploy,
    QuarantinePeer,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrustedFailureAssessment {
    pub class: TrustedFailureClass,
    pub retry_in_process: bool,
    pub directives: Vec<TrustedServiceDirective>,
}

fn trusted_log_io(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::Io(format!("trusted epoch log: {error}"))
}

fn trusted_log_storage(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::Io(format!("trusted epoch log: {error}"))
}

fn trusted_log_encode(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::WireProtocol(format!("encode trusted epoch log record: {error}"))
}

fn trusted_log_decode(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::WireProtocol(format!("decode trusted epoch log record: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blossom::{Header, VerificationBody};
    use crate::crypto::{Keypair, Signature};
    use crate::node::NodeIdentity;
    use crate::state::EpochBody;
    use redb::StorageBackend;
    use std::io;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicU8, Ordering};

    const NO_FAULT: u8 = 0;
    const STORAGE_FULL: u8 = 1;
    const SYNC_FAILURE: u8 = 2;

    fn nodes(count: usize) -> Vec<NodeIdentity> {
        (0..count)
            .map(|index| {
                let keypair = Keypair::generate();
                NodeIdentity::new(
                    keypair.public,
                    (index == 0).then_some(keypair.secret),
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
        live: Arc<RwLock<Vec<u8>>>,
        durable: Arc<RwLock<Vec<u8>>>,
        fault: Arc<AtomicU8>,
    }

    impl FaultStorage {
        fn new() -> Self {
            Self {
                live: Arc::new(RwLock::new(Vec::new())),
                durable: Arc::new(RwLock::new(Vec::new())),
                fault: Arc::new(AtomicU8::new(NO_FAULT)),
            }
        }

        fn set_fault(&self, fault: u8) {
            self.fault.store(fault, Ordering::SeqCst);
        }

        fn backend(&self) -> FaultBackend {
            *self.live.write().unwrap() = self.durable.read().unwrap().clone();
            FaultBackend {
                live: self.live.clone(),
                durable: self.durable.clone(),
                fault: self.fault.clone(),
            }
        }
    }

    #[derive(Debug)]
    struct FaultBackend {
        live: Arc<RwLock<Vec<u8>>>,
        durable: Arc<RwLock<Vec<u8>>>,
        fault: Arc<AtomicU8>,
    }

    impl FaultBackend {
        fn fail_if(&self, expected: u8, message: &'static str) -> io::Result<()> {
            if self.fault.load(Ordering::SeqCst) == expected {
                return Err(io::Error::new(
                    if expected == STORAGE_FULL {
                        io::ErrorKind::StorageFull
                    } else {
                        io::ErrorKind::Other
                    },
                    message,
                ));
            }
            Ok(())
        }
    }

    impl StorageBackend for FaultBackend {
        fn len(&self) -> io::Result<u64> {
            Ok(self.live.read().unwrap().len() as u64)
        }

        fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
            let offset =
                usize::try_from(offset).map_err(|_| io::Error::other("offset overflow"))?;
            let bytes = self.live.read().unwrap();
            let source = bytes
                .get(offset..offset.saturating_add(out.len()))
                .ok_or_else(|| io::Error::other("read out of bounds"))?;
            out.copy_from_slice(source);
            Ok(())
        }

        fn set_len(&self, len: u64) -> io::Result<()> {
            self.fail_if(STORAGE_FULL, "injected trusted ENOSPC")?;
            let len = usize::try_from(len).map_err(|_| io::Error::other("length overflow"))?;
            self.live.write().unwrap().resize(len, 0);
            Ok(())
        }

        fn sync_data(&self) -> io::Result<()> {
            self.fail_if(SYNC_FAILURE, "injected trusted fsync failure")?;
            *self.durable.write().unwrap() = self.live.read().unwrap().clone();
            Ok(())
        }

        fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            self.fail_if(STORAGE_FULL, "injected trusted ENOSPC")?;
            let offset =
                usize::try_from(offset).map_err(|_| io::Error::other("offset overflow"))?;
            let mut bytes = self.live.write().unwrap();
            let destination = bytes
                .get_mut(offset..offset.saturating_add(data.len()))
                .ok_or_else(|| io::Error::other("write out of bounds"))?;
            destination.copy_from_slice(data);
            Ok(())
        }
    }

    fn fault_store(
        storage: &FaultStorage,
        seed: &EpochChain,
        self_public_key: PubKey,
    ) -> Result<(TrustedEpochLog, EpochChain)> {
        let database = Database::builder()
            .create_with_backend(storage.backend())
            .map_err(trusted_log_storage)?;
        TrustedEpochLog::from_database(
            database,
            self_public_key,
            seed,
            ConsensusNodeRemovalPolicy::disabled(),
        )
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
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blossom-trusted-log-soak-{}-{unique}.redb",
            std::process::id()
        ));
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
        std::fs::remove_file(path).ok();
    }
}
