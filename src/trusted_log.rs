use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use borsh::{BorshDeserialize, BorshSerialize};
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
use crate::{
    BlossomLogStore, BlossomLogStoreConfig, BlossomLogStoreIdentity, BlossomLogTransaction,
};

const TRUSTED_LOG_FORMAT_VERSION: u16 = 1;
const TRUSTED_LOG_MANIFEST_KEY: &str = "manifest";
const TRUSTED_LOG_HEAD_NONCE_KEY: &str = "head_nonce";
const TRUSTED_LOG_HEAD_HASH_KEY: &str = "head_hash";

const TRUSTED_LOG_MANIFEST_TABLE: &str = "trusted_log_manifest_v1";
const TRUSTED_LOG_META_U64_TABLE: &str = "trusted_log_meta_u64_v1";
const TRUSTED_LOG_META_BYTES_TABLE: &str = "trusted_log_meta_bytes_v1";
const TRUSTED_LOG_EPOCHS_TABLE: &str = "trusted_log_epochs_v1";
const TRUSTED_LOG_ROUND_LOCKS_TABLE: &str = "trusted_log_round_locks_v1";
const TRUSTED_LOG_LOCAL_BLOCKS_TABLE: &str = "trusted_log_local_blocks_v1";

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
    store: BlossomLogStore,
    manifest: TrustedLogManifest,
    consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    #[cfg(test)]
    test_fault: Option<std::sync::Arc<std::sync::atomic::AtomicU8>>,
}

impl TrustedEpochLog {
    pub(crate) fn open(
        path: impl AsRef<Path>,
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
        let public_scope = borsh::to_vec(&manifest).map_err(trusted_log_encode)?;
        let identity = BlossomLogStoreIdentity::new("trusted-epochs", public_scope, 1)?;
        let store = Self {
            store: BlossomLogStore::open(BlossomLogStoreConfig::new(path.as_ref()), identity)?,
            manifest,
            consensus_node_removal_policy,
            #[cfg(test)]
            test_fault: None,
        };
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

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut BlossomLogTransaction<'_>) -> Result<T>,
    ) -> Result<T> {
        #[cfg(test)]
        if self
            .test_fault
            .as_ref()
            .is_some_and(|fault| fault.load(std::sync::atomic::Ordering::SeqCst) != 0)
        {
            return Err(BlossomError::Io(
                "trusted epoch log: injected durability failure".to_string(),
            ));
        }
        self.store.transaction(operation).map(|(result, _)| result)
    }

    fn read_manifest(&self) -> Result<Option<TrustedLogManifest>> {
        let Some(bytes) = self.store.get(
            TRUSTED_LOG_MANIFEST_TABLE,
            TRUSTED_LOG_MANIFEST_KEY.as_bytes(),
        )?
        else {
            return Ok(None);
        };
        borsh::from_slice(&bytes)
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
        self.transact(|transaction| {
            transaction.insert(
                TRUSTED_LOG_MANIFEST_TABLE,
                TRUSTED_LOG_MANIFEST_KEY.as_bytes().to_vec(),
                manifest_bytes,
            )?;
            for (nonce, bytes) in encoded_epochs {
                transaction.insert(
                    TRUSTED_LOG_EPOCHS_TABLE,
                    nonce.to_be_bytes().to_vec(),
                    bytes,
                )?;
            }
            write_head(transaction, head)?;
            Ok(())
        })
    }

    pub(crate) fn load_chain(&self) -> Result<EpochChain> {
        let epochs = self
            .store
            .scan(TRUSTED_LOG_EPOCHS_TABLE)?
            .into_iter()
            .map(|(_, bytes)| borsh::from_slice::<Epoch>(&bytes).map_err(trusted_log_decode))
            .collect::<Result<Vec<_>>>()?;
        let chain = EpochChain { epochchain: epochs };
        validate_trusted_chain(&chain, self.consensus_node_removal_policy)?;
        let expected = chain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let head = read_head(&self.store)?;
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
        self.transact(|transaction| {
            let head = read_write_head_epoch(transaction)?;
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
            let existing_locks = transaction
                .scan(TRUSTED_LOG_ROUND_LOCKS_TABLE)?
                .into_iter()
                .map(|(_, bytes)| {
                    borsh::from_slice::<TrustedRoundLock>(&bytes).map_err(trusted_log_decode)
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
            if let Some(existing) = transaction.get(TRUSTED_LOG_ROUND_LOCKS_TABLE, &key)? {
                let existing =
                    borsh::from_slice::<TrustedRoundLock>(&existing).map_err(trusted_log_decode)?;
                if existing.candidate_hash() != round_lock.candidate_hash()
                    || existing.verification.body.blocks != round_lock.verification.body.blocks
                {
                    return Err(BlossomError::InvalidConfiguration(
                        "trusted node refuses to confirm two candidates for one round".to_string(),
                    ));
                }
                return Ok(());
            }
            transaction.insert(TRUSTED_LOG_ROUND_LOCKS_TABLE, key, bytes)?;
            Ok(())
        })
    }

    pub(crate) fn persist_local_block(&self, block: &Block) -> Result<()> {
        if block.body.validator != self.manifest.self_public_key {
            return Err(BlossomError::UnknownSender);
        }
        block.verify_unsigned_integrity()?;
        let bytes = borsh::to_vec(block).map_err(trusted_log_encode)?;
        self.transact(|transaction| {
            let head = read_write_head_epoch(transaction)?;
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
            let key = block.body.nonce.value().to_be_bytes().to_vec();
            if let Some(existing) = transaction.get(TRUSTED_LOG_LOCAL_BLOCKS_TABLE, &key)? {
                let existing = borsh::from_slice::<Block>(&existing).map_err(trusted_log_decode)?;
                if existing.hash != block.hash {
                    return Err(BlossomError::DuplicateBlock);
                }
                return Ok(());
            }
            transaction.insert(TRUSTED_LOG_LOCAL_BLOCKS_TABLE, key, bytes)?;
            Ok(())
        })
    }

    pub(crate) fn pending_local_block(&self) -> Result<Option<Block>> {
        let head = self.load_head_epoch()?;
        let expected_nonce = head.body.nonce.new_next();
        let Some(bytes) = self.store.get(
            TRUSTED_LOG_LOCAL_BLOCKS_TABLE,
            &expected_nonce.value().to_be_bytes(),
        )?
        else {
            return Ok(None);
        };
        let block = borsh::from_slice::<Block>(&bytes).map_err(trusted_log_decode)?;
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
        let Some(bytes) = self.store.get(TRUSTED_LOG_ROUND_LOCKS_TABLE, &key)? else {
            return Ok(None);
        };
        let round_lock =
            borsh::from_slice::<TrustedRoundLock>(&bytes).map_err(trusted_log_decode)?;
        round_lock.validate(self.manifest.self_public_key)?;
        if round_lock.round_id != *round_id {
            return Err(BlossomError::InvalidConfiguration(
                "trusted epoch log round-lock key conflicts with its record".to_string(),
            ));
        }
        Ok(Some(round_lock))
    }

    pub(crate) fn round_locks(&self) -> Result<Vec<TrustedRoundLock>> {
        let mut locks = self
            .store
            .scan(TRUSTED_LOG_ROUND_LOCKS_TABLE)?
            .into_iter()
            .map(|(_, bytes)| {
                let round_lock =
                    borsh::from_slice::<TrustedRoundLock>(&bytes).map_err(trusted_log_decode)?;
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
        let (nonce, expected_hash) = read_head(&self.store)?;
        let bytes = self
            .store
            .get(TRUSTED_LOG_EPOCHS_TABLE, &nonce.value().to_be_bytes())?
            .ok_or_else(|| {
                BlossomError::InvalidConfiguration(
                    "trusted epoch log head record is missing".to_string(),
                )
            })?;
        let epoch = borsh::from_slice::<Epoch>(&bytes).map_err(trusted_log_decode)?;
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
        self.append_validated_epochs_log_store(epochs_to_append, round_id)
    }

    fn append_validated_epochs_log_store(
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

        self.transact(|transaction| {
            let (current_nonce, current_hash) = read_write_head(transaction)?;
            if current_nonce == head.body.nonce && current_hash == head.hash {
                return Ok(());
            }
            let first = epochs_to_append
                .first()
                .expect("non-empty trusted epoch append");
            if first.body.last_epoch != current_hash
                || first.body.previous_nonce != Some(current_nonce)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted epoch append raced with a different stable-prefix extension"
                        .to_string(),
                ));
            }
            for ((nonce, bytes), epoch) in encoded.iter().zip(epochs_to_append) {
                let key = nonce.to_be_bytes().to_vec();
                if let Some(existing) = transaction.get(TRUSTED_LOG_EPOCHS_TABLE, &key)? {
                    let existing =
                        borsh::from_slice::<Epoch>(&existing).map_err(trusted_log_decode)?;
                    if existing.hash != epoch.hash {
                        return Err(BlossomError::InvalidConfiguration(
                            "trusted epoch log contains conflicting epochs at one nonce"
                                .to_string(),
                        ));
                    }
                } else {
                    transaction.insert(TRUSTED_LOG_EPOCHS_TABLE, key, bytes.clone())?;
                }
            }

            let stale_keys = transaction
                .scan(TRUSTED_LOG_LOCAL_BLOCKS_TABLE)?
                .into_iter()
                .map(|(key, bytes)| {
                    decode_trusted_u64(&key, "local block nonce").map(|nonce| (nonce, bytes))
                })
                .filter_map(|entry| match entry {
                    Ok((nonce, bytes)) if nonce <= head.body.nonce.value() => {
                        Some(Ok((nonce, bytes)))
                    }
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect::<Result<Vec<_>>>()?;
            if stale_keys.len() > 1 {
                return Err(BlossomError::InvalidConfiguration(
                    "trusted epoch log contains multiple stale local writer blocks".to_string(),
                ));
            }
            let mut retry_block = None;
            for (nonce, bytes) in stale_keys {
                let mut block = borsh::from_slice::<Block>(&bytes).map_err(trusted_log_decode)?;
                let committed = epochs_to_append.iter().any(|epoch| {
                    epoch.body.nonce.value() == nonce && epoch.body.blocks.contains_key(&block.hash)
                });
                transaction.remove(TRUSTED_LOG_LOCAL_BLOCKS_TABLE, nonce.to_be_bytes().to_vec())?;
                if !committed {
                    block.body.last_epoch = head.hash;
                    block.body.nonce = head.body.nonce.new_next();
                    block.body.dispatched = 0;
                    block.seal_unsigned(self.manifest.self_public_key);
                    retry_block = Some(block);
                }
            }
            if let Some(retry_block) = retry_block {
                let key = retry_block.body.nonce.value().to_be_bytes().to_vec();
                if let Some(existing) = transaction.get(TRUSTED_LOG_LOCAL_BLOCKS_TABLE, &key)? {
                    let existing =
                        borsh::from_slice::<Block>(&existing).map_err(trusted_log_decode)?;
                    if existing.hash != retry_block.hash {
                        return Err(BlossomError::DuplicateBlock);
                    }
                } else {
                    transaction.insert(
                        TRUSTED_LOG_LOCAL_BLOCKS_TABLE,
                        key,
                        borsh::to_vec(&retry_block).map_err(trusted_log_encode)?,
                    )?;
                }
            }

            let persisted_locks = transaction
                .scan(TRUSTED_LOG_ROUND_LOCKS_TABLE)?
                .into_iter()
                .map(|(key, bytes)| {
                    let lock = borsh::from_slice::<TrustedRoundLock>(&bytes)
                        .map_err(trusted_log_decode)?;
                    lock.validate(self.manifest.self_public_key)?;
                    Ok((key, lock))
                })
                .collect::<Result<Vec<_>>>()?;
            for (_, lock) in &persisted_locks {
                if lock.round_id.group_id != self.manifest.group_id
                    || lock.round_id.previous_epoch_hash != current_hash
                    || lock.round_id.previous_epoch_nonce != current_nonce
                    || lock.round_id.nonce != first.body.nonce
                    || !lock
                        .verification
                        .body
                        .blocks
                        .keys()
                        .all(|hash| first.body.blocks.contains_key(hash))
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
                let epoch_blocks = first
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
                transaction.remove(TRUSTED_LOG_ROUND_LOCKS_TABLE, key)?;
            }
            write_head(transaction, head)?;
            Ok(())
        })
    }

    pub(crate) fn head(&self) -> Result<TrustedLogHead> {
        let (nonce, hash) = read_head(&self.store)?;
        let epoch_count =
            u64::try_from(self.store.scan(TRUSTED_LOG_EPOCHS_TABLE)?.len()).map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "trusted epoch count exceeds the durable format".to_string(),
                )
            })?;
        let pending_round_lock = !self.store.scan(TRUSTED_LOG_ROUND_LOCKS_TABLE)?.is_empty();
        Ok(TrustedLogHead {
            nonce,
            hash,
            epoch_count,
            pending_round_lock,
        })
    }
}

fn write_head(transaction: &mut BlossomLogTransaction<'_>, epoch: &Epoch) -> Result<()> {
    transaction.insert(
        TRUSTED_LOG_META_U64_TABLE,
        TRUSTED_LOG_HEAD_NONCE_KEY.as_bytes().to_vec(),
        epoch.body.nonce.value().to_be_bytes().to_vec(),
    )?;
    transaction.insert(
        TRUSTED_LOG_META_BYTES_TABLE,
        TRUSTED_LOG_HEAD_HASH_KEY.as_bytes().to_vec(),
        epoch.hash.as_ref().to_vec(),
    )
}

fn read_head(store: &BlossomLogStore) -> Result<(Nonce, HashType)> {
    let nonce = store
        .get(
            TRUSTED_LOG_META_U64_TABLE,
            TRUSTED_LOG_HEAD_NONCE_KEY.as_bytes(),
        )?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted epoch log is missing its head nonce".to_string(),
            )
        })?;
    let nonce = decode_trusted_u64(&nonce, "head nonce")?;
    let hash = store
        .get(
            TRUSTED_LOG_META_BYTES_TABLE,
            TRUSTED_LOG_HEAD_HASH_KEY.as_bytes(),
        )?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted epoch log is missing its head hash".to_string(),
            )
        })?;
    let hash_bytes: [u8; 32] = hash.as_ref().try_into().map_err(|_| {
        BlossomError::InvalidConfiguration(
            "trusted epoch log head hash has invalid length".to_string(),
        )
    })?;
    Ok((Nonce::new(nonce), HashType(hash_bytes)))
}

fn read_write_head(transaction: &BlossomLogTransaction<'_>) -> Result<(Nonce, HashType)> {
    let nonce = transaction
        .get(
            TRUSTED_LOG_META_U64_TABLE,
            TRUSTED_LOG_HEAD_NONCE_KEY.as_bytes(),
        )?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted epoch log is missing its head nonce".to_string(),
            )
        })?;
    let nonce = decode_trusted_u64(&nonce, "head nonce")?;
    let hash_bytes = transaction
        .get(
            TRUSTED_LOG_META_BYTES_TABLE,
            TRUSTED_LOG_HEAD_HASH_KEY.as_bytes(),
        )?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted epoch log is missing its head hash".to_string(),
            )
        })?;
    let hash_bytes: [u8; 32] = hash_bytes.try_into().map_err(|_| {
        BlossomError::InvalidConfiguration(
            "trusted epoch log head hash has invalid length".to_string(),
        )
    })?;
    Ok((Nonce::new(nonce), HashType(hash_bytes)))
}

fn read_write_head_epoch(transaction: &BlossomLogTransaction<'_>) -> Result<Epoch> {
    let (nonce, expected_hash) = read_write_head(transaction)?;
    let bytes = transaction
        .get(TRUSTED_LOG_EPOCHS_TABLE, &nonce.value().to_be_bytes())?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "trusted epoch log head record is missing".to_string(),
            )
        })?;
    let epoch = borsh::from_slice::<Epoch>(&bytes).map_err(trusted_log_decode)?;
    if epoch.body.nonce != nonce || epoch.hash != expected_hash {
        return Err(BlossomError::InvalidConfiguration(
            "trusted epoch log head metadata conflicts with its record".to_string(),
        ));
    }
    Ok(epoch)
}

fn decode_trusted_u64(bytes: &[u8], field: &str) -> Result<u64> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
        BlossomError::InvalidConfiguration(format!("trusted epoch log {field} has invalid length"))
    })?;
    Ok(u64::from_be_bytes(bytes))
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
}
