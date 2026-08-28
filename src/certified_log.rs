//! Crash-safe append-only persistence for verified epoch certificates.

use std::path::Path;
use std::sync::{Arc, Mutex};

use borsh::{BorshDeserialize, BorshSerialize};

use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::hash::HashType;
use crate::membership::ConsensusNodeRemovalPolicy;
use crate::nonce::Nonce;
use crate::state::{Epoch, EpochChain, validate_certified_extension};
use crate::{
    BlossomLogStore, BlossomLogStoreConfig, BlossomLogStoreIdentity, BlossomLogTransaction,
};

const CERTIFIED_LOG_FORMAT_VERSION: u16 = 1;
const CERTIFIED_LOG_HEAD_NONCE_KEY: &str = "head_nonce";
const CERTIFIED_LOG_HEAD_HASH_KEY: &str = "head_hash";
const CERTIFIED_LOG_META_U64_TABLE: &str = "certified_log_meta_u64_v1";
const CERTIFIED_LOG_META_BYTES_TABLE: &str = "certified_log_meta_bytes_v1";
const CERTIFIED_LOG_EPOCHS_TABLE: &str = "certified_log_epochs_v1";

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq)]
struct CertifiedRemovalPolicyManifest {
    enabled: bool,
    min_remaining_verifiers: u64,
    max_removals_per_epoch: u64,
    required_observers: Option<u64>,
}

impl CertifiedRemovalPolicyManifest {
    fn from_policy(policy: ConsensusNodeRemovalPolicy) -> Result<Self> {
        Ok(Self {
            enabled: policy.enabled,
            min_remaining_verifiers: u64::try_from(policy.min_remaining_verifiers).map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "certified removal-policy minimum does not fit the durable format".to_string(),
                )
            })?,
            max_removals_per_epoch: u64::try_from(policy.max_removals_per_epoch).map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "certified removal-policy maximum does not fit the durable format".to_string(),
                )
            })?,
            required_observers: policy
                .required_observers
                .map(u64::try_from)
                .transpose()
                .map_err(|_| {
                    BlossomError::InvalidConfiguration(
                        "certified removal-policy observer threshold does not fit the durable format"
                            .to_string(),
                    )
                })?,
        })
    }
}

#[derive(Clone)]
pub(crate) struct CertifiedEpochLog {
    store: BlossomLogStore,
    consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    append_lock: Arc<Mutex<()>>,
}

impl CertifiedEpochLog {
    pub(crate) fn open(
        path: impl AsRef<Path>,
        self_public_key: PubKey,
        seed: &EpochChain,
        consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    ) -> Result<(Self, EpochChain)> {
        validate_certified_chain(seed, consensus_node_removal_policy)?;
        let genesis = seed
            .epochchain
            .first()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let public_scope = borsh::to_vec(&(
            CERTIFIED_LOG_FORMAT_VERSION,
            genesis.body.group_id,
            self_public_key,
            genesis.hash,
            genesis.body.effective_consensus_parameters(),
            CertifiedRemovalPolicyManifest::from_policy(consensus_node_removal_policy)?,
        ))
        .map_err(certified_log_encode)?;
        let identity = BlossomLogStoreIdentity::new("certified-epochs", public_scope, 1)?;
        let log = Self {
            store: BlossomLogStore::open(BlossomLogStoreConfig::new(path.as_ref()), identity)?,
            consensus_node_removal_policy,
            append_lock: Arc::new(Mutex::new(())),
        };
        let recovered = match read_optional_head(&log.store)? {
            Some(_) => {
                let recovered = log.load_chain()?;
                if recovered.epochchain.len() >= seed.epochchain.len() {
                    ensure_certified_prefix(seed, &recovered)?;
                    recovered
                } else {
                    ensure_certified_prefix(&recovered, seed)?;
                    log.synchronize(seed)?;
                    seed.clone()
                }
            }
            None => {
                log.seed(seed)?;
                seed.clone()
            }
        };
        Ok((log, recovered))
    }

    fn transact<T>(
        &self,
        operation: impl FnOnce(&mut BlossomLogTransaction<'_>) -> Result<T>,
    ) -> Result<T> {
        self.store.transaction(operation).map(|(result, _)| result)
    }

    fn seed(&self, chain: &EpochChain) -> Result<()> {
        let encoded_epochs = chain
            .epochchain
            .iter()
            .map(|epoch| {
                borsh::to_vec(epoch)
                    .map(|bytes| (epoch.body.nonce.value(), bytes))
                    .map_err(certified_log_encode)
            })
            .collect::<Result<Vec<_>>>()?;
        let head = chain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        self.transact(|transaction| {
            for (nonce, bytes) in encoded_epochs {
                transaction.insert(
                    CERTIFIED_LOG_EPOCHS_TABLE,
                    nonce.to_be_bytes().to_vec(),
                    bytes,
                )?;
            }
            write_head(transaction, head)
        })
    }

    pub(crate) fn load_chain(&self) -> Result<EpochChain> {
        let epochs = self
            .store
            .scan(CERTIFIED_LOG_EPOCHS_TABLE)?
            .into_iter()
            .map(|(_, bytes)| borsh::from_slice::<Epoch>(&bytes).map_err(certified_log_decode))
            .collect::<Result<Vec<_>>>()?;
        let chain = EpochChain { epochchain: epochs };
        validate_certified_chain(&chain, self.consensus_node_removal_policy)?;
        let expected = chain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if read_head(&self.store)? != (expected.body.nonce, expected.hash) {
            return Err(BlossomError::InvalidConfiguration(
                "certified epoch log head does not match its final record".to_string(),
            ));
        }
        Ok(chain)
    }

    /// Appends every in-memory certified epoch after the durable head.
    ///
    /// Concurrent verified completion paths share one lock and re-resolve the
    /// durable prefix while holding it. A caller that observes two newly
    /// installed epochs therefore appends both rather than skipping or racing
    /// the intermediate certificate.
    pub(crate) fn synchronize(&self, chain: &EpochChain) -> Result<()> {
        let _guard = self.append_lock.lock().map_err(|_| {
            BlossomError::InvalidConfiguration(
                "certified epoch append lock is poisoned".to_string(),
            )
        })?;
        let (head_nonce, head_hash) = read_head(&self.store)?;
        let head_index = chain
            .epochchain
            .binary_search_by_key(&head_nonce.value(), |epoch| epoch.body.nonce.value())
            .map_err(|_| {
                BlossomError::InvalidConfiguration(
                    "certified epoch log head is absent from the in-memory chain".to_string(),
                )
            })?;
        let durable_head = &chain.epochchain[head_index];
        if durable_head.hash != head_hash {
            return Err(BlossomError::InvalidConfiguration(
                "certified epoch log head conflicts with the in-memory chain".to_string(),
            ));
        }
        let epochs = &chain.epochchain[head_index + 1..];
        if epochs.is_empty() {
            return Ok(());
        }
        let mut previous = durable_head;
        for epoch in epochs {
            validate_certified_extension(previous, epoch, self.consensus_node_removal_policy)?;
            previous = epoch;
        }
        self.append_validated_epochs(epochs)
    }

    fn append_validated_epochs(&self, epochs: &[Epoch]) -> Result<()> {
        let encoded = epochs
            .iter()
            .map(|epoch| {
                borsh::to_vec(epoch)
                    .map(|bytes| (epoch.body.nonce.value(), bytes))
                    .map_err(certified_log_encode)
            })
            .collect::<Result<Vec<_>>>()?;
        let first = epochs.first().ok_or_else(|| {
            BlossomError::InvalidConfiguration("empty certified epoch append".to_string())
        })?;
        let head = epochs.last().ok_or_else(|| {
            BlossomError::InvalidConfiguration("empty certified epoch append".to_string())
        })?;
        self.transact(|transaction| {
            let (current_nonce, current_hash) = read_write_head(transaction)?;
            if current_nonce == head.body.nonce && current_hash == head.hash {
                return Ok(());
            }
            if first.body.last_epoch != current_hash
                || first.body.previous_nonce != Some(current_nonce)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "certified epoch append raced with a different stable-prefix extension"
                        .to_string(),
                ));
            }
            for ((nonce, bytes), epoch) in encoded.iter().zip(epochs) {
                let key = nonce.to_be_bytes().to_vec();
                if let Some(existing) = transaction.get(CERTIFIED_LOG_EPOCHS_TABLE, &key)? {
                    let existing =
                        borsh::from_slice::<Epoch>(&existing).map_err(certified_log_decode)?;
                    if existing.hash != epoch.hash {
                        return Err(BlossomError::InvalidConfiguration(
                            "certified epoch log contains conflicting epochs at one nonce"
                                .to_string(),
                        ));
                    }
                } else {
                    transaction.insert(CERTIFIED_LOG_EPOCHS_TABLE, key, bytes.clone())?;
                }
            }
            write_head(transaction, head)
        })
    }
}

fn ensure_certified_prefix(prefix: &EpochChain, chain: &EpochChain) -> Result<()> {
    let matches = prefix.epochchain.len() <= chain.epochchain.len()
        && prefix
            .epochchain
            .iter()
            .zip(&chain.epochchain)
            .all(|(left, right)| left.body.nonce == right.body.nonce && left.hash == right.hash);
    if !matches {
        return Err(BlossomError::InvalidConfiguration(
            "certified epoch log conflicts with startup epoch history".to_string(),
        ));
    }
    Ok(())
}

fn validate_certified_chain(
    chain: &EpochChain,
    consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
) -> Result<()> {
    let genesis = chain
        .epochchain
        .first()
        .ok_or(BlossomError::EmptyEpochChain)?;
    if genesis.body.previous_nonce.is_some()
        || genesis.hash != HashType::hash(&genesis.body.to_bytes())
    {
        return Err(BlossomError::InvalidConfiguration(
            "certified epoch log has an invalid genesis".to_string(),
        ));
    }
    genesis.body.effective_consensus_parameters().validate()?;
    for pair in chain.epochchain.windows(2) {
        validate_certified_extension(&pair[0], &pair[1], consensus_node_removal_policy)?;
    }
    Ok(())
}

fn write_head(transaction: &mut BlossomLogTransaction<'_>, epoch: &Epoch) -> Result<()> {
    transaction.insert(
        CERTIFIED_LOG_META_U64_TABLE,
        CERTIFIED_LOG_HEAD_NONCE_KEY.as_bytes().to_vec(),
        epoch.body.nonce.value().to_be_bytes().to_vec(),
    )?;
    transaction.insert(
        CERTIFIED_LOG_META_BYTES_TABLE,
        CERTIFIED_LOG_HEAD_HASH_KEY.as_bytes().to_vec(),
        epoch.hash.as_ref().to_vec(),
    )
}

fn read_optional_head(store: &BlossomLogStore) -> Result<Option<(Nonce, HashType)>> {
    let nonce = store.get(
        CERTIFIED_LOG_META_U64_TABLE,
        CERTIFIED_LOG_HEAD_NONCE_KEY.as_bytes(),
    )?;
    let hash = store.get(
        CERTIFIED_LOG_META_BYTES_TABLE,
        CERTIFIED_LOG_HEAD_HASH_KEY.as_bytes(),
    )?;
    match (nonce, hash) {
        (None, None) => Ok(None),
        (Some(nonce), Some(hash)) => Ok(Some((
            Nonce::new(decode_u64(&nonce, "head nonce")?),
            decode_hash(&hash, "head hash")?,
        ))),
        _ => Err(BlossomError::InvalidConfiguration(
            "certified epoch log head metadata is incomplete".to_string(),
        )),
    }
}

fn read_head(store: &BlossomLogStore) -> Result<(Nonce, HashType)> {
    read_optional_head(store)?.ok_or_else(|| {
        BlossomError::InvalidConfiguration("certified epoch log is missing its head".to_string())
    })
}

fn read_write_head(transaction: &BlossomLogTransaction<'_>) -> Result<(Nonce, HashType)> {
    let nonce = transaction
        .get(
            CERTIFIED_LOG_META_U64_TABLE,
            CERTIFIED_LOG_HEAD_NONCE_KEY.as_bytes(),
        )?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "certified epoch log is missing its head nonce".to_string(),
            )
        })?;
    let hash = transaction
        .get(
            CERTIFIED_LOG_META_BYTES_TABLE,
            CERTIFIED_LOG_HEAD_HASH_KEY.as_bytes(),
        )?
        .ok_or_else(|| {
            BlossomError::InvalidConfiguration(
                "certified epoch log is missing its head hash".to_string(),
            )
        })?;
    Ok((
        Nonce::new(decode_u64(&nonce, "head nonce")?),
        decode_hash(&hash, "head hash")?,
    ))
}

fn decode_u64(bytes: &[u8], field: &str) -> Result<u64> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
        BlossomError::InvalidConfiguration(format!(
            "certified epoch log {field} has invalid length"
        ))
    })?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_hash(bytes: &[u8], field: &str) -> Result<HashType> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        BlossomError::InvalidConfiguration(format!(
            "certified epoch log {field} has invalid length"
        ))
    })?;
    Ok(HashType(bytes))
}

fn certified_log_encode(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::WireProtocol(format!("encode certified epoch log record: {error}"))
}

fn certified_log_decode(error: impl std::fmt::Display) -> BlossomError {
    BlossomError::WireProtocol(format!("decode certified epoch log record: {error}"))
}
