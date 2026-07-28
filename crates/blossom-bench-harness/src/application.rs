//! Benchmark-only KV/append command specification.
//!
//! Blossom core deliberately treats these commands and results as opaque.

use std::collections::{BTreeMap, BTreeSet};

use blossom::{
    ActiveActiveCommand, ApplicationCommand, ApplicationResult, BlossomError, ClientEpoch,
    ClientId, CommandIdentity, HashType, OrderedApplication, OrderedBatch,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum CommandOperation {
    BlindWrite {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Append {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    CompareAndSwap {
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        value: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum CommandResult {
    Written,
    Appended {
        new_length: u64,
    },
    CompareAndSwap {
        swapped: bool,
        current: Option<Vec<u8>>,
    },
}

pub fn active_active_command(
    identity: CommandIdentity,
    operation: CommandOperation,
) -> Result<ActiveActiveCommand, BlossomError> {
    let bytes = borsh::to_vec(&operation).map_err(|error| {
        BlossomError::WireProtocol(format!("encode benchmark application command: {error}"))
    })?;
    Ok(ActiveActiveCommand {
        identity,
        command: ApplicationCommand::new(bytes)?,
    })
}

pub fn decode_operation(command: &ActiveActiveCommand) -> Result<CommandOperation, BlossomError> {
    borsh::from_slice(command.command.as_bytes()).map_err(|error| {
        BlossomError::WireProtocol(format!("decode benchmark application command: {error}"))
    })
}

pub fn encode_result(result: &CommandResult) -> Result<ApplicationResult, BlossomError> {
    let bytes = borsh::to_vec(result).map_err(|error| {
        BlossomError::WireProtocol(format!("encode benchmark application result: {error}"))
    })?;
    ApplicationResult::new(bytes)
}

pub fn decode_result(result: &ApplicationResult) -> Result<CommandResult, BlossomError> {
    borsh::from_slice(result.as_bytes()).map_err(|error| {
        BlossomError::WireProtocol(format!("decode benchmark application result: {error}"))
    })
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct CachedResult {
    command_hash: HashType,
    result: CommandResult,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
struct SessionState {
    contiguous_sequence: u64,
    sparse_executed: BTreeSet<u64>,
    recent_results: BTreeMap<u64, CachedResult>,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct SharedStateMachine {
    values: BTreeMap<Vec<u8>, Vec<u8>>,
    max_reorder: u64,
    max_sessions: usize,
    sessions: BTreeMap<(ClientId, ClientEpoch), SessionState>,
}

impl SharedStateMachine {
    pub fn new(max_reorder: u64) -> Result<Self, BlossomError> {
        if max_reorder == 0 {
            return Err(BlossomError::InvalidConfiguration(
                "benchmark deduplication reorder window must be positive".to_string(),
            ));
        }
        Ok(Self {
            values: BTreeMap::new(),
            max_reorder,
            max_sessions: 65_536,
            sessions: BTreeMap::new(),
        })
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.values.get(key).map(Vec::as_slice)
    }

    pub fn values(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.values
    }

    pub fn canonical_hash(&self) -> Result<HashType, BlossomError> {
        let bytes = borsh::to_vec(self).map_err(|error| {
            BlossomError::WireProtocol(format!("encode benchmark application state: {error}"))
        })?;
        Ok(HashType::hash_slices([
            b"blossom/benchmark/application-state/v1".as_slice(),
            bytes.as_slice(),
        ]))
    }

    pub fn apply(&mut self, command: &ActiveActiveCommand) -> Result<CommandResult, BlossomError> {
        command.validate()?;
        let command_hash = command.hash()?;
        let session_key = (command.identity.client_id, command.identity.client_epoch);
        if let Some(session) = self.sessions.get(&session_key) {
            if let Some(cached) = session.recent_results.get(&command.identity.sequence) {
                if cached.command_hash != command_hash {
                    return Err(BlossomError::InvalidConfiguration(
                        "conflicting bytes for one benchmark command identity".to_string(),
                    ));
                }
                return Ok(cached.result.clone());
            }
            if command.identity.sequence <= session.contiguous_sequence
                || command.identity.sequence
                    > session.contiguous_sequence.saturating_add(self.max_reorder)
            {
                return Err(BlossomError::InvalidConfiguration(
                    "benchmark command sequence is outside the retained reorder window".to_string(),
                ));
            }
        } else {
            if self.sessions.len() >= self.max_sessions {
                return Err(BlossomError::BlockQueueFull);
            }
            if command.identity.sequence > self.max_reorder {
                return Err(BlossomError::InvalidConfiguration(
                    "first benchmark command sequence is outside the reorder window".to_string(),
                ));
            }
        }

        let result = match decode_operation(command)? {
            CommandOperation::BlindWrite { key, value } => {
                self.values.insert(key, value);
                CommandResult::Written
            }
            CommandOperation::Append { key, value } => {
                let stored = self.values.entry(key).or_default();
                stored.extend_from_slice(&value);
                CommandResult::Appended {
                    new_length: u64::try_from(stored.len()).unwrap_or(u64::MAX),
                }
            }
            CommandOperation::CompareAndSwap {
                key,
                expected,
                value,
            } => {
                let current = self.values.get(&key).cloned();
                let swapped = current == expected;
                if swapped {
                    self.values.insert(key, value);
                }
                CommandResult::CompareAndSwap { swapped, current }
            }
        };

        let session = self
            .sessions
            .entry(session_key)
            .or_insert_with(|| SessionState {
                contiguous_sequence: 0,
                sparse_executed: BTreeSet::new(),
                recent_results: BTreeMap::new(),
            });
        session.sparse_executed.insert(command.identity.sequence);
        session.recent_results.insert(
            command.identity.sequence,
            CachedResult {
                command_hash,
                result: result.clone(),
            },
        );
        while session
            .contiguous_sequence
            .checked_add(1)
            .is_some_and(|next| session.sparse_executed.remove(&next))
        {
            session.contiguous_sequence += 1;
        }
        let retain_from = session
            .contiguous_sequence
            .saturating_sub(self.max_reorder.saturating_sub(1));
        session
            .recent_results
            .retain(|sequence, _| *sequence >= retain_from);
        Ok(result)
    }
}

impl OrderedApplication for SharedStateMachine {
    fn apply_ordered(
        &mut self,
        ordered: &OrderedBatch,
    ) -> Result<Vec<ApplicationResult>, BlossomError> {
        ordered
            .batch
            .commands
            .iter()
            .map(|admitted| {
                self.apply(&admitted.command)
                    .and_then(|result| encode_result(&result))
            })
            .collect()
    }
}
