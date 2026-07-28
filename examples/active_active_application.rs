use std::collections::BTreeMap;

use blossom::{
    ApplicationResult, BlossomError, HashType, OrderedApplication, OrderedBatch, Result, Watermark,
};
use borsh::{BorshDeserialize, BorshSerialize};

/// Application-owned command specification. Blossom sees only its encoded
/// bytes and the `command_spec_version` committed by each batch reference.
#[derive(BorshSerialize, BorshDeserialize)]
enum ShardCommand {
    Put { key: Vec<u8>, value: Vec<u8> },
    Append { stream: Vec<u8>, value: Vec<u8> },
}

#[derive(BorshSerialize)]
enum ShardResult {
    Written,
    Appended { new_length: u64 },
}

/// Minimal adapter usable by a KV shard, a stream shard, or both.
///
/// Production implementations should persist `applied` in the same durable
/// transaction as their application mutations and result bytes.
#[derive(Default)]
struct ShardApplication {
    applied: BTreeMap<(HashType, Watermark), Vec<ApplicationResult>>,
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
    streams: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl OrderedApplication for ShardApplication {
    fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>> {
        let replay_key = (ordered.reference_hash, ordered.watermark);
        if let Some(results) = self.applied.get(&replay_key) {
            return Ok(results.clone());
        }

        let mut staged_kv = self.kv.clone();
        let mut staged_streams = self.streams.clone();
        let mut results = Vec::with_capacity(ordered.batch.commands.len());
        for admitted in &ordered.batch.commands {
            let command = borsh::from_slice::<ShardCommand>(admitted.command.command.as_bytes())
                .map_err(|error| {
                    BlossomError::ExternalService(format!("decode application command: {error}"))
                })?;
            let result = match command {
                ShardCommand::Put { key, value } => {
                    staged_kv.insert(key, value);
                    ShardResult::Written
                }
                ShardCommand::Append { stream, value } => {
                    let stored = staged_streams.entry(stream).or_default();
                    stored.extend_from_slice(&value);
                    ShardResult::Appended {
                        new_length: stored.len() as u64,
                    }
                }
            };
            let bytes = borsh::to_vec(&result).map_err(|error| {
                BlossomError::ExternalService(format!("encode application result: {error}"))
            })?;
            results.push(ApplicationResult::new(bytes)?);
        }

        self.kv = staged_kv;
        self.streams = staged_streams;
        self.applied.insert(replay_key, results.clone());
        Ok(results)
    }
}

fn main() {
    let _application = ShardApplication::default();
    println!("pass this adapter to GlobalOrderedEngine::apply_contiguous_to()");
}
