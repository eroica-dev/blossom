use std::collections::{BTreeMap, BTreeSet};

use blossom::{
    BlossomError, CommandOperation, CommandResult, HashType, OrderedApplication, OrderedBatch,
    Result, Watermark,
};

/// Minimal application adapter usable by a KV shard, a stream shard, or both.
///
/// Production implementations should persist `applied` in the same durable
/// transaction as their application mutations.
#[derive(Default)]
struct ShardApplication {
    applied: BTreeSet<(HashType, Watermark)>,
    kv: BTreeMap<Vec<u8>, Vec<u8>>,
    streams: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl OrderedApplication for ShardApplication {
    fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<CommandResult>> {
        let replay_key = (ordered.reference_hash, ordered.watermark);
        if self.applied.contains(&replay_key) {
            return Ok(ordered.canonical_results.clone());
        }

        let mut staged_kv = self.kv.clone();
        let mut staged_streams = self.streams.clone();
        let mut results = Vec::with_capacity(ordered.batch.commands.len());
        for admitted in &ordered.batch.commands {
            match &admitted.command.operation {
                CommandOperation::BlindWrite { key, value } => {
                    staged_kv.insert(key.clone(), value.clone());
                    results.push(CommandResult::Written);
                }
                CommandOperation::Append { key, value } => {
                    let stream = staged_streams.entry(key.clone()).or_default();
                    stream.extend_from_slice(value);
                    results.push(CommandResult::Appended {
                        new_length: stream.len() as u64,
                    });
                }
                CommandOperation::CompareAndSwap {
                    key,
                    expected,
                    value,
                } => {
                    let current = staged_kv.get(key).cloned();
                    let swapped = &current == expected;
                    if swapped {
                        staged_kv.insert(key.clone(), value.clone());
                    }
                    results.push(CommandResult::CompareAndSwap { swapped, current });
                }
            }
        }
        if results != ordered.canonical_results {
            return Err(BlossomError::ExternalService(
                "application state diverged from Blossom's shared specification".to_string(),
            ));
        }
        self.kv = staged_kv;
        self.streams = staged_streams;

        // In a durable application this marker and the mutations above belong
        // in one atomic transaction.
        if !self.applied.insert(replay_key) {
            return Err(BlossomError::ExternalService(
                "ordered replay marker was not committed".to_string(),
            ));
        }
        Ok(results)
    }
}

fn main() {
    let _application = ShardApplication::default();
    println!("pass this adapter to GlobalOrderedEngine::apply_contiguous_to()");
}
