//! Shared active-active fixtures and responsibility-focused test modules.

use super::*;
use crate::algorithm::ConsensusParameters;
use crate::block::Block;
use crate::crypto::Keypair;
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::state::EpochBody;
use indextreemap::IndexTreeMap;

#[derive(BorshSerialize, BorshDeserialize)]
struct TestCommand {
    key: Vec<u8>,
    value: Vec<u8>,
}

fn test_result() -> ApplicationResult {
    ApplicationResult::new(vec![1]).unwrap()
}

#[derive(Default)]
struct RecordingApplication {
    applied: BTreeSet<(HashType, Watermark)>,
    values: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl OrderedApplication for RecordingApplication {
    fn apply_ordered(&mut self, ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>> {
        if !self
            .applied
            .insert((ordered.reference_hash, ordered.watermark))
        {
            return Ok(vec![test_result(); ordered.batch.commands.len()]);
        }
        for admitted in &ordered.batch.commands {
            let command = borsh::from_slice::<TestCommand>(admitted.command.command.as_bytes())
                .map_err(encode_error)?;
            self.values.insert(command.key, command.value);
        }
        Ok(vec![test_result(); ordered.batch.commands.len()])
    }
}

struct FailingApplication;

impl OrderedApplication for FailingApplication {
    fn apply_ordered(&mut self, _ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>> {
        Err(BlossomError::ExternalService(
            "application unavailable".to_string(),
        ))
    }
}

struct DivergentApplication;

impl OrderedApplication for DivergentApplication {
    fn apply_ordered(&mut self, _ordered: &OrderedBatch) -> Result<Vec<ApplicationResult>> {
        Ok(Vec::new())
    }
}

fn command(client: u8, sequence: u64, value: &[u8]) -> ActiveActiveCommand {
    let payload = borsh::to_vec(&TestCommand {
        key: b"key".to_vec(),
        value: value.to_vec(),
    })
    .unwrap();
    ActiveActiveCommand {
        identity: CommandIdentity {
            client_id: ClientId([client; 16]),
            client_epoch: ClientEpoch(1),
            sequence,
        },
        command: ApplicationCommand::new(payload).unwrap(),
    }
}

fn batch() -> CommandBatch {
    CommandBatch {
        commands: vec![
            AdmittedCommand {
                origin_sequence: 10,
                command: command(1, 10, b"ten"),
            },
            AdmittedCommand {
                origin_sequence: 11,
                command: command(1, 11, b"eleven"),
            },
        ],
    }
}

fn reference(batch: &CommandBatch, origin: PubKey) -> BatchReference {
    BatchReference::for_batch(
        batch,
        BatchReferenceMetadata {
            cluster_id: HashType([1; 32]),
            consensus_group_id: ConsensusGroupId::root(),
            shard: b"shard-0".to_vec(),
            route_generation: RouteGeneration(1),
            command_spec_version: CommandSpecVersion(1),
            origin,
            origin_incarnation: 1,
            origin_key_generation: 1,
            data_holder_membership_epoch: ReplicaMembershipEpoch(3),
            validator_generation: ValidatorGeneration(5),
            previous_origin_reference_hash: HashType::default(),
        },
    )
    .unwrap()
}

mod engine;
mod model;
mod store;
mod trusted_ordering;
