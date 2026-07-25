use std::path::Path;
use std::time::Instant;

use blossom::{
    ActiveActiveCommand, CommandResult, ConsensusGroupId, HaAcknowledge, HaConfirm, HaDispatch,
    HighAvailabilityParameters, HighAvailabilityRuntime, NodeIdentity, PubKey, SharedStateMachine,
    Transaction, high_availability_fault_tolerance, high_availability_majority,
};
use redb::{Database, Durability, TableDefinition};
use serde::Serialize;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
const HA_APPLICATION_TABLE: TableDefinition<u8, &[u8]> =
    TableDefinition::new("ha_benchmark_application_v1");

#[derive(Debug, Clone, Serialize)]
pub struct HaAppliedSample {
    pub node_count: usize,
    pub majority: usize,
    pub tolerated_inactive: usize,
    pub writer_count: usize,
    pub command_count: usize,
    pub dispatch_nanos: u64,
    pub available_nanos: u64,
    pub finalized_nanos: u64,
    pub applied_nanos: u64,
    pub sealed_nanos: Option<u64>,
    pub control_bytes: u64,
    pub payload_bytes: u64,
    pub finalized_epoch_hash: blossom::HashType,
    pub state_hash: blossom::HashType,
    pub results: Vec<CommandResult>,
}

/// In-process fixed-slot HA adapter.
///
/// Every runtime independently validates the same messages and independently
/// applies the resulting hash-sorted epoch. The adapter intentionally performs
/// no network shortcuts in the protocol state machine; its only simplification
/// is replacing sockets with direct method calls for protocol-core benchmarks.
pub struct FixedSlotHaCluster {
    runtimes: Vec<HighAvailabilityRuntime>,
    applications: Vec<HaApplication>,
    parameters: HighAvailabilityParameters,
    durable: bool,
}

struct HaEpochExchange {
    dispatches: Vec<HaDispatch>,
    acknowledgements: Vec<HaAcknowledge>,
    confirmations: Vec<HaConfirm>,
    dispatch_nanos: u64,
    available_nanos: u64,
    finalized_nanos: u64,
}

impl FixedSlotHaCluster {
    pub fn new(node_count: usize) -> Result<Self, BoxError> {
        Self::with_parameters(node_count, HighAvailabilityParameters::default())
    }

    pub fn with_parameters(
        node_count: usize,
        parameters: HighAvailabilityParameters,
    ) -> Result<Self, BoxError> {
        let members = benchmark_members(node_count);
        let group = ConsensusGroupId::named(format!("ha-benchmark-{node_count}"));
        let runtimes = members
            .iter()
            .map(|member| {
                HighAvailabilityRuntime::new(
                    group,
                    member.public_key(),
                    members.clone(),
                    parameters,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let applications = (0..node_count)
            .map(|_| HaApplication::in_memory())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            runtimes,
            applications,
            parameters,
            durable: false,
        })
    }

    pub fn with_durable_storage(
        node_count: usize,
        parameters: HighAvailabilityParameters,
        root: impl AsRef<Path>,
    ) -> Result<Self, BoxError> {
        let members = benchmark_members(node_count);
        let group = ConsensusGroupId::named(format!("ha-benchmark-{node_count}"));
        let runtimes = members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                HighAvailabilityRuntime::open(
                    root.as_ref().join(format!("node-{index}.redb")),
                    group,
                    member.public_key(),
                    members.clone(),
                    parameters,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let applications = (0..node_count)
            .map(|index| {
                HaApplication::durable(root.as_ref().join(format!("application-{index}.redb")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            runtimes,
            applications,
            parameters,
            durable: true,
        })
    }

    pub fn node_count(&self) -> usize {
        self.runtimes.len()
    }

    pub fn parameters(&self) -> HighAvailabilityParameters {
        self.parameters
    }

    pub fn fixed_membership_hash(&self) -> blossom::HashType {
        self.runtimes[0].members().fixed_identity_hash()
    }

    pub fn state_hash(&self) -> Result<blossom::HashType, blossom::BlossomError> {
        self.applications[0].machine.canonical_hash()
    }

    pub fn state_machine(&self) -> &SharedStateMachine {
        &self.applications[0].machine
    }

    pub fn client_write_universal(
        &mut self,
        commands: Vec<ActiveActiveCommand>,
        seal: bool,
    ) -> Result<HaAppliedSample, BoxError> {
        if commands.is_empty() || commands.len() > self.node_count() {
            return Err(format!(
                "HA universal writes require 1..={} commands",
                self.node_count()
            )
            .into());
        }
        for command in &commands {
            command.validate()?;
        }
        let started = Instant::now();
        let transaction_sets = (0..self.node_count())
            .map(|index| {
                commands
                    .get(index)
                    .map(Transaction::from_borsh)
                    .transpose()
                    .map(|transaction| transaction.into_iter().collect::<Vec<_>>())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let payload_bytes = transaction_sets
            .iter()
            .flatten()
            .map(Transaction::payload_len)
            .sum::<usize>() as u64;
        let exchange = self.run_epoch(transaction_sets)?;
        let dispatch_wire_bytes = encoded_len_sum(&exchange.dispatches)?;
        let acknowledgement_wire_bytes = encoded_len_sum(&exchange.acknowledgements)?;
        let confirmation_wire_bytes = encoded_len_sum(&exchange.confirmations)?;

        let head = self.runtimes[0].head().clone();
        let mut canonical_results = Vec::new();
        for (_, block) in head.ordered_blocks() {
            for transaction in &block.body.txs {
                let command = transaction.payload_as_borsh::<ActiveActiveCommand>()?;
                canonical_results.push(self.applications[0].apply(&command)?);
            }
        }
        // `Applied` means one state machine has advanced. Replica-wide
        // convergence is checked below but is intentionally outside this
        // milestone, matching OpenRaft client_write() semantics.
        let applied_nanos = elapsed_nanos(started);
        for application in self.applications.iter_mut().skip(1) {
            let mut results = Vec::new();
            for (_, block) in head.ordered_blocks() {
                for transaction in &block.body.txs {
                    let command = transaction.payload_as_borsh::<ActiveActiveCommand>()?;
                    results.push(application.apply(&command)?);
                }
            }
            if results != canonical_results {
                return Err("HA application results diverged across healthy nodes".into());
            }
        }
        let state_hash = self.applications[0].machine.canonical_hash()?;
        if self
            .applications
            .iter()
            .skip(1)
            .any(|application| application.machine.canonical_hash().ok() != Some(state_hash))
        {
            return Err("HA state hashes diverged across healthy nodes".into());
        }

        let sealed_nanos = if seal {
            for _ in 0..self.parameters.mutable_epoch_depth {
                self.run_epoch(vec![Vec::new(); self.node_count()])?;
            }
            Some(elapsed_nanos(started))
        } else {
            None
        };

        Ok(HaAppliedSample {
            node_count: self.node_count(),
            majority: high_availability_majority(self.node_count()),
            tolerated_inactive: high_availability_fault_tolerance(self.node_count()),
            writer_count: commands.len(),
            command_count: commands.len(),
            dispatch_nanos: exchange.dispatch_nanos,
            available_nanos: exchange.available_nanos,
            finalized_nanos: exchange.finalized_nanos,
            applied_nanos,
            sealed_nanos,
            control_bytes: dispatch_wire_bytes
                .saturating_sub(payload_bytes)
                .saturating_add(acknowledgement_wire_bytes)
                .saturating_add(confirmation_wire_bytes),
            payload_bytes,
            finalized_epoch_hash: head.hash,
            state_hash,
            results: canonical_results,
        })
    }

    fn run_epoch(
        &mut self,
        transaction_sets: Vec<Vec<Transaction>>,
    ) -> Result<HaEpochExchange, BoxError> {
        let started = Instant::now();
        let dispatches = self
            .runtimes
            .iter_mut()
            .zip(transaction_sets)
            .map(|(runtime, transactions)| runtime.build_dispatch(transactions))
            .collect::<Result<Vec<_>, _>>()?;
        for (sender, dispatch) in dispatches.iter().enumerate() {
            for (receiver, runtime) in self.runtimes.iter_mut().enumerate() {
                if receiver != sender {
                    runtime.receive_dispatch(dispatch.clone())?;
                }
            }
        }
        let dispatch_nanos = elapsed_nanos(started);
        let acknowledgements = if self.durable {
            parallel_acknowledgements(&mut self.runtimes)?
        } else {
            self.runtimes
                .iter_mut()
                .map(HighAvailabilityRuntime::acknowledge)
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut available_nanos = None;
        for (sender, acknowledgement) in acknowledgements.iter().enumerate() {
            for (receiver, runtime) in self.runtimes.iter_mut().enumerate() {
                if receiver != sender {
                    runtime.receive_acknowledgement(acknowledgement.clone())?;
                }
                if receiver == 0
                    && runtime.current_round().available_mask(runtime.members())
                        == runtime.current_round().received_mask
                    && available_nanos.is_none()
                {
                    available_nanos = Some(elapsed_nanos(started));
                }
            }
        }
        let confirmations = if self.durable {
            parallel_confirmations(&mut self.runtimes)?
        } else {
            self.runtimes
                .iter_mut()
                .map(|runtime| runtime.confirm().map(|(confirmation, _)| confirmation))
                .collect::<Result<Vec<_>, _>>()?
        };
        let starting_head_nonce = self.runtimes[0].head().nonce;
        let mut finalized_nanos = None;
        if self.durable {
            for (sender, confirmation) in confirmations.iter().enumerate() {
                if sender != 0 {
                    self.runtimes[0].receive_confirmation(confirmation.clone())?;
                }
                if self.runtimes[0].head().nonce > starting_head_nonce && finalized_nanos.is_none()
                {
                    finalized_nanos = Some(elapsed_nanos(started));
                }
            }
            parallel_confirmation_delivery(&mut self.runtimes[1..], 1, &confirmations)?;
        } else {
            for (sender, confirmation) in confirmations.iter().enumerate() {
                for (receiver, runtime) in self.runtimes.iter_mut().enumerate() {
                    if receiver != sender {
                        runtime.receive_confirmation(confirmation.clone())?;
                    }
                    if receiver == 0
                        && runtime.head().nonce > starting_head_nonce
                        && finalized_nanos.is_none()
                    {
                        finalized_nanos = Some(elapsed_nanos(started));
                    }
                }
            }
        }
        let head_hash = self.runtimes[0].head().hash;
        if self
            .runtimes
            .iter()
            .any(|runtime| runtime.head().hash != head_hash)
        {
            return Err("HA runtimes finalized different epoch hashes".into());
        }
        Ok(HaEpochExchange {
            dispatches,
            acknowledgements,
            confirmations,
            dispatch_nanos,
            available_nanos: available_nanos.ok_or("HA availability milestone was not reached")?,
            finalized_nanos: finalized_nanos.ok_or("HA finality milestone was not reached")?,
        })
    }
}

fn parallel_acknowledgements(
    runtimes: &mut [HighAvailabilityRuntime],
) -> Result<Vec<HaAcknowledge>, BoxError> {
    std::thread::scope(|scope| {
        let handles = runtimes
            .iter_mut()
            .map(|runtime| scope.spawn(|| runtime.acknowledge()))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| "HA acknowledgement worker panicked")?
                    .map_err(Into::into)
            })
            .collect()
    })
}

fn parallel_confirmations(
    runtimes: &mut [HighAvailabilityRuntime],
) -> Result<Vec<HaConfirm>, BoxError> {
    std::thread::scope(|scope| {
        let handles = runtimes
            .iter_mut()
            .map(|runtime| scope.spawn(|| runtime.confirm().map(|(confirmation, _)| confirmation)))
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| "HA confirmation worker panicked")?
                    .map_err(Into::into)
            })
            .collect()
    })
}

fn parallel_confirmation_delivery(
    runtimes: &mut [HighAvailabilityRuntime],
    receiver_offset: usize,
    confirmations: &[HaConfirm],
) -> Result<(), BoxError> {
    std::thread::scope(|scope| {
        let handles = runtimes
            .iter_mut()
            .enumerate()
            .map(|(offset, runtime)| {
                scope.spawn(move || {
                    let receiver = receiver_offset + offset;
                    for (sender, confirmation) in confirmations.iter().enumerate() {
                        if receiver != sender {
                            runtime.receive_confirmation(confirmation.clone())?;
                        }
                    }
                    Ok::<_, blossom::BlossomError>(())
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle
                .join()
                .map_err(|_| "HA confirmation-delivery worker panicked")??;
        }
        Ok(())
    })
}

struct HaApplication {
    machine: SharedStateMachine,
    database: Option<Database>,
}

impl HaApplication {
    fn in_memory() -> Result<Self, blossom::BlossomError> {
        Ok(Self {
            machine: SharedStateMachine::new(4096)?,
            database: None,
        })
    }

    fn durable(path: impl AsRef<Path>) -> Result<Self, BoxError> {
        let database = Database::create(path)?;
        let mut transaction = database.begin_write()?;
        transaction.set_durability(Durability::Immediate)?;
        {
            transaction.open_table(HA_APPLICATION_TABLE)?;
        }
        transaction.commit()?;
        let application = Self {
            machine: SharedStateMachine::new(4096)?,
            database: Some(database),
        };
        application.persist()?;
        Ok(application)
    }

    fn apply(&mut self, command: &ActiveActiveCommand) -> Result<CommandResult, BoxError> {
        let result = self.machine.apply(command)?;
        self.persist()?;
        Ok(result)
    }

    fn persist(&self) -> Result<(), BoxError> {
        let Some(database) = &self.database else {
            return Ok(());
        };
        let encoded = borsh::to_vec(&self.machine)?;
        let mut transaction = database.begin_write()?;
        transaction.set_durability(Durability::Immediate)?;
        {
            let mut table = transaction.open_table(HA_APPLICATION_TABLE)?;
            table.insert(0u8, encoded.as_slice())?;
        }
        transaction.commit()?;
        Ok(())
    }
}

fn benchmark_members(node_count: usize) -> Vec<NodeIdentity> {
    (0..node_count)
        .map(|index| {
            NodeIdentity::new(
                PubKey([index as u8; 32]),
                None,
                "tcp",
                "127.0.0.1",
                20_000 + index as u16,
                false,
            )
        })
        .collect()
}

fn encoded_len_sum<T: borsh::BorshSerialize>(values: &[T]) -> Result<u64, BoxError> {
    values.iter().try_fold(0u64, |total, value| {
        let bytes = borsh::to_vec(value)?;
        Ok(total.saturating_add(bytes.len() as u64))
    })
}

fn elapsed_nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blossom::{ClientEpoch, ClientId, CommandIdentity, CommandOperation};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn command(writer: u8, sequence: u64) -> ActiveActiveCommand {
        ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([writer; 16]),
                client_epoch: ClientEpoch(1),
                sequence,
            },
            operation: CommandOperation::BlindWrite {
                key: vec![writer],
                value: sequence.to_le_bytes().to_vec(),
            },
        }
    }

    #[test]
    fn every_supported_cluster_applies_all_universal_writers() {
        for nodes in 2..=7 {
            let mut cluster = FixedSlotHaCluster::new(nodes).unwrap();
            let commands = (0..nodes)
                .map(|writer| command(writer as u8, 1))
                .collect::<Vec<_>>();
            let sample = cluster.client_write_universal(commands, false).unwrap();
            assert_eq!(sample.results.len(), nodes);
            assert_eq!(sample.majority, high_availability_majority(nodes));
            assert!(
                sample
                    .results
                    .iter()
                    .all(|result| *result == CommandResult::Written)
            );
        }
    }

    #[test]
    fn sealing_advances_exactly_the_configured_depth() {
        let mut cluster = FixedSlotHaCluster::new(3).unwrap();
        let sample = cluster
            .client_write_universal(vec![command(0, 1)], true)
            .unwrap();
        assert!(sample.sealed_nanos.is_some());
        assert_eq!(cluster.runtimes[0].sealed_watermark().position, 1);
    }

    #[test]
    fn durable_profile_flushes_protocol_and_application_state() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "blossom-ha-adapter-{}-{unique}",
            std::process::id()
        ));
        let mut cluster = FixedSlotHaCluster::with_durable_storage(
            3,
            HighAvailabilityParameters::default(),
            &root,
        )
        .unwrap();
        let sample = cluster
            .client_write_universal(vec![command(0, 1), command(1, 1)], false)
            .unwrap();
        assert!(
            sample
                .results
                .iter()
                .all(|result| *result == CommandResult::Written)
        );
        drop(cluster);
        std::fs::remove_dir_all(root).unwrap();
    }
}
