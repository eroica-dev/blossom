use std::thread;
use std::time::{Duration, Instant};

use blossom::{
    ActiveActiveCommand, ActiveActiveHaEngine, AdmittedCommand, ApplicationCommand, ClientEpoch,
    ClientId, CommandBatch, CommandIdentity, CommandSpecVersion, ConsensusGroupId,
    DurableAdmissionStore, HighAvailabilityParameters, HighAvailabilityRuntime, Keypair,
    NodeIdentity, PreparedActiveActiveHaShardBatch, PubKey, ReplicaMembershipEpoch,
    RouteGeneration, SiteId, StoreGeneration,
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const SHARDS: u8 = 8;
const COMMANDS_PER_SHARD: u64 = 4_096;

fn members() -> Vec<NodeIdentity> {
    (0..3)
        .map(|index| {
            NodeIdentity::new(
                PubKey([index; 32]),
                None,
                "tcp",
                "127.0.0.1",
                20_000 + u16::from(index),
                false,
            )
        })
        .collect()
}

fn shard_commands(shard: u8) -> Vec<ActiveActiveCommand> {
    (1..=COMMANDS_PER_SHARD)
        .map(|sequence| ActiveActiveCommand {
            identity: CommandIdentity {
                client_id: ClientId([shard; 16]),
                client_epoch: ClientEpoch(1),
                sequence,
            },
            command: ApplicationCommand::new(sequence.to_le_bytes().to_vec()).unwrap(),
        })
        .collect()
}

fn durable_engine(root: &std::path::Path) -> ActiveActiveHaEngine {
    let members = members();
    let runtime = HighAvailabilityRuntime::open(
        root.join("runtime.redb"),
        ConsensusGroupId::named("active-active-ha-sharded-benchmark"),
        members[0].public_key(),
        members,
        HighAvailabilityParameters::default(),
    )
    .unwrap();
    ActiveActiveHaEngine::open(
        root.join("lifecycle.redb"),
        runtime,
        RouteGeneration(1),
        CommandSpecVersion(1),
    )
    .unwrap()
}

fn benchmark_sharded_lifecycle(c: &mut Criterion) {
    let temporary = tempfile::tempdir().unwrap();
    let mut engine = durable_engine(temporary.path());
    let shard_commands = (1..=SHARDS).map(shard_commands).collect::<Vec<_>>();
    let mut group = c.benchmark_group("active_active_ha");
    group.throughput(Throughput::Elements(u64::from(SHARDS) * COMMANDS_PER_SHARD));
    group.bench_function("prepared_8x4096_durable_accept_complete", |benchmark| {
        benchmark.iter_custom(|iterations| {
            let start = Instant::now();
            for _ in 0..iterations {
                let prepared = thread::scope(|scope| {
                    let workers = shard_commands
                        .iter()
                        .map(|commands| {
                            scope.spawn(|| {
                                PreparedActiveActiveHaShardBatch::prepare(commands.clone()).unwrap()
                            })
                        })
                        .collect::<Vec<_>>();
                    workers
                        .into_iter()
                        .map(|worker| worker.join().unwrap())
                        .collect::<Vec<_>>()
                });
                let hashes = engine.accept_prepared_shard_batches(prepared).unwrap();
                let completions = shard_commands
                    .iter()
                    .zip(hashes)
                    .flat_map(|(commands, hashes)| {
                        commands.iter().map(|command| command.identity).zip(hashes)
                    })
                    .collect::<Vec<_>>();
                engine.complete_accepted_batch(&completions).unwrap();
            }
            start.elapsed()
        });
    });
    group.finish();
}

fn benchmark_sharded_admission(c: &mut Criterion) {
    let temporary = tempfile::tempdir().unwrap();
    let stores = (1..=SHARDS)
        .map(|shard| {
            DurableAdmissionStore::open(
                temporary.path().join(format!("admission-{shard}.redb")),
                SiteId("site-a".to_string()),
                StoreGeneration(1),
                Keypair::generate().signer(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut group = c.benchmark_group("active_active_admission");
    group.throughput(Throughput::Elements(u64::from(SHARDS) * COMMANDS_PER_SHARD));
    group.bench_function("durable_8x4096", |benchmark| {
        benchmark.iter_custom(|iterations| {
            let start = Instant::now();
            for iteration in 0..iterations {
                thread::scope(|scope| {
                    let workers = stores
                        .iter()
                        .enumerate()
                        .map(|(offset, store)| {
                            scope.spawn(move || {
                                let commands = shard_commands(offset as u8 + 1)
                                    .into_iter()
                                    .enumerate()
                                    .map(|(command_offset, mut command)| {
                                        command.identity.client_epoch = ClientEpoch(iteration + 1);
                                        AdmittedCommand {
                                            origin_sequence: iteration * COMMANDS_PER_SHARD
                                                + command_offset as u64
                                                + 1,
                                            command,
                                        }
                                    })
                                    .collect();
                                store
                                    .admit_command_batch(
                                        format!("shard-{}", offset + 1).into_bytes(),
                                        &CommandBatch { commands },
                                        ReplicaMembershipEpoch(1),
                                    )
                                    .unwrap();
                            })
                        })
                        .collect::<Vec<_>>();
                    for worker in workers {
                        worker.join().unwrap();
                    }
                });
            }
            start.elapsed()
        });
    });
    group.finish();
}

fn criterion() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = criterion();
    targets = benchmark_sharded_lifecycle, benchmark_sharded_admission
}
criterion_main!(benches);
