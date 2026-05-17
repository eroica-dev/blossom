use std::collections::BTreeMap;

use blossom::algorithm::select_quorums;
use blossom::{
    Block, Dispatch, DispatchBody, HashType, Keypair, LocalBlock, MessageMatrix, NodeIdentity,
    Nonce, PubKey, RuntimeConfig, SignatureTree, Transaction, genesis_epoch,
};
use blossom::{DoHash, NodeRuntime, WireRequest, framed_len};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_hash_and_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitives");

    for size in [32usize, 512, 4096] {
        group.bench_with_input(
            BenchmarkId::new("transaction_new", size),
            &size,
            |b, size| {
                b.iter(|| Transaction::new(vec![7; *size]));
            },
        );
    }

    let keypair = Keypair::generate();
    group.bench_function("block_sign_32_txs", |b| {
        b.iter_batched(
            || block_with_txs(32),
            |mut block| {
                block.sign(&keypair.secret);
                black_box(block)
            },
            BatchSize::SmallInput,
        );
    });

    let mut signed = block_with_txs(32);
    signed.sign(&keypair.secret);
    group.bench_function("block_verify_integrity_32_txs", |b| {
        b.iter(|| black_box(&signed).verify_integrity().unwrap());
    });

    group.finish();
}

fn bench_quorum_and_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_selection");

    for size in [6usize, 36, 216] {
        let nodes = keys(size);
        let self_key = nodes[size / 2];
        let seed = HashType::hash(b"criterion-seed");
        group.bench_with_input(BenchmarkId::new("select_quorums", size), &size, |b, _| {
            b.iter(|| black_box(select_quorums(nodes.iter().copied(), &self_key, seed, true)));
        });
    }

    let quorum = keys(6);
    group.bench_function("message_matrix_dispatch_echo", |b| {
        b.iter_batched(
            || MessageMatrix::new(&quorum, &quorum[0]),
            |mut matrix| {
                for sender in &quorum[1..] {
                    matrix.update(
                        true,
                        blossom::Msg::Dispatch(Dispatch {
                            header: blossom::Header {
                                sender: *sender,
                                ..Default::default()
                            },
                            body: DispatchBody::default(),
                        }),
                    );
                }
                black_box(matrix.status())
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_protocol_messages(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_messages");
    let keypair = Keypair::generate();
    let block = signed_block(&keypair);
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block);
    let body = DispatchBody {
        blocks_hash: blocks.hash(),
        blocks,
        signature_tree: SignatureTree::default(),
        signature_tree_hash: SignatureTree::default().hash(),
    };

    group.bench_function("dispatch_body_verify", |b| {
        b.iter(|| {
            let (accepted, accepted_hash, tree, tree_hash) =
                black_box(&body).verify_body(&BTreeMap::new());
            black_box((accepted, accepted_hash, tree, tree_hash))
        });
    });

    group.finish();
}

fn bench_runtime(c: &mut Criterion) {
    let mut group = c.benchmark_group("runtime");

    group.bench_function("submit_block_and_dispatch", |b| {
        b.iter_batched(
            runtime_and_block,
            |(runtime, block)| {
                runtime.submit_block(block).unwrap();
                black_box(runtime.dispatch_local_block(0).unwrap())
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("local_block_close_and_dequeue", |b| {
        let keypair = Keypair::generate();
        b.iter_batched(
            || {
                let mut local = LocalBlock::new(8);
                local.add_transaction(Transaction::new("bench-tx"));
                local
            },
            |mut local| {
                local
                    .close_block(&keypair.secret, HashType([1; 32]), Nonce::new(1))
                    .unwrap();
                black_box(
                    local
                        .dequeue_block(Some(keypair.public), HashType([1; 32]), Nonce::new(1), 0)
                        .unwrap(),
                )
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_block_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_scaling");
    group.sample_size(10);

    let keypair = Keypair::generate();
    for count in [1_000usize, 10_000] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::new("sign_block_32b_txs", count),
            &count,
            |b, count| {
                b.iter_batched(
                    || block_with_payload_txs(*count, 32),
                    |mut block| {
                        block.sign(&keypair.secret);
                        black_box(block)
                    },
                    BatchSize::LargeInput,
                );
            },
        );

        let mut signed = block_with_payload_txs(count, 32);
        signed.sign(&keypair.secret);
        group.bench_with_input(
            BenchmarkId::new("verify_block_32b_txs", count),
            &count,
            |b, _| b.iter(|| black_box(&signed).verify_integrity().unwrap()),
        );

        let submit = WireRequest::SubmitBlock(signed.clone());
        group.bench_with_input(
            BenchmarkId::new("submit_frame_len_32b_txs", count),
            &count,
            |b, _| {
                b.iter(|| {
                    black_box(
                        framed_len(black_box(&submit)).expect("wire length should be computable"),
                    )
                });
            },
        );
    }

    group.finish();
}

fn block_with_txs(count: usize) -> Block {
    let mut block = Block::default();
    block.body.last_epoch = HashType([1; 32]);
    block.body.nonce = Nonce::new(1);
    for index in 0..count {
        block
            .body
            .txs
            .push(Transaction::new(format!("bench-tx-{index}")));
    }
    block
}

fn block_with_payload_txs(count: usize, payload_len: usize) -> Block {
    let mut block = Block::default();
    block.body.last_epoch = HashType([1; 32]);
    block.body.nonce = Nonce::new(1);
    for index in 0..count {
        let mut bytes = vec![0; payload_len];
        let index_bytes = (index as u64).to_le_bytes();
        let take = bytes.len().min(index_bytes.len());
        bytes[..take].copy_from_slice(&index_bytes[..take]);
        block.body.txs.push(Transaction::new(bytes));
    }
    block
}

fn signed_block(keypair: &Keypair) -> Block {
    let mut block = block_with_txs(16);
    block.sign(&keypair.secret);
    block
}

fn keys(count: usize) -> Vec<PubKey> {
    (0..count)
        .map(|index| {
            let mut bytes = [0; 32];
            bytes[24..].copy_from_slice(&(index as u64).to_le_bytes());
            PubKey(bytes)
        })
        .collect()
}

fn runtime_and_block() -> (NodeRuntime, Block) {
    let keypair = Keypair::generate();
    let self_node = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );
    let genesis = genesis_epoch([self_node.clone()]);
    let mut config = RuntimeConfig::new(self_node);
    config.genesis = Some(genesis.clone());
    let runtime = NodeRuntime::new(config);

    let mut block = block_with_txs(4);
    block.body.last_epoch = genesis.hash;
    block.body.nonce = genesis.body.nonce.new_next();
    block.sign(&keypair.secret);
    (runtime, block)
}

criterion_group!(
    benches,
    bench_hash_and_block,
    bench_quorum_and_matrix,
    bench_protocol_messages,
    bench_runtime,
    bench_block_scaling
);
criterion_main!(benches);
