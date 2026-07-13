use std::collections::BTreeMap;

use blossom::algorithm::select_quorums;
use blossom::{
    Block, BlockHandle, BlockIndex, Dispatch, DispatchBody, HashType, Keypair, LatencyTopology,
    LocalBlock, MessageMatrix, NodeIdentity, Nonce, PubKey, RuntimeConfig, SignatureTree,
    Transaction, TrustMode, genesis_epoch,
};
use blossom::{
    DoHash, EncodedFrame, NodeRuntime, WireRequest, framed_len, hot_wire_request_framed_len,
};
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

        #[cfg(feature = "external-transaction-hashes")]
        group.bench_with_input(
            BenchmarkId::new("transaction_external_hash_u64", size),
            &size,
            |b, size| {
                b.iter(|| Transaction::from_external_hash_u64(7, vec![7; *size]));
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

    group.bench_function("block_seal_unsigned_32_txs", |b| {
        b.iter_batched(
            || block_with_txs(32),
            |mut block| {
                block.seal_unsigned(keypair.public);
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

    let mut unsigned = block_with_txs(32);
    unsigned.seal_unsigned(keypair.public);
    group.bench_function("block_verify_unsigned_integrity_32_txs", |b| {
        b.iter(|| black_box(&unsigned).verify_unsigned_integrity().unwrap());
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

    group.bench_function("trusted_submit_block_and_dispatch", |b| {
        b.iter_batched(
            runtime_and_unsigned_block,
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

    group.bench_function("local_block_add_transactions_1000", |b| {
        b.iter_batched(
            || {
                (0..1_000)
                    .map(|index| {
                        let mut bytes = vec![0; 32];
                        bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
                        Transaction::new(bytes)
                    })
                    .collect::<Vec<_>>()
            },
            |txs| {
                let mut local = LocalBlock::new(1_024);
                for tx in txs {
                    local.add_transaction(tx);
                }
                black_box(local)
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_block_index(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_index");
    let count = 216usize;
    let btree = btree_block_index(0, count);
    let shared = shared_block_index(0, count);

    group.bench_function(BenchmarkId::new("clone_btree", count), |b| {
        b.iter(|| black_box(black_box(&btree).clone()));
    });
    group.bench_function(BenchmarkId::new("clone_shared", count), |b| {
        b.iter(|| black_box(black_box(&shared).clone()));
    });

    let btree_groups = (0..6)
        .map(|group| btree_block_index(group * 36, 36))
        .collect::<Vec<_>>();
    let shared_groups = (0..6)
        .map(|group| shared_block_index(group * 36, 36))
        .collect::<Vec<_>>();

    group.bench_function("union_btree_6x36", |b| {
        b.iter(|| {
            let mut output = BTreeMap::new();
            for map in black_box(&btree_groups) {
                output.extend(map.clone());
            }
            black_box(output)
        });
    });
    group.bench_function("union_shared_6x36", |b| {
        b.iter(|| {
            let groups = black_box(&shared_groups);
            let output = groups[0].union_from(groups[1..].iter());
            black_box(output)
        });
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

        group.bench_with_input(
            BenchmarkId::new("submit_frame_encode_32b_txs", count),
            &count,
            |b, _| {
                b.iter(|| {
                    black_box(
                        EncodedFrame::encode(black_box(&submit)).expect("wire frame should encode"),
                    )
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("submit_hot_frame_len_32b_txs", count),
            &count,
            |b, _| {
                b.iter(|| {
                    black_box(
                        hot_wire_request_framed_len(black_box(&submit))
                            .expect("wire length should be computable")
                            .expect("submit block should have hot wire encoding"),
                    )
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("submit_hot_frame_encode_32b_txs", count),
            &count,
            |b, _| {
                b.iter(|| {
                    black_box(
                        EncodedFrame::encode_hot_wire_request(black_box(&submit))
                            .expect("wire frame should encode")
                            .expect("submit block should have hot wire encoding"),
                    )
                });
            },
        );

        let encoded = EncodedFrame::encode_hot_wire_request(&submit)
            .expect("wire frame should encode")
            .expect("submit block should have hot wire encoding");
        group.bench_with_input(
            BenchmarkId::new("submit_frame_clone_32b_txs", count),
            &count,
            |b, _| b.iter(|| black_box(black_box(&encoded).clone())),
        );
    }

    group.finish();
}

#[cfg_attr(not(feature = "filtered-transactions"), allow(unused_variables))]
fn bench_filtered_transactions(c: &mut Criterion) {
    #[cfg(feature = "filtered-transactions")]
    {
        let mut group = c.benchmark_group("filtered_transactions");
        group.sample_size(10);

        let target = Keypair::generate();
        let non_target = Keypair::generate();
        let payload = vec![7; 4096];
        let slot = blossom::FilteredTransactionSlot::for_payload(
            HashType::hash(b"bench-key"),
            1,
            vec![target.public],
            &payload,
            blossom::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();

        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_function("filtered_full_4kb", |b| {
            b.iter(|| {
                black_box(
                    Transaction::filtered_full(
                        HashType::hash(b"bench-key"),
                        1,
                        vec![target.public],
                        black_box(payload.clone()),
                        blossom::FilteredDeliveryPolicy::Gossip,
                    )
                    .unwrap(),
                )
            });
        });

        group.bench_function("filtered_tombstone_from_slot", |b| {
            b.iter(|| black_box(Transaction::filtered_tombstone(black_box(slot.clone())).unwrap()));
        });

        let full = Transaction::filtered_full(
            HashType::hash(b"bench-key"),
            1,
            vec![target.public],
            payload.clone(),
            blossom::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        group.bench_function("materialize_target_full_view", |b| {
            b.iter(|| black_box(black_box(&full).materialize_for(&target.public)));
        });
        group.bench_function("materialize_non_target_tombstone", |b| {
            b.iter(|| black_box(black_box(&full).materialize_for(&non_target.public)));
        });

        let mut block = Block::default();
        for index in 0..1_000usize {
            let mut tx_payload = vec![0; 128];
            tx_payload[..8].copy_from_slice(&(index as u64).to_le_bytes());
            block.body.txs.push(
                Transaction::filtered_full(
                    HashType::hash(&tx_payload[..8]),
                    1,
                    vec![target.public],
                    tx_payload,
                    blossom::FilteredDeliveryPolicy::Gossip,
                )
                .unwrap(),
            );
        }
        group.throughput(Throughput::Elements(block.body.txs.len() as u64));
        group.bench_function("materialize_block_1000_non_target", |b| {
            b.iter(|| black_box(black_box(&block).materialize_for(&non_target.public)));
        });

        group.finish();
    }
}

#[cfg_attr(not(feature = "availability-gossip"), allow(unused_variables))]
fn bench_availability_gossip(c: &mut Criterion) {
    #[cfg(feature = "availability-gossip")]
    {
        let mut group = c.benchmark_group("availability_gossip");
        group.sample_size(10);

        let holder = Keypair::generate();
        let target = Keypair::generate();
        let entries = (0..128usize)
            .map(|index| {
                let mut payload = vec![0; 256];
                payload[..8].copy_from_slice(&(index as u64).to_le_bytes());
                let slot = blossom::FilteredTransactionSlot::for_payload(
                    HashType::hash(&payload[..8]),
                    1,
                    vec![target.public],
                    &payload,
                    blossom::FilteredDeliveryPolicy::Gossip,
                )
                .unwrap();
                blossom::AvailabilityEntry::new(slot).unwrap()
            })
            .collect::<Vec<_>>();

        let body = blossom::AvailabilityGossipBody {
            scope: blossom::ConsensusGroupId::root(),
            holder: holder.public,
            entries,
        };
        group.throughput(Throughput::Elements(body.entries.len() as u64));
        group.bench_function("sign_gossip_128_entries", |b| {
            let signer = holder.signer();
            b.iter(|| {
                black_box(
                    blossom::AvailabilityGossip::signed(black_box(body.clone()), &signer).unwrap(),
                )
            });
        });

        let gossip = blossom::AvailabilityGossip::signed(body.clone(), &holder.signer()).unwrap();
        group.bench_function("verify_gossip_128_entries", |b| {
            b.iter(|| {
                black_box(&gossip).verify().unwrap();
                black_box(())
            });
        });

        let payload = vec![9; 4096];
        let slot = blossom::FilteredTransactionSlot::for_payload(
            HashType::hash(b"delivery-key"),
            1,
            vec![target.public],
            &payload,
            blossom::FilteredDeliveryPolicy::Gossip,
        )
        .unwrap();
        let delivery_body = blossom::FilteredPayloadDeliveryBody {
            scope: blossom::ConsensusGroupId::root(),
            holder: holder.public,
            slot_hash: slot.hash(),
            slot,
            payload,
        };
        group.throughput(Throughput::Bytes(delivery_body.payload.len() as u64));
        group.bench_function("sign_delivery_4kb", |b| {
            let signer = holder.signer();
            b.iter(|| {
                black_box(
                    blossom::FilteredPayloadDelivery::signed(
                        black_box(delivery_body.clone()),
                        &signer,
                    )
                    .unwrap(),
                )
            });
        });

        let delivery =
            blossom::FilteredPayloadDelivery::signed(delivery_body, &holder.signer()).unwrap();
        group.bench_function("verify_delivery_4kb", |b| {
            b.iter(|| {
                black_box(&delivery).verify().unwrap();
                black_box(())
            });
        });

        group.bench_function("ideal_rounds_36_fanout_6", |b| {
            b.iter(|| black_box(blossom::ideal_push_gossip_rounds(36, 6).unwrap()));
        });

        group.finish();
    }
}

#[cfg_attr(not(feature = "fair-block-ordering"), allow(unused_variables))]
fn bench_fair_block_ordering(c: &mut Criterion) {
    #[cfg(feature = "fair-block-ordering")]
    {
        let mut group = c.benchmark_group("fair_block_ordering");
        group.sample_size(10);

        for (block_count, txs_per_block) in [(6usize, 256usize), (36, 128), (216, 64)] {
            let blocks = fair_order_blocks(block_count, txs_per_block, 32);
            let total_txs = block_count * txs_per_block;
            group.throughput(Throughput::Elements(total_txs as u64));

            group.bench_with_input(
                BenchmarkId::new("raw_collect_and_hash_block_leaves", block_count),
                &blocks,
                |b, blocks| {
                    b.iter(|| {
                        let leaves = black_box(blocks).keys().copied().collect::<Vec<_>>();
                        black_box(HashType::hash_slices(leaves.iter().map(AsRef::as_ref)))
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("fair_transaction_count", block_count),
                &blocks,
                |b, blocks| {
                    b.iter(|| black_box(blossom::fair_order_transaction_count(black_box(blocks))));
                },
            );

            group.bench_with_input(
                BenchmarkId::new("fair_order_seed", block_count),
                &blocks,
                |b, blocks| {
                    b.iter(|| black_box(blossom::fair_block_order_seed(black_box(blocks))));
                },
            );

            group.bench_with_input(
                BenchmarkId::new("fair_ordered_block_commitments", block_count),
                &blocks,
                |b, blocks| {
                    b.iter(|| {
                        black_box(blossom::fair_ordered_block_commitments(black_box(blocks)))
                    });
                },
            );
        }

        group.finish();
    }
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

#[cfg(feature = "fair-block-ordering")]
fn fair_order_blocks(
    block_count: usize,
    txs_per_block: usize,
    payload_len: usize,
) -> BTreeMap<HashType, Block> {
    (0..block_count)
        .map(|block_index| {
            let mut block = block_with_payload_txs(txs_per_block, payload_len);
            block.body.nonce = Nonce::new(block_index as u64 + 1);
            block.seal_unsigned(PubKey(HashType::hash(&block_index.to_le_bytes()).0));
            (block.hash, block)
        })
        .collect()
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

fn runtime_and_unsigned_block() -> (NodeRuntime, Block) {
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
    config.trust_mode = TrustMode::Trusted;
    let runtime = NodeRuntime::new(config);

    let mut block = block_with_txs(4);
    block.body.last_epoch = genesis.hash;
    block.body.nonce = genesis.body.nonce.new_next();
    block.seal_unsigned(keypair.public);
    (runtime, block)
}

fn btree_block_index(start: usize, count: usize) -> BTreeMap<HashType, BlockHandle> {
    (start..start + count)
        .map(|index| {
            let block = indexed_signed_block(index);
            let handle = BlockHandle::new(block).unwrap();
            (handle.hash(), handle)
        })
        .collect()
}

fn shared_block_index(start: usize, count: usize) -> BlockIndex {
    let mut index = BlockIndex::new();
    for (hash, handle) in btree_block_index(start, count) {
        index.insert(hash, handle);
    }
    index
}

fn indexed_signed_block(index: usize) -> Block {
    let keypair = Keypair::generate();
    let mut block = block_with_payload_txs(4, 32);
    block.body.last_epoch = HashType([1; 32]);
    block.body.nonce = Nonce::new(index as u64 + 1);
    block.sign(&keypair.secret);
    block
}

fn bench_latency_topology(c: &mut Criterion) {
    let (topology, source, anchors, candidates) = latency_topology_fixture(16, 64);
    let (three_route_topology, three_route_source, _, three_route_candidates) =
        latency_topology_fixture(3, 2);
    let now_millis = 10_000;
    let mut observed = topology.clone();
    let mut group = c.benchmark_group("latency_topology");

    group.bench_function("observe_existing_relationship", |b| {
        b.iter(|| {
            black_box(observed.observe(
                black_box(source),
                black_box(anchors[0]),
                black_box(12_345),
                black_box(now_millis),
            ))
        });
    });
    group.bench_function("estimate_direct_relationship", |b| {
        b.iter(|| {
            black_box(
                topology
                    .estimate(
                        black_box(source),
                        black_box(anchors[0]),
                        black_box(now_millis),
                    )
                    .unwrap(),
            )
        });
    });
    group.bench_function("estimate_16_anchors", |b| {
        b.iter(|| {
            black_box(
                topology
                    .estimate(
                        black_box(source),
                        black_box(candidates[0]),
                        black_box(now_millis),
                    )
                    .unwrap(),
            )
        });
    });
    group.bench_function("estimate_one_node_3_routes", |b| {
        b.iter(|| {
            black_box(
                three_route_topology
                    .estimate(
                        black_box(three_route_source),
                        black_box(three_route_candidates[0]),
                        black_box(now_millis),
                    )
                    .unwrap(),
            )
        });
    });
    group.bench_function("closest_of_2_3_routes", |b| {
        b.iter(|| {
            black_box(
                three_route_topology
                    .closest_peer(
                        black_box(three_route_source),
                        three_route_candidates.iter().copied(),
                        black_box(now_millis),
                    )
                    .unwrap(),
            )
        });
    });
    group.bench_function("stress_closest_of_64_16_anchors", |b| {
        b.iter(|| {
            black_box(
                topology
                    .closest_peer(
                        black_box(source),
                        candidates.iter().copied(),
                        black_box(now_millis),
                    )
                    .unwrap(),
            )
        });
    });
    group.finish();
}

fn latency_topology_fixture(
    anchor_count: usize,
    candidate_count: usize,
) -> (LatencyTopology, PubKey, Vec<PubKey>, Vec<PubKey>) {
    let source = topology_key(1);
    let anchors = (0..anchor_count)
        .map(|index| topology_key(2 + index as u64))
        .collect::<Vec<_>>();
    let candidates = (0..candidate_count)
        .map(|index| topology_key(1_000 + index as u64))
        .collect::<Vec<_>>();
    let mut points = BTreeMap::new();
    points.insert(source, (1_000.0, 2_000.0));
    for (index, anchor) in anchors.iter().enumerate() {
        let angle = std::f64::consts::TAU * index as f64 / anchor_count as f64;
        points.insert(*anchor, (20_000.0 * angle.cos(), 20_000.0 * angle.sin()));
    }
    for (index, candidate) in candidates.iter().enumerate() {
        points.insert(
            *candidate,
            (
                -12_000.0 + (index % 16) as f64 * 1_500.0,
                -8_000.0 + (index / 16) as f64 * 4_000.0,
            ),
        );
    }

    let mut topology = LatencyTopology::default();
    for anchor in &anchors {
        observe_topology_distance(&mut topology, &points, source, *anchor);
    }
    for candidate in &candidates {
        for anchor in &anchors {
            observe_topology_distance(&mut topology, &points, *candidate, *anchor);
        }
    }
    for first in 0..anchors.len() {
        for second in (first + 1)..anchors.len() {
            observe_topology_distance(&mut topology, &points, anchors[first], anchors[second]);
        }
    }
    (topology, source, anchors, candidates)
}

fn observe_topology_distance(
    topology: &mut LatencyTopology,
    points: &BTreeMap<PubKey, (f64, f64)>,
    first: PubKey,
    second: PubKey,
) {
    let first_point = points[&first];
    let second_point = points[&second];
    let distance = (first_point.0 - second_point.0).hypot(first_point.1 - second_point.1);
    topology.observe(first, second, distance.round() as u64, 10_000);
}

fn topology_key(value: u64) -> PubKey {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    PubKey(bytes)
}

criterion_group!(
    benches,
    bench_hash_and_block,
    bench_quorum_and_matrix,
    bench_protocol_messages,
    bench_runtime,
    bench_block_index,
    bench_block_scaling,
    bench_filtered_transactions,
    bench_availability_gossip,
    bench_fair_block_ordering,
    bench_latency_topology
);
criterion_main!(benches);
