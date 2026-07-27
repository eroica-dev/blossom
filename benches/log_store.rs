use std::hint::black_box;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use blossom::{BlossomLogStore, BlossomLogStoreConfig, BlossomLogStoreIdentity};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct BenchStore {
    path: PathBuf,
    store: Option<BlossomLogStore>,
}

impl BenchStore {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "blossom-log-store-bench-{label}-{}-{unique}-{sequence}",
            std::process::id()
        ));
        let store = open(&path);
        Self {
            path,
            store: Some(store),
        }
    }

    fn store(&self) -> &BlossomLogStore {
        self.store.as_ref().expect("benchmark store is open")
    }

    fn close(&mut self) {
        if let Some(store) = self.store.take() {
            store.shutdown().expect("shutdown benchmark store");
        }
    }
}

impl Drop for BenchStore {
    fn drop(&mut self) {
        self.close();
        std::fs::remove_dir_all(&self.path).ok();
    }
}

fn open(path: &PathBuf) -> BlossomLogStore {
    BlossomLogStore::open(
        BlossomLogStoreConfig::new(path),
        BlossomLogStoreIdentity::new("criterion", b"public-benchmark-scope".to_vec(), 1)
            .expect("benchmark identity"),
    )
    .expect("open benchmark store")
}

fn benchmark_log_store(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("blossom_log_store");
    group.throughput(Throughput::Elements(1));

    let commit_store = BenchStore::new("commit");
    let mut revision = 0u64;
    group.bench_function("commit_256_bytes", |bencher| {
        bencher.iter(|| {
            revision = revision.checked_add(1).expect("benchmark revision bound");
            commit_store
                .store()
                .transaction(|transaction| {
                    transaction.insert("values", revision.to_be_bytes().to_vec(), vec![0x5a; 256])
                })
                .expect("commit benchmark transaction");
        });
    });

    let read_store = BenchStore::new("read");
    read_store
        .store()
        .transaction(|transaction| transaction.insert("values", b"key".to_vec(), vec![0x6b; 256]))
        .expect("seed read benchmark");
    group.bench_function("materialized_read_256_bytes", |bencher| {
        bencher.iter(|| {
            black_box(
                read_store
                    .store()
                    .get("values", b"key")
                    .expect("read benchmark value"),
            );
        });
    });

    let checkpoint_store = BenchStore::new("checkpoint");
    checkpoint_store
        .store()
        .transaction(|transaction| {
            for index in 0..1_000u64 {
                transaction.insert(
                    "values",
                    index.to_be_bytes().to_vec(),
                    vec![index as u8; 256],
                )?;
            }
            Ok(())
        })
        .expect("seed checkpoint benchmark");
    group.bench_function("checkpoint_1000x256_bytes", |bencher| {
        bencher.iter(|| {
            checkpoint_store
                .store()
                .checkpoint()
                .expect("checkpoint benchmark state");
        });
    });

    group.bench_function("replay_100_transactions", |bencher| {
        bencher.iter_batched(
            || {
                let mut fixture = BenchStore::new("replay");
                for index in 0..100u64 {
                    fixture
                        .store()
                        .transaction(|transaction| {
                            transaction.insert(
                                "values",
                                index.to_be_bytes().to_vec(),
                                vec![index as u8; 256],
                            )
                        })
                        .expect("seed replay benchmark");
                }
                fixture.close();
                fixture
            },
            |fixture| {
                let reopened = open(&fixture.path);
                black_box(reopened.snapshot().revision());
                reopened.shutdown().expect("close replay benchmark store");
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, benchmark_log_store);
criterion_main!(benches);
