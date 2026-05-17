# Zero-Copy IndexTreeMap Design Notes

## Goal

Make `indextreemap` suitable as Blossom's canonical ordered index for large
block sets without requiring full `Block` or transaction payload clones during
epoch propagation.

The immediate Blossom hotspot is not key lookup. It is repeated cloning of
`BTreeMap<HashType, Block>` during quorum propagation and dispatch construction.
`IndexTreeMap` can become the right replacement if map snapshots, unions, and
hashing are cheap over shared block handles.

## Blossom Requirements

Blossom needs a map/set layer with these properties:

- Deterministic key order for consensus hashing and wire compatibility.
- Cheap snapshots for per-round state, especially before/after quorum merges.
- Cheap union of block sets by key.
- Borrowed iteration over keys and values.
- Optional index lookup for quorum and validator ordering.
- No deep clone of large values when cloning a map.
- A way to cache or derive canonical key hashes without rebuilding large
  temporary byte buffers.

## Proposed Data Model

Keep `IndexTreeMap<K, V>` as the ordered key/value type, but make large values
cheap to clone at the value layer:

```rust
pub type BlockIndex = IndexTreeMap<HashType, BlockHandle>;

#[derive(Clone)]
pub struct BlockHandle {
    inner: Arc<BlockRecord>,
}

pub struct BlockRecord {
    pub block: Block,
    pub encoded: Bytes,
    pub encoded_len: usize,
    pub hash: HashType,
}
```

For Blossom, the map owns ordered keys and shared handles. Full block payloads
live in a block store or `Arc<BlockRecord>`, and propagation copies only hashes
and reference-counted handles.

## IndexTreeMap Changes

### 1. Persistent Snapshot Support

Add a persistent/copy-on-write variant so `clone()` shares tree nodes instead of
deep-cloning every key and value.

Possible shape:

```rust
pub struct SharedIndexTreeMap<K, V> {
    root: Arc<Node<K, V>>,
    len: usize,
}
```

Mutation should use `Arc::make_mut` or path-copying so inserts/removes copy only
the nodes on the modified path. This is the biggest expected win for Blossom's
`before_round = states.clone()` pattern.

Keep the existing owned `IndexTreeMap` API if compatibility matters; add the
shared variant alongside it first.

### 2. Borrowed Iteration Without Value Clone Bounds

Today several iterator APIs require `K: Clone` and `V: Clone`. Add borrowed
iterators that only require the lifetime of `&self`.

Needed APIs:

```rust
fn iter_ref(&self) -> impl Iterator<Item = (&K, &V)>;
fn keys_ref(&self) -> impl Iterator<Item = &K>;
fn values_ref(&self) -> impl Iterator<Item = &V>;
```

These should not require `V: Clone`. Blossom hashing and wire-size accounting
only need borrowed key/value access.

### 3. Efficient Ordered Union

Add a union operation that reuses existing shared nodes or values where possible.

Useful API:

```rust
fn union_from<'a, I>(&self, others: I) -> Self
where
    I: IntoIterator<Item = &'a Self>;
```

For Blossom, conflict policy can be "same key wins, value is identical by hash."
If a duplicate key maps to a different value, return an error in checked mode.

Also useful:

```rust
fn extend_from_ref(&mut self, other: &Self);
fn contains_all_keys(&self, other: &Self) -> bool;
```

### 4. Cached Canonical Key Hash

Blossom currently hashes block sets by concatenating ordered keys and SHA-256
hashing the result. Avoid rebuilding a temporary `Vec` each time.

Two viable approaches:

1. Streaming hash:

```rust
fn hash_keys_ordered<H>(&self, hasher: &mut H)
where
    H: Digest;
```

2. Cached subtree digest:

```rust
fn ordered_key_hash(&self) -> HashType;
```

Cached subtree digests are better long term, but streaming hash is simpler and
still avoids one allocation per hash call.

### 5. Serialization Strategy

Do not require Blossom to put `IndexTreeMap<HashType, Arc<BlockRecord>>` directly
on the wire.

Instead, support canonical borrowed serialization helpers:

```rust
fn serialize_entries_ordered<W, F>(&self, writer: W, encode_value: F)
where
    F: FnMut(&K, &V, &mut W) -> Result<()>;
```

Blossom can then serialize a block handle by writing the cached encoded block
bytes, while still preserving the same ordered map semantics.

## Blossom Integration Plan

1. Introduce `BlockRecord` and `BlockHandle`.
2. Replace internal propagation maps with `IndexTreeMap<HashType, BlockHandle>`.
3. Keep external wire structs compatible initially by materializing owned
   `BTreeMap<HashType, Block>` only at the boundary.
4. Add cached encoded block bytes and encoded lengths to `BlockRecord`.
5. Replace full dispatch-size recomputation with cached length accounting.
6. Move wire sending toward `Bytes`/handoff once internal sharing is working.

This order keeps protocol behavior stable while removing the deepest clone path.

## Non-Goals

- Do not make Borsh itself zero-copy in this pass.
- Do not change protocol message semantics just to fit a data structure.
- Do not replace every `BTreeMap` immediately; start with block-set paths.
- Do not optimize away signature verification/signing until cloning is under
  control.

## Tests

`indextreemap` should add tests for:

- Clone of shared map preserves all entries.
- Mutating a clone does not mutate the original.
- Iteration order matches `BTreeMap`.
- Union is deterministic regardless of input order.
- Duplicate-key union with unequal values is rejected in checked mode.
- Cached/streamed ordered key hash matches Blossom's current key-concat hash.
- Borrowed iterators work for a non-`Clone` value type.

Blossom should add tests for:

- Block index hash matches the old `BTreeMap<HashType, Block>` hash.
- Dispatch body built from handles is wire-equivalent to the old dispatch.
- Propagation convergence is unchanged across 6, 12, and 36 validators.

## Benchmarks

Measure these before and after:

- Clone/snapshot cost for 36 block maps with 1,000 tx per block.
- Quorum union cost over 36 validators and two rounds.
- Ordered key hash cost for 36 block hashes.
- Dispatch construction cost.
- Full epoch harness at 36 nodes and 1M transactions.

Success criteria for the first pass:

- Map snapshot/clone should no longer appear as the dominant perf hotspot.
- Allocation/page-fault samples should drop materially.
- Epoch harness should preserve convergence and wire-byte accounting.
- Any remaining hot path should shift toward signing, hashing, or actual
  serialization rather than payload cloning.
