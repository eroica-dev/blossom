# Code Organization and Maintenance

Blossom keeps stable public module paths while dividing large implementations
into responsibility-focused child files. The repository intentionally uses the
Rust 2018+ parent-file layout:

```text
src/
├── runtime.rs
├── runtime/
│   ├── application.rs
│   ├── consensus.rs
│   ├── core.rs
│   ├── messages.rs
│   ├── multi_group.rs
│   ├── recovery.rs
│   └── snapshot.rs
├── active_active.rs
├── active_active/
│   ├── certificates.rs
│   ├── engine.rs
│   ├── model.rs
│   ├── store.rs
│   └── tracking.rs
├── high_availability.rs
└── high_availability/
    ├── durable.rs
    ├── engine.rs
    ├── membership.rs
    ├── parameters.rs
    ├── protocol.rs
    ├── rounds.rs
    ├── status.rs
    └── transport.rs

crates/blossom-bench-harness/src/
├── blossom_adapter.rs
├── blossom_adapter/
│   ├── active_cluster.rs
│   ├── order_cluster.rs
│   ├── trusted_cluster.rs
│   └── tests.rs
├── raft_adapter.rs
└── raft_adapter/
    ├── campaign.rs
    ├── cluster.rs
    ├── network.rs
    └── tests.rs
```

There are no `mod.rs` files. A public parent such as `runtime.rs` is the module
facade; `runtime/*.rs` contains its private implementation modules.

## Facade responsibilities

Parent files own:

- module-level protocol and threat-model documentation;
- stable public re-exports;
- shared public records and private state envelopes;
- constants and domain separators used by several child modules;
- small helpers whose invariants span more than one responsibility.

Child files own focused `impl` blocks or one family of records. Moving an item
to a child must not change its public path. Re-export a public record from the
parent when necessary; use `pub(super)` only for a real sibling dependency.
Do not make an internal item fully `pub` merely to make the split compile.

The child modules use `use super::*` deliberately. They are implementation
fragments of one facade, and the parent defines their shared dependency
boundary. External code cannot name these private child modules.

Line count is a signal, not an ownership boundary. Split a child when it starts
owning two independently testable invariants, mixes protocol records with I/O,
or makes reviewers load unrelated state transitions to understand a change.
Do not create another file solely to move a short helper away from the state it
protects.

## Runtime ownership

The Global Blossom runtime is divided by operation:

| File | Owner |
| --- | --- |
| `runtime/core.rs` | construction, status, accessors, and telemetry |
| `runtime/application.rs` | opaque application state and filtered availability |
| `runtime/consensus.rs` | local production, fan-out, and consensus stages |
| `runtime/messages.rs` | inbound authentication, validation, and dispatch |
| `runtime/recovery.rs` | certified catch-up, snapshots, and repair |
| `runtime/snapshot.rs` | versioned snapshot decoding and identity checks |
| `runtime/multi_group.rs` | independent group routing |

If a method both validates an inbound message and changes a consensus stage,
keep envelope validation in `messages.rs` and the reusable state transition in
`consensus.rs`. Recovery may call those transitions only after it validates the
certified anchor and suffix.

## Active-active ownership

| File | Owner |
| --- | --- |
| `active_active/model.rs` | commands, references, generations, and milestones |
| `active_active/certificates.rs` | signed and certified evidence |
| `active_active/store.rs` | transactional persistence operations |
| `active_active/engine.rs` | ordering, application, and read barriers |
| `active_active/tracking.rs` | applied-by and cutover/retention decisions |

The engine must not interpret application bytes. New command semantics belong
to the embedding application. Changes to route or command-spec generations
must remain hash-committed in `BatchReference` and atomically activated at a
quiescent application boundary.

## High-availability ownership

| File | Owner |
| --- | --- |
| `high_availability/parameters.rs` | committed parameters and stable slots |
| `high_availability/protocol.rs` | round records, candidates, and epochs |
| `high_availability/rounds.rs` | dispatch through finalization |
| `high_availability/membership.rs` | amendments and slot lifecycle |
| `high_availability/status.rs` | health, topology, and recovery records |
| `high_availability/durable.rs` | state validation and delta persistence |
| `high_availability/transport.rs` | authenticated sessions and bounded I/O |
| `high_availability/engine.rs` | construction, status, snapshots, and compaction |

Durable state advances before a message or completion is exposed. Transport
authentication does not replace protocol validation, and protocol code must
not reach into socket state. Membership transitions occur only through
committed certificates at an empty epoch boundary.

## Benchmark and simulation harness ownership

The benchmark harness uses the same parent-file facade pattern as the product
modules:

| File | Owner |
| --- | --- |
| `blossom_adapter/order_cluster.rs` | verified global-ordering cluster construction, epoch driving, and convergence |
| `blossom_adapter/trusted_cluster.rs` | trusted-consensus cluster orchestration |
| `blossom_adapter/active_cluster.rs` | active-active application and campaign operations |
| `raft_adapter/network.rs` | deterministic OpenRaft RPC transport and injected link behavior |
| `raft_adapter/cluster.rs` | OpenRaft node lifecycle, snapshots, restart, and replication control |
| `raft_adapter/campaign.rs` | fault-plan execution and stable campaign reports |

Keep protocol assertions in the harness even when the product already checks
the same invariant. The harness is a downstream consumer: its checks prove that
the public API carries enough evidence for an application to validate finality,
recovery, and publication without reaching into Blossom internals.

## Tests

Each facade has a `tests.rs` helper module and a `tests/` directory mirroring
the production responsibilities. Put shared fixtures in `tests.rs`; put a test
next to the responsibility whose invariant it protects. Process-spawning tests
that use `--exact` must use the complete nested Rust test path.

Large production modules keep their unit tests in `<module>/tests.rs` instead
of appending a large `mod tests { ... }` block to `<module>.rs`. Small,
tightly-coupled tests may remain inline. This preserves the public parent module
path while keeping substantial test-only fixtures independently navigable.
Binary crate roots use an explicit `#[path]` only when Rust's crate-root lookup
would otherwise make the test filename ambiguous.

Persistence changes need crash/reopen coverage. Protocol changes need both the
positive path and the closest invalid evidence or threshold boundary. Public
API changes need an integration test or compiling example that uses only
public paths.

## Documentation contract

Every public facade and every child file starts with module documentation.
The runtime, active-active, and high-availability facades enable
`warn(missing_docs)` for their complete subtrees; the release rustdoc command
promotes those warnings to errors.
Public APIs should document:

- what the value proves or owns;
- whether input is trusted, verified, or application-defined;
- the durability point at which success is returned;
- replay and idempotency requirements;
- bounds, freshness, and terminal-state behavior;
- feature gates and threat-model limitations.

Update the relevant guide whenever a change affects an operational contract.
Keep examples on public paths so rustdoc and downstream consumers exercise the
same surface.

## Validation

Before committing a structural or documentation change, run:

```sh
cargo fmt --all --check
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace --all-features
```

Protocol, durability, HA, or release changes must also run the relevant
production gate described in [Testing and Validation](testing-and-validation.md).
