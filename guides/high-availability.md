# Small-Cluster High Availability

The `high-availability` feature is Blossom's trusted active-active protocol for
two through seven fixed node identities. Every active member may write in every
epoch. OpenRaft remains the benchmarked leader-based active-passive option and
is kept outside Blossom core.

Enable the API directly from an application such as `shard-kv` or
`shard-stream`:

```toml
[dependencies]
blossom = { version = "2", features = ["high-availability"] }
```

HA uses fixed member slots sorted by public key, `u8` masks, and fixed arrays.
It does not use hierarchical quorum selection or `BLOSSOM_QUORUM_SIZE`.
An application may also publish sealed HA state references through an
independent Global Blossom network; this does not add HA replicas to Blossom's
membership. See [Parallel HA and Global Blossom Networks](parallel-ha-global-blossom.md).

## Guarantees

| Active members | Strict majority | Inactive tolerated |
| ---: | ---: | ---: |
| 2 | 2 | 0 |
| 3 | 2 | 1 |
| 4 | 3 | 1 |
| 5 | 3 | 2 |
| 6 | 4 | 2 |
| 7 | 4 | 3 |

The isolated HA TCP profile authenticates trusted peers with a shared 256-bit
transport key. Its challenge/response handshake binds the group, fixed genesis
membership, committed HA parameters, client identity, and server identity.
Every request and response is HMAC-SHA-256 authenticated with a derived session
key and strictly increasing sequence number. This rejects unauthenticated
connections, member spoofing, modified frames, and replay without adding
per-message public-key signatures to the trusted hot path. The profile does not
encrypt payloads; deploy it over TLS when confidentiality is required.

The protocol protects correctness under crashes, delay, reordering, and
partitions; it does not protect against malicious trusted members, Sybil
identities, or Byzantine equivocation. Because all members share the transport
key, key distribution and coordinated rotation belong to the deployment
control plane.

## Service replication modes

Node count is a supported topology boundary, not an automatic protocol
selector. Applications explicitly choose:

```rust
enum HaReplicationMode {
    LeaderlessActiveActive,
    MajorityLeaderActivePassive,
}
```

`LeaderlessActiveActive` is implemented by Blossom HA and routes writes to any
active member. `MajorityLeaderActivePassive` routes writes to the current
leader and is implemented by an external Raft driver. Blossom core contains no
OpenRaft dependency.

Use `HaServiceTopology::active_active(member_count)` or
`HaServiceTopology::active_passive(physical_nodes, voting_nodes)` to validate a
2–7 node deployment and expose its write route, majority, and tolerated voter
failures. `HaServiceTopology::assess` combines responsive-voter count with the
external leadership observation into machine-readable readiness and service
directives.

A two-voter topology requires both voters in either mode. If one is lost, the
survivor remains locally readable but rejects new consensus writes and emits
`NotifyOperators`, `NotifyUsers`, `DrainWrites`, and `AwaitQuorum`. Leadership
does not let one of two voters safely distinguish a crashed peer from a
partition. Continuous write availability after one failure therefore requires
at least three voting durability domains.

Each round is:

1. Every active slot dispatches at most one block directly to every peer.
2. Each receiver broadcasts its monotonic received-slot mask.
3. Each member durably locks one available candidate and broadcasts a
   confirmation.
4. A strict majority confirming the same candidate finalizes the epoch.

Genesis hashes the sorted fixed public-key identities. Candidate and epoch
hashes bind that fixed-membership hash, the membership generation, active mask,
previous epoch hash, previous nonce, current nonce, included slots, and block
hashes. Included blocks are ordered by `(block_hash, slot)` with a fixed-array
sort over at most seven entries.

## Mutable application view

Consensus epochs and confirmation locks are immutable. The latest logical
application epochs may receive append-only `AmendmentRecord`s. With the
defaults, epoch `E` remains mutable until six successors confirm; amendments
targeting older epochs return `EpochSealed`.

An amendment is never a side-channel state mutation. Build its committed
transaction with `HighAvailabilityRuntime::amendment_transaction` and include
that transaction in a later dispatch block. Every receiver validates the
target hash, target/containing nonces, origin slot, command identity, and depth
before acknowledging the block. Finalization then imports the same committed
record into every replica's logical replay view.

Applications can consume `StateRevision`, `EpochLifecycle`, and the sealed
watermark directly:

- stream consumers should publish sealed output by default;
- key-value applications may expose versioned provisional state;
- compare-and-swap and strict reads should wait for `Milestone::Sealed`.

Configure the two committed depths at startup:

```text
BLOSSOM_MUTABLE_EPOCH_DEPTH=6
BLOSSOM_UNRESPONSIVE_EPOCH_DEPTH=6
```

CLI values should be passed to
`HighAvailabilityParameters::resolve_startup`; CLI takes precedence over the
environment, then the default of six. Restored runtimes reject parameter or
membership mismatches.

## Responsiveness and membership

Majority-observed dispatch, acknowledgement, or confirmation activity creates
presence for a member. Six consecutive finalized epochs without certified
presence mark it unresponsive. A strict majority may suspend that fixed slot at
an empty epoch boundary, effective for the next epoch. HA never permits fewer
than two active slots, so a two-node cluster stops when either member is
unavailable.

Reactivation requires catch-up through the current head and majority approval.
HA v1 does not add, remove, or replace genesis identities.

Catch-up is application-managed through
`HighAvailabilityRuntime::recovery_snapshot` and
`HighAvailabilityRuntime::install_recovery_snapshot`. A recovery snapshot
contains finalized epochs, amendments, committed HA parameters, presence, and
membership certificates; it excludes transient round state. Installation
requires the local round and membership-vote lock to be empty, preserves local
endpoint and secret material, rejects rollback or a conflicting finalized
prefix, validates the complete chain, and durably stores it before exposing the
new head. Exported member identities are always stripped of secret keys.

Use `vote_to_suspend` or `vote_to_reactivate`, broadcast the returned
`HaMembershipVote`, and pass received votes to `receive_membership_vote`.
Each member durably locks one membership proposal per generation before its
vote is returned. A strict-majority `HaMembershipCertificate` is stored before
the active mask and generation are used by the next epoch.

## Runtime entry points

Use `HighAvailabilityRuntime::new` for an in-memory protocol-core instance or
`HighAvailabilityRuntime::open` for immediate-durability redb state.
`HighAvailabilityTcpNode` serves the isolated authenticated HA wire profile and
reuses persistent outgoing peer connections. Supply the same transport key to
every fixed member:

```rust
use blossom::high_availability::{
    HaTransportKey, HighAvailabilityTcpClient, HighAvailabilityTcpNode,
};

let transport_key = HaTransportKey::from_environment()?;
let client =
    HighAvailabilityTcpClient::for_runtime(&runtime, transport_key.clone());
let node = HighAvailabilityTcpNode::new(runtime, peers, transport_key)?;
```

`BLOSSOM_HA_TRANSPORT_KEY` is exactly 32 bytes encoded as 64 hexadecimal
characters. `HaTransportKey` redacts its `Debug` output. Applications may load
the same bytes from their secret manager and call `HaTransportKey::new`
directly instead of using an environment variable.

The normal message flow uses:

```text
build_dispatch / receive_dispatch
    -> acknowledge / receive_acknowledgement
    -> confirm / receive_confirmation
```

Every mutating durable-runtime call persists before returning. In particular,
`confirm` persists the member's one-candidate lock before the caller can
broadcast it. Confirmation is idempotent: after a crash in that interval,
calling `confirm` reconstructs and returns the exact locked confirmation for
retransmission.

## Service health and recovery integration

Applications do not need to infer lifecycle actions from protocol internals.
`HaNodeStatus::operational_status` returns a machine-readable
`HaOperationalStatus` with:

- `Ready`, `Degraded`, `Unavailable`, or `Suspended` health;
- current and required responsive-node counts;
- write and local-read readiness;
- the strict-read sealed watermark;
- directives such as `NotifyOperators`, `NotifyUsers`, `DrainWrites`,
  `AwaitQuorum`, `FetchRecoverySnapshot`, `RestartOrRedeploy`, and
  `AwaitReactivation`.

Persist the previous `HaNodeStatus` and call `operational_events_since` after
each status observation to produce structured head, sealed-watermark,
membership, node-availability, health, and state-revision transitions. These
events are suitable inputs for service supervisors, health endpoints, alerting,
deployment automation, and user-facing incident notifications.

Epoch presence cannot detect a partition until another epoch finalizes.
Therefore every dispatch, acknowledgement, and confirmation broadcast also
returns `HaBroadcastReport`. Call `HaBroadcastReport::assess(active_nodes)` or
`HighAvailabilityTcpNode::assess_broadcast` to detect immediate reachability
loss. A subquorum result includes `NotifyUsers`, `DrainWrites`, and
`AwaitQuorum`; a quorum-preserving partial failure remains writable but
degraded.

Before accepting a recovered or redeployed peer, compare status with
`HaNodeStatus::assess_peer` or
`HighAvailabilityRuntime::assess_peer_status`. The result distinguishes
compatible, locally behind, peer behind, divergent, and incompatible states.
Divergent or incompatible peers are explicitly quarantined. A fresh or lagging
instance is directed to fetch and install a recovery snapshot before resuming.

These directives describe required actions; Blossom deliberately does not call
a particular paging, deployment, or user-notification provider. Integrating
services map them onto their own control plane.

Protocol operations return `BlossomError`. Pass an error to
`assess_high_availability_failure` to obtain a machine-readable
`HaFailureAssessment`. Durable-store I/O failures are classified
`DurabilityUnavailable`, disable in-process retry, and direct the service to
notify operators and users, drain writes, and restart or redeploy. This is
intentional: redb requires the failed database handle to be closed and reopened
after an I/O error. Authentication failures direct the service to quarantine
the peer.

## Production fault gate

Run the HA-specific production gate before shipping a protocol or storage
change:

```bash
./scripts/ha-production-validation.sh
```

The gate includes:

- all HA unit, TCP, and Hegel state-machine/property tests;
- authenticated-session spoof, wrong-key, raw-client, frame-integrity, and
  replay rejection;
- an authenticated subprocess SIGKILL/reopen/reconnect check with durable
  mid-epoch state;
- deterministic `redb::StorageBackend` ENOSPC and fsync failure injection,
  volatile-write loss, in-memory rollback, and recovery from the last durable
  commit;
- the formal strict-majority checks for every supported size;
- a 1,001-epoch immediate-durability soak with repeated reopen and snapshot
  recovery;
- three deterministic 1,200-epoch campaigns for every cluster size from two
  through seven;
- transient asymmetric loss, duplicate and reordered delivery, all tolerated
  boundary crash counts, minority isolation, suspension/reactivation,
  redeployment, mutable amendments, corrupted recovery snapshots, and an
  explicit below-quorum no-progress probe.

Each chaos artifact contains the seed, complete epoch/fault trace, final
watermarks and hashes, recovery counts, expected and unexpected stalls, and
safety violations. A fixed seed is exactly replayable because simulations use
`HighAvailabilityRuntime::build_dispatch_at` to remove wall-clock timestamps
from protocol input.

The repository's `HA Merge Gate / Release and HA production gate` check runs
this gate for every pull request and push to `main`; configure branch protection
to require that exact check before merging.

This gate is necessary, not sufficient, for a production rollout. It now
exercises the authenticated wire profile, real subprocess kill/restart, and
deterministic failures at redb's storage boundary. Deployment qualification
must additionally run on the target filesystems and at least two physical
hosts, exercise infrastructure-level power loss and capacity exhaustion, and
verify the service's concrete alerting and redeployment integrations. The
current Kani, Quint, and Apalache models prove threshold and quorum-intersection
properties; they are not a full formal proof of every HA state transition.

## Head-to-head smoke benchmark

Run the protocol-core comparison for every physical footprint from two through
seven:

```bash
./benchmarks/scripts/run-ha-head-to-head.sh
```

Run all supported footprints with twelve paired AB/BA repetitions in both the
in-memory and immediate-durability profiles:

```bash
./benchmarks/scripts/run-ha-head-to-head-full.sh
```

Blossom runs one writer per node. Raft uses 2, 3, 5, or 7 voters and learners
for even footprints. The JSON artifact records Dispatch, Available, Finalized,
Applied, and optional Sealed latency separately and is deliberately marked
non-publishable until the full repetition, steady-state, fault, restart, and
confidence-interval gates are satisfied.

Set `DURABLE=1` to give both protocols immediate-durability redb stores. Set
`WAIT_FOR_SEAL=1` independently to include sealed-visibility latency.
