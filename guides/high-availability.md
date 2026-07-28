# Small-Cluster High Availability

Blossom ships two native small-cluster HA engines:

- `high-availability` enables the trusted leaderless active-active protocol for
  two through seven fixed node identities. Every active member may write in
  every epoch.
- `active-passive` enables the native OpenRaft leader-based runtime. One leader
  accepts writes while followers and learners replicate the committed log.

Enable the API directly from an application such as `shard-kv` or
`shard-stream`:

```toml
[dependencies]
blossom = { package = "blossom-consensus", version = "2", features = ["high-availability"] }
```

Use `features = ["active-passive"]` for OpenRaft active-passive; it enables the
shared HA topology API automatically.

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
encrypt payloads. Because the key is shared, a compromised trusted member can
claim another member identity. Deploy over key-bound mTLS when confidentiality
or Byzantine member impersonation is in scope.

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
leader and is implemented by `ActivePassiveRuntime` using OpenRaft.

Use `HaServiceTopology::active_active(member_count)` or
`HaServiceTopology::active_passive(physical_nodes, voting_nodes)` to validate a
2–7 node deployment and expose its write route, majority, and tolerated voter
failures. `HaServiceTopology::assess` combines responsive-voter count with the
engine's leadership observation into machine-readable readiness and service
directives.

A two-voter topology requires both voters in either mode. If one is lost, the
survivor remains locally readable but rejects new consensus writes and emits
`NotifyOperators`, `NotifyUsers`, `DrainWrites`, and `AwaitQuorum`. Leadership
does not let one of two voters safely distinguish a crashed peer from a
partition. Continuous write availability after one failure therefore requires
at least three voting durability domains.

## Native active-passive runtime

`ActivePassiveRuntime` owns an OpenRaft node and exposes initialization,
opaque client writes, linearizable-read barriers, learner catch-up, voter
replacement, metrics, status, and shutdown. Blossom also ships
`ShardStreamRaftLogStore`, an OpenRaft v2 adapter over `BlossomLogStore` and
its embedded ShardLog. Open
it with `open_bound` so the store directory is permanently bound to the
configured cluster name and node ID.

The embedding service supplies two application-specific pieces required by
OpenRaft:

- a `RaftNetworkFactory<ActivePassiveRaftConfig>` that sends vote,
  append-entries, and snapshot RPCs over the service's authenticated transport;
- a `RaftStateMachine<ActivePassiveRaftConfig>` that atomically persists the
  applied log ID, membership, application mutation, result, deduplication
  record, and active application contract.

This is an application boundary, not an external consensus driver: elections,
log replication, joint-consensus membership changes, snapshots, failover, and
linearizable read authority run inside Blossom's pinned OpenRaft runtime.
Blossom re-exports its pinned `openraft` crate from
`blossom::active_passive::openraft` so implementations cannot accidentally
compile against incompatible trait versions.

Each state machine starts with an `ActivePassiveContract` and applies
`ActivePassiveRequest` records in log order. A `Command` must match the route
generation and command-spec version active at that exact log position.
`ActivateContract` atomically advances both fences. Commands and results remain
opaque application bytes, and retry safety is keyed by `CommandIdentity`.
Snapshots must contain the application data, membership, contract, applied
watermark, and deduplication results together.

For reads, call `ensure_linearizable` on the leader before reading the
application state machine. A follower may serve an explicitly stale/local read
but cannot manufacture a fresh read barrier. Failed leader writes and reads
return OpenRaft forward-to-leader or quorum errors.

Membership replacement is:

1. Add the new node with `add_learner(..., true)` and let it catch up.
2. Call `replace_voters` with the complete replacement voter set.
3. Remove or retain displaced voters as learners according to deployment
   policy.

The facade requires the replacement set to preserve the topology's declared
voter count and prevents learners from exceeding its physical-node count.
Use a deliberate cluster migration to resize the topology.

OpenRaft does not authenticate or encrypt application transports. Production
network implementations must use key-bound mTLS or an equivalent mutually
authenticated channel and enforce connect, request, idle, concurrency, and
payload limits. The in-memory log store and in-process test network are for
tests only.

## Native active-active runtime

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
- compare-and-swap and strict reads should call `require_sealed` (or compare
  against `sealed_watermark`) before exposing a provisional HA result. `Sealed`
  is an HA epoch lifecycle boundary, not a global-order `Milestone`.

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
The membership proposal commits the exact head hash and `StateRevision`, not
only its nonce, so a vote for one recovered state cannot authorize another. HA
v1 does not add, remove, or replace genesis identities.

Catch-up is application-managed through
`HighAvailabilityRuntime::recovery_snapshot` and
`HighAvailabilityRuntime::install_recovery_snapshot`. A recovery snapshot
contains finalized epochs, amendments, committed HA parameters, presence, and
membership certificates; it excludes transient round state. Installation
requires the local round and membership-vote lock to be empty, preserves the
local endpoint, rejects rollback or a conflicting finalized prefix, validates
the complete chain, and durably stores it before exposing the new head.
Exported and durable member identities are always public-only.

Long-running clusters should periodically call
`compact_history_through(sealed_nonce)`. It creates a majority-certified
`HaHistoryCheckpoint`, retains that sealed epoch as the recovery anchor,
summarizes older membership, presence, and amendment history into a cumulative
revision, and removes the summarized prefix without changing `StateRevision`.
Recovery snapshots carry the checkpoint and validate it before a learner
accepts the retained suffix. `history_checkpoint` and `retained_epoch_count`
expose compaction status.

Use `vote_to_suspend` or `vote_to_reactivate`, broadcast the returned
`HaMembershipVote`, and pass received votes to `receive_membership_vote`.
Each member durably locks one membership proposal per generation before its
vote is returned. A strict-majority `HaMembershipCertificate` is stored before
the active mask and generation are used by the next epoch.

Applications that want one service-level facade can wrap the runtime in
`ActiveActiveHaEngine`. It exposes recovery status and hash-committed recovery
manifests, installs learner catch-up snapshots, delegates reactivation votes,
and makes application-contract cutover explicit. `begin_cutover` performs a
route-only transition. `begin_application_cutover` atomically commits both the
next route generation and next command-spec version. Before activation, every
locally accepted write from the old contract must be recertified, translated
and rehashed with `recertify_accepted_as`, or explicitly aborted. The manifest
commits those resolutions together with both application generations, the HA
membership generation, and the active mask, so neither a membership change nor
a decoder upgrade can silently reinterpret or discard accepted work. New
command identities are rejected while a cutover is active; idempotent retries
of already accepted identities remain available.

Production services must open both durable layers on distinct redb files:
`HighAvailabilityRuntime::open` for protocol state and
`ActiveActiveHaEngine::open` for accepted writes, application-contract state,
and cutover progress. Every active-active lifecycle mutation is committed with
immediate durability before it returns. `ActiveActiveHaEngine::new` remains the
in-memory simulation and test constructor. `recovery_status` exposes both
durability flags, and `is_production_durable` requires both stores. Because the
lifecycle file contains opaque application commands, Unix deployments reject
files with group or other permissions; create and retain it as an owner-only
regular file.

If HA membership changes after a cutover is prepared, activation fails closed
because the membership generation and active mask no longer match. Call
`cancel_application_cutover` to durably return its accepted-write resolutions
to `Pending`, then begin and resolve a new cutover against current membership.

Cutover and recovery manifests use format version 2 and reject version-1
payloads. Accepted lifecycle state is bounded to 4,096 writes and 64 MiB of
original plus translated command bytes.

Durable runtime state uses an explicit format-v1 envelope in
`ha_runtime_state_v1`. Unversioned development state from before 2.0.0 is a
deliberate reset boundary rather than a supported migration: create a new store
directory, install a certified recovery snapshot from a current peer, and
securely remove the old file. A legacy database file fails closed and is never
overwritten. This avoids copying legacy secrets forward.

## Runtime entry points

Use `HighAvailabilityRuntime::new` for an in-memory protocol-core instance or
`HighAvailabilityRuntime::open` for embedded ShardLog durability.
`HighAvailabilityTcpNode` serves the isolated authenticated HA wire profile and
reuses persistent outgoing peer connections. Supply the same transport key to
every fixed member:

```rust
use blossom::high_availability::{
    HaNetworkLimits, HaTransportKey, HighAvailabilityTcpClient,
    HighAvailabilityTcpNode,
};

let transport_key = HaTransportKey::from_environment()?;
let limits = HaNetworkLimits::default();
let client = HighAvailabilityTcpClient::for_runtime_with_limits(
    &runtime,
    transport_key.clone(),
    limits,
)?;
let node =
    HighAvailabilityTcpNode::new_with_limits(runtime, peers, transport_key, limits)?;
```

`BLOSSOM_HA_TRANSPORT_KEY` is exactly 32 bytes encoded as 64 hexadecimal
characters. `HaTransportKey` redacts its `Debug` output. Applications may load
the same bytes from their secret manager and call `HaTransportKey::new`
directly instead of using an environment variable.

`HaNetworkLimits` applies positive connect, per-request, and idle deadlines plus
a server connection/concurrency ceiling. A blackholed peer therefore returns a
failed broadcast result instead of stalling the round driver indefinitely.
Wire frames remain subject to Blossom's fixed maximum payload. Rate limiting,
encryption, and per-node certificate authentication belong to the deployment
transport or private mTLS sidecar.

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
intentional: the LogStore is poisoned after an ambiguous storage failure and
must be closed and reopened before further writes. Authentication failures
direct the service to quarantine the peer.

## Production fault gate

Run the HA-specific production gate before shipping a protocol or storage
change:

```bash
./scripts/ha-production-validation.sh
```

The gate includes:

- all HA unit, TCP, and Hegel state-machine/property tests;
- durable active-active acceptance, command translation, cutover cancellation,
  restart, format-version, and resource-bound tests;
- authenticated-session spoof, wrong-key, raw-client, frame-integrity, and
  replay rejection;
- an authenticated subprocess SIGKILL/reopen/reconnect check with durable
  mid-epoch state;
- deterministic ENOSPC and fsync failure injection, volatile-write loss,
  in-memory rollback, and recovery from the last durable commit;
- the formal strict-majority checks for every supported size;
- a 1,001-epoch immediate-durability soak with repeated reopen and snapshot
  recovery.

The authoritative deterministic fault campaigns are owned by the separate
`deterministic-simulation` repository. Its pinned Blossom adapter and
`blossom-protocol-{pr,nightly,release}` profiles cover:

- deterministic campaigns for every cluster size from two through seven;
- transient asymmetric loss, duplicate and reordered delivery, all tolerated
  boundary crash counts, minority isolation, suspension/reactivation,
  redeployment, mutable amendments, corrupted recovery snapshots, and an
  explicit below-quorum no-progress probe.

Each chaos artifact contains the seed, complete epoch/fault trace, final
watermarks and hashes, recovery counts, expected and unexpected stalls, and
safety violations. A fixed seed is exactly replayable because simulations use
`HighAvailabilityRuntime::build_dispatch_at` to remove wall-clock timestamps
from protocol input.

The Blossom repository's `HA Merge Gate / Release and HA production gate`
check runs the local gate for every pull request and push to `main`. The
deterministic-simulation repository runs its pinned Blossom PR campaign in CI
and its longer profile on releases. Production qualification requires both
repositories to pin each other's reviewed revisions and both required checks
to pass; neither checkout silently substitutes the other's gate.

This gate is necessary, not sufficient, for a production rollout. It now
exercises the authenticated wire profile, real subprocess kill/restart, and
deterministic failures at the embedded storage boundary. Deployment qualification
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

Set `DURABLE=1` to give both protocols embedded ShardLog stores. Set
`WAIT_FOR_SEAL=1` independently to include sealed-visibility latency.
