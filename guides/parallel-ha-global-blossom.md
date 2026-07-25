# Parallel HA and Global Blossom Networks

HA and Global Blossom solve different availability problems and remain
independent consensus domains.

| Network | Membership | Purpose |
| --- | --- | --- |
| HA | 2–7 fixed replicas per service group | Local durability, failover, and active-active service writes |
| Global Blossom | At least 6 independent Blossom members | Global membership and deterministic ordering across groups |

An installation may run many HA groups alongside one Global Blossom network.
Some physical processes may participate in both, but membership in one network
never creates a vote in the other.

```text
HA group A ── sealed state reference ─┐
HA group B ── sealed state reference ─┼─→ Global Blossom ordered application log
HA group N ── sealed state reference ─┘
```

Enable the application coordination API with:

```toml
[dependencies]
blossom = { version = "2", features = ["parallel-networks"] }
```

## Coordination flow

1. Create an `HaGroupRegistration` from each `HighAvailabilityRuntime`.
2. Submit `ParallelNetworkEvent::RegisterHaGroup` as an ordinary Global
   Blossom DAG payload.
3. After the HA sealed watermark advances, create an
   `HaGroupStateReference` with the application state root.
4. Submit `ParallelNetworkEvent::PublishHaState` through Global Blossom.
5. When Global Blossom returns a finalized checkpoint and its exact ordered
   vertex delta, call `ParallelNetworkCoordinator::apply_global_checkpoint`.

The coordinator checks the Global Blossom checkpoint hash and ordered-delta
commitment, each vertex-to-event payload commitment, HA registration, strict
majority mask, mutable-depth boundary, and the per-group state-reference chain.
Application is transactional: one invalid record rejects the complete
coordination update.

Persist `ParallelNetworkCoordinator::snapshot()` with the service's applied
Global Blossom watermark. On redeploy, restore it with
`ParallelNetworkCoordinator::from_snapshot`; version, canonical ordering,
registration/reference consistency, checkpoint pairing, and the snapshot hash
are validated before state becomes visible.

Only sealed HA state may be exported. The reference includes the HA group,
fixed membership hash, current membership generation and active mask,
parameters hash, sealed epoch and sealing head, confirmation mask, sealed
revision hash, and application state root.

## Isolation guarantees

- HA replicas are never counted as Global Blossom members by the coordination
  API.
- Advancing HA does not advance a Global Blossom checkpoint.
- Applying a Global Blossom checkpoint does not advance or reconfigure HA.
- Loss of HA quorum stops new references from that group but does not alter
  Global Blossom safety.
- Loss of Global Blossom quorum stops new global coordination while each HA
  group can continue its local work.
- Registration and state publication are descriptive. Services perform any
  deployment, routing, notification, or membership action explicitly after
  observing finalized coordination state.

HA group replacement and automatic cross-network membership mutation are not
part of v1. Replacing fixed HA identities requires a separately versioned
registration transition.
