# Operations

## Runtime Persistence

`blossom-node` supports committed runtime snapshots, an append-only verified
epoch-certificate log, and durable verified block storage:

- `BLOSSOM_STATE_SNAPSHOT`
- `BLOSSOM_CERTIFIED_EPOCH_LOG`
- `BLOSSOM_BLOCK_STORE`
- `BLOSSOM_BOOTSTRAP_SERVICES`

Verified production nodes should configure `BLOSSOM_CERTIFIED_EPOCH_LOG`. Each
commit then synchronizes only the new certified epoch through ShardLog; the
JSON snapshot remains a compatibility checkpoint and is no longer rewritten
in proportion to complete chain history. Startup validates and replays the
certificate log from its genesis identity.

The node can sync bootstrap address-book metadata, but reachability metadata
does not change validator membership.

## TCP Wire Surface

The TCP server accepts one length-prefixed request frame per connection:

```text
u32 big-endian payload length
Borsh-encoded WireRequest
```

Responses use the same frame shape with `WireResponse`.

Important requests include `Health`, `Ping`, `State`, `EpochChain`,
`CertifiedEpochSuffix`, `AddressBook`, `RegisterService`, `Group`, `NextNonce`,
`SubmitBlock`, `Dispatch`, `PrefillDispatch`, `Message`, `SendNonce`,
`BlockNonce`, `GetBlock`, and `SendBlock`. Verified catch-up uses only the
anchor-bound, certificate-validated `CertifiedEpochSuffix`; the weaker
`EpochChainRange` protocol is not retained.

## Telemetry

`TelemetrySink` implementations emit stage progress, spans, dropped-node events,
reconnect events, block-flow metrics, and errors. `blossom-observer` collects
JSONL telemetry and analyzes distributed health across nodes.

Production services can enable the `observability` feature to fan the same
events into bounded `fast-telemetry` metrics/spans and structured
`eden-logger` records. The service owns exporter and global logger
initialization. See [Observability](observability.md) for setup and signal
coverage.

## Production Notes

Request-driven TCP deployments can set `require_local_pending_block` to avoid
initiating empty epochs. The same driver still handles certified epoch
announcement and catch-up after a commit, on a state-changing protocol wakeup,
while a failed announcement remains retryable, or while an authenticated
newer-head hint still needs catch-up. Those recovery-only ticks do not enter
dispatch and therefore cannot create another epoch.

Before public trustless deployment, operators should add deployment-specific key
management, monitoring, alerting, public-join abuse controls, and multi-host
soak testing.
