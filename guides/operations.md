# Operations

## Runtime Persistence

`blossom-node` supports committed runtime snapshots and durable verified block
storage:

- `BLOSSOM_STATE_SNAPSHOT`
- `BLOSSOM_BLOCK_STORE`
- `BLOSSOM_BOOTSTRAP_SERVICES`

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

Before public trustless deployment, operators should add deployment-specific key
management, monitoring, alerting, public-join abuse controls, and multi-host
soak testing.
