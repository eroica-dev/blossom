# blossom-observer

Telemetry collection and offline analysis for distributed Blossom runs.

The library ingests Blossom JSONL telemetry and produces aggregate node, stage,
error, span, membership, and block-transfer statistics. The bundled
`blossom-observer` binary can collect events over TCP, serve a small local
dashboard, persist JSONL, or analyze an existing capture.

```sh
cargo install blossom-observer --version 2.0.0
blossom-observer serve --bind 127.0.0.1:7717
blossom-observer analyze --input blossom-events.jsonl
```

The observer is an operational aid, not a consensus participant or security
boundary. Rust 1.93 is required. See the
[Blossom repository](https://github.com/d-tietjen/blossom) for telemetry and
deployment guidance.
