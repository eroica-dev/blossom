# blossom-propagation

Feature-gated data-plane propagation policy primitives for Blossom.

This crate models latency-first full-push delivery, bandwidth-aware inventory
delivery, and adaptive selection between them. It keeps payload-routing policy
separate from consensus and validates the authentication, redundancy, quorum,
and Byzantine-withholding constraints required by trustless operation.

Most applications should enable propagation through `blossom-consensus`
features. Use this crate directly when implementing or testing a custom
transport planner.

```toml
[dependencies]
blossom-propagation = { version = "2.0.0", features = ["adaptive"] }
```

Rust 1.93 is required. See the
[Blossom repository](https://github.com/d-tietjen/blossom) for protocol
documentation and security guidance.
