# Releasing Blossom

This repository is prepared for the `blossom-consensus` 2.0.0 release.

## Preconditions

- Use Rust 1.93 from `rust-toolchain.toml`.
- Work from a clean `main` whose commit is pushed and reproducible.
- Make the source repository public before publishing so Cargo metadata,
  documentation links, security reporting, and source provenance are usable.
- Confirm crates.io access for `blossom-consensus`.
- Confirm the authoritative Blossom campaigns pass at the pinned revision in
  `eden-dev-inc/deterministic-simulation`.
- Run `scripts/release-gate.sh` and retain `target/release-gate/`.
- Review `CHANGELOG.md`, package contents, normalized manifests, and generated
  rustdoc.
- Confirm the code-organization guide still matches the public facade and child
  module layout.

## Dependency order

Publish in this order because crates.io verifies registry dependencies rather
than workspace or Git sources:

1. `shardlog` 0.1.0 from `d-tietjen/shard-stream` commit
   `03ef769a46d574622a838fca7b4884a93ba24177`;
2. `blossom-consensus` 2.0.0.

ShardLog's own package, deployment, and rollback procedure lives in
`docs/SHARDLOG.md` in the shard-stream repository. Do not substitute
`shard-stream-core` or `shard-stream-storage` as public dependencies.

After confirming that `shardlog` 0.1.0 resolves from crates.io, run:

```sh
scripts/package-release.sh
```

This verifies the single public Blossom archive. Propagation policies are
modules within `blossom-consensus` and are selected with the
`propagation-push`, `propagation-inventory`, and `propagation-adaptive`
features. The observer and benchmark harness remain non-publishable workspace
tools. The script only invokes `cargo package`; it never invokes
`cargo publish`.

## Consumer dependency

The package name avoids the unrelated crates.io package named `blossom`.
Consumers retain the expected Rust crate name with a dependency alias:

```toml
[dependencies]
blossom = { package = "blossom-consensus", version = "2.0.0" }
```

## Publishing and tagging

Publishing is a separate, deliberate operator action after the prepared history
and package archives have been approved. Publish one package at a time in the
dependency order, verify it on crates.io and docs.rs, then continue.

Only after the exact release commit is final:

1. create a signed `v2.0.0` tag;
2. push the tag;
3. attach the changelog and validation evidence to the GitHub release;
4. verify a fresh consumer project can resolve the dependency alias, compile
   default features, and compile the selected HA profiles.

If any package is wrong, do not reuse the version. Yank it, fix forward with a
new patch release, and retain the original source and validation evidence.
