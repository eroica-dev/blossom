# Security Policy

Blossom is pre-release consensus infrastructure. It has not received an
independent production security audit. Do not use the public issue tracker for
private vulnerability reports.

## Supported versions

Until the first crates.io release, only the current `main` branch receives
security fixes. After release, the latest 2.x release line will receive fixes;
older pre-release commits and unpublished snapshots are unsupported.

## Reporting

Open a private draft advisory through the repository's **Security →
Advisories → New draft security advisory** flow. If that channel is
unavailable, contact the published package maintainer privately. Do not include
secrets, production data, or exploit details in a public issue.

Include:

- the affected commit, feature set, and deployment profile;
- the expected invariant and observed behavior;
- a minimal reproduction or deterministic trace when possible;
- whether confidentiality, integrity, availability, or consensus safety is
  affected;
- any known workaround or evidence of active exploitation.

Maintainers will acknowledge the report, reproduce it privately, coordinate a
fix and disclosure window, and credit the reporter unless anonymity is
requested. No response-time guarantee is offered before the project has a
staffed security rotation.

## Security boundaries

The verified Global Blossom profile checks signatures and quorum certificates
under the threat model documented in the protocol guide and whitepaper. The
native active-active HA profile is an authenticated crash-fault protocol for
fixed, trusted members; it is not Byzantine consensus. Native active-passive
uses OpenRaft for majority leadership, but the embedding application still owns
authenticated and encrypted Raft transport plus its application state machine.

`insecure-fast-hash` deliberately weakens protocol commitments and is never
appropriate for an untrusted deployment. Trusted mode, shared-key HA transport,
and development-only sidecars must be evaluated against the deployment's
compromise model. Telemetry sinks and application command/result bytes may
contain operationally sensitive data even though Blossom does not interpret
them.

Signing keys are memory-only protocol inputs. Blossom's snapshots, wire
records, durable LogStore identities, debug formatting, and HA state must
contain public identities only. Treat any persisted private signing material as
a vulnerability.

## Production prerequisites

Before exposing Blossom outside a controlled network, deployments need:

- per-peer authenticated encryption such as mTLS or Noise/QUIC;
- isolated signing-key storage and rotation procedures;
- bounded connections, requests, payloads, and retry rates;
- monitored durability, quorum, membership-freshness, and recovery signals;
- tested backup, checkpoint, catch-up, and fail-closed procedures;
- independent review of the selected protocol profile and application
  integration.

See [Operations](guides/operations.md), [Verified Membership and
Discovery](guides/verified-membership-and-discovery.md), and [Small-Cluster High
Availability](guides/high-availability.md) for the corresponding deployment
contracts.
