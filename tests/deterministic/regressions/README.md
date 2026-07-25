# Deterministic regression corpus

Only minimized scenarios that reproduce a protocol or sandbox defect belong in
this directory. Generated full traces, client histories, state digests, and
campaign summaries remain under `target/deterministic-sandbox/` and must not be
committed.

Every regression scenario must include the failed property name, original seed,
protocol/topology, and replay command. A regression is removable only when its
behavior is made impossible by a deliberate protocol-version change.
