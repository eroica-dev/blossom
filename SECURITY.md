# Security Policy

Blossom is experimental protocol software. Please do not use the public issue
tracker for private vulnerability reports.

To report a vulnerability, contact the maintainers privately through the
repository's security advisory channel or the published maintainer contact for
the project. Include a concise description, affected commit or release, and a
minimal reproduction when possible.

Security-sensitive areas include consensus safety, Byzantine fault handling,
wire decoding, admission/reconnection logic, telemetry exposure, and any mode
that weakens cryptographic checks such as `--trusted` or
`insecure-fast-hash`.
