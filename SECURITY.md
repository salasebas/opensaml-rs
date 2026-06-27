# Security Policy

This project is experimental. It implements SAML 2.0 **Service Provider** and
**Identity Provider** flows, and XML cryptography (signature verification,
encryption, C14N) is delegated to `bergshamra` behind the default
`crypto-bergshamra` feature. Do not use it for production authentication until
the relevant crate is explicitly documented as stable.

This is an independent, unofficial project. It is not affiliated with,
maintained by, endorsed by, or sponsored by the npm `samlify` package or its
authors.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub Security
Advisories for this repository once enabled. Until then, open a minimal public
issue that does not include exploit details and ask for a private disclosure
channel.

## Scope

Security-sensitive behavior (signature verification, replay/audience checks,
assertion decryption) should be ported with tests and reviewed against the
pinned upstream snapshot in `reference/upstream-samlify/VERSION.md` and the
local clone under `reference/upstream-samlify/<version>/repository/` (see
`./scripts/fetch-upstream-samlify.sh`).
