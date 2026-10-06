# Security policy

`saml-rs` implements SAML 2.0 Service Provider and Identity Provider flows.
XML cryptography (signature verification, encryption, C14N) is delegated to
`bergshamra` behind the default `crypto-bergshamra` feature.

## How to report a vulnerability

Report a suspected vulnerability in private.

1. Use GitHub Security Advisories for this repository when that channel is
   enabled.
2. Until then, open a minimal public issue that does not include exploit
   details, and ask for a private disclosure channel.

## Scope

Security-sensitive behaviour covers:

- SAML signature verification and signed-reference selection
- replay and audience checks
- destination and recipient validation
- assertion decryption
- XML parsing limits
- template escaping

How a fix for one of these is tested is in
[Contributing](CONTRIBUTING.md#how-to-change-saml-behaviour).
