# Security Policy

This project is experimental. It implements SAML 2.0 **Service Provider** and
**Identity Provider** flows, and XML cryptography (signature verification,
encryption, C14N) is delegated to `bergshamra` behind the default
`crypto-bergshamra` feature. Do not use `saml-rs` for production
authentication until it is explicitly documented as stable.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub Security
Advisories for this repository once enabled. Until then, open a minimal public
issue that does not include exploit details and ask for a private disclosure
channel.

## Scope

Security-sensitive behavior includes SAML signature verification,
signed-reference selection, replay/audience checks, destination/recipient
validation, assertion decryption, XML parsing limits, and template escaping.

Security fixes should include regression tests and should fail closed with
explicit `SamlError` variants where practical.
