# Changelog

All notable changes to the opensaml-rs workspace are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

## Unreleased

### Added

- SAML 2.0 protocol layer to parity with npm `samlify` v2.10.2:
  - Constants (URNs, bindings, status codes, algorithms, NameID formats).
  - XML field extraction engine over `quick-xml` (`local-name()` XPath subset)
    with DOCTYPE hardening, plus the samlify field-sets.
  - Default message templates and tag substitution.
  - Service Provider and Identity Provider metadata parsing and generation.
  - HTTP-POST, HTTP-Redirect and HTTP-POST-SimpleSign message building.
  - `ServiceProvider`/`IdentityProvider` entities, login request/response
    creation and parsing, Single Logout, and the inbound `flow` orchestration
    (status, issuer and time validation).
- Optional `crypto-bergshamra` feature delegating XML cryptography to
  `bergshamra`: key/certificate loading, XML-DSig signing and verification with
  anti-wrapping (XSW) protection, XML-Enc assertion encrypt/decrypt, and
  detached redirect/SimpleSign message signatures.
- `samlify` crate forwards the `crypto-bergshamra` feature.

### Changed

- Reworked the crate from SP-only stubs to full SP + IdP. Without
  `crypto-bergshamra`, operations requiring signing, verification or encryption
  fail closed with `OpenSamlError::Unsupported`.
