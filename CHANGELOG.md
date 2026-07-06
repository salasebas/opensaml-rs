# Changelog

All notable changes to `saml-rs` are documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning while the API is still pre-1.0.

Entries before the rebrand use the package names that were current at the time.

## Unreleased

### Changed

- Renamed the primary package from `opensaml` to `saml-rs`; Rust imports now use
  `saml_rs`.
- Moved implementation code from `crates/opensaml/src` to `src`.
- Renamed `OpenSamlError` to `SamlError`.
- Retired alias crates from active publication; do not yank existing healthy
  alias versions.
- Added typed config builders and direction-specific AuthnRequest policy names;
  builders use strict defaults while constructors/default policy values preserve
  compatibility, and final config validation now covers policy requirements.
- Hardened detailed metadata signature verification so signed metadata evidence
  is exposed through accessors, default-limit detailed wrappers are available,
  and unsafe metadata reference transforms such as XPath/XSLT fail closed before
  descriptor coverage is accepted.

## [0.1.4] - 2026-06-21

### Changed

- Updated `quick-xml` from 0.37.5 to 0.40.1, `time` from 0.3.47 to
  0.3.49, and `uuid` from 1.23.2 to 1.23.3.
- Pinned GitHub Actions workflow dependencies to immutable commit SHAs and
  disabled checkout credential persistence.
- Added Dependabot cooldown windows for Cargo and GitHub Actions updates.

### Fixed

- Adapted the internal XML DOM parser to `quick-xml` 0.40 text/reference
  events so predefined and numeric XML entities in element text are preserved.
- Removed the auto-label workflow that used `pull_request_target`, clearing the
  remaining high-severity `zizmor` trigger finding.

## [0.1.3] - 2026-06-20

### Changed

- Updated `bergshamra` from 0.4.0 to 0.5.1.
- Re-audited the XML security trust-model comment against `bergshamra` 0.5.1
  secure `DsigContext::new()` defaults.
- XSW coverage includes duplicate SAML assertion IDs.

### Fixed

- Reject duplicate SAML `ID`/`AssertionID` values before trusting an XML-DSig
  verification result.

## [0.1.2] - 2026-06-14

### Changed

- Alias crate READMEs and crate descriptions simplified.
- Workspace version bump to 0.1.2 (packaging-only for alias crates).

## [0.1.1] - 2026-06-02

### Added

- `create_logout_request_with_id` / `create_logout_response_with_id` — optional
  caller-provided `LogoutRequest` / `LogoutResponse` IDs.

### Changed

- Root `README.md` rewrite: Rust-only positioning, opensaml vs samael
  comparison, and sectioned quick-start examples; `opensaml` on crates.io now
  uses that README.
- The published crate ships its `tests/` and `examples/` (packaging only; the
  consumed library is unchanged).

### Fixed

- XML-escape `Location` attribute values in generated SP/IdP metadata.

## [0.1.0] - 2026-06-01

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
- `crypto-bergshamra` feature delegating XML cryptography to
  `bergshamra` (**on by default**): key/certificate loading, XML-DSig signing
  and verification with anti-wrapping (XSW) protection, XML-Enc assertion
  encrypt/decrypt, and detached redirect/SimpleSign message signatures.
- `samlify` crate forwards the `crypto-bergshamra` feature.
- Customization to parity with samlify: a `User` subject with attributes wired
  into `IdentityProvider::create_login_response` (via `LoginResponseTemplate`),
  a `customTagReplacement` hook and custom message templates, `SignatureConfig`
  (signature prefix + placement), configurable `transformationAlgorithms`, a
  configurable encrypted-assertion tag prefix, and `SessionIndex` on logout.
- `Metadata::export_metadata` / `get_support_bindings` and `util::verify_fields`.
- Inline-certificate-vs-metadata mismatch is rejected with
  `OpenSamlError::UnmatchCertificate` (samlify rolling-cert safety).
- Conformance test suite ported 1:1 from samlify v2.10.2: all 131 active
  upstream cases (flow 64, index 47, issues 11, extractor 9) reproduced as 132
  Rust tests in `tests/{extractor,issues,index,flow}_conformance.rs`, with the
  upstream key/metadata fixtures. The crate runs 206 tests in total (89 without
  `crypto-bergshamra`); the whole suite passes.
- Security hardening: `<Audience>` restriction validation (`validate_audience`,
  on by default → `UnmatchAudience`), `InResponseTo` binding via
  `ServiceProvider::parse_login_response_with_request_id` (→ `InvalidInResponseTo`),
  metadata signature verification (`crypto::verify_metadata_signature` /
  `Metadata::verify_signature`), and XSW + robustness test suites
  (`tests/{xsw,hardening,robustness}.rs`). Schema validation remains pluggable
  via `context::set_schema_validator` on top of the always-on DOCTYPE rejection.
- Runnable end-to-end example: `cargo run -p opensaml --example sso`.
- Crypto-backend audit (bergshamra 0.4.0): documented the verification trust
  model in `crypto::verify` (signature, digest and XSW position checks always
  run; `insecure` only skips X.509 *chain* validation, irrelevant to the
  metadata key-pinning model; `trusted_keys_only` never imports inline key
  material). Hardening: signed `<Reference>` URIs must be same-document
  (`#id` or whole-document); external/remote/file references are rejected
  (`ERR_EXTERNAL_REFERENCE`).

### Changed

- `crypto-bergshamra` is now enabled by default; disable with
  `default-features = false` for the crypto-free protocol layer (operations
  requiring signing, verification or encryption then fail closed with
  `OpenSamlError::Unsupported`).
- Reworked the crate from SP-only stubs to full SP + IdP.
- Signature verification tries each metadata-declared certificate individually,
  so signatures verify against any current key (rolling-certificate support).
- When encrypting, the IdP always signs the message *after* encryption (sound
  encrypt-then-sign); signing the message then encrypting a sub-element would
  invalidate the outer signature.

### Fixed

- Decryption strips a leading XML declaration from the recovered assertion so
  it can be re-parsed in place during the inbound flow.
