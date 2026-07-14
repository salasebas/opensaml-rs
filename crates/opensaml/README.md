# opensaml

[![crates.io](https://img.shields.io/crates/v/opensaml.svg)](https://crates.io/crates/opensaml)
[![docs.rs](https://img.shields.io/docsrs/opensaml)](https://docs.rs/opensaml)
[![MIT licensed](https://img.shields.io/crates/l/opensaml)](https://github.com/salasebas/saml-rs/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](#security)

**Pure-Rust SAML 2.0** Service Provider and Identity Provider support. The
protocol layer uses Rust XML parsing and does not require `libxml2`, `xmlsec1`,
or an OpenSSL build chain. XML cryptography (XML-DSig, XML-Enc, C14N, detached
message signatures) is delegated to [`bergshamra`](https://crates.io/crates/bergshamra)
behind the default `crypto-bergshamra` feature.

```toml
[dependencies]
opensaml = "0.1"

# Crypto-free protocol layer only:
# opensaml = { version = "0.1", default-features = false }
```

This package is a maintained compatibility re-export. Its Rust import path is
`opensaml`.

## Why opensaml?

`opensaml` is aimed at applications that need SAML SP/IdP flows without a C XML
security stack in their build and deployment environment.

| Area | opensaml |
|------|---------|
| Native dependencies | No `libxml2`, `xmlsec1`, or OpenSSL build chain for the protocol layer |
| Roles | Service Provider and Identity Provider |
| Bindings | HTTP-POST, HTTP-Redirect, HTTP-POST-SimpleSign |
| Metadata | Parse and generate SP/IdP metadata; verify signed metadata |
| Single Logout | Create and parse `LogoutRequest` / `LogoutResponse` |
| Crypto | XML-DSig, XML-Enc, detached signatures via `bergshamra` |
| Hardening | Request correlation, audience/destination/issuer checks, XSW guards, bounded parsing |
| Unsafe code | `#![forbid(unsafe_code)]` |

Compared with [`samael`](https://crates.io/crates/samael), the main tradeoff is
deployment shape: `samael` is the established Rust SAML crate and commonly uses
the native `xmlsec` stack, while `opensaml` keeps the SAML protocol path
Rust-only and delegates XML crypto to a Rust crate.

## What you can do

| Area | Highlights |
|------|------------|
| Web SSO | Signed `AuthnRequest` / `Response`, HTTP-POST, HTTP-Redirect, POST-SimpleSign |
| Metadata | Parse peer metadata, generate SP/IdP descriptors, verify signed aggregates |
| Single Logout | Create and parse logout request/response flows across all three bindings |
| Validation | Issuer, audience, destination/recipient, bearer confirmation, status, time windows, request correlation |
| Crypto | XML-DSig sign/verify, XML-Enc encrypt/decrypt, detached message signatures, metadata key pinning |
| Extraction | `quick-xml` DOM plus local-name field extraction |

### Unsupported SAML profiles

The high-level `Saml` API currently focuses on browser Web SSO, metadata-driven
SP/IdP setup, XML signature/encryption through `bergshamra`, and Single Logout.
It does not yet implement Artifact resolution, SOAP/back-channel profiles,
ECP/PAOS, SAML query protocols, NameID management, or metadata federation. If
you need one of those profiles for a real interoperability target, please open
an issue with the profile, binding, IdP/SP product, and a minimal expected flow
so we can consider the implementation.

## Quick Start

The primary API is the typed `Saml` facade. Build local SP/IdP configuration
with `SpConfig::builder` and `IdpConfig::builder`, import peer metadata into
typed descriptors, and keep the returned `Pending<_>` value with your browser
session while the SAML round trip is in flight.

### Runnable typed SSO

A signed SP -> IdP -> SP round trip is available as an executable example:

```sh
cargo run -p opensaml --example sso
```

Source: [`examples/sso.rs`](examples/sso.rs).

The repository also includes a typed Single Logout walkthrough in
[`examples/slo.rs`](examples/slo.rs) and a low-level compatibility walkthrough
in [`examples/raw_compat.rs`](examples/raw_compat.rs).

The [crate-root docs](https://docs.rs/opensaml/latest/opensaml/) contain
doctested fragments for the typed `Saml` facade, including
[`Saml<Sp>::start_sso`](https://docs.rs/opensaml/latest/opensaml/struct.Saml.html#method.start_sso),
[`Saml<Sp>::finish_sso`](https://docs.rs/opensaml/latest/opensaml/struct.Saml.html#method.finish_sso),
[`Saml<Idp>::receive_sso`](https://docs.rs/opensaml/latest/opensaml/struct.Saml.html#method.receive_sso),
and [`Saml<Sp>::finish_slo`](https://docs.rs/opensaml/latest/opensaml/struct.Saml.html#method.finish_slo).
Those rustdoc snippets are compiled by `cargo test --doc`; the README stays as
an entry point and links to the complete examples above.

### Service Provider SSO flow

1. Build local SP state with `SpConfig::builder` and `Saml::sp`.
2. Import peer IdP metadata into `IdpDescriptor`.
3. Start SSO with `sp.start_sso(...)` and store `started.pending` with the
   browser session.
4. In the ACS handler, pass the posted response fields and the matching pending
   value to `sp.finish_sso(...)`.

See [`examples/sso.rs`](examples/sso.rs) for a complete signed SP -> IdP -> SP
round trip and the [doctested crate-root SSO
fragment](https://docs.rs/opensaml/latest/opensaml/#sp-initiated-sso) for the
compact API shape.

### Identity Provider - receive and respond

The IdP side mirrors the SP flow: import peer SP metadata into `SpDescriptor`,
parse an `AuthnRequest` with `idp.receive_sso(...)`, then produce a typed
browser response with `idp.respond_sso(...)`. The complete path is exercised in
[`examples/sso.rs`](examples/sso.rs), and the short rustdoc version is in the
[Identity Provider flows](https://docs.rs/opensaml/latest/opensaml/#identity-provider-flows)
crate-root section.

### Single Logout

Typed Single Logout starts from `session.logout_subject()`, stores the
`PendingLogoutRequest`, and finishes only with the matching `LogoutResponse`.
Peer-initiated logout uses `Received<LogoutRequest>` rather than free-form
request ID strings. See [`examples/slo.rs`](examples/slo.rs) for the complete
typed walkthrough and the [doctested SLO
fragment](https://docs.rs/opensaml/latest/opensaml/#single-logout) for the compact
shape.

### Metadata

Metadata trust is explicit. The rustdoc
[Metadata trust](https://docs.rs/opensaml/latest/opensaml/#metadata-trust)
section describes production-shaped signed metadata validation with pinned
certificates. `MetadataTrustPolicy::UnsignedForCompatibility` is available for
legacy interoperability, but it is a compatibility exception rather than a
production default.

The compact rustdoc flow snippets use
`ReplayPolicy::DisabledForCompatibility` only to keep examples dependency-free.
Production inbound validation should use `ReplayPolicy::RequireCache` with a
caller-owned replay cache and the retention guidance in
[`SamlValidationContext`](https://docs.rs/opensaml/latest/opensaml/struct.SamlValidationContext.html).

### Advanced/raw compatibility

The low-level compatibility API remains available under `opensaml::raw` for
callers that need direct access to `ServiceProvider`, `IdentityProvider`,
`HttpRequest`, `BindingContext`, or protocol helper functions. New browser
SSO/SLO integrations should start with `Saml`, typed descriptors, and the
builder-backed config types shown above.
Use visible docs.rs modules, crate-root re-exports, and `opensaml::raw` before
reaching for hidden lower-level module paths.

## Features

```toml
[features]
default = ["crypto-bergshamra"]
crypto-bergshamra = ["dep:bergshamra"]
```

With `default-features = false`, the protocol layer still builds messages,
parses metadata, and runs extraction. Operations that need signing,
verification, or encryption return `OpenSamlError::Unsupported`.

The default `crypto-bergshamra` feature currently requires Rust 1.85 because
the `bergshamra` 0.6.3 dependency graph reaches `kryptering` 0.4.1 and
`crypto-bigint` 0.7.5, which declares Rust 1.85.

With `crypto-bergshamra` enabled:

- XML signatures can be verified against metadata-declared keys.
- Signed-reference placement checks help mitigate XML Signature Wrapping (XSW).
- XML-Enc support is available, but software RSA key-transport decryption is
  gated off by default and requires an explicit compatibility opt-in through
  [`XmlEncryptionPolicy`](https://docs.rs/opensaml/latest/opensaml/struct.XmlEncryptionPolicy.html).

## Security

`opensaml` is pre-1.0 and has not had an external security audit. Review the
crate, configuration, and peer metadata trust model before production use.

Security-sensitive defaults and checks include:

- `#![forbid(unsafe_code)]` on the crate root.
- DOCTYPE / XXE rejection and bounded XML parsing before authentication.
- XML escaping for generated templates, metadata endpoint locations, and SAML
  attribute values.
- Response validation for issuer, SAML status, assertion time window, audience,
  destination/recipient, bearer subject confirmation, and `InResponseTo`.
- Logout validation for issuer and request/response correlation.
- Signed metadata verification with root coverage requirements.
- AuthnRequest root-signature coverage when signed requests are required.
- Detached Redirect/SimpleSign signatures bound to the fields consumed by the
  flow parser.
- HTTP-Redirect raw DEFLATE output limits.
- XML-Enc software RSA key-transport decryption disabled by default because the
  bundled RustCrypto RSA backend, reached through `bergshamra` / `kryptering`,
  is affected by RUSTSEC-2023-0071.

Schema validation is optional defense in depth via
`context::set_schema_validator`.

## Development

```sh
cargo fmt --all --check
cargo clippy -p opensaml --all-targets -- -D warnings
cargo nextest run -p opensaml
cargo test -p opensaml --doc
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p opensaml --lib --all-features --no-deps
cargo test -p opensaml --doc --no-default-features
cargo check -p opensaml --no-default-features
```

## License

[MIT](LICENSE).
