# saml-rs

[![crates.io](https://img.shields.io/crates/v/saml-rs.svg)](https://crates.io/crates/saml-rs)
[![docs.rs](https://img.shields.io/docsrs/saml-rs)](https://docs.rs/saml-rs)
[![MIT licensed](https://img.shields.io/crates/l/saml-rs)](https://github.com/salasebas/saml-rs/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](#security)

**Pure-Rust SAML 2.0** Service Provider and Identity Provider support. The
protocol layer uses Rust XML parsing and does not require `libxml2`, `xmlsec1`,
or an OpenSSL build chain. XML cryptography (XML-DSig, XML-Enc, C14N, detached
message signatures) is delegated to [`bergshamra`](https://crates.io/crates/bergshamra)
behind the default `crypto-bergshamra` feature.

```toml
[dependencies]
saml-rs = "0.1"

# Crypto-free protocol layer only:
# saml-rs = { version = "0.1", default-features = false }
```

The project now publishes one crate: `saml-rs`. The Rust import path is
`saml_rs`.

## Why saml-rs?

`saml-rs` is aimed at applications that need SAML SP/IdP flows without a C XML
security stack in their build and deployment environment.

| Area | saml-rs |
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
the native `xmlsec` stack, while `saml-rs` keeps the SAML protocol path
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
cargo run -p saml-rs --example sso
```

Source: [`examples/sso.rs`](examples/sso.rs).

The repository also includes a typed Single Logout walkthrough in
[`examples/slo.rs`](examples/slo.rs) and a low-level compatibility walkthrough
in [`examples/raw_compat.rs`](examples/raw_compat.rs).

### Service Provider - start SSO

```rust
use saml_rs::{
    AcsEndpoint, BrowserInput, CertificatePem, Credentials, EntityId, IdpDescriptor,
    MetadataTrustPolicy, PrivateKeyPem, Saml, SpConfig, StartSso, SsoResponse,
};

let credentials = Credentials {
    signing_key: Some(PrivateKeyPem::new(include_str!("sp-key.pem"))),
    signing_certificate: Some(CertificatePem::new(include_str!("sp-cert.pem"))),
    ..Credentials::default()
};
let sp = Saml::sp(
    SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .credentials(credentials)
        .build()?,
)?;
let idp = IdpDescriptor::from_metadata_xml_for(
    EntityId::try_new("https://idp.example.com/metadata")?,
    idp_metadata_xml,
    MetadataTrustPolicy::UnsignedForCompatibility,
)?;

let started = sp.start_sso(&idp, StartSso::redirect())?;
let redirect_url = started.outbound.redirect_url()?;

// Store started.pending with the user's browser session. Later, in the ACS
// handler, pass the posted fields back to the same SP facade:
let session = sp.finish_sso(
    &idp,
    &started.pending,
    BrowserInput::<SsoResponse>::post(form_fields),
    validation,
)?;
let name_id = session.name_id().value();
```

### Identity Provider - receive and respond

```rust
use saml_rs::{
    AuthnRequest, BrowserInput, NameId, RespondSso, Saml, SpDescriptor, Subject,
};

let request = idp.receive_sso(
    &sp,
    BrowserInput::<AuthnRequest>::post(request_fields),
    validation,
)?;
let response = idp.respond_sso(
    &sp,
    &request,
    Subject::new(NameId::new("alice@example.com", None), Vec::new()),
    RespondSso::post(),
)?;
let response_fields = response.post_form()?.fields();
```

### Single Logout

```rust
use saml_rs::{BrowserInput, LogoutRequest, LogoutResponse, RespondSlo, StartSlo};

if let Some(subject) = session.logout_subject() {
    let logout = sp.start_slo(&idp, subject, StartSlo::post())?;

    // Peer receives the LogoutRequest and emits a LogoutResponse.
    let received = idp_saml.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(logout_request_fields),
        validation_for_request,
    )?;
    let response = idp_saml.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;

    let completed = sp.finish_slo(
        &idp,
        &logout.pending,
        BrowserInput::<LogoutResponse>::post(response.post_form()?.fields().to_vec()),
        validation_for_response,
    )?;
    assert_eq!(completed.peer_entity_id(), idp.entity_id());
}
```

### Metadata

```rust
use saml_rs::{EntityId, IdpDescriptor, MetadataTrustPolicy};

let sp_metadata_xml = sp.metadata_xml();
let idp = IdpDescriptor::from_metadata_xml_for(
    EntityId::try_new("https://idp.example.com/metadata")?,
    idp_metadata_xml,
    MetadataTrustPolicy::UnsignedForCompatibility,
)?;
```

### Advanced/raw compatibility

The low-level compatibility API remains available under `saml_rs::raw` for
callers that need direct access to `ServiceProvider`, `IdentityProvider`,
`HttpRequest`, `BindingContext`, or protocol helper functions. New browser
SSO/SLO integrations should start with `Saml`, typed descriptors, and the
builder-backed config types shown above.
Use visible docs.rs modules, crate-root re-exports, and `saml_rs::raw` before
reaching for hidden lower-level module paths.

## Features

```toml
[features]
default = ["crypto-bergshamra"]
crypto-bergshamra = ["dep:bergshamra"]
```

With `default-features = false`, the protocol layer still builds messages,
parses metadata, and runs extraction. Operations that need signing,
verification, or encryption return `SamlError::Unsupported`.

The default `crypto-bergshamra` feature currently requires Rust 1.85 because
the `bergshamra` 0.6.3 dependency graph reaches `kryptering` 0.4.1 and
`crypto-bigint` 0.7.5, which declares Rust 1.85.

With `crypto-bergshamra` enabled:

- XML signatures can be verified against metadata-declared keys.
- Signed-reference placement checks help mitigate XML Signature Wrapping (XSW).
- XML-Enc support is available, but software RSA key-transport decryption is
  gated off by default and requires an explicit compatibility opt-in.

## Security

`saml-rs` is pre-1.0 and has not had an external security audit. Review the
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
cargo clippy -p saml-rs --all-targets -- -D warnings
cargo nextest run -p saml-rs
cargo test -p saml-rs --doc
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --all-features --no-deps
cargo test -p saml-rs --doc --no-default-features
cargo check -p saml-rs --no-default-features
```

## License

[MIT](LICENSE).
