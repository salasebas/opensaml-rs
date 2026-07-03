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

### Current Scope

`saml-rs` currently focuses on browser-facing SAML 2.0 SSO/SLO flows. It does
not yet implement every SAML profile or binding defined by OASIS. In
particular, HTTP-Artifact resolution, SOAP bindings, Enhanced Client or Proxy
(ECP/PAOS), assertion query/request protocols, authorization decision queries,
NameID management, and advanced federation profiles are out of scope for the
current release line.

If your deployment needs one of these profiles, please open an issue with the
target IdP/SP, binding, profile, and interoperability requirements so we can
evaluate the implementation scope.

## Quick Start

### Service Provider - Login Request

```rust
use saml_rs::constants::Binding;
use saml_rs::entity::EntitySetting;
use saml_rs::metadata::{Endpoint, SpMetadataConfig};
use saml_rs::ServiceProvider;

let sp = ServiceProvider::from_config(
    &SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        assertion_consumer_service: vec![Endpoint::new(
            Binding::Post,
            "https://sp.example.com/acs",
        )],
        ..Default::default()
    },
    EntitySetting::default(),
)?;

// Binding::Redirect uses raw DEFLATE + query-string dispatch.
let request = sp.create_login_request(&idp, Binding::Post, None)?;
```

### Identity Provider - Login Response

```rust
use saml_rs::constants::Binding;
use saml_rs::entity::User;
use saml_rs::flow::HttpRequest;
use saml_rs::idp::LoginResponseOptions;

let req = HttpRequest::post(vec![("SAMLRequest".into(), saml_request_b64)]);
let parsed = idp.parse_login_request(&sp, Binding::Post, &req)?;

let response = idp.create_login_response(
    &sp,
    Binding::Post,
    &User::new("alice@example.com"),
    &LoginResponseOptions {
        in_response_to: parsed.extract.get_str("request.id"),
        ..Default::default()
    },
)?;
```

### Service Provider - Consume Response

```rust
use saml_rs::constants::Binding;
use saml_rs::flow::HttpRequest;

let resp = HttpRequest::post(vec![("SAMLResponse".into(), saml_response_b64)]);

let result = sp.parse_login_response_with_request_id(
    &idp,
    Binding::Post,
    &resp,
    &authn_request_id,
)?;

let name_id = result.extract.get_str("nameID");
```

### Metadata

```rust
use saml_rs::constants::Binding;
use saml_rs::metadata::{generate_sp_metadata, IdpMetadata, SpMetadataConfig};

let idp_meta = IdpMetadata::from_xml(idp_metadata_xml)?;
let sso_url = idp_meta.get_single_sign_on_service(Binding::Redirect);

let xml = generate_sp_metadata(&SpMetadataConfig {
    entity_id: "https://sp.example.com/metadata".into(),
    ..Default::default()
});
```

### Single Logout

```rust
use saml_rs::constants::Binding;
use saml_rs::entity::User;
use saml_rs::flow::HttpRequest;
use saml_rs::logout::{create_logout_request, parse_logout_response};

let logout = create_logout_request(
    &sp.setting,
    &sp.metadata,
    &idp.metadata,
    Binding::Post,
    &User::new("alice@example.com"),
    None,
    true,
)?;

let resp = HttpRequest::post(vec![("SAMLResponse".into(), saml_response_b64)]);
let parsed = parse_logout_response(
    &sp.setting,
    &idp.metadata,
    Binding::Post,
    &resp,
    &logout.id,
)?;
```

### End-to-End Example

A runnable signed SP -> IdP -> SP round trip:

```sh
cargo run -p saml-rs --example sso
```

Source: [`examples/sso.rs`](examples/sso.rs).

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
cargo check -p saml-rs --no-default-features
```

## License

[MIT](LICENSE).
