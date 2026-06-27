# opensaml-rs

[![crates.io](https://img.shields.io/crates/v/opensaml.svg)](https://crates.io/crates/opensaml)
[![docs.rs](https://img.shields.io/docsrs/opensaml)](https://docs.rs/opensaml)
[![MIT licensed](https://img.shields.io/crates/l/opensaml)](https://github.com/salasebas/opensaml-rs/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](#security)

**Pure-Rust SAML 2.0** — Service Provider and Identity Provider in one crate. No `libxml2`, no `xmlsec1`, no OpenSSL build chain for the protocol layer. XML cryptography (XML-DSig, XML-Enc, C14N) is delegated to [`bergshamra`](https://crates.io/crates/bergshamra) behind an optional feature that is **on by default**.

Behavior is ported to parity with npm [`samlify`](https://www.npmjs.com/package/samlify) v2.10.2, with the upstream test suite carried over 1:1 and additional hardening (audience restriction, `InResponseTo` binding, XML Signature Wrapping tests, metadata key pinning, signed-metadata verification).

```toml
[dependencies]
opensaml = "0.1"
# Crypto-free protocol layer only:
# opensaml = { version = "0.1", default-features = false }
```

> Alias crates ([`samlify`](crates/samlify), [`open-saml`](crates/open-saml), [`rust-saml`](crates/rust-saml), [`rustsaml`](crates/rustsaml), [`saml-rs`](crates/saml-rs), [`samlrs`](crates/samlrs)) are thin `pub use opensaml::*;` re-exports.

---

## Why opensaml vs. [samael](https://crates.io/crates/samael)?

| | **opensaml** | **samael** |
|---|:---:|:---:|
| **Native C/XML stack** (`libxml2`, `xmlsec1`, `libxslt`, …) | None — protocol in Rust; crypto via [`bergshamra`](https://crates.io/crates/bergshamra) | Required with default `xmlsec` feature |
| **OpenSSL at build time** | No | Yes (typical `xmlsec` setup) |
| **System packages to install** | None | `libiconv`, `libtool`, `libxml2`, `libxslt`, `libclang`, `openssl`, `pkg-config`, `xmlsec1`, … |
| **Cross-compile** (musl, distroless, arm64) | Straightforward | Native libs needed on every target |
| **`cargo audit` for the SAML stack** | Rust dependency graph | Split: crates + OS packages |
| **SP + IdP in one library** | First-class `ServiceProvider` + `IdentityProvider` | SP-oriented; IdP-initiated SSO supported |
| **HTTP bindings** | POST, Redirect, POST-SimpleSign | Redirect → POST (primary documented path) |
| **Single Logout** | Create + parse, all three bindings | Limited / evolving |
| **Metadata** | Parse + generate (SP and IdP) | Deserialize-focused |
| **Signed metadata verification** | Yes | — |
| **XSW / reference hardening** | Explicit guard + strict verification via bergshamra | Inherits xmlsec behavior |
| **`#![forbid(unsafe_code)]`** | Yes | No |
| **API shape** | Ported from npm `samlify` v2.10.2 | Builder-style `ServiceProvider` |

**Takeaway:** [samael](https://crates.io/crates/samael) is the established SAML crate on crates.io, but signing and verification pull in **libxml2 + xmlsec1 + OpenSSL** and a host of system libraries. **opensaml** keeps the protocol layer and XML crypto on a **Rust-only** path (no C XML stack), ships **SP and IdP** with **three bindings** and **Single Logout**, and adds hardening beyond the samlify port (audience, `InResponseTo`, XSW tests, metadata key pinning).

---

## What you can do

| Area | Highlights |
|------|------------|
| **Web SSO** | Signed `AuthnRequest` / `Response`, HTTP-POST and HTTP-Redirect, POST-SimpleSign |
| **Metadata** | Parse peer metadata, generate SP/IdP descriptors, verify signed aggregates |
| **Single Logout** | `LogoutRequest` / `LogoutResponse` create and parse (all three bindings) |
| **Validation** | Issuer, `<Audience>`, assertion time window, status codes, optional `InResponseTo` |
| **Crypto** (default) | XML-DSig sign/verify, XML-Enc encrypt/decrypt, detached redirect signatures, anti-wrapping |
| **Extraction** | quick-xml DOM + local-name field sets (samlify-compatible extract engine) |

---

## Quick start

### Service Provider — login request

```rust
use opensaml::constants::Binding;
use opensaml::entity::EntitySetting;
use opensaml::metadata::{Endpoint, SpMetadataConfig};
use opensaml::ServiceProvider;

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

// Binding::Redirect for DEFLATE + query-string dispatch
let request = sp.create_login_request(&idp, Binding::Post, None)?;
// POST: request.context is the base64 SAMLRequest
// Redirect: use binding helpers to build the redirect URL
```

### Identity Provider — login response

```rust
use opensaml::constants::Binding;
use opensaml::entity::{EntitySetting, User};
use opensaml::flow::HttpRequest;
use opensaml::idp::LoginResponseOptions;
use opensaml::IdentityProvider;

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

### Service Provider — consume response

```rust
use opensaml::flow::HttpRequest;

let resp = HttpRequest::post(vec![("SAMLResponse".into(), saml_response_b64)]);

// Prefer binding to the outbound AuthnRequest id (replay / CSRF hygiene)
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
use opensaml::constants::Binding;
use opensaml::metadata::{generate_sp_metadata, IdpMetadata, SpMetadataConfig};

// Parse peer IdP metadata
let idp_meta = IdpMetadata::from_xml(idp_metadata_xml)?;
let sso_url = idp_meta.get_single_sign_on_service(Binding::Redirect);

// Generate your SP descriptor
let xml = generate_sp_metadata(&SpMetadataConfig {
    entity_id: "https://sp.example.com/metadata".into(),
    ..Default::default()
});
```

### Single Logout

```rust
use opensaml::constants::Binding;
use opensaml::entity::{EntitySetting, User};
use opensaml::flow::HttpRequest;
use opensaml::logout::{create_logout_request, parse_logout_response};

let logout = create_logout_request(
    &sp.setting,
    &sp.metadata,
    &idp.metadata,
    Binding::Post,
    &User::new("alice@example.com"),
    None,  // relay_state
    true,  // want_signed
)?;

let resp = HttpRequest::post(vec![("SAMLResponse".into(), saml_response_b64)]);
let parsed = parse_logout_response(&sp.setting, &idp.metadata, Binding::Post, &resp)?;
```

### End-to-end example (signed round-trip)

A runnable SP → IdP → SP flow with RSA-SHA256 signatures:

```sh
cargo run -p opensaml --example sso
```

Source: [`crates/opensaml/examples/sso.rs`](crates/opensaml/examples/sso.rs).

---

## Crates in this workspace

| Crate | Role |
|-------|------|
| [`opensaml`](crates/opensaml) | Library: constants, XML, templates, metadata, bindings, `ServiceProvider` / `IdentityProvider`, flow, logout, validation, crypto (feature). |
| [`samlify`](crates/samlify) | Thin re-export: `pub use opensaml::*;` — drop-in crate name only. |
| [`open-saml`](crates/open-saml), [`rust-saml`](crates/rust-saml), [`rustsaml`](crates/rustsaml), [`saml-rs`](crates/saml-rs), [`samlrs`](crates/samlrs) | Same thin re-export as `samlify`. |

Crate-level API details: [docs.rs/opensaml](https://docs.rs/opensaml) and the `opensaml` crate rustdoc module map.

---

## Features

```toml
[features]
default = ["crypto-bergshamra"]
crypto-bergshamra = ["dep:bergshamra"]   # XML-DSig, XML-Enc, detached signatures
```

With `default-features = false`, the protocol layer still builds messages, parses metadata, and runs extraction; any operation that needs signing, verification, or encryption returns `OpenSamlError::Unsupported` (fail closed).

With `crypto-bergshamra` enabled (default):

- Verification can pin to metadata-declared keys (`trusted_keys_only`).
- Strict signed-reference placement helps mitigate XML Signature Wrapping (XSW).
- An additional wrapping guard runs in `crypto::verify`.

---

## Security

- `#![forbid(unsafe_code)]` on the crate root.
- Inbound responses: signature (when required), issuer, `<Audience>`, assertion validity window, SAML status; optional `InResponseTo` via `parse_login_response_with_request_id`.
- Inbound `LogoutRequest` parsing requires signatures by default and always
  checks the request `<Issuer>` against the expected peer metadata. Set
  `want_logout_request_signed = false` only for legacy peers that cannot sign
  logout requests.
- DOCTYPE / XXE rejection in the XML layer; optional XSD validation via `context::set_schema_validator`.
- **Pre-1.0** and **not externally audited** — review crypto and deployment choices before production.

---

## Status

| | |
|---|---|
| **Version** | `0.1.1` (APIs may change until 1.0) |
| **Reference port** | npm `samlify` v2.10.2 |
| **Tests** | Upstream samlify suite ported 1:1 + XSW / audience / metadata-signature cases |
| **Audit** | None yet |

---

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
```

Upstream reference sources (gitignored): `./scripts/fetch-upstream-samlify.sh` → `reference/upstream-samlify/2.10.2/`.

---

## License

[MIT](LICENSE).
