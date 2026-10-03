# saml-rs

[![crates.io](https://img.shields.io/crates/v/saml-rs.svg)](https://crates.io/crates/saml-rs)
[![docs.rs](https://img.shields.io/docsrs/saml-rs)](https://docs.rs/saml-rs)
[![MIT licensed](https://img.shields.io/crates/l/saml-rs)](https://github.com/salasebas/opensaml-rs/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](#security)

Pure-Rust SAML 2.0 Service Provider and Identity Provider support. Use it when
an application needs browser Web SSO, metadata, and Single Logout without
`libxml2`, `xmlsec1`, or an OpenSSL build chain. XML-DSig, XML-Enc, C14N, and
detached message signatures go through
[`bergshamra`](https://crates.io/crates/bergshamra).

The Cargo package is `saml-rs`. The Rust import path is `saml_rs`. Source and
issues live in [salasebas/opensaml-rs](https://github.com/salasebas/opensaml-rs).

**Status:** pre-1.0. Minor releases can change the API or runtime behavior.
There has been no external security audit. Review the crate, your
configuration, and the peer metadata trust model before production use.

**Help:** [open an issue](https://github.com/salasebas/opensaml-rs/issues).
Before a minor upgrade, read the
[migration guides](docs/migrations/README.md).

## Install

```toml
[dependencies]
saml-rs = "0.5"

# Protocol layer only, with signing and encryption disabled:
# saml-rs = { version = "0.5", default-features = false }
```

Rust 1.88 or newer is required.

## Get started

The typed `Saml` facade is the API for new browser SSO and SLO integrations.
Build local state with `SpConfig::builder` or `IdpConfig::builder`, import the
peer from metadata, and store the returned `Pending<_>` value with the browser
session until the round trip finishes.

A signed SP to IdP to SP round trip:

```sh
cargo run -p saml-rs --example sso
```

Source: [`examples/sso.rs`](examples/sso.rs). Single Logout is
[`examples/slo.rs`](examples/slo.rs). The low-level compatibility path is
[`examples/raw_compat.rs`](examples/raw_compat.rs).

Service Provider SSO:

1. Build `SpConfig` and call `Saml::sp`.
2. Import peer IdP metadata into `IdpDescriptor`.
3. Call `sp.start_sso(...)` and store `started.pending` with the browser session.
4. In the assertion consumer service, pass the posted fields and that pending
   value to `sp.finish_sso(...)`.

The same shape, checked by `cargo test --doc`, is in the
[crate-root SSO example](https://docs.rs/saml-rs/latest/saml_rs/#sp-initiated-sso).
Identity Provider receive-and-respond is in
[`examples/sso.rs`](examples/sso.rs) and the
[Identity Provider flows](https://docs.rs/saml-rs/latest/saml_rs/#identity-provider-flows)
section. Logout is in [`examples/slo.rs`](examples/slo.rs) and the
[Single Logout](https://docs.rs/saml-rs/latest/saml_rs/#single-logout) section.

Callers that still need `ServiceProvider`, `IdentityProvider`, `HttpRequest`,
or `BindingContext` can use `saml_rs::raw`. New integrations should start with
`Saml`.

## What you can do

| Area | Support |
| --- | --- |
| Web SSO | Signed `AuthnRequest` and `Response` over HTTP-POST, HTTP-Redirect, and HTTP-POST-SimpleSign |
| Metadata | Parse peer metadata, generate SP and IdP descriptors, verify signed metadata |
| Single Logout | Create and parse `LogoutRequest` and `LogoutResponse` on the same three bindings |
| Validation | Issuer, audience, destination, recipient, bearer confirmation, status, time windows, and request correlation |
| Crypto | XML-DSig, XML-Enc, detached signatures, and metadata key pinning through `bergshamra` |
| Parsing | `quick-xml` DOM with local-name extraction, bounded before authentication |

Artifact resolution, SOAP and other back-channel profiles, ECP/PAOS, SAML query
protocols, NameID management, and metadata federation are outside the typed
`Saml` API. Open an issue with the profile, binding, peer product, and a
minimal expected flow if you need one of them.

## Where to read next

| Need | Start here |
| --- | --- |
| Learn a full flow | [`examples/sso.rs`](examples/sso.rs) and [`examples/slo.rs`](examples/slo.rs) |
| Change an existing integration | [Migration guides](docs/migrations/README.md) |
| Look up a type or method | [docs.rs](https://docs.rs/saml-rs/latest/saml_rs/) |
| Choose metadata trust or replay policy | [Metadata trust](https://docs.rs/saml-rs/latest/saml_rs/#metadata-trust) and [`SamlValidationContext`](https://docs.rs/saml-rs/latest/saml_rs/struct.SamlValidationContext.html) |

The compact rustdoc snippets use `ReplayPolicy::DisabledForCompatibility` and,
where noted, unsigned metadata so the examples stay dependency-free. Production
inbound validation should use `ReplayPolicy::RequireCache` with a caller-owned
replay cache. `MetadataTrustPolicy::UnsignedForCompatibility` is a legacy
interoperability choice.

`IdpConfig` issuance lifetime, Session Authority logout expiration, and inbound
`IssueInstant` / `NotOnOrAfter` rules are documented on the methods that apply
them, including
[`Saml<Idp>::start_slo`](https://docs.rs/saml-rs/latest/saml_rs/struct.Saml.html#method.start_slo).

## Features

```toml
[features]
default = ["crypto-bergshamra"]
crypto-bergshamra = [
    "crypto-rustcrypto",
    "crypto-legacy-algorithms",
    "crypto-post-quantum",
    "crypto-pkcs11",
]
crypto-rustcrypto = ["dep:bergshamra", "bergshamra/rustcrypto"]
crypto-aws-lc = ["dep:bergshamra", "bergshamra/aws-lc"]
crypto-fips = ["dep:bergshamra", "bergshamra/fips"]
```

With `default-features = false`, the crate still builds messages, parses
metadata, and extracts fields. Signing, verification, and encryption return
`SamlError::Unsupported`.

Select at most one of `crypto-rustcrypto`, `crypto-aws-lc`, and `crypto-fips`.
Combinations are rejected at compile time. Disable the default features before
selecting AWS-LC or FIPS. `crypto-legacy-algorithms`, `crypto-post-quantum`,
and `crypto-pkcs11` forward Bergshamra capabilities and do not select a
provider. The default `crypto-bergshamra` feature enables those capabilities
together with RustCrypto.

Bergshamra supports AWS-LC and FIPS on Linux x86_64 and aarch64. This
repository's provider matrix currently runs on Linux x86_64. `saml-rs`
initializes Bergshamra before the first crypto operation. Applications can
fail early at startup:

```rust
fn startup() -> Result<(), saml_rs::SamlError> {
    let provider = saml_rs::initialize_crypto_provider()?;
    assert_ne!(
        provider.fips_status(),
        saml_rs::CryptoFipsStatus::Uninitialized,
    );
    Ok(())
}
```

Initialization, attestation, unsupported-algorithm, and key-import failures
map to `SamlError::Crypto`. `crypto-fips` means the selected AWS-LC provider
attested FIPS mode. It does not mean the consuming binary or deployment is
FIPS certified. FIPS policy rejects algorithms outside its approved set,
including SHA-1 `RSA_OAEP_MGF1P` key transport and both signing and verifying
`RSA_SHA1`. Non-FIPS AWS-LC still verifies inbound RSA-SHA1 Redirect and
XML-DSig signatures. AWS-LC has a narrower algorithm set than RustCrypto; see
Bergshamra's
[provider capabilities](https://github.com/kushaldas/bergshamra/blob/v0.9.0/docs/provider-capabilities.md)
before enabling a custom algorithm URI.

With `crypto-bergshamra` enabled:

- XML signatures can be verified against metadata-declared keys.
- Signed-reference placement checks help mitigate XML Signature Wrapping.
- XML-Enc is available. On RustCrypto, software RSA key-transport decryption
  stays off until the caller opts in through
  [`XmlEncryptionPolicy`](https://docs.rs/saml-rs/latest/saml_rs/struct.XmlEncryptionPolicy.html).
  AWS-LC decrypts RSA-OAEP with the default options.

## Security

- `#![forbid(unsafe_code)]` on the crate root.
- DOCTYPE and XXE rejection, with bounded XML parsing before authentication.
- XML escaping for generated templates, metadata endpoint locations, and SAML
  attribute values.
- Response checks for issuer, status, assertion time window, audience,
  destination, recipient, bearer subject confirmation, and `InResponseTo`.
- Logout checks for issuer and request/response correlation.
- Signed metadata must cover the signed root.
- Signed `AuthnRequest` messages must cover the request root when signed
  requests are required.
- Detached Redirect and SimpleSign signatures are bound to the fields the flow
  parser consumes.
- HTTP-Redirect raw DEFLATE output is limited.
- Software RSA key-transport decryption is disabled by default on RustCrypto
  because that backend, reached through `bergshamra` and `kryptering`, is
  affected by RUSTSEC-2023-0071. AWS-LC and FIPS do not use that gate.

Schema validation is optional defense in depth through
`context::set_schema_validator`.

## Compatibility crates

Depend on `saml-rs` for new code. This repository also publishes four
compatibility packages that re-export the same API, so existing dependencies
keep resolving:

| Package | Import | docs.rs |
| --- | --- | --- |
| [`opensaml`](https://crates.io/crates/opensaml) | `opensaml` | [docs](https://docs.rs/opensaml) |
| [`samlify`](https://crates.io/crates/samlify) | `samlify` | [docs](https://docs.rs/samlify) |
| [`rustsaml`](https://crates.io/crates/rustsaml) | `rustsaml` | [docs](https://docs.rs/rustsaml) |
| [`samlet`](https://crates.io/crates/samlet) | `samlet` | [docs](https://docs.rs/samlet) |

`opensaml` still exports the deprecated `OpenSamlError` alias of `SamlError`.
These packages are maintained with `saml-rs`. They are separate from
Shibboleth OpenSAML and from the Node.js samlify project.
[`samael`](https://crates.io/crates/samael) is the other established Rust SAML
crate; it commonly uses the native `xmlsec` stack.

## Development

```sh
cargo fmt --all --check
cargo clippy -p saml-rs --all-targets -- -D warnings
cargo nextest run -p saml-rs
cargo test -p saml-rs --doc
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --no-deps
cargo test -p saml-rs --doc --no-default-features
cargo check -p saml-rs --no-default-features
cargo nextest run -p saml-rs --no-default-features --features crypto-rustcrypto
```

AWS-LC and FIPS checks run on supported Linux runners. See
[`.github/workflows/ci.yml`](https://github.com/salasebas/opensaml-rs/blob/main/.github/workflows/ci.yml).

## License

[MIT](LICENSE).
