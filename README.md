# saml-rs

[![crates.io](https://img.shields.io/crates/v/saml-rs.svg)](https://crates.io/crates/saml-rs)
[![docs.rs](https://img.shields.io/docsrs/saml-rs)](https://docs.rs/saml-rs)
[![MIT licensed](https://img.shields.io/crates/l/saml-rs)](https://github.com/salasebas/saml-rs/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success)](#security)

Pure-Rust SAML 2.0 service provider and identity provider support for browser
Web SSO, metadata, and Single Logout. XML-DSig, XML-Enc, C14N, and detached
message signatures go through
[`bergshamra`](https://crates.io/crates/bergshamra). The crate does not need
`libxml2`, `xmlsec1`, or an OpenSSL build chain.

The Cargo package is `saml-rs`. The Rust import path is `saml_rs`. Source and
issues live in [salasebas/saml-rs](https://github.com/salasebas/saml-rs).

**Status:** pre-1.0. A minor release can change the API or runtime behaviour.
There has been no external security audit. Review the crate, your
configuration, and the peer metadata trust model before production use.

**Help:** [open an issue](https://github.com/salasebas/saml-rs/issues).
Before a minor upgrade, follow the
[migration guides](docs/migrations/README.md).

## Install

```toml
[dependencies]
saml-rs = "0.5"

# Protocol layer only, with signing and encryption disabled:
# saml-rs = { version = "0.5", default-features = false }
```

Rust 1.88 or newer is required.

## How to add service-provider SSO

Use the typed `Saml` facade for a new browser integration. Build local state
with `SpConfig::builder`, import the peer from metadata, and keep the returned
`Pending<_>` value with the browser session until the round trip finishes.

1. Build `SpConfig` and call `Saml::sp`.
2. Import peer IdP metadata into `IdpDescriptor`.
3. Call `sp.start_sso(...)` and store `started.pending` with the browser session.
4. In the assertion consumer service, pass the posted fields and that pending
   value to `sp.finish_sso(...)`.

Run that SP to IdP to SP round trip:

```sh
cargo run -p saml-rs --example sso
```

Source: [`examples/sso.rs`](examples/sso.rs). The same calls, checked by
`cargo test --doc`, are in the
[crate-root SSO example](https://docs.rs/saml-rs/latest/saml_rs/#sp-initiated-sso).

Those snippets use `ReplayPolicy::DisabledForCompatibility` and, where noted,
unsigned metadata so they compile alone. For production inbound validation, use
`ReplayPolicy::RequireCache` with a caller-owned replay cache.
`MetadataTrustPolicy::UnsignedForCompatibility` is a legacy interoperability
choice. Choose either policy in
[metadata trust](https://docs.rs/saml-rs/latest/saml_rs/#metadata-trust) and
[`SamlValidationContext`](https://docs.rs/saml-rs/latest/saml_rs/struct.SamlValidationContext.html).

`finish_sso` returns an `SsoSession`. Read embedded XML signature evidence from
`verified_xml_signatures()`: one item per verified signature over the Response
root or the consumed Assertion, including its `SignatureMethod@Algorithm` URI.
`sig_alg()` is only the detached `SigAlg` from HTTP-Redirect or
HTTP-POST-SimpleSign. Neither value applies an application algorithm allowlist.

To receive and respond as an identity provider, follow
[`examples/sso.rs`](examples/sso.rs) and the
[Identity Provider flows](https://docs.rs/saml-rs/latest/saml_rs/#identity-provider-flows).
For logout, follow [`examples/slo.rs`](examples/slo.rs) and
[Single Logout](https://docs.rs/saml-rs/latest/saml_rs/#single-logout).
Issuance lifetime and Session Authority logout expiration are on
[`Saml<Idp>::start_slo`](https://docs.rs/saml-rs/latest/saml_rs/struct.Saml.html#method.start_slo).

If you still need `ServiceProvider`, `IdentityProvider`, `HttpRequest`, or
`BindingContext`, use `saml_rs::raw`
([`examples/raw_compat.rs`](examples/raw_compat.rs)).

## What the typed API covers

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
| Run a full flow | [`examples/sso.rs`](examples/sso.rs) and [`examples/slo.rs`](examples/slo.rs) |
| Change an existing integration | [Migration guides](docs/migrations/README.md) |
| Look up a type or method | [docs.rs](https://docs.rs/saml-rs/latest/saml_rs/) |
| Choose metadata trust or replay policy | [Metadata trust](https://docs.rs/saml-rs/latest/saml_rs/#metadata-trust) and [`SamlValidationContext`](https://docs.rs/saml-rs/latest/saml_rs/struct.SamlValidationContext.html) |

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
repository's provider tests run on Linux x86_64. `saml-rs` initialises
Bergshamra before the first crypto operation. To surface that failure at
startup:

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

Initialisation, attestation, unsupported-algorithm, and key-import failures
map to `SamlError::Crypto`. `crypto-fips` means the selected AWS-LC provider
attested FIPS mode. It does not certify the consuming binary or deployment.
FIPS policy rejects algorithms outside its approved set, including SHA-1
`RSA_OAEP_MGF1P` key transport and both signing and verifying `RSA_SHA1`.
Non-FIPS AWS-LC still verifies inbound RSA-SHA1 Redirect and XML-DSig
signatures. AWS-LC has a narrower algorithm set than RustCrypto. Custom
algorithm URIs are listed in Bergshamra's
[provider capabilities](https://github.com/kushaldas/bergshamra/blob/v0.9.0/docs/provider-capabilities.md).

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

Schema validation is optional defence in depth through
`context::set_schema_validator`.

## Compatibility crates

New code depends on `saml-rs`. This repository also publishes four
compatibility packages that re-export the same API:

| Package | Import | docs.rs |
| --- | --- | --- |
| [`opensaml`](https://crates.io/crates/opensaml) | `opensaml` | [docs](https://docs.rs/opensaml) |
| [`samlify`](https://crates.io/crates/samlify) | `samlify` | [docs](https://docs.rs/samlify) |
| [`rustsaml`](https://crates.io/crates/rustsaml) | `rustsaml` | [docs](https://docs.rs/rustsaml) |
| [`samlet`](https://crates.io/crates/samlet) | `samlet` | [docs](https://docs.rs/samlet) |

`opensaml` still exports the deprecated `OpenSamlError` alias of `SamlError`.
`opensaml`, `samlify`, and `samlet` are maintained with `saml-rs`.
`rustsaml` is no longer maintained. These packages are separate from
Shibboleth OpenSAML and from the Node.js samlify project.
[`samael`](https://crates.io/crates/samael) is the other established Rust SAML
crate; it commonly uses the native `xmlsec` stack.

## How to check a change

Follow [Contributing](CONTRIBUTING.md).

## License

[MIT](LICENSE).
