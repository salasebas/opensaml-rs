# opensaml

> **Experimental.** SAML 2.0 **Service Provider** (SP) only. APIs will change.

`opensaml` provides the SAML 2.0 SP protocol layer and HTTP bindings. XML
cryptography (XML-DSig, XML-Enc, C14N) is **not** implemented here — it is
delegated to [`bergshamra`](https://crates.io/crates/bergshamra) behind the
optional `crypto-bergshamra` feature.

## Scope

| Capability | npm `samlify` | `opensaml` (this crate) | `bergshamra` |
| --- | --- | --- | --- |
| Metadata / AuthnRequest / response shapes | ✅ | 🚧 stubs (SP-first) | — |
| HTTP-POST & HTTP-Redirect bindings | ✅ | ✅ (M0) | — |
| DEFLATE / base64 / XML escaping | ✅ | ✅ (M0) | — |
| XML-DSig signing & verification | ✅ | ➡️ delegated | ✅ |
| XML-Enc (encrypted assertions) | ✅ | ➡️ delegated | ✅ |
| C14N / transforms | ✅ | ➡️ delegated | ✅ |

The `samlify` crate in this workspace is just `pub use opensaml::*;` — a
familiar crate name, unrelated to the npm package.

## What works in M0

`opensaml::binding`:

- `xml_escape` / `html_escape`
- `deflate_raw_encode` / `deflate_raw_decode`
- `base64_encode` / `base64_decode` (whitespace-normalizing)
- `saml_post_binding_form` (auto-submit HTML form)
- `redirect_binding_query` (unsigned query; signed redirect lands in M2)

Everything in `metadata`, `authn`, `response`, and `logout` is a documented
stub returning `OpenSamlError::Unsupported`.

## Features

```toml
[features]
default = []
crypto-bergshamra = ["dep:bergshamra"]  # off by default in M0
```

With `crypto-bergshamra`, `crypto::BergshamraBackend` implements the
`XmlSecurityBackend` trait. Recommended bergshamra configuration for SAML SP
verification (wired up in M1):

- `trusted_keys_only` — only accept signatures from configured IdP keys.
- `strict_verification` — reject unsigned/partially-signed assertions.

## Reference

The npm `samlify` source (tag `v2.10.2`) is used as a behavioral/porting
reference. Populate it locally with:

```bash
./scripts/fetch-upstream-samlify.sh
```

It clones into `reference/upstream-samlify/2.10.2/repository/` (gitignored).

## Roadmap

| Milestone | Contents |
| --- | --- |
| M1 | `parse_login_response_post` + bergshamra verify (`trusted_keys_only`, `strict_verification`) |
| M2 | Redirect binding: query signature verify/sign |
| M3 | SLO (single logout) parse/create |
| M4 | `EncryptedAssertion` decrypt (bergshamra-enc) |
| M5 | Consumed by `openauth-saml`; tests ported from upstream `packages/sso` |
