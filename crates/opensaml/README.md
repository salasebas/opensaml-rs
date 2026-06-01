# opensaml

> **Experimental.** SAML 2.0 Service Provider **and** Identity Provider. APIs may change.

`opensaml` implements the SAML 2.0 protocol layer to parity with npm `samlify`
v2.10.2 — metadata, AuthnRequest/Response, Single Logout, the three bindings
(HTTP-POST, HTTP-Redirect, HTTP-POST-SimpleSign), XML field extraction, and
time/status/issuer validation. XML cryptography (XML-DSig, XML-Enc, C14N) is
**not** implemented here — it is delegated to
[`bergshamra`](https://crates.io/crates/bergshamra) behind the optional
`crypto-bergshamra` feature.

## Scope

| Capability | npm `samlify` | `opensaml` |
| --- | --- | --- |
| Metadata parse / generate (SP + IdP) | ✅ | ✅ |
| AuthnRequest / Response / Logout | ✅ | ✅ |
| HTTP-POST / Redirect / POST-SimpleSign | ✅ | ✅ |
| XML field extraction + validation | ✅ | ✅ |
| XML-DSig sign & verify (+ anti-wrapping) | ✅ | ➡️ `bergshamra` (feature) |
| XML-Enc (encrypted assertions) | ✅ | ➡️ `bergshamra` (feature) |
| Detached redirect/SimpleSign signatures | ✅ | ➡️ `bergshamra` (feature) |

Without the `crypto-bergshamra` feature, any operation requiring signing,
verification, or encryption fails closed with `OpenSamlError::Unsupported`;
unsigned message building, metadata, and extraction work feature-free.

The `samlify` crate in this workspace is just `pub use opensaml::*;` — a
familiar crate name, unrelated to the npm package.

## Modules

- `constants` — SAML URNs, bindings, status codes, algorithms, NameID formats.
- `xml` — quick-xml DOM + `extract` engine (local-name XPath subset) and field-sets.
- `template` — default message templates + tag substitution.
- `metadata` — SP/IdP metadata parse and generate.
- `binding` — DEFLATE/base64/escaping, redirect URL + POST form building.
- `entity` / `sp` / `idp` — `EntitySetting`, `ServiceProvider`, `IdentityProvider`.
- `flow` — inbound message decode → validate → (verify/decrypt) → extract.
- `logout` — Single Logout create/parse.
- `validator` — `verify_time`, `check_status`.
- `crypto` (feature `crypto-bergshamra`) — key/cert loading, XML-DSig
  sign/verify (+ anti-wrapping), XML-Enc encrypt/decrypt, detached signatures.

## Features

```toml
[features]
default = []
crypto-bergshamra = ["dep:bergshamra"]  # XML crypto; off by default
```

With `crypto-bergshamra`, verification uses bergshamra's `trusted_keys_only`
(accept only metadata-declared IdP keys) and `strict_verification` (reject
out-of-position signed references) — plus an explicit XML Signature Wrapping
guard in `crypto::verify`.
