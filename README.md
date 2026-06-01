# opensaml-rs

SAML 2.0 **Service Provider** and **Identity Provider** for Rust, ported to
parity with npm [`samlify`](https://www.npmjs.com/package/samlify) v2.10.2:
metadata, the three HTTP bindings (POST, Redirect, POST-SimpleSign),
AuthnRequest/Response, Single Logout, and the inbound flow with signature
verification, decryption, and anti-wrapping protection. XML cryptography
(XML-DSig, XML-Enc, C14N) is delegated to
[`bergshamra`](https://crates.io/crates/bergshamra). `#![forbid(unsafe_code)]`.

## Crates

| Crate | Description |
|-------|-------------|
| [`opensaml`](crates/opensaml) | The library: constants, XML extraction, templates, metadata, bindings, SP/IdP entities, flow, and crypto. |
| [`samlify`](crates/samlify) | Thin re-export of `opensaml` under a familiar crate name (`pub use opensaml::*;`). |

> `samlify` here is only a Rust crate name; it is an independent, unofficial
> project and shares no code with the npm `samlify` package.

## Quick start

```toml
[dependencies]
opensaml = "0.0.1"   # XML crypto on by default; disable with default-features = false
```

```sh
cargo run -p opensaml --example sso   # signed SSO round-trip
```

See [`crates/opensaml/README.md`](crates/opensaml/README.md) for the full API,
feature flags, and the security model.

## Status

Pre-1.0 (APIs may change). Feature-complete against samlify v2.10.2, with the
upstream test suite ported 1:1, plus production hardening: `<Audience>`
restriction, `InResponseTo` binding, XSW attack-vector tests, metadata-key
pinning, and metadata signature verification. Not yet externally audited —
review before production use.

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## License

[MIT](LICENSE).
