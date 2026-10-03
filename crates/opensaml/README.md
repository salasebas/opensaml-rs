# opensaml

[![crates.io](https://img.shields.io/crates/v/opensaml.svg)](https://crates.io/crates/opensaml)
[![docs.rs](https://img.shields.io/docsrs/opensaml)](https://docs.rs/opensaml)
[![MIT licensed](https://img.shields.io/crates/l/opensaml)](https://github.com/salasebas/saml-rs/blob/main/LICENSE)

Compatibility re-export of [`saml-rs`](https://crates.io/crates/saml-rs). The
implementation, examples, and issue tracker are in
[salasebas/saml-rs](https://github.com/salasebas/saml-rs). This package
is not Shibboleth OpenSAML.

**Status:** maintained with `saml-rs`, and pre-1.0. New projects should depend
on `saml-rs`. The Rust import path here is `opensaml`. `OpenSamlError` is a
deprecated alias of `SamlError`.

**Help:** [open an issue](https://github.com/salasebas/saml-rs/issues) on
the source repository.

## Install

```toml
[dependencies]
opensaml = "0.5"
```

```rust
use opensaml::{Saml, Sp};
```

Feature flags match `saml-rs` and are forwarded to it. With
`default-features = false`, select one crypto provider before calling signing
or encryption APIs. The canonical feature list is in the
[saml-rs README](https://github.com/salasebas/saml-rs/blob/main/README.md#features).

## Use it

Follow the [saml-rs guide](https://github.com/salasebas/saml-rs/blob/main/README.md):

- [Signed SSO example](https://github.com/salasebas/saml-rs/blob/main/examples/sso.rs)
- [Single Logout example](https://github.com/salasebas/saml-rs/blob/main/examples/slo.rs)
- [API reference](https://docs.rs/opensaml)
- [Migration guides](https://github.com/salasebas/saml-rs/blob/main/docs/migrations/README.md)

From a clone of the source repository:

```sh
cargo run -p saml-rs --example sso
```

## Security

`opensaml` 0.5 and later forbid unsafe code and re-export the `saml-rs`
validation and crypto policy. Read the
[saml-rs security notes](https://github.com/salasebas/saml-rs/blob/main/README.md#security)
before production use. This crate has not had an external security audit.

## License

[MIT](https://github.com/salasebas/saml-rs/blob/main/LICENSE).
