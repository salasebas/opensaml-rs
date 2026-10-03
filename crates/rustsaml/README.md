# rustsaml

[![crates.io](https://img.shields.io/crates/v/rustsaml.svg)](https://crates.io/crates/rustsaml)
[![docs.rs](https://img.shields.io/docsrs/rustsaml)](https://docs.rs/rustsaml)
[![MIT licensed](https://img.shields.io/crates/l/rustsaml)](https://github.com/salasebas/saml-rs/blob/main/LICENSE)

**Deprecated.** `rustsaml` will no longer be maintained. Please use
[`saml-rs`](https://crates.io/crates/saml-rs).

```toml
[dependencies]
saml-rs = "0.5"
```

```rust
use saml_rs::{Saml, Sp};
```

The import path changes from `rustsaml` to `saml_rs`. The API is the same.

This package remains a compatibility re-export, so existing dependencies keep
resolving. Do not add `rustsaml` to a new project.

The implementation, examples, and issue tracker are in
[salasebas/saml-rs](https://github.com/salasebas/saml-rs).

**Help:** [open an issue](https://github.com/salasebas/saml-rs/issues) on
the source repository.

## Use saml-rs

Follow the [saml-rs guide](https://github.com/salasebas/saml-rs/blob/main/README.md):

- [Signed SSO example](https://github.com/salasebas/saml-rs/blob/main/examples/sso.rs)
- [Single Logout example](https://github.com/salasebas/saml-rs/blob/main/examples/slo.rs)
- [API reference](https://docs.rs/saml-rs)
- [Migration guides](https://github.com/salasebas/saml-rs/blob/main/docs/migrations/README.md)

From a clone of the source repository:

```sh
cargo run -p saml-rs --example sso
```

## Security

Read the
[saml-rs security notes](https://github.com/salasebas/saml-rs/blob/main/README.md#security)
before production use. This crate has not had an external security audit.

## License

[MIT](https://github.com/salasebas/saml-rs/blob/main/LICENSE).
