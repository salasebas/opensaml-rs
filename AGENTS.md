# opensaml-rs Agent Guide

Standalone Rust workspace for SAML 2.0 Service Provider support.

## Crates

- `opensaml` — all SAML SP logic: HTTP bindings (POST form, Redirect query,
  DEFLATE, base64, escaping) plus documented stubs for metadata, AuthnRequest,
  response parsing, and logout. `#![forbid(unsafe_code)]`, no business deps
  beyond `base64`, `flate2`, `quick-xml`, `thiserror`, `url`.
- `samlify` — thin re-export (`pub use opensaml::*;`). No logic of its own. It
  is a Rust crate-name alias, unrelated to the npm `samlify` package.
- XML cryptography (XML-DSig, XML-Enc, C14N) is delegated to the `bergshamra`
  crate behind the optional `crypto-bergshamra` feature (off by default in M0).

## Reference

`samlify` (npm, tag `v2.10.2`) is the behavioral/porting reference. Sources live
under `reference/upstream-samlify/2.10.2/repository/` (gitignored). If missing,
run `./scripts/fetch-upstream-samlify.sh`. Do not commit upstream clones.

## Acceptance Guide

Verify only the crates you touched plus plausible side effects. Default loop:

```bash
cargo fmt --all --check
cargo clippy -p <crate> --all-targets -- -D warnings
cargo nextest run -p <crate>
```

`unwrap_used`, `expect_used`, and `panic` are workspace `warn` lints, so under
`-D warnings` they fail the build — including tests. Prefer returning
`Result<_, Box<dyn std::error::Error>>` and `?` in tests over `.unwrap()`.

## Dependencies

Propose new dependencies before adding them. Keep optional integrations (e.g.
`bergshamra`) behind feature flags.
