# opensaml-rs Agent Guide

Standalone Rust workspace for SAML 2.0 Service Provider support.

## Crates

- `opensaml` — SAML 2.0 Service Provider **and** Identity Provider logic ported
  to parity with npm `samlify` v2.10.2: constants, XML extraction (quick-xml),
  templates, metadata parse/generate, the three bindings (HTTP-POST,
  HTTP-Redirect, HTTP-POST-SimpleSign), entity/flow orchestration, time/status
  validation, and Single Logout. XML cryptography (XML-DSig sign/verify with
  anti-wrapping, XML-Enc encrypt/decrypt, detached message signatures) is
  delegated to the `bergshamra` crate behind the optional `crypto-bergshamra`
  feature (off by default). `#![forbid(unsafe_code)]`.
- `samlify` — thin re-export (`pub use opensaml::*;`). No logic of its own. It
  is a Rust crate-name alias, unrelated to the npm `samlify` package. Forwards
  the `crypto-bergshamra` feature.
- XML cryptography is delegated to `bergshamra`; without the feature, signing,
  verification, and encryption fail closed with `OpenSamlError::Unsupported`.

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
