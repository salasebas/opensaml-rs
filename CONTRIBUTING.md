# Contributing

`saml-rs` is an independent, unofficial Rust SAML 2.0 Service Provider and
Identity Provider toolkit.

## Setup

```bash
cargo install --locked cargo-nextest
```

All published workspace packages require Rust 1.88. The default
`crypto-bergshamra` feature uses `bergshamra` 0.8.0 with `kryptering` 0.5 and
preserves the RustCrypto-backed defaults.

## Tests

Verify the package plus plausible side effects:

```bash
cargo fmt --all --check
cargo clippy -p saml-rs --all-targets -- -D warnings
cargo nextest run -p saml-rs
cargo test -p saml-rs --doc
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --no-deps
cargo test -p saml-rs --doc --no-default-features
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --no-deps --no-default-features
cargo check -p saml-rs --no-default-features
```

Do not use `--all-features`. Document-crypto providers are mutually exclusive.
AWS-LC, FIPS, and provider-specific rustdoc run in the Linux `provider-matrix`
job in `.github/workflows/ci.yml`.

`unwrap_used`, `expect_used`, and `panic` are package `warn` lints, so under
`-D warnings` they fail the build, including tests. Prefer returning
`Result<_, Box<dyn std::error::Error>>` and `?` in tests over `.unwrap()`.

## SAML Behavior Work

When adding or changing SAML behavior:

1. Ground the change in the SAML specifications or targeted interoperability
   evidence.
2. Write a focused Rust test.
3. Implement an idiomatic Rust equivalent with explicit errors.
4. Keep XML cryptography (XML-DSig, XML-Enc, C14N) delegated to `bergshamra`
   behind the optional `crypto-bergshamra` feature.

Propose new dependencies before adding them, and keep optional integrations
behind feature flags. Do not commit generated or vendor trees.

Historical fixture provenance is documented in `tests/fixtures/PROVENANCE.md`.

## Pull Requests

Use conventional commit-style PR titles where possible.
