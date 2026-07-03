# Contributing

opensaml-rs is an independent, unofficial Rust SAML 2.0 Service Provider and
Identity Provider toolkit. It is not affiliated with, maintained by, endorsed
by, or sponsored by the npm `samlify` package or its authors; the `samlify`
crate here is only a Rust crate-name alias and shares no code with the npm
package.

## Setup

```bash
./scripts/fetch-upstream-samlify.sh   # local porting reference only
cargo install --locked cargo-nextest
```

The default `crypto-bergshamra` feature requires Rust 1.85 because the
`bergshamra` 0.6.3 dependency graph reaches `kryptering` 0.4.1 and
`crypto-bigint` 0.7.5, which declares Rust 1.85.

## Tests

Verify only the crates you touched plus plausible side effects:

```bash
cargo fmt --all --check
cargo clippy -p <crate> --all-targets -- -D warnings
cargo nextest run -p <crate>
```

`unwrap_used`, `expect_used`, and `panic` are workspace `warn` lints, so under
`-D warnings` they fail the build — including tests. Prefer returning
`Result<_, Box<dyn std::error::Error>>` and `?` in tests over `.unwrap()`.

## Porting Work

`samlify` (npm, pinned in `reference/upstream-samlify/VERSION.md`) is the
behavioral/porting reference. The original conformance port targets v2.10.2;
new porting work compares against the active pin. When porting behavior:

1. Read the active pin in `reference/upstream-samlify/VERSION.md`.
2. Inspect the matching sources under
   `reference/upstream-samlify/<version>/repository/`.
3. Write a focused Rust test.
4. Implement an idiomatic Rust equivalent with explicit errors.
5. Keep XML cryptography (XML-DSig, XML-Enc, C14N) delegated to `bergshamra`
   behind the optional `crypto-bergshamra` feature.

Propose new dependencies before adding them, and keep optional integrations
behind feature flags. Do not commit upstream clones.

## Pull Requests

Use conventional commit-style PR titles where possible.
