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

## Dependency Updates

Do not update every dependency to the latest version in one PR. Parser,
crypto, and routine maintenance updates need separate review lanes.

For `quick-xml` PRs, inspect `crates/opensaml/src/xml/dom.rs` and
`crates/opensaml/src/xml/extract.rs`. Add parser regression tests when behavior
changes, then run the parser and flow checks from plan 007:

```bash
cargo nextest run -p opensaml xml::dom
cargo nextest run -p opensaml --test robustness
cargo nextest run -p opensaml --test redirect_inflate_limit
cargo nextest run -p opensaml
cargo check -p opensaml --no-default-features
cargo deny check advisories
cargo audit --ignore RUSTSEC-2023-0071
```

For `bergshamra` or crypto-adjacent PRs, inspect `DsigContext`, `verify`,
`verify_all`, `VerifiedReference`, XML-Enc RSA key transport, and the
`RUSTSEC-2023-0071` policy. Run the matrix from plans 008 and 009, including:

```bash
cargo nextest run -p opensaml --test xsw
cargo nextest run -p opensaml --test hardening
cargo nextest run -p opensaml --test flow_conformance
cargo nextest run -p opensaml
cargo nextest run --workspace
cargo check -p opensaml --no-default-features
cargo tree -p opensaml -i rsa
cargo deny check advisories
cargo audit
```

Once plan 008 lands, also test no-default behavior with
`cargo nextest run -p opensaml --no-default-features`. If
`RUSTSEC-2023-0071` remains no-fixed, explain in the PR summary why the deny
ignore remains and confirm software RSA key-transport decryption is still
disabled by default. If the advisory becomes fixed or the dependency graph no
longer reaches `rsa`, remove the stale ignore and update README or security
text.

Alias crates should remain thin re-exports. Workspace checks cover them when
root dependency metadata changes. Dependency PRs may change compatibility code,
tests, and directly relevant docs only; rebrand, typed SAML models,
Artifact/SOAP/ECP/query/NameID management, and metadata federation work require
separate plans.

Fixture private keys are public test fixtures only. Never paste their values
into generated reports, plans, or PR bodies. Rotate any fixture credential that
was ever reused outside tests.

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
