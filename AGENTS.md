# opensaml-rs Agent Guide

This is a Rust workspace for SAML 2.0 Service Provider and Identity Provider
support. Keep this file short and operational: it should tell agents how to
work in the repo, not restate the README.

## Repo Shape

- `crates/opensaml` is the implementation crate. Put protocol, XML, metadata,
  binding, validation, logout, and crypto-adapter changes there.
- `crates/samlify`, `crates/open-saml`, `crates/rust-saml`, `crates/rustsaml`,
  `crates/saml-rs`, and `crates/samlrs` are alias crates. They should remain
  thin re-exports unless the task is explicitly about packaging or crate docs.
- XML cryptography is delegated to `bergshamra` behind the default
  `crypto-bergshamra` feature. Do not add in-tree XML-DSig/XML-Enc
  implementations.
- The workspace forbids unsafe code.

## Working Rules

- Read the nearby code and tests before changing behavior. Prefer existing
  module boundaries and error styles.
- Keep diffs focused. Do not mix documentation cleanup, behavior changes, and
  dependency upgrades unless the task asks for it.
- Use `rg` / `rg --files` for searches.
- Do not commit upstream reference clones or other generated/vendor trees.
- Do not add dependencies without proposing them first. Keep optional
  integrations behind feature flags.
- If a user has local changes, preserve them and work around them.

## Porting Reference

- The npm `samlify` source is a behavioral reference only. The active pin lives
  in `reference/upstream-samlify/VERSION.md`.
- Fetch the pinned source with:

  ```bash
  ./scripts/fetch-upstream-samlify.sh
  ```

- Reference sources live under
  `reference/upstream-samlify/<version>/repository/` and are gitignored.
- When porting upstream behavior, cite or inspect the matching upstream file,
  add a focused Rust test, then implement the Rust equivalent.
- Do not claim full parity with a newer upstream version until the changed
  upstream behavior has tests or an explicit tracking note in `PARITY.md`.

## Checks

Run the narrowest checks that cover the touched code plus plausible side
effects:

```bash
cargo fmt --all --check
cargo clippy -p <crate> --all-targets -- -D warnings
cargo nextest run -p <crate>
```

Use workspace-wide checks when touching shared configuration, workspace
features, release metadata, or multiple crates:

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
```

For crypto feature boundaries, also check:

```bash
cargo check -p opensaml --no-default-features
```

## Rust Style

- Prefer explicit `Result` errors over panics.
- `unwrap_used`, `expect_used`, and `panic` are workspace `warn` lints; under
  `-D warnings` they fail builds, including tests.
- In tests, return `Result<(), Box<dyn std::error::Error>>` and use `?` instead
  of `.unwrap()` / `.expect()`.
- Keep XML handling structured. Avoid ad hoc string parsing when the local DOM,
  extractor, metadata, or binding helpers can express the behavior.
- Keep security-sensitive validation fail-closed. Missing, malformed, unsigned,
  or untrusted inputs should produce explicit `OpenSamlError` variants where
  practical.

## Security-Sensitive Areas

Be especially conservative when changing:

- signature verification or signed-reference selection
- XML parsing limits, DOCTYPE/XXE handling, and extraction
- `InResponseTo`, issuer, audience, destination/recipient, and bearer checks
- HTTP-Redirect DEFLATE handling
- XML-Enc decryption and software RSA key-transport options
- metadata key selection and signed metadata verification

Add regression tests for security fixes.

## Docs And Releases

- Keep README claims aligned with `PARITY.md`, `CHANGELOG.md`, and the active
  upstream pin.
- Do not hardcode future release versions in docs. This workspace uses
  release-plz and Conventional Commits to decide the next version.
- The Rust `samlify` crate is an alias crate, unrelated to the npm package.
