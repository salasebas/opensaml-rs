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
- Keep non-mechanical diffs reviewable. If a change grows large, split it into
  the smallest coherent stages.

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
- Do not claim support for newer upstream behavior until the changed behavior
  has tests or an explicit tracking note.

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

- Prefer private modules and explicitly exported public crate API.
- Prefer explicit `Result` errors over panics.
- `unwrap_used`, `expect_used`, and `panic` are workspace `warn` lints; under
  `-D warnings` they fail builds, including tests.
- Avoid boolean or ambiguous `Option` parameters in public or SAML flow APIs.
  Prefer enums, named builders, or typed options when they make call sites
  self-documenting.
- When possible, make `match` statements exhaustive and avoid wildcard arms.
- New traits should include doc comments explaining their role and how
  implementations are expected to use them.
- Use inline format arguments, collapse nested `if` statements when clear, and
  prefer method references over redundant closures.
- In tests, return `Result<(), Box<dyn std::error::Error>>` and use `?` instead
  of `.unwrap()` / `.expect()`.
- Prefer focused behavior tests. Compare whole objects when practical, and
  avoid test-only helpers in implementation modules.
- Keep XML handling structured. Avoid ad hoc string parsing when the local DOM,
  extractor, metadata, or binding helpers can express the behavior.
- Keep security-sensitive validation fail-closed. Missing, malformed, unsigned,
  or untrusted inputs should produce explicit `SamlError` variants where
  practical.
- Avoid growing large modules. Prefer new focused modules over extending files
  that are already large, especially `idp.rs`, `logout.rs`, `flow.rs`, and
  `sp.rs`.

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

- Keep README claims aligned with `CHANGELOG.md` and the active upstream pin.
- Do not hardcode future release versions in docs. This workspace uses
  release-plz and Conventional Commits to decide the next version.
- The Rust `samlify` crate is an alias crate, unrelated to the npm package.
