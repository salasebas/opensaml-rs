# saml-rs Agent Guide

This is a Rust package for SAML 2.0 Service Provider and Identity Provider
support. Keep this file short and operational: it should tell agents how to
work in the repo, not restate the README.

## Repo Shape

- `src/` contains the implementation. Put protocol, XML, metadata, binding,
  validation, logout, and crypto-adapter changes there.
- `tests/` contains integration tests and committed fixtures.
- `examples/` contains runnable examples.
- XML cryptography is delegated to `bergshamra` behind the default
  `crypto-bergshamra` feature. Do not add in-tree XML-DSig/XML-Enc
  implementations.
- The package forbids unsafe code.

## Working Rules

- Read the nearby code and tests before changing behavior. Prefer existing
  module boundaries and error styles.
- Keep diffs focused. Do not mix documentation cleanup, behavior changes, and
  dependency upgrades unless the task asks for it.
- Use `rg` / `rg --files` for searches.
- Do not commit generated/vendor trees.
- Do not add dependencies without proposing them first. Keep optional
  integrations behind feature flags.
- If a user has local changes, preserve them and work around them.
- Keep non-mechanical diffs reviewable. If a change grows large, split it into
  the smallest coherent stages.
- New SAML behavior must follow `docs/standards-conformance.md`.

## Standards Conformance

- Read `docs/standards-conformance.md` before adding or changing SAML
  generation, parsing, validation, bindings, profiles, or metadata behavior.
- Cite and verify the applicable OASIS standard, schema, profile/binding, and
  approved errata. Identify the obligated actor, condition, and scope.
- A producer `MUST` or `MUST NOT` does not automatically require a receiver to
  reject non-conforming input. Add rejection only when an applicable normative
  receiver or schema rule requires it.
- Mandatory requirements are always enforced. Recommendations are default-on
  and may be relaxed only by an explicit, narrowly named policy. Optional
  capabilities require intentional configuration.
- Scope conformance claims by role, direction, profile or flow, binding, and
  feature. Lower-level XML support does not imply conformance with a complete
  profile, binding, or SAML V2.0 as a whole.
- MUST NOT retroactively change existing behavior, defaults, or public APIs
  solely to align them with the conformance policy unless the task explicitly
  authorizes that change. If existing behavior appears to predate or conflict
  with the policy, preserve it, report the normative evidence and compatibility
  or security impact, and ask for direction before changing it.
- Do not present library safety or application policy as an OASIS wire
  requirement, and do not invent validation for unspecified behavior.

## Fixture Provenance

- Historical fixture provenance is documented in
  `tests/fixtures/PROVENANCE.md`.
- Do not commit fetched upstream clones or other local reference trees.

## Checks

Run the narrowest checks that cover the touched code plus plausible side
effects:

```bash
cargo fmt --all --check
cargo clippy -p saml-rs --all-targets -- -D warnings
cargo nextest run -p saml-rs
```

When touching shared configuration, release metadata, or feature boundaries,
also check:

```bash
cargo test -p saml-rs --doc
RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc -p saml-rs --lib --all-features --no-deps
cargo test -p saml-rs --doc --no-default-features
cargo check -p saml-rs --no-default-features
```

## Rust Style

- Prefer private modules and explicitly exported public crate API.
- Prefer explicit `Result` errors over panics.
- `unwrap_used`, `expect_used`, and `panic` are package `warn` lints; under
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

- Keep README claims aligned with `CHANGELOG.md`.
- Do not hardcode future release versions in docs. This repository uses
  release-plz and Conventional Commits to decide the next version.
- The published crate is `saml-rs`, and Rust imports use `saml_rs`.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in GitHub Issues via the `gh` CLI. See
`docs/agents/issue-tracker.md`.

### Triage labels

The default five-role triage label vocabulary is used. See
`docs/agents/triage-labels.md`.

### Domain docs

Domain documentation uses the single-context layout. See
`docs/agents/domain.md`.
