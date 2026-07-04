# Plan 017: Standardize semantic SAML error variants

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/error.rs src/flow.rs src/sp.rs src/idp.rs src/logout.rs src/validator.rs src/crypto tests`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/011-typed-saml-api-contract.md
- **Category**: migration / security / dx
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

The current error enum still carries several samlify-style string codes and
generic `Invalid(String)`, `Xml(String)`, and `Crypto(String)` buckets. That
makes the public API harder to branch on, harder to document, and easier to
regress because unrelated validation failures collapse into the same variant.
The `danielkov/saml` design gets one important thing right: each security
validation rule should map to a semantic error variant. This plan applies that
lesson without copying its crypto implementation.

## Current state

- `SamlError` is already `#[non_exhaustive]`, which allows adding variants
  without forcing every downstream match to break:

  ```rust
  // src/error.rs:4-7
  #[derive(Debug, thiserror::Error)]
  #[non_exhaustive]
  pub enum SamlError {
  ```

- Several variants are still opaque buckets:

  ```rust
  // src/error.rs:14-22
  Xml(String),
  Invalid(String),
  Unsupported(String),
  ```

- Important protocol failures exist, but names and payloads are inconsistent:

  ```rust
  // src/error.rs:24-39
  UnmatchIssuer,
  UnmatchAudience,
  UnmatchDestination,
  InvalidInResponseTo,
  UndefinedStatus,
  FailedStatus { top: String, second: String },
  ```

- Validation currently returns those variants from the flow layer:

  ```rust
  // src/flow.rs:525-545
  return Err(SamlError::UnmatchIssuer);
  return Err(SamlError::InvalidInResponseTo);
  return Err(SamlError::UnmatchAudience);
  ```

- Some security-sensitive crypto errors are string-only:

  ```rust
  // src/crypto/verify.rs:82-126
  SamlError::Crypto("ERR_EXTERNAL_REFERENCE".into())
  SamlError::Crypto("ERR_UNRESOLVED_REFERENCE".into())
  ```

Reference design checked on 2026-07-04:

- The external `danielkov/saml` RFC set documents one `Error` enum where
  distinct validation rules get distinct variants.
- Its current `src/error.rs` includes variants such as `IssuerMismatch`,
  `DestinationMismatch`, `InResponseToMismatch`, `AudienceMismatch`,
  `SignatureMissing`, `DisallowedAlgorithm`, `ReferenceResolution`, and
  `StatusNotSuccess`.

Use those as API inspiration only. Do not import code.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| Focused tests | `cargo nextest run -p saml-rs error` | exit 0 |
| Full crate tests | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- `src/error.rs`
- Error construction sites in:
  - `src/flow.rs`
  - `src/sp.rs`
  - `src/idp.rs`
  - `src/logout.rs`
  - `src/validator.rs`
  - `src/crypto/verify.rs`
  - `src/crypto/sign.rs`
  - `src/crypto/enc.rs`
- Focused tests in `tests/error_taxonomy.rs`
- Existing tests that assert old variants and must be migrated carefully

**Out of scope**:

- Replacing `bergshamra` or implementing XML-DSig/XML-Enc in-tree.
- Redesigning every public method to return typed results. That belongs to
  plans 013-015.
- Removing legacy variants in the same PR if doing so creates a broad churn
  spike. Prefer adding semantic variants first, then migrating call sites.
- Changing wire validation behavior. This plan changes error shape, not
  whether invalid SAML is accepted or rejected.

## Git workflow

- Suggested branch: `advisor/017-semantic-error-taxonomy`
- Commit style: `refactor(error): add semantic SAML validation errors`
- Do not push or open a PR unless the operator instructed it.

## Target design

Keep `SamlError` as the canonical error type for now. Add semantic variants
with useful payloads where the caller can act or log precisely:

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SamlError {
    #[error("issuer mismatch: expected {expected}, got {actual:?}")]
    IssuerMismatch {
        expected: String,
        actual: Option<String>,
    },

    #[error("destination mismatch: expected {expected}, got {actual:?}")]
    DestinationMismatch {
        expected: String,
        actual: Option<String>,
    },

    #[error("inResponseTo mismatch: expected {expected:?}, got {actual:?}")]
    InResponseToMismatch {
        expected: Option<String>,
        actual: Option<String>,
    },

    #[error("relay state mismatch")]
    RelayStateMismatch {
        expected: RelayStateState,
        actual: RelayStateState,
    },

    #[error("audience restriction not satisfied: expected {expected}")]
    AudienceMismatch {
        expected: String,
    },

    #[error("status not success: top={top}, second={second:?}")]
    StatusNotSuccess {
        top: String,
        second: Option<String>,
    },

    #[error("signature missing where required")]
    SignatureMissing,

    #[error("required binding parameter missing: {name}")]
    MissingBindingParameter {
        name: &'static str,
    },

    #[error("signature verification failed: {reason}")]
    SignatureVerification {
        reason: &'static str,
    },

    #[error("signed reference could not be resolved: {reason}")]
    ReferenceResolution {
        reason: &'static str,
    },

    #[error("signed reference does not cover consumed payload")]
    SignedReferenceMismatch,

    #[error("no trusted certificate could be selected for verification")]
    NoTrustedCertificate,

    #[error("SAML time window is invalid for {field}")]
    TimeWindowInvalid {
        field: &'static str,
    },

    #[error("subject confirmation is not satisfied: {reason}")]
    SubjectConfirmationInvalid {
        reason: &'static str,
    },

    #[error("replayed SAML message or assertion")]
    ReplayDetected {
        key: String,
    },

    #[error("unsupported binding: {binding:?}")]
    UnsupportedBinding {
        binding: crate::constants::Binding,
    },

    // Keep existing bucket variants for lower-level adapter errors during the
    // transition.
}
```

Names do not have to match this snippet exactly, but they must be semantic,
documented, and branchable with `matches!`.

## Steps

### Step 1: Add semantic variants without changing behavior

Add the new variants and doc comments to `src/error.rs`.

Keep legacy variants temporarily:

- `UnmatchIssuer`
- `UnmatchAudience`
- `UnmatchDestination`
- `InvalidInResponseTo`
- `FailedStatus`
- `UndefinedBinding`
- `MissingSigAlg`
- `FailedToVerifySignature`
- `FailedMessageSignatureVerification`
- `UnmatchCertificate`
- `Crypto(String)`

Add private helper constructors only when they reduce repeated payload assembly.
Avoid `From<&str>` implementations that hide which validation rule failed.

**Verify**: `cargo fmt --all --check` -> exit 0.

### Step 2: Migrate status and context validation errors

Update `src/validator.rs` and `src/flow.rs`
first because they contain the highest-value validation rules:

- issuer mismatch
- destination mismatch
- `InResponseTo` mismatch
- audience mismatch
- non-success status
- subject confirmation failure, with the best available reason
- expired / not-yet-valid condition when the current code can distinguish it
- replay duplicate from plan 020, if that plan has landed first

When the current code does not have the actual value available, either extract
it from the existing `Value` tree or use `actual: None`. Do not add ad hoc XML
parsing just to fill an error payload.

Add tests in `tests/error_taxonomy.rs` that exercise at least:

- bad issuer returns `IssuerMismatch`
- bad destination returns `DestinationMismatch`
- bad audience returns `AudienceMismatch`
- bad `InResponseTo` returns `InResponseToMismatch`
- non-success status returns `StatusNotSuccess`

Use existing hardening fixtures/tests as the pattern; do not paste private key
fixtures into the plan or into new docs.

**Verify**: `cargo nextest run -p saml-rs error_taxonomy` -> tests pass.

### Step 3: Migrate binding and detached-signature errors

Update binding/flow errors where the public caller benefits from branching:

- `Binding::Artifact` on unsupported front-channel paths should become
  `UnsupportedBinding { binding: Binding::Artifact }` or a more specific
  `UnsupportedProfile`.
- Missing `Signature`, missing `SigAlg`, missing `SAMLRequest`/`SAMLResponse`,
  missing `RelayState` correlation input, and missing detached octet strings
  should become distinct semantic missing-parameter variants. Today
  `src/flow.rs:387-392` maps all of these detached-signature cases to
  `MissingSigAlg`; do not preserve that ambiguity in the typed API.
- RelayState correlation must distinguish absent, present empty, and present
  value. For SP-initiated SSO/SLO, if pending state expects absence and inbound
  has RelayState, return a semantic mismatch unless an explicit compatibility
  policy permits the extra parameter.
- Failed Redirect/SimpleSign verification should become
  `SignatureVerification { reason: "detached message signature" }`.

Keep compatibility tests for the old variants only if raw compatibility still
requires them. Prefer migrating tests to semantic variants.

**Verify**: `cargo nextest run -p saml-rs flow_conformance` -> tests pass.

### Step 4: Migrate crypto adapter string errors where safe

In `src/crypto/verify.rs`, convert high-level structural
failures into branchable errors:

- external reference -> `ReferenceResolution` or `SignatureVerification`
- unresolved reference -> `ReferenceResolution`
- verified reference does not cover consumed content -> `SignedReferenceMismatch`
- no selected certificate -> `NoTrustedCertificate` or `SignatureVerification`
- inline certificate mismatch against metadata -> a trust/certificate mismatch
  variant rather than a generic crypto string
- metadata signature without covered consumed descriptor -> the same
  `SignedReferenceMismatch` family used for messages

Do not unwrap or parse bergshamra internals beyond what the adapter already
exposes. If an error only exists as an opaque backend string, keep
`Crypto(String)`.

**Verify**:
`cargo nextest run -p saml-rs xsw` and
`cargo nextest run -p saml-rs flow_conformance` -> tests pass.

### Step 5: Document the taxonomy

Add rustdoc to `SamlError` grouping variants by category:

- wire/XML
- signature/crypto
- SAML protocol validation
- metadata/trust
- configuration
- unsupported profiles

Add a short module-level note that `SamlError` is `#[non_exhaustive]` and
callers should include a fallback match arm.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

## Test plan

- New `tests/error_taxonomy.rs`.
- Migrate existing assertions in `hardening.rs`, `flow_conformance.rs`,
  `logout.rs` tests, and crypto/XSW tests only where the code path changes.
- Keep one test proving generic backend errors still surface as `Crypto(_)`
  when no semantic mapping is available.

## Done criteria

- [ ] `SamlError` has semantic variants for issuer, destination,
      `InResponseTo`, audience, non-success status, missing/failed signatures,
      unsupported binding/profile, signed-reference mismatch, replay duplicate,
      and trusted-certificate selection.
- [ ] At least five focused tests assert the new semantic variants.
- [ ] Existing security tests still pass.
- [ ] `cargo fmt --all --check` exits 0.
- [ ] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [ ] `cargo nextest run -p saml-rs` exits 0.
- [ ] `cargo check -p saml-rs --no-default-features` exits 0.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Changing the error shape requires changing public return types outside
  `SamlError`.
- The live code no longer has the validation paths cited in "Current state".
- You need to alter acceptance/rejection behavior to make tests pass.
- A semantic mapping would require inspecting unstable `bergshamra` internals.
- A verification command fails twice after a reasonable fix attempt.

## Maintenance notes

Reviewers should check that this PR does not weaken fail-closed validation.
The API value is in making failures more precise, not in accepting more SAML.
Future typed facade work should expose this same error type as `SamlError`
unless a later plan deliberately wraps it.
