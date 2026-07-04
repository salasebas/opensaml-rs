# Plan 021: Make signed metadata trust and verified descriptors explicit

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/metadata src/crypto src/sp.rs src/idp.rs src/entity.rs tests`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/011-typed-saml-api-contract.md, plans/017-semantic-error-taxonomy.md, plans/019-architecture-rfcs-validation-docs.md
- **Category**: security / api / metadata
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

Metadata parsing, metadata signature verification, and peer construction are
currently separate low-level operations. A caller can verify signed metadata and
then accidentally keep using an unverified descriptor value. The typed API
should make trust status visible in the type names: raw parsed metadata is not
the same as a verified peer descriptor.

This borrows the useful idea from `danielkov/saml` that metadata trust is a
first-class boundary, while preserving this crate's `bergshamra` delegation and
not adding federation, CA, or XML security implementations in-tree.

## Current state

- Raw metadata parsing returns role metadata without trust status:

  ```rust
  // src/metadata/mod.rs:64-92
  pub struct Metadata {
      xml: String,
      pub(crate) meta: Value,
  }
  ```

- Metadata signature verification returns only `bool`:

  ```rust
  // src/metadata/mod.rs:184-195
  pub fn verify_signature_with_limits(
      &self,
      trusted_certs: &[String],
      limits: XmlLimits,
  ) -> Result<bool, SamlError> {
      crate::crypto::verify_metadata_signature_with_limits(&self.xml, trusted_certs, limits)
  }
  ```

- The crypto adapter can return signed content for general XML verification, but
  the metadata helper discards that detail:

  ```rust
  // src/crypto/verify.rs:338-345
  pub fn verify_metadata_signature_with_limits(
      xml: &str,
      trusted_certs: &[String],
      limits: XmlLimits,
  ) -> Result<bool, SamlError> {
      Ok(verify_signature_with_limits(xml, trusted_certs, limits)?.0)
  }
  ```

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| Focused tests | `cargo nextest run -p saml-rs metadata_trust` | exit 0 |
| Full crate tests | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- Typed trust policy and verified metadata/peer descriptor wrappers.
- Metadata signature verification result that preserves covered signed content
  or explicitly documents when only a boolean is available.
- Tests proving verified peer construction cannot be confused with raw parsed
  metadata.

**Out of scope**:

- Federation metadata aggregation, metadata refresh schedulers, PKIX chain
  validation, or public CA trust.
- Replacing `bergshamra`.
- In-tree XML-DSig, canonicalization, or XML-Enc.
- Changing raw metadata parsing behavior before typed wrappers exist.

## Git workflow

- Suggested branch: `advisor/021-verified-metadata-trust-boundary`
- Commit style: `feat(metadata): add verified metadata peer boundary`
- Do not push or open a PR unless the operator instructed it.

## Target design

Add explicit trust-state types in the typed API lane:

```rust
pub struct ParsedMetadata<R> {
    raw: crate::metadata::Metadata,
    role: core::marker::PhantomData<R>,
}

pub struct VerifiedIdpMetadata {
    raw: crate::metadata::Metadata,
    verified_xml: String,
    trust: MetadataTrust,
}

pub struct VerifiedSpMetadata {
    raw: crate::metadata::Metadata,
    verified_xml: String,
    trust: MetadataTrust,
}

pub struct MetadataTrust {
    pub trusted_certificate: CertificateFingerprint,
}

pub enum MetadataTrustPolicy<'a> {
    UnsignedForCompatibility,
    RequireSignature { trusted_certs: &'a [CertificatePem] },
}
```

Keep generic verified metadata helpers private if they are useful internally.
Public API names should be role-specific (`VerifiedIdpMetadata` and
`VerifiedSpMetadata`) so callers do not confuse role markers with trust state.

Exact field names can change, but the API must preserve these boundaries:

- raw parsed metadata can create an explicitly unverified peer only when the
  caller chooses compatibility policy;
- signed metadata verification must fail closed when the signature does not
  cover the consumed `<EntityDescriptor>`;
- trusted certificates are caller-pinned metadata trust anchors, not a CA store.

## Steps

### Step 1: Add typed trust policy and parsed metadata wrappers

Add typed wrappers for SP and IdP peer descriptors that distinguish:

- parsed but unverified metadata;
- verified metadata;
- compatibility-accepted unsigned metadata.

Do not remove `IdpMetadata::from_xml` or `SpMetadata::from_xml`; they remain raw
compatibility constructors.

**Verify**: `cargo nextest run -p saml-rs metadata_trust` -> tests pass.

### Step 2: Preserve verified metadata coverage

Update the metadata verification helper or add a new typed helper that returns a
structured verification result:

```rust
pub struct MetadataSignatureVerification {
    pub verified: bool,
    pub signed_entity_descriptor_xml: Option<String>,
}
```

Rules:

- The typed `RequireSignature` path must require `verified == true`.
- It must also require `signed_entity_descriptor_xml` to cover the descriptor
  that will be parsed into the peer.
- If the backend cannot provide coverage detail, return a semantic error from
  plan 017 rather than silently accepting a boolean.

**Verify**: `cargo nextest run -p saml-rs metadata_signature` -> tests pass.

### Step 3: Wire typed peer constructors

Update typed descriptor constructors from plans 011-012 so call sites are
explicit and bind the expected entity ID:

```rust
let idp = IdpDescriptor::from_metadata_xml_for(
    expected_idp_entity_id,
    xml,
    MetadataTrustPolicy::RequireSignature { trusted_certs: &[cert] },
)?;
```

`from_metadata_xml(xml, trust)` may remain only as a convenience for callers
that explicitly accept the entity ID found in metadata.

For deployments that pin metadata out of band, allow an explicit compatibility
constructor or policy name such as `UnsignedForCompatibility`. Avoid names like
`insecure: true`.

**Verify**: `cargo nextest run -p saml-rs metadata_trust` -> tests pass.

### Step 4: Add docs and examples

Add rustdoc examples for:

- verified IdP descriptor construction from signed metadata;
- explicit unsigned compatibility construction;
- no-default-features behavior where metadata crypto verification is
  unsupported and fails closed.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

## Test plan

- `tests/metadata_trust.rs` covers verified and explicit unsigned policy.
- `tests/metadata_signature.rs` covers bad signature, missing trust anchor,
  signature that verifies but does not cover the consumed descriptor, and
  duplicate-ID/XSW metadata cases if fixtures already exist.
- Existing metadata parsing tests continue to pass.

## Done criteria

- [ ] Typed peer descriptors carry an explicit trust state.
- [ ] Signed metadata verification preserves descriptor coverage.
- [ ] Unsigned metadata is accepted only through an explicitly named
      compatibility path.
- [ ] No CA/federation/storage dependency was added.
- [ ] `bergshamra` remains the XML security backend.
- [ ] `cargo fmt --all --check` exits 0.
- [ ] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [ ] `cargo nextest run -p saml-rs` exits 0.
- [ ] `cargo test -p saml-rs --doc` exits 0.
- [ ] `cargo check -p saml-rs --no-default-features` exits 0.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The signed metadata helper cannot determine which XML was covered.
- The typed peer API would make unverified metadata look like verified
  metadata.
- The implementation starts requiring PKIX, online metadata refresh, or a new
  XML security backend.
- A no-default-features build would expose a typed constructor that appears to
  verify metadata but cannot.

## Maintenance notes

This plan is intentionally separate from plan 019. Plan 019 records the
architecture decision; this plan gives the public API enough type information to
enforce that decision in real call sites.
