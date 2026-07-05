# Plan 018: Add type-narrowed bindings, endpoints, and pending trackers

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/constants.rs src/metadata/generate.rs src/entity.rs src/flow.rs src/sp.rs src/idp.rs tests`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/011-typed-saml-api-contract.md, plans/012-typed-config-policies.md
- **Category**: migration / dx / security
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

The current API represents all bindings with one enum and all metadata
endpoints with one endpoint struct. That was useful for samlify parity, but it
lets illegal or unsupported combinations survive until runtime. The
`danielkov/saml` API has a strong idea worth adopting: use narrower public
types where the SAML profile only permits a subset. This plan adds those types
before the typed facade is wired so plans 013-014 do not build on overloaded
`BindingContext` and raw `String` IDs.

## Current state

- One enum represents every binding currently known to this crate:

  ```rust
  // src/constants.rs:10-19
  pub enum Binding {
      Redirect,
      Post,
      SimpleSign,
      Artifact,
  }
  ```

- Unsupported Artifact reaches runtime branches in SSO paths:

  ```rust
  // src/flow.rs:174
  Binding::Artifact => return Err(SamlError::UndefinedBinding),
  ```

- One endpoint type is used for SSO, SLO, and ACS metadata generation:

  ```rust
  // src/metadata/generate.rs:8-20
  pub struct Endpoint {
      pub binding: Binding,
      pub location: String,
      pub is_default: bool,
  }
  ```

- `BindingContext` overloads Redirect URLs and POST payloads in one field:

  ```rust
  // src/entity.rs:232-250
  pub struct BindingContext {
      pub id: String,
      pub context: String,
      pub relay_state: Option<String>,
      pub entity_endpoint: String,
      pub binding: crate::constants::Binding,
      pub request_type: &'static str,
      pub signature: Option<String>,
      pub sig_alg: Option<String>,
  }
  ```

Reference design checked on 2026-07-04:

- The external `danielkov/saml` RFC set separates a general `Binding` from
  `SsoResponseBinding` and `SsoResponseEndpoint`, making Redirect/SOAP
  impossible for Web Browser SSO responses.

Use that as a pattern, but keep this crate's current support for
HTTP-POST-SimpleSign.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| Focused tests | `cargo nextest run -p saml-rs typed_bindings` | exit 0 |
| Full crate tests | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- New typed model/config modules from plans 011-013, for example:
  - `src/model.rs`
  - `src/browser.rs`
  - `src/config.rs`
- Narrowing helpers around:
  - `src/constants.rs`
  - `src/metadata/generate.rs`
  - `src/entity.rs`
- Tests in `tests/typed_bindings.rs`

**Out of scope**:

- Removing `Binding::Artifact` from raw compatibility.
- Implementing Artifact, SOAP, ECP, query protocols, or NameID management.
- Changing raw `Endpoint` or `BindingContext` behavior before typed adapters
  exist.
- Adding serde as a required dependency. If serialization for pending trackers
  is desired, gate it behind a later optional `serde` feature.

## Git workflow

- Suggested branch: `advisor/018-type-narrowed-bindings`
- Commit style: `feat(api): add typed SAML binding subsets`
- Do not push or open a PR unless the operator instructed it.

## Target design

Add public typed subsets for the supported browser profiles:

```rust
pub enum SsoRequestBinding {
    Redirect,
    Post,
    SimpleSign,
}

pub enum SsoResponseBinding {
    Post,
    SimpleSign,
}

pub enum LogoutBinding {
    Redirect,
    Post,
    SimpleSign,
}

pub struct SsoEndpoint {
    binding: SsoRequestBinding,
    location: EndpointUrl,
}

pub struct AcsEndpoint {
    binding: SsoResponseBinding,
    location: EndpointUrl,
    index: Option<u16>,
    is_default: bool,
}

pub struct SloEndpoint {
    binding: LogoutBinding,
    location: EndpointUrl,
}

pub struct PendingAuthnRequest {
    request_id: MessageId,
    relay_state: RelayStateParam,
    acs: AcsEndpoint,
    response_binding: SsoResponseBinding,
    idp_entity_id: EntityId,
}

pub struct PendingSnapshot<Message> {
    id: String,
    relay_state: RelayStateParam,
    peer_entity_id: String,
    expected_binding: String,
    issued_at: Option<SamlInstant>,
    expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}
```

Naming may differ if plans 012-013 already introduced better names. The rule is
more important than the exact names: illegal Web Browser SSO response bindings
must not be representable in the typed API, and endpoint types must encode
their role. Do not use one `Endpoint` shape for SSO, ACS, and SLO in the typed
API just because raw metadata generation does.

## Steps

### Step 1: Add typed binding subsets

Create typed binding enums in the same public module used by plans 012-013.

Requirements:

- `SsoRequestBinding` maps to raw `Binding::Redirect`, `Binding::Post`, and
  `Binding::SimpleSign`.
- `SsoResponseBinding` maps to raw `Binding::Post` and
  `Binding::SimpleSign`.
- `LogoutBinding` maps to raw `Binding::Redirect`, `Binding::Post`, and
  `Binding::SimpleSign`.
- `TryFrom<Binding> for SsoRequestBinding` rejects `Binding::Artifact`.
- `TryFrom<Binding> for SsoResponseBinding` rejects `Binding::Redirect` and
  `Binding::Artifact`.
- `TryFrom<Binding> for LogoutBinding` rejects `Binding::Artifact`.
- Error on rejection should use the semantic error from plan 017 if that plan
  has landed. Otherwise use the current `SamlError::UndefinedBinding` and
  leave a TODO-free note in the test name.

**Verify**: `cargo nextest run -p saml-rs typed_bindings` -> tests pass.

### Step 2: Add typed endpoint wrappers

Add `SsoEndpoint`, `AcsEndpoint`, and `SloEndpoint` wrappers needed by the typed
config from plan 012.

Rules:

- `AcsEndpoint` must not have a Redirect constructor.
- `SsoEndpoint` must not carry ACS-only fields such as `index` or `is_default`.
- `SloEndpoint` must not carry ACS-only fields either.
- `AcsEndpoint::try_from_raw(Endpoint)` must reject raw endpoints whose binding
  cannot be converted to `SsoResponseBinding`.
- `SsoEndpoint::try_from_raw(Endpoint)` must reject raw Artifact endpoints until
  Artifact is implemented.
- `SloEndpoint::try_from_raw(Endpoint)` must reject raw Artifact endpoints until
  Artifact is implemented.
- Endpoint URL validation should reuse the typed URL/newtype from plan 013 if
  it exists; otherwise use `url::Url` directly and accept absolute HTTP(S)
  URLs only.
- Keep conversion back to raw `Endpoint` for internal metadata generation.

Add tests:

- POST ACS endpoint converts to raw metadata endpoint.
- SimpleSign ACS endpoint converts to raw metadata endpoint.
- Redirect ACS endpoint narrowing fails.
- Artifact ACS endpoint narrowing fails until Artifact is implemented.
- Redirect SSO endpoint narrows successfully.
- SSO and SLO endpoints do not expose ACS `index` or default flags.

**Verify**: `cargo nextest run -p saml-rs typed_bindings` -> tests pass.

### Step 3: Add pending tracker types

Add `PendingAuthnRequest` or reuse `Pending<AuthnRequest>` from plan 013 if it
already exists.

It must carry:

- request ID
- RelayState as exact tri-state: absent, present empty, or present value
- selected ACS endpoint
- selected response binding
- selected IdP entity ID
- issue instant and optional expiration if plan 020 has landed

Do not put the whole raw `ServiceProvider` or `IdentityProvider` inside the
pending tracker. The caller should be able to serialize/store this later
without serializing keys or metadata.

Expose accessors plus `PendingSnapshot<AuthnRequest>` so web applications can
persist state without requiring `serde`. `Pending::from_snapshot(snapshot)` must
validate request ID, RelayState state, peer entity ID, expected binding, issue
time, and expiration before reconstructing typed pending state. Snapshots must
not store private keys, certificates, raw metadata XML, raw entity settings, or
whole raw SP/IdP values.

**Verify**: `cargo nextest run -p saml-rs typed_bindings` -> tests pass.

### Step 4: Wire adapters into the typed API lane

Update the typed API contract or model tests from plans 011-013 so examples use
the narrowed types rather than raw `Binding` where practical.

Do not rewrite raw `ServiceProvider::create_login_request` in this plan. The
typed facade in plan 014 will convert narrowed types into raw calls.

**Verify**: `cargo check -p saml-rs --all-targets` -> exit 0.

## Test plan

- New `tests/typed_bindings.rs`.
- Test all `TryFrom<Binding>` success/failure cases.
- Test endpoint constructors and raw conversion.
- Test pending tracker preserves ID, RelayState state, IdP entity ID, ACS, and
  response binding.
- Test `PendingSnapshot<AuthnRequest>` round trips through validation and stores
  no keys or raw metadata.

## Done criteria

- [x] Typed browser request and response binding subsets exist.
- [x] ACS endpoints cannot be constructed with Redirect or Artifact in typed
      API code.
- [x] SSO, ACS, and SLO endpoint wrappers do not share one public typed struct.
- [x] Pending AuthnRequest state carries selected IdP entity ID, ACS, response
      binding, and exact RelayState state.
- [x] `PendingSnapshot<AuthnRequest>` persists correlation state without keys or
      raw metadata.
- [x] Raw compatibility types remain available.
- [x] `cargo fmt --all --check` exits 0.
- [x] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [x] `cargo nextest run -p saml-rs` exits 0.
- [x] `cargo check -p saml-rs --no-default-features` exits 0.
- [x] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Plans 012-013 already introduced incompatible type names; ask the reviewer
  whether to adapt this plan or mark it superseded.
- Enforcing narrowed types would require changing raw metadata parsing behavior
  in the same PR.
- The implementation starts requiring serde or a new dependency.
- A verification command fails twice after a reasonable fix attempt.

## Maintenance notes

This plan is a foundation for plan 014. Reviewers should focus on whether the
typed API makes illegal SSO response bindings impossible while preserving raw
escape hatches for compatibility and future Artifact support.
