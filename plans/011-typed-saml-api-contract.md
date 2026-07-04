# Plan 011: Establish the typed Saml API contract and raw compatibility boundary

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/lib.rs src/error.rs src/entity.rs src/flow.rs src/sp.rs src/idp.rs src/logout.rs tests`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P0
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: direction / migration / dx
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

The current public API exposes the implementation port from npm `samlify` as the
main docs.rs surface. That makes common SP/IdP web flows depend on low-level
modules, stringly typed extraction, and mutable entity internals. This plan sets
the public contract before implementation work begins: normal users start from
`Saml`, low-level protocol pieces live under `raw` or `compat`, and `FlowResult`
remains an escape hatch rather than the primary typed API.

This is intentionally a breaking pre-1.0 API direction. Do not preserve a poor
surface only for compatibility.

## Current state

- `src/lib.rs` publicly exposes every implementation module:

  ```rust
  // src/lib.rs:17-31
  pub mod binding;
  pub mod constants;
  pub mod context;
  pub mod crypto;
  pub mod entity;
  pub mod error;
  pub mod flow;
  pub mod idp;
  pub mod logout;
  pub mod metadata;
  pub mod sp;
  pub mod template;
  pub mod util;
  pub mod validator;
  pub mod xml;
  ```

- The root re-exports old role types, not a `Saml` facade:

  ```rust
  // src/lib.rs:33-36
  pub use entity::EntitySetting;
  pub use error::SamlError;
  pub use idp::IdentityProvider;
  pub use sp::ServiceProvider;
  ```

- `FlowResult` is dynamic and string-keyed:

  ```rust
  // src/flow.rs:124-132
  pub struct FlowResult {
      pub saml_content: String,
      pub extract: Value,
      pub sig_alg: Option<String>,
  }
  ```

- Outbound messages use one overloaded context field:

  ```rust
  // src/entity.rs:232-250
  pub struct BindingContext {
      pub id: String,
      /// Redirect: the full URL. POST/SimpleSign: the base64 message.
      pub context: String,
      pub relay_state: Option<String>,
      pub entity_endpoint: String,
      pub binding: crate::constants::Binding,
      pub request_type: &'static str,
      pub signature: Option<String>,
      pub sig_alg: Option<String>,
  }
  ```

- `ServiceProvider` and `IdentityProvider` expose mutable internals:

  ```rust
  // src/sp.rs:18-24
  pub struct ServiceProvider {
      pub setting: EntitySetting,
      pub metadata: SpMetadata,
  }

  // src/idp.rs:32-38
  pub struct IdentityProvider {
      pub setting: EntitySetting,
      pub metadata: IdpMetadata,
  }
  ```

- Tests and examples depend on dotted string paths:

  ```rust
  // tests/conformance.rs:120-123
  let request = HttpRequest::post(vec![("SAMLResponse".into(), response.context)]);
  let parsed =
      sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_r1")?;
  assert_eq!(parsed.extract.get_str("nameID"), Some("alice@example.com"));
  ```

- docs.rs for the published crate currently lists implementation modules as the
  crate items, including `binding`, `crypto`, `flow`, `template`, and `xml`.
  That mirrors `lib.rs`, not the API users should start with.

External references checked for API inspiration on 2026-07-04:

- `saml` 0.0.1-alpha.0 on docs.rs has typed config, `StartLogin`,
  `ConsumeResponse`, `Dispatch`, typed algorithms, and caller-owned replay/time
  state.
- `samael` 0.0.21 on docs.rs advertises message serialization/deserialization,
  SSO, assertion validation, and xmlsec-backed signing/verification, but its
  latest docs.rs build failed and its default shape pulls native crypto/XML
  dependencies.

Use those references only for shape comparison. This crate should keep XML
crypto delegated to `bergshamra` and should not add framework, async, serde, or
native C dependency requirements in the typed API wave.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint implementation crate | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| Test implementation crate | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |
| Workspace sanity | `cargo check --workspace --all-targets` | exit 0 |

## Scope

**In scope**:

- `src/lib.rs`
- `src/error.rs`
- New public facade contract modules, if needed:
  - `src/api.rs` or `src/saml.rs`
  - `src/raw.rs`
  - `src/types.rs`
- Minimal tests that prove the new contract compiles:
  - `tests/typed_api_contract.rs`

**Out of scope**:

- Implementing all typed SSO/SLO behavior. That belongs to plans 013-015.
- Renaming the Cargo package or workspace packages.
- Implementing Artifact resolution, SOAP/back-channel profiles, ECP/PAOS, SAML
  queries, NameID management, or metadata federation in the high-level typed
  API.
- Replacing `bergshamra`, adding in-tree XML-DSig/XML-Enc, or adding native C
  dependencies.
- Adding HTTP framework integrations.

## Git workflow

- Suggested branch: `advisor/011-typed-saml-api-contract`
- Commit style: conventional commits, for example `feat(api): add typed Saml facade contract`
- Do not push or open a PR unless the operator instructed it.

## Design decision

Implement a method-oriented role-typed facade:

```rust
pub struct Saml<Role = Unknown> {
    // private fields
}

pub enum Unknown {}
pub enum Sp {}
pub enum Idp {}

impl Saml<Unknown> {
    pub fn sp(config: SpConfig) -> Result<Saml<Sp>, SamlError>;
    pub fn idp(config: IdpConfig) -> Result<Saml<Idp>, SamlError>;
}
```

Do not choose either rejected design:

- Do not keep `FlowResult` as the primary user result. It stays reachable as
  raw/compat data and through `raw_flow()` accessors on typed results.
- Do not build a full typestate graph such as `Saml<Role, Flow, Message,
  Binding, Verified>`. That would increase monomorphization, docs.rs noise, and
  error-message complexity for little benefit.
- Do not make the only public entry point an enum like `exchange(SpOp)`. It is
  compact, but method names such as `start_sso`, `finish_sso`, `receive_sso`,
  and `respond_sso` are more discoverable on docs.rs.

The intended high-level shape after the later plans is:

```rust
let sp = Saml::sp(sp_config)?;
let idp = IdpDescriptor::from_metadata_xml_for(
    expected_idp_entity_id,
    idp_metadata,
    MetadataTrustPolicy::UnsignedForCompatibility,
)?;

let started = sp.start_sso(&idp, StartSso::redirect())?;
store_pending(started.pending.snapshot());
redirect(started.outbound.redirect_url()?);

let input = BrowserInput::<SsoResponse>::post(form_fields);
let validation = SamlValidationContext::new(now, replay_cache)?;
let session = sp.finish_sso(&idp, &started.pending, input, validation)?;
let name_id = session.subject().name_id().value();
```

## Steps

### Step 1: Add a typed API module skeleton

Add a new module such as `src/api.rs` or
`src/saml.rs`. Prefer `api.rs` if the public re-export is still
`Saml`; prefer `saml.rs` if it reads better in rustdoc.

Add these public marker and facade types with doc comments:

- `Saml<Role = Unknown>`
- `Unknown`
- `Sp`
- `Idp`
- `SamlError`

For this first plan, `SamlError` may be a public alias:

```rust
pub type SamlError = crate::error::SamlError;
```

Do not rename every internal `SamlError` use in this plan. The typed API
should document `SamlError`; raw compatibility may continue to expose
`SamlError`.

Add private fields only if the constructors are implemented in this plan.
Otherwise use a private `PhantomData<Role>` field and mark constructors as
`todo!()` only in tests that do not execute. Do not leave runtime `todo!()` in
public methods that are called by tests.

**Verify**: `cargo fmt --all --check` -> exit 0.

### Step 2: Add the raw compatibility module

Add `src/raw.rs` and re-export low-level current types there.
At minimum:

```rust
pub use crate::entity::{BindingContext, EntitySetting, User};
pub use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
pub use crate::idp::{IdentityProvider, LoginResponseOptions};
pub use crate::logout;
pub use crate::metadata;
pub use crate::sp::{LoginRequestOptions, ServiceProvider};
```

Do not move code yet. The goal is a stable place for advanced callers before
later plans reduce root-level docs noise.

**Verify**: `cargo check -p saml-rs` -> exit 0.

### Step 3: Re-export the intended public front door from lib.rs

Update `src/lib.rs` so docs.rs presents the typed API first.
Add root re-exports:

```rust
pub mod api;
pub mod raw;

pub use api::{Idp, Saml, SamlError, Sp, Unknown};
```

Keep old module exports compiling in this plan. If you add `#[doc(hidden)]` to
old modules now, first verify that rustdoc links and workspace packages still build.
It is acceptable to defer hiding old modules to plan 016.
Root-level `ServiceProvider` and `IdentityProvider` may remain only as
compatibility exports during migration; mark them rustdoc-deprecated or
compat-only before typed API stabilization.

Replace the root crate docs with user-facing direction:

- "Start with `Saml` for browser SSO/SLO."
- "`raw` contains the compatibility API and low-level protocol helpers; advanced
  callers should import `raw::ServiceProvider` and `raw::IdentityProvider`
  rather than root compatibility exports."
- "XML signing, verification, encryption, and decryption stay delegated to
  `bergshamra` behind `crypto-bergshamra`."
- "Unsupported SAML profiles such as Artifact resolution, SOAP/back-channel,
  ECP/PAOS, SAML queries, NameID management, and metadata federation are not
  part of this high-level facade yet."

Do not claim typed SSO/SLO methods are implemented until plans 014 and 015 land.
Use "planned" language or only document types that exist.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

### Step 4: Add contract tests for role naming and raw compatibility

Create `tests/typed_api_contract.rs`.

The first test should compile and assert that the new public names are usable:

```rust
use saml_rs::{Idp, Saml, SamlError, Sp};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn saml_role_markers_are_public_api() {
    assert_send_sync::<Saml<Sp>>();
    assert_send_sync::<Saml<Idp>>();
    let _: Option<SamlError> = None;
}
```

If `Saml<Role>` cannot be `Send + Sync` because private internals are not ready,
do not force that bound. Instead assert public type availability with a simpler
generic helper:

```rust
fn accepts_role<T>(_value: Option<T>) {}
accepts_role::<Saml<Sp>>(None);
accepts_role::<Saml<Idp>>(None);
```

Add a second test that proves raw compatibility still exposes the old types:

```rust
#[test]
fn raw_exports_legacy_flow_types() {
    let _ = std::any::type_name::<saml_rs::raw::FlowResult>();
    let _ = std::any::type_name::<saml_rs::raw::BindingContext>();
}
```

**Verify**: `cargo nextest run -p saml-rs typed_api_contract` -> all tests pass.

### Step 5: Add compile-fail documentation for unsupported high-level bindings

In the new API module docs, add a short `compile_fail` example showing that
`Binding::Artifact` is not accepted by the high-level browser binding type.
If plan 013 has not yet added the browser binding type, add the example as
`ignore` with a clear TODO comment and move the actual compile-fail test to
plan 013. Do not add a false compile-fail example.

The intended end state is:

```rust
/// ```compile_fail
/// use saml_rs::{Binding, SsoRequestBinding};
///
/// let binding: SsoRequestBinding = Binding::Artifact;
/// ```
```

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

## Test plan

- `tests/typed_api_contract.rs` checks public facade naming and
  raw compatibility exports.
- Root doctests compile.
- Workspace packages, if any are added later, still compile.

## Done criteria

- [ ] `saml_rs::{Saml, Sp, Idp, SamlError}` is available from the crate root.
- [ ] `saml_rs::raw::{FlowResult, BindingContext, HttpRequest}` is available.
- [ ] Root rustdoc points users to `Saml` first and `raw` second.
- [ ] `cargo fmt --all --check` exits 0.
- [ ] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [ ] `cargo nextest run -p saml-rs` exits 0.
- [ ] `cargo test -p saml-rs --doc` exits 0.
- [ ] `cargo check -p saml-rs --no-default-features` exits 0.
- [ ] `cargo check --workspace --all-targets` exits 0.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The root public module layout in `lib.rs` no longer matches the excerpts.
- Adding `raw` creates a re-export cycle or exposes private items in a way that
  cannot be fixed without moving implementation modules.
- Workspace package checks fail because the public module layout changed.
- The implementation appears to require adding dependencies.
- You discover the crate has already adopted a different typed facade design.

## Maintenance notes

- Reviewers should focus on naming and docs.rs surface, not just compilation.
  This is the API direction that later plans will build on.
- Keep `FlowResult` alive for advanced interop, but do not let new examples
  teach users to read `extract.get_str(...)` as the normal path.
- Keep the public name `Saml`; avoid introducing new "OpenSaml" branded types
  in the high-level API.
