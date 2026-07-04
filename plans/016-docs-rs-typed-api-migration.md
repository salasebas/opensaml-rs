# Plan 016: Make docs.rs teach the typed Saml API first

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- README.md src/lib.rs examples tests docs plans`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: LOW
- **Depends on**: plans/014-typed-web-sso-facade.md, plans/015-typed-single-logout-facade.md, plans/019-architecture-rfcs-validation-docs.md, plans/020-typed-sso-validation-context.md, plans/021-verified-metadata-trust-boundary.md
- **Category**: docs / dx / tests
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

An API redesign fails if docs.rs still teaches the old stringly typed flow.
Current examples are useful for maintainers but not ideal for users: they show
low-level entities, raw `HttpRequest`, `FlowResult.extract`, and direct access
to internals. This plan makes the typed `Saml` facade the first docs.rs story,
keeps examples executable, and explicitly says which SAML profiles are not yet
supported.

## Current state

- Crate-level docs describe current support and implementation modules, but not
  the typed facade as the first user journey:

  ```rust
  // src/lib.rs:1-11
  //! `saml-rs` - SAML 2.0 **Service Provider** and **Identity Provider** library.
  //!
  //! The crate supports SP/IdP metadata, HTTP-POST, HTTP-Redirect,
  //! HTTP-POST-SimpleSign, browser SSO flows, Single Logout, bounded XML parsing,
  //! and local-name field extraction over `quick-xml`.
  ```

- The only example is a raw signed SSO round trip:

  ```rust
  // examples/sso.rs:55-64
  let request = sp.create_login_request(&idp, Binding::Post, None)?;
  println!("SP  -> AuthnRequest id = {}", request.id);

  let req = HttpRequest::post(vec![("SAMLRequest".into(), request.context.clone())]);
  let parsed = idp.parse_login_request(&sp, Binding::Post, &req)?;
  println!(
      "IdP <- request issuer  = {:?}",
      parsed.extract.get_str("issuer")
  );
  ```

- The README quick start uses undefined variables in snippets and raw result
  access. For example, it currently teaches parsing through `HttpRequest` and
  `FlowResult.extract`.

- docs.rs for the published crate shows implementation modules as primary items
  because the root crate publicly exports them.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| Workspace tests | `cargo nextest run --workspace` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Examples | `cargo check -p saml-rs --examples` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- `src/lib.rs`
- `README.md`
- `examples/*.rs`
- Workspace package READMEs if they mention old root examples
- Doctest-only hidden setup modules, if needed

**Out of scope**:

- Adding new protocol support.
- Rebranding Cargo package names.
- Removing raw compatibility API.
- Pasting private key fixture contents into docs.

## Git workflow

- Suggested branch: `advisor/016-docs-rs-typed-api-migration`
- Commit style: `docs(api): document the typed Saml facade`
- Do not push or open a PR unless the operator instructed it.

## Target docs structure

`src/lib.rs` should have these sections in this order:

1. "Start here" - `Saml` typed facade.
2. "SP-initiated SSO" - start and finish with `Pending<AuthnRequest>`.
3. "IdP-initiated SSO" - separate `accept_unsolicited_sso` method.
4. "Identity Provider flows" - receive AuthnRequest and respond.
5. "Single Logout" - start/receive/respond/finish with typed correlation.
6. "Metadata trust" - explain pinned/explicit metadata trust and do not imply
   public CA validation.
7. "Raw compatibility API" - `saml_rs::raw` for low-level helpers and legacy
   flow results.
8. "Unsupported profiles" - Artifact, SOAP, ECP, SAML queries, NameID
   management, and metadata federation are not supported by the high-level API
   yet. Ask users to open an issue with an interoperability case if they need
   one of those profiles.

Use the public name `Saml`, not `OpenSaml`, in high-level docs. It is fine for
the crate package to remain `saml-rs` in this plan.

## Steps

### Step 1: Rewrite crate-level docs around typed user journeys

Replace implementation-port prose in `lib.rs` with typed API documentation.

Include examples that compile. Use hidden setup blocks where needed:

```rust
/// ```
/// # fn run() -> Result<(), saml_rs::SamlError> {
/// use saml_rs::{
///     BrowserInput, IdpDescriptor, MetadataTrustPolicy, Saml, SsoResponse,
///     SpConfig, SamlValidationContext, StartSso,
/// };
///
/// # let sp_config = SpConfig::example_for_docs();
/// # let idp_metadata = "<EntityDescriptor>...</EntityDescriptor>";
/// # let expected_idp_entity_id = saml_rs::EntityId::new("https://idp.example")?;
/// let sp = Saml::sp(sp_config)?;
/// let idp = IdpDescriptor::from_metadata_xml_for(
///     expected_idp_entity_id,
///     idp_metadata,
///     MetadataTrustPolicy::UnsignedForCompatibility,
/// )?;
///
/// let started = sp.start_sso(&idp, StartSso::redirect())?;
/// # let form_fields = Vec::new();
/// # let validation: SamlValidationContext<'_> =
/// #     unimplemented!("hidden validation context setup");
/// let session = sp.finish_sso(
///     &idp,
///     &started.pending,
///     BrowserInput::<SsoResponse>::post(form_fields),
///     validation,
/// )?;
/// let _name_id = session.subject().name_id().value();
/// # Ok(())
/// # }
/// ```
```

If `example_for_docs()` helpers do not exist, do not add public fake helpers
only for docs. Prefer hidden helper functions inside doctests or use `no_run`
when real metadata/key setup is too long. At least one minimal example should
be a real doctest that compiles.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

### Step 2: Move raw API docs out of the first screen

If old implementation modules still appear as primary docs.rs items, choose the
least disruptive option:

- Add `#[doc(hidden)]` to modules that are now implementation details, but only
  after verifying internal links and workspace packages compile; or
- Leave modules public but rewrite their module docs to start with "Low-level
  raw API; most users should start with `Saml`."

Do not hide modules that downstream users still need for typed examples, such
as public model/config modules.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

### Step 3: Replace README quick start with typed API snippets

Rewrite the README quick start to use typed `Saml` API:

- SP start SSO.
- SP finish SSO.
- IdP receive/respond.
- Metadata generation or metadata peer parsing.
- SLO short example if plan 015 landed.

Keep raw API documentation under an "Advanced/raw compatibility" section.
Use `raw::ServiceProvider` and `raw::IdentityProvider` as the recommended raw
imports. If root `ServiceProvider` and `IdentityProvider` remain visible during
migration, document them as rustdoc-deprecated or compat-only before typed API
stabilization.

Add an unsupported-profile note in polished English:

```markdown
### Unsupported SAML profiles

The high-level `Saml` API currently focuses on browser Web SSO, metadata-driven
SP/IdP setup, XML signature/encryption through `bergshamra`, and Single Logout.
It does not yet implement Artifact resolution, SOAP/back-channel profiles,
ECP/PAOS, SAML query protocols, NameID management, or metadata federation. If
you need one of those profiles for a real interoperability target, please open
an issue with the profile, binding, IdP/SP product, and a minimal expected flow
so we can consider the implementation.
```

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

### Step 4: Expand examples and keep them compiling

Replace or add examples:

- `examples/sp_sso.rs`
- `examples/idp_sso.rs`
- `examples/slo.rs`
- `examples/raw_compat.rs` if the old example is still useful

Rules:

- Examples may use fixture key files by `include_str!`, but do not paste key
  contents into docs.
- Examples should print typed fields, not `extract.get_str(...)`.
- Examples must compile with default features.
- For no-default-features, either examples should be gated or produce an
  explicit message like the current example.

**Verify**: `cargo check -p saml-rs --examples` -> exit 0.

### Step 5: Add compile-fail docs for common misuse

Add doctests that lock in typed invariants:

- Unsupported Artifact binding cannot be passed to high-level browser SSO.
- `finish_sso` cannot accept `Pending<LogoutRequest>`.
- `respond_slo` cannot accept arbitrary request ID strings if plan 015 exposes
  typed `Received<LogoutRequest>`.

Keep compile-fail snippets short. If rustdoc cannot express one invariant
cleanly, add a normal integration test instead and document why.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

### Step 6: Update workspace package docs if needed

If workspace package READMEs exist and mention old examples, update them to
point to the typed `Saml` API and the main README.

Do not add new workspace packages or re-export logic in this docs plan.

**Verify**: `cargo check --workspace --all-targets` -> exit 0.

## Test plan

- Doctests compile for the root typed API docs.
- Examples compile.
- Compile-fail doctests protect typed invariants.
- Workspace check protects any package-level docs/examples that exist.

## Done criteria

- [ ] docs.rs root docs teach `Saml` before raw modules.
- [ ] README quick start uses typed `Saml` API.
- [ ] README explicitly lists unsupported profiles and invites issues for real
  interoperability needs.
- [ ] Examples use typed accessors instead of `FlowResult.extract`.
- [ ] Raw compatibility is documented as advanced.
- [ ] `cargo fmt --all --check` exits 0.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- [ ] `cargo nextest run --workspace` exits 0.
- [ ] `cargo test -p saml-rs --doc` exits 0.
- [ ] `cargo check -p saml-rs --examples` exits 0.
- [ ] `cargo check -p saml-rs --no-default-features` exits 0.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Typed API examples cannot compile without adding public fake constructors.
- Hiding low-level modules breaks workspace packages or rustdoc links.
- A README example needs real private key material pasted into docs.
- The typed SLO API from plan 015 did not land; in that case, keep SLO docs
  raw/compat or mark typed SLO as planned, not implemented.

## Maintenance notes

- docs.rs is part of the API. Keep examples short, executable, and centered on
  user journeys.
- Avoid overclaiming protocol coverage. Being explicit about unsupported SAML
  profiles prevents users from assuming "SAML library" means every SAML profile.
- Keep `Saml` as the high-level product name even if the crate package remains
  `saml-rs` for publishing reasons.
