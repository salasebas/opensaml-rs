# Plan 014: Ship the typed Saml Web SSO facade

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/api.rs src/saml.rs src/sp.rs src/idp.rs src/entity.rs src/flow.rs tests examples`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Depends on**: plans/011-typed-saml-api-contract.md, plans/012-typed-config-policies.md, plans/013-typed-browser-and-domain-models.md, plans/017-semantic-error-taxonomy.md, plans/018-type-narrowed-bindings-and-trackers.md, plans/020-typed-sso-validation-context.md
- **Category**: migration / dx / security
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

The main user workflow is browser Web SSO: start login, send the browser to the
IdP, receive a response, validate it, and read the authenticated subject. Today
that requires constructing raw SP/IdP entities, choosing low-level bindings,
building `HttpRequest`, passing request IDs manually, and reading `FlowResult`
paths. This plan makes `Saml<Sp>` and `Saml<Idp>` the primary typed SSO API
while preserving raw access for interop.

## Current state

- SP AuthnRequest creation is currently low-level:

  ```rust
  // src/sp.rs:185-190
  pub fn create_login_request(
      &self,
      idp: &IdentityProvider,
      binding: Binding,
      custom: Option<CustomTagReplacement<'_>>,
  ) -> Result<BindingContext, SamlError>
  ```

- SP response consumption validates important runtime facts but returns raw
  `FlowResult`:

  ```rust
  // src/sp.rs:435-441
  pub fn parse_login_response_with_request_id(
      &self,
      idp: &IdentityProvider,
      binding: Binding,
      request: &HttpRequest,
      request_id: &str,
  ) -> Result<FlowResult, SamlError>
  ```

- The validation path already checks issuer, signature, audience,
  destination/recipient, and `InResponseTo`:

  ```rust
  // src/sp.rs:475-492
  let result = flow_with_expected_recipient(
      &FlowOptions {
          binding: Some(binding),
          parser_type: Some(/* SAML response parser */),
          check_signature: true,
          from_issuer: idp.metadata.get_entity_id(),
          ...
          expected_audience: self.setting.validate_audience.then_some(audience.as_str()),
          expected_in_response_to,
      },
      request,
      recipient.as_str(),
  )?;
  ```

- IdP AuthnRequest parsing and response issuing are also low-level:

  ```rust
  // src/idp.rs:207-213
  pub fn create_login_response(
      &self,
      sp: &ServiceProvider,
      binding: Binding,
      user: &User,
      options: &LoginResponseOptions<'_>,
  ) -> Result<BindingContext, SamlError>

  // src/idp.rs:390-395
  pub fn parse_login_request(
      &self,
      sp: &ServiceProvider,
      binding: Binding,
      request: &HttpRequest,
  ) -> Result<FlowResult, SamlError>
  ```

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| SSO facade tests | `cargo nextest run -p saml-rs typed_sso` | exit 0 |
| Full crate tests | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- `src/api.rs` or `src/saml.rs`
- Typed config/model modules from plans 012-013
- Validation context models from plan 020
- Thin wrappers around `src/sp.rs` and `src/idp.rs`
- Tests in `tests/typed_sso.rs`

**Out of scope**:

- SLO methods. That belongs to plan 015.
- Artifact resolution, SOAP/back-channel profiles, ECP/PAOS, SAML queries,
  NameID management, or metadata federation in the high-level typed API.
- Implementing replay storage. The API may accept caller-provided pending state,
  but the crate should not add Redis, database, or session dependencies.
- Replacing current XML generation or crypto internals.

## Git workflow

- Suggested branch: `advisor/014-typed-web-sso-facade`
- Commit style: `feat(api): add typed Web SSO facade`
- Do not push or open a PR unless the operator instructed it.

## Target design

Expose method-oriented SSO methods:

```rust
impl Saml<Sp> {
    pub fn start_sso(
        &self,
        idp: &IdpDescriptor,
        options: StartSso,
    ) -> Result<Started<AuthnRequest>, SamlError>;

    pub fn finish_sso(
        &self,
        idp: &IdpDescriptor,
        pending: &Pending<AuthnRequest>,
        input: BrowserInput<SsoResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError>;

    pub fn accept_unsolicited_sso(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<SsoResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError>;
}

impl Saml<Idp> {
    pub fn receive_sso(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<AuthnRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<AuthnRequest>, SamlError>;

    pub fn respond_sso(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError>;

    pub fn initiate_sso(
        &self,
        sp: &SpDescriptor,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError>;
}
```

`Subject` should replace `User` in the typed API and map internally to
`crate::raw::User`.

`finish_sso` must require `Pending<AuthnRequest>` for SP-initiated SSO. Keep
`accept_unsolicited_sso` separate and visibly named. Do not make request
correlation optional in the default SP finish method. The typed finish path must
also consume plan 020's explicit clock/replay context; do not call a hidden
`now_utc()` path from typed SSO.

## Steps

### Step 1: Store raw entities privately inside Saml roles

Implement `Saml::sp(config)` and `Saml::idp(config)` from plan 011 using typed
configs from plan 012.

Internally, construct existing raw entities:

- `ServiceProvider::from_config(...)`
- `IdentityProvider::from_config(...)`

Keep them private. Add narrow accessors only if needed:

```rust
impl Saml<Sp> {
    pub fn metadata_xml(&self) -> &str;
    pub fn raw_service_provider(&self) -> &crate::raw::ServiceProvider;
}
```

Name raw accessors with `raw_` so docs.rs makes the boundary obvious.

**Verify**: `cargo nextest run -p saml-rs typed_api_contract` and
`cargo nextest run -p saml-rs typed_config` -> tests pass.

### Step 2: Implement SP start_sso

Map `StartSso` to current `LoginRequestOptions` and
`ServiceProvider::create_login_request_with_options`.

Rules:

- Accept only the narrowed request binding from plan 018, not raw `Binding`.
- Return `Started<AuthnRequest>`.
- The `Pending<AuthnRequest>` must include at least request ID, RelayState,
  selected IdP entity ID, selected ACS endpoint, selected response binding,
  issue instant, and request expiration if the API can determine one.
- `Pending<AuthnRequest>` must expose accessors and a
  `PendingSnapshot<AuthnRequest>` persistence shape; `from_snapshot` validates
  request ID, exact RelayState state, peer entity ID, expected binding, and
  timing before reconstructing pending state.
- The pending snapshot must not store keys, raw metadata, raw entity settings,
  or whole raw SP/IdP values.
- The `Outbound<AuthnRequest>` must separate Redirect and POST/SimpleSign.
- Preserve `ForceAuthn`, ACS index, RelayState, and custom template support
  only if typed options can express them clearly. If custom template support is
  too raw, expose it only under an advanced/raw option with docs.
- If a custom AuthnRequest renderer returns `(id, xml)`, validate that the XML
  contains the same request ID before returning `Pending<AuthnRequest>`.

Add tests:

- Redirect start returns an outbound redirect URL and pending request ID.
- POST start returns a POST form and pending request ID.
- Custom template ID mismatch fails before returning `Started<AuthnRequest>`.
- Artifact cannot be passed to `start_sso` because the type does not allow it.

**Verify**: `cargo nextest run -p saml-rs typed_sso` -> tests pass.

### Step 3: Implement SP finish_sso and unsolicited SSO

Map `BrowserInput<SsoResponse>` plus `SamlValidationContext` to the typed flow
adapter from plan 020, then call the existing SP parsing behavior through the
smallest safe internal wrapper:

- `finish_sso` calls `parse_login_response_with_request_id`.
- `accept_unsolicited_sso` calls `parse_unsolicited_login_response`.

Convert `FlowResult` into `SsoSession`.

Rules:

- `finish_sso` must use the ID from `Pending<AuthnRequest>`, not a raw string
  supplied next to the browser input.
- `finish_sso` must check the pending IdP entity ID against the passed
  `IdpDescriptor`.
- `finish_sso` must check the inbound binding against the pending expected
  response binding.
- The typed finish path must check inbound RelayState using the exact
  tri-state semantics defined by plan 013: absent, present empty, and present
  value are distinct. If pending expects absent and inbound has RelayState,
  fail unless an explicit compatibility policy permits it.
- `accept_unsolicited_sso` must remain a separately named method so the caller
  opts into IdP-initiated SSO intentionally.
- Both response consumption methods must use the caller-supplied
  `SamlValidationContext` for `now`, clock skew, and replay policy.
- Preserve current fail-closed validation behavior.

Add tests:

- Full SP-initiated POST round trip returns typed `SsoSession` with
  `name_id().value() == "alice@example.com"`.
- Passing a mismatched `Pending<AuthnRequest>` ID fails with
  `InResponseToMismatch` or the semantic variant from plan 017.
- Passing a pending value whose peer entity ID does not match the
  `IdpDescriptor` fails.
- Passing a response over a binding that does not match pending state fails.
- Passing a mismatched RelayState fails with a semantic correlation error.
- Passing inbound RelayState when pending expected RelayState absence fails
  unless an explicit compatibility policy permits it.
- Reusing the same assertion/response with `ReplayPolicy::RequireCache` fails.
- An unsolicited response with non-empty `InResponseTo` still fails.

**Verify**: `cargo nextest run -p saml-rs typed_sso` -> tests pass.

### Step 4: Implement IdP receive_sso and respond_sso

Map `receive_sso` to `IdentityProvider::parse_login_request`.

Map `respond_sso` to `IdentityProvider::create_login_response`:

- The typed `Subject` maps to raw `User`.
- `RespondSso` carries binding, relay state, and response protection options.
- `respond_sso` uses `request.message().id()` as `InResponseTo`.
- `initiate_sso` does not require a request and must omit `InResponseTo`.
- `respond_sso` must choose from typed ACS response bindings, not raw
  `Binding::Redirect`; plan 018 should make Redirect SAML Response output
  impossible in the typed SSO API.
- `receive_sso` should validate the AuthnRequest `Destination` against the
  IdP's selected SSO endpoint when the incoming message carries it.
- `receive_sso` must use `SamlValidationContext` for inbound signed, timed, or
  replay-sensitive AuthnRequest validation.

Add tests:

- IdP receives an AuthnRequest and returns typed `Received<AuthnRequest>`.
- IdP responds to the typed request; SP finishes using the pending request.
- IdP-initiated response can be consumed only through
  `accept_unsolicited_sso`.
- `receive_sso` uses the supplied `SamlValidationContext`.

**Verify**: `cargo nextest run -p saml-rs typed_sso` -> tests pass.

### Step 5: Add raw escape hatches on typed results

Ensure each typed result exposes raw data without making it primary:

- `SsoSession::raw_flow() -> &FlowResult`
- `Received<AuthnRequest>::raw_flow() -> &FlowResult`
- `Outbound<M>::raw_context() -> Option<&BindingContext>` or
  `into_raw_context(self) -> BindingContext`

Add tests that raw data remains available.

**Verify**: `cargo nextest run -p saml-rs typed_sso` -> tests pass.

### Step 6: Add minimal rustdoc examples

Add doctests for:

- SP start SSO.
- SP finish SSO shape with hidden setup where needed.
- IdP receive/respond shape.

Use hidden setup and placeholder keys. Do not paste fixture key material.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

## Test plan

- `typed_sso` integration tests cover SP start, SP finish, unsolicited SSO,
  mismatch `InResponseTo`, RelayState mismatch, replay-cache duplicate,
  fixed-clock validation, IdP receive, IdP respond, raw escape hatches, and no
  default Artifact path.
- Existing `conformance.rs` and `flow_conformance.rs` must still pass.
- No-default-features check ensures typed API fails closed where crypto is
  unavailable rather than disappearing.

## Done criteria

- [ ] `Saml::sp(...)` and `Saml::idp(...)` construct typed role facades.
- [ ] SP-initiated SSO can be completed without touching `FlowResult.extract`.
- [ ] SP-initiated SSO finish uses caller-owned clock and replay context.
- [ ] SP-initiated SSO finish checks pending peer entity ID and expected
      binding.
- [ ] RelayState tri-state from pending state is checked on finish.
- [ ] IdP request receive/respond can be completed through typed methods.
- [ ] IdP response creation cannot emit `SsoResponse` over Redirect in the typed API.
- [ ] Unsolicited SSO is a separate opt-in method.
- [ ] Raw escape hatches remain available.
- [ ] No HTTP framework or async dependency was added.
- [ ] `cargo fmt --all --check` exits 0.
- [ ] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [ ] `cargo nextest run -p saml-rs` exits 0.
- [ ] `cargo test -p saml-rs --doc` exits 0.
- [ ] `cargo check -p saml-rs --no-default-features` exits 0.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The typed facade must weaken any existing issuer, audience, destination,
  recipient, signature, or `InResponseTo` validation.
- `Pending<AuthnRequest>` cannot be persisted or reconstructed by a web app
  without private crate internals. If that happens, add a typed serializable
  representation proposal before continuing.
- The typed facade would need to skip plan 020's clock/replay context.
- Implementing this requires changing crypto behavior.
- You need to expose mutable `ServiceProvider.setting` or `IdentityProvider.setting`
  to make the typed API work.

## Maintenance notes

- Reviewers should scrutinize correlation: `finish_sso` must bind to the stored
  pending AuthnRequest.
- Keep examples web-framework-neutral. Use generic form/query data inputs.
- This plan creates the core docs.rs story. Later docs should teach this path
  before any raw API.
