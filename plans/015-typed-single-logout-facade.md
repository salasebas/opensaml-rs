# Plan 015: Add typed Single Logout methods to Saml

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/logout.rs src/api.rs src/saml.rs src/entity.rs tests`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/011-typed-saml-api-contract.md, plans/012-typed-config-policies.md, plans/013-typed-browser-and-domain-models.md, plans/014-typed-web-sso-facade.md, plans/020-typed-sso-validation-context.md
- **Category**: migration / dx / security
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

Single Logout is currently exposed as free functions with long positional
argument lists over raw entity internals and boolean signing flags. That makes
it easy to mix SP/IdP metadata, use the wrong request ID, or accidentally
express unsigned behavior. A typed `Saml` API should make SLO look like a
state-machine flow: start logout, persist pending request, receive or respond,
then finish with correlation.

## Current state

- Logout request creation is a seven-argument free function:

  ```rust
  // src/logout.rs:201-209
  pub fn create_logout_request(
      init_setting: &EntitySetting,
      init_meta: &Metadata,
      target_meta: &Metadata,
      binding: Binding,
      user: &User,
      relay_state: Option<&str>,
      want_signed: bool,
  ) -> Result<BindingContext, SamlError>
  ```

- Logout response creation has the same shape:

  ```rust
  // src/logout.rs:313-321
  pub fn create_logout_response(
      init_setting: &EntitySetting,
      init_meta: &Metadata,
      target_meta: &Metadata,
      binding: Binding,
      in_response_to: Option<&str>,
      relay_state: Option<&str>,
      want_signed: bool,
  ) -> Result<BindingContext, SamlError>
  ```

- Response parsing does require a request ID, but it is still a raw string
  beside raw metadata:

  ```rust
  // src/logout.rs:481-487
  pub fn parse_logout_response(
      self_setting: &EntitySetting,
      from_meta: &Metadata,
      binding: Binding,
      request: &HttpRequest,
      request_id: &str,
  ) -> Result<FlowResult, SamlError>
  ```

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| SLO facade tests | `cargo nextest run -p saml-rs typed_slo` | exit 0 |
| Full crate tests | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- Typed SLO methods on `Saml<Sp>` and `Saml<Idp>`
- Typed `LogoutSubject`, `LogoutOptions`, `LogoutCompleted`, and related models
- Wrappers around current `src/logout.rs`
- Tests in `tests/typed_slo.rs`

**Out of scope**:

- Changing current raw logout free functions except for helper extraction.
- SOAP/back-channel logout.
- Artifact resolution.
- ECP/PAOS, SAML queries, metadata federation, or NameID management protocol.
- Accepting request-ID-less logout response completion in the typed API.

## Git workflow

- Suggested branch: `advisor/015-typed-single-logout-facade`
- Commit style: `feat(api): add typed Single Logout facade`
- Do not push or open a PR unless the operator instructed it.

## Target design

Expose SLO methods on both roles with descriptor-typed peers:

```rust
impl Saml<Sp> {
    pub fn start_slo(
        &self,
        idp: &IdpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError>;

    pub fn receive_slo(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError>;

    pub fn respond_slo(
        &self,
        idp: &IdpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError>;

    pub fn finish_slo(
        &self,
        idp: &IdpDescriptor,
        pending: &Pending<LogoutRequest>,
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError>;
}

impl Saml<Idp> {
    pub fn start_slo(
        &self,
        sp: &SpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError>;

    pub fn receive_slo(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError>;

    pub fn respond_slo(
        &self,
        sp: &SpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError>;

    pub fn finish_slo(
        &self,
        sp: &SpDescriptor,
        pending: &Pending<LogoutRequest>,
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError>;
}
```

Avoid a public generic `Peer` abstraction here. `IdpDescriptor` and
`SpDescriptor` supersede earlier peer wording and are clearer in rustdoc.

## Steps

### Step 1: Add typed logout subject and options

Add `LogoutSubject`:

```rust
pub struct LogoutSubject {
    name_id: NameId,
    session_indexes: Vec<SessionIndex>,
}
```

Add conversion from `SsoSession`:

```rust
impl SsoSession {
    pub fn logout_subject(&self) -> Option<LogoutSubject>;
}
```

Return `None` if the parsed login does not contain enough subject data for SLO.
Do not invent missing NameID/session data.

Add `StartSlo` and `RespondSlo` options:

- `binding: LogoutBinding`
- `relay_state: RelayStateParam` or equivalent exact tri-state input
- `signing: LogoutSigning`

Use an enum for signing policy, not a bare bool:

```rust
pub enum LogoutSigning {
    FollowPolicy,
    Sign,
    DoNotSignForCompatibility,
}
```

Document that `DoNotSignForCompatibility` is an explicit interop exception.

**Verify**: `cargo nextest run -p saml-rs typed_slo` -> tests pass.

### Step 2: Implement start_slo

Map typed values to current `create_logout_request`.

Rules:

- Use the correct local raw `EntitySetting` and local metadata internally.
- Use peer metadata from `IdpDescriptor` or `SpDescriptor`.
- Convert `LogoutSigning` into the existing `want_signed` bool.
- Return `Started<LogoutRequest>`.
- Store request ID, exact RelayState state, peer entity ID, expected logout
  binding, issue instant, and expiration in `Pending<LogoutRequest>`.
- Expose `PendingSnapshot<LogoutRequest>` plus `Pending::from_snapshot` so web
  applications can persist pending state without `serde`.
- The snapshot must not store keys, raw metadata, raw entity settings, or whole
  raw SP/IdP values.

Add tests:

- SP can start SLO to IdP.
- IdP can start SLO to SP if metadata has SLO endpoints.
- `Pending<LogoutRequest>` preserves request ID, RelayState, peer entity ID, and
  binding without storing raw credentials or metadata.
- Artifact cannot be passed through typed options.

**Verify**: `cargo nextest run -p saml-rs typed_slo` -> tests pass.

### Step 3: Implement receive_slo

Map `BrowserInput<LogoutRequest>` to current `parse_logout_request`.

Convert the `FlowResult` into typed `Received<LogoutRequest>`.

Add tests:

- A logout request created by `start_slo` can be received by the peer.
- The typed request exposes ID, issuer, NameID, and session indexes.
- `receive_slo` uses the supplied `SamlValidationContext`.
- Raw flow remains accessible.

**Verify**: `cargo nextest run -p saml-rs typed_slo` -> tests pass.

### Step 4: Implement respond_slo

Map typed request data to current `create_logout_response`.

Rules:

- `InResponseTo` must come from `Received<LogoutRequest>`.
- The caller should not pass an arbitrary string request ID to `respond_slo`.
- Return `Outbound<LogoutResponse>`.
- If a custom LogoutResponse template is used, validate that the generated XML
  either omits `InResponseTo` for unsolicited/compat responses or exactly
  matches the typed received request ID. The current custom-template path can
  fill an empty string; typed SLO should not expose that ambiguity.

Add tests:

- Peer responds to received logout request.
- Response `InResponseTo` equals the typed request ID.
- Custom response template with mismatched `InResponseTo` fails before binding.

**Verify**: `cargo nextest run -p saml-rs typed_slo` -> tests pass.

### Step 5: Implement finish_slo

Map typed response input to current `parse_logout_response`.

Rules:

- Use `Pending<LogoutRequest>` as the only source of the expected request ID.
- Check the pending peer entity ID against the passed descriptor.
- Check inbound binding against the pending expected logout binding.
- Match RelayState exactly using absent, present empty, and present value
  semantics. If pending expects absent and inbound has RelayState, fail unless
  an explicit compatibility policy permits it.
- Use the supplied `SamlValidationContext`.
- Return `LogoutCompleted` with status and raw flow.
- Preserve current error on empty or mismatched request ID.

Add tests:

- Full SP-initiated SLO round trip completes.
- Mismatched pending request ID fails.
- Mismatched RelayState fails with a semantic correlation error.
- Mismatched pending peer entity ID fails.
- Mismatched inbound binding fails.
- Inbound RelayState when pending expected absence fails unless explicitly
  allowed by compatibility policy.
- `parse_logout_response_without_request_id` remains only under raw/compat.

**Verify**: `cargo nextest run -p saml-rs typed_slo` -> tests pass.

### Step 6: Add docs and raw escape hatch notes

Add rustdoc examples for:

- Logout from an `SsoSession`.
- Receiving a logout request and responding.

Explain that SOAP/back-channel logout, Artifact resolution, ECP/PAOS, SAML
queries, NameID management, and metadata federation are not implemented in the
typed facade. Do not claim SAML Artifact or SOAP support.

**Verify**: `cargo test -p saml-rs --doc` -> exit 0.

## Test plan

- `typed_slo` integration tests cover both initiator roles where possible,
  typed request/response parsing, request ID correlation, RelayState
  correlation, explicit signing policy, generated/custom template
  `InResponseTo`, and raw escape hatches.
- Existing `logout.rs` unit tests and conformance tests continue to pass.

## Done criteria

- [ ] Typed SLO methods exist for SP and IdP flows.
- [ ] New SLO API has no long positional argument list and no bare signing bool.
- [ ] `finish_slo` correlates by `Pending<LogoutRequest>` and checks pending
      peer entity ID plus expected binding.
- [ ] `respond_slo` takes `Received<LogoutRequest>`, not an arbitrary string.
- [ ] Typed SLO checks RelayState exact tri-state.
- [ ] Custom LogoutResponse rendering cannot silently emit the wrong
      `InResponseTo`.
- [ ] SOAP, Artifact, and request-ID-less completion remain raw/compat only.
- [ ] `cargo fmt --all --check` exits 0.
- [ ] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [ ] `cargo nextest run -p saml-rs` exits 0.
- [ ] `cargo test -p saml-rs --doc` exits 0.
- [ ] `cargo check -p saml-rs --no-default-features` exits 0.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Generic SLO methods make rustdoc confusing or require complicated trait bounds.
  Prefer duplicate role-specific methods if that is clearer.
- Existing raw SLO functions need behavior changes beyond helper extraction.
- The typed facade would accept an uncorrelated logout response by default.
- A required SLO field is not available from current extraction and cannot be
  added through the structured extractor.

## Maintenance notes

- SLO is lower priority than SSO, but it is where a typed API pays off because
  the current raw function signatures are easy to misuse.
- Reviewers should inspect SP-initiated and IdP-initiated paths separately.
- Keep request-ID-less logout response parsing quarantined in raw compatibility.
