# Plan 013: Add typed browser messages and SAML domain results

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report - do not improvise. When done, update the status row for this plan
> in `plans/README.md` - unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 279c419..HEAD -- src/entity.rs src/flow.rs src/util.rs src/constants.rs tests examples`
>
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/011-typed-saml-api-contract.md, plans/012-typed-config-policies.md, plans/018-type-narrowed-bindings-and-trackers.md
- **Category**: migration / dx / tests
- **Planned at**: commit `279c419`, 2026-07-04

## Why this matters

The typed facade cannot be good if it only wraps `FlowResult` and
`BindingContext`. Users need typed outbound browser actions, typed request IDs,
typed subjects, typed attributes, and typed parsed SAML messages. This plan adds
those model types as adapters around current internals before wiring the full
SSO/SLO facade.

## Current state

- One `BindingContext` field means either a full Redirect URL or a base64 POST
  payload:

  ```rust
  // src/entity.rs:237-238
  /// Redirect: the full URL. POST/SimpleSign: the base64 message.
  pub context: String,
  ```

- The same type offers `post_form()` even when the binding is Redirect:

  ```rust
  // src/entity.rs:253-266
  pub fn post_form(&self) -> String {
      crate::binding::saml_post_binding_form_with_signature(
          &self.entity_endpoint,
          self.request_type,
          &self.context,
          self.relay_state.as_deref(),
          self.sig_alg.as_deref(),
          self.signature.as_deref(),
      )
  }
  ```

- Inbound parsed data is a generic tree:

  ```rust
  // src/util.rs:7-21
  pub enum Value {
      Null,
      Str(String),
      Array(Vec<Value>),
      Object(Vec<(String, Value)>),
  }
  ```

- Callers read fields through strings:

  ```rust
  // tests/flow_conformance.rs:239-245
  let parsed = idp.parse_login_request(&sp, binding, &request)?;
  assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));
  ```

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Format | `cargo fmt --all --check` | exit 0 |
| Lint | `cargo clippy -p saml-rs --all-targets -- -D warnings` | exit 0 |
| Tests | `cargo nextest run -p saml-rs typed_models` | exit 0 |
| Full crate tests | `cargo nextest run -p saml-rs` | exit 0 |
| Doc tests | `cargo test -p saml-rs --doc` | exit 0 |
| Feature boundary | `cargo check -p saml-rs --no-default-features` | exit 0 |

## Scope

**In scope**:

- New typed model module, for example `src/model.rs`
- New browser transport module, for example `src/browser.rs`
- Existing conversion helpers in `src/entity.rs` only if needed
- Tests in `tests/typed_models.rs`

**Out of scope**:

- Implementing `Saml<Sp>::start_sso` or `finish_sso`. That belongs to plan 014.
- Implementing typed XML serialization/deserialization for the entire SAML
  schema.
- Replacing the XML extractor. This plan adapts existing extracted `Value` into
  typed models.
- Removing `FlowResult` or `BindingContext`.

## Git workflow

- Suggested branch: `advisor/013-typed-browser-and-domain-models`
- Commit style: `feat(api): add typed SAML browser and result models`
- Do not push or open a PR unless the operator instructed it.

## Target design

Add these public types:

```rust
pub struct RequestId(String);
pub struct AssertionId(String);
pub struct RelayState(String);
pub enum RelayStateState {
    Absent,
    PresentEmpty,
    PresentValue(RelayState),
}
pub struct EntityId(String);
pub struct EndpointUrl(String);
pub struct FormField {
    name: String,
    value: String,
}
pub struct PostForm {
    action: EndpointUrl,
    fields: Vec<FormField>,
}

pub struct NameId {
    value: String,
    format: Option<NameIdFormat>,
}

pub struct Attribute {
    name: String,
    name_format: Option<String>,
    values: Vec<AttributeValue>,
}

pub struct Attributes(Vec<Attribute>);

pub struct Subject {
    name_id: NameId,
    confirmations: Vec<SubjectConfirmation>,
}

pub struct AuthnSession {
    session_index: Option<SessionIndex>,
    not_on_or_after: Option<SamlInstant>,
}

pub enum BrowserInput<Message> {
    Redirect { raw_query: String, _message: PhantomData<Message> },
    Post { fields: Vec<FormField>, _message: PhantomData<Message> },
    SimpleSignPost { raw_body: String, fields: Vec<FormField>, _message: PhantomData<Message> },
}

pub enum Outbound<Message> {
    Redirect { id: RequestId, url: String, relay_state: Option<RelayState> },
    Post { id: RequestId, form: PostForm, relay_state: Option<RelayState> },
    SimpleSignPost { id: RequestId, form: PostForm, relay_state: Option<RelayState> },
}

pub struct Pending<Message> {
    id: RequestId,
    relay_state: RelayStateState,
    request_binding: Option<SsoRequestBinding>,
    response_binding: Option<SsoResponseBinding>,
    peer_entity_id: EntityId,
    _message: PhantomData<Message>,
}

pub struct PendingSnapshot<Message> {
    id: String,
    relay_state: RelayStateState,
    peer_entity_id: String,
    expected_binding: String,
    issued_at: Option<SamlInstant>,
    expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}

pub struct Started<Message> {
    pub pending: Pending<Message>,
    pub outbound: Outbound<Message>,
}
```

Add typed message/result structs:

- `AuthnRequest`
- `SsoResponse`
- `Assertion`
- `SsoSession` or `Login`
- `LogoutRequest`
- `LogoutResponse`
- `LogoutCompleted`
- `Received<Message>`

Each parsed result that comes from current flow must keep a raw escape hatch:

```rust
impl SsoSession {
    pub fn raw_flow(&self) -> &crate::raw::FlowResult;
}
```

Do not expose mutable public fields on these models. Use accessors. Keep owned
`String`s for now; avoid lifetime-heavy models until profiling proves a need.

## Steps

### Step 1: Add typed scalar wrappers

Implement the ID, entity, endpoint, relay, NameID, and attribute wrapper types.

Rules:

- Constructors should validate only cheap, local invariants.
- `RequestId::new("")` must return an error.
- RelayState matching is exact tri-state: absent, present empty, and present
  value are distinct. `RelayState` preserves an explicit empty value; use
  `RelayStateState` or equivalent to represent absence separately.
- `EndpointUrl` should validate absolute HTTP(S) URLs using the existing `url`
  dependency.
- Avoid panics, `unwrap`, or `expect`.

Add tests:

- Empty request IDs fail.
- HTTP(S) endpoint URLs pass; relative URLs fail.
- `Debug` for scalar types is acceptable, except any secret types from plan 012.

**Verify**: `cargo nextest run -p saml-rs typed_models` -> tests pass.

### Step 2: Add typed browser input and outbound messages

Implement `BrowserInput<Message>` and `Outbound<Message>`.

Add conversion from `BindingContext`:

```rust
impl<Message> TryFrom<BindingContext> for Outbound<Message> { ... }
```

Conversion rules:

- `Binding::Redirect` becomes `Outbound::Redirect { url: context, ... }`.
- `Binding::Post` becomes `Outbound::Post` and must produce a form only through
  POST-specific accessors.
- `Binding::SimpleSign` becomes `Outbound::SimpleSignPost` and must include
  both `SigAlg` and `Signature` fields. A partial detached signature state must
  fail instead of silently falling back to a plain POST form.
- `Binding::Artifact` returns `SamlError`.

Add accessors:

- `Outbound::id(&self) -> &RequestId`
- `Outbound::relay_state(&self) -> Option<&RelayState>`
- `Outbound::redirect_url(&self) -> Result<&str, SamlError>`
- `Outbound::post_form(&self) -> Result<&PostForm, SamlError>`
- `Outbound::into_raw_context(self) -> BindingContext` if the raw context is
  stored. If raw context is not stored, provide `raw_context(&self)` only when
  available and document the limitation.

Do not let callers call a POST form method on a Redirect without an explicit
error.

**Verify**: `cargo nextest run -p saml-rs typed_models` -> tests pass.

### Step 3: Add typed inbound conversion from HttpRequest

Implement conversions from `BrowserInput<Message>` into the existing
`HttpRequest`:

```rust
impl<Message> TryFrom<BrowserInput<Message>> for crate::raw::HttpRequest { ... }
```

Rules:

- Redirect input must parse the raw query into key/value pairs compatible with
  existing `HttpRequest::redirect`.
- POST input must preserve fields.
- SimpleSign POST input must preserve `SAMLRequest`/`SAMLResponse`, `RelayState`,
  `SigAlg`, and `Signature` when present.
- Typed SimpleSign POST input must take a raw form body, or be constructed from
  raw body/form input, so the library derives signed octets itself. Do not ask
  typed callers for arbitrary detached octets. Raw `HttpRequest` compatibility
  may keep manual detached-octet inputs.

Do not add a dependency on an HTTP abstraction crate.

**Verify**: `cargo clippy -p saml-rs --all-targets -- -D warnings` -> exit 0.

### Step 4: Add typed message parsers from FlowResult

Implement `TryFrom<FlowResult>` or named constructors for typed models:

```rust
impl TryFrom<FlowResult> for AuthnRequest { ... }
impl TryFrom<FlowResult> for SsoSession { ... }
impl TryFrom<FlowResult> for LogoutRequest { ... }
impl TryFrom<FlowResult> for LogoutResponse { ... }
```

Use existing `Value::get_str(...)` internally, but hide those string keys from
public callers.

Minimum typed fields:

- `AuthnRequest`: `id`, `issuer`, `destination`, `acs_url`, `force_authn`,
  `name_id_policy` when available, and `raw_flow`.
- `SsoSession`: `response_id`, `assertion_id` when available, `issuer`,
  `in_response_to`, `subject`, `name_id`, multi-valued `attributes`,
  `authn_session`, `audience`, `recipient`, `not_before`, `not_on_or_after`,
  `sig_alg`, and `raw_flow`.
- `LogoutRequest`: `id`, `issuer`, `name_id`, `session_indexes`, `destination`,
  and `raw_flow`.
- `LogoutResponse`: `id`, `issuer`, `in_response_to`, `status`, and `raw_flow`.

If a field is not currently extracted, do not parse XML by string search. Either
add a structured extractor field in the existing extractor system or omit the
accessor with a TODO in the plan PR description.

**Verify**: `cargo nextest run -p saml-rs typed_models` -> tests pass.

### Step 5: Add characterization tests against existing flows

Use existing fixtures and helpers from current tests. Do not paste key material.

Add tests that:

- Create an unsigned or signed AuthnRequest with existing `ServiceProvider`,
  parse with existing `IdentityProvider`, convert the `FlowResult` into
  `AuthnRequest`, and assert `request.id() == ctx.id`.
- Create a login response, parse with current SP method, convert to
  `SsoSession`, and assert `name_id().value() == "alice@example.com"`.
- Assert typed attributes preserve multiple values and match
  `FlowResult.extract` for at least one existing attribute fixture, if present.
- Convert Redirect, POST, and SimpleSign `BindingContext` into `Outbound`.
- Assert partial SimpleSign state (`SigAlg` without `Signature`, or the reverse)
  is rejected by the typed conversion.
- Assert Artifact conversion fails at the typed boundary.

**Verify**: `cargo nextest run -p saml-rs typed_models` -> all tests pass.

### Step 6: Add pending snapshots

Add `PendingSnapshot<Message>` and accessors on `Pending<Message>`.

Rules:

- `Pending<Message>` keeps private fields.
- `Pending::snapshot()` returns plain owned data that applications can store
  without requiring `serde`.
- `Pending::from_snapshot(snapshot)` validates message type, request ID,
  RelayState state, peer entity ID, expected binding, issue time, and
  expiration before reconstructing typed state.
- Snapshots must not include private keys, certificates, raw metadata XML, raw
  entity settings, or whole raw SP/IdP values.

**Verify**: `cargo nextest run -p saml-rs typed_models` -> tests pass.

## Test plan

- `typed_models` integration tests cover scalar validation, browser transport
  conversion, typed result conversion, raw escape hatches, and unsupported
  Artifact rejection.
- Existing conformance tests remain unchanged in this plan, except helper reuse.
- Doc examples compile without requiring cryptographic fixture key contents.

## Done criteria

- [ ] Typed scalar wrappers and message models are public and documented.
- [ ] `PendingSnapshot<Message>` supports persistence without storing keys or
      raw metadata.
- [ ] `Outbound` separates Redirect, POST, and SimpleSign semantics.
- [ ] `BrowserInput` converts to existing `HttpRequest`.
- [ ] Typed parsed results expose `raw_flow()`.
- [ ] Existing string-key extraction is internal only for new typed models.
- [ ] Artifact is rejected by the high-level browser binding/model boundary.
- [ ] `cargo fmt --all --check` exits 0.
- [ ] `cargo clippy -p saml-rs --all-targets -- -D warnings` exits 0.
- [ ] `cargo nextest run -p saml-rs` exits 0.
- [ ] `cargo test -p saml-rs --doc` exits 0.
- [ ] `cargo check -p saml-rs --no-default-features` exits 0.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- A typed field requires ad hoc XML string parsing to implement.
- `BindingContext` cannot be converted without losing SimpleSign signature
  fields.
- Existing tests show `FlowResult.extract` keys are inconsistent across
  bindings for the same concept.
- You need to add a serialization/deserialization framework to finish this
  adapter layer.

## Maintenance notes

- This plan intentionally does not implement full SAML schema
  serializers/deserializers. It creates typed API results from the existing
  validated flow.
- Reviewers should inspect every `Value::get_str(...)` key used in conversions.
  A typo there is now hidden behind typed accessors, so tests must lock it down.
- Keep models owned and simple. Borrowed XML-backed views can be a later
  performance project if profiling justifies them.
