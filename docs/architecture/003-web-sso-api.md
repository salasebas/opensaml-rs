# Typed Web SSO API

This document describes the typed browser Web SSO API.

## SP-Initiated Login

```rust
let sp_saml = Saml::sp(sp_config)?;
let idp_descriptor =
    IdpDescriptor::from_metadata_xml_for(expected_idp_entity_id, idp_metadata_xml, trust)?;

let started = sp_saml.start_sso(
    &idp_descriptor,
    StartSso::redirect()
        .relay_state(relay_state)
        .response_binding(SsoResponseBinding::Post),
)?;

store_pending(started.pending.snapshot());
send_to_browser(started.outbound);
```

Method:

```rust
impl Saml<Sp> {
    pub fn start_sso(
        &self,
        idp: &IdpDescriptor,
        options: StartSso,
    ) -> Result<Started<AuthnRequest>, SamlError>;
}
```

`Started<AuthnRequest>`:

```rust
pub struct Started<Message> {
    pub pending: Pending<Message>,
    pub outbound: Outbound<Message>,
}
```

`Pending<AuthnRequest>` should include:

- request ID;
- RelayState as exact tri-state: absent, present empty, or present value;
- IdP entity ID;
- selected ACS endpoint;
- expected response binding;
- issue instant;
- expiration if configured or derivable.

`Pending<AuthnRequest>` (also exported as `PendingAuthnRequest`) has private
fields, but web applications need durable storage. Provide accessors plus a
serializable-without-`serde` `PendingSnapshot<AuthnRequest>` value.
`Pending::snapshot()` returns the snapshot, and
`Pending::from_snapshot(snapshot)` validates required fields, entity ID syntax,
binding values, ACS data, and timing before reconstructing typed pending state.
The snapshot stores no keys, raw metadata, or raw entity settings.

## Finishing SP-Initiated Login

```rust
let pending = Pending::<AuthnRequest>::from_snapshot(load_pending_snapshot())?;

let input = BrowserInput::<SsoResponse>::post(form_fields);

let validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut replay_cache))
    .with_clock_skew(clock_skew);

let session = sp_saml.finish_sso(&idp_descriptor, &pending, input, validation)?;
```

Method:

```rust
impl Saml<Sp> {
    pub fn finish_sso(
        &self,
        idp: &IdpDescriptor,
        pending: &Pending<AuthnRequest>,
        input: BrowserInput<SsoResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError>;
}
```

Rules:

- `finish_sso` must use the request ID from `Pending<AuthnRequest>`.
- `finish_sso` must check the pending peer entity ID against the passed
  `IdpDescriptor`.
- `finish_sso` must check the inbound binding against the pending expected
  response binding.
- `finish_sso` must match RelayState exactly: absent, present empty, and
  present value are distinct. If pending expects absent and the inbound message
  carries RelayState, fail unless an explicit compatibility policy permits it.
- `finish_sso` must use caller-owned `now`, clock skew, and replay policy.
- `finish_sso` must not accept unsolicited responses.

## IdP-Initiated Login

IdP-initiated SSO is supported, but it must be visibly opt-in.

```rust
let session = sp.accept_unsolicited_sso(
    &idp,
    BrowserInput::<SsoResponse>::post(form_fields),
    validation,
)?;
```

Method:

```rust
impl Saml<Sp> {
    pub fn accept_unsolicited_sso(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<SsoResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError>;
}
```

Rules:

- This method should reject responses with non-empty `InResponseTo`.
- The name must stay explicit. Avoid generic `parse_login_response` as the
  typed default.

## IdP Receiving AuthnRequest

```rust
let idp_saml = Saml::idp(idp_config)?;
let sp_descriptor =
    SpDescriptor::from_metadata_xml_for(expected_sp_entity_id, sp_metadata_xml, trust)?;

let request = idp_saml.receive_sso(
    &sp_descriptor,
    BrowserInput::<AuthnRequest>::redirect(raw_query),
    validation,
)?;
```

Method:

```rust
impl Saml<Idp> {
    pub fn receive_sso(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<AuthnRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<AuthnRequest>, SamlError>;
}
```

Rules:

- Validate issuer and signature according to IdP policy.
- Validate AuthnRequest `Destination` against this IdP's SSO endpoint when the
  request carries `Destination`.
- Use `SamlValidationContext` for inbound signed, timed, or replay-sensitive
  AuthnRequest validation.
- Validate requested ACS URL/index against SP metadata before response
  issuance.
- When `AssertionConsumerServiceIndex` is used, resolve the indexed ACS from
  SP metadata and infer the response binding from that endpoint. If a caller
  also sets `response_binding`, it must match the indexed ACS binding.

## IdP Responding to AuthnRequest

```rust
let outbound = idp_saml.respond_sso(
    &sp_descriptor,
    &request,
    subject,
    RespondSso::post(),
)?;
```

Methods:

```rust
impl Saml<Idp> {
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

Rules:

- `respond_sso` gets `InResponseTo` from `Received<AuthnRequest>`, not a raw
  string.
- `respond_sso` echoes `Received<AuthnRequest>` RelayState by default. An
  explicit `relay_state(RelayStateParam::absent())` suppresses echo, and an
  explicit present RelayState overrides it.
- `initiate_sso` omits `InResponseTo`.
- `initiate_sso` does not synthesize RelayState by default.
- Typed SSO responses cannot use Redirect.

## Browser Transport Types

```rust
pub enum BrowserInput<Message> {
    Redirect {
        raw_query: String,
    },
    Post {
        fields: Vec<FormField>,
    },
    SimpleSignPost {
        fields: Vec<FormField>,
        raw_body: String,
    },
}

pub enum Outbound<Message> {
    Redirect {
        id: MessageId,
        url: String,
        relay_state: Option<RelayState>,
    },
    Post {
        id: MessageId,
        form: PostForm,
        relay_state: Option<RelayState>,
    },
    SimpleSignPost {
        id: MessageId,
        form: PostForm,
        relay_state: Option<RelayState>,
    },
}
```

Typed SimpleSign POST input must not ask callers for arbitrary signed octets.
Callers pass parsed fields with `BrowserInput::<M>::simple_sign(fields)` or a
raw form body with `BrowserInput::<M>::simple_sign_body(raw_body)`. The library
parses the form fields and derives the exact octets used for signature
verification. Raw `raw::HttpRequest` compatibility may still accept manual
detached octet data for legacy interop.

Constructors are marker-specific. `BrowserInput<SsoResponse>` exposes POST and
SimpleSign constructors only; a manually constructed Redirect variant is
rejected by typed conversion. `Outbound<SsoResponse>` rejects Redirect raw
contexts.

Raw `BindingContext` should remain available through:

```rust
impl<Message> Outbound<Message> {
    pub fn raw_context(&self) -> &raw::BindingContext;
    pub fn into_raw_context(self) -> raw::BindingContext;
}
```

## Result Types

```rust
pub struct SsoSession {
    // private
}

impl SsoSession {
    pub fn subject(&self) -> &Subject;
    pub fn attributes(&self) -> &Attributes;
    pub fn authn_session(&self) -> &AuthnSession;
    pub fn issuer(&self) -> &EntityId;
    pub fn response_id(&self) -> &MessageId;
    pub fn assertion_id(&self) -> Option<&AssertionId>;
    pub fn in_response_to(&self) -> Option<&MessageId>;
    pub fn raw_flow(&self) -> &raw::FlowResult;
}
```
