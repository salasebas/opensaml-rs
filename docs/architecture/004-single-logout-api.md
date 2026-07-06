# Typed Single Logout API

Single Logout should mirror the typed SSO style: start, receive, respond, and
finish with typed correlation.

## Logout Subject

```rust
pub struct LogoutSubject {
    name_id: NameId,
    session_index: Option<SessionIndex>,
}

impl SsoSession {
    pub fn logout_subject(&self) -> Option<LogoutSubject>;
}
```

`logout_subject` returns `None` if the login session does not contain enough
SAML subject data for logout.

## Options

```rust
pub struct StartSlo {
    binding: LogoutBinding,
    relay_state: Option<RelayState>,
    signing: LogoutSigning,
}

pub struct RespondSlo {
    binding: LogoutBinding,
    relay_state: Option<RelayState>,
    signing: LogoutSigning,
}

pub enum LogoutSigning {
    FollowLocalPolicy,
    Sign,
    DoNotSignForCompatibility,
}
```

Avoid a bare `want_signed: bool` in typed SLO.

## Starting Logout

Prefer explicit methods on both local roles for rustdoc readability.

```rust
impl Saml<Sp> {
    pub fn start_slo(
        &self,
        idp: &IdpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError>;
}

impl Saml<Idp> {
    pub fn start_slo(
        &self,
        sp: &SpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError>;
}
```

`PendingLogoutRequest` should include:

- request ID;
- RelayState as exact tri-state: absent, present empty, or present value;
- peer entity ID;
- selected logout binding;
- issue instant;
- expiration if configured.

`PendingLogoutRequest` exposes accessors and a
`PendingSnapshot<LogoutRequest>` persistence shape. Reconstruct with
`Pending::from_snapshot(snapshot)`, validating peer entity ID, logout binding,
timing, and RelayState state. The snapshot stores no keys, raw metadata, or raw
entity settings.

## Receiving LogoutRequest

```rust
impl Saml<Sp> {
    pub fn receive_slo(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError>;
}

impl Saml<Idp> {
    pub fn receive_slo(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError>;
}
```

`Received<LogoutRequest>` exposes:

- request ID;
- issuer;
- NameID;
- parsed inbound session indexes;
- RelayState;
- raw flow.

`receive_slo` uses `SamlValidationContext` for inbound signed, timed, or
replay-sensitive logout request validation.

## Responding to LogoutRequest

```rust
impl Saml<Sp> {
    pub fn respond_slo(
        &self,
        idp: &IdpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError>;
}

impl Saml<Idp> {
    pub fn respond_slo(
        &self,
        sp: &SpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError>;
}
```

Rules:

- `InResponseTo` comes from `Received<LogoutRequest>`.
- `respond_slo` echoes `Received<LogoutRequest>` RelayState by default. An
  explicit `relay_state(RelayStateParam::absent())` suppresses echo, and an
  explicit present RelayState overrides it.
- Callers must not pass arbitrary request ID strings in the typed API.
- Custom LogoutResponse rendering must not silently emit wrong or empty
  `InResponseTo` when a typed request exists.

## Finishing Logout

```rust
impl Saml<Sp> {
    pub fn finish_slo(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingLogoutRequest,
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError>;
}

impl Saml<Idp> {
    pub fn finish_slo(
        &self,
        sp: &SpDescriptor,
        pending: &PendingLogoutRequest,
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError>;
}
```

Rules:

- Use `PendingLogoutRequest` as the only source of expected `InResponseTo`.
- Check pending peer entity ID against the passed descriptor.
- Check inbound binding against the pending expected logout binding.
- Match RelayState exactly: absent, present empty, and present value are
  distinct. If pending expects absent and the inbound message carries
  RelayState, fail unless an explicit compatibility policy permits it.
- Use `SamlValidationContext` for inbound signed, timed, or replay-sensitive
  logout response validation.
- Keep request-ID-less logout response parsing raw/compat only.

## Result

```rust
pub struct LogoutCompleted {
    status: SamlStatus,
    in_response_to: MessageId,
    raw_flow: raw::FlowResult,
}
```
