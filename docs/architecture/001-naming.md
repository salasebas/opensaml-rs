# Naming Checkpoint

This document records the proposed names before implementation. Names here are
not final until reviewed.

## Crate Names

- Cargo package: `saml-rs`
- Rust import path: `saml_rs`
- Canonical error type: `SamlError`

Do not introduce public names prefixed with `OpenSaml`.

## Active Local Roles

Recommended:

```rust
pub struct Saml<Role = Unknown> {
    // private fields
}

pub enum Unknown {}
pub enum Sp {}
pub enum Idp {}
```

Constructors:

```rust
impl Saml<Unknown> {
    pub fn sp(config: SpConfig) -> Result<Saml<Sp>, SamlError>;
    pub fn idp(config: IdpConfig) -> Result<Saml<Idp>, SamlError>;
}
```

Rationale:

- `Saml<Sp>` and `Saml<Idp>` clearly mean "this crate's active local role".
- The marker type prevents calling IdP-only methods on an SP.
- Internals can remain private, unlike today's raw `ServiceProvider` and
  `IdentityProvider` structs.

## Peer Metadata Names

Recommended:

```rust
pub struct SpDescriptor { /* private */ }
pub struct IdpDescriptor { /* private */ }
```

Rejected:

- `SpPeer` / `IdpPeer`: superseded by `SpDescriptor` / `IdpDescriptor`.
- `ServiceProvider` / `IdentityProvider`: keep for raw compatibility, not the
  primary typed facade.

Rationale:

- A peer in SAML is normally represented by metadata, not by an active local
  role with private settings.
- `Descriptor` is shorthand for trusted peer entity metadata: entity ID, role
  descriptor, keys, endpoints, policies, and trust state.
- `IdpDescriptor` can carry trust state without implying it can issue messages.
- Plans and docs that still say `Peer` should be updated; `Descriptor` is the
  branch source of truth for peer metadata names.

## Raw Compatibility Names

The current public structs stay available under `raw`:

```rust
pub mod raw {
    pub use crate::flow::{FlowResult, HttpRequest};
    pub use crate::entity::{BindingContext, EntitySetting, User};
    pub use crate::sp::ServiceProvider;
    pub use crate::idp::IdentityProvider;
}
```

Root re-exports of `ServiceProvider` and `IdentityProvider` can stay during the
migration window. New docs should prefer `Saml<Sp>` and `Saml<Idp>`.

## Binding Names

Recommended:

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
```

Rationale:

- Web SSO AuthnRequests can use Redirect, POST, and SimpleSign.
- Web SSO Responses should not use Redirect in the typed API.
- Logout has a separate legal binding set.
- Raw `Binding::Artifact` remains available only in raw compatibility until
  Artifact support exists.

## Endpoint Names

Recommended:

```rust
pub struct SsoEndpoint { /* binding: SsoRequestBinding */ }
pub struct AcsEndpoint { /* binding: SsoResponseBinding, index, default */ }
pub struct SloEndpoint { /* binding: LogoutBinding */ }
```

Rationale:

- ACS endpoints have `index` and `is_default`.
- SSO and SLO endpoints do not.
- One generic typed `Endpoint` would keep today's ambiguity.

## Flow State Names

Recommended:

```rust
pub struct Started<Message> {
    pub pending: Pending<Message>,
    pub outbound: Outbound<Message>,
}

pub struct Pending<Message> { /* private */ }
pub struct Received<Message> { /* private */ }
pub struct PendingSnapshot<Message> { /* public data, no keys */ }
```

Message markers:

```rust
pub struct AuthnRequest;
pub struct SsoResponse;
pub struct LogoutRequest;
pub struct LogoutResponse;
```

`Pending<Message>` remains private-field typed state. Web applications persist
`PendingSnapshot<Message>`, rebuilt through validation constructors such as
`Pending::from_snapshot(snapshot)`. Snapshots expose request ID, RelayState
presence/value, peer entity ID, expected binding, and timing metadata, but never
store keys or raw metadata.

## Domain Result Names

Recommended:

```rust
pub struct SsoSession;
pub struct Subject;
pub struct NameId;
pub struct Attributes;
pub struct Attribute;
pub struct AuthnSession;
pub struct LogoutCompleted;
pub struct StartSso;
pub struct RespondSso;
pub struct StartSlo;
pub struct RespondSlo;
pub struct LogoutSubject;
pub struct LogoutSigning;
pub struct SamlStatus;
pub struct PostForm;
pub struct FormField;
```

`Identity` is intentionally not the preferred result name because "identity" is
too broad for a SAML login session. `SsoSession` communicates that this is the
validated result of browser SSO.
