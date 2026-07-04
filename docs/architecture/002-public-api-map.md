# Public API Map

This document maps the current raw API to the intended typed API.

## Root Exports

Proposed root exports:

```rust
pub use api::{Idp, Saml, Sp, Unknown};
pub use config::{
    AlgorithmPolicy, Credentials, IdpConfig, IdpValidationPolicy, SpConfig,
    SpValidationPolicy, XmlPolicy,
};
pub use descriptor::{IdpDescriptor, SpDescriptor};
pub use error::SamlError;
pub use metadata::{MetadataTrustPolicy, VerifiedIdpMetadata, VerifiedSpMetadata};
pub use model::{
    AcsEndpoint, AuthnRequest, AuthnSession, BrowserInput, LogoutBinding,
    LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSigning,
    LogoutSubject, NameId, Outbound, Pending, PendingSnapshot, Received,
    RelayState, SamlStatus, SloEndpoint, SsoEndpoint, SsoRequestBinding,
    SsoResponse, SsoResponseBinding, SsoSession, StartSlo, StartSso,
    Started, Subject, RespondSlo, RespondSso,
};
pub use browser::{FormField, PostForm};
pub use validation::{ReplayCache, ReplayKey, ReplayPolicy, SamlValidationContext};
```

The exact module names can change during implementation, but root docs should
make these types discoverable.

## Current Raw API

Today:

```rust
let request = sp.create_login_request(&idp, Binding::Post, None)?;

let parsed = idp.parse_login_request(
    &sp,
    Binding::Post,
    &HttpRequest::post(vec![("SAMLRequest".into(), request.context.clone())]),
)?;

let response = idp.create_login_response(
    &sp,
    Binding::Post,
    &user,
    &LoginResponseOptions {
        in_response_to: parsed.extract.get_str("request.id"),
        ..Default::default()
    },
)?;

let result = sp.parse_login_response_with_request_id(
    &idp,
    Binding::Post,
    &HttpRequest::post(vec![("SAMLResponse".into(), response.context)]),
    &request.id,
)?;

let name_id = result.extract.get_str("nameID");
```

This remains available as raw compatibility.

## New Typed API

Target:

```rust
let sp_saml = Saml::sp(sp_config)?;
let idp_descriptor =
    IdpDescriptor::from_metadata_xml_for(expected_idp_entity_id, idp_xml, trust_policy)?;

let started = sp_saml.start_sso(&idp_descriptor, StartSso::post())?;

let request = idp_saml.receive_sso(
    &sp_descriptor,
    BrowserInput::<AuthnRequest>::post(form_fields),
    validation,
)?;

let response = idp_saml.respond_sso(
    &sp_descriptor,
    &request,
    subject,
    RespondSso::post(),
)?;

let session = sp_saml.finish_sso(
    &idp_descriptor,
    &started.pending,
    BrowserInput::<SsoResponse>::post(response_fields),
    validation,
)?;
```

## Mapping Table

| Current | New typed API | Notes |
| --- | --- | --- |
| `ServiceProvider` | `Saml<Sp>` | Active local SP. Current type remains raw. |
| `IdentityProvider` | `Saml<Idp>` | Active local IdP. Current type remains raw. |
| peer `ServiceProvider` | `SpDescriptor` | Peer SP metadata and trust state. |
| peer `IdentityProvider` | `IdpDescriptor` | Peer IdP metadata and trust state. |
| `EntitySetting` | `SpConfig`, `IdpConfig` | Typed config with redacted credentials. |
| raw `Binding` | `SsoRequestBinding`, `SsoResponseBinding`, `LogoutBinding` | Operation-specific binding sets. |
| `Endpoint` | `SsoEndpoint`, `AcsEndpoint`, `SloEndpoint` | Endpoint role matters. |
| `BindingContext` | `Outbound<Message>` | Binding-specific browser output. |
| `HttpRequest` | `BrowserInput<Message>` | Typed inbound browser input. |
| bare request ID string | `Pending<AuthnRequest>`, `Pending<LogoutRequest>`, `PendingSnapshot<_>` | Correlation state. |
| `FlowResult` | `SsoSession`, `Received<_>`, `LogoutCompleted` | Typed results with raw escape hatches. |
| `FlowResult.extract.get_str(...)` | typed accessors | String keys become internal. |

`Pending<Message>` has private fields. Applications persist
`PendingSnapshot<Message>` through accessors and rebuild a pending value with a
validating `Pending::from_snapshot` constructor. Snapshots carry correlation
data only: request ID, exact RelayState state, peer entity ID, expected binding,
and timing metadata. They do not carry keys, raw metadata, or raw entity
settings.

## Compatibility Rule

The typed API is additive first. The raw API remains available:

```rust
use saml_rs::raw::{
    BindingContext, EntitySetting, FlowResult, HttpRequest, IdentityProvider,
    ServiceProvider,
};
```

`raw::ServiceProvider` and `raw::IdentityProvider` are the recommended raw
imports. Root-level `ServiceProvider` and `IdentityProvider` can remain during
the migration window only as rustdoc-deprecated compatibility exports before
typed API stabilization.
