# Raw compatibility

The typed API is additive. The current flow API remains available because
removing it would strand integrations that still need direct XML.

## Why raw stays

The current API remains useful for:

- migration;
- unusual interop behaviour;
- tests and conformance fixtures;
- callers that need direct XML, `FlowResult`, or `BindingContext`;
- cases where typed support has not yet been built.

## Proposed Raw Module

```rust
pub mod raw {
    pub use crate::constants::Binding;
    pub use crate::entity::{BindingContext, EntitySetting, User};
    pub use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
    pub use crate::idp::{IdentityProvider, LoginResponseOptions};
    pub use crate::logout;
    pub use crate::metadata;
    pub use crate::sp::{LoginRequestOptions, ServiceProvider};
}
```

## Current Raw Flow

This remains supported:

```rust
use saml_rs::raw::{
    Binding, HttpRequest, IdentityProvider, LoginResponseOptions, ServiceProvider,
};

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

`raw::ServiceProvider` and `raw::IdentityProvider` are the recommended imports
for advanced raw callers. Typed docs should not import those role types from
the crate root.

## Root-Level Compatibility

During the migration window, these may remain available at the crate root:

```rust
pub use idp::IdentityProvider;
pub use sp::ServiceProvider;
pub use entity::EntitySetting;
```

Root-level `ServiceProvider` and `IdentityProvider` stay available for older
imports. Their rustdoc points a new integration at `Saml`, and these notes
describe the typed API first.

## Raw Escape Hatches From Typed Results

Typed results should expose raw data intentionally:

```rust
impl SsoSession {
    pub fn raw_flow(&self) -> &raw::FlowResult;
}

impl<Message> Received<Message> {
    pub fn raw_flow(&self) -> &raw::FlowResult;
}

impl<Message> Outbound<Message> {
    pub fn raw_context(&self) -> &raw::BindingContext;
    pub fn into_raw_context(self) -> raw::BindingContext;
}
```

Rules:

- Raw accessors are named with `raw_`.
- Typed notes describe the typed path. `FlowResult.extract` stays a raw
  escape, because presenting it as the normal result would hide the checks
  the typed session already performed.
- Raw compatibility does not weaken typed validation rules. A typed success
  has already applied those rules; the raw view is the same message, not a
  second, looser verdict.
- Raw logout parsers do not receive the actual local endpoint. Their
  `FlowResult` therefore does not claim that `Destination` was compared with
  the receiving endpoint; direct raw callers own that check.
- Raw `HttpRequest` compatibility may keep manual detached-octet inputs for
  SimpleSign interop; typed `BrowserInput` should derive those octets itself
  from raw browser form input.
