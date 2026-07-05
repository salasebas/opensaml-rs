# Raw Compatibility

The typed API is additive. The current flow API remains available.

## Why Keep Raw

The current API is useful for:

- migration;
- unusual interop behavior;
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

Before typed API stabilization, root-level `ServiceProvider` and
`IdentityProvider` should be rustdoc-deprecated or documented as compat-only.
Docs should still teach the typed API first.

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
- Typed docs should not teach `FlowResult.extract` as the normal path.
- Raw compatibility must not weaken typed validation rules.
- Raw `HttpRequest` compatibility may keep manual detached-octet inputs for
  SimpleSign interop; typed `BrowserInput` should derive those octets itself
  from raw browser form input.
