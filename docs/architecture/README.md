# Typed API architecture

Maintainer notes for the typed public API, matched to the facade that is
implemented now. The package is `saml-rs`. Rust imports it as `saml_rs`. The
low-level flow API stays available as raw compatibility.

## Which note to read

- Names that are canonical, and names that were rejected:
  [001-naming.md](001-naming.md).
- Root exports, modules, and the current-to-new API map:
  [002-public-api-map.md](002-public-api-map.md).
- SP and IdP browser SSO: [003-web-sso-api.md](003-web-sso-api.md).
- Typed Single Logout: [004-single-logout-api.md](004-single-logout-api.md).
- Config, policies, credentials, descriptors, and metadata trust:
  [005-config-and-metadata.md](005-config-and-metadata.md).
- `SamlError`, validation context, clock, replay, RelayState, and metadata
  signature trust: [006-errors-and-validation.md](006-errors-and-validation.md).
- How `flow`, `ServiceProvider`, and `IdentityProvider` stay available:
  [007-raw-compatibility.md](007-raw-compatibility.md).

## Design goals

- Normal SP and IdP browser flows start from `Saml<Sp>` and `Saml<Idp>`.
- Raw flow APIs stay available for migration and advanced interop.
- Local active roles stay separate from peer metadata descriptors.
- Illegal SAML Web SSO binding combinations cannot be represented.
- Request correlation, RelayState, clock, replay, and metadata trust appear
  in function signatures.
- XML security stays in `bergshamra`. This tree does not implement XML-DSig,
  canonicalisation, or XML-Enc.
- Artifact resolution, SOAP and other back-channel profiles, ECP/PAOS, SAML
  queries, NameID management, and metadata federation stay outside the
  high-level typed API.

## Shape of an SP round trip

This is the shape of the typed calls. It is not a complete program.
`sp_config`, the metadata, the clock, and the replay cache come from the
application.

```rust
use saml_rs::{
    AuthnRequest, BrowserInput, IdpDescriptor, MetadataTrustPolicy, Pending,
    ReplayPolicy, Saml, SamlValidationContext, Sp, SpConfig, SsoResponse, StartSso,
};

let sp_saml: Saml<Sp> = Saml::sp(sp_config)?;

let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
    expected_idp_entity_id,
    idp_metadata_xml,
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: &[metadata_signing_cert],
    },
)?;

let started = sp_saml.start_sso(&idp_descriptor, StartSso::redirect())?;
store_pending(started.pending.snapshot());
send_to_browser(started.outbound);

let validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut replay_cache))
    .with_clock_skew(clock_skew);

let pending = Pending::<AuthnRequest>::from_snapshot(load_pending_snapshot())?;
let session = sp_saml.finish_sso(
    &idp_descriptor,
    &pending,
    BrowserInput::<SsoResponse>::post(form_fields),
    validation,
)?;

let name_id = session.subject().name_id().value();
```
