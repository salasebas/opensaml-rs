# Typed API Architecture

This directory captures maintainer notes for the typed public API. Keep these
files aligned with the implemented facade rather than treating them as a
separate future design.

The current crate package is `saml-rs`; Rust users import it as `saml_rs`.
The current low-level flow API stays supported as raw compatibility while the
new typed API becomes the recommended path.

## Documents

- [001-naming.md](001-naming.md): canonical names and rejected names.
- [002-public-api-map.md](002-public-api-map.md): root exports, modules, and
  current-to-new API mapping.
- [003-web-sso-api.md](003-web-sso-api.md): SP and IdP browser SSO flow.
- [004-single-logout-api.md](004-single-logout-api.md): typed SLO flow.
- [005-config-and-metadata.md](005-config-and-metadata.md): config, policies,
  credentials, descriptors, and metadata trust.
- [006-errors-and-validation.md](006-errors-and-validation.md): `SamlError`,
  validation context, clock, replay, RelayState, and metadata signature trust.
- [007-raw-compatibility.md](007-raw-compatibility.md): how the current
  `flow`/`ServiceProvider`/`IdentityProvider` API remains available.

## Design Goals

- Make normal SP/IdP browser flows start from `Saml<Sp>` and `Saml<Idp>`.
- Keep current raw flow APIs available for migration and advanced interop.
- Separate local active roles from peer metadata descriptors.
- Make illegal SAML Web SSO binding combinations unrepresentable in typed API.
- Make request correlation, RelayState, clock, replay, and metadata trust
  visible in function signatures.
- Keep XML security delegated to `bergshamra`; do not add in-tree XML-DSig,
  canonicalization, or XML-Enc implementations.
- Keep unsupported profiles out of the high-level typed API for now: Artifact
  resolution, SOAP/back-channel profiles, ECP/PAOS, SAML queries, NameID
  management, and metadata federation remain raw compatibility or future work.

## High-Level Shape

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
