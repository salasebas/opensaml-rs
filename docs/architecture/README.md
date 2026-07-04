# Typed API Architecture Draft

This directory captures the intended public API before implementation starts.
It is the canonical architecture and naming draft for the typed API on the
`advisor/typed-api-architecture` branch. Plans 011 through 021 should refine
these files in place rather than create a parallel documentation location.

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

## Implementation Order

Recommended order:

1. Finalize this naming checkpoint.
2. Plan 011: create the typed facade and raw boundary.
3. Plan 019: stabilize these architecture docs as durable maintainer notes.
4. Plan 017: improve `SamlError`.
5. Plan 012: add typed config and policies.
6. Plan 018: add narrowed binding, endpoint, and tracker types.
7. Plan 013: add browser/domain models.
8. Plan 020: add caller-owned clock and replay validation context.
9. Plan 021: add verified metadata trust boundary.
10. Plan 014: add typed Web SSO facade.
11. Plan 015: add typed Single Logout facade.
12. Plan 016: update README, docs.rs, and examples.

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
        trusted_certs: &[metadata_signing_cert],
    },
)?;

let started = sp_saml.start_sso(&idp_descriptor, StartSso::redirect())?;
store_pending(started.pending.snapshot());
send_to_browser(started.outbound);

let validation = SamlValidationContext {
    now,
    clock_skew,
    replay: ReplayPolicy::RequireCache(&mut replay_cache),
};

let pending = Pending::<AuthnRequest>::from_snapshot(load_pending_snapshot())?;
let session = sp_saml.finish_sso(
    &idp_descriptor,
    &pending,
    BrowserInput::<SsoResponse>::post(form_fields),
    validation,
)?;

let name_id = session.subject().name_id().value();
```
