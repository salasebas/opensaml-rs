# Artifact resolution service on IdP metadata

This break is unreleased. It applies to the release that first publishes
SOAP artifact resolution.

Two identity-provider metadata structs gain a field. An existing struct
literal that names every field no longer compiles. `SamlError` gains two
variants. It stays `#[non_exhaustive]`, so a match that already ends in `_`
keeps compiling.

## Add the artifact resolution list

This breaks a struct literal of `saml_rs::IdpMetadataConfig` or
`saml_rs::metadata::IdpMetadataConfig` (also imported as
`saml_rs::raw::metadata::IdpMetadataConfig`).

Who must change: code that constructs either struct by listing its fields.
`IdpMetadataConfig::new` and `..Default::default()` on the raw struct already
supply an empty list.

Leave the list empty when this identity provider does not resolve artifacts.
On the typed struct, set `artifact_resolution_service: Vec::new()` beside the
existing fields. On the raw struct, the same field holds
`saml_rs::metadata::ArtifactResolutionEndpoint`. `..Default::default()` still
fills it.

Publish the SOAP endpoint from the typed builder. The builder starts on
Recommended, and this snippet leaves that preset in place. Select
`compatibility()` only for the legacy permissive preset, including a build
without the crypto feature.

```rust
use saml_rs::{ArtifactResolutionService, EndpointUrl, EntityId, IdpConfig, SsoEndpoint};

fn publish() -> Result<IdpConfig, saml_rs::SamlError> {
    IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .artifact_resolution_service(ArtifactResolutionService::new(
            0,
            EndpointUrl::try_new("https://idp.example.com/artifact")?,
        ))
        .build()
}
```

The index is the artifact's `EndpointIndex`. Two services with the same index
are rejected.

## Match the new artifact errors

Who must change: code that matches `SamlError` and wants to handle these
cases by name.

- `SamlError::ArtifactNotReturned` — `ArtifactResponse` succeeded at SOAP and
  reported Success, but it did not contain the protocol message.
- `SamlError::SoapChannelProtection` — the attested SOAP channel lacks the
  authentication, integrity, or confidentiality this dereference requires.

A wildcard arm still covers both.
