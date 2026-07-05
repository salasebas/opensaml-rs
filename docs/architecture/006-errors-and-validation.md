# Errors and Validation

The canonical error type remains `SamlError`.

## Current Problem

Today, `SamlError` mixes semantic SAML failures with generic buckets:

```rust
SamlError::Xml(String)
SamlError::Invalid(String)
SamlError::Unsupported(String)
SamlError::Crypto(String)
SamlError::UnmatchIssuer
SamlError::UnmatchAudience
SamlError::UnmatchDestination
SamlError::InvalidInResponseTo
SamlError::MissingSigAlg
SamlError::UndefinedBinding
```

This works for fail-closed behavior, but it is not enough for a polished typed
API. Callers should branch on validation rule failures without string matching.

## Target Error Shape

Keep `SamlError` and make it semantic:

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SamlError {
    IssuerMismatch {
        expected: String,
        actual: Option<String>,
    },
    AudienceMismatch {
        expected: String,
        actual: Vec<String>,
    },
    DestinationMismatch {
        expected: String,
        actual: Option<String>,
    },
    RecipientMismatch {
        expected: String,
        actual: Option<String>,
    },
    InResponseToMismatch {
        expected: Option<String>,
        actual: Option<String>,
    },
    RelayStateMismatch {
        expected: RelayStateParam,
        actual: RelayStateParam,
    },
    StatusNotSuccess {
        top: String,
        second: Option<String>,
    },
    SubjectConfirmationInvalid {
        reason: &'static str,
    },
    TimeWindowInvalid {
        field: &'static str,
    },
    SignatureMissing,
    MissingBindingParameter {
        name: &'static str,
    },
    SignatureVerification {
        reason: &'static str,
    },
    ReferenceResolution {
        reason: &'static str,
    },
    SignedReferenceMismatch,
    NoTrustedCertificate,
    MetadataTrustFailed {
        reason: &'static str,
    },
    ReplayDetected {
        key: String,
    },
    MissingBinding,
    UnsupportedBinding {
        binding: raw::Binding,
    },
    UnsupportedProfile {
        profile: &'static str,
    },
    Xml(String),
    Crypto(String),
    Unsupported(String),
}
```

Exact payload types can change during implementation. The important rule is
that each security validation rule has a branchable variant.

## Validation Context

Inbound typed browser flows should use caller-owned clock and replay:

```rust
pub struct SamlValidationContext<'a> {
    pub now: SamlInstant,
    pub clock_skew: ClockSkew,
    pub replay: ReplayPolicy<'a>,
}

pub enum ReplayPolicy<'a> {
    RequireCache(&'a mut dyn ReplayCache),
    DisabledForCompatibility,
}

pub trait ReplayCache {
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        expires_at: SamlInstant,
    ) -> Result<(), SamlError>;
}
```

Raw compatibility can keep today's hidden process-clock behavior. Typed browser
flows should not. Use `SamlValidationContext` in `finish_sso`,
`accept_unsolicited_sso`, `receive_sso`, `receive_slo`, `finish_slo`, and any
other inbound signed, timed, or replay-sensitive browser-message validation.

RelayState comparison is exact tri-state:

```rust
pub enum RelayStateParam {
    Absent,
    PresentEmpty,
    PresentValue(RelayState),
}
```

For SP-initiated SSO/SLO, if pending state expects `Absent` and the inbound
message carries any RelayState, fail with `RelayStateMismatch` unless an
explicit compatibility policy permits the extra parameter.

## Validation Order For SP SSO Response

The typed `finish_sso` path should preserve fail-closed validation and make the
order explicit:

1. Decode binding and enforce parser limits.
2. Reject malformed or disallowed XML.
3. Check response status.
4. Verify signature and signed-reference coverage.
5. Check issuer.
6. Check destination and recipient.
7. Check `InResponseTo` against `Pending<AuthnRequest>`.
8. Check RelayState exactly, including absent versus present empty.
9. Check assertion conditions time window using caller-owned `now`.
10. Check audience.
11. Check bearer subject confirmation.
12. Check replay cache for response/assertion/session keys.
13. Convert to `SsoSession`.

## Metadata Signature Validation

Signed metadata validation must not return only `bool` in the typed API.

Target:

```rust
pub struct MetadataSignatureVerification {
    pub verified: bool,
    pub signed_entity_descriptor_xml: Option<String>,
}
```

Rules:

- `RequireSignature` requires `verified == true`.
- It must prove the consumed descriptor is covered by a signed reference.
- If coverage cannot be determined, fail closed with `SignedReferenceMismatch`
  or `MetadataTrustFailed`.
