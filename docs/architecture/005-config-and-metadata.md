# Config, Policies, and Metadata Trust

The typed API should replace `EntitySetting` as the recommended config surface.
`EntitySetting` remains raw compatibility.

## Construction Style

Typed config construction supports two reviewable paths:

- struct literals for advanced callers that want every policy field visible;
- manual, dependency-free builders for application setup code that wants
  required fields checked in one place.

Validated scalar values use fallible constructors for caller-provided input:

```rust
let entity_id = EntityId::try_new("https://sp.example.com/metadata")?;
let acs = AcsEndpoint::post("https://sp.example.com/acs")?;
```

Struct literals keep policy choices explicit:

```rust
let config = SpConfig {
    entity_id,
    metadata: SpMetadataConfig::new(vec![acs]),
    credentials: load_sp_signing_credentials()?,
    validation: SpValidationPolicy::strict(),
    algorithms: AlgorithmPolicy::default(),
    xml: XmlPolicy::default(),
    templates: TemplatePolicy::default(),
};
config.validate()?;
```

Builders keep large setup ergonomic while still returning `Result`. Builders use
strict typed defaults; `SpConfig::new` / `IdpConfig::new`, `try_new`, and public
`Default` policy values preserve compatibility defaults so callers do not
silently opt into signature requirements SAML does not universally require.

```rust
let config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
    .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
    .credentials(load_sp_signing_credentials()?)
    .validation(SpValidationPolicy::strict())
    .build()?;

let idp_config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
    .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
    .validation(IdpValidationPolicy::strict())
    .build()?;
```

Typed metadata and config builders validate entity IDs, required endpoints, and
policy requirements that are meaningful without peer context. Raw compatibility
structs keep their existing defaults and mutation model.

## Config Types

```rust
pub struct SpConfig {
    pub entity_id: EntityId,
    pub metadata: SpMetadataConfig,
    pub credentials: Credentials,
    pub validation: SpValidationPolicy,
    pub algorithms: AlgorithmPolicy,
    pub xml: XmlPolicy,
    pub templates: TemplatePolicy,
}

pub struct IdpConfig {
    pub entity_id: EntityId,
    pub metadata: IdpMetadataConfig,
    pub credentials: Credentials,
    pub validation: IdpValidationPolicy,
    pub algorithms: AlgorithmPolicy,
    pub xml: XmlPolicy,
    pub templates: TemplatePolicy,
}
```

Configs convert internally to today's raw `EntitySetting` when calling legacy
implementation helpers.

## Credentials

```rust
pub struct Credentials {
    signing_key: Option<PrivateKeyPem>,
    signing_key_passphrase: Option<Passphrase>,
    signing_certificate: Option<CertificatePem>,
    encryption_certificate: Option<CertificatePem>,
    decryption_key: Option<PrivateKeyPem>,
    decryption_key_passphrase: Option<Passphrase>,
}

pub struct PrivateKeyPem(String);
pub struct CertificatePem(String);
pub struct Passphrase(String);
```

Rules:

- Secret-bearing types have redacted `Debug`.
- Credential strings stay behind typed wrappers, with `as_str()` available as a
  raw compatibility and migration escape hatch.
- Do not make `EntitySetting` with raw strings the primary typed config.

## Algorithm Policy

```rust
pub enum SignatureAlgorithm {
    RsaSha256,
    RsaSha384,
    RsaSha512,
    Custom(String),
}

pub enum DigestAlgorithm {
    Sha1ForCompatibility,
    #[deprecated]
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Custom(String),
}

pub enum DataEncryptionAlgorithm {
    Aes128,
    Aes256,
    TripleDesForCompatibility,
    #[deprecated]
    TripleDes,
    Aes128Gcm,
    Custom(String),
}

pub enum KeyEncryptionAlgorithm {
    RsaOaepMgf1p,
    Rsa15ForCompatibility,
    #[deprecated]
    Rsa15,
    Custom(String),
}
```

Rules:

- Map known variants to existing constants.
- Keep custom URI constructors simple; backend support is still checked at
  runtime.
- Risky compatibility options must be visible in names.

## XML and Validation Policy

```rust
pub struct XmlPolicy {
    pub clock_drifts: (i64, i64),
    pub redirect_inflate_max_bytes: usize,
    pub limits: XmlLimits,
    pub encryption: XmlEncryptionPolicy,
}

pub struct XmlEncryptionPolicy {
    pub assertions: AssertionEncryptionPolicy,
    // private explicit risk opt-in for software RSA key transport decryption
}

pub enum AssertionEncryptionPolicy {
    PlaintextAssertions,
    EncryptAssertions,
}

pub enum AssertionSignaturePolicy {
    RequireSigned,
    AllowUnsignedForCompatibility,
}

pub enum ResponseSignaturePolicy {
    AllowUnsignedEncryptedCbcForCompatibility,
    RequireForEncryptedCbc,
    RequireSigned,
}

pub enum AuthnRequestSigningPolicy {
    Sign,
    DoNotSignForCompatibility,
}

pub enum AuthnRequestValidationPolicy {
    RequireSigned,
    AllowUnsignedForCompatibility,
}

pub enum LogoutSignaturePolicy {
    RequireSigned,
    AllowUnsignedForCompatibility,
}

pub struct SpValidationPolicy {
    assertions: AssertionSignaturePolicy,
    responses: ResponseSignaturePolicy,
    authn_requests: AuthnRequestSigningPolicy,
    audience: AudienceValidationPolicy,
    name_id_creation: NameIdCreationPolicy,
    logout: LogoutPolicy,
}

pub struct IdpValidationPolicy {
    authn_requests: AuthnRequestValidationPolicy,
    logout: LogoutPolicy,
}
```

SAML V2.0 Approved Errata 05 E26/E93 clarifies that Web Browser SSO over
HTTP-POST requires each Assertion to be protected by signing either the
Assertion itself or the enclosing Response. `SpValidationPolicy::strict()`
deliberately requires direct Assertion coverage as library hardening; this is
stricter than the profile baseline and aligns with the separate
`WantAssertionsSigned` metadata requirement.

The top-level Response remains optional for plaintext Assertions, but Errata 05
E93 recommends outer integrity protection before processing an
`EncryptedAssertion` that uses CBC. Strict policy therefore uses
`ResponseSignaturePolicy::RequireForEncryptedCbc`; compatibility policy exposes
the relaxation explicitly as
`AllowUnsignedEncryptedCbcForCompatibility`. Typed IdPs sign CBC-encrypted
Responses by default. Callers can require Response authentication for every
response with `ResponseSignaturePolicy::RequireSigned` and force producer-side
HTTP-POST signing with `RespondSso::post().sign_response()`.

Avoid bare boolean names for signature requirements and avoid names like
`insecure(true)`. Compatibility exceptions should be visible in enum variants.

## Descriptors

```rust
pub struct IdpDescriptor {
    // private parsed IdP metadata plus trust state
}

pub struct SpDescriptor {
    // private parsed SP metadata plus trust state
}
```

Constructors:

```rust
impl IdpDescriptor {
    pub fn from_metadata_xml_for(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError>;

    pub fn from_metadata_xml(
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError>;
}

impl SpDescriptor {
    pub fn from_metadata_xml_for(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError>;

    pub fn from_metadata_xml(
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError>;
}
```

Prefer `from_metadata_xml_for(expected_entity_id, xml, trust)`. It binds the
metadata to the entity ID the caller intended to trust. The shorter
`from_metadata_xml(xml, trust)` is only a convenience for callers that
explicitly accept the entity ID found in metadata.

## Metadata Trust

```rust
pub enum MetadataTrustPolicy<'a> {
    RequireSignature {
        trusted_certificates: &'a [CertificatePem],
    },
    UnsignedForCompatibility,
}

pub struct VerifiedIdpMetadata {
    descriptor_xml: String,
    trust: MetadataTrust,
}

pub struct VerifiedSpMetadata {
    descriptor_xml: String,
    trust: MetadataTrust,
}

pub struct MetadataTrust {
    trusted_certificate: CertificateFingerprint,
}
```

The implemented typed descriptors store private trust evidence rather than a
public fingerprint type:

```rust
pub struct MetadataSignatureVerification { /* private fields */ }

impl MetadataSignatureVerification {
    pub fn verified(&self) -> bool;
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str>;
}

impl IdpDescriptor {
    pub fn was_verified_with_pinned_certificates(&self) -> bool;
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str>;
}

impl SpDescriptor {
    pub fn was_verified_with_pinned_certificates(&self) -> bool;
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str>;
}
```

Rules:

- `RequireSignature` means signed metadata must verify against caller-pinned
  trusted certificates.
- Verification must prove the consumed `EntityDescriptor` is covered by the
  signature, and metadata signature references may use only descriptor-preserving
  transforms.
- `signed_entity_descriptor_xml()` exposes the signed descriptor evidence when
  pinned verification passed.
- `UnsignedForCompatibility` is explicit and visible in call sites.
- Do not claim PKIX, federation, or online metadata refresh support by default.

## Endpoint Config

```rust
pub struct SsoEndpoint {
    binding: SsoRequestBinding,
    location: EndpointUrl,
}

pub struct AcsEndpoint {
    binding: SsoResponseBinding,
    location: EndpointUrl,
    index: Option<u16>,
    is_default: bool,
}

pub struct SloEndpoint {
    binding: LogoutBinding,
    location: EndpointUrl,
}
```

Rules:

- ACS has index/default fields.
- SSO and SLO do not.
- Raw metadata `Endpoint` remains compatibility only.
