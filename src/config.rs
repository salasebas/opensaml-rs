//! Typed configuration building blocks for high-level SAML APIs.

use core::fmt;
use core::ops::Deref;
use core::str::FromStr;

use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::browser::{AcsEndpoint, SloEndpoint, SsoEndpoint};
use crate::constants::{
    data_encryption_algorithm, digest_algorithm, key_encryption_algorithm, name_id_format,
    signature_algorithm, transform_algorithm, MessageSignatureOrder,
};
use crate::entity::{EntitySetting, SignatureConfig};
use crate::error::SamlError;
#[cfg(feature = "crypto-bergshamra")]
use crate::error::SignatureVerificationReason;
use crate::metadata::{IdpMetadata, Metadata, SpMetadata};
use crate::template::LoginResponseTemplate;
use crate::xml::XmlLimits;

/// PEM-encoded private key material.
///
/// `Debug` is intentionally redacted so key material is not dumped through
/// public config structs.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKeyPem(String);

impl PrivateKeyPem {
    /// Wrap PEM-encoded private key material.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the PEM text.
    ///
    /// The value is secret-bearing key material. Prefer passing typed
    /// credentials through config APIs when possible; this accessor exists for
    /// migration code and raw compatibility escape hatches.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivateKeyPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyPem(<redacted>)")
    }
}

/// PEM-encoded X.509 certificate material.
///
/// `Debug` avoids printing the certificate body by default because certificate
/// fields often travel beside private key configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct CertificatePem(String);

impl CertificatePem {
    /// Wrap PEM-encoded certificate material.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the PEM text for internal compatibility mapping.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CertificatePem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertificatePem(<redacted>)")
    }
}

/// Passphrase used to decrypt private key material.
///
/// `Debug` is intentionally redacted so passphrases are not exposed through
/// logs or failing assertions.
#[derive(Clone, PartialEq, Eq)]
pub struct Passphrase(String);

impl Passphrase {
    /// Wrap passphrase text.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the passphrase text.
    ///
    /// The value is secret-bearing credential material. Prefer passing typed
    /// credentials through config APIs when possible; this accessor exists for
    /// migration code and raw compatibility escape hatches.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// XML signature algorithm used for outgoing signed messages.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSA with SHA-256.
    #[default]
    RsaSha256,
    /// RSA with SHA-384.
    RsaSha384,
    /// RSA with SHA-512.
    RsaSha512,
    /// Backend-specific signature algorithm URI.
    Custom(String),
}

impl SignatureAlgorithm {
    /// Return the XML-DSig algorithm URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::RsaSha256 => signature_algorithm::RSA_SHA256,
            Self::RsaSha384 => signature_algorithm::RSA_SHA384,
            Self::RsaSha512 => signature_algorithm::RSA_SHA512,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// XML digest algorithm URI used by XML-DSig profiles.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-1 digest for legacy interoperability.
    Sha1ForCompatibility,
    /// Deprecated alias for [`Self::Sha1ForCompatibility`].
    #[deprecated(note = "use DigestAlgorithm::Sha1ForCompatibility")]
    Sha1,
    /// SHA-256 digest.
    Sha256,
    /// SHA-384 digest.
    Sha384,
    /// SHA-512 digest.
    Sha512,
    /// Backend-specific digest algorithm URI.
    Custom(String),
}

impl DigestAlgorithm {
    /// Return the XML digest algorithm URI.
    #[expect(
        deprecated,
        reason = "deprecated algorithm aliases remain mapped for compatibility"
    )]
    pub fn as_uri(&self) -> &str {
        match self {
            Self::Sha1ForCompatibility | Self::Sha1 => digest_algorithm::SHA1,
            Self::Sha256 => digest_algorithm::SHA256,
            Self::Sha384 => digest_algorithm::SHA384,
            Self::Sha512 => digest_algorithm::SHA512,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// XML-Enc content encryption algorithm.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DataEncryptionAlgorithm {
    /// AES-128-CBC.
    Aes128,
    /// AES-256-CBC.
    #[default]
    Aes256,
    /// Triple DES CBC for legacy interoperability.
    TripleDesForCompatibility,
    /// Deprecated alias for [`Self::TripleDesForCompatibility`].
    #[deprecated(note = "use DataEncryptionAlgorithm::TripleDesForCompatibility")]
    TripleDes,
    /// AES-128-GCM.
    Aes128Gcm,
    /// Backend-specific content encryption algorithm URI.
    Custom(String),
}

impl DataEncryptionAlgorithm {
    /// Return the XML-Enc algorithm URI.
    #[expect(
        deprecated,
        reason = "deprecated algorithm aliases remain mapped for compatibility"
    )]
    pub fn as_uri(&self) -> &str {
        match self {
            Self::Aes128 => data_encryption_algorithm::AES_128,
            Self::Aes256 => data_encryption_algorithm::AES_256,
            Self::TripleDesForCompatibility | Self::TripleDes => {
                data_encryption_algorithm::TRIPLE_DES
            }
            Self::Aes128Gcm => data_encryption_algorithm::AES_128_GCM,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// XML-Enc key transport algorithm.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum KeyEncryptionAlgorithm {
    /// RSA-OAEP-MGF1P.
    #[default]
    RsaOaepMgf1p,
    /// RSAES-PKCS1-v1_5 for legacy interoperability.
    Rsa15ForCompatibility,
    /// Deprecated alias for [`Self::Rsa15ForCompatibility`].
    #[deprecated(note = "use KeyEncryptionAlgorithm::Rsa15ForCompatibility")]
    Rsa15,
    /// Backend-specific key transport algorithm URI.
    Custom(String),
}

impl KeyEncryptionAlgorithm {
    /// Return the XML-Enc key transport algorithm URI.
    #[expect(
        deprecated,
        reason = "deprecated algorithm aliases remain mapped for compatibility"
    )]
    pub fn as_uri(&self) -> &str {
        match self {
            Self::RsaOaepMgf1p => key_encryption_algorithm::RSA_OAEP_MGF1P,
            Self::Rsa15ForCompatibility | Self::Rsa15 => key_encryption_algorithm::RSA_1_5,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// XML-DSig transform or canonicalization algorithm.
///
/// Custom URI values are forwarded to the configured crypto backend and can
/// still fail at runtime when unsupported by that backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformAlgorithm {
    /// Enveloped-signature transform.
    EnvelopedSignature,
    /// Exclusive XML canonicalization.
    ExclusiveCanonicalization,
    /// Backend-specific transform algorithm URI.
    Custom(String),
}

impl TransformAlgorithm {
    /// Return the XML-DSig transform URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::EnvelopedSignature => transform_algorithm::ENVELOPED_SIGNATURE,
            Self::ExclusiveCanonicalization => transform_algorithm::EXC_C14N,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// SAML NameID format URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameIdFormat {
    /// Email address format.
    EmailAddress,
    /// Persistent identifier format.
    Persistent,
    /// Transient identifier format.
    Transient,
    /// Entity identifier format.
    Entity,
    /// Unspecified format.
    Unspecified,
    /// Kerberos principal name format.
    Kerberos,
    /// Windows domain qualified name format.
    WindowsDomainQualifiedName,
    /// X.509 subject name format.
    X509SubjectName,
    /// Deployment-specific NameID format URI.
    Custom(String),
}

impl NameIdFormat {
    /// Return the SAML NameID format URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::EmailAddress => name_id_format::EMAIL_ADDRESS,
            Self::Persistent => name_id_format::PERSISTENT,
            Self::Transient => name_id_format::TRANSIENT,
            Self::Entity => name_id_format::ENTITY,
            Self::Unspecified => name_id_format::UNSPECIFIED,
            Self::Kerberos => name_id_format::KERBEROS,
            Self::WindowsDomainQualifiedName => name_id_format::WINDOWS_DOMAIN_QUALIFIED_NAME,
            Self::X509SubjectName => name_id_format::X509_SUBJECT_NAME,
            Self::Custom(uri) => uri.as_str(),
        }
    }
}

/// SAML entity ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityId(String);

impl EntityId {
    /// Wrap an entity ID URI or deployment-specific identifier without validation.
    ///
    /// Prefer [`Self::try_new`] for caller-provided input. This constructor is
    /// retained for already-validated compatibility data.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Validate and wrap a non-empty entity ID.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the entity ID is empty.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        validate_entity_id_text(&value)?;
        Ok(Self(value))
    }

    /// Borrow the entity ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for EntityId {
    type Err = SamlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_new(value)
    }
}

impl TryFrom<&str> for EntityId {
    type Error = SamlError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl TryFrom<String> for EntityId {
    type Error = SamlError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

/// Local SP metadata inputs used by typed configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpMetadataConfig {
    /// `<NameIDFormat>` values advertised by the SP.
    pub name_id_format: Vec<NameIdFormat>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<SloEndpoint>,
    /// `AssertionConsumerService` endpoints.
    pub assertion_consumer_service: Vec<AcsEndpoint>,
    /// Element ordering profile for generated metadata.
    pub elements_order: Option<Vec<String>>,
}

impl SpMetadataConfig {
    /// Create SP metadata input with required ACS endpoints visible at the call site.
    ///
    /// This constructor does not validate the endpoint list. Use
    /// [`Self::try_new`] for caller-provided endpoint collections.
    pub fn new(assertion_consumer_service: Vec<AcsEndpoint>) -> Self {
        Self {
            name_id_format: Vec::new(),
            single_logout_service: Vec::new(),
            assertion_consumer_service,
            elements_order: None,
        }
    }

    /// Validate and create SP metadata input.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when no ACS endpoint is supplied.
    pub fn try_new(assertion_consumer_service: Vec<AcsEndpoint>) -> Result<Self, SamlError> {
        let config = Self::new(assertion_consumer_service);
        config.validate()?;
        Ok(config)
    }

    /// Validate required SP metadata inputs.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when no ACS endpoint is supplied.
    pub fn validate(&self) -> Result<(), SamlError> {
        if self.assertion_consumer_service.is_empty() {
            return Err(SamlError::MissingMetadata(
                "AssertionConsumerService".into(),
            ));
        }
        Ok(())
    }
}

/// Local IdP metadata inputs used by typed configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpMetadataConfig {
    /// `<NameIDFormat>` values advertised by the IdP.
    pub name_id_format: Vec<NameIdFormat>,
    /// `SingleSignOnService` endpoints.
    pub single_sign_on_service: Vec<SsoEndpoint>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<SloEndpoint>,
    /// Element ordering profile for generated metadata.
    pub elements_order: Option<Vec<String>>,
}

impl IdpMetadataConfig {
    /// Create IdP metadata input with required SSO endpoints visible at the call site.
    ///
    /// This constructor does not validate the endpoint list. Use
    /// [`Self::try_new`] for caller-provided endpoint collections.
    pub fn new(single_sign_on_service: Vec<SsoEndpoint>) -> Self {
        Self {
            name_id_format: Vec::new(),
            single_sign_on_service,
            single_logout_service: Vec::new(),
            elements_order: None,
        }
    }

    /// Validate and create IdP metadata input.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when no SSO endpoint is supplied.
    pub fn try_new(single_sign_on_service: Vec<SsoEndpoint>) -> Result<Self, SamlError> {
        let config = Self::new(single_sign_on_service);
        config.validate()?;
        Ok(config)
    }

    /// Validate required IdP metadata inputs.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::MissingMetadata`] when no SSO endpoint is supplied.
    pub fn validate(&self) -> Result<(), SamlError> {
        if self.single_sign_on_service.is_empty() {
            return Err(SamlError::MissingMetadata("SingleSignOnService".into()));
        }
        Ok(())
    }
}

/// Secret-bearing and certificate material for local SAML operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    /// Signing private key.
    pub signing_key: Option<PrivateKeyPem>,
    /// Passphrase for [`Self::signing_key`].
    pub signing_key_passphrase: Option<Passphrase>,
    /// Signing certificate.
    pub signing_certificate: Option<CertificatePem>,
    /// Encryption certificate advertised for peers.
    pub encryption_certificate: Option<CertificatePem>,
    /// Decryption private key for encrypted assertions.
    pub decryption_key: Option<PrivateKeyPem>,
    /// Passphrase for [`Self::decryption_key`].
    pub decryption_key_passphrase: Option<Passphrase>,
}

/// Whether SPs require assertion-level signatures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionSignaturePolicy {
    /// Reject unsigned assertions.
    RequireSigned,
    /// Accept unsigned assertions for legacy interoperability.
    #[default]
    AllowUnsignedForCompatibility,
}

/// Whether SPs require message-level signatures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MessageSignaturePolicy {
    /// Reject unsigned protocol messages.
    RequireSigned,
    /// Accept unsigned protocol messages for legacy interoperability.
    #[default]
    AllowUnsignedForCompatibility,
}

/// Whether an SP signs outgoing AuthnRequests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthnRequestSigningPolicy {
    /// Sign outgoing AuthnRequests.
    Sign,
    /// Send unsigned AuthnRequests for legacy interoperability.
    #[default]
    DoNotSignForCompatibility,
}

/// Whether an IdP requires signed inbound AuthnRequests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthnRequestValidationPolicy {
    /// Reject unsigned AuthnRequests.
    RequireSigned,
    /// Accept unsigned AuthnRequests for legacy interoperability.
    #[default]
    AllowUnsignedForCompatibility,
}

/// Whether logout messages require signatures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogoutSignaturePolicy {
    /// Reject unsigned logout messages.
    #[default]
    RequireSigned,
    /// Accept unsigned logout messages for legacy interoperability.
    AllowUnsignedForCompatibility,
}

/// Whether an SP validates assertion audience restrictions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AudienceValidationPolicy {
    /// Require this SP's entity ID in assertion audiences.
    #[default]
    Validate,
    /// Skip audience validation for legacy interoperability.
    SkipForCompatibility,
}

/// Whether SP AuthnRequests allow IdPs to create a new identifier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NameIdCreationPolicy {
    /// Set `AllowCreate="true"` in AuthnRequests.
    AllowCreate,
    /// Set `AllowCreate="false"` in AuthnRequests.
    #[default]
    DoNotAllowCreate,
}

/// SP-side validation and outbound signing policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpValidationPolicy {
    /// Assertion signature requirement.
    pub assertions: AssertionSignaturePolicy,
    /// Response/message signature requirement.
    pub messages: MessageSignaturePolicy,
    /// Outbound AuthnRequest signing behavior.
    pub authn_requests: AuthnRequestSigningPolicy,
    /// Audience validation behavior.
    pub audience: AudienceValidationPolicy,
    /// NameID creation behavior for AuthnRequests.
    pub name_id_creation: NameIdCreationPolicy,
    /// Logout signature validation behavior.
    pub logout: LogoutPolicy,
}

impl SpValidationPolicy {
    /// Strict SP validation and outbound signing defaults.
    pub fn strict() -> Self {
        Self {
            assertions: AssertionSignaturePolicy::RequireSigned,
            messages: MessageSignaturePolicy::RequireSigned,
            authn_requests: AuthnRequestSigningPolicy::Sign,
            audience: AudienceValidationPolicy::Validate,
            name_id_creation: NameIdCreationPolicy::DoNotAllowCreate,
            logout: LogoutPolicy::strict(),
        }
    }

    /// Legacy interoperability policy with unsigned behavior made explicit.
    pub fn compatibility() -> Self {
        Self {
            assertions: AssertionSignaturePolicy::AllowUnsignedForCompatibility,
            messages: MessageSignaturePolicy::AllowUnsignedForCompatibility,
            authn_requests: AuthnRequestSigningPolicy::DoNotSignForCompatibility,
            audience: AudienceValidationPolicy::SkipForCompatibility,
            name_id_creation: NameIdCreationPolicy::DoNotAllowCreate,
            logout: LogoutPolicy::compatibility(),
        }
    }
}

impl Default for SpValidationPolicy {
    fn default() -> Self {
        Self::compatibility()
    }
}

/// IdP-side validation policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpValidationPolicy {
    /// Inbound AuthnRequest signature requirement.
    pub authn_requests: AuthnRequestValidationPolicy,
    /// Logout signature validation behavior.
    pub logout: LogoutPolicy,
}

impl IdpValidationPolicy {
    /// Strict IdP validation defaults.
    pub fn strict() -> Self {
        Self {
            authn_requests: AuthnRequestValidationPolicy::RequireSigned,
            logout: LogoutPolicy::strict(),
        }
    }

    /// Legacy interoperability policy with unsigned behavior made explicit.
    pub fn compatibility() -> Self {
        Self {
            authn_requests: AuthnRequestValidationPolicy::AllowUnsignedForCompatibility,
            logout: LogoutPolicy::compatibility(),
        }
    }
}

impl Default for IdpValidationPolicy {
    fn default() -> Self {
        Self::compatibility()
    }
}

/// Logout request and response signature policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogoutPolicy {
    /// LogoutRequest signature behavior.
    pub requests: LogoutSignaturePolicy,
    /// LogoutResponse signature behavior.
    pub responses: LogoutSignaturePolicy,
}

impl LogoutPolicy {
    /// Require signed logout requests and responses.
    pub fn strict() -> Self {
        Self {
            requests: LogoutSignaturePolicy::RequireSigned,
            responses: LogoutSignaturePolicy::RequireSigned,
        }
    }

    /// Accept unsigned logout requests and responses for legacy interoperability.
    pub fn compatibility() -> Self {
        Self {
            requests: LogoutSignaturePolicy::AllowUnsignedForCompatibility,
            responses: LogoutSignaturePolicy::AllowUnsignedForCompatibility,
        }
    }
}

/// Whether assertions are encrypted in generated responses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionEncryptionPolicy {
    /// Do not encrypt assertions.
    #[default]
    PlaintextAssertions,
    /// Encrypt assertions.
    EncryptAssertions,
}

/// XML encryption policy.
///
/// # Examples
///
/// Use typed configuration to request encrypted assertions in generated
/// responses. This only configures policy; actual encryption uses the crate's
/// XML-Enc backend and deployment credentials.
///
/// ```
/// use saml_rs::{EntityId, IdpConfig, SsoEndpoint, XmlEncryptionPolicy, XmlPolicy};
///
/// let xml = XmlPolicy {
///     encryption: XmlEncryptionPolicy::encrypt_assertions(),
///     ..XmlPolicy::default()
/// };
/// let idp_builder = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
///     .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
///     .xml(xml);
/// # let _ = idp_builder;
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XmlEncryptionPolicy {
    /// Assertion encryption behavior.
    pub assertions: AssertionEncryptionPolicy,
    allow_insecure_software_rsa_key_transport_decryption: bool,
}

impl XmlEncryptionPolicy {
    /// Enable assertion encryption.
    pub fn encrypt_assertions() -> Self {
        Self {
            assertions: AssertionEncryptionPolicy::EncryptAssertions,
            ..Self::default()
        }
    }

    /// Explicitly allow software RSA key-transport decryption despite
    /// `RUSTSEC-2023-0071` timing-risk concerns in the bundled backend.
    pub fn allow_insecure_software_rsa_key_transport_decryption() -> Self {
        Self {
            allow_insecure_software_rsa_key_transport_decryption: true,
            ..Self::default()
        }
    }

    /// Return a copy with the software RSA key-transport risk explicitly allowed.
    pub fn with_insecure_software_rsa_key_transport_decryption_allowed(mut self) -> Self {
        self.allow_insecure_software_rsa_key_transport_decryption = true;
        self
    }

    fn allows_insecure_software_rsa_key_transport_decryption(self) -> bool {
        self.allow_insecure_software_rsa_key_transport_decryption
    }
}

/// XML parser, redirect decompression, clock, and XML encryption policy.
///
/// # Examples
///
/// Software RSA key-transport decryption is disabled by default because the
/// bundled RustCrypto RSA backend, reached through `bergshamra` / `kryptering`,
/// is affected by `RUSTSEC-2023-0071`. Enable it only as an explicit
/// compatibility exception for a deployment that accepts that risk.
///
/// ```
/// use saml_rs::{AcsEndpoint, EntityId, SpConfig, XmlEncryptionPolicy, XmlPolicy};
///
/// let xml = XmlPolicy {
///     encryption: XmlEncryptionPolicy::default()
///         .with_insecure_software_rsa_key_transport_decryption_allowed(),
///     ..XmlPolicy::default()
/// };
/// let sp_builder = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
///     .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
///     .xml(xml);
/// # let _ = sp_builder;
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmlPolicy {
    /// Clock drift tolerance `(not_before_ms, not_on_or_after_ms)`.
    pub clock_drifts: (i64, i64),
    /// Maximum decoded compressed and inflated raw-DEFLATE bytes accepted for
    /// HTTP-Redirect input.
    pub redirect_inflate_max_bytes: usize,
    /// XML parser resource limits.
    pub limits: XmlLimits,
    /// XML encryption behavior.
    pub encryption: XmlEncryptionPolicy,
}

impl Default for XmlPolicy {
    fn default() -> Self {
        Self {
            clock_drifts: (0, 0),
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            limits: XmlLimits::default(),
            encryption: XmlEncryptionPolicy::default(),
        }
    }
}

/// Algorithm choices used by outgoing SAML messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmPolicy {
    /// Signature algorithm URI.
    pub signature: SignatureAlgorithm,
    /// Data encryption algorithm URI.
    pub data_encryption: DataEncryptionAlgorithm,
    /// Key encryption algorithm URI.
    pub key_encryption: KeyEncryptionAlgorithm,
    /// Sign/encrypt operation order for messages that do both.
    pub message_signing_order: MessageSignatureOrder,
    /// XML-DSig reference transforms.
    pub signed_reference_transforms: Vec<TransformAlgorithm>,
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        Self {
            signature: SignatureAlgorithm::default(),
            data_encryption: DataEncryptionAlgorithm::default(),
            key_encryption: KeyEncryptionAlgorithm::default(),
            message_signing_order: MessageSignatureOrder::SignThenEncrypt,
            signed_reference_transforms: vec![
                TransformAlgorithm::EnvelopedSignature,
                TransformAlgorithm::ExclusiveCanonicalization,
            ],
        }
    }
}

/// Template and XML tag-prefix customization.
#[derive(Debug, Clone)]
pub struct TemplatePolicy {
    /// Default RelayState.
    pub relay_state: String,
    /// IdP protocol tag prefix for generated messages.
    pub tag_prefix_protocol: String,
    /// IdP assertion tag prefix for generated messages.
    pub tag_prefix_assertion: String,
    /// IdP tag prefix for generated `<EncryptedAssertion>` elements.
    pub tag_prefix_encrypted_assertion: String,
    /// IdP login response template and attributes.
    pub login_response_template: Option<LoginResponseTemplate>,
    /// SP login request template.
    pub login_request_template: Option<String>,
    /// Logout request template.
    pub logout_request_template: Option<String>,
    /// Logout response template.
    pub logout_response_template: Option<String>,
    /// Embedded-signature placement and prefix.
    pub signature_config: Option<SignatureConfig>,
}

impl Default for TemplatePolicy {
    fn default() -> Self {
        Self {
            relay_state: String::new(),
            tag_prefix_protocol: "samlp".to_string(),
            tag_prefix_assertion: "saml".to_string(),
            tag_prefix_encrypted_assertion: "saml".to_string(),
            login_response_template: None,
            login_request_template: None,
            logout_request_template: None,
            logout_response_template: None,
            signature_config: None,
        }
    }
}

/// Typed Service Provider configuration.
///
/// # Examples
///
/// ```
/// use saml_rs::{AcsEndpoint, EntityId, SpConfig, SpMetadataConfig};
///
/// let acs = AcsEndpoint::post("https://sp.example.com/acs")?;
/// let config = SpConfig::try_new(
///     EntityId::try_new("https://sp.example.com/metadata")?,
///     SpMetadataConfig::new(vec![acs]),
/// )?;
///
/// assert_eq!(config.entity_id.as_str(), "https://sp.example.com/metadata");
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone)]
pub struct SpConfig {
    /// Local SP entity ID.
    pub entity_id: EntityId,
    /// Local SP metadata inputs.
    pub metadata: SpMetadataConfig,
    /// Local credentials.
    pub credentials: Credentials,
    /// Validation and outbound signing policy.
    pub validation: SpValidationPolicy,
    /// Algorithm policy.
    pub algorithms: AlgorithmPolicy,
    /// XML parser, redirect, clock, and encryption policy.
    pub xml: XmlPolicy,
    /// Template and prefix policy.
    pub templates: TemplatePolicy,
}

impl SpConfig {
    /// Create SP configuration with required identity and metadata inputs.
    ///
    /// This convenience constructor accepts already-validated typed inputs but
    /// does not validate the final config. Use [`Self::try_new`] or
    /// [`Self::builder`] for caller-provided setup.
    pub fn new(entity_id: EntityId, metadata: SpMetadataConfig) -> Self {
        Self {
            entity_id,
            metadata,
            credentials: Credentials::default(),
            validation: SpValidationPolicy::default(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
    }

    /// Validate and create SP configuration with compatibility defaults.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the entity ID is empty or required SP
    /// metadata endpoints are missing.
    pub fn try_new(entity_id: EntityId, metadata: SpMetadataConfig) -> Result<Self, SamlError> {
        let config = Self::new(entity_id, metadata);
        config.validate()?;
        Ok(config)
    }

    /// Start a dependency-free SP config builder with strict typed defaults.
    pub fn builder(entity_id: EntityId) -> SpConfigBuilder {
        SpConfigBuilder::new(entity_id)
    }

    /// Validate required SP config fields.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the entity ID is empty or required SP
    /// metadata endpoints are missing.
    pub fn validate(&self) -> Result<(), SamlError> {
        validate_entity_id(&self.entity_id)?;
        self.metadata.validate()?;
        validate_sp_policy(self)
    }
}

/// Dependency-free builder for [`SpConfig`].
#[derive(Debug, Clone)]
pub struct SpConfigBuilder {
    entity_id: EntityId,
    metadata: SpMetadataConfig,
    credentials: Credentials,
    validation: SpValidationPolicy,
    algorithms: AlgorithmPolicy,
    xml: XmlPolicy,
    templates: TemplatePolicy,
}

impl SpConfigBuilder {
    fn new(entity_id: EntityId) -> Self {
        Self {
            entity_id,
            metadata: SpMetadataConfig::new(Vec::new()),
            credentials: Credentials::default(),
            validation: SpValidationPolicy::strict(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
    }

    /// Add an ACS endpoint.
    pub fn acs_endpoint(mut self, endpoint: AcsEndpoint) -> Self {
        self.metadata.assertion_consumer_service.push(endpoint);
        self
    }

    /// Add an SLO endpoint.
    pub fn slo_endpoint(mut self, endpoint: SloEndpoint) -> Self {
        self.metadata.single_logout_service.push(endpoint);
        self
    }

    /// Add an advertised NameID format.
    pub fn name_id_format(mut self, format: NameIdFormat) -> Self {
        self.metadata.name_id_format.push(format);
        self
    }

    /// Set generated metadata element ordering.
    pub fn elements_order(mut self, elements_order: Vec<String>) -> Self {
        self.metadata.elements_order = Some(elements_order);
        self
    }

    /// Set local credentials.
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Set SP validation and outbound signing policy.
    pub fn validation(mut self, validation: SpValidationPolicy) -> Self {
        self.validation = validation;
        self
    }

    /// Set algorithm policy.
    pub fn algorithms(mut self, algorithms: AlgorithmPolicy) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Set XML policy.
    pub fn xml(mut self, xml: XmlPolicy) -> Self {
        self.xml = xml;
        self
    }

    /// Set template policy.
    pub fn templates(mut self, templates: TemplatePolicy) -> Self {
        self.templates = templates;
        self
    }

    /// Build and validate the SP config.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when required fields are missing, selected policy
    /// needs unavailable credentials, or selected policy requires crypto in a
    /// no-default-features build.
    pub fn build(self) -> Result<SpConfig, SamlError> {
        let config = SpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
        };
        config.validate()?;
        Ok(config)
    }
}

/// Typed Identity Provider configuration.
///
/// # Examples
///
/// The builder starts with strict validation defaults. Use compatibility
/// policy explicitly when compiling or testing without the default crypto
/// feature.
///
/// ```
/// use saml_rs::{EntityId, IdpConfig, IdpValidationPolicy, SsoEndpoint};
///
/// let config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
///     .sso_endpoint(SsoEndpoint::post("https://idp.example.com/sso")?)
///     .validation(IdpValidationPolicy::compatibility())
///     .build()?;
///
/// assert_eq!(config.entity_id.as_str(), "https://idp.example.com/metadata");
/// # Ok::<(), saml_rs::SamlError>(())
/// ```
#[derive(Debug, Clone)]
pub struct IdpConfig {
    /// Local IdP entity ID.
    pub entity_id: EntityId,
    /// Local IdP metadata inputs.
    pub metadata: IdpMetadataConfig,
    /// Local credentials.
    pub credentials: Credentials,
    /// Validation policy.
    pub validation: IdpValidationPolicy,
    /// Algorithm policy.
    pub algorithms: AlgorithmPolicy,
    /// XML parser, redirect, clock, and encryption policy.
    pub xml: XmlPolicy,
    /// Template and prefix policy.
    pub templates: TemplatePolicy,
}

impl IdpConfig {
    /// Create IdP configuration with required identity and metadata inputs.
    ///
    /// This convenience constructor accepts already-validated typed inputs but
    /// does not validate the final config. Use [`Self::try_new`] or
    /// [`Self::builder`] for caller-provided setup.
    pub fn new(entity_id: EntityId, metadata: IdpMetadataConfig) -> Self {
        Self {
            entity_id,
            metadata,
            credentials: Credentials::default(),
            validation: IdpValidationPolicy::default(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
    }

    /// Validate and create IdP configuration with compatibility defaults.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the entity ID is empty or required IdP
    /// metadata endpoints are missing.
    pub fn try_new(entity_id: EntityId, metadata: IdpMetadataConfig) -> Result<Self, SamlError> {
        let config = Self::new(entity_id, metadata);
        config.validate()?;
        Ok(config)
    }

    /// Start a dependency-free IdP config builder with strict typed defaults.
    pub fn builder(entity_id: EntityId) -> IdpConfigBuilder {
        IdpConfigBuilder::new(entity_id)
    }

    /// Validate required IdP config fields.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the entity ID is empty or required IdP
    /// metadata endpoints are missing.
    pub fn validate(&self) -> Result<(), SamlError> {
        validate_entity_id(&self.entity_id)?;
        self.metadata.validate()?;
        validate_idp_policy(self)
    }
}

/// Dependency-free builder for [`IdpConfig`].
#[derive(Debug, Clone)]
pub struct IdpConfigBuilder {
    entity_id: EntityId,
    metadata: IdpMetadataConfig,
    credentials: Credentials,
    validation: IdpValidationPolicy,
    algorithms: AlgorithmPolicy,
    xml: XmlPolicy,
    templates: TemplatePolicy,
}

impl IdpConfigBuilder {
    fn new(entity_id: EntityId) -> Self {
        Self {
            entity_id,
            metadata: IdpMetadataConfig::new(Vec::new()),
            credentials: Credentials::default(),
            validation: IdpValidationPolicy::strict(),
            algorithms: AlgorithmPolicy::default(),
            xml: XmlPolicy::default(),
            templates: TemplatePolicy::default(),
        }
    }

    /// Add an SSO endpoint.
    pub fn sso_endpoint(mut self, endpoint: SsoEndpoint) -> Self {
        self.metadata.single_sign_on_service.push(endpoint);
        self
    }

    /// Add an SLO endpoint.
    pub fn slo_endpoint(mut self, endpoint: SloEndpoint) -> Self {
        self.metadata.single_logout_service.push(endpoint);
        self
    }

    /// Add an advertised NameID format.
    pub fn name_id_format(mut self, format: NameIdFormat) -> Self {
        self.metadata.name_id_format.push(format);
        self
    }

    /// Set generated metadata element ordering.
    pub fn elements_order(mut self, elements_order: Vec<String>) -> Self {
        self.metadata.elements_order = Some(elements_order);
        self
    }

    /// Set local credentials.
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Set IdP validation policy.
    pub fn validation(mut self, validation: IdpValidationPolicy) -> Self {
        self.validation = validation;
        self
    }

    /// Set algorithm policy.
    pub fn algorithms(mut self, algorithms: AlgorithmPolicy) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// Set XML policy.
    pub fn xml(mut self, xml: XmlPolicy) -> Self {
        self.xml = xml;
        self
    }

    /// Set template policy.
    pub fn templates(mut self, templates: TemplatePolicy) -> Self {
        self.templates = templates;
        self
    }

    /// Build and validate the IdP config.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when required fields are missing or selected
    /// policy requires crypto in a no-default-features build.
    pub fn build(self) -> Result<IdpConfig, SamlError> {
        let config = IdpConfig {
            entity_id: self.entity_id,
            metadata: self.metadata,
            credentials: self.credentials,
            validation: self.validation,
            algorithms: self.algorithms,
            xml: self.xml,
            templates: self.templates,
        };
        config.validate()?;
        Ok(config)
    }
}

/// Explicit trust policy for imported SAML metadata.
///
/// SAML metadata trust is caller-pinned or federation-driven; this type does
/// not use a public web PKI CA store by default.
/// [`UnsignedForCompatibility`](Self::UnsignedForCompatibility) is for explicit
/// legacy interoperability, not the preferred production trust model.
///
/// # Examples
///
/// ```no_run
/// use saml_rs::{CertificatePem, EntityId, IdpDescriptor, MetadataTrustPolicy};
///
/// # fn load_metadata() -> String { unimplemented!() }
/// # fn load_metadata_signing_cert() -> String { unimplemented!() }
/// # fn run() -> Result<(), saml_rs::SamlError> {
/// let cert = CertificatePem::new(load_metadata_signing_cert());
/// let certificates = [cert];
/// let idp = IdpDescriptor::from_metadata_xml_for(
///     EntityId::try_new("https://idp.example.com/metadata")?,
///     &load_metadata(),
///     MetadataTrustPolicy::RequireSignature {
///         trusted_certificates: &certificates,
///     },
/// )?;
/// assert!(idp.was_verified_with_pinned_certificates());
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Copy)]
pub enum MetadataTrustPolicy<'a> {
    /// Accept unsigned metadata for legacy interoperability.
    UnsignedForCompatibility,
    /// Require a valid metadata signature from one of the pinned certificates.
    RequireSignature {
        /// Caller-pinned certificates trusted to sign the metadata.
        trusted_certificates: &'a [CertificatePem],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(feature = "crypto-bergshamra"), allow(dead_code))]
enum AppliedMetadataTrust {
    UnsignedForCompatibility,
    SignedByPinnedCertificates {
        signed_entity_descriptor_xml: String,
    },
}

fn validate_entity_id_text(value: &str) -> Result<(), SamlError> {
    if value.trim().is_empty() {
        return Err(SamlError::Invalid("entity ID must not be empty".into()));
    }
    Ok(())
}

fn validate_entity_id(entity_id: &EntityId) -> Result<(), SamlError> {
    validate_entity_id_text(entity_id.as_str())
}

fn validate_common_credentials(credentials: &Credentials) -> Result<(), SamlError> {
    if credentials.signing_key_passphrase.is_some() && credentials.signing_key.is_none() {
        return Err(SamlError::MissingKey("signing_key".into()));
    }
    if credentials.decryption_key_passphrase.is_some() && credentials.decryption_key.is_none() {
        return Err(SamlError::MissingKey("decryption_key".into()));
    }
    Ok(())
}

fn validate_sp_policy(config: &SpConfig) -> Result<(), SamlError> {
    validate_sp_crypto_support(config)?;
    validate_common_credentials(&config.credentials)?;
    if matches!(
        config.validation.authn_requests,
        AuthnRequestSigningPolicy::Sign
    ) {
        validate_signing_credentials(&config.credentials)?;
    }
    if matches!(
        config.xml.encryption.assertions,
        AssertionEncryptionPolicy::EncryptAssertions
    ) && config.credentials.decryption_key.is_none()
    {
        return Err(SamlError::MissingKey("decryption_key".into()));
    }
    Ok(())
}

fn validate_idp_policy(config: &IdpConfig) -> Result<(), SamlError> {
    validate_idp_crypto_support(config)?;
    validate_common_credentials(&config.credentials)
}

fn validate_signing_credentials(credentials: &Credentials) -> Result<(), SamlError> {
    if credentials.signing_key.is_none() {
        return Err(SamlError::MissingKey("signing_key".into()));
    }
    if credentials.signing_certificate.is_none() {
        return Err(SamlError::MissingKey("signing_certificate".into()));
    }
    Ok(())
}

#[cfg(feature = "crypto-bergshamra")]
fn validate_sp_crypto_support(_config: &SpConfig) -> Result<(), SamlError> {
    Ok(())
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn validate_sp_crypto_support(config: &SpConfig) -> Result<(), SamlError> {
    if sp_config_requires_crypto(config) {
        return Err(SamlError::Unsupported(
            "selected SP config policy requires the crypto-bergshamra feature".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "crypto-bergshamra")]
fn validate_idp_crypto_support(_config: &IdpConfig) -> Result<(), SamlError> {
    Ok(())
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn validate_idp_crypto_support(config: &IdpConfig) -> Result<(), SamlError> {
    if idp_config_requires_crypto(config) {
        return Err(SamlError::Unsupported(
            "selected IdP config policy requires the crypto-bergshamra feature".into(),
        ));
    }
    Ok(())
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn sp_config_requires_crypto(config: &SpConfig) -> bool {
    matches!(
        config.validation.assertions,
        AssertionSignaturePolicy::RequireSigned
    ) || matches!(
        config.validation.messages,
        MessageSignaturePolicy::RequireSigned
    ) || matches!(
        config.validation.authn_requests,
        AuthnRequestSigningPolicy::Sign
    ) || logout_policy_requires_crypto(config.validation.logout)
        || matches!(
            config.xml.encryption.assertions,
            AssertionEncryptionPolicy::EncryptAssertions
        )
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn idp_config_requires_crypto(config: &IdpConfig) -> bool {
    matches!(
        config.validation.authn_requests,
        AuthnRequestValidationPolicy::RequireSigned
    ) || logout_policy_requires_crypto(config.validation.logout)
        || matches!(
            config.xml.encryption.assertions,
            AssertionEncryptionPolicy::EncryptAssertions
        )
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn logout_policy_requires_crypto(policy: LogoutPolicy) -> bool {
    logout_signature_policy_requires_crypto(policy.requests)
        || logout_signature_policy_requires_crypto(policy.responses)
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn logout_signature_policy_requires_crypto(policy: LogoutSignaturePolicy) -> bool {
    matches!(policy, LogoutSignaturePolicy::RequireSigned)
}

/// Typed IdP peer descriptor imported from metadata.
#[derive(Debug, Clone)]
pub struct IdpDescriptor {
    entity_id: EntityId,
    metadata_xml: String,
    metadata: IdpMetadata,
    trust: AppliedMetadataTrust,
}

impl IdpDescriptor {
    /// Parse IdP metadata for an expected entity ID and explicit trust policy.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the XML is malformed, the entity ID is absent
    /// or unexpected, or the requested trust policy cannot be satisfied.
    pub fn from_metadata_xml_for(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError> {
        validate_entity_id(&expected_entity_id)?;
        let metadata = IdpMetadata::from_xml(xml)?;
        let actual_entity_id = metadata_entity_id(&metadata)?;
        ensure_expected_entity_id(&expected_entity_id, actual_entity_id)?;
        let trust = ensure_metadata_trust(&metadata, trust)?;
        Ok(Self {
            entity_id: expected_entity_id,
            metadata_xml: xml.to_string(),
            metadata,
            trust,
        })
    }

    /// Parse IdP metadata when the caller accepts the metadata-declared entity ID.
    ///
    /// Prefer [`Self::from_metadata_xml_for`] when the expected entity ID is known.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the XML is malformed, the entity ID is absent,
    /// or the requested trust policy cannot be satisfied.
    pub fn from_metadata_xml(xml: &str, trust: MetadataTrustPolicy<'_>) -> Result<Self, SamlError> {
        let metadata = IdpMetadata::from_xml(xml)?;
        let entity_id = EntityId::try_new(metadata_entity_id(&metadata)?)?;
        let trust = ensure_metadata_trust(&metadata, trust)?;
        Ok(Self {
            entity_id,
            metadata_xml: xml.to_string(),
            metadata,
            trust,
        })
    }

    /// Metadata entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    /// Original metadata XML.
    pub fn metadata_xml(&self) -> &str {
        &self.metadata_xml
    }

    /// Parsed IdP metadata.
    pub fn metadata(&self) -> &IdpMetadata {
        &self.metadata
    }

    /// Whether this descriptor was verified with pinned signing certificates.
    pub fn was_verified_with_pinned_certificates(&self) -> bool {
        matches!(
            self.trust,
            AppliedMetadataTrust::SignedByPinnedCertificates { .. }
        )
    }

    /// Signed metadata descriptor XML when pinned metadata verification passed.
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str> {
        match &self.trust {
            AppliedMetadataTrust::SignedByPinnedCertificates {
                signed_entity_descriptor_xml,
            } => Some(signed_entity_descriptor_xml.as_str()),
            AppliedMetadataTrust::UnsignedForCompatibility => None,
        }
    }
}

/// Typed SP peer descriptor imported from metadata.
#[derive(Debug, Clone)]
pub struct SpDescriptor {
    entity_id: EntityId,
    metadata_xml: String,
    metadata: SpMetadata,
    trust: AppliedMetadataTrust,
}

impl SpDescriptor {
    /// Parse SP metadata for an expected entity ID and explicit trust policy.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the XML is malformed, the entity ID is absent
    /// or unexpected, or the requested trust policy cannot be satisfied.
    pub fn from_metadata_xml_for(
        expected_entity_id: EntityId,
        xml: &str,
        trust: MetadataTrustPolicy<'_>,
    ) -> Result<Self, SamlError> {
        validate_entity_id(&expected_entity_id)?;
        let metadata = SpMetadata::from_xml(xml)?;
        let actual_entity_id = metadata_entity_id(&metadata)?;
        ensure_expected_entity_id(&expected_entity_id, actual_entity_id)?;
        let trust = ensure_metadata_trust(&metadata, trust)?;
        Ok(Self {
            entity_id: expected_entity_id,
            metadata_xml: xml.to_string(),
            metadata,
            trust,
        })
    }

    /// Parse SP metadata when the caller accepts the metadata-declared entity ID.
    ///
    /// Prefer [`Self::from_metadata_xml_for`] when the expected entity ID is known.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the XML is malformed, the entity ID is absent,
    /// or the requested trust policy cannot be satisfied.
    pub fn from_metadata_xml(xml: &str, trust: MetadataTrustPolicy<'_>) -> Result<Self, SamlError> {
        let metadata = SpMetadata::from_xml(xml)?;
        let entity_id = EntityId::try_new(metadata_entity_id(&metadata)?)?;
        let trust = ensure_metadata_trust(&metadata, trust)?;
        Ok(Self {
            entity_id,
            metadata_xml: xml.to_string(),
            metadata,
            trust,
        })
    }

    /// Metadata entity ID.
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    /// Original metadata XML.
    pub fn metadata_xml(&self) -> &str {
        &self.metadata_xml
    }

    /// Parsed SP metadata.
    pub fn metadata(&self) -> &SpMetadata {
        &self.metadata
    }

    /// Whether this descriptor was verified with pinned signing certificates.
    pub fn was_verified_with_pinned_certificates(&self) -> bool {
        matches!(
            self.trust,
            AppliedMetadataTrust::SignedByPinnedCertificates { .. }
        )
    }

    /// Signed metadata descriptor XML when pinned metadata verification passed.
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str> {
        match &self.trust {
            AppliedMetadataTrust::SignedByPinnedCertificates {
                signed_entity_descriptor_xml,
            } => Some(signed_entity_descriptor_xml.as_str()),
            AppliedMetadataTrust::UnsignedForCompatibility => None,
        }
    }
}

fn authn_request_signing_enabled(policy: AuthnRequestSigningPolicy) -> bool {
    matches!(policy, AuthnRequestSigningPolicy::Sign)
}

fn authn_request_signature_required(policy: AuthnRequestValidationPolicy) -> bool {
    matches!(policy, AuthnRequestValidationPolicy::RequireSigned)
}

fn assertion_signature_required(policy: AssertionSignaturePolicy) -> bool {
    matches!(policy, AssertionSignaturePolicy::RequireSigned)
}

fn message_signature_required(policy: MessageSignaturePolicy) -> bool {
    matches!(policy, MessageSignaturePolicy::RequireSigned)
}

fn logout_signature_required(policy: LogoutSignaturePolicy) -> Result<bool, SamlError> {
    match policy {
        LogoutSignaturePolicy::RequireSigned => Ok(true),
        LogoutSignaturePolicy::AllowUnsignedForCompatibility => Ok(false),
    }
}

fn metadata_entity_id<M>(metadata: &M) -> Result<&str, SamlError>
where
    M: Deref<Target = Metadata>,
{
    metadata
        .get_entity_id()
        .ok_or_else(|| SamlError::MissingMetadata("entityID".into()))
}

fn ensure_expected_entity_id(expected: &EntityId, actual: &str) -> Result<(), SamlError> {
    if expected.as_str() == actual {
        return Ok(());
    }
    Err(SamlError::Invalid(format!(
        "metadata entityID `{actual}` did not match expected `{}`",
        expected.as_str()
    )))
}

fn ensure_metadata_trust<M>(
    metadata: &M,
    trust: MetadataTrustPolicy<'_>,
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    match trust {
        MetadataTrustPolicy::UnsignedForCompatibility => {
            Ok(AppliedMetadataTrust::UnsignedForCompatibility)
        }
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates,
        } => verify_pinned_metadata_signature(metadata, trusted_certificates),
    }
}

#[cfg(feature = "crypto-bergshamra")]
fn verify_pinned_metadata_signature<M>(
    metadata: &M,
    trusted_certificates: &[CertificatePem],
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    let trusted_certificates: Vec<String> = trusted_certificates
        .iter()
        .map(|certificate| certificate.as_str().to_string())
        .collect();
    let verification = metadata
        .verify_signature_detailed_with_limits(&trusted_certificates, XmlLimits::default())?;
    if verification.verified() {
        let signed_entity_descriptor_xml = verification
            .into_signed_entity_descriptor_xml()
            .ok_or(SamlError::SignedReferenceMismatch)?;
        return Ok(AppliedMetadataTrust::SignedByPinnedCertificates {
            signed_entity_descriptor_xml,
        });
    }
    Err(SamlError::SignatureVerification {
        reason: SignatureVerificationReason::XmlSignature,
    })
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn verify_pinned_metadata_signature<M>(
    _metadata: &M,
    _trusted_certificates: &[CertificatePem],
) -> Result<AppliedMetadataTrust, SamlError>
where
    M: Deref<Target = Metadata>,
{
    Err(SamlError::Unsupported(
        "signed metadata verification requires the crypto-bergshamra feature".into(),
    ))
}

fn name_id_creation_allowed(policy: NameIdCreationPolicy) -> bool {
    matches!(policy, NameIdCreationPolicy::AllowCreate)
}

fn audience_validation_enabled(policy: AudienceValidationPolicy) -> bool {
    matches!(policy, AudienceValidationPolicy::Validate)
}

fn name_id_format_uris(formats: &[NameIdFormat]) -> Vec<String> {
    formats
        .iter()
        .map(|format| format.as_uri().to_string())
        .collect()
}

fn transform_algorithm_uris(algorithms: &[TransformAlgorithm]) -> Vec<String> {
    algorithms
        .iter()
        .map(|algorithm| algorithm.as_uri().to_string())
        .collect()
}

fn apply_common_settings(
    entity_id: &EntityId,
    name_id_format: &[NameIdFormat],
    credentials: &Credentials,
    algorithms: &AlgorithmPolicy,
    xml: &XmlPolicy,
    templates: &TemplatePolicy,
    setting: &mut EntitySetting,
) {
    setting.entity_id = Some(entity_id.as_str().to_string());
    setting.request_signature_algorithm = algorithms.signature.as_uri().to_string();
    setting.data_encryption_algorithm = algorithms.data_encryption.as_uri().to_string();
    setting.key_encryption_algorithm = algorithms.key_encryption.as_uri().to_string();
    setting.message_signing_order = algorithms.message_signing_order;
    setting.is_assertion_encrypted = matches!(
        xml.encryption.assertions,
        AssertionEncryptionPolicy::EncryptAssertions
    );
    setting.allow_insecure_software_rsa_key_transport_decryption = xml
        .encryption
        .allows_insecure_software_rsa_key_transport_decryption();
    setting.relay_state = templates.relay_state.clone();
    setting.name_id_format = name_id_format_uris(name_id_format);
    setting.private_key = credentials
        .signing_key
        .as_ref()
        .map(|key| key.as_str().to_string());
    setting.private_key_pass = credentials
        .signing_key_passphrase
        .as_ref()
        .map(|passphrase| passphrase.as_str().to_string());
    setting.signing_cert = credentials
        .signing_certificate
        .as_ref()
        .map(|certificate| certificate.as_str().to_string());
    setting.encrypt_cert = credentials
        .encryption_certificate
        .as_ref()
        .map(|certificate| certificate.as_str().to_string());
    setting.enc_private_key = credentials
        .decryption_key
        .as_ref()
        .map(|key| key.as_str().to_string());
    setting.enc_private_key_pass = credentials
        .decryption_key_passphrase
        .as_ref()
        .map(|passphrase| passphrase.as_str().to_string());
    setting.clock_drifts = xml.clock_drifts;
    setting.redirect_inflate_max_bytes = xml.redirect_inflate_max_bytes;
    setting.xml_limits = xml.limits;
    setting.tag_prefix_protocol = templates.tag_prefix_protocol.clone();
    setting.tag_prefix_assertion = templates.tag_prefix_assertion.clone();
    setting.tag_prefix_encrypted_assertion = templates.tag_prefix_encrypted_assertion.clone();
    setting.login_response_template = templates.login_response_template.clone();
    setting.login_request_template = templates.login_request_template.clone();
    setting.logout_request_template = templates.logout_request_template.clone();
    setting.logout_response_template = templates.logout_response_template.clone();
    setting.signature_config = templates.signature_config.clone();
    setting.transformation_algorithms =
        transform_algorithm_uris(&algorithms.signed_reference_transforms);
}

impl TryFrom<&SpConfig> for EntitySetting {
    type Error = SamlError;

    fn try_from(config: &SpConfig) -> Result<Self, Self::Error> {
        config.validate()?;
        let mut setting = Self::default();
        apply_common_settings(
            &config.entity_id,
            &config.metadata.name_id_format,
            &config.credentials,
            &config.algorithms,
            &config.xml,
            &config.templates,
            &mut setting,
        );
        setting.allow_create = name_id_creation_allowed(config.validation.name_id_creation);
        setting.authn_requests_signed =
            authn_request_signing_enabled(config.validation.authn_requests);
        setting.want_assertions_signed = assertion_signature_required(config.validation.assertions);
        setting.validate_audience = audience_validation_enabled(config.validation.audience);
        setting.want_message_signed = message_signature_required(config.validation.messages);
        setting.want_logout_request_signed =
            logout_signature_required(config.validation.logout.requests)?;
        setting.want_logout_response_signed =
            logout_signature_required(config.validation.logout.responses)?;
        Ok(setting)
    }
}

impl TryFrom<&IdpConfig> for EntitySetting {
    type Error = SamlError;

    fn try_from(config: &IdpConfig) -> Result<Self, Self::Error> {
        config.validate()?;
        let mut setting = Self::default();
        apply_common_settings(
            &config.entity_id,
            &config.metadata.name_id_format,
            &config.credentials,
            &config.algorithms,
            &config.xml,
            &config.templates,
            &mut setting,
        );
        setting.want_authn_requests_signed =
            authn_request_signature_required(config.validation.authn_requests);
        setting.want_logout_request_signed =
            logout_signature_required(config.validation.logout.requests)?;
        setting.want_logout_response_signed =
            logout_signature_required(config.validation.logout.responses)?;
        Ok(setting)
    }
}
