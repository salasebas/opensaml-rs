use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::constants::MessageSignatureOrder;
use crate::entity::SignatureConfig;
use crate::error::SamlError;
use crate::template::LoginResponseTemplate;
use crate::xml::XmlLimits;

use super::algorithms::{
    DataEncryptionAlgorithm, KeyEncryptionAlgorithm, SignatureAlgorithm, TransformAlgorithm,
};

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

    pub(super) fn allows_insecure_software_rsa_key_transport_decryption(self) -> bool {
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
    ///
    /// The final XML after prefix and placeholder substitution must be
    /// structurally valid and satisfy the LogoutResponse protocol profile.
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
pub(super) fn authn_request_signing_enabled(policy: AuthnRequestSigningPolicy) -> bool {
    matches!(policy, AuthnRequestSigningPolicy::Sign)
}

pub(super) fn authn_request_signature_required(policy: AuthnRequestValidationPolicy) -> bool {
    matches!(policy, AuthnRequestValidationPolicy::RequireSigned)
}

pub(super) fn assertion_signature_required(policy: AssertionSignaturePolicy) -> bool {
    matches!(policy, AssertionSignaturePolicy::RequireSigned)
}

pub(super) fn message_signature_required(policy: MessageSignaturePolicy) -> bool {
    matches!(policy, MessageSignaturePolicy::RequireSigned)
}

pub(super) fn logout_signature_required(policy: LogoutSignaturePolicy) -> Result<bool, SamlError> {
    match policy {
        LogoutSignaturePolicy::RequireSigned => Ok(true),
        LogoutSignaturePolicy::AllowUnsignedForCompatibility => Ok(false),
    }
}
pub(super) fn name_id_creation_allowed(policy: NameIdCreationPolicy) -> bool {
    matches!(policy, NameIdCreationPolicy::AllowCreate)
}

pub(super) fn audience_validation_enabled(policy: AudienceValidationPolicy) -> bool {
    matches!(policy, AudienceValidationPolicy::Validate)
}
