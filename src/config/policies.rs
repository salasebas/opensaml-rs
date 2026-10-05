use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::constants::MessageSignatureOrder;
use crate::entity::SignatureConfig;
use crate::error::SamlError;
use crate::template::LoginResponseTemplate;
use crate::xml::XmlLimits;

use super::algorithms::{
    DataEncryptionAlgorithm, KeyEncryptionAlgorithm, SignatureAlgorithm, TransformAlgorithm,
};

/// Whether an accepting service provider requires a signature on the Assertion
/// itself.
///
/// Web Browser SSO over HTTP POST requires each assertion to be protected by
/// a digital signature on the `<Assertion>` or on the enclosing `<Response>`
/// (SAML V2.0 Approved Errata 05 E26, Profiles §4.1.4.5). Errata 05 E93 says a
/// deployment may also sign both, for non-repudiation, and places that outside
/// SAML. [`Self::RequireSigned`] is that library hardening: inbound
/// acceptance, selected by name, off unless the caller sets it.
/// [`Self::AllowUnsignedForCompatibility`] leaves the hardening off and still
/// accepts a standards-valid response signed only on the `<Response>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssertionSignaturePolicy {
    /// Reject an assertion that is not directly signed.
    ///
    /// Library hardening for the accepting service provider. It does not
    /// select [`XmlSignatureProfile::StrictRsaSha2`].
    RequireSigned,
    /// Do not require a signature directly on the Assertion.
    ///
    /// HTTP POST still requires the assertion to be protected by an Assertion
    /// signature or a Response signature.
    #[default]
    AllowUnsignedForCompatibility,
}

/// Whether an accepting service provider requires authentication of the
/// `<Response>`.
///
/// Approved Errata 05 E93 replaces Core §6.2 and adds a note to Profiles
/// §4.1.4.3: when CBC-mode encryption protects an `<EncryptedAssertion>`, the
/// relying party should require integrity protection, and the `<Response>`
/// should be signed, before the ciphertext is processed. That recommendation
/// obligates the accepting service provider on inbound acceptance.
/// [`Self::RequireForEncryptedCbc`] follows it.
/// [`Self::AllowUnsignedEncryptedCbcForCompatibility`] relaxes that
/// recommendation alone. It does not remove the HTTP POST rule that each
/// assertion must be protected by a signature on the Assertion or the
/// Response.
///
/// [`Self::RequireSigned`] requires a Response signature on every response.
/// The profile allows an Assertion signature instead, so this variant is
/// library hardening and is not part of the Web Browser SSO accept
/// combination below.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResponseSignaturePolicy {
    /// Do not apply the E93 Response-signature recommendation.
    ///
    /// Inbound acceptance, named relaxation of that recommendation.
    #[default]
    AllowUnsignedEncryptedCbcForCompatibility,
    /// Require a signed Response when an `<EncryptedAssertion>` uses CBC.
    ///
    /// Inbound acceptance, recommendation, accepting service provider.
    RequireForEncryptedCbc,
    /// Require Response authentication for every response.
    ///
    /// Library hardening for the accepting service provider.
    RequireSigned,
}

/// Inbound embedded XML-signature algorithm and reference profile.
///
/// The selected profile applies to every embedded signature that authenticates
/// an accepted SSO or Single Logout message. SAML V2.0 Conformance §4.1
/// requires RSAwithSHA1, and Core §5.4.1 says processors should support
/// `rsa-sha1`. Core §5.4.4 lets a verifier reject other transforms; it does
/// not require that rejection. [`Self::StrictRsaSha2`] is therefore library
/// hardening for the accepting party, inbound, and it is independent of
/// [`AssertionSignaturePolicy`]. [`SpValidationPolicy::strict`] keeps the
/// provider-supported profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum XmlSignatureProfile {
    /// Require one local `#id` reference, RSA-SHA256/384/512, a SHA-256/384/512
    /// digest, and exclusive canonicalization. Each transform element, when
    /// present, must belong to the XML-DSig namespace and use enveloped-signature
    /// or exclusive canonicalization.
    ///
    /// Library hardening. Selecting it does not require a signature directly
    /// on the Assertion.
    StrictRsaSha2,
    /// Accept every algorithm and same-document reference shape supported by
    /// the selected cryptographic provider.
    #[default]
    AllowProviderSupportedForCompatibility,
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

/// Whether an identity provider requires a signed inbound `<AuthnRequest>`.
///
/// Web Browser SSO says the request may be signed (Profiles §4.1.4.1) and
/// that `WantAuthnRequestsSigned` may document a requirement (Profiles
/// §4.1.6). Requiring a signature is an optional inbound capability for the
/// identity provider. It stays off unless the caller selects
/// [`Self::RequireSigned`]. Core §3.2.1 requires the responder to verify a
/// signature that is present. [`Self::AllowUnsignedVerifyIfPresent`] does
/// that and still accepts an unsigned request.
/// [`Self::AllowUnsignedForCompatibility`] does not verify a present
/// signature.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthnRequestValidationPolicy {
    /// Reject unsigned AuthnRequests.
    ///
    /// Optional inbound capability for the identity provider.
    RequireSigned,
    /// Accept an unsigned AuthnRequest and verify a signature that is present.
    ///
    /// Verifying a present signature is mandatory for the identity provider
    /// (Core §3.2.1). Requiring a signature stays off.
    AllowUnsignedVerifyIfPresent,
    /// Accept unsigned AuthnRequests without verifying a signature that is
    /// present.
    ///
    /// Compatibility hatch for the mandatory present-signature check.
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

/// Whether an accepting service provider evaluates `<AudienceRestriction>`.
///
/// Core §2.5.1.4, as clarified by Approved Errata 05 E46, makes an audience
/// restriction Valid only when the relying party is a member of one of its
/// audiences, and multiple restrictions form a conjunction. Core §2.5.1.1
/// says the relying party must reject an assertion whose conditions are
/// Invalid or Indeterminate. That is a mandatory inbound rule for the
/// accepting service provider when a restriction is present.
/// [`Self::EvaluatePresentRestrictions`] enforces that rule.
/// [`Self::Validate`] also rejects a bearer assertion that omits the
/// element. Errata 05 E26 (Profiles §4.1.4.2) requires the identity provider
/// to include one. Core condition processing does not make that omission
/// Invalid, so the extra rejection is library hardening.
/// [`Self::SkipForCompatibility`] skips the check. It is the compatibility
/// hatch, not the named relaxation of a recommendation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AudienceValidationPolicy {
    /// Evaluate audience restrictions and reject a bearer assertion that
    /// omits one.
    ///
    /// The present-restriction check is mandatory. Rejecting an omission is
    /// library hardening. [`SpValidationPolicy::strict`] keeps this variant.
    #[default]
    Validate,
    /// Evaluate `<AudienceRestriction>` elements that are present.
    ///
    /// Mandatory inbound rule for the accepting service provider when a
    /// restriction is present (Core §2.5.1.1 and §2.5.1.4, Errata 05 E46).
    /// A bearer assertion that omits the element is not rejected.
    EvaluatePresentRestrictions,
    /// Skip audience evaluation for legacy interoperability.
    ///
    /// Compatibility hatch for the mandatory audience check.
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
///
/// # Web Browser SSO acceptance
///
/// `finish_sso` and `accept_unsolicited_sso` read these fields. There is no
/// `recommended()` constructor. The accept combination for that profile is
/// the fields below; outbound AuthnRequest signing, identifier creation, and
/// logout are not part of this accept classification. Single Logout acceptance
/// is classified on [`LogoutPolicy`].
///
/// - `assertions`: [`AssertionSignaturePolicy::AllowUnsignedForCompatibility`].
///   Actor: accepting service provider. Direction: inbound. Level: library
///   hardening, off.
/// - `responses`: [`ResponseSignaturePolicy::RequireForEncryptedCbc`].
///   Actor: accepting service provider. Direction: inbound. Level:
///   recommendation, on. Relax it with
///   [`ResponseSignaturePolicy::AllowUnsignedEncryptedCbcForCompatibility`].
/// - `xml_signatures`:
///   [`XmlSignatureProfile::AllowProviderSupportedForCompatibility`].
///   Actor: accepting service provider. Direction: inbound. Level: library
///   hardening, off.
/// - `audience`: [`AudienceValidationPolicy::EvaluatePresentRestrictions`].
///   Actor: accepting service provider. Direction: inbound. Level: mandatory
///   when an `<AudienceRestriction>` is present.
///   [`AudienceValidationPolicy::Validate`] also rejects a missing
///   restriction. Actor: accepting service provider. Direction: inbound.
///   Level: library hardening, off in this combination. `strict()` keeps
///   `Validate`.
///
/// These inbound rules have no field and no off switch:
///
/// - UTC `IssueInstant` on the Response and the Assertion. Actor: accepting
///   service provider. Direction: inbound. Level: mandatory (assertion and
///   protocol schemas; Core §1.3.3 and §3.2.2). Core §1.3.3 forbids a
///   producer from generating a leap second. Actor: producer. Direction:
///   outbound. Level: mandatory. It does not require the receiver to reject
///   an inbound leap-second value.
/// - HTTP POST protects each assertion with a signature on the Assertion or
///   the Response. Actor: accepting service provider. Direction: inbound.
///   Level: mandatory (Errata 05 E26, Profiles §4.1.4.5).
/// - Bearer `Recipient`, `NotOnOrAfter`, and `InResponseTo`. Actor: accepting
///   service provider. Direction: inbound. Level: mandatory (Errata 05 E26,
///   Profiles §4.1.4.3). An unsolicited response must not carry
///   `InResponseTo` (Profiles §4.1.4.3 and §4.1.5).
/// - A present `Destination` identifies the actual recipient. Actor:
///   accepting service provider. Direction: inbound. Level: mandatory (Core
///   §3.2.2). A signed HTTP Redirect or HTTP POST message carries
///   `Destination`, and the recipient verifies it (Bindings §3.4.5.2 and
///   §3.5.5.2). Level: mandatory when the message is signed.
///
/// Checking the bearer `Address` stays off. Actor: accepting service
/// provider. Direction: inbound. Level: optional (Profiles §4.1.4.3).
/// HTTP POST replay is mandatory for the accepting service provider
/// (Profiles §4.1.4.5) and remains a caller-supplied
/// [`crate::ReplayPolicy`]. This combination does not enable it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpValidationPolicy {
    /// Assertion signature requirement.
    pub assertions: AssertionSignaturePolicy,
    /// Top-level SAML Response signature requirement.
    pub responses: ResponseSignaturePolicy,
    /// Embedded XML-signature algorithm and reference requirements.
    pub xml_signatures: XmlSignatureProfile,
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
            responses: ResponseSignaturePolicy::RequireForEncryptedCbc,
            xml_signatures: XmlSignatureProfile::AllowProviderSupportedForCompatibility,
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
            responses: ResponseSignaturePolicy::AllowUnsignedEncryptedCbcForCompatibility,
            xml_signatures: XmlSignatureProfile::AllowProviderSupportedForCompatibility,
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
///
/// # Web Browser SSO acceptance
///
/// `receive_sso` reads `authn_requests`. There is no `recommended()`
/// constructor. The accept combination uses
/// [`AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent`].
/// Requiring a signature is optional and stays off. Verifying a signature
/// that is present is mandatory (Core §3.2.1). Logout is not part of this
/// accept classification. Single Logout acceptance is classified on
/// [`LogoutPolicy`].
///
/// These inbound rules have no field and no off switch:
///
/// - UTC `IssueInstant`. Actor: identity provider. Direction: inbound.
///   Level: mandatory (Core §1.3.3 and §3.2.1). An inbound leap-second value
///   stays accepted.
/// - A present `Destination` identifies this identity provider's SSO
///   endpoint. Actor: identity provider. Direction: inbound. Level:
///   mandatory (Core §3.2.1). The identity provider discards the request
///   when it does not.
/// - `AssertionConsumerServiceURL` or `AssertionConsumerServiceIndex`
///   belongs to the service provider before the response is sent. Actor:
///   identity provider. Direction: inbound. Level: mandatory (Profiles
///   §4.1.4.1). The check runs when the response is issued.
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
///
/// # Single Logout acceptance
///
/// `finish_slo` reads `responses`. `receive_slo` reads `requests`. There is
/// no `recommended()` constructor. The accept combination is
/// [`LogoutSignaturePolicy::RequireSigned`] for both fields. Callers select
/// it by setting those fields. [`Self::compatibility`] leaves both at
/// [`LogoutSignaturePolicy::AllowUnsignedForCompatibility`]. [`Self::strict`]
/// is unchanged and already uses [`LogoutSignaturePolicy::RequireSigned`].
///
/// - `requests`: [`LogoutSignaturePolicy::RequireSigned`]. Actor: the
///   recipient of a `LogoutRequest` (session participant or session
///   authority). Direction: inbound. Level: mandatory for HTTP-Redirect,
///   HTTP-POST, and HTTP-POST-SimpleSign (Profiles §4.4.3.1, §4.4.4.1, and
///   Core §3.7.3.1 / §3.7.3.2).
///   [`LogoutSignaturePolicy::AllowUnsignedForCompatibility`] is the
///   compatibility hatch, not a named relaxation of a recommendation.
/// - `responses`: [`LogoutSignaturePolicy::RequireSigned`]. Actor: the
///   recipient of a `LogoutResponse`. Direction: inbound. Level: mandatory
///   for those same bindings (Profiles §4.4.3.4 and §4.4.4.2). The
///   compatibility hatch is the same unsigned variant.
///
/// These inbound rules have no field and no off switch:
///
/// - UTC `IssueInstant`. Actor: the logout recipient. Direction: inbound.
///   Level: mandatory (protocol schema; Core §1.3.3). An inbound leap-second
///   value stays accepted. Core §1.3.3 forbids a producer from generating
///   one and does not require the recipient to reject it.
/// - A present `Destination` identifies the actual recipient. Actor: the
///   logout recipient. Direction: inbound. Level: mandatory (Core §3.2.1 and
///   §3.2.2). A signed HTTP-Redirect, HTTP-POST, or HTTP-POST-SimpleSign
///   message carries `Destination`, and the recipient verifies it. Level:
///   mandatory when the message is signed.
/// - `InResponseTo` on a typed `LogoutResponse` matches the pending
///   `LogoutRequest`. Actor: the original requester. Direction: inbound.
///   Level: mandatory for this typed exchange (Core §3.2.2).
///
/// Rejecting an expired `LogoutRequest@NotOnOrAfter` stays library policy.
/// Core permits a recipient to discard the message after that instant and
/// does not require rejection. [`XmlSignatureProfile::StrictRsaSha2`] stays
/// library hardening and is not selected by this combination.
///
/// Producer rules for `start_slo` and `respond_slo` are selected with
/// [`crate::StartSlo::apply_single_logout_generation_rules`] and
/// [`crate::RespondSlo::apply_single_logout_generation_rules`]. They are not
/// fields of this policy. Requiring a logout signature here does not come
/// from the producer's TLS recommendation.
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

    /// Explicitly allow RustCrypto software RSA key-transport decryption despite
    /// `RUSTSEC-2023-0071` timing-risk concerns in that backend.
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
/// Software RSA key-transport decryption is disabled by default on the
/// RustCrypto provider because that backend, reached through `bergshamra` /
/// `kryptering`, is affected by `RUSTSEC-2023-0071`. Enable it only as an
/// explicit compatibility exception for a RustCrypto deployment that accepts
/// that risk. AWS-LC and FIPS ignore this opt-in.
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
    ///
    /// Typed Session Authority generation requires a complete unqualified
    /// `NotOnOrAfter="{NotOnOrAfter}"` root attribute. Typed SP and raw
    /// compatibility generation do not synthesize the attribute.
    pub logout_request_template: Option<String>,
    /// Logout response template.
    ///
    /// After prefix and placeholder substitution, the final outbound XML must
    /// satisfy the enforced LogoutResponse structure, issuer, destination, and
    /// request-correlation requirements. A root `<ds:Signature>` is rejected
    /// before signing so the library owns signature construction. When
    /// `InResponseTo` is `None`, an attribute whose complete value is the
    /// `{InResponseTo}` placeholder is omitted.
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

pub(super) fn verify_present_authn_request_signature(policy: AuthnRequestValidationPolicy) -> bool {
    matches!(
        policy,
        AuthnRequestValidationPolicy::AllowUnsignedVerifyIfPresent
    )
}

pub(super) fn assertion_signature_required(policy: AssertionSignaturePolicy) -> bool {
    matches!(policy, AssertionSignaturePolicy::RequireSigned)
}

pub(super) fn response_signature_required(policy: ResponseSignaturePolicy) -> bool {
    matches!(policy, ResponseSignaturePolicy::RequireSigned)
}

pub(super) fn encrypted_cbc_response_signature_required(policy: ResponseSignaturePolicy) -> bool {
    matches!(policy, ResponseSignaturePolicy::RequireForEncryptedCbc)
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
    matches!(
        policy,
        AudienceValidationPolicy::Validate | AudienceValidationPolicy::EvaluatePresentRestrictions
    )
}

pub(super) fn audience_restriction_required(policy: AudienceValidationPolicy) -> bool {
    matches!(policy, AudienceValidationPolicy::Validate)
}
