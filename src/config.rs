//! Typed configuration building blocks for high-level SAML APIs.

use core::fmt;
use core::marker::PhantomData;
use core::ops::Deref;

use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::constants::{
    data_encryption_algorithm, digest_algorithm, key_encryption_algorithm, name_id_format,
    signature_algorithm, transform_algorithm, Binding, MessageSignatureOrder,
};
use crate::entity::{EntitySetting, SignatureConfig};
use crate::error::SamlError;
use crate::metadata::{Endpoint, IdpMetadata, Metadata, SpMetadata};
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

    /// Borrow the PEM text for internal compatibility mapping.
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

    /// Borrow the passphrase text for internal compatibility mapping.
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
    /// SHA-1 digest.
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
    pub fn as_uri(&self) -> &str {
        match self {
            Self::Sha1 => digest_algorithm::SHA1,
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
    /// Triple DES CBC.
    TripleDes,
    /// AES-128-GCM.
    Aes128Gcm,
    /// Backend-specific content encryption algorithm URI.
    Custom(String),
}

impl DataEncryptionAlgorithm {
    /// Return the XML-Enc algorithm URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::Aes128 => data_encryption_algorithm::AES_128,
            Self::Aes256 => data_encryption_algorithm::AES_256,
            Self::TripleDes => data_encryption_algorithm::TRIPLE_DES,
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
    /// RSAES-PKCS1-v1_5.
    Rsa15,
    /// Backend-specific key transport algorithm URI.
    Custom(String),
}

impl KeyEncryptionAlgorithm {
    /// Return the XML-Enc key transport algorithm URI.
    pub fn as_uri(&self) -> &str {
        match self {
            Self::RsaOaepMgf1p => key_encryption_algorithm::RSA_OAEP_MGF1P,
            Self::Rsa15 => key_encryption_algorithm::RSA_1_5,
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
    /// Wrap an entity ID URI or deployment-specific identifier.
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
        if value.trim().is_empty() {
            return Err(SamlError::Invalid("entity ID must not be empty".into()));
        }
        Ok(Self(value))
    }

    /// Borrow the entity ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for EntityId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for EntityId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Browser SSO request bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsoRequestBinding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
}

impl SsoRequestBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Redirect => Binding::Redirect,
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
        }
    }
}

impl From<SsoRequestBinding> for Binding {
    fn from(value: SsoRequestBinding) -> Self {
        value.as_binding()
    }
}

impl TryFrom<Binding> for SsoRequestBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Redirect => Ok(Self::Redirect),
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Artifact => Err(SamlError::UndefinedBinding),
        }
    }
}

/// Browser SSO response bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsoResponseBinding {
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
}

impl SsoResponseBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
        }
    }
}

impl From<SsoResponseBinding> for Binding {
    fn from(value: SsoResponseBinding) -> Self {
        value.as_binding()
    }
}

impl TryFrom<Binding> for SsoResponseBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Redirect | Binding::Artifact => Err(SamlError::UndefinedBinding),
        }
    }
}

/// Single Logout bindings supported by the typed API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogoutBinding {
    /// HTTP-Redirect binding.
    Redirect,
    /// HTTP-POST binding.
    Post,
    /// HTTP-POST-SimpleSign binding.
    SimpleSign,
}

impl LogoutBinding {
    /// Convert to the raw compatibility binding.
    pub fn as_binding(self) -> Binding {
        match self {
            Self::Redirect => Binding::Redirect,
            Self::Post => Binding::Post,
            Self::SimpleSign => Binding::SimpleSign,
        }
    }
}

impl From<LogoutBinding> for Binding {
    fn from(value: LogoutBinding) -> Self {
        value.as_binding()
    }
}

impl TryFrom<Binding> for LogoutBinding {
    type Error = SamlError;

    fn try_from(value: Binding) -> Result<Self, Self::Error> {
        match value {
            Binding::Redirect => Ok(Self::Redirect),
            Binding::Post => Ok(Self::Post),
            Binding::SimpleSign => Ok(Self::SimpleSign),
            Binding::Artifact => Err(SamlError::UndefinedBinding),
        }
    }
}

/// Absolute HTTP(S) endpoint URL used by typed SAML endpoint wrappers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointUrl(String);

impl EndpointUrl {
    /// Validate and wrap an absolute HTTP(S) URL.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the URL is not absolute HTTP(S).
    pub fn new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        let parsed = url::Url::parse(&value).map_err(|err| SamlError::Invalid(err.to_string()))?;
        if matches!(parsed.scheme(), "http" | "https") && parsed.has_host() {
            return Ok(Self(value));
        }
        Err(SamlError::Invalid(
            "endpoint URL must be absolute HTTP(S)".into(),
        ))
    }

    /// Borrow the URL string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Single Sign-On service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoEndpoint {
    binding: SsoRequestBinding,
    url: EndpointUrl,
}

impl SsoEndpoint {
    /// Create an SSO endpoint from an already validated URL.
    pub fn new(binding: SsoRequestBinding, url: EndpointUrl) -> Self {
        Self { binding, url }
    }

    /// Create an HTTP-Redirect SSO endpoint.
    pub fn redirect(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::Redirect,
            EndpointUrl::new(url)?,
        ))
    }

    /// Create an HTTP-POST SSO endpoint.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(SsoRequestBinding::Post, EndpointUrl::new(url)?))
    }

    /// Create an HTTP-POST-SimpleSign SSO endpoint.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::SimpleSign,
            EndpointUrl::new(url)?,
        ))
    }

    /// Narrow a raw metadata endpoint into an SSO endpoint.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoRequestBinding::try_from(endpoint.binding)?,
            EndpointUrl::new(endpoint.location)?,
        ))
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            is_default: false,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> SsoRequestBinding {
        self.binding
    }

    /// Endpoint URL.
    pub fn url(&self) -> &EndpointUrl {
        &self.url
    }
}

/// Assertion Consumer Service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcsEndpoint {
    binding: SsoResponseBinding,
    url: EndpointUrl,
    index: Option<u16>,
    is_default: bool,
}

impl AcsEndpoint {
    /// Create an ACS endpoint from an already validated URL.
    pub fn new(binding: SsoResponseBinding, url: EndpointUrl) -> Self {
        Self {
            binding,
            url,
            index: None,
            is_default: false,
        }
    }

    /// Create an HTTP-POST ACS endpoint.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(SsoResponseBinding::Post, EndpointUrl::new(url)?))
    }

    /// Create an HTTP-POST-SimpleSign ACS endpoint.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(
            SsoResponseBinding::SimpleSign,
            EndpointUrl::new(url)?,
        ))
    }

    /// Set the ACS index advertised in metadata.
    pub fn with_index(mut self, index: u16) -> Self {
        self.index = Some(index);
        self
    }

    /// Mark this ACS endpoint as the default endpoint in metadata.
    pub fn with_default(mut self, is_default: bool) -> Self {
        self.is_default = is_default;
        self
    }

    /// Narrow a raw metadata endpoint into an ACS endpoint.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self {
            binding: SsoResponseBinding::try_from(endpoint.binding)?,
            url: EndpointUrl::new(endpoint.location)?,
            index: None,
            is_default: endpoint.is_default,
        })
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            is_default: self.is_default,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> SsoResponseBinding {
        self.binding
    }

    /// Endpoint URL.
    pub fn url(&self) -> &EndpointUrl {
        &self.url
    }

    /// ACS index advertised in metadata.
    pub fn index(&self) -> Option<u16> {
        self.index
    }

    /// Whether this ACS endpoint is the default metadata endpoint.
    pub fn is_default(&self) -> bool {
        self.is_default
    }
}

/// Correlation ID for an AuthnRequest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(String);

impl RequestId {
    /// Validate and wrap a request ID.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the request ID is empty.
    pub fn new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SamlError::Invalid("request ID must not be empty".into()));
        }
        Ok(Self(value))
    }

    /// Borrow the request ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RelayState represented as absent, present empty, or present with a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RelayStateState {
    /// No RelayState parameter was sent.
    Absent,
    /// RelayState was sent with an empty value.
    PresentEmpty,
    /// RelayState was sent with a non-empty value.
    PresentValue(String),
}

impl RelayStateState {
    /// Preserve the exact RelayState presence state from an optional value.
    pub fn from_option(value: Option<impl Into<String>>) -> Self {
        match value {
            None => Self::Absent,
            Some(value) => {
                let value = value.into();
                if value.is_empty() {
                    Self::PresentEmpty
                } else {
                    Self::PresentValue(value)
                }
            }
        }
    }

    /// Borrow RelayState as an optional value.
    pub fn as_deref(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::PresentEmpty => Some(""),
            Self::PresentValue(value) => Some(value.as_str()),
        }
    }

    fn validate(&self) -> Result<(), SamlError> {
        if matches!(self, Self::PresentValue(value) if value.is_empty()) {
            return Err(SamlError::Invalid(
                "RelayState PresentValue must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// SAML instant text carried in pending snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SamlInstant(String);

impl SamlInstant {
    /// Validate and wrap a SAML instant string.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the instant is empty. Full temporal
    /// enforcement is left to the validation policy that consumes the pending
    /// state.
    pub fn new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SamlError::Invalid("SAML instant must not be empty".into()));
        }
        Ok(Self(value))
    }

    /// Borrow the instant string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Marker type for AuthnRequest pending state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthnRequest {}

/// Persistable correlation snapshot for a pending SAML message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSnapshot<Message> {
    /// Correlation ID.
    pub id: String,
    /// Exact RelayState state.
    pub relay_state: RelayStateState,
    /// Peer entity ID.
    pub peer_entity_id: String,
    /// Expected response binding keyword.
    pub expected_binding: String,
    /// Selected ACS URL.
    pub acs_url: String,
    /// Selected ACS binding keyword.
    pub acs_binding: String,
    /// Selected ACS index, if any.
    pub acs_index: Option<u16>,
    /// Whether the selected ACS was default.
    pub acs_is_default: bool,
    /// Issue instant, if recorded.
    pub issued_at: Option<SamlInstant>,
    /// Expiration instant, if recorded.
    pub expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}

impl PendingSnapshot<AuthnRequest> {
    /// Build an AuthnRequest snapshot from persistence fields.
    pub fn authn_request(
        id: impl Into<String>,
        relay_state: RelayStateState,
        peer_entity_id: impl Into<String>,
        expected_binding: impl Into<String>,
        acs_url: impl Into<String>,
        acs_binding: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            relay_state,
            peer_entity_id: peer_entity_id.into(),
            expected_binding: expected_binding.into(),
            acs_url: acs_url.into(),
            acs_binding: acs_binding.into(),
            acs_index: None,
            acs_is_default: false,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        }
    }
}

/// Pending AuthnRequest correlation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthnRequest {
    request_id: RequestId,
    relay_state: RelayStateState,
    acs: AcsEndpoint,
    response_binding: SsoResponseBinding,
    idp_entity_id: EntityId,
    issued_at: Option<SamlInstant>,
    expires_at: Option<SamlInstant>,
}

impl PendingAuthnRequest {
    /// Create pending AuthnRequest state without storing keys or metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the RelayState state is malformed,
    /// the IdP entity ID is empty, or the selected ACS binding does not match
    /// the expected response binding.
    pub fn new(
        request_id: RequestId,
        relay_state: RelayStateState,
        acs: AcsEndpoint,
        response_binding: SsoResponseBinding,
        idp_entity_id: EntityId,
    ) -> Result<Self, SamlError> {
        relay_state.validate()?;
        EntityId::try_new(idp_entity_id.as_str().to_string())?;
        if acs.binding() != response_binding {
            return Err(SamlError::Invalid(
                "ACS binding must match expected response binding".into(),
            ));
        }
        Ok(Self {
            request_id,
            relay_state,
            acs,
            response_binding,
            idp_entity_id,
            issued_at: None,
            expires_at: None,
        })
    }

    /// Record an issue instant.
    pub fn with_issue_instant(mut self, issued_at: SamlInstant) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    /// Record an expiration instant.
    pub fn with_expiration(mut self, expires_at: SamlInstant) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Reconstruct pending AuthnRequest state from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when any snapshot field is malformed or
    /// inconsistent.
    pub fn from_snapshot(snapshot: PendingSnapshot<AuthnRequest>) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        if snapshot.expires_at.is_some() && snapshot.issued_at.is_none() {
            return Err(SamlError::Invalid(
                "pending snapshot expiration requires an issue instant".into(),
            ));
        }
        let request_id = RequestId::new(snapshot.id)?;
        let idp_entity_id = EntityId::try_new(snapshot.peer_entity_id)?;
        let response_binding =
            sso_response_binding_from_snapshot_value(&snapshot.expected_binding)?;
        let acs_binding = sso_response_binding_from_snapshot_value(&snapshot.acs_binding)?;
        let mut acs = AcsEndpoint::new(acs_binding, EndpointUrl::new(snapshot.acs_url)?)
            .with_default(snapshot.acs_is_default);
        if let Some(index) = snapshot.acs_index {
            acs = acs.with_index(index);
        }
        let mut pending = Self::new(
            request_id,
            snapshot.relay_state,
            acs,
            response_binding,
            idp_entity_id,
        )?;
        pending.issued_at = snapshot.issued_at;
        pending.expires_at = snapshot.expires_at;
        Ok(pending)
    }

    /// Build a persistable snapshot.
    pub fn snapshot(&self) -> PendingSnapshot<AuthnRequest> {
        let mut snapshot = PendingSnapshot::authn_request(
            self.request_id.as_str(),
            self.relay_state.clone(),
            self.idp_entity_id.as_str(),
            self.response_binding.as_binding().short_name(),
            self.acs.url().as_str(),
            self.acs.binding().as_binding().short_name(),
        );
        snapshot.acs_index = self.acs.index();
        snapshot.acs_is_default = self.acs.is_default();
        snapshot.issued_at = self.issued_at.clone();
        snapshot.expires_at = self.expires_at.clone();
        snapshot
    }

    /// Request ID.
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// RelayState state.
    pub fn relay_state(&self) -> &RelayStateState {
        &self.relay_state
    }

    /// Selected ACS endpoint.
    pub fn acs(&self) -> &AcsEndpoint {
        &self.acs
    }

    /// Expected response binding.
    pub fn response_binding(&self) -> SsoResponseBinding {
        self.response_binding
    }

    /// Selected IdP entity ID.
    pub fn idp_entity_id(&self) -> &EntityId {
        &self.idp_entity_id
    }

    /// Issue instant, if recorded.
    pub fn issued_at(&self) -> Option<&SamlInstant> {
        self.issued_at.as_ref()
    }

    /// Expiration instant, if recorded.
    pub fn expires_at(&self) -> Option<&SamlInstant> {
        self.expires_at.as_ref()
    }
}

fn sso_response_binding_from_snapshot_value(value: &str) -> Result<SsoResponseBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    SsoResponseBinding::try_from(binding)
}

/// Single Logout service endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SloEndpoint {
    binding: LogoutBinding,
    url: EndpointUrl,
}

impl SloEndpoint {
    /// Create an SLO endpoint from an already validated URL.
    pub fn new(binding: LogoutBinding, url: EndpointUrl) -> Self {
        Self { binding, url }
    }

    /// Create an HTTP-Redirect SLO endpoint.
    pub fn redirect(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(LogoutBinding::Redirect, EndpointUrl::new(url)?))
    }

    /// Create an HTTP-POST SLO endpoint.
    pub fn post(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(LogoutBinding::Post, EndpointUrl::new(url)?))
    }

    /// Create an HTTP-POST-SimpleSign SLO endpoint.
    pub fn simple_sign(url: impl Into<String>) -> Result<Self, SamlError> {
        Ok(Self::new(LogoutBinding::SimpleSign, EndpointUrl::new(url)?))
    }

    /// Narrow a raw metadata endpoint into an SLO endpoint.
    pub fn try_from_raw(endpoint: Endpoint) -> Result<Self, SamlError> {
        Ok(Self::new(
            LogoutBinding::try_from(endpoint.binding)?,
            EndpointUrl::new(endpoint.location)?,
        ))
    }

    /// Convert to the raw metadata endpoint shape.
    pub fn to_raw(&self) -> Endpoint {
        Endpoint {
            binding: self.binding.as_binding(),
            location: self.url.as_str().to_string(),
            is_default: false,
        }
    }

    /// Endpoint binding.
    pub fn binding(&self) -> LogoutBinding {
        self.binding
    }

    /// Endpoint URL.
    pub fn url(&self) -> &EndpointUrl {
        &self.url
    }
}

/// Local SP metadata inputs used by typed configuration.
#[derive(Debug, Clone)]
pub struct SpMetadataConfigTyped {
    /// `<NameIDFormat>` values advertised by the SP.
    pub name_id_format: Vec<NameIdFormat>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<Endpoint>,
    /// `AssertionConsumerService` endpoints.
    pub assertion_consumer_service: Vec<Endpoint>,
    /// Element ordering profile for generated metadata.
    pub elements_order: Option<Vec<String>>,
}

impl SpMetadataConfigTyped {
    /// Create SP metadata input with required ACS endpoints visible at the call site.
    pub fn new(assertion_consumer_service: Vec<Endpoint>) -> Self {
        Self {
            name_id_format: Vec::new(),
            single_logout_service: Vec::new(),
            assertion_consumer_service,
            elements_order: None,
        }
    }
}

/// Local IdP metadata inputs used by typed configuration.
#[derive(Debug, Clone)]
pub struct IdpMetadataConfigTyped {
    /// `<NameIDFormat>` values advertised by the IdP.
    pub name_id_format: Vec<NameIdFormat>,
    /// `SingleSignOnService` endpoints.
    pub single_sign_on_service: Vec<Endpoint>,
    /// `SingleLogoutService` endpoints.
    pub single_logout_service: Vec<Endpoint>,
    /// Element ordering profile for generated metadata.
    pub elements_order: Option<Vec<String>>,
}

impl IdpMetadataConfigTyped {
    /// Create IdP metadata input with required SSO endpoints visible at the call site.
    pub fn new(single_sign_on_service: Vec<Endpoint>) -> Self {
        Self {
            name_id_format: Vec::new(),
            single_sign_on_service,
            single_logout_service: Vec::new(),
            elements_order: None,
        }
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

/// Whether AuthnRequests are, or must be, signed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthnRequestSignaturePolicy {
    /// Require a signed AuthnRequest or sign outgoing AuthnRequests.
    RequireSigned,
    /// Allow unsigned AuthnRequests for legacy interoperability.
    #[default]
    AllowUnsignedForCompatibility,
}

/// Whether logout messages require signatures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogoutSignaturePolicy {
    /// Reject unsigned logout messages.
    #[default]
    RequireSigned,
    /// Defer to peer metadata. Compatibility conversion to [`EntitySetting`]
    /// returns [`SamlError::Unsupported`] because the raw setting has no peer
    /// descriptor context.
    FollowPeerMetadata,
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpValidationPolicy {
    /// Assertion signature requirement.
    pub assertions: AssertionSignaturePolicy,
    /// Response/message signature requirement.
    pub messages: MessageSignaturePolicy,
    /// Outbound AuthnRequest signing behavior.
    pub authn_requests: AuthnRequestSignaturePolicy,
    /// Audience validation behavior.
    pub audience: AudienceValidationPolicy,
    /// NameID creation behavior for AuthnRequests.
    pub name_id_creation: NameIdCreationPolicy,
    /// Logout signature validation behavior.
    pub logout: LogoutPolicy,
}

/// IdP-side validation policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdpValidationPolicy {
    /// Inbound AuthnRequest signature requirement.
    pub authn_requests: AuthnRequestSignaturePolicy,
    /// Logout signature validation behavior.
    pub logout: LogoutPolicy,
}

/// Logout request and response signature policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogoutPolicy {
    /// LogoutRequest signature behavior.
    pub requests: LogoutSignaturePolicy,
    /// LogoutResponse signature behavior.
    pub responses: LogoutSignaturePolicy,
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
/// use saml_rs::constants::Binding;
/// use saml_rs::metadata::Endpoint;
/// use saml_rs::{EntityId, SpConfig, SpMetadataConfigTyped};
///
/// let acs = Endpoint::new(Binding::Post, "https://sp.example.com/acs");
/// let config = SpConfig::new(
///     EntityId::new("https://sp.example.com/metadata"),
///     SpMetadataConfigTyped::new(vec![acs]),
/// );
///
/// assert_eq!(config.entity_id.as_str(), "https://sp.example.com/metadata");
/// ```
#[derive(Debug, Clone)]
pub struct SpConfig {
    /// Local SP entity ID.
    pub entity_id: EntityId,
    /// Local SP metadata inputs.
    pub metadata: SpMetadataConfigTyped,
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
    pub fn new(entity_id: EntityId, metadata: SpMetadataConfigTyped) -> Self {
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
}

/// Typed Identity Provider configuration.
#[derive(Debug, Clone)]
pub struct IdpConfig {
    /// Local IdP entity ID.
    pub entity_id: EntityId,
    /// Local IdP metadata inputs.
    pub metadata: IdpMetadataConfigTyped,
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
    pub fn new(entity_id: EntityId, metadata: IdpMetadataConfigTyped) -> Self {
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
}

/// Explicit trust policy for imported SAML metadata.
///
/// SAML metadata trust is caller-pinned or federation-driven; this type does
/// not use a public web PKI CA store by default.
#[derive(Debug, Clone, Copy)]
pub enum MetadataTrustPolicy<'a> {
    /// Accept unsigned metadata for legacy interoperability.
    UnsignedForCompatibility,
    /// Require a valid metadata signature from one of the pinned certificates.
    RequireSignedByPinnedCertificates(&'a [CertificatePem]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppliedMetadataTrust {
    UnsignedForCompatibility,
    SignedByPinnedCertificates,
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
        let entity_id = EntityId::new(metadata_entity_id(&metadata)?.to_string());
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
        self.trust == AppliedMetadataTrust::SignedByPinnedCertificates
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
        let entity_id = EntityId::new(metadata_entity_id(&metadata)?.to_string());
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
        self.trust == AppliedMetadataTrust::SignedByPinnedCertificates
    }
}

fn authn_request_signature_required(policy: AuthnRequestSignaturePolicy) -> bool {
    matches!(policy, AuthnRequestSignaturePolicy::RequireSigned)
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
        LogoutSignaturePolicy::FollowPeerMetadata => Err(SamlError::Unsupported(
            "LogoutSignaturePolicy::FollowPeerMetadata requires peer descriptor context".into(),
        )),
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
        MetadataTrustPolicy::RequireSignedByPinnedCertificates(certificates) => {
            verify_pinned_metadata_signature(metadata, certificates)
        }
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
    if metadata.verify_signature(&trusted_certificates)? {
        return Ok(AppliedMetadataTrust::SignedByPinnedCertificates);
    }
    Err(SamlError::FailedToVerifySignature)
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
            authn_request_signature_required(config.validation.authn_requests);
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
