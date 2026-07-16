use crate::browser::{AcsEndpoint, SloEndpoint, SsoEndpoint};
use crate::entity::EntitySetting;
use crate::error::SamlError;

use super::algorithms::{name_id_format_uris, transform_algorithm_uris, NameIdFormat};
use super::credentials::Credentials;
use super::descriptors::{validate_entity_id, EntityId, IdpMetadataConfig, SpMetadataConfig};
use super::policies::{
    assertion_signature_required, audience_validation_enabled, authn_request_signature_required,
    authn_request_signing_enabled, logout_signature_required, name_id_creation_allowed,
    response_signature_required, AlgorithmPolicy, AssertionEncryptionPolicy,
    AuthnRequestSigningPolicy, IdpValidationPolicy, SpValidationPolicy, TemplatePolicy, XmlPolicy,
};
#[cfg(not(feature = "crypto-bergshamra"))]
use super::policies::{
    AssertionSignaturePolicy, AuthnRequestValidationPolicy, LogoutPolicy, LogoutSignaturePolicy,
    ResponseSignaturePolicy,
};

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
        config.validation.responses,
        ResponseSignaturePolicy::RequireSigned
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
        setting.want_message_signed = response_signature_required(config.validation.responses);
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
