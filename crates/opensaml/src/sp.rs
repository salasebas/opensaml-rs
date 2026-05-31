//! SAML Service Provider configuration.

/// SAML 2.0 Service Provider descriptor.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServiceProvider {
    /// SP `entityID`.
    pub entity_id: String,
    /// Assertion Consumer Service (ACS) URL.
    pub acs_url: String,
    /// Optional PEM signing/encryption certificate.
    pub signing_cert: Option<String>,
    /// Optional PEM private key.
    pub private_key: Option<String>,
}

impl ServiceProvider {
    /// Create an SP with the required `entityID` and ACS URL.
    pub fn new(entity_id: impl Into<String>, acs_url: impl Into<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            acs_url: acs_url.into(),
            signing_cert: None,
            private_key: None,
        }
    }
}
