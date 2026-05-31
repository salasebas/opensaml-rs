//! Remote SAML Identity Provider metadata (as consumed by the SP).

/// SAML 2.0 Identity Provider descriptor.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IdentityProvider {
    /// IdP `entityID`.
    pub entity_id: String,
    /// IdP SSO (login) endpoint URL.
    pub sso_url: String,
    /// PEM signing certificate used to verify IdP responses.
    pub signing_cert: String,
}

impl IdentityProvider {
    /// Create an IdP descriptor.
    pub fn new(
        entity_id: impl Into<String>,
        sso_url: impl Into<String>,
        signing_cert: impl Into<String>,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            sso_url: sso_url.into(),
            signing_cert: signing_cert.into(),
        }
    }
}
