//! Login response parsing.

use crate::error::OpenSamlError;
use crate::idp::IdentityProvider;
use crate::sp::ServiceProvider;

/// Parsed login response (placeholder shape).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LoginResponse {
    /// NameID / subject of the authenticated principal.
    pub name_id: Option<String>,
}

/// Parse and validate a POST-binding SAML login `Response`.
///
/// Stub: returns [`OpenSamlError::Unsupported`] until M1. With the
/// `crypto-bergshamra` feature, XML-DSig verification is delegated to
/// `bergshamra`.
pub fn parse_login_response_post(
    _sp: &ServiceProvider,
    _idp: &IdentityProvider,
    _b64_response: &str,
) -> Result<LoginResponse, OpenSamlError> {
    Err(OpenSamlError::Unsupported(
        "parse_login_response_post".into(),
    ))
}
