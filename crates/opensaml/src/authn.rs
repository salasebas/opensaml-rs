//! AuthnRequest creation.

use crate::error::OpenSamlError;
use crate::idp::IdentityProvider;
use crate::sp::ServiceProvider;

/// Build a Redirect-binding login URL carrying `SAMLRequest` in the query.
///
/// Stub: returns [`OpenSamlError::Unsupported`] until M1. Will DEFLATE +
/// base64 + url-encode an `<AuthnRequest>` and append it to the IdP SSO URL.
pub fn create_login_request_redirect(
    _sp: &ServiceProvider,
    _idp: &IdentityProvider,
    _relay_state: Option<&str>,
) -> Result<String, OpenSamlError> {
    Err(OpenSamlError::Unsupported(
        "create_login_request_redirect".into(),
    ))
}
