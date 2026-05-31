//! Single Logout (SLO) stubs.

use crate::error::OpenSamlError;

/// Build a Redirect-binding `LogoutRequest` URL.
///
/// Stub: returns [`OpenSamlError::Unsupported`] until M3.
pub fn create_logout_request_redirect() -> Result<String, OpenSamlError> {
    Err(OpenSamlError::Unsupported(
        "create_logout_request_redirect".into(),
    ))
}

/// Build a POST-binding `LogoutResponse` form.
///
/// Stub: returns [`OpenSamlError::Unsupported`] until M3.
pub fn create_logout_response_post() -> Result<String, OpenSamlError> {
    Err(OpenSamlError::Unsupported(
        "create_logout_response_post".into(),
    ))
}
