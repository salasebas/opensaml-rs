//! SP metadata generation.

use crate::error::OpenSamlError;
use crate::sp::ServiceProvider;

/// Generate SAML 2.0 SP metadata XML for `sp`.
///
/// Stub: returns [`OpenSamlError::Unsupported`] until M1.
pub fn generate_sp_metadata(_sp: &ServiceProvider) -> Result<String, OpenSamlError> {
    Err(OpenSamlError::Unsupported("generate_sp_metadata".into()))
}
