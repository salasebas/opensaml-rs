//! XML security backend trait.

use crate::error::SamlError;

/// Pluggable XML signature/encryption backend.
///
/// Implemented by `BergshamraBackend` when a document-crypto provider feature
/// is selected.
pub trait XmlSecurityBackend {
    /// Verify an enveloped XML-DSig signature over `xml` using `cert_pem`.
    fn verify_signature(&self, xml: &str, cert_pem: &str) -> Result<(), SamlError>;
}
