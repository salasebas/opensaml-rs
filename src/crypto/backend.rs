//! XML security backend trait.

use crate::error::SamlError;

/// Pluggable XML signature/encryption backend.
///
/// Implemented by `BergshamraBackend` behind the `crypto-bergshamra` feature.
pub trait XmlSecurityBackend {
    /// Verify an enveloped XML-DSig signature over `xml` using `cert_pem`.
    fn verify_signature(&self, xml: &str, cert_pem: &str) -> Result<(), SamlError>;
}
