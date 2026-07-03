//! `bergshamra`-backed XML security (feature `crypto-bergshamra`).

use crate::crypto::backend::XmlSecurityBackend;
use crate::error::SamlError;

/// [`XmlSecurityBackend`] implementation backed by the `bergshamra` crate.
///
/// Verifies enveloped XML-DSig signatures against a metadata certificate using
/// `trusted_keys_only` + `strict_verification` (see [`crate::crypto::verify`]).
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct BergshamraBackend;

impl XmlSecurityBackend for BergshamraBackend {
    fn verify_signature(&self, xml: &str, cert_pem: &str) -> Result<(), SamlError> {
        match crate::crypto::verify::verify_signature(xml, &[cert_pem.to_string()])? {
            (true, _) => Ok(()),
            (false, _) => Err(SamlError::FailedToVerifySignature),
        }
    }
}
