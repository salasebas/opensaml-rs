//! `bergshamra`-backed XML security (feature `crypto-bergshamra`).

use crate::crypto::backend::XmlSecurityBackend;
use crate::error::OpenSamlError;

/// [`XmlSecurityBackend`] implementation backed by the `bergshamra` crate.
///
/// Stub: wired up in M1 with `trusted_keys_only` + `strict_verification`.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct BergshamraBackend;

impl XmlSecurityBackend for BergshamraBackend {
    fn verify_signature(&self, _xml: &str, _cert_pem: &str) -> Result<(), OpenSamlError> {
        Err(OpenSamlError::Unsupported(
            "BergshamraBackend::verify_signature".into(),
        ))
    }
}
