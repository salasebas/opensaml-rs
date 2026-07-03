//! Key, certificate and KeyInfo helpers backed by `bergshamra` keys
//! (feature `crypto-bergshamra`).

use crate::error::SamlError;
use crate::util::normalize_cert_string;
use bergshamra::keys::keyinfo::build_x509_key_info;
use bergshamra::keys::loader::{load_pem_auto, load_x509_cert_pem};
use bergshamra::keys::Key;

fn crypto_err(err: impl std::fmt::Display) -> SamlError {
    SamlError::Crypto(err.to_string())
}

/// Load a private key from PEM (PKCS#1/PKCS#8, optionally passphrase-protected).
///
/// Wraps samlify's `readPrivateKey`.
pub fn load_private_key(pem: &str, password: Option<&str>) -> Result<Key, SamlError> {
    load_pem_auto(pem.as_bytes(), password).map_err(crypto_err)
}

/// Wrap a bare base64 certificate (as found in metadata) into a PEM block.
fn to_cert_pem(cert: &str) -> String {
    if cert.contains("BEGIN CERTIFICATE") {
        return cert.to_string();
    }
    let b64 = normalize_cert_string(cert);
    let mut body = String::new();
    let mut i = 0;
    while i < b64.len() {
        let end = (i + 64).min(b64.len());
        body.push_str(&b64[i..end]);
        body.push('\n');
        i = end;
    }
    format!("-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n")
}

/// Load an X.509 certificate (PEM or bare base64) as a verification key
/// (wraps samlify's `getPublicKeyPemFromCertificate`).
pub fn load_certificate(cert: &str) -> Result<Key, SamlError> {
    load_x509_cert_pem(to_cert_pem(cert).as_bytes()).map_err(crypto_err)
}

/// Build a `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` block from a
/// certificate (samlify `getKeyInfo` / `createKeySection`).
pub fn build_key_info(cert: &str) -> String {
    let b64 = normalize_cert_string(cert);
    build_x509_key_info(&[b64.as_str()])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    const SP_PRIVKEY_ENC: &str = include_str!("../../tests/fixtures/key/sp_privkey_enc.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_cert.cer");
    const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp_cert.cer");
    // SP signing passphrase from upstream test/key/keypass.txt
    const SP_PASS: &str = "VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px";

    #[test]
    fn loads_unencrypted_private_key() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        assert!(key.has_private_key());
        assert_eq!(key.algorithm_name(), "RSA");
        Ok(())
    }

    #[test]
    fn loads_encrypted_private_key_with_passphrase() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY_ENC, Some(SP_PASS))?;
        assert!(key.has_private_key());
        Ok(())
    }

    #[test]
    fn loads_certificate_and_builds_key_info() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_certificate(IDP_CERT)?;
        assert!(key.rsa_public_key().is_some());

        let key_info = build_key_info(SP_CERT);
        assert!(key_info.contains("<ds:X509Certificate>"));
        assert!(key_info.contains("xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""));
        Ok(())
    }
}
