//! Assertion encryption/decryption (samlify `encryptAssertion` / `decryptAssertion`),
//! delegating XML-Enc to `bergshamra` (feature `crypto-bergshamra`).

use super::keys::load_certificate;
use crate::constants::namespace;
use crate::error::OpenSamlError;
use crate::xml::dom::{self, Node};
use bergshamra::keys::Key;
use bergshamra::{decrypt, encrypt, EncContext, KeysManager};

const ENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const SOFTWARE_RSA_DECRYPTION_DISABLED: &str = "XML-Enc RSA key-transport decryption with software private keys is disabled by default because the bundled RustCrypto rsa backend is affected by RUSTSEC-2023-0071. Enable allow_insecure_software_rsa_key_transport_decryption only as an explicit compatibility exception.";

/// Options for XML-Enc assertion decryption.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct AssertionDecryptionOptions {
    /// Allow the bundled software RSA backend for XML-Enc key transport.
    ///
    /// This preserves compatibility with samlify-style PEM private-key
    /// decryption, but it reaches `RUSTSEC-2023-0071`-affected code when an
    /// attacker can observe timing. Keep this `false` unless the caller has a
    /// deployment-specific reason to accept that risk.
    pub allow_insecure_software_rsa_key_transport_decryption: bool,
}

fn crypto_err(err: impl std::fmt::Display) -> OpenSamlError {
    OpenSamlError::Crypto(err.to_string())
}

pub(crate) fn software_rsa_decryption_disabled() -> OpenSamlError {
    OpenSamlError::Unsupported(SOFTWARE_RSA_DECRYPTION_DISABLED.into())
}

fn child<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    node.children.iter().find(|c| c.local_name == name)
}

/// Encrypt the `<Assertion>` in `xml`, replacing it with `<{prefix}:EncryptedAssertion>`
/// (samlify `encryptAssertion`).
///
/// `encrypt_cert` is the recipient's encryption certificate; `data_alg` /
/// `key_alg` are the data and key encryption algorithm URIs.
pub fn encrypt_assertion(
    xml: &str,
    encrypt_cert: &str,
    data_alg: &str,
    key_alg: &str,
    tag_prefix: &str,
) -> Result<String, OpenSamlError> {
    let doc = dom::parse(xml)?;
    let assertion = child(&doc.root, "Assertion")
        .ok_or_else(|| OpenSamlError::MissingMetadata("Assertion to encrypt".into()))?;
    let assertion_xml = &xml[assertion.start..assertion.end];

    let template = format!(
        "<xenc:EncryptedData xmlns:xenc=\"{enc}\" Type=\"{enc}Element\"><xenc:EncryptionMethod Algorithm=\"{data_alg}\"/><ds:KeyInfo xmlns:ds=\"{dsig}\"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"{key_alg}\"/><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue></xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
        enc = ENC,
        dsig = namespace::DSIG,
    );

    let mut manager = KeysManager::new();
    manager.add_key(load_certificate(encrypt_cert)?);
    let ctx = EncContext::new(manager);
    let encrypted_data = encrypt(&ctx, &template, assertion_xml.as_bytes()).map_err(crypto_err)?;

    let encrypted_assertion = format!(
        "<{prefix}:EncryptedAssertion xmlns:{prefix}=\"{assertion_ns}\">{encrypted_data}</{prefix}:EncryptedAssertion>",
        prefix = tag_prefix,
        assertion_ns = namespace::ASSERTION,
    );
    Ok(format!(
        "{}{}{}",
        &xml[..assertion.start],
        encrypted_assertion,
        &xml[assertion.end..]
    ))
}

/// Decrypt the `<EncryptedAssertion>` in `xml` using `enc_key`, replacing it with
/// the plaintext `<Assertion>` (samlify `decryptAssertion`).
///
/// Returns `(response_with_decrypted_assertion, decrypted_assertion)`.
pub fn decrypt_assertion(
    xml: &str,
    enc_key: &Key,
    options: AssertionDecryptionOptions,
) -> Result<(String, String), OpenSamlError> {
    if !options.allow_insecure_software_rsa_key_transport_decryption {
        return Err(software_rsa_decryption_disabled());
    }

    let doc = dom::parse(xml)?;
    let encrypted = child(&doc.root, "EncryptedAssertion")
        .ok_or_else(|| OpenSamlError::Crypto("ERR_UNDEFINED_ENCRYPTED_ASSERTION".into()))?;
    // bergshamra::decrypt returns the input doc with <EncryptedData> replaced by
    // the plaintext element, so pass only the inner EncryptedData to recover the
    // bare <Assertion>, then drop the EncryptedAssertion wrapper.
    let encrypted_data = child(encrypted, "EncryptedData")
        .ok_or_else(|| OpenSamlError::Crypto("ERR_UNDEFINED_ENCRYPTED_ASSERTION".into()))?;
    let encrypted_data_xml = &xml[encrypted_data.start..encrypted_data.end];

    let mut manager = KeysManager::new();
    manager.add_key(enc_key.clone());
    let ctx = EncContext::new(manager);
    let decrypted = decrypt(&ctx, encrypted_data_xml).map_err(crypto_err)?;
    // The decrypted element may carry an XML declaration; strip it so the
    // assertion can be spliced back into the middle of the Response document.
    let assertion = strip_xml_declaration(&decrypted).to_string();

    let response = format!(
        "{}{}{}",
        &xml[..encrypted.start],
        assertion,
        &xml[encrypted.end..]
    );
    Ok((response, assertion))
}

/// Drop a leading `<?xml ... ?>` declaration (and surrounding whitespace).
fn strip_xml_declaration(xml: &str) -> &str {
    let trimmed = xml.trim_start();
    match trimmed.strip_prefix("<?xml") {
        Some(rest) => match rest.find("?>") {
            Some(end) => rest[end + 2..].trim_start(),
            None => trimmed,
        },
        None => trimmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::data_encryption_algorithm::AES_256;
    use crate::constants::key_encryption_algorithm::RSA_OAEP_MGF1P;
    use crate::crypto::keys::load_private_key;

    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");
    const RESPONSE: &str = include_str!("../../tests/fixtures/response.xml");

    #[test]
    fn encrypt_then_decrypt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_assertion(RESPONSE, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        assert!(encrypted.contains("EncryptedAssertion"));
        assert!(encrypted.contains("EncryptedData"));
        assert!(!encrypted.contains("<saml:Assertion"));

        let key = load_private_key(SP_PRIVKEY, None)?;
        let (response, assertion) = decrypt_assertion(
            &encrypted,
            &key,
            AssertionDecryptionOptions {
                allow_insecure_software_rsa_key_transport_decryption: true,
            },
        )?;
        assert!(assertion.contains("Assertion"));
        assert!(assertion.contains("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"));
        assert!(response.contains("Assertion"));
        assert!(!response.contains("EncryptedAssertion"));
        Ok(())
    }

    #[test]
    fn decrypt_rejects_software_rsa_by_default() -> Result<(), Box<dyn std::error::Error>> {
        let encrypted = encrypt_assertion(RESPONSE, SP_CERT, AES_256, RSA_OAEP_MGF1P, "saml")?;
        let key = load_private_key(SP_PRIVKEY, None)?;
        assert!(matches!(
            decrypt_assertion(&encrypted, &key, AssertionDecryptionOptions::default()),
            Err(OpenSamlError::Unsupported(message))
                if message.contains("RUSTSEC-2023-0071")
        ));
        Ok(())
    }
}
