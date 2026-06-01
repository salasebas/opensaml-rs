//! XML-DSig verification + anti-wrapping (samlify `libsaml.verifySignature`),
//! delegating the cryptography to `bergshamra` (feature `crypto-bergshamra`).
//!
//! Security model:
//! - `trusted_keys_only`: the signature is verified against the certificate(s)
//!   declared in IdP metadata, never an attacker-supplied inline cert. This
//!   subsumes samlify's "cert in node must match metadata" check.
//! - `strict_verification`: bergshamra enforces that each signed reference
//!   targets the document element, an ancestor, or a sibling of the Signature.
//! - Explicit XSW guard: reject any `Assertion`/`Signature` nested under
//!   `SubjectConfirmationData`.
//! - Only content covered by a verified reference is returned for extraction.

use super::keys::load_certificate;
use crate::error::OpenSamlError;
use crate::xml::dom::{self, Node};
use bergshamra::{verify, DsigContext, KeysManager, VerifyResult};

fn children_named<'a>(node: &'a Node, name: &str) -> Vec<&'a Node> {
    node.children
        .iter()
        .filter(|c| c.local_name == name)
        .collect()
}

fn has_child(node: &Node, name: &str) -> bool {
    node.children.iter().any(|c| c.local_name == name)
}

fn has_descendant(node: &Node, names: &[&str]) -> bool {
    node.children
        .iter()
        .any(|c| names.contains(&c.local_name.as_str()) || has_descendant(c, names))
}

/// XSW guard: `Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData//(Assertion|Signature)`.
fn wrapping_detected(root: &Node) -> bool {
    for assertion in children_named(root, "Assertion") {
        for subject in children_named(assertion, "Subject") {
            for sc in children_named(subject, "SubjectConfirmation") {
                for scd in children_named(sc, "SubjectConfirmationData") {
                    if has_descendant(scd, &["Assertion", "Signature"]) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Return the source of the content covered by the verified signature: the lone
/// `<Assertion>`, or the whole `<Response>` when assertions are encrypted.
fn verified_content(root: &Node, xml: &str) -> Option<String> {
    if root.local_name == "Assertion" {
        return Some(xml[root.start..root.end].to_string());
    }
    if root.local_name.contains("Response") {
        let assertions = children_named(root, "Assertion");
        if assertions.len() == 1 {
            let a = assertions[0];
            return Some(xml[a.start..a.end].to_string());
        }
        if has_child(root, "EncryptedAssertion") {
            return Some(xml[root.start..root.end].to_string());
        }
    }
    None
}

/// Verify the XML-DSig signature(s) of `xml` against `metadata_certs`.
///
/// Returns `(verified, signed_content)`:
/// - `(false, None)` when there is no signature or it does not verify;
/// - `(true, Some(xml))` with the signed assertion/response on success;
/// - `Err(PotentialWrappingAttack)` on a detected XSW attempt.
pub fn verify_signature(
    xml: &str,
    metadata_certs: &[String],
) -> Result<(bool, Option<String>), OpenSamlError> {
    let doc = dom::parse(xml)?;
    let root = &doc.root;

    if root.local_name.contains("Response") && wrapping_detected(root) {
        return Err(OpenSamlError::PotentialWrappingAttack);
    }

    // Candidate signatures: message-level (root > Signature) or assertion-level.
    let message_sig = has_child(root, "Signature");
    let assertion_sig = children_named(root, "Assertion")
        .iter()
        .any(|a| has_child(a, "Signature"));
    if !message_sig && !assertion_sig {
        return Ok((false, None));
    }

    let mut manager = KeysManager::new();
    let mut have_key = false;
    for cert in metadata_certs {
        if let Ok(key) = load_certificate(cert) {
            manager.add_key(key);
            have_key = true;
        }
    }
    if !have_key {
        return Err(OpenSamlError::Crypto("NO_SELECTED_CERTIFICATE".into()));
    }

    let ctx = DsigContext::new(manager)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_insecure(true);

    match verify(&ctx, xml).map_err(|e| OpenSamlError::Crypto(e.to_string()))? {
        VerifyResult::Valid { references, .. } => {
            if references.is_empty() {
                return Err(OpenSamlError::Crypto("NO_SIGNATURE_REFERENCES".into()));
            }
            Ok((true, verified_content(root, xml)))
        }
        VerifyResult::Invalid { .. } => Ok((false, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{extract, ExtractorField};

    const RESPONSE_SIGNED: &str = include_str!("../../tests/fixtures/response_signed.xml");
    const SIGNED_REQUEST: &str = include_str!("../../tests/fixtures/signed_request_sha256.xml");
    const ATTACK: &str = include_str!("../../tests/fixtures/attack_response_signed.xml");
    const FALSE_SIGNED: &str = include_str!("../../tests/fixtures/false_signed_request_sha256.xml");
    // IdP signing cert (matches the response_signed.xml signer / idpmeta).
    const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp_cert.cer");
    // SP signing cert (matches signed_request_sha256.xml signer).
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_cert.cer");

    #[test]
    fn verifies_signed_response_with_metadata_cert() -> Result<(), Box<dyn std::error::Error>> {
        let (verified, content) = verify_signature(RESPONSE_SIGNED, &[IDP_CERT.to_string()])?;
        assert!(
            verified,
            "response_signed.xml should verify with the IdP cert"
        );
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn verifies_signed_request_with_sp_cert() -> Result<(), Box<dyn std::error::Error>> {
        let (verified, _) = verify_signature(SIGNED_REQUEST, &[SP_CERT.to_string()])?;
        assert!(
            verified,
            "signed_request_sha256.xml should verify with the SP cert"
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_certificate() -> Result<(), Box<dyn std::error::Error>> {
        // verifying the IdP-signed response against the SP cert must fail (wrong key)
        let (verified, content) = verify_signature(RESPONSE_SIGNED, &[SP_CERT.to_string()])?;
        assert!(!verified);
        assert!(content.is_none());
        Ok(())
    }

    #[test]
    fn rejects_tampered_signature() -> Result<(), Box<dyn std::error::Error>> {
        // false_signed_request_sha256.xml: signature present but content tampered
        let (verified, _) = verify_signature(FALSE_SIGNED, &[SP_CERT.to_string()])?;
        assert!(!verified, "tampered message must not verify");
        Ok(())
    }

    #[test]
    fn rejects_wrapping_attack() -> Result<(), Box<dyn std::error::Error>> {
        // attack_response_signed.xml hides a forged assertion via XSW; it must not
        // produce a trusted (verified, Some(content)) result.
        match verify_signature(ATTACK, &[IDP_CERT.to_string()]) {
            Err(OpenSamlError::PotentialWrappingAttack) => Ok(()),
            Ok((false, _)) => Ok(()),
            Ok((true, _)) => Err("XSW response must not verify".into()),
            Err(other) => Err(format!("unexpected error: {other:?}").into()),
        }
    }

    #[test]
    fn no_signature_returns_false() -> Result<(), Box<dyn std::error::Error>> {
        // a document without any Signature element verifies to (false, None)
        let (verified, content) = verify_signature("<samlp:Response>x</samlp:Response>", &[])?;
        assert!(!verified);
        assert!(content.is_none());
        // keep the extractor import exercised
        let _ = extract("<a/>", &[ExtractorField::new("x", &["a"])])?;
        Ok(())
    }
}
