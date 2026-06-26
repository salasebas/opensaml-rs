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
use crate::util::normalize_cert_string;
use crate::xml::dom::{self, Node};
use bergshamra::{verify, DsigContext, KeysManager, VerifiedReference, VerifyResult};
use std::collections::HashSet;

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

fn saml_id_attr(name: &str) -> bool {
    matches!(name, "ID" | "AssertionID")
}

fn duplicate_saml_id(node: &Node, seen: &mut HashSet<String>) -> Option<String> {
    for (name, value) in &node.attrs {
        if saml_id_attr(name) && !value.is_empty() && !seen.insert(value.clone()) {
            return Some(value.clone());
        }
    }
    node.children
        .iter()
        .find_map(|child| duplicate_saml_id(child, seen))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifiedTarget {
    WholeDocument,
    Id(String),
}

fn verified_target_from_uri(uri: &str) -> Result<VerifiedTarget, OpenSamlError> {
    if uri.is_empty() || uri == "#xpointer(/)" {
        return Ok(VerifiedTarget::WholeDocument);
    }

    let fragment = uri
        .strip_prefix('#')
        .ok_or_else(|| OpenSamlError::Crypto("ERR_EXTERNAL_REFERENCE".into()))?;
    if fragment.is_empty() {
        return Err(OpenSamlError::Crypto(
            "ERR_UNSUPPORTED_REFERENCE_URI".into(),
        ));
    }
    if let Some(id) = fragment
        .strip_prefix("xpointer(id('")
        .and_then(|rest| rest.strip_suffix("'))"))
    {
        if id.is_empty() {
            return Err(OpenSamlError::Crypto(
                "ERR_UNSUPPORTED_REFERENCE_URI".into(),
            ));
        }
        return Ok(VerifiedTarget::Id(id.to_string()));
    }
    if fragment.starts_with("xpointer(") {
        return Err(OpenSamlError::Crypto(
            "ERR_UNSUPPORTED_REFERENCE_URI".into(),
        ));
    }
    Ok(VerifiedTarget::Id(fragment.to_string()))
}

fn verified_targets(
    references: &[VerifiedReference],
) -> Result<Vec<VerifiedTarget>, OpenSamlError> {
    if references.is_empty() {
        return Err(OpenSamlError::Crypto("NO_SIGNATURE_REFERENCES".into()));
    }

    let mut targets = Vec::with_capacity(references.len());
    for reference in references {
        if is_external_reference(&reference.uri) {
            return Err(OpenSamlError::Crypto("ERR_EXTERNAL_REFERENCE".into()));
        }
        if !reference.digest_verified {
            return Err(OpenSamlError::Crypto(
                "ERR_UNVERIFIED_REFERENCE_DIGEST".into(),
            ));
        }
        let target = verified_target_from_uri(&reference.uri)?;
        if matches!(target, VerifiedTarget::Id(_)) && reference.resolved_node.is_none() {
            return Err(OpenSamlError::Crypto("ERR_UNRESOLVED_REFERENCE".into()));
        }
        targets.push(target);
    }
    Ok(targets)
}

fn node_saml_id(node: &Node) -> Option<&str> {
    node.attr("ID").or_else(|| node.attr("AssertionID"))
}

fn target_matches_node(targets: &[VerifiedTarget], node: &Node) -> bool {
    targets.iter().any(|target| match target {
        VerifiedTarget::WholeDocument => true,
        VerifiedTarget::Id(id) => node_saml_id(node).is_some_and(|node_id| node_id == id),
    })
}

fn id_target_matches_node(targets: &[VerifiedTarget], node: &Node) -> bool {
    targets.iter().any(|target| match target {
        VerifiedTarget::WholeDocument => false,
        VerifiedTarget::Id(id) => node_saml_id(node).is_some_and(|node_id| node_id == id),
    })
}

fn response_is_covered(targets: &[VerifiedTarget], root: &Node) -> bool {
    target_matches_node(targets, root)
}

fn verified_content_not_covered() -> OpenSamlError {
    OpenSamlError::Crypto("ERR_VERIFIED_REFERENCE_DOES_NOT_COVER_CONTENT".into())
}

/// Return the source of the content covered by a verified reference: the lone
/// `<Assertion>`, or the whole `<Response>` when assertions are encrypted.
fn verified_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
) -> Result<Option<String>, OpenSamlError> {
    if root.local_name == "Assertion" {
        if target_matches_node(targets, root) {
            return Ok(Some(xml[root.start..root.end].to_string()));
        }
        return Err(verified_content_not_covered());
    }
    if root.local_name.contains("Response") {
        let assertions = children_named(root, "Assertion");
        if assertions.len() > 1 {
            return Err(OpenSamlError::PotentialWrappingAttack);
        }
        if assertions.len() == 1 {
            let a = assertions[0];
            if id_target_matches_node(targets, a) || response_is_covered(targets, root) {
                return Ok(Some(xml[a.start..a.end].to_string()));
            }
            return Err(verified_content_not_covered());
        }
        if has_child(root, "EncryptedAssertion") {
            if response_is_covered(targets, root) {
                return Ok(Some(xml[root.start..root.end].to_string()));
            }
            return Err(verified_content_not_covered());
        }
    }
    Ok(None)
}

/// True for a signed `<Reference>` URI that is not same-document (i.e. not a
/// `#id` fragment or the whole document). Such references can pull external or
/// local-file content into the verified set and are rejected for SAML.
fn is_external_reference(uri: &str) -> bool {
    !uri.is_empty() && !uri.starts_with('#')
}

/// First `<X509Certificate>` text found inside a `<Signature>` (the cert the
/// sender embedded in the message), if any.
fn inline_signature_cert(node: &Node, in_signature: bool) -> Option<String> {
    let in_signature = in_signature || node.local_name == "Signature";
    if in_signature && node.local_name == "X509Certificate" && !node.text.is_empty() {
        return Some(node.text.clone());
    }
    node.children
        .iter()
        .find_map(|c| inline_signature_cert(c, in_signature))
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

    let mut seen_ids = HashSet::new();
    if duplicate_saml_id(root, &mut seen_ids).is_some() {
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

    // samlify ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA: if the message
    // embeds a certificate, it must be one declared in metadata (rolling-cert
    // safety). Verification itself still uses only the metadata certs.
    if let Some(inline) = inline_signature_cert(root, false) {
        let inline = normalize_cert_string(&inline);
        if !metadata_certs.is_empty()
            && !metadata_certs
                .iter()
                .any(|c| normalize_cert_string(c) == inline)
        {
            return Err(OpenSamlError::UnmatchCertificate);
        }
    }

    // Try each metadata certificate individually (rolling-cert support): the
    // signature verifies if any one of the declared keys matches.
    let mut have_key = false;
    let mut tried_invalid = false;
    let mut last_err: Option<OpenSamlError> = None;
    for cert in metadata_certs {
        let key = match load_certificate(cert) {
            Ok(key) => key,
            Err(_) => continue,
        };
        have_key = true;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        // Trust model (audited against bergshamra 0.5.1):
        // - `DsigContext::new()` enables `trusted_keys_only = true`,
        //   `strict_verification = true`, and `hmac_min_out_len = 160` by
        //   default. Verification uses only the metadata-pinned key; inline
        //   KeyInfo (X509Certificate/KeyValue) is never imported as key
        //   material.
        // - `strict_verification`: each signed reference must target the
        //   document element, an ancestor, or a sibling of the Signature (XSW
        //   guard).
        // - `with_insecure(true)`: intentionally skips X.509 chain/path/time
        //   validation only, which is irrelevant to our pinning model. It does
        //   not skip signature, digest, reference, duplicate-ID, or XSW
        //   enforcement.
        // - Inbound SAML verification must never use
        //   `DsigContext::new_permissive()`.
        let ctx = DsigContext::new(manager).with_insecure(true);
        match verify(&ctx, xml) {
            Ok(VerifyResult::Valid {
                signature_node: _,
                references,
                ..
            }) => {
                let targets = verified_targets(&references)?;
                return Ok((true, verified_content(root, xml, &targets)?));
            }
            Ok(VerifyResult::Invalid { .. }) => tried_invalid = true,
            Err(e) => last_err = Some(OpenSamlError::Crypto(e.to_string())),
        }
    }
    if !have_key {
        return Err(OpenSamlError::Crypto("NO_SELECTED_CERTIFICATE".into()));
    }
    // A clean "invalid" (key mismatch / tampered) is a non-error false; only
    // surface a structural error when no certificate produced a verdict.
    match last_err {
        Some(err) if !tried_invalid => Err(err),
        _ => Ok((false, None)),
    }
}

/// Verify the enveloped XML-DSig signature on a metadata document against
/// trusted certificate(s); returns whether it is valid.
pub fn verify_metadata_signature(
    xml: &str,
    trusted_certs: &[String],
) -> Result<bool, OpenSamlError> {
    Ok(verify_signature(xml, trusted_certs)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{extract, ExtractorField};

    #[test]
    fn external_reference_detection() {
        assert!(!is_external_reference("")); // whole document
        assert!(!is_external_reference("#_assertion123")); // same-document
        assert!(is_external_reference("https://evil.example.com/x"));
        assert!(is_external_reference("/etc/passwd"));
        assert!(is_external_reference("file:///etc/passwd"));
        assert!(is_external_reference("cid:attachment"));
    }

    #[test]
    fn same_document_reference_target_parsing() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(verified_target_from_uri("")?, VerifiedTarget::WholeDocument);
        assert_eq!(
            verified_target_from_uri("#_assertion123")?,
            VerifiedTarget::Id("_assertion123".to_string())
        );
        assert_eq!(
            verified_target_from_uri("#xpointer(/)")?,
            VerifiedTarget::WholeDocument
        );
        assert_eq!(
            verified_target_from_uri("#xpointer(id('_assertion123'))")?,
            VerifiedTarget::Id("_assertion123".to_string())
        );
        Ok(())
    }

    #[test]
    fn unsupported_reference_target_parsing_fails() {
        assert!(matches!(
            verified_target_from_uri("#"),
            Err(OpenSamlError::Crypto(message))
                if message == "ERR_UNSUPPORTED_REFERENCE_URI"
        ));
        assert!(matches!(
            verified_target_from_uri("#xpointer(//saml:Assertion)"),
            Err(OpenSamlError::Crypto(message))
                if message == "ERR_UNSUPPORTED_REFERENCE_URI"
        ));
    }

    #[test]
    fn duplicate_saml_id_allows_unique_ids() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion"/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(duplicate_saml_id(&doc.root, &mut seen), None);
        Ok(())
    }

    #[test]
    fn duplicate_saml_id_returns_repeated_value() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_same"/><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_same"/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(
            duplicate_saml_id(&doc.root, &mut seen),
            Some("_same".to_string())
        );
        Ok(())
    }

    #[test]
    fn duplicate_saml_id_ignores_empty_values() -> Result<(), Box<dyn std::error::Error>> {
        let doc = dom::parse(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID=""><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID=""/></samlp:Response>"#,
        )?;
        let mut seen = HashSet::new();
        assert_eq!(duplicate_saml_id(&doc.root, &mut seen), None);
        Ok(())
    }

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
        // RESPONSE_SIGNED embeds the IdP cert; verifying against the SP cert trips
        // the inline-vs-metadata mismatch guard (samlify UNMATCH_CERTIFICATE).
        match verify_signature(RESPONSE_SIGNED, &[SP_CERT.to_string()]) {
            Err(OpenSamlError::UnmatchCertificate) => Ok(()),
            other => Err(format!("expected UnmatchCertificate, got {other:?}").into()),
        }
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
