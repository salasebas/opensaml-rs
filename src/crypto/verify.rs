//! XML-DSig verification and anti-wrapping checks, delegating cryptography to
//! `bergshamra` (feature `crypto-bergshamra`).
//!
//! Security model:
//! - `trusted_keys_only`: the signature is verified against the certificate(s)
//!   declared in IdP metadata, never an attacker-supplied inline cert.
//! - `strict_verification`: bergshamra enforces that each signed reference
//!   targets the document element, an ancestor, or a sibling of the Signature.
//! - Explicit XSW guard: reject any `Assertion`/`Signature` nested under
//!   `SubjectConfirmationData`.
//! - Only content covered by a verified reference is returned for extraction.

use super::keys::load_certificate;
use crate::constants::transform_algorithm;
use crate::error::{ReferenceResolutionReason, SamlError, SignatureVerificationReason};
use crate::util::normalize_cert_string;
use crate::xml::dom::{self, Node, XmlLimits};
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

fn reference_resolution(reason: ReferenceResolutionReason) -> SamlError {
    SamlError::ReferenceResolution { reason }
}

fn verified_target_from_uri(uri: &str) -> Result<VerifiedTarget, SamlError> {
    if uri.is_empty() || uri == "#xpointer(/)" {
        return Ok(VerifiedTarget::WholeDocument);
    }

    let fragment = uri
        .strip_prefix('#')
        .ok_or_else(|| reference_resolution(ReferenceResolutionReason::ExternalReference))?;
    if fragment.is_empty() {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    }
    if let Some(id) = fragment
        .strip_prefix("xpointer(id('")
        .and_then(|rest| rest.strip_suffix("'))"))
    {
        if id.is_empty() {
            return Err(reference_resolution(
                ReferenceResolutionReason::UnsupportedReferenceUri,
            ));
        }
        return Ok(VerifiedTarget::Id(id.to_string()));
    }
    if fragment.starts_with("xpointer(") {
        return Err(reference_resolution(
            ReferenceResolutionReason::UnsupportedReferenceUri,
        ));
    }
    Ok(VerifiedTarget::Id(fragment.to_string()))
}

fn verified_targets(references: &[VerifiedReference]) -> Result<Vec<VerifiedTarget>, SamlError> {
    if references.is_empty() {
        return Err(reference_resolution(
            ReferenceResolutionReason::MissingSignatureReference,
        ));
    }

    let mut targets = Vec::with_capacity(references.len());
    for reference in references {
        if is_external_reference(&reference.uri) {
            return Err(reference_resolution(
                ReferenceResolutionReason::ExternalReference,
            ));
        }
        if !reference.digest_verified {
            return Err(SamlError::SignatureVerification {
                reason: SignatureVerificationReason::ReferenceDigest,
            });
        }
        let target = verified_target_from_uri(&reference.uri)?;
        if matches!(target, VerifiedTarget::Id(_)) && reference.resolved_node.is_none() {
            return Err(reference_resolution(
                ReferenceResolutionReason::UnresolvedReference,
            ));
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

fn verified_content_not_covered() -> SamlError {
    SamlError::SignedReferenceMismatch
}

const EXC_C14N_WITH_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
const XML_C14N_10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const XML_C14N_10_WITH_COMMENTS: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const XML_C14N_11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const XML_C14N_11_WITH_COMMENTS: &str = "http://www.w3.org/2006/12/xml-c14n11#WithComments";

fn metadata_signature_transform_allowed(algorithm: &str) -> bool {
    matches!(
        algorithm,
        transform_algorithm::ENVELOPED_SIGNATURE
            | transform_algorithm::EXC_C14N
            | EXC_C14N_WITH_COMMENTS
            | XML_C14N_10
            | XML_C14N_10_WITH_COMMENTS
            | XML_C14N_11
            | XML_C14N_11_WITH_COMMENTS
    )
}

fn ensure_metadata_reference_transforms_preserve_descriptor(
    reference: &Node,
) -> Result<(), SamlError> {
    for transforms in children_named(reference, "Transforms") {
        for transform in children_named(transforms, "Transform") {
            if transform
                .attr("Algorithm")
                .is_some_and(metadata_signature_transform_allowed)
            {
                continue;
            }
            return Err(verified_content_not_covered());
        }
    }
    Ok(())
}

fn ensure_metadata_signature_transforms_preserve_descriptor(root: &Node) -> Result<(), SamlError> {
    if root.local_name != "EntityDescriptor" {
        return Ok(());
    }

    for signature in children_named(root, "Signature") {
        for signed_info in children_named(signature, "SignedInfo") {
            for reference in children_named(signed_info, "Reference") {
                ensure_metadata_reference_transforms_preserve_descriptor(reference)?;
            }
        }
    }
    Ok(())
}

fn verified_root_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
) -> Result<String, SamlError> {
    if target_matches_node(targets, root) {
        return Ok(xml[root.start..root.end].to_string());
    }
    Err(verified_content_not_covered())
}

/// Return the source of the content covered by a verified reference: the lone
/// `<Assertion>`, a consumed root element, or the whole `<Response>` when
/// assertions are encrypted.
fn verified_content(
    root: &Node,
    xml: &str,
    targets: &[VerifiedTarget],
) -> Result<Option<String>, SamlError> {
    if root.local_name == "Assertion" {
        return verified_root_content(root, xml, targets).map(Some);
    }
    if root.local_name.contains("Response") {
        let assertions = children_named(root, "Assertion");
        if assertions.len() > 1 {
            return Err(SamlError::PotentialWrappingAttack);
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
    if root.local_name == "EntityDescriptor" {
        if target_matches_node(targets, root) {
            return Ok(Some(xml[root.start..root.end].to_string()));
        }
        return Err(verified_content_not_covered());
    }
    if matches!(
        root.local_name.as_str(),
        "AuthnRequest" | "LogoutRequest" | "LogoutResponse"
    ) {
        return verified_root_content(root, xml, targets).map(Some);
    }
    Ok(None)
}

/// True for a signed `<Reference>` URI that is not same-document (i.e. not a
/// `#id` fragment or the whole document). Such references can pull external or
/// local-file content into the verified set and are rejected for SAML.
fn is_external_reference(uri: &str) -> bool {
    !uri.is_empty() && !uri.starts_with('#')
}

fn has_saml_xml_signature(root: &Node) -> bool {
    has_child(root, "Signature")
        || children_named(root, "Assertion")
            .iter()
            .any(|assertion| has_child(assertion, "Signature"))
}

pub(crate) fn has_xml_signature_with_limits(
    xml: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    Ok(has_saml_xml_signature(&doc.root))
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
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, trust checks, reference resolution,
/// cryptographic verification, or signed-content coverage checks fail.
pub fn verify_signature(
    xml: &str,
    metadata_certs: &[String],
) -> Result<(bool, Option<String>), SamlError> {
    verify_signature_with_limits(xml, metadata_certs, XmlLimits::default())
}

/// Verify the XML-DSig signature(s) of `xml` with explicit XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, trust checks, reference resolution,
/// cryptographic verification, or signed-content coverage checks fail.
pub fn verify_signature_with_limits(
    xml: &str,
    metadata_certs: &[String],
    limits: XmlLimits,
) -> Result<(bool, Option<String>), SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    let root = &doc.root;

    if root.local_name.contains("Response") && wrapping_detected(root) {
        return Err(SamlError::PotentialWrappingAttack);
    }

    let mut seen_ids = HashSet::new();
    if duplicate_saml_id(root, &mut seen_ids).is_some() {
        return Err(SamlError::PotentialWrappingAttack);
    }

    // Candidate signatures: message-level (root > Signature) or assertion-level.
    if !has_saml_xml_signature(root) {
        return Ok((false, None));
    }

    // If the message embeds a certificate, it must be one declared in metadata
    // (rolling-cert safety). Verification itself still uses only the metadata
    // certs.
    if let Some(inline) = inline_signature_cert(root, false) {
        let inline = normalize_cert_string(&inline);
        if !metadata_certs.is_empty()
            && !metadata_certs
                .iter()
                .any(|c| normalize_cert_string(c) == inline)
        {
            return Err(SamlError::CertificateMismatch);
        }
    }

    // Try each metadata certificate individually (rolling-cert support): the
    // signature verifies if any one of the declared keys matches.
    let mut have_key = false;
    let mut tried_invalid = false;
    let mut last_err: Option<SamlError> = None;
    for cert in metadata_certs {
        let key = match load_certificate(cert) {
            Ok(key) => key,
            Err(_) => continue,
        };
        have_key = true;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        // Trust model (audited against bergshamra 0.6.3):
        // - Metadata certificates are pinned key material, not a public CA
        //   chain. Verification uses only the metadata-pinned key; inline
        //   KeyInfo (X509Certificate/KeyValue) is never imported as key
        //   material.
        // - Set `trusted_keys_only`, `strict_verification`, and
        //   `hmac_min_out_len` explicitly instead of relying on upstream
        //   defaults.
        // - `strict_verification`: each signed reference must target the
        //   document element, an ancestor, or a sibling of the Signature (XSW
        //   guard).
        // - `with_insecure(true)`: intentionally skips X.509 chain/path/time
        //   validation only, which is irrelevant to our pinning model. It does
        //   not skip signature, digest, reference, duplicate-ID, or XSW
        //   enforcement.
        // - Inbound SAML verification must never use
        //   `DsigContext::new_permissive()`.
        let ctx = DsigContext::new(manager)
            .with_trusted_keys_only(true)
            .with_strict_verification(true)
            .with_hmac_min_out_len(160)
            .with_insecure(true);
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
            Err(e) => last_err = Some(SamlError::Crypto(e.to_string())),
        }
    }
    if !have_key {
        return Err(SamlError::NoTrustedCertificate);
    }
    // A clean "invalid" (key mismatch / tampered) is a non-error false; only
    // surface a structural error when no certificate produced a verdict.
    match last_err {
        Some(err) if !tried_invalid => Err(err),
        _ => Ok((false, None)),
    }
}

/// Detailed metadata signature verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataSignatureVerification {
    verified: bool,
    signed_entity_descriptor_xml: Option<String>,
}

impl MetadataSignatureVerification {
    pub(crate) fn from_signed_descriptor(signed_entity_descriptor_xml: String) -> Self {
        Self {
            verified: true,
            signed_entity_descriptor_xml: Some(signed_entity_descriptor_xml),
        }
    }

    pub(crate) fn unverified() -> Self {
        Self {
            verified: false,
            signed_entity_descriptor_xml: None,
        }
    }

    /// Whether a metadata signature verified against the pinned certificates.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// The signed `<EntityDescriptor>` XML when verification succeeds.
    pub fn signed_entity_descriptor_xml(&self) -> Option<&str> {
        self.signed_entity_descriptor_xml.as_deref()
    }

    pub(crate) fn into_signed_entity_descriptor_xml(self) -> Option<String> {
        self.signed_entity_descriptor_xml
    }
}

/// Verify the enveloped XML-DSig signature on a metadata document against
/// trusted certificate(s); returns whether it is valid and covers the consumed
/// `<EntityDescriptor>` document.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, or signed `<EntityDescriptor>` coverage checks fail.
pub fn verify_metadata_signature(
    xml: &str,
    trusted_certificates: &[String],
) -> Result<bool, SamlError> {
    verify_metadata_signature_with_limits(xml, trusted_certificates, XmlLimits::default())
}

/// Verify a metadata XML-DSig signature with explicit XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, or signed `<EntityDescriptor>` coverage checks fail.
pub fn verify_metadata_signature_with_limits(
    xml: &str,
    trusted_certificates: &[String],
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    Ok(
        verify_metadata_signature_detailed_with_limits(xml, trusted_certificates, limits)?
            .verified(),
    )
}

/// Verify a metadata XML-DSig signature and preserve signed descriptor coverage
/// using default XML parser limits.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, transform policy, or signed `<EntityDescriptor>` coverage
/// checks fail.
pub fn verify_metadata_signature_detailed(
    xml: &str,
    trusted_certificates: &[String],
) -> Result<MetadataSignatureVerification, SamlError> {
    verify_metadata_signature_detailed_with_limits(xml, trusted_certificates, XmlLimits::default())
}

/// Verify a metadata XML-DSig signature and preserve signed descriptor coverage.
///
/// # Errors
///
/// Returns [`SamlError`] when XML parsing, certificate loading, cryptographic
/// verification, transform policy, or signed `<EntityDescriptor>` coverage
/// checks fail.
pub fn verify_metadata_signature_detailed_with_limits(
    xml: &str,
    trusted_certificates: &[String],
    limits: XmlLimits,
) -> Result<MetadataSignatureVerification, SamlError> {
    let doc = dom::parse_with_limits(xml, limits)?;
    ensure_metadata_signature_transforms_preserve_descriptor(&doc.root)?;

    let (verified, signed_entity_descriptor_xml) =
        verify_signature_with_limits(xml, trusted_certificates, limits)?;
    if !verified {
        return Ok(MetadataSignatureVerification::unverified());
    }
    signed_entity_descriptor_xml
        .map(MetadataSignatureVerification::from_signed_descriptor)
        .ok_or_else(verified_content_not_covered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;
    use crate::constants::{digest_for_signature, namespace, transform_algorithm};
    use crate::crypto::construct_saml_signature;
    use crate::crypto::keys::load_private_key;
    use crate::util::normalize_cert_string;
    use crate::xml::{extract, ExtractorField};
    use bergshamra::sign;

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
    fn metadata_signature_transform_allowlist_preserves_canonicalization_interoperability() {
        const XPATH_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
        const XSLT_TRANSFORM: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
        const UNKNOWN_TRANSFORM: &str = "urn:example:unknown-transform";

        for algorithm in [
            transform_algorithm::ENVELOPED_SIGNATURE,
            transform_algorithm::EXC_C14N,
            EXC_C14N_WITH_COMMENTS,
            XML_C14N_10,
            XML_C14N_10_WITH_COMMENTS,
            XML_C14N_11,
            XML_C14N_11_WITH_COMMENTS,
        ] {
            assert!(
                metadata_signature_transform_allowed(algorithm),
                "{algorithm}"
            );
        }

        for algorithm in [XPATH_TRANSFORM, XSLT_TRANSFORM, UNKNOWN_TRANSFORM] {
            assert!(
                !metadata_signature_transform_allowed(algorithm),
                "{algorithm}"
            );
        }
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
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::UnsupportedReferenceUri
            })
        ));
        assert!(matches!(
            verified_target_from_uri("#xpointer(//saml:Assertion)"),
            Err(SamlError::ReferenceResolution {
                reason: ReferenceResolutionReason::UnsupportedReferenceUri
            })
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
    const RESPONSE: &str = include_str!("../../tests/fixtures/response.xml");
    const SP_PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    // IdP signing cert (matches the response_signed.xml signer / idpmeta).
    const IDP_CERT: &str = include_str!("../../tests/fixtures/key/idp_cert.cer");
    // SP signing cert (matches signed_request_sha256.xml signer).
    const SP_CERT: &str = include_str!("../../tests/fixtures/key/sp_cert.cer");
    const SP_SIGNING_CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");

    fn response_with_first_invalid_signature() -> Result<String, Box<dyn std::error::Error>> {
        let cert = normalize_cert_string(IDP_CERT);
        let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
        let invalid_signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"><ds:Transforms><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>invalid</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc_c14n = transform_algorithm::EXC_C14N,
            sig_alg = RSA_SHA256,
        );
        Ok(RESPONSE_SIGNED.replacen(
            "<samlp:Status>",
            &format!("{invalid_signature}<samlp:Status>"),
            1,
        ))
    }

    fn cid_reference_response() -> Result<String, Box<dyn std::error::Error>> {
        let cert = normalize_cert_string(SP_SIGNING_CERT);
        let signature = format!(
            "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"cid:attachment-1@example.com\"><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
            dsig = namespace::DSIG,
            exc_c14n = transform_algorithm::EXC_C14N,
            sig_alg = RSA_SHA256,
            digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?,
        );
        let template =
            RESPONSE.replacen("<samlp:Status>", &format!("{signature}<samlp:Status>"), 1);
        let key = load_private_key(SP_PRIVKEY, None)?;
        let mut manager = KeysManager::new();
        manager.add_key(key);
        let ctx = DsigContext::new(manager).with_insecure(true);
        Ok(sign(&ctx, &template)?)
    }

    fn assert_reference_resolution(
        result: Result<(bool, Option<String>), SamlError>,
        expected: ReferenceResolutionReason,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match result {
            Err(SamlError::ReferenceResolution { reason }) if reason == expected => Ok(()),
            other => Err(format!("expected reference resolution {expected}, got {other:?}").into()),
        }
    }

    #[test]
    fn dsig_context_secure_defaults_survive_insecure_builder() {
        let ctx = DsigContext::new(KeysManager::new());
        assert!(ctx.trusted_keys_only);
        assert!(ctx.strict_verification);
        assert_eq!(ctx.hmac_min_out_len, 160);
        assert!(!ctx.insecure);

        let insecure = ctx.with_insecure(true);
        assert!(insecure.insecure);
        assert!(insecure.trusted_keys_only);
        assert!(insecure.strict_verification);
        assert_eq!(insecure.hmac_min_out_len, 160);
    }

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
    fn verifies_generated_same_document_signature() -> Result<(), Box<dyn std::error::Error>> {
        let key = load_private_key(SP_PRIVKEY, None)?;
        let signed = construct_saml_signature(
            RESPONSE,
            false,
            &key,
            SP_SIGNING_CERT,
            RSA_SHA256,
            &[],
            None,
        )?;
        let (verified, content) = verify_signature(&signed, &[SP_SIGNING_CERT.to_string()])?;
        assert!(verified);
        assert!(content
            .ok_or("expected signed assertion")?
            .contains("Assertion"));
        Ok(())
    }

    #[test]
    fn inline_certificate_is_not_used_without_metadata_pin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        match verify_signature(RESPONSE_SIGNED, &[]) {
            Err(SamlError::NoTrustedCertificate) => Ok(()),
            other => Err(format!("expected missing pinned certificate, got {other:?}").into()),
        }
    }

    #[test]
    fn first_invalid_signature_prevents_later_valid_signature_from_authorizing_response(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let result = verify_signature(
            &response_with_first_invalid_signature()?,
            &[IDP_CERT.to_string()],
        )?;
        assert_eq!(result, (false, None));
        Ok(())
    }

    #[test]
    fn signed_cid_reference_is_rejected_before_content_extraction(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_reference_resolution(
            verify_signature(&cid_reference_response()?, &[SP_SIGNING_CERT.to_string()]),
            ReferenceResolutionReason::ExternalReference,
        )
    }

    #[test]
    fn rejects_signed_request_without_root_coverage() -> Result<(), Box<dyn std::error::Error>> {
        match verify_signature(SIGNED_REQUEST, &[SP_CERT.to_string()]) {
            Err(SamlError::SignedReferenceMismatch) => Ok(()),
            other => {
                Err(format!("expected uncovered AuthnRequest rejection, got {other:?}").into())
            }
        }
    }

    #[test]
    fn rejects_wrong_certificate() -> Result<(), Box<dyn std::error::Error>> {
        // RESPONSE_SIGNED embeds the IdP cert; verifying against the SP cert
        // trips the inline-vs-metadata mismatch guard.
        match verify_signature(RESPONSE_SIGNED, &[SP_CERT.to_string()]) {
            Err(SamlError::CertificateMismatch) => Ok(()),
            other => Err(format!("expected CertificateMismatch, got {other:?}").into()),
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
            Err(SamlError::PotentialWrappingAttack) => Ok(()),
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
