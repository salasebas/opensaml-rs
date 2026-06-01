//! XML Signature Wrapping (XSW) attack-vector corpus. Each variant must never
//! surface attacker-controlled content as cryptographically trusted.
#![cfg(feature = "crypto-bergshamra")]
#![allow(clippy::unwrap_used)]

use opensaml::constants::signature_algorithm::RSA_SHA256;
use opensaml::crypto::keys::load_private_key;
use opensaml::crypto::{construct_saml_signature, verify_signature};
use opensaml::xml::{extract, ExtractorField};
use opensaml::OpenSamlError;

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");
const RESPONSE: &str = include_str!("fixtures/misc/response.xml");
const ATTACK: &str = include_str!("fixtures/misc/attack_response_signed.xml");

const FORGED: &str = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_forged\" Version=\"2.0\" IssueInstant=\"2024-01-01T00:00:00Z\"><saml:Issuer>https://idp.example.com/metadata</saml:Issuer><saml:Subject><saml:NameID>attacker@evil.com</saml:NameID></saml:Subject></saml:Assertion>";

/// Sign the assertion inside `response.xml` and return the signed Response.
fn signed_response() -> String {
    let key = load_private_key(PRIVKEY, None).unwrap();
    construct_saml_signature(RESPONSE, false, &key, CERT, RSA_SHA256, &[], None).unwrap()
}

/// The legitimately signed Response must verify and yield the real assertion.
#[test]
fn baseline_signed_response_verifies() -> Result<(), Box<dyn std::error::Error>> {
    let (verified, content) = verify_signature(&signed_response(), &[CERT.to_string()])?;
    assert!(verified);
    assert!(content.unwrap_or_default().contains("Assertion"));
    Ok(())
}

/// Assertion/Signature smuggled under `SubjectConfirmationData` is rejected.
#[test]
fn subjectconfirmation_wrapping_rejected() -> Result<(), Box<dyn std::error::Error>> {
    match verify_signature(ATTACK, &[CERT.to_string()]) {
        Err(OpenSamlError::PotentialWrappingAttack) => Ok(()),
        Ok((false, _)) => Ok(()),
        Ok((true, content)) => {
            assert!(!content.unwrap_or_default().contains("attacker"));
            Ok(())
        }
        Err(other) => Err(format!("unexpected error: {other:?}").into()),
    }
}

/// A forged sibling assertion prepended before the signed one is never trusted.
#[test]
fn sibling_forged_assertion_not_trusted() -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response();
    let pos = signed.find("<saml:Assertion").ok_or("no assertion")?;
    let wrapped = format!("{}{}{}", &signed[..pos], FORGED, &signed[pos..]);
    let (_, content) = verify_signature(&wrapped, &[CERT.to_string()])?;
    assert!(!content.unwrap_or_default().contains("attacker@evil.com"));
    Ok(())
}

/// A forged sibling assertion appended after the signed one is never trusted.
#[test]
fn trailing_forged_assertion_not_trusted() -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response();
    let pos = signed
        .rfind("</samlp:Response>")
        .ok_or("no response close")?;
    let wrapped = format!("{}{}{}", &signed[..pos], FORGED, &signed[pos..]);
    let (_, content) = verify_signature(&wrapped, &[CERT.to_string()])?;
    assert!(!content.unwrap_or_default().contains("attacker@evil.com"));
    Ok(())
}

/// Tampering with signed content invalidates the signature.
#[test]
fn tampered_signed_content_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let signed = signed_response();
    let tampered = signed.replacen(
        "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
        "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d8",
        1,
    );
    assert!(!verify_signature(&tampered, &[CERT.to_string()])?.0);
    Ok(())
}

/// An XML comment inside a value must not truncate it (comment-splice resistance).
#[test]
fn comment_splice_reads_full_value() -> Result<(), Box<dyn std::error::Error>> {
    let xml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:Subject><saml:NameID>user<!---->@victim.com</saml:NameID></saml:Subject></saml:Assertion>";
    let r = extract(
        xml,
        &[ExtractorField::new(
            "nameID",
            &["Assertion", "Subject", "NameID"],
        )],
    )?;
    assert_eq!(r.get_str("nameID"), Some("user@victim.com"));
    Ok(())
}

/// An unsigned response is never trusted.
#[test]
fn unsigned_response_not_trusted() -> Result<(), Box<dyn std::error::Error>> {
    let (verified, content) = verify_signature(RESPONSE, &[CERT.to_string()])?;
    assert!(!verified);
    assert!(content.is_none());
    Ok(())
}
