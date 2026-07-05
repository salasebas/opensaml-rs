#![cfg(feature = "crypto-bergshamra")]

use bergshamra::{sign, DsigContext, KeysManager};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::{digest_for_signature, namespace, transform_algorithm};
use saml_rs::crypto::keys::load_private_key;
use saml_rs::crypto::{
    construct_saml_signature, verify_metadata_signature_detailed_with_limits,
    verify_metadata_signature_with_limits,
};
use saml_rs::entity::{SignatureAction, SignatureConfig};
use saml_rs::util::normalize_cert_string;
use saml_rs::xml::XmlLimits;
use saml_rs::SamlError;

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn idp_metadata_xml() -> &'static str {
    r#"<EntityDescriptor ID="_md1" entityID="https://idp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>"#
}

fn sign_root_metadata(xml: &str) -> Result<String, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some("/*[local-name(.)='EntityDescriptor']".into()),
        action: SignatureAction::Prepend,
    };
    construct_saml_signature(xml, true, &key, CERT, RSA_SHA256, &[], Some(&config))
}

fn signed_child_metadata() -> Result<String, Box<dyn std::error::Error>> {
    let digest = digest_for_signature(RSA_SHA256).ok_or("unknown digest")?;
    let signature = format!(
        "<ds:Signature xmlns:ds=\"{dsig}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"{exc_c14n}\"/><ds:SignatureMethod Algorithm=\"{sig_alg}\"/><ds:Reference URI=\"#_signed_child\"><ds:Transforms><ds:Transform Algorithm=\"{enveloped}\"/><ds:Transform Algorithm=\"{exc_c14n}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{digest}\"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        dsig = namespace::DSIG,
        exc_c14n = transform_algorithm::EXC_C14N,
        sig_alg = RSA_SHA256,
        enveloped = transform_algorithm::ENVELOPED_SIGNATURE,
        cert = normalize_cert_string(CERT),
    );
    let template = format!(
        "<EntityDescriptor ID=\"_evil_root\" entityID=\"https://evil.example.com/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">{signature}<IDPSSODescriptor ID=\"_signed_child\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://trusted.example.com/sso\"/></IDPSSODescriptor></EntityDescriptor>"
    );
    let key = load_private_key(PRIVKEY, None)?;
    let mut manager = KeysManager::new();
    manager.add_key(key);
    let ctx = DsigContext::new(manager).with_insecure(true);
    Ok(sign(&ctx, &template)?)
}

#[test]
fn metadata_signature_detailed_preserves_signed_descriptor(
) -> Result<(), Box<dyn std::error::Error>> {
    let signed = sign_root_metadata(idp_metadata_xml())?;
    let verification = verify_metadata_signature_detailed_with_limits(
        &signed,
        &[CERT.to_string()],
        XmlLimits::default(),
    )?;

    assert!(verification.verified);
    let signed_xml = verification
        .signed_entity_descriptor_xml
        .ok_or("missing signed descriptor")?;
    assert!(signed_xml.contains("entityID=\"https://idp.example.com/metadata\""));
    assert!(signed_xml.contains("<ds:Signature"));
    Ok(())
}

#[test]
fn metadata_signature_bool_wrapper_uses_detailed_coverage() -> Result<(), Box<dyn std::error::Error>>
{
    let signed = sign_root_metadata(idp_metadata_xml())?;

    assert!(verify_metadata_signature_with_limits(
        &signed,
        &[CERT.to_string()],
        XmlLimits::default(),
    )?);
    Ok(())
}

#[test]
fn metadata_signature_unsigned_metadata_returns_unverified(
) -> Result<(), Box<dyn std::error::Error>> {
    let verification = verify_metadata_signature_detailed_with_limits(
        idp_metadata_xml(),
        &[CERT.to_string()],
        XmlLimits::default(),
    )?;

    assert!(!verification.verified);
    assert_eq!(verification.signed_entity_descriptor_xml, None);
    Ok(())
}

#[test]
fn metadata_signature_rejects_signed_child_without_descriptor_coverage(
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped = signed_child_metadata()?;

    match verify_metadata_signature_detailed_with_limits(
        &wrapped,
        &[CERT.to_string()],
        XmlLimits::default(),
    ) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}
