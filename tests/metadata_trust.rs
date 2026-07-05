#![cfg(feature = "crypto-bergshamra")]

use bergshamra::{sign, DsigContext, KeysManager};
use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::{digest_for_signature, namespace, transform_algorithm};
use saml_rs::crypto::construct_saml_signature;
use saml_rs::crypto::keys::load_private_key;
use saml_rs::entity::{SignatureAction, SignatureConfig};
use saml_rs::error::SignatureVerificationReason;
use saml_rs::util::normalize_cert_string;
use saml_rs::{
    CertificatePem, EntityId, IdpDescriptor, MetadataTrustPolicy, SamlError, SpDescriptor,
};

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn idp_metadata_xml() -> &'static str {
    r#"<EntityDescriptor ID="_idp_md1" entityID="https://idp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>"#
}

fn sp_metadata_xml() -> &'static str {
    r#"<EntityDescriptor ID="_sp_md1" entityID="https://sp.example.com/metadata" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0"/></SPSSODescriptor></EntityDescriptor>"#
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

fn trust<'a>(certificates: &'a [CertificatePem]) -> MetadataTrustPolicy<'a> {
    MetadataTrustPolicy::RequireSignature {
        trusted_certificates: certificates,
    }
}

#[test]
fn metadata_trust_accepts_signed_idp_descriptor_with_pinned_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let signed = sign_root_metadata(idp_metadata_xml())?;
    let descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &signed,
        trust(std::slice::from_ref(&cert)),
    )?;

    assert!(descriptor.was_verified_with_pinned_certificates());
    assert!(descriptor
        .signed_entity_descriptor_xml()
        .is_some_and(|xml| xml.contains("https://idp.example.com/metadata")));
    Ok(())
}

#[test]
fn metadata_trust_accepts_signed_sp_descriptor_with_pinned_certificate(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let signed = sign_root_metadata(sp_metadata_xml())?;
    let descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://sp.example.com/metadata")?,
        &signed,
        trust(std::slice::from_ref(&cert)),
    )?;

    assert!(descriptor.was_verified_with_pinned_certificates());
    assert!(descriptor
        .signed_entity_descriptor_xml()
        .is_some_and(|xml| xml.contains("https://sp.example.com/metadata")));
    Ok(())
}

#[test]
fn metadata_trust_rejects_unsigned_metadata_when_signature_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    match IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp_metadata_xml(),
        trust(std::slice::from_ref(&cert)),
    ) {
        Err(SamlError::SignatureVerification { reason }) => {
            assert_eq!(reason, SignatureVerificationReason::XmlSignature);
            Ok(())
        }
        other => Err(format!("expected metadata signature failure, got {other:?}").into()),
    }
}

#[test]
fn metadata_trust_rejects_signature_without_descriptor_coverage(
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertificatePem::new(CERT);
    let wrapped = signed_child_metadata()?;

    match IdpDescriptor::from_metadata_xml(&wrapped, trust(std::slice::from_ref(&cert))) {
        Err(SamlError::SignedReferenceMismatch) => Ok(()),
        other => Err(format!("expected SignedReferenceMismatch, got {other:?}").into()),
    }
}
