//! Production-hardening tests: Audience restriction and InResponseTo / anti-replay.
#![cfg(feature = "crypto-bergshamra")]
#![allow(clippy::unwrap_used)]

use opensaml::constants::signature_algorithm::RSA_SHA256;
use opensaml::constants::Binding;
use opensaml::entity::{EntitySetting, User};
use opensaml::flow::HttpRequest;
use opensaml::idp::LoginResponseOptions;
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::{IdentityProvider, OpenSamlError, ServiceProvider};

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn signing() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVKEY.into());
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    setting
}

fn idp() -> IdentityProvider {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            ..Default::default()
        },
        signing(),
    )
    .unwrap()
}

fn sp_with(entity_id: &str, setting: EntitySetting) -> ServiceProvider {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: entity_id.into(),
            want_assertions_signed: true,
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        setting,
    )
    .unwrap()
}

fn response_for(sp: &ServiceProvider) -> String {
    idp()
        .create_login_response(
            sp,
            Binding::Post,
            &User::new("a@example.com"),
            &LoginResponseOptions {
                in_response_to: Some("_req1"),
                ..Default::default()
            },
        )
        .unwrap()
        .context
}

#[test]
fn audience_match_accepts() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp))]);
    let parsed = sp.parse_login_response(&idp(), Binding::Post, &req)?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn audience_mismatch_rejected() {
    // Response is addressed (Audience) to sp1; sp2 must reject it.
    let sp1 = sp_with("https://sp1.example.com/metadata", signing());
    let sp2 = sp_with("https://sp2.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp1))]);
    assert!(matches!(
        sp2.parse_login_response(&idp(), Binding::Post, &req),
        Err(OpenSamlError::UnmatchAudience)
    ));
}

#[test]
fn audience_validation_opt_out() -> Result<(), Box<dyn std::error::Error>> {
    let sp1 = sp_with("https://sp1.example.com/metadata", signing());
    let mut setting = signing();
    setting.validate_audience = false;
    let sp2 = sp_with("https://sp2.example.com/metadata", setting);
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp1))]);
    // With audience validation disabled, sp2 accepts it (signature still checked).
    sp2.parse_login_response(&idp(), Binding::Post, &req)?;
    Ok(())
}

#[test]
fn in_response_to_match_accepts() -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp))]);
    sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_req1")?;
    Ok(())
}

#[test]
fn in_response_to_mismatch_rejected() {
    let sp = sp_with("https://sp.example.com/metadata", signing());
    let req = HttpRequest::post(vec![("SAMLResponse".into(), response_for(&sp))]);
    assert!(matches!(
        sp.parse_login_response_with_request_id(&idp(), Binding::Post, &req, "_wrong"),
        Err(OpenSamlError::InvalidInResponseTo)
    ));
}

#[test]
fn sign_then_encrypt_message_auto_resolves() -> Result<(), Box<dyn std::error::Error>> {
    // Request sign-then-encrypt (encrypt_then_sign=false) with an encrypted,
    // message-signed response. The IdP must produce a verifiable response
    // (it signs the message after encryption, since the other order is unsound).
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            ..Default::default()
        },
        idp_setting,
    )?;
    let mut sp_setting = signing();
    sp_setting.is_assertion_encrypted = true;
    sp_setting.enc_private_key = Some(PRIVKEY.into());
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            want_assertions_signed: false, // message gets signed
            signing_certs: vec![CERT.into()],
            encrypt_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        sp_setting,
    )?;
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("a@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            encrypt_then_sign: false, // requested sign-then-encrypt; resolved safely
            ..Default::default()
        },
    )?;
    let req = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = sp.parse_login_response(&idp, Binding::Post, &req)?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn signed_metadata_verifies_against_trust_anchor() -> Result<(), Box<dyn std::error::Error>> {
    use opensaml::crypto::keys::load_private_key;
    use opensaml::crypto::{construct_saml_signature, verify_metadata_signature};
    use opensaml::entity::{SignatureAction, SignatureConfig};
    use opensaml::metadata::IdpMetadata;

    let md = "<EntityDescriptor ID=\"_md1\" entityID=\"https://idp.example.com/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp/sso\"/></IDPSSODescriptor></EntityDescriptor>";
    let key = load_private_key(PRIVKEY, None)?;
    let config = SignatureConfig {
        prefix: "ds".into(),
        reference: Some("/*[local-name(.)='EntityDescriptor']".into()),
        action: SignatureAction::Prepend,
    };
    let signed = construct_saml_signature(md, true, &key, CERT, RSA_SHA256, &[], Some(&config))?;

    // Valid against the trust anchor.
    assert!(verify_metadata_signature(&signed, &[CERT.to_string()])?);
    // Also reachable via the parsed Metadata.
    assert!(IdpMetadata::from_xml(&signed)?.verify_signature(&[CERT.to_string()])?);
    // Tampered entityID no longer verifies.
    let tampered = signed.replacen(
        "https://idp.example.com/metadata",
        "https://evil/metadata",
        1,
    );
    assert!(!verify_metadata_signature(&tampered, &[CERT.to_string()])?);
    Ok(())
}
