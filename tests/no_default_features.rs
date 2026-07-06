#![cfg(not(feature = "crypto-bergshamra"))]

use saml_rs::binding::{base64_decode, base64_encode, deflate_raw_decode};
use saml_rs::constants::{Binding, ParserType};
use saml_rs::entity::{EntitySetting, User};
use saml_rs::flow::{flow, FlowOptions, HttpRequest};
use saml_rs::idp::LoginResponseOptions;
use saml_rs::logout::{create_logout_request, create_logout_response};
use saml_rs::metadata::{Endpoint, IdpMetadata, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::xml::{extract, ExtractorField};
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AuthnRequestSigningPolicy, AuthnRequestValidationPolicy,
    CertificatePem, EntityId, IdentityProvider, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    LogoutSignaturePolicy, MessageSignaturePolicy, MetadataTrustPolicy, Saml, SamlError,
    ServiceProvider, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, StartSso,
    XmlEncryptionPolicy, XmlPolicy,
};

fn idp_config(want_authn_requests_signed: bool) -> IdpMetadataConfig {
    IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        want_authn_requests_signed,
        single_sign_on_service: vec![
            Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
            Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
        ],
        single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp.example.com/slo")],
        ..Default::default()
    }
}

fn sp_config(authn_requests_signed: bool) -> SpMetadataConfig {
    SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        authn_requests_signed,
        assertion_consumer_service: vec![Endpoint::new(
            Binding::Post,
            "https://sp.example.com/acs",
        )],
        single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp.example.com/slo")],
        ..Default::default()
    }
}

fn idp(want_authn_requests_signed: bool) -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &idp_config(want_authn_requests_signed),
        EntitySetting::default(),
    )
}

fn sp(authn_requests_signed: bool) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(&sp_config(authn_requests_signed), EntitySetting::default())
}

fn assert_unsupported(result: Result<impl Sized, SamlError>) {
    assert!(matches!(result, Err(SamlError::Unsupported(_))));
}

fn sp_config_builder() -> Result<saml_rs::SpConfigBuilder, SamlError> {
    Ok(
        SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .validation(SpValidationPolicy::compatibility()),
    )
}

fn idp_config_builder() -> Result<saml_rs::IdpConfigBuilder, SamlError> {
    Ok(
        IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .validation(IdpValidationPolicy::compatibility()),
    )
}

#[test]
fn unsigned_metadata_parsing_and_xml_extraction_still_work(
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata_xml = idp(false)?.metadata_xml().to_string();
    let metadata = IdpMetadata::from_xml(&metadata_xml)?;
    assert_eq!(
        metadata.get_entity_id(),
        Some("https://idp.example.com/metadata")
    );

    let extracted = extract(
        r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject></saml:Assertion>"#,
        &[ExtractorField::new(
            "nameID",
            &["Assertion", "Subject", "NameID"],
        )],
    )?;
    assert_eq!(extracted.get_str("nameID"), Some("user@example.com"));
    Ok(())
}

#[test]
fn typed_metadata_descriptors_parse_unsigned_metadata_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_metadata_xml = idp(false)?.metadata_xml().to_string();
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &idp_metadata_xml,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert_eq!(
        idp_descriptor.entity_id().as_str(),
        "https://idp.example.com/metadata"
    );

    let sp_metadata_xml = sp(false)?.metadata_xml().to_string();
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://sp.example.com/metadata")?,
        &sp_metadata_xml,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    assert_eq!(
        sp_descriptor.entity_id().as_str(),
        "https://sp.example.com/metadata"
    );
    Ok(())
}

#[test]
fn typed_metadata_require_signature_is_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let idp_metadata_xml = idp(false)?.metadata_xml().to_string();
    let cert = CertificatePem::new("placeholder");

    assert_unsupported(IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        &idp_metadata_xml,
        MetadataTrustPolicy::RequireSignature {
            trusted_certificates: std::slice::from_ref(&cert),
        },
    ));
    Ok(())
}

#[test]
fn typed_config_builders_construct_protocol_only_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp_config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
        .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
        .validation(SpValidationPolicy::compatibility())
        .build()?;
    let idp_config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
        .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
        .validation(IdpValidationPolicy::compatibility())
        .build()?;

    assert_eq!(
        sp_config.entity_id.as_str(),
        "https://sp.example.com/metadata"
    );
    assert_eq!(
        idp_config.entity_id.as_str(),
        "https://idp.example.com/metadata"
    );
    assert_eq!(sp_config.validation, SpValidationPolicy::compatibility());
    assert_eq!(idp_config.validation, IdpValidationPolicy::compatibility());
    Ok(())
}

#[test]
fn typed_facades_start_unsigned_sso_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config_builder()?.build()?)?;
    let idp = Saml::idp(idp_config_builder()?.build()?)?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new("https://idp.example.com/metadata")?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;

    assert!(started
        .outbound
        .redirect_url()?
        .starts_with("https://idp.example.com/sso"));
    assert_eq!(started.pending.request_id(), started.outbound.id());
    Ok(())
}

#[test]
fn typed_config_builders_return_unsupported_for_crypto_required_policy_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(
        SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
            .build(),
    );
    assert_unsupported(
        IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
            .build(),
    );
    Ok(())
}

#[test]
fn sp_required_assertion_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.assertions = AssertionSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_required_message_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.messages = MessageSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_signed_authn_requests_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.authn_requests = AuthnRequestSigningPolicy::Sign;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_signed_logout_policy_returns_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = SpValidationPolicy::compatibility();
    validation.logout.requests = LogoutSignaturePolicy::RequireSigned;

    assert_unsupported(sp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn sp_encrypted_assertions_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions(),
        ..XmlPolicy::default()
    };

    assert_unsupported(sp_config_builder()?.xml(xml).build());
    Ok(())
}

#[test]
fn idp_required_authn_request_signatures_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = IdpValidationPolicy::compatibility();
    validation.authn_requests = AuthnRequestValidationPolicy::RequireSigned;

    assert_unsupported(idp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn idp_signed_logout_policy_returns_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut validation = IdpValidationPolicy::compatibility();
    validation.logout.responses = LogoutSignaturePolicy::RequireSigned;

    assert_unsupported(idp_config_builder()?.validation(validation).build());
    Ok(())
}

#[test]
fn idp_encrypted_assertions_return_unsupported_without_default_crypto(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = XmlPolicy {
        encryption: XmlEncryptionPolicy::encrypt_assertions(),
        ..XmlPolicy::default()
    };

    assert_unsupported(idp_config_builder()?.xml(xml).build());
    Ok(())
}

#[test]
fn unsigned_login_request_creation_still_works() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = sp(false)?.create_login_request(&idp(false)?, Binding::Post, None)?;
    let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
    assert!(xml.contains("<samlp:AuthnRequest"));
    assert!(ctx.signature.is_none());
    Ok(())
}

#[test]
fn unsigned_login_request_redirect_decoding_still_works() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = sp(false)?.create_login_request(&idp(false)?, Binding::Redirect, None)?;
    let url = url::Url::parse(&ctx.context)?;
    let (_, encoded) = url
        .query_pairs()
        .find(|(key, _)| key == "SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(deflate_raw_decode(&base64_decode(encoded.as_ref())?)?)?;
    assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs\""));
    Ok(())
}

#[test]
fn signing_login_request_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(sp(true)?.create_login_request(&idp(true)?, Binding::Post, None));
    Ok(())
}

#[test]
fn signed_login_response_creation_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(idp(false)?.create_login_response(
        &sp(false)?,
        Binding::Post,
        &User::new("user@example.com"),
        &LoginResponseOptions::default(),
    ));
    Ok(())
}

#[test]
fn encrypted_assertion_parse_path_returns_unsupported() {
    let request = HttpRequest::post(vec![(
        "SAMLResponse".into(),
        base64_encode(
            br#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></samlp:Response>"#,
        ),
    )]);
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlResponse);
    options.check_signature = true;
    options.decrypt_key = Some("private key is unavailable without crypto feature");

    assert_unsupported(flow(&options, &request));
}

#[test]
fn signed_logout_request_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(create_logout_request(
        &EntitySetting::default(),
        &sp(false)?.metadata,
        &idp(false)?.metadata,
        Binding::Post,
        &User::new("user@example.com"),
        None,
        true,
    ));
    Ok(())
}

#[test]
fn signed_logout_response_returns_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    assert_unsupported(create_logout_response(
        &EntitySetting::default(),
        &idp(false)?.metadata,
        &sp(false)?.metadata,
        Binding::Post,
        Some("_logout_request"),
        None,
        true,
    ));
    Ok(())
}
