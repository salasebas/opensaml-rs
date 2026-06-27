#![cfg(feature = "crypto-bergshamra")]

use opensaml::binding::base64_decode;
use opensaml::constants::signature_algorithm::RSA_SHA256;
use opensaml::constants::Binding;
use opensaml::entity::{EntitySetting, User};
use opensaml::idp::LoginResponseOptions;
use opensaml::logout::create_logout_request;
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::template::{LoginResponseAttribute, LoginResponseTemplate, LOGIN_RESPONSE_TEMPLATE};
use opensaml::{IdentityProvider, ServiceProvider};

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn signing() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVKEY.into());
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    setting
}

fn idp(setting: EntitySetting) -> TestResult<IdentityProvider> {
    Ok(IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
            ..Default::default()
        },
        setting,
    )?)
}

fn sp() -> TestResult<ServiceProvider> {
    Ok(ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            ..Default::default()
        },
        signing(),
    )?)
}

fn decode_binding_context(context: &str) -> TestResult<String> {
    Ok(String::from_utf8(base64_decode(context)?)?)
}

#[test]
fn login_response_name_id_escapes_xml_markup_before_signing() -> TestResult {
    let idp = idp(signing())?;
    let sp = sp()?;
    let injected_name_id = concat!(
        "attacker@example.com",
        "</saml:NameID>",
        "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">",
        "admin@example.com",
        "</saml:NameID>",
        "<saml:NameID>"
    );

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new(injected_name_id),
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<saml:NameID").count(), 1);
    assert!(xml.contains("&lt;/saml:NameID&gt;"));
    assert!(xml.contains("&lt;saml:NameID Format=&quot;"));
    assert!(!xml.contains("<saml:NameID>admin@example.com</saml:NameID>"));
    Ok(())
}

#[test]
fn login_response_attribute_values_escape_xml_markup_before_signing() -> TestResult {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: vec![LoginResponseAttribute {
            name: "role".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: "user.role".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let injected_role = concat!(
        "user",
        "</saml:AttributeValue></saml:Attribute>",
        "<saml:Attribute Name=\"admin\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">",
        "<saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ",
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">",
        "true",
        "</saml:AttributeValue>",
        "</saml:Attribute>",
        "<saml:Attribute Name=\"role\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">",
        "<saml:AttributeValue xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ",
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">",
        "user"
    );
    let user = User {
        name_id: "attacker@example.com".into(),
        attributes: vec![("user.role".into(), injected_role.into())],
        session_index: None,
    };

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<saml:Attribute ").count(), 1);
    assert_eq!(xml.matches("<saml:AttributeValue ").count(), 1);
    assert!(xml.contains("&lt;/saml:AttributeValue&gt;"));
    assert!(xml.contains("&lt;saml:Attribute Name=&quot;admin&quot;"));
    assert!(!xml.contains("<saml:Attribute Name=\"admin\""));
    Ok(())
}

#[test]
fn logout_request_name_id_escapes_xml_markup_before_signing() -> TestResult {
    let idp = idp(signing())?;
    let sp = sp()?;
    let injected_name_id = concat!(
        "attacker@example.com",
        "</saml:NameID>",
        "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">",
        "admin@example.com",
        "</saml:NameID>",
        "<saml:NameID>"
    );

    let ctx = create_logout_request(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        &User::new(injected_name_id),
        None,
        true,
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<saml:NameID").count(), 1);
    assert!(xml.contains("&lt;/saml:NameID&gt;"));
    assert!(xml.contains("&lt;saml:NameID Format=&quot;"));
    assert!(!xml.contains("<saml:NameID>admin@example.com</saml:NameID>"));
    Ok(())
}
