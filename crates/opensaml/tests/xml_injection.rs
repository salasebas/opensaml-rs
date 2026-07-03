#![cfg(feature = "crypto-bergshamra")]

use opensaml::binding::base64_decode;
use opensaml::constants::signature_algorithm::RSA_SHA256;
use opensaml::constants::Binding;
use opensaml::entity::{EntitySetting, User};
use opensaml::flow::HttpRequest;
use opensaml::idp::LoginResponseOptions;
use opensaml::logout::{create_logout_request, create_logout_response};
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::template::{LoginResponseAttribute, LoginResponseTemplate, LOGIN_RESPONSE_TEMPLATE};
use opensaml::xml::dom::{parse_roots, Node};
use opensaml::{IdentityProvider, OpenSamlError, ServiceProvider};

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

fn login_response_shape(xml: &str) -> TestResult {
    let roots = parse_roots(xml)?;
    assert_eq!(roots.len(), 1);
    let response = roots.first().ok_or("missing response root")?;
    assert_eq!(response.local_name, "Response");
    assert_eq!(direct_children(response, "Assertion").count(), 1);
    assert_eq!(direct_children(response, "Issuer").count(), 1);

    let assertion = direct_children(response, "Assertion")
        .next()
        .ok_or("missing assertion")?;
    assert_eq!(direct_children(assertion, "Issuer").count(), 1);
    Ok(())
}

fn direct_children<'a>(node: &'a Node, local_name: &'a str) -> impl Iterator<Item = &'a Node> {
    node.children
        .iter()
        .filter(move |child| child.local_name == local_name)
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
fn login_response_wrapper_fields_escape_xml_markup_before_signing() -> TestResult {
    const HOSTILE_IDP_ENTITY_ID: &str =
        "https://idp.example.com/metadata</saml:Issuer><InjectedIssuer>evil</InjectedIssuer>";
    const HOSTILE_SP_ENTITY_ID: &str =
        "https://sp.example.com/metadata</saml:Audience><InjectedAudience>evil</InjectedAudience>";
    const HOSTILE_ACS: &str =
        "https://sp.example.com/acs\" injected=\"yes\"><InjectedDestination/>";
    const HOSTILE_REQUEST_ID: &str =
        "_req\" injected=\"yes\"></samlp:Response><samlp:Response ID=\"evil\">";
    const HOSTILE_NAME_ID_FORMAT: &str =
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" injected=\"yes";

    let mut idp_setting = signing();
    idp_setting.name_id_format = vec![HOSTILE_NAME_ID_FORMAT.into()];
    let idp = IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: HOSTILE_IDP_ENTITY_ID.into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://idp/slo")],
            ..Default::default()
        },
        idp_setting,
    )?;
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: HOSTILE_SP_ENTITY_ID.into(),
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, HOSTILE_ACS)],
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            ..Default::default()
        },
        signing(),
    )?;

    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("wrapper@example.com"),
        &LoginResponseOptions {
            in_response_to: Some(HOSTILE_REQUEST_ID),
            ..Default::default()
        },
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    login_response_shape(&xml)?;
    assert!(!xml.contains("<InjectedIssuer>"));
    assert!(!xml.contains("<InjectedAudience>"));
    assert!(!xml.contains("<InjectedDestination"));
    assert!(!xml.contains("<samlp:Response ID=\"evil\""));
    assert!(!xml.contains(" injected=\"yes"));
    assert!(xml.contains("&lt;InjectedIssuer&gt;evil&lt;/InjectedIssuer&gt;"));
    assert!(xml.contains("&lt;InjectedAudience&gt;evil&lt;/InjectedAudience&gt;"));
    assert!(
        xml.contains("Destination=\"https://sp.example.com/acs&quot; injected=&quot;yes&quot;&gt;")
    );
    assert!(
        xml.contains("Recipient=\"https://sp.example.com/acs&quot; injected=&quot;yes&quot;&gt;")
    );
    assert!(xml.contains("InResponseTo=\"_req&quot; injected=&quot;yes&quot;&gt;"));
    assert!(xml.contains("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress&quot; injected=&quot;yes\""));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, HOSTILE_REQUEST_ID)?;
    assert_eq!(
        parsed.extract.get_str("nameID"),
        Some("wrapper@example.com")
    );
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
fn login_response_attribute_default_rendering_uses_exact_value_tags() -> TestResult {
    const DOT_EMAIL: &str = "dot@example.com";
    const UNDERSCORE_EMAIL: &str = "underscore@example.com";

    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: vec![
            LoginResponseAttribute {
                name: "dot-email".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
                value_xsi_type: "xs:string".into(),
                value_tag: "user.email".into(),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            },
            LoginResponseAttribute {
                name: "underscore-email".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
                value_xsi_type: "xs:string".into(),
                value_tag: "user_email".into(),
                value_xmlns_xs: None,
                value_xmlns_xsi: None,
            },
        ],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let user = User {
        name_id: "attacker@example.com".into(),
        attributes: vec![
            ("user.email".into(), DOT_EMAIL.into()),
            ("user_email".into(), UNDERSCORE_EMAIL.into()),
        ],
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
    assert!(!xml.contains("{attr"));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_req1")?;
    let attributes = parsed
        .extract
        .get("attributes")
        .ok_or("missing parsed attributes")?;
    assert_eq!(
        attributes
            .get_key("dot-email")
            .and_then(|value| value.as_str()),
        Some(DOT_EMAIL)
    );
    assert_eq!(
        attributes
            .get_key("underscore-email")
            .and_then(|value| value.as_str()),
        Some(UNDERSCORE_EMAIL)
    );
    Ok(())
}

#[test]
fn login_response_attribute_missing_value_fails_before_signing() -> TestResult {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: vec![LoginResponseAttribute {
            name: "mail".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: "user.email".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }],
    });
    let idp = idp(setting)?;
    let sp = sp()?;

    let result = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("attacker@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_req1"),
            ..Default::default()
        },
    );

    assert!(
        matches!(result, Err(OpenSamlError::Invalid(_))),
        "expected missing attribute to fail closed, got {result:?}"
    );
    Ok(())
}

#[test]
fn login_response_attribute_default_rendering_leaves_no_attr_placeholders() -> TestResult {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: vec![LoginResponseAttribute {
            name: "mail".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: "user.email".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let user = User {
        name_id: "attacker@example.com".into(),
        attributes: vec![("user.email".into(), "user@example.com".into())],
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

    assert!(!xml.contains("{attr"));
    Ok(())
}

#[test]
fn login_response_attribute_metadata_escapes_xml_markup_before_signing() -> TestResult {
    const ATTRIBUTE_NAME: &str = "mail\" FriendlyName=\"pwned\" injected=\"yes";
    const ATTRIBUTE_VALUE: &str = "user@example.com";

    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: vec![LoginResponseAttribute {
            name: ATTRIBUTE_NAME.into(),
            name_format: "urn:format\" injected_format=\"yes".into(),
            value_xsi_type: "xs:string'\" injected_type=\"yes".into(),
            value_tag: "user.email".into(),
            value_xmlns_xs: Some("http://www.w3.org/2001/XMLSchema\" injected_xs=\"yes".into()),
            value_xmlns_xsi: Some(
                "http://www.w3.org/2001/XMLSchema-instance\" injected_xsi=\"yes".into(),
            ),
        }],
    });
    let idp = idp(setting)?;
    let sp = sp()?;
    let user = User {
        name_id: "attacker@example.com".into(),
        attributes: vec![("user.email".into(), ATTRIBUTE_VALUE.into())],
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
    assert!(!xml.contains(" FriendlyName=\"pwned\""));
    assert!(!xml.contains(" injected=\"yes\""));
    assert!(!xml.contains(" injected_format=\"yes\""));
    assert!(!xml.contains(" injected_xs=\"yes\""));
    assert!(!xml.contains(" injected_xsi=\"yes\""));
    assert!(!xml.contains(" injected_type=\"yes\""));
    assert!(xml.contains("Name=\"mail&quot; FriendlyName=&quot;pwned&quot; injected=&quot;yes\""));
    assert!(xml.contains("NameFormat=\"urn:format&quot; injected_format=&quot;yes\""));
    assert!(
        xml.contains("xmlns:xs=\"http://www.w3.org/2001/XMLSchema&quot; injected_xs=&quot;yes\"")
    );
    assert!(xml.contains(
        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance&quot; injected_xsi=&quot;yes\""
    ));
    assert!(xml.contains("xsi:type=\"xs:string&apos;&quot; injected_type=&quot;yes\""));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_req1")?;
    assert_eq!(
        parsed
            .extract
            .get("attributes")
            .and_then(|attributes| attributes.get_key(ATTRIBUTE_NAME))
            .and_then(|value| value.as_str()),
        Some(ATTRIBUTE_VALUE)
    );
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

#[test]
fn logout_request_session_index_escapes_xml_markup_before_signing() -> TestResult {
    let idp = idp(signing())?;
    let sp = sp()?;
    let injected_session_index = concat!(
        "_session\"quoted",
        "</samlp:SessionIndex>",
        "<samlp:SessionIndex>admin-session</samlp:SessionIndex>",
        "<samlp:SessionIndex>"
    );
    let mut user = User::new("attacker@example.com");
    user.session_index = Some(injected_session_index.into());

    let ctx = create_logout_request(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        &user,
        None,
        true,
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<samlp:SessionIndex>").count(), 1);
    assert!(xml.contains("&lt;/samlp:SessionIndex&gt;"));
    assert!(xml.contains("&lt;samlp:SessionIndex&gt;admin-session"));
    assert!(!xml.contains("<samlp:SessionIndex>admin-session</samlp:SessionIndex>"));
    Ok(())
}

#[test]
fn logout_response_in_response_to_escapes_xml_markup_before_signing() -> TestResult {
    let idp = idp(signing())?;
    let sp = sp()?;
    let injected_request_id = concat!(
        "_req\" injected=\"yes",
        "\"></samlp:LogoutResponse>",
        "<samlp:LogoutResponse ID=\"evil\">"
    );

    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some(injected_request_id),
        None,
        true,
    )?;
    let xml = decode_binding_context(&ctx.context)?;

    assert!(xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("<samlp:LogoutResponse").count(), 1);
    assert!(xml.contains("InResponseTo=\"_req&quot; injected=&quot;yes"));
    assert!(xml.contains("&lt;/samlp:LogoutResponse&gt;"));
    assert!(!xml.contains(" injected=\"yes"));
    assert!(!xml.contains("<samlp:LogoutResponse ID=\"evil\">"));
    Ok(())
}
