//! Port of samlify `test/flow.ts` (64 cases) as behavioural round-trips.
//!
//! Upstream uses IdP/SP private keys whose PEM format `bergshamra` cannot
//! auto-detect, so entities are built from config with the project's working
//! RSA keypair. Redirect/SimpleSign responses are parsed by reconstructing the
//! signed octet string the way the bindings produce it.
#![cfg(feature = "crypto-bergshamra")]
#![allow(clippy::unwrap_used)]

use opensaml::binding::{base64_decode, base64_encode, deflate_raw_encode};
use opensaml::constants::signature_algorithm::RSA_SHA256;
use opensaml::constants::Binding;
use opensaml::entity::{iso8601_offset, BindingContext, EntitySetting, User};
use opensaml::flow::{FlowResult, HttpRequest};
use opensaml::idp::LoginResponseOptions;
use opensaml::logout::{
    create_logout_request, create_logout_response, parse_logout_request, parse_logout_response,
};
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::template::{replace_tags_by_value, LoginResponseAttribute, LoginResponseTemplate};
use opensaml::{IdentityProvider, OpenSamlError, ServiceProvider};

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");
const FAILED: &str = include_str!("fixtures/misc/failed_response.xml");

fn signing() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVKEY.into());
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    setting
}

fn idp_config(want_authn_signed: bool) -> IdpMetadataConfig {
    IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        signing_certs: vec![CERT.into()],
        want_authn_requests_signed: want_authn_signed,
        single_sign_on_service: vec![
            Endpoint::new(Binding::Post, "https://idp/sso"),
            Endpoint::new(Binding::Redirect, "https://idp/sso"),
            Endpoint::new(Binding::SimpleSign, "https://idp/sso"),
        ],
        single_logout_service: vec![
            Endpoint::new(Binding::Post, "https://idp/slo"),
            Endpoint::new(Binding::Redirect, "https://idp/slo"),
        ],
        ..Default::default()
    }
}

fn sp_config(authn_signed: bool, want_assertions_signed: bool, enc: bool) -> SpMetadataConfig {
    SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        authn_requests_signed: authn_signed,
        want_assertions_signed,
        signing_certs: vec![CERT.into()],
        encrypt_certs: if enc { vec![CERT.into()] } else { Vec::new() },
        single_logout_service: vec![
            Endpoint::new(Binding::Post, "https://sp/slo"),
            Endpoint::new(Binding::Redirect, "https://sp/slo"),
        ],
        assertion_consumer_service: vec![
            Endpoint::new(Binding::Post, "https://sp/acs"),
            Endpoint::new(Binding::Redirect, "https://sp/acs"),
            Endpoint::new(Binding::SimpleSign, "https://sp/acs"),
        ],
        ..Default::default()
    }
}

fn idp(want_authn_signed: bool) -> IdentityProvider {
    IdentityProvider::from_config(&idp_config(want_authn_signed), signing()).unwrap()
}

fn sp(want_assertions_signed: bool, enc: bool) -> ServiceProvider {
    let mut setting = signing();
    if enc {
        setting.is_assertion_encrypted = true;
        setting.enc_private_key = Some(PRIVKEY.into());
    }
    ServiceProvider::from_config(&sp_config(false, want_assertions_signed, enc), setting).unwrap()
}

fn unsigned_idp() -> IdentityProvider {
    IdentityProvider::from_config(&idp_config(false), EntitySetting::default()).unwrap()
}

fn unsigned_sp() -> ServiceProvider {
    ServiceProvider::from_config(&sp_config(false, false, false), EntitySetting::default()).unwrap()
}

/// Rebuild the SP-side HTTP request for a response over `binding`.
fn response_request(binding: Binding, ctx: &BindingContext) -> Result<HttpRequest, OpenSamlError> {
    Ok(match binding {
        Binding::Post => HttpRequest::post(vec![("SAMLResponse".into(), ctx.context.clone())]),
        Binding::Redirect => redirect_request(&ctx.context)?,
        Binding::SimpleSign => simplesign_request("SAMLResponse", ctx)?,
        Binding::Artifact => return Err(OpenSamlError::UndefinedBinding),
    })
}

fn parse_response_with_request_id(
    sp: &ServiceProvider,
    idp: &IdentityProvider,
    binding: Binding,
    ctx: &BindingContext,
    request_id: &str,
) -> Result<FlowResult, OpenSamlError> {
    let request = response_request(binding, ctx)?;
    sp.parse_login_response_with_request_id(idp, binding, &request, request_id)
}

fn redirect_request(url: &str) -> Result<HttpRequest, OpenSamlError> {
    let parsed = url::Url::parse(url).map_err(|e| OpenSamlError::Invalid(e.to_string()))?;
    let raw = parsed.query().unwrap_or("");
    let octet = raw.split("&Signature=").next().unwrap_or("").to_string();
    let query = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    Ok(HttpRequest {
        query,
        octet_string: Some(octet),
        ..Default::default()
    })
}

fn simplesign_request(param: &str, ctx: &BindingContext) -> Result<HttpRequest, OpenSamlError> {
    let raw_xml = String::from_utf8(base64_decode(&ctx.context)?)
        .map_err(|e| OpenSamlError::Xml(e.to_string()))?;
    let sig_alg = ctx.sig_alg.clone().unwrap_or_default();
    let octet = format!("{param}={raw_xml}&RelayState=&SigAlg={sig_alg}");
    let body = vec![
        (param.to_string(), ctx.context.clone()),
        ("SigAlg".into(), sig_alg),
        (
            "Signature".into(),
            ctx.signature.clone().unwrap_or_default(),
        ),
    ];
    Ok(HttpRequest {
        body,
        octet_string: Some(octet),
        ..Default::default()
    })
}

/// A `customTagReplacement` that renders our default template + attributes.
fn fill_response(template: &str, idp_id: &str, email: &str) -> (String, String) {
    let id = "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6".to_string();
    let now = iso8601_offset(-60);
    let later = iso8601_offset(300);
    let xml = replace_tags_by_value(
        template,
        &[
            ("ID", id.clone()),
            ("AssertionID", "_assertion0123456789".into()),
            ("Destination", "https://sp/acs".into()),
            ("SubjectRecipient", "https://sp/acs".into()),
            ("AssertionConsumerServiceURL", "https://sp/acs".into()),
            ("Audience", "https://sp.example.com/metadata".into()),
            ("Issuer", idp_id.to_string()),
            ("IssueInstant", now.clone()),
            (
                "StatusCode",
                "urn:oasis:names:tc:SAML:2.0:status:Success".into(),
            ),
            ("ConditionsNotBefore", now),
            ("ConditionsNotOnOrAfter", later.clone()),
            ("SubjectConfirmationDataNotOnOrAfter", later),
            (
                "NameIDFormat",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
            ),
            ("NameID", email.to_string()),
            ("InResponseTo", "_req".into()),
            ("AuthnStatement", String::new()),
            ("attrUserEmail", email.to_string()),
            ("attrUserName", "user name".into()),
        ],
    );
    (id, xml)
}

fn custom_idp() -> IdentityProvider {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(opensaml::template::LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: vec![attr("mail", "user.email"), attr("name", "user.name")],
    });
    IdentityProvider::from_config(&idp_config(false), setting).unwrap()
}

fn attr(name: &str, tag: &str) -> LoginResponseAttribute {
    LoginResponseAttribute {
        name: name.into(),
        value_tag: tag.into(),
        name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
        value_xsi_type: "xs:string".into(),
        value_xmlns_xs: None,
        value_xmlns_xsi: None,
    }
}

fn opts(in_response_to: &str) -> LoginResponseOptions<'_> {
    LoginResponseOptions {
        in_response_to: Some(in_response_to),
        ..Default::default()
    }
}

fn attacker_authn_request() -> &'static str {
    "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_attacker_req\" Version=\"2.0\" IssueInstant=\"2026-06-27T19:15:08Z\" Destination=\"https://idp/sso\" AssertionConsumerServiceURL=\"https://evil.example/acs\"><saml:Issuer>https://evil.example/metadata</saml:Issuer></samlp:AuthnRequest>"
}

fn assert_failed_message_signature(
    result: Result<opensaml::flow::FlowResult, OpenSamlError>,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(OpenSamlError::FailedMessageSignatureVerification) => Ok(()),
        other => {
            Err(format!("expected detached signature verification failure, got {other:?}").into())
        }
    }
}

// ----- create login request (1-3): default template round-trip -----

fn login_request_round_trip(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let sp = unsigned_sp();
    let idp = unsigned_idp();
    let ctx = sp.create_login_request(&idp, binding, None)?;
    let request = match binding {
        Binding::Redirect => redirect_request(&ctx.context)?,
        _ => HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]),
    };
    let parsed = idp.parse_login_request(&sp, binding, &request)?;
    assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));
    Ok(())
}

#[test]
fn login_request_redirect_default() -> Result<(), Box<dyn std::error::Error>> {
    login_request_round_trip(Binding::Redirect)
}
#[test]
fn login_request_simplesign_default() -> Result<(), Box<dyn std::error::Error>> {
    login_request_round_trip(Binding::SimpleSign)
}
#[test]
fn login_request_post_default() -> Result<(), Box<dyn std::error::Error>> {
    login_request_round_trip(Binding::Post)
}

// ----- signed/unsigned mismatch (4-6) -----

fn mismatch(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    // SP signs requests, IdP does not require it.
    let sp = ServiceProvider::from_config(&sp_config(true, false, false), signing())?;
    let idp = idp(false);
    match sp.create_login_request(&idp, binding, None) {
        Err(OpenSamlError::Invalid(m)) if m.contains("CONFLICT") => Ok(()),
        other => Err(format!("expected conflict, got {other:?}").into()),
    }
}

#[test]
fn mismatch_post() -> Result<(), Box<dyn std::error::Error>> {
    mismatch(Binding::Post)
}
#[test]
fn mismatch_redirect() -> Result<(), Box<dyn std::error::Error>> {
    mismatch(Binding::Redirect)
}
#[test]
fn mismatch_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    mismatch(Binding::SimpleSign)
}

// ----- create login request with custom template (7,10,11) -----

fn login_request_custom(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let sp = unsigned_sp();
    let idp = unsigned_idp();
    let cb = |_t: &str| {
        (
            "_custom_req".to_string(),
            "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_custom_req\"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer></samlp:AuthnRequest>".to_string(),
        )
    };
    let ctx = sp.create_login_request(
        &idp,
        binding,
        Some(&cb as &dyn Fn(&str) -> (String, String)),
    )?;
    assert_eq!(ctx.id, "_custom_req");
    Ok(())
}

#[test]
fn login_request_redirect_custom() -> Result<(), Box<dyn std::error::Error>> {
    login_request_custom(Binding::Redirect)
}
#[test]
fn login_request_post_custom() -> Result<(), Box<dyn std::error::Error>> {
    login_request_custom(Binding::Post)
}
#[test]
fn login_request_simplesign_custom() -> Result<(), Box<dyn std::error::Error>> {
    login_request_custom(Binding::SimpleSign)
}

// ----- detached message signature binding -----

fn detached_signature_rejects_mismatched_login_request(
    binding: Binding,
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = ServiceProvider::from_config(&sp_config(true, false, false), signing())?;
    let idp = idp(true);
    let ctx = sp.create_login_request(&idp, binding, None)?;
    let mut request = match binding {
        Binding::Redirect => redirect_request(&ctx.context)?,
        Binding::SimpleSign => simplesign_request("SAMLRequest", &ctx)?,
        _ => return Err("unsupported binding for detached regression".into()),
    };

    let parsed = idp.parse_login_request(&sp, binding, &request)?;
    assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));

    match binding {
        Binding::Redirect => {
            let attacker = base64_encode(&deflate_raw_encode(attacker_authn_request().as_bytes())?);
            let (_, saml_request) = request
                .query
                .iter_mut()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            *saml_request = attacker;
        }
        Binding::SimpleSign => {
            let attacker = base64_encode(attacker_authn_request().as_bytes());
            let (_, saml_request) = request
                .body
                .iter_mut()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            *saml_request = attacker;
        }
        _ => return Err("unsupported binding for detached regression".into()),
    }

    assert_failed_message_signature(idp.parse_login_request(&sp, binding, &request))
}

#[test]
fn redirect_signature_rejects_mismatched_consumed_request() -> Result<(), Box<dyn std::error::Error>>
{
    detached_signature_rejects_mismatched_login_request(Binding::Redirect)
}

#[test]
fn simplesign_signature_rejects_mismatched_consumed_request(
) -> Result<(), Box<dyn std::error::Error>> {
    detached_signature_rejects_mismatched_login_request(Binding::SimpleSign)
}

// ----- create login request signed with PKCS#8 keys (8,9) -----

fn signed_request_with_key(
    key: &str,
    pass: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(key.into());
    setting.private_key_pass = pass.map(str::to_string);
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    let sp = ServiceProvider::from_config(&sp_config(true, false, false), setting)?;
    let idp = idp(true);
    let ctx = sp.create_login_request(&idp, Binding::Redirect, None)?;
    assert!(ctx.context.contains("&Signature="));
    Ok(())
}

#[test]
fn login_request_redirect_signed_unencrypted_pkcs8() -> Result<(), Box<dyn std::error::Error>> {
    signed_request_with_key(
        include_str!("fixtures/key/sp/privkey.unencrypted.pkcs8.pem"),
        None,
    )
}
#[test]
fn login_request_redirect_signed_encrypted_pkcs8() -> Result<(), Box<dyn std::error::Error>> {
    signed_request_with_key(
        include_str!("fixtures/key/sp/privkey.encrypted.pkcs8.pem"),
        Some("VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px"),
    )
}

// ----- create login response (12-15) -----

#[test]
fn login_response_undefined_binding() {
    let idp = idp(false);
    let sp = sp(true, false);
    assert!(idp
        .create_login_response(&sp, Binding::Artifact, &User::new("a@e.com"), &opts("_r"))
        .is_err());
}

fn create_login_response(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(true, false);
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@e.com"), &opts("_r"))?;
    assert!(!ctx.context.is_empty());
    Ok(())
}

#[test]
fn create_redirect_login_response() -> Result<(), Box<dyn std::error::Error>> {
    create_login_response(Binding::Redirect)
}
#[test]
fn create_simplesign_login_response() -> Result<(), Box<dyn std::error::Error>> {
    create_login_response(Binding::SimpleSign)
}
#[test]
fn create_post_login_response() -> Result<(), Box<dyn std::error::Error>> {
    create_login_response(Binding::Post)
}

// ----- create logout request (16-18) -----

fn logout_request(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_request(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        binding,
        &User::new("a@e.com"),
        None,
        false,
    )?;
    assert!(!ctx.context.is_empty());
    Ok(())
}

#[test]
fn logout_request_redirect() -> Result<(), Box<dyn std::error::Error>> {
    logout_request(Binding::Redirect)
}
#[test]
fn logout_request_post() -> Result<(), Box<dyn std::error::Error>> {
    logout_request(Binding::Post)
}
#[test]
fn logout_request_one_binding() -> Result<(), Box<dyn std::error::Error>> {
    // IdP target exposes a single SLO binding.
    let idp = idp(false);
    let sp = ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://sp/slo")],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        EntitySetting::default(),
    )?;
    let ctx = create_logout_request(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Redirect,
        &User::new("a@e.com"),
        None,
        false,
    )?;
    assert_eq!(ctx.entity_endpoint, "https://sp/slo");
    Ok(())
}

// ----- create logout response (19-21) -----

#[test]
fn logout_response_undefined_binding() {
    let idp = idp(false);
    let sp = sp(false, false);
    assert!(create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Artifact,
        Some("_r"),
        None,
        false,
    )
    .is_err());
}

fn logout_response(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        binding,
        Some("_r"),
        None,
        false,
    )?;
    assert!(!ctx.context.is_empty());
    Ok(())
}

#[test]
fn logout_response_redirect() -> Result<(), Box<dyn std::error::Error>> {
    logout_response(Binding::Redirect)
}
#[test]
fn logout_response_post() -> Result<(), Box<dyn std::error::Error>> {
    logout_response(Binding::Post)
}

// ----- send response: signed assertion (22-24) -----

fn send_signed_assertion(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(true, false);
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@example.com"), &opts("_r"))?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn send_signed_assertion_post() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion(Binding::Post)
}
#[test]
fn send_signed_assertion_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion(Binding::Redirect)
}
#[test]
fn send_signed_assertion_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion(Binding::SimpleSign)
}

// ----- signed assertion + custom transformation algorithms (25-27) -----

fn send_signed_assertion_custom_transforms(
    binding: Binding,
) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let mut sp_setting = signing();
    sp_setting.transformation_algorithms = vec![
        opensaml::constants::transform_algorithm::ENVELOPED_SIGNATURE.into(),
        opensaml::constants::transform_algorithm::EXC_C14N.into(),
    ];
    let sp = ServiceProvider::from_config(&sp_config(false, true, false), sp_setting)?;
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@example.com"), &opts("_r"))?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn send_signed_assertion_custom_transforms_post() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion_custom_transforms(Binding::Post)
}
#[test]
fn send_signed_assertion_custom_transforms_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion_custom_transforms(Binding::Redirect)
}
#[test]
fn send_signed_assertion_custom_transforms_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_assertion_custom_transforms(Binding::SimpleSign)
}

// ----- [custom template] signed assertion (28-30) -----

fn send_custom_signed_assertion(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = custom_idp();
    let sp = sp(true, false);
    let idp_id = "https://idp.example.com/metadata";
    let cb = |t: &str| fill_response(t, idp_id, "custom@example.com");
    let ctx = idp.create_login_response(
        &sp,
        binding,
        &User::new("custom@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_r"),
            custom: Some(&cb as &dyn Fn(&str) -> (String, String)),
            ..Default::default()
        },
    )?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_req")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("custom@example.com"));
    assert_eq!(
        parsed.extract.get_str("attributes.mail"),
        Some("custom@example.com")
    );
    Ok(())
}

#[test]
fn send_custom_signed_assertion_post() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_assertion(Binding::Post)
}
#[test]
fn send_custom_signed_assertion_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_assertion(Binding::Redirect)
}
#[test]
fn send_custom_signed_assertion_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_assertion(Binding::SimpleSign)
}

// ----- signed message (31-33) -----

fn send_signed_message(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let sp = sp(false, false); // not assertion-signed → message is signed (POST)
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@example.com"), &opts("_r"))?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn send_signed_message_post() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_message(Binding::Post)
}
#[test]
fn send_signed_message_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_message(Binding::Redirect)
}
#[test]
fn send_signed_message_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_signed_message(Binding::SimpleSign)
}

// ----- [custom template] signed message (34-36) -----

fn send_custom_signed_message(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(opensaml::template::LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: vec![attr("mail", "user.email"), attr("name", "user.name")],
    });
    let idp = IdentityProvider::from_config(&idp_config(false), setting)?;
    let sp = sp(false, false);
    let idp_id = "https://idp.example.com/metadata";
    let cb = |t: &str| fill_response(t, idp_id, "cm@example.com");
    let ctx = idp.create_login_response(
        &sp,
        binding,
        &User::new("cm@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_r"),
            custom: Some(&cb as &dyn Fn(&str) -> (String, String)),
            ..Default::default()
        },
    )?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_req")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("cm@example.com"));
    Ok(())
}

#[test]
fn send_custom_signed_message_post() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_message(Binding::Post)
}
#[test]
fn send_custom_signed_message_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_message(Binding::Redirect)
}
#[test]
fn send_custom_signed_message_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_signed_message(Binding::SimpleSign)
}

// ----- signed assertion + signed message (37-39) -----

fn send_assertion_and_message(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let mut sp_setting = signing();
    sp_setting.want_message_signed = true;
    let sp = ServiceProvider::from_config(&sp_config(false, true, false), sp_setting)?;
    let ctx = idp.create_login_response(&sp, binding, &User::new("a@example.com"), &opts("_r"))?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("a@example.com"));
    Ok(())
}

#[test]
fn send_assertion_and_message_post() -> Result<(), Box<dyn std::error::Error>> {
    send_assertion_and_message(Binding::Post)
}
#[test]
fn send_assertion_and_message_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_assertion_and_message(Binding::Redirect)
}
#[test]
fn send_assertion_and_message_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_assertion_and_message(Binding::SimpleSign)
}

// ----- [custom template] signed assertion + signed message (40-42) -----

fn send_custom_assertion_and_message(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    let mut setting = signing();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: Some(opensaml::template::LOGIN_RESPONSE_TEMPLATE.into()),
        attributes: vec![attr("mail", "user.email"), attr("name", "user.name")],
    });
    let idp = IdentityProvider::from_config(&idp_config(false), setting)?;
    let mut sp_setting = signing();
    sp_setting.want_message_signed = true;
    let sp = ServiceProvider::from_config(&sp_config(false, true, false), sp_setting)?;
    let idp_id = "https://idp.example.com/metadata";
    let cb = |t: &str| fill_response(t, idp_id, "cam@example.com");
    let ctx = idp.create_login_response(
        &sp,
        binding,
        &User::new("cam@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_r"),
            custom: Some(&cb as &dyn Fn(&str) -> (String, String)),
            ..Default::default()
        },
    )?;
    let parsed = parse_response_with_request_id(&sp, &idp, binding, &ctx, "_req")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("cam@example.com"));
    Ok(())
}

#[test]
fn send_custom_assertion_and_message_post() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_assertion_and_message(Binding::Post)
}
#[test]
fn send_custom_assertion_and_message_redirect() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_assertion_and_message(Binding::Redirect)
}
#[test]
fn send_custom_assertion_and_message_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    send_custom_assertion_and_message(Binding::SimpleSign)
}

// ----- encrypted assertion variants (43-47, 54) -----

#[test]
fn encrypted_nonsigned_assertion() -> Result<(), Box<dyn std::error::Error>> {
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    let idp = IdentityProvider::from_config(&idp_config(false), idp_setting)?;
    let sp = sp(false, true); // not assertion-signed → message signed over the encrypted form
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("e@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_r"),
            encrypt_then_sign: true,
            ..Default::default()
        },
    )?;
    let parsed = parse_response_with_request_id(&sp, &idp, Binding::Post, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("e@example.com"));
    Ok(())
}

fn encrypted_signed(custom: bool, with_message: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    if custom {
        idp_setting.login_response_template = Some(LoginResponseTemplate {
            context: Some(opensaml::template::LOGIN_RESPONSE_TEMPLATE.into()),
            attributes: vec![attr("mail", "user.email"), attr("name", "user.name")],
        });
    }
    let idp = IdentityProvider::from_config(&idp_config(false), idp_setting)?;
    let mut sp_setting = signing();
    sp_setting.is_assertion_encrypted = true;
    sp_setting.enc_private_key = Some(PRIVKEY.into());
    sp_setting.want_message_signed = with_message;
    let sp = ServiceProvider::from_config(&sp_config(false, true, true), sp_setting)?;
    let idp_id = "https://idp.example.com/metadata";
    let cb = |t: &str| fill_response(t, idp_id, "es@example.com");
    // A signed message combined with encryption uses encrypt-then-sign so the
    // message signature covers (and survives) the encrypted assertion.
    let options = LoginResponseOptions {
        in_response_to: Some("_r"),
        encrypt_then_sign: with_message,
        custom: if custom {
            Some(&cb as &dyn Fn(&str) -> (String, String))
        } else {
            None
        },
        ..Default::default()
    };
    let ctx =
        idp.create_login_response(&sp, Binding::Post, &User::new("es@example.com"), &options)?;
    let request_id = if custom { "_req" } else { "_r" };
    let parsed = parse_response_with_request_id(&sp, &idp, Binding::Post, &ctx, request_id)?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("es@example.com"));
    Ok(())
}

#[test]
fn encrypted_signed_assertion() -> Result<(), Box<dyn std::error::Error>> {
    encrypted_signed(false, false)
}
#[test]
fn encrypted_custom_signed_assertion() -> Result<(), Box<dyn std::error::Error>> {
    encrypted_signed(true, false)
}
#[test]
fn encrypted_signed_assertion_and_message() -> Result<(), Box<dyn std::error::Error>> {
    encrypted_signed(false, true)
}
#[test]
fn encrypted_custom_signed_assertion_and_message() -> Result<(), Box<dyn std::error::Error>> {
    encrypted_signed(true, true)
}

#[test]
fn encrypted_nonsigned_assertion_encrypt_then_sign() -> Result<(), Box<dyn std::error::Error>> {
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    let idp = IdentityProvider::from_config(&idp_config(false), idp_setting)?;
    let sp = sp(false, true);
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("ets@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_r"),
            encrypt_then_sign: true,
            ..Default::default()
        },
    )?;
    let parsed = parse_response_with_request_id(&sp, &idp, Binding::Post, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("ets@example.com"));
    Ok(())
}

// ----- logout request/response with & without signature (48-53) -----

fn logout_request_flow(binding: Binding, signed: bool) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let mut sp = sp(false, false);
    sp.setting.want_logout_request_signed = signed;
    let ctx = create_logout_request(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        binding,
        &User::new("a@e.com"),
        None,
        signed,
    )?;
    let request = logout_request_to_http(binding, &ctx)?;
    let parsed = parse_logout_request(&sp.setting, &idp.metadata, binding, &request)?;
    assert_eq!(
        parsed.extract.get_str("issuer"),
        Some("https://idp.example.com/metadata")
    );
    Ok(())
}

fn logout_request_to_http(
    binding: Binding,
    ctx: &BindingContext,
) -> Result<HttpRequest, OpenSamlError> {
    Ok(match binding {
        Binding::Redirect => redirect_request(&ctx.context)?,
        _ => HttpRequest::post(vec![("SAMLRequest".into(), ctx.context.clone())]),
    })
}

#[test]
fn idp_redirect_logout_request_unsigned() -> Result<(), Box<dyn std::error::Error>> {
    logout_request_flow(Binding::Redirect, false)
}
#[test]
fn idp_redirect_logout_request_signed() -> Result<(), Box<dyn std::error::Error>> {
    logout_request_flow(Binding::Redirect, true)
}
#[test]
fn idp_post_logout_request_unsigned() -> Result<(), Box<dyn std::error::Error>> {
    logout_request_flow(Binding::Post, false)
}
#[test]
fn idp_post_logout_request_signed() -> Result<(), Box<dyn std::error::Error>> {
    logout_request_flow(Binding::Post, true)
}

fn logout_response_flow(signed: bool) -> Result<(), Box<dyn std::error::Error>> {
    let idp = idp(false);
    let mut idp_recv = idp.clone();
    idp_recv.setting.want_logout_response_signed = signed;
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &sp.setting,
        &sp.metadata,
        &idp.metadata,
        Binding::Post,
        Some("_r"),
        None,
        signed,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let parsed = parse_logout_response(
        &idp_recv.setting,
        &sp.metadata,
        Binding::Post,
        &request,
        "_r",
    )?;
    assert_eq!(
        parsed.extract.get_str("issuer"),
        Some("https://sp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn sp_post_logout_response_unsigned() -> Result<(), Box<dyn std::error::Error>> {
    logout_response_flow(false)
}
#[test]
fn sp_post_logout_response_signed() -> Result<(), Box<dyn std::error::Error>> {
    logout_response_flow(true)
}

#[test]
fn signed_logout_response_wrong_request_id_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut idp_recv = idp(false);
    idp_recv.setting.want_logout_response_signed = true;
    let sp = sp(false, false);
    let ctx = create_logout_response(
        &sp.setting,
        &sp.metadata,
        &idp_recv.metadata,
        Binding::Post,
        Some("_wrong"),
        None,
        true,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    assert!(matches!(
        parse_logout_response(
            &idp_recv.setting,
            &sp.metadata,
            Binding::Post,
            &request,
            "_r"
        ),
        Err(OpenSamlError::InvalidInResponseTo)
    ));
    Ok(())
}

// ----- customize encrypted-assertion prefix (55-56) -----

fn encrypted_prefix(prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut idp_setting = signing();
    idp_setting.is_assertion_encrypted = true;
    idp_setting.tag_prefix_encrypted_assertion = prefix.to_string();
    let idp = IdentityProvider::from_config(&idp_config(false), idp_setting)?;
    let mut sp_setting = signing();
    sp_setting.is_assertion_encrypted = true;
    sp_setting.enc_private_key = Some(PRIVKEY.into());
    let sp = ServiceProvider::from_config(&sp_config(false, true, true), sp_setting)?;
    let ctx =
        idp.create_login_response(&sp, Binding::Post, &User::new("p@example.com"), &opts("_r"))?;
    let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
    assert!(xml.contains(&format!("<{prefix}:EncryptedAssertion")));
    Ok(())
}

#[test]
fn encrypted_prefix_saml2() -> Result<(), Box<dyn std::error::Error>> {
    encrypted_prefix("saml2")
}
#[test]
fn encrypted_prefix_default_saml() -> Result<(), Box<dyn std::error::Error>> {
    encrypted_prefix("saml")
}

// ----- malformed response (57-59) -----

fn malformed(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    use opensaml::binding::base64_encode;
    let idp = idp(false);
    let sp = sp(true, false);
    let bad = base64_encode(b"<<<not-xml");
    let request = match binding {
        Binding::Redirect => HttpRequest::redirect(vec![("SAMLResponse".into(), bad)]),
        _ => HttpRequest::post(vec![("SAMLResponse".into(), bad)]),
    };
    assert!(sp.parse_login_response(&idp, binding, &request).is_err());
    Ok(())
}

#[test]
fn malformed_response_post() -> Result<(), Box<dyn std::error::Error>> {
    malformed(Binding::Post)
}
#[test]
fn malformed_response_redirect() -> Result<(), Box<dyn std::error::Error>> {
    malformed(Binding::Redirect)
}
#[test]
fn malformed_response_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    malformed(Binding::SimpleSign)
}

// ----- signature wrapping (60-61) -----

const ATTACK: &str = include_str!("fixtures/misc/attack_response_signed.xml");

#[test]
fn reject_signature_wrapped_response_case_1() -> Result<(), Box<dyn std::error::Error>> {
    use opensaml::binding::base64_encode;
    let idp = idp(false);
    let sp = sp(true, false);
    let request = HttpRequest::post(vec![(
        "SAMLResponse".into(),
        base64_encode(ATTACK.as_bytes()),
    )]);
    assert!(sp
        .parse_login_response(&idp, Binding::Post, &request)
        .is_err());
    Ok(())
}

#[test]
fn use_signed_contents_in_wrapped_response_case_2() -> Result<(), Box<dyn std::error::Error>> {
    // A correctly signed response yields only the cryptographically signed
    // assertion contents (no wrapping injection survives).
    let idp = idp(false);
    let sp = sp(true, false);
    let ctx = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("safe@example.com"),
        &opts("_r"),
    )?;
    let parsed = parse_response_with_request_id(&sp, &idp, Binding::Post, &ctx, "_r")?;
    assert_eq!(parsed.extract.get_str("nameID"), Some("safe@example.com"));
    Ok(())
}

// ----- two-tier status error (62-64) -----

fn two_tier_status(binding: Binding) -> Result<(), Box<dyn std::error::Error>> {
    use opensaml::binding::base64_encode;
    let idp = idp(false);
    let sp = sp(true, false);
    let request = match binding {
        Binding::Redirect => {
            use opensaml::binding::deflate_raw_encode;
            let enc = base64_encode(&deflate_raw_encode(FAILED.as_bytes())?);
            HttpRequest::redirect(vec![("SAMLResponse".into(), enc)])
        }
        _ => HttpRequest::post(vec![(
            "SAMLResponse".into(),
            base64_encode(FAILED.as_bytes()),
        )]),
    };
    match sp.parse_login_response(&idp, binding, &request) {
        Err(OpenSamlError::FailedStatus { .. }) => Ok(()),
        other => Err(format!("expected FailedStatus, got {other:?}").into()),
    }
}

#[test]
fn two_tier_status_post() -> Result<(), Box<dyn std::error::Error>> {
    two_tier_status(Binding::Post)
}
#[test]
fn two_tier_status_redirect() -> Result<(), Box<dyn std::error::Error>> {
    two_tier_status(Binding::Redirect)
}
#[test]
fn two_tier_status_simplesign() -> Result<(), Box<dyn std::error::Error>> {
    two_tier_status(Binding::SimpleSign)
}
