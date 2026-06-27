use opensaml::binding::{
    base64_encode, deflate_raw_decode, deflate_raw_encode, MAX_DEFLATE_RAW_DECODE_BYTES,
};
use opensaml::constants::{Binding, ParserType};
use opensaml::entity::EntitySetting;
use opensaml::flow::{flow, FlowOptions, HttpRequest};
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::xml::XmlLimits;
use opensaml::{IdentityProvider, OpenSamlError, ServiceProvider};
use url::Url;

const LIMIT_ERROR: &str = "ERR_DEFLATE_OUTPUT_LIMIT_EXCEEDED";
const BASE64_LIMIT_ERROR: &str = "ERR_BASE64_OUTPUT_LIMIT_EXCEEDED";
const XML_LIMIT_ERROR: &str = "ERR_XML_LIMIT_EXCEEDED";

fn oversized_deflate_payload() -> Result<Vec<u8>, OpenSamlError> {
    let oversized = vec![b'A'; MAX_DEFLATE_RAW_DECODE_BYTES + 1];
    deflate_raw_encode(&oversized)
}

fn redirect_request(url: &str) -> Result<HttpRequest, OpenSamlError> {
    let parsed = Url::parse(url).map_err(|e| OpenSamlError::Invalid(e.to_string()))?;
    Ok(HttpRequest::redirect(
        parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
    ))
}

fn unsigned_sp() -> Result<ServiceProvider, OpenSamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn unsigned_idp(setting: EntitySetting) -> Result<IdentityProvider, OpenSamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(Binding::Redirect, "https://idp/sso")],
            ..Default::default()
        },
        setting,
    )
}

#[test]
fn deflate_raw_decode_rejects_oversized_output() -> Result<(), Box<dyn std::error::Error>> {
    let compressed = oversized_deflate_payload()?;
    let err = deflate_raw_decode(&compressed)
        .err()
        .ok_or("inflate unexpectedly succeeded")?;

    assert!(matches!(
        err,
        OpenSamlError::Invalid(message) if message == LIMIT_ERROR
    ));
    Ok(())
}

#[test]
fn flow_options_custom_redirect_inflate_limit_is_enforced() -> Result<(), Box<dyn std::error::Error>>
{
    let compressed = deflate_raw_encode(b"not xml but larger than the custom cap")?;
    let request = HttpRequest::redirect(vec![(
        "SAMLRequest".to_string(),
        base64_encode(&compressed),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Redirect);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.redirect_inflate_max_bytes = 8;

    let err = flow(&opts, &request)
        .err()
        .ok_or("redirect flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        OpenSamlError::Invalid(message) if message == LIMIT_ERROR
    ));
    Ok(())
}

#[test]
fn entity_setting_custom_redirect_inflate_limit_is_enforced(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = unsigned_sp()?;
    let mut setting = EntitySetting::default();
    setting.redirect_inflate_max_bytes = 8;
    let idp = unsigned_idp(setting)?;
    let ctx = sp.create_login_request(&idp, Binding::Redirect, None)?;
    let request = redirect_request(&ctx.context)?;

    let err = idp
        .parse_login_request(&sp, Binding::Redirect, &request)
        .err()
        .ok_or("redirect parse unexpectedly succeeded")?;

    assert!(matches!(
        err,
        OpenSamlError::Invalid(message) if message == LIMIT_ERROR
    ));
    Ok(())
}

#[test]
fn redirect_flow_rejects_oversized_inflated_message() -> Result<(), Box<dyn std::error::Error>> {
    let compressed = oversized_deflate_payload()?;
    let request = HttpRequest::redirect(vec![(
        "SAMLRequest".to_string(),
        base64_encode(&compressed),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Redirect);
    opts.parser_type = Some(ParserType::SamlRequest);

    let err = flow(&opts, &request)
        .err()
        .ok_or("redirect flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        OpenSamlError::Invalid(message) if message == LIMIT_ERROR
    ));
    Ok(())
}

#[test]
fn post_flow_rejects_decoded_xml_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    let request = HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        base64_encode(b"<AuthnRequest/>"),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Post);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.xml_limits = XmlLimits {
        max_bytes: 8,
        ..Default::default()
    };

    let err = flow(&opts, &request)
        .err()
        .ok_or("POST flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        OpenSamlError::Invalid(message) if message == BASE64_LIMIT_ERROR
    ));
    Ok(())
}

#[test]
fn simplesign_flow_rejects_decoded_xml_byte_limit() -> Result<(), Box<dyn std::error::Error>> {
    let request = HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        base64_encode(b"<AuthnRequest/>"),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::SimpleSign);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.xml_limits = XmlLimits {
        max_bytes: 8,
        ..Default::default()
    };

    let err = flow(&opts, &request)
        .err()
        .ok_or("SimpleSign flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        OpenSamlError::Invalid(message) if message == BASE64_LIMIT_ERROR
    ));
    Ok(())
}

#[test]
fn post_flow_rejects_dom_node_budget_before_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!("<AuthnRequest>{}</AuthnRequest>", "<Extra/>".repeat(4));
    let request = HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        base64_encode(xml.as_bytes()),
    )]);
    let mut opts = FlowOptions::default();
    opts.binding = Some(Binding::Post);
    opts.parser_type = Some(ParserType::SamlRequest);
    opts.xml_limits = XmlLimits {
        max_nodes: 3,
        ..Default::default()
    };

    let err = flow(&opts, &request)
        .err()
        .ok_or("POST flow unexpectedly succeeded")?;

    assert!(matches!(
        err,
        OpenSamlError::Invalid(message) if message.contains(XML_LIMIT_ERROR)
    ));
    Ok(())
}
