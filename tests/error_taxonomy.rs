#![cfg(feature = "crypto-bergshamra")]

use saml_rs::constants::signature_algorithm::RSA_SHA256;
use saml_rs::constants::{status_code, Binding, ParserType};
use saml_rs::entity::{iso8601_offset, EntitySetting, User};
use saml_rs::flow::HttpRequest;
use saml_rs::idp::LoginResponseOptions;
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::template::replace_tags_by_value;
use saml_rs::validator::check_status;
use saml_rs::{IdentityProvider, SamlError, ServiceProvider};

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");
const FAILED: &str = include_str!("fixtures/failed_response.xml");

#[derive(Debug, Clone)]
struct ResponseShape {
    issuer: String,
    destination: String,
    audience: String,
    response_in_response_to: String,
    subject_in_response_to: String,
}

impl Default for ResponseShape {
    fn default() -> Self {
        Self {
            issuer: "https://idp.example.com/metadata".into(),
            destination: "https://sp.example.com/acs".into(),
            audience: "https://sp.example.com/metadata".into(),
            response_in_response_to: "_request123".into(),
            subject_in_response_to: "_request123".into(),
        }
    }
}

fn signing() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(PRIVKEY.into());
    setting.signing_cert = Some(CERT.into());
    setting.request_signature_algorithm = RSA_SHA256.into();
    setting
}

fn idp() -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: vec![CERT.into()],
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            ..Default::default()
        },
        signing(),
    )
}

fn sp() -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            want_assertions_signed: true,
            signing_certs: vec![CERT.into()],
            assertion_consumer_service: vec![Endpoint::new(
                Binding::Post,
                "https://sp.example.com/acs",
            )],
            ..Default::default()
        },
        signing(),
    )
}

fn signed_response(shape: &ResponseShape) -> Result<String, SamlError> {
    let idp = idp()?;
    let sp = sp()?;
    let custom = |template: &str| {
        let id = "_response_taxonomy".to_string();
        let now = iso8601_offset(-60);
        let later = iso8601_offset(300);
        let xml = replace_tags_by_value(
            template,
            &[
                ("ID", id.clone()),
                ("AssertionID", "_assertion_taxonomy".into()),
                ("Destination", shape.destination.clone()),
                ("SubjectRecipient", "https://sp.example.com/acs".into()),
                (
                    "AssertionConsumerServiceURL",
                    "https://sp.example.com/acs".into(),
                ),
                ("Audience", shape.audience.clone()),
                ("Issuer", shape.issuer.clone()),
                ("IssueInstant", now.clone()),
                ("StatusCode", status_code::SUCCESS.into()),
                ("ConditionsNotBefore", now),
                ("ConditionsNotOnOrAfter", later.clone()),
                ("SubjectConfirmationDataNotOnOrAfter", later),
                (
                    "NameIDFormat",
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into(),
                ),
                ("NameID", "user@example.com".into()),
                ("InResponseTo", shape.response_in_response_to.clone()),
                ("AuthnStatement", String::new()),
            ],
        )
        .replace(
            "InResponseTo=\"_request123\"/>",
            &format!("InResponseTo=\"{}\"/>", shape.subject_in_response_to),
        );
        (id, xml)
    };
    Ok(idp
        .create_login_response(
            &sp,
            Binding::Post,
            &User::new("user@example.com"),
            &LoginResponseOptions {
                in_response_to: Some(shape.response_in_response_to.as_str()),
                custom: Some(&custom),
                ..Default::default()
            },
        )?
        .context)
}

fn parse_response(response: String, request_id: &str) -> Result<(), SamlError> {
    let sp = sp()?;
    let idp = idp()?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), response)]);
    sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, request_id)?;
    Ok(())
}

#[test]
fn error_taxonomy_bad_issuer_returns_issuer_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(&ResponseShape {
        issuer: "https://attacker.example.com/metadata".into(),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, "https://idp.example.com/metadata");
            assert_eq!(
                actual.as_deref(),
                Some("https://attacker.example.com/metadata")
            );
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_bad_destination_returns_destination_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(&ResponseShape {
        destination: "https://evil.example.com/acs".into(),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, "https://sp.example.com/acs");
            assert_eq!(actual.as_deref(), Some("https://evil.example.com/acs"));
            Ok(())
        }
        other => Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_bad_audience_returns_audience_mismatch() -> Result<(), Box<dyn std::error::Error>>
{
    let response = signed_response(&ResponseShape {
        audience: "https://evil.example.com/metadata".into(),
        ..Default::default()
    })?;

    match parse_response(response, "_request123") {
        Err(SamlError::AudienceMismatch { expected }) => {
            assert_eq!(expected, "https://sp.example.com/metadata");
            Ok(())
        }
        other => Err(format!("expected AudienceMismatch, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_bad_in_response_to_returns_in_response_to_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = signed_response(&ResponseShape::default())?;

    match parse_response(response, "_different") {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some("_different"));
            assert_eq!(actual.as_deref(), Some("_request123"));
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn error_taxonomy_non_success_status_returns_status_not_success(
) -> Result<(), Box<dyn std::error::Error>> {
    match check_status(FAILED, ParserType::SamlResponse) {
        Err(SamlError::StatusNotSuccess { top, second }) => {
            assert_eq!(top, status_code::REQUESTER);
            assert_eq!(second.as_deref(), Some(status_code::INVALID_NAME_ID_POLICY));
            Ok(())
        }
        other => Err(format!("expected StatusNotSuccess, got {other:?}").into()),
    }
}
