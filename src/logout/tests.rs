use super::*;
use crate::binding::{base64_decode, deflate_raw_decode};
use crate::constants::Binding;
use crate::entity::{EntitySetting, User};
use crate::error::SamlError;
use crate::flow::HttpRequest;
use crate::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use crate::{IdentityProvider, ServiceProvider};
use url::Url;

fn sp() -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            single_logout_service: vec![
                Endpoint::new(Binding::Redirect, "https://sp/slo"),
                Endpoint::new(Binding::Post, "https://sp/slo"),
            ],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn idp() -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![
                Endpoint::new(Binding::Redirect, "https://idp/slo"),
                Endpoint::new(Binding::Post, "https://idp/slo"),
            ],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn unsigned_setting() -> EntitySetting {
    EntitySetting {
        want_logout_request_signed: false,
        ..Default::default()
    }
}

fn unsigned_sp(entity_id: &str) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: entity_id.into(),
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        unsigned_setting(),
    )
}

#[test]
fn logout_request_redirect_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, mut idp) = (sp()?, idp()?);
    idp.setting.want_logout_request_signed = false;
    let ctx = create_logout_request(
        &sp.setting,
        &sp.metadata,
        &idp.metadata,
        Binding::Redirect,
        &User::new("user@example.com"),
        None,
        false,
    )?;
    assert_eq!(ctx.entity_endpoint, "https://idp/slo");
    let url = Url::parse(&ctx.context)?;
    let (_, value) = url
        .query_pairs()
        .find(|(k, _)| k == "SAMLRequest")
        .ok_or("missing SAMLRequest")?;
    let xml = String::from_utf8(deflate_raw_decode(&base64_decode(&value)?)?)?;
    assert!(xml.contains("<samlp:LogoutRequest"));
    assert!(xml.contains("user@example.com"));

    // IdP parses it (unsigned)
    let request = HttpRequest::redirect(vec![("SAMLRequest".into(), value.into_owned())]);
    let result = parse_logout_request(&idp.setting, &sp.metadata, Binding::Redirect, &request)?;
    assert_eq!(
        result.extract.get_str("issuer"),
        Some("https://sp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn logout_requests_require_signatures_by_default() {
    assert!(EntitySetting::default().want_logout_request_signed);
}

#[test]
fn unsigned_logout_request_rejects_unexpected_issuer_when_explicitly_allowed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut idp = idp()?;
    idp.setting.want_logout_request_signed = false;
    let expected_sp = unsigned_sp("https://expected-sp.example.com/metadata")?;
    let attacker_sp = unsigned_sp("https://attacker-sp.example.com/metadata")?;
    let ctx = create_logout_request(
        &attacker_sp.setting,
        &attacker_sp.metadata,
        &idp.metadata,
        Binding::Post,
        &User::new("victim@example.com"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

    let result = parse_logout_request(&idp.setting, &expected_sp.metadata, Binding::Post, &request);

    assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
    Ok(())
}

#[cfg(feature = "crypto-bergshamra")]
mod signed_tests {
    use super::*;
    use crate::constants::signature_algorithm::RSA_SHA256;

    const PRIVKEY: &str = include_str!("../../tests/fixtures/key/sp_privkey.pem");
    const CERT: &str = include_str!("../../tests/fixtures/key/sp_signing_cert.cer");

    fn signing_setting() -> EntitySetting {
        EntitySetting {
            private_key: Some(PRIVKEY.into()),
            signing_cert: Some(CERT.into()),
            request_signature_algorithm: RSA_SHA256.into(),
            ..Default::default()
        }
    }

    fn signed_sp(entity_id: &str) -> Result<ServiceProvider, SamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                entity_id: entity_id.into(),
                signing_certs: vec![CERT.into()],
                single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
                assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
                ..Default::default()
            },
            signing_setting(),
        )
    }

    #[test]
    fn signed_logout_request_rejects_unexpected_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let idp = idp()?;
        let expected_sp = signed_sp("https://expected-sp.example.com/metadata")?;
        let attacker_sp = signed_sp("https://attacker-sp.example.com/metadata")?;
        let ctx = create_logout_request(
            &attacker_sp.setting,
            &attacker_sp.metadata,
            &idp.metadata,
            Binding::Post,
            &User::new("victim@example.com"),
            None,
            true,
        )?;
        let request = HttpRequest::post(vec![("SAMLRequest".into(), ctx.context)]);

        let result =
            parse_logout_request(&idp.setting, &expected_sp.metadata, Binding::Post, &request);

        assert!(matches!(result, Err(SamlError::IssuerMismatch { .. })));
        Ok(())
    }
}

#[test]
fn logout_response_post_round_trips() -> Result<(), Box<dyn std::error::Error>> {
    let (mut sp, idp) = (sp()?, idp()?);
    sp.setting.want_logout_response_signed = false;
    // IdP responds to SP's logout; target is the SP (SLO via redirect endpoint)
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
    assert!(xml.contains("<samlp:LogoutResponse"));

    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);
    let result =
        parse_logout_response(&sp.setting, &idp.metadata, Binding::Post, &request, "_req1")?;
    assert_eq!(
        result.extract.get_str("issuer"),
        Some("https://idp.example.com/metadata")
    );
    Ok(())
}

#[test]
fn logout_response_rejects_empty_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let (mut sp, idp) = (sp()?, idp()?);
    sp.setting.want_logout_response_signed = false;
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    assert!(matches!(
        parse_logout_response(&sp.setting, &idp.metadata, Binding::Post, &request, ""),
        Err(SamlError::InvalidInResponseTo)
    ));
    Ok(())
}

#[test]
fn logout_response_rejects_wrong_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let (mut sp, idp) = (sp()?, idp()?);
    sp.setting.want_logout_response_signed = false;
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    assert!(matches!(
        parse_logout_response(
            &sp.setting,
            &idp.metadata,
            Binding::Post,
            &request,
            "_other"
        ),
        Err(SamlError::InResponseToMismatch { .. })
    ));
    Ok(())
}

#[test]
fn default_logout_response_parsing_requires_signature() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = (sp()?, idp()?);
    let ctx = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        Binding::Post,
        Some("_req1"),
        None,
        false,
    )?;
    let request = HttpRequest::post(vec![("SAMLResponse".into(), ctx.context)]);

    let result =
        parse_logout_response(&sp.setting, &idp.metadata, Binding::Post, &request, "_req1");

    #[cfg(feature = "crypto-bergshamra")]
    assert!(matches!(result, Err(SamlError::SignatureMissing)));

    #[cfg(not(feature = "crypto-bergshamra"))]
    assert!(matches!(result, Err(SamlError::Unsupported(_))));

    Ok(())
}
