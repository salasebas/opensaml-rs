use opensaml::binding::{base64_decode, deflate_raw_decode};
use opensaml::constants::Binding;
use opensaml::entity::{EntitySetting, User};
use opensaml::logout::{create_logout_request, create_logout_response};
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::{IdentityProvider, OpenSamlError, ServiceProvider};

fn idp() -> Result<IdentityProvider, OpenSamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
            single_logout_service: vec![
                Endpoint::new(Binding::Post, "https://idp/slo"),
                Endpoint::new(Binding::Redirect, "https://idp/slo"),
                Endpoint::new(Binding::SimpleSign, "https://idp/slo"),
            ],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn sp() -> Result<ServiceProvider, OpenSamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp/slo")],
            assertion_consumer_service: vec![Endpoint::new(Binding::Post, "https://sp/acs")],
            ..Default::default()
        },
        EntitySetting::default(),
    )
}

fn user(session_index: Option<&str>) -> User {
    let mut user = User::new("user@example.com");
    user.session_index = session_index.map(str::to_string);
    user
}

fn logout_request_xml(
    binding: Binding,
    session_index: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let sp = sp()?;
    let idp = idp()?;
    let user = user(session_index);
    let context = create_logout_request(
        &sp.setting,
        &sp.metadata,
        &idp.metadata,
        binding,
        &user,
        None,
        false,
    )?;
    decode_logout_request(binding, &context.context)
}

fn logout_response_xml(
    binding: Binding,
    in_response_to: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let idp = idp()?;
    let sp = sp()?;
    let context = create_logout_response(
        &idp.setting,
        &idp.metadata,
        &sp.metadata,
        binding,
        in_response_to,
        None,
        false,
    )?;
    decode_logout_response(binding, &context.context)
}

fn decode_logout_request(
    binding: Binding,
    context: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    decode_binding_context(binding, context, "SAMLRequest")
}

fn decode_logout_response(
    binding: Binding,
    context: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    decode_binding_context(binding, context, "SAMLResponse")
}

fn decode_binding_context(
    binding: Binding,
    context: &str,
    query_param: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match binding {
        Binding::Post | Binding::SimpleSign => Ok(String::from_utf8(base64_decode(context)?)?),
        Binding::Redirect => {
            let url = url::Url::parse(context)?;
            let value = url
                .query_pairs()
                .find_map(|(key, value)| (key == query_param).then_some(value.into_owned()))
                .ok_or("missing SAML message")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                &value,
            )?)?)?)
        }
        Binding::Artifact => Err("artifact binding does not render logout messages here".into()),
    }
}

#[test]
fn logout_request_post_includes_session_index_when_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = logout_request_xml(Binding::Post, Some("_session-123"))?;
    assert!(xml.contains("<samlp:SessionIndex>_session-123</samlp:SessionIndex>"));
    Ok(())
}

#[test]
fn logout_request_redirect_includes_session_index_when_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = logout_request_xml(Binding::Redirect, Some("_session-123"))?;
    assert!(xml.contains("<samlp:SessionIndex>_session-123</samlp:SessionIndex>"));
    Ok(())
}

#[test]
fn logout_request_simplesign_includes_session_index_when_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = logout_request_xml(Binding::SimpleSign, Some("_session-123"))?;
    assert!(xml.contains("<samlp:SessionIndex>_session-123</samlp:SessionIndex>"));
    Ok(())
}

#[test]
fn logout_request_omits_session_index_when_absent() -> Result<(), Box<dyn std::error::Error>> {
    let xml = logout_request_xml(Binding::Post, None)?;
    assert!(!xml.contains("<samlp:SessionIndex>"));
    Ok(())
}

#[test]
fn logout_response_post_omits_in_response_to_when_absent() -> Result<(), Box<dyn std::error::Error>>
{
    let xml = logout_response_xml(Binding::Post, None)?;
    assert!(!xml.contains("InResponseTo="));
    Ok(())
}
