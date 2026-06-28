use opensaml::binding::{base64_decode, deflate_raw_decode};
use opensaml::constants::Binding;
use opensaml::entity::{BindingContext, EntitySetting};
use opensaml::flow::HttpRequest;
use opensaml::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use opensaml::sp::LoginRequestOptions;
use opensaml::{IdentityProvider, OpenSamlError, ServiceProvider};
use url::Url;

fn idp_config(want_authn_requests_signed: bool) -> IdpMetadataConfig {
    IdpMetadataConfig {
        entity_id: "https://idp.example.com/metadata".into(),
        want_authn_requests_signed,
        single_sign_on_service: vec![
            Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
            Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
            Endpoint::new(Binding::SimpleSign, "https://idp.example.com/sso"),
        ],
        ..Default::default()
    }
}

fn sp_config(authn_requests_signed: bool) -> SpMetadataConfig {
    SpMetadataConfig {
        entity_id: "https://sp.example.com/metadata".into(),
        authn_requests_signed,
        assertion_consumer_service: vec![
            Endpoint::new(Binding::Post, "https://sp.example.com/acs"),
            Endpoint::new(Binding::Redirect, "https://sp.example.com/redirect-acs"),
            Endpoint::new(Binding::SimpleSign, "https://sp.example.com/simplesign-acs"),
        ],
        ..Default::default()
    }
}

fn unsigned_idp() -> Result<IdentityProvider, OpenSamlError> {
    IdentityProvider::from_config(&idp_config(false), EntitySetting::default())
}

fn unsigned_sp_with_setting(setting: EntitySetting) -> Result<ServiceProvider, OpenSamlError> {
    ServiceProvider::from_config(&sp_config(false), setting)
}

fn unsigned_sp() -> Result<ServiceProvider, OpenSamlError> {
    unsigned_sp_with_setting(EntitySetting::default())
}

fn request_xml(ctx: &BindingContext) -> Result<String, Box<dyn std::error::Error>> {
    match ctx.binding {
        Binding::Redirect => {
            let url = Url::parse(&ctx.context)?;
            let (_, value) = url
                .query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                &value,
            )?)?)?)
        }
        Binding::Post | Binding::SimpleSign => Ok(String::from_utf8(base64_decode(&ctx.context)?)?),
        Binding::Artifact => Err("artifact binding is unsupported".into()),
    }
}

fn redirect_relay_state(url: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    Ok(Url::parse(url)?
        .query_pairs()
        .find_map(|(key, value)| (key == "RelayState").then_some(value.into_owned())))
}

#[test]
fn legacy_create_login_request_callback_still_works() -> Result<(), Box<dyn std::error::Error>> {
    let replace = |_template: &str| {
        (
            "_custom".to_string(),
            "<samlp:AuthnRequest ID=\"_custom\"/>".to_string(),
        )
    };
    let ctx = unsigned_sp()?.create_login_request(
        &unsigned_idp()?,
        Binding::Post,
        Some(&replace as &dyn Fn(&str) -> (String, String)),
    )?;

    assert_eq!(ctx.id, "_custom");
    assert!(request_xml(&ctx)?.contains("ID=\"_custom\""));
    Ok(())
}

#[test]
fn redirect_per_request_relay_state_appears_in_url() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = unsigned_sp()?.create_login_request_with_options(
        &unsigned_idp()?,
        Binding::Redirect,
        &LoginRequestOptions {
            relay_state: Some("request state"),
            ..Default::default()
        },
    )?;

    assert_eq!(ctx.relay_state.as_deref(), Some("request state"));
    assert_eq!(
        redirect_relay_state(&ctx.context)?.as_deref(),
        Some("request state")
    );
    Ok(())
}

#[test]
fn post_and_simplesign_per_request_relay_state_appear_in_context(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Post, Binding::SimpleSign] {
        let ctx = unsigned_sp()?.create_login_request_with_options(
            &unsigned_idp()?,
            binding,
            &LoginRequestOptions {
                relay_state: Some("request state"),
                ..Default::default()
            },
        )?;

        assert_eq!(ctx.relay_state.as_deref(), Some("request state"));
    }
    Ok(())
}

#[test]
fn per_request_relay_state_overrides_entity_state_without_leaking(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut setting = EntitySetting::default();
    setting.relay_state = "entity state".into();
    let sp = unsigned_sp_with_setting(setting)?;
    let idp = unsigned_idp()?;

    let first = sp.create_login_request_with_options(
        &idp,
        Binding::Redirect,
        &LoginRequestOptions {
            relay_state: Some("request state"),
            ..Default::default()
        },
    )?;
    let second = sp.create_login_request_with_options(
        &idp,
        Binding::Redirect,
        &LoginRequestOptions::default(),
    )?;
    let third = sp.create_login_request_with_options(
        &idp,
        Binding::Redirect,
        &LoginRequestOptions {
            relay_state: Some(""),
            ..Default::default()
        },
    )?;

    assert_eq!(first.relay_state.as_deref(), Some("request state"));
    assert_eq!(
        redirect_relay_state(&first.context)?.as_deref(),
        Some("request state")
    );
    assert_eq!(second.relay_state.as_deref(), Some("entity state"));
    assert_eq!(
        redirect_relay_state(&second.context)?.as_deref(),
        Some("entity state")
    );
    assert_eq!(third.relay_state.as_deref(), Some(""));
    assert_eq!(redirect_relay_state(&third.context)?.as_deref(), Some(""));
    Ok(())
}

#[test]
fn force_authn_renders_true_and_false_for_all_login_request_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        for force_authn in [true, false] {
            let ctx = unsigned_sp()?.create_login_request_with_options(
                &unsigned_idp()?,
                binding,
                &LoginRequestOptions {
                    force_authn: Some(force_authn),
                    ..Default::default()
                },
            )?;

            assert!(request_xml(&ctx)?.contains(&format!("ForceAuthn=\"{force_authn}\"")));
        }
    }
    Ok(())
}

#[test]
fn force_authn_is_omitted_by_default() -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        let ctx = unsigned_sp()?.create_login_request_with_options(
            &unsigned_idp()?,
            binding,
            &LoginRequestOptions::default(),
        )?;

        assert!(!request_xml(&ctx)?.contains("ForceAuthn="));
    }
    Ok(())
}

#[test]
fn acs_index_renders_and_omits_url_and_protocol_binding_for_all_login_request_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        for index in [0, 7] {
            let ctx = unsigned_sp()?.create_login_request_with_options(
                &unsigned_idp()?,
                binding,
                &LoginRequestOptions {
                    assertion_consumer_service_index: Some(index),
                    ..Default::default()
                },
            )?;
            let xml = request_xml(&ctx)?;

            assert!(xml.contains(&format!("AssertionConsumerServiceIndex=\"{index}\"")));
            assert!(!xml.contains("AssertionConsumerServiceURL="));
            assert!(!xml.contains("ProtocolBinding="));
        }
    }
    Ok(())
}

#[test]
fn no_options_rendering_keeps_acs_url_and_protocol_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in [Binding::Redirect, Binding::Post, Binding::SimpleSign] {
        let ctx = unsigned_sp()?.create_login_request_with_options(
            &unsigned_idp()?,
            binding,
            &LoginRequestOptions::default(),
        )?;
        let xml = request_xml(&ctx)?;

        assert!(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.com/acs\""));
        assert!(xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
        assert!(!xml.contains("AssertionConsumerServiceIndex="));
    }
    Ok(())
}

#[cfg(feature = "crypto-bergshamra")]
mod signed {
    use super::*;
    use opensaml::constants::signature_algorithm::RSA_SHA256;

    const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
    const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

    fn signing_setting() -> EntitySetting {
        let mut setting = EntitySetting::default();
        setting.private_key = Some(PRIVKEY.into());
        setting.signing_cert = Some(CERT.into());
        setting.request_signature_algorithm = RSA_SHA256.into();
        setting
    }

    fn signed_idp() -> Result<IdentityProvider, OpenSamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                signing_certs: vec![CERT.into()],
                ..idp_config(true)
            },
            signing_setting(),
        )
    }

    fn signed_sp() -> Result<ServiceProvider, OpenSamlError> {
        ServiceProvider::from_config(
            &SpMetadataConfig {
                signing_certs: vec![CERT.into()],
                ..sp_config(true)
            },
            signing_setting(),
        )
    }

    fn redirect_request(url: &str) -> Result<HttpRequest, Box<dyn std::error::Error>> {
        let parsed = Url::parse(url)?;
        let raw_query = parsed.query().unwrap_or_default();
        let octet = raw_query
            .split_once("&Signature=")
            .map(|(signed, _)| signed)
            .unwrap_or(raw_query)
            .to_string();
        let query = parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        Ok(HttpRequest {
            query,
            octet_string: Some(octet),
            ..Default::default()
        })
    }

    fn simplesign_request(ctx: &BindingContext) -> Result<HttpRequest, Box<dyn std::error::Error>> {
        let xml = String::from_utf8(base64_decode(&ctx.context)?)?;
        let relay_state = ctx.relay_state.clone().ok_or("missing RelayState")?;
        let sig_alg = ctx.sig_alg.clone().ok_or("missing SigAlg")?;
        let signature = ctx.signature.clone().ok_or("missing Signature")?;
        let octet = format!("SAMLRequest={xml}&RelayState={relay_state}&SigAlg={sig_alg}");
        Ok(HttpRequest {
            body: vec![
                ("SAMLRequest".into(), ctx.context.clone()),
                ("RelayState".into(), relay_state),
                ("SigAlg".into(), sig_alg),
                ("Signature".into(), signature),
            ],
            octet_string: Some(octet),
            ..Default::default()
        })
    }

    #[test]
    fn signed_detached_requests_parse_with_per_request_relay_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for binding in [Binding::Redirect, Binding::SimpleSign] {
            let sp = signed_sp()?;
            let idp = signed_idp()?;
            let ctx = sp.create_login_request_with_options(
                &idp,
                binding,
                &LoginRequestOptions {
                    relay_state: Some("signed request state"),
                    ..Default::default()
                },
            )?;
            let request = match binding {
                Binding::Redirect => redirect_request(&ctx.context)?,
                Binding::SimpleSign => simplesign_request(&ctx)?,
                Binding::Post | Binding::Artifact => return Err("unexpected binding".into()),
            };
            let parsed = idp.parse_login_request(&sp, binding, &request)?;

            assert_eq!(ctx.relay_state.as_deref(), Some("signed request state"));
            assert_eq!(parsed.extract.get_str("request.id"), Some(ctx.id.as_str()));
        }
        Ok(())
    }
}
