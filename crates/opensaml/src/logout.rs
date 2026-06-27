//! Single Logout (SLO) — create/parse LogoutRequest & LogoutResponse
//! (samlify `Entity.createLogoutRequest/createLogoutResponse/parseLogout*`).

use crate::binding::{base64_encode, build_redirect_url};
use crate::constants::{status_code, Binding, CertUse, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting, User};
use crate::error::OpenSamlError;
use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
use crate::metadata::Metadata;
use crate::template::{replace_tags_by_value, LOGOUT_REQUEST_TEMPLATE, LOGOUT_RESPONSE_TEMPLATE};

fn issuer_of(setting: &EntitySetting, meta: &Metadata) -> String {
    setting
        .entity_id
        .clone()
        .or_else(|| meta.get_entity_id().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(feature = "crypto-bergshamra")]
fn sign_logout(
    setting: &EntitySetting,
    binding: Binding,
    xml: &str,
    destination: &str,
    relay: Option<&str>,
    parser_type: ParserType,
) -> Result<(String, Option<String>, Option<String>), OpenSamlError> {
    use crate::binding::{append_signature, build_redirect_octet};
    use crate::crypto::{
        construct_message_signature, construct_saml_signature, keys::load_private_key,
    };

    let key_pem = setting
        .private_key
        .as_deref()
        .ok_or_else(|| OpenSamlError::MissingKey("private_key".into()))?;
    let cert = setting
        .signing_cert
        .as_deref()
        .ok_or_else(|| OpenSamlError::MissingKey("signing_cert".into()))?;
    let sig_alg = &setting.request_signature_algorithm;
    let key = load_private_key(key_pem, setting.private_key_pass.as_deref())?;
    match binding {
        Binding::Redirect => {
            let octet = build_redirect_octet(parser_type, xml, relay, sig_alg)?;
            let sig = construct_message_signature(&octet, &key, sig_alg)?;
            Ok((append_signature(destination, &octet, &sig), None, None))
        }
        _ => {
            let signed = construct_saml_signature(
                xml,
                true,
                &key,
                cert,
                sig_alg,
                &setting.transformation_algorithms,
                setting.signature_config.as_ref(),
            )?;
            Ok((base64_encode(signed.as_bytes()), None, None))
        }
    }
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn sign_logout(
    _setting: &EntitySetting,
    _binding: Binding,
    _xml: &str,
    _destination: &str,
    _relay: Option<&str>,
    _parser_type: ParserType,
) -> Result<(String, Option<String>, Option<String>), OpenSamlError> {
    Err(OpenSamlError::Unsupported(
        "signing logout messages requires feature crypto-bergshamra".into(),
    ))
}

fn unsigned_context(
    binding: Binding,
    xml: &str,
    destination: &str,
    parser_type: ParserType,
    relay: Option<&str>,
) -> Result<String, OpenSamlError> {
    match binding {
        Binding::Redirect => build_redirect_url(destination, parser_type, xml, relay),
        Binding::Post | Binding::SimpleSign => Ok(base64_encode(xml.as_bytes())),
        Binding::Artifact => Err(OpenSamlError::UndefinedBinding),
    }
}

/// Build a `<LogoutRequest>` from `init` to `target` (samlify `createLogoutRequest`).
///
/// `user` supplies the `<NameID>` and an optional `SessionIndex` (available to
/// custom `logout_request_template`s; the default template omits it, as samlify).
pub fn create_logout_request(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &User,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, OpenSamlError> {
    create_logout_request_with_id(
        init_setting,
        init_meta,
        target_meta,
        binding,
        user,
        relay_state,
        want_signed,
        None,
    )
}

/// Like [`create_logout_request`] but uses `message_id` when provided.
#[allow(clippy::too_many_arguments)] // extends the 7-arg samlify-shaped API with optional `message_id`
pub fn create_logout_request_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &User,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, OpenSamlError> {
    let destination = target_meta
        .get_single_logout_service(binding)
        .ok_or_else(|| OpenSamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let name_id_format = init_setting
        .name_id_format
        .first()
        .cloned()
        .unwrap_or_default();
    let template = init_setting
        .logout_request_template
        .as_deref()
        .unwrap_or(LOGOUT_REQUEST_TEMPLATE);
    let xml = replace_tags_by_value(
        template,
        &[
            ("ID", id.clone()),
            ("IssueInstant", now_iso8601()),
            ("Destination", destination.clone()),
            ("Issuer", issuer_of(init_setting, init_meta)),
            ("NameIDFormat", name_id_format),
            ("NameID", user.name_id.clone()),
            (
                "SessionIndex",
                user.session_index.clone().unwrap_or_default(),
            ),
        ],
    );
    let (context, signature, sig_alg) = if want_signed {
        sign_logout(
            init_setting,
            binding,
            &xml,
            &destination,
            relay_state,
            ParserType::LogoutRequest,
        )?
    } else {
        (
            unsigned_context(
                binding,
                &xml,
                &destination,
                ParserType::LogoutRequest,
                relay_state,
            )?,
            None,
            None,
        )
    };
    Ok(BindingContext {
        id,
        context,
        relay_state: relay_state.map(str::to_string),
        entity_endpoint: destination,
        binding,
        request_type: "SAMLRequest",
        signature,
        sig_alg,
    })
}

/// Build a `<LogoutResponse>` from `init` to `target` (samlify `createLogoutResponse`).
pub fn create_logout_response(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, OpenSamlError> {
    create_logout_response_with_id(
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        None,
    )
}

/// Like [`create_logout_response`] but uses `message_id` when provided.
#[allow(clippy::too_many_arguments)] // extends the 7-arg samlify-shaped API with optional `message_id`
pub fn create_logout_response_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, OpenSamlError> {
    let destination = target_meta
        .get_single_logout_service(binding)
        .ok_or_else(|| OpenSamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let template = init_setting
        .logout_response_template
        .as_deref()
        .unwrap_or(LOGOUT_RESPONSE_TEMPLATE);
    let xml = replace_tags_by_value(
        template,
        &[
            ("ID", id.clone()),
            ("IssueInstant", now_iso8601()),
            ("Destination", destination.clone()),
            (
                "InResponseTo",
                in_response_to.unwrap_or_default().to_string(),
            ),
            ("Issuer", issuer_of(init_setting, init_meta)),
            ("StatusCode", status_code::SUCCESS.to_string()),
        ],
    );
    let (context, signature, sig_alg) = if want_signed {
        sign_logout(
            init_setting,
            binding,
            &xml,
            &destination,
            relay_state,
            ParserType::LogoutResponse,
        )?
    } else {
        (
            unsigned_context(
                binding,
                &xml,
                &destination,
                ParserType::LogoutResponse,
                relay_state,
            )?,
            None,
            None,
        )
    };
    Ok(BindingContext {
        id,
        context,
        relay_state: relay_state.map(str::to_string),
        entity_endpoint: destination,
        binding,
        request_type: "SAMLResponse",
        signature,
        sig_alg,
    })
}

/// Parse a `<LogoutRequest>` from `from` (samlify `parseLogoutRequest`).
pub fn parse_logout_request(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, OpenSamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    flow(
        &FlowOptions {
            binding: Some(binding),
            parser_type: Some(ParserType::LogoutRequest),
            check_signature: self_setting.want_logout_request_signed,
            from_issuer: from_meta.get_entity_id(),
            signing_certs: &signing_certs,
            decrypt_key: None,
            decrypt_key_pass: None,
            clock_drifts: self_setting.clock_drifts,
            expected_audience: None,
            expected_in_response_to: None,
        },
        request,
    )
}

/// Parse a `<LogoutResponse>` from `from` (samlify `parseLogoutResponse`).
pub fn parse_logout_response(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, OpenSamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    flow(
        &FlowOptions {
            binding: Some(binding),
            parser_type: Some(ParserType::LogoutResponse),
            check_signature: self_setting.want_logout_response_signed,
            from_issuer: from_meta.get_entity_id(),
            signing_certs: &signing_certs,
            decrypt_key: None,
            decrypt_key_pass: None,
            clock_drifts: self_setting.clock_drifts,
            expected_audience: None,
            expected_in_response_to: None,
        },
        request,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{base64_decode, deflate_raw_decode};
    use crate::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
    use crate::{IdentityProvider, ServiceProvider};
    use url::Url;

    fn sp() -> Result<ServiceProvider, OpenSamlError> {
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

    fn idp() -> Result<IdentityProvider, OpenSamlError> {
        IdentityProvider::from_config(
            &IdpMetadataConfig {
                entity_id: "https://idp.example.com/metadata".into(),
                single_sign_on_service: vec![Endpoint::new(Binding::Post, "https://idp/sso")],
                single_logout_service: vec![Endpoint::new(Binding::Redirect, "https://idp/slo")],
                ..Default::default()
            },
            EntitySetting::default(),
        )
    }

    #[test]
    fn logout_request_redirect_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let (sp, idp) = (sp()?, idp()?);
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
    fn logout_response_post_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let (sp, idp) = (sp()?, idp()?);
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
        let result = parse_logout_response(&sp.setting, &idp.metadata, Binding::Post, &request)?;
        assert_eq!(
            result.extract.get_str("issuer"),
            Some("https://idp.example.com/metadata")
        );
        Ok(())
    }
}
