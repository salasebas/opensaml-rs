//! Single Logout (SLO): create and parse LogoutRequest and LogoutResponse.

use crate::binding::{base64_encode, build_redirect_url};
use crate::constants::{namespace, status_code, Binding, CertUse, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting, User};
use crate::error::SamlError;
use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
use crate::metadata::Metadata;
use crate::template::{
    apply_tag_prefixes, replace_tags_by_optional_value, replace_tags_by_value, validate_tag_prefix,
};
use crate::xml::write::XmlWriter;

fn issuer_of(setting: &EntitySetting, meta: &Metadata) -> String {
    setting
        .entity_id
        .clone()
        .or_else(|| meta.get_entity_id().map(str::to_string))
        .unwrap_or_default()
}

fn render_default_logout_response(
    setting: &EntitySetting,
    meta: &Metadata,
    id: &str,
    issue_instant: &str,
    destination: &str,
    in_response_to: Option<&str>,
) -> Result<String, SamlError> {
    validate_tag_prefix("protocol", &setting.tag_prefix_protocol)?;
    validate_tag_prefix("assertion", &setting.tag_prefix_assertion)?;

    let protocol_prefix = &setting.tag_prefix_protocol;
    let assertion_prefix = &setting.tag_prefix_assertion;
    let root_name = format!("{protocol_prefix}:LogoutResponse");
    let issuer_name = format!("{assertion_prefix}:Issuer");
    let status_name = format!("{protocol_prefix}:Status");
    let status_code_name = format!("{protocol_prefix}:StatusCode");
    let xmlns_protocol = format!("xmlns:{protocol_prefix}");
    let xmlns_assertion = format!("xmlns:{assertion_prefix}");
    let issuer = issuer_of(setting, meta);

    let mut attrs = vec![
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", id),
        ("Version", "2.0"),
        ("IssueInstant", issue_instant),
        ("Destination", destination),
    ];
    if let Some(value) = in_response_to {
        attrs.push(("InResponseTo", value));
    }

    let mut writer = XmlWriter::new();
    writer.start(&root_name, &attrs);
    writer.text_element(&issuer_name, &[], &issuer);
    writer.start(&status_name, &[]);
    writer.empty(&status_code_name, &[("Value", status_code::SUCCESS)]);
    writer.end(&status_name);
    writer.end(&root_name);
    Ok(writer.finish())
}

fn render_default_logout_request(
    setting: &EntitySetting,
    meta: &Metadata,
    id: &str,
    issue_instant: &str,
    destination: &str,
    user: &User,
    name_id_format: &str,
) -> Result<String, SamlError> {
    validate_tag_prefix("protocol", &setting.tag_prefix_protocol)?;
    validate_tag_prefix("assertion", &setting.tag_prefix_assertion)?;

    let protocol_prefix = &setting.tag_prefix_protocol;
    let assertion_prefix = &setting.tag_prefix_assertion;
    let root_name = format!("{protocol_prefix}:LogoutRequest");
    let issuer_name = format!("{assertion_prefix}:Issuer");
    let name_id_name = format!("{assertion_prefix}:NameID");
    let session_index_name = format!("{protocol_prefix}:SessionIndex");
    let xmlns_protocol = format!("xmlns:{protocol_prefix}");
    let xmlns_assertion = format!("xmlns:{assertion_prefix}");
    let issuer = issuer_of(setting, meta);

    let attrs = [
        (xmlns_protocol.as_str(), namespace::PROTOCOL),
        (xmlns_assertion.as_str(), namespace::ASSERTION),
        ("ID", id),
        ("Version", "2.0"),
        ("IssueInstant", issue_instant),
        ("Destination", destination),
    ];

    let mut writer = XmlWriter::new();
    writer.start(&root_name, &attrs);
    writer.text_element(&issuer_name, &[], &issuer);
    writer.text_element(&name_id_name, &[("Format", name_id_format)], &user.name_id);
    if let Some(session_index) = user.session_index.as_deref() {
        writer.text_element(&session_index_name, &[], session_index);
    }
    writer.end(&root_name);
    Ok(writer.finish())
}

#[cfg(feature = "crypto-bergshamra")]
fn sign_logout(
    setting: &EntitySetting,
    binding: Binding,
    xml: &str,
    destination: &str,
    relay: Option<&str>,
    parser_type: ParserType,
) -> Result<(String, Option<String>, Option<String>), SamlError> {
    use crate::binding::{append_signature, build_redirect_octet};
    use crate::crypto::{
        construct_message_signature, construct_saml_signature, keys::load_private_key,
    };

    if matches!(binding, Binding::Artifact) {
        return Err(SamlError::UndefinedBinding);
    }

    let sig_alg = &setting.request_signature_algorithm;
    let key_pem = setting
        .private_key
        .as_deref()
        .ok_or_else(|| SamlError::MissingKey("private_key".into()))?;
    let key = load_private_key(key_pem, setting.private_key_pass.as_deref())?;
    match binding {
        Binding::Redirect => {
            let octet = build_redirect_octet(parser_type, xml, relay, sig_alg)?;
            let sig = construct_message_signature(&octet, &key, sig_alg)?;
            Ok((append_signature(destination, &octet, &sig), None, None))
        }
        Binding::Post => {
            let cert = setting
                .signing_cert
                .as_deref()
                .ok_or_else(|| SamlError::MissingKey("signing_cert".into()))?;
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
        Binding::SimpleSign => {
            let octet = crate::binding::build_simplesign_octet(
                parser_type.query_param(),
                xml,
                relay,
                sig_alg,
            );
            let sig = construct_message_signature(&octet, &key, sig_alg)?;
            Ok((
                base64_encode(xml.as_bytes()),
                Some(sig),
                Some(sig_alg.clone()),
            ))
        }
        Binding::Artifact => Err(SamlError::UndefinedBinding),
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
) -> Result<(String, Option<String>, Option<String>), SamlError> {
    Err(SamlError::Unsupported(
        "signing logout messages requires feature crypto-bergshamra".into(),
    ))
}

fn unsigned_context(
    binding: Binding,
    xml: &str,
    destination: &str,
    parser_type: ParserType,
    relay: Option<&str>,
) -> Result<String, SamlError> {
    match binding {
        Binding::Redirect => build_redirect_url(destination, parser_type, xml, relay),
        Binding::Post | Binding::SimpleSign => Ok(base64_encode(xml.as_bytes())),
        Binding::Artifact => Err(SamlError::UndefinedBinding),
    }
}

/// Build a `<LogoutRequest>` from `init` to `target`.
///
/// `user` supplies the `<NameID>` and optional `<samlp:SessionIndex>`.
pub fn create_logout_request(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &User,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
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
#[allow(clippy::too_many_arguments)] // public API adds optional `message_id`
pub fn create_logout_request_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &User,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let destination = target_meta
        .get_single_logout_service(binding)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let name_id_format = init_setting
        .name_id_format
        .first()
        .cloned()
        .unwrap_or_default();
    let issue_instant = now_iso8601();
    let xml = if let Some(template) = init_setting.logout_request_template.as_deref() {
        validate_tag_prefix("protocol", &init_setting.tag_prefix_protocol)?;
        validate_tag_prefix("assertion", &init_setting.tag_prefix_assertion)?;
        let template = apply_tag_prefixes(
            template,
            &init_setting.tag_prefix_protocol,
            &init_setting.tag_prefix_assertion,
        );
        replace_tags_by_optional_value(
            &template,
            &[
                ("ID", Some(id.clone())),
                ("IssueInstant", Some(issue_instant)),
                ("Destination", Some(destination.clone())),
                ("Issuer", Some(issuer_of(init_setting, init_meta))),
                ("NameIDFormat", Some(name_id_format)),
                ("NameID", Some(user.name_id.clone())),
                ("SessionIndex", user.session_index.clone()),
            ],
        )
    } else {
        render_default_logout_request(
            init_setting,
            init_meta,
            &id,
            &issue_instant,
            &destination,
            user,
            &name_id_format,
        )?
    };
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

/// Build a `<LogoutResponse>` from `init` to `target`.
pub fn create_logout_response(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
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
#[allow(clippy::too_many_arguments)] // public API adds optional `message_id`
pub fn create_logout_response_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let destination = target_meta
        .get_single_logout_service(binding)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let issue_instant = now_iso8601();
    let xml = if let Some(template) = init_setting.logout_response_template.as_deref() {
        validate_tag_prefix("protocol", &init_setting.tag_prefix_protocol)?;
        validate_tag_prefix("assertion", &init_setting.tag_prefix_assertion)?;
        let template = apply_tag_prefixes(
            template,
            &init_setting.tag_prefix_protocol,
            &init_setting.tag_prefix_assertion,
        );
        replace_tags_by_value(
            &template,
            &[
                ("ID", id.clone()),
                ("IssueInstant", issue_instant),
                ("Destination", destination.clone()),
                (
                    "InResponseTo",
                    in_response_to.unwrap_or_default().to_string(),
                ),
                ("Issuer", issuer_of(init_setting, init_meta)),
                ("StatusCode", status_code::SUCCESS.to_string()),
            ],
        )
    } else {
        render_default_logout_response(
            init_setting,
            init_meta,
            &id,
            &issue_instant,
            &destination,
            in_response_to,
        )?
    };
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

/// Parse a `<LogoutRequest>` from `from`.
pub fn parse_logout_request(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, SamlError> {
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
            allow_insecure_software_rsa_key_transport_decryption: false,
            clock_drifts: self_setting.clock_drifts,
            redirect_inflate_max_bytes: self_setting.redirect_inflate_max_bytes,
            xml_limits: self_setting.xml_limits,
            expected_audience: None,
            expected_in_response_to: None,
        },
        request,
    )
}

fn parse_logout_response_inner(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    expected_in_response_to: Option<&str>,
) -> Result<FlowResult, SamlError> {
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
            allow_insecure_software_rsa_key_transport_decryption: false,
            clock_drifts: self_setting.clock_drifts,
            redirect_inflate_max_bytes: self_setting.redirect_inflate_max_bytes,
            xml_limits: self_setting.xml_limits,
            expected_audience: None,
            expected_in_response_to,
        },
        request,
    )
}

/// Parse a `<LogoutResponse>` from `from` and require it to answer `request_id`.
///
/// Single Logout responses are state-machine messages. The caller must pass the
/// ID of the `LogoutRequest` it issued so stale or unrelated responses cannot be
/// accepted as completion for the current logout transaction.
pub fn parse_logout_response(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    request_id: &str,
) -> Result<FlowResult, SamlError> {
    if request_id.is_empty() {
        return Err(SamlError::InvalidInResponseTo);
    }
    parse_logout_response_inner(self_setting, from_meta, binding, request, Some(request_id))
}

/// Parse a `<LogoutResponse>` without binding it to a `LogoutRequest` ID.
///
/// Prefer [`parse_logout_response`] for normal SLO handling. This exists for
/// legacy interop and custom state machines that perform request correlation
/// outside this crate.
pub fn parse_logout_response_without_request_id(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, SamlError> {
    parse_logout_response_inner(self_setting, from_meta, binding, request, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{base64_decode, deflate_raw_decode};
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

        let result =
            parse_logout_request(&idp.setting, &expected_sp.metadata, Binding::Post, &request);

        assert!(matches!(result, Err(SamlError::UnmatchIssuer)));
        Ok(())
    }

    #[cfg(feature = "crypto-bergshamra")]
    mod signed_tests {
        use super::*;
        use crate::constants::signature_algorithm::RSA_SHA256;

        const PRIVKEY: &str = include_str!("../tests/fixtures/key/sp_privkey.pem");
        const CERT: &str = include_str!("../tests/fixtures/key/sp_signing_cert.cer");

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
                    assertion_consumer_service: vec![Endpoint::new(
                        Binding::Post,
                        "https://sp/acs",
                    )],
                    ..Default::default()
                },
                signing_setting(),
            )
        }

        #[test]
        fn signed_logout_request_rejects_unexpected_issuer(
        ) -> Result<(), Box<dyn std::error::Error>> {
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

            assert!(matches!(result, Err(SamlError::UnmatchIssuer)));
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
            Err(SamlError::InvalidInResponseTo)
        ));
        Ok(())
    }

    #[test]
    fn default_logout_response_parsing_requires_signature() -> Result<(), Box<dyn std::error::Error>>
    {
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
        assert!(matches!(result, Err(SamlError::FailedToVerifySignature)));

        #[cfg(not(feature = "crypto-bergshamra"))]
        assert!(matches!(result, Err(SamlError::Unsupported(_))));

        Ok(())
    }
}
