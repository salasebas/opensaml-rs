use saml_rs::constants::Binding;
use saml_rs::metadata::{Endpoint, IdpMetadataConfig, SpMetadataConfig};
use saml_rs::raw::{BindingContext, FlowResult};
use saml_rs::template::{LoginResponseAttribute, LoginResponseTemplate};
use saml_rs::util::Value;
use saml_rs::{raw::LoginResponseOptions, raw::User};
use saml_rs::{
    AuthnRequest, BrowserInput, EndpointUrl, EntitySetting, FormField, IdentityProvider,
    LogoutRequest, LogoutResponse, Outbound, Pending, RelayState, RelayStateState, RequestId,
    SamlError, SamlInstant, ServiceProvider, SsoRequestBinding, SsoResponseBinding, SsoSession,
};

const IDP_PRIVATE_KEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const IDP_CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

#[test]
fn typed_models_empty_request_ids_fail() {
    assert!(matches!(RequestId::new(""), Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_endpoint_url_accepts_absolute_http_urls() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(
        EndpointUrl::new("https://sp.example.com/acs")?.as_str(),
        "https://sp.example.com/acs"
    );
    assert_eq!(
        EndpointUrl::new("http://localhost:3000/sso")?.as_str(),
        "http://localhost:3000/sso"
    );
    Ok(())
}

#[test]
fn typed_models_endpoint_url_rejects_relative_urls() {
    assert!(matches!(
        EndpointUrl::new("/acs"),
        Err(SamlError::Invalid(_))
    ));
}

#[test]
fn typed_models_relay_state_preserves_tri_state() {
    assert_eq!(
        RelayStateState::from_option(Option::<String>::None),
        RelayStateState::Absent
    );
    assert_eq!(
        RelayStateState::from_option(Some(String::new())),
        RelayStateState::PresentEmpty
    );
    assert_eq!(
        RelayStateState::from_option(Some("state".to_string())),
        RelayStateState::PresentValue(RelayState::new("state"))
    );
}

fn binding_context(binding: Binding) -> BindingContext {
    BindingContext {
        id: "_request123".to_string(),
        context: match binding {
            Binding::Redirect => "https://idp.example.com/sso?SAMLRequest=abc".to_string(),
            Binding::Post | Binding::SimpleSign => "PHNhbWxwOkF1dGhuUmVxdWVzdC8+".to_string(),
            Binding::Artifact => "artifact".to_string(),
        },
        relay_state: Some("relay".to_string()),
        entity_endpoint: "https://idp.example.com/sso".to_string(),
        binding,
        request_type: "SAMLRequest",
        signature: None,
        sig_alg: None,
    }
}

#[test]
fn typed_models_redirect_outbound_exposes_only_redirect_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let outbound: Outbound<AuthnRequest> = binding_context(Binding::Redirect).try_into()?;

    assert_eq!(outbound.id().as_str(), "_request123");
    assert_eq!(
        outbound.redirect_url()?,
        "https://idp.example.com/sso?SAMLRequest=abc"
    );
    assert!(matches!(
        outbound.post_form(),
        Err(SamlError::UndefinedBinding)
    ));
    assert_eq!(
        outbound.relay_state().map(RelayState::as_str),
        Some("relay")
    );
    Ok(())
}

#[test]
fn typed_models_post_outbound_exposes_post_form() -> Result<(), Box<dyn std::error::Error>> {
    let outbound: Outbound<AuthnRequest> = binding_context(Binding::Post).try_into()?;
    let form = outbound.post_form()?;

    assert_eq!(form.action().as_str(), "https://idp.example.com/sso");
    assert_eq!(
        form.value("SAMLRequest"),
        Some("PHNhbWxwOkF1dGhuUmVxdWVzdC8+")
    );
    assert!(matches!(
        outbound.redirect_url(),
        Err(SamlError::UndefinedBinding)
    ));
    Ok(())
}

#[test]
fn typed_models_post_outbound_rejects_detached_signature_fields() {
    let mut context = binding_context(Binding::Post);
    context.sig_alg = Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string());
    context.signature = Some("signature-value".to_string());

    let result = Outbound::<AuthnRequest>::try_from(context);

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_simplesign_outbound_preserves_signature_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut context = binding_context(Binding::SimpleSign);
    context.sig_alg = Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string());
    context.signature = Some("signature-value".to_string());

    let outbound: Outbound<AuthnRequest> = context.try_into()?;
    let form = outbound.post_form()?;

    assert_eq!(
        form.value("SigAlg"),
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    );
    assert_eq!(form.value("Signature"), Some("signature-value"));
    Ok(())
}

#[test]
fn typed_models_simplesign_outbound_rejects_partial_signature_state() {
    let mut context = binding_context(Binding::SimpleSign);
    context.sig_alg = Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string());

    let result = Outbound::<AuthnRequest>::try_from(context);

    assert!(matches!(result, Err(SamlError::Invalid(_))));
}

#[test]
fn typed_models_artifact_outbound_is_rejected() {
    let result = Outbound::<AuthnRequest>::try_from(binding_context(Binding::Artifact));

    assert!(matches!(result, Err(SamlError::UndefinedBinding)));
}

#[test]
fn typed_models_redirect_browser_input_converts_to_http_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::redirect(
        "?SAMLRequest=abc&RelayState=relay&SigAlg=alg&Signature=sig",
    );

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

    assert_eq!(
        request.query,
        vec![
            ("SAMLRequest".to_string(), "abc".to_string()),
            ("RelayState".to_string(), "relay".to_string()),
            ("SigAlg".to_string(), "alg".to_string()),
            ("Signature".to_string(), "sig".to_string()),
        ]
    );
    assert_eq!(
        request.octet_string.as_deref(),
        Some("SAMLRequest=abc&RelayState=relay&SigAlg=alg")
    );
    Ok(())
}

#[test]
fn typed_models_redirect_browser_input_uses_canonical_signed_octets_with_extra_params(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::redirect(
        "?ignored=before&Signature=sig&SAMLRequest=abc%2Bdef&RelayState=relay%20state&extra=after&SigAlg=http%3A%2F%2Fexample.com%2Falg",
    );

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

    assert_eq!(
        request.octet_string.as_deref(),
        Some(
            "SAMLRequest=abc%2Bdef&RelayState=relay%20state&SigAlg=http%3A%2F%2Fexample.com%2Falg"
        )
    );
    Ok(())
}

#[test]
fn typed_models_redirect_browser_input_rejects_duplicate_signed_fields() {
    for (name, raw_query) in [
        (
            "SAMLRequest",
            "SAMLRequest=abc&SAMLRequest=def&SigAlg=alg&Signature=sig",
        ),
        (
            "SAMLResponse",
            "SAMLResponse=abc&SAMLResponse=def&SigAlg=alg&Signature=sig",
        ),
        (
            "RelayState",
            "SAMLRequest=abc&RelayState=one&RelayState=two&SigAlg=alg&Signature=sig",
        ),
        (
            "SigAlg",
            "SAMLRequest=abc&SigAlg=one&SigAlg=two&Signature=sig",
        ),
        (
            "Signature",
            "SAMLRequest=abc&SigAlg=alg&Signature=one&Signature=two",
        ),
    ] {
        let input = BrowserInput::<AuthnRequest>::redirect(raw_query);

        let result = saml_rs::raw::HttpRequest::try_from(input);

        assert!(
            matches!(result, Err(SamlError::Invalid(_))),
            "expected duplicate {name} to fail"
        );
    }
}

#[test]
fn typed_models_post_browser_input_preserves_fields() -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::post(vec![
        FormField::new("SAMLRequest", "abc"),
        FormField::new("RelayState", ""),
    ]);

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

    assert_eq!(
        request.body,
        vec![
            ("SAMLRequest".to_string(), "abc".to_string()),
            ("RelayState".to_string(), String::new()),
        ]
    );
    assert_eq!(request.octet_string, None);
    Ok(())
}

#[test]
fn typed_models_simplesign_browser_input_derives_signed_octets(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::simple_sign_post(
        "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdC8%2B&RelayState=relay&SigAlg=alg&Signature=sig",
        vec![
            FormField::new("SAMLRequest", "PHNhbWxwOkF1dGhuUmVxdWVzdC8+"),
            FormField::new("RelayState", "relay"),
            FormField::new("SigAlg", "alg"),
            FormField::new("Signature", "sig"),
        ],
    );

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

    assert_eq!(
        request.octet_string.as_deref(),
        Some("SAMLRequest=<samlp:AuthnRequest/>&RelayState=relay&SigAlg=alg")
    );
    Ok(())
}

#[test]
fn typed_models_simplesign_browser_input_accepts_raw_body_only(
) -> Result<(), Box<dyn std::error::Error>> {
    let input = BrowserInput::<AuthnRequest>::simple_sign_post(
        "SAMLRequest=PHNhbWxwOkF1dGhuUmVxdWVzdC8%2B&RelayState=relay&SigAlg=alg&Signature=sig",
        vec![],
    );

    let request = saml_rs::raw::HttpRequest::try_from(input)?;

    assert_eq!(
        request.body,
        vec![
            (
                "SAMLRequest".to_string(),
                "PHNhbWxwOkF1dGhuUmVxdWVzdC8+".to_string()
            ),
            ("RelayState".to_string(), "relay".to_string()),
            ("SigAlg".to_string(), "alg".to_string()),
            ("Signature".to_string(), "sig".to_string()),
        ]
    );
    assert_eq!(
        request.octet_string.as_deref(),
        Some("SAMLRequest=<samlp:AuthnRequest/>&RelayState=relay&SigAlg=alg")
    );
    Ok(())
}

fn value_object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn value_str(value: &str) -> Value {
    Value::Str(value.to_string())
}

#[test]
fn typed_models_authn_request_from_flow_result_exposes_typed_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
        saml_content: "<samlp:AuthnRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![
                    ("id", value_str("_request123")),
                    ("destination", value_str("https://idp.example.com/sso")),
                    (
                        "assertionConsumerServiceUrl",
                        value_str("https://sp.example.com/acs"),
                    ),
                ]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
            (
                "nameIDPolicy",
                value_object(vec![
                    (
                        "format",
                        value_str("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
                    ),
                    ("allowCreate", value_str("true")),
                ]),
            ),
        ]),
    };

    let request = AuthnRequest::try_from(flow)?;

    assert_eq!(request.id().as_str(), "_request123");
    assert_eq!(request.issuer().as_str(), "https://sp.example.com/metadata");
    assert_eq!(
        request.destination().map(EndpointUrl::as_str),
        Some("https://idp.example.com/sso")
    );
    assert_eq!(
        request.acs_url().map(EndpointUrl::as_str),
        Some("https://sp.example.com/acs")
    );
    assert_eq!(
        request
            .name_id_policy()
            .and_then(saml_rs::NameIdPolicy::allow_create),
        Some(true)
    );
    assert_eq!(request.raw_flow().saml_content, "<samlp:AuthnRequest/>");
    Ok(())
}

#[test]
fn typed_models_sso_session_from_flow_result_preserves_multi_valued_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: Some("sig-alg".to_string()),
        extract: value_object(vec![
            (
                "response",
                value_object(vec![
                    ("id", value_str("_response123")),
                    ("inResponseTo", value_str("_request123")),
                ]),
            ),
            ("issuer", value_str("https://idp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
            (
                "attributes",
                value_object(vec![(
                    "eduPersonAffiliation",
                    Value::Array(vec![value_str("users"), value_str("examplerole1")]),
                )]),
            ),
            (
                "sessionIndex",
                value_object(vec![
                    ("sessionIndex", value_str("_session123")),
                    ("authnInstant", value_str("2026-07-04T12:00:00Z")),
                    ("sessionNotOnOrAfter", value_str("2026-07-04T13:00:00Z")),
                ]),
            ),
            (
                "conditions",
                value_object(vec![
                    ("notBefore", value_str("2026-07-04T11:59:00Z")),
                    ("notOnOrAfter", value_str("2026-07-04T13:00:00Z")),
                ]),
            ),
            ("audience", value_str("https://sp.example.com/metadata")),
            (
                "subjectConfirmation",
                value_str("<saml:SubjectConfirmation/>"),
            ),
        ]),
    };

    let session = SsoSession::try_from(flow)?;
    let affiliation = session
        .attributes()
        .get("eduPersonAffiliation")
        .ok_or("missing affiliation")?;

    assert_eq!(session.response_id().as_str(), "_response123");
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        affiliation
            .values()
            .iter()
            .map(saml_rs::AttributeValue::as_str)
            .collect::<Vec<_>>(),
        vec!["users", "examplerole1"]
    );
    assert_eq!(
        session
            .authn_session()
            .session_index()
            .map(|id| id.as_str()),
        Some("_session123")
    );
    assert_eq!(session.sig_alg(), Some("sig-alg"));
    Ok(())
}

#[test]
fn typed_models_logout_request_from_flow_result_exposes_session_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
        saml_content: "<samlp:LogoutRequest/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "request",
                value_object(vec![
                    ("id", value_str("_logout123")),
                    ("destination", value_str("https://idp.example.com/slo")),
                ]),
            ),
            ("issuer", value_str("https://sp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
            (
                "sessionIndex",
                Value::Array(vec![value_str("_session1"), value_str("_session2")]),
            ),
        ]),
    };

    let request = LogoutRequest::try_from(flow)?;

    assert_eq!(request.id().as_str(), "_logout123");
    assert_eq!(request.issuer().as_str(), "https://sp.example.com/metadata");
    assert_eq!(
        request
            .session_indexes()
            .iter()
            .map(|index| index.as_str())
            .collect::<Vec<_>>(),
        vec!["_session1", "_session2"]
    );
    assert_eq!(
        request.destination().map(EndpointUrl::as_str),
        Some("https://idp.example.com/slo")
    );
    Ok(())
}

#[test]
fn typed_models_logout_response_from_flow_result_exposes_correlation(
) -> Result<(), Box<dyn std::error::Error>> {
    let flow = FlowResult {
        saml_content: "<samlp:LogoutResponse/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "response",
                value_object(vec![
                    ("id", value_str("_logout_response123")),
                    ("inResponseTo", value_str("_logout123")),
                    ("destination", value_str("https://sp.example.com/slo")),
                ]),
            ),
            ("issuer", value_str("https://idp.example.com/metadata")),
        ]),
    };

    let response = LogoutResponse::try_from(flow)?;

    assert_eq!(response.id().as_str(), "_logout_response123");
    assert_eq!(
        response.in_response_to().map(RequestId::as_str),
        Some("_logout123")
    );
    assert_eq!(
        response.destination().map(EndpointUrl::as_str),
        Some("https://sp.example.com/slo")
    );
    Ok(())
}

fn sp(setting: EntitySetting) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_config(
        &SpMetadataConfig {
            entity_id: "https://sp.example.com/metadata".into(),
            single_logout_service: vec![Endpoint::new(Binding::Post, "https://sp.example.com/slo")],
            assertion_consumer_service: vec![
                Endpoint::new(Binding::Post, "https://sp.example.com/acs"),
                Endpoint::new(Binding::SimpleSign, "https://sp.example.com/acs-simple"),
            ],
            ..Default::default()
        },
        setting,
    )
}

fn idp(setting: EntitySetting) -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_config(
        &IdpMetadataConfig {
            entity_id: "https://idp.example.com/metadata".into(),
            signing_certs: setting
                .signing_cert
                .clone()
                .map(|cert| vec![cert])
                .unwrap_or_default(),
            single_sign_on_service: vec![
                Endpoint::new(Binding::Post, "https://idp.example.com/sso"),
                Endpoint::new(Binding::Redirect, "https://idp.example.com/sso"),
                Endpoint::new(Binding::SimpleSign, "https://idp.example.com/sso"),
            ],
            single_logout_service: vec![Endpoint::new(
                Binding::Post,
                "https://idp.example.com/slo",
            )],
            ..Default::default()
        },
        setting,
    )
}

fn signing_setting() -> EntitySetting {
    let mut setting = EntitySetting::default();
    setting.private_key = Some(IDP_PRIVATE_KEY.to_string());
    setting.signing_cert = Some(IDP_CERT.to_string());
    setting
}

fn attribute(name: &str, tag: &str) -> LoginResponseAttribute {
    LoginResponseAttribute {
        name: name.to_string(),
        name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string(),
        value_xsi_type: "xs:string".to_string(),
        value_tag: tag.to_string(),
        value_xmlns_xs: None,
        value_xmlns_xsi: None,
    }
}

fn idp_with_attribute_template() -> Result<IdentityProvider, SamlError> {
    let mut setting = signing_setting();
    setting.login_response_template = Some(LoginResponseTemplate {
        context: None,
        attributes: vec![
            attribute("mail", "mail"),
            attribute("eduPersonAffiliation", "affiliation.primary"),
            attribute("eduPersonAffiliation", "affiliation.secondary"),
        ],
    });
    idp(setting)
}

#[test]
fn typed_models_existing_authn_request_flow_converts_to_typed_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp = idp(EntitySetting::default())?;
    let context = sp.create_login_request(&idp, Binding::Post, None)?;
    let request =
        saml_rs::raw::HttpRequest::post(vec![("SAMLRequest".to_string(), context.context.clone())]);

    let parsed = idp.parse_login_request(&sp, Binding::Post, &request)?;
    let typed = AuthnRequest::try_from(parsed)?;

    assert_eq!(typed.id().as_str(), context.id.as_str());
    assert_eq!(typed.issuer().as_str(), "https://sp.example.com/metadata");
    Ok(())
}

#[test]
fn typed_models_existing_login_response_flow_converts_to_typed_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp = idp(signing_setting())?;
    let context = idp.create_login_response(
        &sp,
        Binding::Post,
        &User::new("alice@example.com"),
        &LoginResponseOptions {
            in_response_to: Some("_request123"),
            ..Default::default()
        },
    )?;
    let request =
        saml_rs::raw::HttpRequest::post(vec![("SAMLResponse".to_string(), context.context)]);

    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_request123")?;
    let session = SsoSession::try_from(parsed)?;

    assert_eq!(session.name_id().value(), "alice@example.com");
    assert_eq!(
        session.in_response_to().map(RequestId::as_str),
        Some("_request123")
    );
    Ok(())
}

#[test]
fn typed_models_existing_login_response_flow_preserves_multi_value_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = sp(EntitySetting::default())?;
    let idp = idp_with_attribute_template()?;
    let user = User {
        name_id: "alice@example.com".to_string(),
        attributes: vec![
            ("mail".to_string(), "alice@example.com".to_string()),
            ("affiliation.primary".to_string(), "users".to_string()),
            (
                "affiliation.secondary".to_string(),
                "examplerole1".to_string(),
            ),
        ],
        session_index: None,
    };
    let context = idp.create_login_response(
        &sp,
        Binding::Post,
        &user,
        &LoginResponseOptions {
            in_response_to: Some("_request123"),
            ..Default::default()
        },
    )?;
    let request =
        saml_rs::raw::HttpRequest::post(vec![("SAMLResponse".to_string(), context.context)]);

    let parsed =
        sp.parse_login_response_with_request_id(&idp, Binding::Post, &request, "_request123")?;
    let raw_values = parsed
        .extract
        .get("attributes.eduPersonAffiliation")
        .cloned();
    let session = SsoSession::try_from(parsed)?;
    let affiliation = session
        .attributes()
        .get("eduPersonAffiliation")
        .ok_or("missing affiliation")?;

    assert_eq!(
        raw_values,
        Some(Value::Array(vec![
            value_str("users"),
            value_str("examplerole1")
        ]))
    );
    assert_eq!(
        affiliation
            .values()
            .iter()
            .map(saml_rs::AttributeValue::as_str)
            .collect::<Vec<_>>(),
        vec!["users", "examplerole1"]
    );
    Ok(())
}

#[test]
fn typed_models_pending_snapshot_round_trips_without_raw_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let pending = Pending::<AuthnRequest>::new(
        RequestId::new("_request123")?,
        RelayStateState::from_option(Some("relay".to_string())),
        Some(SsoRequestBinding::Redirect),
        Some(SsoResponseBinding::Post),
        saml_rs::EntityId::try_new("https://idp.example.com/metadata")?,
    )?
    .with_issue_instant(SamlInstant::new("2026-07-04T12:00:00Z")?)
    .with_expiration(SamlInstant::new("2026-07-04T12:05:00Z")?);

    let snapshot = pending.snapshot();
    let snapshot_debug = format!("{snapshot:?}");
    let restored = Pending::<AuthnRequest>::from_snapshot(snapshot)?;

    assert_eq!(restored.id().as_str(), "_request123");
    assert_eq!(
        restored.relay_state(),
        &RelayStateState::PresentValue(RelayState::new("relay"))
    );
    assert_eq!(
        restored.request_binding(),
        Some(SsoRequestBinding::Redirect)
    );
    assert_eq!(restored.response_binding(), Some(SsoResponseBinding::Post));
    assert_eq!(
        restored.peer_entity_id().as_str(),
        "https://idp.example.com/metadata"
    );
    assert_eq!(
        restored.issued_at().map(SamlInstant::as_str),
        Some("2026-07-04T12:00:00Z")
    );
    assert_eq!(
        restored.expires_at().map(SamlInstant::as_str),
        Some("2026-07-04T12:05:00Z")
    );
    assert!(!snapshot_debug.contains("PRIVATE KEY"));
    assert!(!snapshot_debug.contains("<EntityDescriptor"));
    Ok(())
}

#[test]
fn typed_models_pending_snapshot_validates_expiration_requires_issue_instant(
) -> Result<(), Box<dyn std::error::Error>> {
    let pending = Pending::<AuthnRequest>::new(
        RequestId::new("_request123")?,
        RelayStateState::Absent,
        Some(SsoRequestBinding::Redirect),
        Some(SsoResponseBinding::Post),
        saml_rs::EntityId::try_new("https://idp.example.com/metadata")?,
    )?;
    let mut snapshot = pending.snapshot();
    snapshot.expires_at = Some(SamlInstant::new("2026-07-04T12:05:00Z")?);

    assert!(matches!(
        Pending::<AuthnRequest>::from_snapshot(snapshot),
        Err(SamlError::Invalid(_))
    ));
    Ok(())
}
