#![cfg(feature = "crypto-bergshamra")]

use saml_rs::binding::{base64_decode, base64_encode, deflate_raw_decode};
use saml_rs::raw::{Binding, FlowResult};
use saml_rs::util::Value;
use saml_rs::{
    AcsEndpoint, BrowserInput, CertificatePem, Credentials, EntityId, FormField, IdpConfig,
    IdpDescriptor, IdpValidationPolicy, LogoutBinding, LogoutRequest, LogoutResponse,
    LogoutSigning, LogoutSubject, MetadataTrustPolicy, NameId, Outbound, PendingLogoutRequest,
    PendingSnapshot, PrivateKeyPem, Received, RelayStateParam, RespondSlo, Saml, SamlError,
    SamlValidationContext, SessionIndex, SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy,
    SsoEndpoint, SsoSession, StartSlo, TemplatePolicy,
};
use time::OffsetDateTime;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_SLO_POST: &str = "https://sp.example.com/slo/post";
const SP_SLO_REDIRECT: &str = "https://sp.example.com/slo/redirect";
const SP_SLO_SIMPLESIGN: &str = "https://sp.example.com/slo/simple-sign";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SLO_POST: &str = "https://idp.example.com/slo/post";
const IDP_SLO_REDIRECT: &str = "https://idp.example.com/slo/redirect";
const IDP_SLO_SIMPLESIGN: &str = "https://idp.example.com/slo/simple-sign";

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

const BAD_LOGOUT_RESPONSE_TEMPLATE: &str = r#"
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}"
    Destination="{Destination}" InResponseTo="_wrong">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="{StatusCode}"/>
    </samlp:Status>
</samlp:LogoutResponse>
"#;

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn sp_config() -> Result<SpConfig, SamlError> {
    SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?)
        .slo_endpoint(SloEndpoint::post(SP_SLO_POST)?)
        .slo_endpoint(SloEndpoint::redirect(SP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::simple_sign(SP_SLO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(SpValidationPolicy::strict())
        .build()
}

fn idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
        .slo_endpoint(SloEndpoint::redirect(IDP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::simple_sign(IDP_SLO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::strict())
        .build()
}

fn bad_template_idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::strict())
        .templates(TemplatePolicy {
            logout_response_template: Some(BAD_LOGOUT_RESPONSE_TEMPLATE.to_string()),
            ..TemplatePolicy::default()
        })
        .build()
}

fn facades() -> Result<(Saml<saml_rs::Sp>, Saml<saml_rs::Idp>), SamlError> {
    Ok((Saml::sp(sp_config()?)?, Saml::idp(idp_config()?)?))
}

fn compatibility_facades() -> Result<(Saml<saml_rs::Sp>, Saml<saml_rs::Idp>), SamlError> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?)
            .slo_endpoint(SloEndpoint::post(SP_SLO_POST)?)
            .validation(SpValidationPolicy::compatibility())
            .build()?,
    )?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
            .validation(IdpValidationPolicy::compatibility())
            .build()?,
    )?;
    Ok((sp, idp))
}

fn descriptors(
    sp: &Saml<saml_rs::Sp>,
    idp: &Saml<saml_rs::Idp>,
) -> Result<(SpDescriptor, IdpDescriptor), SamlError> {
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    Ok((sp_descriptor, idp_descriptor))
}

fn subject() -> Result<LogoutSubject, SamlError> {
    Ok(LogoutSubject::new(
        NameId::new("alice@example.com", None),
        vec![SessionIndex::try_new("_session123")?],
    ))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(
        OffsetDateTime::now_utc(),
        saml_rs::ReplayPolicy::DisabledForCompatibility,
    )
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

fn post_form_value<'a>(
    fields: &'a [FormField],
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    fields
        .iter()
        .find(|field| field.name() == name)
        .map(FormField::value)
        .ok_or_else(|| format!("missing {name}").into())
}

fn redirect_query<Message>(
    outbound: &Outbound<Message>,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = url::Url::parse(outbound.redirect_url()?)?;
    Ok(url.query().unwrap_or_default().to_string())
}

fn outbound_xml<Message>(
    outbound: &Outbound<Message>,
    message_field: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Redirect => {
            let url = url::Url::parse(outbound.redirect_url()?)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == message_field)
                .ok_or("missing SAML message")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                encoded.as_ref(),
            )?)?)?)
        }
        Binding::Post | Binding::SimpleSign => {
            Ok(String::from_utf8(base64_decode(&outbound.raw_context().context)?)?)
        }
        Binding::Artifact => Err("artifact binding is unsupported".into()),
    }
}

struct SloExchange {
    sp: Saml<saml_rs::Sp>,
    idp: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
    pending: PendingLogoutRequest,
    received: Received<LogoutRequest>,
    response_fields: Vec<FormField>,
}

fn sp_started_exchange() -> Result<SloExchange, SamlError> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("logout-state".to_string()))?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state.clone()),
    )?;
    assert_eq!(started.outbound.raw_context().request_type, "SAMLRequest");

    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;
    assert_eq!(received.message().issuer().as_str(), SP_ENTITY_ID);
    assert_eq!(
        received.message().name_id().map(NameId::value),
        Some("alice@example.com")
    );
    assert_eq!(received.message().session_indexes().len(), 1);
    assert!(!received.message().raw_flow().saml_content.is_empty());

    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().relay_state(relay_state),
    )?;
    assert_eq!(response.raw_context().request_type, "SAMLResponse");
    let response_fields = post_fields(&response)?;

    Ok(SloExchange {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
        pending: started.pending,
        received,
        response_fields,
    })
}

fn value_str(value: &str) -> Value {
    Value::Str(value.to_string())
}

fn value_object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn sso_session() -> Result<SsoSession, SamlError> {
    SsoSession::try_from(FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "response",
                value_object(vec![("id", value_str("_response123"))]),
            ),
            (
                "assertion",
                value_object(vec![("id", value_str("_assertion123"))]),
            ),
            ("issuer", value_str(IDP_ENTITY_ID)),
            ("nameID", value_str("alice@example.com")),
            (
                "sessionIndex",
                value_object(vec![
                    ("sessionIndex", value_str("_session123")),
                    ("authnInstant", value_str("2026-07-04T12:00:00Z")),
                ]),
            ),
        ]),
    })
}

#[test]
fn typed_slo_subject_can_come_from_sso_session() -> Result<(), Box<dyn std::error::Error>> {
    let session = sso_session()?;
    let subject = session.logout_subject().ok_or("missing logout subject")?;

    assert_eq!(subject.name_id().value(), "alice@example.com");
    assert_eq!(subject.session_indexes()[0].as_str(), "_session123");
    Ok(())
}

#[test]
fn typed_facade_starts_slo_redirect() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::redirect())?;

    let redirect_url = started.outbound.redirect_url()?;
    assert!(redirect_url.starts_with(IDP_SLO_REDIRECT));
    assert_eq!(started.pending.id(), started.outbound.id());
    assert_eq!(started.pending.request_binding(), LogoutBinding::Redirect);
    assert_eq!(started.pending.peer_entity_id().as_str(), IDP_ENTITY_ID);
    Ok(())
}

#[test]
fn typed_slo_logout_request_session_index_follows_subject() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let with_session = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let with_session_xml = outbound_xml(&with_session.outbound, "SAMLRequest")?;
    assert!(with_session_xml.contains("<samlp:SessionIndex>_session123</samlp:SessionIndex>"));

    let without_session = sp.start_slo(
        &idp_descriptor,
        LogoutSubject::from_name_id(NameId::new("alice@example.com", None)),
        StartSlo::post(),
    )?;
    let without_session_xml = outbound_xml(&without_session.outbound, "SAMLRequest")?;
    assert!(!without_session_xml.contains("SessionIndex"));
    Ok(())
}

#[test]
fn typed_slo_start_and_response_bindings_use_peer_endpoints(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let redirect = sp.start_slo(&idp_descriptor, subject()?, StartSlo::redirect())?;
    assert!(redirect.outbound.redirect_url()?.starts_with(IDP_SLO_REDIRECT));
    assert_eq!(redirect.pending.request_binding(), LogoutBinding::Redirect);

    let post = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    assert_eq!(post.outbound.post_form()?.action().as_str(), IDP_SLO_POST);
    assert_eq!(post.pending.request_binding(), LogoutBinding::Post);

    let simple_sign = sp.start_slo(&idp_descriptor, subject()?, StartSlo::simple_sign())?;
    let simple_sign_form = simple_sign.outbound.post_form()?;
    assert_eq!(simple_sign_form.action().as_str(), IDP_SLO_SIMPLESIGN);
    assert!(simple_sign_form.value("SigAlg").is_some());
    assert!(simple_sign_form.value("Signature").is_some());
    assert_eq!(
        simple_sign.pending.request_binding(),
        LogoutBinding::SimpleSign
    );

    let exchange = sp_started_exchange()?;
    let redirect_response =
        exchange
            .idp
            .respond_slo(&sp_descriptor, &exchange.received, RespondSlo::redirect())?;
    assert!(redirect_response
        .redirect_url()?
        .starts_with(SP_SLO_REDIRECT));

    let post_response =
        exchange
            .idp
            .respond_slo(&sp_descriptor, &exchange.received, RespondSlo::post())?;
    assert_eq!(post_response.post_form()?.action().as_str(), SP_SLO_POST);

    let simple_sign_response = exchange.idp.respond_slo(
        &sp_descriptor,
        &exchange.received,
        RespondSlo::simple_sign(),
    )?;
    let simple_sign_response_form = simple_sign_response.post_form()?;
    assert_eq!(
        simple_sign_response_form.action().as_str(),
        SP_SLO_SIMPLESIGN
    );
    assert!(simple_sign_response_form.value("SigAlg").is_some());
    assert!(simple_sign_response_form.value("Signature").is_some());
    Ok(())
}

#[test]
fn typed_slo_rejects_peer_without_requested_logout_binding(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::strict())
            .build()?,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    match sp.start_slo(&idp_descriptor, subject()?, StartSlo::redirect()) {
        Err(SamlError::MissingMetadata(field)) => {
            assert_eq!(field, "SingleLogoutService");
            Ok(())
        }
        other => Err(format!("expected MissingMetadata, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_runs_sp_initiated_slo() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;

    let completed = exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    )?;

    assert_eq!(completed.peer_entity_id().as_str(), IDP_ENTITY_ID);
    assert_eq!(
        completed.status(),
        Some(saml_rs::constants::status_code::SUCCESS)
    );
    let response = completed.response().ok_or("missing logout response")?;
    assert_eq!(response.in_response_to(), Some(exchange.pending.id()));
    assert!(!completed
        .raw_flow()
        .ok_or("missing raw flow")?
        .saml_content
        .is_empty());
    assert_eq!(exchange.received.message().id(), exchange.pending.id());
    assert_eq!(exchange.sp_descriptor.entity_id().as_str(), SP_ENTITY_ID);
    assert_eq!(
        exchange
            .idp
            .raw_identity_provider()
            .metadata
            .get_entity_id(),
        Some(IDP_ENTITY_ID)
    );
    Ok(())
}

#[test]
fn typed_facade_start_slo_renders_multiple_session_indexes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let subject = LogoutSubject::new(
        NameId::new("alice@example.com", None),
        vec![
            SessionIndex::try_new("_session123")?,
            SessionIndex::try_new("_session456")?,
        ],
    );

    let started = sp.start_slo(&idp_descriptor, subject, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;

    assert_eq!(
        received
            .message()
            .session_indexes()
            .iter()
            .map(SessionIndex::as_str)
            .collect::<Vec<_>>(),
        vec!["_session123", "_session456"]
    );
    Ok(())
}

#[test]
fn typed_facade_runs_idp_initiated_slo() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("idp-logout".to_string()))?;
    let started = idp.start_slo(
        &sp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state.clone()),
    )?;

    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = sp.receive_slo(&idp_descriptor, request_input, validation())?;
    assert_eq!(received.message().issuer().as_str(), IDP_ENTITY_ID);

    let response = sp.respond_slo(
        &idp_descriptor,
        &received,
        RespondSlo::post().relay_state(relay_state),
    )?;
    let completed = idp.finish_slo(
        &sp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    )?;

    assert_eq!(completed.peer_entity_id().as_str(), SP_ENTITY_ID);
    assert_eq!(
        completed
            .response()
            .and_then(LogoutResponse::in_response_to),
        Some(started.pending.id())
    );
    Ok(())
}

#[test]
fn typed_facade_rejects_slo_pending_peer_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let other_idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new("https://other-idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::strict())
            .build()?,
    )?;
    let other_descriptor = IdpDescriptor::from_metadata_xml(
        other_idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    match exchange.sp.finish_slo(
        &other_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, IDP_ENTITY_ID);
            assert_eq!(
                actual.as_deref(),
                Some("https://other-idp.example.com/metadata")
            );
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_slo_response_binding_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let pending = PendingLogoutRequest::try_new(
        exchange.pending.id().clone(),
        exchange.pending.relay_state().clone(),
        LogoutBinding::SimpleSign,
        exchange.pending.peer_entity_id().clone(),
    )?;

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::UnsupportedBinding { binding }) => {
            assert_eq!(binding, saml_rs::raw::Binding::Post);
            Ok(())
        }
        other => Err(format!("expected UnsupportedBinding, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_slo_relay_state_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let mut exchange = sp_started_exchange()?;
    for field in &mut exchange.response_fields {
        if field.name() == "RelayState" {
            *field = FormField::new("RelayState", "other-logout");
        }
    }

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(
                expected,
                RelayStateParam::try_from_option(Some("logout-state".to_string()))?
            );
            assert_eq!(
                actual,
                RelayStateParam::try_from_option(Some("other-logout".to_string()))?
            );
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_duplicate_redirect_relay_state_on_finish_slo(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("logout-state".to_string()))?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::redirect().relay_state(relay_state.clone()),
    )?;
    let received = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::redirect(redirect_query(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::redirect().relay_state(relay_state),
    )?;
    let duplicate_query = format!(
        "{}&RelayState=other-logout-state",
        redirect_query(&response)?
    );

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::redirect(duplicate_query),
        validation(),
    ) {
        Err(SamlError::Invalid(message)) => {
            assert!(message.contains("duplicate RelayState"));
            Ok(())
        }
        other => Err(format!("expected Invalid, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_receive_slo_rejects_destination_mismatch() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = idp.start_slo(&sp_descriptor, subject()?, StartSlo::post())?;
    let mut fields = post_fields(&started.outbound)?;
    let request = post_form_value(&fields, "SAMLRequest")?.to_string();
    let xml = String::from_utf8(base64_decode(&request)?)?.replace(
        &format!("Destination=\"{SP_SLO_POST}\""),
        "Destination=\"https://sp.example.com/slo/wrong\"",
    );
    for field in &mut fields {
        if field.name() == "SAMLRequest" {
            *field = FormField::new("SAMLRequest", base64_encode(xml.as_bytes()));
        }
    }

    match sp.receive_slo(
        &idp_descriptor,
        BrowserInput::<LogoutRequest>::post(fields),
        validation(),
    ) {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, SP_SLO_POST);
            assert_eq!(actual.as_deref(), Some("https://sp.example.com/slo/wrong"));
            Ok(())
        }
        other => Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_finish_slo_rejects_destination_mismatch() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let received = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let response = idp.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
    let mut fields = post_fields(&response)?;
    let response = post_form_value(&fields, "SAMLResponse")?.to_string();
    let xml = String::from_utf8(base64_decode(&response)?)?.replace(
        &format!("Destination=\"{SP_SLO_POST}\""),
        "Destination=\"https://sp.example.com/slo/wrong\"",
    );
    for field in &mut fields {
        if field.name() == "SAMLResponse" {
            *field = FormField::new("SAMLResponse", base64_encode(xml.as_bytes()));
        }
    }

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(fields),
        validation(),
    ) {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, SP_SLO_POST);
            assert_eq!(actual.as_deref(), Some("https://sp.example.com/slo/wrong"));
            Ok(())
        }
        other => Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_slo_wrong_pending_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let mut snapshot: PendingSnapshot<LogoutRequest> = exchange.pending.snapshot();
    snapshot.id = "_different_logout".to_string();
    let wrong_pending = PendingLogoutRequest::from_snapshot(snapshot)?;

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &wrong_pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some("_different_logout"));
            assert_eq!(actual.as_deref(), Some(exchange.pending.id().as_str()));
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_unexpected_slo_relay_state() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().relay_state(RelayStateParam::try_from_option(Some(
            "unexpected".to_string(),
        ))?),
    )?;

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(expected, RelayStateParam::Absent);
            assert_eq!(
                actual,
                RelayStateParam::try_from_option(Some("unexpected".to_string()))?
            );
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_custom_logout_response_in_response_to_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(bad_template_idp_config()?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;

    match idp.respond_slo(&sp_descriptor, &received, RespondSlo::post()) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some(received.message().id().as_str()));
            assert_eq!(actual.as_deref(), Some("_wrong"));
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_allows_explicit_unsigned_slo_for_compatibility(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().signing(LogoutSigning::DoNotSignForCompatibility),
    )?;

    assert!(started.outbound.post_form()?.value("SAMLRequest").is_some());
    Ok(())
}
