#![cfg(feature = "crypto-bergshamra")]

use saml_rs::raw::FlowResult;
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
