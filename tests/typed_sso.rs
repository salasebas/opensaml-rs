#![cfg(feature = "crypto-bergshamra")]

use std::collections::HashMap;

use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, Outbound,
    PendingAuthnRequest, PendingSnapshot, PrivateKeyPem, Received, RelayStateParam, ReplayCache,
    ReplayKey, ReplayPolicy, RespondSso, Saml, SamlError, SamlValidationContext, SpConfig,
    SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse, SsoResponseBinding, StartSso,
    Subject,
};
use time::OffsetDateTime;

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_ACS_SIMPLESIGN: &str = "https://sp.example.com/acs/simple-sign";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

#[derive(Default)]
struct MemoryReplayCache {
    seen: HashMap<String, OffsetDateTime>,
}

impl ReplayCache for MemoryReplayCache {
    fn check_and_store(
        &mut self,
        key: ReplayKey,
        expires_at: OffsetDateTime,
    ) -> Result<(), SamlError> {
        let cache_key = key.cache_key();
        if self.seen.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        self.seen.insert(cache_key, expires_at);
        Ok(())
    }
}

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

fn sp_config() -> Result<SpConfig, SamlError> {
    SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
        .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(SpValidationPolicy::strict())
        .build()
}

fn idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::strict())
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

fn subject() -> Subject {
    Subject::new(NameId::new("alice@example.com", None), Vec::new())
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(
        OffsetDateTime::now_utc(),
        ReplayPolicy::DisabledForCompatibility,
    )
}

fn validation_with_cache(cache: &mut dyn ReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(OffsetDateTime::now_utc(), ReplayPolicy::RequireCache(cache))
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

struct SsoExchange {
    sp: Saml<saml_rs::Sp>,
    idp: Saml<saml_rs::Idp>,
    sp_descriptor: SpDescriptor,
    idp_descriptor: IdpDescriptor,
    pending: PendingAuthnRequest,
    received: Received<AuthnRequest>,
    response_fields: Vec<FormField>,
}

fn start_receive_respond_with(
    start_options: StartSso,
    respond_options: RespondSso,
) -> Result<SsoExchange, SamlError> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, start_options)?;
    assert_eq!(started.outbound.raw_context().request_type, "SAMLRequest");

    let request_input = BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_sso(&sp_descriptor, request_input, validation())?;
    assert_eq!(received.message().issuer().as_str(), SP_ENTITY_ID);
    assert!(!received.message().raw_flow().saml_content.is_empty());

    let response = idp.respond_sso(&sp_descriptor, &received, subject(), respond_options)?;
    assert_eq!(response.raw_context().request_type, "SAMLResponse");
    let response_fields = post_fields(&response)?;

    Ok(SsoExchange {
        sp,
        idp,
        sp_descriptor,
        idp_descriptor,
        pending: started.pending,
        received,
        response_fields,
    })
}

fn start_receive_respond() -> Result<SsoExchange, SamlError> {
    let relay_state = RelayStateParam::try_from_option(Some("state-123".to_string()))?;
    start_receive_respond_with(
        StartSso::post().relay_state(relay_state.clone()),
        RespondSso::post().relay_state(relay_state),
    )
}

#[test]
fn typed_facade_start_sso_redirect_returns_url() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::redirect())?;

    let redirect_url = started.outbound.redirect_url()?;
    assert!(redirect_url.starts_with(IDP_SSO_REDIRECT));
    assert_eq!(started.pending.request_id(), started.outbound.id());
    assert_eq!(
        started.pending.request_binding(),
        Some(saml_rs::SsoRequestBinding::Redirect)
    );
    Ok(())
}

#[test]
fn typed_facade_runs_sp_initiated_sso() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;

    let session = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation(),
    )?;

    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
    assert_eq!(
        session.in_response_to(),
        Some(exchange.pending.request_id())
    );
    assert_eq!(session.name_id().value(), "alice@example.com");
    assert!(!session.raw_flow().saml_content.is_empty());
    assert_eq!(
        exchange.received.message().id(),
        exchange.pending.request_id()
    );
    assert_eq!(
        exchange
            .idp
            .raw_identity_provider()
            .metadata
            .get_entity_id(),
        Some(IDP_ENTITY_ID)
    );
    assert_eq!(exchange.sp_descriptor.entity_id().as_str(), SP_ENTITY_ID);
    Ok(())
}

#[test]
fn typed_facade_rejects_pending_peer_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let other_idp = Saml::idp(
        IdpConfig::builder(EntityId::try_new("https://other-idp.example.com/metadata")?)
            .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
            .credentials(credentials())
            .validation(IdpValidationPolicy::strict())
            .build()?,
    )?;
    let other_descriptor = IdpDescriptor::from_metadata_xml(
        other_idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    match exchange.sp.finish_sso(
        &other_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
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
fn typed_facade_rejects_response_binding_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let pending = PendingAuthnRequest::try_new(
        exchange.pending.request_id().clone(),
        exchange.pending.relay_state().clone(),
        AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?,
        SsoResponseBinding::SimpleSign,
        exchange.pending.idp_entity_id().clone(),
    )?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
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
fn typed_facade_rejects_relay_state_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let mut exchange = start_receive_respond()?;
    for field in &mut exchange.response_fields {
        if field.name() == "RelayState" {
            *field = FormField::new("RelayState", "other-state");
        }
    }

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(
                expected,
                RelayStateParam::try_from_option(Some("state-123".to_string()))?
            );
            assert_eq!(
                actual,
                RelayStateParam::try_from_option(Some("other-state".to_string()))?
            );
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_unexpected_relay_state() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond_with(
        StartSso::post(),
        RespondSso::post().relay_state(RelayStateParam::try_from_option(Some(
            "unexpected".to_string(),
        ))?),
    )?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
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
fn typed_facade_rejects_wrong_pending_request_id() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let mut snapshot: PendingSnapshot<AuthnRequest> = exchange.pending.snapshot();
    snapshot.id = "_different_request".to_string();
    let wrong_pending = PendingAuthnRequest::from_snapshot(snapshot)?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &wrong_pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected.as_deref(), Some("_different_request"));
            assert_eq!(
                actual.as_deref(),
                Some(exchange.pending.request_id().as_str())
            );
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_solicited_response_as_unsolicited() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = start_receive_respond()?;

    match exchange.sp.accept_unsolicited_sso(
        &exchange.idp_descriptor,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::InResponseToMismatch { expected, actual }) => {
            assert_eq!(expected, None);
            assert_eq!(
                actual.as_deref(),
                Some(exchange.pending.request_id().as_str())
            );
            Ok(())
        }
        other => Err(format!("expected InResponseToMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_checks_replay_cache() -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let mut cache = MemoryReplayCache::default();

    let first = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    assert!(!first.replay_keys().is_empty());

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert!(key.starts_with("response_id:"));
            Ok(())
        }
        other => Err(format!("expected ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_accepts_unsolicited_sso_explicitly() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response = idp.initiate_sso(
        &sp_descriptor,
        subject(),
        RespondSso::post().relay_state(RelayStateParam::present_empty()),
    )?;
    let session = sp.accept_unsolicited_sso(
        &idp_descriptor,
        BrowserInput::<SsoResponse>::post(post_fields(&response)?),
        validation(),
    )?;

    assert_eq!(session.issuer().as_str(), IDP_ENTITY_ID);
    assert_eq!(session.in_response_to(), None);
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}
