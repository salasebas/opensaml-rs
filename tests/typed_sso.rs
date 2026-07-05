#![cfg(feature = "crypto-bergshamra")]

use std::collections::HashMap;

use saml_rs::binding::{base64_decode, deflate_raw_decode};
use saml_rs::error::TimeWindowField;
use saml_rs::raw::Binding;
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId, NameIdFormat,
    Outbound, PendingAuthnRequest, PendingSnapshot, PrivateKeyPem, Received, RelayStateParam,
    ReplayCache, ReplayKey, ReplayPolicy, RespondSso, Saml, SamlError, SamlValidationContext,
    SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse, SsoResponseBinding,
    StartSso, Subject, TemplatePolicy,
};
use time::{Duration, OffsetDateTime};

const SP_ENTITY_ID: &str = "https://sp.example.com/metadata";
const IDP_ENTITY_ID: &str = "https://idp.example.com/metadata";
const SP_ACS_POST: &str = "https://sp.example.com/acs/post";
const SP_ACS_SIMPLESIGN: &str = "https://sp.example.com/acs/simple-sign";
const IDP_SSO_POST: &str = "https://idp.example.com/sso/post";
const IDP_SSO_REDIRECT: &str = "https://idp.example.com/sso/redirect";
const IDP_SSO_SIMPLESIGN: &str = "https://idp.example.com/sso/simple-sign";

const HOSTILE_SP_ENTITY_ID: &str = concat!(
    "https://sp.example.com/metadata",
    "</saml:Issuer>",
    "<evil:Injected>issuer</evil:Injected>",
    "<saml:Issuer>"
);
const HOSTILE_IDP_SSO_DESTINATION: &str = concat!(
    "https://idp.example.com/sso?",
    "continue=%3Cevil:Injected%3Edestination%3C%2Fevil:Injected%3E",
    "&quote=%22"
);
const HOSTILE_ACS_URL: &str = concat!(
    "https://sp.example.com/acs?",
    "continue=%3Cevil:Injected%3Eacs%3C%2Fevil:Injected%3E",
    "&quote=%22"
);
const HOSTILE_NAME_ID_FORMAT: &str = concat!(
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\"/>",
    "<evil:Injected>nameid</evil:Injected>",
    "<samlp:NameIDPolicy Format=\""
);

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
        .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::strict())
        .build()
}

fn hostile_sp_config() -> Result<SpConfig, SamlError> {
    SpConfig::builder(EntityId::try_new(HOSTILE_SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(HOSTILE_ACS_URL)?.mark_default())
        .credentials(credentials())
        .validation(SpValidationPolicy::strict())
        .name_id_format(NameIdFormat::Custom(HOSTILE_NAME_ID_FORMAT.to_string()))
        .build()
}

fn hostile_idp_config() -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(HOSTILE_IDP_SSO_DESTINATION)?)
        .sso_endpoint(SsoEndpoint::redirect(HOSTILE_IDP_SSO_DESTINATION)?)
        .sso_endpoint(SsoEndpoint::simple_sign(HOSTILE_IDP_SSO_DESTINATION)?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::strict())
        .build()
}

fn facades() -> Result<(Saml<saml_rs::Sp>, Saml<saml_rs::Idp>), SamlError> {
    Ok((Saml::sp(sp_config()?)?, Saml::idp(idp_config()?)?))
}

fn hostile_facades() -> Result<(Saml<saml_rs::Sp>, Saml<saml_rs::Idp>), SamlError> {
    Ok((
        Saml::sp(hostile_sp_config()?)?,
        Saml::idp(hostile_idp_config()?)?,
    ))
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

fn form_value<'a>(fields: &'a [FormField], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|field| field.name() == name)
        .map(FormField::value)
}

fn authn_request_xml(
    outbound: &Outbound<AuthnRequest>,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Redirect => {
            let url = url::Url::parse(outbound.redirect_url()?)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
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

fn authn_request_input(
    outbound: &Outbound<AuthnRequest>,
) -> Result<BrowserInput<AuthnRequest>, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Redirect => {
            let url = url::Url::parse(outbound.redirect_url()?)?;
            Ok(BrowserInput::<AuthnRequest>::redirect(
                url.query().unwrap_or_default(),
            ))
        }
        Binding::Post => Ok(BrowserInput::<AuthnRequest>::post(post_fields(outbound)?)),
        Binding::SimpleSign => Ok(BrowserInput::<AuthnRequest>::simple_sign(post_fields(
            outbound,
        )?)),
        Binding::Artifact => Err("artifact binding is unsupported".into()),
    }
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
fn typed_builder_authn_request_escapes_hostile_values_for_all_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = hostile_facades()?;
    let sp_descriptor = SpDescriptor::from_metadata_xml_for(
        EntityId::try_new(HOSTILE_SP_ENTITY_ID)?,
        sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    for start in [
        StartSso::redirect(),
        StartSso::post(),
        StartSso::simple_sign(),
    ] {
        let relay_state = RelayStateParam::try_from_option(Some("typed-state".to_string()))?;
        let started = sp.start_sso(
            &idp_descriptor,
            start.force_authn(true).relay_state(relay_state),
        )?;
        let xml = authn_request_xml(&started.outbound)?;

        assert_eq!(xml.matches("<samlp:AuthnRequest").count(), 1);
        assert_eq!(xml.matches("<saml:Issuer").count(), 1);
        assert!(!xml.contains("<evil:Injected"));
        assert!(!xml.contains("</evil:Injected"));
        assert!(xml.contains("ForceAuthn=\"true\""));
        assert!(xml.contains("issuer&lt;/evil:Injected"));
        assert!(xml.contains(
            "Destination=\"https://idp.example.com/sso?continue=%3Cevil:Injected%3Edestination%3C%2Fevil:Injected%3E&amp;quote=%22\""
        ));
        assert!(xml.contains(
            "AssertionConsumerServiceURL=\"https://sp.example.com/acs?continue=%3Cevil:Injected%3Eacs%3C%2Fevil:Injected%3E&amp;quote=%22\""
        ));
        assert!(
            xml.contains("Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress&quot;/")
        );
        assert!(xml.contains("nameid&lt;/evil:Injected"));

        let received = idp.receive_sso(
            &sp_descriptor,
            authn_request_input(&started.outbound)?,
            validation(),
        )?;
        assert_eq!(received.message().issuer().as_str(), HOSTILE_SP_ENTITY_ID);
        assert_eq!(
            started.outbound.relay_state().map(|state| state.as_str()),
            Some("typed-state")
        );
    }
    Ok(())
}

#[test]
fn typed_builder_authn_request_options_render_force_authn_and_acs_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for force_authn in [Some(true), Some(false), None] {
        let mut options = StartSso::post();
        if let Some(force_authn) = force_authn {
            options = options.force_authn(force_authn);
        }
        let xml = authn_request_xml(&sp.start_sso(&idp_descriptor, options)?.outbound)?;
        match force_authn {
            Some(force_authn) => assert!(xml.contains(&format!("ForceAuthn=\"{force_authn}\""))),
            None => assert!(!xml.contains("ForceAuthn=")),
        }
    }

    let xml = authn_request_xml(
        &sp.start_sso(
            &idp_descriptor,
            StartSso::post()
                .response_binding(SsoResponseBinding::SimpleSign)
                .acs_index(1),
        )?
        .outbound,
    )?;
    assert!(xml.contains("AssertionConsumerServiceIndex=\"1\""));
    assert!(!xml.contains("AssertionConsumerServiceURL="));
    assert!(!xml.contains("ProtocolBinding="));
    Ok(())
}

#[test]
fn typed_detached_authn_requests_parse_with_relay_state() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    for start in [StartSso::redirect(), StartSso::simple_sign()] {
        let relay_state = RelayStateParam::try_from_option(Some("signed-state".to_string()))?;
        let started = sp.start_sso(&idp_descriptor, start.relay_state(relay_state))?;
        let received = idp.receive_sso(
            &sp_descriptor,
            authn_request_input(&started.outbound)?,
            validation(),
        )?;

        assert_eq!(received.message().id(), started.pending.request_id());
        assert_eq!(
            started.outbound.relay_state().map(|state| state.as_str()),
            Some("signed-state")
        );
    }
    Ok(())
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
fn typed_facade_rejects_response_when_pending_acs_was_mutated(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = start_receive_respond()?;
    let mut snapshot: PendingSnapshot<AuthnRequest> = exchange.pending.snapshot();
    snapshot.acs_url = "https://sp.example.com/acs/other".to_string();
    let wrong_pending = PendingAuthnRequest::from_snapshot(snapshot)?;

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &wrong_pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, "https://sp.example.com/acs/other");
            assert_eq!(actual.as_deref(), Some(SP_ACS_POST));
            Ok(())
        }
        other => Err(format!("expected DestinationMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_indexed_non_first_acs_finishes_successfully(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post().acs_index(1))?;
    assert_eq!(
        started.pending.response_binding(),
        SsoResponseBinding::SimpleSign
    );
    assert_eq!(started.pending.acs().location().as_str(), SP_ACS_SIMPLESIGN);

    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(received.message().acs_index(), Some(1));
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::simple_sign(),
    )?;
    let response_fields = post_fields(&response)?;
    assert_eq!(response.post_form()?.action().as_str(), SP_ACS_SIMPLESIGN);

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::simple_sign(response_fields),
        validation(),
    )?;

    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn typed_facade_rejects_explicit_response_binding_conflict_with_acs_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    match sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .acs_index(1)
            .response_binding(SsoResponseBinding::Post),
    ) {
        Err(SamlError::Invalid(message)) => {
            assert!(message.contains("conflicts with ACS index"));
            Ok(())
        }
        other => Err(format!("expected Invalid conflict, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_absent_relay_state_suppresses_raw_default() -> Result<(), Box<dyn std::error::Error>>
{
    let sp_config = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
        .credentials(credentials())
        .validation(SpValidationPolicy::strict())
        .templates(TemplatePolicy {
            relay_state: "legacy-default".to_string(),
            ..TemplatePolicy::default()
        })
        .build()?;
    let sp = Saml::sp(sp_config)?;
    let idp = Saml::idp(idp_config()?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    assert_eq!(started.outbound.relay_state(), None);
    assert_eq!(
        form_value(post_fields(&started.outbound)?.as_slice(), "RelayState"),
        None
    );

    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(received.relay_state(), &RelayStateParam::Absent);
    let response = idp.respond_sso(&sp_descriptor, &received, subject(), RespondSso::post())?;
    let response_fields = post_fields(&response)?;
    assert_eq!(form_value(&response_fields, "RelayState"), None);

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response_fields),
        validation(),
    )?;

    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn typed_facade_respond_sso_echoes_request_relay_state_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let relay_state = RelayStateParam::try_from_option(Some("state-echo".to_string()))?;
    let exchange = start_receive_respond_with(
        StartSso::post().relay_state(relay_state.clone()),
        RespondSso::post(),
    )?;

    assert_eq!(exchange.received.relay_state(), &relay_state);
    assert_eq!(
        form_value(&exchange.response_fields, "RelayState"),
        Some("state-echo")
    );
    let session = exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation(),
    )?;
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn typed_facade_respond_sso_relay_state_override_still_wins(
) -> Result<(), Box<dyn std::error::Error>> {
    let override_state = RelayStateParam::try_from_option(Some("override".to_string()))?;
    let exchange = start_receive_respond_with(
        StartSso::post().relay_state(RelayStateParam::try_from_option(Some(
            "request-state".to_string(),
        ))?),
        RespondSso::post().relay_state(override_state),
    )?;

    assert_eq!(
        form_value(&exchange.response_fields, "RelayState"),
        Some("override")
    );
    Ok(())
}

#[test]
fn typed_facade_respond_sso_rejects_wrong_sp_descriptor() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = start_receive_respond()?;
    let other_sp = Saml::sp(
        SpConfig::builder(EntityId::try_new("https://other-sp.example.com/metadata")?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?)
            .credentials(credentials())
            .validation(SpValidationPolicy::strict())
            .build()?,
    )?;
    let other_descriptor = SpDescriptor::from_metadata_xml(
        other_sp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    match exchange.idp.respond_sso(
        &other_descriptor,
        &exchange.received,
        subject(),
        RespondSso::post(),
    ) {
        Err(SamlError::IssuerMismatch { expected, actual }) => {
            assert_eq!(expected, SP_ENTITY_ID);
            assert_eq!(
                actual.as_deref(),
                Some("https://other-sp.example.com/metadata")
            );
            Ok(())
        }
        other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_post_response_when_request_demands_simplesign(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(
        received.message().protocol_binding(),
        Some(SsoResponseBinding::SimpleSign)
    );

    match idp.respond_sso(&sp_descriptor, &received, subject(), RespondSso::post()) {
        Err(SamlError::Invalid(message)) => {
            assert!(message.contains("ProtocolBinding"));
            Ok(())
        }
        other => Err(format!("expected Invalid ProtocolBinding conflict, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_response_targets_requested_acs_url() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    assert_eq!(
        received.message().acs_url().map(|url| url.as_str()),
        Some(SP_ACS_SIMPLESIGN)
    );

    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::simple_sign(),
    )?;

    assert_eq!(response.post_form()?.action().as_str(), SP_ACS_SIMPLESIGN);
    Ok(())
}

#[test]
fn typed_facade_duplicate_response_relay_state_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut exchange = start_receive_respond()?;
    exchange
        .response_fields
        .push(FormField::new("RelayState", "duplicate"));

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation(),
    ) {
        Err(SamlError::Invalid(message)) => {
            assert!(message.contains("RelayState"));
            Ok(())
        }
        other => Err(format!("expected Invalid duplicate RelayState, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_authn_request_replay_cache_rejects_duplicate(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let fields = post_fields(&started.outbound)?;
    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::minutes(5);
    let mut cache = MemoryReplayCache::default();

    let first_validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache))
        .with_message_replay_expiration(expires_at);
    idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(fields.clone()),
        first_validation,
    )?;

    let second_validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache))
        .with_message_replay_expiration(expires_at);
    match idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(fields),
        second_validation,
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(
                key,
                format!("request_id:{}", started.pending.request_id().as_str())
            );
            Ok(())
        }
        other => Err(format!("expected ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_authn_request_replay_requires_expiration() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let mut cache = MemoryReplayCache::default();

    match idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        SamlValidationContext::new(
            OffsetDateTime::now_utc(),
            ReplayPolicy::RequireCache(&mut cache),
        ),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::ReplayExpiration);
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration failure, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_preserves_subject_name_id_format() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        validation(),
    )?;
    let subject = Subject::new(
        NameId::new("alice", Some(NameIdFormat::Persistent)),
        Vec::new(),
    );
    let response = idp.respond_sso(&sp_descriptor, &received, subject, RespondSso::post())?;
    let response_fields = post_fields(&response)?;
    let encoded = form_value(&response_fields, "SAMLResponse").ok_or("missing SAMLResponse")?;
    let xml = String::from_utf8(base64_decode(encoded)?)?;
    assert!(xml.contains("Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\""));

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::post(response_fields),
        validation(),
    )?;

    assert_eq!(session.name_id().value(), "alice");
    assert_eq!(session.name_id().format(), Some(&NameIdFormat::Persistent));
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
