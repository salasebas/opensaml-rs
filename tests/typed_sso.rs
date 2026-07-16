#![cfg(feature = "crypto-bergshamra")]

use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use saml_rs::binding::{base64_decode, base64_encode, deflate_raw_decode};
use saml_rs::error::TimeWindowField;
use saml_rs::raw::Binding;
use saml_rs::{
    AcsEndpoint, AuthnRequest, BrowserInput, CertificatePem, Credentials, EntityId, ForceAuthn,
    FormField, IdpConfig, IdpDescriptor, IdpValidationPolicy, MetadataTrustPolicy, NameId,
    NameIdFormat, Outbound, PendingAuthnRequest, PendingSnapshot, PrivateKeyPem, Received,
    RelayStateParam, ReplayCache, ReplayKey, ReplayPolicy, RespondSso, Saml, SamlError,
    SamlValidationContext, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoResponse,
    SsoResponseBinding, StartSso, Subject,
};
use url::Url;

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
    seen: HashMap<String, SystemTime>,
}

impl ReplayCache for MemoryReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
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

fn compatibility_facades() -> Result<(Saml<saml_rs::Sp>, Saml<saml_rs::Idp>), SamlError> {
    let sp = SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.mark_default())
        .acs_endpoint(AcsEndpoint::simple_sign(SP_ACS_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(SpValidationPolicy::compatibility())
        .build()?;
    let idp = IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .sso_endpoint(SsoEndpoint::redirect(IDP_SSO_REDIRECT)?)
        .sso_endpoint(SsoEndpoint::simple_sign(IDP_SSO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::compatibility())
        .build()?;
    Ok((Saml::sp(sp)?, Saml::idp(idp)?))
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
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
}

fn validation_with_cache(cache: &mut dyn ReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
        .with_replay_retention(Duration::from_secs(5 * 60))
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

fn authn_request_xml(
    outbound: &Outbound<AuthnRequest>,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Redirect => {
            let url = Url::parse(outbound.redirect_url()?)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .ok_or("missing SAMLRequest")?;
            Ok(String::from_utf8(deflate_raw_decode(&base64_decode(
                encoded.as_ref(),
            )?)?)?)
        }
        Binding::Post | Binding::SimpleSign => Ok(String::from_utf8(base64_decode(
            &outbound.raw_context().context,
        )?)?),
        Binding::Artifact => Err("artifact binding is unsupported".into()),
    }
}

fn authn_request_input(
    outbound: &Outbound<AuthnRequest>,
) -> Result<BrowserInput<AuthnRequest>, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Redirect => {
            let url = Url::parse(outbound.redirect_url()?)?;
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

fn post_authn_request_input_with_xml(xml: &str) -> BrowserInput<AuthnRequest> {
    BrowserInput::<AuthnRequest>::post(vec![FormField::new(
        "SAMLRequest",
        base64_encode(xml.as_bytes()),
    )])
}

fn replace_issue_instant(
    xml: &str,
    replacement: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let (before, after) = xml
        .split_once(" IssueInstant=\"")
        .ok_or("missing IssueInstant attribute")?;
    let (_, after) = after
        .split_once('"')
        .ok_or("unterminated IssueInstant attribute")?;
    let replacement = replacement
        .map(|value| format!(" IssueInstant=\"{value}\""))
        .unwrap_or_default();
    Ok(format!("{before}{replacement}{after}"))
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
        StartSso::post().relay_state(relay_state),
        RespondSso::post(),
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
            start
                .force_authn(ForceAuthn::Required)
                .relay_state(relay_state),
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

    for force_authn in [
        Some(ForceAuthn::Required),
        Some(ForceAuthn::NotRequired),
        None,
    ] {
        let mut options = StartSso::post();
        if let Some(force_authn) = force_authn {
            options = options.force_authn(force_authn);
        }
        let xml = authn_request_xml(&sp.start_sso(&idp_descriptor, options)?.outbound)?;
        match force_authn {
            Some(ForceAuthn::Required) => assert!(xml.contains("ForceAuthn=\"true\"")),
            Some(ForceAuthn::NotRequired) => assert!(xml.contains("ForceAuthn=\"false\"")),
            None => assert!(!xml.contains("ForceAuthn=")),
        }
    }

    let xml = authn_request_xml(
        &sp.start_sso(
            &idp_descriptor,
            StartSso::post().assertion_consumer_service_index(1),
        )?
        .outbound,
    )?;
    assert!(xml.contains("AssertionConsumerServiceIndex=\"1\""));
    assert!(!xml.contains("AssertionConsumerServiceURL="));
    assert!(!xml.contains("ProtocolBinding="));
    Ok(())
}

#[test]
fn typed_builder_rejects_acs_index_response_binding_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    match sp.start_sso(
        &idp_descriptor,
        StartSso::post()
            .assertion_consumer_service_index(1)
            .response_binding(SsoResponseBinding::Post),
    ) {
        Err(SamlError::Invalid(message)) => {
            assert!(message.contains("AssertionConsumerServiceIndex binding"));
            Ok(())
        }
        other => Err(format!("expected Invalid ACS binding mismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_unknown_acs_index() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;

    match sp.start_sso(
        &idp_descriptor,
        StartSso::post().assertion_consumer_service_index(99),
    ) {
        Err(SamlError::MissingMetadata(name)) => {
            assert_eq!(name, "AssertionConsumerService");
            Ok(())
        }
        other => Err(format!("expected MissingMetadata, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_honors_custom_acs_index_from_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(
        SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
            .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?.with_index(7))
            .credentials(credentials())
            .validation(SpValidationPolicy::strict())
            .build()?,
    )?;
    let idp = Saml::idp(idp_config()?)?;
    let idp_descriptor = IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(IDP_ENTITY_ID)?,
        idp.metadata_xml(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )?;

    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().assertion_consumer_service_index(7),
    )?;
    let xml = authn_request_xml(&started.outbound)?;

    assert_eq!(started.pending.acs().index(), Some(7));
    assert!(sp.metadata_xml().contains("index=\"7\""));
    assert!(xml.contains("AssertionConsumerServiceIndex=\"7\""));
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
fn typed_facade_rejects_missing_authn_request_issue_instant_in_real_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = replace_issue_instant(&authn_request_xml(&started.outbound)?, None)?;

    match idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&xml),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("missing required unqualified attribute IssueInstant") =>
        {
            Ok(())
        }
        other => {
            Err(format!("expected missing IssueInstant ProtocolProfile, got {other:?}").into())
        }
    }
}

#[test]
fn typed_facade_rejects_malformed_authn_request_issue_instant_in_real_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = replace_issue_instant(
        &authn_request_xml(&started.outbound)?,
        Some("not-an-instant"),
    )?;

    match idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&xml),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            ) =>
        {
            Ok(())
        }
        other => {
            Err(format!("expected malformed IssueInstant ProtocolProfile, got {other:?}").into())
        }
    }
}

#[test]
fn typed_facade_accepts_old_normalized_authn_request_issue_instant_in_real_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = compatibility_facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let xml = replace_issue_instant(
        &authn_request_xml(&started.outbound)?,
        Some(" &#x9;2001-01-01T00:00:00Z&#xA; "),
    )?;
    let received = idp.receive_sso(
        &sp_descriptor,
        post_authn_request_input_with_xml(&xml),
        validation(),
    )?;

    assert_eq!(
        received.message().issue_instant().as_str(),
        "2001-01-01T00:00:00Z"
    );
    Ok(())
}

#[test]
fn typed_facade_receive_sso_checks_authn_request_replay() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let request_fields = post_fields(&started.outbound)?;
    let mut cache = MemoryReplayCache::default();

    let received = idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(request_fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let replay_key = format!("authn_request_id:{}", received.message().id().as_str());
    assert!(cache.seen.contains_key(&replay_key));

    match idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(request_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, replay_key);
            Ok(())
        }
        other => Err(format!("expected AuthnRequest ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_receive_sso_requires_replay_retention_for_authn_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(&idp_descriptor, StartSso::post())?;
    let mut cache = MemoryReplayCache::default();
    let validation =
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache));

    match idp.receive_sso(
        &sp_descriptor,
        BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?),
        validation,
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::ReplayExpiration);
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration error, got {other:?}").into()),
    }
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

    assert_eq!(
        exchange.received.relay_state(),
        &RelayStateParam::try_from_option(Some("state-123".to_string()))?
    );

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
fn typed_facade_runs_simplesign_sso_response_binding() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().response_binding(SsoResponseBinding::SimpleSign),
    )?;
    let request_input = BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_sso(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::simple_sign(),
    )?;
    let response_form = response.post_form()?;
    assert_eq!(response_form.action().as_str(), SP_ACS_SIMPLESIGN);
    assert!(response_form.value("SigAlg").is_some());
    assert!(response_form.value("Signature").is_some());

    let session = sp.finish_sso(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<SsoResponse>::simple_sign(response_form.fields().to_vec()),
        validation(),
    )?;

    assert_eq!(session.in_response_to(), Some(started.pending.request_id()));
    assert_eq!(session.name_id().value(), "alice@example.com");
    Ok(())
}

#[test]
fn typed_facade_persists_indexed_acs_for_response_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_sso(
        &idp_descriptor,
        StartSso::post().assertion_consumer_service_index(1),
    )?;

    assert_eq!(
        started.pending.response_binding(),
        SsoResponseBinding::SimpleSign
    );
    assert_eq!(started.pending.acs().index(), Some(1));
    assert_eq!(started.pending.acs().location().as_str(), SP_ACS_SIMPLESIGN);
    let snapshot = started.pending.snapshot();
    assert_eq!(snapshot.acs_index, Some(1));
    let restored = PendingAuthnRequest::from_snapshot(snapshot)?;
    assert_eq!(restored.acs().index(), Some(1));
    assert_eq!(restored.response_binding(), SsoResponseBinding::SimpleSign);

    let request_input = BrowserInput::<AuthnRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_sso(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_sso(
        &sp_descriptor,
        &received,
        subject(),
        RespondSso::simple_sign(),
    )?;
    let session = sp.finish_sso(
        &idp_descriptor,
        &restored,
        BrowserInput::<SsoResponse>::simple_sign(post_fields(&response)?),
        validation(),
    )?;

    assert_eq!(session.in_response_to(), Some(restored.request_id()));
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
fn typed_facade_rejects_response_with_wrong_sp_descriptor() -> Result<(), Box<dyn std::error::Error>>
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
fn typed_facade_allows_respond_sso_to_suppress_relay_state_echo(
) -> Result<(), Box<dyn std::error::Error>> {
    let relay_state = RelayStateParam::try_from_option(Some("state-123".to_string()))?;
    let exchange = start_receive_respond_with(
        StartSso::post().relay_state(relay_state),
        RespondSso::post().relay_state(RelayStateParam::absent()),
    )?;

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
            assert_eq!(actual, RelayStateParam::Absent);
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_allows_respond_sso_to_override_relay_state_echo(
) -> Result<(), Box<dyn std::error::Error>> {
    let relay_state = RelayStateParam::try_from_option(Some("state-123".to_string()))?;
    let exchange = start_receive_respond_with(
        StartSso::post().relay_state(relay_state),
        RespondSso::post().relay_state(RelayStateParam::try_from_option(Some(
            "override".to_string(),
        ))?),
    )?;

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
                RelayStateParam::try_from_option(Some("override".to_string()))?
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
    let replay_keys: Vec<_> = first
        .replay_keys()
        .into_iter()
        .map(|key| key.cache_key())
        .collect();
    assert!(replay_keys
        .iter()
        .any(|key| key.starts_with("response_id:")));
    assert!(replay_keys
        .iter()
        .any(|key| key.starts_with("assertion_id:")));

    match exchange.sp.finish_sso(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<SsoResponse>::post(exchange.response_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert!(replay_keys.contains(&key));
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
