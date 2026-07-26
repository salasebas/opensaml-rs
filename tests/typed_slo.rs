#![cfg(feature = "crypto-bergshamra")]

use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use saml_rs::binding::{
    append_signature, base64_decode, base64_encode, build_redirect_octet, deflate_raw_decode,
};
use saml_rs::constants::{signature_algorithm::RSA_SHA256, ParserType};
use saml_rs::crypto::{
    construct_message_signature, construct_saml_signature, keys::load_private_key,
};
use saml_rs::error::TimeWindowField;
use saml_rs::raw::{Binding, FlowResult};
use saml_rs::util::Value;
use saml_rs::{
    AcsEndpoint, BrowserInput, CertificatePem, ClockSkew, Credentials, EntityId, FormField,
    IdpConfig, IdpDescriptor, IdpValidationPolicy, LogoutBinding, LogoutCompleted, LogoutRequest,
    LogoutResponse, LogoutSigning, LogoutSubject, MetadataTrustPolicy, NameId, Outbound,
    PendingLogoutRequest, PendingSnapshot, PrivateKeyPem, Received, RelayStateParam, ReplayCache,
    ReplayKey, ReplayPolicy, RespondSlo, Saml, SamlError, SamlValidationContext, SessionIndex,
    SloEndpoint, SpConfig, SpDescriptor, SpValidationPolicy, SsoEndpoint, SsoSession, StartSlo,
    TemplatePolicy,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

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

const ALL_LOGOUT_BINDINGS: [LogoutBinding; 3] = [
    LogoutBinding::Post,
    LogoutBinding::Redirect,
    LogoutBinding::SimpleSign,
];
const UNSIGNED_COMPATIBILITY_BINDINGS: [LogoutBinding; 2] =
    [LogoutBinding::Post, LogoutBinding::Redirect];

const PRIVKEY: &str = include_str!("fixtures/key/sp_privkey.pem");
const CERT: &str = include_str!("fixtures/key/sp_signing_cert.cer");

#[derive(Debug, Clone, Copy)]
enum LocalSloRole {
    Sp,
    Idp,
}

const LOCAL_SLO_ROLES: [LocalSloRole; 2] = [LocalSloRole::Sp, LocalSloRole::Idp];

struct SloEndpointSet {
    post: &'static str,
    redirect: &'static str,
    simple_sign: &'static str,
}

impl SloEndpointSet {
    fn for_binding(&self, binding: LogoutBinding) -> &'static str {
        match binding {
            LogoutBinding::Post => self.post,
            LogoutBinding::Redirect => self.redirect,
            LogoutBinding::SimpleSign => self.simple_sign,
        }
    }
}

impl LocalSloRole {
    fn endpoint(self, binding: LogoutBinding) -> &'static str {
        let endpoints = match self {
            Self::Sp => SloEndpointSet {
                post: SP_SLO_POST,
                redirect: SP_SLO_REDIRECT,
                simple_sign: SP_SLO_SIMPLESIGN,
            },
            Self::Idp => SloEndpointSet {
                post: IDP_SLO_POST,
                redirect: IDP_SLO_REDIRECT,
                simple_sign: IDP_SLO_SIMPLESIGN,
            },
        };
        endpoints.for_binding(binding)
    }
}

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

const CUSTOM_LOGOUT_REQUEST_TEMPLATE: &str = r#"
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{ID}" Version="2.0" IssueInstant="__ISSUE_INSTANT__"__NOT_ON_OR_AFTER__
    Destination="{Destination}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>
    <samlp:SessionIndex>{SessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>
"#;

fn logout_request_template(issue_instant: &str, not_on_or_after: Option<&str>) -> String {
    let not_on_or_after = not_on_or_after
        .map(|value| format!(r#" NotOnOrAfter="{value}""#))
        .unwrap_or_default();
    CUSTOM_LOGOUT_REQUEST_TEMPLATE
        .replace("__ISSUE_INSTANT__", issue_instant)
        .replace("__NOT_ON_OR_AFTER__", &not_on_or_after)
}

fn credentials() -> Credentials {
    Credentials {
        signing_key: Some(PrivateKeyPem::new(PRIVKEY)),
        signing_certificate: Some(CertificatePem::new(CERT)),
        ..Credentials::default()
    }
}

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

struct ExpiringReplayCache {
    now: SystemTime,
    seen: HashMap<String, SystemTime>,
}

impl ExpiringReplayCache {
    fn new(now: SystemTime) -> Self {
        Self {
            now,
            seen: HashMap::new(),
        }
    }
}

impl ReplayCache for ExpiringReplayCache {
    fn check_and_store(&mut self, key: ReplayKey, expires_at: SystemTime) -> Result<(), SamlError> {
        self.seen.retain(|_, deadline| self.now < *deadline);
        let cache_key = key.cache_key();
        if self.seen.contains_key(&cache_key) {
            return Err(SamlError::ReplayDetected { key: cache_key });
        }
        self.seen.insert(cache_key, expires_at);
        Ok(())
    }
}

fn sp_config() -> Result<SpConfig, SamlError> {
    sp_config_with_validation_and_logout_request_template(SpValidationPolicy::strict(), None)
}

fn sp_config_with_validation(validation: SpValidationPolicy) -> Result<SpConfig, SamlError> {
    sp_config_with_validation_and_logout_request_template(validation, None)
}

fn sp_config_with_validation_and_logout_request_template(
    validation: SpValidationPolicy,
    template: Option<&str>,
) -> Result<SpConfig, SamlError> {
    SpConfig::builder(EntityId::try_new(SP_ENTITY_ID)?)
        .acs_endpoint(AcsEndpoint::post(SP_ACS_POST)?)
        .slo_endpoint(SloEndpoint::post(SP_SLO_POST)?)
        .slo_endpoint(SloEndpoint::redirect(SP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::simple_sign(SP_SLO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(validation)
        .templates(TemplatePolicy {
            logout_request_template: template.map(str::to_string),
            ..TemplatePolicy::default()
        })
        .build()
}

fn sp_config_with_logout_request_template(template: &str) -> Result<SpConfig, SamlError> {
    sp_config_with_validation_and_logout_request_template(
        SpValidationPolicy::strict(),
        Some(template),
    )
}

fn idp_config() -> Result<IdpConfig, SamlError> {
    idp_config_with_validation(IdpValidationPolicy::strict())
}

fn idp_config_with_validation(validation: IdpValidationPolicy) -> Result<IdpConfig, SamlError> {
    idp_config_with_validation_and_logout_request_template(validation, None)
}

fn idp_config_with_validation_and_logout_request_template(
    validation: IdpValidationPolicy,
    template: Option<&str>,
) -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
        .slo_endpoint(SloEndpoint::redirect(IDP_SLO_REDIRECT)?)
        .slo_endpoint(SloEndpoint::simple_sign(IDP_SLO_SIMPLESIGN)?)
        .credentials(credentials())
        .validation(validation)
        .templates(TemplatePolicy {
            logout_request_template: template.map(str::to_string),
            ..TemplatePolicy::default()
        })
        .build()
}

fn idp_config_with_logout_response_template(
    logout_response_template: String,
) -> Result<IdpConfig, SamlError> {
    IdpConfig::builder(EntityId::try_new(IDP_ENTITY_ID)?)
        .sso_endpoint(SsoEndpoint::post(IDP_SSO_POST)?)
        .slo_endpoint(SloEndpoint::post(IDP_SLO_POST)?)
        .credentials(credentials())
        .validation(IdpValidationPolicy::strict())
        .templates(TemplatePolicy {
            logout_response_template: Some(logout_response_template),
            ..TemplatePolicy::default()
        })
        .build()
}

fn bad_template_idp_config() -> Result<IdpConfig, SamlError> {
    idp_config_with_logout_response_template(BAD_LOGOUT_RESPONSE_TEMPLATE.to_string())
}

fn bad_profile_template_idp_config() -> Result<IdpConfig, SamlError> {
    idp_config_with_logout_response_template(BAD_LOGOUT_RESPONSE_TEMPLATE.replace(
        r#"IssueInstant="{IssueInstant}""#,
        r#"IssueInstant="not-a-date""#,
    ))
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
    Ok(LogoutSubject::with_session_index(
        NameId::new("alice@example.com", None),
        SessionIndex::try_new("_session123")?,
    ))
}

fn validation() -> SamlValidationContext<'static> {
    SamlValidationContext::new(
        SystemTime::now(),
        saml_rs::ReplayPolicy::DisabledForCompatibility,
    )
}

fn validation_with_cache(cache: &mut dyn ReplayCache) -> SamlValidationContext<'_> {
    SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(cache))
        .with_replay_retention(Duration::from_secs(5 * 60))
}

fn post_fields<Message>(outbound: &Outbound<Message>) -> Result<Vec<FormField>, SamlError> {
    Ok(outbound.post_form()?.fields().to_vec())
}

fn logout_request_input(
    outbound: &Outbound<LogoutRequest>,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutRequest>, SamlError> {
    match binding {
        LogoutBinding::Redirect => {
            let url = outbound.redirect_url()?;
            let (_, query) = url
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
            Ok(BrowserInput::<LogoutRequest>::redirect(query))
        }
        LogoutBinding::Post => Ok(BrowserInput::<LogoutRequest>::post(post_fields(outbound)?)),
        LogoutBinding::SimpleSign => Ok(BrowserInput::<LogoutRequest>::simple_sign(post_fields(
            outbound,
        )?)),
    }
}

fn start_slo_for_binding(binding: LogoutBinding) -> StartSlo {
    match binding {
        LogoutBinding::Redirect => StartSlo::redirect(),
        LogoutBinding::Post => StartSlo::post(),
        LogoutBinding::SimpleSign => StartSlo::simple_sign(),
    }
}

fn start_unsigned_slo_for_binding(binding: LogoutBinding) -> StartSlo {
    start_slo_for_binding(binding).signing(LogoutSigning::DoNotSignForCompatibility)
}

#[derive(Debug, Clone, Copy)]
enum RequestProtection {
    Signed,
    UnsignedCompatibility,
}

fn receive_custom_logout_request(
    template: &str,
    binding: LogoutBinding,
    receiver_role: LocalSloRole,
    protection: RequestProtection,
    validation: SamlValidationContext<'_>,
) -> Result<Received<LogoutRequest>, SamlError> {
    let start_options = match protection {
        RequestProtection::Signed => start_slo_for_binding(binding),
        RequestProtection::UnsignedCompatibility => start_unsigned_slo_for_binding(binding),
    };
    match receiver_role {
        LocalSloRole::Idp => {
            let sp = Saml::sp(sp_config_with_logout_request_template(template)?)?;
            let idp = Saml::idp(match protection {
                RequestProtection::Signed => idp_config()?,
                RequestProtection::UnsignedCompatibility => {
                    idp_config_with_validation(IdpValidationPolicy::compatibility())?
                }
            })?;
            let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
            let started = sp.start_slo(&idp_descriptor, subject()?, start_options)?;
            idp.receive_slo(
                &sp_descriptor,
                logout_request_input(&started.outbound, binding)?,
                validation,
            )
        }
        LocalSloRole::Sp => {
            let sp = Saml::sp(match protection {
                RequestProtection::Signed => sp_config()?,
                RequestProtection::UnsignedCompatibility => {
                    sp_config_with_validation(SpValidationPolicy::compatibility())?
                }
            })?;
            let idp = Saml::idp(idp_config_with_validation_and_logout_request_template(
                IdpValidationPolicy::strict(),
                Some(template),
            )?)?;
            let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
            let started = idp.start_slo(&sp_descriptor, subject()?, start_options)?;
            sp.receive_slo(
                &idp_descriptor,
                logout_request_input(&started.outbound, binding)?,
                validation,
            )
        }
    }
}

fn logout_response_xml(
    id: &str,
    issuer: &str,
    in_response_to: &str,
    destination: Option<&str>,
) -> String {
    let destination = destination
        .map(|destination| format!(r#" Destination="{destination}""#))
        .unwrap_or_default();
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{id}" Version="2.0" IssueInstant="2000-01-01T00:00:00Z"
    InResponseTo="{in_response_to}"{destination}>
    <saml:Issuer>{issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:LogoutResponse>"#
    )
}

fn signed_logout_response_input(
    xml: &str,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutResponse>, SamlError> {
    let key = load_private_key(PRIVKEY, None)?;
    match binding {
        LogoutBinding::Post => {
            let signed = construct_saml_signature(xml, true, &key, CERT, RSA_SHA256, &[], None)?;
            Ok(BrowserInput::<LogoutResponse>::post(vec![FormField::new(
                "SAMLResponse",
                base64_encode(signed.as_bytes()),
            )]))
        }
        LogoutBinding::Redirect => {
            let octet = build_redirect_octet(ParserType::LogoutResponse, xml, None, RSA_SHA256)?;
            let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
            let url = append_signature("https://receiver.example.com/slo", &octet, &signature);
            let (_, query) = url
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
            Ok(BrowserInput::<LogoutResponse>::redirect(query))
        }
        LogoutBinding::SimpleSign => {
            let octet = format!("SAMLResponse={xml}&SigAlg={RSA_SHA256}");
            let signature = construct_message_signature(&octet, &key, RSA_SHA256)?;
            Ok(BrowserInput::<LogoutResponse>::simple_sign(vec![
                FormField::new("SAMLResponse", base64_encode(xml.as_bytes())),
                FormField::new("SigAlg", RSA_SHA256),
                FormField::new("Signature", signature),
            ]))
        }
    }
}

fn unsigned_logout_response_input(
    xml: &str,
    binding: LogoutBinding,
) -> Result<BrowserInput<LogoutResponse>, SamlError> {
    match binding {
        LogoutBinding::Post => Ok(BrowserInput::<LogoutResponse>::post(vec![FormField::new(
            "SAMLResponse",
            base64_encode(xml.as_bytes()),
        )])),
        LogoutBinding::Redirect => {
            let url = saml_rs::binding::build_redirect_url(
                "https://receiver.example.com/slo",
                ParserType::LogoutResponse,
                xml,
                None,
            )?;
            let (_, query) = url
                .split_once('?')
                .ok_or_else(|| SamlError::Invalid("redirect URL is missing a query".into()))?;
            Ok(BrowserInput::<LogoutResponse>::redirect(query))
        }
        LogoutBinding::SimpleSign => Err(SamlError::Invalid(
            "SimpleSign input requires its binding-level signature".into(),
        )),
    }
}

#[derive(Debug, Clone, Copy)]
enum ResponseProtection {
    Signed,
    UnsignedCompatibility,
}

fn finish_custom_logout_response(
    receiver_role: LocalSloRole,
    binding: LogoutBinding,
    destination: Option<&str>,
    protection: ResponseProtection,
    validation: SamlValidationContext<'_>,
) -> Result<LogoutCompleted, SamlError> {
    let sp = Saml::sp(match protection {
        ResponseProtection::Signed => sp_config()?,
        ResponseProtection::UnsignedCompatibility => {
            sp_config_with_validation(SpValidationPolicy::compatibility())?
        }
    })?;
    let idp = Saml::idp(match protection {
        ResponseProtection::Signed => idp_config()?,
        ResponseProtection::UnsignedCompatibility => {
            idp_config_with_validation(IdpValidationPolicy::compatibility())?
        }
    })?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let response_id = format!("_{receiver_role:?}_{binding:?}_{protection:?}_response");

    match receiver_role {
        LocalSloRole::Sp => {
            let started =
                sp.start_slo(&idp_descriptor, subject()?, start_slo_for_binding(binding))?;
            let xml = logout_response_xml(
                &response_id,
                IDP_ENTITY_ID,
                started.pending.id().as_str(),
                destination,
            );
            let input = match protection {
                ResponseProtection::Signed => signed_logout_response_input(&xml, binding)?,
                ResponseProtection::UnsignedCompatibility => {
                    unsigned_logout_response_input(&xml, binding)?
                }
            };
            sp.finish_slo(&idp_descriptor, &started.pending, input, validation)
        }
        LocalSloRole::Idp => {
            let started =
                idp.start_slo(&sp_descriptor, subject()?, start_slo_for_binding(binding))?;
            let xml = logout_response_xml(
                &response_id,
                SP_ENTITY_ID,
                started.pending.id().as_str(),
                destination,
            );
            let input = match protection {
                ResponseProtection::Signed => signed_logout_response_input(&xml, binding)?,
                ResponseProtection::UnsignedCompatibility => {
                    unsigned_logout_response_input(&xml, binding)?
                }
            };
            idp.finish_slo(&sp_descriptor, &started.pending, input, validation)
        }
    }
}

fn system_time(value: &str) -> Result<SystemTime, Box<dyn std::error::Error>> {
    Ok(SystemTime::from(OffsetDateTime::parse(value, &Rfc3339)?))
}

fn replace_response_issue_instant(
    fields: Vec<FormField>,
    replacement: Option<&str>,
) -> Result<Vec<FormField>, Box<dyn std::error::Error>> {
    fields
        .into_iter()
        .map(|field| {
            if field.name() != "SAMLResponse" {
                return Ok(field);
            }
            let xml = String::from_utf8(base64_decode(field.value())?)?;
            let (before, after) = xml
                .split_once(" IssueInstant=\"")
                .ok_or("missing IssueInstant attribute")?;
            let (_, after) = after
                .split_once('"')
                .ok_or("unterminated IssueInstant attribute")?;
            let replacement = replacement
                .map(|value| format!(" IssueInstant=\"{value}\""))
                .unwrap_or_default();
            let xml = format!("{before}{replacement}{after}");
            Ok(FormField::new(
                "SAMLResponse",
                base64_encode(xml.as_bytes()),
            ))
        })
        .collect()
}

fn outbound_xml<Message>(
    outbound: &Outbound<Message>,
    message_field: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match outbound.raw_context().binding {
        Binding::Redirect => {
            let url = Url::parse(outbound.redirect_url()?)?;
            let (_, encoded) = url
                .query_pairs()
                .find(|(key, _)| key == message_field)
                .ok_or("missing SAML message")?;
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
        StartSlo::post().relay_state(relay_state),
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

    let response = idp.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
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
                value_object(vec![
                    ("id", value_str("_response123")),
                    ("issueInstant", value_str("2024-01-01T00:00:00Z")),
                ]),
            ),
            (
                "assertion",
                value_object(vec![
                    ("id", value_str("_assertion123")),
                    ("issueInstant", value_str("2024-01-01T00:00:01Z")),
                ]),
            ),
            ("issuer", value_str(IDP_ENTITY_ID)),
            ("nameID", value_str("alice@example.com")),
            (
                "sessionIndex",
                Value::Array(vec![
                    value_object(vec![
                        ("sessionIndex", value_str("_session123")),
                        ("authnInstant", value_str("2026-07-04T12:00:00Z")),
                    ]),
                    value_object(vec![("sessionIndex", value_str("_session456"))]),
                ]),
            ),
        ]),
    })
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
    assert!(redirect
        .outbound
        .redirect_url()?
        .starts_with(IDP_SLO_REDIRECT));
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
fn typed_slo_signs_front_channel_responses_despite_compatibility_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(idp_config_with_validation(
        IdpValidationPolicy::compatibility(),
    )?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;

    let post = idp.respond_slo(&sp_descriptor, &received, RespondSlo::post())?;
    assert!(outbound_xml(&post, "SAMLResponse")?.contains("<ds:Signature"));

    let redirect = idp.respond_slo(&sp_descriptor, &received, RespondSlo::redirect())?;
    let redirect_url = Url::parse(redirect.redirect_url()?)?;
    assert!(redirect_url
        .query_pairs()
        .any(|(name, value)| name == "Signature" && !value.is_empty()));
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
fn typed_slo_subject_can_come_from_sso_session() -> Result<(), Box<dyn std::error::Error>> {
    let session = sso_session()?;
    let subject = session.logout_subject().ok_or("missing logout subject")?;

    assert_eq!(subject.name_id().value(), "alice@example.com");
    assert_eq!(
        subject
            .session_indexes()
            .iter()
            .map(SessionIndex::as_str)
            .collect::<Vec<_>>(),
        vec!["_session123", "_session456"]
    );
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

    assert_eq!(
        exchange.received.relay_state(),
        &RelayStateParam::try_from_option(Some("logout-state".to_string()))?
    );

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
    assert_eq!(
        response.issue_instant().as_str(),
        response.issue_instant().as_str().trim()
    );
    assert!(response.issue_instant().as_str().ends_with('Z'));
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
fn typed_facade_rejects_missing_logout_response_issue_instant_in_real_flow(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let response_fields = replace_response_issue_instant(exchange.response_fields, None)?;

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(response_fields),
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "LogoutResponse is missing required unqualified attribute IssueInstant",
            ) =>
        {
            Ok(())
        }
        other => Err(format!("expected LogoutResponse IssueInstant error, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_receive_slo_checks_logout_request_replay() -> Result<(), Box<dyn std::error::Error>>
{
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_fields = post_fields(&started.outbound)?;
    let mut cache = MemoryReplayCache::default();

    let received = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let replay_key = format!("logout_request_id:{}", received.message().id().as_str());
    assert!(cache.seen.contains_key(&replay_key));

    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, replay_key);
            Ok(())
        }
        other => Err(format!("expected LogoutRequest ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_rejects_expired_signed_logout_request_before_replay_for_all_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T12:00:00Z"));
    for binding in [
        LogoutBinding::Post,
        LogoutBinding::Redirect,
        LogoutBinding::SimpleSign,
    ] {
        let mut cache = MemoryReplayCache::default();
        let validation = SamlValidationContext::new(
            system_time("2026-07-15T12:00:00Z")?,
            ReplayPolicy::RequireCache(&mut cache),
        );
        match receive_custom_logout_request(
            &template,
            binding,
            LocalSloRole::Idp,
            RequestProtection::Signed,
            validation,
        ) {
            Err(SamlError::TimeWindowInvalid { field }) => {
                assert_eq!(field, TimeWindowField::LogoutRequestNotOnOrAfter);
                assert!(cache.seen.is_empty());
            }
            other => {
                return Err(format!(
                    "expected expired signed LogoutRequest for {binding:?}, got {other:?}"
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facade_rejects_signed_logout_request_without_destination_before_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", None).replacen(
        "\n    Destination=\"{Destination}\"",
        "",
        1,
    );
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let mut cache = MemoryReplayCache::default();
            match receive_custom_logout_request(
                &template,
                binding,
                receiver_role,
                RequestProtection::Signed,
                validation_with_cache(&mut cache),
            ) {
                Err(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, receiver_role.endpoint(binding));
                    assert_eq!(actual, None);
                    assert!(cache.seen.is_empty());
                }
                other => {
                    return Err(format!(
                        "expected {receiver_role:?} missing Destination rejection for {binding:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facades_use_binding_specific_destination_for_both_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", None);
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let received = receive_custom_logout_request(
                &template,
                binding,
                receiver_role,
                RequestProtection::Signed,
                validation(),
            )?;
            assert_eq!(
                received.message().destination().map(|url| url.as_str()),
                Some(receiver_role.endpoint(binding))
            );
        }
    }
    Ok(())
}

#[test]
fn typed_facades_reject_mismatched_logout_request_destination_before_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", None).replace(
        r#"Destination="{Destination}""#,
        r#"Destination="https://wrong.example/slo""#,
    );

    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let mut cache = MemoryReplayCache::default();
            match receive_custom_logout_request(
                &template,
                binding,
                receiver_role,
                RequestProtection::Signed,
                validation_with_cache(&mut cache),
            ) {
                Err(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, receiver_role.endpoint(binding));
                    assert_eq!(actual.as_deref(), Some("https://wrong.example/slo"));
                    assert!(cache.seen.is_empty());
                }
                other => {
                    return Err(format!(
                        "expected {receiver_role:?} DestinationMismatch for {binding:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facades_allow_unsigned_missing_destination_only_under_compatibility_policy(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", None).replacen(
        "\n    Destination=\"{Destination}\"",
        "",
        1,
    );

    for binding in UNSIGNED_COMPATIBILITY_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let received = receive_custom_logout_request(
                &template,
                binding,
                receiver_role,
                RequestProtection::UnsignedCompatibility,
                validation(),
            )?;
            assert_eq!(received.message().destination(), None);
        }
    }
    Ok(())
}

#[test]
fn typed_facade_rejects_qualified_logout_request_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", None).replace(
        r#"Destination="{Destination}""#,
        r#"samlp:Destination="{Destination}""#,
    );

    match receive_custom_logout_request(
        &template,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("attribute Destination on LogoutRequest must be unqualified") =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected qualified Destination protocol-profile rejection, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facade_receive_slo_uses_not_on_or_after_deadline_without_generic_retention(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T12:01:00Z"));
    let mut cache = MemoryReplayCache::default();
    let validation = SamlValidationContext::new(
        system_time("2026-07-15T12:00:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    )
    .with_clock_skew(ClockSkew::strict().with_not_on_or_after_millis(30_000));

    let received = receive_custom_logout_request(
        &template,
        LogoutBinding::Post,
        LocalSloRole::Idp,
        RequestProtection::Signed,
        validation,
    )?;
    let replay_key = format!("logout_request_id:{}", received.message().id().as_str());
    assert_eq!(
        cache.seen.get(&replay_key),
        Some(&system_time("2026-07-15T12:01:30Z")?)
    );
    assert_eq!(
        received.message().issue_instant().as_str(),
        "2000-01-01T00:00:00Z"
    );
    assert_eq!(
        received
            .message()
            .not_on_or_after()
            .map(saml_rs::SamlInstant::as_str),
        Some("2026-07-15T12:01:00Z")
    );
    Ok(())
}

#[test]
fn typed_facade_replay_deadline_includes_not_on_or_after_skew(
) -> Result<(), Box<dyn std::error::Error>> {
    let template = logout_request_template("2000-01-01T00:00:00Z", Some("2026-07-15T12:01:00Z"));
    let sp = Saml::sp(sp_config_with_logout_request_template(&template)?)?;
    let idp = Saml::idp(idp_config()?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_fields = post_fields(&started.outbound)?;
    let first_now = system_time("2026-07-15T12:00:00Z")?;
    let mut cache = ExpiringReplayCache::new(first_now);
    let skew = ClockSkew::strict().with_not_on_or_after_millis(30_000);

    let received = idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        SamlValidationContext::new(first_now, ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(skew),
    )?;
    let replay_key = format!("logout_request_id:{}", received.message().id().as_str());
    assert_eq!(
        cache.seen.get(&replay_key),
        Some(&system_time("2026-07-15T12:01:30Z")?)
    );

    cache.now = system_time("2026-07-15T12:01:01Z")?;
    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields.clone()),
        SamlValidationContext::new(cache.now, ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(skew),
    ) {
        Err(SamlError::ReplayDetected { key }) => assert_eq!(key, replay_key),
        other => return Err(format!("expected skew-retained replay, got {other:?}").into()),
    }

    cache.now = system_time("2026-07-15T12:01:30Z")?;
    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(request_fields),
        SamlValidationContext::new(cache.now, ReplayPolicy::RequireCache(&mut cache))
            .with_clock_skew(skew),
    ) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::LogoutRequestNotOnOrAfter);
            Ok(())
        }
        other => Err(format!("expected exact effective deadline rejection, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_receive_slo_requires_replay_retention_for_logout_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let mut cache = MemoryReplayCache::default();
    let validation =
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache));

    match idp.receive_slo(
        &sp_descriptor,
        BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?),
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
fn typed_facade_finish_slo_checks_logout_response_replay() -> Result<(), Box<dyn std::error::Error>>
{
    let exchange = sp_started_exchange()?;
    let mut cache = MemoryReplayCache::default();

    let completed = exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields.clone()),
        validation_with_cache(&mut cache),
    )?;
    let response = completed.response().ok_or("missing logout response")?;
    let replay_key = format!("logout_response_id:{}", response.id().as_str());
    assert!(cache.seen.contains_key(&replay_key));

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
        validation_with_cache(&mut cache),
    ) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, replay_key);
            Ok(())
        }
        other => Err(format!("expected LogoutResponse ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_facades_accept_matching_logout_response_destination_for_all_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let endpoint = receiver_role.endpoint(binding);
            let completed = finish_custom_logout_response(
                receiver_role,
                binding,
                Some(endpoint),
                ResponseProtection::Signed,
                validation(),
            )?;
            assert_eq!(
                completed
                    .response()
                    .and_then(LogoutResponse::destination)
                    .map(|url| url.as_str()),
                Some(endpoint)
            );
        }
    }
    Ok(())
}

#[test]
fn typed_facade_rejects_qualified_logout_response_destination(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (_sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let xml = logout_response_xml(
        "_qualified_response_destination",
        IDP_ENTITY_ID,
        started.pending.id().as_str(),
        Some(SP_SLO_POST),
    )
    .replace(" Destination=", " samlp:Destination=");

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        signed_logout_response_input(&xml, LogoutBinding::Post)?,
        validation(),
    ) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains("attribute Destination on LogoutResponse must be unqualified") =>
        {
            Ok(())
        }
        other => Err(format!(
            "expected qualified LogoutResponse Destination rejection, got {other:?}"
        )
        .into()),
    }
}

#[test]
fn typed_facades_reject_signed_logout_response_without_destination_before_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let mut cache = MemoryReplayCache::default();
            match finish_custom_logout_response(
                receiver_role,
                binding,
                None,
                ResponseProtection::Signed,
                validation_with_cache(&mut cache),
            ) {
                Err(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, receiver_role.endpoint(binding));
                    assert_eq!(actual, None);
                    assert!(cache.seen.is_empty());
                }
                other => {
                    return Err(format!(
                        "expected {receiver_role:?} missing response Destination rejection for {binding:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facades_reject_mismatched_logout_response_destination_before_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in ALL_LOGOUT_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let mut cache = MemoryReplayCache::default();
            match finish_custom_logout_response(
                receiver_role,
                binding,
                Some("https://wrong.example/slo"),
                ResponseProtection::Signed,
                validation_with_cache(&mut cache),
            ) {
                Err(SamlError::DestinationMismatch { expected, actual }) => {
                    assert_eq!(expected, receiver_role.endpoint(binding));
                    assert_eq!(actual.as_deref(), Some("https://wrong.example/slo"));
                    assert!(cache.seen.is_empty());
                }
                other => {
                    return Err(format!(
                        "expected {receiver_role:?} response DestinationMismatch for {binding:?}, got {other:?}"
                    )
                    .into());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn typed_facades_allow_unsigned_logout_response_without_destination_in_compatibility_mode(
) -> Result<(), Box<dyn std::error::Error>> {
    for binding in UNSIGNED_COMPATIBILITY_BINDINGS {
        for receiver_role in LOCAL_SLO_ROLES {
            let completed = finish_custom_logout_response(
                receiver_role,
                binding,
                None,
                ResponseProtection::UnsignedCompatibility,
                validation(),
            )?;
            assert_eq!(
                completed.response().and_then(LogoutResponse::destination),
                None
            );
        }
    }
    Ok(())
}

#[test]
fn typed_facade_finish_slo_requires_replay_retention_for_logout_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let exchange = sp_started_exchange()?;
    let mut cache = MemoryReplayCache::default();
    let validation =
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut cache));

    match exchange.sp.finish_slo(
        &exchange.idp_descriptor,
        &exchange.pending,
        BrowserInput::<LogoutResponse>::post(exchange.response_fields),
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
fn typed_facade_runs_idp_initiated_slo() -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("idp-logout".to_string()))?;
    let started = idp.start_slo(
        &sp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state),
    )?;

    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = sp.receive_slo(&idp_descriptor, request_input, validation())?;
    assert_eq!(received.message().issuer().as_str(), IDP_ENTITY_ID);

    let response = sp.respond_slo(&idp_descriptor, &received, RespondSlo::post())?;
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
fn typed_facade_allows_respond_slo_to_suppress_relay_state_echo(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("logout-state".to_string()))?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state),
    )?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().relay_state(RelayStateParam::absent()),
    )?;

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(
                expected,
                RelayStateParam::try_from_option(Some("logout-state".to_string()))?
            );
            assert_eq!(actual, RelayStateParam::Absent);
            Ok(())
        }
        other => Err(format!("expected RelayStateMismatch, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_allows_respond_slo_to_override_relay_state_echo(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sp, idp) = facades()?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let relay_state = RelayStateParam::try_from_option(Some("logout-state".to_string()))?;
    let started = sp.start_slo(
        &idp_descriptor,
        subject()?,
        StartSlo::post().relay_state(relay_state),
    )?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;
    let response = idp.respond_slo(
        &sp_descriptor,
        &received,
        RespondSlo::post().relay_state(RelayStateParam::try_from_option(Some(
            "override".to_string(),
        ))?),
    )?;

    match sp.finish_slo(
        &idp_descriptor,
        &started.pending,
        BrowserInput::<LogoutResponse>::post(post_fields(&response)?),
        validation(),
    ) {
        Err(SamlError::RelayStateMismatch { expected, actual }) => {
            assert_eq!(
                expected,
                RelayStateParam::try_from_option(Some("logout-state".to_string()))?
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
fn typed_facade_rejects_custom_logout_response_profile_before_correlation(
) -> Result<(), Box<dyn std::error::Error>> {
    let sp = Saml::sp(sp_config()?)?;
    let idp = Saml::idp(bad_profile_template_idp_config()?)?;
    let (sp_descriptor, idp_descriptor) = descriptors(&sp, &idp)?;
    let started = sp.start_slo(&idp_descriptor, subject()?, StartSlo::post())?;
    let request_input = BrowserInput::<LogoutRequest>::post(post_fields(&started.outbound)?);
    let received = idp.receive_slo(&sp_descriptor, request_input, validation())?;

    match idp.respond_slo(&sp_descriptor, &received, RespondSlo::post()) {
        Err(SamlError::ProtocolProfile(message))
            if message.contains(
                "LogoutResponse IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            ) =>
        {
            Ok(())
        }
        other => Err(format!("expected custom LogoutResponse profile error, got {other:?}").into()),
    }
}

#[test]
fn typed_facade_allows_explicit_unsigned_logout_request_for_compatibility(
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
