use std::collections::HashMap;

use saml_rs::binding::base64_encode;
use saml_rs::constants::{Binding, ParserType};
use saml_rs::flow::{flow, FlowOptions, FlowResult, HttpRequest};
use saml_rs::util::Value;
use saml_rs::{
    ClockSkew, ReplayCache, ReplayKey, ReplayPolicy, SamlError, SamlValidationContext, SsoSession,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const RESPONSE: &str = include_str!("fixtures/response.xml");

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

fn instant(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}

fn response_request(xml: &str) -> HttpRequest {
    HttpRequest::post(vec![(
        "SAMLResponse".to_string(),
        base64_encode(xml.as_bytes()),
    )])
}

fn parse_response_at(xml: &str, validation: &SamlValidationContext<'_>) -> Result<(), SamlError> {
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlResponse);
    options.now = Some(validation.now());
    options.clock_drifts = validation.clock_skew().as_millis();
    flow(&options, &response_request(xml)).map(|_| ())
}

fn xml_with_late_subject_and_session() -> String {
    RESPONSE
        .replace(
            "SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\"",
            "SubjectConfirmationData NotOnOrAfter=\"2026-01-18T06:21:48Z\"",
        )
        .replace(
            "SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\"",
            "SessionNotOnOrAfter=\"2026-07-17T09:01:48Z\"",
        )
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

fn session_flow() -> FlowResult {
    FlowResult {
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
            ("issuer", value_str("https://idp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
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
                value_object(vec![("notOnOrAfter", value_str("2026-07-04T13:00:00Z"))]),
            ),
        ]),
    }
}

fn sso_session() -> Result<SsoSession, SamlError> {
    SsoSession::try_from(session_flow())
}

#[test]
fn typed_validation_context_expired_condition_uses_fixed_clock(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = xml_with_late_subject_and_session();
    let validation = SamlValidationContext::new(
        instant("2025-01-01T00:00:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    )
    .with_clock_skew(ClockSkew::strict());

    match parse_response_at(&xml, &validation) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, "Conditions");
            Ok(())
        }
        other => Err(format!("expected expired Conditions, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_not_yet_valid_condition_uses_fixed_clock(
) -> Result<(), Box<dyn std::error::Error>> {
    let validation = SamlValidationContext::new(
        instant("2014-07-17T01:01:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    );

    match parse_response_at(RESPONSE, &validation) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, "Conditions");
            Ok(())
        }
        other => Err(format!("expected not-yet-valid Conditions, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_invalid_timestamp_fails_closed_at_fixed_clock(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = xml_with_late_subject_and_session().replace(
        "NotBefore=\"2014-07-17T01:01:18Z\"",
        "NotBefore=\"not-a-date\"",
    );
    let validation = SamlValidationContext::new(
        instant("2014-07-17T01:02:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    );

    match parse_response_at(&xml, &validation) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, "Conditions");
            Ok(())
        }
        other => Err(format!("expected invalid Conditions timestamp, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_extracts_sso_replay_keys() -> Result<(), Box<dyn std::error::Error>> {
    let session = sso_session()?;
    let keys = session
        .replay_keys()
        .into_iter()
        .map(|key| key.cache_key())
        .collect::<Vec<_>>();

    assert_eq!(
        keys,
        vec![
            "response:_response123",
            "assertion:_assertion123",
            "session:_session123"
        ]
    );
    Ok(())
}

#[test]
fn typed_validation_context_replay_cache_stores_new_keys() -> Result<(), Box<dyn std::error::Error>>
{
    let session = sso_session()?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );

    session.check_replay(&mut validation)?;
    assert_eq!(cache.seen.len(), 3);
    assert!(cache.seen.contains_key("response:_response123"));
    assert!(cache.seen.contains_key("assertion:_assertion123"));
    assert!(cache.seen.contains_key("session:_session123"));
    Ok(())
}

#[test]
fn typed_validation_context_duplicate_replay_returns_semantic_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = sso_session()?;
    let now = instant("2026-07-04T12:05:00Z")?;
    let mut cache = MemoryReplayCache::default();
    {
        let mut validation =
            SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache));
        session.check_replay(&mut validation)?;
    }

    let mut validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache));
    match session.check_replay(&mut validation) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, "response:_response123");
            Ok(())
        }
        other => Err(format!("expected ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_disabled_replay_is_explicit_compatibility(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    if let Value::Object(entries) = &mut flow.extract {
        entries.retain(|(key, _)| key != "conditions" && key != "sessionIndex");
    }
    let session = SsoSession::try_from(flow)?;
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    );

    session.check_replay(&mut validation)?;
    session.check_replay(&mut validation)?;
    Ok(())
}

#[test]
fn typed_validation_context_replay_without_expiration_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    if let Value::Object(entries) = &mut flow.extract {
        entries.retain(|(key, _)| key != "conditions" && key != "sessionIndex");
    }
    let session = SsoSession::try_from(flow)?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );

    match session.check_replay(&mut validation) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, "ReplayExpiration");
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration failure, got {other:?}").into()),
    }
}
