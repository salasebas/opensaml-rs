use std::collections::HashMap;

use saml_rs::binding::base64_encode;
use saml_rs::constants::{Binding, ParserType};
use saml_rs::error::{SubjectConfirmationReason, TimeWindowField};
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

fn xml_with_late_conditions_and_session() -> String {
    RESPONSE
        .replace(
            "Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\"",
            "Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2026-01-18T06:21:48Z\"",
        )
        .replace(
            "SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\"",
            "SessionNotOnOrAfter=\"2026-07-17T09:01:48Z\"",
        )
}

fn xml_with_late_subject_and_conditions() -> String {
    RESPONSE
        .replace(
            "SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\"",
            "SubjectConfirmationData NotOnOrAfter=\"2026-01-18T06:21:48Z\"",
        )
        .replace(
            "Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\"",
            "Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2026-01-18T06:21:48Z\"",
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

fn bearer_subject_confirmation(not_on_or_after: &str) -> Value {
    value_str(&format!(
        "<saml:SubjectConfirmation xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData NotOnOrAfter=\"{not_on_or_after}\"/></saml:SubjectConfirmation>"
    ))
}

fn session_flow_with_ids(response_id: &str, assertion_id: &str) -> FlowResult {
    FlowResult {
        saml_content: "<samlp:Response/>".to_string(),
        sig_alg: None,
        extract: value_object(vec![
            (
                "response",
                value_object(vec![("id", value_str(response_id))]),
            ),
            (
                "assertion",
                value_object(vec![("id", value_str(assertion_id))]),
            ),
            ("issuer", value_str("https://idp.example.com/metadata")),
            ("nameID", value_str("alice@example.com")),
            (
                "subjectConfirmation",
                bearer_subject_confirmation("2026-07-04T14:00:00Z"),
            ),
            (
                "sessionIndex",
                value_object(vec![
                    ("sessionIndex", value_str("_session123")),
                    ("authnInstant", value_str("2026-07-04T12:00:00Z")),
                    ("sessionNotOnOrAfter", value_str("2026-07-04T13:30:00Z")),
                ]),
            ),
            (
                "conditions",
                value_object(vec![("notOnOrAfter", value_str("2026-07-04T13:00:00Z"))]),
            ),
        ]),
    }
}

fn session_flow() -> FlowResult {
    session_flow_with_ids("_response123", "_assertion123")
}

fn sso_session() -> Result<SsoSession, SamlError> {
    SsoSession::try_from(session_flow())
}

fn remove_extract_keys(flow: &mut FlowResult, keys: &[&str]) {
    if let Value::Object(entries) = &mut flow.extract {
        entries.retain(|(key, _)| !keys.iter().any(|remove| key == remove));
    }
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
            assert_eq!(field, TimeWindowField::Conditions);
            Ok(())
        }
        other => Err(format!("expected expired Conditions, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_expired_subject_confirmation_uses_fixed_clock(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = xml_with_late_conditions_and_session();
    let validation = SamlValidationContext::new(
        instant("2025-01-01T00:00:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    )
    .with_clock_skew(ClockSkew::strict());

    match parse_response_at(&xml, &validation) {
        Err(SamlError::SubjectConfirmationInvalid { reason }) => {
            assert_eq!(reason, SubjectConfirmationReason::TimeWindowInvalid);
            Ok(())
        }
        other => Err(format!("expected expired SubjectConfirmationData, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_expired_session_not_on_or_after_uses_fixed_clock(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = xml_with_late_subject_and_conditions();
    let validation = SamlValidationContext::new(
        instant("2025-01-01T00:00:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    )
    .with_clock_skew(ClockSkew::strict());

    match parse_response_at(&xml, &validation) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::SessionNotOnOrAfter);
            Ok(())
        }
        other => Err(format!("expected expired SessionNotOnOrAfter, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_repeated_session_applies_skew_after_raw_minimum(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = xml_with_late_subject_and_conditions()
        .replace(
            "SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\"",
            "SessionNotOnOrAfter=\"2024-12-31T23:59:30Z\"",
        )
        .replacen(
            "</saml:AuthnStatement>",
            "</saml:AuthnStatement><saml:AuthnStatement AuthnInstant=\"2024-12-31T23:00:00Z\" SessionNotOnOrAfter=\"2025-01-01T00:10:00Z\" SessionIndex=\"_later\"/>",
            1,
        );
    let validation = SamlValidationContext::new(
        instant("2025-01-01T00:00:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    )
    .with_clock_skew(ClockSkew::strict().with_not_on_or_after_millis(60_000));

    parse_response_at(&xml, &validation)?;
    Ok(())
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
            assert_eq!(field, TimeWindowField::Conditions);
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
            assert_eq!(field, TimeWindowField::Conditions);
            Ok(())
        }
        other => Err(format!("expected invalid Conditions timestamp, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_clock_skew_exposes_named_millis(
) -> Result<(), Box<dyn std::error::Error>> {
    let clock_skew = ClockSkew::strict()
        .with_not_before_millis(-30_000)
        .with_not_on_or_after_millis(120_000);

    assert_eq!(clock_skew.not_before_millis(), -30_000);
    assert_eq!(clock_skew.not_on_or_after_millis(), 120_000);
    assert_eq!(clock_skew.as_millis(), (-30_000, 120_000));
    Ok(())
}

#[test]
fn typed_validation_context_extracts_sso_replay_keys_without_session_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = sso_session()?;
    let keys = session
        .replay_keys()
        .into_iter()
        .map(|key| key.cache_key())
        .collect::<Vec<_>>();

    assert!(session.authn_session().session_index().is_some());
    assert_eq!(
        keys,
        vec!["response_id:_response123", "assertion_id:_assertion123"]
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
    )
    .with_clock_skew(ClockSkew::strict().with_not_on_or_after_millis(1_000));

    session.check_and_store_replay(&mut validation)?;
    let expected_expires_at = instant("2026-07-04T13:00:01Z")?;
    assert_eq!(cache.seen.len(), 2);
    assert_eq!(
        cache.seen.get("response_id:_response123"),
        Some(&expected_expires_at)
    );
    assert_eq!(
        cache.seen.get("assertion_id:_assertion123"),
        Some(&expected_expires_at)
    );
    Ok(())
}

#[test]
fn typed_validation_context_duplicate_response_id_replay_returns_semantic_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = sso_session()?;
    let now = instant("2026-07-04T12:05:00Z")?;
    let mut cache = MemoryReplayCache::default();
    {
        let mut validation =
            SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache));
        session.check_and_store_replay(&mut validation)?;
    }

    let mut validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache));
    match session.check_and_store_replay(&mut validation) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, "response_id:_response123");
            Ok(())
        }
        other => Err(format!("expected ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_duplicate_assertion_id_replay_returns_semantic_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let first = sso_session()?;
    let second = SsoSession::try_from(session_flow_with_ids("_response456", "_assertion123"))?;
    let now = instant("2026-07-04T12:05:00Z")?;
    let mut cache = MemoryReplayCache::default();
    {
        let mut validation =
            SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache));
        first.check_and_store_replay(&mut validation)?;
    }

    let mut validation = SamlValidationContext::new(now, ReplayPolicy::RequireCache(&mut cache));
    match second.check_and_store_replay(&mut validation) {
        Err(SamlError::ReplayDetected { key }) => {
            assert_eq!(key, "assertion_id:_assertion123");
            Ok(())
        }
        other => Err(format!("expected ReplayDetected, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_replay_expiration_uses_conditions_fallback(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    remove_extract_keys(&mut flow, &["sessionIndex", "subjectConfirmation"]);
    let session = SsoSession::try_from(flow)?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    )
    .with_clock_skew(ClockSkew::strict().with_not_on_or_after_millis(2_000));

    session.check_and_store_replay(&mut validation)?;
    assert_eq!(
        cache.seen.get("response_id:_response123"),
        Some(&instant("2026-07-04T13:00:02Z")?)
    );
    Ok(())
}

#[test]
fn typed_validation_context_replay_expiration_uses_subject_confirmation_data(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    remove_extract_keys(&mut flow, &["conditions", "sessionIndex"]);
    let session = SsoSession::try_from(flow)?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );

    session.check_and_store_replay(&mut validation)?;
    assert_eq!(
        cache.seen.get("response_id:_response123"),
        Some(&instant("2026-07-04T14:00:00Z")?)
    );
    Ok(())
}

#[test]
fn typed_validation_context_replay_expiration_uses_session_not_on_or_after(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    remove_extract_keys(&mut flow, &["conditions", "subjectConfirmation"]);
    let session = SsoSession::try_from(flow)?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );

    session.check_and_store_replay(&mut validation)?;
    assert_eq!(
        cache.seen.get("response_id:_response123"),
        Some(&instant("2026-07-04T13:30:00Z")?)
    );
    Ok(())
}

#[test]
fn typed_validation_context_replay_expiration_uses_earliest_authn_statement(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    remove_extract_keys(&mut flow, &["conditions", "subjectConfirmation"]);
    flow.extract.insert(
        "sessionIndex",
        Value::Array(vec![
            value_object(vec![
                ("sessionIndex", value_str("_later")),
                ("sessionNotOnOrAfter", value_str("2026-07-04T13:30:00Z")),
            ]),
            value_object(vec![
                ("sessionIndex", value_str("_earlier")),
                ("sessionNotOnOrAfter", value_str("2026-07-04T12:30:00Z")),
            ]),
        ]),
    );
    let session = SsoSession::try_from(flow)?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );

    session.check_and_store_replay(&mut validation)?;
    assert_eq!(
        cache.seen.get("response_id:_response123"),
        Some(&instant("2026-07-04T12:30:00Z")?)
    );
    Ok(())
}

#[test]
fn typed_validation_context_malformed_authn_statement_expiration_fails_replay_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    remove_extract_keys(&mut flow, &["conditions", "subjectConfirmation"]);
    flow.extract.insert(
        "sessionIndex",
        Value::Array(vec![
            value_object(vec![(
                "sessionNotOnOrAfter",
                value_str("2026-07-04T13:30:00Z"),
            )]),
            value_object(vec![("sessionNotOnOrAfter", value_str("not-a-time"))]),
        ]),
    );
    let session = SsoSession::try_from(flow)?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );

    match session.check_and_store_replay(&mut validation) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::ReplayExpiration);
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration failure, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_replay_expiration_at_now_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let session = sso_session()?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T13:00:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );

    match session.check_and_store_replay(&mut validation) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::ReplayExpiration);
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration failure, got {other:?}").into()),
    }
}

#[test]
fn typed_validation_context_disabled_replay_is_explicit_compatibility(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    remove_extract_keys(
        &mut flow,
        &["conditions", "sessionIndex", "subjectConfirmation"],
    );
    let session = SsoSession::try_from(flow)?;
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::DisabledForCompatibility,
    );

    session.check_and_store_replay(&mut validation)?;
    session.check_and_store_replay(&mut validation)?;
    Ok(())
}

#[test]
fn typed_validation_context_replay_without_expiration_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut flow = session_flow();
    remove_extract_keys(
        &mut flow,
        &["conditions", "sessionIndex", "subjectConfirmation"],
    );
    let session = SsoSession::try_from(flow)?;
    let mut cache = MemoryReplayCache::default();
    let mut validation = SamlValidationContext::new(
        instant("2026-07-04T12:05:00Z")?,
        ReplayPolicy::RequireCache(&mut cache),
    );

    match session.check_and_store_replay(&mut validation) {
        Err(SamlError::TimeWindowInvalid { field }) => {
            assert_eq!(field, TimeWindowField::ReplayExpiration);
            Ok(())
        }
        other => Err(format!("expected ReplayExpiration failure, got {other:?}").into()),
    }
}
