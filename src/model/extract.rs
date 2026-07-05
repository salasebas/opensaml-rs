use super::attributes::{Attribute, AttributeValue, Attributes};
use super::endpoint::EndpointUrl;
use super::identifiers::{MessageId, SamlInstant, SessionIndex};
use super::session::AuthnSession;
use super::subject::{NameIdPolicy, SubjectConfirmation};
use crate::config::{EntityId, NameIdFormat};
use crate::constants::name_id_format;
use crate::error::SamlError;
use crate::util::Value;

pub(super) fn required_str<'a>(extract: &'a Value, path: &str) -> Result<&'a str, SamlError> {
    extract
        .get_str(path)
        .ok_or_else(|| SamlError::Invalid(format!("missing extracted field {path}")))
}

pub(super) fn optional_request_id(
    extract: &Value,
    path: &str,
) -> Result<Option<MessageId>, SamlError> {
    extract.get_str(path).map(MessageId::try_new).transpose()
}

pub(super) fn optional_endpoint(
    extract: &Value,
    path: &str,
) -> Result<Option<EndpointUrl>, SamlError> {
    extract.get_str(path).map(EndpointUrl::try_new).transpose()
}

pub(super) fn optional_instant(
    extract: &Value,
    path: &str,
) -> Result<Option<SamlInstant>, SamlError> {
    extract.get_str(path).map(SamlInstant::try_new).transpose()
}

pub(super) fn name_id_policy_from_extract(extract: &Value) -> Option<NameIdPolicy> {
    let format = extract
        .get_str("nameIDPolicy.format")
        .map(name_id_format_from_uri);
    let allow_create = extract
        .get_str("nameIDPolicy.allowCreate")
        .and_then(parse_bool);
    NameIdPolicy::from_parsed(format, allow_create)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }
}

fn name_id_format_from_uri(uri: &str) -> NameIdFormat {
    match uri {
        name_id_format::EMAIL_ADDRESS => NameIdFormat::EmailAddress,
        name_id_format::PERSISTENT => NameIdFormat::Persistent,
        name_id_format::TRANSIENT => NameIdFormat::Transient,
        name_id_format::ENTITY => NameIdFormat::Entity,
        name_id_format::UNSPECIFIED => NameIdFormat::Unspecified,
        name_id_format::KERBEROS => NameIdFormat::Kerberos,
        name_id_format::WINDOWS_DOMAIN_QUALIFIED_NAME => NameIdFormat::WindowsDomainQualifiedName,
        name_id_format::X509_SUBJECT_NAME => NameIdFormat::X509SubjectName,
        _ => NameIdFormat::Custom(uri.to_string()),
    }
}

fn value_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Str(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        Value::Null | Value::Object(_) => Vec::new(),
    }
}

pub(super) fn attributes_from_extract(extract: &Value) -> Attributes {
    let Some(Value::Object(entries)) = extract.get("attributes") else {
        return Attributes::default();
    };
    let attributes = entries
        .iter()
        .map(|(name, value)| {
            let values = value_strings(value)
                .into_iter()
                .map(AttributeValue::new)
                .collect();
            Attribute::new(name.clone(), None, values)
        })
        .collect();
    Attributes::new(attributes)
}

pub(super) fn subject_confirmations_from_extract(extract: &Value) -> Vec<SubjectConfirmation> {
    match extract.get("subjectConfirmation") {
        Some(Value::Str(xml)) => vec![SubjectConfirmation::from_raw_xml(xml.clone())],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(SubjectConfirmation::from_raw_xml)
            .collect(),
        Some(Value::Null | Value::Object(_)) | None => Vec::new(),
    }
}

pub(super) fn authn_session_from_extract(extract: &Value) -> Result<AuthnSession, SamlError> {
    let session_index = extract
        .get_str("sessionIndex.sessionIndex")
        .map(SessionIndex::try_new)
        .transpose()?;
    let authn_instant = optional_instant(extract, "sessionIndex.authnInstant")?;
    let not_on_or_after = optional_instant(extract, "sessionIndex.sessionNotOnOrAfter")?;
    Ok(AuthnSession::new(
        session_index,
        authn_instant,
        not_on_or_after,
    ))
}

pub(super) fn entity_ids_from_value(value: Option<&Value>) -> Result<Vec<EntityId>, SamlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value_strings(value)
        .into_iter()
        .map(EntityId::try_new)
        .collect()
}

pub(super) fn session_indexes_from_value(
    value: Option<&Value>,
) -> Result<Vec<SessionIndex>, SamlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value_strings(value)
        .into_iter()
        .map(SessionIndex::try_new)
        .collect()
}
