//! Typed SAML domain models built from validated raw flow results.

use crate::browser::EndpointUrl;
use crate::config::{EntityId, NameIdFormat};
use crate::constants::name_id_format;
use crate::error::SamlError;
use crate::raw::FlowResult;
use crate::util::Value;

/// Correlation ID for an AuthnRequest or response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(String);

impl RequestId {
    /// Validate and wrap a request ID.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the request ID is empty.
    pub fn new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SamlError::Invalid("request ID must not be empty".into()));
        }
        Ok(Self(value))
    }

    /// Borrow the request ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Assertion ID extracted from a SAML assertion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssertionId(String);

impl AssertionId {
    /// Validate and wrap an assertion ID.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the assertion ID is empty.
    pub fn new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SamlError::Invalid("assertion ID must not be empty".into()));
        }
        Ok(Self(value))
    }

    /// Borrow the assertion ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RelayState value when a browser message carries the parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayState(String);

impl RelayState {
    /// Wrap a RelayState value, preserving an explicit empty string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the RelayState string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RelayState represented as absent, present empty, or present with a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RelayStateState {
    /// No RelayState parameter was sent.
    Absent,
    /// RelayState was sent with an empty value.
    PresentEmpty,
    /// RelayState was sent with a non-empty value.
    PresentValue(RelayState),
}

impl RelayStateState {
    /// Preserve the exact RelayState presence state from an optional value.
    pub fn from_option(value: Option<impl Into<String>>) -> Self {
        match value {
            None => Self::Absent,
            Some(value) => {
                let value = value.into();
                if value.is_empty() {
                    Self::PresentEmpty
                } else {
                    Self::PresentValue(RelayState::new(value))
                }
            }
        }
    }

    /// Borrow RelayState as an optional value.
    pub fn as_deref(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::PresentEmpty => Some(""),
            Self::PresentValue(value) => Some(value.as_str()),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), SamlError> {
        if matches!(self, Self::PresentValue(value) if value.as_str().is_empty()) {
            return Err(SamlError::Invalid(
                "RelayState PresentValue must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// SAML instant text carried in pending snapshots and parsed results.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SamlInstant(String);

impl SamlInstant {
    /// Validate and wrap a SAML instant string.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the instant is empty. Full temporal
    /// enforcement is left to the validation policy that consumes the value.
    pub fn new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SamlError::Invalid("SAML instant must not be empty".into()));
        }
        Ok(Self(value))
    }

    /// Borrow the instant string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SessionIndex from an AuthnStatement or LogoutRequest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionIndex(String);

impl SessionIndex {
    /// Validate and wrap a SessionIndex.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the SessionIndex is empty.
    pub fn new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SamlError::Invalid("SessionIndex must not be empty".into()));
        }
        Ok(Self(value))
    }

    /// Borrow the SessionIndex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// NameID value and optional format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameId {
    value: String,
    format: Option<NameIdFormat>,
}

impl NameId {
    /// Create a NameID value.
    pub fn new(value: impl Into<String>, format: Option<NameIdFormat>) -> Self {
        Self {
            value: value.into(),
            format,
        }
    }

    /// Borrow the NameID text.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// NameID format, when extracted.
    pub fn format(&self) -> Option<&NameIdFormat> {
        self.format.as_ref()
    }
}

/// AuthnRequest NameIDPolicy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameIdPolicy {
    format: Option<NameIdFormat>,
    allow_create: Option<bool>,
}

impl NameIdPolicy {
    /// Create a NameIDPolicy model.
    pub fn new(format: Option<NameIdFormat>, allow_create: Option<bool>) -> Self {
        Self {
            format,
            allow_create,
        }
    }

    /// Requested NameID format.
    pub fn format(&self) -> Option<&NameIdFormat> {
        self.format.as_ref()
    }

    /// Whether the IdP may create a new identifier.
    pub fn allow_create(&self) -> Option<bool> {
        self.allow_create
    }
}

/// A single SAML attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeValue(String);

impl AttributeValue {
    /// Wrap an attribute value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the attribute value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SAML attribute with one or more values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    name: String,
    name_format: Option<String>,
    values: Vec<AttributeValue>,
}

impl Attribute {
    /// Create a SAML attribute.
    pub fn new(
        name: impl Into<String>,
        name_format: Option<String>,
        values: Vec<AttributeValue>,
    ) -> Self {
        Self {
            name: name.into(),
            name_format,
            values,
        }
    }

    /// Attribute name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Attribute name format, when extracted.
    pub fn name_format(&self) -> Option<&str> {
        self.name_format.as_deref()
    }

    /// Attribute values.
    pub fn values(&self) -> &[AttributeValue] {
        &self.values
    }
}

/// Collection of SAML attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attributes(Vec<Attribute>);

impl Attributes {
    /// Create an attribute collection.
    pub fn new(values: Vec<Attribute>) -> Self {
        Self(values)
    }

    /// Borrow the attributes as a slice.
    pub fn as_slice(&self) -> &[Attribute] {
        &self.0
    }

    /// Find an attribute by name.
    pub fn get(&self, name: &str) -> Option<&Attribute> {
        self.0.iter().find(|attribute| attribute.name() == name)
    }
}

impl IntoIterator for Attributes {
    type Item = Attribute;
    type IntoIter = std::vec::IntoIter<Attribute>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// SubjectConfirmation captured from the validated flow result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectConfirmation {
    raw_xml: String,
}

impl SubjectConfirmation {
    /// Create a subject confirmation from extractor context XML.
    pub fn from_raw_xml(raw_xml: impl Into<String>) -> Self {
        Self {
            raw_xml: raw_xml.into(),
        }
    }

    /// Borrow the raw confirmation XML captured by the extractor.
    pub fn raw_xml(&self) -> &str {
        &self.raw_xml
    }
}

/// SAML subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    name_id: NameId,
    confirmations: Vec<SubjectConfirmation>,
}

impl Subject {
    /// Create a subject.
    pub fn new(name_id: NameId, confirmations: Vec<SubjectConfirmation>) -> Self {
        Self {
            name_id,
            confirmations,
        }
    }

    /// Subject NameID.
    pub fn name_id(&self) -> &NameId {
        &self.name_id
    }

    /// Subject confirmations.
    pub fn confirmations(&self) -> &[SubjectConfirmation] {
        &self.confirmations
    }
}

/// AuthnStatement session data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnSession {
    session_index: Option<SessionIndex>,
    authn_instant: Option<SamlInstant>,
    not_on_or_after: Option<SamlInstant>,
}

impl AuthnSession {
    /// Create session data.
    pub fn new(
        session_index: Option<SessionIndex>,
        authn_instant: Option<SamlInstant>,
        not_on_or_after: Option<SamlInstant>,
    ) -> Self {
        Self {
            session_index,
            authn_instant,
            not_on_or_after,
        }
    }

    /// SessionIndex, when present.
    pub fn session_index(&self) -> Option<&SessionIndex> {
        self.session_index.as_ref()
    }

    /// AuthnInstant, when present.
    pub fn authn_instant(&self) -> Option<&SamlInstant> {
        self.authn_instant.as_ref()
    }

    /// SessionNotOnOrAfter, when present.
    pub fn not_on_or_after(&self) -> Option<&SamlInstant> {
        self.not_on_or_after.as_ref()
    }
}

/// Parsed AuthnRequest result.
#[derive(Debug, Clone)]
pub struct AuthnRequest {
    id: RequestId,
    issuer: EntityId,
    destination: Option<EndpointUrl>,
    acs_url: Option<EndpointUrl>,
    name_id_policy: Option<NameIdPolicy>,
    raw_flow: FlowResult,
}

impl AuthnRequest {
    /// Request ID.
    pub fn id(&self) -> &RequestId {
        &self.id
    }

    /// Request issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// Destination endpoint, when present.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// AssertionConsumerServiceURL, when present.
    pub fn acs_url(&self) -> Option<&EndpointUrl> {
        self.acs_url.as_ref()
    }

    /// NameIDPolicy, when present.
    pub fn name_id_policy(&self) -> Option<&NameIdPolicy> {
        self.name_id_policy.as_ref()
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for AuthnRequest {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let id = RequestId::new(required_str(&raw_flow.extract, "request.id")?)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let destination = optional_endpoint(&raw_flow.extract, "request.destination")?;
        let acs_url = optional_endpoint(&raw_flow.extract, "request.assertionConsumerServiceUrl")?;
        let name_id_policy = name_id_policy_from_extract(&raw_flow.extract);
        Ok(Self {
            id,
            issuer,
            destination,
            acs_url,
            name_id_policy,
            raw_flow,
        })
    }
}

/// Parsed SSO response envelope.
#[derive(Debug, Clone)]
pub struct SsoResponse {
    response_id: RequestId,
    issuer: EntityId,
    in_response_to: Option<RequestId>,
    raw_flow: FlowResult,
}

impl SsoResponse {
    /// Response ID.
    pub fn response_id(&self) -> &RequestId {
        &self.response_id
    }

    /// Assertion issuer used by the current validated flow result.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&RequestId> {
        self.in_response_to.as_ref()
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for SsoResponse {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let response_id = RequestId::new(required_str(&raw_flow.extract, "response.id")?)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let in_response_to = optional_request_id(&raw_flow.extract, "response.inResponseTo")?;
        Ok(Self {
            response_id,
            issuer,
            in_response_to,
            raw_flow,
        })
    }
}

/// Assertion view extracted from an SSO session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    id: Option<AssertionId>,
    issuer: EntityId,
    subject: Subject,
}

impl Assertion {
    /// Create an assertion view.
    pub fn new(id: Option<AssertionId>, issuer: EntityId, subject: Subject) -> Self {
        Self {
            id,
            issuer,
            subject,
        }
    }

    /// Assertion ID, when extracted.
    pub fn id(&self) -> Option<&AssertionId> {
        self.id.as_ref()
    }

    /// Assertion issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// Assertion subject.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }
}

/// Parsed SSO login session.
#[derive(Debug, Clone)]
pub struct SsoSession {
    response_id: RequestId,
    assertion_id: Option<AssertionId>,
    issuer: EntityId,
    in_response_to: Option<RequestId>,
    subject: Subject,
    attributes: Attributes,
    authn_session: AuthnSession,
    audience: Vec<EntityId>,
    not_before: Option<SamlInstant>,
    not_on_or_after: Option<SamlInstant>,
    sig_alg: Option<String>,
    raw_flow: FlowResult,
}

impl SsoSession {
    /// Response ID.
    pub fn response_id(&self) -> &RequestId {
        &self.response_id
    }

    /// Assertion ID, when extracted.
    pub fn assertion_id(&self) -> Option<&AssertionId> {
        self.assertion_id.as_ref()
    }

    /// Assertion issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&RequestId> {
        self.in_response_to.as_ref()
    }

    /// Subject.
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// Subject NameID.
    pub fn name_id(&self) -> &NameId {
        self.subject.name_id()
    }

    /// Attributes.
    pub fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    /// AuthnStatement session data.
    pub fn authn_session(&self) -> &AuthnSession {
        &self.authn_session
    }

    /// Audience restrictions.
    pub fn audience(&self) -> &[EntityId] {
        &self.audience
    }

    /// Conditions NotBefore.
    pub fn not_before(&self) -> Option<&SamlInstant> {
        self.not_before.as_ref()
    }

    /// Conditions NotOnOrAfter.
    pub fn not_on_or_after(&self) -> Option<&SamlInstant> {
        self.not_on_or_after.as_ref()
    }

    /// Verified detached signature algorithm, when applicable.
    pub fn sig_alg(&self) -> Option<&str> {
        self.sig_alg.as_deref()
    }

    /// Assertion view.
    pub fn assertion(&self) -> Assertion {
        Assertion::new(
            self.assertion_id.clone(),
            self.issuer.clone(),
            self.subject.clone(),
        )
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for SsoSession {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let response_id = RequestId::new(required_str(&raw_flow.extract, "response.id")?)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let in_response_to = optional_request_id(&raw_flow.extract, "response.inResponseTo")?;
        let name_id = NameId::new(required_str(&raw_flow.extract, "nameID")?, None);
        let subject = Subject::new(
            name_id,
            subject_confirmations_from_extract(&raw_flow.extract),
        );
        let attributes = attributes_from_extract(&raw_flow.extract);
        let authn_session = authn_session_from_extract(&raw_flow.extract)?;
        let audience = entity_ids_from_value(raw_flow.extract.get("audience"))?;
        let not_before = optional_instant(&raw_flow.extract, "conditions.notBefore")?;
        let not_on_or_after = optional_instant(&raw_flow.extract, "conditions.notOnOrAfter")?;
        let sig_alg = raw_flow.sig_alg.clone();
        Ok(Self {
            response_id,
            assertion_id: None,
            issuer,
            in_response_to,
            subject,
            attributes,
            authn_session,
            audience,
            not_before,
            not_on_or_after,
            sig_alg,
            raw_flow,
        })
    }
}

/// Parsed LogoutRequest result.
#[derive(Debug, Clone)]
pub struct LogoutRequest {
    id: RequestId,
    issuer: EntityId,
    name_id: Option<NameId>,
    session_indexes: Vec<SessionIndex>,
    destination: Option<EndpointUrl>,
    raw_flow: FlowResult,
}

impl LogoutRequest {
    /// LogoutRequest ID.
    pub fn id(&self) -> &RequestId {
        &self.id
    }

    /// LogoutRequest issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// NameID, when present.
    pub fn name_id(&self) -> Option<&NameId> {
        self.name_id.as_ref()
    }

    /// Session indexes.
    pub fn session_indexes(&self) -> &[SessionIndex] {
        &self.session_indexes
    }

    /// Destination endpoint, when present.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for LogoutRequest {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let id = RequestId::new(required_str(&raw_flow.extract, "request.id")?)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let name_id = raw_flow
            .extract
            .get_str("nameID")
            .map(|value| NameId::new(value, None));
        let session_indexes = session_indexes_from_value(raw_flow.extract.get("sessionIndex"))?;
        let destination = optional_endpoint(&raw_flow.extract, "request.destination")?;
        Ok(Self {
            id,
            issuer,
            name_id,
            session_indexes,
            destination,
            raw_flow,
        })
    }
}

/// Parsed LogoutResponse result.
#[derive(Debug, Clone)]
pub struct LogoutResponse {
    id: RequestId,
    issuer: EntityId,
    in_response_to: Option<RequestId>,
    destination: Option<EndpointUrl>,
    raw_flow: FlowResult,
}

impl LogoutResponse {
    /// LogoutResponse ID.
    pub fn id(&self) -> &RequestId {
        &self.id
    }

    /// LogoutResponse issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&RequestId> {
        self.in_response_to.as_ref()
    }

    /// Destination endpoint, when present.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for LogoutResponse {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let id = RequestId::new(required_str(&raw_flow.extract, "response.id")?)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let in_response_to = optional_request_id(&raw_flow.extract, "response.inResponseTo")?;
        let destination = optional_endpoint(&raw_flow.extract, "response.destination")?;
        Ok(Self {
            id,
            issuer,
            in_response_to,
            destination,
            raw_flow,
        })
    }
}

/// Marker result for completed logout flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutCompleted {
    peer_entity_id: EntityId,
}

impl LogoutCompleted {
    /// Create a completed logout marker.
    pub fn new(peer_entity_id: EntityId) -> Self {
        Self { peer_entity_id }
    }

    /// Peer entity ID involved in the completed logout.
    pub fn peer_entity_id(&self) -> &EntityId {
        &self.peer_entity_id
    }
}

/// Typed received message wrapper.
#[derive(Debug, Clone)]
pub struct Received<Message> {
    message: Message,
}

impl<Message> Received<Message> {
    /// Create a received message wrapper.
    pub fn new(message: Message) -> Self {
        Self { message }
    }

    /// Borrow the typed message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Consume the wrapper and return the typed message.
    pub fn into_message(self) -> Message {
        self.message
    }
}

fn required_str<'a>(extract: &'a Value, path: &str) -> Result<&'a str, SamlError> {
    extract
        .get_str(path)
        .ok_or_else(|| SamlError::Invalid(format!("missing extracted field {path}")))
}

fn optional_request_id(extract: &Value, path: &str) -> Result<Option<RequestId>, SamlError> {
    extract.get_str(path).map(RequestId::new).transpose()
}

fn optional_endpoint(extract: &Value, path: &str) -> Result<Option<EndpointUrl>, SamlError> {
    extract.get_str(path).map(EndpointUrl::new).transpose()
}

fn optional_instant(extract: &Value, path: &str) -> Result<Option<SamlInstant>, SamlError> {
    extract.get_str(path).map(SamlInstant::new).transpose()
}

fn name_id_policy_from_extract(extract: &Value) -> Option<NameIdPolicy> {
    let format = extract
        .get_str("nameIDPolicy.format")
        .map(name_id_format_from_uri);
    let allow_create = extract
        .get_str("nameIDPolicy.allowCreate")
        .and_then(parse_bool);
    (format.is_some() || allow_create.is_some()).then(|| NameIdPolicy::new(format, allow_create))
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

fn attributes_from_extract(extract: &Value) -> Attributes {
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

fn subject_confirmations_from_extract(extract: &Value) -> Vec<SubjectConfirmation> {
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

fn authn_session_from_extract(extract: &Value) -> Result<AuthnSession, SamlError> {
    let session_index = extract
        .get_str("sessionIndex.sessionIndex")
        .map(SessionIndex::new)
        .transpose()?;
    let authn_instant = optional_instant(extract, "sessionIndex.authnInstant")?;
    let not_on_or_after = optional_instant(extract, "sessionIndex.sessionNotOnOrAfter")?;
    Ok(AuthnSession::new(
        session_index,
        authn_instant,
        not_on_or_after,
    ))
}

fn entity_ids_from_value(value: Option<&Value>) -> Result<Vec<EntityId>, SamlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value_strings(value)
        .into_iter()
        .map(EntityId::try_new)
        .collect()
}

fn session_indexes_from_value(value: Option<&Value>) -> Result<Vec<SessionIndex>, SamlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value_strings(value)
        .into_iter()
        .map(SessionIndex::new)
        .collect()
}
