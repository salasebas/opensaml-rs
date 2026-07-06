use super::attributes::Attributes;
use super::extract::{
    attributes_from_extract, authn_session_from_extract, entity_ids_from_value, optional_instant,
    optional_request_id, required_str, subject_confirmations_from_extract,
};
use super::identifiers::{AssertionId, MessageId, SamlInstant};
use super::session::AuthnSession;
use super::subject::{NameId, Subject};
use super::{ReplayKey, ReplayPolicy, SamlValidationContext};
use crate::config::EntityId;
use crate::error::{SamlError, TimeWindowField};
use crate::raw::FlowResult;
use crate::xml::{extract_with_limits, ExtractorField, XmlLimits};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

const BEARER_SUBJECT_CONFIRMATION_METHOD: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const REPLAY_EXPIRATION_FIELD: TimeWindowField = TimeWindowField::ReplayExpiration;

/// Parsed SSO response envelope.
#[derive(Debug, Clone)]
pub struct SsoResponse {
    response_id: MessageId,
    issuer: EntityId,
    in_response_to: Option<MessageId>,
    raw_flow: FlowResult,
}

impl SsoResponse {
    /// Response ID.
    pub fn response_id(&self) -> &MessageId {
        &self.response_id
    }

    /// Assertion issuer used by the current validated flow result.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&MessageId> {
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
        let response_id = MessageId::try_new(required_str(&raw_flow.extract, "response.id")?)?;
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
    response_id: MessageId,
    assertion_id: AssertionId,
    issuer: EntityId,
    in_response_to: Option<MessageId>,
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
    pub fn response_id(&self) -> &MessageId {
        &self.response_id
    }

    /// Assertion ID.
    pub fn assertion_id(&self) -> &AssertionId {
        &self.assertion_id
    }

    /// Assertion issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&MessageId> {
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
            Some(self.assertion_id.clone()),
            self.issuer.clone(),
            self.subject.clone(),
        )
    }

    /// Replay keys available from this validated SSO session.
    pub fn replay_keys(&self) -> Vec<ReplayKey> {
        vec![
            ReplayKey::ResponseId(self.response_id.clone()),
            ReplayKey::AssertionId(self.assertion_id.clone()),
        ]
    }

    /// Check and store this session's replay keys using the caller cache.
    ///
    /// This method is intended for typed inbound SSO facades. It should be
    /// called only after signature, issuer, audience, destination, recipient,
    /// `InResponseTo`, and time validation have already passed.
    pub fn check_and_store_replay(
        &self,
        validation: &mut SamlValidationContext<'_>,
    ) -> Result<(), SamlError> {
        let validation_now = validation.now();
        let not_on_or_after_skew_ms = validation.clock_skew().not_on_or_after_millis();
        match validation.replay_policy() {
            ReplayPolicy::DisabledForCompatibility => Ok(()),
            ReplayPolicy::RequireCache(cache) => {
                let expires_at = self.replay_expires_at(validation_now, not_on_or_after_skew_ms)?;
                let keys = self.replay_keys();
                for key in keys {
                    cache.check_and_store(key, expires_at)?;
                }
                Ok(())
            }
        }
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }

    fn replay_expires_at(
        &self,
        validation_now: OffsetDateTime,
        not_on_or_after_skew_ms: i64,
    ) -> Result<OffsetDateTime, SamlError> {
        let mut candidates = Vec::with_capacity(3);
        if let Some(instant) = self.not_on_or_after() {
            candidates.push(parse_replay_expiration(instant.as_str())?);
        }
        if let Some(instant) = self.authn_session().not_on_or_after() {
            candidates.push(parse_replay_expiration(instant.as_str())?);
        }
        if let Some(instant) = self.bearer_subject_confirmation_expires_at()? {
            candidates.push(instant);
        }

        let expires_at = candidates
            .into_iter()
            .min()
            .ok_or(SamlError::TimeWindowInvalid {
                field: REPLAY_EXPIRATION_FIELD,
            })?
            + Duration::milliseconds(not_on_or_after_skew_ms);
        if validation_now >= expires_at {
            return Err(SamlError::TimeWindowInvalid {
                field: REPLAY_EXPIRATION_FIELD,
            });
        }
        Ok(expires_at)
    }

    fn bearer_subject_confirmation_expires_at(&self) -> Result<Option<OffsetDateTime>, SamlError> {
        let fields = [
            ExtractorField::new("subjectConfirmation", &["SubjectConfirmation"]).attrs(&["Method"]),
            ExtractorField::new(
                "subjectConfirmationData",
                &["SubjectConfirmation", "SubjectConfirmationData"],
            )
            .attrs(&["NotOnOrAfter"]),
        ];
        let mut expires_at = None;
        for confirmation in self.subject.confirmations() {
            let extracted =
                extract_with_limits(confirmation.raw_xml(), &fields, XmlLimits::default())?;
            if extracted.get_str("subjectConfirmation") != Some(BEARER_SUBJECT_CONFIRMATION_METHOD)
            {
                continue;
            }
            let Some(not_on_or_after) = extracted.get_str("subjectConfirmationData") else {
                continue;
            };
            let candidate = parse_replay_expiration(not_on_or_after)?;
            match expires_at {
                Some(current) if current >= candidate => {}
                Some(_) | None => expires_at = Some(candidate),
            }
        }
        Ok(expires_at)
    }
}

fn parse_replay_expiration(value: &str) -> Result<OffsetDateTime, SamlError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| SamlError::TimeWindowInvalid {
        field: REPLAY_EXPIRATION_FIELD,
    })
}

impl TryFrom<FlowResult> for SsoSession {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let response_id = MessageId::try_new(required_str(&raw_flow.extract, "response.id")?)?;
        let assertion_id = AssertionId::try_new(required_str(&raw_flow.extract, "assertion.id")?)?;
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
            assertion_id,
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
