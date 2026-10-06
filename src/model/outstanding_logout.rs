use super::identifiers::{SamlInstant, SessionIndex};
use super::sso::SsoSession;
use super::subject::NameId;
use super::validation::SamlValidationContext;
use crate::error::SamlError;
use crate::validator::effective_not_on_or_after;
use crate::xml::parse_saml_utc_date_time;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// A `LogoutRequest` the caller has already accepted.
///
/// It names one principal, the sessions that logout ended, and
/// `NotOnOrAfter`. Pass it to
/// [`Saml<Sp>::finish_sso_with_outstanding_logout`] or
/// [`Saml<Sp>::accept_unsolicited_sso_with_outstanding_logout`]. The library
/// does not store it.
///
/// While validation time is still before `NotOnOrAfter`, including the
/// validation context's `NotOnOrAfter` clock skew, a later assertion for that
/// principal and session is rejected. At or after that deadline the logout
/// does not reject the assertion.
///
/// The principal matches when the NameID values are equal. When this logout
/// includes a [`NameId`] format, the assertion NameID format must be identical,
/// as in Core §3.3.4. When the logout omits `Format`, only the values are
/// compared: a typed `LogoutRequest` NameID does not carry `Format`.
/// `NameQualifier`, `SPNameQualifier`, and `SPProvidedID` are not on [`NameId`]
/// and are not compared.
/// An empty session list means the logout carried no `SessionIndex` and
/// applies to every session of the principal.
///
/// [`Saml<Sp>::finish_sso_with_outstanding_logout`]: crate::Saml::finish_sso_with_outstanding_logout
/// [`Saml<Sp>::accept_unsolicited_sso_with_outstanding_logout`]: crate::Saml::accept_unsolicited_sso_with_outstanding_logout
///
/// # Examples
///
/// ```
/// use saml_rs::{NameId, NameIdFormat, OutstandingLogout, SamlInstant, SessionIndex};
///
/// # fn main() -> Result<(), saml_rs::SamlError> {
/// let logout = OutstandingLogout::try_new(
///     NameId::new(
///         "alice@example.com",
///         Some(NameIdFormat::EmailAddress),
///     ),
///     vec![SessionIndex::try_new("_session")?],
///     SamlInstant::try_new("2026-10-06T00:00:00Z")?,
/// )?;
/// # let _ = logout;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutstandingLogout {
    principal: NameId,
    sessions: Vec<SessionIndex>,
    not_on_or_after: SamlInstant,
    deadline: OffsetDateTime,
}

impl OutstandingLogout {
    /// Create an outstanding logout from the principal, sessions, and
    /// `NotOnOrAfter` the caller accepted.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the principal value is empty or
    /// `not_on_or_after` is not a representable SAML UTC `xs:dateTime`.
    pub fn try_new(
        principal: NameId,
        sessions: Vec<SessionIndex>,
        not_on_or_after: SamlInstant,
    ) -> Result<Self, SamlError> {
        if principal.value().trim().is_empty() {
            return Err(SamlError::Invalid(
                "outstanding logout principal must not be empty".into(),
            ));
        }
        let normalized = parse_saml_utc_date_time(not_on_or_after.as_str()).ok_or_else(|| {
            SamlError::Invalid(
                "outstanding logout NotOnOrAfter must be a SAML UTC xs:dateTime ending in Z".into(),
            )
        })?;
        let deadline = OffsetDateTime::parse(normalized, &Rfc3339).map_err(|_| {
            SamlError::Invalid(
                "outstanding logout NotOnOrAfter cannot be represented as a UTC instant".into(),
            )
        })?;
        let not_on_or_after = SamlInstant::try_new(normalized)?;
        Ok(Self {
            principal,
            sessions,
            not_on_or_after,
            deadline,
        })
    }

    /// Principal named by the accepted logout.
    pub fn principal(&self) -> &NameId {
        &self.principal
    }

    /// Sessions named by the accepted logout.
    ///
    /// Empty means the logout carried no `SessionIndex`.
    pub fn sessions(&self) -> &[SessionIndex] {
        &self.sessions
    }

    /// `NotOnOrAfter` from the accepted logout, normalized as a SAML UTC instant.
    pub fn not_on_or_after(&self) -> &SamlInstant {
        &self.not_on_or_after
    }

    pub(crate) fn matches_unexpired(
        &self,
        session: &SsoSession,
        validation: &SamlValidationContext<'_>,
    ) -> Result<bool, SamlError> {
        if !self.same_principal(session.name_id()) || !self.same_session(session) {
            return Ok(false);
        }
        let now = validation.now_offset()?;
        let effective = effective_not_on_or_after(
            self.deadline,
            validation.clock_skew().not_on_or_after_millis(),
        )?;
        Ok(now < effective)
    }

    fn same_principal(&self, name_id: &NameId) -> bool {
        if self.principal.value() != name_id.value() {
            return false;
        }
        self.principal
            .format()
            .is_none_or(|format| name_id.format() == Some(format))
    }

    fn same_session(&self, session: &SsoSession) -> bool {
        if self.sessions.is_empty() {
            return true;
        }
        session.authn_sessions().iter().any(|authn| {
            authn
                .session_index()
                .is_some_and(|index| self.sessions.contains(index))
        })
    }
}
