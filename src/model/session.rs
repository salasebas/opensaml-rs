use super::identifiers::{SamlInstant, SessionIndex};
use crate::error::{SamlError, TimeWindowField};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Session data from one `AuthnStatement`.
///
/// Each value preserves the statement's `SessionIndex`, `AuthnInstant`, and
/// `SessionNotOnOrAfter` as one tuple. Assertions with repeated statements are
/// represented by multiple values in document order through
/// [`crate::SsoSession::authn_sessions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthnSession {
    session_index: Option<SessionIndex>,
    authn_instant: Option<SamlInstant>,
    not_on_or_after: Option<SamlInstant>,
}

pub(super) static EMPTY_AUTHN_SESSION: AuthnSession = AuthnSession {
    session_index: None,
    authn_instant: None,
    not_on_or_after: None,
};

pub(crate) fn earliest_authn_session_expiration<'a>(
    values: impl IntoIterator<Item = &'a str>,
    error_field: TimeWindowField,
) -> Result<Option<OffsetDateTime>, SamlError> {
    let mut earliest = None;
    for value in values {
        let candidate = OffsetDateTime::parse(value, &Rfc3339)
            .map_err(|_| SamlError::TimeWindowInvalid { field: error_field })?;
        if earliest.is_none_or(|current| candidate < current) {
            earliest = Some(candidate);
        }
    }
    Ok(earliest)
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
