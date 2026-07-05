use super::identifiers::{SamlInstant, SessionIndex};

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
