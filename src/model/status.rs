use crate::constants::status_code;
use crate::error::SamlError;

/// Top-level `StatusCode` value on a SAML status response.
///
/// SAML Core 2.0 section 3.2.2.2 requires the topmost `StatusCode` `Value` to
/// be one of these four URIs. A second-level code is not a top-level value.
///
/// For a session authority, Core section 3.7.3.2 says this value reports only
/// that authority's own session: [`Self::Success`] when the authority
/// terminated it, and [`Self::Requester`], [`Self::Responder`], or
/// [`Self::VersionMismatch`] when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TopLevelStatusCode {
    /// `urn:oasis:names:tc:SAML:2.0:status:Success`.
    Success,
    /// `urn:oasis:names:tc:SAML:2.0:status:Requester`.
    Requester,
    /// `urn:oasis:names:tc:SAML:2.0:status:Responder`.
    Responder,
    /// `urn:oasis:names:tc:SAML:2.0:status:VersionMismatch`.
    VersionMismatch,
}

impl TopLevelStatusCode {
    /// Absolute URI carried in `StatusCode/@Value`.
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::Success => status_code::SUCCESS,
            Self::Requester => status_code::REQUESTER,
            Self::Responder => status_code::RESPONDER,
            Self::VersionMismatch => status_code::VERSION_MISMATCH,
        }
    }
}

/// Subordinate `StatusCode` nested inside the top-level code.
///
/// SAML Core 2.0 section 3.2.2.2 makes this element optional. The defined
/// second-level URIs live in [`crate::constants::status_code`]. A deployment
/// may also supply its own absolute URI. [`Self::partial_logout`] is the
/// second-level code Core section 3.7.3.2 requires from a session authority
/// when other session participants do not confirm logout. It does not replace
/// the top-level code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubordinateStatusCode {
    uri: String,
}

impl SubordinateStatusCode {
    /// `urn:oasis:names:tc:SAML:2.0:status:PartialLogout`.
    pub fn partial_logout() -> Self {
        Self {
            uri: status_code::PARTIAL_LOGOUT.to_string(),
        }
    }

    /// Wrap an absolute status-code URI.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when `uri` is empty, contains
    /// whitespace, or is not an absolute URI. Logout response generation
    /// rejects those values.
    pub fn try_new(uri: impl Into<String>) -> Result<Self, SamlError> {
        let uri = uri.into();
        if uri.is_empty() || uri.chars().any(char::is_whitespace) || url::Url::parse(&uri).is_err()
        {
            return Err(SamlError::Invalid(
                "subordinate status code must be a non-empty absolute URI without whitespace"
                    .into(),
            ));
        }
        Ok(Self { uri })
    }

    /// Absolute URI carried in the nested `StatusCode/@Value`.
    pub fn as_uri(&self) -> &str {
        &self.uri
    }
}

/// Status of a SAML `StatusResponseType`, including `Response` and `LogoutResponse`.
///
/// The same value is passed to a logout responder and can be passed later by
/// an identity provider issuing an error `Response`. Omitting it on
/// `respond_slo` selects [`Self::success`] with no subordinate code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    top_level: TopLevelStatusCode,
    subordinate: Option<SubordinateStatusCode>,
}

impl Status {
    /// Top-level `Success` and no subordinate code.
    pub fn success() -> Self {
        Self::from_top_level(TopLevelStatusCode::Success)
    }

    /// Top-level `Requester` and no subordinate code.
    pub fn requester() -> Self {
        Self::from_top_level(TopLevelStatusCode::Requester)
    }

    /// Top-level `Responder` and no subordinate code.
    pub fn responder() -> Self {
        Self::from_top_level(TopLevelStatusCode::Responder)
    }

    /// Top-level `VersionMismatch` and no subordinate code.
    pub fn version_mismatch() -> Self {
        Self::from_top_level(TopLevelStatusCode::VersionMismatch)
    }

    fn from_top_level(top_level: TopLevelStatusCode) -> Self {
        Self {
            top_level,
            subordinate: None,
        }
    }

    /// Nest a subordinate `StatusCode` under the top-level code.
    ///
    /// A later call replaces the previous subordinate code.
    #[must_use]
    pub fn with_subordinate(mut self, subordinate: SubordinateStatusCode) -> Self {
        self.subordinate = Some(subordinate);
        self
    }

    /// Top-level status code.
    pub fn top_level(&self) -> TopLevelStatusCode {
        self.top_level
    }

    /// Subordinate status code, when one was supplied.
    pub fn subordinate(&self) -> Option<&SubordinateStatusCode> {
        self.subordinate.as_ref()
    }
}
