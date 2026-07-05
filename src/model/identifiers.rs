use crate::error::SamlError;

/// SAML protocol message `ID`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageId(String);

impl MessageId {
    /// Validate and wrap a SAML protocol message ID.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the message ID is empty.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(SamlError::Invalid(
                "SAML message ID must not be empty".into(),
            ));
        }
        Ok(Self(value))
    }

    /// Borrow the message ID string.
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
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
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
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
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
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
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
