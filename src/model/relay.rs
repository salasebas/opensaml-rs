use crate::error::SamlError;

/// SAML Bindings 2.0 recommends limiting RelayState to 80 bytes.
///
/// Reference: <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf>.
pub const MAX_RELAY_STATE_BYTES: usize = 80;

/// RelayState value when a browser message carries the parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayState(String);

impl RelayState {
    pub(crate) fn from_preserved_value(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Wrap a RelayState value after enforcing the SAML Bindings byte limit.
    ///
    /// Explicit empty RelayState is allowed so callers can preserve browser
    /// parameter presence separately from absence.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the UTF-8 byte length exceeds
    /// [`MAX_RELAY_STATE_BYTES`].
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        validate_relay_state_bytes(&value)?;
        Ok(Self(value))
    }

    /// Borrow the RelayState string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RelayState represented as absent, present empty, or present with a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RelayStateParam {
    /// No RelayState parameter was sent.
    Absent,
    /// RelayState was sent with an empty value.
    PresentEmpty,
    /// RelayState was sent with a non-empty value.
    PresentValue(RelayState),
}

impl RelayStateParam {
    /// Preserve the exact RelayState presence state from an optional value.
    pub fn from_option(value: Option<impl Into<String>>) -> Self {
        match value {
            None => Self::Absent,
            Some(value) => {
                let value = value.into();
                if value.is_empty() {
                    Self::PresentEmpty
                } else {
                    Self::PresentValue(RelayState::from_preserved_value(value))
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
        if let Some(value) = self.as_deref() {
            validate_relay_state_bytes(value)?;
        }
        Ok(())
    }
}

fn validate_relay_state_bytes(value: &str) -> Result<(), SamlError> {
    if value.len() > MAX_RELAY_STATE_BYTES {
        return Err(SamlError::Invalid(
            "RelayState exceeds SAML Bindings 80-byte limit".into(),
        ));
    }
    Ok(())
}
