use crate::error::SamlError;

/// Absolute HTTP(S) endpoint URL used by typed SAML endpoint wrappers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointUrl(String);

impl EndpointUrl {
    /// Validate and wrap an absolute HTTP(S) URL.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the URL is not absolute HTTP(S).
    pub fn try_new(value: impl Into<String>) -> Result<Self, SamlError> {
        let value = value.into();
        let parsed = url::Url::parse(&value).map_err(|err| SamlError::Invalid(err.to_string()))?;
        if matches!(parsed.scheme(), "http" | "https") && parsed.has_host() {
            return Ok(Self(value));
        }
        Err(SamlError::Invalid(
            "endpoint URL must be absolute HTTP(S)".into(),
        ))
    }

    /// Borrow the URL string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
