//! Error types for `opensaml`.

/// Errors produced by the `opensaml` Service Provider library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenSamlError {
    /// Raw DEFLATE (de)compression failed.
    #[error("deflate error: {0}")]
    Deflate(#[from] std::io::Error),
    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Malformed or unexpected XML.
    #[error("xml error: {0}")]
    Xml(String),
    /// Input failed validation.
    #[error("invalid input: {0}")]
    Invalid(String),
    /// Functionality not yet implemented in the current milestone.
    #[error("unsupported: {0}")]
    Unsupported(String),
}
