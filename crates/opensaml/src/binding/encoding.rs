//! Base64 helpers with SAML whitespace normalization.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::OpenSamlError;

/// Standard base64 encoding (no line wrapping).
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decode standard base64, ignoring any SAML-inserted whitespace.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, OpenSamlError> {
    let normalized: String = input.split_whitespace().collect();
    Ok(STANDARD.decode(normalized)?)
}
