//! Base64 helpers with SAML whitespace normalization.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::error::OpenSamlError;

const BASE64_OUTPUT_LIMIT_EXCEEDED: &str = "ERR_BASE64_OUTPUT_LIMIT_EXCEEDED";

/// Standard base64 encoding (no line wrapping).
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Decode standard base64, ignoring any SAML-inserted whitespace.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, OpenSamlError> {
    let normalized: String = input.split_whitespace().collect();
    Ok(STANDARD.decode(normalized)?)
}

/// Decode standard base64, rejecting inputs whose decoded output would exceed
/// `max_output_len` bytes.
pub fn base64_decode_with_limit(
    input: &str,
    max_output_len: usize,
) -> Result<Vec<u8>, OpenSamlError> {
    let normalized_len = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .count();
    let max_encoded_len = max_output_len
        .saturating_add(2)
        .saturating_div(3)
        .saturating_mul(4);
    if normalized_len > max_encoded_len {
        return Err(OpenSamlError::Invalid(BASE64_OUTPUT_LIMIT_EXCEEDED.into()));
    }

    let mut normalized = String::with_capacity(normalized_len);
    normalized.extend(input.chars().filter(|ch| !ch.is_whitespace()));
    let out = STANDARD.decode(normalized)?;
    if out.len() > max_output_len {
        return Err(OpenSamlError::Invalid(BASE64_OUTPUT_LIMIT_EXCEEDED.into()));
    }
    Ok(out)
}
