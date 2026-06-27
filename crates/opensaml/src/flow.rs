//! Inbound message flow (samlify `flow.ts`): decode → validate XML/status →
//! (signature verify + optional decrypt) → extract → issuer/time validation.

use crate::binding::{base64_decode, deflate_raw_decode};
use crate::constants::{Binding, ParserType};
use crate::context::is_valid_xml;
use crate::error::OpenSamlError;
use crate::util::Value;
use crate::validator::{check_status, verify_time};
use crate::xml::{extract, fields, ExtractorField};

/// Decoded HTTP request inputs for a binding.
#[derive(Debug, Default, Clone)]
pub struct HttpRequest {
    /// URL-decoded query parameters (HTTP-Redirect).
    pub query: Vec<(String, String)>,
    /// Form body parameters (HTTP-POST / SimpleSign).
    pub body: Vec<(String, String)>,
    /// Signed octet string for detached-signature verification.
    pub octet_string: Option<String>,
}

impl HttpRequest {
    /// HTTP-Redirect request from query pairs.
    pub fn redirect(query: Vec<(String, String)>) -> Self {
        Self {
            query,
            ..Default::default()
        }
    }

    /// HTTP-POST/SimpleSign request from body pairs.
    pub fn post(body: Vec<(String, String)>) -> Self {
        Self {
            body,
            ..Default::default()
        }
    }

    fn query_get(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    fn body_get(&self, key: &str) -> Option<&str> {
        self.body
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Inputs controlling a flow run.
#[derive(Debug, Default, Clone)]
pub struct FlowOptions<'a> {
    /// Protocol binding.
    pub binding: Option<Binding>,
    /// Message parser type.
    pub parser_type: Option<ParserType>,
    /// Whether to require and verify a signature.
    pub check_signature: bool,
    /// Expected issuer (peer `entityID`).
    pub from_issuer: Option<&'a str>,
    /// Peer signing certificate(s) for verification.
    pub signing_certs: &'a [String],
    /// Our decryption private key PEM (when assertions are encrypted).
    pub decrypt_key: Option<&'a str>,
    /// Passphrase for `decrypt_key`.
    pub decrypt_key_pass: Option<&'a str>,
    /// Clock drift tolerance `(not_before_ms, not_on_or_after_ms)`.
    pub clock_drifts: (i64, i64),
    /// Expected `<Audience>` (this SP's entity ID); `None` skips the check.
    pub expected_audience: Option<&'a str>,
    /// Expected `InResponseTo` (originating request ID); `None` skips the check.
    pub expected_in_response_to: Option<&'a str>,
}

/// Result of a successful flow.
#[derive(Debug, Clone)]
pub struct FlowResult {
    /// The decoded (and, when verified, authenticated) SAML XML.
    pub saml_content: String,
    /// Extracted fields.
    pub extract: Value,
    /// Verified signature algorithm, if a signature was checked.
    pub sig_alg: Option<String>,
}

fn default_fields(
    parser_type: ParserType,
    assertion: Option<&str>,
) -> Result<Vec<ExtractorField>, OpenSamlError> {
    Ok(match parser_type {
        ParserType::SamlRequest => fields::login_request_fields(),
        ParserType::SamlResponse => {
            let assertion =
                assertion.ok_or_else(|| OpenSamlError::Xml("ERR_EMPTY_ASSERTION".into()))?;
            fields::login_response_fields(assertion)
        }
        ParserType::LogoutRequest => fields::logout_request_fields(),
        ParserType::LogoutResponse => fields::logout_response_fields(),
    })
}

fn decode_message(
    binding: Binding,
    parser_type: ParserType,
    request: &HttpRequest,
) -> Result<String, OpenSamlError> {
    let direction = parser_type.query_param();
    let bytes = match binding {
        Binding::Redirect => {
            let content = request
                .query_get(direction)
                .ok_or_else(|| OpenSamlError::Invalid("ERR_REDIRECT_FLOW_BAD_ARGS".into()))?;
            deflate_raw_decode(&base64_decode(content)?)?
        }
        Binding::Post | Binding::SimpleSign => {
            let content = request
                .body_get(direction)
                .ok_or_else(|| OpenSamlError::Invalid("ERR_FLOW_BAD_ARGS".into()))?;
            base64_decode(content)?
        }
        Binding::Artifact => return Err(OpenSamlError::UndefinedBinding),
    };
    String::from_utf8(bytes).map_err(|e| OpenSamlError::Xml(e.to_string()))
}

fn assertion_shortcut(xml: &str) -> Result<Option<String>, OpenSamlError> {
    let field = ExtractorField::new("assertion", &["Response", "Assertion"]).with_context();
    Ok(extract(xml, std::slice::from_ref(&field))?
        .get_str("assertion")
        .map(str::to_string))
}

/// Verify (and optionally decrypt) the message, returning the authenticated
/// `(saml_content, assertion)` (samlify `postFlow`). Requires `crypto-bergshamra`.
#[cfg(feature = "crypto-bergshamra")]
fn verify_and_prepare(
    xml: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
) -> Result<(String, Option<String>), OpenSamlError> {
    use crate::crypto::{decrypt_assertion, keys::load_private_key, verify_signature};

    let (verified, verified_node) = verify_signature(xml, opts.signing_certs)?;
    let decrypt_required = opts.decrypt_key.is_some();
    let load_key = || load_private_key(opts.decrypt_key.unwrap_or_default(), opts.decrypt_key_pass);

    if decrypt_required && verified && parser_type == ParserType::SamlResponse {
        if let Some(node) = verified_node {
            // signed-then-encrypted: the verified content is a Response carrying
            // an EncryptedAssertion.
            let (content, assertion) = decrypt_assertion(&node, &load_key()?)?;
            return Ok((content, Some(assertion)));
        }
    }
    if decrypt_required && !verified {
        // encrypted-then-signed: decrypt first, then verify the result.
        let (content, _) = decrypt_assertion(xml, &load_key()?)?;
        let (re_verified, re_node) = verify_signature(&content, opts.signing_certs)?;
        return if re_verified {
            Ok((content, re_node))
        } else {
            Err(OpenSamlError::FailedToVerifySignature)
        };
    }
    if verified {
        return Ok((xml.to_string(), verified_node));
    }
    Err(OpenSamlError::FailedToVerifySignature)
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn verify_and_prepare(
    _xml: &str,
    _parser_type: ParserType,
    _opts: &FlowOptions<'_>,
) -> Result<(String, Option<String>), OpenSamlError> {
    Err(OpenSamlError::Unsupported(
        "signature verification requires feature crypto-bergshamra".into(),
    ))
}

/// Verify a detached (redirect/SimpleSign) message signature, returning the
/// verified `SigAlg`. Requires `crypto-bergshamra`.
#[cfg(feature = "crypto-bergshamra")]
fn verify_detached(
    binding: Binding,
    request: &HttpRequest,
    opts: &FlowOptions<'_>,
) -> Result<String, OpenSamlError> {
    let get = |k: &str| match binding {
        Binding::Redirect => request.query_get(k),
        _ => request.body_get(k),
    };
    let signature = get("Signature").ok_or(OpenSamlError::MissingSigAlg)?;
    let sig_alg = get("SigAlg").ok_or(OpenSamlError::MissingSigAlg)?;
    let octet = request
        .octet_string
        .as_deref()
        .ok_or(OpenSamlError::MissingSigAlg)?;
    let verified = opts.signing_certs.iter().any(|cert| {
        crate::crypto::verify_message_signature(octet, signature, cert, sig_alg).unwrap_or(false)
    });
    if verified {
        Ok(sig_alg.to_string())
    } else {
        Err(OpenSamlError::FailedMessageSignatureVerification)
    }
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn verify_detached(
    _binding: Binding,
    _request: &HttpRequest,
    _opts: &FlowOptions<'_>,
) -> Result<String, OpenSamlError> {
    Err(OpenSamlError::Unsupported(
        "signature verification requires feature crypto-bergshamra".into(),
    ))
}

fn audience_contains(extracted: &Value, expected: &str) -> bool {
    match extracted.get("audience") {
        Some(Value::Str(s)) => s == expected,
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn validate_context(
    parser_type: ParserType,
    extracted: &Value,
    opts: &FlowOptions<'_>,
) -> Result<(), OpenSamlError> {
    let is_response = matches!(
        parser_type,
        ParserType::SamlResponse | ParserType::LogoutResponse
    );
    if is_response {
        if let Some(expected) = opts.from_issuer {
            if extracted.get_str("issuer") != Some(expected) {
                return Err(OpenSamlError::UnmatchIssuer);
            }
        }
        if let Some(expected) = opts.expected_in_response_to {
            if extracted.get_str("response.inResponseTo") != Some(expected) {
                return Err(OpenSamlError::InvalidInResponseTo);
            }
        }
    }
    if parser_type == ParserType::SamlResponse {
        if let Some(expected) = opts.expected_audience {
            if !audience_contains(extracted, expected) {
                return Err(OpenSamlError::UnmatchAudience);
            }
        }
        if let Some(session_not_on_or_after) = extracted.get_str("sessionIndex.sessionNotOnOrAfter")
        {
            if !verify_time(None, Some(session_not_on_or_after), opts.clock_drifts) {
                return Err(OpenSamlError::ExpiredSession);
            }
        }
        if let Some(conditions) = extracted.get("conditions") {
            let not_before = conditions.get_str("notBefore");
            let not_on_or_after = conditions.get_str("notOnOrAfter");
            if !verify_time(not_before, not_on_or_after, opts.clock_drifts) {
                return Err(OpenSamlError::SubjectUnconfirmed);
            }
        }
    }
    Ok(())
}

/// Run the inbound flow described by `opts` against `request`.
pub fn flow(opts: &FlowOptions<'_>, request: &HttpRequest) -> Result<FlowResult, OpenSamlError> {
    let binding = opts.binding.ok_or(OpenSamlError::UndefinedBinding)?;
    let parser_type = opts
        .parser_type
        .ok_or_else(|| OpenSamlError::Invalid("ERR_UNDEFINED_PARSERTYPE".into()))?;

    let xml = decode_message(binding, parser_type, request)?;
    is_valid_xml(&xml)?;
    check_status(&xml, parser_type)?;

    let (saml_content, assertion, sig_alg) = if opts.check_signature {
        match binding {
            Binding::Redirect | Binding::SimpleSign => {
                let sig_alg = verify_detached(binding, request, opts)?;
                let assertion = if parser_type == ParserType::SamlResponse {
                    assertion_shortcut(&xml)?
                } else {
                    None
                };
                (xml, assertion, Some(sig_alg))
            }
            _ => {
                let (content, assertion) = verify_and_prepare(&xml, parser_type, opts)?;
                (content, assertion, None)
            }
        }
    } else {
        let assertion = if parser_type == ParserType::SamlResponse {
            assertion_shortcut(&xml)?
        } else {
            None
        };
        (xml, assertion, None)
    };

    let fields = default_fields(parser_type, assertion.as_deref())?;
    let extracted = extract(&saml_content, &fields)?;
    validate_context(parser_type, &extracted, opts)?;

    Ok(FlowResult {
        saml_content,
        extract: extracted,
        sig_alg,
    })
}
