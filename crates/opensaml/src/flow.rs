//! Inbound message flow (samlify `flow.ts`): decode → validate XML/status →
//! (signature verify + optional decrypt) → extract → issuer/time validation.

use crate::binding::{
    base64_decode_with_limit, deflate_raw_decode_with_limit, MAX_DEFLATE_RAW_DECODE_BYTES,
};
use crate::constants::{Binding, ParserType};
use crate::context::is_valid_xml_with_limits;
use crate::error::OpenSamlError;
use crate::util::Value;
use crate::validator::{check_status_with_limits, verify_time};
use crate::xml::{extract_with_limits, fields, ExtractorField, XmlLimits};

const BEARER_SUBJECT_CONFIRMATION_METHOD: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

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

    fn query_get(&self, key: &str) -> Result<Option<&str>, OpenSamlError> {
        single_param(&self.query, key)
    }

    fn body_get(&self, key: &str) -> Result<Option<&str>, OpenSamlError> {
        single_param(&self.body, key)
    }
}

fn single_param<'a>(
    params: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, OpenSamlError> {
    let mut values = params
        .iter()
        .filter(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.as_str());
    let first = values.next();
    if values.next().is_some() {
        return Err(OpenSamlError::Invalid("ERR_AMBIGUOUS_FLOW_INPUT".into()));
    }
    Ok(first)
}

/// Inputs controlling a flow run.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct FlowOptions<'a> {
    /// Protocol binding.
    pub binding: Option<Binding>,
    /// Message parser type.
    pub parser_type: Option<ParserType>,
    /// Maximum decoded compressed and inflated raw-DEFLATE bytes accepted for
    /// HTTP-Redirect input.
    pub redirect_inflate_max_bytes: usize,
    /// XML parser resource limits for decoded messages and DOM reparses.
    pub xml_limits: XmlLimits,
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
    /// Allow XML-Enc RSA key-transport decryption with the bundled software RSA backend.
    ///
    /// Disabled by default because that path reaches `RUSTSEC-2023-0071`-affected
    /// code when an attacker can observe timing.
    pub allow_insecure_software_rsa_key_transport_decryption: bool,
    /// Clock drift tolerance `(not_before_ms, not_on_or_after_ms)`.
    pub clock_drifts: (i64, i64),
    /// Expected `<Audience>` (this SP's entity ID); `None` skips the check.
    pub expected_audience: Option<&'a str>,
    /// Expected `InResponseTo` (originating request ID); `None` skips the check.
    pub expected_in_response_to: Option<&'a str>,
}

impl<'a> Default for FlowOptions<'a> {
    fn default() -> Self {
        Self {
            binding: None,
            parser_type: None,
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            xml_limits: XmlLimits::default(),
            check_signature: false,
            from_issuer: None,
            signing_certs: &[],
            decrypt_key: None,
            decrypt_key_pass: None,
            allow_insecure_software_rsa_key_transport_decryption: false,
            clock_drifts: (0, 0),
            expected_audience: None,
            expected_in_response_to: None,
        }
    }
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
    redirect_inflate_max_bytes: usize,
    xml_limits: XmlLimits,
) -> Result<String, OpenSamlError> {
    let direction = parser_type.query_param();
    let bytes = match binding {
        Binding::Redirect => {
            let content = request
                .query_get(direction)?
                .ok_or_else(|| OpenSamlError::Invalid("ERR_REDIRECT_FLOW_BAD_ARGS".into()))?;
            let redirect_max_bytes = redirect_inflate_max_bytes.min(xml_limits.max_bytes);
            let compressed = base64_decode_with_limit(content, redirect_max_bytes)?;
            deflate_raw_decode_with_limit(&compressed, redirect_max_bytes)?
        }
        Binding::Post | Binding::SimpleSign => {
            let content = request
                .body_get(direction)?
                .ok_or_else(|| OpenSamlError::Invalid("ERR_FLOW_BAD_ARGS".into()))?;
            base64_decode_with_limit(content, xml_limits.max_bytes)?
        }
        Binding::Artifact => return Err(OpenSamlError::UndefinedBinding),
    };
    xml_limits.check_input_bytes(bytes.len())?;
    String::from_utf8(bytes).map_err(|e| OpenSamlError::Xml(e.to_string()))
}

fn assertion_shortcut(xml: &str, limits: XmlLimits) -> Result<Option<String>, OpenSamlError> {
    let field = ExtractorField::new("assertion", &["Response", "Assertion"]).with_context();
    Ok(
        extract_with_limits(xml, std::slice::from_ref(&field), limits)?
            .get_str("assertion")
            .map(str::to_string),
    )
}

#[cfg(feature = "crypto-bergshamra")]
fn verified_content_not_covered() -> OpenSamlError {
    OpenSamlError::Crypto("ERR_VERIFIED_REFERENCE_DOES_NOT_COVER_CONTENT".into())
}

#[cfg(feature = "crypto-bergshamra")]
fn decoded_octet_params(octet: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(octet.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

#[cfg(feature = "crypto-bergshamra")]
fn detached_mismatch() -> OpenSamlError {
    OpenSamlError::FailedMessageSignatureVerification
}

#[cfg(feature = "crypto-bergshamra")]
fn ensure_redirect_octet_matches_consumed_fields(
    parser_type: ParserType,
    request: &HttpRequest,
    sig_alg: &str,
    octet: &str,
) -> Result<(), OpenSamlError> {
    let direction = parser_type.query_param();
    let signed = decoded_octet_params(octet);
    if single_param(&signed, "Signature")?.is_some() {
        return Err(detached_mismatch());
    }

    let signed_message = single_param(&signed, direction)?.ok_or_else(detached_mismatch)?;
    let consumed_message = request
        .query_get(direction)?
        .ok_or_else(detached_mismatch)?;
    if signed_message != consumed_message {
        return Err(detached_mismatch());
    }

    let signed_sig_alg = single_param(&signed, "SigAlg")?.ok_or_else(detached_mismatch)?;
    if signed_sig_alg != sig_alg {
        return Err(detached_mismatch());
    }

    let signed_relay_state = single_param(&signed, "RelayState")?;
    let consumed_relay_state = request.query_get("RelayState")?;
    if signed_relay_state != consumed_relay_state {
        return Err(detached_mismatch());
    }

    Ok(())
}

#[cfg(feature = "crypto-bergshamra")]
fn ensure_simplesign_octet_matches_consumed_fields(
    parser_type: ParserType,
    request: &HttpRequest,
    xml: &str,
    sig_alg: &str,
    octet: &str,
) -> Result<(), OpenSamlError> {
    let direction = parser_type.query_param();
    request.body_get(direction)?.ok_or_else(detached_mismatch)?;

    let message_and_sig_alg = format!("{direction}={xml}&SigAlg={sig_alg}");
    let message_empty_relay_and_sig_alg = format!("{direction}={xml}&RelayState=&SigAlg={sig_alg}");
    let matches = match request.body_get("RelayState")? {
        Some(relay_state) => {
            let expected = format!("{direction}={xml}&RelayState={relay_state}&SigAlg={sig_alg}");
            octet == expected
        }
        // Existing outbound SimpleSign signs an empty RelayState field even
        // when the form body omits RelayState.
        None => octet == message_and_sig_alg || octet == message_empty_relay_and_sig_alg,
    };

    if matches {
        Ok(())
    } else {
        Err(detached_mismatch())
    }
}

#[cfg(feature = "crypto-bergshamra")]
fn ensure_detached_octet_matches_consumed_fields(
    binding: Binding,
    parser_type: ParserType,
    request: &HttpRequest,
    xml: &str,
    sig_alg: &str,
    octet: &str,
) -> Result<(), OpenSamlError> {
    match binding {
        Binding::Redirect => {
            ensure_redirect_octet_matches_consumed_fields(parser_type, request, sig_alg, octet)
        }
        Binding::SimpleSign => ensure_simplesign_octet_matches_consumed_fields(
            parser_type,
            request,
            xml,
            sig_alg,
            octet,
        ),
        Binding::Post | Binding::Artifact => Ok(()),
    }
}

/// Verify (and optionally decrypt) the message, returning the authenticated
/// `(saml_content, assertion)` (samlify `postFlow`). Requires `crypto-bergshamra`.
#[cfg(feature = "crypto-bergshamra")]
fn verify_and_prepare(
    xml: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
) -> Result<(String, Option<String>), OpenSamlError> {
    use crate::crypto::{
        decrypt_assertion_with_limits,
        enc::{software_rsa_decryption_disabled, AssertionDecryptionOptions},
        keys::load_private_key,
        verify_signature_with_limits,
    };

    let (verified, verified_node) =
        verify_signature_with_limits(xml, opts.signing_certs, opts.xml_limits)?;
    let decrypt_required = opts.decrypt_key.is_some();
    if decrypt_required && !opts.allow_insecure_software_rsa_key_transport_decryption {
        return Err(software_rsa_decryption_disabled());
    }
    let decrypt_options = AssertionDecryptionOptions {
        allow_insecure_software_rsa_key_transport_decryption: opts
            .allow_insecure_software_rsa_key_transport_decryption,
    };
    let load_key = || load_private_key(opts.decrypt_key.unwrap_or_default(), opts.decrypt_key_pass);

    if decrypt_required && verified && parser_type == ParserType::SamlResponse {
        if let Some(node) = verified_node {
            // signed-then-encrypted: the verified content is a Response carrying
            // an EncryptedAssertion.
            let (content, assertion) = decrypt_assertion_with_limits(
                &node,
                &load_key()?,
                decrypt_options,
                opts.xml_limits,
            )?;
            return Ok((content, Some(assertion)));
        }
    }
    if decrypt_required && !verified {
        // encrypted-then-signed: decrypt first, then verify the result.
        let (content, _) =
            decrypt_assertion_with_limits(xml, &load_key()?, decrypt_options, opts.xml_limits)?;
        let (re_verified, re_node) =
            verify_signature_with_limits(&content, opts.signing_certs, opts.xml_limits)?;
        return if re_verified {
            Ok((content, re_node))
        } else {
            Err(OpenSamlError::FailedToVerifySignature)
        };
    }
    if verified {
        if matches!(
            parser_type,
            ParserType::SamlRequest | ParserType::LogoutRequest | ParserType::LogoutResponse
        ) {
            let content = verified_node.ok_or_else(verified_content_not_covered)?;
            return Ok((content, None));
        }
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
    parser_type: ParserType,
    request: &HttpRequest,
    opts: &FlowOptions<'_>,
    xml: &str,
) -> Result<String, OpenSamlError> {
    let get = |k: &str| -> Result<Option<&str>, OpenSamlError> {
        match binding {
            Binding::Redirect => request.query_get(k),
            _ => request.body_get(k),
        }
    };
    let signature = get("Signature")?.ok_or(OpenSamlError::MissingSigAlg)?;
    let sig_alg = get("SigAlg")?.ok_or(OpenSamlError::MissingSigAlg)?;
    let octet = request
        .octet_string
        .as_deref()
        .ok_or(OpenSamlError::MissingSigAlg)?;
    ensure_detached_octet_matches_consumed_fields(
        binding,
        parser_type,
        request,
        xml,
        sig_alg,
        octet,
    )?;
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
    _parser_type: ParserType,
    _request: &HttpRequest,
    _opts: &FlowOptions<'_>,
    _xml: &str,
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

fn subject_confirmation_xmls(extracted: &Value) -> Vec<&str> {
    match extracted.get("subjectConfirmation") {
        Some(Value::Str(xml)) => vec![xml.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn is_valid_bearer_subject_confirmation(
    xml: &str,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<bool, OpenSamlError> {
    let fields = [
        ExtractorField::new("subjectConfirmation", &["SubjectConfirmation"]).attrs(&["Method"]),
        ExtractorField::new(
            "subjectConfirmationData",
            &["SubjectConfirmation", "SubjectConfirmationData"],
        )
        .attrs(&["NotOnOrAfter", "Recipient", "InResponseTo"]),
    ];
    let extracted = extract_with_limits(xml, &fields, opts.xml_limits)?;

    if extracted.get_str("subjectConfirmation") != Some(BEARER_SUBJECT_CONFIRMATION_METHOD) {
        return Ok(false);
    }

    let Some(not_on_or_after) = extracted.get_str("subjectConfirmationData.notOnOrAfter") else {
        return Ok(false);
    };
    if !verify_time(None, Some(not_on_or_after), opts.clock_drifts) {
        return Ok(false);
    }

    if let Some(expected) = expected_recipient {
        if extracted.get_str("subjectConfirmationData.recipient") != Some(expected) {
            return Ok(false);
        }
    }

    if let Some(expected) = opts.expected_in_response_to {
        if extracted.get_str("subjectConfirmationData.inResponseTo") != Some(expected) {
            return Ok(false);
        }
    }

    Ok(true)
}

fn validate_subject_confirmation(
    extracted: &Value,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), OpenSamlError> {
    for xml in subject_confirmation_xmls(extracted) {
        if is_valid_bearer_subject_confirmation(xml, opts, expected_recipient)? {
            return Ok(());
        }
    }
    Err(OpenSamlError::SubjectUnconfirmed)
}

fn validate_response_destination(
    extracted: &Value,
    expected_recipient: Option<&str>,
) -> Result<(), OpenSamlError> {
    let Some(expected) = expected_recipient else {
        return Ok(());
    };
    if let Some(destination) = extracted.get_str("response.destination") {
        if destination != expected {
            return Err(OpenSamlError::UnmatchDestination);
        }
    }
    Ok(())
}

fn validate_context(
    parser_type: ParserType,
    extracted: &Value,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), OpenSamlError> {
    let should_validate_issuer = matches!(
        parser_type,
        ParserType::SamlRequest
            | ParserType::SamlResponse
            | ParserType::LogoutRequest
            | ParserType::LogoutResponse
    );
    if should_validate_issuer {
        if let Some(expected) = opts.from_issuer {
            if extracted.get_str("issuer") != Some(expected) {
                return Err(OpenSamlError::UnmatchIssuer);
            }
        }
    }
    let is_response = matches!(
        parser_type,
        ParserType::SamlResponse | ParserType::LogoutResponse
    );
    if is_response {
        if let Some(expected) = opts.expected_in_response_to {
            if extracted.get_str("response.inResponseTo") != Some(expected) {
                return Err(OpenSamlError::InvalidInResponseTo);
            }
        }
    }
    if parser_type == ParserType::SamlResponse {
        validate_response_destination(extracted, expected_recipient)?;
        validate_subject_confirmation(extracted, opts, expected_recipient)?;
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

fn flow_inner(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: Option<&str>,
) -> Result<FlowResult, OpenSamlError> {
    let binding = opts.binding.ok_or(OpenSamlError::UndefinedBinding)?;
    let parser_type = opts
        .parser_type
        .ok_or_else(|| OpenSamlError::Invalid("ERR_UNDEFINED_PARSERTYPE".into()))?;

    let xml = decode_message(
        binding,
        parser_type,
        request,
        opts.redirect_inflate_max_bytes,
        opts.xml_limits,
    )?;
    is_valid_xml_with_limits(&xml, opts.xml_limits)?;
    check_status_with_limits(&xml, parser_type, opts.xml_limits)?;

    let (saml_content, assertion, sig_alg) = if opts.check_signature {
        match binding {
            Binding::Redirect | Binding::SimpleSign => {
                let sig_alg = verify_detached(binding, parser_type, request, opts, &xml)?;
                let assertion = if parser_type == ParserType::SamlResponse {
                    assertion_shortcut(&xml, opts.xml_limits)?
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
            assertion_shortcut(&xml, opts.xml_limits)?
        } else {
            None
        };
        (xml, assertion, None)
    };

    let fields = default_fields(parser_type, assertion.as_deref())?;
    let extracted = extract_with_limits(&saml_content, &fields, opts.xml_limits)?;
    validate_context(parser_type, &extracted, opts, expected_recipient)?;

    Ok(FlowResult {
        saml_content,
        extract: extracted,
        sig_alg,
    })
}

/// Run the inbound flow described by `opts` against `request`.
pub fn flow(opts: &FlowOptions<'_>, request: &HttpRequest) -> Result<FlowResult, OpenSamlError> {
    flow_inner(opts, request, None)
}

pub(crate) fn flow_with_expected_recipient(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: &str,
) -> Result<FlowResult, OpenSamlError> {
    flow_inner(opts, request, Some(expected_recipient))
}
