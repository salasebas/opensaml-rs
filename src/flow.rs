//! Inbound message flow: decode, validate XML/status, verify signatures,
//! optionally decrypt, extract fields, and validate issuer/time constraints.

use crate::binding::{
    base64_decode_with_limit, deflate_raw_decode_with_limit, MAX_DEFLATE_RAW_DECODE_BYTES,
};
use crate::constants::{Binding, ParserType};
use crate::context::is_valid_xml_with_limits;
#[cfg(feature = "crypto-bergshamra")]
use crate::error::SignatureVerificationReason;
use crate::error::{SamlError, SubjectConfirmationReason, TimeWindowField};
#[cfg(feature = "crypto-bergshamra")]
use crate::model::RelayStateParam;
use crate::model::{authn_statement_not_on_or_after_values, earliest_authn_session_expiration};
use crate::util::Value;
use crate::validator::{
    check_status_with_limits, conditions_time_bounds, logout_request_not_on_or_after_deadline,
    verify_time_at,
};
use crate::xml::{
    extract_with_limits, fields, validate_protocol_profile, ExtractorField, XmlLimits,
};
use std::time::SystemTime;
use time::{Duration, OffsetDateTime};

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

    fn query_get(&self, key: &str) -> Result<Option<&str>, SamlError> {
        single_param(&self.query, key)
    }

    fn body_get(&self, key: &str) -> Result<Option<&str>, SamlError> {
        single_param(&self.body, key)
    }
}

fn single_param<'a>(
    params: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, SamlError> {
    let mut values = params
        .iter()
        .filter(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.as_str());
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid("ERR_AMBIGUOUS_FLOW_INPUT".into()));
    }
    Ok(first)
}

fn missing_binding_parameter(name: &'static str) -> SamlError {
    SamlError::MissingBindingParameter { name }
}

fn unsupported_binding(binding: Binding) -> SamlError {
    SamlError::UnsupportedBinding { binding }
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
    /// Validation instant. `None` keeps raw compatibility behavior by reading
    /// the process clock during validation.
    pub now: Option<SystemTime>,
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
            now: None,
            expected_audience: None,
            expected_in_response_to: None,
        }
    }
}

impl FlowOptions<'_> {
    fn validation_now(&self) -> Result<OffsetDateTime, SamlError> {
        self.now.map_or_else(
            || Ok(OffsetDateTime::now_utc()),
            crate::validator::offset_datetime_from_system_time,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssertionSignatureRequirement {
    Compatible,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageSignatureRequirement {
    Compatible,
    Response,
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
) -> Result<Vec<ExtractorField>, SamlError> {
    Ok(match parser_type {
        ParserType::SamlRequest => fields::login_request_fields(),
        ParserType::SamlResponse => {
            let assertion =
                assertion.ok_or_else(|| SamlError::Xml("ERR_EMPTY_ASSERTION".into()))?;
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
) -> Result<String, SamlError> {
    let direction = parser_type.query_param();
    let bytes = match binding {
        Binding::Redirect => {
            let content = request
                .query_get(direction)?
                .ok_or_else(|| missing_binding_parameter(direction))?;
            let redirect_max_bytes = redirect_inflate_max_bytes.min(xml_limits.max_bytes);
            let compressed = base64_decode_with_limit(content, redirect_max_bytes)?;
            deflate_raw_decode_with_limit(&compressed, redirect_max_bytes)?
        }
        Binding::Post | Binding::SimpleSign => {
            let content = request
                .body_get(direction)?
                .ok_or_else(|| missing_binding_parameter(direction))?;
            base64_decode_with_limit(content, xml_limits.max_bytes)?
        }
        Binding::Artifact => return Err(unsupported_binding(binding)),
    };
    xml_limits.check_input_bytes(bytes.len())?;
    String::from_utf8(bytes).map_err(|e| SamlError::Xml(e.to_string()))
}

fn assertion_shortcut(xml: &str, limits: XmlLimits) -> Result<Option<String>, SamlError> {
    let field = ExtractorField::new("assertion", &["Response", "Assertion"]).with_context();
    Ok(
        extract_with_limits(xml, std::slice::from_ref(&field), limits)?
            .get_str("assertion")
            .map(str::to_string),
    )
}

#[cfg(feature = "crypto-bergshamra")]
fn verified_content_not_covered() -> SamlError {
    SamlError::SignedReferenceMismatch
}

#[cfg(feature = "crypto-bergshamra")]
fn decoded_octet_params(octet: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(octet.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

#[cfg(feature = "crypto-bergshamra")]
fn detached_signature_verification() -> SamlError {
    SamlError::SignatureVerification {
        reason: SignatureVerificationReason::DetachedMessageSignature,
    }
}

#[cfg(feature = "crypto-bergshamra")]
fn relay_state_param(value: Option<&str>) -> Option<RelayStateParam> {
    RelayStateParam::try_from_option(value.map(str::to_string)).ok()
}

#[cfg(feature = "crypto-bergshamra")]
fn detached_relay_state_mismatch(expected: Option<&str>, actual: Option<&str>) -> SamlError {
    match (relay_state_param(expected), relay_state_param(actual)) {
        (Some(expected), Some(actual)) => SamlError::RelayStateMismatch { expected, actual },
        _ => SamlError::SignatureVerification {
            reason: SignatureVerificationReason::RelayStateCorrelation,
        },
    }
}

#[cfg(feature = "crypto-bergshamra")]
fn ensure_redirect_octet_matches_consumed_fields(
    parser_type: ParserType,
    request: &HttpRequest,
    sig_alg: &str,
    octet: &str,
) -> Result<(), SamlError> {
    let direction = parser_type.query_param();
    let signed = decoded_octet_params(octet);
    if single_param(&signed, "Signature")?.is_some() {
        return Err(detached_signature_verification());
    }

    let signed_message =
        single_param(&signed, direction)?.ok_or_else(|| missing_binding_parameter(direction))?;
    let consumed_message = request
        .query_get(direction)?
        .ok_or_else(|| missing_binding_parameter(direction))?;
    if signed_message != consumed_message {
        return Err(detached_signature_verification());
    }

    let signed_sig_alg =
        single_param(&signed, "SigAlg")?.ok_or_else(|| missing_binding_parameter("SigAlg"))?;
    if signed_sig_alg != sig_alg {
        return Err(detached_signature_verification());
    }

    let signed_relay_state = single_param(&signed, "RelayState")?;
    let consumed_relay_state = request.query_get("RelayState")?;
    if signed_relay_state != consumed_relay_state {
        return Err(detached_relay_state_mismatch(
            signed_relay_state,
            consumed_relay_state,
        ));
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
) -> Result<(), SamlError> {
    let direction = parser_type.query_param();
    request
        .body_get(direction)?
        .ok_or_else(|| missing_binding_parameter(direction))?;

    let message_and_sig_alg = format!("{direction}={xml}&SigAlg={sig_alg}");
    let message_empty_relay_and_sig_alg = format!("{direction}={xml}&RelayState=&SigAlg={sig_alg}");
    let matches = match request.body_get("RelayState")? {
        Some(relay_state) => {
            let expected = format!("{direction}={xml}&RelayState={relay_state}&SigAlg={sig_alg}");
            octet == expected
        }
        // Older saml-rs outbound SimpleSign signed an empty RelayState field
        // even when the form body omitted RelayState; keep accepting it for
        // compatibility.
        None => octet == message_and_sig_alg || octet == message_empty_relay_and_sig_alg,
    };

    if matches {
        Ok(())
    } else {
        Err(detached_signature_verification())
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
) -> Result<(), SamlError> {
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

#[cfg(feature = "crypto-bergshamra")]
fn required_xml_signature_failed(signature_present: bool) -> SamlError {
    if signature_present {
        SamlError::SignatureVerification {
            reason: SignatureVerificationReason::XmlSignature,
        }
    } else {
        SamlError::SignatureMissing
    }
}

#[cfg(feature = "crypto-bergshamra")]
fn verify_embedded_signature(
    xml: &str,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
    message_signature: MessageSignatureRequirement,
) -> Result<(bool, Option<String>, bool, bool), SamlError> {
    use crate::crypto::verify::{
        verify_signature_with_limits, verify_signatures_detailed_with_limits,
    };

    match (assertion_signature, message_signature) {
        (AssertionSignatureRequirement::Compatible, MessageSignatureRequirement::Compatible) => {
            let (verified, signed_content) =
                verify_signature_with_limits(xml, opts.signing_certs, opts.xml_limits)?;
            Ok((verified, signed_content, false, false))
        }
        _ => {
            let verification =
                verify_signatures_detailed_with_limits(xml, opts.signing_certs, opts.xml_limits)?;
            let verified = verification.verified();
            let assertion_directly_covered = verification.assertion_directly_covered();
            let response_covered = verification.response_covered();
            Ok((
                verified,
                verification.into_signed_content(),
                assertion_directly_covered,
                response_covered,
            ))
        }
    }
}

#[cfg(feature = "crypto-bergshamra")]
fn require_direct_assertion_coverage(
    assertion_signature: AssertionSignatureRequirement,
    assertion_directly_covered: bool,
) -> Result<(), SamlError> {
    if assertion_signature == AssertionSignatureRequirement::Direct && !assertion_directly_covered {
        return Err(SamlError::AssertionSignatureRequired);
    }
    Ok(())
}

#[cfg(feature = "crypto-bergshamra")]
fn require_response_coverage(
    message_signature: MessageSignatureRequirement,
    response_covered: bool,
) -> Result<(), SamlError> {
    if message_signature == MessageSignatureRequirement::Response && !response_covered {
        return Err(SamlError::SignedReferenceMismatch);
    }
    Ok(())
}

/// Verify and optionally decrypt the message, returning the authenticated
/// `(saml_content, assertion)`. Requires `crypto-bergshamra`.
#[cfg(feature = "crypto-bergshamra")]
fn verify_and_prepare(
    xml: &str,
    parser_type: ParserType,
    opts: &FlowOptions<'_>,
    assertion_signature: AssertionSignatureRequirement,
    message_signature: MessageSignatureRequirement,
) -> Result<(String, Option<String>), SamlError> {
    use crate::crypto::{
        decrypt_assertion_with_limits,
        enc::{software_rsa_decryption_disabled, AssertionDecryptionOptions},
        keys::load_private_key,
        verify::has_xml_signature_with_limits,
    };

    let signature_present = has_xml_signature_with_limits(xml, opts.xml_limits)?;
    let (verified, verified_node, assertion_directly_covered, response_covered) =
        verify_embedded_signature(xml, opts, assertion_signature, message_signature)?;
    if message_signature == MessageSignatureRequirement::Response {
        if !verified {
            return Err(required_xml_signature_failed(signature_present));
        }
        require_response_coverage(message_signature, response_covered)?;
    }
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
            is_valid_xml_with_limits(&content, opts.xml_limits)?;
            validate_protocol_profile(&content, parser_type, opts.xml_limits)?;
            if assertion_signature == AssertionSignatureRequirement::Direct {
                let decrypted_signature_present =
                    has_xml_signature_with_limits(&assertion, opts.xml_limits)?;
                let (decrypted_verified, _, decrypted_assertion_covered, _) =
                    verify_embedded_signature(
                        &assertion,
                        opts,
                        assertion_signature,
                        MessageSignatureRequirement::Compatible,
                    )?;
                if !decrypted_verified {
                    return Err(required_xml_signature_failed(decrypted_signature_present));
                }
                require_direct_assertion_coverage(
                    assertion_signature,
                    decrypted_assertion_covered,
                )?;
            }
            return Ok((content, Some(assertion)));
        }
    }
    if decrypt_required && !verified {
        // encrypted-then-signed: decrypt first, then verify the result.
        let (content, assertion) =
            decrypt_assertion_with_limits(xml, &load_key()?, decrypt_options, opts.xml_limits)?;
        is_valid_xml_with_limits(&content, opts.xml_limits)?;
        validate_protocol_profile(&content, parser_type, opts.xml_limits)?;
        let verification_xml = if assertion_signature == AssertionSignatureRequirement::Direct {
            assertion.as_str()
        } else {
            content.as_str()
        };
        let signature_present = has_xml_signature_with_limits(verification_xml, opts.xml_limits)?;
        let (re_verified, re_node, re_assertion_directly_covered, _) = verify_embedded_signature(
            verification_xml,
            opts,
            assertion_signature,
            MessageSignatureRequirement::Compatible,
        )?;
        return if re_verified {
            require_direct_assertion_coverage(assertion_signature, re_assertion_directly_covered)?;
            let verified_assertion = if assertion_signature == AssertionSignatureRequirement::Direct
            {
                Some(assertion)
            } else {
                re_node
            };
            Ok((content, verified_assertion))
        } else {
            Err(required_xml_signature_failed(signature_present))
        };
    }
    if verified {
        require_direct_assertion_coverage(assertion_signature, assertion_directly_covered)?;
        if matches!(
            parser_type,
            ParserType::SamlRequest | ParserType::LogoutRequest | ParserType::LogoutResponse
        ) {
            let content = verified_node.ok_or_else(verified_content_not_covered)?;
            return Ok((content, None));
        }
        return Ok((xml.to_string(), verified_node));
    }
    Err(required_xml_signature_failed(signature_present))
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn verify_and_prepare(
    _xml: &str,
    _parser_type: ParserType,
    _opts: &FlowOptions<'_>,
    _assertion_signature: AssertionSignatureRequirement,
    _message_signature: MessageSignatureRequirement,
) -> Result<(String, Option<String>), SamlError> {
    Err(SamlError::Unsupported(
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
) -> Result<String, SamlError> {
    let get = |k: &str| -> Result<Option<&str>, SamlError> {
        match binding {
            Binding::Redirect => request.query_get(k),
            _ => request.body_get(k),
        }
    };
    let signature = get("Signature")?.ok_or(SamlError::SignatureMissing)?;
    let sig_alg = get("SigAlg")?.ok_or_else(|| missing_binding_parameter("SigAlg"))?;
    let octet = request
        .octet_string
        .as_deref()
        .ok_or_else(|| missing_binding_parameter("octet_string"))?;
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
        Err(detached_signature_verification())
    }
}

#[cfg(not(feature = "crypto-bergshamra"))]
fn verify_detached(
    _binding: Binding,
    _parser_type: ParserType,
    _request: &HttpRequest,
    _opts: &FlowOptions<'_>,
    _xml: &str,
) -> Result<String, SamlError> {
    Err(SamlError::Unsupported(
        "signature verification requires feature crypto-bergshamra".into(),
    ))
}

fn audience_restriction_contains(
    audience_restriction: &str,
    expected: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    let field = ExtractorField::new("audience", &["AudienceRestriction", "Audience"]);
    let extracted =
        extract_with_limits(audience_restriction, std::slice::from_ref(&field), limits)?;
    Ok(match extracted.get("audience") {
        Some(Value::Str(audience)) => audience == expected,
        Some(Value::Array(audiences)) => audiences
            .iter()
            .any(|audience| audience.as_str() == Some(expected)),
        _ => false,
    })
}

fn audience_restrictions_contain(
    assertion: Option<&str>,
    expected: &str,
    limits: XmlLimits,
) -> Result<bool, SamlError> {
    let Some(assertion) = assertion else {
        return Ok(false);
    };
    let field = ExtractorField::new(
        "audienceRestriction",
        &["Assertion", "Conditions", "AudienceRestriction"],
    )
    .with_context();
    let extracted = extract_with_limits(assertion, std::slice::from_ref(&field), limits)?;

    match extracted.get("audienceRestriction") {
        Some(Value::Str(audience_restriction)) => {
            audience_restriction_contains(audience_restriction, expected, limits)
        }
        Some(Value::Array(audience_restrictions)) if !audience_restrictions.is_empty() => {
            for audience_restriction in audience_restrictions {
                let Some(audience_restriction) = audience_restriction.as_str() else {
                    return Ok(false);
                };
                if !audience_restriction_contains(audience_restriction, expected, limits)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn subject_confirmation_xmls(extracted: &Value) -> Vec<&str> {
    match extracted.get("subjectConfirmation") {
        Some(Value::Str(xml)) => vec![xml.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubjectConfirmationCheck {
    Valid,
    Invalid(SubjectConfirmationReason),
}

fn check_bearer_subject_confirmation(
    xml: &str,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<SubjectConfirmationCheck, SamlError> {
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
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::InvalidMethod,
        ));
    }

    let Some(not_on_or_after) = extracted.get_str("subjectConfirmationData.notOnOrAfter") else {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::MissingNotOnOrAfter,
        ));
    };
    if !verify_time_at(
        None,
        Some(not_on_or_after),
        opts.clock_drifts,
        opts.validation_now()?,
    ) {
        return Ok(SubjectConfirmationCheck::Invalid(
            SubjectConfirmationReason::TimeWindowInvalid,
        ));
    }

    if let Some(expected) = expected_recipient {
        if extracted.get_str("subjectConfirmationData.recipient") != Some(expected) {
            return Ok(SubjectConfirmationCheck::Invalid(
                SubjectConfirmationReason::RecipientMismatch,
            ));
        }
    }

    if let Some(expected) = opts.expected_in_response_to {
        if extracted.get_str("subjectConfirmationData.inResponseTo") != Some(expected) {
            return Ok(SubjectConfirmationCheck::Invalid(
                SubjectConfirmationReason::InResponseToMismatch,
            ));
        }
    }

    Ok(SubjectConfirmationCheck::Valid)
}

fn validate_subject_confirmation(
    extracted: &Value,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), SamlError> {
    let mut reason = None;
    for xml in subject_confirmation_xmls(extracted) {
        match check_bearer_subject_confirmation(xml, opts, expected_recipient)? {
            SubjectConfirmationCheck::Valid => return Ok(()),
            SubjectConfirmationCheck::Invalid(current) => reason = Some(current),
        }
    }
    Err(SamlError::SubjectConfirmationInvalid {
        reason: reason.unwrap_or(SubjectConfirmationReason::MissingBearerConfirmation),
    })
}

fn validate_response_destination(
    extracted: &Value,
    expected_recipient: Option<&str>,
) -> Result<(), SamlError> {
    let Some(expected) = expected_recipient else {
        return Ok(());
    };
    if let Some(destination) = extracted.get_str("response.destination") {
        if destination != expected {
            return Err(SamlError::destination_mismatch(expected, Some(destination)));
        }
    }
    Ok(())
}

fn validate_context(
    parser_type: ParserType,
    assertion: Option<&str>,
    extracted: &Value,
    opts: &FlowOptions<'_>,
    expected_recipient: Option<&str>,
) -> Result<(), SamlError> {
    let should_validate_issuer = matches!(
        parser_type,
        ParserType::SamlRequest
            | ParserType::SamlResponse
            | ParserType::LogoutRequest
            | ParserType::LogoutResponse
    );
    if should_validate_issuer {
        if let Some(expected) = opts.from_issuer {
            let actual = extracted.get_str("issuer");
            if actual != Some(expected) {
                return Err(SamlError::issuer_mismatch(expected, actual));
            }
        }
    }
    let is_response = matches!(
        parser_type,
        ParserType::SamlResponse | ParserType::LogoutResponse
    );
    if is_response {
        if let Some(expected) = opts.expected_in_response_to {
            let actual = extracted.get_str("response.inResponseTo");
            if actual != Some(expected) {
                return Err(SamlError::in_response_to_mismatch(Some(expected), actual));
            }
        }
    }
    if parser_type == ParserType::SamlResponse {
        validate_response_destination(extracted, expected_recipient)?;
        validate_subject_confirmation(extracted, opts, expected_recipient)?;
        if let Some(expected) = opts.expected_audience {
            if !audience_restrictions_contain(assertion, expected, opts.xml_limits)? {
                return Err(SamlError::AudienceMismatch {
                    expected: expected.to_string(),
                });
            }
        }
        let session_bounds = authn_statement_not_on_or_after_values(extracted)?;
        if let Some(raw_expiration) =
            earliest_authn_session_expiration(session_bounds, TimeWindowField::SessionNotOnOrAfter)?
        {
            let expiration = raw_expiration
                .checked_add(Duration::milliseconds(opts.clock_drifts.1))
                .ok_or(SamlError::TimeWindowInvalid {
                    field: TimeWindowField::SessionNotOnOrAfter,
                })?;
            if opts.validation_now()? >= expiration {
                return Err(SamlError::TimeWindowInvalid {
                    field: TimeWindowField::SessionNotOnOrAfter,
                });
            }
        }
        let (not_before, not_on_or_after) = conditions_time_bounds(extracted)?;
        if !verify_time_at(
            not_before,
            not_on_or_after,
            opts.clock_drifts,
            opts.validation_now()?,
        ) {
            return Err(SamlError::TimeWindowInvalid {
                field: TimeWindowField::Conditions,
            });
        }
    }
    if parser_type == ParserType::LogoutRequest {
        logout_request_not_on_or_after_deadline(
            extracted,
            opts.validation_now()?,
            opts.clock_drifts.1,
        )?;
    }
    Ok(())
}

fn flow_inner(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: Option<&str>,
    assertion_signature: AssertionSignatureRequirement,
    message_signature: MessageSignatureRequirement,
) -> Result<FlowResult, SamlError> {
    let binding = opts
        .binding
        .ok_or_else(|| missing_binding_parameter("binding"))?;
    let parser_type = opts
        .parser_type
        .ok_or_else(|| SamlError::Invalid("ERR_UNDEFINED_PARSERTYPE".into()))?;

    let xml = decode_message(
        binding,
        parser_type,
        request,
        opts.redirect_inflate_max_bytes,
        opts.xml_limits,
    )?;
    is_valid_xml_with_limits(&xml, opts.xml_limits)?;
    validate_protocol_profile(&xml, parser_type, opts.xml_limits)?;
    check_status_with_limits(&xml, parser_type, opts.xml_limits)?;

    let (saml_content, assertion, sig_alg) = if opts.check_signature {
        match binding {
            Binding::Redirect | Binding::SimpleSign => {
                let sig_alg = verify_detached(binding, parser_type, request, opts, &xml)?;
                let (saml_content, assertion) = if parser_type == ParserType::SamlResponse
                    && assertion_signature == AssertionSignatureRequirement::Direct
                {
                    verify_and_prepare(
                        &xml,
                        parser_type,
                        opts,
                        assertion_signature,
                        MessageSignatureRequirement::Compatible,
                    )?
                } else {
                    let assertion = if parser_type == ParserType::SamlResponse {
                        assertion_shortcut(&xml, opts.xml_limits)?
                    } else {
                        None
                    };
                    (xml, assertion)
                };
                (saml_content, assertion, Some(sig_alg))
            }
            _ => {
                let (content, assertion) = verify_and_prepare(
                    &xml,
                    parser_type,
                    opts,
                    assertion_signature,
                    message_signature,
                )?;
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
    validate_context(
        parser_type,
        assertion.as_deref(),
        &extracted,
        opts,
        expected_recipient,
    )?;

    Ok(FlowResult {
        saml_content,
        extract: extracted,
        sig_alg,
    })
}

/// Run the inbound flow described by `opts` against `request`.
pub fn flow(opts: &FlowOptions<'_>, request: &HttpRequest) -> Result<FlowResult, SamlError> {
    flow_inner(
        opts,
        request,
        None,
        AssertionSignatureRequirement::Compatible,
        MessageSignatureRequirement::Compatible,
    )
}

pub(crate) fn flow_with_expected_recipient(
    opts: &FlowOptions<'_>,
    request: &HttpRequest,
    expected_recipient: &str,
    assertion_signature: AssertionSignatureRequirement,
    message_signature: MessageSignatureRequirement,
) -> Result<FlowResult, SamlError> {
    flow_inner(
        opts,
        request,
        Some(expected_recipient),
        assertion_signature,
        message_signature,
    )
}
