use crate::constants::{Binding, CertUse, ParserType};
use crate::entity::EntitySetting;
use crate::error::SamlError;
use crate::flow::{flow, FlowOptions, FlowResult, HttpRequest};
use crate::metadata::Metadata;
use time::OffsetDateTime;

/// Parse a `<LogoutRequest>` from `from`.
///
/// # Errors
///
/// Returns an error if `binding` is unsupported, required binding parameters
/// are missing, the SAML payload cannot be base64/DEFLATE decoded, XML parsing
/// or extraction fails, the peer issuer does not match `from_meta`, or logout
/// request signature validation fails when `self_setting` requires signed
/// requests. Signature failures include missing signatures, untrusted signing
/// certificates, invalid detached signatures, RelayState/signed-octet
/// correlation failures, and XML signature validation errors.
pub fn parse_logout_request(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, SamlError> {
    parse_logout_request_inner(
        self_setting,
        from_meta,
        binding,
        request,
        None,
        self_setting.clock_drifts,
    )
}

pub(crate) fn parse_logout_request_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    now: OffsetDateTime,
    clock_drifts: (i64, i64),
) -> Result<FlowResult, SamlError> {
    parse_logout_request_inner(
        self_setting,
        from_meta,
        binding,
        request,
        Some(now),
        clock_drifts,
    )
}

fn parse_logout_request_inner(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    now: Option<OffsetDateTime>,
    clock_drifts: (i64, i64),
) -> Result<FlowResult, SamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    flow(
        &FlowOptions {
            binding: Some(binding),
            parser_type: Some(ParserType::LogoutRequest),
            check_signature: self_setting.want_logout_request_signed,
            from_issuer: from_meta.get_entity_id(),
            signing_certs: &signing_certs,
            decrypt_key: None,
            decrypt_key_pass: None,
            allow_insecure_software_rsa_key_transport_decryption: false,
            clock_drifts,
            now: now.map(Into::into),
            redirect_inflate_max_bytes: self_setting.redirect_inflate_max_bytes,
            xml_limits: self_setting.xml_limits,
            expected_audience: None,
            expected_in_response_to: None,
        },
        request,
    )
}

fn parse_logout_response_inner(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    expected_in_response_to: Option<&str>,
    now: Option<OffsetDateTime>,
    clock_drifts: (i64, i64),
) -> Result<FlowResult, SamlError> {
    let signing_certs = from_meta.x509_certificates(CertUse::Signing);
    flow(
        &FlowOptions {
            binding: Some(binding),
            parser_type: Some(ParserType::LogoutResponse),
            check_signature: self_setting.want_logout_response_signed,
            from_issuer: from_meta.get_entity_id(),
            signing_certs: &signing_certs,
            decrypt_key: None,
            decrypt_key_pass: None,
            allow_insecure_software_rsa_key_transport_decryption: false,
            clock_drifts,
            now: now.map(Into::into),
            redirect_inflate_max_bytes: self_setting.redirect_inflate_max_bytes,
            xml_limits: self_setting.xml_limits,
            expected_audience: None,
            expected_in_response_to,
        },
        request,
    )
}

/// Parse a `<LogoutResponse>` from `from` and require it to answer `request_id`.
///
/// Single Logout responses are state-machine messages. The caller must pass the
/// ID of the `LogoutRequest` it issued so stale or unrelated responses cannot be
/// accepted as completion for the current logout transaction.
///
/// An empty caller-provided `request_id` is rejected as
/// [`SamlError::InvalidInResponseTo`]. A non-empty `request_id` that does not
/// match the SAML response returns [`SamlError::InResponseToMismatch`].
///
/// # Errors
///
/// Returns an error if `request_id` is empty, `binding` is unsupported,
/// required binding parameters are missing, the SAML payload cannot be
/// base64/DEFLATE decoded, XML parsing or extraction fails, the peer issuer
/// does not match `from_meta`, `InResponseTo` does not match `request_id`, or
/// logout response signature validation fails when `self_setting` requires
/// signed responses. Signature failures include missing signatures, untrusted
/// signing certificates, invalid detached signatures, RelayState/signed-octet
/// correlation failures, and XML signature validation errors.
pub fn parse_logout_response(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    request_id: &str,
) -> Result<FlowResult, SamlError> {
    if request_id.is_empty() {
        return Err(SamlError::InvalidInResponseTo);
    }
    parse_logout_response_inner(
        self_setting,
        from_meta,
        binding,
        request,
        Some(request_id),
        None,
        self_setting.clock_drifts,
    )
}

pub(crate) fn parse_logout_response_at(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
    request_id: &str,
    now: OffsetDateTime,
    clock_drifts: (i64, i64),
) -> Result<FlowResult, SamlError> {
    if request_id.is_empty() {
        return Err(SamlError::InvalidInResponseTo);
    }
    parse_logout_response_inner(
        self_setting,
        from_meta,
        binding,
        request,
        Some(request_id),
        Some(now),
        clock_drifts,
    )
}

/// Parse a `<LogoutResponse>` without binding it to a `LogoutRequest` ID.
///
/// Prefer [`parse_logout_response`] for normal SLO handling. This exists for
/// legacy interop and custom state machines that perform request correlation
/// outside this crate.
///
/// # Errors
///
/// Returns an error if `binding` is unsupported, required binding parameters
/// are missing, the SAML payload cannot be base64/DEFLATE decoded, XML parsing
/// or extraction fails, the peer issuer does not match `from_meta`, or logout
/// response signature validation fails when `self_setting` requires signed
/// responses. Signature failures include missing signatures, untrusted signing
/// certificates, invalid detached signatures, RelayState/signed-octet
/// correlation failures, and XML signature validation errors. This function
/// deliberately does not enforce `InResponseTo` correlation.
pub fn parse_logout_response_without_request_id(
    self_setting: &EntitySetting,
    from_meta: &Metadata,
    binding: Binding,
    request: &HttpRequest,
) -> Result<FlowResult, SamlError> {
    parse_logout_response_inner(
        self_setting,
        from_meta,
        binding,
        request,
        None,
        None,
        self_setting.clock_drifts,
    )
}
