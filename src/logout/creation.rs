use crate::constants::{status_code, Binding, ParserType};
use crate::entity::{generate_id, now_iso8601, BindingContext, EntitySetting, User};
use crate::error::SamlError;
use crate::metadata::Metadata;
use crate::template::{
    apply_tag_prefixes, replace_tags_by_optional_value, replace_tags_by_value, validate_tag_prefix,
};
use crate::xml::dom::parse_roots_with_limits;

use super::bindings::unsigned_context;
use super::rendering::{
    issuer_of, render_default_logout_request, render_default_logout_response, LogoutRequestSubject,
};
use super::signing::sign_logout;

/// Build a `<LogoutRequest>` from `init` to `target`.
///
/// `user` supplies the `<NameID>` and optional `<samlp:SessionIndex>`.
///
/// # Errors
///
/// Returns an error if `target_meta` has no SLO endpoint for `binding`,
/// `binding` is unsupported, the configured logout template cannot represent
/// the supplied subject, configured XML tag prefixes are invalid, default XML
/// rendering fails, or Redirect DEFLATE encoding fails. When `want_signed` is
/// true, missing or invalid signing keys/certificates, unavailable crypto
/// support, XML signature construction, and detached-signature construction
/// errors are propagated.
pub fn create_logout_request(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &User,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
    create_logout_request_with_id(
        init_setting,
        init_meta,
        target_meta,
        binding,
        user,
        relay_state,
        want_signed,
        None,
    )
}

/// Like [`create_logout_request`] but uses `message_id` when provided.
///
/// # Errors
///
/// Returns the same errors as [`create_logout_request`]. Empty `message_id`
/// values are ignored and replaced with a generated ID.
#[allow(clippy::too_many_arguments)] // public API adds optional `message_id`
pub fn create_logout_request_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    user: &User,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, SamlError> {
    let name_id_format = init_setting
        .name_id_format
        .first()
        .cloned()
        .unwrap_or_default();
    let issue_instant = now_iso8601();
    let subject = LogoutRequestSubject::from_user(user);
    create_logout_request_for_subject_inner(LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        subject: &subject,
        relay_state,
        want_signed,
        message_id,
        name_id_format: &name_id_format,
        issue_instant: &issue_instant,
    })
}

pub(crate) struct LogoutRequestSessionIndexes<'a> {
    pub(crate) init_setting: &'a EntitySetting,
    pub(crate) init_meta: &'a Metadata,
    pub(crate) target_meta: &'a Metadata,
    pub(crate) binding: Binding,
    pub(crate) name_id: &'a str,
    pub(crate) session_indexes: &'a [String],
    pub(crate) relay_state: Option<&'a str>,
    pub(crate) want_signed: bool,
}

pub(crate) fn create_logout_request_with_session_indexes(
    input: LogoutRequestSessionIndexes<'_>,
) -> Result<BindingContext, SamlError> {
    let LogoutRequestSessionIndexes {
        init_setting,
        init_meta,
        target_meta,
        binding,
        name_id,
        session_indexes,
        relay_state,
        want_signed,
    } = input;

    let name_id_format = init_setting
        .name_id_format
        .first()
        .cloned()
        .unwrap_or_default();
    let issue_instant = now_iso8601();
    let subject = LogoutRequestSubject {
        name_id,
        session_indexes: session_indexes.iter().map(String::as_str).collect(),
    };
    create_logout_request_for_subject_inner(LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        subject: &subject,
        relay_state,
        want_signed,
        message_id: None,
        name_id_format: &name_id_format,
        issue_instant: &issue_instant,
    })
}

struct LogoutRequestInput<'a> {
    init_setting: &'a EntitySetting,
    init_meta: &'a Metadata,
    target_meta: &'a Metadata,
    binding: Binding,
    subject: &'a LogoutRequestSubject<'a>,
    relay_state: Option<&'a str>,
    want_signed: bool,
    message_id: Option<&'a str>,
    name_id_format: &'a str,
    issue_instant: &'a str,
}

fn create_logout_request_for_subject_inner(
    input: LogoutRequestInput<'_>,
) -> Result<BindingContext, SamlError> {
    let LogoutRequestInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        subject,
        relay_state,
        want_signed,
        message_id,
        name_id_format,
        issue_instant,
    } = input;

    let destination = target_meta
        .get_single_logout_service(binding)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let xml = if let Some(template) = init_setting.logout_request_template.as_deref() {
        if subject.session_indexes.len() > 1 {
            return Err(SamlError::Unsupported(
                "custom LogoutRequest templates cannot render multiple SessionIndex values".into(),
            ));
        }
        validate_tag_prefix("protocol", &init_setting.tag_prefix_protocol)?;
        validate_tag_prefix("assertion", &init_setting.tag_prefix_assertion)?;
        let template = apply_tag_prefixes(
            template,
            &init_setting.tag_prefix_protocol,
            &init_setting.tag_prefix_assertion,
        );
        replace_tags_by_optional_value(
            &template,
            &[
                ("ID", Some(id.clone())),
                ("IssueInstant", Some(issue_instant.to_string())),
                ("Destination", Some(destination.clone())),
                ("Issuer", Some(issuer_of(init_setting, init_meta))),
                ("NameIDFormat", Some(name_id_format.to_string())),
                ("NameID", Some(subject.name_id.to_string())),
                (
                    "SessionIndex",
                    subject
                        .session_indexes
                        .first()
                        .map(|value| (*value).to_string()),
                ),
            ],
        )
    } else {
        render_default_logout_request(
            init_setting,
            init_meta,
            &id,
            issue_instant,
            &destination,
            subject,
            name_id_format,
        )?
    };
    let (context, signature, sig_alg) = if want_signed {
        sign_logout(
            init_setting,
            binding,
            &xml,
            &destination,
            relay_state,
            ParserType::LogoutRequest,
        )?
    } else {
        (
            unsigned_context(
                binding,
                &xml,
                &destination,
                ParserType::LogoutRequest,
                relay_state,
            )?,
            None,
            None,
        )
    };
    Ok(BindingContext {
        id,
        context,
        relay_state: relay_state.map(str::to_string),
        entity_endpoint: destination,
        binding,
        request_type: "SAMLRequest",
        signature,
        sig_alg,
    })
}

/// Build a `<LogoutResponse>` from `init` to `target`.
///
/// # Errors
///
/// Returns an error if `binding` is unsupported, `target_meta` has no SLO
/// endpoint for `binding`, configured XML tag prefixes are invalid, default XML
/// rendering fails, or Redirect DEFLATE encoding fails. When `want_signed` is
/// true, missing or invalid signing keys/certificates, unavailable crypto
/// support, XML signature construction, and detached-signature construction
/// errors are propagated.
pub fn create_logout_response(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
    create_logout_response_with_id(
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        None,
    )
}

struct LogoutResponseInput<'a> {
    init_setting: &'a EntitySetting,
    init_meta: &'a Metadata,
    target_meta: &'a Metadata,
    binding: Binding,
    in_response_to: Option<&'a str>,
    relay_state: Option<&'a str>,
    want_signed: bool,
    message_id: Option<&'a str>,
    validate_template_in_response_to: bool,
}

/// Like [`create_logout_response`] but uses `message_id` when provided.
///
/// # Errors
///
/// Returns the same errors as [`create_logout_response`]. Empty `message_id`
/// values are ignored and replaced with a generated ID.
#[allow(clippy::too_many_arguments)] // public API adds optional `message_id`
pub fn create_logout_response_with_id(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
    message_id: Option<&str>,
) -> Result<BindingContext, SamlError> {
    create_logout_response_inner(LogoutResponseInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        message_id,
        validate_template_in_response_to: false,
    })
}

pub(crate) fn create_logout_response_checked(
    init_setting: &EntitySetting,
    init_meta: &Metadata,
    target_meta: &Metadata,
    binding: Binding,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    want_signed: bool,
) -> Result<BindingContext, SamlError> {
    create_logout_response_inner(LogoutResponseInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        message_id: None,
        validate_template_in_response_to: true,
    })
}

fn create_logout_response_inner(
    input: LogoutResponseInput<'_>,
) -> Result<BindingContext, SamlError> {
    let LogoutResponseInput {
        init_setting,
        init_meta,
        target_meta,
        binding,
        in_response_to,
        relay_state,
        want_signed,
        message_id,
        validate_template_in_response_to,
    } = input;

    if matches!(binding, Binding::Artifact) {
        return Err(SamlError::UnsupportedBinding {
            binding: Binding::Artifact,
        });
    }
    let destination = target_meta
        .get_single_logout_service(binding)
        .ok_or_else(|| SamlError::MissingMetadata("SingleLogoutService".into()))?;
    let id = message_id
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(generate_id);
    let issue_instant = now_iso8601();
    let xml = if let Some(template) = init_setting.logout_response_template.as_deref() {
        validate_tag_prefix("protocol", &init_setting.tag_prefix_protocol)?;
        validate_tag_prefix("assertion", &init_setting.tag_prefix_assertion)?;
        let template = apply_tag_prefixes(
            template,
            &init_setting.tag_prefix_protocol,
            &init_setting.tag_prefix_assertion,
        );
        replace_tags_by_value(
            &template,
            &[
                ("ID", id.clone()),
                ("IssueInstant", issue_instant),
                ("Destination", destination.clone()),
                (
                    "InResponseTo",
                    in_response_to.unwrap_or_default().to_string(),
                ),
                ("Issuer", issuer_of(init_setting, init_meta)),
                ("StatusCode", status_code::SUCCESS.to_string()),
            ],
        )
    } else {
        render_default_logout_response(
            init_setting,
            init_meta,
            &id,
            &issue_instant,
            &destination,
            in_response_to,
        )?
    };
    if validate_template_in_response_to && init_setting.logout_response_template.is_some() {
        validate_logout_response_in_response_to(&xml, in_response_to, init_setting.xml_limits)?;
    }
    let (context, signature, sig_alg) = if want_signed {
        sign_logout(
            init_setting,
            binding,
            &xml,
            &destination,
            relay_state,
            ParserType::LogoutResponse,
        )?
    } else {
        (
            unsigned_context(
                binding,
                &xml,
                &destination,
                ParserType::LogoutResponse,
                relay_state,
            )?,
            None,
            None,
        )
    };
    Ok(BindingContext {
        id,
        context,
        relay_state: relay_state.map(str::to_string),
        entity_endpoint: destination,
        binding,
        request_type: "SAMLResponse",
        signature,
        sig_alg,
    })
}

fn validate_logout_response_in_response_to(
    xml: &str,
    expected: Option<&str>,
    limits: crate::xml::XmlLimits,
) -> Result<(), SamlError> {
    let roots = parse_roots_with_limits(xml, limits)?;
    let actual = roots
        .iter()
        .find(|node| node.local_name == "LogoutResponse")
        .and_then(|node| node.attr("InResponseTo"))
        .filter(|value| !value.is_empty());
    if actual == expected {
        return Ok(());
    }
    Err(SamlError::in_response_to_mismatch(expected, actual))
}
