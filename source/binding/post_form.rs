//! HTTP-POST binding auto-submit form.

use super::escape::html_escape;
use crate::error::OpenSamlError;
use url::Url;

const UNSAFE_POST_BINDING_ACTION_URL: &str = "ERR_UNSAFE_POST_BINDING_ACTION_URL";
const PARTIAL_POST_BINDING_SIGNATURE: &str = "ERR_PARTIAL_POST_BINDING_SIGNATURE";

struct HiddenField<'a> {
    name: &'a str,
    value: &'a str,
}

fn render_post_form(action: &str, fields: &[HiddenField<'_>]) -> String {
    let action = html_escape(action);
    let fields = fields
        .iter()
        .map(|field| {
            let name = html_escape(field.name);
            let value = html_escape(field.value);
            format!("<input type=\"hidden\" name=\"{name}\" value=\"{value}\"/>")
        })
        .collect::<String>();
    format!(
        "<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">\
<form method=\"post\" action=\"{action}\">{fields}\
<noscript><input type=\"submit\" value=\"Continue\"/></noscript></form></body></html>"
    )
}

fn binding_fields<'a>(
    param_name: &'a str,
    b64_value: &'a str,
    relay_state: Option<&'a str>,
    sig_alg: Option<&'a str>,
    signature: Option<&'a str>,
) -> Vec<HiddenField<'a>> {
    let mut fields = vec![HiddenField {
        name: param_name,
        value: b64_value,
    }];
    if let Some(state) = relay_state {
        fields.push(HiddenField {
            name: "RelayState",
            value: state,
        });
    }
    if let (Some(sig_alg), Some(signature)) = (sig_alg, signature) {
        fields.push(HiddenField {
            name: "SigAlg",
            value: sig_alg,
        });
        fields.push(HiddenField {
            name: "Signature",
            value: signature,
        });
    }
    fields
}

fn validate_signature_fields(
    sig_alg: Option<&str>,
    signature: Option<&str>,
) -> Result<(), OpenSamlError> {
    match (sig_alg, signature) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(OpenSamlError::Invalid(
            PARTIAL_POST_BINDING_SIGNATURE.into(),
        )),
    }
}

/// Build a self-submitting HTML form for the SAML HTTP-POST binding.
///
/// `param_name` is `SAMLRequest` or `SAMLResponse`; `b64_value` is the
/// base64-encoded message. An optional `relay_state` is added as a hidden
/// field. All values are HTML-escaped.
///
/// This compatibility helper does not validate the `action` URL. Prefer
/// [`try_saml_post_binding_form`] when rendering a browser-bound response from
/// configurable or otherwise untrusted endpoints.
pub fn saml_post_binding_form(
    action: &str,
    param_name: &str,
    b64_value: &str,
    relay_state: Option<&str>,
) -> String {
    let fields = binding_fields(param_name, b64_value, relay_state, None, None);
    render_post_form(action, &fields)
}

pub(crate) fn saml_post_binding_form_with_signature(
    action: &str,
    param_name: &str,
    b64_value: &str,
    relay_state: Option<&str>,
    sig_alg: Option<&str>,
    signature: Option<&str>,
) -> String {
    let fields = binding_fields(param_name, b64_value, relay_state, sig_alg, signature);
    render_post_form(action, &fields)
}

/// Build a self-submitting HTML form after validating the action URL.
///
/// This is the safe browser path for SAML POST forms. It accepts only absolute
/// `http` and `https` URLs for the form `action`.
///
/// # Errors
///
/// Returns [`OpenSamlError::Invalid`] when `action` is not an absolute HTTP(S)
/// URL.
pub fn try_saml_post_binding_form(
    action: &str,
    param_name: &str,
    b64_value: &str,
    relay_state: Option<&str>,
) -> Result<String, OpenSamlError> {
    try_saml_post_binding_form_with_signature(
        action,
        param_name,
        b64_value,
        relay_state,
        None,
        None,
    )
}

pub(crate) fn try_saml_post_binding_form_with_signature(
    action: &str,
    param_name: &str,
    b64_value: &str,
    relay_state: Option<&str>,
    sig_alg: Option<&str>,
    signature: Option<&str>,
) -> Result<String, OpenSamlError> {
    validate_post_form_action(action)?;
    validate_signature_fields(sig_alg, signature)?;
    Ok(saml_post_binding_form_with_signature(
        action,
        param_name,
        b64_value,
        relay_state,
        sig_alg,
        signature,
    ))
}

fn validate_post_form_action(action: &str) -> Result<(), OpenSamlError> {
    let url = Url::parse(action)
        .map_err(|_| OpenSamlError::Invalid(UNSAFE_POST_BINDING_ACTION_URL.into()))?;
    if matches!(url.scheme(), "http" | "https") && url.has_host() {
        Ok(())
    } else {
        Err(OpenSamlError::Invalid(
            UNSAFE_POST_BINDING_ACTION_URL.into(),
        ))
    }
}
