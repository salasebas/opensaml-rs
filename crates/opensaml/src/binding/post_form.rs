//! HTTP-POST binding auto-submit form.

use super::escape::html_escape;
use crate::error::OpenSamlError;
use url::Url;

const UNSAFE_POST_BINDING_ACTION_URL: &str = "ERR_UNSAFE_POST_BINDING_ACTION_URL";

/// Build a self-submitting HTML form for the SAML HTTP-POST binding.
///
/// `param_name` is `SAMLRequest` or `SAMLResponse`; `b64_value` is the
/// base64-encoded message. An optional `relay_state` is added as a hidden
/// field. All values are HTML-escaped.
pub fn saml_post_binding_form(
    action: &str,
    param_name: &str,
    b64_value: &str,
    relay_state: Option<&str>,
) -> String {
    let action = html_escape(action);
    let name = html_escape(param_name);
    let value = html_escape(b64_value);
    let mut fields = format!("<input type=\"hidden\" name=\"{name}\" value=\"{value}\"/>");
    if let Some(state) = relay_state {
        let state = html_escape(state);
        fields.push_str(&format!(
            "<input type=\"hidden\" name=\"RelayState\" value=\"{state}\"/>"
        ));
    }
    format!(
        "<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">\
<form method=\"post\" action=\"{action}\">{fields}\
<noscript><input type=\"submit\" value=\"Continue\"/></noscript></form></body></html>"
    )
}

/// Build a self-submitting HTML form after validating the action URL.
///
/// Accepts only absolute `http` and `https` URLs for the form `action`.
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
    validate_post_form_action(action)?;
    Ok(saml_post_binding_form(
        action,
        param_name,
        b64_value,
        relay_state,
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
