//! HTTP-Redirect binding query construction.

use url::form_urlencoded::byte_serialize;

fn url_encode(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

/// Build the unsigned query string for the SAML HTTP-Redirect binding.
///
/// `saml_param` is `SAMLRequest` or `SAMLResponse`; `b64_value` is the
/// base64-encoded, raw-DEFLATEd message. For a signed redirect, append
/// `&SigAlg=<uri>&Signature=<b64>` computed over this encoded query (M2).
pub fn redirect_binding_query(
    saml_param: &str,
    b64_value: &str,
    relay_state: Option<&str>,
) -> String {
    let value = url_encode(b64_value);
    let mut query = format!("{saml_param}={value}");
    if let Some(state) = relay_state {
        let state = url_encode(state);
        query.push_str(&format!("&RelayState={state}"));
    }
    query
}
