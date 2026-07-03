//! HTTP-Redirect binding query construction.

use super::deflate::deflate_raw_encode;
use super::encoding::base64_encode;
use crate::constants::ParserType;
use crate::error::SamlError;
use url::form_urlencoded::byte_serialize;

fn url_encode(value: &str) -> String {
    byte_serialize(value.as_bytes()).collect()
}

fn has_query(base_url: &str) -> bool {
    base_url
        .split_once('?')
        .map(|(_, q)| !q.is_empty())
        .unwrap_or(false)
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

/// Build a full unsigned HTTP-Redirect URL.
///
/// DEFLATE → base64 → url-encode the message, choose `?`/`&` based on whether
/// `base_url` already carries a query, and append an optional `RelayState`.
pub fn build_redirect_url(
    base_url: &str,
    parser_type: ParserType,
    xml: &str,
    relay_state: Option<&str>,
) -> Result<String, SamlError> {
    let deflated = deflate_raw_encode(xml.as_bytes())?;
    let encoded = base64_encode(&deflated);
    let query = redirect_binding_query(parser_type.query_param(), &encoded, relay_state);
    let separator = if has_query(base_url) { '&' } else { '?' };
    Ok(format!("{base_url}{separator}{query}"))
}

/// Build the octet string to sign for a signed HTTP-Redirect message.
pub fn build_redirect_octet(
    parser_type: ParserType,
    xml: &str,
    relay_state: Option<&str>,
    sig_alg: &str,
) -> Result<String, SamlError> {
    let deflated = deflate_raw_encode(xml.as_bytes())?;
    let encoded = base64_encode(&deflated);
    let mut octet = format!("{}={}", parser_type.query_param(), url_encode(&encoded));
    if let Some(state) = relay_state {
        octet.push_str(&format!("&RelayState={}", url_encode(state)));
    }
    octet.push_str(&format!("&SigAlg={}", url_encode(sig_alg)));
    Ok(octet)
}

/// Finish a signed HTTP-Redirect URL: `base_url[?&]<octet>&Signature=<enc(sig)>`.
pub fn append_signature(base_url: &str, octet: &str, signature_b64: &str) -> String {
    let separator = if has_query(base_url) { '&' } else { '?' };
    format!(
        "{base_url}{separator}{octet}&Signature={}",
        url_encode(signature_b64)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{base64_decode, deflate_raw_decode, saml_post_binding_form};
    use url::Url;

    const REQUEST: &str = "<samlp:AuthnRequest ID=\"_1\">hi&amp;bye</samlp:AuthnRequest>";

    #[test]
    fn redirect_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let url = build_redirect_url(
            "https://idp.example.com/sso",
            ParserType::SamlRequest,
            REQUEST,
            Some("state 1"),
        )?;
        assert!(url.starts_with("https://idp.example.com/sso?SAMLRequest="));
        let parsed = Url::parse(&url)?;
        let mut pairs = parsed.query_pairs();
        let (k, v) = pairs.next().ok_or("missing SAMLRequest")?;
        assert_eq!(k, "SAMLRequest");
        let inflated = deflate_raw_decode(&base64_decode(&v)?)?;
        assert_eq!(String::from_utf8(inflated)?, REQUEST);
        let relay = parsed
            .query_pairs()
            .find(|(k, _)| k == "RelayState")
            .map(|(_, v)| v.into_owned());
        assert_eq!(relay.as_deref(), Some("state 1"));
        Ok(())
    }

    #[test]
    fn redirect_uses_amp_when_base_has_query() -> Result<(), Box<dyn std::error::Error>> {
        let url = build_redirect_url(
            "http://sp.example.com/acs?x=1",
            ParserType::SamlResponse,
            REQUEST,
            None,
        )?;
        assert!(url.contains("?x=1&SAMLResponse="));
        Ok(())
    }

    #[test]
    fn post_and_simplesign_base64_message() -> Result<(), Box<dyn std::error::Error>> {
        // POST / SimpleSign carry base64(xml) verbatim (no DEFLATE)
        let b64 = base64_encode(REQUEST.as_bytes());
        assert_eq!(String::from_utf8(base64_decode(&b64)?)?, REQUEST);
        let form = saml_post_binding_form(
            "https://idp.example.com/sso",
            ParserType::SamlRequest.query_param(),
            &b64,
            None,
        );
        assert!(form.contains("name=\"SAMLRequest\""));
        assert!(form.contains(&b64));
        Ok(())
    }
}
