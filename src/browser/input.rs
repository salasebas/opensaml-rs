//! Inbound browser message conversion helpers.
//!
//! References: SAML Bindings 2.0 <https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf> and HTTP POST-SimpleSign <https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-binding-simplesign.html>.

use core::marker::PhantomData;

use super::forms::FormField;
use crate::binding::{base64_decode_with_limit, build_simplesign_octet};
use crate::constants::url_params;
use crate::error::SamlError;
use crate::raw::HttpRequest;
use crate::xml::XmlLimits;

/// Typed browser input for inbound SAML messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserInput<Message> {
    /// HTTP-Redirect input as a raw query string.
    Redirect {
        /// Raw URL query, with or without a leading `?`.
        raw_query: String,
        /// Message marker.
        _message: PhantomData<Message>,
    },
    /// HTTP-POST input as parsed form fields.
    Post {
        /// Parsed form fields.
        fields: Vec<FormField>,
        /// Message marker.
        _message: PhantomData<Message>,
    },
    /// HTTP-POST-SimpleSign input.
    SimpleSignPost {
        /// Raw form body.
        raw_body: String,
        /// Parsed form fields.
        fields: Vec<FormField>,
        /// Message marker.
        _message: PhantomData<Message>,
    },
}

impl<Message> BrowserInput<Message> {
    /// Create Redirect input from a raw query string.
    pub fn redirect(raw_query: impl Into<String>) -> Self {
        Self::Redirect {
            raw_query: raw_query.into(),
            _message: PhantomData,
        }
    }

    /// Create POST input from parsed fields.
    pub fn post(fields: Vec<FormField>) -> Self {
        Self::Post {
            fields,
            _message: PhantomData,
        }
    }

    /// Create SimpleSign input from parsed fields.
    pub fn simple_sign(fields: Vec<FormField>) -> Self {
        Self::SimpleSignPost {
            raw_body: String::new(),
            fields,
            _message: PhantomData,
        }
    }

    /// Parse a raw `application/x-www-form-urlencoded` SimpleSign body.
    pub fn simple_sign_body(raw_body: impl Into<String>) -> Self {
        let raw_body = raw_body.into();
        let fields = parse_form_fields(&raw_body);
        Self::SimpleSignPost {
            raw_body,
            fields,
            _message: PhantomData,
        }
    }
}

impl<Message> TryFrom<BrowserInput<Message>> for HttpRequest {
    type Error = SamlError;

    fn try_from(value: BrowserInput<Message>) -> Result<Self, Self::Error> {
        match value {
            BrowserInput::Redirect { raw_query, .. } => {
                let raw_query = raw_query.trim_start_matches('?').to_string();
                let octet_string = redirect_octet_from_raw_query(&raw_query)?;
                let query = parse_form_pairs(&raw_query);
                Ok(HttpRequest {
                    query,
                    octet_string,
                    ..Default::default()
                })
            }
            BrowserInput::Post { fields, .. } => Ok(HttpRequest::post(fields_to_pairs(fields))),
            BrowserInput::SimpleSignPost {
                raw_body,
                mut fields,
                ..
            } => {
                if fields.is_empty() {
                    fields = parse_form_fields(&raw_body);
                }
                let octet_string = simplesign_octet_from_fields(&fields)?;
                let mut request = HttpRequest::post(fields_to_pairs(fields));
                request.octet_string = Some(octet_string);
                Ok(request)
            }
        }
    }
}

struct RawQueryParam<'a> {
    name: &'a str,
    encoded_value: &'a str,
}

fn raw_query_params(raw_query: &str) -> impl Iterator<Item = RawQueryParam<'_>> {
    raw_query
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.split_once('=') {
            Some((name, encoded_value)) => RawQueryParam {
                name,
                encoded_value,
            },
            None => RawQueryParam {
                name: segment,
                encoded_value: "",
            },
        })
}

fn unique_encoded_query_value<'a>(
    params: &'a [RawQueryParam<'a>],
    name: &str,
) -> Result<Option<&'a str>, SamlError> {
    let mut values = params
        .iter()
        .filter(|param| param.name == name)
        .map(|param| param.encoded_value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid(format!(
            "ambiguous Redirect field {name}"
        )));
    }
    Ok(first)
}

fn redirect_octet_from_raw_query(raw_query: &str) -> Result<Option<String>, SamlError> {
    let params: Vec<_> = raw_query_params(raw_query).collect();
    let request = unique_encoded_query_value(&params, url_params::SAML_REQUEST)?;
    let response = unique_encoded_query_value(&params, url_params::SAML_RESPONSE)?;
    let (message_name, message_value) = match (request, response) {
        (Some(request), None) => (url_params::SAML_REQUEST, request),
        (None, Some(response)) => (url_params::SAML_RESPONSE, response),
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => {
            return Err(SamlError::Invalid(
                "expected exactly one Redirect SAML message field".into(),
            ))
        }
    };
    let relay_state = unique_encoded_query_value(&params, url_params::RELAY_STATE)?;
    let sig_alg = unique_encoded_query_value(&params, url_params::SIG_ALG)?;
    let signature = unique_encoded_query_value(&params, url_params::SIGNATURE)?;

    let sig_alg = match (sig_alg, signature) {
        (Some(sig_alg), Some(_)) => sig_alg,
        (None, None) => return Ok(None),
        _ => {
            return Err(SamlError::Invalid(
                "incomplete Redirect signature parameters".into(),
            ))
        }
    };

    Ok(Some(match relay_state {
        Some(relay_state) => {
            format!("{message_name}={message_value}&RelayState={relay_state}&SigAlg={sig_alg}")
        }
        None => format!("{message_name}={message_value}&SigAlg={sig_alg}"),
    }))
}

fn parse_form_pairs(raw: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(raw.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn parse_form_fields(raw: &str) -> Vec<FormField> {
    parse_form_pairs(raw)
        .into_iter()
        .map(|(name, value)| FormField::new(name, value))
        .collect()
}

fn fields_to_pairs(fields: Vec<FormField>) -> Vec<(String, String)> {
    fields.into_iter().map(FormField::into_pair).collect()
}

fn field_value<'a>(fields: &'a [FormField], name: &str) -> Result<Option<&'a str>, SamlError> {
    let mut values = fields
        .iter()
        .filter(|field| field.name() == name)
        .map(FormField::value);
    let first = values.next();
    if values.next().is_some() {
        return Err(SamlError::Invalid("ambiguous form field".into()));
    }
    Ok(first)
}

fn simplesign_octet_from_fields(fields: &[FormField]) -> Result<String, SamlError> {
    let (message_name, encoded) = match (
        field_value(fields, url_params::SAML_REQUEST)?,
        field_value(fields, url_params::SAML_RESPONSE)?,
    ) {
        (Some(request), None) => (url_params::SAML_REQUEST, request),
        (None, Some(response)) => (url_params::SAML_RESPONSE, response),
        _ => {
            return Err(SamlError::Invalid(
                "expected exactly one SAML message field".into(),
            ))
        }
    };
    let raw_xml = String::from_utf8(base64_decode_with_limit(
        encoded,
        XmlLimits::default().max_bytes,
    )?)
    .map_err(|err| SamlError::Xml(err.to_string()))?;
    let sig_alg = field_value(fields, url_params::SIG_ALG)?.ok_or(SamlError::MissingSigAlg)?;
    let relay_state = field_value(fields, url_params::RELAY_STATE)?;
    Ok(build_simplesign_octet(
        message_name,
        &raw_xml,
        relay_state,
        sig_alg,
    ))
}
