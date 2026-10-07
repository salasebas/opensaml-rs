//! SOAP envelopes and the PAOS HTTP header for Enhanced Client/Proxy SSO.

use crate::error::SamlError;
use crate::model::RelayStateParam;
use crate::xml::dom::{parse_with_limits, Node};
use crate::xml::write::XmlWriter;
use crate::xml::XmlLimits;

pub(super) const PAOS_VERSION: &str = "urn:liberty:paos:2003-08";
pub(super) const ECP_PROFILE: &str = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
pub(super) const PAOS_MEDIA_TYPE: &str = "application/vnd.paos+xml";
pub(super) const SOAP_MEDIA_TYPE: &str = "text/xml; charset=utf-8";
const SOAP_ACTOR_NEXT: &str = "http://schemas.xmlsoap.org/soap/actor/next";
const SOAP_ENVELOPE_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const PAOS_NS: &str = "urn:liberty:paos:2003-08";
const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// PAOS header field value with a double-quoted version and service.
pub(super) const E54_PAOS_HEADER: &str = concat!(
    "ver=\"urn:liberty:paos:2003-08\";",
    "\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\""
);

pub(super) fn parse_client_headers(accept: &str, paos: &str) -> Result<(), SamlError> {
    let accept = header_value(accept, "Accept");
    if !lists_media_type(accept, PAOS_MEDIA_TYPE) {
        return Err(SamlError::ProtocolProfile(
            "Accept must include application/vnd.paos+xml".into(),
        ));
    }
    let paos = header_value(paos, "PAOS");
    if !has_double_quoted_version(paos) {
        return Err(SamlError::ProtocolProfile(
            "PAOS header must include ver=\"urn:liberty:paos:2003-08\" with double quotes".into(),
        ));
    }
    if !double_quoted_values(paos).contains(&ECP_PROFILE) {
        return Err(SamlError::ProtocolProfile(
            "PAOS header must include \"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\" with double quotes"
                .into(),
        ));
    }
    Ok(())
}

pub(super) struct SpToEcp<'a> {
    pub(super) response_consumer_url: &'a str,
    pub(super) provider_name: Option<&'a str>,
    pub(super) is_passive: Option<bool>,
    pub(super) issuer: &'a str,
    pub(super) identity_provider_id: &'a str,
    pub(super) identity_provider_loc: &'a str,
    pub(super) relay_state: Option<&'a str>,
    pub(super) authn_request_xml: &'a str,
}

pub(super) fn sp_to_ecp_envelope(input: &SpToEcp<'_>) -> String {
    let mut header = XmlWriter::new();
    header.empty(
        "paos:Request",
        &[
            ("xmlns:paos", PAOS_NS),
            ("responseConsumerURL", input.response_consumer_url),
            ("service", ECP_PROFILE),
            ("SOAP-ENV:mustUnderstand", "1"),
            ("SOAP-ENV:actor", SOAP_ACTOR_NEXT),
        ],
    );

    let mut ecp_attrs = vec![
        ("xmlns:ecp", ECP_PROFILE),
        ("SOAP-ENV:mustUnderstand", "1"),
        ("SOAP-ENV:actor", SOAP_ACTOR_NEXT),
    ];
    if let Some(provider_name) = input.provider_name {
        ecp_attrs.push(("ProviderName", provider_name));
    }
    let is_passive = input
        .is_passive
        .map(|value| if value { "true" } else { "false" });
    if let Some(is_passive) = is_passive {
        ecp_attrs.push(("IsPassive", is_passive));
    }
    header.start("ecp:Request", &ecp_attrs);
    header.text_element("saml:Issuer", &[("xmlns:saml", ASSERTION_NS)], input.issuer);
    header.start("samlp:IDPList", &[("xmlns:samlp", PROTOCOL_NS)]);
    header.empty(
        "samlp:IDPEntry",
        &[
            ("ProviderID", input.identity_provider_id),
            ("Loc", input.identity_provider_loc),
        ],
    );
    header.end("samlp:IDPList");
    header.end("ecp:Request");
    if let Some(relay_state) = input.relay_state {
        header.text_element(
            "ecp:RelayState",
            &[
                ("xmlns:ecp", ECP_PROFILE),
                ("SOAP-ENV:mustUnderstand", "1"),
                ("SOAP-ENV:actor", SOAP_ACTOR_NEXT),
            ],
            relay_state,
        );
    }
    envelope(&header.finish(), input.authn_request_xml)
}

pub(super) struct IdpToEcp<'a> {
    pub(super) assertion_consumer_service_url: &'a str,
    pub(super) response_xml: &'a str,
}

pub(super) fn idp_to_ecp_envelope(input: &IdpToEcp<'_>) -> String {
    let mut header = XmlWriter::new();
    header.empty(
        "ecp:Response",
        &[
            ("xmlns:ecp", ECP_PROFILE),
            ("SOAP-ENV:mustUnderstand", "1"),
            ("SOAP-ENV:actor", SOAP_ACTOR_NEXT),
            (
                "AssertionConsumerServiceURL",
                input.assertion_consumer_service_url,
            ),
        ],
    );
    envelope(&header.finish(), input.response_xml)
}

pub(super) fn soap_fault_envelope() -> String {
    format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\"><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode><faultstring>SOAP request could not be processed</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
}

pub(super) struct SoapBody {
    pub(super) element_xml: String,
    pub(super) relay_state: RelayStateParam,
}

pub(super) fn read_soap_body(
    envelope_xml: &str,
    element_name: &str,
    limits: XmlLimits,
) -> Result<SoapBody, SamlError> {
    if !envelope_xml.contains(SOAP_ENVELOPE_NS) {
        return Err(SamlError::ProtocolProfile(
            "SOAP envelope namespace is missing".into(),
        ));
    }
    let document = parse_with_limits(envelope_xml, limits)?;
    if document.root.local_name != "Envelope" {
        return Err(SamlError::ProtocolProfile(
            "SOAP message must be an Envelope".into(),
        ));
    }
    let body = child(&document.root, "Body")
        .ok_or_else(|| SamlError::ProtocolProfile("SOAP envelope is missing a Body".into()))?;
    let elements: Vec<&Node> = body.children.iter().collect();
    let [element] = elements.as_slice() else {
        return Err(SamlError::ProtocolProfile(format!(
            "SOAP body must contain one {element_name}"
        )));
    };
    if element.local_name != element_name {
        return Err(SamlError::ProtocolProfile(format!(
            "SOAP body must contain one {element_name}"
        )));
    }
    let element_xml = xml_slice(envelope_xml, element)?.to_string();
    let relay_state = relay_state_header(envelope_xml, &document.root)?;
    Ok(SoapBody {
        element_xml,
        relay_state,
    })
}

fn envelope(header_xml: &str, body_xml: &str) -> String {
    format!(
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\"><SOAP-ENV:Header>{header_xml}</SOAP-ENV:Header><SOAP-ENV:Body>{body_xml}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
}

fn relay_state_header(xml: &str, envelope: &Node) -> Result<RelayStateParam, SamlError> {
    let Some(header) = child(envelope, "Header") else {
        return Ok(RelayStateParam::absent());
    };
    let relay_states: Vec<&Node> = header
        .children
        .iter()
        .filter(|node| node.local_name == "RelayState")
        .collect();
    match relay_states.as_slice() {
        [] => Ok(RelayStateParam::absent()),
        [relay_state] => {
            let in_ecp_namespace = header_relay_state_namespaces(xml)?;
            if in_ecp_namespace.len() != relay_states.len() {
                return Err(SamlError::Xml(
                    "RelayState header count did not match the SOAP header".into(),
                ));
            }
            if !in_ecp_namespace[0] {
                return Err(SamlError::ProtocolProfile(
                    "RelayState header must use the ECP profile namespace".into(),
                ));
            }
            RelayStateParam::try_from_option(Some(relay_state.text.clone()))
        }
        _ => Err(SamlError::ProtocolProfile(
            "SOAP header must contain at most one RelayState".into(),
        )),
    }
}

fn header_relay_state_namespaces(xml: &str) -> Result<Vec<bool>, SamlError> {
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;
    use quick_xml::reader::NsReader;

    let mut reader = NsReader::from_str(xml);
    let mut buf = Vec::new();
    let mut depth = 0usize;
    let mut header_depth = None;
    let mut namespaces = Vec::new();
    loop {
        let (resolved, event) = reader
            .read_resolved_event_into(&mut buf)
            .map_err(|err| SamlError::Xml(err.to_string()))?;
        match &event {
            Event::Start(element) | Event::Empty(element) => {
                let next_depth = depth + 1;
                let local_name = element.local_name();
                if header_depth.is_none() && next_depth == 2 && local_name.as_ref() == "Header" {
                    header_depth = Some(next_depth);
                }
                if header_depth == Some(next_depth - 1) && local_name.as_ref() == "RelayState" {
                    let in_ecp_namespace = matches!(
                        resolved,
                        ResolveResult::Bound(namespace)
                            if namespace.as_ref() == ECP_PROFILE
                    );
                    namespaces.push(in_ecp_namespace);
                }
                if matches!(event, Event::Start(_)) {
                    depth = next_depth;
                }
            }
            Event::End(_) => {
                if header_depth == Some(depth) {
                    break;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok(namespaces)
}

fn child<'a>(node: &'a Node, name: &str) -> Option<&'a Node> {
    node.children.iter().find(|child| child.local_name == name)
}

fn xml_slice<'a>(xml: &'a str, node: &Node) -> Result<&'a str, SamlError> {
    xml.get(node.start..node.end)
        .ok_or_else(|| SamlError::Xml("SOAP element offsets fell outside the message".into()))
}

fn header_value<'a>(header: &'a str, name: &str) -> &'a str {
    let trimmed = header.trim();
    let Some((field, value)) = trimmed.split_once(':') else {
        return trimmed;
    };
    if field.trim().eq_ignore_ascii_case(name) {
        value.trim()
    } else {
        trimmed
    }
}

fn lists_media_type(header: &str, media_type: &str) -> bool {
    header
        .split([',', ';'])
        .any(|part| part.trim().eq_ignore_ascii_case(media_type))
}

fn has_double_quoted_version(header: &str) -> bool {
    let needle = format!("\"{PAOS_VERSION}\"");
    header.match_indices("ver").any(|(index, _)| {
        let after = header[index + 3..].trim_start();
        let Some(after) = after.strip_prefix('=') else {
            return false;
        };
        after.trim_start().starts_with(needle.as_str())
    })
}

fn double_quoted_values(header: &str) -> Vec<&str> {
    let mut values = Vec::new();
    let mut rest = header;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            break;
        };
        values.push(&after[..end]);
        rest = &after[end + 1..];
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e54_header_is_accepted() {
        let accept = "text/html; application/vnd.paos+xml";
        assert!(parse_client_headers(accept, E54_PAOS_HEADER).is_ok());
    }

    #[test]
    fn single_quoted_paos_header_is_rejected() -> Result<(), String> {
        let paos = "ver='urn:liberty:paos:2003-08';'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp'";
        match parse_client_headers("application/vnd.paos+xml", paos) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            other => Err(format!("expected ProtocolProfile, got {other:?}")),
        }
    }

    #[test]
    fn comma_separated_double_quotes_are_accepted() {
        let paos =
            "ver=\"urn:liberty:paos:2003-08\",\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";
        assert!(parse_client_headers("application/vnd.paos+xml", paos).is_ok());
    }

    #[test]
    fn soap_body_preserves_the_saml_element() -> Result<(), SamlError> {
        let authn = "<samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest>";
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: "https://sp.example.com/acs",
            provider_name: Some("Example SP"),
            is_passive: Some(false),
            issuer: "https://sp.example.com/metadata",
            identity_provider_id: "https://idp.example.com/metadata",
            identity_provider_loc: "https://idp.example.com/soap",
            relay_state: Some("state"),
            authn_request_xml: authn,
        });
        let body = read_soap_body(&envelope, "AuthnRequest", XmlLimits::default())?;
        assert_eq!(body.element_xml, authn);
        assert_eq!(body.relay_state.as_deref(), Some("state"));
        assert!(envelope.contains("responseConsumerURL=\"https://sp.example.com/acs\""));
        assert!(envelope.contains(&format!("service=\"{ECP_PROFILE}\"")));
        Ok(())
    }

    #[test]
    fn relay_state_namespace_may_be_declared_on_an_ancestor() -> Result<(), SamlError> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:ecp=\"{ECP_PROFILE}\"><SOAP-ENV:Header><ecp:RelayState>state</ecp:RelayState></SOAP-ENV:Header><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        let body = read_soap_body(&xml, "AuthnRequest", XmlLimits::default())?;
        assert_eq!(body.relay_state.as_deref(), Some("state"));
        Ok(())
    }

    #[test]
    fn relay_state_in_another_namespace_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\"><SOAP-ENV:Header><other:RelayState>state</other:RelayState></SOAP-ENV:Header><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "AuthnRequest", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn soap_body_must_contain_one_element() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\"><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest><samlp:Response ID=\"_2\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "AuthnRequest", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }
}
