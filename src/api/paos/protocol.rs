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
    if !has_ecp_service(paos) {
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
    let is_passive = match input.is_passive {
        Some(true) => "true",
        Some(false) | None => "false",
    };
    ecp_attrs.push(("IsPassive", is_passive));
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
    let document = parse_with_limits(envelope_xml, limits)?;
    let (root_is_soap_envelope, child_is_soap) = soap_direct_children(envelope_xml)?;
    if document.root.local_name != "Envelope" || !root_is_soap_envelope {
        return Err(SamlError::ProtocolProfile(
            "SOAP message must be an Envelope".into(),
        ));
    }
    if child_is_soap.len() != document.root.children.len() {
        return Err(SamlError::Xml(
            "SOAP child count did not match the envelope".into(),
        ));
    }
    // A SOAP 1.1 envelope carries at most one Header followed by exactly one
    // Body. Anything else is not this profile's exchange.
    let mut saw_header = false;
    let mut saw_body = false;
    for (node, is_soap) in document.root.children.iter().zip(&child_is_soap) {
        if !is_soap || (node.local_name != "Header" && node.local_name != "Body") {
            return Err(SamlError::ProtocolProfile(
                "SOAP envelope must contain only a Header and a Body".into(),
            ));
        }
        if node.local_name == "Header" {
            if saw_header || saw_body {
                return Err(SamlError::ProtocolProfile(
                    "SOAP envelope must contain at most one Header before the Body".into(),
                ));
            }
            saw_header = true;
        } else if saw_body {
            return Err(SamlError::ProtocolProfile(
                "SOAP envelope must contain exactly one Body".into(),
            ));
        } else {
            saw_body = true;
        }
    }
    let body = soap_child(&document.root, &child_is_soap, "Body")
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
    if !soap_body_child_in_protocol_namespace(envelope_xml, elements.len())? {
        return Err(SamlError::ProtocolProfile(format!(
            "SOAP body element must use the {PROTOCOL_NS} namespace"
        )));
    }
    let element_xml = xml_slice(envelope_xml, element)?.to_string();
    let relay_state = match soap_child(&document.root, &child_is_soap, "Header") {
        Some(header) => relay_state_header(envelope_xml, header)?,
        None => RelayStateParam::absent(),
    };
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

fn soap_direct_children(xml: &str) -> Result<(bool, Vec<bool>), SamlError> {
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;
    use quick_xml::reader::NsReader;

    let mut reader = NsReader::from_str(xml);
    let mut buf = Vec::new();
    let mut depth = 0usize;
    let mut root_is_soap_envelope = false;
    let mut saw_root = false;
    let mut children = Vec::new();
    loop {
        let (resolved, event) = reader
            .read_resolved_event_into(&mut buf)
            .map_err(|err| SamlError::Xml(err.to_string()))?;
        let in_soap_namespace = matches!(
            resolved,
            ResolveResult::Bound(namespace) if namespace.as_ref() == SOAP_ENVELOPE_NS
        );
        match &event {
            Event::Start(element) | Event::Empty(element) => {
                let next_depth = depth + 1;
                let local_name = element.local_name();
                if !saw_root && next_depth == 1 {
                    saw_root = true;
                    root_is_soap_envelope = in_soap_namespace && local_name.as_ref() == "Envelope";
                } else if saw_root && next_depth == 2 {
                    children.push(in_soap_namespace);
                }
                if matches!(event, Event::Start(_)) {
                    depth = next_depth;
                }
            }
            Event::End(_) => {
                if depth == 1 {
                    break;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    Ok((root_is_soap_envelope, children))
}

fn soap_child<'a>(envelope: &'a Node, child_is_soap: &[bool], name: &str) -> Option<&'a Node> {
    envelope
        .children
        .iter()
        .zip(child_is_soap)
        .find(|(node, is_soap)| node.local_name == name && **is_soap)
        .map(|(node, _)| node)
}

fn relay_state_header(xml: &str, header: &Node) -> Result<RelayStateParam, SamlError> {
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
                let in_soap_namespace = matches!(
                    &resolved,
                    ResolveResult::Bound(namespace) if namespace.as_ref() == SOAP_ENVELOPE_NS
                );
                if header_depth.is_none()
                    && next_depth == 2
                    && local_name.as_ref() == "Header"
                    && in_soap_namespace
                {
                    header_depth = Some(next_depth);
                }
                if header_depth == Some(next_depth - 1) && local_name.as_ref() == "RelayState" {
                    let in_ecp_namespace = matches!(
                        &resolved,
                        ResolveResult::Bound(namespace) if namespace.as_ref() == ECP_PROFILE
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

fn xml_slice<'a>(xml: &'a str, node: &Node) -> Result<&'a str, SamlError> {
    xml.get(node.start..node.end)
        .ok_or_else(|| SamlError::Xml("SOAP element offsets fell outside the message".into()))
}

/// Whether the SOAP body's children use the SAML 2.0 protocol namespace.
///
/// Prefixes may be declared on any ancestor, so the whole envelope is
/// traversed with its in-scope bindings instead of slicing the body out.
fn soap_body_child_in_protocol_namespace(
    xml: &str,
    expected_children: usize,
) -> Result<bool, SamlError> {
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;
    use quick_xml::reader::NsReader;

    let mut reader = NsReader::from_str(xml);
    let mut buf = Vec::new();
    let mut depth = 0usize;
    let mut body_depth = None;
    let mut in_protocol = Vec::new();
    loop {
        let (resolved, event) = reader
            .read_resolved_event_into(&mut buf)
            .map_err(|err| SamlError::Xml(err.to_string()))?;
        match &event {
            Event::Start(element) | Event::Empty(element) => {
                let next_depth = depth + 1;
                let local_name = element.local_name();
                if body_depth.is_none()
                    && next_depth == 2
                    && local_name.as_ref() == "Body"
                    && matches!(
                        &resolved,
                        ResolveResult::Bound(namespace)
                            if namespace.as_ref() == SOAP_ENVELOPE_NS
                    )
                {
                    body_depth = Some(next_depth);
                }
                if body_depth == Some(next_depth - 1) {
                    in_protocol.push(matches!(
                        &resolved,
                        ResolveResult::Bound(namespace)
                            if namespace.as_ref() == PROTOCOL_NS
                    ));
                }
                if matches!(event, Event::Start(_)) {
                    depth = next_depth;
                }
            }
            Event::End(_) => {
                if body_depth == Some(depth) {
                    break;
                }
                depth = depth.saturating_sub(1);
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    if body_depth.is_none() {
        return Err(SamlError::Xml("SOAP body was not found".into()));
    }
    if in_protocol.len() != expected_children {
        return Err(SamlError::Xml(
            "SAML element count did not match the SOAP body".into(),
        ));
    }
    Ok(in_protocol.into_iter().next().unwrap_or(false))
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

fn paos_tokens(header: &str) -> impl Iterator<Item = &str> {
    header
        .split([',', ';'])
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn has_double_quoted_version(header: &str) -> bool {
    let expected = format!("\"{PAOS_VERSION}\"");
    paos_tokens(header).any(|token| {
        let Some(rest) = token.strip_prefix("ver") else {
            return false;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            return false;
        };
        rest.trim_start() == expected
    })
}

fn has_ecp_service(header: &str) -> bool {
    let expected = format!("\"{ECP_PROFILE}\"");
    paos_tokens(header).any(|token| token == expected)
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
    fn ver_attribute_name_must_match_exactly() {
        let ecp = "\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";
        for paos in [
            format!("server=\"urn:liberty:paos:2003-08\";{ecp}"),
            format!("xver=\"urn:liberty:paos:2003-08\";{ecp}"),
            format!("version=\"urn:liberty:paos:2003-08\";{ecp}"),
            format!("cover=\"urn:liberty:paos:2003-08\";{ecp}"),
        ] {
            assert!(
                parse_client_headers("application/vnd.paos+xml", &paos).is_err(),
                "accepted {paos}"
            );
        }
    }

    #[test]
    fn ecp_service_must_be_its_own_token() {
        let paos =
            "ver=\"urn:liberty:paos:2003-08\";foo=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\"";
        assert!(parse_client_headers("application/vnd.paos+xml", paos).is_err());
    }

    #[test]
    fn accept_without_paos_is_rejected() {
        assert!(parse_client_headers("text/html", E54_PAOS_HEADER).is_err());
    }

    #[test]
    fn soap_body_preserves_the_saml_element() -> Result<(), SamlError> {
        let authn = format!(
            "<samlp:AuthnRequest xmlns:samlp=\"{PROTOCOL_NS}\" ID=\"_1\"></samlp:AuthnRequest>"
        );
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: "https://sp.example.com/acs",
            provider_name: Some("Example SP"),
            is_passive: Some(false),
            issuer: "https://sp.example.com/metadata",
            identity_provider_id: "https://idp.example.com/metadata",
            identity_provider_loc: "https://idp.example.com/soap",
            relay_state: Some("state"),
            authn_request_xml: &authn,
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
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:ecp=\"{ECP_PROFILE}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header><ecp:RelayState>state</ecp:RelayState></SOAP-ENV:Header><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        let body = read_soap_body(&xml, "AuthnRequest", XmlLimits::default())?;
        assert_eq!(body.relay_state.as_deref(), Some("state"));
        Ok(())
    }

    #[test]
    fn relay_state_in_another_namespace_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header><other:RelayState>state</other:RelayState></SOAP-ENV:Header><SOAP-ENV:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"
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

    #[test]
    fn omitted_is_passive_is_false_on_the_ecp_request() {
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: "https://sp.example.com/acs?a=1&b=2",
            provider_name: Some("A\"B&C"),
            is_passive: None,
            issuer: "https://sp.example.com/metadata",
            identity_provider_id: "https://idp.example.com/metadata",
            identity_provider_loc: "https://idp.example.com/soap",
            relay_state: None,
            authn_request_xml: "<samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest>",
        });
        assert!(envelope.contains("IsPassive=\"false\""));
        assert!(envelope.contains("ProviderName=\"A&quot;B&amp;C\""));
        assert!(envelope.contains("responseConsumerURL=\"https://sp.example.com/acs?a=1&amp;b=2\""));
    }

    #[test]
    fn a_non_soap_body_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<!-- {SOAP_ENVELOPE_NS} --><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\"><other:Body><samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest></other:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "AuthnRequest", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn body_element_in_another_namespace_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:other=\"urn:example:other\"><SOAP-ENV:Header/><SOAP-ENV:Body><other:Response ID=\"_1\"></other:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn saml_protocol_namespace_may_be_declared_on_an_ancestor() -> Result<(), SamlError> {
        for xml in [
            format!(
                "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
            ),
            format!(
                "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns=\"{PROTOCOL_NS}\"><SOAP-ENV:Header/><SOAP-ENV:Body><Response ID=\"_1\"></Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
            ),
        ] {
            let body = read_soap_body(&xml, "Response", XmlLimits::default())?;
            assert!(body.element_xml.contains("ID=\"_1\""));
        }
        Ok(())
    }

    #[test]
    fn extra_envelope_child_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Header/><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body><SOAP-ENV:Extra/></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn duplicate_body_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body><SOAP-ENV:Body><samlp:Response ID=\"_2\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn header_after_body_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{SOAP_ENVELOPE_NS}\" xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:ecp=\"{ECP_PROFILE}\"><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body><SOAP-ENV:Header><ecp:RelayState>state</ecp:RelayState></SOAP-ENV:Header></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn soap_12_envelope_is_rejected() -> Result<(), String> {
        let xml = format!(
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:samlp=\"{PROTOCOL_NS}\"><SOAP-ENV:Body><samlp:Response ID=\"_1\"></samlp:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        );
        match read_soap_body(&xml, "Response", XmlLimits::default()) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            Err(other) => Err(format!("expected ProtocolProfile, got {other:?}")),
            Ok(_) => Err("expected ProtocolProfile, got a SOAP body".into()),
        }
    }

    #[test]
    fn requested_is_passive_true_is_carried() {
        let envelope = sp_to_ecp_envelope(&SpToEcp {
            response_consumer_url: "https://sp.example.com/acs",
            provider_name: None,
            is_passive: Some(true),
            issuer: "https://sp.example.com/metadata",
            identity_provider_id: "https://idp.example.com/metadata",
            identity_provider_loc: "https://idp.example.com/soap",
            relay_state: None,
            authn_request_xml: "<samlp:AuthnRequest ID=\"_1\"></samlp:AuthnRequest>",
        });
        assert!(envelope.contains("IsPassive=\"true\""));
    }
}
