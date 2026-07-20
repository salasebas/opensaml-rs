use super::{
    classify_namespace, element_label, profile_error, require_version_2,
    validate_closed_unqualified_attributes, NamespaceKind,
};
use crate::constants::{name_id_format, namespace, status_code};
use crate::error::SamlError;
use crate::xml::dom::{parse_with_limits, Document, XmlLimits};
use crate::xml::parse_generated_saml_utc_date_time;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::NsReader;
use url::Url;

#[derive(Debug)]
enum OutboundLogoutElement {
    Root,
    Issuer,
    Signature,
    Extensions { child_seen: bool },
    Status,
    StatusCode { child_seen: bool },
    StatusMessage,
    StatusDetail,
    ExtensionContent,
}

#[derive(Debug, Default)]
struct OutboundLogoutState {
    root_stage: u8,
    status_stage: u8,
    saw_signature: bool,
    destination: Option<String>,
}

struct OutboundLogoutExpectation<'a> {
    id: &'a str,
    destination: &'a str,
    issuer: &'a str,
    in_response_to: Option<&'a str>,
    validation: OutboundLogoutValidation,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum OutboundLogoutValidation {
    BeforeSigning { destination_required: bool },
    AfterPostSigning,
}

impl OutboundLogoutValidation {
    fn destination_required(self) -> bool {
        match self {
            Self::BeforeSigning {
                destination_required,
            } => destination_required,
            Self::AfterPostSigning => true,
        }
    }

    fn root_signature_required(self) -> bool {
        matches!(self, Self::AfterPostSigning)
    }

    fn root_signature_allowed(self) -> bool {
        matches!(self, Self::AfterPostSigning)
    }
}

fn is_xml_name_start_char(value: char) -> bool {
    matches!(
        value,
        'A'..='Z'
            | '_'
            | 'a'..='z'
            | '\u{c0}'..='\u{d6}'
            | '\u{d8}'..='\u{f6}'
            | '\u{f8}'..='\u{2ff}'
            | '\u{370}'..='\u{37d}'
            | '\u{37f}'..='\u{1fff}'
            | '\u{200c}'..='\u{200d}'
            | '\u{2070}'..='\u{218f}'
            | '\u{2c00}'..='\u{2fef}'
            | '\u{3001}'..='\u{d7ff}'
            | '\u{f900}'..='\u{fdcf}'
            | '\u{fdf0}'..='\u{fffd}'
            | '\u{10000}'..='\u{effff}'
    )
}

fn is_xml_name_char(value: char) -> bool {
    is_xml_name_start_char(value)
        || matches!(
            value,
            '-' | '.'
                | '0'..='9'
                | '\u{b7}'
                | '\u{300}'..='\u{36f}'
                | '\u{203f}'..='\u{2040}'
        )
}

fn is_ncname(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(is_xml_name_start_char) && chars.all(is_xml_name_char)
}

fn attribute_value<'a>(values: &'a [(Vec<u8>, String)], name: &[u8]) -> Option<&'a str> {
    values
        .iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value.as_str()))
}

fn require_generated_issue_instant(
    values: &[(Vec<u8>, String)],
    element: &BytesStart<'_>,
) -> Result<(), SamlError> {
    let issue_instant = attribute_value(values, b"IssueInstant").ok_or_else(|| {
        profile_error(format!(
            "{} is missing required unqualified attribute IssueInstant",
            element_label(element),
        ))
    })?;
    if parse_generated_saml_utc_date_time(issue_instant).is_none() {
        return Err(profile_error(format!(
            "{} IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
            element_label(element),
        )));
    }
    Ok(())
}

fn validate_outbound_logout_root(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    expectation: &OutboundLogoutExpectation<'_>,
    state: &mut OutboundLogoutState,
) -> Result<(), SamlError> {
    if element.local_name().as_ref() != b"LogoutResponse"
        || element_namespace != NamespaceKind::Protocol
    {
        return Err(profile_error(format!(
            "expected root {{{}}}LogoutResponse, got {}",
            namespace::PROTOCOL,
            element_label(element),
        )));
    }
    let attributes = validate_closed_unqualified_attributes(
        reader,
        element,
        &[
            b"ID",
            b"InResponseTo",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"Consent",
        ],
        &[b"ID", b"Version", b"IssueInstant"],
    )?;
    require_version_2(&attributes, element)?;
    require_generated_issue_instant(&attributes, element)?;

    let id = attribute_value(&attributes, b"ID").ok_or_else(|| {
        profile_error("LogoutResponse is missing required unqualified attribute ID")
    })?;
    if !is_ncname(id) {
        return Err(profile_error(
            "LogoutResponse ID must use the XML Schema xs:ID lexical form",
        ));
    }
    if id != expectation.id {
        return Err(SamlError::Invalid(format!(
            "outbound LogoutResponse ID mismatch: expected {}, got {id}",
            expectation.id
        )));
    }

    state.destination = attribute_value(&attributes, b"Destination").map(str::to_string);
    if let Some(actual) = state.destination.as_deref() {
        if !is_absolute_saml_uri(actual) {
            return Err(profile_error(
                "LogoutResponse Destination must be a non-empty absolute URI without whitespace",
            ));
        }
        if actual != expectation.destination {
            return Err(SamlError::destination_mismatch(
                expectation.destination,
                Some(actual),
            ));
        }
    }

    if let Some(consent) = attribute_value(&attributes, b"Consent") {
        if !is_absolute_saml_uri(consent) {
            return Err(profile_error(
                "LogoutResponse Consent must be a non-empty absolute URI without whitespace",
            ));
        }
    }

    let actual_in_response_to = attribute_value(&attributes, b"InResponseTo");
    if actual_in_response_to.is_some_and(|value| !is_ncname(value)) {
        return Err(profile_error(
            "LogoutResponse InResponseTo must use the XML Schema NCName lexical form",
        ));
    }
    // SAML Core 2.0 §3.2.2 requires correlation when the request is known and
    // requires omission when there is no known request to reference.
    if actual_in_response_to != expectation.in_response_to {
        return Err(SamlError::in_response_to_mismatch(
            expectation.in_response_to,
            actual_in_response_to,
        ));
    }
    Ok(())
}

fn validate_outbound_issuer(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
) -> Result<(), SamlError> {
    if element_namespace != NamespaceKind::Assertion {
        return Err(profile_error("Issuer has an invalid namespace"));
    }
    let attributes = validate_closed_unqualified_attributes(
        reader,
        element,
        &[
            b"Format",
            b"NameQualifier",
            b"SPNameQualifier",
            b"SPProvidedID",
        ],
        &[],
    )?;
    if let Some(format) = attribute_value(&attributes, b"Format") {
        if format != name_id_format::ENTITY {
            return Err(profile_error(
                "LogoutResponse Issuer Format must be omitted or use the entity identifier format",
            ));
        }
    }
    if [
        b"NameQualifier".as_slice(),
        b"SPNameQualifier".as_slice(),
        b"SPProvidedID".as_slice(),
    ]
    .iter()
    .any(|name| attribute_value(&attributes, name).is_some())
    {
        return Err(profile_error(
            "entity-format LogoutResponse Issuer must omit NameQualifier, SPNameQualifier, and SPProvidedID",
        ));
    }
    Ok(())
}

fn is_absolute_saml_uri(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_whitespace) && Url::parse(value).is_ok()
}

fn validate_outbound_status_code(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    top_level: bool,
) -> Result<(), SamlError> {
    if element_namespace != NamespaceKind::Protocol {
        return Err(profile_error("StatusCode has an invalid namespace"));
    }
    let attributes =
        validate_closed_unqualified_attributes(reader, element, &[b"Value"], &[b"Value"])?;
    let value = attribute_value(&attributes, b"Value").ok_or_else(|| {
        profile_error("StatusCode is missing required unqualified attribute Value")
    })?;
    if !is_absolute_saml_uri(value) {
        return Err(profile_error(
            "StatusCode Value must be a non-empty absolute URI without whitespace",
        ));
    }
    if top_level
        && !matches!(
            value,
            status_code::SUCCESS
                | status_code::REQUESTER
                | status_code::RESPONDER
                | status_code::VERSION_MISMATCH
        )
    {
        return Err(profile_error(
            "top-level StatusCode Value must be Success, Requester, Responder, or VersionMismatch",
        ));
    }
    Ok(())
}

fn validate_outbound_root_child(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    expectation: &OutboundLogoutExpectation<'_>,
    state: &mut OutboundLogoutState,
) -> Result<OutboundLogoutElement, SamlError> {
    let local = element.local_name();
    match (local.as_ref(), element_namespace, state.root_stage) {
        (b"Issuer", NamespaceKind::Assertion, 0) => {
            validate_outbound_issuer(reader, element, element_namespace)?;
            state.root_stage = 1;
            Ok(OutboundLogoutElement::Issuer)
        }
        (b"Signature", NamespaceKind::Dsig, 1) => {
            if !expectation.validation.root_signature_allowed() {
                // Library policy centralizes root signature construction. This
                // also ensures Redirect can meet Bindings 2.0 §3.4.4.1 before
                // DEFLATE without teaching generic binding helpers about XML.
                return Err(profile_error(
                    "outbound LogoutResponse templates must not contain a root ds:Signature before library signing",
                ));
            }
            state.root_stage = 2;
            state.saw_signature = true;
            Ok(OutboundLogoutElement::Signature)
        }
        (b"Extensions", NamespaceKind::Protocol, 1 | 2) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.root_stage = 3;
            Ok(OutboundLogoutElement::Extensions { child_seen: false })
        }
        (b"Status", NamespaceKind::Protocol, 1..=3) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.root_stage = 4;
            Ok(OutboundLogoutElement::Status)
        }
        _ => Err(profile_error(
            "LogoutResponse children must be Issuer, optional Signature, optional Extensions, and exactly one final Status",
        )),
    }
}

fn validate_outbound_status_child(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    state: &mut OutboundLogoutState,
) -> Result<OutboundLogoutElement, SamlError> {
    let local = element.local_name();
    match (local.as_ref(), element_namespace, state.status_stage) {
        (b"StatusCode", NamespaceKind::Protocol, 0) => {
            validate_outbound_status_code(reader, element, element_namespace, true)?;
            state.status_stage = 1;
            Ok(OutboundLogoutElement::StatusCode { child_seen: false })
        }
        (b"StatusMessage", NamespaceKind::Protocol, 1) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.status_stage = 2;
            Ok(OutboundLogoutElement::StatusMessage)
        }
        (b"StatusDetail", NamespaceKind::Protocol, 1 | 2) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.status_stage = 3;
            Ok(OutboundLogoutElement::StatusDetail)
        }
        _ => Err(profile_error(
            "Status children must be exactly one StatusCode, optional StatusMessage, and optional StatusDetail in that order",
        )),
    }
}

fn validate_outbound_logout_start(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    stack: &mut [OutboundLogoutElement],
    expectation: &OutboundLogoutExpectation<'_>,
    state: &mut OutboundLogoutState,
) -> Result<OutboundLogoutElement, SamlError> {
    let Some(parent) = stack.last_mut() else {
        validate_outbound_logout_root(reader, element, element_namespace, expectation, state)?;
        return Ok(OutboundLogoutElement::Root);
    };

    match parent {
        OutboundLogoutElement::Root => {
            validate_outbound_root_child(reader, element, element_namespace, expectation, state)
        }
        OutboundLogoutElement::Issuer => Err(profile_error(
            "LogoutResponse Issuer must not contain child elements",
        )),
        OutboundLogoutElement::Status => {
            validate_outbound_status_child(reader, element, element_namespace, state)
        }
        OutboundLogoutElement::StatusCode { child_seen } => {
            if *child_seen
                || element.local_name().as_ref() != b"StatusCode"
                || element_namespace != NamespaceKind::Protocol
            {
                return Err(profile_error(
                    "StatusCode may contain at most one subordinate StatusCode",
                ));
            }
            validate_outbound_status_code(reader, element, element_namespace, false)?;
            *child_seen = true;
            Ok(OutboundLogoutElement::StatusCode { child_seen: false })
        }
        OutboundLogoutElement::StatusMessage => Err(profile_error(
            "StatusMessage must not contain child elements",
        )),
        OutboundLogoutElement::Extensions { child_seen } => {
            // Core 2.0 §3.2.2 narrows the protocol schema's ##other wildcard:
            // direct extension elements must use a namespace not defined by SAML.
            if !matches!(
                element_namespace,
                NamespaceKind::Dsig | NamespaceKind::XmlEncryption | NamespaceKind::Other
            ) {
                return Err(profile_error(
                    "Extensions direct children must use a namespace not defined by SAML",
                ));
            }
            *child_seen = true;
            Ok(OutboundLogoutElement::ExtensionContent)
        }
        OutboundLogoutElement::StatusDetail
        | OutboundLogoutElement::Signature
        | OutboundLogoutElement::ExtensionContent => Ok(OutboundLogoutElement::ExtensionContent),
    }
}

fn finish_outbound_logout_element(
    element: &OutboundLogoutElement,
    state: &OutboundLogoutState,
) -> Result<(), SamlError> {
    match element {
        OutboundLogoutElement::Root if state.root_stage != 4 => Err(profile_error(
            "LogoutResponse must contain Issuer and exactly one final Status",
        )),
        OutboundLogoutElement::Status if state.status_stage == 0 => Err(profile_error(
            "Status must contain exactly one StatusCode as its first child",
        )),
        OutboundLogoutElement::Extensions { child_seen: false } => Err(profile_error(
            "Extensions must contain at least one extension element",
        )),
        _ => Ok(()),
    }
}

fn validate_structural_text(
    parent: Option<&OutboundLogoutElement>,
    text: &[u8],
) -> Result<(), SamlError> {
    if is_structural_element(parent)
        && !text
            .iter()
            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Err(profile_error(
            "structural LogoutResponse elements may contain only whitespace text",
        ));
    }
    Ok(())
}

fn is_structural_element(parent: Option<&OutboundLogoutElement>) -> bool {
    matches!(
        parent,
        Some(
            OutboundLogoutElement::Root
                | OutboundLogoutElement::Status
                | OutboundLogoutElement::StatusCode { .. }
                | OutboundLogoutElement::Extensions { .. }
                | OutboundLogoutElement::StatusDetail
        )
    )
}

fn validate_structural_reference(
    parent: Option<&OutboundLogoutElement>,
    reference: &BytesRef<'_>,
) -> Result<(), SamlError> {
    if is_structural_element(parent)
        && !matches!(
            reference
                .resolve_char_ref()
                .map_err(|error| SamlError::Xml(error.to_string()))?,
            Some(' ' | '\t' | '\r' | '\n')
        )
    {
        return Err(profile_error(
            "structural LogoutResponse elements may contain only whitespace text",
        ));
    }
    Ok(())
}

fn validate_outbound_logout_stream(
    xml: &str,
    expectation: &OutboundLogoutExpectation<'_>,
) -> Result<OutboundLogoutState, SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut stack = Vec::new();
    let mut state = OutboundLogoutState::default();

    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        let element_namespace = classify_namespace(resolved);
        match event {
            Event::Start(element) => {
                let current = validate_outbound_logout_start(
                    &reader,
                    &element,
                    element_namespace,
                    &mut stack,
                    expectation,
                    &mut state,
                )?;
                stack.push(current);
            }
            Event::Empty(element) => {
                let current = validate_outbound_logout_start(
                    &reader,
                    &element,
                    element_namespace,
                    &mut stack,
                    expectation,
                    &mut state,
                )?;
                finish_outbound_logout_element(&current, &state)?;
            }
            Event::End(_) => {
                let current = stack
                    .pop()
                    .ok_or_else(|| SamlError::Xml("unexpected closing element".into()))?;
                finish_outbound_logout_element(&current, &state)?;
            }
            Event::Text(text) => {
                let text = text
                    .decode()
                    .map_err(|error| SamlError::Xml(error.to_string()))?;
                validate_structural_text(stack.last(), text.as_bytes())?;
            }
            Event::CData(text) => {
                validate_structural_text(stack.last(), text.as_ref())?;
            }
            Event::GeneralRef(reference) => {
                validate_structural_reference(stack.last(), &reference)?;
            }
            Event::DocType(_) => return Err(SamlError::Xml("DOCTYPE is not allowed".into())),
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
        }
    }
    Ok(state)
}

pub(crate) fn validate_logout_response_outbound(
    xml: &str,
    expected_id: &str,
    expected_destination: &str,
    expected_issuer: &str,
    expected_in_response_to: Option<&str>,
    validation: OutboundLogoutValidation,
) -> Result<Document, SamlError> {
    let document = parse_with_limits(xml, XmlLimits::unbounded())?;
    let expectation = OutboundLogoutExpectation {
        id: expected_id,
        destination: expected_destination,
        issuer: expected_issuer,
        in_response_to: expected_in_response_to,
        validation,
    };
    let state = validate_outbound_logout_stream(xml, &expectation)?;

    let issuer = document.root.children.first().ok_or_else(|| {
        profile_error("LogoutResponse must contain an Issuer before all other children")
    })?;
    if issuer.text.is_empty() {
        return Err(profile_error(
            "LogoutResponse Issuer must identify the responding entity",
        ));
    }
    if issuer.text != expectation.issuer {
        return Err(SamlError::issuer_mismatch(
            expectation.issuer,
            Some(&issuer.text),
        ));
    }
    if (expectation.validation.destination_required() || state.saw_signature)
        && state.destination.is_none()
    {
        return Err(SamlError::destination_mismatch(
            expectation.destination,
            None,
        ));
    }
    if expectation.validation.root_signature_required() && !state.saw_signature {
        return Err(profile_error(
            "signed POST LogoutResponse must contain a root ds:Signature in schema order",
        ));
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESTINATION: &str = "https://sp.example.com/slo";
    const ISSUER: &str = "https://idp.example.com/metadata";
    const RESPONSE_ID: &str = "_response";

    fn response_xml_with_attributes(
        id: &str,
        destination: Option<&str>,
        additional_attributes: &str,
        children: &str,
    ) -> String {
        let destination = destination
            .map(|value| format!(r#" Destination="{value}""#))
            .unwrap_or_default();
        format!(
            r#"<samlp:LogoutResponse xmlns:samlp="{protocol}" xmlns:saml="{assertion}" xmlns:ds="{dsig}" xmlns:x="urn:example:extension" ID="{id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"{destination}{additional_attributes}>{children}</samlp:LogoutResponse>"#,
            protocol = namespace::PROTOCOL,
            assertion = namespace::ASSERTION,
            dsig = namespace::DSIG,
        )
    }

    fn response_xml(id: &str, destination: Option<&str>, children: &str) -> String {
        response_xml_with_attributes(id, destination, "", children)
    }

    fn issuer(attributes: &str, value: &str) -> String {
        format!(r#"<saml:Issuer{attributes}>{value}</saml:Issuer>"#)
    }

    fn status(contents: &str) -> String {
        format!("<samlp:Status>{contents}</samlp:Status>")
    }

    fn success_status() -> String {
        status(&format!(
            r#"<samlp:StatusCode Value="{}"/>"#,
            status_code::SUCCESS
        ))
    }

    fn canonical_children() -> String {
        format!(
            r#"{issuer}<samlp:Extensions><x:Extension/></samlp:Extensions><samlp:Status><samlp:StatusCode Value="{success}"><samlp:StatusCode Value="urn:example:subordinate"/></samlp:StatusCode><samlp:StatusMessage>completed</samlp:StatusMessage><samlp:StatusDetail><x:Detail/></samlp:StatusDetail></samlp:Status>"#,
            issuer = issuer(&format!(r#" Format="{}""#, name_id_format::ENTITY), ISSUER),
            success = status_code::SUCCESS,
        )
    }

    fn validate(xml: &str, expected_id: &str, signed: bool) -> Result<Document, SamlError> {
        validate_with_in_response_to(xml, expected_id, None, signed)
    }

    fn validate_with_in_response_to(
        xml: &str,
        expected_id: &str,
        expected_in_response_to: Option<&str>,
        signed: bool,
    ) -> Result<Document, SamlError> {
        validate_logout_response_outbound(
            xml,
            expected_id,
            DESTINATION,
            ISSUER,
            expected_in_response_to,
            OutboundLogoutValidation::BeforeSigning {
                destination_required: signed,
            },
        )
    }

    fn expect_profile_error(xml: &str) -> Result<(), Box<dyn std::error::Error>> {
        match validate(xml, RESPONSE_ID, false) {
            Err(SamlError::ProtocolProfile(_)) => Ok(()),
            other => Err(format!("expected ProtocolProfile error, got {other:?}").into()),
        }
    }

    #[test]
    fn outbound_logout_response_accepts_canonical_schema_and_slo_profile(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xml = response_xml_with_attributes(
            RESPONSE_ID,
            Some(DESTINATION),
            r#" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" xmlns:opaque="urn:example:opaque""#,
            &canonical_children().replace(
                "<x:Extension/>",
                r#"<x:Extension opaque:attribute="value">opaque text<samlp:Nested/></x:Extension>"#,
            ),
        );
        let document = validate(&xml, RESPONSE_ID, true)?;

        assert_eq!(document.root.attr("ID"), Some(RESPONSE_ID));
        Ok(())
    }

    #[test]
    fn outbound_logout_response_rejects_invalid_root_child_cardinality_and_order(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = issuer("", ISSUER);
        let status = success_status();
        let cases = [
            issuer.clone(),
            format!("{issuer}{status}{status}"),
            format!("{status}{issuer}"),
            format!("{issuer}{status}<samlp:Extensions/>"),
        ];

        for children in cases {
            expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
        }
        Ok(())
    }

    #[test]
    fn outbound_logout_response_rejects_status_without_status_code(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let children = format!("{}{}", issuer("", ISSUER), status(""));

        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))
    }

    #[test]
    fn outbound_logout_response_rejects_missing_or_qualified_status_code_value(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            "<samlp:StatusCode/>",
            r#"<samlp:StatusCode x:Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>"#,
        ];

        for status_code in cases {
            let children = format!("{}{}", issuer("", ISSUER), status(status_code));
            expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
        }
        Ok(())
    }

    #[test]
    fn outbound_logout_response_rejects_invalid_status_child_cardinality_and_order(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let code = format!(r#"<samlp:StatusCode Value="{}"/>"#, status_code::SUCCESS);
        let cases = [
            format!("{code}<samlp:StatusDetail/><samlp:StatusMessage>late</samlp:StatusMessage>"),
            format!(
                "{code}<samlp:StatusMessage>one</samlp:StatusMessage><samlp:StatusMessage>two</samlp:StatusMessage>"
            ),
            format!("{code}<samlp:StatusDetail/><samlp:StatusDetail/>"),
            format!("{code}<x:Unexpected/>"),
        ];

        for contents in cases {
            let children = format!("{}{}", issuer("", ISSUER), status(&contents));
            expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
        }
        Ok(())
    }

    #[test]
    fn outbound_logout_response_rejects_nonstandard_top_level_status_code(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let children = format!(
            "{}{}",
            issuer("", ISSUER),
            status(r#"<samlp:StatusCode Value="urn:example:custom"/>"#)
        );

        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))
    }

    #[test]
    fn outbound_logout_response_rejects_duplicate_or_relative_subordinate_status_code(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            format!(
                r#"<samlp:StatusCode Value="{success}"><samlp:StatusCode Value="urn:example:first"/><samlp:StatusCode Value="urn:example:second"/></samlp:StatusCode>"#,
                success = status_code::SUCCESS
            ),
            format!(
                r#"<samlp:StatusCode Value="{success}"><samlp:StatusCode Value="relative"/></samlp:StatusCode>"#,
                success = status_code::SUCCESS
            ),
            format!(
                r#"<samlp:StatusCode Value="{success}"><samlp:StatusCode/></samlp:StatusCode>"#,
                success = status_code::SUCCESS
            ),
        ];

        for status_code in cases {
            let children = format!("{}{}", issuer("", ISSUER), status(&status_code));
            expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
        }
        Ok(())
    }

    #[test]
    fn outbound_logout_response_rejects_missing_wrong_or_invalid_format_issuer(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status = success_status();
        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &status))?;

        let invalid_format = format!(
            "{}{}",
            issuer(r#" Format="urn:example:format""#, ISSUER),
            status
        );
        expect_profile_error(&response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &invalid_format,
        ))?;

        for qualifier in ["NameQualifier", "SPNameQualifier", "SPProvidedID"] {
            let qualified = format!(
                "{}{}",
                issuer(&format!(r#" {qualifier}="urn:example:qualifier""#), ISSUER),
                success_status()
            );
            expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &qualified))?;
        }

        let wrong = format!(
            "{}{}",
            issuer("", "https://attacker.example.com/metadata"),
            success_status()
        );
        match validate(
            &response_xml(RESPONSE_ID, Some(DESTINATION), &wrong),
            RESPONSE_ID,
            false,
        ) {
            Err(SamlError::IssuerMismatch { .. }) => Ok(()),
            other => Err(format!("expected IssuerMismatch, got {other:?}").into()),
        }
    }

    #[test]
    fn outbound_logout_response_enforces_xs_id_lexical_form_and_local_id_invariant(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let children = format!("{}{}", issuer("", ISSUER), success_status());
        for invalid_id in ["", "9response", "bad:id"] {
            expect_profile_error(&response_xml(invalid_id, Some(DESTINATION), &children))?;
        }

        match validate(
            &response_xml("_other", Some(DESTINATION), &children),
            RESPONSE_ID,
            false,
        ) {
            Err(SamlError::Invalid(message)) if message.contains("ID mismatch") => Ok(()),
            other => Err(format!("expected local ID invariant error, got {other:?}").into()),
        }
    }

    #[test]
    fn outbound_logout_response_accepts_unicode_ncname_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let children = format!("{}{}", issuer("", ISSUER), success_status());
        let xml = response_xml("Δresponse", Some(DESTINATION), &children);

        validate(&xml, "Δresponse", false)?;
        Ok(())
    }

    #[test]
    fn outbound_logout_response_enforces_destination_when_present_or_signed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let children = format!("{}{}", issuer("", ISSUER), success_status());
        let wrong = response_xml(
            RESPONSE_ID,
            Some("https://attacker.example.com/slo"),
            &children,
        );
        match validate(&wrong, RESPONSE_ID, false) {
            Err(SamlError::DestinationMismatch { .. }) => {}
            other => return Err(format!("expected DestinationMismatch, got {other:?}").into()),
        }

        let omitted = response_xml(RESPONSE_ID, None, &children);
        match validate(&omitted, RESPONSE_ID, true) {
            Err(SamlError::DestinationMismatch { .. }) => {}
            other => return Err(format!("expected signed Destination error, got {other:?}").into()),
        }

        validate(&omitted, RESPONSE_ID, false)?;
        Ok(())
    }

    #[test]
    fn outbound_logout_response_enforces_in_response_to_correlation_and_ncname(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let children = format!("{}{}", issuer("", ISSUER), success_status());
        let matching = response_xml_with_attributes(
            RESPONSE_ID,
            Some(DESTINATION),
            r#" InResponseTo="_request""#,
            &children,
        );
        validate_with_in_response_to(&matching, RESPONSE_ID, Some("_request"), false)?;

        let cases = [
            (
                response_xml(RESPONSE_ID, Some(DESTINATION), &children),
                Some("_request"),
            ),
            (
                response_xml_with_attributes(
                    RESPONSE_ID,
                    Some(DESTINATION),
                    r#" InResponseTo="_other""#,
                    &children,
                ),
                Some("_request"),
            ),
            (
                response_xml_with_attributes(
                    RESPONSE_ID,
                    Some(DESTINATION),
                    r#" InResponseTo="_request""#,
                    &children,
                ),
                None,
            ),
        ];
        for (xml, expected) in cases {
            match validate_with_in_response_to(&xml, RESPONSE_ID, expected, false) {
                Err(SamlError::InResponseToMismatch { .. }) => {}
                other => {
                    return Err(format!("expected InResponseToMismatch, got {other:?}").into());
                }
            }
        }

        for invalid in ["", "9request", "bad:request", "bad request"] {
            let xml = response_xml_with_attributes(
                RESPONSE_ID,
                Some(DESTINATION),
                &format!(r#" InResponseTo="{invalid}""#),
                &children,
            );
            match validate_with_in_response_to(&xml, RESPONSE_ID, Some(invalid), false) {
                Err(SamlError::ProtocolProfile(_)) => {}
                other => {
                    return Err(format!("expected invalid NCName rejection, got {other:?}").into());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn outbound_logout_response_rejects_unexpected_known_element_attributes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let status_code = format!(r#"<samlp:StatusCode Value="{}"/>"#, status_code::SUCCESS);
        let cases = [
            response_xml_with_attributes(
                RESPONSE_ID,
                Some(DESTINATION),
                r#" Unexpected="value""#,
                &format!("{}{}", issuer("", ISSUER), status(&status_code)),
            ),
            response_xml_with_attributes(
                RESPONSE_ID,
                Some(DESTINATION),
                r#" x:Unexpected="value""#,
                &format!("{}{}", issuer("", ISSUER), status(&status_code)),
            ),
            response_xml_with_attributes(
                RESPONSE_ID,
                Some(DESTINATION),
                r#" x:ID="_qualified""#,
                &format!("{}{}", issuer("", ISSUER), status(&status_code)),
            ),
            response_xml(
                RESPONSE_ID,
                Some(DESTINATION),
                &format!(
                    "{}{}",
                    issuer(r#" Unexpected="value""#, ISSUER),
                    status(&status_code)
                ),
            ),
            response_xml(
                RESPONSE_ID,
                Some(DESTINATION),
                &format!(
                    "{}{}",
                    issuer("", ISSUER),
                    r#"<samlp:Status Unexpected="value"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>"#
                ),
            ),
            response_xml(
                RESPONSE_ID,
                Some(DESTINATION),
                &format!(
                    "{}{}",
                    issuer("", ISSUER),
                    status(
                        r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" Unexpected="value"/>"#
                    )
                ),
            ),
            response_xml(
                RESPONSE_ID,
                Some(DESTINATION),
                &format!(
                    "{}{}",
                    issuer("", ISSUER),
                    status(&format!(
                        r#"{status_code}<samlp:StatusMessage Unexpected="value">message</samlp:StatusMessage>"#
                    ))
                ),
            ),
            response_xml(
                RESPONSE_ID,
                Some(DESTINATION),
                &format!(
                    "{}{}",
                    issuer("", ISSUER),
                    status(&format!(
                        r#"{status_code}<samlp:StatusDetail Unexpected="value"/>"#
                    ))
                ),
            ),
            response_xml(
                RESPONSE_ID,
                Some(DESTINATION),
                &format!(
                    r#"{}<samlp:Extensions Unexpected="value"><x:Extension/></samlp:Extensions>{}"#,
                    issuer("", ISSUER),
                    success_status()
                ),
            ),
        ];

        for xml in cases {
            expect_profile_error(&xml)?;
        }
        Ok(())
    }

    #[test]
    fn outbound_logout_response_rejects_invalid_destination_or_consent_uri(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let children = format!("{}{}", issuer("", ISSUER), success_status());
        expect_profile_error(&response_xml(RESPONSE_ID, Some("relative/path"), &children))?;
        expect_profile_error(&response_xml_with_attributes(
            RESPONSE_ID,
            Some(DESTINATION),
            r#" Consent="relative consent""#,
            &children,
        ))
    }

    #[test]
    fn outbound_logout_response_enforces_extensions_boundary(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = issuer("", ISSUER);
        let status = success_status();
        let cases = [
            format!("{issuer}<samlp:Extensions/>{status}"),
            format!("{issuer}<samlp:Extensions>text</samlp:Extensions>{status}"),
            format!("{issuer}<samlp:Extensions><Extension/></samlp:Extensions>{status}"),
            format!("{issuer}<samlp:Extensions><samlp:Extension/></samlp:Extensions>{status}"),
            format!("{issuer}<samlp:Extensions><saml:Extension/></samlp:Extensions>{status}"),
        ];
        for children in cases {
            expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))?;
        }
        Ok(())
    }

    #[test]
    fn outbound_logout_response_keeps_status_detail_open_but_element_only(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let issuer = issuer("", ISSUER);
        let code = format!(r#"<samlp:StatusCode Value="{}"/>"#, status_code::SUCCESS);
        for detail in [
            "<samlp:StatusDetail/>",
            r#"<samlp:StatusDetail><Arbitrary attr="value">opaque</Arbitrary></samlp:StatusDetail>"#,
        ] {
            let xml = response_xml(
                RESPONSE_ID,
                Some(DESTINATION),
                &format!("{issuer}{}", status(&format!("{code}{detail}"))),
            );
            validate(&xml, RESPONSE_ID, false)?;
        }

        let invalid = response_xml(
            RESPONSE_ID,
            Some(DESTINATION),
            &format!(
                "{issuer}{}",
                status(&format!(
                    "{code}<samlp:StatusDetail>text</samlp:StatusDetail>"
                ))
            ),
        );
        expect_profile_error(&invalid)
    }

    #[test]
    fn outbound_logout_response_rejects_root_signature_before_library_signing(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let children = format!(
            "{}<ds:Signature><ds:SignedInfo/></ds:Signature>{}",
            issuer("", ISSUER),
            success_status()
        );

        expect_profile_error(&response_xml(RESPONSE_ID, Some(DESTINATION), &children))
    }
}
