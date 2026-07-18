use super::{
    classify_namespace, element_label, profile_error, require_version_2, root_consumed_attributes,
    validate_unqualified_attributes, NamespaceKind,
};
use crate::constants::{name_id_format, namespace, status_code, ParserType};
use crate::error::SamlError;
use crate::xml::dom::{parse_with_limits, Document, XmlLimits};
use crate::xml::parse_generated_saml_utc_date_time;
use quick_xml::events::{BytesStart, Event};
use quick_xml::NsReader;
use url::Url;

#[derive(Debug)]
enum OutboundLogoutElement {
    Root,
    Issuer,
    Signature,
    Extensions,
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
    let attributes = validate_unqualified_attributes(
        reader,
        element,
        root_consumed_attributes(ParserType::LogoutResponse),
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
            "custom LogoutResponse ID mismatch: expected {}, got {id}",
            expectation.id
        )));
    }

    state.destination = attribute_value(&attributes, b"Destination").map(str::to_string);
    if let Some(actual) = state.destination.as_deref() {
        if actual != expectation.destination {
            return Err(SamlError::destination_mismatch(
                expectation.destination,
                Some(actual),
            ));
        }
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
    let attributes = validate_unqualified_attributes(
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

fn is_absolute_status_code_uri(value: &str) -> bool {
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
    let attributes = validate_unqualified_attributes(reader, element, &[b"Value"], &[b"Value"])?;
    let value = attribute_value(&attributes, b"Value").ok_or_else(|| {
        profile_error("StatusCode is missing required unqualified attribute Value")
    })?;
    if !is_absolute_status_code_uri(value) {
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
            state.root_stage = 2;
            state.saw_signature = true;
            Ok(OutboundLogoutElement::Signature)
        }
        (b"Extensions", NamespaceKind::Protocol, 1 | 2) => {
            state.root_stage = 3;
            Ok(OutboundLogoutElement::Extensions)
        }
        (b"Status", NamespaceKind::Protocol, 1..=3) => {
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
            state.status_stage = 2;
            Ok(OutboundLogoutElement::StatusMessage)
        }
        (b"StatusDetail", NamespaceKind::Protocol, 1 | 2) => {
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
            validate_outbound_root_child(reader, element, element_namespace, state)
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
        OutboundLogoutElement::Signature
        | OutboundLogoutElement::Extensions
        | OutboundLogoutElement::StatusDetail
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
        _ => Ok(()),
    }
}

fn validate_structural_text(
    parent: Option<&OutboundLogoutElement>,
    text: &[u8],
) -> Result<(), SamlError> {
    let requires_whitespace = matches!(
        parent,
        Some(
            OutboundLogoutElement::Root
                | OutboundLogoutElement::Status
                | OutboundLogoutElement::StatusCode { .. }
        )
    );
    if requires_whitespace
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
            Event::GeneralRef(_) => {
                if matches!(
                    stack.last(),
                    Some(
                        OutboundLogoutElement::Root
                            | OutboundLogoutElement::Status
                            | OutboundLogoutElement::StatusCode { .. }
                    )
                ) {
                    return Err(profile_error(
                        "structural LogoutResponse elements may contain only whitespace text",
                    ));
                }
            }
            Event::DocType(_) => return Err(SamlError::Xml("DOCTYPE is not allowed".into())),
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
        }
    }
    Ok(state)
}

pub(crate) fn validate_custom_logout_response_outbound(
    xml: &str,
    expected_id: &str,
    expected_destination: &str,
    expected_issuer: &str,
    validation: OutboundLogoutValidation,
) -> Result<Document, SamlError> {
    let document = parse_with_limits(xml, XmlLimits::unbounded())?;
    let expectation = OutboundLogoutExpectation {
        id: expected_id,
        destination: expected_destination,
        issuer: expected_issuer,
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

    fn response_xml(id: &str, destination: Option<&str>, children: &str) -> String {
        let destination = destination
            .map(|value| format!(r#" Destination="{value}""#))
            .unwrap_or_default();
        format!(
            r#"<samlp:LogoutResponse xmlns:samlp="{protocol}" xmlns:saml="{assertion}" xmlns:ds="{dsig}" xmlns:x="urn:example:extension" ID="{id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"{destination}>{children}</samlp:LogoutResponse>"#,
            protocol = namespace::PROTOCOL,
            assertion = namespace::ASSERTION,
            dsig = namespace::DSIG,
        )
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
            r#"{issuer}<ds:Signature><ds:SignedInfo/></ds:Signature><samlp:Extensions><x:Extension/></samlp:Extensions><samlp:Status><samlp:StatusCode Value="{success}"><samlp:StatusCode Value="urn:example:subordinate"/></samlp:StatusCode><samlp:StatusMessage>completed</samlp:StatusMessage><samlp:StatusDetail><x:Detail/></samlp:StatusDetail></samlp:Status>"#,
            issuer = issuer(&format!(r#" Format="{}""#, name_id_format::ENTITY), ISSUER),
            success = status_code::SUCCESS,
        )
    }

    fn validate(xml: &str, expected_id: &str, signed: bool) -> Result<Document, SamlError> {
        validate_custom_logout_response_outbound(
            xml,
            expected_id,
            DESTINATION,
            ISSUER,
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
        let xml = response_xml(RESPONSE_ID, Some(DESTINATION), &canonical_children());
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
}
