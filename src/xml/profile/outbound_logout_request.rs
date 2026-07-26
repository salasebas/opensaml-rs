use super::{
    classify_namespace, element_label, profile_error, require_version_2,
    validate_closed_unqualified_attributes, NamespaceKind,
};
use crate::constants::{name_id_format, namespace};
use crate::error::SamlError;
use crate::xml::dom::{parse_with_limits, Document, XmlLimits};
use crate::xml::parse_generated_saml_utc_date_time;
use quick_xml::events::{BytesStart, Event};
use quick_xml::NsReader;

#[derive(Debug, Clone, Copy)]
pub(crate) enum OutboundLogoutRequestValidation {
    BeforeSigning,
    AfterPostSigning,
}

pub(crate) struct OutboundLogoutRequestExpectation<'a> {
    pub(crate) id: &'a str,
    pub(crate) issue_instant: &'a str,
    pub(crate) destination: &'a str,
    pub(crate) issuer: &'a str,
    pub(crate) expiration: &'a str,
    pub(crate) name_id: &'a str,
    pub(crate) name_id_format: &'a str,
    pub(crate) session_indexes: &'a [&'a str],
}

#[derive(Debug)]
enum Element {
    Root,
    Issuer,
    Signature,
    SignatureContent,
    NameId,
    SessionIndex,
}

#[derive(Debug, Default)]
enum RootStage {
    #[default]
    ExpectIssuer,
    AfterIssuer,
    AfterSignature,
    AfterNameId,
    AfterSessionIndex,
}

#[derive(Debug, Default)]
struct State {
    root_stage: RootStage,
    saw_signature: bool,
}

fn attribute_value<'a>(values: &'a [(Vec<u8>, String)], name: &[u8]) -> Option<&'a str> {
    values
        .iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value.as_str()))
}

fn validate_root(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    expectation: &OutboundLogoutRequestExpectation<'_>,
) -> Result<(), SamlError> {
    if element.local_name().as_ref() != b"LogoutRequest"
        || element_namespace != NamespaceKind::Protocol
    {
        return Err(profile_error(format!(
            "expected root {{{}}}LogoutRequest, got {}",
            namespace::PROTOCOL,
            element_label(element),
        )));
    }
    let attributes = validate_closed_unqualified_attributes(
        reader,
        element,
        &[
            b"ID",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"NotOnOrAfter",
            b"Reason",
            b"Consent",
        ],
        &[b"ID", b"Version", b"IssueInstant", b"Destination"],
    )?;
    require_version_2(&attributes, element)?;

    let id = attribute_value(&attributes, b"ID").ok_or_else(|| {
        profile_error("LogoutRequest is missing required unqualified attribute ID")
    })?;
    if id != expectation.id {
        return Err(SamlError::Invalid(format!(
            "outbound LogoutRequest ID mismatch: expected {}, got {id}",
            expectation.id
        )));
    }
    let issue_instant = attribute_value(&attributes, b"IssueInstant").ok_or_else(|| {
        profile_error("LogoutRequest is missing required unqualified attribute IssueInstant")
    })?;
    if parse_generated_saml_utc_date_time(issue_instant).is_none() {
        return Err(profile_error(
            "LogoutRequest IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z",
        ));
    }
    if issue_instant != expectation.issue_instant {
        return Err(SamlError::Invalid(format!(
            "outbound LogoutRequest IssueInstant mismatch: expected {}, got {issue_instant}",
            expectation.issue_instant
        )));
    }
    let destination = attribute_value(&attributes, b"Destination");
    if destination != Some(expectation.destination) {
        return Err(SamlError::destination_mismatch(
            expectation.destination,
            destination,
        ));
    }

    let expiration = attribute_value(&attributes, b"NotOnOrAfter");
    if expiration.is_some_and(|value| parse_generated_saml_utc_date_time(value).is_none()) {
        return Err(profile_error(
            "LogoutRequest NotOnOrAfter must use the SAML-conformant UTC xs:dateTime form ending in Z",
        ));
    }
    if expiration != Some(expectation.expiration) {
        return Err(profile_error(format!(
            "Session Authority LogoutRequest NotOnOrAfter must equal the generated expiration {}",
            expectation.expiration,
        )));
    }
    Ok(())
}

fn validate_issuer(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
) -> Result<(), SamlError> {
    if element_namespace != NamespaceKind::Assertion {
        return Err(profile_error(
            "LogoutRequest Issuer has an invalid namespace",
        ));
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
                "LogoutRequest Issuer Format must be omitted or use the entity identifier format",
            ));
        }
    }
    if [
        b"NameQualifier".as_slice(),
        b"SPNameQualifier",
        b"SPProvidedID",
    ]
    .iter()
    .any(|name| attribute_value(&attributes, name).is_some())
    {
        return Err(profile_error(
            "entity-format LogoutRequest Issuer must omit NameQualifier, SPNameQualifier, and SPProvidedID",
        ));
    }
    Ok(())
}

fn validate_name_id(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    expected_format: &str,
) -> Result<(), SamlError> {
    if element_namespace != NamespaceKind::Assertion {
        return Err(profile_error(
            "LogoutRequest NameID has an invalid namespace",
        ));
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
        &[b"Format"],
    )?;
    let format = attribute_value(&attributes, b"Format").ok_or_else(|| {
        profile_error("LogoutRequest NameID is missing required generated Format")
    })?;
    if format != expected_format {
        return Err(profile_error(format!(
            "LogoutRequest NameID Format mismatch: expected {expected_format}, got {format}",
        )));
    }
    Ok(())
}

fn validate_start(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    stack: &[Element],
    expectation: &OutboundLogoutRequestExpectation<'_>,
    validation: OutboundLogoutRequestValidation,
    state: &mut State,
) -> Result<Element, SamlError> {
    let Some(parent) = stack.last() else {
        validate_root(reader, element, element_namespace, expectation)?;
        return Ok(Element::Root);
    };
    if matches!(parent, Element::Signature | Element::SignatureContent) {
        return Ok(Element::SignatureContent);
    }
    if !matches!(parent, Element::Root) {
        return Err(profile_error(
            "LogoutRequest Issuer, NameID, and SessionIndex must not contain child elements",
        ));
    }

    match (
        element.local_name().as_ref(),
        element_namespace,
        &state.root_stage,
    ) {
        (b"Issuer", NamespaceKind::Assertion, RootStage::ExpectIssuer) => {
            validate_issuer(reader, element, element_namespace)?;
            state.root_stage = RootStage::AfterIssuer;
            Ok(Element::Issuer)
        }
        (b"Signature", NamespaceKind::Dsig, RootStage::AfterIssuer) => {
            if !matches!(validation, OutboundLogoutRequestValidation::AfterPostSigning) {
                return Err(profile_error(
                    "outbound LogoutRequest templates must not contain a root ds:Signature before library signing",
                ));
            }
            state.root_stage = RootStage::AfterSignature;
            state.saw_signature = true;
            Ok(Element::Signature)
        }
        (
            b"NameID",
            NamespaceKind::Assertion,
            RootStage::AfterIssuer | RootStage::AfterSignature,
        ) => {
            validate_name_id(
                reader,
                element,
                element_namespace,
                expectation.name_id_format,
            )?;
            state.root_stage = RootStage::AfterNameId;
            Ok(Element::NameId)
        }
        (
            b"SessionIndex",
            NamespaceKind::Protocol,
            RootStage::AfterNameId | RootStage::AfterSessionIndex,
        ) => {
            validate_closed_unqualified_attributes(reader, element, &[], &[])?;
            state.root_stage = RootStage::AfterSessionIndex;
            Ok(Element::SessionIndex)
        }
        _ => Err(profile_error(
            "LogoutRequest children must be Issuer, an optional library-owned Signature, NameID, and SessionIndex values in schema order",
        )),
    }
}

fn validate_stream(
    xml: &str,
    expectation: &OutboundLogoutRequestExpectation<'_>,
    validation: OutboundLogoutRequestValidation,
) -> Result<State, SamlError> {
    let mut reader = NsReader::from_str(xml);
    let mut stack = Vec::new();
    let mut state = State::default();
    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        let element_namespace = classify_namespace(resolved);
        match event {
            Event::Start(element) => {
                let current = validate_start(
                    &reader,
                    &element,
                    element_namespace,
                    &stack,
                    expectation,
                    validation,
                    &mut state,
                )?;
                stack.push(current);
            }
            Event::Empty(element) => {
                validate_start(
                    &reader,
                    &element,
                    element_namespace,
                    &stack,
                    expectation,
                    validation,
                    &mut state,
                )?;
            }
            Event::End(_) => {
                stack
                    .pop()
                    .ok_or_else(|| SamlError::Xml("unexpected closing element".into()))?;
            }
            Event::Text(text) if matches!(stack.last(), Some(Element::Root)) => {
                let text = text
                    .decode()
                    .map_err(|error| SamlError::Xml(error.to_string()))?;
                if !text.bytes().all(|byte| byte.is_ascii_whitespace()) {
                    return Err(profile_error(
                        "structural LogoutRequest elements may contain only whitespace text",
                    ));
                }
            }
            Event::CData(_) | Event::GeneralRef(_)
                if matches!(stack.last(), Some(Element::Root)) =>
            {
                return Err(profile_error(
                    "structural LogoutRequest elements may contain only whitespace text",
                ));
            }
            Event::DocType(_) => return Err(SamlError::Xml("DOCTYPE is not allowed".into())),
            Event::Eof => break,
            Event::Decl(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::GeneralRef(_) => {}
        }
    }
    Ok(state)
}

pub(crate) fn validate_logout_request_outbound(
    xml: &str,
    expectation: &OutboundLogoutRequestExpectation<'_>,
    validation: OutboundLogoutRequestValidation,
) -> Result<Document, SamlError> {
    let document = parse_with_limits(xml, XmlLimits::unbounded())?;
    let state = validate_stream(xml, expectation, validation)?;
    if !matches!(
        state.root_stage,
        RootStage::AfterNameId | RootStage::AfterSessionIndex
    ) {
        return Err(profile_error(
            "LogoutRequest must contain Issuer followed by exactly one NameID",
        ));
    }
    if matches!(
        validation,
        OutboundLogoutRequestValidation::AfterPostSigning
    ) && !state.saw_signature
    {
        return Err(profile_error(
            "signed POST LogoutRequest must contain a root ds:Signature in schema order",
        ));
    }

    let mut children = document.root.children.iter();
    let issuer = children
        .next()
        .ok_or_else(|| profile_error("LogoutRequest is missing Issuer"))?;
    if issuer.text != expectation.issuer {
        return Err(SamlError::issuer_mismatch(
            expectation.issuer,
            Some(&issuer.text),
        ));
    }
    let mut child = children
        .next()
        .ok_or_else(|| profile_error("LogoutRequest is missing NameID"))?;
    if child.local_name == "Signature" {
        child = children
            .next()
            .ok_or_else(|| profile_error("LogoutRequest is missing NameID"))?;
    }
    if child.text != expectation.name_id {
        return Err(SamlError::Invalid(format!(
            "outbound LogoutRequest NameID mismatch: expected {}, got {}",
            expectation.name_id, child.text
        )));
    }
    let actual_session_indexes: Vec<_> = children.map(|node| node.text.as_str()).collect();
    if actual_session_indexes != expectation.session_indexes {
        return Err(SamlError::Invalid(
            "outbound LogoutRequest SessionIndex values do not match the requested subject".into(),
        ));
    }
    Ok(document)
}
