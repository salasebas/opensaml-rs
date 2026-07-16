use crate::constants::{namespace, ParserType};
use crate::error::SamlError;
use crate::xml::dom::XmlLimits;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::{NsReader, XmlVersion};

const XML_ENCRYPTION_NS: &[u8] = b"http://www.w3.org/2001/04/xmlenc#";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamespaceKind {
    Protocol,
    Assertion,
    Dsig,
    XmlEncryption,
    Unbound,
    Other,
    Unknown,
}

#[derive(Debug)]
struct ExpandedName {
    local: Vec<u8>,
    namespace: NamespaceKind,
}

impl ExpandedName {
    fn is(&self, local: &[u8], namespace: NamespaceKind) -> bool {
        self.local == local && self.namespace == namespace
    }
}

fn classify_namespace(resolved: ResolveResult<'_>) -> NamespaceKind {
    match resolved {
        ResolveResult::Bound(value) if value.as_ref() == namespace::PROTOCOL.as_bytes() => {
            NamespaceKind::Protocol
        }
        ResolveResult::Bound(value) if value.as_ref() == namespace::ASSERTION.as_bytes() => {
            NamespaceKind::Assertion
        }
        ResolveResult::Bound(value) if value.as_ref() == namespace::DSIG.as_bytes() => {
            NamespaceKind::Dsig
        }
        ResolveResult::Bound(value) if value.as_ref() == XML_ENCRYPTION_NS => {
            NamespaceKind::XmlEncryption
        }
        ResolveResult::Bound(_) => NamespaceKind::Other,
        ResolveResult::Unbound => NamespaceKind::Unbound,
        ResolveResult::Unknown(_) => NamespaceKind::Unknown,
    }
}

fn profile_error(message: impl Into<String>) -> SamlError {
    SamlError::ProtocolProfile(message.into())
}

fn parser_root(parser_type: ParserType) -> &'static [u8] {
    match parser_type {
        ParserType::SamlRequest => b"AuthnRequest",
        ParserType::SamlResponse => b"Response",
        ParserType::LogoutRequest => b"LogoutRequest",
        ParserType::LogoutResponse => b"LogoutResponse",
    }
}

fn element_label(element: &BytesStart<'_>) -> String {
    String::from_utf8_lossy(element.local_name().as_ref()).into_owned()
}

fn validate_unqualified_attributes(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    consumed: &[&[u8]],
    required: &[&[u8]],
) -> Result<Vec<(Vec<u8>, String)>, SamlError> {
    let mut values = Vec::new();
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| SamlError::Xml(error.to_string()))?;
        let (resolved, local) = reader.resolver().resolve_attribute(attribute.key);
        if !consumed.contains(&local.as_ref()) {
            continue;
        }
        if !matches!(resolved, ResolveResult::Unbound) {
            return Err(profile_error(format!(
                "attribute {} on {} must be unqualified",
                String::from_utf8_lossy(local.as_ref()),
                element_label(element),
            )));
        }
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, element.decoder())
            .map_err(|error| SamlError::Xml(error.to_string()))?
            .into_owned();
        values.push((local.as_ref().to_vec(), value));
    }

    for required_name in required {
        if !values.iter().any(|(name, _)| name == required_name) {
            return Err(profile_error(format!(
                "{} is missing required unqualified attribute {}",
                element_label(element),
                String::from_utf8_lossy(required_name),
            )));
        }
    }
    Ok(values)
}

fn require_version_2(
    values: &[(Vec<u8>, String)],
    element: &BytesStart<'_>,
) -> Result<(), SamlError> {
    let version = values
        .iter()
        .find_map(|(name, value)| (name == b"Version").then_some(value.as_str()));
    if version != Some("2.0") {
        return Err(profile_error(format!(
            "{} Version must be 2.0",
            element_label(element),
        )));
    }
    Ok(())
}

fn parse_two_ascii_digits(value: &[u8], offset: usize) -> Option<u8> {
    let tens = value.get(offset)?.checked_sub(b'0')?;
    let ones = value.get(offset + 1)?.checked_sub(b'0')?;
    (tens <= 9 && ones <= 9).then_some(tens * 10 + ones)
}

fn year_modulo(year: &[u8], modulus: u16) -> Option<u16> {
    year.iter().try_fold(0, |remainder, digit| {
        let digit = digit.checked_sub(b'0')?;
        (digit <= 9).then_some((remainder * 10 + u16::from(digit)) % modulus)
    })
}

fn is_leap_year(year: &[u8]) -> bool {
    matches!(year_modulo(year, 400), Some(0))
        || (matches!(year_modulo(year, 4), Some(0)) && !matches!(year_modulo(year, 100), Some(0)))
}

fn is_valid_calendar_day(year: &[u8], month: u8, day: u8) -> bool {
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&day)
}

fn is_saml_utc_date_time(value: &str) -> bool {
    let Some(without_timezone) = value.strip_suffix('Z') else {
        return false;
    };
    let bytes = without_timezone.as_bytes();
    let year_start = usize::from(bytes.first() == Some(&b'-'));
    let Some(year_separator) = bytes
        .get(year_start..)
        .and_then(|remaining| remaining.iter().position(|byte| *byte == b'-'))
        .map(|offset| year_start + offset)
    else {
        return false;
    };
    let year = &bytes[year_start..year_separator];
    if year.len() < 4
        || (year.len() > 4 && year.first() == Some(&b'0'))
        || year.iter().all(|digit| *digit == b'0')
        || year_modulo(year, 400).is_none()
    {
        return false;
    }

    let time_end = year_separator + 15;
    if bytes.len() < time_end
        || bytes.get(year_separator) != Some(&b'-')
        || bytes.get(year_separator + 3) != Some(&b'-')
        || bytes.get(year_separator + 6) != Some(&b'T')
        || bytes.get(year_separator + 9) != Some(&b':')
        || bytes.get(year_separator + 12) != Some(&b':')
    {
        return false;
    }

    let Some(month) = parse_two_ascii_digits(bytes, year_separator + 1) else {
        return false;
    };
    let Some(day) = parse_two_ascii_digits(bytes, year_separator + 4) else {
        return false;
    };
    let Some(hour) = parse_two_ascii_digits(bytes, year_separator + 7) else {
        return false;
    };
    let Some(minute) = parse_two_ascii_digits(bytes, year_separator + 10) else {
        return false;
    };
    let Some(second) = parse_two_ascii_digits(bytes, year_separator + 13) else {
        return false;
    };
    if !is_valid_calendar_day(year, month, day) || minute > 59 || second > 59 {
        return false;
    }

    let fractional = &bytes[time_end..];
    let valid_fractional = fractional.is_empty()
        || (fractional.first() == Some(&b'.')
            && fractional.len() > 1
            && fractional[1..].iter().all(u8::is_ascii_digit));
    if !valid_fractional {
        return false;
    }

    hour < 24
        || (hour == 24
            && minute == 0
            && second == 0
            && fractional
                .get(1..)
                .is_none_or(|digits| digits.iter().all(|digit| *digit == b'0')))
}

fn require_authn_request_issue_instant(
    values: &[(Vec<u8>, String)],
    element: &BytesStart<'_>,
) -> Result<(), SamlError> {
    let issue_instant = values
        .iter()
        .find_map(|(name, value)| (name == b"IssueInstant").then_some(value.as_str()))
        .ok_or_else(|| {
            profile_error(format!(
                "{} is missing required unqualified attribute IssueInstant",
                element_label(element),
            ))
        })?;
    if !is_saml_utc_date_time(issue_instant) {
        return Err(profile_error(format!(
            "{} IssueInstant must be a valid UTC xs:dateTime ending in Z",
            element_label(element),
        )));
    }
    Ok(())
}

fn root_consumed_attributes(parser_type: ParserType) -> &'static [&'static [u8]] {
    match parser_type {
        ParserType::SamlRequest => &[
            b"ID",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"AssertionConsumerServiceURL",
            b"ProtocolBinding",
            b"AssertionConsumerServiceIndex",
        ],
        ParserType::SamlResponse => &[
            b"ID",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"InResponseTo",
        ],
        ParserType::LogoutRequest => &[b"ID", b"Version", b"IssueInstant", b"Destination"],
        ParserType::LogoutResponse => &[
            b"ID",
            b"Version",
            b"IssueInstant",
            b"Destination",
            b"InResponseTo",
        ],
    }
}

fn validate_root(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    parser_type: ParserType,
) -> Result<(), SamlError> {
    let expected = parser_root(parser_type);
    if element.local_name().as_ref() != expected || element_namespace != NamespaceKind::Protocol {
        return Err(profile_error(format!(
            "expected root {{{}}}{}, got {}",
            namespace::PROTOCOL,
            String::from_utf8_lossy(expected),
            element_label(element),
        )));
    }
    let required: &[&[u8]] = match parser_type {
        ParserType::SamlRequest => &[b"ID", b"Version", b"IssueInstant"],
        ParserType::SamlResponse | ParserType::LogoutRequest | ParserType::LogoutResponse => {
            &[b"ID", b"Version"]
        }
    };
    let attributes = validate_unqualified_attributes(
        reader,
        element,
        root_consumed_attributes(parser_type),
        required,
    )?;
    require_version_2(&attributes, element)?;
    if parser_type == ParserType::SamlRequest {
        require_authn_request_issue_instant(&attributes, element)?;
    }
    Ok(())
}

fn expected_child_namespace(stack: &[ExpandedName], child: &[u8]) -> Option<NamespaceKind> {
    let parent = stack.last()?;
    let root = stack.first()?;

    if stack.len() == 1 && parent.namespace == NamespaceKind::Protocol {
        if matches!(child, b"Issuer") {
            return Some(NamespaceKind::Assertion);
        }
        if matches!(child, b"Signature") {
            return Some(NamespaceKind::Dsig);
        }
        if root.is(b"AuthnRequest", NamespaceKind::Protocol) {
            return match child {
                b"NameIDPolicy" | b"RequestedAuthnContext" => Some(NamespaceKind::Protocol),
                b"AuthnContextClassRef" => Some(NamespaceKind::Assertion),
                _ => None,
            };
        }
        if root.is(b"Response", NamespaceKind::Protocol) {
            return match child {
                b"Status" => Some(NamespaceKind::Protocol),
                b"Assertion" | b"EncryptedAssertion" => Some(NamespaceKind::Assertion),
                _ => None,
            };
        }
        if root.is(b"LogoutRequest", NamespaceKind::Protocol) {
            return match child {
                b"NameID" => Some(NamespaceKind::Assertion),
                b"SessionIndex" => Some(NamespaceKind::Protocol),
                _ => None,
            };
        }
        if root.is(b"LogoutResponse", NamespaceKind::Protocol) && child == b"Status" {
            return Some(NamespaceKind::Protocol);
        }
    }

    if parent.is(b"Status", NamespaceKind::Protocol)
        || parent.is(b"StatusCode", NamespaceKind::Protocol)
    {
        return (child == b"StatusCode").then_some(NamespaceKind::Protocol);
    }
    if parent.is(b"RequestedAuthnContext", NamespaceKind::Protocol) {
        return (child == b"AuthnContextClassRef").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"Assertion", NamespaceKind::Assertion) {
        return match child {
            b"Signature" => Some(NamespaceKind::Dsig),
            b"Issuer" | b"Subject" | b"Conditions" | b"AuthnStatement" | b"AttributeStatement" => {
                Some(NamespaceKind::Assertion)
            }
            _ => None,
        };
    }
    if parent.is(b"Subject", NamespaceKind::Assertion) {
        return match child {
            b"NameID" | b"SubjectConfirmation" => Some(NamespaceKind::Assertion),
            _ => None,
        };
    }
    if parent.is(b"SubjectConfirmation", NamespaceKind::Assertion) {
        return (child == b"SubjectConfirmationData").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"Conditions", NamespaceKind::Assertion) {
        return (child == b"AudienceRestriction").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"AudienceRestriction", NamespaceKind::Assertion) {
        return (child == b"Audience").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"AttributeStatement", NamespaceKind::Assertion) {
        return (child == b"Attribute").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"Attribute", NamespaceKind::Assertion) {
        return (child == b"AttributeValue").then_some(NamespaceKind::Assertion);
    }
    if parent.is(b"EncryptedAssertion", NamespaceKind::Assertion) {
        return (child == b"EncryptedData").then_some(NamespaceKind::XmlEncryption);
    }
    None
}

fn consumed_attributes(element: &ExpandedName) -> &'static [&'static [u8]] {
    match (element.namespace, element.local.as_slice()) {
        (NamespaceKind::Assertion, b"Assertion") => &[b"ID", b"Version", b"IssueInstant"],
        (NamespaceKind::Protocol, b"StatusCode") => &[b"Value"],
        (NamespaceKind::Protocol, b"NameIDPolicy") => &[b"Format", b"AllowCreate"],
        (NamespaceKind::Assertion, b"Conditions") => &[b"NotBefore", b"NotOnOrAfter"],
        (NamespaceKind::Assertion, b"NameID") => &[b"Format"],
        (NamespaceKind::Assertion, b"SubjectConfirmation") => &[b"Method"],
        (NamespaceKind::Assertion, b"SubjectConfirmationData") => {
            &[b"NotOnOrAfter", b"Recipient", b"InResponseTo"]
        }
        (NamespaceKind::Assertion, b"AuthnStatement") => {
            &[b"AuthnInstant", b"SessionNotOnOrAfter", b"SessionIndex"]
        }
        (NamespaceKind::Assertion, b"Attribute") => &[b"Name"],
        _ => &[],
    }
}

fn validate_element(
    reader: &NsReader<&[u8]>,
    element: &BytesStart<'_>,
    element_namespace: NamespaceKind,
    stack: &[ExpandedName],
    parser_type: ParserType,
) -> Result<(), SamlError> {
    if stack.is_empty() {
        return validate_root(reader, element, element_namespace, parser_type);
    }

    let local = element.local_name();
    let expected_namespace = expected_child_namespace(stack, local.as_ref());
    if let Some(expected) = expected_namespace {
        if element_namespace != expected {
            return Err(profile_error(format!(
                "{} has an invalid namespace",
                element_label(element),
            )));
        }
    }
    if expected_namespace.is_none() {
        return Ok(());
    }

    let expanded = ExpandedName {
        local: local.as_ref().to_vec(),
        namespace: element_namespace,
    };
    let consumed = consumed_attributes(&expanded);
    if expanded.is(b"Assertion", NamespaceKind::Assertion) {
        let attributes =
            validate_unqualified_attributes(reader, element, consumed, &[b"ID", b"Version"])?;
        require_version_2(&attributes, element)?;
    } else if !consumed.is_empty() {
        validate_unqualified_attributes(reader, element, consumed, &[])?;
    }
    Ok(())
}

pub(crate) fn validate_protocol_profile(
    xml: &str,
    parser_type: ParserType,
    limits: XmlLimits,
) -> Result<(), SamlError> {
    limits.check_input_bytes(xml.len())?;
    let mut reader = NsReader::from_str(xml);
    reader
        .resolver_mut()
        .set_max_declarations_per_element(limits.max_attributes_per_element);
    let mut stack = Vec::new();
    let mut saw_root = false;

    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|error| SamlError::Xml(error.to_string()))?;
        let element_namespace = classify_namespace(resolved);
        match event {
            Event::Start(element) => {
                validate_element(&reader, &element, element_namespace, &stack, parser_type)?;
                saw_root = true;
                stack.push(ExpandedName {
                    local: element.local_name().as_ref().to_vec(),
                    namespace: element_namespace,
                });
            }
            Event::Empty(element) => {
                validate_element(&reader, &element, element_namespace, &stack, parser_type)?;
                saw_root = true;
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Eof => break,
            Event::Decl(_)
            | Event::Text(_)
            | Event::CData(_)
            | Event::Comment(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::GeneralRef(_) => {}
        }
    }

    if !saw_root {
        return Err(profile_error("missing SAML protocol root"));
    }
    Ok(())
}
