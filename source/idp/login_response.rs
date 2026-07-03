use crate::constants::namespace;
use crate::error::SamlError;
use crate::template::{write_login_response_attribute_statement, LoginResponseAttribute};
use crate::xml::write::XmlWriter;

const VERSION: &str = "2.0";
const XMLNS_XS: &str = "http://www.w3.org/2001/XMLSchema";
const XMLNS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
const BEARER_CONFIRMATION: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

pub(super) struct LoginResponseXml<'a> {
    pub(super) protocol_prefix: &'a str,
    pub(super) assertion_prefix: &'a str,
    pub(super) response_id: &'a str,
    pub(super) assertion_id: &'a str,
    pub(super) issue_instant: &'a str,
    pub(super) destination: &'a str,
    pub(super) subject_recipient: &'a str,
    pub(super) issuer: &'a str,
    pub(super) status_code: &'a str,
    pub(super) subject_confirmation_not_on_or_after: &'a str,
    pub(super) conditions_not_before: &'a str,
    pub(super) conditions_not_on_or_after: &'a str,
    pub(super) audience: &'a str,
    pub(super) name_id_format: &'a str,
    pub(super) name_id: &'a str,
    pub(super) in_response_to: &'a str,
    pub(super) attributes: &'a [LoginResponseAttribute],
    pub(super) user_attributes: &'a [(String, String)],
}

pub(super) fn render_default_login_response(
    input: &LoginResponseXml<'_>,
) -> Result<String, SamlError> {
    let response_name = qname(input.protocol_prefix, "Response");
    let protocol_xmlns = format!("xmlns:{}", input.protocol_prefix);
    let assertion_xmlns = format!("xmlns:{}", input.assertion_prefix);
    let assertion_name = qname(input.assertion_prefix, "Assertion");

    let mut writer = XmlWriter::new();
    writer.start(
        &response_name,
        &[
            (protocol_xmlns.as_str(), namespace::PROTOCOL),
            (assertion_xmlns.as_str(), namespace::ASSERTION),
            ("ID", input.response_id),
            ("Version", VERSION),
            ("IssueInstant", input.issue_instant),
            ("Destination", input.destination),
            ("InResponseTo", input.in_response_to),
        ],
    );
    writer.text_element(&qname(input.assertion_prefix, "Issuer"), &[], input.issuer);
    writer.start(&qname(input.protocol_prefix, "Status"), &[]);
    writer.empty(
        &qname(input.protocol_prefix, "StatusCode"),
        &[("Value", input.status_code)],
    );
    writer.end(&qname(input.protocol_prefix, "Status"));

    writer.start(
        &assertion_name,
        &[
            ("xmlns:xsi", XMLNS_XSI),
            ("xmlns:xs", XMLNS_XS),
            (assertion_xmlns.as_str(), namespace::ASSERTION),
            ("ID", input.assertion_id),
            ("Version", VERSION),
            ("IssueInstant", input.issue_instant),
        ],
    );
    writer.text_element(&qname(input.assertion_prefix, "Issuer"), &[], input.issuer);
    writer.start(&qname(input.assertion_prefix, "Subject"), &[]);
    writer.text_element(
        &qname(input.assertion_prefix, "NameID"),
        &[("Format", input.name_id_format)],
        input.name_id,
    );
    writer.start(
        &qname(input.assertion_prefix, "SubjectConfirmation"),
        &[("Method", BEARER_CONFIRMATION)],
    );
    writer.empty(
        &qname(input.assertion_prefix, "SubjectConfirmationData"),
        &[
            ("NotOnOrAfter", input.subject_confirmation_not_on_or_after),
            ("Recipient", input.subject_recipient),
            ("InResponseTo", input.in_response_to),
        ],
    );
    writer.end(&qname(input.assertion_prefix, "SubjectConfirmation"));
    writer.end(&qname(input.assertion_prefix, "Subject"));
    writer.start(
        &qname(input.assertion_prefix, "Conditions"),
        &[
            ("NotBefore", input.conditions_not_before),
            ("NotOnOrAfter", input.conditions_not_on_or_after),
        ],
    );
    writer.start(&qname(input.assertion_prefix, "AudienceRestriction"), &[]);
    writer.text_element(
        &qname(input.assertion_prefix, "Audience"),
        &[],
        input.audience,
    );
    writer.end(&qname(input.assertion_prefix, "AudienceRestriction"));
    writer.end(&qname(input.assertion_prefix, "Conditions"));
    write_login_response_attribute_statement(
        &mut writer,
        input.attributes,
        input.user_attributes,
        input.assertion_prefix,
    )?;
    writer.end(&assertion_name);
    writer.end(&response_name);
    Ok(writer.finish())
}

fn qname(prefix: &str, local_name: &str) -> String {
    format!("{prefix}:{local_name}")
}
