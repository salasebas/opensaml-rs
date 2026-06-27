//! Default SAML message templates and tag substitution (samlify `libsaml.ts`).
//!
//! `{Tag}` placeholders are filled by [`replace_tags_by_value`]. Replacement
//! values are XML-escaped in both attribute and element-text positions so
//! caller-provided data cannot become signed SAML markup.

use crate::binding::xml_escape;
use crate::util::camel_case;

/// Default `<AuthnRequest>` template.
pub const LOGIN_REQUEST_TEMPLATE: &str = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"{AssertionConsumerServiceURL}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:NameIDPolicy Format=\"{NameIDFormat}\" AllowCreate=\"{AllowCreate}\"/></samlp:AuthnRequest>";

/// Default `<LogoutRequest>` template.
pub const LOGOUT_REQUEST_TEMPLATE: &str = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\"><saml:Issuer>{Issuer}</saml:Issuer><saml:NameID Format=\"{NameIDFormat}\">{NameID}</saml:NameID></samlp:LogoutRequest>";

/// Default `<AttributeStatement>` wrapper template.
pub const ATTRIBUTE_STATEMENT_TEMPLATE: &str =
    "<saml:AttributeStatement>{Attributes}</saml:AttributeStatement>";

/// Default `<Attribute>` template.
pub const ATTRIBUTE_TEMPLATE: &str = "<saml:Attribute Name=\"{Name}\" NameFormat=\"{NameFormat}\"><saml:AttributeValue xmlns:xs=\"{ValueXmlnsXs}\" xmlns:xsi=\"{ValueXmlnsXsi}\" xsi:type=\"{ValueXsiType}\">{Value}</saml:AttributeValue></saml:Attribute>";

/// Default login `<Response>` template.
pub const LOGIN_RESPONSE_TEMPLATE: &str = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" InResponseTo=\"{InResponseTo}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{StatusCode}\"/></samlp:Status><saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{AssertionID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\"><saml:Issuer>{Issuer}</saml:Issuer><saml:Subject><saml:NameID Format=\"{NameIDFormat}\">{NameID}</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData NotOnOrAfter=\"{SubjectConfirmationDataNotOnOrAfter}\" Recipient=\"{SubjectRecipient}\" InResponseTo=\"{InResponseTo}\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{ConditionsNotBefore}\" NotOnOrAfter=\"{ConditionsNotOnOrAfter}\"><saml:AudienceRestriction><saml:Audience>{Audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>{AuthnStatement}{AttributeStatement}</saml:Assertion></samlp:Response>";

/// Default `<LogoutResponse>` template.
pub const LOGOUT_RESPONSE_TEMPLATE: &str = "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{ID}\" Version=\"2.0\" IssueInstant=\"{IssueInstant}\" Destination=\"{Destination}\" InResponseTo=\"{InResponseTo}\"><saml:Issuer>{Issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{StatusCode}\"/></samlp:Status></samlp:LogoutResponse>";

/// Replace `{key}` placeholders in `raw_xml`.
///
/// Placeholder replacement text is XML-escaped before insertion. XML fragments
/// such as generated attribute statements must be spliced into templates before
/// calling this helper.
pub fn replace_tags_by_value(raw_xml: &str, tags: &[(&str, String)]) -> String {
    let mut xml = raw_xml.to_string();
    for (key, value) in tags {
        let needle = format!("{{{key}}}");
        let mut result = String::with_capacity(xml.len());
        let mut rest = xml.as_str();
        while let Some(pos) = rest.find(&needle) {
            result.push_str(&rest[..pos]);
            result.push_str(&xml_escape(value));
            rest = &rest[pos + needle.len()..];
        }
        result.push_str(rest);
        xml = result;
    }
    xml
}

/// A single `<Attribute>` to render in a login response (samlify `LoginResponseAttribute`).
#[derive(Debug, Clone)]
pub struct LoginResponseAttribute {
    /// `Name` attribute.
    pub name: String,
    /// `NameFormat` attribute.
    pub name_format: String,
    /// `xsi:type` of the value.
    pub value_xsi_type: String,
    /// Tag whose runtime value fills the `AttributeValue` (becomes `{attr<Tag>}`).
    pub value_tag: String,
    /// Optional `xmlns:xs` override.
    pub value_xmlns_xs: Option<String>,
    /// Optional `xmlns:xsi` override.
    pub value_xmlns_xsi: Option<String>,
}

fn tagging(prefix: &str, content: &str) -> String {
    let camel = camel_case(content);
    let mut chars = camel.chars();
    match chars.next() {
        Some(first) => {
            let mut out = prefix.to_string();
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
            out
        }
        None => prefix.to_string(),
    }
}

/// Placeholder key (without braces) for an attribute value tag: `attr<CamelCase>`
/// (samlify `tagging('attr', valueTag)`). The runtime value fills `{<key>}`.
pub fn attr_tag(value_tag: &str) -> String {
    tagging("attr", value_tag)
}

/// IdP login `<Response>` template config (samlify `LoginResponseTemplate`).
#[derive(Debug, Clone, Default)]
pub struct LoginResponseTemplate {
    /// Custom `<Response>` template; `None` uses [`LOGIN_RESPONSE_TEMPLATE`].
    pub context: Option<String>,
    /// Attributes rendered into the assertion's `<AttributeStatement>`.
    pub attributes: Vec<LoginResponseAttribute>,
}

/// Build an `<AttributeStatement>` from `attributes` (samlify `attributeStatementBuilder`).
///
/// Each attribute's value becomes a new `{attr<Tag>}` placeholder to be filled
/// later by [`replace_tags_by_value`].
pub fn attribute_statement_builder(
    attributes: &[LoginResponseAttribute],
    attribute_template: &str,
    attribute_statement_template: &str,
) -> String {
    const DEFAULT_XS: &str = "http://www.w3.org/2001/XMLSchema";
    const DEFAULT_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
    let attrs: String = attributes
        .iter()
        .map(|a| {
            let value_placeholder = format!("{{{}}}", tagging("attr", &a.value_tag));
            attribute_template
                .replacen("{Name}", &a.name, 1)
                .replacen("{NameFormat}", &a.name_format, 1)
                .replacen(
                    "{ValueXmlnsXs}",
                    a.value_xmlns_xs.as_deref().unwrap_or(DEFAULT_XS),
                    1,
                )
                .replacen(
                    "{ValueXmlnsXsi}",
                    a.value_xmlns_xsi.as_deref().unwrap_or(DEFAULT_XSI),
                    1,
                )
                .replacen("{ValueXsiType}", &a.value_xsi_type, 1)
                .replacen("{Value}", &value_placeholder, 1)
        })
        .collect();
    attribute_statement_template.replacen("{Attributes}", &attrs, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_values_are_escaped_in_attributes_and_element_text() {
        let rendered = replace_tags_by_value(
            "<a X=\"{V}\">{T}</a>",
            &[
                ("V", "a\"b&c<d".to_string()),
                ("T", "<raw>&amp;".to_string()),
            ],
        );
        assert_eq!(
            rendered,
            "<a X=\"a&quot;b&amp;c&lt;d\">&lt;raw&gt;&amp;amp;</a>"
        );
    }

    #[test]
    fn renders_full_authn_request() {
        let xml = replace_tags_by_value(
            LOGIN_REQUEST_TEMPLATE,
            &[
                ("ID", "_abc".to_string()),
                ("IssueInstant", "2024-01-01T00:00:00Z".to_string()),
                ("Destination", "https://idp.example.com/sso".to_string()),
                ("Issuer", "https://sp.example.com/metadata".to_string()),
                (
                    "AssertionConsumerServiceURL",
                    "https://sp.example.com/acs".to_string(),
                ),
                (
                    "NameIDFormat",
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string(),
                ),
                ("AllowCreate", "true".to_string()),
            ],
        );
        assert!(xml.starts_with("<samlp:AuthnRequest"));
        assert!(xml.contains("ID=\"_abc\""));
        assert!(xml.contains("Destination=\"https://idp.example.com/sso\""));
        assert!(xml.contains("<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>"));
        assert!(!xml.contains('{'));
    }

    #[test]
    fn builds_attribute_statement_with_value_placeholder() {
        let attrs = vec![LoginResponseAttribute {
            name: "mail".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into(),
            value_xsi_type: "xs:string".into(),
            value_tag: "user.email".into(),
            value_xmlns_xs: None,
            value_xmlns_xsi: None,
        }];
        let built =
            attribute_statement_builder(&attrs, ATTRIBUTE_TEMPLATE, ATTRIBUTE_STATEMENT_TEMPLATE);
        assert!(built.starts_with("<saml:AttributeStatement>"));
        assert!(built.contains("Name=\"mail\""));
        assert!(built.contains("xsi:type=\"xs:string\""));
        // value_tag -> {attrUserEmail}
        assert!(built.contains("{attrUserEmail}"));
    }
}
