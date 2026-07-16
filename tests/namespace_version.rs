use saml_rs::binding::{base64_encode, deflate_raw_encode};
use saml_rs::constants::{Binding, ParserType};
use saml_rs::flow::{flow, FlowOptions, HttpRequest};
use saml_rs::SamlError;

#[cfg(feature = "crypto-bergshamra")]
use saml_rs::constants::{
    data_encryption_algorithm::AES_256, key_encryption_algorithm::RSA_OAEP_MGF1P,
};
#[cfg(feature = "crypto-bergshamra")]
use saml_rs::crypto::encrypt_assertion;

const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const MISSING_ISSUE_INSTANT_CONTEXT: &str = "missing required unqualified attribute IssueInstant";
const MALFORMED_ISSUE_INSTANT_CONTEXT: &str =
    "IssueInstant must use the SAML-conformant UTC xs:dateTime form ending in Z";
#[cfg(feature = "crypto-bergshamra")]
const PRIVATE_KEY: &str = include_str!("fixtures/key/sp_privkey.pem");
#[cfg(feature = "crypto-bergshamra")]
const CERTIFICATE: &str = include_str!("fixtures/key/sp_signing_cert.cer");

fn run_flow_with_binding(
    xml: &str,
    parser_type: ParserType,
    binding: Binding,
    check_signature: bool,
) -> Result<(), SamlError> {
    let encoded = match binding {
        Binding::Redirect => base64_encode(&deflate_raw_encode(xml.as_bytes())?),
        Binding::Post | Binding::SimpleSign => base64_encode(xml.as_bytes()),
        Binding::Artifact => return Err(SamlError::UnsupportedBinding { binding }),
    };
    let parameter = (parser_type.query_param().to_string(), encoded);
    let request = match binding {
        Binding::Redirect => HttpRequest::redirect(vec![parameter]),
        Binding::Post | Binding::SimpleSign => HttpRequest::post(vec![parameter]),
        Binding::Artifact => return Err(SamlError::UnsupportedBinding { binding }),
    };
    let mut options = FlowOptions::default();
    options.binding = Some(binding);
    options.parser_type = Some(parser_type);
    options.check_signature = check_signature;
    flow(&options, &request).map(|_| ())
}

fn run_flow(xml: &str, parser_type: ParserType) -> Result<(), SamlError> {
    run_flow_with_binding(xml, parser_type, Binding::Post, false)
}

fn expect_profile_rejection(
    xml: &str,
    parser_type: ParserType,
) -> Result<(), Box<dyn std::error::Error>> {
    match run_flow(xml, parser_type) {
        Err(SamlError::ProtocolProfile(_)) => Ok(()),
        Err(other) => Err(format!("expected ProtocolProfile, got {other:?}").into()),
        Ok(()) => Err("expected SAML profile rejection".into()),
    }
}

fn expect_profile_rejection_with_context(
    xml: &str,
    parser_type: ParserType,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match run_flow(xml, parser_type) {
        Err(SamlError::ProtocolProfile(message)) if message.contains(context) => Ok(()),
        Err(SamlError::ProtocolProfile(message)) => {
            Err(format!("expected {context} context, got {message:?}").into())
        }
        Err(other) => Err(format!("expected ProtocolProfile, got {other:?}").into()),
        Ok(()) => Err("expected SAML profile rejection".into()),
    }
}

fn expect_profile_rejection_with_binding_and_context(
    xml: &str,
    parser_type: ParserType,
    binding: Binding,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match run_flow_with_binding(xml, parser_type, binding, true) {
        Err(SamlError::ProtocolProfile(message)) if message.contains(context) => Ok(()),
        Err(SamlError::ProtocolProfile(message)) => {
            Err(format!("expected {context} context, got {message:?}").into())
        }
        Err(other) => Err(format!("expected ProtocolProfile, got {other:?}").into()),
        Ok(()) => Err("expected SAML profile rejection".into()),
    }
}

fn authn_request_xml(issue_instant: Option<&str>) -> String {
    let issue_instant = issue_instant
        .map(|value| format!(r#" IssueInstant="{value}""#))
        .unwrap_or_default();
    format!(
        r#"<p:AuthnRequest xmlns:p="{PROTOCOL_NS}" ID="_request" Version="2.0"{issue_instant}/>"#
    )
}

fn response_xml(protocol_ns: &str, assertion_ns: &str, version: &str) -> String {
    format!(
        r#"<p:Response xmlns:p="{protocol_ns}" xmlns:a="{assertion_ns}" ID="_response" {version}>
<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status>
<a:Assertion ID="_assertion" Version="2.0">
<a:Subject><a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><a:SubjectConfirmationData NotOnOrAfter="2999-01-01T00:00:00Z"/></a:SubjectConfirmation></a:Subject>
</a:Assertion>
</p:Response>"#
    )
}

#[test]
fn canonical_prefixes_are_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"")
        .replace("p:", "samlp:")
        .replace("xmlns:p", "xmlns:samlp")
        .replace("a:", "saml:")
        .replace("xmlns:a", "xmlns:saml");
    run_flow(&xml, ParserType::SamlResponse)?;
    Ok(())
}

#[test]
fn alternate_prefixes_with_oasis_namespaces_are_accepted() -> Result<(), Box<dyn std::error::Error>>
{
    let xml = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"");
    run_flow(&xml, ParserType::SamlResponse)?;
    Ok(())
}

#[test]
fn default_protocol_namespace_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<AuthnRequest xmlns="{PROTOCOL_NS}" ID="_request" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#
    );
    run_flow(&xml, ParserType::SamlRequest)?;
    Ok(())
}

#[test]
fn authn_request_issue_instant_validation_precedes_signature_handling_for_supported_bindings(
) -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (authn_request_xml(None), MISSING_ISSUE_INSTANT_CONTEXT),
        (
            authn_request_xml(Some("2023-02-29T00:00:00Z")),
            MALFORMED_ISSUE_INSTANT_CONTEXT,
        ),
        (
            authn_request_xml(Some("2024-01-01T00:00:00+00:00")),
            MALFORMED_ISSUE_INSTANT_CONTEXT,
        ),
    ];
    for binding in [Binding::Post, Binding::Redirect, Binding::SimpleSign] {
        for (xml, context) in &cases {
            expect_profile_rejection_with_binding_and_context(
                xml,
                ParserType::SamlRequest,
                binding,
                context,
            )?;
        }
    }
    Ok(())
}

#[test]
fn authn_request_issue_instant_rejects_invalid_lexical_forms(
) -> Result<(), Box<dyn std::error::Error>> {
    for issue_instant in [
        "not-an-instant",
        "2024-01-01_00:00:00Z",
        "2024-01-01T00:00:00+00:00",
        "2024-01-01T00:00:00+01:00",
        "2024-01-01T00:00:00z",
        "2024-01-01T00: 00:00Z",
        "2024-01-01T24:00:00.001Z",
        "\u{a0}2024-01-01T00:00:00Z\u{a0}",
    ] {
        let xml = authn_request_xml(Some(issue_instant));
        expect_profile_rejection_with_context(
            &xml,
            ParserType::SamlRequest,
            MALFORMED_ISSUE_INSTANT_CONTEXT,
        )?;
    }
    Ok(())
}

#[test]
fn authn_request_issue_instant_rejects_leap_seconds_per_saml(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = authn_request_xml(Some("2024-01-01T00:00:60Z"));

    expect_profile_rejection_with_context(
        &xml,
        ParserType::SamlRequest,
        MALFORMED_ISSUE_INSTANT_CONTEXT,
    )
}

#[test]
fn authn_request_issue_instant_accepts_valid_utc_lexical_forms(
) -> Result<(), Box<dyn std::error::Error>> {
    for issue_instant in [
        "2000-01-01T00:00:00Z",
        "2024-01-01T00:00:00.000Z",
        "2024-01-01T00:00:00.123456789012Z",
        "12345-01-01T00:00:00Z",
        "2000-02-29T24:00:00.000Z",
    ] {
        let xml = authn_request_xml(Some(issue_instant));
        run_flow(&xml, ParserType::SamlRequest)?;
    }
    Ok(())
}

#[test]
fn authn_request_issue_instant_collapses_surrounding_xml_schema_whitespace(
) -> Result<(), Box<dyn std::error::Error>> {
    for issue_instant in [
        " \t\n\r2000-01-01T00:00:00Z \t\n\r",
        "&#x9;&#xA;&#xD;2000-01-01T00:00:00Z&#x20;&#x9;",
    ] {
        let xml = authn_request_xml(Some(issue_instant));
        run_flow(&xml, ParserType::SamlRequest)?;
    }
    Ok(())
}

#[test]
fn foreign_root_namespace_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<x:AuthnRequest xmlns:x="urn:example:foreign" xmlns:a="{ASSERTION_NS}" ID="_request" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><a:Issuer>https://sp.example.test</a:Issuer></x:AuthnRequest>"#
    );
    expect_profile_rejection_with_context(&xml, ParserType::SamlRequest, "expected root")
}

#[test]
fn unbound_root_prefix_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml =
        r#"<p:AuthnRequest ID="_request" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#;
    expect_profile_rejection_with_context(xml, ParserType::SamlRequest, "expected root")
}

#[test]
fn foreign_assertion_namespace_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml(PROTOCOL_NS, "urn:example:foreign", "Version=\"2.0\"");
    expect_profile_rejection(&xml, ParserType::SamlResponse)
}

#[test]
fn wrong_assertion_version_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"").replace(
        "ID=\"_assertion\" Version=\"2.0\"",
        "ID=\"_assertion\" Version=\"1.0\"",
    );
    expect_profile_rejection_with_context(&xml, ParserType::SamlResponse, "Version")
}

#[test]
fn missing_assertion_version_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"")
        .replace("ID=\"_assertion\" Version=\"2.0\"", "ID=\"_assertion\"");
    expect_profile_rejection_with_context(&xml, ParserType::SamlResponse, "Version")
}

#[test]
fn foreign_status_namespace_is_rejected_before_status_consumption(
) -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"")
        .replace("<p:Status>", "<x:Status xmlns:x=\"urn:example:foreign\">")
        .replace("</p:Status>", "</x:Status>");
    expect_profile_rejection(&xml, ParserType::SamlResponse)
}

#[test]
fn foreign_signature_namespaces_are_rejected_before_signature_selection(
) -> Result<(), Box<dyn std::error::Error>> {
    let response_signature = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"").replace(
        "<p:Status>",
        "<x:Signature xmlns:x=\"urn:example:foreign\"/><p:Status>",
    );
    expect_profile_rejection(&response_signature, ParserType::SamlResponse)?;

    let assertion_signature = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"").replace(
        "<a:Subject>",
        "<x:Signature xmlns:x=\"urn:example:foreign\"/><a:Subject>",
    );
    expect_profile_rejection(&assertion_signature, ParserType::SamlResponse)
}

#[test]
fn foreign_encrypted_data_namespace_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<p:Response xmlns:p="{PROTOCOL_NS}" xmlns:a="{ASSERTION_NS}" ID="_response" Version="2.0"><p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status><a:EncryptedAssertion><x:EncryptedData xmlns:x="urn:example:foreign"/></a:EncryptedAssertion></p:Response>"#
    );
    expect_profile_rejection(&xml, ParserType::SamlResponse)
}

#[test]
fn namespaced_required_attribute_aliases_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let root_version = format!(
        r#"<p:AuthnRequest xmlns:p="{PROTOCOL_NS}" xmlns:x="urn:example:foreign" ID="_request" x:Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#
    );
    expect_profile_rejection_with_context(
        &root_version,
        ParserType::SamlRequest,
        "attribute Version on AuthnRequest must be unqualified",
    )?;

    let root_id = format!(
        r#"<p:AuthnRequest xmlns:p="{PROTOCOL_NS}" xmlns:x="urn:example:foreign" x:ID="_request" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#
    );
    expect_profile_rejection_with_context(
        &root_id,
        ParserType::SamlRequest,
        "attribute ID on AuthnRequest must be unqualified",
    )?;

    let assertion_id = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"").replace(
        "<a:Assertion ID=\"_assertion\"",
        "<a:Assertion xmlns:x=\"urn:example:foreign\" x:ID=\"_assertion\"",
    );
    expect_profile_rejection_with_context(
        &assertion_id,
        ParserType::SamlResponse,
        "attribute ID on Assertion must be unqualified",
    )
}

#[test]
fn namespaced_consumed_attribute_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<p:AuthnRequest xmlns:p="{PROTOCOL_NS}" xmlns:x="urn:example:foreign" ID="_request" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" x:Destination="https://idp.example.test"/>"#
    );
    expect_profile_rejection_with_context(
        &xml,
        ParserType::SamlRequest,
        "attribute Destination on AuthnRequest must be unqualified",
    )
}

#[test]
fn qualified_issue_instant_collision_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        r#"<p:AuthnRequest xmlns:p="{PROTOCOL_NS}" xmlns:x="urn:example:foreign" ID="_request" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" x:IssueInstant="2024-01-02T00:00:00Z"/>"#
    );
    expect_profile_rejection_with_context(
        &xml,
        ParserType::SamlRequest,
        "attribute IssueInstant on AuthnRequest must be unqualified",
    )
}

#[test]
fn foreign_extension_name_collisions_are_not_consumed() -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"").replace(
        "<p:Status>",
        "<p:Extensions><x:Extension xmlns:x=\"urn:example:extension\"><x:Status/><x:Signature/><x:Assertion/></x:Extension></p:Extensions><p:Status>",
    );
    run_flow(&xml, ParserType::SamlResponse)?;
    Ok(())
}

#[test]
fn all_parser_roots_require_version_2() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            ParserType::SamlRequest,
            format!(
                r#"<p:AuthnRequest xmlns:p="{PROTOCOL_NS}" ID="_id" Version="1.0" IssueInstant="2024-01-01T00:00:00Z"/>"#
            ),
        ),
        (
            ParserType::SamlResponse,
            response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"1.0\""),
        ),
        (
            ParserType::LogoutRequest,
            format!(r#"<p:LogoutRequest xmlns:p="{PROTOCOL_NS}" ID="_id" Version="1.0"/>"#),
        ),
        (
            ParserType::LogoutResponse,
            format!(r#"<p:LogoutResponse xmlns:p="{PROTOCOL_NS}" ID="_id" Version="1.0"/>"#),
        ),
    ];
    for (parser_type, xml) in cases {
        expect_profile_rejection_with_context(&xml, parser_type, "Version")?;
    }
    Ok(())
}

#[test]
fn all_parser_roots_accept_version_2() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            ParserType::SamlRequest,
            format!(
                r#"<p:AuthnRequest xmlns:p="{PROTOCOL_NS}" ID="_id" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"/>"#
            ),
        ),
        (
            ParserType::SamlResponse,
            response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\""),
        ),
        (
            ParserType::LogoutRequest,
            format!(r#"<p:LogoutRequest xmlns:p="{PROTOCOL_NS}" ID="_id" Version="2.0"/>"#),
        ),
        (
            ParserType::LogoutResponse,
            format!(
                r#"<p:LogoutResponse xmlns:p="{PROTOCOL_NS}" ID="_id" Version="2.0"><p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status></p:LogoutResponse>"#
            ),
        ),
    ];
    for (parser_type, xml) in cases {
        run_flow(&xml, parser_type)?;
    }
    Ok(())
}

#[cfg(feature = "crypto-bergshamra")]
#[test]
fn decrypted_assertion_is_revalidated_before_signature_selection(
) -> Result<(), Box<dyn std::error::Error>> {
    let wrong_version = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"").replace(
        "ID=\"_assertion\" Version=\"2.0\"",
        "ID=\"_assertion\" Version=\"1.0\"",
    );
    let encrypted = encrypt_assertion(&wrong_version, CERTIFICATE, AES_256, RSA_OAEP_MGF1P, "a")?;
    let request = HttpRequest::post(vec![(
        "SAMLResponse".into(),
        base64_encode(encrypted.as_bytes()),
    )]);
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlResponse);
    options.check_signature = true;
    options.decrypt_key = Some(PRIVATE_KEY);
    options.allow_insecure_software_rsa_key_transport_decryption = true;

    match flow(&options, &request) {
        Err(SamlError::ProtocolProfile(message)) if message.contains("Version") => Ok(()),
        Err(SamlError::ProtocolProfile(message)) => {
            Err(format!("expected Version context, got {message:?}").into())
        }
        other => Err(format!("expected post-decryption ProtocolProfile, got {other:?}").into()),
    }
}

#[cfg(feature = "crypto-bergshamra")]
#[test]
fn decrypted_assertion_honors_xml_depth_limit_before_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let nested_extension = format!(
        "<x:Extension xmlns:x=\"urn:example:extension\">{}<x:Leaf/>{}</x:Extension>",
        "<x:Extension>".repeat(20),
        "</x:Extension>".repeat(20),
    );
    let plaintext = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"2.0\"")
        .replace("<a:Subject>", &format!("{nested_extension}<a:Subject>"));
    let encrypted = encrypt_assertion(&plaintext, CERTIFICATE, AES_256, RSA_OAEP_MGF1P, "a")?;
    let request = HttpRequest::post(vec![(
        "SAMLResponse".into(),
        base64_encode(encrypted.as_bytes()),
    )]);
    let mut options = FlowOptions::default();
    options.binding = Some(Binding::Post);
    options.parser_type = Some(ParserType::SamlResponse);
    options.check_signature = true;
    options.xml_limits.max_depth = 12;

    match flow(&options, &request) {
        Err(SamlError::SignatureMissing) => {}
        other => {
            return Err(
                format!("expected encrypted envelope to pass limits, got {other:?}").into(),
            );
        }
    }

    options.decrypt_key = Some(PRIVATE_KEY);
    options.allow_insecure_software_rsa_key_transport_decryption = true;
    match flow(&options, &request) {
        Err(SamlError::Invalid(message)) if message.contains("max XML depth") => Ok(()),
        other => Err(format!("expected decrypted max-depth rejection, got {other:?}").into()),
    }
}

#[test]
fn wrong_root_version_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml(PROTOCOL_NS, ASSERTION_NS, "Version=\"1.0\"");
    expect_profile_rejection_with_context(&xml, ParserType::SamlResponse, "Version")
}

#[test]
fn missing_root_version_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let xml = response_xml(PROTOCOL_NS, ASSERTION_NS, "");
    expect_profile_rejection_with_context(&xml, ParserType::SamlResponse, "Version")
}
