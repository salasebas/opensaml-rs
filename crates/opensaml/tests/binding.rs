use opensaml::binding::{
    deflate_raw_decode, deflate_raw_encode, saml_post_binding_form, try_saml_post_binding_form,
    xml_escape,
};
use opensaml::constants::Binding;
use opensaml::entity::BindingContext;
use opensaml::OpenSamlError;

#[test]
fn deflate_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let original = b"<samlp:AuthnRequest ID=\"_abc\" Version=\"2.0\"/>";
    let compressed = deflate_raw_encode(original)?;
    let restored = deflate_raw_decode(&compressed)?;
    assert_eq!(restored, original);
    Ok(())
}

#[test]
fn xml_escape_golden() {
    assert_eq!(
        xml_escape("a & b <c> \"d\" 'e'"),
        "a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"
    );
}

#[test]
fn post_form_escapes_value_and_includes_fields() {
    let form = saml_post_binding_form(
        "https://idp.example.org/acs",
        "SAMLResponse",
        "PHNhbWxwOlJlc3BvbnNlLz4=",
        Some("next=<script>"),
    );

    // Includes the action and the hidden SAML input.
    assert!(form.contains("action=\"https://idp.example.org/acs\""));
    assert!(form.contains("name=\"SAMLResponse\""));
    assert!(form.contains("value=\"PHNhbWxwOlJlc3BvbnNlLz4=\""));

    // A `<` in a value must be HTML-escaped, never emitted raw.
    assert!(form.contains("next=&lt;script&gt;"));
    assert!(!form.contains("<script>"));
}

#[test]
fn try_post_form_accepts_https_action_url() -> Result<(), Box<dyn std::error::Error>> {
    let form = try_saml_post_binding_form(
        "https://idp.example.org/acs",
        "SAMLResponse",
        "PHNhbWxwOlJlc3BvbnNlLz4=",
        None,
    )?;

    assert!(form.contains("action=\"https://idp.example.org/acs\""));
    Ok(())
}

#[test]
fn try_post_form_rejects_active_and_non_http_action_urls() {
    for action in [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "ftp://idp.example.org/acs",
        "idp.example.org/acs",
        "/saml/acs",
    ] {
        let result = try_saml_post_binding_form(action, "SAMLResponse", "payload", None);

        assert!(
            matches!(
                &result,
                Err(OpenSamlError::Invalid(message))
                    if message == "ERR_UNSAFE_POST_BINDING_ACTION_URL"
            ),
            "unexpected result for {action}: {result:?}"
        );
    }
}

#[test]
fn binding_context_try_post_form_rejects_active_endpoint() {
    let context = BindingContext {
        id: "_id".into(),
        context: "PHNhbWxwOlJlc3BvbnNlLz4=".into(),
        relay_state: None,
        entity_endpoint: "javascript:alert(1)".into(),
        binding: Binding::Post,
        request_type: "SAMLResponse",
        signature: None,
        sig_alg: None,
    };

    let result = context.try_post_form();

    assert!(
        matches!(
            &result,
            Err(OpenSamlError::Invalid(message)) if message == "ERR_UNSAFE_POST_BINDING_ACTION_URL"
        ),
        "unexpected result: {result:?}"
    );
}
