use opensaml::binding::{
    deflate_raw_decode, deflate_raw_encode, saml_post_binding_form, xml_escape,
};

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
