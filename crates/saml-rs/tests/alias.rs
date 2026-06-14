//! Verifies the `saml-rs` crate re-exports the `opensaml` public API.

#[test]
fn reexports_constants_and_types() {
    assert_eq!(
        saml_rs::constants::Binding::Redirect.urn(),
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    );
    let _setting = saml_rs::EntitySetting::default();
    let _err = saml_rs::OpenSamlError::UndefinedBinding;
}
