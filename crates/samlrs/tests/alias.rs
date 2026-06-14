//! Verifies the `samlrs` crate re-exports the `opensaml` public API.

#[test]
fn reexports_constants_and_types() {
    assert_eq!(
        samlrs::constants::Binding::Redirect.urn(),
        "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    );
    let _setting = samlrs::EntitySetting::default();
    let _err = samlrs::OpenSamlError::UndefinedBinding;
}
