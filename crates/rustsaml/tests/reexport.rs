use std::any::TypeId;

#[test]
fn rustsaml_reexports_canonical_saml_error_type() {
    assert_eq!(
        TypeId::of::<rustsaml::SamlError>(),
        TypeId::of::<saml_rs::SamlError>()
    );

    let _: Option<rustsaml::Saml<rustsaml::Sp>> = None;
}
