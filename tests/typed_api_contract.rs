use saml_rs::{Idp, Saml, SamlError, Sp};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn typed_api_contract_exposes_role_markers() {
    assert_send_sync::<Saml<Sp>>();
    assert_send_sync::<Saml<Idp>>();
    let _: Option<SamlError> = None;
}

#[test]
fn typed_api_contract_reexports_raw_flow_types() {
    let _ = std::any::type_name::<saml_rs::raw::FlowResult>();
    let _ = std::any::type_name::<saml_rs::raw::BindingContext>();
    let _ = std::any::type_name::<saml_rs::raw::HttpRequest>();
}
