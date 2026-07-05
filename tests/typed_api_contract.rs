use saml_rs::{
    AcsEndpoint, AuthnRequest, EndpointUrl, EntityId, Idp, LogoutBinding, PendingAuthnRequest,
    PendingSnapshot, RelayStateState, RequestId, Saml, SamlError, SamlInstant, SloEndpoint, Sp,
    SsoEndpoint, SsoRequestBinding, SsoResponseBinding,
};

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

#[test]
fn typed_api_contract_reexports_typed_binding_building_blocks(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_send_sync::<SsoRequestBinding>();
    assert_send_sync::<SsoResponseBinding>();
    assert_send_sync::<LogoutBinding>();
    assert_send_sync::<EndpointUrl>();
    assert_send_sync::<SsoEndpoint>();
    assert_send_sync::<AcsEndpoint>();
    assert_send_sync::<SloEndpoint>();
    assert_send_sync::<RequestId>();
    assert_send_sync::<RelayStateState>();
    assert_send_sync::<SamlInstant>();
    assert_send_sync::<PendingAuthnRequest>();
    assert_send_sync::<PendingSnapshot<AuthnRequest>>();

    let acs = AcsEndpoint::post("https://sp.example.com/acs")?;
    let pending = PendingAuthnRequest::new(
        RequestId::new("_request123")?,
        RelayStateState::from_option(Some("relay".to_string())),
        acs,
        SsoResponseBinding::Post,
        EntityId::try_new("https://idp.example.com/metadata")?,
    )?;
    let _: PendingSnapshot<AuthnRequest> = pending.snapshot();
    let _ = SsoEndpoint::redirect("https://idp.example.com/sso")?;
    let _ = SloEndpoint::new(
        LogoutBinding::Redirect,
        EndpointUrl::new("https://idp.example.com/slo")?,
    );
    let _ = SsoRequestBinding::Redirect;
    Ok(())
}
