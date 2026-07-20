use saml_rs::{
    AcsEndpoint, AuthnRequest, EndpointUrl, EntityId, Idp, LogoutBinding, LogoutRequest, MessageId,
    NameIdCreationRequest, PendingAuthnRequest, PendingLogoutRequest, PendingSnapshot,
    RelayStateParam, Saml, SamlError, SamlInstant, SloEndpoint, Sp, SsoEndpoint, SsoRequestBinding,
    SsoResponseBinding,
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
    let _ = std::any::type_name::<saml_rs::raw::Binding>();
    let _ = std::any::type_name::<saml_rs::raw::FlowResult>();
    let _ = std::any::type_name::<saml_rs::raw::BindingContext>();
    let _ = std::any::type_name::<saml_rs::raw::HttpRequest>();
}

#[test]
fn typed_api_contract_reexports_config_builders() {
    let _ = std::any::type_name::<saml_rs::SpConfigBuilder>();
    let _ = std::any::type_name::<saml_rs::IdpConfigBuilder>();
    let _ = std::any::type_name::<saml_rs::AuthnRequestSigningPolicy>();
    let _ = std::any::type_name::<saml_rs::AuthnRequestValidationPolicy>();
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
    assert_send_sync::<MessageId>();
    assert_send_sync::<RelayStateParam>();
    assert_send_sync::<SamlInstant>();
    assert_send_sync::<PendingAuthnRequest>();
    assert_send_sync::<PendingSnapshot<AuthnRequest>>();
    assert_send_sync::<PendingLogoutRequest>();
    assert_send_sync::<PendingSnapshot<LogoutRequest>>();
    assert_send_sync::<NameIdCreationRequest>();

    let acs = AcsEndpoint::post("https://sp.example.com/acs")?;
    let pending = PendingAuthnRequest::try_new(
        MessageId::try_new("_request123")?,
        RelayStateParam::try_from_option(Some("relay".to_string()))?,
        acs,
        SsoResponseBinding::Post,
        EntityId::try_new("https://idp.example.com/metadata")?,
    )?;
    let _: PendingSnapshot<AuthnRequest> = pending.snapshot();
    let logout_pending = PendingLogoutRequest::try_new(
        MessageId::try_new("_logout123")?,
        RelayStateParam::present_empty(),
        LogoutBinding::Redirect,
        EntityId::try_new("https://idp.example.com/metadata")?,
    )?;
    let _: PendingSnapshot<LogoutRequest> = logout_pending.snapshot();
    let _ = SsoEndpoint::redirect("https://idp.example.com/sso")?;
    let _ = SloEndpoint::new(
        LogoutBinding::Redirect,
        EndpointUrl::try_new("https://idp.example.com/slo")?,
    );
    let _ = SsoRequestBinding::Redirect;
    Ok(())
}

#[test]
fn typed_api_contract_reexports_browser_and_model_types() {
    let _: for<'a> fn(&'a AuthnRequest) -> &'a SamlInstant = AuthnRequest::issue_instant;
    let _: for<'a> fn(&'a saml_rs::SsoResponse) -> &'a SamlInstant =
        saml_rs::SsoResponse::issue_instant;
    let _: for<'a> fn(&'a saml_rs::SsoSession) -> &'a SamlInstant =
        saml_rs::SsoSession::response_issue_instant;
    let _: for<'a> fn(&'a saml_rs::SsoSession) -> &'a SamlInstant =
        saml_rs::SsoSession::assertion_issue_instant;
    let _ = std::any::type_name::<saml_rs::BrowserInput<saml_rs::AuthnRequest>>();
    let _ = std::any::type_name::<saml_rs::FormField>();
    let _ = std::any::type_name::<saml_rs::Outbound<saml_rs::AuthnRequest>>();
    let _ = std::any::type_name::<saml_rs::Pending<saml_rs::AuthnRequest>>();
    let _ = std::any::type_name::<saml_rs::PostForm>();
    let _ = std::any::type_name::<saml_rs::Started<saml_rs::AuthnRequest>>();
    let _ = std::any::type_name::<saml_rs::Assertion>();
    let _ = std::any::type_name::<saml_rs::AssertionId>();
    let _ = std::any::type_name::<saml_rs::Attribute>();
    let _ = std::any::type_name::<saml_rs::AttributeValue>();
    let _ = std::any::type_name::<saml_rs::Attributes>();
    let _ = std::any::type_name::<saml_rs::AuthnSession>();
    let _ = std::any::type_name::<saml_rs::LogoutCompleted>();
    let _ = std::any::type_name::<saml_rs::LogoutRequest>();
    let _ = std::any::type_name::<saml_rs::LogoutResponse>();
    let _ = std::any::type_name::<saml_rs::NameId>();
    let _ = std::any::type_name::<saml_rs::NameIdPolicy>();
    let _ = std::any::type_name::<saml_rs::Received<saml_rs::SsoResponse>>();
    let _ = std::any::type_name::<saml_rs::RelayState>();
    let _ = saml_rs::MAX_RELAY_STATE_BYTES;
    let _ = std::any::type_name::<saml_rs::SessionIndex>();
    let _ = std::any::type_name::<saml_rs::SsoResponse>();
    let _ = std::any::type_name::<saml_rs::SsoSession>();
    let _ = std::any::type_name::<saml_rs::Subject>();
    let _ = std::any::type_name::<saml_rs::SubjectConfirmation>();
}
