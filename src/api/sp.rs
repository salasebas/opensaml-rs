use crate::browser::{BrowserInput, Outbound, PendingAuthnRequest, SsoResponseBinding, Started};
use crate::config::IdpDescriptor;
use crate::flow::HttpRequest;
use crate::model::{AuthnRequest, SamlValidationContext, SsoResponse, SsoSession};
use crate::sp::{LoginRequestOptions, LoginResponseParseOptions, ServiceProvider};

use super::raw_mapping::{
    ensure_entity_id, ensure_relay_state, ensure_sso_response_binding, input_binding,
    raw_idp_descriptor, relay_state_from_input, selected_acs,
};
use super::{ForceAuthn, Saml, SamlError, Sp, StartSso};

impl Saml<Sp> {
    /// Local SP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.raw_service_provider().metadata_xml()
    }

    /// Raw compatibility Service Provider.
    pub fn raw_service_provider(&self) -> &ServiceProvider {
        &self.0.service_provider
    }

    /// Start SP-initiated Web SSO.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, the IdP metadata
    /// cannot be parsed or trusted, the requested ACS is missing or conflicts
    /// with the selected binding, or request creation fails because required
    /// metadata, signing keys, or supported bindings are unavailable.
    ///
    /// # Examples
    ///
    /// ```
    /// use saml_rs::{
    ///     AcsEndpoint, EntityId, IdpConfig, IdpDescriptor, IdpValidationPolicy,
    ///     MetadataTrustPolicy, RelayStateParam, Saml, SpConfig, SpValidationPolicy,
    ///     SsoEndpoint, StartSso,
    /// };
    ///
    /// # fn main() -> Result<(), saml_rs::SamlError> {
    /// let sp_config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
    ///     .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
    ///     .validation(SpValidationPolicy::compatibility())
    ///     .build()?;
    /// let idp_config = IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata")?)
    ///     .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso")?)
    ///     .validation(IdpValidationPolicy::compatibility())
    ///     .build()?;
    ///
    /// let sp = Saml::sp(sp_config)?;
    /// let idp = Saml::idp(idp_config)?;
    /// let idp = IdpDescriptor::from_metadata_xml(
    ///     idp.metadata_xml(),
    ///     MetadataTrustPolicy::UnsignedForCompatibility,
    /// )?;
    /// let relay_state = RelayStateParam::try_from_option(Some("state".to_string()))?;
    /// let started = sp.start_sso(&idp, StartSso::redirect().relay_state(relay_state))?;
    ///
    /// let redirect_url = started.outbound.redirect_url()?;
    /// # let _ = redirect_url;
    /// # Ok(()) }
    /// ```
    pub fn start_sso(
        &self,
        idp: &IdpDescriptor,
        options: StartSso,
    ) -> Result<Started<AuthnRequest>, SamlError> {
        options.relay_state.validate()?;
        let raw_idp = raw_idp_descriptor(idp)?;
        let acs = selected_acs(
            self.raw_service_provider(),
            options.response_binding,
            options.acs_index,
        )?;
        let response_binding = acs.binding();
        let raw_options = LoginRequestOptions {
            relay_state: options.relay_state.as_deref(),
            force_authn: options.force_authn.map(ForceAuthn::as_bool),
            assertion_consumer_service_index: options.acs_index,
            response_binding: Some(response_binding.as_binding()),
            ..Default::default()
        };
        let context = self
            .raw_service_provider()
            .create_login_request_with_options(
                &raw_idp,
                options.binding.as_binding(),
                &raw_options,
            )?;
        let outbound = Outbound::<AuthnRequest>::try_from(context)?;
        let pending = PendingAuthnRequest::try_new(
            outbound.id().clone(),
            options.relay_state,
            acs,
            response_binding,
            idp.entity_id().clone(),
        )?
        .with_request_binding(options.binding);
        Ok(Started { pending, outbound })
    }

    /// Finish SP-initiated SSO using stored pending AuthnRequest state.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// request, including issuer, binding, relay state, destination, recipient,
    /// or `InResponseTo` mismatches; when XML, signature, certificate trust,
    /// audience, or time-window validation fails; or when replay validation
    /// returns `ReplayDetected` or `TimeWindowInvalid`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, IdpDescriptor, PendingAuthnRequest, ReplayPolicy, Saml,
    ///     SamlValidationContext, SsoResponse,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     pending: &PendingAuthnRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let input = BrowserInput::<SsoResponse>::post(fields);
    /// let session = sp.finish_sso(idp, pending, input, validation)?;
    ///
    /// let name_id = session.name_id().value();
    /// # let _ = name_id;
    /// # Ok(()) }
    /// ```
    pub fn finish_sso(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingAuthnRequest,
        input: BrowserInput<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        ensure_entity_id(pending.idp_entity_id(), idp.entity_id())?;
        ensure_sso_response_binding(input_binding(&input), pending.response_binding())?;
        ensure_relay_state(pending.relay_state(), &relay_state_from_input(&input)?)?;
        let raw_idp = raw_idp_descriptor(idp)?;
        let request = HttpRequest::try_from(input)?;
        let flow = self
            .raw_service_provider()
            .parse_login_response_with_request_id_at(
                &raw_idp,
                pending.response_binding().as_binding(),
                &request,
                pending.request_id().as_str(),
                LoginResponseParseOptions::at(
                    validation.now(),
                    validation.clock_skew().as_millis(),
                )
                .with_expected_recipient(pending.acs().location().as_str()),
            )?;
        let session = SsoSession::try_from(flow)?;
        session.check_and_store_replay(&mut validation)?;
        Ok(session)
    }

    /// Accept an IdP-initiated SSO response explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the browser binding is not valid for SSO
    /// responses, the IdP metadata cannot be parsed or trusted, XML parsing or
    /// signature verification fails, destination, recipient, audience, or time
    /// validation fails, or replay validation returns `ReplayDetected` or
    /// `TimeWindowInvalid`.
    pub fn accept_unsolicited_sso(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<SsoResponse>,
        mut validation: SamlValidationContext<'_>,
    ) -> Result<SsoSession, SamlError> {
        let binding = SsoResponseBinding::try_from(input_binding(&input))?;
        let raw_idp = raw_idp_descriptor(idp)?;
        let request = HttpRequest::try_from(input)?;
        let flow = self
            .raw_service_provider()
            .parse_unsolicited_login_response_at(
                &raw_idp,
                binding.as_binding(),
                &request,
                validation.now(),
                validation.clock_skew().as_millis(),
            )?;
        let session = SsoSession::try_from(flow)?;
        session.check_and_store_replay(&mut validation)?;
        Ok(session)
    }
}
