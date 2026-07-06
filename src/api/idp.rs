use crate::browser::{BrowserInput, Outbound, SsoRequestBinding};
use crate::config::SpDescriptor;
use crate::error::SamlError as Error;
use crate::flow::HttpRequest;
use crate::idp::{IdentityProvider, LoginResponseOptions, LoginResponseOverrides};
use crate::model::{
    AuthnRequest, Received, RelayStateParam, ReplayKey, SamlValidationContext, SsoResponse, Subject,
};

use super::raw_mapping::{
    ensure_entity_id, input_binding, raw_sp_descriptor, relay_state_from_input, response_target,
};
use super::{Idp, RespondSso, Saml, SamlError};

impl Saml<Idp> {
    /// Local IdP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.raw_identity_provider().metadata_xml()
    }

    /// Raw compatibility Identity Provider.
    pub fn raw_identity_provider(&self) -> &IdentityProvider {
        &self.0.identity_provider
    }

    /// Receive an SP AuthnRequest.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when browser input or relay state is invalid, the
    /// request binding is unsupported, SP metadata cannot be parsed, XML
    /// parsing or signature/trust validation fails, the request destination
    /// does not match local metadata, or replay validation detects a duplicate
    /// or expired request.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     AuthnRequest, BrowserInput, FormField, ReplayPolicy, RespondSso, Saml,
    ///     SamlValidationContext, SpDescriptor, Subject,
    /// };
    /// use time::OffsetDateTime;
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     fields: Vec<FormField>,
    /// #     subject: Subject,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     OffsetDateTime::now_utc(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let input = BrowserInput::<AuthnRequest>::post(fields);
    /// let request = idp.receive_sso(sp, input, validation)?;
    /// let response = idp.respond_sso(sp, &request, subject, RespondSso::post())?;
    ///
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn receive_sso(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<AuthnRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<AuthnRequest>, SamlError> {
        let relay_state = relay_state_from_input(&input)?;
        let binding = SsoRequestBinding::try_from(input_binding(&input))?;
        let raw_sp = raw_sp_descriptor(sp)?;
        let request = HttpRequest::try_from(input)?;
        let flow = self.raw_identity_provider().parse_login_request_at(
            &raw_sp,
            binding.as_binding(),
            &request,
            validation.now(),
            validation.clock_skew().as_millis(),
        )?;
        let authn = AuthnRequest::try_from(flow)?;
        if let Some(destination) = authn.destination() {
            let expected = self
                .raw_identity_provider()
                .metadata
                .get_single_sign_on_service(binding.as_binding())
                .ok_or_else(|| Error::MissingMetadata("SingleSignOnService".into()))?;
            if destination.as_str() != expected {
                return Err(Error::destination_mismatch(
                    &expected,
                    Some(destination.as_str()),
                ));
            }
        }
        let mut validation = validation;
        validation.check_and_store_message_replay(ReplayKey::AuthnRequestId(authn.id().clone()))?;
        Ok(Received::new(authn).with_relay_state(relay_state))
    }

    /// Respond to a received SP AuthnRequest.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the request issuer does not match the SP
    /// descriptor, relay state is invalid, the request ACS selection conflicts
    /// with the response binding or SP metadata, required metadata or signing
    /// keys are missing, or response creation fails.
    pub fn respond_sso(
        &self,
        sp: &SpDescriptor,
        request: &Received<AuthnRequest>,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        ensure_entity_id(request.message().issuer(), sp.entity_id())?;
        self.issue_sso(sp, Some(request), subject, options)
    }

    /// Initiate IdP-initiated SSO.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, SP metadata cannot be
    /// parsed, a compatible ACS endpoint or signing key is missing, the
    /// selected binding is unsupported, or response creation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, IdpDescriptor, ReplayPolicy, RespondSso, Saml,
    ///     SamlValidationContext, SpDescriptor, SsoResponse, Subject,
    /// };
    /// use time::OffsetDateTime;
    ///
    /// # fn initiate(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     sp_descriptor: &SpDescriptor,
    /// #     idp_descriptor: &IdpDescriptor,
    /// #     subject: Subject,
    /// #     form_fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.initiate_sso(sp_descriptor, subject, RespondSso::post())?;
    /// let form = response.post_form()?;
    /// # let _ = form;
    ///
    /// let validation = SamlValidationContext::new(
    ///     OffsetDateTime::now_utc(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let session = sp.accept_unsolicited_sso(
    ///     idp_descriptor,
    ///     BrowserInput::<SsoResponse>::post(form_fields),
    ///     validation,
    /// )?;
    /// let issuer = session.issuer().as_str();
    /// # let _ = issuer;
    /// # Ok(()) }
    /// ```
    pub fn initiate_sso(
        &self,
        sp: &SpDescriptor,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        self.issue_sso(sp, None, subject, options)
    }
    fn issue_sso(
        &self,
        sp: &SpDescriptor,
        request: Option<&Received<AuthnRequest>>,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let relay_state = options.relay_state.unwrap_or_else(|| {
            request.map_or_else(RelayStateParam::absent, |request| {
                request.relay_state().clone()
            })
        });
        relay_state.validate()?;
        let raw_sp = raw_sp_descriptor(sp)?;
        let (binding, explicit_acs) = match request {
            Some(request) => response_target(&raw_sp, request.message(), options.binding)?,
            None => (options.binding, None),
        };
        let name_id_format = subject
            .name_id()
            .format()
            .map(|format| format.as_uri().to_string());
        let user = user_from_subject(subject);
        let raw_options = LoginResponseOptions {
            in_response_to: request.map(|request| request.message().id().as_str()),
            relay_state: relay_state.as_deref(),
            encrypt_then_sign: false,
            custom: None,
        };
        let context = self
            .raw_identity_provider()
            .create_login_response_with_overrides(
                &raw_sp,
                binding.as_binding(),
                &user,
                &raw_options,
                LoginResponseOverrides {
                    acs: explicit_acs.as_deref(),
                    name_id_format: name_id_format.as_deref(),
                },
            )?;
        Outbound::<SsoResponse>::try_from(context)
    }
}
fn user_from_subject(subject: Subject) -> crate::entity::User {
    let name_id = subject.name_id().value().to_string();
    crate::entity::User::new(name_id)
}
