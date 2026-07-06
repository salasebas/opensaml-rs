//! Typed high-level API contract for `saml-rs`.
//!
//! Artifact binding is not part of the high-level browser SSO request binding
//! contract.
//!
//! ```compile_fail
//! use saml_rs::SsoRequestBinding;
//!
//! let binding = SsoRequestBinding::Artifact;
//! ```

use crate::browser::{
    AcsEndpoint, BrowserInput, LogoutBinding, Outbound, Pending, PendingAuthnRequest,
    PendingLogoutRequest, SsoRequestBinding, SsoResponseBinding, Started,
};
use crate::config::{
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, CertificatePem, EntityId, IdpConfig,
    IdpDescriptor, NameIdFormat, SpConfig, SpDescriptor,
};
use crate::constants::Binding;
use crate::entity::EntitySetting;
use crate::error::SamlError as Error;
use crate::flow::HttpRequest;
use crate::idp::{IdentityProvider, LoginResponseOptions, LoginResponseOverrides};
use crate::logout::{
    create_logout_request_with_session_indexes, create_logout_response_checked,
    parse_logout_request_at, parse_logout_response_at,
};
use crate::metadata::{
    IdpMetadataConfig as RawIdpMetadataConfig, Metadata, SpMetadataConfig as RawSpMetadataConfig,
};
use crate::model::{
    AuthnRequest, LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSubject, Received,
    RelayStateParam, SamlValidationContext, SsoResponse, SsoSession, Subject,
};
use crate::sp::{ExpectedLoginResponse, LoginRequestOptions, ServiceProvider};

/// Typed SAML facade for high-level browser SSO/SLO flows.
pub struct Saml<Role = Unknown>(Role);

/// Marker role used before a facade has been configured as an SP or IdP.
pub enum Unknown {}

/// Marker role for a Service Provider facade.
pub struct Sp {
    service_provider: ServiceProvider,
}

/// Marker role for an Identity Provider facade.
pub struct Idp {
    identity_provider: IdentityProvider,
}

/// Error type returned by the typed SAML API.
pub type SamlError = Error;

#[derive(Debug, Clone, Copy)]
enum RequestedResponseBinding {
    DefaultPost,
    Explicit(SsoResponseBinding),
}

impl RequestedResponseBinding {
    fn binding(self) -> SsoResponseBinding {
        match self {
            Self::DefaultPost => SsoResponseBinding::Post,
            Self::Explicit(binding) => binding,
        }
    }

    fn explicit(self) -> Option<SsoResponseBinding> {
        match self {
            Self::DefaultPost => None,
            Self::Explicit(binding) => Some(binding),
        }
    }
}

/// Options for starting SP-initiated Web SSO.
#[derive(Debug, Clone)]
pub struct StartSso {
    binding: SsoRequestBinding,
    response_binding: RequestedResponseBinding,
    relay_state: RelayStateParam,
    force_authn: Option<bool>,
    acs_index: Option<u16>,
}

impl StartSso {
    /// Start SSO with HTTP-Redirect AuthnRequest dispatch.
    pub fn redirect() -> Self {
        Self::new(SsoRequestBinding::Redirect)
    }

    /// Start SSO with HTTP-POST AuthnRequest dispatch.
    pub fn post() -> Self {
        Self::new(SsoRequestBinding::Post)
    }

    /// Start SSO with HTTP-POST-SimpleSign AuthnRequest dispatch.
    pub fn simple_sign() -> Self {
        Self::new(SsoRequestBinding::SimpleSign)
    }

    fn new(binding: SsoRequestBinding) -> Self {
        Self {
            binding,
            response_binding: RequestedResponseBinding::DefaultPost,
            relay_state: RelayStateParam::absent(),
            force_authn: None,
            acs_index: None,
        }
    }

    /// Set the expected SAML Response binding.
    pub fn response_binding(mut self, binding: SsoResponseBinding) -> Self {
        self.response_binding = RequestedResponseBinding::Explicit(binding);
        self
    }

    /// Set exact RelayState state for the outbound request.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = relay_state;
        self
    }

    /// Set ForceAuthn.
    pub fn force_authn(mut self, force_authn: bool) -> Self {
        self.force_authn = Some(force_authn);
        self
    }

    /// Emit `ForceAuthn="true"`.
    pub fn force_authn_required(self) -> Self {
        self.force_authn(true)
    }

    /// Emit `ForceAuthn="false"`.
    pub fn force_authn_not_required(self) -> Self {
        self.force_authn(false)
    }

    /// Omit `ForceAuthn`.
    pub fn force_authn_omitted(mut self) -> Self {
        self.force_authn = None;
        self
    }

    /// Select an AssertionConsumerServiceIndex.
    pub fn acs_index(mut self, acs_index: u16) -> Self {
        self.acs_index = Some(acs_index);
        self
    }
}

/// Options for issuing SAML Responses from an IdP.
#[derive(Debug, Clone)]
pub struct RespondSso {
    binding: SsoResponseBinding,
    relay_state: Option<RelayStateParam>,
    encrypt_then_sign: bool,
}

impl RespondSso {
    /// Respond with HTTP-POST.
    pub fn post() -> Self {
        Self::new(SsoResponseBinding::Post)
    }

    /// Respond with HTTP-POST-SimpleSign.
    pub fn simple_sign() -> Self {
        Self::new(SsoResponseBinding::SimpleSign)
    }

    fn new(binding: SsoResponseBinding) -> Self {
        Self {
            binding,
            relay_state: None,
            encrypt_then_sign: false,
        }
    }

    /// Set exact RelayState state for the response.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    /// Request encrypt-then-sign ordering for encrypted responses.
    ///
    /// The raw response builder already resolves message signatures over
    /// encrypted assertions to the sound order required for verification.
    pub fn encrypt_then_sign(mut self) -> Self {
        self.encrypt_then_sign = true;
        self
    }
}

/// Explicit signing choice for typed Single Logout messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutSigning {
    /// Use the local typed logout policy.
    FollowPolicy,
    /// Sign this logout message.
    Sign,
    /// Send unsigned logout for an explicit compatibility exception.
    DoNotSignForCompatibility,
}

/// Options for issuing a LogoutRequest.
#[derive(Debug, Clone)]
pub struct StartSlo {
    binding: LogoutBinding,
    relay_state: RelayStateParam,
    signing: LogoutSigning,
}

impl StartSlo {
    /// Start SLO with HTTP-Redirect.
    pub fn redirect() -> Self {
        Self::new(LogoutBinding::Redirect)
    }

    /// Start SLO with HTTP-POST.
    pub fn post() -> Self {
        Self::new(LogoutBinding::Post)
    }

    /// Start SLO with HTTP-POST-SimpleSign.
    pub fn simple_sign() -> Self {
        Self::new(LogoutBinding::SimpleSign)
    }

    fn new(binding: LogoutBinding) -> Self {
        Self {
            binding,
            relay_state: RelayStateParam::absent(),
            signing: LogoutSigning::FollowPolicy,
        }
    }

    /// Set exact RelayState state for the logout request.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = relay_state;
        self
    }

    /// Set logout request signing behavior.
    pub fn signing(mut self, signing: LogoutSigning) -> Self {
        self.signing = signing;
        self
    }
}

/// Options for issuing a LogoutResponse.
#[derive(Debug, Clone)]
pub struct RespondSlo {
    binding: LogoutBinding,
    relay_state: RelayStateParam,
    signing: LogoutSigning,
}

impl RespondSlo {
    /// Respond with HTTP-Redirect.
    pub fn redirect() -> Self {
        Self::new(LogoutBinding::Redirect)
    }

    /// Respond with HTTP-POST.
    pub fn post() -> Self {
        Self::new(LogoutBinding::Post)
    }

    /// Respond with HTTP-POST-SimpleSign.
    pub fn simple_sign() -> Self {
        Self::new(LogoutBinding::SimpleSign)
    }

    fn new(binding: LogoutBinding) -> Self {
        Self {
            binding,
            relay_state: RelayStateParam::absent(),
            signing: LogoutSigning::FollowPolicy,
        }
    }

    /// Set exact RelayState state for the logout response.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = relay_state;
        self
    }

    /// Set logout response signing behavior.
    pub fn signing(mut self, signing: LogoutSigning) -> Self {
        self.signing = signing;
        self
    }
}

impl Saml {
    /// Build a typed Service Provider facade.
    pub fn sp(config: SpConfig) -> Result<Saml<Sp>, SamlError> {
        let setting = EntitySetting::try_from(&config)?;
        let raw_config = raw_sp_metadata_config(&config);
        let service_provider = ServiceProvider::from_config(&raw_config, setting)?;
        Ok(Saml(Sp { service_provider }))
    }

    /// Build a typed Identity Provider facade.
    pub fn idp(config: IdpConfig) -> Result<Saml<Idp>, SamlError> {
        let setting = EntitySetting::try_from(&config)?;
        let raw_config = raw_idp_metadata_config(&config);
        let identity_provider = IdentityProvider::from_config(&raw_config, setting)?;
        Ok(Saml(Idp { identity_provider }))
    }
}

impl Saml<Sp> {
    /// Local SP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.raw_service_provider().metadata_xml()
    }

    /// Raw compatibility Service Provider.
    ///
    /// This is an escape hatch for compatibility and advanced integrations. It
    /// bypasses the typed facade invariants enforced by methods such as
    /// [`Self::start_sso`] and [`Self::finish_sso`].
    pub fn raw_service_provider(&self) -> &ServiceProvider {
        &self.0.service_provider
    }

    /// Start SP-initiated Web SSO.
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
            force_authn: options.force_authn,
            assertion_consumer_service_index: options.acs_index,
            response_binding: Some(response_binding.as_binding()),
            ..Default::default()
        };
        let context = self
            .raw_service_provider()
            .create_login_request_with_options_suppressing_default_relay_state(
                &raw_idp,
                options.binding.as_binding(),
                &raw_options,
            )?;
        let outbound = Outbound::<AuthnRequest>::try_from(context)?;
        let pending = Pending::<AuthnRequest>::try_new(
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
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, IdpDescriptor, PendingAuthnRequest, ReplayPolicy, Saml,
    ///     SamlValidationContext, SsoResponse,
    /// };
    /// use time::OffsetDateTime;
    ///
    /// # fn finish(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     pending: &PendingAuthnRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     OffsetDateTime::now_utc(),
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
            .parse_login_response_with_request_id_and_recipient_at(
                &raw_idp,
                pending.response_binding().as_binding(),
                &request,
                ExpectedLoginResponse {
                    request_id: pending.request_id().as_str(),
                    recipient: pending.acs().location().as_str(),
                },
                validation.now(),
                validation.clock_skew().as_millis(),
            )?;
        let session = SsoSession::try_from(flow)?;
        session.check_and_store_replay(&mut validation)?;
        Ok(session)
    }

    /// Accept an IdP-initiated SSO response explicitly.
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

    /// Start SP-initiated Single Logout.
    pub fn start_slo(
        &self,
        idp: &IdpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        start_slo_impl(
            &self.raw_service_provider().setting,
            &self.raw_service_provider().metadata,
            idp.entity_id(),
            &raw_idp.metadata,
            subject,
            options,
        )
    }

    /// Receive an IdP LogoutRequest.
    pub fn receive_slo(
        &self,
        idp: &IdpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        receive_slo_impl(
            &self.raw_service_provider().setting,
            &self.raw_service_provider().metadata,
            &raw_idp.metadata,
            input,
            validation,
        )
    }

    /// Respond to a received IdP LogoutRequest.
    pub fn respond_slo(
        &self,
        idp: &IdpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        respond_slo_impl(
            &self.raw_service_provider().setting,
            &self.raw_service_provider().metadata,
            &raw_idp.metadata,
            request,
            options,
        )
    }

    /// Finish SP-initiated Single Logout using stored pending LogoutRequest state.
    pub fn finish_slo(
        &self,
        idp: &IdpDescriptor,
        pending: &PendingLogoutRequest,
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError> {
        let raw_idp = raw_idp_descriptor(idp)?;
        finish_slo_impl(
            &self.raw_service_provider().setting,
            &self.raw_service_provider().metadata,
            idp.entity_id(),
            &raw_idp.metadata,
            pending,
            input,
            validation,
        )
    }
}

impl Saml<Idp> {
    /// Local IdP metadata XML.
    pub fn metadata_xml(&self) -> &str {
        self.raw_identity_provider().metadata_xml()
    }

    /// Raw compatibility Identity Provider.
    ///
    /// This is an escape hatch for compatibility and advanced integrations. It
    /// bypasses the typed facade invariants enforced by methods such as
    /// [`Self::receive_sso`] and [`Self::respond_sso`].
    pub fn raw_identity_provider(&self) -> &IdentityProvider {
        &self.0.identity_provider
    }

    /// Receive an SP AuthnRequest.
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
        mut validation: SamlValidationContext<'_>,
    ) -> Result<Received<AuthnRequest>, SamlError> {
        let binding = SsoRequestBinding::try_from(input_binding(&input))?;
        let relay_state = relay_state_from_input(&input)?;
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
        authn.check_and_store_replay(&mut validation)?;
        Ok(Received::with_relay_state(authn, relay_state))
    }

    /// Respond to a received SP AuthnRequest.
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
    pub fn initiate_sso(
        &self,
        sp: &SpDescriptor,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        self.issue_sso(sp, None, subject, options)
    }

    /// Start IdP-initiated Single Logout.
    pub fn start_slo(
        &self,
        sp: &SpDescriptor,
        subject: LogoutSubject,
        options: StartSlo,
    ) -> Result<Started<LogoutRequest>, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        start_slo_impl(
            &self.raw_identity_provider().setting,
            &self.raw_identity_provider().metadata,
            sp.entity_id(),
            &raw_sp.metadata,
            subject,
            options,
        )
    }

    /// Receive an SP LogoutRequest.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, LogoutRequest, ReplayPolicy, RespondSlo, Saml,
    ///     SamlValidationContext, SpDescriptor,
    /// };
    /// use time::OffsetDateTime;
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     OffsetDateTime::now_utc(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let input = BrowserInput::<LogoutRequest>::post(fields);
    /// let request = idp.receive_slo(sp, input, validation)?;
    /// let response = idp.respond_slo(sp, &request, RespondSlo::post())?;
    ///
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
    pub fn receive_slo(
        &self,
        sp: &SpDescriptor,
        input: BrowserInput<LogoutRequest>,
        validation: SamlValidationContext<'_>,
    ) -> Result<Received<LogoutRequest>, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        receive_slo_impl(
            &self.raw_identity_provider().setting,
            &self.raw_identity_provider().metadata,
            &raw_sp.metadata,
            input,
            validation,
        )
    }

    /// Respond to a received SP LogoutRequest.
    pub fn respond_slo(
        &self,
        sp: &SpDescriptor,
        request: &Received<LogoutRequest>,
        options: RespondSlo,
    ) -> Result<Outbound<LogoutResponse>, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        respond_slo_impl(
            &self.raw_identity_provider().setting,
            &self.raw_identity_provider().metadata,
            &raw_sp.metadata,
            request,
            options,
        )
    }

    /// Finish IdP-initiated Single Logout using stored pending LogoutRequest state.
    pub fn finish_slo(
        &self,
        sp: &SpDescriptor,
        pending: &PendingLogoutRequest,
        input: BrowserInput<LogoutResponse>,
        validation: SamlValidationContext<'_>,
    ) -> Result<LogoutCompleted, SamlError> {
        let raw_sp = raw_sp_descriptor(sp)?;
        finish_slo_impl(
            &self.raw_identity_provider().setting,
            &self.raw_identity_provider().metadata,
            sp.entity_id(),
            &raw_sp.metadata,
            pending,
            input,
            validation,
        )
    }

    fn issue_sso(
        &self,
        sp: &SpDescriptor,
        request: Option<&Received<AuthnRequest>>,
        subject: Subject,
        options: RespondSso,
    ) -> Result<Outbound<SsoResponse>, SamlError> {
        let relay_state = options.relay_state.clone().unwrap_or_else(|| {
            request.map_or_else(RelayStateParam::absent, |r| r.relay_state().clone())
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
            encrypt_then_sign: options.encrypt_then_sign,
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

fn raw_sp_metadata_config(config: &SpConfig) -> RawSpMetadataConfig {
    RawSpMetadataConfig {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: certificates(&config.credentials.signing_certificate),
        encrypt_certs: certificates(&config.credentials.encryption_certificate),
        authn_requests_signed: matches!(
            config.validation.authn_requests,
            AuthnRequestSigningPolicy::Sign
        ),
        want_assertions_signed: matches!(
            config.validation.assertions,
            crate::config::AssertionSignaturePolicy::RequireSigned
        ),
        name_id_format: name_id_format_uris(&config.metadata.name_id_format),
        single_logout_service: config
            .metadata
            .single_logout_service
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        assertion_consumer_service: config
            .metadata
            .assertion_consumer_service
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        elements_order: config.metadata.elements_order.clone(),
    }
}

fn raw_idp_metadata_config(config: &IdpConfig) -> RawIdpMetadataConfig {
    RawIdpMetadataConfig {
        entity_id: config.entity_id.as_str().to_string(),
        signing_certs: certificates(&config.credentials.signing_certificate),
        encrypt_certs: certificates(&config.credentials.encryption_certificate),
        want_authn_requests_signed: matches!(
            config.validation.authn_requests,
            AuthnRequestValidationPolicy::RequireSigned
        ),
        name_id_format: name_id_format_uris(&config.metadata.name_id_format),
        single_sign_on_service: config
            .metadata
            .single_sign_on_service
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        single_logout_service: config
            .metadata
            .single_logout_service
            .iter()
            .map(|endpoint| endpoint.to_raw())
            .collect(),
        elements_order: config.metadata.elements_order.clone(),
    }
}

fn certificates(certificate: &Option<CertificatePem>) -> Vec<String> {
    certificate
        .as_ref()
        .map(|certificate| vec![certificate.as_str().to_string()])
        .unwrap_or_default()
}

fn name_id_format_uris(formats: &[NameIdFormat]) -> Vec<String> {
    formats
        .iter()
        .map(|format| format.as_uri().to_string())
        .collect()
}

fn raw_idp_descriptor(idp: &IdpDescriptor) -> Result<IdentityProvider, SamlError> {
    IdentityProvider::from_metadata(idp.metadata_xml(), EntitySetting::default())
}

fn raw_sp_descriptor(sp: &SpDescriptor) -> Result<ServiceProvider, SamlError> {
    ServiceProvider::from_metadata(sp.metadata_xml(), EntitySetting::default())
}

fn selected_acs(
    sp: &ServiceProvider,
    requested_binding: RequestedResponseBinding,
    index: Option<u16>,
) -> Result<AcsEndpoint, SamlError> {
    if let Some(index) = index {
        let endpoint = sp
            .metadata
            .get_assertion_consumer_service_by_index(index)?
            .ok_or_else(|| Error::MissingMetadata("AssertionConsumerService".into()))?;
        let binding = SsoResponseBinding::try_from(endpoint.binding)?;
        if let Some(explicit) = requested_binding.explicit() {
            if explicit != binding {
                return Err(Error::Invalid(
                    "requested response binding conflicts with ACS index".into(),
                ));
            }
        }
        return Ok(AcsEndpoint::new(
            binding,
            crate::model::EndpointUrl::try_new(endpoint.location)?,
        )
        .with_index(index)
        .with_default_flag(endpoint.is_default));
    }

    let binding = requested_binding.binding();
    let endpoint = sp
        .metadata
        .get_assertion_consumer_service_endpoint(binding.as_binding())
        .ok_or_else(|| Error::MissingMetadata("AssertionConsumerService".into()))?;
    Ok(AcsEndpoint::new(
        binding,
        crate::model::EndpointUrl::try_new(endpoint.location)?,
    )
    .with_default_flag(endpoint.is_default))
}

fn response_target(
    sp: &ServiceProvider,
    request: &AuthnRequest,
    selected_binding: SsoResponseBinding,
) -> Result<(SsoResponseBinding, Option<String>), SamlError> {
    if request.acs_url().is_some() && request.acs_index().is_some() {
        return Err(Error::Invalid(
            "AuthnRequest must not specify both ACS URL and ACS index".into(),
        ));
    }
    if let Some(protocol_binding) = request.protocol_binding() {
        if protocol_binding != selected_binding {
            return Err(Error::Invalid(
                "response binding conflicts with AuthnRequest ProtocolBinding".into(),
            ));
        }
    }
    let binding = request.protocol_binding().unwrap_or(selected_binding);

    if let Some(acs_url) = request.acs_url() {
        if !sp
            .metadata
            .has_assertion_consumer_service(binding.as_binding(), acs_url.as_str())
        {
            return Err(Error::destination_mismatch(
                acs_url.as_str(),
                sp.metadata
                    .get_assertion_consumer_service(binding.as_binding())
                    .as_deref(),
            ));
        }
        return Ok((binding, Some(acs_url.as_str().to_string())));
    }

    if let Some(index) = request.acs_index() {
        let endpoint = sp
            .metadata
            .get_assertion_consumer_service_by_index(index)?
            .ok_or_else(|| Error::MissingMetadata("AssertionConsumerService".into()))?;
        let indexed_binding = SsoResponseBinding::try_from(endpoint.binding)?;
        if indexed_binding != binding {
            return Err(Error::Invalid(
                "response binding conflicts with AuthnRequest ACS index".into(),
            ));
        }
        return Ok((binding, Some(endpoint.location)));
    }

    Ok((binding, None))
}

fn input_binding<Message>(input: &BrowserInput<Message>) -> Binding {
    match input {
        BrowserInput::Redirect { .. } => Binding::Redirect,
        BrowserInput::Post { .. } => Binding::Post,
        BrowserInput::SimpleSignPost { .. } => Binding::SimpleSign,
    }
}

fn relay_state_from_input<Message>(
    input: &BrowserInput<Message>,
) -> Result<RelayStateParam, SamlError> {
    match input {
        BrowserInput::Redirect { raw_query, .. } => {
            let mut values =
                url::form_urlencoded::parse(raw_query.trim_start_matches('?').as_bytes())
                    .filter(|(name, _)| name == "RelayState")
                    .map(|(_, value)| value.into_owned());
            let value = values.next();
            if values.next().is_some() {
                return Err(Error::Invalid("duplicate RelayState".into()));
            }
            RelayStateParam::try_from_option(value)
        }
        BrowserInput::Post { fields, .. } | BrowserInput::SimpleSignPost { fields, .. } => {
            let mut values = fields
                .iter()
                .filter(|field| field.name() == "RelayState")
                .map(|field| field.value().to_string());
            let value = values.next();
            if values.next().is_some() {
                return Err(Error::Invalid("duplicate RelayState".into()));
            }
            RelayStateParam::try_from_option(value)
        }
    }
}

fn ensure_relay_state(
    expected: &RelayStateParam,
    actual: &RelayStateParam,
) -> Result<(), SamlError> {
    if expected == actual {
        return Ok(());
    }
    Err(Error::RelayStateMismatch {
        expected: expected.clone(),
        actual: actual.clone(),
    })
}

fn ensure_entity_id(expected: &EntityId, actual: &EntityId) -> Result<(), SamlError> {
    if expected == actual {
        return Ok(());
    }
    Err(Error::issuer_mismatch(
        expected.as_str(),
        Some(actual.as_str()),
    ))
}

fn ensure_sso_response_binding(
    actual: Binding,
    expected: SsoResponseBinding,
) -> Result<(), SamlError> {
    if actual == expected.as_binding() {
        return Ok(());
    }
    Err(Error::UnsupportedBinding { binding: actual })
}

fn user_from_subject(subject: Subject) -> crate::entity::User {
    let name_id = subject.name_id().value().to_string();
    crate::entity::User::new(name_id)
}

struct TypedLogoutSubject {
    name_id: String,
    session_indexes: Vec<String>,
}

fn start_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_entity_id: &EntityId,
    peer_metadata: &Metadata,
    subject: LogoutSubject,
    options: StartSlo,
) -> Result<Started<LogoutRequest>, SamlError> {
    options.relay_state.validate()?;
    let subject = typed_logout_subject(subject);
    let context = create_logout_request_with_session_indexes(
        local_setting,
        local_metadata,
        peer_metadata,
        options.binding.as_binding(),
        &subject.name_id,
        &subject.session_indexes,
        options.relay_state.as_deref(),
        logout_request_signing(local_setting, options.signing),
    )?;
    let outbound = Outbound::<LogoutRequest>::try_from(context)?;
    let pending = PendingLogoutRequest::try_new(
        outbound.id().clone(),
        options.relay_state,
        options.binding,
        peer_entity_id.clone(),
    )?;
    Ok(Started { pending, outbound })
}

fn receive_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_metadata: &Metadata,
    input: BrowserInput<LogoutRequest>,
    validation: SamlValidationContext<'_>,
) -> Result<Received<LogoutRequest>, SamlError> {
    let binding = LogoutBinding::try_from(input_binding(&input))?;
    let request = HttpRequest::try_from(input)?;
    let flow = parse_logout_request_at(
        local_setting,
        peer_metadata,
        binding.as_binding(),
        &request,
        validation.now(),
        validation.clock_skew().as_millis(),
    )?;
    let logout = LogoutRequest::try_from(flow)?;
    ensure_logout_destination(local_metadata, binding, logout.destination())?;
    Ok(Received::new(logout))
}

fn respond_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_metadata: &Metadata,
    request: &Received<LogoutRequest>,
    options: RespondSlo,
) -> Result<Outbound<LogoutResponse>, SamlError> {
    options.relay_state.validate()?;
    let context = create_logout_response_checked(
        local_setting,
        local_metadata,
        peer_metadata,
        options.binding.as_binding(),
        Some(request.message().id().as_str()),
        options.relay_state.as_deref(),
        logout_response_signing(local_setting, options.signing),
    )?;
    Outbound::<LogoutResponse>::try_from(context)
}

fn finish_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_entity_id: &EntityId,
    peer_metadata: &Metadata,
    pending: &PendingLogoutRequest,
    input: BrowserInput<LogoutResponse>,
    validation: SamlValidationContext<'_>,
) -> Result<LogoutCompleted, SamlError> {
    ensure_entity_id(pending.peer_entity_id(), peer_entity_id)?;
    ensure_logout_response_binding(input_binding(&input), pending.response_binding())?;
    ensure_relay_state(pending.relay_state(), &relay_state_from_input(&input)?)?;
    let request = HttpRequest::try_from(input)?;
    let flow = parse_logout_response_at(
        local_setting,
        peer_metadata,
        pending.response_binding().as_binding(),
        &request,
        pending.id().as_str(),
        validation.now(),
        validation.clock_skew().as_millis(),
    )?;
    let response = LogoutResponse::try_from(flow)?;
    ensure_logout_destination(
        local_metadata,
        pending.response_binding(),
        response.destination(),
    )?;
    Ok(LogoutCompleted::from_response(
        peer_entity_id.clone(),
        response,
    ))
}

fn logout_request_signing(setting: &EntitySetting, signing: LogoutSigning) -> bool {
    match signing {
        LogoutSigning::FollowPolicy => setting.want_logout_request_signed,
        LogoutSigning::Sign => true,
        LogoutSigning::DoNotSignForCompatibility => false,
    }
}

fn logout_response_signing(setting: &EntitySetting, signing: LogoutSigning) -> bool {
    match signing {
        LogoutSigning::FollowPolicy => setting.want_logout_response_signed,
        LogoutSigning::Sign => true,
        LogoutSigning::DoNotSignForCompatibility => false,
    }
}

fn ensure_logout_response_binding(
    actual: Binding,
    expected: LogoutBinding,
) -> Result<(), SamlError> {
    if actual == expected.as_binding() {
        return Ok(());
    }
    Err(Error::UnsupportedBinding { binding: actual })
}

fn ensure_logout_destination(
    local_metadata: &Metadata,
    binding: LogoutBinding,
    actual: Option<&crate::model::EndpointUrl>,
) -> Result<(), SamlError> {
    let Some(actual) = actual else {
        return Ok(());
    };
    let expected = local_metadata
        .get_single_logout_service(binding.as_binding())
        .ok_or_else(|| Error::MissingMetadata("SingleLogoutService".into()))?;
    if actual.as_str() == expected {
        return Ok(());
    }
    Err(Error::destination_mismatch(
        &expected,
        Some(actual.as_str()),
    ))
}

fn typed_logout_subject(subject: LogoutSubject) -> TypedLogoutSubject {
    TypedLogoutSubject {
        name_id: subject.name_id().value().to_string(),
        session_indexes: subject
            .session_indexes()
            .iter()
            .map(|session_index| session_index.as_str().to_string())
            .collect(),
    }
}
