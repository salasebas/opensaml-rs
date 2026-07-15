use crate::browser::{BrowserInput, LogoutBinding, Outbound, PendingLogoutRequest, Started};
use crate::config::{EntityId, IdpDescriptor, SpDescriptor};
use crate::constants::Binding;
use crate::entity::EntitySetting;
use crate::error::SamlError as Error;
use crate::flow::HttpRequest;
use crate::logout::{
    create_logout_request_with_session_indexes, create_logout_response_checked,
    parse_logout_request_at, parse_logout_response_at, LogoutRequestSessionIndexes,
};
use crate::metadata::Metadata;
use crate::model::{
    LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSubject, Received, ReplayKey,
    SamlValidationContext,
};

use super::raw_mapping::{
    ensure_entity_id, ensure_relay_state, input_binding, raw_idp_descriptor, raw_sp_descriptor,
    relay_state_from_input,
};
use super::{Idp, LogoutSigning, RespondSlo, Saml, SamlError, Sp, StartSlo};

impl Saml<Sp> {
    /// Start SP-initiated Single Logout.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, IdP metadata cannot
    /// be parsed, a compatible logout endpoint or signing key is missing, the
    /// selected binding is unsupported, or logout request creation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{IdpDescriptor, LogoutSubject, Saml, StartSlo};
    ///
    /// # fn logout(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     subject: LogoutSubject,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = sp.start_slo(idp, subject, StartSlo::post())?;
    /// let form = started.outbound.post_form()?;
    /// let snapshot = started.pending.snapshot();
    /// # let _ = (form, snapshot);
    /// # Ok(()) }
    /// ```
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
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the browser input or relay state is invalid,
    /// the binding is unsupported for logout, IdP metadata cannot be parsed,
    /// XML parsing or signature/trust validation fails, the destination does
    /// not match local metadata, or replay validation detects a duplicate or
    /// expired message.
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
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when IdP metadata cannot be parsed, relay state is
    /// invalid, a compatible logout endpoint or signing key is missing, the
    /// selected binding is unsupported, or logout response creation fails.
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
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// request, including issuer, binding, relay state, destination, or
    /// `InResponseTo` mismatches; when IdP metadata cannot be parsed; when XML,
    /// signature, trust, status, or time validation fails; or when replay
    /// validation detects a duplicate or expired message.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, IdpDescriptor, LogoutResponse, PendingLogoutRequest,
    ///     ReplayPolicy, Saml, SamlValidationContext,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     sp: &Saml<saml_rs::Sp>,
    /// #     idp: &IdpDescriptor,
    /// #     pending: &PendingLogoutRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let completed = sp.finish_slo(
    ///     idp,
    ///     pending,
    ///     BrowserInput::<LogoutResponse>::post(fields),
    ///     validation,
    /// )?;
    ///
    /// let peer = completed.peer_entity_id().as_str();
    /// # let _ = peer;
    /// # Ok(()) }
    /// ```
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
    /// Start IdP-initiated Single Logout.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when relay state is invalid, SP metadata cannot be
    /// parsed, a compatible logout endpoint or signing key is missing, the
    /// selected binding is unsupported, or logout request creation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{LogoutSubject, Saml, SpDescriptor, StartSlo};
    ///
    /// # fn logout(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     subject: LogoutSubject,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let started = idp.start_slo(sp, subject, StartSlo::post())?;
    /// let form = started.outbound.post_form()?;
    /// let snapshot = started.pending.snapshot();
    /// # let _ = (form, snapshot);
    /// # Ok(()) }
    /// ```
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
    /// # Errors
    ///
    /// Returns [`SamlError`] when the browser input or relay state is invalid,
    /// the binding is unsupported for logout, SP metadata cannot be parsed, XML
    /// parsing or signature/trust validation fails, the destination does not
    /// match local metadata, or replay validation detects a duplicate or
    /// expired message.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, LogoutRequest, ReplayPolicy, RespondSlo, Saml,
    ///     SamlValidationContext, SpDescriptor,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
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
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when SP metadata cannot be parsed, relay state is
    /// invalid, a compatible logout endpoint or signing key is missing, the
    /// selected binding is unsupported, or logout response creation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{LogoutRequest, Received, RespondSlo, Saml, SpDescriptor};
    ///
    /// # fn respond(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     request: &Received<LogoutRequest>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let response = idp.respond_slo(sp, request, RespondSlo::post())?;
    /// let form = response.post_form()?;
    /// # let _ = form;
    /// # Ok(()) }
    /// ```
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
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when the response does not match the pending
    /// request, including issuer, binding, relay state, destination, or
    /// `InResponseTo` mismatches; when SP metadata cannot be parsed; when XML,
    /// signature, trust, status, or time validation fails; or when replay
    /// validation detects a duplicate or expired message.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use saml_rs::{
    ///     BrowserInput, FormField, LogoutResponse, PendingLogoutRequest, ReplayPolicy,
    ///     Saml, SamlValidationContext, SpDescriptor,
    /// };
    /// use std::time::SystemTime;
    ///
    /// # fn finish(
    /// #     idp: &Saml<saml_rs::Idp>,
    /// #     sp: &SpDescriptor,
    /// #     pending: &PendingLogoutRequest,
    /// #     fields: Vec<FormField>,
    /// # ) -> Result<(), saml_rs::SamlError> {
    /// let validation = SamlValidationContext::new(
    ///     SystemTime::now(),
    ///     ReplayPolicy::DisabledForCompatibility,
    /// );
    /// let completed = idp.finish_slo(
    ///     sp,
    ///     pending,
    ///     BrowserInput::<LogoutResponse>::post(fields),
    ///     validation,
    /// )?;
    ///
    /// let peer = completed.peer_entity_id().as_str();
    /// # let _ = peer;
    /// # Ok(()) }
    /// ```
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
    let context = create_logout_request_with_session_indexes(LogoutRequestSessionIndexes {
        init_setting: local_setting,
        init_meta: local_metadata,
        target_meta: peer_metadata,
        binding: options.binding.as_binding(),
        name_id: &subject.name_id,
        session_indexes: &subject.session_indexes,
        relay_state: options.relay_state.as_deref(),
        want_signed: logout_request_signing(local_setting, options.signing),
    })?;
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
    mut validation: SamlValidationContext<'_>,
) -> Result<Received<LogoutRequest>, SamlError> {
    let relay_state = relay_state_from_input(&input)?;
    let binding = LogoutBinding::try_from(input_binding(&input))?;
    let request = HttpRequest::try_from(input)?;
    let flow = parse_logout_request_at(
        local_setting,
        peer_metadata,
        binding.as_binding(),
        &request,
        validation.now_offset(),
        validation.clock_skew().as_millis(),
    )?;
    let logout = LogoutRequest::try_from(flow)?;
    ensure_logout_destination(local_metadata, binding, logout.destination())?;
    validation.check_and_store_message_replay(ReplayKey::LogoutRequestId(logout.id().clone()))?;
    Ok(Received::new(logout).with_relay_state(relay_state))
}

fn respond_slo_impl(
    local_setting: &EntitySetting,
    local_metadata: &Metadata,
    peer_metadata: &Metadata,
    request: &Received<LogoutRequest>,
    options: RespondSlo,
) -> Result<Outbound<LogoutResponse>, SamlError> {
    let relay_state = options
        .relay_state
        .unwrap_or_else(|| request.relay_state().clone());
    relay_state.validate()?;
    let context = create_logout_response_checked(
        local_setting,
        local_metadata,
        peer_metadata,
        options.binding.as_binding(),
        Some(request.message().id().as_str()),
        relay_state.as_deref(),
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
    mut validation: SamlValidationContext<'_>,
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
        validation.now_offset(),
        validation.clock_skew().as_millis(),
    )?;
    let response = LogoutResponse::try_from(flow)?;
    ensure_logout_destination(
        local_metadata,
        pending.response_binding(),
        response.destination(),
    )?;
    validation
        .check_and_store_message_replay(ReplayKey::LogoutResponseId(response.id().clone()))?;
    Ok(LogoutCompleted::from_response(
        peer_entity_id.clone(),
        response,
    ))
}

fn logout_request_signing(setting: &EntitySetting, signing: LogoutSigning) -> bool {
    match signing {
        LogoutSigning::FollowLocalPolicy => setting.want_logout_request_signed,
        LogoutSigning::Sign => true,
        LogoutSigning::DoNotSignForCompatibility => false,
    }
}

fn logout_response_signing(setting: &EntitySetting, signing: LogoutSigning) -> bool {
    match signing {
        LogoutSigning::FollowLocalPolicy => setting.want_logout_response_signed,
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
