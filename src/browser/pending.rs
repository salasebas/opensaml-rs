use core::marker::PhantomData;

use super::bindings::{SsoRequestBinding, SsoResponseBinding};
use super::endpoints::AcsEndpoint;
use super::outbound::Outbound;
use crate::config::EntityId;
use crate::constants::Binding;
use crate::error::SamlError;
use crate::model::{AuthnRequest, EndpointUrl, MessageId, RelayStateParam, SamlInstant};

/// Persistable correlation snapshot for a pending SAML message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSnapshot<Message> {
    /// Correlation ID.
    pub id: String,
    /// Exact RelayState state.
    pub relay_state: RelayStateParam,
    /// Peer entity ID.
    pub peer_entity_id: String,
    /// Expected response binding keyword.
    pub expected_binding: String,
    /// Selected request binding keyword, if tracked.
    pub request_binding: Option<String>,
    /// Selected ACS URL.
    pub acs_url: String,
    /// Selected ACS binding keyword.
    pub acs_binding: String,
    /// Selected ACS index, if any.
    pub acs_index: Option<u16>,
    /// Whether the selected ACS was default.
    pub acs_is_default: bool,
    /// Issue instant, if recorded.
    pub issued_at: Option<SamlInstant>,
    /// Expiration instant, if recorded.
    pub expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}

impl PendingSnapshot<AuthnRequest> {
    /// Build an AuthnRequest snapshot from persistence fields.
    pub fn authn_request(
        id: impl Into<String>,
        relay_state: RelayStateParam,
        peer_entity_id: impl Into<String>,
        expected_binding: impl Into<String>,
        acs_url: impl Into<String>,
        acs_binding: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            relay_state,
            peer_entity_id: peer_entity_id.into(),
            expected_binding: expected_binding.into(),
            request_binding: None,
            acs_url: acs_url.into(),
            acs_binding: acs_binding.into(),
            acs_index: None,
            acs_is_default: false,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        }
    }
}

/// Pending SAML message correlation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending<Message> {
    id: MessageId,
    relay_state: RelayStateParam,
    request_binding: Option<SsoRequestBinding>,
    response_binding: Option<SsoResponseBinding>,
    peer_entity_id: EntityId,
    issued_at: Option<SamlInstant>,
    expires_at: Option<SamlInstant>,
    _message: PhantomData<Message>,
}

impl<Message> Pending<Message> {
    /// Create pending message state.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when RelayState or peer entity ID are malformed.
    pub fn try_new(
        id: MessageId,
        relay_state: RelayStateParam,
        request_binding: Option<SsoRequestBinding>,
        response_binding: Option<SsoResponseBinding>,
        peer_entity_id: EntityId,
    ) -> Result<Self, SamlError> {
        relay_state.validate()?;
        EntityId::try_new(peer_entity_id.as_str().to_string())?;
        Ok(Self {
            id,
            relay_state,
            request_binding,
            response_binding,
            peer_entity_id,
            issued_at: None,
            expires_at: None,
            _message: PhantomData,
        })
    }

    /// Record an issue instant.
    pub fn with_issue_instant(mut self, issued_at: SamlInstant) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    /// Record an expiration instant.
    pub fn with_expiration(mut self, expires_at: SamlInstant) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// SAML protocol message ID.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// RelayState state.
    pub fn relay_state(&self) -> &RelayStateParam {
        &self.relay_state
    }

    /// Request binding, when tracked.
    pub fn request_binding(&self) -> Option<SsoRequestBinding> {
        self.request_binding
    }

    /// Expected response binding, when tracked.
    pub fn response_binding(&self) -> Option<SsoResponseBinding> {
        self.response_binding
    }

    /// Peer entity ID.
    pub fn peer_entity_id(&self) -> &EntityId {
        &self.peer_entity_id
    }

    /// Issue instant, if recorded.
    pub fn issued_at(&self) -> Option<&SamlInstant> {
        self.issued_at.as_ref()
    }

    /// Expiration instant, if recorded.
    pub fn expires_at(&self) -> Option<&SamlInstant> {
        self.expires_at.as_ref()
    }

    /// Build a persistable snapshot.
    pub fn snapshot(&self) -> PendingSnapshot<Message> {
        PendingSnapshot {
            id: self.id.as_str().to_string(),
            relay_state: self.relay_state.clone(),
            peer_entity_id: self.peer_entity_id.as_str().to_string(),
            expected_binding: self
                .response_binding
                .map(|binding| binding.as_binding().short_name().to_string())
                .unwrap_or_default(),
            request_binding: self
                .request_binding
                .map(|binding| binding.as_binding().short_name().to_string()),
            acs_url: String::new(),
            acs_binding: String::new(),
            acs_index: None,
            acs_is_default: false,
            issued_at: self.issued_at.clone(),
            expires_at: self.expires_at.clone(),
            _message: PhantomData,
        }
    }

    /// Reconstruct pending state from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when any snapshot field is malformed or inconsistent.
    pub fn from_snapshot(snapshot: PendingSnapshot<Message>) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        if snapshot.expires_at.is_some() && snapshot.issued_at.is_none() {
            return Err(SamlError::Invalid(
                "pending snapshot expiration requires an issue instant".into(),
            ));
        }
        let request_binding = snapshot
            .request_binding
            .as_deref()
            .map(sso_request_binding_from_snapshot_value)
            .transpose()?;
        let response_binding = if snapshot.expected_binding.is_empty() {
            None
        } else {
            Some(sso_response_binding_from_snapshot_value(
                &snapshot.expected_binding,
            )?)
        };
        Ok(Self {
            id: MessageId::try_new(snapshot.id)?,
            relay_state: snapshot.relay_state,
            request_binding,
            response_binding,
            peer_entity_id: EntityId::try_new(snapshot.peer_entity_id)?,
            issued_at: snapshot.issued_at,
            expires_at: snapshot.expires_at,
            _message: PhantomData,
        })
    }
}

/// Pending AuthnRequest correlation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthnRequest {
    request_id: MessageId,
    relay_state: RelayStateParam,
    acs: AcsEndpoint,
    response_binding: SsoResponseBinding,
    idp_entity_id: EntityId,
    issued_at: Option<SamlInstant>,
    expires_at: Option<SamlInstant>,
}

impl PendingAuthnRequest {
    /// Create pending AuthnRequest state without storing keys or metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError::Invalid`] when the RelayState state is malformed,
    /// the IdP entity ID is empty, or the selected ACS binding does not match
    /// the expected response binding.
    pub fn try_new(
        request_id: MessageId,
        relay_state: RelayStateParam,
        acs: AcsEndpoint,
        response_binding: SsoResponseBinding,
        idp_entity_id: EntityId,
    ) -> Result<Self, SamlError> {
        relay_state.validate()?;
        EntityId::try_new(idp_entity_id.as_str().to_string())?;
        if acs.binding() != response_binding {
            return Err(SamlError::Invalid(
                "ACS binding must match expected response binding".into(),
            ));
        }
        Ok(Self {
            request_id,
            relay_state,
            acs,
            response_binding,
            idp_entity_id,
            issued_at: None,
            expires_at: None,
        })
    }

    /// Record an issue instant.
    pub fn with_issue_instant(mut self, issued_at: SamlInstant) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    /// Record an expiration instant.
    pub fn with_expiration(mut self, expires_at: SamlInstant) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Reconstruct pending AuthnRequest state from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SamlError`] when any snapshot field is malformed or
    /// inconsistent.
    pub fn from_snapshot(snapshot: PendingSnapshot<AuthnRequest>) -> Result<Self, SamlError> {
        snapshot.relay_state.validate()?;
        if snapshot.expires_at.is_some() && snapshot.issued_at.is_none() {
            return Err(SamlError::Invalid(
                "pending snapshot expiration requires an issue instant".into(),
            ));
        }
        let request_id = MessageId::try_new(snapshot.id)?;
        let idp_entity_id = EntityId::try_new(snapshot.peer_entity_id)?;
        let response_binding =
            sso_response_binding_from_snapshot_value(&snapshot.expected_binding)?;
        let acs_binding = sso_response_binding_from_snapshot_value(&snapshot.acs_binding)?;
        let mut acs = AcsEndpoint::new(acs_binding, EndpointUrl::try_new(snapshot.acs_url)?)
            .with_default_flag(snapshot.acs_is_default);
        if let Some(index) = snapshot.acs_index {
            acs = acs.with_index(index);
        }
        let mut pending = Self::try_new(
            request_id,
            snapshot.relay_state,
            acs,
            response_binding,
            idp_entity_id,
        )?;
        pending.issued_at = snapshot.issued_at;
        pending.expires_at = snapshot.expires_at;
        Ok(pending)
    }

    /// Build a persistable snapshot.
    pub fn snapshot(&self) -> PendingSnapshot<AuthnRequest> {
        let mut snapshot = PendingSnapshot::authn_request(
            self.request_id.as_str(),
            self.relay_state.clone(),
            self.idp_entity_id.as_str(),
            self.response_binding.as_binding().short_name(),
            self.acs.location().as_str(),
            self.acs.binding().as_binding().short_name(),
        );
        snapshot.acs_index = self.acs.index();
        snapshot.acs_is_default = self.acs.is_default();
        snapshot.issued_at = self.issued_at.clone();
        snapshot.expires_at = self.expires_at.clone();
        snapshot
    }

    /// Request ID.
    pub fn request_id(&self) -> &MessageId {
        &self.request_id
    }

    /// RelayState state.
    pub fn relay_state(&self) -> &RelayStateParam {
        &self.relay_state
    }

    /// Selected ACS endpoint.
    pub fn acs(&self) -> &AcsEndpoint {
        &self.acs
    }

    /// Expected response binding.
    pub fn response_binding(&self) -> SsoResponseBinding {
        self.response_binding
    }

    /// Selected IdP entity ID.
    pub fn idp_entity_id(&self) -> &EntityId {
        &self.idp_entity_id
    }

    /// Issue instant, if recorded.
    pub fn issued_at(&self) -> Option<&SamlInstant> {
        self.issued_at.as_ref()
    }

    /// Expiration instant, if recorded.
    pub fn expires_at(&self) -> Option<&SamlInstant> {
        self.expires_at.as_ref()
    }
}

fn sso_response_binding_from_snapshot_value(value: &str) -> Result<SsoResponseBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    SsoResponseBinding::try_from(binding)
}

fn sso_request_binding_from_snapshot_value(value: &str) -> Result<SsoRequestBinding, SamlError> {
    let binding = Binding::from_short_name(value)
        .or_else(|| Binding::from_urn(value))
        .ok_or(SamlError::UndefinedBinding)?;
    SsoRequestBinding::try_from(binding)
}

/// Started browser flow with pending state and outbound browser action.
#[derive(Debug, Clone)]
pub struct Started<Message> {
    /// Pending correlation state.
    pub pending: Pending<Message>,
    /// Outbound browser action.
    pub outbound: Outbound<Message>,
}
