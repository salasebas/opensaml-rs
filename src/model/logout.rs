use super::extract::{
    optional_endpoint, optional_request_id, required_str, session_indexes_from_value,
};
use super::identifiers::{MessageId, SessionIndex};
use super::subject::NameId;
use super::EndpointUrl;
use crate::config::EntityId;
use crate::error::SamlError;
use crate::raw::FlowResult;

/// Parsed LogoutRequest result.
#[derive(Debug, Clone)]
pub struct LogoutRequest {
    id: MessageId,
    issuer: EntityId,
    name_id: Option<NameId>,
    session_indexes: Vec<SessionIndex>,
    destination: Option<EndpointUrl>,
    raw_flow: FlowResult,
}

impl LogoutRequest {
    /// LogoutRequest ID.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// LogoutRequest issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// NameID, when present.
    pub fn name_id(&self) -> Option<&NameId> {
        self.name_id.as_ref()
    }

    /// Session indexes.
    pub fn session_indexes(&self) -> &[SessionIndex] {
        &self.session_indexes
    }

    /// Destination endpoint, when present.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for LogoutRequest {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, "request.id")?)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let name_id = raw_flow
            .extract
            .get_str("nameID")
            .map(|value| NameId::new(value, None));
        let session_indexes = session_indexes_from_value(raw_flow.extract.get("sessionIndex"))?;
        let destination = optional_endpoint(&raw_flow.extract, "request.destination")?;
        Ok(Self {
            id,
            issuer,
            name_id,
            session_indexes,
            destination,
            raw_flow,
        })
    }
}

/// Parsed LogoutResponse result.
#[derive(Debug, Clone)]
pub struct LogoutResponse {
    id: MessageId,
    issuer: EntityId,
    in_response_to: Option<MessageId>,
    destination: Option<EndpointUrl>,
    raw_flow: FlowResult,
}

impl LogoutResponse {
    /// LogoutResponse ID.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// LogoutResponse issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// InResponseTo, when present.
    pub fn in_response_to(&self) -> Option<&MessageId> {
        self.in_response_to.as_ref()
    }

    /// Destination endpoint, when present.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for LogoutResponse {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, "response.id")?)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let in_response_to = optional_request_id(&raw_flow.extract, "response.inResponseTo")?;
        let destination = optional_endpoint(&raw_flow.extract, "response.destination")?;
        Ok(Self {
            id,
            issuer,
            in_response_to,
            destination,
            raw_flow,
        })
    }
}

/// Marker result for completed logout flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutCompleted {
    peer_entity_id: EntityId,
}

impl LogoutCompleted {
    /// Create a completed logout marker.
    pub fn new(peer_entity_id: EntityId) -> Self {
        Self { peer_entity_id }
    }

    /// Peer entity ID involved in the completed logout.
    pub fn peer_entity_id(&self) -> &EntityId {
        &self.peer_entity_id
    }
}
