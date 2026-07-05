use super::extract::{name_id_policy_from_extract, optional_endpoint, required_str};
use super::identifiers::MessageId;
use super::subject::NameIdPolicy;
use super::EndpointUrl;
use crate::config::EntityId;
use crate::error::SamlError;
use crate::raw::FlowResult;

/// Parsed AuthnRequest result.
#[derive(Debug, Clone)]
pub struct AuthnRequest {
    id: MessageId,
    issuer: EntityId,
    destination: Option<EndpointUrl>,
    acs_url: Option<EndpointUrl>,
    name_id_policy: Option<NameIdPolicy>,
    raw_flow: FlowResult,
}

impl AuthnRequest {
    /// Request ID.
    pub fn id(&self) -> &MessageId {
        &self.id
    }

    /// Request issuer.
    pub fn issuer(&self) -> &EntityId {
        &self.issuer
    }

    /// Destination endpoint, when present.
    pub fn destination(&self) -> Option<&EndpointUrl> {
        self.destination.as_ref()
    }

    /// AssertionConsumerServiceURL, when present.
    pub fn acs_url(&self) -> Option<&EndpointUrl> {
        self.acs_url.as_ref()
    }

    /// NameIDPolicy, when present.
    pub fn name_id_policy(&self) -> Option<&NameIdPolicy> {
        self.name_id_policy.as_ref()
    }

    /// Raw validated flow result.
    pub fn raw_flow(&self) -> &FlowResult {
        &self.raw_flow
    }
}

impl TryFrom<FlowResult> for AuthnRequest {
    type Error = SamlError;

    fn try_from(raw_flow: FlowResult) -> Result<Self, Self::Error> {
        let id = MessageId::try_new(required_str(&raw_flow.extract, "request.id")?)?;
        let issuer = EntityId::try_new(required_str(&raw_flow.extract, "issuer")?)?;
        let destination = optional_endpoint(&raw_flow.extract, "request.destination")?;
        let acs_url = optional_endpoint(&raw_flow.extract, "request.assertionConsumerServiceUrl")?;
        let name_id_policy = name_id_policy_from_extract(&raw_flow.extract);
        Ok(Self {
            id,
            issuer,
            destination,
            acs_url,
            name_id_policy,
            raw_flow,
        })
    }
}
