use super::extract::{name_id_policy_from_extract, optional_endpoint, optional_u16, required_str};
use super::identifiers::MessageId;
use super::subject::NameIdPolicy;
use super::{EndpointUrl, ReplayKey, SamlValidationContext};
use crate::browser::SsoResponseBinding;
use crate::config::EntityId;
use crate::constants::Binding;
use crate::error::SamlError;
use crate::raw::FlowResult;

/// Parsed AuthnRequest result.
#[derive(Debug, Clone)]
pub struct AuthnRequest {
    id: MessageId,
    issuer: EntityId,
    destination: Option<EndpointUrl>,
    acs_url: Option<EndpointUrl>,
    protocol_binding: Option<SsoResponseBinding>,
    acs_index: Option<u16>,
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

    /// Requested response `ProtocolBinding`, when present.
    pub fn protocol_binding(&self) -> Option<SsoResponseBinding> {
        self.protocol_binding
    }

    /// Requested `AssertionConsumerServiceIndex`, when present.
    pub fn acs_index(&self) -> Option<u16> {
        self.acs_index
    }

    /// NameIDPolicy, when present.
    pub fn name_id_policy(&self) -> Option<&NameIdPolicy> {
        self.name_id_policy.as_ref()
    }

    /// Check and store this AuthnRequest's replay key using caller cache state.
    pub fn check_and_store_replay(
        &self,
        validation: &mut SamlValidationContext<'_>,
    ) -> Result<(), SamlError> {
        validation.check_and_store_message_replay(ReplayKey::AuthnRequestId(self.id.clone()))
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
        let protocol_binding = optional_response_binding(&raw_flow.extract)?;
        let acs_index = optional_u16(&raw_flow.extract, "request.assertionConsumerServiceIndex")?;
        let name_id_policy = name_id_policy_from_extract(&raw_flow.extract)?;
        Ok(Self {
            id,
            issuer,
            destination,
            acs_url,
            protocol_binding,
            acs_index,
            name_id_policy,
            raw_flow,
        })
    }
}

fn optional_response_binding(
    extract: &crate::util::Value,
) -> Result<Option<SsoResponseBinding>, SamlError> {
    let Some(protocol_binding) = extract.get_str("request.protocolBinding") else {
        return Ok(None);
    };
    let binding = Binding::from_urn(protocol_binding).ok_or_else(|| {
        SamlError::Invalid(format!(
            "unsupported AuthnRequest ProtocolBinding {protocol_binding}"
        ))
    })?;
    SsoResponseBinding::try_from(binding).map(Some)
}
