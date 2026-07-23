use crate::browser::{LogoutBinding, SsoRequestBinding, SsoResponseBinding};
use crate::model::RelayStateParam;

/// Explicit `ForceAuthn` value for outbound AuthnRequests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForceAuthn {
    /// Emit `ForceAuthn="true"`.
    Required,
    /// Emit `ForceAuthn="false"`.
    NotRequired,
}

impl ForceAuthn {
    pub(super) fn as_bool(self) -> bool {
        match self {
            Self::Required => true,
            Self::NotRequired => false,
        }
    }
}

/// Options for starting SP-initiated Web SSO.
#[derive(Debug, Clone)]
pub struct StartSso {
    pub(super) binding: SsoRequestBinding,
    pub(super) response_binding: Option<SsoResponseBinding>,
    pub(super) relay_state: RelayStateParam,
    pub(super) force_authn: Option<ForceAuthn>,
    pub(super) acs_index: Option<u16>,
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
            response_binding: None,
            relay_state: RelayStateParam::absent(),
            force_authn: None,
            acs_index: None,
        }
    }

    /// Set the expected SAML Response binding.
    pub fn response_binding(mut self, binding: SsoResponseBinding) -> Self {
        self.response_binding = Some(binding);
        self
    }

    /// Set exact RelayState state for the outbound request.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = relay_state;
        self
    }

    /// Set the exact `ForceAuthn` value.
    pub fn force_authn(mut self, force_authn: ForceAuthn) -> Self {
        self.force_authn = Some(force_authn);
        self
    }

    /// Select an AssertionConsumerServiceIndex.
    pub fn assertion_consumer_service_index(mut self, acs_index: u16) -> Self {
        self.acs_index = Some(acs_index);
        self
    }
}

/// Options for issuing SAML Responses from an IdP.
#[derive(Debug, Clone)]
pub struct RespondSso {
    pub(super) binding: SsoResponseBinding,
    pub(super) relay_state: Option<RelayStateParam>,
    response_signing: ResponseSigning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseSigning {
    FollowEncryptedCbcRecommendation,
    Always,
    AllowUnsignedEncryptedCbcForCompatibility,
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
            response_signing: ResponseSigning::FollowEncryptedCbcRecommendation,
        }
    }

    /// Always authenticate the top-level SAML Response.
    ///
    /// HTTP-POST embeds an XML signature covering the Response. HTTP-POST-
    /// SimpleSign continues to use its binding-defined detached signature.
    pub fn sign_response(mut self) -> Self {
        self.response_signing = ResponseSigning::Always;
        self
    }

    /// Allow an unsigned Response around a CBC-encrypted Assertion.
    ///
    /// This explicitly relaxes SAML V2.0 Approved Errata 05 E93, which
    /// recommends signing the Response so the ciphertext is integrity
    /// protected. By default, typed IdPs sign such Responses automatically.
    pub fn allow_unsigned_encrypted_cbc_for_compatibility(mut self) -> Self {
        self.response_signing = ResponseSigning::AllowUnsignedEncryptedCbcForCompatibility;
        self
    }

    /// Set exact RelayState state for the response.
    ///
    /// When omitted for a response to a received request, the received
    /// RelayState is echoed. Pass [`RelayStateParam::absent`] to suppress echo.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = Some(relay_state);
        self
    }

    pub(super) fn should_sign_response(
        &self,
        assertion_encrypted: bool,
        data_encryption_algorithm: &str,
    ) -> bool {
        match self.response_signing {
            ResponseSigning::FollowEncryptedCbcRecommendation => {
                assertion_encrypted
                    && crate::constants::is_xml_encryption_cbc_algorithm(data_encryption_algorithm)
            }
            ResponseSigning::Always => true,
            ResponseSigning::AllowUnsignedEncryptedCbcForCompatibility => false,
        }
    }
}

/// Explicit signing choice for typed Single Logout requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutSigning {
    /// Use the local typed logout policy.
    FollowLocalPolicy,
    /// Sign this logout message.
    Sign,
    /// Send unsigned logout for an explicit compatibility exception.
    DoNotSignForCompatibility,
}

/// Options for issuing a LogoutRequest.
#[derive(Debug, Clone)]
pub struct StartSlo {
    pub(super) binding: LogoutBinding,
    pub(super) relay_state: RelayStateParam,
    pub(super) signing: LogoutSigning,
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
            signing: LogoutSigning::FollowLocalPolicy,
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
    pub(super) binding: LogoutBinding,
    pub(super) relay_state: Option<RelayStateParam>,
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
            relay_state: None,
        }
    }

    /// Set exact RelayState state for the logout response.
    ///
    /// When omitted, the received LogoutRequest RelayState is echoed. Pass
    /// [`RelayStateParam::absent`] to suppress echo.
    pub fn relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = Some(relay_state);
        self
    }
}
