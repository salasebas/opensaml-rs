//! Entity base settings shared by [`crate::sp::ServiceProvider`] and
//! [`crate::idp::IdentityProvider`] (samlify `entity.ts` `defaultEntitySetting`).

use crate::binding::MAX_DEFLATE_RAW_DECODE_BYTES;
use crate::constants::{
    data_encryption_algorithm, key_encryption_algorithm, signature_algorithm, transform_algorithm,
    MessageSignatureOrder,
};
use crate::xml::XmlLimits;

/// Runtime configuration for an entity (keys, algorithms, flags).
///
/// Use [`EntitySetting::default`] and tweak the fields you need.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct EntitySetting {
    /// Override entity ID (otherwise taken from metadata).
    pub entity_id: Option<String>,
    /// Signature algorithm URI for outgoing signatures.
    pub request_signature_algorithm: String,
    /// Data encryption algorithm URI.
    pub data_encryption_algorithm: String,
    /// Key encryption algorithm URI.
    pub key_encryption_algorithm: String,
    /// Sign-then-encrypt vs encrypt-then-sign.
    pub message_signing_order: MessageSignatureOrder,
    /// `AllowCreate` for the NameIDPolicy.
    pub allow_create: bool,
    /// Whether assertions are encrypted.
    pub is_assertion_encrypted: bool,
    /// Allow XML-Enc RSA key-transport decryption with the bundled software RSA backend.
    ///
    /// This is disabled by default because `bergshamra` currently reaches the
    /// RustCrypto `rsa` crate, which is affected by `RUSTSEC-2023-0071` when an
    /// attacker can observe timing. Prefer an external/HSM decryptor once one is
    /// exposed through the public API; enable this only as an explicit
    /// compatibility exception for deployments that accept that risk.
    pub allow_insecure_software_rsa_key_transport_decryption: bool,
    /// Default RelayState.
    pub relay_state: String,
    /// SP: signs its AuthnRequests.
    pub authn_requests_signed: bool,
    /// SP: requires signed assertions.
    pub want_assertions_signed: bool,
    /// SP: reject a `<Response>` whose `<Audience>` is not this entity (default `true`).
    pub validate_audience: bool,
    /// SP: requires signed messages.
    pub want_message_signed: bool,
    /// IdP: requires signed AuthnRequests.
    pub want_authn_requests_signed: bool,
    /// Requires signed LogoutRequest (default `true`).
    pub want_logout_request_signed: bool,
    /// Requires signed LogoutResponse.
    pub want_logout_response_signed: bool,
    /// Supported NameID formats.
    pub name_id_format: Vec<String>,
    /// Signing private key (PEM).
    pub private_key: Option<String>,
    /// Passphrase for `private_key`.
    pub private_key_pass: Option<String>,
    /// Signing certificate (PEM/base64).
    pub signing_cert: Option<String>,
    /// Encryption certificate (PEM/base64).
    pub encrypt_cert: Option<String>,
    /// Decryption private key (PEM).
    pub enc_private_key: Option<String>,
    /// Passphrase for `enc_private_key`.
    pub enc_private_key_pass: Option<String>,
    /// Clock drift tolerance `(not_before_ms, not_on_or_after_ms)`.
    pub clock_drifts: (i64, i64),
    /// Maximum decoded compressed and inflated raw-DEFLATE bytes accepted for
    /// HTTP-Redirect input.
    ///
    /// SAML does not define this limit; the default is a conservative
    /// resource-exhaustion guard for unauthenticated Redirect messages.
    pub redirect_inflate_max_bytes: usize,
    /// XML parser resource limits for inbound messages and metadata parsing.
    pub xml_limits: XmlLimits,
    /// IdP: protocol tag prefix for generated IdP messages (default `samlp`).
    pub tag_prefix_protocol: String,
    /// IdP: assertion tag prefix for generated IdP messages (default `saml`).
    pub tag_prefix_assertion: String,
    /// IdP: tag prefix for the `<EncryptedAssertion>` element (default `saml`).
    pub tag_prefix_encrypted_assertion: String,
    /// IdP: login `<Response>` template + attribute configuration.
    pub login_response_template: Option<crate::template::LoginResponseTemplate>,
    /// SP: custom `<AuthnRequest>` template (`None` uses the default).
    pub login_request_template: Option<String>,
    /// Custom `<LogoutRequest>` template (`None` uses the default).
    pub logout_request_template: Option<String>,
    /// Custom `<LogoutResponse>` template (`None` uses the default).
    pub logout_response_template: Option<String>,
    /// Custom embedded-signature placement/prefix (`None` uses the default).
    pub signature_config: Option<SignatureConfig>,
    /// XML-DSig transforms applied to signed references (default
    /// enveloped-signature + exclusive C14N).
    pub transformation_algorithms: Vec<String>,
}

/// Custom message rendering hook (samlify `customTagReplacement`): given the
/// resolved template, returns `(id, rendered_xml)`.
pub type CustomTagReplacement<'a> = &'a dyn Fn(&str) -> (String, String);

/// Where to place the `<Signature>` relative to the reference element
/// (samlify `signatureConfig.location.action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAction {
    /// Insert as the reference's next sibling (samlify default).
    #[default]
    After,
    /// Insert as the reference's previous sibling.
    Before,
    /// Insert as the reference's first child.
    Prepend,
    /// Insert as the reference's last child.
    Append,
}

/// Customizes the embedded XML-DSig signature (samlify `signatureConfig`).
#[derive(Debug, Clone)]
pub struct SignatureConfig {
    /// Element prefix for the signature (default `ds`).
    pub prefix: String,
    /// `local-name()` XPath of the reference element; `None` keeps the default
    /// (after the signed target's `<Issuer>`).
    pub reference: Option<String>,
    /// Placement relative to `reference`.
    pub action: SignatureAction,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            prefix: "ds".to_string(),
            reference: None,
            action: SignatureAction::After,
        }
    }
}

impl Default for EntitySetting {
    fn default() -> Self {
        Self {
            entity_id: None,
            request_signature_algorithm: signature_algorithm::RSA_SHA256.to_string(),
            data_encryption_algorithm: data_encryption_algorithm::AES_256.to_string(),
            key_encryption_algorithm: key_encryption_algorithm::RSA_OAEP_MGF1P.to_string(),
            message_signing_order: MessageSignatureOrder::SignThenEncrypt,
            allow_create: false,
            is_assertion_encrypted: false,
            allow_insecure_software_rsa_key_transport_decryption: false,
            relay_state: String::new(),
            authn_requests_signed: false,
            want_assertions_signed: false,
            validate_audience: true,
            want_message_signed: false,
            want_authn_requests_signed: false,
            want_logout_request_signed: true,
            want_logout_response_signed: true,
            name_id_format: Vec::new(),
            private_key: None,
            private_key_pass: None,
            signing_cert: None,
            encrypt_cert: None,
            enc_private_key: None,
            enc_private_key_pass: None,
            clock_drifts: (0, 0),
            redirect_inflate_max_bytes: MAX_DEFLATE_RAW_DECODE_BYTES,
            xml_limits: XmlLimits::default(),
            tag_prefix_protocol: "samlp".to_string(),
            tag_prefix_assertion: "saml".to_string(),
            tag_prefix_encrypted_assertion: "saml".to_string(),
            login_response_template: None,
            login_request_template: None,
            logout_request_template: None,
            logout_response_template: None,
            signature_config: None,
            transformation_algorithms: vec![
                transform_algorithm::ENVELOPED_SIGNATURE.to_string(),
                transform_algorithm::EXC_C14N.to_string(),
            ],
        }
    }
}

/// Generate a SAML message ID (`_` + UUIDv4), matching samlify's default.
pub fn generate_id() -> String {
    format!("_{}", uuid::Uuid::new_v4())
}

/// The authenticated subject an IdP issues a response for (samlify `user`).
#[derive(Debug, Clone, Default)]
pub struct User {
    /// `<NameID>` value (samlify `user.email`).
    pub name_id: String,
    /// Attribute values keyed by their `LoginResponseAttribute.value_tag`;
    /// each fills the `{attr<Tag>}` placeholder produced for that attribute.
    pub attributes: Vec<(String, String)>,
    /// `SessionIndex` for Single Logout requests (samlify `user.sessionIndex`).
    pub session_index: Option<String>,
}

impl User {
    /// A subject with just a NameID and no attributes.
    pub fn new(name_id: impl Into<String>) -> Self {
        Self {
            name_id: name_id.into(),
            ..Default::default()
        }
    }
}

/// Current UTC time as an ISO-8601 `IssueInstant` (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_iso8601() -> String {
    iso8601_offset(0)
}

/// UTC time `seconds` from now as ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn iso8601_offset(seconds: i64) -> String {
    let t = time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    )
}

/// The product of building an outbound message for a binding (samlify `BindingContext`).
#[derive(Debug, Clone)]
pub struct BindingContext {
    /// Generated message ID.
    pub id: String,
    /// Redirect: the full URL. POST/SimpleSign: the base64 message.
    pub context: String,
    /// RelayState, if any.
    pub relay_state: Option<String>,
    /// Destination endpoint.
    pub entity_endpoint: String,
    /// Binding used.
    pub binding: crate::constants::Binding,
    /// `SAMLRequest` or `SAMLResponse`.
    pub request_type: &'static str,
    /// Detached signature (redirect/SimpleSign signed messages), if computed.
    pub signature: Option<String>,
    /// Signature algorithm URI accompanying `signature`.
    pub sig_alg: Option<String>,
}

impl BindingContext {
    /// Build the POST/SimpleSign auto-submit form (the `context` must be base64).
    ///
    /// If exactly one of `sig_alg` or `signature` is present, this infallible
    /// helper omits the detached SimpleSign fields. Use [`Self::try_post_form`]
    /// to reject partial detached signature state.
    pub fn post_form(&self) -> String {
        crate::binding::saml_post_binding_form_with_signature(
            &self.entity_endpoint,
            self.request_type,
            &self.context,
            self.relay_state.as_deref(),
            self.sig_alg.as_deref(),
            self.signature.as_deref(),
        )
    }

    /// Build the POST/SimpleSign auto-submit form after validating the endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::SamlError::Invalid`] when `entity_endpoint`
    /// is not an absolute HTTP(S) URL, or when detached SimpleSign state has
    /// only one of `sig_alg` or `signature`.
    pub fn try_post_form(&self) -> Result<String, crate::error::SamlError> {
        crate::binding::try_saml_post_binding_form_with_signature(
            &self.entity_endpoint,
            self.request_type,
            &self.context,
            self.relay_state.as_deref(),
            self.sig_alg.as_deref(),
            self.signature.as_deref(),
        )
    }
}
