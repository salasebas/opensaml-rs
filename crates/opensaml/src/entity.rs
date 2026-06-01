//! Entity base settings shared by [`crate::sp::ServiceProvider`] and
//! [`crate::idp::IdentityProvider`] (samlify `entity.ts` `defaultEntitySetting`).

use crate::constants::{
    data_encryption_algorithm, key_encryption_algorithm, signature_algorithm, MessageSignatureOrder,
};

/// Runtime configuration for an entity (keys, algorithms, flags).
///
/// Use [`EntitySetting::default`] and tweak the fields you need.
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
    /// Default RelayState.
    pub relay_state: String,
    /// SP: signs its AuthnRequests.
    pub authn_requests_signed: bool,
    /// SP: requires signed assertions.
    pub want_assertions_signed: bool,
    /// SP: requires signed messages.
    pub want_message_signed: bool,
    /// IdP: requires signed AuthnRequests.
    pub want_authn_requests_signed: bool,
    /// Requires signed LogoutRequest.
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
            relay_state: String::new(),
            authn_requests_signed: false,
            want_assertions_signed: false,
            want_message_signed: false,
            want_authn_requests_signed: false,
            want_logout_request_signed: false,
            want_logout_response_signed: false,
            name_id_format: Vec::new(),
            private_key: None,
            private_key_pass: None,
            signing_cert: None,
            encrypt_cert: None,
            enc_private_key: None,
            enc_private_key_pass: None,
            clock_drifts: (0, 0),
        }
    }
}

/// Generate a SAML message ID (`_` + UUIDv4), matching samlify's default.
pub fn generate_id() -> String {
    format!("_{}", uuid::Uuid::new_v4())
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
    pub fn post_form(&self) -> String {
        crate::binding::saml_post_binding_form(
            &self.entity_endpoint,
            self.request_type,
            &self.context,
            self.relay_state.as_deref(),
        )
    }
}
