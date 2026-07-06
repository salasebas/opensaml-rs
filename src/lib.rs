//! `saml-rs` - SAML 2.0 Service Provider and Identity Provider support.
//!
//! # Start here
//!
//! Start new browser SSO/SLO integrations with [`Saml`]. The typed facade keeps
//! local role state in [`Saml<Sp>`] or [`Saml<Idp>`], accepts peer metadata
//! through typed descriptors, and returns pending transaction values that
//! callers can store with browser session state.
//!
//! The dependency-free config builders use strict typed defaults. Opt into
//! compatibility policy by name when a legacy peer requires unsigned protocol
//! messages.
//! Where the compact flow examples below use
//! [`ReplayPolicy::DisabledForCompatibility`] or unsigned metadata, treat those
//! as explicit interoperability choices. Production-shaped inbound flows should
//! use [`ReplayPolicy::RequireCache`] with a caller-owned [`ReplayCache`] and,
//! when protocol timestamps are not enough for expiry,
//! [`SamlValidationContext::with_replay_retention`].
//!
//! ```
//! use saml_rs::{AcsEndpoint, EntityId, SpConfig, SpValidationPolicy};
//!
//! # fn main() -> Result<(), saml_rs::SamlError> {
//! let config = SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
//!     .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
//!     .validation(SpValidationPolicy::compatibility())
//!     .build()?;
//!
//! assert_eq!(config.entity_id.as_str(), "https://sp.example.com/metadata");
//! # Ok(()) }
//! ```
//!
//! # SP-initiated SSO
//!
//! [`Saml<Sp>::start_sso`] creates the browser action and [`PendingAuthnRequest`].
//! Store the pending value and pass it back to [`Saml<Sp>::finish_sso`] when the
//! ACS endpoint receives the SAML response.
//!
//! ```no_run
//! use saml_rs::{
//!     AcsEndpoint, BrowserInput, EntityId, FormField, IdpDescriptor,
//!     MetadataTrustPolicy, ReplayPolicy, Saml, SamlValidationContext, SpConfig,
//!     SpValidationPolicy, SsoResponse, StartSso,
//! };
//! use time::OffsetDateTime;
//!
//! # fn run(
//! #     idp_metadata_xml: &str,
//! #     form_fields: Vec<FormField>,
//! # ) -> Result<(), saml_rs::SamlError> {
//! let sp = Saml::sp(
//!     SpConfig::builder(EntityId::try_new("https://sp.example.com/metadata")?)
//!         .acs_endpoint(AcsEndpoint::post("https://sp.example.com/acs")?)
//!         .validation(SpValidationPolicy::compatibility())
//!         .build()?,
//! )?;
//! let idp = IdpDescriptor::from_metadata_xml_for(
//!     EntityId::try_new("https://idp.example.com/metadata")?,
//!     idp_metadata_xml,
//!     MetadataTrustPolicy::UnsignedForCompatibility,
//! )?;
//!
//! let started = sp.start_sso(&idp, StartSso::redirect())?;
//! let redirect_url = started.outbound.redirect_url()?;
//! # let _ = redirect_url;
//!
//! let validation = SamlValidationContext::new(
//!     OffsetDateTime::now_utc(),
//!     ReplayPolicy::DisabledForCompatibility,
//! );
//! let session = sp.finish_sso(
//!     &idp,
//!     &started.pending,
//!     BrowserInput::<SsoResponse>::post(form_fields),
//!     validation,
//! )?;
//! let name_id = session.name_id().value();
//! # let _ = name_id;
//! # Ok(()) }
//! ```
//!
//! # IdP-initiated SSO
//!
//! Use [`Saml<Sp>::accept_unsolicited_sso`] for IdP-initiated responses. This
//! method is separate from `finish_sso` so unsolicited responses are an explicit
//! caller choice rather than a missing pending request.
//!
//! ```no_run
//! use saml_rs::{
//!     BrowserInput, FormField, IdpDescriptor, ReplayPolicy, Saml,
//!     SamlValidationContext, SsoResponse,
//! };
//! use time::OffsetDateTime;
//!
//! # fn accept(
//! #     sp: &Saml<saml_rs::Sp>,
//! #     idp: &IdpDescriptor,
//! #     form_fields: Vec<FormField>,
//! # ) -> Result<(), saml_rs::SamlError> {
//! let validation = SamlValidationContext::new(
//!     OffsetDateTime::now_utc(),
//!     ReplayPolicy::DisabledForCompatibility,
//! );
//! let session = sp.accept_unsolicited_sso(
//!     idp,
//!     BrowserInput::<SsoResponse>::post(form_fields),
//!     validation,
//! )?;
//! let issuer = session.issuer().as_str();
//! # let _ = issuer;
//! # Ok(()) }
//! ```
//!
//! # Identity Provider flows
//!
//! [`Saml<Idp>::receive_sso`] parses an SP `AuthnRequest`; [`Saml<Idp>::respond_sso`]
//! returns the typed browser response.
//!
//! ```no_run
//! use saml_rs::{
//!     AuthnRequest, BrowserInput, FormField, NameId, ReplayPolicy, RespondSso,
//!     Saml, SamlValidationContext, SpDescriptor, Subject,
//! };
//! use time::OffsetDateTime;
//!
//! # fn respond(
//! #     idp: &Saml<saml_rs::Idp>,
//! #     sp: &SpDescriptor,
//! #     request_fields: Vec<FormField>,
//! # ) -> Result<(), saml_rs::SamlError> {
//! let validation = SamlValidationContext::new(
//!     OffsetDateTime::now_utc(),
//!     ReplayPolicy::DisabledForCompatibility,
//! );
//! let request = idp.receive_sso(
//!     sp,
//!     BrowserInput::<AuthnRequest>::post(request_fields),
//!     validation,
//! )?;
//! let response = idp.respond_sso(
//!     sp,
//!     &request,
//!     Subject::new(NameId::new("alice@example.com", None), Vec::new()),
//!     RespondSso::post(),
//! )?;
//! let form = response.post_form()?;
//! # let _ = form;
//! # Ok(()) }
//! ```
//!
//! # Single Logout
//!
//! Typed SLO uses the same pattern: start with a [`LogoutSubject`], store the
//! returned [`PendingLogoutRequest`], and finish only with the matching
//! [`LogoutResponse`]. Receiving and responding to peer-initiated logout uses
//! [`Received<LogoutRequest>`] instead of free-form request ID strings.
//!
//! ```no_run
//! use saml_rs::{
//!     BrowserInput, FormField, IdpDescriptor, LogoutResponse, ReplayPolicy,
//!     Saml, SamlValidationContext, SsoSession, StartSlo,
//! };
//! use time::OffsetDateTime;
//!
//! # fn logout(
//! #     sp: &Saml<saml_rs::Sp>,
//! #     idp: &IdpDescriptor,
//! #     session: &SsoSession,
//! #     response_fields: Vec<FormField>,
//! # ) -> Result<(), saml_rs::SamlError> {
//! if let Some(subject) = session.logout_subject() {
//!     let started = sp.start_slo(idp, subject, StartSlo::post())?;
//!     let validation = SamlValidationContext::new(
//!         OffsetDateTime::now_utc(),
//!         ReplayPolicy::DisabledForCompatibility,
//!     );
//!     let completed = sp.finish_slo(
//!         idp,
//!         &started.pending,
//!         BrowserInput::<LogoutResponse>::post(response_fields),
//!         validation,
//!     )?;
//!     let peer = completed.peer_entity_id().as_str();
//!     # let _ = peer;
//! }
//! # Ok(()) }
//! ```
//!
//! # Compile-time flow boundaries
//!
//! SSO and SLO pending values are different types. A logout pending value cannot
//! be used to finish Web SSO:
//!
//! ```compile_fail
//! use saml_rs::{
//!     BrowserInput, IdpDescriptor, PendingLogoutRequest, Saml,
//!     SamlValidationContext, SsoResponse,
//! };
//!
//! fn wrong(
//!     sp: &Saml<saml_rs::Sp>,
//!     idp: &IdpDescriptor,
//!     pending: &PendingLogoutRequest,
//!     input: BrowserInput<SsoResponse>,
//!     validation: SamlValidationContext<'_>,
//! ) -> Result<(), saml_rs::SamlError> {
//!     let _ = sp.finish_sso(idp, pending, input, validation)?;
//!     Ok(())
//! }
//! ```
//!
//! SLO responses are correlated through [`Received<LogoutRequest>`], not
//! arbitrary request ID strings:
//!
//! ```compile_fail
//! use saml_rs::{RespondSlo, Saml, SpDescriptor};
//!
//! fn wrong(
//!     idp: &Saml<saml_rs::Idp>,
//!     sp: &SpDescriptor,
//!     request_id: &str,
//! ) -> Result<(), saml_rs::SamlError> {
//!     let _ = idp.respond_slo(sp, request_id, RespondSlo::post())?;
//!     Ok(())
//! }
//! ```
//!
//! # Metadata trust
//!
//! Metadata trust is explicit and caller-pinned. [`MetadataTrustPolicy`] can
//! accept unsigned metadata for explicit legacy compatibility or require a
//! signature from caller-provided certificates with
//! [`MetadataTrustPolicy::RequireSignature`]. Prefer signed metadata with pinned
//! certificates for production trust decisions; the crate does not treat the
//! public web PKI CA store as SAML metadata trust.
//!
//! # Raw compatibility API
//!
//! The [`raw`] module contains the low-level compatibility API and protocol
//! helpers. Advanced callers should import [`raw::ServiceProvider`],
//! [`raw::IdentityProvider`], [`raw::HttpRequest`], and [`raw::BindingContext`]
//! from there rather than using root compatibility exports.
//!
//! # Unsupported profiles
//!
//! The high-level [`Saml`] API focuses on browser Web SSO, metadata-driven SP/IdP
//! setup, XML signature/encryption through `bergshamra`, and Single Logout. It
//! does not yet implement Artifact resolution, SOAP/back-channel profiles,
//! ECP/PAOS, SAML query protocols, NameID management, or metadata federation. If
//! you need one of those profiles for a real interoperability target, please
//! open an issue with the profile, binding, IdP/SP product, and a minimal
//! expected flow so we can consider the implementation.
//!
//! XML cryptography (XML-DSig sign/verify with anti-wrapping, XML-Enc, detached
//! message signatures) is delegated to `bergshamra` behind the
//! `crypto-bergshamra` feature, which is on by default. Configure assertion
//! encryption and XML-Enc compatibility exceptions through [`XmlEncryptionPolicy`].
//! Disable default features to build the crypto-free protocol layer; crypto
//! operations then fail closed with [`SamlError::Unsupported`].

#![forbid(unsafe_code)]

#[doc(hidden)]
pub mod api;
#[doc(hidden)]
pub mod binding;
pub mod browser;
pub mod config;
pub mod constants;
#[doc(hidden)]
pub mod context;
#[doc(hidden)]
pub mod crypto;
#[doc(hidden)]
pub mod entity;
pub mod error;
#[doc(hidden)]
pub mod flow;
#[doc(hidden)]
pub mod idp;
#[doc(hidden)]
pub mod logout;
pub mod metadata;
pub mod model;
pub mod raw;
#[doc(hidden)]
pub mod sp;
#[doc(hidden)]
pub mod template;
#[doc(hidden)]
pub mod util;
#[doc(hidden)]
pub mod validator;
#[doc(hidden)]
pub mod xml;

pub use api::{
    ForceAuthn, Idp, LogoutSigning, RespondSlo, RespondSso, Saml, SamlError, Sp, StartSlo,
    StartSso, Unknown,
};
pub use browser::{
    AcsEndpoint, BrowserInput, EndpointUrl, FormField, LogoutBinding, Outbound, Pending,
    PendingAuthnRequest, PendingLogoutRequest, PendingSnapshot, PostForm, SloEndpoint, SsoEndpoint,
    SsoRequestBinding, SsoResponseBinding, Started,
};
pub use config::{
    AlgorithmPolicy, AssertionEncryptionPolicy, AssertionSignaturePolicy, AudienceValidationPolicy,
    AuthnRequestSigningPolicy, AuthnRequestValidationPolicy, CertificatePem, Credentials,
    DataEncryptionAlgorithm, DigestAlgorithm, EntityId, IdpConfig, IdpConfigBuilder, IdpDescriptor,
    IdpMetadataConfig, IdpValidationPolicy, KeyEncryptionAlgorithm, LogoutPolicy,
    LogoutSignaturePolicy, MessageSignaturePolicy, MetadataTrustPolicy, NameIdCreationPolicy,
    NameIdFormat, Passphrase, PrivateKeyPem, SignatureAlgorithm, SpConfig, SpConfigBuilder,
    SpDescriptor, SpMetadataConfig, SpValidationPolicy, TemplatePolicy, TransformAlgorithm,
    XmlEncryptionPolicy, XmlPolicy,
};
#[doc = "Compatibility export. Prefer `raw::EntitySetting` for low-level APIs."]
pub use entity::EntitySetting;
#[doc = "Compatibility export. Prefer `raw::IdentityProvider` for low-level APIs."]
pub use idp::IdentityProvider;
#[cfg(feature = "crypto-bergshamra")]
pub use metadata::MetadataSignatureVerification;
pub use model::{
    Assertion, AssertionId, Attribute, AttributeValue, Attributes, AuthnRequest, AuthnSession,
    ClockSkew, LogoutCompleted, LogoutRequest, LogoutResponse, LogoutSubject, MessageId, NameId,
    NameIdCreationRequest, NameIdPolicy, Received, RelayState, RelayStateParam, ReplayCache,
    ReplayKey, ReplayPolicy, SamlInstant, SamlValidationContext, SessionIndex, SsoResponse,
    SsoSession, Subject, SubjectConfirmation, MAX_RELAY_STATE_BYTES,
};
#[doc = "Compatibility export. Prefer `raw::ServiceProvider` for low-level APIs."]
pub use sp::ServiceProvider;
